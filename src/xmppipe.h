/* Copyright (c) 2015-2019, Michael Santos <michael.santos@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <strophe.h>

#ifndef HAVE_STRTONUM
#include "strtonum.h"
#endif

#define XMPPIPE_VERSION "0.13.0"
#define XMPPIPE_RESOURCE "xmppipe"

#define XMPPIPE_STREQ(a, b) (strcmp((a), (b)) == 0)
#define XMPPIPE_STRNEQ(a, b) (strcmp((a), (b)) != 0)

#define BASE64_LENGTH(n) ((((n) + 2) / 3) * 4)

enum {
  XMPPIPE_S_DISCONNECTED,
  XMPPIPE_S_CONNECTING,
  XMPPIPE_S_CONNECTED,

  XMPPIPE_S_MUC_SERVICE_LOOKUP,
  XMPPIPE_S_MUC_FEATURE_LOOKUP,
  XMPPIPE_S_MUC_WAITJOIN,
  XMPPIPE_S_MUC_JOIN,
  XMPPIPE_S_MUC_UNLOCK,

  XMPPIPE_S_READY,
  XMPPIPE_S_READY_AVAIL,
  XMPPIPE_S_READY_EMPTY,
};

enum {
  XMPPIPE_OPT_DISCARD = 1 << 0, /* Throw away stdin if no occupants in MUC */
  XMPPIPE_OPT_DISCARD_TO_STDOUT =
      1 << 1,                   /* Throw away stdin and send to local stdout */
  XMPPIPE_OPT_EOF = 1 << 2,     /* Keep running on stdin EOF */
  XMPPIPE_OPT_SIGPIPE = 1 << 3, /* Exit if no occupants in MUC */
  XMPPIPE_OPT_GROUPCHAT = 1 << 4, /* Use groupchat */
};

enum { XMPPIPE_FMT_TEXT = 0, XMPPIPE_FMT_CSV };

typedef struct {
  xmpp_ctx_t *ctx;
  xmpp_conn_t *conn;
  int handled;

  char *room;       /* room, room@conference.xmpp.example.com */
  char *server;     /* xmpp.example.com */
  char *resource;   /* nick */
  char *mucservice; /* conference.xmpp.example.com */
  char *mucjid;     /* room@conference.xmpp.example.com/nick */
  char *subject;    /* topic/subject for MUC */
  char *out;        /* room@conference.xmpp.example.com */

  char *upload; /* XEP 0363 upload service */

  int status;
  int occupants;
  u_int32_t poll;      /* milliseconds */
  u_int32_t keepalive; /* periodically send a keepalive (milliseconds) */
  u_int32_t
      keepalive_fail; /* number of consecutive keepalives without a reply */
  u_int32_t keepalive_limit; /* number of keepalives without a reply */
  u_int32_t interval;        /* time since last keepalive (milliseconds) */
  size_t bufsz;              /* size of read buffer */

  int sm_enabled; /* stanzas: iq, message, presence */

  u_int32_t sm_request; /* count of sent stanzas */
  u_int32_t
      sm_request_unack; /* count of unacknowledged stream management requests */
  u_int32_t sm_request_interval; /* request ack every interval stanzas */

  u_int32_t sm_ack_recv; /* count of stanzas received from server */
  u_int32_t sm_ack_sent; /* server's count of stanzas we've sent */

  u_int32_t sm_unacked;
  u_int32_t sm_fc;

  int opt;
  int verbose;
  int encode; /* base64 encode/decode data to MUC */
  int format; /* input format: stdin, colon */
} xmppipe_state_t;

void event_loop(xmppipe_state_t *state);

/* handlers */
int handle_message(xmpp_conn_t *const, xmpp_stanza_t *const, void *const);
int handle_null(xmpp_conn_t *const, xmpp_stanza_t *const, void *const);
int handle_ping_reply(xmpp_conn_t *const, xmpp_stanza_t *const, void *const);
int handle_presence(xmpp_conn_t *const, xmpp_stanza_t *const, void *const);
void xmppipe_ping(xmppipe_state_t *);
int handle_presence_error(xmpp_conn_t *const, xmpp_stanza_t *const,
                          void *const);
int handle_sm_ack(xmpp_conn_t *const, xmpp_stanza_t *const, void *const);
int handle_sm_enabled(xmpp_conn_t *const, xmpp_stanza_t *const, void *const);
int handle_sm_request(xmpp_conn_t *const, xmpp_stanza_t *const, void *const);
int handle_version(xmpp_conn_t *const, xmpp_stanza_t *const, void *const);
int handle_iq(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
              void *const userdata);

void xmppipe_muc_join(xmppipe_state_t *);
void xmppipe_muc_subject(xmppipe_state_t *, char *);
void xmppipe_muc_unlock(xmppipe_state_t *);

void xmppipe_send_stanza(xmppipe_state_t *, char *, size_t);
void xmppipe_send_stanza_fmt(xmppipe_state_t *state, char *buf, size_t len);
void xmppipe_send_message(xmppipe_state_t *, char *, char *, char *, size_t);
void xmppipe_send(xmppipe_state_t *, xmpp_stanza_t *const);

int xmppipe_fmt_init(void);
char *xmppipe_fmt_encode(const char *);
char *xmppipe_nfmt_encode(const char *, size_t);
char *xmppipe_fmt_decode(const char *);
char *xmppipe_nfmt_decode(const char *, size_t);
int xmppipe_set_nonblock(int fd);

char *xmppipe_servername(char *);
char *xmppipe_roomname(char *);
char *xmppipe_conference(char *, char *);
char *xmppipe_mucjid(char *, char *);

void xmppipe_next_state(xmppipe_state_t *state, int status);
void xmppipe_stream_close(xmppipe_state_t *);

char *xmppipe_getenv(const char *);
char *xmppipe_strdup(const char *);
void *xmppipe_malloc(size_t);
void *xmppipe_calloc(size_t, size_t);

xmpp_stanza_t *xmppipe_message_new(xmpp_ctx_t *ctx, const char *const type,
                                   const char *const to, const char *const id);
void xmppipe_message_set_body(xmpp_stanza_t *msg, const char *const text);
xmpp_stanza_t *xmppipe_stanza_reply(xmpp_stanza_t *const stanza);

xmpp_stanza_t *xmppipe_stanza_new(xmpp_ctx_t *);
void xmppipe_stanza_set_attribute(xmpp_stanza_t *const, const char *const,
                                  const char *const);
void xmppipe_stanza_set_id(xmpp_stanza_t *const, const char *const);
void xmppipe_stanza_set_name(xmpp_stanza_t *, const char *const);
void xmppipe_stanza_set_ns(xmpp_stanza_t *const, const char *const);
void xmppipe_stanza_set_text(xmpp_stanza_t *, const char *const);
void xmppipe_stanza_set_type(xmpp_stanza_t *const, const char *const);
void xmppipe_stanza_add_child(xmpp_stanza_t *, xmpp_stanza_t *);

int xmppipe_sandbox_init(xmppipe_state_t *state);
int xmppipe_sandbox_stdin(xmppipe_state_t *state);
int xmppipe_conn_fd(xmppipe_state_t *state);

int b64_ntop(u_char const *src, size_t srclength, char *target,
             size_t targsize);
int b64_pton(char const *src, u_char *target, size_t targsize);
