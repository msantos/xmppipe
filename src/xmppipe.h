/* Copyright (c) 2015, Michael Santos <michael.santos@gmail.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <err.h>

#include <strophe.h>

#define XMPPIPE_VERSION "0.4.0"

#define XMPPIPE_STREQ(a,b)      !strcmp((a),(b))
#define XMPPIPE_STRNEQ(a,b)     strcmp((a),(b))

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
    XMPPIPE_OPT_DISCARD = 1 << 0,           /* Throw away stdin if no occupants in MUC */
    XMPPIPE_OPT_DISCARD_TO_STDOUT = 1 << 1, /* Throw away stdin and send to local stdout */
    XMPPIPE_OPT_EOF = 1 << 2,               /* Keep running on stdin EOF */
    XMPPIPE_OPT_SIGPIPE = 1 << 3,           /* Exit if no occupants in MUC */
};

typedef struct {
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;

    char *room;         /* room, room@conference.xmpp.example.com */
    char *server;       /* xmpp.example.com */
    char *resource;     /* nick */
    char *mucservice;   /* conference.xmpp.example.com */
    char *mucjid;       /* room@conference.xmpp.example.com/nick */
    char *subject;      /* topic/subject for MUC */
    char *out;          /* room@conference.xmpp.example.com */

    int status;
    int occupants;
    u_int32_t poll;     /* milliseconds */
    u_int32_t keepalive; /* periodically send a keepalive (milliseconds) */
    u_int32_t interval;  /* time since last keepalive (milliseconds) */
    size_t bufsz;       /* size of read buffer */

    int opt;
    int verbose;
} xmppipe_state_t;


int xmppipe_encode_init();
char *xmppipe_encode(const char *);
char *xmppipe_id_alloc();
int xmppipe_set_nonblock(int fd);

char *xmppipe_servername(char *);
char *xmppipe_roomname(char *);
char *xmppipe_conference(char *, char *);
char *xmppipe_mucjid(char *, char *);

char *xmppipe_getenv(const char *);
char *xmppipe_strdup(const char *);
void *xmppipe_malloc(size_t);
void *xmppipe_calloc(size_t, size_t);
