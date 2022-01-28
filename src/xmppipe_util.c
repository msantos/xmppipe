/* Copyright (c) 2015-2022, Michael Santos <michael.santos@gmail.com>
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
#include "xmppipe.h"

#include <fcntl.h>

#define XMPPIPE_NULL(a_)                                                       \
  if ((a_) == NULL) {                                                          \
    errx(3, "invalid argument: %s/%s (%s:%d)", __FUNCTION__, #a_, __FILE__,    \
         __LINE__);                                                            \
  }

const char *const xmppipe_states[] = {"XMPPIPE_S_DISCONNECTED",
                                      "XMPPIPE_S_CONNECTING",
                                      "XMPPIPE_S_CONNECTED",

                                      "XMPPIPE_S_MUC_SERVICE_LOOKUP",
                                      "XMPPIPE_S_MUC_FEATURE_LOOKUP",
                                      "XMPPIPE_S_MUC_WAITJOIN",
                                      "XMPPIPE_S_MUC_JOIN",
                                      "XMPPIPE_S_MUC_UNLOCK",

                                      "XMPPIPE_S_READY",
                                      "XMPPIPE_S_READY_AVAIL",
                                      "XMPPIPE_S_READY_EMPTY"};

int xmppipe_set_nonblock(int fd) {
  int flags = 0;

  flags = fcntl(fd, F_GETFD);
  if (flags < 0)
    return -1;

  if (fcntl(fd, F_SETFD, flags | O_NONBLOCK) < 0)
    return -1;

  return 0;
}

char *xmppipe_getenv(const char *s) {
  char *p = getenv(s);

  if (p == NULL)
    return NULL;

  return xmppipe_strdup(p);
}

char *xmppipe_strdup(const char *s) {
  char *buf = NULL;

  if (s == NULL)
    errx(2, "invalid string");

  buf = strdup(s);
  if (buf == NULL)
    err(3, "xmppipe_strdup");

  return buf;
}

void *xmppipe_malloc(size_t size) {
  char *buf = NULL;

  if (size == 0 || size > 0xffff)
    errx(2, "invalid size: %zd", size);

  buf = malloc(size);
  if (buf == NULL)
    err(3, "xmppipe_malloc: %zu", size);

  return buf;
}

void *xmppipe_calloc(size_t nmemb, size_t size) {
  char *buf = NULL;

  buf = calloc(nmemb, size);
  if (buf == NULL)
    err(3, "xmppipe_calloc: %zu/%zu", nmemb, size);

  return buf;
}

xmpp_stanza_t *xmppipe_message_new(xmpp_ctx_t *ctx, const char *const type,
                                   const char *const to, const char *const id) {
  xmpp_stanza_t *m = xmpp_message_new(ctx, type, to, id);

  if (m == NULL)
    err(3, "xmppipe_message_new");

  return m;
}

void xmppipe_message_set_body(xmpp_stanza_t *msg, const char *const text) {
  int rv;

  rv = xmpp_message_set_body(msg, text);
  if (rv != XMPP_EOK)
    errx(EXIT_FAILURE, "xmpp_message_set_body: %u", rv);
}

xmpp_stanza_t *xmppipe_stanza_reply(xmpp_stanza_t *const stanza) {
  xmpp_stanza_t *s = xmpp_stanza_reply(stanza);

  if (s == NULL)
    err(3, "xmppipe_stanza_reply");

  return s;
}

xmpp_stanza_t *xmppipe_stanza_new(xmpp_ctx_t *ctx) {
  xmpp_stanza_t *s = xmpp_stanza_new(ctx);

  if (s == NULL)
    err(3, "xmppipe_stanza_new");

  return s;
}

void xmppipe_stanza_set_attribute(xmpp_stanza_t *const stanza,
                                  const char *const key,
                                  const char *const value) {
  XMPPIPE_NULL(stanza);
  XMPPIPE_NULL(key);
  XMPPIPE_NULL(value);

  if (xmpp_stanza_set_attribute(stanza, key, value) < 0)
    err(3, "xmppipe_stanza_set_attribute");
}

void xmppipe_stanza_set_id(xmpp_stanza_t *const stanza, const char *const id) {
  XMPPIPE_NULL(stanza);
  XMPPIPE_NULL(id);

  if (xmpp_stanza_set_id(stanza, id) < 0)
    err(3, "xmppipe_stanza_set_id");
}

void xmppipe_stanza_set_name(xmpp_stanza_t *stanza, const char *const name) {
  XMPPIPE_NULL(stanza);
  XMPPIPE_NULL(name);

  switch (xmpp_stanza_set_name(stanza, name)) {
  case 0:
    return;
  case XMPP_EMEM:
    err(3, "xmppipe_stanza_set_name");
  case XMPP_EINVOP:
    err(4, "invalid operation");
  default:
    err(5, "unknown error");
  }
}

void xmppipe_stanza_set_ns(xmpp_stanza_t *const stanza, const char *const ns) {
  XMPPIPE_NULL(stanza);
  XMPPIPE_NULL(ns);

  if (xmpp_stanza_set_ns(stanza, ns) < 0)
    err(3, "xmppipe_stanza_set_ns");
}

void xmppipe_stanza_set_text(xmpp_stanza_t *stanza, const char *const text) {
  XMPPIPE_NULL(stanza);
  XMPPIPE_NULL(text);

  if (xmpp_stanza_set_text(stanza, text) < 0)
    err(3, "xmppipe_stanza_set_text");
}

void xmppipe_stanza_set_type(xmpp_stanza_t *const stanza,
                             const char *const type) {
  XMPPIPE_NULL(stanza);
  XMPPIPE_NULL(type);

  if (xmpp_stanza_set_type(stanza, type) < 0)
    err(3, "xmppipe_stanza_set_type");
}

void xmppipe_stanza_add_child(xmpp_stanza_t *stanza, xmpp_stanza_t *child) {
  XMPPIPE_NULL(stanza);
  XMPPIPE_NULL(child);

  if (xmpp_stanza_add_child(stanza, child) < 0)
    err(3, "xmppipe_stanza_add_child");
}

char *xmppipe_servername(char *jid) {
  char *buf = xmppipe_strdup(jid);
  char *p = strchr(buf, '@');
  char *q;

  if (p == NULL) {
    free(buf);
    return NULL;
  }

  *p++ = '\0';

  q = xmppipe_strdup(p);
  free(buf);

  return q;
}

char *xmppipe_conference(char *room, char *mucservice) {
  size_t len = strlen(room) + 1 + strlen(mucservice) + 1;
  char *buf = xmppipe_malloc(len);

  (void)snprintf(buf, len, "%s@%s", room, mucservice);

  return buf;
}

char *xmppipe_mucjid(char *muc, char *resource) {
  size_t len = strlen(muc) + 1 + strlen(resource) + 1;
  char *buf = xmppipe_malloc(len);

  (void)snprintf(buf, len, "%s/%s", muc, resource);

  return buf;
}

char *xmppipe_chatjid(char *jid, char *servername) {
  size_t len = strlen(jid) + 1 + strlen(servername) + 1;
  char *buf = xmppipe_malloc(len);

  (void)snprintf(buf, len, "%s@%s", jid, servername);

  return buf;
}

char *xmppipe_roomname(char *label) {
  char *buf = NULL;
  size_t len = 64;
  char name[16] = {0};

  if (gethostname(name, sizeof(name) - 1) < 0) {
    (void)snprintf(name, sizeof(name) - 1, "%s", XMPPIPE_RESOURCE);
  }

  buf = xmppipe_malloc(len);
  (void)snprintf(buf, len, "%s-%s-%d", label, name, getuid());

  return buf;
}

char *xmppipe_uuid_gen(xmpp_ctx_t *ctx) {
  char *uuid;

  uuid = xmpp_uuid_gen(ctx);

  if (uuid == NULL)
    errx(EXIT_FAILURE, "unable to allocate message id");

  return uuid;
}

void xmppipe_next_state(xmppipe_state_t *state, int status) {
  if (state->verbose)
    (void)fprintf(stderr, "next state: %s (%d) -> %s (%d)\n",
                  (state->status < 0 || state->status > XMPPIPE_S_READY_EMPTY)
                      ? "unknown"
                      : xmppipe_states[state->status],
                  state->status,
                  (state->status < 0 || state->status > XMPPIPE_S_READY_EMPTY)
                      ? "unknown"
                      : xmppipe_states[status],
                  status);

  state->status = status;
}
