/* Copyright (c) 2019-2023, Michael Santos <michael.santos@gmail.com>
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

int handle_message(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
                   void *const userdata) {
  xmpp_stanza_t *child;
  xmppipe_state_t *state = userdata;

  char *message = NULL;
  const char *type;
  const char *from;
  const char *to;
  const char *ns;

  char *etype;
  char *efrom;
  char *eto;
  char *emessage = NULL;

  char *symbol = "m";

  if (xmpp_stanza_get_child_by_name(stanza, "delay"))
    return 1;

  from = xmpp_stanza_get_attribute(stanza, "from");
  if (from == NULL)
    return 1;

  to = xmpp_stanza_get_attribute(stanza, "to");
  if (to == NULL)
    return 1;

  type = xmpp_stanza_get_type(stanza);
  if (type == NULL)
    return 1;

  /* Check if the message is from us */
  if (XMPPIPE_STREQ(type, "groupchat") && XMPPIPE_STREQ(from, state->mucjid))
    return 1;

  child = xmpp_stanza_get_child_by_name(stanza, "displayed");
  if (child != NULL) {
    ns = xmpp_stanza_get_ns(child);
    if (XMPPIPE_STREQ(ns, "urn:xmpp:chat-markers:0"))
      symbol = "M";
  }

  child = xmpp_stanza_get_child_by_name(stanza, "body");

  if (child != NULL) {
    message = xmpp_stanza_get_text(child);
    if (message != NULL) {
      if (state->encode) {
        size_t len = strlen(message);
        unsigned char *buf = NULL;
        size_t n = 0;

        xmpp_base64_decode_bin(state->ctx, message, len, &buf, &n);

        if (buf == NULL) {
          /* Not a base64 message */
          return 1;
        }

        emessage = xmppipe_nfmt_encode((char *)buf, n);
        xmpp_free(state->ctx, buf);
      } else {
        emessage = xmppipe_fmt_encode(message);
      }

      xmpp_free(state->ctx, message);
    }
    goto XMPPIPE_STDOUT;
  }

  child = xmpp_stanza_get_child_by_name(stanza, "subject");
  if (child != NULL) {
    message = xmpp_stanza_get_text(child);
    if (message != NULL)
      emessage = xmppipe_fmt_encode(message);
    symbol = "S";
    xmpp_free(state->ctx, message);
  }

XMPPIPE_STDOUT:
  etype = xmppipe_fmt_encode(type);
  efrom = xmppipe_fmt_encode(from);
  eto = xmppipe_fmt_encode(to);

  (void)printf("%s:%s:%s:%s:%s\n", symbol, etype, efrom, eto,
               emessage == NULL ? "" : emessage);

  state->interval = 0;

  free(etype);
  free(efrom);
  free(eto);
  free(emessage);

  return 1;
}
