/* Copyright (c) 2015-2023, Michael Santos <michael.santos@gmail.com>
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

int handle_ping_reply(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
                      void *const userdata) {
  xmppipe_state_t *state = userdata;
  state->keepalive_fail = 0;
  return 1;
}

void xmppipe_ping(xmppipe_state_t *state) {
  xmpp_stanza_t *iq = NULL;
  xmpp_stanza_t *ping = NULL;

  iq = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(iq, "iq");
  xmppipe_stanza_set_type(iq, "get");
  xmppipe_stanza_set_id(iq, "c2s1");
  xmppipe_stanza_set_attribute(iq, "from",
                               xmpp_conn_get_bound_jid(state->conn));

  ping = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(ping, "ping");
  xmppipe_stanza_set_ns(ping, "urn:xmpp:ping");

  xmppipe_stanza_add_child(iq, ping);
  (void)xmpp_stanza_release(ping);

  xmppipe_send(state, iq);
  (void)xmpp_stanza_release(iq);

  state->keepalive_fail++;
}

// <iq from='juliet@capulet.lit/balcony' to='capulet.lit' id='s2c1'
// type='result'/>
int handle_pong(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
                void *const userdata) {
  xmppipe_state_t *state = userdata;
  xmpp_stanza_t *iq;
  const char *from;
  const char *id;

  from = xmpp_stanza_get_attribute(stanza, "from");
  if (from == NULL)
    return 1;

  id = xmpp_stanza_get_attribute(stanza, "id");
  if (id == NULL)
    return 1;

  iq = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(iq, "iq");
  xmppipe_stanza_set_type(iq, "result");
  xmppipe_stanza_set_id(iq, id);
  xmppipe_stanza_set_attribute(iq, "from",
                               xmpp_conn_get_bound_jid(state->conn));
  xmppipe_stanza_set_attribute(iq, "to", from);

  xmppipe_send(state, iq);
  (void)xmpp_stanza_release(iq);

  return 1;
}
