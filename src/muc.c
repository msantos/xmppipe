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

void xmppipe_muc_join(xmppipe_state_t *state) {
  xmpp_stanza_t *presence;
  xmpp_stanza_t *x;

  presence = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(presence, "presence");
  xmppipe_stanza_set_attribute(presence, "to", state->mucjid);

  x = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(x, "x");
  xmppipe_stanza_set_ns(x, "http://jabber.org/protocol/muc");

  xmppipe_stanza_add_child(presence, x);
  (void)xmpp_stanza_release(x);

  xmppipe_send(state, presence);
  (void)xmpp_stanza_release(presence);
}

void xmppipe_muc_subject(xmppipe_state_t *state, char *buf) {
  xmpp_stanza_t *message;
  xmpp_stanza_t *subject;
  xmpp_stanza_t *text;

  message = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(message, "message");
  xmppipe_stanza_set_attribute(message, "to", state->out);
  xmppipe_stanza_set_attribute(message, "type", "groupchat");

  subject = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(subject, "subject");

  text = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_text(text, buf);

  xmppipe_stanza_add_child(subject, text);
  xmppipe_stanza_add_child(message, subject);
  (void)xmpp_stanza_release(text);
  (void)xmpp_stanza_release(subject);

  xmppipe_send(state, message);
  (void)xmpp_stanza_release(message);
}

void xmppipe_muc_unlock(xmppipe_state_t *state) {
  xmpp_stanza_t *iq;
  xmpp_stanza_t *q;
  xmpp_stanza_t *x;

  iq = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(iq, "iq");
  xmppipe_stanza_set_attribute(iq, "to", state->out);
  xmppipe_stanza_set_attribute(iq, "id", "create1");
  xmppipe_stanza_set_attribute(iq, "type", "set");

  q = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(q, "query");
  xmppipe_stanza_set_ns(q, "http://jabber.org/protocol/muc#owner");

  x = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(x, "x");
  xmppipe_stanza_set_ns(x, "jabber:x:data");
  xmppipe_stanza_set_attribute(x, "type", "submit");

  xmppipe_stanza_add_child(q, x);
  xmppipe_stanza_add_child(iq, q);
  (void)xmpp_stanza_release(x);
  (void)xmpp_stanza_release(q);

  xmppipe_send(state, iq);
  (void)xmpp_stanza_release(iq);
}
