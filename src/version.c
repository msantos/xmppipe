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

int handle_version(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
                   void *const userdata) {
  xmpp_stanza_t *reply;
  xmpp_stanza_t *query;
  xmpp_stanza_t *name;
  xmpp_stanza_t *version;
  xmpp_stanza_t *text;
  xmpp_stanza_t *child;

  const char *ns;
  const char *id;

  xmppipe_state_t *state = userdata;
  xmpp_ctx_t *ctx = state->ctx;

  reply = xmppipe_stanza_reply(stanza);
  xmppipe_stanza_set_name(reply, "iq");
  xmppipe_stanza_set_type(reply, "result");

  id = xmpp_stanza_get_attribute(stanza, "id");
  if (id == NULL) {
    (void)xmpp_stanza_release(reply);
    return 1;
  }

  xmppipe_stanza_set_id(reply, id);

  query = xmppipe_stanza_new(ctx);
  xmppipe_stanza_set_name(query, "query");

  child = xmpp_stanza_get_children(stanza);
  if (child == NULL) {
    (void)xmpp_stanza_release(query);
    (void)xmpp_stanza_release(reply);
    return 1;
  }

  ns = xmpp_stanza_get_ns(child);
  if (ns)
    xmppipe_stanza_set_ns(query, ns);

  name = xmppipe_stanza_new(ctx);
  xmppipe_stanza_set_name(name, "name");
  xmppipe_stanza_add_child(query, name);
  (void)xmpp_stanza_release(name);

  text = xmppipe_stanza_new(ctx);
  xmppipe_stanza_set_text(text, "xmppipe");
  xmppipe_stanza_add_child(name, text);
  (void)xmpp_stanza_release(text);

  version = xmppipe_stanza_new(ctx);
  xmppipe_stanza_set_name(version, "version");

  text = xmppipe_stanza_new(ctx);
  xmppipe_stanza_set_text(text, XMPPIPE_VERSION);
  xmppipe_stanza_add_child(version, text);
  (void)xmpp_stanza_release(text);

  xmppipe_stanza_add_child(query, version);
  (void)xmpp_stanza_release(version);

  xmppipe_stanza_add_child(reply, query);
  (void)xmpp_stanza_release(query);

  xmppipe_send(state, reply);
  (void)xmpp_stanza_release(reply);

  return 1;
}
