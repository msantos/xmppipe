/* Copyright (c) 2019, Michael Santos <michael.santos@gmail.com>
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

int handle_iq(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
              void *const userdata) {
  xmppipe_state_t *state = userdata;
  xmpp_stanza_t *slot;
  xmpp_stanza_t *item;

  const char *from = NULL;
  const char *to = NULL;
  const char *get = NULL;
  const char *put = NULL;

  char *efrom;
  char *eto;
  char *eget;
  char *eput;

  from = xmpp_stanza_get_attribute(stanza, "from");

  if (from == NULL)
    return 1;

  slot = xmpp_stanza_get_child_by_ns(stanza, "urn:xmpp:http:upload:0");

  /* only handles XEP 0363 */
  if (slot == NULL)
    return 1;

  to = xmpp_stanza_get_attribute(stanza, "to");

  if (to == NULL)
    return 1;

  if (XMPPIPE_STRNEQ(from, state->upload)) {
    if (state->verbose)
      (void)fprintf(stderr,
                    "error: received XEP363 slot from: %s (using: %s)\n", from,
                    state->upload);
    return 1;
  }

  for (item = xmpp_stanza_get_children(slot); item != NULL;
       item = xmpp_stanza_get_next(item)) {
    const char *name = xmpp_stanza_get_name(item);

    if (name == NULL)
      continue;

    if (XMPPIPE_STREQ(name, "get"))
      get = xmpp_stanza_get_attribute(item, "url");

    if (XMPPIPE_STREQ(name, "put"))
      put = xmpp_stanza_get_attribute(item, "url");
  }

  if (get == NULL || put == NULL)
    return 1;

  efrom = xmppipe_fmt_encode(from);
  eto = xmppipe_fmt_encode(to);

  eget = xmppipe_fmt_encode(get);
  eput = xmppipe_fmt_encode(put);

  (void)printf("U:%s:%s:%s:%s%%7c%s\n",
               state->opt & XMPPIPE_OPT_GROUPCHAT ? "groupchat" : "chat", efrom,
               eto, eget, eput);

  free(efrom);
  free(eto);

  free(eget);
  free(eput);

  return 1;
}
