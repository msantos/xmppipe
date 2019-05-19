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
#include "xmppipe.h"

int handle_null(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
                void *const userdata) {
  xmppipe_state_t *state = userdata;
  const char *name = NULL;

  name = xmpp_stanza_get_name(stanza);
  if (name == NULL)
    return 1;

  if (XMPPIPE_STREQ(name, "iq") || XMPPIPE_STREQ(name, "message") ||
      XMPPIPE_STREQ(name, "presence"))
    state->sm_ack_recv++;

  return 1;
}
