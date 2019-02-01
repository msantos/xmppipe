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

    int
handle_sm_enabled(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmppipe_state_t *state = userdata;
    state->sm_enabled = 1;
    return 0;
}

    int
handle_sm_request(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmppipe_state_t *state = userdata;

    xmpp_stanza_t *a = NULL;
    char h[11] = {0};

    if (state->sm_request % state->sm_request_interval != 0)
        return 1;

    (void)snprintf(h, sizeof(h), "%u", state->sm_ack_recv);

    /* <a xmlns='urn:xmpp:sm:3' h='1'/> */
    a = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(a, "a");
    xmppipe_stanza_set_ns(a, "urn:xmpp:sm:3");
    xmppipe_stanza_set_attribute(a, "h", h);

    xmpp_send(state->conn, a);
    (void)xmpp_stanza_release(a);

    return 1;
}
