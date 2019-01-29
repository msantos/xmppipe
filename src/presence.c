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
handle_presence(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmppipe_state_t *state = userdata;
    xmpp_stanza_t *x = NULL;
    xmpp_stanza_t *item = NULL;

    const char *from = NULL;
    const char *to = NULL;
    const char *type = NULL;
    const char *code = NULL;

    char *efrom = NULL;
    char *eto = NULL;
    char *etype = NULL;

    int me = 0;

    from = xmpp_stanza_get_attribute(stanza, "from");
    to = xmpp_stanza_get_attribute(stanza, "to");

    if (from == NULL || to == NULL)
        return 1;

    x = xmpp_stanza_get_child_by_ns(stanza,
        "http://jabber.org/protocol/muc#user");

    if (x) {
        for (item = xmpp_stanza_get_children(x); item != NULL;
                item = xmpp_stanza_get_next(item)) {
            const char *name = xmpp_stanza_get_name(item);

            if (name && XMPPIPE_STREQ(name, "status")) {
                code = xmpp_stanza_get_attribute(item, "code");
                if (code && XMPPIPE_STREQ(code, "110")) {
                    /* Check for nick conflict */
                    if (XMPPIPE_STRNEQ(from, state->mucjid)) {
                        free(state->mucjid);
                        state->mucjid= xmppipe_strdup(from);
                    }
                    xmppipe_next_state(state, XMPPIPE_S_READY);
                    me = 1;
                    break;
                }
                /* code ignored */
            }
        }
    }

    type = xmpp_stanza_get_attribute(stanza, "type");

    if (type == NULL)
        type = "available";

    if (me != 0 && XMPPIPE_STREQ(type, "available")) {
        state->occupants++;
    }
    else if (XMPPIPE_STREQ(type, "unavailable") && (state->occupants > 0)) {
        state->occupants--;
    }

    if (state->status == XMPPIPE_S_READY && state->occupants > 0)
        xmppipe_next_state(state, XMPPIPE_S_READY_AVAIL);

    if (state->status == XMPPIPE_S_READY_AVAIL && state->occupants == 0)
        xmppipe_next_state(state, XMPPIPE_S_READY_EMPTY);

    etype = xmppipe_fmt_encode(type);
    efrom = xmppipe_fmt_encode(from);
    eto = xmppipe_fmt_encode(to);

    (void)printf("p:%s:%s:%s\n", etype, efrom, eto);

    state->interval = 0;

    free(etype);
    free(efrom);
    free(eto);

    return 1;
}
