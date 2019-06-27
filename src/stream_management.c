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

int handle_sm_enabled(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
                      void *const userdata) {
  xmppipe_state_t *state = userdata;
  state->sm_enabled = 1;
  return 0;
}

int handle_sm_request(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
                      void *const userdata) {
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

int handle_sm_ack(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
                  void *const userdata) {
  xmppipe_state_t *state = userdata;
  const char *h = NULL;
  u_int32_t ack = 0;
  const char *errstr = NULL;

  h = xmpp_stanza_get_attribute(stanza, "h");

  if (h == NULL)
    return 1;

  ack = (u_int32_t)strtonum(h, 0, UINT_MAX - 1, &errstr);
  if (errstr)
    goto XMPPIPE_STREAMERR;

  if (state->verbose)
    (void)fprintf(stderr, "SM: request=%u ack=%u last=%u\n", state->sm_request,
                  ack, state->sm_ack_sent);

  state->sm_request_unack = 0;

  /* Number of stanzas received by server exceeds the number sent by
   * the client.
   */
  if (ack > state->sm_request)
    goto XMPPIPE_STREAMERR;

  /* Server count not incremented since last request (stanzas may have
   * been dropped).
   *
   * Could resend dropped stanzas.
   *
   */
  if (ack == state->sm_ack_sent)
    goto XMPPIPE_STREAMERR;

  state->sm_ack_sent = ack;
  return 1;

XMPPIPE_STREAMERR:
  xmppipe_stream_close(state);
  errx(EXIT_FAILURE, "ack sequence mismatch: request=%u, ack=%u\n",
       state->sm_request, state->sm_ack_sent);
}

void xmppipe_stream_close(xmppipe_state_t *state) {
  if (state->sm_enabled)
    xmpp_send_raw_string(state->conn, "</stream:stream>");
}
