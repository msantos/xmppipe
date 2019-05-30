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

#include <netinet/in.h>
#include <resolv.h>
#include <sys/select.h>

static int handle_stdin(xmppipe_state_t *state, int fd, char *buf, size_t len);

void event_loop(xmppipe_state_t *state) {
  int fd = STDIN_FILENO;
  int eof = 0;
  char *buf = NULL;

  if (xmppipe_set_nonblock(fd) < 0)
    return;

  buf = xmppipe_calloc(state->bufsz, 1);

  for (;;) {
    if (state->status == XMPPIPE_S_DISCONNECTED)
      goto XMPPIPE_EXIT;

    if (state->sm_enabled) {
      if (state->sm_ack_sent > state->sm_request)
        errx(EXIT_FAILURE, "h too large: sent=%u, server responded=%u",
             state->sm_request, state->sm_ack_sent);

      if ((state->sm_request_unack > state->sm_unacked) ||
          (state->sm_request - state->sm_ack_sent > state->sm_fc)) {
        if (state->verbose)
          (void)fprintf(stderr, "WAIT: request=%u ack_sent=%u unack=%u\n",
                        state->sm_request, state->sm_ack_sent,
                        state->sm_request_unack);
        goto XMPPIPE_POLL;
      }
    }

    if (eof) {
      if (state->opt & XMPPIPE_OPT_EOF)
        goto XMPPIPE_POLL;

      if (state->sm_enabled && (state->sm_ack_sent < state->sm_request)) {
        if (state->verbose)
          (void)fprintf(stderr, "POLLING: request: %d ack: %d\n",
                        state->sm_request, state->sm_ack_sent);
        goto XMPPIPE_POLL;
      } else
        goto XMPPIPE_EXIT;
    }

    switch (handle_stdin(state, fd, buf, state->bufsz - 1)) {
    case -1:
      goto XMPPIPE_EXIT;
    case 0:
      if (!(state->opt & XMPPIPE_OPT_EOF) && !state->sm_enabled)
        goto XMPPIPE_EXIT;

      eof = 1;
      break;
    case 1:
      break;
    default:
      (void)memset(buf, '\0', state->bufsz);
      break;
    }

    state->interval += state->poll;

  XMPPIPE_POLL:
    if (state->keepalive > 0 && state->interval > state->keepalive) {
      xmppipe_ping(state);
      state->interval = 0;
    }

    if (state->keepalive_fail > state->keepalive_limit)
      errx(EXIT_FAILURE, "no response to keepalives");

    xmpp_run_once(state->ctx, state->poll);

    state->interval += state->poll;

    if ((state->opt & XMPPIPE_OPT_SIGPIPE) &&
        state->status == XMPPIPE_S_READY_EMPTY)
      goto XMPPIPE_EXIT;
  }

XMPPIPE_EXIT:
  free(buf);
  return;
}

static int handle_stdin(xmppipe_state_t *state, int fd, char *buf, size_t len) {
  fd_set rfds;
  struct timeval tv = {0};
  ssize_t n = 0;
  int rv = 0;

  tv.tv_sec = 0;
  tv.tv_usec = state->poll * 1000;

  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);

  rv = select(fd + 1, &rfds, NULL, NULL, &tv);

  if (rv < 0) {
    warn("select");
    return -1;
  }

  if (FD_ISSET(fd, &rfds)) {
    n = read(fd, buf, len);

    if (n <= 0)
      return n;

    if (state->verbose > 2)
      (void)fprintf(stderr, "STDIN:%s\n", buf);

    /* read and discard the data */
    if ((state->opt & XMPPIPE_OPT_DISCARD) && state->occupants == 0) {
      if (state->opt & XMPPIPE_OPT_DISCARD_TO_STDOUT) {
        char *enc = NULL;
        enc = xmppipe_fmt_encode(buf);
        (void)printf("!:%s\n", enc);
        free(enc);
      }
      return 2;
    }

    xmppipe_send_stanza(state, buf, n);
    state->interval = 0;
    return 3;
  }

  return 1;
}
