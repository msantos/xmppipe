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

    void
xmppipe_send_stanza(xmppipe_state_t *state, char *buf, size_t len)
{
    switch (state->format) {
      case XMPPIPE_FMT_TEXT:
        xmppipe_send_message(state,
            state->out,
            (state->opt & XMPPIPE_OPT_GROUPCHAT) ? "groupchat" : "chat",
            buf, len);
        return;

      case XMPPIPE_FMT_CSV:
        xmppipe_send_stanza_fmt(state, buf, len);
        break;

      default:
        if (state->verbose)
          (void)fprintf(stderr, "unsupported format: %d\n", state->format);

        return;
    }
}

    void
xmppipe_send_stanza_fmt(xmppipe_state_t *state, char *buf, size_t len)
{
    char *to = NULL;
    char *type = NULL;
    char *default_type;

    int i;
    size_t n;
    char *tmp;
    char *start;
    char *end;
    char *body = NULL;
    int valid = 0;

    default_type = (state->opt & XMPPIPE_OPT_GROUPCHAT) ? "groupchat" : "chat";

    tmp = xmppipe_strdup(buf);
    start = tmp;

    /* trailing newline */
    end = strchr(start, '\n');
    if (end != NULL)
      *end = '\0';

    for (i = 0; start != NULL; i++) {
      end = strchr(start, ':');
      if (end != NULL)
        *end++ = '\0';

      n = strlen(start);

      if (state->verbose)
          (void)fprintf(stderr, "message:%d:%s\n", i,
              n == 0 ? "<empty>" : start);

      switch (i) {
        case 0:
          if (n != 1) {
            if (state->verbose)
              (void)fprintf(stderr, "stanza required\n");

            goto XMPPIPE_DONE;
          }

          switch (start[0]) {
            case 'm':
              break;
            case 'p':
              /* unsupported: fall through */
            default:
              if (state->verbose)
                (void)fprintf(stderr, "unsupported stanza: %c\n", start[0]);

              goto XMPPIPE_DONE;
          }
          break;

        case 1:
          type = xmppipe_fmt_decode((n == 0) ? default_type : start);
          if (type == NULL)
            goto XMPPIPE_DONE;
          break;

        case 2:
          to = xmppipe_fmt_decode((n == 0) ? state->out : start);
          if (to == NULL)
            goto XMPPIPE_DONE;

          break;

        case 3:
          break;

        case 4:
          body = xmppipe_fmt_decode(start);
          if (body == NULL)
            goto XMPPIPE_DONE;

          valid = 1;
          break;

        default:
          goto XMPPIPE_DONE;
      }

      start = end;
    }

XMPPIPE_DONE:
    if (valid == 1)
      xmppipe_send_message(state, to, type, body, strlen(body));
    else
      if (state->verbose)
        (void)fprintf(stderr, "invalid input\n");

    free(tmp);
    free(type);
    free(to);
    free(body);
}

    void
xmppipe_send_message(xmppipe_state_t *state, char *to, char *type, char *buf,
        size_t len)
{
    xmpp_stanza_t *message = NULL;
    xmpp_stanza_t *body = NULL;
    xmpp_stanza_t *text = NULL;
    char *id = NULL;

    id = xmpp_uuid_gen(state->ctx);

    if (id == NULL) {
        errx(EXIT_FAILURE, "unable to allocate message id");
    }

    message = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(message, "message");
    xmppipe_stanza_set_type(message, type);
    xmppipe_stanza_set_attribute(message, "to", to);
    xmppipe_stanza_set_id(message, id);

    body = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(body, "body");

    text = xmppipe_stanza_new(state->ctx);

    if (state->encode) {
        size_t len = strlen(buf);
        char *b64 = xmpp_base64_encode(state->ctx, (unsigned char *)buf, len);

        if (b64 == NULL)
            errx(EXIT_FAILURE, "encode: invalid input: %zu", len);

        xmppipe_stanza_set_text(text, b64);
        xmpp_free(state->ctx, b64);
    }
    else {
        xmppipe_stanza_set_text(text, buf);
    }

    xmppipe_stanza_add_child(body, text);
    xmppipe_stanza_add_child(message, body);

    xmppipe_send(state, message);
    (void)xmpp_stanza_release(message);
    xmpp_free(state->ctx, id);
}

    void
xmppipe_send(xmppipe_state_t *state, xmpp_stanza_t *const stanza)
{
    xmpp_stanza_t *r = NULL;

    state->sm_request++;

    xmpp_send(state->conn, stanza);

    if (state->sm_enabled == 0)
        return;

    if (state->sm_request % state->sm_request_interval != 0)
        return;

    r = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(r, "r");
    xmppipe_stanza_set_ns(r, "urn:xmpp:sm:3");
    xmpp_send(state->conn, r);
    state->sm_request_unack++;

    (void)xmpp_stanza_release(r);
}
