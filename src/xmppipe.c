/* Copyright (c) 2015, Michael Santos <michael.santos@gmail.com>
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

#include <resolv.h>
#include <sys/select.h>
#include <sys/types.h>

extern char *__progname;

static void usage(xmppipe_state_t *xp);

void handle_connection(xmpp_conn_t * const, const xmpp_conn_event_t, const int,
        xmpp_stream_error_t * const, void * const userdata);
int handle_disco_items(xmpp_conn_t * const, xmpp_stanza_t * const,
        void * const);
int handle_disco_info(xmpp_conn_t * const, xmpp_stanza_t * const,
        void * const);
int handle_version(xmpp_conn_t * const, xmpp_stanza_t * const, void * const);
int handle_message(xmpp_conn_t * const, xmpp_stanza_t * const, void * const);
int handle_presence(xmpp_conn_t * const, xmpp_stanza_t * const, void * const);
int handle_presence_error(xmpp_conn_t * const, xmpp_stanza_t * const,
        void * const);
int handle_ping_reply(xmpp_conn_t * const, xmpp_stanza_t * const, void * const);
int handle_sm_request(xmpp_conn_t * const, xmpp_stanza_t * const, void * const);
int handle_sm_enabled(xmpp_conn_t * const, xmpp_stanza_t * const, void * const);
int handle_sm_ack(xmpp_conn_t * const, xmpp_stanza_t * const, void * const);
int handle_null(xmpp_conn_t * const, xmpp_stanza_t * const, void * const);

int xmppipe_connect_init(xmppipe_state_t *);
int xmppipe_stream_init(xmppipe_state_t *);
int xmppipe_muc_init(xmppipe_state_t *);
int xmppipe_presence_init(xmppipe_state_t *);
void event_loop(xmppipe_state_t *);
int handle_stdin(xmppipe_state_t *, int, char *, size_t);
void xmppipe_stream_close(xmppipe_state_t *);

void xmppipe_muc_join(xmppipe_state_t *);
void xmppipe_muc_unlock(xmppipe_state_t *);
void xmppipe_muc_subject(xmppipe_state_t *, char *);
void xmppipe_send_message(xmppipe_state_t *, char *, char *, char *, size_t);
void xmppipe_send(xmppipe_state_t *, xmpp_stanza_t *const);
void xmppipe_ping(xmppipe_state_t *);

    int
main(int argc, char **argv)
{
    xmppipe_state_t *state = NULL;
    xmpp_log_t *log = NULL;
    char *jid = NULL;
    char *pass = NULL;
    char *addr = NULL;
    u_int16_t port = 0;

    int ch = 0;

    state = xmppipe_calloc(1, sizeof(xmppipe_state_t));

    state->status = XMPPIPE_S_CONNECTING;
    state->bufsz = 2049;
    state->poll = 10;
    state->keepalive = 60 * 1000;
    state->keepalive_limit = 3;
    state->sm_request_interval = 1;
    state->sm_fc = 15;
    state->sm_unacked = 5;

    jid = xmppipe_getenv("XMPPIPE_USERNAME");
    pass = xmppipe_getenv("XMPPIPE_PASSWORD");

    while ( (ch = getopt(argc, argv, "a:b:c:dDehI:k:K:o:P:p:r:sS:u:U:vx")) != -1) {
        switch (ch) {
            case 'u':
                /* username/jid */
                jid = xmppipe_strdup(optarg);
                break;
            case 'p':
                /* password */
                pass = xmppipe_strdup(optarg);
                break;
            case 'o':
                /* output/muc */
                state->room = xmppipe_strdup(optarg);
                break;
            case 'a': {
                    /* address:port */
                    char *p = NULL;
                    addr = xmppipe_strdup(optarg);
                    p = strchr(addr, ':');
                    if (p) {
                        *p++ = '\0';
                        port = (u_int16_t)atoi(p);
                    }
                }
                break;
            case 'r':
                state->resource = xmppipe_strdup(optarg);
                break;
            case 'S':
                state->subject = xmppipe_strdup(optarg);
                break;
            case 'v':
                state->verbose++;
                break;
            case 'x':
                state->encode = 1;
                break;

            case 'b':
                /* read buffer size */
                state->bufsz = (size_t)atoi(optarg);
                break;
            case 'c':
                /* XEP-0198: stream management flow control */
                state->sm_fc = (u_int32_t)atoi(optarg);
                break;
            case 'I':
                /* XEP-0198: stream management request interval */
                state->sm_request_interval = (u_int32_t)atoi(optarg);
                break;
            case 'k':
                /* XEP-0199: XMPP ping keepalives */
                state->keepalive = (u_int32_t)atoi(optarg) * 1000;
                break;
            case 'K':
                /* XEP-0199: number of keepalive without a reply */
                state->keepalive_limit = (u_int32_t)atoi(optarg);
                break;
            case 'P':
                /* poll delay */
                state->poll = (u_int32_t)atoi(optarg);
                break;
            case 'U':
                /* XEP-0198: stream management unacked requests */
                state->sm_unacked = (u_int32_t)atoi(optarg);
                break;

            case 'd':
                state->opt |= XMPPIPE_OPT_DISCARD;
                break;
            case 'D':
                state->opt |= XMPPIPE_OPT_DISCARD;
                state->opt |= XMPPIPE_OPT_DISCARD_TO_STDOUT;
                break;
            case 'e':
                state->opt |= XMPPIPE_OPT_EOF;
                break;
            case 's':
                state->opt |= XMPPIPE_OPT_SIGPIPE;
                break;

            case 'h':
            default:
                usage(state);
        }
    }

    if (!jid)
        usage(state);

    if (state->bufsz < 3 || state->bufsz >= 0xffff
            || (state->encode && BASE64_LENGTH(state->bufsz) + 1 > 0xffff))
        usage(state);

    if (state->keepalive_limit < 1)
        usage(state);

    state->server = xmppipe_servername(jid);

    if (!state->room)
        state->room = xmppipe_roomname("stdout");

    if (!state->resource)
        state->resource = xmppipe_strdup("xmppipe");

    if (strchr(state->room, '@')) {
        state->out = xmppipe_strdup(state->room);
        state->mucjid = xmppipe_mucjid(state->out, state->resource);
    }

    if (xmppipe_fmt_init() < 0)
        errx(EXIT_FAILURE, "xmppipe_fmt_init");

    xmpp_initialize();

    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);

    state->ctx = xmpp_ctx_new(NULL, (state->verbose > 1 ? log : NULL));
    if (!state->ctx)
        errx(EXIT_FAILURE, "could not allocate context");

    state->conn = xmpp_conn_new(state->ctx);
    if (!state->conn)
        errx(EXIT_FAILURE, "could not allocate connection");

    xmpp_conn_set_jid(state->conn, jid);
    xmpp_conn_set_pass(state->conn, pass);

    if (xmpp_connect_client(state->conn, addr, port, handle_connection, state) < 0)
        errx(EXIT_FAILURE, "connection failed");

    if (xmppipe_connect_init(state) < 0)
        errx(EXIT_FAILURE, "XMPP handshake failed");

    if (xmppipe_stream_init(state) < 0)
        errx(EXIT_FAILURE, "enabling stream management failed");

    if (xmppipe_muc_init(state) < 0)
        errx(EXIT_FAILURE, "failed to join MUC");

    if (xmppipe_presence_init(state) < 0)
        errx(EXIT_FAILURE, "publishing presence failed");

    if (state->subject)
        xmppipe_muc_subject(state, state->subject);

    event_loop(state);

    xmppipe_stream_close(state);
    (void)xmpp_conn_release(state->conn);
    xmpp_ctx_free(state->ctx);
    xmpp_shutdown();

    return 0;
}

    int
xmppipe_connect_init(xmppipe_state_t *state)
{
    for ( ; ; ) {
        xmpp_run_once(state->ctx, state->poll);
        switch (state->status) {
            case XMPPIPE_S_CONNECTED:
                return 0;
            case XMPPIPE_S_CONNECTING:
                break;
            default:
                return -1;
        }
    }
}

    int
xmppipe_stream_init(xmppipe_state_t *state)
{
    xmpp_stanza_t *enable = NULL;

    if (state->sm_request_interval == 0)
        return 0;

    /* <enable xmlns='urn:xmpp:sm:3'/> */
    enable = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(enable, "enable");
    xmppipe_stanza_set_ns(enable, "urn:xmpp:sm:3");
    xmpp_send(state->conn, enable);
    (void)xmpp_stanza_release(enable);

    xmpp_handler_add(state->conn, handle_sm_enabled,
            "urn:xmpp:sm:3", "enabled", NULL, state);
    xmpp_handler_add(state->conn, handle_sm_request,
            "urn:xmpp:sm:3", "r", NULL, state);
    xmpp_handler_add(state->conn, handle_sm_ack,
            "urn:xmpp:sm:3", "a", NULL, state);

    /* XXX multiple handlers can be called for each event
     * XXX
     * XXX * is the order handlers are called determinisitc?
     * XXX * the NULL handler needs to installed as soon as stream management is enabled
     * XXX * a handler has to exist for unsupported events
     */
    xmpp_handler_add(state->conn, handle_null, NULL, NULL, NULL, state);

    return 0;
}

    int
xmppipe_muc_init(xmppipe_state_t *state)
{
    xmpp_stanza_t *presence = NULL;
    xmpp_stanza_t *iq = NULL;
    xmpp_stanza_t *query = NULL;

    xmpp_handler_add(state->conn, handle_presence_error,
            "http://jabber.org/protocol/muc", "presence", "error", state);
    xmpp_handler_add(state->conn, handle_presence,
            "http://jabber.org/protocol/muc#user", "presence", NULL, state);
    xmpp_handler_add(state->conn, handle_version,
            "jabber:iq:version", "iq", NULL, state);
    xmpp_handler_add(state->conn, handle_message, NULL, "message", NULL, state);
    xmpp_id_handler_add(state->conn, handle_ping_reply, "c2s1", state);

    /* Discover the MUC service */
    if (!state->out) {
        xmpp_handler_add(state->conn, handle_disco_items,
                "http://jabber.org/protocol/disco#items", "iq", "result",
                state);
        xmpp_handler_add(state->conn, handle_disco_info,
                "http://jabber.org/protocol/disco#info", "iq", "result",
                state);

        iq = xmppipe_stanza_new(state->ctx);
        xmppipe_stanza_set_name(iq, "iq");
        xmppipe_stanza_set_type(iq, "get");
        xmppipe_stanza_set_attribute(iq, "to", state->server);

        query = xmppipe_stanza_new(state->ctx);
        xmppipe_stanza_set_name(query, "query");
        xmppipe_stanza_set_ns(query, "http://jabber.org/protocol/disco#items");

        xmppipe_stanza_add_child(iq, query);

        xmppipe_send(state, iq);
        (void)xmpp_stanza_release(iq);

        state->status = XMPPIPE_S_MUC_SERVICE_LOOKUP;
    }

    /* Send initial <presence/> so that we appear online to contacts */
    presence = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(presence, "presence");
    xmppipe_send(state, presence);
    (void)xmpp_stanza_release(presence);

    if (state->out) {
        xmppipe_muc_join(state);
        xmppipe_muc_unlock(state);
        state->status = XMPPIPE_S_MUC_WAITJOIN;
    }

    return 0;
}

    int
xmppipe_presence_init(xmppipe_state_t *state)
{
    for ( ; ; ) {
        xmpp_run_once(state->ctx, state->poll);
        switch (state->status) {
            case XMPPIPE_S_READY:
            case XMPPIPE_S_READY_AVAIL:
            case XMPPIPE_S_READY_EMPTY:
                return 0;
            default:
                break;
        }
    }
}

    void
event_loop(xmppipe_state_t *state)
{
    int fd = STDIN_FILENO;
    int eof = 0;
    char *buf = NULL;

    if (xmppipe_set_nonblock(fd) < 0)
        return;

    buf = xmppipe_calloc(state->bufsz, 1);

    for ( ; ; ) {
        if (state->status == XMPPIPE_S_DISCONNECTED)
            goto XMPPIPE_EXIT;

        if (state->sm_enabled &&
                ( (state->sm_request_unack > state->sm_unacked)
                 || (state->sm_request - state->sm_ack_sent > state->sm_fc))) {
            if (state->verbose)
                (void)fprintf(stderr, "WAIT: request=%u ack_sent=%u unack=%u\n",
                        state->sm_request, state->sm_ack_sent,
                        state->sm_request_unack);
            goto XMPPIPE_POLL;
        }

        if (eof) {
            if (state->opt & XMPPIPE_OPT_EOF)
                goto XMPPIPE_POLL;

            if (state->sm_enabled && (state->sm_ack_sent < state->sm_request)) {
                if (state->verbose)
                    (void)fprintf(stderr, "POLLING: request: %d ack: %d\n",
                            state->sm_request, state->sm_ack_sent);
                goto XMPPIPE_POLL;
            }
            else
                goto XMPPIPE_EXIT;
        }

        switch (handle_stdin(state, fd, buf, state->bufsz-1)) {
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

        if ((state->opt & XMPPIPE_OPT_SIGPIPE)
                && state->status == XMPPIPE_S_READY_EMPTY)
            goto XMPPIPE_EXIT;

        (void)fflush(stdout);
    }

XMPPIPE_EXIT:
    free(buf);
    return;
}

    int
handle_stdin(xmppipe_state_t *state, int fd, char *buf, size_t len)
{
    int nfds = 1;
    fd_set rfds;
    struct timeval tv = {0};
    ssize_t n = 0;
    int rv = 0;

    tv.tv_sec = 0;
    tv.tv_usec = state->poll * 1000;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    rv = select(nfds+1, &rfds, NULL, NULL, &tv);

    if (rv < 0) {
        warn("select");
        return -1;
    }

    if (FD_ISSET(fd, &rfds)) {
        n = read(fd, buf, len);

        if (n < 0)
            return -1;

        if (n == 0)
            return 0;

        if (state->verbose > 2)
            (void)fprintf(stderr, "STDIN:%s\n", buf);

        /* read and discard the data */
        if ((state->opt & XMPPIPE_OPT_DISCARD) && state->occupants == 0) {
            if (state->opt & XMPPIPE_OPT_DISCARD_TO_STDOUT) {
                char *enc = NULL;
                enc = xmppipe_fmt(buf);
                (void)printf("!:%s\n", enc);
                free(enc);
            }
            return 2;
        }

        xmppipe_send_message(state, state->out, "groupchat", buf, n);
        state->interval = 0;
        return 3;
    }

    return 1;
}

    void
handle_connection(xmpp_conn_t * const conn, const xmpp_conn_event_t status,
        const int error, xmpp_stream_error_t * const stream_error,
        void * const userdata)
{
    xmppipe_state_t *state = userdata;

    switch (status) {
        case XMPP_CONN_CONNECT:
            if (state->verbose)
                fprintf(stderr, "DEBUG: connected\n");
            state->status = XMPPIPE_S_CONNECTED;
            break;

        default:
            state->status = XMPPIPE_S_DISCONNECTED;
            if (state->verbose)
                fprintf(stderr, "DEBUG: disconnected\n");
            errx(EXIT_FAILURE, "handle_connection: disconnected");
    }
}

    int
handle_null(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmppipe_state_t *state = userdata;
    char *name = NULL;

    name = xmpp_stanza_get_name(stanza);
    if (!name)
        return 1;

    if (XMPPIPE_STREQ(name, "iq")
            || XMPPIPE_STREQ(name, "message")
            || XMPPIPE_STREQ(name, "presence"))
        state->sm_ack_recv++;

    return 1;
}

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

    int
handle_sm_ack(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmppipe_state_t *state = userdata;
    char *h = NULL;
    u_int32_t ack = 0;

    h = xmpp_stanza_get_attribute(stanza, "h");

    if (!h)
        return 1;

    ack = (u_int32_t)atoi(h); /* XXX */

    if (state->verbose)
        (void)fprintf(stderr, "SM: request=%u ack=%u last=%u\n",
                state->sm_request, ack, state->sm_ack_sent);

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

    int
handle_disco_items(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmpp_stanza_t *query, *item;
    xmppipe_state_t *state = userdata;
    xmpp_ctx_t *ctx = state->ctx;

    query = xmpp_stanza_get_child_by_name(stanza, "query");

    if (!query)
        return 1;

    for (item = xmpp_stanza_get_children(query); item != NULL;
            item = xmpp_stanza_get_next(item)) {
        xmpp_stanza_t *iq, *reply;
        char *jid = NULL;
        char *name = NULL;

        name = xmpp_stanza_get_name(item);
        if (!name)
            continue;

        if (XMPPIPE_STRNEQ(name, "item"))
            continue;

        jid = xmpp_stanza_get_attribute(item, "jid");
        if (!jid)
            continue;

        iq = xmppipe_stanza_new(ctx);
        xmppipe_stanza_set_name(iq, "iq");
        xmppipe_stanza_set_type(iq, "get");
        xmppipe_stanza_set_attribute(iq, "to", jid);

        reply = xmppipe_stanza_new(ctx);
        xmppipe_stanza_set_name(reply, "query");
        xmppipe_stanza_set_ns(reply, "http://jabber.org/protocol/disco#info");

        xmppipe_stanza_add_child(iq, reply);

        xmppipe_send(state, iq);
        (void)xmpp_stanza_release(iq);
    }

    return 0;
}

    int
handle_disco_info(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmpp_stanza_t *query, *child;
    char *from = NULL;
    xmppipe_state_t *state = userdata;

    from = xmpp_stanza_get_attribute(stanza, "from");

    if (!from)
        return 1;

    query = xmpp_stanza_get_child_by_name(stanza, "query");

    if (!query)
        return 1;

    for (child = xmpp_stanza_get_children(query); child != NULL;
            child = xmpp_stanza_get_next(child)) {
        char *feature = NULL;
        char *var = NULL;

        feature = xmpp_stanza_get_name(child);
        if (!feature)
            continue;

        if (XMPPIPE_STRNEQ(feature, "feature"))
            continue;

        var = xmpp_stanza_get_attribute(child, "var");
        if (!var)
            continue;

        if (XMPPIPE_STRNEQ(var, "http://jabber.org/protocol/muc"))
            continue;

        state->mucservice = xmppipe_strdup(from);
        state->out = xmppipe_conference(state->room, state->mucservice);
        state->mucjid = xmppipe_mucjid(state->out, state->resource);

        xmppipe_muc_join(state);
        xmppipe_muc_unlock(state);

        return 0;
    }

    return 1;
}

    int
handle_version(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmpp_stanza_t *reply = NULL;
    xmpp_stanza_t *query = NULL;
    xmpp_stanza_t *name = NULL;
    xmpp_stanza_t *version = NULL;
    xmpp_stanza_t *text = NULL;
    xmpp_stanza_t *child = NULL;

    char *ns = NULL;
    char *id = NULL;
    char *from = NULL;

    xmppipe_state_t *state = userdata;
    xmpp_ctx_t *ctx = state->ctx;

    reply = xmppipe_stanza_new(ctx);
    xmppipe_stanza_set_name(reply, "iq");
    xmppipe_stanza_set_type(reply, "result");

    id = xmpp_stanza_get_attribute(stanza, "from");
    if (!id)
        return 1;

    xmppipe_stanza_set_id(reply, id);

    from = xmpp_stanza_get_attribute(stanza, "from");
    if (!from)
        return 1;

    xmppipe_stanza_set_attribute(reply, "to",  from);

    query = xmppipe_stanza_new(ctx);
    xmppipe_stanza_set_name(query, "query");

    child = xmpp_stanza_get_children(stanza);
    if (!child) {
        (void)xmpp_stanza_release(query);
        return 1;
    }

    ns = xmpp_stanza_get_ns(child);
    if (ns)
        xmppipe_stanza_set_ns(query, ns);

    name = xmppipe_stanza_new(ctx);
    xmppipe_stanza_set_name(name, "name");
    xmppipe_stanza_add_child(query, name);

    text = xmppipe_stanza_new(ctx);
    xmppipe_stanza_set_text(text, "xmppipe");
    xmppipe_stanza_add_child(name, text);

    version = xmppipe_stanza_new(ctx);
    xmppipe_stanza_set_name(version, "version");
    xmppipe_stanza_add_child(query, version);

    text = xmppipe_stanza_new(ctx);
    xmppipe_stanza_set_text(text, XMPPIPE_VERSION);
    xmppipe_stanza_add_child(version, text);

    xmppipe_stanza_add_child(reply, query);

    xmppipe_send(state, reply);
    (void)xmpp_stanza_release(reply);

    return 1;
}

    int
handle_presence(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmppipe_state_t *state = userdata;
    xmpp_stanza_t *x = NULL;
    xmpp_stanza_t *item = NULL;

    char *from = NULL;
    char *to = NULL;
    char *type = NULL;
    char *code = NULL;

    char *efrom = NULL;
    char *eto = NULL;
    char *etype = NULL;

    int me = 0;

    from = xmpp_stanza_get_attribute(stanza, "from");
    to = xmpp_stanza_get_attribute(stanza, "to");

    if (!from || !to)
        return 1;

    x = xmpp_stanza_get_child_by_name(stanza, "x");

    if (x) {
        for (item = xmpp_stanza_get_children(x); item != NULL;
                item = xmpp_stanza_get_next(item)) {
            char *name = xmpp_stanza_get_name(item);

            if (name && XMPPIPE_STREQ(name, "status")) {
                code = xmpp_stanza_get_attribute(item, "code");
                if (code && XMPPIPE_STREQ(code, "110")) {
                    /* Check for nick conflict */
                    if (XMPPIPE_STRNEQ(from, state->mucjid)) {
                        free(state->mucjid);
                        state->mucjid= xmppipe_strdup(from);
                    }
                    state->status = XMPPIPE_S_READY;
                    me = 1;
                    break;
                }
                /* code ignored */
            }
        }
    }

    type = xmpp_stanza_get_attribute(stanza, "type");

    if (!type)
        type = "available";

    if (!me && XMPPIPE_STREQ(type, "available")) {
        state->occupants++;
    }
    else if (XMPPIPE_STREQ(type, "unavailable") && (state->occupants > 0)) {
        state->occupants--;
    }

    if (state->status == XMPPIPE_S_READY && state->occupants > 0)
        state->status = XMPPIPE_S_READY_AVAIL;

    if (state->status == XMPPIPE_S_READY_AVAIL && state->occupants == 0)
        state->status = XMPPIPE_S_READY_EMPTY;

    etype = xmppipe_fmt(type);
    efrom = xmppipe_fmt(from);
    eto = xmppipe_fmt(to);

    (void)printf("p:%s:%s:%s\n", etype, efrom, eto);
    state->interval = 0;

    free(etype);
    free(efrom);
    free(eto);

    return 1;
}

    int
handle_presence_error(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmppipe_state_t *state = userdata;
    xmpp_stanza_t *error = NULL;
    xmpp_stanza_t *child = NULL;

    char *from = NULL;
    char *to = NULL;
    char *code = NULL;
    char *text = NULL;

    from = xmpp_stanza_get_attribute(stanza, "from");
    to = xmpp_stanza_get_attribute(stanza, "to");

    if (!from || !to)
        return 1;

    /* Check error is to our JID (user@example.org/binding) */
    if (XMPPIPE_STRNEQ(to, xmpp_conn_get_bound_jid(conn)))
        return 1;

    /* Check error is from our resource in the MUC (room@example.org/nick) */
    if (XMPPIPE_STRNEQ(from, state->mucjid))
        return 1;

    error = xmpp_stanza_get_child_by_name(stanza, "error");
    if (!error)
        return 1;

    code = xmpp_stanza_get_attribute(error, "code");
    child = xmpp_stanza_get_child_by_name(error, "text");
    if (child)
        text = xmpp_stanza_get_text(child);

    errx(EXIT_FAILURE, "%s: %s", code ? code : "no error code specified",
            text ? text : "no description");
}


    int
handle_message(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmpp_stanza_t *child = NULL;
    xmppipe_state_t *state = userdata;

    char *message = NULL;
    char *type = NULL;
    char *from = NULL;

    char *etype = NULL;
    char *efrom = NULL;
    char *emessage = NULL;

    if (xmpp_stanza_get_child_by_name(stanza, "delay"))
        return 1;

    from = xmpp_stanza_get_attribute(stanza, "from");
    if (!from)
        return 1;

    type = xmpp_stanza_get_type(stanza);
    if (!type)
        return 1;

    /* Check if the message is from us */
    if (XMPPIPE_STREQ(type, "groupchat") && XMPPIPE_STREQ(from, state->mucjid))
        return 1;

    if (!xmpp_stanza_get_child_by_name(stanza, "body"))
        return 1;

    child = xmpp_stanza_get_child_by_name(stanza, "body");
    if (!child)
        return 1;

    message = xmpp_stanza_get_text(child);
    if (!message)
        return 1;

    if (state->encode) {
        /* Does not need to be NULL terminated, buf is passed with length */
        size_t len = strlen(message) * 3 / 4;
        char *buf = xmppipe_calloc(len, 1);
        size_t n = b64_pton(message, (u_char *)buf, len);
        if (n < 0)
            errx(EXIT_FAILURE, "invalid base64 message");
        emessage = xmppipe_nfmt(buf,n);
        free(buf);
    }
    else {
        emessage = xmppipe_fmt(message);
    }

    etype = xmppipe_fmt(type);
    efrom = xmppipe_fmt(from);

    (void)printf("m:%s:%s:%s\n", etype, efrom, emessage);
    state->interval = 0;

    free(message);
    free(etype);
    free(efrom);
    free(emessage);

    return 1;
}

    int
handle_ping_reply(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmppipe_state_t *state = userdata;
    state->keepalive_fail = 0;
    return 1;
}

    void
xmppipe_muc_join(xmppipe_state_t *state)
{
    xmpp_stanza_t *presence = NULL;
    xmpp_stanza_t *x = NULL;

    presence = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(presence, "presence");
    xmppipe_stanza_set_attribute(presence, "to", state->mucjid);

    x = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(x, "x");
    xmppipe_stanza_set_ns(x, "http://jabber.org/protocol/muc");

    xmppipe_stanza_add_child(presence, x);

    xmppipe_send(state, presence);
    (void)xmpp_stanza_release(presence);
}

    void
xmppipe_muc_unlock(xmppipe_state_t *state)
{
    xmpp_stanza_t *iq = NULL;
    xmpp_stanza_t *q= NULL;
    xmpp_stanza_t *x = NULL;

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

    xmppipe_send(state, iq);
    (void)xmpp_stanza_release(iq);
}

    void
xmppipe_muc_subject(xmppipe_state_t *state, char *buf)
{
    xmpp_stanza_t *message = NULL;
    xmpp_stanza_t *subject= NULL;
    xmpp_stanza_t *text= NULL;

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

    xmppipe_send(state, message);
    (void)xmpp_stanza_release(message);
}

    void
xmppipe_send_message(xmppipe_state_t *state, char *to, char *type, char *buf,
        size_t len)
{
    xmpp_stanza_t *message = NULL;
    xmpp_stanza_t *body = NULL;
    xmpp_stanza_t *text = NULL;
    char *id = NULL;

    id = xmppipe_id_alloc();

    message = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(message, "message");
    xmppipe_stanza_set_type(message, type);
    xmppipe_stanza_set_attribute(message, "to", to);
    xmppipe_stanza_set_id(message, id);

    body = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(body, "body");

    text = xmppipe_stanza_new(state->ctx);

    if (state->encode) {
        size_t b64len = BASE64_LENGTH(len) + 1; /* Include trailing NULL */
        char *b64 = xmppipe_calloc(b64len, 1);
        if (b64_ntop((u_char *)buf, len, b64, b64len) < 0)
            errx(EXIT_FAILURE, "encode: invalid input: %zu/%zu", len, b64len);
        xmppipe_stanza_set_text(text, b64);
        free(b64);
    }
    else {
        xmppipe_stanza_set_text(text, buf);
    }

    xmppipe_stanza_add_child(body, text);
    xmppipe_stanza_add_child(message, body);

    xmppipe_send(state, message);
    (void)xmpp_stanza_release(message);
    free(id);
}

    void
xmppipe_ping(xmppipe_state_t *state)
{
    xmpp_stanza_t *iq = NULL;
    xmpp_stanza_t *ping = NULL;

    iq = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(iq, "iq");
    xmppipe_stanza_set_type(iq, "get");
    xmppipe_stanza_set_id(iq, "c2s1");
    xmppipe_stanza_set_attribute(iq, "from", xmpp_conn_get_bound_jid(state->conn));

    ping = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(ping, "ping");
    xmppipe_stanza_set_ns(ping, "urn:xmpp:ping");

    xmppipe_stanza_add_child(iq, ping);

    xmppipe_send(state, iq);
    (void)xmpp_stanza_release(iq);

    state->keepalive_fail++;
}

    void
xmppipe_send(xmppipe_state_t *state, xmpp_stanza_t *const stanza)
{
    xmpp_stanza_t *r = NULL;

    state->sm_request++;

    xmpp_send(state->conn, stanza);

    if (!state->sm_enabled)
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

    void
xmppipe_stream_close(xmppipe_state_t *state)
{
    if (state->sm_enabled)
        xmpp_send_raw_string(state->conn, "</stream:stream>");
}

    static void
usage(xmppipe_state_t *state)
{
    (void)fprintf(stderr, "%s %s\n",
            __progname, XMPPIPE_VERSION);
    (void)fprintf(stderr,
            "usage: %s <options>\n"
            "   -u <jid>        username (aka JID)\n"
            "   -p <password>   password\n"
            "   -r <resource>   resource (aka MUC nick)\n"
            "   -o <output>     MUC room to send stdout\n"
            "   -S <subject>    set MUC subject\n"
            "   -a <addr:port>  set XMPP server address (port is optional)\n"

            "   -d              discard stdin when MUC is empty\n"
            "   -D              discard stdin and print to local stdout\n"
            "   -e              ignore stdin EOF\n"
            "   -s              exit when MUC is empty\n"
            "   -x              base64 encode/decode data\n"

            "   -b <size>       size of read buffer\n"
            "   -I <interval>   request stream management status ever interval messages\n"
            "   -k <seconds>    periodically send a keepalive\n"
            "   -K <count>      number of keepalive failures before exiting\n"
            "   -P <ms>         poll delay\n"
            "   -v              verbose\n",
            __progname
            );

    exit (EXIT_FAILURE);
}
