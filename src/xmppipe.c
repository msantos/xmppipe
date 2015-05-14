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

int xmppipe_connect_init(xmppipe_state_t *);
int xmppipe_muc_init(xmppipe_state_t *);
int xmppipe_presence_init(xmppipe_state_t *);
void event_loop(xmppipe_state_t *);
int handle_stdin(xmppipe_state_t *, int, char *, size_t);

void xmppipe_muc_join(xmppipe_state_t *);
void xmppipe_muc_unlock(xmppipe_state_t *);
void xmppipe_muc_subject(xmppipe_state_t *, char *);
void xmppipe_send_message(xmppipe_state_t *, char *, char *, char *);
void xmppipe_ping(xmppipe_state_t *);

    int
main(int argc, char **argv)
{
    xmppipe_state_t *state = NULL;
    xmpp_conn_t *conn = NULL;
    xmpp_log_t *log = NULL;
    char *jid = NULL;
    char *pass = NULL;

    int ch = 0;

    state = xmppipe_calloc(1, sizeof(xmppipe_state_t));

    state->status = XMPPIPE_S_CONNECTING;
    state->bufsz = 4097;
    state->poll = 10;
    state->keepalive = 60 * 1000;

    jid = xmppipe_getenv("XMPPIPE_USERNAME");
    pass = xmppipe_getenv("XMPPIPE_PASSWORD");

    while ( (ch = getopt(argc, argv, "dDehk:m:o:P:p:r:sS:u:v")) != -1) {
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
            case 'r':
                state->resource = xmppipe_strdup(optarg);
                break;
            case 'S':
                state->subject = xmppipe_strdup(optarg);
                break;
            case 'v':
                state->verbose++;
                break;

            case 'k':
                /* keepalives */
                state->keepalive = (u_int32_t)atoi(optarg) * 1000;
                break;
            case 'm':
                /* read buffer size */
                state->bufsz = (size_t)atoi(optarg);
                break;
            case 'P':
                /* poll delay */
                state->poll = (u_int32_t)atoi(optarg);
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

    if (state->bufsz < 3 || state->bufsz >= 0xffff)
        usage(state);

    if (state->keepalive == 0)
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

    if (xmppipe_encode_init() < 0)
        errx(EXIT_FAILURE, "xmppipe_encode_init");

    xmpp_initialize();

    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    state->ctx = xmpp_ctx_new(NULL, (state->verbose > 1 ? log : NULL));

    conn = xmpp_conn_new(state->ctx);
    state->conn = conn;

    xmpp_conn_set_jid(conn, jid);
    xmpp_conn_set_pass(conn, pass);

    xmpp_connect_client(conn, NULL, 0, handle_connection, state);

    if (xmppipe_connect_init(state) < 0)
        goto XMPPIPE_ERR;

    if (xmppipe_muc_init(state) < 0)
        goto XMPPIPE_ERR;

    if (xmppipe_presence_init(state) < 0)
        goto XMPPIPE_ERR;

    if (state->subject)
        xmppipe_muc_subject(state, state->subject);

    event_loop(state);

XMPPIPE_ERR:
    xmpp_conn_release(conn);
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

    /* Discover the MUC service */
    if (!state->out) {
        xmpp_handler_add(state->conn, handle_disco_items,
                "http://jabber.org/protocol/disco#items", "iq", "result",
                state);
        xmpp_handler_add(state->conn, handle_disco_info,
                "http://jabber.org/protocol/disco#info", "iq", "result",
                state);

        iq = xmpp_stanza_new(state->ctx);
        xmpp_stanza_set_name(iq, "iq");
        xmpp_stanza_set_type(iq, "get");
        xmpp_stanza_set_attribute(iq, "to", state->server);

        query = xmpp_stanza_new(state->ctx);
        xmpp_stanza_set_name(query, "query");
        xmpp_stanza_set_ns(query, "http://jabber.org/protocol/disco#items");

        xmpp_stanza_add_child(iq, query);

        xmpp_send(state->conn, iq);
        xmpp_stanza_release(iq);

        state->status = XMPPIPE_S_MUC_SERVICE_LOOKUP;
    }

    /* Send initial <presence/> so that we appear online to contacts */
    presence = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(presence, "presence");
    xmpp_send(state->conn, presence);
    xmpp_stanza_release(presence);

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

    buf = xmppipe_calloc(1, state->bufsz);

    for ( ; ; ) {
        if (state->status == XMPPIPE_S_DISCONNECTED)
            goto XMPPIPE_EXIT;

        if (eof)
            goto XMPPIPE_POLL;

        switch (handle_stdin(state, fd, buf, state->bufsz-1)) {
            case -1:
                goto XMPPIPE_EXIT;
            case 0:
                if (!(state->opt & XMPPIPE_OPT_EOF))
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
        if (state->interval > state->keepalive) {
            xmppipe_ping(state);
            state->interval = 0;
        }

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

        if (state->verbose)
            (void)fprintf(stderr, "STDIN:%s\n", buf);

        /* read and discard the data */
        if ((state->opt & XMPPIPE_OPT_DISCARD) && state->occupants == 0) {
            if (state->opt & XMPPIPE_OPT_DISCARD_TO_STDOUT) {
                char *enc = NULL;
                enc = xmppipe_encode(buf);
                (void)printf("!:%s\n", enc);
                free(enc);
            }
            return 2;
        }

        xmppipe_send_message(state, state->out, "groupchat", buf);
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
    }
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

        if (XMPPIPE_STRNEQ(xmpp_stanza_get_name(item), "item"))
            continue;

        jid = xmpp_stanza_get_attribute(item, "jid");
        if (!jid)
            continue;

        iq = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(iq, "iq");
        xmpp_stanza_set_type(iq, "get");
        xmpp_stanza_set_attribute(iq, "to", jid);

        reply = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(reply, "query");
        xmpp_stanza_set_ns(reply, "http://jabber.org/protocol/disco#info");

        xmpp_stanza_add_child(iq, reply);

        xmpp_send(conn, iq);
        xmpp_stanza_release(iq);
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
        if (XMPPIPE_STRNEQ(xmpp_stanza_get_name(child), "feature"))
            continue;

        if (XMPPIPE_STRNEQ(xmpp_stanza_get_attribute(child, "var"),
                    "http://jabber.org/protocol/muc"))
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
    xmpp_stanza_t *reply, *query, *name, *version, *text;
    char *ns;
    xmppipe_state_t *state = userdata;
    xmpp_ctx_t *ctx = state->ctx;

    reply = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(reply, "iq");
    xmpp_stanza_set_type(reply, "result");
    xmpp_stanza_set_id(reply, xmpp_stanza_get_id(stanza));
    xmpp_stanza_set_attribute(reply, "to",
            xmpp_stanza_get_attribute(stanza, "from"));

    query = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(query, "query");
    ns = xmpp_stanza_get_ns(xmpp_stanza_get_children(stanza));
    if (ns) {
        xmpp_stanza_set_ns(query, ns);
    }

    name = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(name, "name");
    xmpp_stanza_add_child(query, name);

    text = xmpp_stanza_new(ctx);
    xmpp_stanza_set_text(text, "xmppipe");
    xmpp_stanza_add_child(name, text);

    version = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(version, "version");
    xmpp_stanza_add_child(query, version);

    text = xmpp_stanza_new(ctx);
    xmpp_stanza_set_text(text, XMPPIPE_VERSION);
    xmpp_stanza_add_child(version, text);

    xmpp_stanza_add_child(reply, query);

    xmpp_send(conn, reply);
    xmpp_stanza_release(reply);
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

            if (XMPPIPE_STREQ(name, "status")) {
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

    etype = xmppipe_encode(type);
    efrom = xmppipe_encode(from);
    eto = xmppipe_encode(to);

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
    text = xmpp_stanza_get_text(xmpp_stanza_get_child_by_name(error, "text"));

    errx(EXIT_FAILURE, "%s: %s", code ? code : "no error code specified",
            text ? text : "no description");
}


    int
handle_message(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
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
    type = xmpp_stanza_get_type(stanza);

    if (!type)
        return 1;

    /* Check if the message is from us */
    if (XMPPIPE_STREQ(type, "groupchat") && XMPPIPE_STREQ(from, state->mucjid))
        return 1;

    if (!xmpp_stanza_get_child_by_name(stanza, "body"))
        return 1;

    message = xmpp_stanza_get_text(
            xmpp_stanza_get_child_by_name(stanza, "body")
            );

    if (!message)
        return 1;

    etype = xmppipe_encode(type);
    efrom = xmppipe_encode(from);
    emessage = xmppipe_encode(message);

    (void)printf("m:%s:%s:%s\n", etype, efrom, emessage);
    state->interval = 0;

    free(message);
    free(etype);
    free(efrom);
    free(emessage);

    return 1;
}

    void
xmppipe_muc_join(xmppipe_state_t *state)
{
    xmpp_stanza_t *presence = NULL;
    xmpp_stanza_t *x = NULL;

    presence = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(presence, "presence");
    xmpp_stanza_set_attribute(presence, "to", state->mucjid);

    x = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(x, "x");
    xmpp_stanza_set_ns(x, "http://jabber.org/protocol/muc");

    xmpp_stanza_add_child(presence, x);

    xmpp_send(state->conn, presence);
    xmpp_stanza_release(presence);
}

    void
xmppipe_muc_unlock(xmppipe_state_t *state)
{
    xmpp_stanza_t *iq = NULL;
    xmpp_stanza_t *q= NULL;
    xmpp_stanza_t *x = NULL;

    iq = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(iq, "iq");
    xmpp_stanza_set_attribute(iq, "to", state->out);
    xmpp_stanza_set_attribute(iq, "id", "create1");
    xmpp_stanza_set_attribute(iq, "type", "set");

    q = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(q, "query");
    xmpp_stanza_set_ns(q, "http://jabber.org/protocol/muc#owner");

    x = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(x, "x");
    xmpp_stanza_set_ns(x, "jabber:x:data");
    xmpp_stanza_set_attribute(x, "type", "submit");

    xmpp_stanza_add_child(q, x);
    xmpp_stanza_add_child(iq, q);

    xmpp_send(state->conn, iq);
    xmpp_stanza_release(iq);
}

    void
xmppipe_muc_subject(xmppipe_state_t *state, char *buf)
{
    xmpp_stanza_t *message = NULL;
    xmpp_stanza_t *subject= NULL;
    xmpp_stanza_t *text= NULL;

    message = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(message, "message");
    xmpp_stanza_set_attribute(message, "to", state->out);
    xmpp_stanza_set_attribute(message, "type", "groupchat");

    subject = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(subject, "subject");

    text = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_text(text, buf);

    xmpp_stanza_add_child(subject, text);
    xmpp_stanza_add_child(message, subject);

    xmpp_send(state->conn, message);
    xmpp_stanza_release(message);
}

    void
xmppipe_send_message(xmppipe_state_t *state, char *to, char *type, char *buf)
{
    xmpp_stanza_t *message = NULL;
    xmpp_stanza_t *body = NULL;
    xmpp_stanza_t *text = NULL;
    char *id = NULL;

    id = xmppipe_id_alloc();

    message = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(message, "message");
    xmpp_stanza_set_type(message, type);
    xmpp_stanza_set_attribute(message, "to", to);
    xmpp_stanza_set_id(message, id);

    body = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(body, "body");

    text = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_text(text, buf);

    xmpp_stanza_add_child(body, text);
    xmpp_stanza_add_child(message, body);

    xmpp_send(state->conn, message);
    xmpp_stanza_release(message);
    free(id);
}

    void
xmppipe_ping(xmppipe_state_t *state)
{
    xmpp_stanza_t *iq = NULL;
    xmpp_stanza_t *ping = NULL;

    iq = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(iq, "iq");
    xmpp_stanza_set_type(iq, "get");
    xmpp_stanza_set_id(iq, "c2s1"); /* XXX set unique id */
    xmpp_stanza_set_attribute(iq, "from", xmpp_conn_get_bound_jid(state->conn));

    ping = xmpp_stanza_new(state->ctx);
    xmpp_stanza_set_name(ping, "ping");
    xmpp_stanza_set_ns(ping, "urn:xmpp:ping");

    xmpp_stanza_add_child(iq, ping);

    xmpp_send(state->conn, iq);
    xmpp_stanza_release(iq);
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

            "   -d              discard stdin when MUC is empty\n"
            "   -D              discard stdin and print to local stdout\n"
            "   -e              ignore stdin EOF\n"
            "   -s              exit when MUC is empty\n"

            "   -k <ms>         periodically send a keepalive\n"
            "   -m <size>       size of read buffer\n"
            "   -P <ms>         poll delay\n"
            "   -v              verbose\n",
            __progname
            );

    exit (EXIT_FAILURE);
}
