/* Copyright (c) 2015-2018, Michael Santos <michael.santos@gmail.com>
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
#include <netinet/in.h>
#include <resolv.h>
#include <getopt.h>

extern char *__progname;

static void usage(xmppipe_state_t *xp);

static long long xmppipe_strtonum(xmppipe_state_t *state, const char *nptr,
        long long minval, long long maxval);
static void xmppipe_next_state(xmppipe_state_t *state, int status);

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
void xmppipe_send_stanza(xmppipe_state_t *, char *, size_t);
void xmppipe_send_message(xmppipe_state_t *, char *, char *, char *, size_t);
void xmppipe_send(xmppipe_state_t *, xmpp_stanza_t *const);
void xmppipe_ping(xmppipe_state_t *);

enum {
    OPT_NO_TLS_VERIFY = 1,
    OPT_CHAT,
};

static const char const *xmppipe_states[] = {
    "XMPPIPE_S_DISCONNECTED",
    "XMPPIPE_S_CONNECTING",
    "XMPPIPE_S_CONNECTED",

    "XMPPIPE_S_MUC_SERVICE_LOOKUP",
    "XMPPIPE_S_MUC_FEATURE_LOOKUP",
    "XMPPIPE_S_MUC_WAITJOIN",
    "XMPPIPE_S_MUC_JOIN",
    "XMPPIPE_S_MUC_UNLOCK",

    "XMPPIPE_S_READY",
    "XMPPIPE_S_READY_AVAIL",
    "XMPPIPE_S_READY_EMPTY"
};

static const struct option long_options[] =
{
    {"address",            required_argument,  NULL, 'a'},
    {"buffer-size",        required_argument,  NULL, 'b'},
    {"flow-control",       required_argument,  NULL, 'c'},
    {"chat",               no_argument,        NULL, OPT_CHAT},
    {"discard",            no_argument,        NULL, 'd'},
    {"discard-to-stdout",  no_argument,        NULL, 'D'},
    {"ignore-eof",         no_argument,        NULL, 'e'},
    {"format",             required_argument,  NULL, 'F'},
    {"interval",           required_argument,  NULL, 'I'},
    {"keepalive",          required_argument,  NULL, 'k'},
    {"keepalive-failures", required_argument,  NULL, 'K'},
    {"output",             required_argument,  NULL, 'o'},
    {"password",           required_argument,  NULL, 'p'},
    {"poll-delay",         required_argument,  NULL, 'P'},
    {"resource",           required_argument,  NULL, 'r'},
    {"exit-when-empty",    no_argument,        NULL, 's'},
    {"subject",            required_argument,  NULL, 'S'},
    {"username",           required_argument,  NULL, 'u'},
    {"unacked-requests",   required_argument,  NULL, 'U'},
    {"verbose",            no_argument,        NULL, 'v'},
    {"base64",             no_argument,        NULL, 'x'},
    {"help",               no_argument,        NULL, 'h'},

    {"no-tls-verify",      no_argument,        NULL, OPT_NO_TLS_VERIFY},

    {NULL,                 0,                  NULL, 0}
};

    int
main(int argc, char **argv)
{
    xmppipe_state_t *state = NULL;
    xmpp_log_t *log = NULL;
    char *jid = NULL;
    char *pass = NULL;
    char *addr = NULL;
    u_int16_t port = 0;
    int flags = 0;

    int ch = 0;

    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0)
        err(EXIT_FAILURE, "setvbuf");

    state = xmppipe_calloc(1, sizeof(xmppipe_state_t));

    xmppipe_next_state(state, XMPPIPE_S_CONNECTING);
    state->bufsz = 2049;
    state->poll = 10;
    state->keepalive = 60 * 1000;
    state->keepalive_limit = 3;
    state->sm_request_interval = 1;
    state->sm_fc = 15;
    state->sm_unacked = 5;
    state->room = xmppipe_roomname("stdout");
    state->resource = xmppipe_strdup(XMPPIPE_RESOURCE);
    state->opt |= XMPPIPE_OPT_GROUPCHAT;

    jid = xmppipe_getenv("XMPPIPE_USERNAME");
    pass = xmppipe_getenv("XMPPIPE_PASSWORD");

    if (xmppipe_sandbox_init(state) < 0)
        err(EXIT_FAILURE, "sandbox failed");

    while ( (ch = getopt_long(argc, argv, "a:b:c:dDeF:hI:k:K:o:P:p:r:sS:u:U:vx",
                    long_options, NULL)) != -1) {
        switch (ch) {
            case 'u':
                /* username/jid */
                free(jid);
                jid = xmppipe_strdup(optarg);
                break;
            case 'p':
                /* password */
                free(pass);
                pass = xmppipe_strdup(optarg);
                break;
            case 'o':
                /* output/muc */
                free(state->room);
                state->room = xmppipe_strdup(optarg);
                break;
            case 'a': {
                    /* address:port */
                    char *p = NULL;
                    free(addr);
                    addr = xmppipe_strdup(optarg);
                    p = strchr(addr, ':');
                    if (p) {
                        *p++ = '\0';
                        port = xmppipe_strtonum(state, p, 0, 0xfffe);
                    }
                }
                break;
            case 'r':
                free(state->resource);
                state->resource = xmppipe_strdup(optarg);
                break;
            case 'S':
                free(state->subject);
                state->subject = xmppipe_strdup(optarg);
                break;
            case 'v':
                state->verbose++;
                break;
            case 'F':
                if (strcmp(optarg, "stdin") == 0)
                    state->format = XMPPIPE_FMT_STDIN;
                else if (strcmp(optarg, "colon") == 0)
                    state->format = XMPPIPE_FMT_COLON;
                else
                    usage(state);

                break;
            case 'x':
                state->encode = 1;
                break;

            case 'b':
                /* read buffer size */
                state->bufsz = xmppipe_strtonum(state, optarg, 3, 0xfffe);
                break;
            case 'c':
                /* XEP-0198: stream management flow control */
                state->sm_fc = xmppipe_strtonum(state, optarg, 0, 0xfffe);
                break;
            case 'I':
                /* XEP-0198: stream management request interval */
                state->sm_request_interval = xmppipe_strtonum(state, optarg, 0,
                        0xfffe);
                break;
            case 'k':
                /* XEP-0199: XMPP ping keepalives */
                state->sm_request_interval = xmppipe_strtonum(state, optarg, 0,
                        0xfffe) * 1000;
                break;
            case 'K':
                /* XEP-0199: number of keepalive without a reply */
                state->keepalive_limit = xmppipe_strtonum(state, optarg, 0,
                        0xfffe);
                break;
            case 'P':
                /* poll delay */
                state->poll = xmppipe_strtonum(state, optarg, 0, 0xfffe);
                break;
            case 'U':
                /* XEP-0198: stream management unacked requests */
                state->sm_unacked = xmppipe_strtonum(state, optarg, 0, 0xfffe);
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

            case OPT_NO_TLS_VERIFY:
                flags |= XMPP_CONN_FLAG_TRUST_TLS;
                break;
            case OPT_CHAT:
                state->opt &= ~XMPPIPE_OPT_GROUPCHAT;
                break;

            case 'h':
            default:
                usage(state);
        }
    }

    argc -= optind;
    argv += optind;

    if (argc > 0) {
      free(state->room);
      state->room = xmppipe_strdup(argv[0]);
    }

    if (jid == NULL)
        usage(state);

    if (state->encode && BASE64_LENGTH(state->bufsz) + 1 > 0xffff)
        usage(state);

    if (state->keepalive_limit < 1)
        usage(state);

    state->server = xmppipe_servername(jid);

    if (strchr(state->room, '@')) {
        state->out = xmppipe_strdup(state->room);
        state->mucjid = xmppipe_mucjid(state->out, state->resource);
    }
    else if (!(state->opt & XMPPIPE_OPT_GROUPCHAT)) {
        char *from = strchr(jid, '@');
        if (from == NULL)
            usage(state);
        from++;
        state->out = xmppipe_conference(state->room, from);
    }

    if (xmppipe_fmt_init() < 0)
        errx(EXIT_FAILURE, "xmppipe_fmt_init");

    xmpp_initialize();

    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);

    state->ctx = xmpp_ctx_new(NULL, (state->verbose > 1 ? log : NULL));
    if (state->ctx == NULL)
        errx(EXIT_FAILURE, "could not allocate context");

    state->conn = xmpp_conn_new(state->ctx);
    if (state->conn == NULL)
        errx(EXIT_FAILURE, "could not allocate connection");

    if (xmpp_conn_set_flags(state->conn, flags) < 0)
        errx(EXIT_FAILURE, "failed to set connection flags");

    xmpp_conn_set_jid(state->conn, jid);
    xmpp_conn_set_pass(state->conn, pass);

    if (xmpp_connect_client(state->conn, addr, port, handle_connection, state) < 0)
        errx(EXIT_FAILURE, "connection failed");

    if (xmppipe_connect_init(state) < 0)
        errx(EXIT_FAILURE, "XMPP handshake failed");

    if (state->verbose)
        (void)fprintf(stderr, "sandbox: stdin: %s\n", XMPPIPE_SANDBOX);

    if (xmppipe_sandbox_stdin(state) < 0)
        err(EXIT_FAILURE, "sandbox failed");

    if (xmppipe_stream_init(state) < 0)
        errx(EXIT_FAILURE, "enabling stream management failed");

    if ( (state->opt & XMPPIPE_OPT_GROUPCHAT) && xmppipe_muc_init(state) < 0)
        errx(EXIT_FAILURE, "failed to join MUC");

    if (xmppipe_presence_init(state) < 0)
        errx(EXIT_FAILURE, "publishing presence failed");

    if ( (state->opt & XMPPIPE_OPT_GROUPCHAT) && state->subject)
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
    xmpp_handler_add(state->conn, handle_message,
        NULL, "message", NULL, state);
    xmpp_handler_add(state->conn, handle_version,
            "jabber:iq:version", "iq", NULL, state);
    xmpp_id_handler_add(state->conn, handle_ping_reply, "c2s1", state);

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
    xmpp_stanza_t *iq = NULL;
    xmpp_stanza_t *query = NULL;

    xmpp_handler_add(state->conn, handle_presence_error,
            "http://jabber.org/protocol/muc", "presence", "error", state);
    xmpp_handler_add(state->conn, handle_presence,
            "http://jabber.org/protocol/muc#user", "presence", NULL, state);

    /* Discover the MUC service */
    if (state->out == NULL) {
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
        xmppipe_stanza_set_id(iq, "_xmppipe_muc_init");

        query = xmppipe_stanza_new(state->ctx);
        xmppipe_stanza_set_name(query, "query");
        xmppipe_stanza_set_ns(query, "http://jabber.org/protocol/disco#items");

        xmppipe_stanza_add_child(iq, query);

        xmppipe_send(state, iq);
        (void)xmpp_stanza_release(iq);

        xmppipe_next_state(state, XMPPIPE_S_MUC_SERVICE_LOOKUP);
    }

    return 0;
}

    int
xmppipe_presence_init(xmppipe_state_t *state)
{
    xmpp_stanza_t *presence = NULL;

    /* Send initial <presence/> so that we appear online to contacts */
    presence = xmppipe_stanza_new(state->ctx);
    xmppipe_stanza_set_name(presence, "presence");
    xmppipe_send(state, presence);
    (void)xmpp_stanza_release(presence);

    if (!(state->opt & XMPPIPE_OPT_GROUPCHAT))
      xmppipe_next_state(state, XMPPIPE_S_READY_AVAIL);

    if ( (state->opt & XMPPIPE_OPT_GROUPCHAT) && state->out) {
        xmppipe_muc_join(state);
        xmppipe_muc_unlock(state);
        xmppipe_next_state(state, XMPPIPE_S_MUC_WAITJOIN);
    }

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

        if (state->sm_enabled) {
            if (state->sm_ack_sent > state->sm_request)
                errx(EXIT_FAILURE, "h too large: sent=%u, server responded=%u",
                        state->sm_request, state->sm_ack_sent);

            if ( (state->sm_request_unack > state->sm_unacked)
                 || (state->sm_request - state->sm_ack_sent > state->sm_fc)) {
                if (state->verbose)
                    (void)fprintf(stderr,
                            "WAIT: request=%u ack_sent=%u unack=%u\n",
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
    }

XMPPIPE_EXIT:
    free(buf);
    return;
}

    int
handle_stdin(xmppipe_state_t *state, int fd, char *buf, size_t len)
{
    fd_set rfds;
    struct timeval tv = {0};
    ssize_t n = 0;
    int rv = 0;

    tv.tv_sec = 0;
    tv.tv_usec = state->poll * 1000;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    rv = select(fd+1, &rfds, NULL, NULL, &tv);

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
            xmppipe_next_state(state, XMPPIPE_S_CONNECTED);
            break;

        default:
            xmppipe_next_state(state, XMPPIPE_S_DISCONNECTED);
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
    const char *name = NULL;

    name = xmpp_stanza_get_name(stanza);
    if (name == NULL)
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
    const char *h = NULL;
    u_int32_t ack = 0;
    const char *errstr = NULL;

    h = xmpp_stanza_get_attribute(stanza, "h");

    if (h == NULL)
        return 1;

    ack = strtonum(h, 0, UINT_MAX-1, &errstr);
    if (errstr)
        goto XMPPIPE_STREAMERR;

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

    if (query == NULL)
        return 1;

    for (item = xmpp_stanza_get_children(query); item != NULL;
            item = xmpp_stanza_get_next(item)) {
        xmpp_stanza_t *iq, *reply;
        const char *jid = NULL;
        const char *name = NULL;
        char *id = NULL;

        name = xmpp_stanza_get_name(item);
        if (name == NULL)
            continue;

        if (XMPPIPE_STRNEQ(name, "item"))
            continue;

        jid = xmpp_stanza_get_attribute(item, "jid");
        if (jid == NULL)
            continue;

        iq = xmppipe_stanza_new(ctx);
        xmppipe_stanza_set_name(iq, "iq");
        xmppipe_stanza_set_type(iq, "get");
        xmppipe_stanza_set_attribute(iq, "to", jid);

        id = xmpp_uuid_gen(state->ctx);
        if (id == NULL) {
            errx(EXIT_FAILURE, "unable to allocate message id");
        }
        xmppipe_stanza_set_id(iq, id);

        reply = xmppipe_stanza_new(ctx);
        xmppipe_stanza_set_name(reply, "query");
        xmppipe_stanza_set_ns(reply, "http://jabber.org/protocol/disco#info");

        xmppipe_stanza_add_child(iq, reply);

        xmppipe_send(state, iq);
        (void)xmpp_stanza_release(iq);
        xmpp_free(state->ctx, id);
    }

    return 0;
}

    int
handle_disco_info(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmpp_stanza_t *query, *child;
    const char *from = NULL;
    xmppipe_state_t *state = userdata;

    from = xmpp_stanza_get_attribute(stanza, "from");

    if (from == NULL)
        return 1;

    query = xmpp_stanza_get_child_by_name(stanza, "query");

    if (query == NULL)
        return 1;

    for (child = xmpp_stanza_get_children(query); child != NULL;
            child = xmpp_stanza_get_next(child)) {
        const char *feature = NULL;
        const char *var = NULL;

        feature = xmpp_stanza_get_name(child);
        if (feature == NULL)
            continue;

        if (XMPPIPE_STRNEQ(feature, "feature"))
            continue;

        var = xmpp_stanza_get_attribute(child, "var");
        if (var == NULL)
            continue;

        if (XMPPIPE_STRNEQ(var, "http://jabber.org/protocol/muc"))
            continue;

        state->mucservice = xmppipe_strdup(from);
        state->out = xmppipe_conference(state->room, state->mucservice);
        state->mucjid = xmppipe_mucjid(state->out, state->resource);

        if (state->opt & XMPPIPE_OPT_GROUPCHAT) {
        xmppipe_muc_join(state);
        xmppipe_muc_unlock(state);
        }

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

    const char *ns = NULL;
    const char *id = NULL;
    const char *from = NULL;

    xmppipe_state_t *state = userdata;
    xmpp_ctx_t *ctx = state->ctx;

    reply = xmppipe_stanza_new(ctx);
    xmppipe_stanza_set_name(reply, "iq");
    xmppipe_stanza_set_type(reply, "result");

    id = xmpp_stanza_get_attribute(stanza, "id");
    if (id == NULL)
        return 1;

    xmppipe_stanza_set_id(reply, id);

    from = xmpp_stanza_get_attribute(stanza, "from");
    if (from == NULL)
        return 1;

    xmppipe_stanza_set_attribute(reply, "to",  from);

    query = xmppipe_stanza_new(ctx);
    xmppipe_stanza_set_name(query, "query");

    child = xmpp_stanza_get_children(stanza);
    if (child == NULL) {
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

    int
handle_presence_error(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza,
        void * const userdata)
{
    xmppipe_state_t *state = userdata;
    xmpp_stanza_t *error = NULL;
    xmpp_stanza_t *child = NULL;

    const char *from = NULL;
    const char *to = NULL;
    const char *code = NULL;
    const char *text = NULL;

    from = xmpp_stanza_get_attribute(stanza, "from");
    to = xmpp_stanza_get_attribute(stanza, "to");

    if (from == NULL || to == NULL)
        return 1;

    /* Check error is to our JID (user@example.org/binding) */
    if (XMPPIPE_STRNEQ(to, xmpp_conn_get_bound_jid(conn)))
        return 1;

    /* Check error is from our resource in the MUC (room@example.org/nick) */
    if (XMPPIPE_STRNEQ(from, state->mucjid))
        return 1;

    error = xmpp_stanza_get_child_by_name(stanza, "error");
    if (error == NULL)
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
    const char *type = NULL;
    const char *from = NULL;
    const char *to = NULL;

    char *etype = NULL;
    char *efrom = NULL;
    char *eto = NULL;
    char *emessage = NULL;

    if (xmpp_stanza_get_child_by_name(stanza, "delay"))
        return 1;

    from = xmpp_stanza_get_attribute(stanza, "from");
    if (from == NULL)
        return 1;

    to = xmpp_stanza_get_attribute(stanza, "to");
    if (to == NULL)
        return 1;

    type = xmpp_stanza_get_type(stanza);
    if (type == NULL)
        return 1;

    /* Check if the message is from us */
    if (XMPPIPE_STREQ(type,
          state->opt & XMPPIPE_OPT_GROUPCHAT ? "groupchat" : "chat")
        && XMPPIPE_STREQ(from, state->mucjid))
        return 1;

    child = xmpp_stanza_get_child_by_name(stanza, "body");
    if (child == NULL)
        return 1;

    message = xmpp_stanza_get_text(child);
    if (message == NULL)
        return 1;

    if (state->encode) {
        size_t len = strlen(message);
        unsigned char *buf = NULL;
        size_t n = 0;

        xmpp_base64_decode_bin(state->ctx, message, len, &buf, &n);

        if (buf == NULL) {
            /* Not a base64 message */
            return 1;
        }

        emessage = xmppipe_nfmt_encode((char *)buf,n);
        xmpp_free(state->ctx, buf);
    }
    else {
        emessage = xmppipe_fmt_encode(message);
    }

    etype = xmppipe_fmt_encode(type);
    efrom = xmppipe_fmt_encode(from);
    eto = xmppipe_fmt_encode(to);

    (void)printf("m:%s:%s:%s:%s\n", etype, efrom, eto, emessage);

    state->interval = 0;

    free(message);
    free(etype);
    free(efrom);
    free(eto);
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
xmppipe_send_stanza(xmppipe_state_t *state, char *buf, size_t len)
{
    char *to = NULL;
    char *type = NULL;
    char *deftype;

    int i;
    size_t n;
    char *tmp = NULL;
    char *start = NULL;
    char *end = NULL;
    char *body = NULL;
    int valid = 0;

    deftype = (state->opt & XMPPIPE_OPT_GROUPCHAT) ? "groupchat" : "chat";

    switch (state->format) {
      case XMPPIPE_FMT_STDIN:
        xmppipe_send_message(state, state->out, deftype, buf, len);
        return;

      case XMPPIPE_FMT_COLON:
        break;

      default:
        if (state->verbose)
          (void)fprintf(stderr, "unsupported format: %d\n", state->format);

        return;
    }

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
          type = xmppipe_fmt_decode((n == 0) ? deftype : start);
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

    void
xmppipe_stream_close(xmppipe_state_t *state)
{
    if (state->sm_enabled)
        xmpp_send_raw_string(state->conn, "</stream:stream>");
}

    static long long
xmppipe_strtonum(xmppipe_state_t *state, const char *nptr, long long minval,
        long long maxval)
{
    long long n = 0;
    const char *errstr = NULL;

    n = strtonum(nptr, minval, maxval, &errstr);
    if (errstr)
        errx(EXIT_FAILURE, "%s: %s", errstr, nptr);

    return n;
}

    static void
xmppipe_next_state(xmppipe_state_t *state, int status)
{
    if (state->verbose)
      (void)fprintf(stderr, "next state: %s (%d) -> %s (%d)\n",
          (state->status < 0 || state->status > XMPPIPE_S_READY_EMPTY) ? "unknown" : xmppipe_states[state->status],
          state->status,
          (state->status < 0 || state->status > XMPPIPE_S_READY_EMPTY) ? "unknown" : xmppipe_states[status],
          status);

    state->status = status;
}

    static void
usage(xmppipe_state_t *state)
{
    (void)fprintf(stderr, "%s %s (using %s sandbox)\n",
            __progname, XMPPIPE_VERSION, XMPPIPE_SANDBOX);
    (void)fprintf(stderr,
            "usage: %s [OPTIONS]\n"
            "   -u, --username <jid>                XMPP username (aka JID)\n"
            "   -p, --password <password>           XMPP password\n"
            "   -r, --resource <resource>           resource (aka MUC nick)\n"
            "   -S, --subject <subject>             set MUC subject\n"
            "   -a, --address <addr:port>           set XMPP server address (port is optional)\n"

            "   -d, --discard                       discard stdin when MUC is empty\n"
            "   -D, --discard-to-stdout             discard stdin and print to local stdout\n"
            "   -e, --ignore-eof                    ignore stdin EOF\n"
            "   -s, --exit-when-empty               exit when all participants leave MUC\n"
            "   -x, --base64                        base64 encode/decode data\n"

            "   -b, --buffer-size <size>            size of stdin read buffer\n"
            "   -I, --interval <interval>           request stream management status every interval messages\n"
            "   -k, --keepalives <seconds>          periodically send a keepalive\n"
            "   -K, --keepalive-failures <count>    number of keepalive failures before exiting\n"
            "   -P, --poll-delay <ms>               poll delay\n"
            "   -v, --verbose                       verbose\n"

            "       --chat                          use one to one chat\n"
            "       --no-tls-verify                 disable TLS certificate verification\n",
            __progname
            );

    exit (EXIT_FAILURE);
}
