/* Copyright (c) 2015-2020, Michael Santos <michael.santos@gmail.com>
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

#include <getopt.h>

extern char *__progname;

static void usage(xmppipe_state_t *xp);

static long long xmppipe_strtonum(xmppipe_state_t *state, const char *nptr,
                                  long long minval, long long maxval);

void handle_connection(xmpp_conn_t *const, const xmpp_conn_event_t, const int,
                       xmpp_stream_error_t *const, void *const userdata);
int handle_disco_items(xmpp_conn_t *const, xmpp_stanza_t *const, void *const);
int handle_disco_info(xmpp_conn_t *const, xmpp_stanza_t *const, void *const);

int xmppipe_connect_init(xmppipe_state_t *);
int xmppipe_stream_init(xmppipe_state_t *);
int xmppipe_muc_init(xmppipe_state_t *);
int xmppipe_presence_init(xmppipe_state_t *);

enum {
  OPT_NO_TLS_VERIFY = 1,
  OPT_CHAT,
};

static const struct option long_options[] = {
    {"address", required_argument, NULL, 'a'},
    {"buffer-size", required_argument, NULL, 'b'},
    {"flow-control", required_argument, NULL, 'c'},
    {"chat", no_argument, NULL, OPT_CHAT},
    {"discard", no_argument, NULL, 'd'},
    {"discard-to-stdout", no_argument, NULL, 'D'},
    {"ignore-eof", no_argument, NULL, 'e'},
    {"format", required_argument, NULL, 'F'},
    {"interval", required_argument, NULL, 'I'},
    {"keepalive", required_argument, NULL, 'k'},
    {"keepalive-failures", required_argument, NULL, 'K'},
    {"output", required_argument, NULL, 'o'},
    {"password", required_argument, NULL, 'p'},
    {"poll-delay", required_argument, NULL, 'P'},
    {"resource", required_argument, NULL, 'r'},
    {"exit-when-empty", no_argument, NULL, 's'},
    {"subject", required_argument, NULL, 'S'},
    {"username", required_argument, NULL, 'u'},
    {"unacked-requests", required_argument, NULL, 'U'},
    {"verbose", no_argument, NULL, 'v'},
    {"version", no_argument, NULL, 'V'},
    {"base64", no_argument, NULL, 'x'},
    {"help", no_argument, NULL, 'h'},

    {"no-tls-verify", no_argument, NULL, OPT_NO_TLS_VERIFY},

    {NULL, 0, NULL, 0}};

int main(int argc, char **argv) {
  xmppipe_state_t *state = NULL;
  xmpp_log_t *log = NULL;
  char *jid = NULL;
  char *pass = NULL;
  char *addr = NULL;
  u_int16_t port = 0;
  long flags = 0;

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

  if (restrict_process_init(state) < 0)
    err(EXIT_FAILURE, "restrict_process failed");

  while ((ch = getopt_long(argc, argv, "a:b:c:dDeF:hI:k:K:o:P:p:r:sS:u:U:vVx",
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
        port = (u_int16_t)xmppipe_strtonum(state, p, 0, 0xfffe);
      }
    } break;
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
    case 'V':
      (void)printf("%s (%s)\n", XMPPIPE_VERSION, RESTRICT_PROCESS);
      exit(0);
      break;
    case 'F':
      if (strcmp(optarg, "text") == 0)
        state->format = XMPPIPE_FMT_TEXT;
      else if (strcmp(optarg, "csv") == 0)
        state->format = XMPPIPE_FMT_CSV;
      else
        usage(state);

      break;
    case 'x':
      state->encode = 1;
      break;

    case 'b':
      /* read buffer size */
      state->bufsz = (size_t)xmppipe_strtonum(state, optarg, 3, 0xfffe);
      break;
    case 'c':
      /* XEP-0198: stream management flow control */
      state->sm_fc = (u_int32_t)xmppipe_strtonum(state, optarg, 0, 0xfffe);
      break;
    case 'I':
      /* XEP-0198: stream management request interval */
      state->sm_request_interval =
          (u_int32_t)xmppipe_strtonum(state, optarg, 0, 0xfffe);
      break;
    case 'k':
      /* XEP-0199: XMPP ping keepalives */
      state->keepalive =
          (u_int32_t)xmppipe_strtonum(state, optarg, 0, 0xfffe) * 1000;
      break;
    case 'K':
      /* XEP-0199: number of keepalive without a reply */
      state->keepalive_limit =
          (u_int32_t)xmppipe_strtonum(state, optarg, 1, 0xfffe);
      break;
    case 'P':
      /* poll delay */
      state->poll = (u_int32_t)xmppipe_strtonum(state, optarg, 0, 0xfffe);
      break;
    case 'U':
      /* XEP-0198: stream management unacked requests */
      state->sm_unacked = (u_int32_t)xmppipe_strtonum(state, optarg, 0, 0xfffe);
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

  state->server = xmppipe_servername(jid);

  if (strchr(state->room, '@')) {
    state->out = xmppipe_strdup(state->room);
    state->mucjid = xmppipe_mucjid(state->out, state->resource);
  } else if (!(state->opt & XMPPIPE_OPT_GROUPCHAT)) {
    state->out = xmppipe_strdup(jid);
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

  if (xmpp_connect_client(state->conn, addr, port, handle_connection, state) <
      0)
    errx(EXIT_FAILURE, "connection failed");

  if (xmppipe_connect_init(state) < 0)
    errx(EXIT_FAILURE, "XMPP handshake failed");

  if (state->verbose)
    (void)fprintf(stderr, "restrict_process: stdin: %s\n", RESTRICT_PROCESS);

  if (restrict_process_stdin(state) < 0)
    err(EXIT_FAILURE, "restrict_process failed");

  if (xmppipe_stream_init(state) < 0)
    errx(EXIT_FAILURE, "enabling stream management failed");

  if ((state->opt & XMPPIPE_OPT_GROUPCHAT) && xmppipe_muc_init(state) < 0)
    errx(EXIT_FAILURE, "failed to join MUC");

  if (xmppipe_presence_init(state) < 0)
    errx(EXIT_FAILURE, "publishing presence failed");

  if ((state->opt & XMPPIPE_OPT_GROUPCHAT) && state->subject)
    xmppipe_muc_subject(state, state->subject);

  event_loop(state);

  xmppipe_stream_close(state);
  (void)xmpp_conn_release(state->conn);
  xmpp_ctx_free(state->ctx);
  xmpp_shutdown();

  return 0;
}

int xmppipe_connect_init(xmppipe_state_t *state) {
  for (;;) {
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

int xmppipe_stream_init(xmppipe_state_t *state) {
  xmpp_stanza_t *enable = NULL;

  if (state->sm_request_interval == 0)
    return 0;

  /* <enable xmlns='urn:xmpp:sm:3'/> */
  enable = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(enable, "enable");
  xmppipe_stanza_set_ns(enable, "urn:xmpp:sm:3");
  xmpp_send(state->conn, enable);
  (void)xmpp_stanza_release(enable);

  xmpp_handler_add(state->conn, handle_sm_enabled, "urn:xmpp:sm:3", "enabled",
                   NULL, state);
  xmpp_handler_add(state->conn, handle_sm_request, "urn:xmpp:sm:3", "r", NULL,
                   state);
  xmpp_handler_add(state->conn, handle_sm_ack, "urn:xmpp:sm:3", "a", NULL,
                   state);
  xmpp_handler_add(state->conn, handle_message, NULL, "message", NULL, state);
  xmpp_handler_add(state->conn, handle_version, "jabber:iq:version", "iq", NULL,
                   state);
  xmpp_handler_add(state->conn, handle_iq, NULL, "iq", "result", state);
  xmpp_id_handler_add(state->conn, handle_ping_reply, "c2s1", state);

  /* XXX multiple handlers can be called for each event
   * XXX
   * XXX * is the order handlers are called determinisitc?
   * XXX * the NULL handler needs to installed as soon as stream management is
   * enabled
   * XXX * a handler has to exist for unsupported events
   */
  xmpp_handler_add(state->conn, handle_null, NULL, NULL, NULL, state);

  return 0;
}

int xmppipe_muc_init(xmppipe_state_t *state) {
  xmpp_stanza_t *iq = NULL;
  xmpp_stanza_t *query = NULL;

  xmpp_handler_add(state->conn, handle_presence_error,
                   "http://jabber.org/protocol/muc", "presence", "error",
                   state);
  xmpp_handler_add(state->conn, handle_presence,
                   "http://jabber.org/protocol/muc#user", "presence", NULL,
                   state);

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
    (void)xmpp_stanza_release(query);

    xmppipe_send(state, iq);
    (void)xmpp_stanza_release(iq);

    xmppipe_next_state(state, XMPPIPE_S_MUC_SERVICE_LOOKUP);
  }

  return 0;
}

int xmppipe_presence_init(xmppipe_state_t *state) {
  xmpp_stanza_t *presence = NULL;

  /* Send initial <presence/> so that we appear online to contacts */
  presence = xmppipe_stanza_new(state->ctx);
  xmppipe_stanza_set_name(presence, "presence");
  xmppipe_send(state, presence);
  (void)xmpp_stanza_release(presence);

  if (!(state->opt & XMPPIPE_OPT_GROUPCHAT))
    xmppipe_next_state(state, XMPPIPE_S_READY_AVAIL);

  if ((state->opt & XMPPIPE_OPT_GROUPCHAT) && state->out) {
    xmppipe_muc_join(state);
    xmppipe_muc_unlock(state);
    xmppipe_next_state(state, XMPPIPE_S_MUC_WAITJOIN);
  }

  for (;;) {
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

void handle_connection(xmpp_conn_t *const conn, const xmpp_conn_event_t status,
                       const int error, xmpp_stream_error_t *const stream_error,
                       void *const userdata) {
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

int handle_disco_items(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
                       void *const userdata) {
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

    id = xmppipe_uuid_gen(state->ctx);
    xmppipe_stanza_set_id(iq, id);

    reply = xmppipe_stanza_new(ctx);
    xmppipe_stanza_set_name(reply, "query");
    xmppipe_stanza_set_ns(reply, "http://jabber.org/protocol/disco#info");

    xmppipe_stanza_add_child(iq, reply);
    (void)xmpp_stanza_release(reply);

    xmppipe_send(state, iq);
    (void)xmpp_stanza_release(iq);
    xmpp_free(state->ctx, id);
  }

  return 0;
}

int handle_disco_info(xmpp_conn_t *const conn, xmpp_stanza_t *const stanza,
                      void *const userdata) {
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

    if (XMPPIPE_STREQ(var, "urn:xmpp:http:upload:0")) {
      state->upload = xmppipe_strdup(from);
      continue;
    }

    if (XMPPIPE_STRNEQ(var, "http://jabber.org/protocol/muc"))
      continue;

    state->mucservice = xmppipe_strdup(from);
    state->out = xmppipe_conference(state->room, state->mucservice);
    state->mucjid = xmppipe_mucjid(state->out, state->resource);

    if (state->opt & XMPPIPE_OPT_GROUPCHAT) {
      xmppipe_muc_join(state);
      xmppipe_muc_unlock(state);
    }

    return 1;
  }

  return 1;
}

static long long xmppipe_strtonum(xmppipe_state_t *state, const char *nptr,
                                  long long minval, long long maxval) {
  long long n = 0;
  const char *errstr = NULL;

  n = strtonum(nptr, minval, maxval, &errstr);
  if (errstr)
    errx(EXIT_FAILURE, "%s: %s", errstr, nptr);

  return n;
}

static void usage(xmppipe_state_t *state) {
  (void)fprintf(stderr, "%s %s (using %s mode process restriction)\n",
                __progname, XMPPIPE_VERSION, RESTRICT_PROCESS);
  (void)fprintf(
      stderr,
      "usage: %s [OPTIONS]\n"
      "   -u, --username <jid>                XMPP username (aka JID)\n"
      "   -p, --password <password>           XMPP password\n"
      "   -r, --resource <resource>           resource (aka MUC nick)\n"
      "   -S, --subject <subject>             set MUC subject\n"
      "   -a, --address <addr[:port]>         set XMPP server address\n"
      "   -F, --format <text|csv>             stdin is text (default) or colon "
      "separated values\n"

      "   -d, --discard                       discard stdin when MUC is empty\n"
      "   -D, --discard-to-stdout             discard stdin and print to local "
      "stdout\n"
      "   -e, --ignore-eof                    ignore stdin EOF\n"
      "   -s, --exit-when-empty               exit when all participants leave "
      "MUC\n"
      "   -x, --base64                        base64 encode/decode data\n"

      "   -b, --buffer-size <size>            size of stdin read buffer\n"
      "   -I, --interval <interval>           request stream management status "
      "every interval messages\n"
      "   -k, --keepalive <seconds>           periodically send a keepalive\n"
      "   -K, --keepalive-failures <count>    number of keepalive failures "
      "before exiting\n"
      "   -P, --poll-delay <ms>               poll delay\n"
      "   -v, --verbose                       verbose\n"
      "   -V, --version                       display version\n"

      "       --chat                          use one to one chat\n"
      "       --no-tls-verify                 disable TLS certificate "
      "verification\n",
      __progname);

  exit(EXIT_FAILURE);
}
