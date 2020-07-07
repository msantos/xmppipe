xmppipe: stdio over XMPP
========================

xmppipe redirects stdin/stdout in a shell pipeline to an XMPP MUC
(XEP-0045). xmppipe supports flow control using stream management
(XEP-0198) and can optionally deal with overload by acting as a circuit
breaker or by discarding messages.

xmppipe works with line oriented tools like grep, sed and
awk by outputting each message as a newline terminated,
[percent-encoded](https://en.wikipedia.org/wiki/Percent-encoding) string.

xmppipe can be used in shell scripts to quickly write interactive bots
for monitoring systems or for sending alerts.

Usage
-----

    xmppipe [*options*]

    XMPPIPE_USERNAME=me@example.com
    XMPPIPE_PASSWORD="password"

    # default name: stdout-*hostname*-*uid*
    xmpipe
    xmppipe muc
    xmppipe muc@example.com

Requirements
------------

* [libstrophe](https://github.com/strophe/libstrophe)

  libstrophe 0.9.2 or later is required for [TLS certificate
  verification](https://github.com/strophe/libstrophe/issues/100).

Build
-----

    $ make

Tests
-----

    # Install bats:
    # apt-get install bats
    # git clone https://github.com/sstephenson/bats.git # or from git
    make test

Sandboxing
----------

xmppipe applies 2 sandboxes:

* a permissive "init" sandbox allowing network connections to the
  XMPP server

* once the connection is established, a stricter "stdio" sandbox
  limits the process to stdio

The effectiveness of the sandbox depends on which mechanism is used. By
default:

* Linux:

    * init: seccomp(2)
    * stdio: seccomp(2)

* OpenBSD:

    * init: pledge(2)
    * stdio: pledge(2)

* FreeBSD:

    * init: setrlimit(2)
    * stdio: setrlimit(2)/capsicum(4)

* other: setrlimit(2)

    * init: setrlimit(2)
    * stdio: setrlimit(2)

Selecting the sandbox is done at compile time. For example, to use the
"rlimit" sandbox:

    XMPPIPE_SANDBOX=rlimit make

If a sandbox is interfering with normal operation, please open an issue.
To disable the sandbox, compile using the "null" sandbox:

    XMPPIPE_SANDBOX=null make

Options
-------

-u, --username *JID*
:   XMPP username: takes precedence over environment variable

-p, --password *password*
:   XMPP password: takes precedence over environment variable

-r, --resource *resource*
:   XMPP resource, used as the nickname in the MUC

-S, --subject *subject*
:   XMPP MUC subject

-a, --address *address:port*
:   Specify the IP address and port of the XMPP server

-F, --format *text:csv*
:   stdin is text (default) or colon separated values

-d, --discard
:   Discard stdin when MUC is empty

-D, --discard-to-stdout
:   Discard stdin and print to local stdout

-e, --ignore-eof
:   Ignore stdin EOF

-s, --exit-when-empty
:   Exit when MUC is empty

-x, --base64
:   Base64 encode/decode data

-b, --buffer-size *size*
:   Size of read buffer

-I, --interval *interval*
:   Request stream management status every interval messages

-k, --keepalive *seconds*
:   Periodically send a keepalive

-K, --keepalive-failures *count*
:   Number of keepalive failures before exiting

-P, --poll-delay *ms*
:   Poll delay

-v, --verbose
:   Increase verbosity

-V, --version
:   Display version

--chat
:   Use one to one chat

--no-tls-verify
:   Disable TLS certificate verification

Decoding Percent-Encoded Strings
--------------------------------

Using bash:

~~~ shell
decode() {
  printf '%b' "${1//%/\\x}"
}
~~~

Examples
--------

### Shell Bot

An interactive XMPP bot written in the shell:

~~~ shell
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

trap cleanup EXIT

TMPDIR=$(mktemp -d)

in="$TMPDIR/stdin"
out="$TMPDIR/stdout"

mkfifo $in
mkfifo $out

cleanup() {
  rm -rf $TMPDIR
}

decode() {
  printf '%b' "${1//%/\\x}"
}

bot() {
  while IFS=: read -r stanza type from to body; do
    case "$stanza" in
      m) ;;

      p)
        decode "$stanza:$type:$from:$to" 1>&2
        echo 1>&2
        continue
        ;;

      *) continue ;;
    esac

    USER="$(decode ${from#*/})"
    MSG="$(decode ${body})"

    case $MSG in
      *"has set the subject to:"*) ;;
      "sudo make me a sandwich")
        echo "$USER: you're a sandwich"
        ;;
      sudo*)
        echo "I'm sorry, $USER. I'm afraid I can't do that."
        ;;
      uptime)
        uptime
        ;;
      exit)
        echo "exiting ..."
        exit 0
        ;;
      *)
        echo "$MSG"
        ;;
    esac
  done <$out
}

bot >$in &
xmppipe "$@" <$in >$out
~~~

### Sending Notifications/Alerts

Start `xmppipe` attached to a pipe:

~~~ shell
mkfifo /tmp/xmpp

xmppipe -o groupchat <>/tmp/xmpp
~~~

Any data written to the pipe will be sent to the groupchat:

~~~ shell
echo "test" >/tmp/xmpp

df -h >/tmp/mpp

git diff >/tmp/xmpp
~~~

### SSH over XMPP

See [examples/ssh-over-xmpp](https://github.com/msantos/xmppipe/blob/master/examples/ssh-over-xmpp):

~~~ shell
# Server: has access to the destination SSH server
# ssh-over-xmpp server <conference> <IP address> <port>
ssh-over-xmpp server sshxmpp 1.2.3.4 22

## Client: has access to the XMPP server
ssh -o ProxyCommand="ssh-over-xmpp client sshxmpp" 127.0.0.1
~~~

### Stream Events from Riemann

This example will stream events from a query to an XMPP MUC using
[Riemann's](https://github.com/riemann/riemann) SSE interface. The events
are written to a named pipe to avoid buffering.

~~~ shell
mkfifo riemann
curl -s --get --data subscribe=true \
  --data-urlencode 'query=(service ~= "^example")' \
  http://example.com:80/index </dev/null >riemann &
xmppipe --verbose --verbose \
  --discard --subject "riemann events" muc <riemann
~~~

### Desktop Notifications

~~~ shell
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

decode() {
  printf '%b' "${1//%/\\x}"
}

MUC=""

while getopts ":o:" opt; do
  case $opt in
    o) MUC="$OPTARG" ;;
    *) ;;
  esac
done

xmppipe "$@" | while IFS=: read stanza type from to body; do
  case "$stanza" in
    m) notify-send "$MUC" "$(decode $body)" ;;
    *) continue ;;
  esac
done
~~~

### Mirror a terminal session using script(1)

* user

~~~ shell
#!/bin/bash

MUC=console

TMPDIR=$(mktemp -d)
FIFO=$TMPDIR/console
mkfifo $FIFO

stty cols 80 rows 24
(cat $FIFO | xmppipe --resource user -x $MUC) >/dev/null 2>$TMPDIR/stderr &
script -q -f $FIFO
~~~

* viewers

~~~ shell
#!/bin/bash

decode() {
  printf '%b' "${1//%/\\x}"
}

stty cols 80 rows 24
xmppipe --resource viewer --base64 console |
  while IFS=: read -r x s f t m; do
    [ "$m" = "m" ] && decode "$m"
  done
~~~

### Mirror a terminal session to a web page

### Image Upload

Upload an image using HTTP Upload (XEP-0363) then display it inline.

See [examples/image-upload](https://github.com/msantos/xmppipe/blob/master/examples/image-upload):

~~~
image-upload -o groupchat
~~~

~~~
# file must be in the same working directory as image-upload
echo "upload::::example.png" >/tmp/image_upload/stdin
~~~

Environment Variables
---------------------

* XMPPIPE_USERNAME: XMPP jid

* XMPPIPE_PASSWORD: XMPP password

Format
------

Each message is terminated by a new line. Message fields are separated by
":" and percent encoded.

Colon separated valued are accepted as input if the input format type
is set to csv (`--format=csv`).

### Presence

    p:<available|unavailable>:<to jid>:<from jid>

Input/Output:

    Both

Example:

    p:available:test@muc.example.com/xmppipe:occupant@example.com/1234

### Message

    m:<chat|groupchat|normal|headline>:<from jid>:<to jid>:<message body>

Input/Output:

    Both

Example:

    m:groupchat:test@muc.example.com/mobile:user1@example.com/1234:Hello
    m:chat:user1@example.com/mobile:user2@example.com:Message%20goes%20here

### Inline Image

Inline images will add a hint so clients (notably
[Conversations](https://github.com/iNPUTmice/Conversations) will display
the image instead of a URL.

* type, from and to are optional
* message body: the percent escaped URL

    I:<chat|groupchat|normal|headline>:<from jid>:<to jid>:<url>

Input/Output:

    Input only

Example:

    I::::https%3A%2F%2Fhttpstatusdogs.com%2Fimg%2F500.jpg

### XEP-0363: HTTP Upload

HTTP uploads create an upload slot. The XMPP server will respond with
`get` and `put` URLs. The `put` URL can be used to upload the file using,
e.g., `curl`. The `get` URL is used by clients for downloading the file.

Note: currently xmppipe creates the slot but does not upload the file.

The input format is:

* type, from and to are optional
* message body: percent escaped, pipe separated value
    * filename
    * size
    * optional: MIME type

    u:<chat|groupchat|normal|headline>:<from jid>:<to jid>:<filename>|<size (bytes)>[|<content-type>]

The output format is:

* type, from and to are optional
* message body: percent escaped, pipe separated value
    * get URL
    * put URL

    U:<chat|groupchat|normal|headline>:<from jid>:<to jid>:<get URL>|<put URL>

Example:

    # $ stat --format="%s" example.png
    # 16698
    u::::example.png%7C16698

    # also specify content type
    u::::example.png%7C16698%7Cimage%2Fpng

    # server response: slot created
    U:groupchat:upload.example.com:user@example.com/123:https%3A//example.com/upload/0b9da82fea20a78778cbeddeab0472286cc35ed1/xyEaWFVZv3sv5ay9AGH5qBU02gglZRyUeGbjQg3k/example.png%7chttps%3A//example.com/upload/0b9da82fea20a78778cbeddeab0472286cc35ed1/xyEaWFVZv3sv5ay9AGH5qBU02gglZRyUeGbjQg3k/example.png

    # to upload the file
    curl https://example.com/upload/0b9da82fea20a78778cbeddeab0472286cc35ed1/xyEaWFVZv3sv5ay9AGH5qBU02gglZRyUeGbjQg3k/example.png --upload-file example.png

Compatibility
-------------

Testing is done with ejabberd.

Also confirmed to work with:

* ejabberd ([creep.im](https://compliance.conversations.im/server/creep.im/))
* prosody ([dismail.de](https://compliance.conversations.im/server/dismail.de/))
* openfire ([jab.im](https://compliance.conversations.im/server/jab.im/))
* tigase ([tigase.im](https://compliance.conversations.im/server/tigase.im/))
* mongooseim


License
-------

Copyright (c) 2015-2020, Michael Santos <michael.santos@gmail.com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

TODO
----

* support [XEP-0384: OMEMO Encryption](https://xmpp.org/extensions/xep-0384.html)

* support alternative input modes

  * "raw" mode: XML input/output

* HTTP Upload

  * support PUT header elements
  * handle error conditions

  Questions:

  * save the maximum file size returned by the server and disallow uploads
    larger than the value?

  * xmppipe is "pinned" to the upload server returned in the IQ reply (the
    "to" field is ignored)

  * allow other upload servers?

  * error if different upload server is specified in "u:<from>:<to>"?
