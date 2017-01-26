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
    xmppipe -o muc

Requirements
------------

* [libstrophe](https://github.com/strophe/libstrophe)

* Linux: libuuid

~~~
apt-get install uuid-dev
~~~

Build
-----

    $ make

Options
-------

-u *JID*
:   XMPP username: takes precedence over environment variable

-p *password*
:   XMPP password: takes precedence over environment variable

-r *resource*
:   XMPP resource, used as the nickname in the MUC

-o *output*
:   XMPP MUC name

    Default: stdout-*hostname*-*pid*

-S *subject*
:   XMPP MUC subject

-a *address:port*
:   Specify the IP address and port of the XMPP server

-d
:   Discard stdin when MUC is empty

-D
:   Discard stdin and print to local stdout

-e
:   Ignore stdin EOF

-s
:   Exit when MUC is empty

-x
:   Base64 encode/decode data

-b *size*
:   Size of read buffer

-I *interval*
:   Request stream management status every interval messages

-k *seconds* 
:   Periodically send a keepalive

-K *count*
:   Number of keepalive failures before exiting

-P *ms*
:   Poll delay

-v
:   Increase verbosity

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

set -e
set -u
set -o pipefail

trap cleanup 0

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
    while read line; do
        IFS=:
        set -- $line
        if [ "$1" = "p" ]; then
            decode "$line" 1>&2
            echo 1>&2
        elif [ "$1" = "m" ]; then
            USER="$(decode ${3#*%2F})"
            IFS=$OFS
            MSG="$(decode ${!#})"
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
                    echo "$@"
                    ;;
            esac
        fi
    done < $out
}

bot > $in &
xmppipe "$@" <$in >$out
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
    http://example.com:80/index < /dev/null > riemann &
xmppipe -o "muc" -d -vv -S "riemann events" < riemann
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
(cat $FIFO | xmppipe -r user -o $MUC -x) > /dev/null 2> $TMPDIR/stderr &
script -q -f $FIFO
~~~

* viewers

~~~ shell
#!/bin/bash

decode() {
    printf '%b' "${1//%/\\x}"
}

stty cols 80 rows 24
xmppipe -r viewer -o console -x | while read l; do
    IFS=:
    set -- $l
    if [ "$1" = "m" ]; then
        decode $5
    fi
done
~~~

### Mirror a terminal session to a web page

Environment Variables
---------------------

* XMPPIPE_USERNAME: XMPP jid

* XMPPIPE_PASSWORD: XMPP password

Format
------

Each message is terminated by a new line. Message fields are separated by
":" and percent encoded.

### Presence

    p:<available|unavailable>:<to jid>:<from jid>

Example:

    p:available:test@muc.example.com/xmppipe:occupant@example.com/1234

### Message

    m:<chat|groupchat>:<from jid>:<to jid>:<message body>

Example:

    m:groupchat:test@muc.example.com/mobile:user1@example.com/1234:Hello
    m:chat:user1@example.com/mobile:user2@example.com:Message%20goes%20here

Compatibility
-------------

Tested with ejabberd and mongooseim.

Security Considerations
-----------------------

[libstrophe](https://github.com/strophe/libstrophe.git) does not verify
the TLS server certificates. Sessions can be MITM'ed.

libstrophe has support for TLS certificate verification on a
[branch](https://github.com/strophe/libstrophe/tree/tls-cert).

[libmesode](https://github.com/boothj5/libmesode.git) supports TLS
certificate verification.

License
-------

Copyright (c) 2015-2016, Michael Santos <michael.santos@gmail.com>

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

* Support TLS certificate verification

  Switch to using [libmesode](https://github.com/boothj5/libmesode)

* support [XEP-0384: OMEMO Encryption](https://xmpp.org/extensions/xep-0384.html)

* sandbox

  After connecting to the XMPP server, xmppipe reads from stdin, writes
  to stdout and read/writes from the network socket.

  Drop additional capabilities using OS-specific sandboxes:

  * OpenBSD: pledge(2)
  * Linux: BPF syscall filtering using prctl(2) or seccomp(2)
  * FreeBSD: capabilities using capsicum(4)
  * any: setrlimit(2)
