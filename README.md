xmppipe: stdio over XMPP
========================

xmppipe redirects stdin/stdout in a shell pipeline to an XMPP MUC
(XEP-0045). xmppipe supports flow control using stream management
(XEP-0198) and can optionally deal with overload by acting as a circuit
breaker or discarding messages.

xmppipe works with line oriented tools like grep, sed and
awk by outputting each message as a newline terminated,
[percent-encoded](https://en.wikipedia.org/wiki/Percent-encoding) string.

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
:   Request stream management status ever interval messages

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

~~~
printf '%b' "${1//%/\\x}"
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

### Mirror a terminal session

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

TODO
----

* TLS support
