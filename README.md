xmppipe: stdio over XMPP
========================

xmppipe can be used in a shell pipeline to redirect stdin/stdout to an XMPP
MUC (XEP-0045). xmppipe supports flow control using stream management
(XEP-0198) and can optionally deal with overload by acting as a circuit
breaker or discarding messages.

To support line oriented tools like grep, sed and awk, the message body
is percent escaped.

Usage
-----

    xmppipe [*options*]

    XMPPIPE_USERNAME=me@example.com
    XMPPIPE_PASSWORD="password"
    xmppipe -o muc

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

Decoding Percent Escaped
------------------------

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

See examples/ssh-over-xmpp:

~~~
# Server: has access to the destination SSH server
# ssh-over-xmpp server <conference> <IP address> <port>
ssh-over-xmpp server sshxmpp 1.2.3.4 22

## Client: has access to the XMPP server
ssh -o ProxyCommand="ssh-over-xmpp client sshxmpp" 127.0.0.1
~~~

### Mirror a shell

### Mirror a shell to a web page

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

    p:available:test%40muc.example.com%2Fxmppipe:occupant%40example.com%2F1234

### Message

    m:<chat|groupchat>:<from jid>:<to jid>:<message body>

Example:

    m:groupchat:test%40muc.example.com%2Fmobile:user1%40example.com%2F1234:Hello
    m:chat:user1%40example.com%2Fmobile:user2%40example.com:Message%20goes%20here

TODO
----

* TLS support
