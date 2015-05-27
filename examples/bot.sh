#!/bin/bash

#set -x
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
    DEBUG=0
    while read line; do
        OFS=$IFS
        IFS=:
        set -- $line
        if [ "$1" = "p" ]; then
            decode "$line" 1>&2
            echo 1>&2
        elif [ "$1" = "m" ]; then
            USER="$(decode ${3#*%2F})"
            IFS=$OFS
            MSG="$(decode $4)"
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
                runtime)
                    LC_ALL=POSIX ps -o etime= $$
                    ;;
                exit)
                    echo "exiting ..."
                    exit 0
                    ;;
                debug)
                    if [ "$DEBUG" = "0" ]; then
                        DEBUG=1
                    else
                        DEBUG=0
                    fi
                    ;;
                *)
                    if [ "$DEBUG" == "0" ]; then
                        printf "%s: %s\n" "$USER" "$MSG"
                    else
                        echo "$@"
                    fi
                    ;;
            esac
        fi
        IFS=$OFS
    done < $out
}

bot > $in &
xmppipe "$@" <$in >$out
