#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

trap cleanup 0

BOT_DEBUG=${BOT_DEBUG-""}

if [ "$BOT_DEBUG" ]; then
set -x
fi

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
    local DEBUG=0
    OFS=$IFS
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
                runtime)
                    LC_ALL=POSIX ps -o etime= $$
                    ;;
                exit)
                    echo "exiting ..."
                    exit 0
                    ;;
                debug)
                    DEBUG=$(( DEBUG ? 0 : 1 ))
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
    done < $out
}

bot > $in &
xmppipe "$@" <$in >$out
