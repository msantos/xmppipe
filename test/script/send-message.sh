#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

TMPDIR=$(mktemp -d)

mkdir -p $TMPDIR
mkfifo $TMPDIR/stdin
mkfifo $TMPDIR/stdout

trap atexit 0
atexit() {
    rm -rf $TMPDIR
}

wait_presence() {
    TO=$1
    MESSAGE=$2
    while read l; do
        IFS=":/"
        set -- $l
        if [ "$1" = "p" ] && [ "$2" = "available" ] && [ "$4" = "$TO" ]; then
            echo "$MESSAGE"
            exit 0
        fi
    done < $TMPDIR/stdout
}

while getopts "o:r:t:u:p:" opt; do
    case $opt in
        o) MUC="$OPTARG" ;;
        r) FROM="$OPTARG" ;;
        t) TO="$OPTARG" ;;
        u) XMPPIPE_USERNAME="$OPTARG" ;;
        p) XMPPIPE_PASSWORD="$OPTARG" ;;
        *) exit 1 ;;
    esac
done

shift $((OPTIND-1))

wait_presence "$TO" "$@" > $TMPDIR/stdin &
xmppipe -r "$FROM" -u "$XMPPIPE_USERNAME" -p "$XMPPIPE_PASSWORD" "$MUC" < $TMPDIR/stdin > $TMPDIR/stdout
