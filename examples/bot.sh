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

mkfifo "$in"
mkfifo "$out"

cleanup() {
  rm -rf "$TMPDIR"
}

decode() {
  printf '%b' "${1//%/\\x}"
}

bot() {
  local DEBUG=0
  while IFS=: read stanza type from to body; do
    case "$stanza" in
      m) ;;
      p)
        decode "$stanza:$type:$from:$to" 1>&2
        echo 1>&2
        continue
        ;;
      *) continue ;;
    esac

    USER="$(decode "${from#*/}")"
    MSG="$(decode "$body")"

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
        DEBUG=$((DEBUG ? 0 : 1))
        ;;
      *)
        if [ "$DEBUG" == "0" ]; then
          printf "%s: %s\n" "$USER" "$MSG"
        else
          echo "$MSG"
        fi
        ;;
    esac
  done <"$out"
}

bot >"$in" &
xmppipe "$@" <"$in" >"$out"
