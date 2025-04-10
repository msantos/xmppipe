#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

shopt -s nullglob

if [ "$BOT_DEBUG" ]; then
  set -x
fi

decode() {
  printf '%b' "${1//%/\\x}"
}

bot() {
  local DEBUG=0
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
  done
}

coproc bot
xmppipe "$@" <&"${COPROC[0]}" >&"${COPROC[1]}"
