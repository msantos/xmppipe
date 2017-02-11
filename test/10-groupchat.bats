#!/usr/bin/env bats

@test "enter MUC" {
    xmppipe < /dev/null | grep -q "^p:available"
}

@test "send groupchat" {
    MESSAGE="test-$$"
    echo $MESSAGE | xmppipe -vv 2>&1 | grep -q $MESSAGE
}

@test "redirect stdout/stderr to files" {
    TMPDIR=$(mktemp -d)
    MESSAGE="test-$$"
    echo $MESSAGE | xmppipe -vv > $TMPDIR/stdout 2> $TMPDIR/stderr
    grep -q "^p:available:" $TMPDIR/stdout
    grep -q $MESSAGE $TMPDIR/stderr
}
