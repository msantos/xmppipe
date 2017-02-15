#!/usr/bin/env bats

[ "$XMPPIPE_USERNAME" ]
[ "$XMPPIPE_PASSWORD" ]
[ "$XMPPIPE_TEST_USERNAME" ]
[ "$XMPPIPE_TEST_PASSWORD" ]

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

@test "sending/receive message: stdin" {
    (sleep 10; echo 'test123 ~!@#$' | xmppipe -o xmppipe-test -r user1 -u $XMPPIPE_TEST_USERNAME -p $XMPPIPE_TEST_PASSWORD) &
    xmppipe -o xmppipe-test -s | egrep "^m:groupchat:[^/]+/user1:[^:]+:test123%20~%21@%23%24%0A"
}
