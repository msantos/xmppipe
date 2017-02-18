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

@test "send/receive message: using stdin" {
    (sleep 10; echo 'test123: ~!@#$' | xmppipe -o xmppipe-test-1 -r user1 -u "$XMPPIPE_TEST_USERNAME" -p "$XMPPIPE_TEST_PASSWORD") &
    xmppipe -o xmppipe-test-1 -s | egrep "^m:groupchat:[^/]+/user1:[^:]+:test123%3A%20~%21@%23%24%0A"
}

@test "send/receive message: using script" {
    test/script/send-message.sh \
        -o xmppipe-test-2 \
        -r user1 \
        -t user2 \
        -u "$XMPPIPE_TEST_USERNAME" \
        -p "$XMPPIPE_TEST_PASSWORD" \
        'test123: &(*)_+' &
    xmppipe -r user2 -o xmppipe-test-2 -s | egrep "^m:groupchat:[^/]+/user1:[^:]+:test123%3A%20%26%28%2A%29_%2B%0A"
}

@test "send/receive message: base64 stdin" {
    (sleep 10; echo 'test123: ~!@#$' | xmppipe -x -o xmppipe-test-1 -r user1 -u "$XMPPIPE_TEST_USERNAME" -p "$XMPPIPE_TEST_PASSWORD") &
    xmppipe -x -o xmppipe-test-1 -s | egrep "^m:groupchat:[^/]+/user1:[^:]+:test123%3A%20~%21@%23%24%0A"
}
