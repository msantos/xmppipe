#!/usr/bin/env bats

if [ ! "$XMPPIPE_USERNAME" ] || [ ! "$XMPPIPE_PASSWORD" ] ||
   [ ! "$XMPPIPE_TEST_USERNAME" ] || [ ! "$XMPPIPE_TEST_PASSWORD" ]; then
cat << EOF
Please ensure the following environment variables are set to valid
XMPP accounts:

XMPPIPE_USERNAME=${XMPPIPE_USERNAME-<unset>}
XMPPIPE_PASSWORD=${XMPPIPE_PASSWORD-<unset>}
XMPPIPE_TEST_USERNAME=${XMPPIPE_TEST_USERNAME-<unset>}
XMPPIPE_TEST_PASSWORD=${XMPPIPE_TEST_PASSWORD-<unset>}

EOF

   exit 1
fi

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
    (sleep 10; echo 'test123: ~!@#$' | xmppipe -r user1 -u "$XMPPIPE_TEST_USERNAME" -p "$XMPPIPE_TEST_PASSWORD" xmppipe-test-1) &
    xmppipe -s xmppipe-test-1 | egrep "^m:groupchat:[^/]+/user1:[^:]+:test123%3A%20~%21@%23%24%0A"
}

@test "send/receive message: using script" {
    test/script/send-message.sh \
        -o xmppipe-test-2 \
        -r user1 \
        -t user2 \
        -u "$XMPPIPE_TEST_USERNAME" \
        -p "$XMPPIPE_TEST_PASSWORD" \
        'test123: &(*)_+' &
    sleep 10
    xmppipe -r user2 -s xmppipe-test-2 | egrep "^m:groupchat:[^/]+/user1:[^:]+:test123%3A%20%26%28%2A%29_%2B%0A"
}

@test "send/receive message: base64 stdin" {
    (sleep 10; echo 'test123: ~!@#$' | xmppipe -x -r user1 -u "$XMPPIPE_TEST_USERNAME" -p "$XMPPIPE_TEST_PASSWORD" xmppipe-test-1) &
    xmppipe -x -s xmppipe-test-1 | egrep "^m:groupchat:[^/]+/user1:[^:]+:test123%3A%20~%21@%23%24%0A"
}
