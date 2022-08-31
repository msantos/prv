#!/usr/bin/env bats

MSG='1234567890abcdefghijklmnopqrstuvwxyz 123'

@test "NUL prefaced message" {
    run sh -c "printf '\0test' | prv"
    cat << EOF
--- output
$output
--- output
EOF

    [ "$status" -eq 0 ]

    result='test'

    cat << EOF
--- expected
$result
--- expected
EOF
    [ "$output" = "$result" ]
}

@test "discard limit" {
    run sh -c "yes \"$MSG\" | head -10 | prv --limit=3 --window=10"
    cat << EOF
--- output
$output
--- output
EOF

    [ "$status" -eq 0 ]

    result="$MSG
$MSG
$MSG"

    cat << EOF
--- expected
$result
--- expected
EOF
    [ "$output" = "$result" ]
}

@test "window: number of messages per window" {
    run sh -c "(timeout -s 9 3 yes \"$MSG\" | prv --limit=1 --window=1) 2>&1 | grep -cv Killed"
    cat << EOF
--- output
$output
--- output
EOF

    # timeout quirk: elapsed = 4 seconds
    result="4"

    cat << EOF
--- expected
$result
--- expected
EOF
    [ "$output" -eq "$result" ]
}

@test "process restriction: ioctl: redirect stdout to a device" {
    run script -e -a /dev/null -c "prv <<<$PATH >/dev/null"
    cat << EOF
--- output
$output
--- output
EOF
    [ "$status" -eq 0 ]
}
