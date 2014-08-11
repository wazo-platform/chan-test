#!/bin/sh -e

HOST="${1:-$HOST}"

if [ -z "$HOST" ]; then
    echo "usage: $(basename $0) <host>" >&2
    exit 1
fi

rsync -v -rlp --exclude=.git ./ "$HOST:chan-test"
ssh "$HOST" sh -e <<EOF
cd chan-test
make
service asterisk stop
make install
service asterisk start
EOF
