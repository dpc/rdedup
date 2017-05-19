#!/bin/bash

export RDEDUP_DIR=/tmp/e2e-test
export RDEDUP_PASSPHRASE=testing

dd if=/dev/urandom of=test.data bs=1m count=1
src_sum=$(cat test.data | shasum)
if [ -d $RDEDUP_DIR ]; then
    rm -rf $RDEDUP_DIR
fi
cargo run --release init
cat test.data | cargo run --release store test

test_sum=$(cargo run --release load test | shasum)

rm test.data

if [ "$src_sum" != "$test_sum" ]; then
    echo "data loaded from repo did not match the source"
    exit -1
fi

export RDEDUP_DIR=
export RDEDUP_PASSPHRASE=