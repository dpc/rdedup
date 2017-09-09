
export RDEDUP_CMD="./target/release/rdedup"
export RDEDUP_DIR=/tmp/rdedup-e2e-test.repo
export RDEDUP_PASSPHRASE=testing
export RUST_BACKTRACE=1


test_data_path=/tmp/rdedup-e2e-test.data
chunking_list=$($RDEDUP_CMD init --chunking '?' 2>&1 | grep values \
  | sed 's/.*\[values: \(.*\)\].*/\1/' | tr -d ',') || echo
encryptiton_list=$($RDEDUP_CMD init --encryption '?' 2>&1 | grep values \
  | sed 's/.*\[values: \(.*\)\].*/\1/' | tr -d ',') || echo
compression_list=$($RDEDUP_CMD init --compression '?' 2>&1 | grep values \
  | sed 's/.*\[values: \(.*\)\].*/\1/' | tr -d ',') || echo
hashing_list=$($RDEDUP_CMD init --hashing '?' 2>&1 | grep values \
  | sed 's/.*\[values: \(.*\)\].*/\1/' | tr -d ',') || echo

run_e2e_test() {
  args=""
  if [ ! -z "$1" ]; then
    args="$args --chunking $1"
  fi
  if [ ! -z "$2" ]; then
    args="$args --chunk-size $2"
  fi
  if [ ! -z "$3" ]; then
    args="$args --compression $3"
  fi
  if [ ! -z "$4" ]; then
    args="$args --encryption $4"
  fi
  if [ ! -z "$5" ]; then
    args="$args --hashing $5"
  fi
  if [ ! -z "$6" ]; then
    args="$args --nesting $6"
  fi

  src_digest=$(cat $test_data_path | shasum)
  if [ -d $RDEDUP_DIR ]; then
    rm -rf $RDEDUP_DIR
  fi

  echo "Running $RDEDUP_CMD init $args"
  $RDEDUP_CMD init $args

  echo "Running $RDEDUP_CMD store"
  cat $test_data_path | $RDEDUP_CMD store test

  echo "Running $RDEDUP_CMD load"
  restored_digest=$($RDEDUP_CMD load test | shasum)

  if [ "$src_digest" != "$restored_digest" ]; then
    echo "restore data corrupted $src_digest != $restored_digest"
    exit -1
  fi
}

# vim: et sw=2
