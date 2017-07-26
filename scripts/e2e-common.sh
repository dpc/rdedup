test_data_path=/tmp/rdedup-e2e-test.data
chunking_list=`cargo run --release -- init --help | grep chunking | sed 's/.*\[values: \(.*\)\].*/\1/' | tr -d ','`
encryptiton_list=`cargo run --release -- init --help | grep encryption | sed 's/.*\[values: \(.*\)\].*/\1/' | tr -d ','`
compression_list=`cargo run --release -- init --help | grep compression | sed 's/.*\[values: \(.*\)\].*/\1/' | tr -d ','`
hashing_list=`cargo run --release -- init --help | grep hashing | sed 's/.*\[values: \(.*\)\].*/\1/' | tr -d ','`

export RDEDUP_DIR=/tmp/rdedup-e2e-test.repo
export RDEDUP_PASSPHRASE=testing
export RUST_BACKTRACE=1

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
  cargo run --release -- init $args

  cat $test_data_path | cargo run --release store test

  restored_digest=$(cargo run --release load test | shasum)

  if [ "$src_digest" != "$restored_digest" ]; then
    echo "restore data corrupted $src_digest != $restored_digest"
    exit -1
  fi
}

# vim: et sw=2
