#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset

my_dir="$(dirname "$0")"
source "$my_dir/e2e-common.sh"

cargo build --release || exit 1

# init
dd if=/dev/urandom of=$test_data_path bs=1024 count=$(($RANDOM % 128))

for chunking in $chunking_list  ; do
  for compression in $compression_list ; do
    for encryption in $encryptiton_list ; do
      for hashing in $hashing_list ; do
        chunk_size=""
        nesting=""
        run_e2e_test "$chunking" "$chunk_size" "$compression" "$encryption" "$hashing" "$nesting"
      done
    done
  done
done

# cleanup
rm $test_data_path

unset RDEDUP_DIR
unset RDEDUP_PASSPHRASE

# vim: et sw=2
