#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset

my_dir="$(dirname "$0")"
source "$my_dir/e2e-common.sh"

cargo build --release || exit 1

# init
dd if=/dev/urandom of=$test_data_path bs=1024 count=$(($RANDOM % 128 + $RANDOM % 128))

for chunking in $chunking_list  ; do
  for chunk_size in 1K 512K 16M ; do
    for compression in $compression_list ; do
      for encryption in $encryptiton_list ; do
        for hashing in $hashing_list ; do
          for nesting in 0 1 12 ; do
            run_e2e_test "weak" "$chunking" "$chunk_size" "$compression" "$encryption" "$hashing" "$nesting"
          done
        done
      done
    done
  done
done

# cleanup
rm $test_data_path

unset RDEDUP_DIR
unset RDEDUP_PASSPHRASE

# vim: et sw=2
