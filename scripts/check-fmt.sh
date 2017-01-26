#!/bin/bash
~/.cargo/bin/cargo-fmt
cd lib && ~/.cargo/bin/cargo-fmt && cd ..
git diff > fmt-diff.patch
if [ -s fmt-diff.patch ]; then
  rm fmt-diff.patch
  echo "rustfmt found formatting issues"
  exit -1
fi
rm fmt-diff.patch
