#!/bin/bash
~/.cargo/bin/cargo-fmt
cd lib && ~/.cargo/bin/cargo-fmt && cd ..
git diff > fmt-diff.patch
if [ -s fmt-diff.patch ]; then
  echo "rustfmt found formatting issues"
  cat fmt-diff.patch
  rm fmt-diff.patch
  exit -1
fi
rm fmt-diff.patch
exit 0
