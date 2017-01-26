#!/bin/bash

wget https://github.com/jedisct1/libsodium/releases/download/1.0.8/libsodium-1.0.8.tar.gz
tar xvfz libsodium-1.0.8.tar.gz
cd libsodium-1.0.8
./configure --prefix=$HOME/installed_libsodium
make
make install
cd ..
