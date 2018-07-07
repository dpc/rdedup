#!/bin/bash

version=1.0.16
wget https://github.com/jedisct1/libsodium/releases/download/$version/libsodium-$version.tar.gz
tar xvfz libsodium-$version.tar.gz
cd libsodium-$version
./configure --prefix=$HOME/installed_libsodium
make
make install
cd ..
