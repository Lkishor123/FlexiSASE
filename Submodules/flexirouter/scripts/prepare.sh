#!/bin/bash

apt-get install -y python-cffi python-pycparser python-ply build-essential

cd vpp

make install-dep
make install-ext-deps

cd -


