#!/bin/bash

apt-get install -y libgcrypt11-dev flex bison qtbase5-dev qttools5-dev-tools qttools5-dev qtmultimedia5-dev libqt5svg5-dev libpcap-dev qt5-default

git clone https://code.wireshark.org/review/wireshark

cd wireshark
mkdir build
cd build
cmake -G Ninja ../
ninja -j 8
ninja install
cd -
cd -
rm -rf wireshark


