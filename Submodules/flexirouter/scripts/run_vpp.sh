#!/bin/bash

SCRIPTS_PATH=`pwd`/scripts
DEVBIND_PATH=vpp/extras/vpp_config/scripts

mv /etc/netplan /etc/netplan.old
mkdir /etc/netplan
cp $SCRIPTS_PATH/50-cloud-init.baseline.yaml /etc/netplan

/sbin/modprobe uio_pci_generic

ip link set dev enp0s3 down
ip link set dev enp0s8 down

cd vpp

gdb --args ./build-root/build-vpp_debug-native/vpp/bin/vpp -c ../scripts/startup.conf

cd -

python $DEVBIND_PATH/dpdk-devbind.py -b e1000 00:03.0 00:08.0

rm -rf /etc/netplan
mv /etc/netplan.old /etc/netplan
netplan apply
