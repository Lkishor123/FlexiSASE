vppctl exec `pwd`/ipip.txt

vppctl exec `pwd`/vxlan.txt

ifconfig vpp2 10.100.0.7 netmask 255.255.255.254

vppctl exec `pwd`/ipsec.txt
