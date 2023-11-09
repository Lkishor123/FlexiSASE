vppctl exec `pwd`/gre.txt
ifconfig vpp4 10.100.0.6 netmask 255.255.255.254

ip route add 10.10.10.0/24 via 10.100.0.7
