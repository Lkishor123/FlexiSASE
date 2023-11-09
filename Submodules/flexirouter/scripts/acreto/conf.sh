vppctl exec `pwd`/ipsec.txt

ifconfig vpp2 10.100.0.7 netmask 255.255.255.254

echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/vpp2/rp_filter

vppctl exec `pwd`/l3xc.txt





