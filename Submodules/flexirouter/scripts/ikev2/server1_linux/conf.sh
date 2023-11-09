cp ipsec.conf /etc
cp ipsec.secrets /etc

ip link add name loop1 type dummy
ip link set dev loop1 up
ip address add 192.168.3.1/24 dev loop1

ipsec restart




