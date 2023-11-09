ipsec pki --gen  > server-key.der
ipsec pki --self --in server-key.der --dn "CN=vpp.home" > server-cert.der
openssl x509 -inform DER -in server-cert.der -out server-cert.pem
openssl rsa -inform DER -in server-key.der -out server-key.pem

ipsec pki --gen  > client-key.der
ipsec pki --self --in client-key.der --dn "CN=roadwarrior.vpn.example.com" > client-cert.der
openssl x509 -inform DER -in client-cert.der -out client-cert.pem
openssl rsa -inform DER -in client-key.der -out client-key.pem
