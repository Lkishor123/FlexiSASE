openssl req -new -newkey rsa:4096 -days 10 -nodes -x509 -subj "/CN=vpp.home" -keyout server-key.pem -out server-cert.pem

openssl req -new -newkey rsa:4096 -days 10 -nodes -x509 -subj "/CN=roadwarrior.vpn.example.com" -keyout client-key.pem -out client-cert.pem
