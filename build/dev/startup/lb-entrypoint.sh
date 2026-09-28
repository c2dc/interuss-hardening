#!/bin/sh
set -e

# TLS-passthrough load balancer for the DSS instances (mode tcp).
#
# The DSS enforces RFC 8705 sender-constrained tokens: every request must
# present the same client certificate the token was bound to. If this LB
# terminated TLS (mode http) and re-originated to the DSS, the client cert would
# be stripped and every authenticated call would 403. So we operate at L4 —
# haproxy forwards the raw TLS stream to a DSS :443, which terminates the
# client's mutual-TLS handshake itself and sees the real client certificate.
#
# Each DSS server certificate carries `dss.lb.localutm` as a SAN
# (openbao-init.sh), so whichever backend a client is balanced to presents a
# certificate valid for the name the client dialed.

cat > /tmp/haproxy.cfg <<'EOF'
global
    maxconn 1024

defaults
    mode tcp
    timeout connect 5s
    timeout client 30s
    timeout server 30s

resolvers docker
    nameserver dns1 127.0.0.11:53

frontend dss_in
    bind *:443
    default_backend dss_pool

backend dss_pool
    balance roundrobin
EOF

i=1
while [ "$i" -le "$NUM_USS" ]; do
  j=1
  while [ "$j" -le "$NUM_NODES" ]; do
    echo "    server dss${j}_${i} dss${j}.uss${i}.localutm:443 check resolvers docker init-addr none"
    j=$((j+1))
  done
  i=$((i+1))
done >> /tmp/haproxy.cfg

exec haproxy -f /tmp/haproxy.cfg
