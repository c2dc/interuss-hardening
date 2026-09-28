#!/bin/sh
# shellcheck disable=SC2086

set -e

# This startup script is meant to be invoked from within a Docker container
# started by docker-compose.yaml, not on a local system.

DEBUG_ON=${1:-0}
JWT_AUDIENCES="localhost,host.docker.internal,dss.lb.localutm,${JWT_AUDIENCES}"

# ---------------------------------------------------------------------------
# TLS front: core-service listens only on loopback; nginx terminates HTTPS with
# a vault-issued cert on :443 and plain :80 is redirected (except the localhost
# health check). Clients reach the DSS at https://dss<node>.uss<idx>.localutm.
# ---------------------------------------------------------------------------
apk add --no-cache nginx >/dev/null 2>&1 || { echo "core_service: failed to install nginx" >&2; exit 1; }
mkdir -p /run/nginx
rm -f /etc/nginx/http.d/default.conf
cat > /etc/nginx/http.d/dss.conf <<NGINX
server {
    listen 80 default_server;
    location = /healthy { proxy_pass http://127.0.0.1:8080; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl default_server;
    ssl_certificate     /secrets/dss-tls/uss${USS_IDX:?}/server.crt;
    ssl_certificate_key /secrets/dss-tls/uss${USS_IDX:?}/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    client_max_body_size 16m;

    # RFC 8705 sender-constrained tokens: accept a client cert (same OpenBao CA
    # trusted by the OAuth token endpoint) when offered, but don't hard-require
    # one at the TLS layer -- rejection for a missing/mismatched cert happens at
    # the app layer below (auth_request), which gives a clear 403 instead of a
    # raw TLS handshake failure.
    ssl_client_certificate /secrets/oauth/clients/ca.crt;
    ssl_verify_client      optional;
    ssl_verify_depth       2;

    # Internal-only: checks that the bearer token on the real request is bound
    # (cnf.x5t#S256) to the certificate presented on this same connection.
    # oauth-signer is now network-isolated (oauth_backend_network) and no longer
    # reachable from the ecosystem network, so we reach its checker THROUGH the
    # oauth front (which relays to it) rather than hitting :8081 directly.
    location = /_verify_cnf {
        internal;
        proxy_pass https://oauth.authority.localutm:8443/verify-cnf;
        proxy_ssl_server_name on;
        proxy_pass_request_body off;
        proxy_set_header Content-Length    "";
        proxy_set_header Authorization     \$http_authorization;
        proxy_set_header X-SSL-Client-Cert \$ssl_client_escaped_cert;
    }

    location / {
        auth_request /_verify_cnf;
        # auth_request discards the subrequest's own body on failure, which
        # would otherwise leave the client with an empty response -- DSS's own
        # API contract guarantees a JSON ErrorResponse body on every 4xx, so
        # rejections here need to keep that contract too (verified against the
        # existing "Unauthorized requests return the proper error message body"
        # conformance check, ASTM F3548 DSS0005,5).
        error_page 401 = @cnf_401;
        error_page 403 = @cnf_403;
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              \$host;
        proxy_set_header X-Forwarded-For   \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }

    location @cnf_401 {
        internal;
        default_type application/json;
        return 401 '{"message":"missing or invalid bearer token"}';
    }
    location @cnf_403 {
        internal;
        default_type application/json;
        return 403 '{"message":"client certificate missing or does not match token binding (RFC 8705)"}';
    }
}
NGINX
nginx

# apply netem config for intra/inter-USS subnets, if requested
if [ -n "$INTRA_USS_NETEM_CONF" ] || [ -n "$INTER_USS_NETEM_CONF" ]; then
  apk add iproute2-tc

  # Get the first two bytes of the address (/16)
  NETEM_NET_PREFIX=$(echo "$INTER_USS_SUBNET" | cut -d. -f1-2)
  # List IP addresses to find the correct interface
  NETEM_IFACE=$(ip -o -4 addr show | grep -F " inet ${NETEM_NET_PREFIX}." | head -n 1 | awk '{print $2}')
  if [ -z "$NETEM_IFACE" ]; then
    echo "ERROR: no interface found in subnet ${INTER_USS_SUBNET}, refusing to start without traffic shaping" >&2
    exit 1
  fi
  echo "Applying netem on interface ${NETEM_IFACE}"

  # create handle on the USS network interface
  tc qdisc add dev "$NETEM_IFACE" root handle 1: prio

  if [ -n "$INTRA_USS_NETEM_CONF" ]; then
    tc qdisc add dev "$NETEM_IFACE" parent 1:2 handle 30: netem $INTRA_USS_NETEM_CONF
    tc filter add dev "$NETEM_IFACE" parent 1:0 protocol ip prio 1 u32 match ip dst "$INTRA_USS_SUBNET" flowid 1:2
  fi

  if [ -n "$INTER_USS_NETEM_CONF" ]; then
    tc qdisc add dev "$NETEM_IFACE" parent 1:3 handle 31: netem $INTER_USS_NETEM_CONF
    tc filter add dev "$NETEM_IFACE" parent 1:0 protocol ip prio 2 u32 match ip dst "$INTER_USS_SUBNET" flowid 1:3
  fi
fi

# POSIX compliant tests to select the datastore backend.
if [ "${COMPOSE_PROFILES#*"ybdb"}" != "${COMPOSE_PROFILES}" ]; then
  echo "Using Yugabyte"
  DATASTORE_CONNECTION="-datastore_host ${DATASTORE_HOST} -datastore_user yugabyte --datastore_port 5433"
  DB_PORT=5433
elif [ "${COMPOSE_PROFILES#*"raft"}" != "${COMPOSE_PROFILES}" ]; then
  echo "Using raft"
  DATASTORE_CONNECTION="-store_type raft -raft_node_id=${RAFT_ID} -rid_raft_peers=${RID_RAFT_NODES} -scd_raft_peers=${SCD_RAFT_NODES} -aux_raft_peers=${AUX_RAFT_NODES} -raft_datadir /raftdata"
  DB_PORT=
else
  echo "Using CockroachDB"
  # The cluster runs in secure mode: connect over TLS and authenticate with the
  # root client certificate at /secrets/certs (ca.crt, client.root.crt,
  # client.root.key), issued by the OpenBao vault (docker-compose.secrets.yaml).
  DATASTORE_CONNECTION="-datastore_host ${DATASTORE_HOST} -datastore_ssl_mode verify-full -datastore_ssl_dir /secrets/certs -datastore_user root"
  DB_PORT=26257
fi

# raft has no external datastore to wait for.
if [ -n "$DB_PORT" ]; then
  echo "Waiting for datastore ${DATASTORE_HOST}:${DB_PORT}..."
  until nc -z -w 2 "${DATASTORE_HOST}" "${DB_PORT}" 2>/dev/null; do
    echo "Datastore ${DATASTORE_HOST}:${DB_PORT} is not available yet, sleeping..."
    sleep 2
  done
  echo "Datastore ${DATASTORE_HOST}:${DB_PORT} is online!"
fi

if [ "$DEBUG_ON" = "1" ]; then
  echo "Debug Mode: on"

  # Linter is disabled to properly unwrap $DATASTORE_CONNECTION.
  # shellcheck disable=SC2086
  dlv --headless --listen=:4000 --api-version=2 --accept-multiclient exec --continue /usr/bin/core-service -- \
  ${DATASTORE_CONNECTION} \
  -jwks_endpoint https://oauth.authority.localutm:8443/.well-known/jwks.json \
  -jwks_key_ids "$(cat /secrets/oauth/kid)" \
  -jwks_refresh_interval 30s \
  -log_format console \
  -dump_requests \
  -addr 127.0.0.1:8080 \
  -accepted_jwt_audiences ${JWT_AUDIENCES} \
  -enable_scd \
  -locality local_dev_uss${USS_IDX:?}_node${USS_NODE_IDX:?} \
  -public_endpoint https://dss${USS_NODE_IDX:?}.uss${USS_IDX:?}.localutm \
  ${CORE_SERVICE_EXTRA_FLAGS}
else
  echo "Debug Mode: off"

  # Linter is disabled to properly unwrap $DATASTORE_CONNECTION.
  # shellcheck disable=SC2086
  /usr/bin/core-service \
  ${DATASTORE_CONNECTION} \
  -jwks_endpoint https://oauth.authority.localutm:8443/.well-known/jwks.json \
  -jwks_key_ids "$(cat /secrets/oauth/kid)" \
  -jwks_refresh_interval 30s \
  -log_format console \
  -dump_requests \
  -addr 127.0.0.1:8080 \
  -accepted_jwt_audiences ${JWT_AUDIENCES} \
  -enable_scd \
  -locality local_dev_uss${USS_IDX:?}_node${USS_NODE_IDX:?} \
  -public_endpoint https://dss${USS_NODE_IDX:?}.uss${USS_IDX:?}.localutm \
  ${CORE_SERVICE_EXTRA_FLAGS}
fi
