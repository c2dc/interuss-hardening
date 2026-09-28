#!/bin/sh
# Bootstrap the local ecosystem's secret material in OpenBao (dev mode):
#
#   * a PKI secrets engine that IS the CockroachDB cluster CA — the CA private
#     key is generated inside OpenBao and is never returned or written to disk;
#   * a KV v2 engine holding the OAuth signing key and the uss_qualifier
#     message-signing keypair, seeded from build/test-certs/ (mounted read-only
#     at /seed).
#
# It then materialises what the (vault-unaware) ecosystem containers consume into
# /secrets, which is bind-mounted to build/dev/dss-secrets/ on the host and
# mounted read-only into the per-USS stacks by docker-compose.yaml.
#
# Invoked once by the `openbao-init` service in docker-compose.secrets.yaml.

set -eu

apk add --no-cache jq openssl >/dev/null 2>&1 || { echo "openbao-init: could not install jq/openssl" >&2; exit 1; }

export BAO_ADDR="${BAO_ADDR:-http://vault.localutm:8200}"
export BAO_TOKEN="${BAO_TOKEN:?BAO_TOKEN (OpenBao dev root token) must be set}"

NUM_USS="${NUM_USS:-2}"
NUM_NODES="${NUM_NODES:-1}"

echo "openbao-init: waiting for ${BAO_ADDR} ..."
tries=0
until bao status >/dev/null 2>&1; do
  tries=$((tries + 1))
  [ "$tries" -gt 60 ] && { echo "openbao-init: OpenBao did not become ready" >&2; exit 1; }
  sleep 1
done

CERTS=/secrets/certs
mkdir -p "$CERTS" /secrets/auth2 /secrets/messagesigning

# ---------------------------------------------------------------------------
# PKI — the CockroachDB cluster CA.
# pki/root/generate/internal keeps the private key inside OpenBao; only the
# certificate is ever emitted.
# ---------------------------------------------------------------------------
if ! bao secrets list -format=json | jq -e '."pki/"' >/dev/null 2>&1; then
  bao secrets enable -path=pki -max-lease-ttl=87600h pki >/dev/null
  bao write -field=certificate pki/root/generate/internal \
    common_name="InterUSS Local CRDB CA" issuer_name="crdb-ca" \
    key_type=rsa key_bits=2048 ttl=87600h > "${CERTS}/ca.crt"
  bao write pki/roles/crdb \
    allow_any_name=true enforce_hostnames=false \
    allow_localhost=true allow_ip_sans=true \
    client_flag=true server_flag=true \
    key_type=rsa key_bits=2048 ttl=8760h max_ttl=8760h >/dev/null
fi

# SAN list for the shared node certificate: every possible DB node hostname / IP
# for the current NUM_USS x NUM_NODES topology (mirrors the deterministic IPs
# assigned in run_locally.sh: 172.27.<uss>.<128|node>).
ALT="localhost,node"
IPS="127.0.0.1"
i=1
while [ "$i" -le "$NUM_USS" ]; do
  ALT="${ALT},datastore.uss${i}.localutm"
  j=1
  while [ "$j" -le "$NUM_NODES" ]; do
    ALT="${ALT},db${j}.uss${i}.localutm"
    IPS="${IPS},172.27.${i}.$((128 | j))"
    j=$((j + 1))
  done
  i=$((i + 1))
done

echo "openbao-init: issuing node cert (SANs: ${ALT} ; IPs: ${IPS})"
bao write -format=json pki/issue/crdb \
  common_name="node" alt_names="${ALT}" ip_sans="${IPS}" ttl=8760h > /tmp/node.json
jq -r '.data.certificate' /tmp/node.json > "${CERTS}/node.crt"
jq -r '.data.private_key' /tmp/node.json > "${CERTS}/node.key"

echo "openbao-init: issuing client.root cert"
bao write -format=json pki/issue/crdb \
  common_name="root" exclude_cn_from_sans=true ttl=8760h > /tmp/root.json
jq -r '.data.certificate' /tmp/root.json > "${CERTS}/client.root.crt"
jq -r '.data.private_key' /tmp/root.json > "${CERTS}/client.root.key"
rm -f /tmp/node.json /tmp/root.json

# ---------------------------------------------------------------------------
# KV v2 — static ecosystem secrets, seeded from build/test-certs (/seed, ro).
# ---------------------------------------------------------------------------
if ! bao secrets list -format=json | jq -e '."secret/"' >/dev/null 2>&1; then
  bao secrets enable -path=secret -version=2 kv >/dev/null
fi

bao kv put secret/auth2 \
  key=@/seed/auth2.key \
  pem=@/seed/auth2.pem >/dev/null

bao kv put secret/messagesigning \
  priv=@/seed/messagesigning/mock_faa_priv.pem \
  pub_der_b64="$(base64 /seed/messagesigning/mock_faa_pub.der | tr -d '\n')" >/dev/null

# Materialise for containers that read files rather than talk to the vault.
bao kv get -field=key secret/auth2 > /secrets/auth2/auth2.key
bao kv get -field=pem secret/auth2 > /secrets/auth2/auth2.pem
bao kv get -field=priv secret/messagesigning > /secrets/messagesigning/mock_faa_priv.pem
bao kv get -field=pub_der_b64 secret/messagesigning | base64 -d > /secrets/messagesigning/mock_faa_pub.der

# ---------------------------------------------------------------------------
# CockroachDB store encryption-at-rest (AES-256, CCL --enterprise-encryption).
# Key file format is CockroachDB's own: 32-byte random key ID + N-byte key
# (32 bytes => AES-256), which is exactly `openssl rand 64` — no need for the
# `cockroach` binary in this (openbao-based) init container. One key for the
# whole logical cluster (every USS/node), mirroring the single shared CA above.
# Fully functional without a CockroachDB Cloud license — CockroachDB never
# disables working encryption for licensing, it only logs a warning after a
# 7-day unlicensed grace period.
# ---------------------------------------------------------------------------
mkdir -p /secrets/crdb-encryption
if ! bao kv get secret/crdb-encryption >/dev/null 2>&1; then
  bao kv put secret/crdb-encryption key_b64="$(openssl rand 64 | base64 | tr -d '\n')" >/dev/null
fi
bao kv get -field=key_b64 secret/crdb-encryption | base64 -d > /secrets/crdb-encryption/aes-256.key

# ---------------------------------------------------------------------------
# MinIO — the WORM log store. TLS cert issued from the same PKI; MinIO root
# credentials and Vector's write-only access key are generated here, kept in KV,
# and materialised for the minio / minio-init / vector services.
# ---------------------------------------------------------------------------
mkdir -p /secrets/minio

bao write -format=json pki/issue/crdb \
  common_name="minio.localutm" alt_names="localhost" ip_sans="127.0.0.1" ttl=8760h > /tmp/minio.json
jq -r '.data.certificate' /tmp/minio.json > /secrets/minio/public.crt
jq -r '.data.private_key' /tmp/minio.json > /secrets/minio/private.key
cp "${CERTS}/ca.crt" /secrets/minio/ca.crt
rm -f /tmp/minio.json

if ! bao kv get secret/minio >/dev/null 2>&1; then
  # MinIO service-account secret keys must be 8-40 chars, so vector_secret /
  # chainer_secret are 32 hex chars; the root password has no such limit.
  # kms_key_secret_b64 is a 32-byte (AES-256) key for MinIO's built-in
  # single-key KMS (SSE-S3 default bucket encryption) — see the minio-init.sh
  # `mc encrypt set` call. chainer_key/chainer_secret are for the log-chainer
  # service — read-only on the whole bucket,
  # write-only on logs/checkpoints/*, provisioned in minio-init.sh.
  bao kv put secret/minio \
    root_user="localadmin" \
    root_password="$(openssl rand -hex 24)" \
    vector_key="vector-log-writer" \
    vector_secret="$(openssl rand -hex 16)" \
    kms_key_name="worm-logs-master" \
    kms_key_secret_b64="$(openssl rand -base64 32)" \
    chainer_key="log-chainer" \
    chainer_secret="$(openssl rand -hex 16)" >/dev/null
fi

bao kv get -field=root_user      secret/minio > /secrets/minio/root_user
bao kv get -field=root_password  secret/minio > /secrets/minio/root_password
bao kv get -field=vector_key     secret/minio > /secrets/minio/vector_key
bao kv get -field=vector_secret  secret/minio > /secrets/minio/vector_secret
bao kv get -field=chainer_key    secret/minio > /secrets/minio/chainer_key
bao kv get -field=chainer_secret secret/minio > /secrets/minio/chainer_secret

# MinIO's MINIO_KMS_SECRET_KEY_FILE format: "<key-name>:<base64 32-byte key>".
printf '%s:%s' "$(bao kv get -field=kms_key_name secret/minio)" \
  "$(bao kv get -field=kms_key_secret_b64 secret/minio)" > /secrets/minio/kms_key

# ---------------------------------------------------------------------------
# OAuth / JWT hardening:
#   * a fresh RS256 signing key (never in git); its public half is served as
#     JWKS by the oauth-signer service and consumed by core-service
#     (-jwks_endpoint) and mock_uss.
#   * a client-auth PKI role + the CA so the token endpoint can require mutual
#     TLS; the token `sub` is the verified client-cert CN.
#   * server certs for the TLS fronts (token endpoint, DSS, mock_uss).
# ---------------------------------------------------------------------------
mkdir -p /secrets/oauth/clients /secrets/dss-tls /secrets/mock-tls

issue_pki() { # $1=role  $2=common_name  $3=out_dir  $4=cert_name  $5=key_name  [$6=extra bao args]
  mkdir -p "$3"
  # shellcheck disable=SC2086
  bao write -format=json "pki/issue/$1" \
    common_name="$2" ttl=8760h ${6:-} > /tmp/pki.json
  jq -r '.data.certificate' /tmp/pki.json > "$3/$4"
  jq -r '.data.private_key' /tmp/pki.json > "$3/$5"
  rm -f /tmp/pki.json
}

# JWT signing key + key id, plus the front<->signer shared secret (X-Proxy-Auth)
# that lets oauth-signer prove a /token request actually traversed the mTLS
# front.
if ! bao kv get secret/oauth >/dev/null 2>&1; then
  bao kv put secret/oauth \
    priv="$(openssl genrsa 2048 2>/dev/null)" \
    kid="$(openssl rand -hex 8)" \
    proxy_secret="$(openssl rand -hex 32)" >/dev/null
fi
bao kv get -field=priv secret/oauth > /secrets/oauth/signing.key
bao kv get -field=kid  secret/oauth > /secrets/oauth/kid
bao kv get -field=proxy_secret secret/oauth > /secrets/oauth/proxy_secret

# Client-auth role + the CA that the token endpoint verifies clients against.
bao read pki/roles/oauth-client >/dev/null 2>&1 || bao write pki/roles/oauth-client \
  allow_any_name=true enforce_hostnames=false allow_bare_domains=true \
  client_flag=true server_flag=false key_type=rsa key_bits=2048 \
  ttl=8760h max_ttl=8760h >/dev/null
cp "${CERTS}/ca.crt" /secrets/oauth/clients/ca.crt

for p in uss1 uss2 uss3 uss4 uss6 uss_qualifier uss_qualifier_2; do
  issue_pki oauth-client "$p" "/secrets/oauth/clients/$p" crt key "exclude_cn_from_sans=true"
done

# Server cert for the token endpoint (nginx).
issue_pki crdb oauth.authority.localutm /secrets/oauth server.crt server.key "alt_names=localhost ip_sans=127.0.0.1"

# Server cert per USS for the DSS TLS front (nginx sidecar).
#
# The SAN list must cover EVERY node hostname of that USS, not just node 1: the
# DSS container's hostname is dss${USS_NODE_IDX}.uss${USS_IDX}.localutm and
# core_service.sh advertises exactly that as -public_endpoint, while all nodes of a
# USS share this one certificate (/secrets/dss-tls/uss${i}). This previously
# hardcoded `dss1.`, so at NUM_NODES>1 every node after the first served a
# certificate invalid for its own name — latent, because nothing in the standard
# environment dials a node ≥2 by hostname. Same nested NUM_USS x NUM_NODES loop the
# CockroachDB node cert above already uses.
i=1
while [ "$i" -le "$NUM_USS" ]; do
  DSS_ALT="dss.lb.localutm,localhost"
  j=1
  while [ "$j" -le "$NUM_NODES" ]; do
    DSS_ALT="${DSS_ALT},dss${j}.uss${i}.localutm"
    j=$((j + 1))
  done
  echo "openbao-init: issuing DSS cert for uss${i} (SANs: ${DSS_ALT})"
  issue_pki crdb "dss1.uss${i}.localutm" "/secrets/dss-tls/uss${i}" server.crt server.key \
    "alt_names=${DSS_ALT} ip_sans=127.0.0.1"
  i=$((i + 1))
done

# Server certs for the mock_uss hostnames (gunicorn TLS; separate compose).
for h in scdsc.uss1.localutm scdsc.uss2.localutm geoawareness.uss1.localutm \
         v22a.ridsp.uss1.localutm v22a.riddp.uss1.localutm \
         v19.ridsp.uss2.localutm v19.riddp.uss3.localutm \
         tracer.uss4.localutm scdsc.log.uss6.localutm; do
  issue_pki crdb "$h" "/secrets/mock-tls/$h" server.crt server.key "alt_names=localhost ip_sans=127.0.0.1"
done

# ---------------------------------------------------------------------------
# Permissions — CockroachDB (and MinIO) refuse group/other-readable key files.
# All consumers run as root (the harness runs under sudo), so 600 keys are fine.
# ---------------------------------------------------------------------------
find /secrets/oauth /secrets/dss-tls /secrets/mock-tls -type d -exec chmod 700 {} +
find /secrets/oauth /secrets/dss-tls /secrets/mock-tls -type f \( -name '*.key' -o -name key \) -exec chmod 600 {} +
chmod 600 /secrets/oauth/signing.key /secrets/oauth/proxy_secret
find /secrets/oauth /secrets/dss-tls /secrets/mock-tls -type f \( -name '*.crt' -o -name crt -o -name kid \) -exec chmod 644 {} +

chmod 700 /secrets /secrets/certs /secrets/auth2 /secrets/messagesigning /secrets/minio /secrets/crdb-encryption
chmod 600 "${CERTS}/node.key" "${CERTS}/client.root.key" \
  /secrets/auth2/auth2.key /secrets/messagesigning/mock_faa_priv.pem \
  /secrets/minio/private.key \
  /secrets/minio/root_user /secrets/minio/root_password \
  /secrets/minio/vector_key /secrets/minio/vector_secret \
  /secrets/minio/chainer_key /secrets/minio/chainer_secret \
  /secrets/minio/kms_key /secrets/crdb-encryption/aes-256.key
chmod 644 "${CERTS}/ca.crt" "${CERTS}/node.crt" "${CERTS}/client.root.crt" \
  /secrets/auth2/auth2.pem /secrets/messagesigning/mock_faa_pub.der \
  /secrets/minio/public.crt /secrets/minio/ca.crt

echo "openbao-init: done — secret material provisioned to /secrets"
