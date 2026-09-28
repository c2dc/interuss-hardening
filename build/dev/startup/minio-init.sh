#!/bin/sh
# Provision the WORM log bucket in MinIO:
#   * bucket created with S3 Object Lock, default retention COMPLIANCE / 3 days
#     (no actor can overwrite or delete a locked object version while MinIO runs);
#   * versioning on (an overwrite just adds another locked version);
#   * default SSE-S3 encryption at rest (data-at-rest encryption via the
#     vault-issued KMS master key the `minio` service registered);
#   * a 7-day lifecycle cap so storage stays bounded;
#   * a write-only service account for Vector (s3:PutObject on logs/* only);
#   * a list/read + checkpoints-only-write service account for the log-chainer.
#
# Run once by the `minio-init` service in docker-compose.secrets.yaml after the
# `minio` service is healthy. /secrets/minio is bind-mounted read-write so the
# effective Vector credentials can be written where the `vector` service reads
# them.

set -eu

S=/secrets/minio
ALIAS=worm
ENDPOINT="https://minio.localutm:9000"
BUCKET=logs

ROOT_USER=$(cat "$S/root_user")
ROOT_PW=$(cat "$S/root_password")
VECTOR_KEY=$(cat "$S/vector_key")
VECTOR_SECRET=$(cat "$S/vector_secret")
CHAINER_KEY=$(cat "$S/chainer_key")
CHAINER_SECRET=$(cat "$S/chainer_secret")

# Trust the Vault-issued MinIO certificate (so mc runs without --insecure).
mkdir -p /root/.mc/certs/CAs
cp "$S/ca.crt" /root/.mc/certs/CAs/vault-ca.crt

# Env-based alias: unlike `mc alias set`, this does not probe the endpoint at
# definition time, so we can define it before MinIO is listening and just retry.
export MC_HOST_worm="https://${ROOT_USER}:${ROOT_PW}@minio.localutm:9000"

echo "minio-init: waiting for MinIO ..."
tries=0
until mc ls "$ALIAS" >/dev/null 2>&1; do
  tries=$((tries + 1))
  if [ "$tries" -gt 90 ]; then
    echo "minio-init: MinIO did not become ready:" >&2
    mc ls "$ALIAS" || true
    exit 1
  fi
  sleep 2
done

# Object Lock can only be enabled at bucket creation.
mc mb --with-lock --ignore-existing "$ALIAS/$BUCKET"
mc version enable "$ALIAS/$BUCKET" >/dev/null 2>&1 || true
mc retention set --default COMPLIANCE 3d "$ALIAS/$BUCKET"

# Data-at-rest encryption: every object written from here on is transparently
# AES-256-GCM encrypted server-side (SSE-S3), keyed by the vault-issued KMS
# master key registered via MINIO_KMS_SECRET_KEY_FILE on the `minio` service.
mc encrypt set sse-s3 "$ALIAS/$BUCKET"

# Bound storage. MinIO will not expire an object still under a retention lock, so
# the effective minimum lifetime remains the 3-day COMPLIANCE window. Clear any
# existing rules first so re-runs (the bucket survives `stop`/`restart`) don't
# stack duplicates.
mc ilm rule remove --all --force "$ALIAS/$BUCKET" >/dev/null 2>&1 || true
mc ilm rule add "$ALIAS/$BUCKET" --expire-days 7 --noncurrent-expire-days 7 2>/dev/null \
  || mc ilm add "$ALIAS/$BUCKET" --expiry-days 7 2>/dev/null \
  || echo "minio-init: WARNING could not set a lifecycle rule"

# Least privilege: Vector may only PutObject into logs/*.
cat > /tmp/log-writer.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::logs/*"] }
  ]
}
EOF

SVC_OK=0
if mc admin policy create "$ALIAS" log-writer /tmp/log-writer.json >/dev/null 2>&1 \
   || mc admin policy add "$ALIAS" log-writer /tmp/log-writer.json >/dev/null 2>&1; then
  if mc admin user svcacct add "$ALIAS" "$ROOT_USER" \
       --access-key "$VECTOR_KEY" --secret-key "$VECTOR_SECRET" \
       --policy /tmp/log-writer.json >/dev/null 2>&1; then
    SVC_OK=1
    echo "minio-init: created write-only service account for Vector"
  fi
fi
rm -f /tmp/log-writer.json

# Write the credentials Vector will actually use. Normally the restricted service
# account; if this MinIO build lacks svcacct/policy support, fall back to root so
# shipping still works (WORM is still enforced by the bucket lock).
if [ "$SVC_OK" = "1" ]; then
  printf '%s' "$VECTOR_KEY"    > "$S/vector_key"
  printf '%s' "$VECTOR_SECRET" > "$S/vector_secret"
else
  echo "minio-init: WARNING svcacct unavailable — Vector will use MinIO root credentials"
  printf '%s' "$ROOT_USER" > "$S/vector_key"
  printf '%s' "$ROOT_PW"   > "$S/vector_secret"
fi
chmod 600 "$S/vector_key" "$S/vector_secret"

# Least privilege: the log-chainer may list
# and read the whole bucket (it needs to see every object to build each
# checkpoint's manifest, and to read back its own prior checkpoints to resume
# the chain) but may only ever write into logs/checkpoints/* — it cannot write
# where Vector writes, and — like every other credential, including root —
# cannot modify or delete anything at all once written (Object Lock applies
# regardless of credential).
#
# GetBucketObjectLockConfiguration (bucket ARN, not logs/*) lets the chainer read
# the bucket's *default* retention policy and commit it into each checkpoint, so a
# COMPLIANCE→GOVERNANCE downgrade becomes detectable. It is
# strictly read-only and reveals nothing beyond what `make show-worm-logs` already
# prints. The matching Put* action is deliberately NOT granted: writing the lock
# configuration is exactly the privilege a retention-downgrade attack needs, and handing it to a
# long-running `restart: always` service to let it self-repair would give any
# compromise of that service the very primitive the check exists to detect.
cat > /tmp/log-chainer.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::logs"] },
    { "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::logs/*"] },
    { "Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::logs/checkpoints/*"] },
    { "Effect": "Allow", "Action": ["s3:GetBucketObjectLockConfiguration"], "Resource": ["arn:aws:s3:::logs"] }
  ]
}
EOF

SVC_OK=0
if mc admin policy create "$ALIAS" log-chainer /tmp/log-chainer.json >/dev/null 2>&1 \
   || mc admin policy add "$ALIAS" log-chainer /tmp/log-chainer.json >/dev/null 2>&1; then
  if mc admin user svcacct add "$ALIAS" "$ROOT_USER" \
       --access-key "$CHAINER_KEY" --secret-key "$CHAINER_SECRET" \
       --policy /tmp/log-chainer.json >/dev/null 2>&1; then
    SVC_OK=1
    echo "minio-init: created list/read + checkpoints-only-write service account for log-chainer"
  fi
fi
rm -f /tmp/log-chainer.json

if [ "$SVC_OK" = "1" ]; then
  printf '%s' "$CHAINER_KEY"    > "$S/chainer_key"
  printf '%s' "$CHAINER_SECRET" > "$S/chainer_secret"
else
  echo "minio-init: WARNING svcacct unavailable — log-chainer will use MinIO root credentials"
  printf '%s' "$ROOT_USER" > "$S/chainer_key"
  printf '%s' "$ROOT_PW"   > "$S/chainer_secret"
fi
chmod 600 "$S/chainer_key" "$S/chainer_secret"

echo "minio-init: done — bucket '$BUCKET' is WORM (Object Lock, COMPLIANCE 3d), versioned"
