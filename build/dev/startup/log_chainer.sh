#!/bin/sh
# Periodic hash-chain checkpointing over the WORM log bucket.
#
# Object Lock (minio-init.sh) already stops any credential -- including MinIO
# root -- from modifying or deleting a stored log object. What it does not
# give you is a way to *prove*, independent of trusting MinIO's own internal
# bookkeeping, that the sequence of objects is complete and unaltered. This
# script closes that gap: every CHECK_INTERVAL seconds it lists the whole
# bucket, and writes a new checkpoint into logs/checkpoints/ that commits to
# the exact object set (key + size + ETag, as MinIO itself reports them) seen
# at that moment, chained to the previous checkpoint:
#
#   chain_hash_n = sha256(chain_hash_{n-1} || body_n)
#
# Each checkpoint's body begins with a record of the bucket's observed *default*
# Object Lock configuration, e.g. `retention COMPLIANCE 3DAYS`, followed by the
# manifest. That default configuration is mutable by MinIO root (inherent S3
# behaviour: only per-object COMPLIANCE retention is immutable), so a root
# attacker can silently downgrade it to GOVERNANCE — weakening every *future*
# write while already-locked objects stay immutable. It cannot be prevented, so
# it is instead made evident: because the record sits inside the hashed body
# rather than in the header, it is covered by the chain, and a downgrade is
# permanently timestamped in an immutable checkpoint that survives any later
# repair. `make verify-log-chain` exits 2 on drift.
#
# Checkpoints live in the *same* WORM bucket, so they inherit the bucket's own
# Object Lock, SSE-S3 encryption and versioning automatically -- a checkpoint,
# once written, is exactly as immutable as a log object. This trusts MinIO's reported
# ETag rather than independently re-hashing every object's content (an explicit
# tradeoff), and each round rebuilds the full manifest rather than an
# incremental delta.
#
# Run by the `log-chainer` service in docker-compose.secrets.yaml, after
# `minio-init` completes successfully.

set -eu

S=/secrets/minio
ALIAS=worm
BUCKET=logs
CKPT_PREFIX="checkpoints/"
CHECK_INTERVAL="${LOG_CHAINER_INTERVAL:-60}"

# Fixed genesis constant for the very first checkpoint's prev_hash -- the
# bucket itself is ephemeral per `up` (destroyed by `down-locally`, same as
# every other secret/volume in this environment), so there is no
# cross-restart persistence requirement that would call for anything fancier
# (e.g. vault-derived). Reproducible by anyone: printf '%s' \
#   "interuss-log-chain-genesis" | sha256sum
GENESIS="118ffdf7b004e947c723fe9bf80e0d60ee5a5783f5eadf52521753cc8c82668b"

# What minio-init.sh provisions, and therefore what every checkpoint is expected
# to record. verify_log_chain.sh holds the same pair and compares against it.
EXPECTED_MODE="COMPLIANCE"
EXPECTED_VALIDITY="3DAYS"

CHAINER_KEY=$(cat "$S/chainer_key")
CHAINER_SECRET=$(cat "$S/chainer_secret")

mkdir -p /root/.mc/certs/CAs
cp "$S/ca.crt" /root/.mc/certs/CAs/vault-ca.crt

# Env-based alias: unlike `mc alias set`, this does not probe the endpoint at
# definition time (same rationale as minio-init.sh).
export MC_HOST_worm="https://${CHAINER_KEY}:${CHAINER_SECRET}@minio.localutm:9000"

echo "log-chainer: waiting for the bucket ..."
tries=0
until mc ls "$ALIAS/$BUCKET" >/dev/null 2>&1; do
  tries=$((tries + 1))
  if [ "$tries" -gt 90 ]; then
    echo "log-chainer: bucket did not become reachable:" >&2
    mc ls "$ALIAS/$BUCKET" || true
    exit 1
  fi
  sleep 2
done

# Find the highest-numbered existing checkpoint (checkpoints/NNNNNNNN.chk),
# ignoring anything under the prefix that doesn't match that exact pattern.
# This is how the chain's state is recovered after a restart -- the bucket
# itself is the only source of truth, no separate state volume is kept.
find_last_checkpoint() {
  LAST_SEQ=0
  LAST_NAME=""
  if mc ls --recursive "$ALIAS/$BUCKET/$CKPT_PREFIX" >/tmp/ckpt_ls.txt 2>/dev/null; then
    while IFS= read -r line; do
      name=""
      for tok in $line; do name="$tok"; done
      case "$name" in
        [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].chk)
          seq_str=${name%.chk}
          seq_num=$((10#$seq_str))
          if [ "$seq_num" -gt "$LAST_SEQ" ]; then
            LAST_SEQ=$seq_num
            LAST_NAME=$name
          fi
          ;;
      esac
    done < /tmp/ckpt_ls.txt
  fi
  rm -f /tmp/ckpt_ls.txt
}

# Read the bucket's default Object Lock configuration. `mc retention info
# --default` prints one prose line:
#
#   Object locking 'COMPLIANCE' is configured for 3DAYS.
#
# The minio/mc image has no grep/awk/sed/jq/python, so this is
# parsed with cut and shell builtins only: the mode is the sole single-quoted
# token, and the validity is whitespace field 7 with its trailing period
# stripped.
#
# Fails CLOSED. A missing permission does not produce a clear access-denied here
# — it produces `Remote bucket ... does not support locking`, which must never be
# read as "no problem". Anything that does not parse as the expected sentence is
# recorded as UNKNOWN, which verify_log_chain.sh treats as drift.
read_retention() {
  _line=""
  _line=$(mc retention info --default "$ALIAS/$BUCKET" 2>&1 | head -n1) || _line=""
  RET_MODE=$(printf '%s\n' "$_line" | cut -d"'" -f2)
  RET_VALIDITY=$(printf '%s\n' "$_line" | cut -d' ' -f7)
  RET_VALIDITY=${RET_VALIDITY%.}
  case "$_line" in
    "Object locking '"*"' is configured for "*) ;;
    *) RET_MODE=""; RET_VALIDITY="" ;;
  esac
  [ -n "$RET_MODE" ] || RET_MODE="UNKNOWN"
  [ -n "$RET_VALIDITY" ] || RET_VALIDITY="UNKNOWN"

  if [ "$RET_MODE" != "$EXPECTED_MODE" ] || [ "$RET_VALIDITY" != "$EXPECTED_VALIDITY" ]; then
    # Loud, because this stdout is itself shipped to the WORM bucket by Vector,
    # so the alert lands in the immutable store alongside the checkpoint.
    echo "log-chainer: WARNING — WORM retention drift: expected ${EXPECTED_MODE} ${EXPECTED_VALIDITY}, observed ${RET_MODE} ${RET_VALIDITY} (mc said: ${_line:-<no output>})" >&2
  fi
}

checkpoint_round() {
  find_last_checkpoint
  if [ "$LAST_SEQ" -eq 0 ]; then
    NEXT_SEQ=1
    PREV_HASH="$GENESIS"
  else
    NEXT_SEQ=$((LAST_SEQ + 1))
    PREV_HASH=$(mc cat "$ALIAS/$BUCKET/$CKPT_PREFIX$LAST_NAME" | head -n1)
  fi

  # Manifest: every object currently in the bucket (log objects AND prior
  # checkpoints -- the chain is naturally self-referential over its own
  # history), as MinIO itself reports them. Sorted for a deterministic byte
  # sequence to hash, since ordering isn't otherwise guaranteed round to round.
  mc ls --recursive --json "$ALIAS/$BUCKET" | sort > /tmp/manifest.txt

  # Body = retention record, then the manifest. The retention record is placed
  # INSIDE the hashed body rather than alongside the header fields: a header line
  # would sit outside sha256(prev_hash || body) and could be rewritten to claim
  # COMPLIANCE without breaking the chain, defeating the point of recording it.
  read_retention
  {
    echo "retention $RET_MODE $RET_VALIDITY"
    cat /tmp/manifest.txt
  } > /tmp/body.txt

  CHAIN_HASH=$( { printf '%s' "$PREV_HASH"; cat /tmp/body.txt; } | sha256sum | cut -d' ' -f1)
  TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  SEQ_PADDED=$(printf '%08d' "$NEXT_SEQ")

  {
    echo "$CHAIN_HASH"
    echo "$PREV_HASH"
    echo "$NEXT_SEQ"
    echo "$TS"
    cat /tmp/body.txt
  } | mc pipe "$ALIAS/$BUCKET/${CKPT_PREFIX}${SEQ_PADDED}.chk"

  OBJ_COUNT=$(wc -l < /tmp/manifest.txt)
  rm -f /tmp/manifest.txt /tmp/body.txt
  echo "log-chainer: checkpoint ${SEQ_PADDED} written — ${OBJ_COUNT} objects in manifest, retention=${RET_MODE} ${RET_VALIDITY}, chain_hash=${CHAIN_HASH}"
}

echo "log-chainer: starting, checkpointing every ${CHECK_INTERVAL}s"
while true; do
  checkpoint_round
  sleep "$CHECK_INTERVAL"
done
