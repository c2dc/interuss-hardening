#!/bin/sh
# Verify the WORM log bucket's hash chain.
#
# Walks every checkpoint in logs/checkpoints/, in sequence order, and confirms:
#   1. each checkpoint's own chain_hash is genuinely sha256(prev_hash || body),
#      where body = the retention record followed by the manifest -- catches a
#      corrupted or hand-forged checkpoint, including one whose retention record
#      was edited to hide a downgrade;
#   2. each checkpoint's prev_hash equals the previous checkpoint's chain_hash
#      (or the fixed genesis constant, for the first) -- catches a checkpoint
#      that doesn't actually continue the chain (an injected/replayed entry);
#   3. the WORM retention configuration each checkpoint recorded is still the
#      COMPLIANCE 3DAYS that minio-init.sh provisioned, and that the *live*
#      bucket configuration is too -- catches a retention downgrade.
#
# Exit codes:
#   0  chain intact and retention as provisioned
#   1  chain broken (a checkpoint was corrupted, forged, or does not continue)
#   2  chain intact, but a WORM retention downgrade was recorded or is live
# 1 wins over 2 when both apply: a broken chain is the more serious result and
# makes everything the chain says about retention untrustworthy anyway.
#
# Run via `make verify-log-chain`. Uses MinIO root credentials (an operator
# diagnostic, like `make show-worm-logs` -- not a running service, so PoLP
# scoping doesn't apply the same way it does to log-chainer's own credential).

set -eu

S=/secrets/minio
ALIAS=worm
BUCKET=logs
CKPT_PREFIX="checkpoints/"
GENESIS="118ffdf7b004e947c723fe9bf80e0d60ee5a5783f5eadf52521753cc8c82668b"

# Must match log_chainer.sh's constants of the same name.
EXPECTED_RETENTION="retention COMPLIANCE 3DAYS"

mkdir -p /root/.mc/certs/CAs
cp "$S/ca.crt" /root/.mc/certs/CAs/vault-ca.crt
mc alias set "$ALIAS" "https://minio.localutm:9000" "$(cat "$S/root_user")" "$(cat "$S/root_password")" >/dev/null

# Collect valid checkpoint names (NNNNNNNN.chk), in ascending sequence order.
: > /tmp/names.txt
if mc ls --recursive "$ALIAS/$BUCKET/$CKPT_PREFIX" >/tmp/ckpt_ls.txt 2>/dev/null; then
  while IFS= read -r line; do
    name=""
    for tok in $line; do name="$tok"; done
    case "$name" in
      [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].chk) echo "$name" >> /tmp/names.txt ;;
    esac
  done < /tmp/ckpt_ls.txt
fi
rm -f /tmp/ckpt_ls.txt
sort -o /tmp/names.txt /tmp/names.txt

COUNT=$(wc -l < /tmp/names.txt)
# An empty checkpoint set must NOT be reported as success. It used to return 0
# here, before the live-retention check below had run -- so deleting every
# checkpoint produced a clean PASS *and* silently disabled retention-drift
# detection, turning the absence of evidence into evidence of absence. Fail
# closed instead: skip the per-checkpoint loop (an empty names.txt iterates zero
# times on its own), still run the live check, and exit non-zero at the end.
#
# This is also the state right after a bring-up, before log-chainer's first
# round, which is why the message below says so.
NO_CHECKPOINTS=0
if [ "$COUNT" -eq 0 ]; then
  NO_CHECKPOINTS=1
  echo "NO CHECKPOINTS: logs/checkpoints/ is empty."
  echo "      Either log-chainer has not completed its first round yet (wait ~60s"
  echo "      after bring-up and re-run), or the chain has been destroyed."
fi

EXPECTED_PREV="$GENESIS"
FAILED=0
DRIFTED=0
FIRST_DRIFT=""
while IFS= read -r name; do
  mc cat "$ALIAS/$BUCKET/$CKPT_PREFIX$name" > /tmp/ckpt.txt
  chain_hash=$(head -n1 /tmp/ckpt.txt)
  prev_hash=$(head -n2 /tmp/ckpt.txt | tail -n1)
  seq=$(head -n3 /tmp/ckpt.txt | tail -n1)
  ts=$(head -n4 /tmp/ckpt.txt | tail -n1)
  # Body = line 5 onward: the retention record, then the manifest. The hash is
  # taken over the whole body exactly as before -- splitting it here changes only
  # how it is read, never what is hashed.
  tail -n +5 /tmp/ckpt.txt > /tmp/body.txt
  retention=$(head -n1 /tmp/body.txt)
  tail -n +2 /tmp/body.txt > /tmp/manifest.txt

  recomputed=$( { printf '%s' "$prev_hash"; cat /tmp/body.txt; } | sha256sum | cut -d' ' -f1)

  ok=1
  if [ "$recomputed" != "$chain_hash" ]; then
    echo "FAIL: $name (seq $seq, $ts) — stored chain_hash does not match sha256(prev_hash || body)."
    echo "      stored:     $chain_hash"
    echo "      recomputed: $recomputed"
    echo "      => this checkpoint's own content is inconsistent (corrupted or hand-forged)."
    echo "         The body covers the retention record as well as the manifest, so this also"
    echo "         fires if someone edited the retention line to hide a downgrade."
    ok=0
  fi
  if [ "$prev_hash" != "$EXPECTED_PREV" ]; then
    echo "FAIL: $name (seq $seq, $ts) — prev_hash does not match the previous checkpoint's chain_hash."
    echo "      expected: $EXPECTED_PREV"
    echo "      found:    $prev_hash"
    echo "      => this checkpoint does not continue the chain (injected/replayed/out-of-order entry)."
    ok=0
  fi
  # Retention drift is reported separately from a chain break: the chain can be
  # perfectly intact and still faithfully record that the WORM policy was
  # weakened. Because the record is inside the hashed body, an intact chain is
  # what makes this reading trustworthy.
  if [ "$retention" != "$EXPECTED_RETENTION" ]; then
    echo "DRIFT: $name (seq $seq, $ts) — WORM retention was not as provisioned."
    echo "      expected: $EXPECTED_RETENTION"
    echo "      recorded: $retention"
    echo "      => the bucket's default Object Lock policy was weakened (or unreadable)"
    echo "         at this checkpoint; objects written while it held inherit that policy."
    DRIFTED=1
    [ -n "$FIRST_DRIFT" ] || FIRST_DRIFT="$name (seq $seq, $ts): $retention"
  fi

  if [ "$ok" -eq 1 ]; then
    # "chain ok" specifically, not "everything ok": a checkpoint can have an
    # intact hash and still faithfully record a weakened retention policy above.
    echo "OK (chain): $name (seq $seq, $ts) — $(wc -l < /tmp/manifest.txt) objects, $retention, chain_hash=$chain_hash"
  else
    FAILED=1
  fi
  EXPECTED_PREV="$chain_hash"
done < /tmp/names.txt

rm -f /tmp/names.txt /tmp/ckpt.txt /tmp/body.txt /tmp/manifest.txt

# The recorded values only cover up to the last checkpoint, so also read the live
# configuration: a downgrade in the last few seconds is not in any checkpoint yet.
# Same fail-closed parse as log_chainer.sh's read_retention.
live_line=""
live_line=$(mc retention info --default "$ALIAS/$BUCKET" 2>&1 | head -n1) || live_line=""
live_mode=$(printf '%s\n' "$live_line" | cut -d"'" -f2)
live_validity=$(printf '%s\n' "$live_line" | cut -d' ' -f7)
live_validity=${live_validity%.}
case "$live_line" in
  "Object locking '"*"' is configured for "*) ;;
  *) live_mode=""; live_validity="" ;;
esac
[ -n "$live_mode" ] || live_mode="UNKNOWN"
[ -n "$live_validity" ] || live_validity="UNKNOWN"

echo "---"
if [ "retention $live_mode $live_validity" = "$EXPECTED_RETENTION" ]; then
  echo "Live bucket retention: $live_mode $live_validity (as provisioned)."
else
  echo "DRIFT: live bucket retention is $live_mode $live_validity, expected ${EXPECTED_RETENTION#retention }."
  DRIFTED=1
  [ -n "$FIRST_DRIFT" ] || FIRST_DRIFT="live bucket configuration: retention $live_mode $live_validity"
fi

echo "---"
if [ "$NO_CHECKPOINTS" -ne 0 ]; then
  echo "FAIL: no checkpoints to verify — the chain is absent, not intact. (exit 1)"
  echo "      The live retention reported above is the ONLY evidence available;"
  echo "      with no chain there is no record of what it was at any earlier time."
  exit 1
elif [ "$FAILED" -ne 0 ]; then
  echo "FAIL: chain is broken — see above. (exit 1)"
  exit 1
elif [ "$DRIFTED" -ne 0 ]; then
  echo "FAIL: $COUNT checkpoint(s), chain intact from genesis — but WORM retention drifted. (exit 2)"
  echo "      first divergence: $FIRST_DRIFT"
  echo "      The chain is intact, so this record is trustworthy: the default Object Lock"
  echo "      policy really was weakened. Restoring it does not erase these checkpoints."
  exit 2
else
  echo "PASS: $COUNT checkpoint(s), chain intact from genesis, retention as provisioned."
  exit 0
fi
