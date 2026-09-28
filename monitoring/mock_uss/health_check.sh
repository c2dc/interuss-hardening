#!/usr/bin/env sh

# This script is intended to be called from within a Docker container running
# mock_uss via the interuss/monitoring image to determine the health status of
# the container.

scheme=http
[ -n "${MOCK_USS_TLS_CERT:-}" ] && scheme=https

curl --fail -k --max-time 2 "${scheme}://127.0.0.1:${MOCK_USS_PORT:-5000}/status" || exit 1
