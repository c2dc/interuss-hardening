#!/usr/bin/env bash

set -eo pipefail

# This script is intended to be called from within a Docker container running
# mock_uss via the interuss/monitoring image.  In that context, this script is
# the entrypoint into the mock_uss server.

# Ensure mock_uss is the working directory
OS=$(uname)
if [[ $OS == "Darwin" ]]; then
	# OSX uses BSD readlink
	BASEDIR="$(dirname "$0")"
else
	BASEDIR=$(readlink -e "$(dirname "$0")")
fi
cd "${BASEDIR}" || exit 1

# Use mock_uss's health check
cp health_check.sh /app

# Start mock_uss server
port=${MOCK_USS_PORT:-5000}
export PYTHONUNBUFFERED=TRUE

# Serve HTTPS with the vault-issued cert when one is provided.
tls_args=""
if [ -n "${MOCK_USS_TLS_CERT:-}" ] && [ -n "${MOCK_USS_TLS_KEY:-}" ]; then
    tls_args="--certfile=${MOCK_USS_TLS_CERT} --keyfile=${MOCK_USS_TLS_KEY}"
fi

# shellcheck disable=SC2086
uv run gunicorn \
    --preload \
    --config ./gunicorn.conf.py \
    --worker-class="gevent" \
    --workers=4 \
    --worker-tmp-dir="/dev/shm" \
    ${tls_args} \
    "--bind=0.0.0.0:${port}" \
    monitoring.mock_uss.app:webapp
