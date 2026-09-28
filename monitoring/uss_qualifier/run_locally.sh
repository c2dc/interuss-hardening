#!/usr/bin/env bash

set -eo pipefail

# Find and change to repo root directory
OS=$(uname)
if [[ "$OS" == "Darwin" ]]; then
	# OSX uses BSD readlink
	BASEDIR="$(dirname "$0")"
else
	BASEDIR=$(readlink -e "$(dirname "$0")")
fi
cd "${BASEDIR}/../.." || exit 1

(
cd monitoring || exit 1
make image
)

CONFIG_NAME="${1:-ALL}"

# https://stackoverflow.com/a/9057392
# shellcheck disable=SC2124
OTHER_ARGS=${@:2}

# NOTE: this is a convenience alias, NOT a launch/regression gate. main.py runs
# these sequentially in ONE container and returns on the first non-zero exit, so
# a failure early in the list hides every configuration after it. To actually
# gate a release, invoke each configuration separately and judge each by its own
# report.
#
# This list must stay in sync with configurations/dev/. It previously enumerated
# only 14 of the 17, silently skipping datastore_mtls, netrid_concurrency and
# uspace_f3548, so anyone running it believed they had full coverage.
if [ "$CONFIG_NAME" == "ALL" ]; then
  CONFIG_NAME="\
configurations.dev.noop,\
configurations.dev.geoawareness_cis,\
configurations.dev.generate_rid_test_data,\
configurations.dev.geospatial_comprehension,\
configurations.dev.general_flight_auth,\
configurations.dev.message_signing,\
configurations.dev.minimal_probing,\
configurations.dev.dss_probing,\
configurations.dev.datastore_mtls,\
configurations.dev.f3548_self_contained,\
configurations.dev.utm_implementation_us.environments.local.test_1,\
configurations.dev.netrid_v22a,\
configurations.dev.netrid_v19,\
configurations.dev.netrid_concurrency,\
configurations.dev.uspace,\
configurations.dev.uspace_f3548,\
configurations.dev.access_tokens"
fi

echo "Running configuration(s): ${CONFIG_NAME}"

CONFIG_FLAG="--config ${CONFIG_NAME}"

AUTH_SPEC='DummyOAuth(https://oauth.authority.localutm:8443/token,uss_qualifier)'
AUTH_SPEC_2='DummyOAuth(https://oauth.authority.localutm:8443/token,uss_qualifier_2)'

QUALIFIER_OPTIONS="$CONFIG_FLAG $OTHER_ARGS"

OUTPUT_DIR="monitoring/uss_qualifier/output"
mkdir -p "$OUTPUT_DIR"

CACHE_DIR="monitoring/uss_qualifier/.templates_cache"
mkdir -p "$CACHE_DIR"

if [ "$CI" == "true" ]; then
  docker_args="--add-host host.docker.internal:host-gateway" # Required to reach other containers in Ubuntu (used for Github Actions)
else
  docker_args="-it"
fi

# Initialize an empty string for additional Docker options
PRIVATE_REPOS_ENV_FLAG=""

# Check if GITHUB_PRIVATE_REPOS is set and not empty
if [ -n "${GITHUB_PRIVATE_REPOS}" ]; then
  PRIVATE_REPOS_ENV_FLAG="-e GITHUB_PRIVATE_REPOS=${GITHUB_PRIVATE_REPOS}"
fi

# shellcheck disable=SC2086
docker run --pull never ${docker_args} --name uss_qualifier \
  --rm \
  --network interop_ecosystem_network \
  --add-host=host.docker.internal:host-gateway \
  -u "$(id -u):$(id -g)" \
  -e PYTHONBUFFERED=1 \
  -e AUTH_SPEC=${AUTH_SPEC} \
  -e AUTH_SPEC_2=${AUTH_SPEC_2} \
  -e AUTH_ADAPTER_CERT_DIR=/secrets/oauth/clients \
  -e REQUESTS_CA_BUNDLE=/tmp/ca-bundle.crt \
  -e PROJ_NETWORK \
  ${PRIVATE_REPOS_ENV_FLAG} \
  -e MONITORING_GITHUB_ROOT=${MONITORING_GITHUB_ROOT:-} \
  -v "$(pwd)/build/dev/dss-secrets:/secrets:ro" \
  -v "$(pwd)/$OUTPUT_DIR:/app/$OUTPUT_DIR" \
  -v "$(pwd)/$CACHE_DIR:/app/$CACHE_DIR" \
  -w /app/monitoring/uss_qualifier \
  interuss/monitoring \
  sh -c "cat /etc/ssl/certs/ca-certificates.crt /secrets/oauth/clients/ca.crt > /tmp/ca-bundle.crt && exec uv run main.py $QUALIFIER_OPTIONS"
