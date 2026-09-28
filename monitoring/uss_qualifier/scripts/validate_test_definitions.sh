#!/usr/bin/env bash

set -eo pipefail
set -o xtrace

# Find and change to repo root directory
OS=$(uname)
if [[ "$OS" == "Darwin" ]]; then
	# OSX uses BSD readlink
	BASEDIR="$(dirname "$0")"
else
	BASEDIR=$(readlink -e "$(dirname "$0")")
fi
cd "${BASEDIR}/../../.." || exit 1

(
cd monitoring || exit 1
# The `image-dev` target and the Dockerfile's dev stage were removed when the
# project was trimmed to the local UTM test ecosystem. The in_container script
# below is documented as running under the `interuss/monitoring` image anyway,
# so this uses the surviving image rather than resurrecting the dev one.
make image
)

# shellcheck disable=SC2086
docker run --pull never --name test_definition_validator \
  --rm \
  -e MONITORING_GITHUB_ROOT=${MONITORING_GITHUB_ROOT:-} \
  interuss/monitoring \
  uss_qualifier/scripts/in_container/validate_test_definitions.sh
