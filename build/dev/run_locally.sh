#!/usr/bin/env bash

set -eo pipefail

# This script deploys a local UTM interoperability ecosystem.

if [[ -z $(command -v docker) ]]; then
  echo "docker is required but not installed.  Visit https://docs.docker.com/install/ to install."
  exit 1
fi

OS=$(uname)
if [[ "$OS" == "Darwin" ]]; then
	# OSX uses BSD readlink
	BASEDIR="$(dirname "$0")"
else
	BASEDIR=$(readlink -e "$(dirname "$0")")
fi

cd "${BASEDIR}" || exit 1

export NUM_USS=${NUM_USS:-2}
export NUM_NODES=${NUM_NODES:-1}
DB_TYPE=${DB_TYPE:-crdb}

# Replication factor for the CockroachDB cluster (crdb-init applies it to RANGE
# default). This CANNOT simply be NUM_USS: CockroachDB rejects num_replicas=2
# outright ("at least 3 replicas are required for multi-replica configurations"),
# and even with a target of 3 its allocator refuses to up-replicate 1->2 across
# only two stores ("avoid up-replicating to fragile quorum"). So any topology
# with fewer than 3 total nodes must be an explicit single-replica cluster.
#
# Consequence, stated plainly: the DEFAULT NUM_USS=2 topology is a SINGLE-REPLICA
# cluster with no redundancy and no per-USS replica. Use NUM_USS>=3 to get the
# "each USS holds a replica" property.
TOTAL_DB_NODES=$((NUM_USS * NUM_NODES))
if [ "$TOTAL_DB_NODES" -ge 3 ]; then
  export NUM_REPLICAS=$TOTAL_DB_NODES
else
  export NUM_REPLICAS=1
fi

export DSS_IMAGE="${DSS_IMAGE:-interuss/dss:v0.23.0-rc5}"
export CORE_SERVICE_EXTRA_FLAGS="${CORE_SERVICE_EXTRA_FLAGS:---enable_time_based_notification_index}"

DC_COMMAND=$*

if [[ ! "$DC_COMMAND" ]]; then
  DC_COMMAND="up"
  DC_OPTIONS="--build -d"
elif [[ "$DC_COMMAND" == "down" ]]; then
  DC_OPTIONS="--volumes --remove-orphans"
elif [[ "$DC_COMMAND" == "debug" ]]; then
  DC_COMMAND=up
  DC_OPTIONS="-d"
  export DEBUG_ON=1
fi

# Which per-USS projects to act on, as "<uss> <node>" pairs.
#
# For `up` this is exactly the requested topology. For `stop`/`down` it ALSO
# includes every per-USS project that actually exists, because the two need not
# agree: tearing down with a smaller NUM_USS than the bring-up used left the
# excess projects running, and those containers then held the shared networks
# open ("network ... has active endpoints"), leaving a stale DSS reachable on the
# ecosystem network. Deriving the list from reality rather than from the
# environment makes `make down-locally` sufficient at any node count.
uss_node_pairs() {
  local i j
  for ((i=1; i<=NUM_USS; i++)); do
    for ((j=1; j<=NUM_NODES; j++)); do
      echo "$i $j"
    done
  done
  if [[ "$DC_COMMAND" == "down" || "$DC_COMMAND" == "stop" ]]; then
    docker ps -a --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null \
      | sed -n 's/^local_infra_\([0-9]\{1,\}\)-\([0-9]\{1,\}\)$/\1 \2/p'
  fi
}
USS_NODE_PAIRS=$(uss_node_pairs | sort -u -k1,1n -k2,2n)

if [[ "$DC_COMMAND" == up* ]]; then
  DC_COMMAND=${DC_COMMAND//--wait/}
  if [[ ! "$DC_COMMAND" =~ "-d" && ! "$DC_OPTIONS" =~ "-d" ]]; then
    DC_OPTIONS="${DC_OPTIONS} -d"
  fi
  echo "Creating networks..."
  docker network create --subnet=172.27.0.0/16 \
                        --ip-range=172.27.0.0/24 \
                        --gateway=172.27.0.1 \
                        dss_internal_network || true
  docker network create interop_ecosystem_network || true

  # Bring up the shared-infra project (OpenBao vault + MinIO WORM log store +
  # Vector) first, so it can provision cert/secret material into
  # build/dev/dss-secrets/ (bind-mounted read-only by the per-USS stacks) and the
  # log pipeline is capturing before anything else starts. Mirrors how the shared
  # external networks above are created up front.
  mkdir -p "${BASEDIR}/dss-secrets"
  # Vector bind-mounts the mock USS interaction-log tree read-only so the
  # structured ASTM records reach the WORM store. The mock fleet is brought
  # up much later by `make start-uss-mocks`, and that tree is git-ignored, so
  # without this the Docker daemon would create the mount source itself as root —
  # the same defect mock_uss/run_locally.sh guards against for the individual
  # log directories.
  mkdir -p "${BASEDIR}/../../monitoring/mock_uss/output"
  echo "Starting shared infra (OpenBao vault, MinIO log store, Vector)..."
  docker compose -f docker-compose.secrets.yaml -p local_infra_secrets up -d

  wait_for_init() {
    local name=$1
    local rc
    rc=$(docker wait "$name")
    if [[ "$rc" != "0" ]]; then
      echo "ERROR: ${name} failed (exit ${rc}); logs follow:"
      docker logs "$name" || true
      exit 1
    fi
  }
  echo "Provisioning secrets..."
  wait_for_init local_infra_secrets-openbao-init-1
  echo "Provisioning WORM log bucket..."
  wait_for_init local_infra_secrets-minio-init-1
  echo "Shared infra ready; secrets in ${BASEDIR}/dss-secrets"

  echo "Starting containers..."
fi

if [[ "$DB_TYPE" == "raft" ]]; then
  RID_RAFT_NODES=""
  SCD_RAFT_NODES=""
  AUX_RAFT_NODES=""
  for ((i=1; i<=NUM_USS; i++)); do
    for ((j=1; j<=NUM_NODES; j++)); do
      NODE_IDX=$(( (i-1) * NUM_NODES + j ))
      PADDED_NODE_IDX=$(printf "%02d" "$NODE_IDX")
      NODE_IP="172.27.${i}.${j}"
      RID_RAFT_NODES="${RID_RAFT_NODES},${NODE_IDX}=http://${NODE_IP}:95${PADDED_NODE_IDX}"
      SCD_RAFT_NODES="${SCD_RAFT_NODES},${NODE_IDX}=http://${NODE_IP}:96${PADDED_NODE_IDX}"
      AUX_RAFT_NODES="${AUX_RAFT_NODES},${NODE_IDX}=http://${NODE_IP}:97${PADDED_NODE_IDX}"
    done
  done
  export RID_RAFT_NODES=${RID_RAFT_NODES#,}
  export SCD_RAFT_NODES=${SCD_RAFT_NODES#,}
  export AUX_RAFT_NODES=${AUX_RAFT_NODES#,}
fi

while read -r i j; do
  [ -n "$i" ] || continue
  export USS_IDX=$i
  export USS_NODE_IDX=$j
  NODE_IDX=$(( (i-1) * NUM_NODES + j ))
  export RAFT_ID=$NODE_IDX
  PADDED_NODE_IDX=$(printf "%02d" "$NODE_IDX")
  export PADDED_NODE_IDX

  if [[ "$DC_COMMAND" == "down" || "$DC_COMMAND" == "stop" ]]; then
    # Enable every profile when tearing down. The up-time derivation below keys
    # the bootstrap profile off the project's POSITION in the topology
    # (i == NUM_USS), so a teardown at a different node count would reach the
    # right project and still leave its bootstrapper/init containers unmatched.
    export COMPOSE_PROFILES=crdb,ybdb,raft,bootstrap-crdb,bootstrap-ybdb,oauth,lb
  else
    export COMPOSE_PROFILES=${DB_TYPE}
    if [ "$i" -eq 1 ] && [ "$j" -eq 1 ]; then
      export COMPOSE_PROFILES=${COMPOSE_PROFILES},oauth,lb
    fi
    if [ "$i" -eq "$NUM_USS" ] && [ "$j" -eq "$NUM_NODES" ] && [ "$DB_TYPE" != "raft" ]; then
      export COMPOSE_PROFILES=${COMPOSE_PROFILES},bootstrap-${DB_TYPE}
    fi
  fi

  # keep the DSS and the DB in the same subnet by using the first bit of the last byte of the IP
  # e.g. for USS 3 node 2 the IPs would be 172.27.3.2 for the DSS container and 172.27.3.130 for the DB container
  export DSS_IP="172.27.$USS_IDX.$USS_NODE_IDX"
  export DB_IP="172.27.$USS_IDX.$((2#10000000 | USS_NODE_IDX))" # '2#' is the binary syntax for bash arithmetic operations

  # shellcheck disable=SC2086
  docker compose -f docker-compose.yaml -p "local_infra_${USS_IDX}-${USS_NODE_IDX}" $DC_COMMAND $DC_OPTIONS &
  sleep 0.1 # reduce probability of race condition in joining network at container start
done <<< "$USS_NODE_PAIRS"
wait

if [[ "$DC_COMMAND" == up* && "$DB_TYPE" == "crdb" ]]; then
  # crdb-init performs `cockroach init` and applies the replication zone config.
  # It runs in the LAST per-USS project (see the bootstrap-crdb profile above).
  # It used to fail silently: nothing waited on it and its entrypoint swallowed
  # the ALTER's exit status, so a rejected zone config went unnoticed and the
  # cluster stayed at one replica.
  crdb_init_container="local_infra_${NUM_USS}-${NUM_NODES}-crdb-init-1"
  echo "Waiting for datastore initialization (${crdb_init_container})..."
  crdb_init_rc=$(docker wait "${crdb_init_container}" 2>/dev/null || echo "missing")
  if [[ "$crdb_init_rc" != "0" ]]; then
    echo "ERROR: ${crdb_init_container} failed (exit ${crdb_init_rc}); logs follow:"
    docker logs "${crdb_init_container}" || true
    exit 1
  fi
  echo "Datastore initialized (replication factor ${NUM_REPLICAS})."
fi

if [[ "$DC_COMMAND" == up* ]]; then
  echo "Verifying and repairing docker network connections..."

  check_and_connect() {
    local container=$1
    local network=$2
    if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
      if ! docker inspect "${container}" --format '{{json .NetworkSettings.Networks}}' | grep -q "\"${network}\""; then
        echo "Warning: Container ${container} is not connected to ${network}. Reconnecting and restarting so the entrypoint reapplies traffic shaping..."
        docker network connect "${network}" "${container}" || {
          docker stop -t 2 "${container}" >/dev/null 2>&1 || true
          docker network connect "${network}" "${container}"
        }
        docker restart "${container}"
      fi
    fi
  }

  for ((i=1; i<=NUM_USS; i++)); do
    for ((j=1; j<=NUM_NODES; j++)); do
      check_and_connect "local_infra_${i}-${j}-dss-1" "dss_internal_network"
      check_and_connect "local_infra_${i}-${j}-dss-1" "interop_ecosystem_network"
      if [ "$DB_TYPE" != "raft" ]; then
        check_and_connect "local_infra_${i}-${j}-${DB_TYPE}-1" "dss_internal_network"
      fi
    done
  done

  check_and_connect "local_infra_1-1-oauth-1" "interop_ecosystem_network"
  echo "Network verification complete."

  echo "Waiting for all containers to become healthy..."
  timeout=240
  interval=5
  elapsed=0
  all_healthy=true

  while [ $elapsed -lt $timeout ]; do
    all_healthy=true
    unhealthy_containers=()

    check_container_health() {
      local container=$1
      if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        all_healthy=false
        unhealthy_containers+=("$container (not running)")
        return
      fi

      local health_status
      health_status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container")
      if [[ "$health_status" == "unhealthy" || "$health_status" == "starting" ]]; then
        all_healthy=false
        unhealthy_containers+=("$container ($health_status)")
      fi
    }

    check_container_health "local_infra_secrets-openbao-1"
    check_container_health "local_infra_secrets-minio-1"
    check_container_health "local_infra_secrets-vector-1"
    for ((i=1; i<=NUM_USS; i++)); do
      for ((j=1; j<=NUM_NODES; j++)); do
        check_container_health "local_infra_${i}-${j}-dss-1"
        if [ "$DB_TYPE" != "raft" ]; then
          check_container_health "local_infra_${i}-${j}-${DB_TYPE}-1"
        fi
      done
    done
    check_container_health "local_infra_1-1-oauth-1"
    check_container_health "local_infra_1-1-oauth-signer-1"

    if [ "$all_healthy" = true ]; then
      echo "All containers are healthy!"
      break
    fi

    echo "Still waiting (elapsed ${elapsed}s)... Unhealthy/starting/not-running:"
    for uc in "${unhealthy_containers[@]}"; do
      echo "  - $uc"
    done

    sleep $interval
    elapsed=$((elapsed + interval))
  done

  if [ "$all_healthy" != true ]; then
    echo "Error: Timeout waiting for containers to become healthy."
    exit 1
  fi
fi

if [[ "$DC_COMMAND" == "down" ]]; then
  echo "Stopping shared infra (vault + WORM log store)..."
  # --volumes removes minio_data and vector_buffer: all stored logs are destroyed
  # on `down`, regardless of the COMPLIANCE object-lock retention.
  docker compose -f docker-compose.secrets.yaml -p local_infra_secrets down --volumes --remove-orphans || true
  echo "Removing networks..."
  docker network rm dss_internal_network || true
  docker network rm interop_ecosystem_network || true
  echo "Removing provisioned secret material..."
  rm -rf "${BASEDIR}/dss-secrets" "${BASEDIR}/dss-certs" "${BASEDIR}/.dss-ca"
fi
