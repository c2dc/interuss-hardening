ifeq ($(OS),Windows_NT)
	detected_OS := Windows
else
	detected_OS := $(shell uname -s)
endif

.PHONY: image
image:
	cd monitoring && make image

.PHONY: start-locally
# The oauth-signer runs from interuss/monitoring, so the image must be built
# locally before the stack starts; compose is told never to pull it instead.
start-locally: image
	build/dev/run_locally.sh up --wait

.PHONY: start-uss-mocks
start-uss-mocks:
	monitoring/mock_uss/start_all_local_mocks.sh

.PHONY: stop-uss-mocks
stop-uss-mocks:
	monitoring/mock_uss/stop_all_local_mocks.sh

# The prepended dash ignores errors. This allows collecting logs even if some containers are missing.
.PHONY: collect-local-logs
collect-local-logs:
	mkdir -p logs
	-sh -c "build/dev/run_locally.sh logs --timestamps" > logs/local_infra.log 2>&1
	-docker compose -f build/dev/docker-compose.secrets.yaml -p local_infra_secrets logs --timestamps > logs/local_infra_secrets.log 2>&1
	-sh -c 'for c in $$(docker ps --format "{{.Names}}" | grep -E "crdb-1$$" | grep -v crdb-init); do mkdir -p "logs/$$c.crdb-file-logs"; docker cp "$$c:/cockroach/cockroach-data/logs/." "logs/$$c.crdb-file-logs/"; done' 2>/dev/null
	-docker logs mock_uss_scdsc_a > logs/mock_uss_scdsc_a.log 2>&1
	-docker logs mock_uss_scdsc_b > logs/mock_uss_scdsc_b.log 2>&1
	-docker logs mock_uss_geoawareness > logs/mock_uss_geoawareness.log 2>&1
	-docker logs mock_uss_ridsp > logs/mock_uss_ridsp.log 2>&1
	-docker logs mock_uss_riddp > logs/mock_uss_riddp.log 2>&1
	-docker logs mock_uss_ridsp_v19 > logs/mock_uss_ridsp_v19.log 2>&1
	-docker logs mock_uss_riddp_v19 > logs/mock_uss_riddp_v19.log 2>&1
	-docker logs mock_uss_tracer > logs/mock_uss_tracer.log 2>&1
	-docker logs mock_uss_scdsc_interaction_log > logs/mock_uss_scdsc_interaction_log.log 2>&1

# List what the WORM log store currently holds (all object versions) and its
# retention policy. Uses the MinIO root credentials materialised by the vault.
.PHONY: show-worm-logs
show-worm-logs:
	@docker run --rm --network dss_internal_network \
	  -v "$(CURDIR)/build/dev/dss-secrets/minio:/s:ro" --entrypoint sh \
	  local/mc:RELEASE.2025-07-21T05-28-08Z -c '\
	    mkdir -p /root/.mc/certs/CAs && cp /s/ca.crt /root/.mc/certs/CAs/vault-ca.crt && \
	    mc alias set worm https://minio.localutm:9000 "$$(cat /s/root_user)" "$$(cat /s/root_password)" >/dev/null && \
	    echo "== retention ==" && mc retention info --default worm/logs && \
	    echo "== objects (all versions) ==" && mc ls --recursive --versions worm/logs'

# Verify the WORM bucket's hash chain (build/dev/startup/log_chainer.sh):
# walks every checkpoint, confirms each is internally consistent and correctly
# linked to the one before it, and checks the recorded + live WORM retention
# configuration.
#
# The script distinguishes its two failure modes by exit status (1 = chain
# broken, 2 = retention drift), but GNU make collapses ANY recipe failure to its
# own exit status 2, so `make verify-log-chain` cannot convey the difference.
# The real status is therefore echoed below, and anything that needs to branch on
# it (CI, a monitoring hook) should run the docker command directly rather than
# going through make.
.PHONY: verify-log-chain
verify-log-chain:
	@docker run --rm --network dss_internal_network \
	  -v "$(CURDIR)/build/dev/dss-secrets/minio:/secrets/minio:ro" \
	  -v "$(CURDIR)/build/dev/startup/verify_log_chain.sh:/startup/verify_log_chain.sh:ro" \
	  --entrypoint sh local/mc:RELEASE.2025-07-21T05-28-08Z /startup/verify_log_chain.sh; \
	  rc=$$?; \
	  if [ $$rc -ne 0 ]; then \
	    echo "verify_log_chain.sh exit status: $$rc  (1 = chain broken, 2 = WORM retention drift)"; \
	    echo "note: make itself always reports Error 2 on failure — trust the line above, not make's."; \
	  fi; \
	  exit $$rc

.PHONY: stop-locally
stop-locally:
	build/dev/run_locally.sh stop

.PHONY: down-locally
down-locally:
	build/dev/run_locally.sh down

.PHONY: clean-locally
clean-locally: down-locally
	-docker ps -aq --filter network=interop_ecosystem_network | xargs -r docker rm -f
	-docker ps -aq --filter network=dss_internal_network | xargs -r docker rm -f

# For local development when restarts are frequently required (such as when testing changes on the DSS)
.PHONY: restart-all
restart-all: stop-uss-mocks down-locally start-locally start-uss-mocks

# For local development when restarts of the mock USS are frequently required
.PHONY: restart-uss-mocks
restart-uss-mocks: stop-uss-mocks start-uss-mocks
