# interuss-hardening

A security-hardened local UTM (UAS Traffic Management) test ecosystem. It runs a DSS pool, a mock USS
fleet and the `uss_qualifier` conformance framework on one machine with Docker. It is derived from
[InterUSS `monitoring`](https://github.com/interuss/monitoring) and distributed under the
[Apache License 2.0](LICENSE).

Hardening includes:

- mutual TLS between services and between CockroachDB nodes;
- a secrets vault that issues all certificates;
- encryption at rest;
- sender-constrained (RFC 8705), least-privilege OAuth tokens;
- WORM, hash-chained log storage.

## Requirements

- Docker with the Compose plugin
- GNU make, bash
- Submodules initialised: `git submodule update --init`

## Usage

```bash
sudo ./monitoring/build.sh           # build the interuss/monitoring image (start-locally also does this)
make start-locally                   # vault, WORM log store, DSS pool, OAuth, load balancer
make start-uss-mocks                 # mock USS fleet
monitoring/uss_qualifier/run_locally.sh configurations.dev.minimal_probing
make verify-log-chain                # check the log hash chain and WORM retention
make stop-uss-mocks                  # stop the mock USS fleet
make down-locally                    # tear down the rest, including volumes
```

After changing code under `monitoring/`, rebuild the image with `monitoring/build.sh`.

The `interuss/monitoring` image is always built locally and never pulled: every compose service and
`docker run` that uses it sets `pull_policy: never` / `--pull never`, so a missing image fails
instead of silently running the unpinned upstream image from Docker Hub.
