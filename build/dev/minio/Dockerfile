# MinIO server and client (mc), compiled from source at pinned releases.
#
# MinIO no longer distributes free prebuilt artifacts: the Docker Hub and
# quay.io repositories deny anonymous pulls and dl.min.io answers 410 Gone. The
# source is still public, so both binaries are built here from the exact release
# tags, and packaged on the same ubi9/ubi-micro base as the official images so
# the scripts that run in them (minio-init.sh, log_chainer.sh,
# verify_log_chain.sh) see the same userland: sh and coreutils, but no
# grep/awk/sed/jq/python.
#
# Two targets: `minio` (the server) and `mc` (the client).

ARG MINIO_RELEASE=RELEASE.2025-07-23T15-54-02Z
ARG MC_RELEASE=RELEASE.2025-07-21T05-28-08Z

FROM golang:1.24-alpine AS build
RUN apk add --no-cache git ca-certificates
ENV CGO_ENABLED=0

# Upstream derives the version from the release timestamp (with ':' in the
# time part) and embeds it via buildscripts/gen-ldflags.go.
FROM build AS build-minio
ARG MINIO_RELEASE
RUN git clone --depth 1 --branch "${MINIO_RELEASE}" https://github.com/minio/minio /src
WORKDIR /src
RUN version=$(echo "${MINIO_RELEASE#RELEASE.}" | sed 's/T\(..\)-\(..\)-\(..\)Z/T\1:\2:\3Z/') && \
    go build -tags kqueue -trimpath \
      -ldflags "$(MINIO_RELEASE=RELEASE go run buildscripts/gen-ldflags.go "$version")" \
      -o /out/minio

FROM build AS build-mc
ARG MC_RELEASE
RUN git clone --depth 1 --branch "${MC_RELEASE}" https://github.com/minio/mc /src
WORKDIR /src
RUN version=$(echo "${MC_RELEASE#RELEASE.}" | sed 's/T\(..\)-\(..\)-\(..\)Z/T\1:\2:\3Z/') && \
    go build -tags kqueue -trimpath \
      -ldflags "$(MC_RELEASE=RELEASE go run buildscripts/gen-ldflags.go "$version")" \
      -o /out/mc

FROM registry.access.redhat.com/ubi9/ubi-micro:9.6 AS minio
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build-minio /src/LICENSE /licenses/LICENSE
COPY --from=build-minio /out/minio /usr/bin/minio
EXPOSE 9000
VOLUME ["/data"]
ENTRYPOINT ["/usr/bin/minio"]

FROM registry.access.redhat.com/ubi9/ubi-micro:9.6 AS mc
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build-mc /src/LICENSE /licenses/LICENSE
COPY --from=build-mc /out/mc /usr/bin/mc
ENTRYPOINT ["/usr/bin/mc"]
