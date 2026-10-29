#!/bin/sh
# Build and run the Linux end-to-end harness in Docker.
# Requires a running Docker engine with --privileged support.
set -e
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"

mkdir -p desktop/linux/docker-e2e/out
docker build -t teleweb-e2e -f desktop/linux/docker-e2e/Dockerfile .
docker run --rm --privileged -v "$ROOT/desktop/linux/docker-e2e/out:/out/logs" teleweb-e2e
