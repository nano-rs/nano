#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
query_image="${NANOSIEM_FIXTURE_QUERY_IMAGE:-us-central1-docker.pkg.dev/nano-rs/nanosiem-scale-tests/nan2361/scale04/query@sha256:c38776f4238987568c9c83a63c27a8930998299615ea6544267aa3eaea810e3e}"
builder_image="${NANOSIEM_FIXTURE_BUILDER_IMAGE:-nan2361-scale03-lake-retained-builder-amd64:ced9291a8}"
output_image="${NANOSIEM_LOCAL_CHDB_FIXTURE_IMAGE:-nan2361-enterprise-shared-chdb-fixture:c0061810491a}"

docker image inspect "$query_image" >/dev/null
docker image inspect "$builder_image" >/dev/null
docker build \
  --platform linux/amd64 \
  --build-arg "QUERY_IMAGE=$query_image" \
  --build-arg "BUILDER_IMAGE=$builder_image" \
  --file "$fixture_dir/Dockerfile.chdb-lake-worker" \
  --tag "$output_image" \
  "$fixture_dir"
docker image inspect "$output_image" --format '{{.Id}}'
