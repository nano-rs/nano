#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

# Refresh the host-side lake schema inputs from the containerized query worker.
#
# WHY THIS EXISTS
# The worker's config and its OCSF source manifest live inside a named Docker
# volume (`nano-lake-runtime`), so a Nano process running directly on the host
# cannot read them and the container's `/var/lib/...` paths are meaningless
# there. Host processes launched by scripts/start-microservices-dev.sh therefore
# need their own copy, and a copy taken once goes stale on the NEXT generation
# promotion -- which happens continuously under ingest. A stale copy is not
# cosmetic: the field inventory the product uses to resolve OCSF paths then
# describes a generation the worker is not serving, so validation "passes"
# against a schema universe that is not live.
#
# Re-run this before every validation run, and after any promotion. The paired
# assertion in benchmarks/security-lake-chdb/product_beta_validation.py compares
# the refreshed file's generation stamp against worker /health, so a SKIPPED
# refresh fails the matrix loudly instead of silently validating the wrong set.
#
# This script is READ-ONLY with respect to the running stack: it copies out of
# the worker container and never writes into the volume, restarts a service, or
# mutates a generation.

set -euo pipefail

# NAN-2361: default to DISCOVERY rather than one validation rig's container
# name. docker-compose.opensource.yml names the shipped worker
# `nano-lake-query-worker`; the scale/smoke projects name theirs differently but
# all carry the same compose service label. --container still wins.
container=""
worker_url="http://127.0.0.1:3015"
destination=""
quiet="false"

usage() {
    cat >&2 <<'USAGE'
usage: refresh-host-lake-schema.sh [options]

  --container NAME   query-worker container to read from
                     (default: discovered via the compose service label
                     com.docker.compose.service=lake-query-worker, then
                     nano-lake-query-worker)
  --worker-url URL   worker base URL for the /health cross-check
                     (default: http://127.0.0.1:3015)
  --destination DIR  host directory to write into
                     (default: <repo>/logs/lake-open-core/host-schema)
  --quiet            only print the resulting worker-config path

Prints the export line to feed NANO_LAKE_WORKER_CONFIG.
USAGE
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --container) container="${2:?--container requires a value}"; shift 2 ;;
        --worker-url) worker_url="${2:?--worker-url requires a value}"; shift 2 ;;
        --destination) destination="${2:?--destination requires a value}"; shift 2 ;;
        --quiet) quiet="true"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 64 ;;
    esac
done

if [[ -z "$container" ]]; then
    container="$(docker ps --filter 'label=com.docker.compose.service=lake-query-worker' \
        --format '{{.Names}}' | head -1)"
fi
if [[ -z "$container" ]] && docker ps --format '{{.Names}}' | grep -qx 'nano-lake-query-worker'; then
    container="nano-lake-query-worker"
fi
if [[ -z "$container" ]]; then
    echo "no running lake query worker found; pass --container NAME or start the lake control plane:" >&2
    echo "  COMPOSE_PROFILES=lake docker compose -f docker-compose.opensource.yml up -d" >&2
    exit 1
fi

# A restarting worker cannot be `docker cp`d from, and the raw daemon error
# ("Container <hex> is restarting, wait until the container is running") reads
# like a transient hiccup when it is usually a crash loop. Say which it is.
state="$(docker inspect "$container" --format '{{.State.Status}} {{.RestartCount}}' 2>/dev/null || true)"
if [[ "${state%% *}" != "running" ]]; then
    echo "lake query worker '$container' is ${state%% *} (restarts: ${state##* }); cannot read its config." >&2
    echo "  docker logs --tail 40 $container" >&2
    exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
destination="${destination:-$repo_root/logs/lake-open-core/host-schema}"

for tool in docker curl python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "❌ $tool is required" >&2
        exit 69
    }
done

if ! docker inspect "$container" >/dev/null 2>&1; then
    echo "❌ container $container is not present; start the lake stack first" >&2
    exit 69
fi

# Resolve --config from the container's own command rather than assuming the
# default path, so a worker started with an override is still handled.
worker_config_in_container="$(docker inspect "$container" --format '{{json .Config.Cmd}}' \
    | python3 -c '
import json, sys
command = json.load(sys.stdin) or []
for index, argument in enumerate(command):
    if argument == "--config" and index + 1 < len(command):
        print(command[index + 1])
        break
')"
worker_config_in_container="${worker_config_in_container:-/var/lib/nano-lake/config/worker.json}"

mkdir -p "$destination"
container_config="$destination/.worker.container.json"
docker exec "$container" cat "$worker_config_in_container" > "$container_config"

manifest_in_container="$(python3 -c '
import json, sys
config = json.load(open(sys.argv[1]))
print(config["tenant"]["source_manifest"]["path"])
' "$container_config")"

host_manifest="$destination/source-manifest.json"
# `docker cp` reads the volume through the container without needing it to serve
# a request, and works for a multi-megabyte manifest where `exec cat` would be
# at the mercy of stdio buffering.
docker cp "$container:$manifest_in_container" "$host_manifest" >/dev/null

# Fail closed on a torn or mismatched copy: the worker verifies this digest for
# itself (VerifiedArtifact), so a host copy that does not match it is not the
# manifest the worker is serving.
python3 - "$container_config" "$host_manifest" "$destination/worker.json" "$worker_url" <<'PYTHON'
import hashlib
import json
import sys
import urllib.request

container_config_path, host_manifest_path, output_path, worker_url = sys.argv[1:5]

config = json.load(open(container_config_path))
declared = config["tenant"]["source_manifest"]["sha256"]

digest = hashlib.sha256()
with open(host_manifest_path, "rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
observed = digest.hexdigest()

if observed != declared:
    raise SystemExit(
        f"❌ copied manifest digest {observed[:16]}... != declared {declared[:16]}...; "
        "the generation rotated mid-copy -- re-run this script"
    )

# Cross-check the worker is actually serving the generation we just copied. A
# promotion between the copy and this probe means the copy is already stale.
with urllib.request.urlopen(f"{worker_url}/health", timeout=5) as response:
    health = json.load(response)

if health.get("tenant_id") and health["tenant_id"] != config.get("assigned_tenant_id"):
    raise SystemExit(
        f"❌ worker serves tenant {health['tenant_id']!r} but the config is assigned "
        f"{config.get('assigned_tenant_id')!r}; refusing to write a cross-tenant host config"
    )
if health.get("generation_id") != config.get("generation_id"):
    raise SystemExit(
        f"❌ worker generation {health.get('generation_id')} != copied config "
        f"{config.get('generation_id')}; a promotion raced this refresh -- re-run"
    )

# Only the manifest pointer is rewritten; every other field stays byte-faithful
# so the file keeps describing the generation the worker actually serves.
config["tenant"]["source_manifest"]["path"] = host_manifest_path
if isinstance(config.get("entity_sidecar"), dict):
    # The activator writes the same {path,sha256} to both keys; keep them agreed.
    if config["entity_sidecar"].get("manifest", {}).get("sha256") == declared:
        config["entity_sidecar"]["manifest"]["path"] = host_manifest_path

with open(output_path, "w") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PYTHON

generation="$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["generation_id"])
' "$destination/worker.json")"

rm -f "$container_config"

if [[ "$quiet" == "true" ]]; then
    echo "$destination/worker.json"
else
    echo "✅ host lake schema refreshed from $container"
    echo "   generation:      $generation"
    echo "   worker config:   $destination/worker.json"
    echo "   source manifest: $host_manifest"
    echo
    echo "export NANO_LAKE_WORKER_CONFIG=$destination/worker.json"
    echo "# unset NANO_LAKE_SCHEMA_MANIFEST so the worker config is the single source"
fi
