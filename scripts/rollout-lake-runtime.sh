#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

# Coordinate an in-place open-core lake upgrade without replacing the only
# query worker before the new maintenance image has published a generation
# pinned to the same query compiler. All arguments are passed to
# `docker compose` (for example: -f docker-compose.opensource.yml).

set -euo pipefail

if [[ "$#" -eq 0 ]]; then
    echo "usage: $0 <docker compose arguments>" >&2
    exit 64
fi

compose=(docker compose "$@")
poll_seconds="${NANO_LAKE_ROLLOUT_POLL_SECS:-2}"
timeout_seconds="${NANO_LAKE_ROLLOUT_TIMEOUT_SECS:-300}"

service_is_running() {
    local service="$1"
    "${compose[@]}" ps --status running --services 2>/dev/null \
        | grep -Fxq "$service"
}

compiler_sha_from_worker_config() {
    "${compose[@]}" exec -T lake-generation-manager sh -c '
        sed -n '\''/"compiler"[[:space:]]*:/,/}/ {
            /"sha256"/ {
                s/.*"sha256":[[:space:]]*"\([^"]*\)".*/\1/p
                q
            }
        }'\'' /var/lib/nano-lake/config/worker.json
    ' 2>/dev/null || true
}

# The serving compiler digest is on the bearer-authenticated /v1/identity
# route; the unauthenticated /health carries only the status verdict since
# NAN-2361 P2. Reading /health here returned nothing, so every in-place
# re-run of install.sh on the lake profile timed out and failed (NAN-3389).
# The token is read inside the worker container and never leaves it.
# shellcheck disable=SC2016  # $(cat …) must expand inside the container
compiler_sha_from_identity() {
    "${compose[@]}" exec -T lake-query-worker sh -c \
        'curl -fsS --max-time 3 -H "Authorization: Bearer $(cat /var/lib/nano-lake/config/query-token)" http://127.0.0.1:3015/v1/identity' 2>/dev/null \
        | sed -n 's/.*"compiler_sha256":"\([^"]*\)".*/\1/p' \
        | head -1 || true
}

query_image="${NANO_LAKE_QUERY_IMAGE_REF:-}"
if [[ -z "$query_image" ]]; then
    while IFS= read -r image; do
        case "$image" in
            *nano-lake-query:*) query_image="$image"; break ;;
        esac
    done < <("${compose[@]}" config --images)
fi
if [[ -z "$query_image" ]]; then
    echo "lake rollout: could not resolve the lake query image" >&2
    exit 1
fi

expected_compiler_sha="$({
    docker run --rm --entrypoint /bin/sh "$query_image" -c \
        'tr -d "\r\n" < /usr/local/lib/nano-lake/lake_query_compile.sha256'
} 2>/dev/null)"
if [[ ! "$expected_compiler_sha" =~ ^[0-9a-f]{64}$ ]]; then
    echo "lake rollout: query image did not expose a valid compiler SHA-256" >&2
    exit 1
fi

# A fresh install has no serving worker to preserve. Let the ordinary Compose
# dependency graph bootstrap it instead of inventing an upgrade path.
if ! service_is_running lake-query-worker \
    || ! service_is_running lake-generation-manager; then
    echo "lake rollout: no existing lake runtime; normal bootstrap required"
    exit 0
fi

current_compiler_sha="$(compiler_sha_from_identity)"
if [[ "$current_compiler_sha" == "$expected_compiler_sha" ]]; then
    echo "lake rollout: query compiler already matches the pulled image"
    exit 0
fi

echo "lake rollout: staging maintenance image for compiler $expected_compiler_sha"
"${compose[@]}" up -d --no-deps --force-recreate lake-generation-manager

deadline=$(( $(date +%s) + timeout_seconds ))
staged_compiler_sha=""
while (( $(date +%s) < deadline )); do
    staged_compiler_sha="$(compiler_sha_from_worker_config)"
    if [[ "$staged_compiler_sha" == "$expected_compiler_sha" ]]; then
        break
    fi
    if ! service_is_running lake-generation-manager; then
        echo "lake rollout: generation manager stopped before staging the compiler" >&2
        exit 1
    fi
    sleep "$poll_seconds"
done
if [[ "$staged_compiler_sha" != "$expected_compiler_sha" ]]; then
    echo "lake rollout: timed out waiting for a generation compatible with $expected_compiler_sha" >&2
    exit 1
fi

# The old worker keeps its already-loaded generation if hot reload rejects the
# new compiler digest. Replace it only after the compatible config is durable;
# the activator waits for this new process before committing promotion.
echo "lake rollout: compatible generation staged; replacing query and durable runners"
"${compose[@]}" up -d --no-deps --force-recreate \
    lake-query-worker lake-job-runner

deadline=$(( $(date +%s) + timeout_seconds ))
healthy_compiler_sha=""
while (( $(date +%s) < deadline )); do
    healthy_compiler_sha="$(compiler_sha_from_identity)"
    if [[ "$healthy_compiler_sha" == "$expected_compiler_sha" ]]; then
        echo "lake rollout: query worker is healthy on compiler $expected_compiler_sha"
        exit 0
    fi
    sleep "$poll_seconds"
done

echo "lake rollout: replacement query worker did not become healthy on the expected compiler" >&2
exit 1
