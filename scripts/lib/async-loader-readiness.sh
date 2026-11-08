#!/usr/bin/env bash
# Shared ClickHouse asynchronous-loader readiness state machine.
# The caller supplies nano_async_loader_query, which prints:
#   <failed> <not_ok> <total>

nano_wait_async_loaders() {
    local timeout_seconds="${1:-300}" interval_seconds="${2:-3}"
    local deadline response failed not_ok total
    deadline=$(( $(date +%s) + timeout_seconds ))

    while :; do
        response=$(nano_async_loader_query 2>/dev/null || true)
        if [[ "$response" =~ ^([0-9]+)[[:space:]]+([0-9]+)[[:space:]]+([0-9]+)$ ]]; then
            failed=${BASH_REMATCH[1]}
            not_ok=${BASH_REMATCH[2]}
            total=${BASH_REMATCH[3]}
            if (( failed > 0 )); then
                printf 'ClickHouse asynchronous loader reports %s failed object(s) across the cluster.\n' "$failed" >&2
                return 2
            fi
            if (( total > 0 && not_ok == 0 )); then
                printf 'ClickHouse asynchronous loader ready (%s object states are OK).\n' "$total"
                return 0
            fi
        fi
        if (( $(date +%s) >= deadline )); then
            printf 'Timed out waiting for every ClickHouse asynchronous-loader object to become OK (last result: %s).\n' "${response:-unavailable}" >&2
            return 1
        fi
        sleep "$interval_seconds"
    done
}
