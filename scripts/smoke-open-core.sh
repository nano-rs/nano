#!/usr/bin/env bash
#
# Post-install / post-upgrade smoke for an open-core nano deployment.
#
# WHY THIS EXISTS
# install.sh stops at "API healthy" + "admin created". Fourteen long-running
# services in the lake profile carry `restart: unless-stopped` and NO
# healthcheck, so when one of them fails it restarts forever and nothing says
# so: `docker ps` shows "Restarting", /api/health stays 200 (it covers
# PostgreSQL and the query worker, not the publish/compaction/retention lane),
# and the operator finds out when a search returns nothing. A real open-core
# validation stack was observed with four services at >3100 restarts each,
# accumulated silently over two days.
#
# This script is the missing signal. By default it is READ-ONLY (--prevalence
# is the one opt-in exception): it inspects container
# state and calls health endpoints. It never starts, stops, restarts, or
# reconfigures anything, and it writes nothing outside stdout.
#
# Usage:
#   scripts/smoke-open-core.sh [-f COMPOSE_FILE] [-p PROJECT] [-u BASE_URL]
#                              [--max-restarts N] [--quiet]
#                              [--prevalence [--env-file FILE]]
#
#   -f  compose file            (default: docker-compose.opensource.yml)
#   -p  compose project name    (default: the compose file's directory name,
#                                which is what Compose itself uses)
#   -u  base URL through nginx  (default: http://localhost)
#   --max-restarts N            restarts above which a container is a failure
#                               (default: 3 — a couple of boot-order retries are
#                               normal, a loop is not)
#   --prevalence                also run scripts/smoke-open-core-prevalence.sh
#                               (NAN-3451). That check WRITES: it ingests
#                               marked events and deploys a smoke log source,
#                               so it is opt-in and the default run stays
#                               read-only. A healthy run takes 1-3 minutes
#                               (lean stamps at ingest; the rare list is a
#                               durable job it polls).
#   --env-file FILE             env file for the prevalence check's credentials
#                               (default: .env)
#
# Exit codes: 0 = healthy, 1 = one or more checks failed, 2 = usage/environment.

set -uo pipefail

COMPOSE_FILE="docker-compose.opensource.yml"
PROJECT=""
BASE_URL="${NANO_BASE_URL:-http://localhost}"
MAX_RESTARTS=3
QUIET=0
PREVALENCE=0
ENV_FILE=".env"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f) COMPOSE_FILE="$2"; shift 2 ;;
        -p) PROJECT="$2"; shift 2 ;;
        -u) BASE_URL="$2"; shift 2 ;;
        --max-restarts) MAX_RESTARTS="$2"; shift 2 ;;
        --quiet) QUIET=1; shift ;;
        --prevalence) PREVALENCE=1; shift ;;
        --env-file) ENV_FILE="$2"; shift 2 ;;
        -h|--help) sed -n '2,43p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

c_reset='\033[0m'; c_red='\033[31m'; c_green='\033[32m'; c_yellow='\033[33m'; c_blue='\033[34m'
FAILURES=0
section() { (( QUIET )) || printf "\n%b==>%b %s\n" "$c_blue" "$c_reset" "$*"; }
ok()      { (( QUIET )) || printf "  %bok%b   %s\n" "$c_green" "$c_reset" "$*"; }
bad()     { printf "  %bFAIL%b %s\n" "$c_red" "$c_reset" "$*"; FAILURES=$((FAILURES + 1)); }
note()    { (( QUIET )) || printf "  %b…%b    %s\n" "$c_yellow" "$c_reset" "$*"; }

command -v docker >/dev/null 2>&1 || { echo "docker is required." >&2; exit 2; }
[[ -f "$COMPOSE_FILE" ]] || { echo "$COMPOSE_FILE not found — run from the repo root." >&2; exit 2; }

if [[ -z "$PROJECT" ]]; then
    PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$(cd "$(dirname "$COMPOSE_FILE")" && pwd -P)")}"
fi
PROJECT=$(printf '%s' "$PROJECT" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]/-/g')

# Portable to bash 3.2 (the macOS system bash): `mapfile` is bash 4+.
CONTAINERS=()
while IFS= read -r _name; do
    [[ -n "$_name" ]] && CONTAINERS+=("$_name")
done < <(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}')
if [[ "${#CONTAINERS[@]}" == "0" ]]; then
    echo "no containers found for compose project '$PROJECT'." >&2
    echo "Pass -p with the project name, e.g.:  $0 -p nano" >&2
    docker ps --format '  {{.Names}}  (project: {{.Label "com.docker.compose.project"}})' >&2
    exit 2
fi
printf "%bopen-core smoke%b  project=%s  compose=%s  base=%s\n" "$c_blue" "$c_reset" "$PROJECT" "$COMPOSE_FILE" "$BASE_URL"

# ---------------------------------------------------------------------------
# 1. Restart loops — the failure mode nothing else reports.
# ---------------------------------------------------------------------------
section "restart loops (> $MAX_RESTARTS restarts, or currently restarting)"
looping=0
for c in ${CONTAINERS[@]+"${CONTAINERS[@]}"}; do
    read -r status restarts <<< "$(docker inspect "$c" --format '{{.State.Status}} {{.RestartCount}}' 2>/dev/null || echo "unknown 0")"
    if [[ "$status" == "restarting" ]] || (( restarts > MAX_RESTARTS )); then
        looping=$((looping + 1))
        svc=$(docker inspect "$c" --format '{{index .Config.Labels "com.docker.compose.service"}}' 2>/dev/null)
        bad "$c (service: ${svc:-?}) status=$status restarts=$restarts"
        # The last non-empty log line is almost always the recurring cause.
        last=$(docker logs --tail 40 "$c" 2>&1 | grep -vE '^\s*$' | tail -1 | cut -c1-160)
        [[ -n "$last" ]] && printf "         last: %s\n" "$last"
    fi
done
(( looping == 0 )) && ok "no container is restarting or above $MAX_RESTARTS restarts"

# ---------------------------------------------------------------------------
# 2. One-shot bootstrap services must have completed successfully.
# ---------------------------------------------------------------------------
section "one-shot bootstrap services exited 0"
oneshot=0
for c in ${CONTAINERS[@]+"${CONTAINERS[@]}"}; do
    # `restart: "no"` is the usual one-shot. `restart: on-failure` is also a
    # one-shot (lake-catalog-migrate uses it to retry a transient catalog
    # outage), so a clean exit 0 there is success, not a stopped service.
    policy=$(docker inspect "$c" --format '{{.HostConfig.RestartPolicy.Name}}' 2>/dev/null)
    [[ "$policy" == "no" || "$policy" == "" || "$policy" == "on-failure" ]] || continue
    read -r status code <<< "$(docker inspect "$c" --format '{{.State.Status}} {{.State.ExitCode}}' 2>/dev/null || echo "unknown 1")"
    oneshot=$((oneshot + 1))
    if [[ "$status" == "exited" && "$code" == "0" ]]; then
        ok "$c exited 0"
    elif [[ "$status" == "running" || "$status" == "created" ]]; then
        note "$c is $status (still bootstrapping)"
    else
        bad "$c status=$status exit=$code"
        docker logs --tail 8 "$c" 2>&1 | sed 's/^/         /' | tail -8
    fi
done
(( oneshot == 0 )) && note "no one-shot services in this project"

# ---------------------------------------------------------------------------
# 3. Long-running services are running, and healthy where a healthcheck exists.
# ---------------------------------------------------------------------------
section "long-running services"
for c in ${CONTAINERS[@]+"${CONTAINERS[@]}"}; do
    # Mirror of the classification above: only always/unless-stopped services
    # are expected to be running right now.
    policy=$(docker inspect "$c" --format '{{.HostConfig.RestartPolicy.Name}}' 2>/dev/null)
    [[ "$policy" == "always" || "$policy" == "unless-stopped" ]] || continue
    status=$(docker inspect "$c" --format '{{.State.Status}}' 2>/dev/null)
    health=$(docker inspect "$c" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null)
    if [[ "$status" != "running" ]]; then
        bad "$c is $status (expected running)"
    elif [[ "$health" == "unhealthy" ]]; then
        bad "$c is running but unhealthy"
        docker inspect "$c" --format '{{range .State.Health.Log}}{{.Output}}{{end}}' 2>/dev/null | tail -3 | sed 's/^/         /'
    elif [[ "$health" == "none" ]]; then
        ok "$c running (no healthcheck; restart count is its only signal)"
    else
        ok "$c running ($health)"
    fi
done

# ---------------------------------------------------------------------------
# 4. PostgreSQL major matches the pin.
# ---------------------------------------------------------------------------
section "PostgreSQL major version"
if [[ -x ./scripts/preflight-postgres-major.sh ]]; then
    if out=$(./scripts/preflight-postgres-major.sh -f "$COMPOSE_FILE" -p "$PROJECT" 2>&1); then
        ok "$(printf '%s' "$out" | tail -1 | sed 's/^[[:space:]]*//')"
    else
        bad "data directory major does not match the pinned server"
        printf '%s\n' "$out" | sed 's/^/         /'
    fi
else
    note "scripts/preflight-postgres-major.sh not present — skipped"
fi

# ---------------------------------------------------------------------------
# 5. HTTP surfaces through nginx.
# ---------------------------------------------------------------------------
section "HTTP surfaces"
if command -v curl >/dev/null 2>&1; then
    body=$(curl -fsS --max-time 10 "$BASE_URL/api/health" 2>/dev/null || true)
    if [[ -z "$body" ]]; then
        bad "GET $BASE_URL/api/health did not return 200"
    elif grep -q '"status":"ok"' <<< "$body"; then
        ok "GET /api/health -> ok"
    else
        bad "GET /api/health -> $body"
    fi

    status_json=$(curl -fsS --max-time 10 "$BASE_URL/api/setup/status" 2>/dev/null || true)
    if grep -q '"initialized":true' <<< "$status_json"; then
        ok "GET /api/setup/status -> initialized"
    elif [[ -n "$status_json" ]]; then
        note "GET /api/setup/status -> not initialized (no admin account yet)"
    else
        bad "GET $BASE_URL/api/setup/status did not return 200"
    fi
else
    note "curl not installed — HTTP checks skipped"
fi

# ---------------------------------------------------------------------------
# 6. Lake query worker, when this project runs the lake profile.
# ---------------------------------------------------------------------------
worker=$(docker ps --filter "label=com.docker.compose.project=$PROJECT" \
    --filter 'label=com.docker.compose.service=lake-query-worker' --format '{{.Names}}' | head -1)
if [[ -n "$worker" ]]; then
    section "lake query worker"
    port=$(docker port "$worker" 3015/tcp 2>/dev/null | head -1 | sed 's/.*://')
    if [[ -z "$port" ]]; then
        note "$worker publishes no host port for 3015 — probing from inside the container"
        health=$(docker exec "$worker" sh -c 'curl -fsS --max-time 5 http://127.0.0.1:3015/health' 2>/dev/null || true)
    else
        health=$(curl -fsS --max-time 5 "http://127.0.0.1:${port}/health" 2>/dev/null || true)
    fi
    if [[ -z "$health" ]]; then
        bad "lake query worker /health is unreachable"
    else
        gen=$(printf '%s' "$health" | sed -n 's/.*"generation_id":"\([^"]*\)".*/\1/p')
        if grep -q '"status":"ok"\|"ready":true' <<< "$health"; then
            ok "lake query worker healthy (generation: ${gen:-unknown})"
        else
            bad "lake query worker /health -> $(printf '%s' "$health" | cut -c1-160)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 7. Prevalence end to end (opt-in, writes): ingest-time enrichments[]
#    stamps, prevalence_min, `| prevalence file_hash`, the hash lookup and the
#    durable rare-list job.
# ---------------------------------------------------------------------------
if (( PREVALENCE )); then
    section "prevalence (writes smoke events)"
    if bash "$(dirname "$0")/smoke-open-core-prevalence.sh" -u "$BASE_URL" --env-file "$ENV_FILE"; then
        ok "prevalence smoke passed"
    else
        bad "prevalence smoke failed (see output above)"
    fi
fi

# ---------------------------------------------------------------------------
printf "\n"
if (( FAILURES == 0 )); then
    printf "%bopen-core smoke passed.%b\n" "$c_green" "$c_reset"
    exit 0
fi
printf "%b%s check(s) failed.%b\n" "$c_red" "$FAILURES" "$c_reset"
printf "Runbook: docs/getting-started/open-core-operations.md\n"
exit 1
