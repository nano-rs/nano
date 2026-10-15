#!/usr/bin/env bash
#
# Refuse a PostgreSQL major-version mismatch BEFORE it becomes a crash loop.
#
# nano's open-core compose pins `postgres:18`. A PostgreSQL server refuses to
# open a data directory written by a different major version:
#
#   FATAL:  database files are incompatible with server
#   DETAIL: The data directory was initialized by PostgreSQL version 17,
#           which is not compatible with this version 18.6
#
# Because the `postgres` service is `restart: unless-stopped`, that becomes an
# invisible crash loop: every service gated on `postgres: service_healthy` waits
# forever, and `install.sh` eventually times out blaming nano-api/nginx. This
# script turns that into an immediate, actionable failure.
#
# Usage:
#   scripts/preflight-postgres-major.sh [-f COMPOSE_FILE] [-v VOLUME] [-p PROJECT]
#
#   -f  compose file to read the postgres image pin from
#       (default: docker-compose.opensource.yml)
#   -v  docker volume holding PGDATA (default: resolved from -p, else
#       nano-postgres-data)
#   -p  compose project name, used to resolve the real volume name
#       (default: the compose file's directory, matching Compose's own rule)
#
# Exit codes:  0 = safe to start (empty volume, or majors match)
#              1 = major-version mismatch (message explains the fix)
#              2 = usage / environment error
#
# Read-only: mounts the data volume `:ro` and never writes to it.

set -euo pipefail

COMPOSE_FILE="docker-compose.opensource.yml"
VOLUME=""
PROJECT=""

while getopts ":f:v:p:h" opt; do
    case "$opt" in
        f) COMPOSE_FILE="$OPTARG" ;;
        v) VOLUME="$OPTARG" ;;
        p) PROJECT="$OPTARG" ;;
        h) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "usage: $0 [-f COMPOSE_FILE] [-v VOLUME] [-p PROJECT]" >&2; exit 2 ;;
    esac
done

err()  { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; }
ok()   { printf '  \033[32mok\033[0m   %s\n' "$*"; }
note() { printf '  \033[33m…\033[0m    %s\n' "$*"; }

command -v docker >/dev/null 2>&1 || { err "docker is required."; exit 2; }
[[ -f "$COMPOSE_FILE" ]] || { err "$COMPOSE_FILE not found — run from the repo root."; exit 2; }

# The pinned postgres image, taken straight from the compose so this can never
# drift from what the stack actually starts.
PG_IMAGE=$(grep -oE 'image:[[:space:]]*postgres:[0-9]+@sha256:[0-9a-f]+' "$COMPOSE_FILE" \
    | head -1 | sed 's/^image:[[:space:]]*//')
if [[ -z "$PG_IMAGE" ]]; then
    PG_IMAGE=$(grep -oE 'image:[[:space:]]*postgres:[0-9]+' "$COMPOSE_FILE" | head -1 | sed 's/^image:[[:space:]]*//')
fi
[[ -n "$PG_IMAGE" ]] || { err "no postgres image pin found in $COMPOSE_FILE"; exit 2; }

# Compose derives the volume name as <project>_<volume>. The project defaults to
# the basename of the directory holding the compose file.
if [[ -z "$VOLUME" ]]; then
    if [[ -z "$PROJECT" ]]; then
        PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$(cd "$(dirname "$COMPOSE_FILE")" && pwd -P)")}"
    fi
    # Normalize the way Compose does: lowercase, non-alphanumerics to '-'.
    PROJECT=$(printf '%s' "$PROJECT" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]/-/g')
    VOLUME="${PROJECT}_nano-postgres-data"
fi

if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then
    ok "no existing PostgreSQL volume ($VOLUME) — a fresh cluster will be initialized."
    exit 0
fi

# PG_MAJOR is set by the official image, so the expected major follows the pin
# automatically instead of being hardcoded here.
EXPECTED=$(docker run --rm --entrypoint sh "$PG_IMAGE" -c 'printf "%s" "$PG_MAJOR"' 2>/dev/null || true)
[[ -n "$EXPECTED" ]] || { err "could not read PG_MAJOR from $PG_IMAGE"; exit 2; }

FOUND=$(docker run --rm -v "$VOLUME":/pgdata:ro --entrypoint sh "$PG_IMAGE" \
    -c 'if [ -f /pgdata/PG_VERSION ]; then tr -d "[:space:]" < /pgdata/PG_VERSION; fi' 2>/dev/null || true)

if [[ -z "$FOUND" ]]; then
    ok "volume $VOLUME holds no cluster yet — PostgreSQL $EXPECTED will initialize it."
    exit 0
fi

if [[ "$FOUND" == "$EXPECTED" ]]; then
    ok "volume $VOLUME is PostgreSQL $FOUND, matching the pinned server ($PG_IMAGE)."
    exit 0
fi

err "PostgreSQL major-version mismatch — refusing to start."
cat >&2 <<MSG

  Data directory : $VOLUME  (PostgreSQL $FOUND)
  Pinned server  : $PG_IMAGE  (PostgreSQL $EXPECTED)

  PostgreSQL $EXPECTED cannot open a PostgreSQL $FOUND data directory. Starting the
  stack as-is gives you a crash-looping 'postgres' container and every other
  service stuck waiting on it.

  Migrate the data first (offline, non-destructive — your $FOUND volume is kept):

      docker compose -f $COMPOSE_FILE down
      scripts/upgrade-postgres-major.sh -f $COMPOSE_FILE
      docker compose -f $COMPOSE_FILE up -d

  Runbook: docs/getting-started/open-core-operations.md
MSG
note "To inspect first: scripts/upgrade-postgres-major.sh -f $COMPOSE_FILE --dry-run"
exit 1
