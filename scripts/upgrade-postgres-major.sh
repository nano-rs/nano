#!/usr/bin/env bash
#
# Offline PostgreSQL major-version upgrade for an open-core nano install.
#
# nano's open-core compose pins a single PostgreSQL major. A server refuses to
# open a data directory written by a different major, so bumping the pin on an
# existing install requires migrating the data. This script does that with a
# dump/restore, which needs no extra tooling beyond the two postgres images and
# works across any major-version gap.
#
# It is NON-DESTRUCTIVE by construction:
#   1. Byte-copies the existing volume to  <volume>__pg<old>__<timestamp>
#      (kept forever — this is the rollback artifact).
#   2. Runs the OLD server against that copy and `pg_dumpall`s it to a plain-SQL
#      file on the host (a second, independent recovery path).
#   3. Initializes a NEW cluster on the pinned major in a scratch volume and
#      restores the dump into it.
#   4. VERIFIES the restore (database list, per-database table counts, the
#      _sqlx_migrations row count, and the bootstrap superuser) against the
#      source before touching anything else.
#   5. Only then swaps the verified new cluster into the volume the compose
#      expects, and removes the scratch volume.
#
# The original data is never written to: step 2 runs against the copy.
#
# Usage:
#   docker compose -f docker-compose.opensource.yml down
#   scripts/upgrade-postgres-major.sh [-f COMPOSE_FILE] [-p PROJECT] [-v VOLUME]
#                                     [-b BACKUP_DIR] [--dry-run] [--yes]
#   docker compose -f docker-compose.opensource.yml up -d
#
# Exit codes: 0 = upgraded, or already on the pinned major (idempotent)
#             1 = refused or failed (nothing swapped; original volume intact)
#             2 = usage / environment error

set -euo pipefail

COMPOSE_FILE="docker-compose.opensource.yml"
PROJECT=""
VOLUME=""
BACKUP_DIR="./backups"
DRY_RUN=0
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f) COMPOSE_FILE="$2"; shift 2 ;;
        -p) PROJECT="$2"; shift 2 ;;
        -v) VOLUME="$2"; shift 2 ;;
        -b) BACKUP_DIR="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

c_reset='\033[0m'; c_red='\033[31m'; c_green='\033[32m'; c_yellow='\033[33m'; c_blue='\033[34m'
log()  { printf "%b==>%b %s\n" "$c_blue" "$c_reset" "$*"; }
ok()   { printf "%b  ok%b   %s\n" "$c_green" "$c_reset" "$*"; }
warn() { printf "%b   !%b   %s\n" "$c_yellow" "$c_reset" "$*"; }
die()  { printf "%bFAIL%b %s\n" "$c_red" "$c_reset" "$*" >&2; exit "${2:-1}"; }

command -v docker >/dev/null 2>&1 || die "docker is required." 2
[[ -f "$COMPOSE_FILE" ]] || die "$COMPOSE_FILE not found — run from the repo root." 2

# ---------------------------------------------------------------------------
# Resolve the pinned image, the expected major, and the volume.
# ---------------------------------------------------------------------------
PG_IMAGE=$(grep -oE 'image:[[:space:]]*postgres:[0-9]+@sha256:[0-9a-f]+' "$COMPOSE_FILE" \
    | head -1 | sed 's/^image:[[:space:]]*//')
[[ -n "$PG_IMAGE" ]] || PG_IMAGE=$(grep -oE 'image:[[:space:]]*postgres:[0-9]+' "$COMPOSE_FILE" \
    | head -1 | sed 's/^image:[[:space:]]*//')
[[ -n "$PG_IMAGE" ]] || die "no postgres image pin found in $COMPOSE_FILE" 2

if [[ -z "$VOLUME" ]]; then
    if [[ -z "$PROJECT" ]]; then
        PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$(cd "$(dirname "$COMPOSE_FILE")" && pwd -P)")}"
    fi
    PROJECT=$(printf '%s' "$PROJECT" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]/-/g')
    VOLUME="${PROJECT}_nano-postgres-data"
fi

docker volume inspect "$VOLUME" >/dev/null 2>&1 \
    || die "volume $VOLUME does not exist — nothing to upgrade. (Pass -v/-p if your project name differs.)"

NEW_MAJOR=$(docker run --rm --entrypoint sh "$PG_IMAGE" -c 'printf "%s" "$PG_MAJOR"' 2>/dev/null || true)
[[ -n "$NEW_MAJOR" ]] || die "could not read PG_MAJOR from $PG_IMAGE" 2

OLD_MAJOR=$(docker run --rm -v "$VOLUME":/pgdata:ro --entrypoint sh "$PG_IMAGE" \
    -c 'if [ -f /pgdata/PG_VERSION ]; then tr -d "[:space:]" < /pgdata/PG_VERSION; fi' 2>/dev/null || true)
[[ -n "$OLD_MAJOR" ]] || die "volume $VOLUME holds no PostgreSQL cluster (no PG_VERSION) — nothing to upgrade."

log "volume        : $VOLUME"
log "current major : PostgreSQL $OLD_MAJOR"
log "pinned server : $PG_IMAGE (PostgreSQL $NEW_MAJOR)"

if [[ "$OLD_MAJOR" == "$NEW_MAJOR" ]]; then
    ok "already on PostgreSQL $NEW_MAJOR — nothing to do."
    exit 0
fi
if (( OLD_MAJOR > NEW_MAJOR )); then
    die "the volume is PostgreSQL $OLD_MAJOR but the compose pins $NEW_MAJOR. Downgrades are not supported; restore from a backup taken on $NEW_MAJOR instead."
fi

RUNNING=$(docker ps -q --filter "volume=$VOLUME" | wc -l | tr -d ' ')
if [[ "$RUNNING" != "0" ]]; then
    docker ps --filter "volume=$VOLUME" --format '  {{.Names}} ({{.Status}})' >&2
    die "the volume is in use by the container(s) above. Stop the stack first: docker compose -f $COMPOSE_FILE down"
fi

OLD_IMAGE="postgres:${OLD_MAJOR}"
TS=$(date +%Y%m%d-%H%M%S)
SNAPSHOT="${VOLUME}__pg${OLD_MAJOR}__${TS}"
SCRATCH="${VOLUME}__pg${NEW_MAJOR}__${TS}"
DUMP_FILE="${BACKUP_DIR}/${VOLUME}-pg${OLD_MAJOR}-${TS}.sql"
RESTORE_LOG="${BACKUP_DIR}/${VOLUME}-pg${NEW_MAJOR}-${TS}.restore.log"

if (( DRY_RUN )); then
    cat <<PLAN

Plan (nothing has been changed):
  1. copy    $VOLUME  ->  $SNAPSHOT            (rollback artifact, kept)
  2. dump    $OLD_IMAGE on the copy  ->  $DUMP_FILE
  3. init    $PG_IMAGE in $SCRATCH and restore the dump
  4. verify  database list, table counts, _sqlx_migrations, superuser
  5. swap    the verified cluster into $VOLUME, remove $SCRATCH

  $OLD_IMAGE is pulled from Docker Hub by tag (the repo pins only the target
  major). Re-run without --dry-run to perform the upgrade.

PLAN
    exit 0
fi

if (( ! ASSUME_YES )); then
    # /dev/tty can exist yet be unopenable (no controlling terminal: CI,
    # setsid, agents); probe it so that case gets the --yes message below.
    if [[ -t 0 ]] || { : </dev/tty; } 2>/dev/null; then
        printf 'Upgrade %s from PostgreSQL %s to %s? [y/N] ' "$VOLUME" "$OLD_MAJOR" "$NEW_MAJOR" > /dev/tty
        read -r reply < /dev/tty || reply=""
        case "$reply" in [yY]*) ;; *) die "aborted by operator." ;; esac
    else
        die "refusing to run non-interactively without --yes."
    fi
fi

mkdir -p "$BACKUP_DIR"
BACKUP_ABS="$(cd "$BACKUP_DIR" && pwd -P)"

cleanup_scratch() {
    docker rm -f "pgupg-old-$TS" "pgupg-new-$TS" >/dev/null 2>&1 || true
}
trap cleanup_scratch EXIT

# ---------------------------------------------------------------------------
# 1. Snapshot the existing volume. The original is never written to after this.
# ---------------------------------------------------------------------------
log "1/5 copying $VOLUME -> $SNAPSHOT"
docker volume create "$SNAPSHOT" >/dev/null
docker run --rm -v "$VOLUME":/from:ro -v "$SNAPSHOT":/to --entrypoint sh "$PG_IMAGE" \
    -c 'cd /from && cp -a . /to/' || die "snapshot copy failed — original volume untouched."
ok "snapshot volume $SNAPSHOT created"

# ---------------------------------------------------------------------------
# 2. Dump from the snapshot using the OLD server.
# ---------------------------------------------------------------------------
log "2/5 dumping with $OLD_IMAGE (this pulls the old image if absent)"
docker run --rm -d --name "pgupg-old-$TS" \
    -e POSTGRES_PASSWORD=upgrade-scratch \
    -e PGDATA=/var/lib/postgresql/data \
    -v "$SNAPSHOT":/var/lib/postgresql/data \
    "$OLD_IMAGE" >/dev/null || die "could not start $OLD_IMAGE on the snapshot."

for _ in $(seq 1 90); do
    docker exec "pgupg-old-$TS" pg_isready >/dev/null 2>&1 && break
    sleep 1
done
docker exec "pgupg-old-$TS" pg_isready >/dev/null 2>&1 \
    || { docker logs --tail 30 "pgupg-old-$TS" >&2; die "old server never became ready."; }

# The bootstrap superuser is always OID 10 — read it rather than assume a name.
SUPERUSER=$(docker exec "pgupg-old-$TS" psql -U postgres -tAc \
    "SELECT rolname FROM pg_roles WHERE oid = 10" 2>/dev/null || true)
if [[ -z "$SUPERUSER" ]]; then
    SUPERUSER=$(docker exec "pgupg-old-$TS" sh -c \
        'psql -U "$(ls /var/lib/postgresql/data/../ >/dev/null 2>&1; echo postgres)" -tAc "SELECT rolname FROM pg_roles WHERE oid = 10"' 2>/dev/null || true)
fi
# `postgres` may not exist as a role; fall back to the socket's default identity.
if [[ -z "$SUPERUSER" ]]; then
    for cand in nanosiem postgres; do
        if docker exec "pgupg-old-$TS" psql -U "$cand" -tAc 'SELECT 1' >/dev/null 2>&1; then
            SUPERUSER=$(docker exec "pgupg-old-$TS" psql -U "$cand" -tAc "SELECT rolname FROM pg_roles WHERE oid = 10")
            break
        fi
    done
fi
[[ -n "$SUPERUSER" ]] || die "could not determine the cluster's bootstrap superuser."
ok "bootstrap superuser: $SUPERUSER"

SRC_DBS=$(docker exec "pgupg-old-$TS" psql -U "$SUPERUSER" -tAc \
    "SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1")
declare -a SRC_TABLE_COUNTS=()
while IFS= read -r db; do
    [[ -z "$db" ]] && continue
    n=$(docker exec "pgupg-old-$TS" psql -U "$SUPERUSER" -d "$db" -tAc \
        "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')")
    SRC_TABLE_COUNTS+=("$db=$n")
done <<< "$SRC_DBS"
SRC_MIGRATIONS=$(docker exec "pgupg-old-$TS" psql -U "$SUPERUSER" -d "$SUPERUSER" -tAc \
    "SELECT count(*) FROM _sqlx_migrations" 2>/dev/null || echo "n/a")

docker exec "pgupg-old-$TS" pg_dumpall -U "$SUPERUSER" > "$DUMP_FILE" \
    || die "pg_dumpall failed — nothing was changed."
chmod 600 "$DUMP_FILE"
docker stop "pgupg-old-$TS" >/dev/null
ok "dump written to $BACKUP_ABS/$(basename "$DUMP_FILE") ($(wc -c < "$DUMP_FILE" | tr -d ' ') bytes)"
ok "source: $(printf '%s ' ${SRC_TABLE_COUNTS[@]+"${SRC_TABLE_COUNTS[@]}"})_sqlx_migrations=$SRC_MIGRATIONS"

# ---------------------------------------------------------------------------
# 3. Initialize the NEW cluster in a scratch volume and restore.
# ---------------------------------------------------------------------------
log "3/5 initializing PostgreSQL $NEW_MAJOR in $SCRATCH and restoring"
docker volume create "$SCRATCH" >/dev/null
docker run --rm -d --name "pgupg-new-$TS" \
    -e POSTGRES_USER="$SUPERUSER" \
    -e POSTGRES_PASSWORD=upgrade-scratch \
    -e PGDATA=/var/lib/postgresql/data \
    -v "$SCRATCH":/var/lib/postgresql/data \
    "$PG_IMAGE" >/dev/null || die "could not start the pinned server on the scratch volume."

# The image's entrypoint runs initdb behind a temporary server that listens
# only on the unix socket, then stops it and starts the real one. A socket
# probe can pass against that temporary server and the restore or the
# verification below then hits "the database system is shutting down".
# Probe over TCP: only the final server listens there.
for _ in $(seq 1 90); do
    docker exec "pgupg-new-$TS" pg_isready -h 127.0.0.1 -U "$SUPERUSER" >/dev/null 2>&1 && break
    sleep 1
done
docker exec "pgupg-new-$TS" pg_isready -h 127.0.0.1 -U "$SUPERUSER" >/dev/null 2>&1 \
    || { docker logs --tail 30 "pgupg-new-$TS" >&2; die "new server never became ready."; }

# ON_ERROR_STOP stays off: pg_dumpall recreates the bootstrap role that initdb
# already made, which is a single expected collision. Correctness is proven by
# the structural verification below, not by the absence of notices.
docker exec -i "pgupg-new-$TS" psql -U "$SUPERUSER" -d postgres -v ON_ERROR_STOP=0 \
    < "$DUMP_FILE" > "$RESTORE_LOG" 2>&1 || true

# A dropped connection is never an expected notice: fail on FATAL / lost
# server lines too, not only on ERROR.
UNEXPECTED=$(grep -E '^(psql:.*)?(ERROR|FATAL):|server closed the connection|connection to server .* failed' "$RESTORE_LOG" 2>/dev/null \
    | grep -vE 'role "'"$SUPERUSER"'" already exists' \
    | grep -vE 'database "'"$SUPERUSER"'" already exists' \
    | grep -vE 'schema "public" already exists' || true)
if [[ -n "$UNEXPECTED" ]]; then
    printf '%s\n' "$UNEXPECTED" | head -20 >&2
    die "restore reported unexpected errors (full log: $RESTORE_LOG). Original volume $VOLUME is untouched."
fi
ok "restore completed (log: $BACKUP_ABS/$(basename "$RESTORE_LOG"))"

# ---------------------------------------------------------------------------
# 4. Verify the restored cluster against the source.
# ---------------------------------------------------------------------------
log "4/5 verifying the restored cluster"
NEW_DBS=$(docker exec "pgupg-new-$TS" psql -U "$SUPERUSER" -tAc \
    "SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1")
if [[ "$(printf '%s' "$SRC_DBS")" != "$(printf '%s' "$NEW_DBS")" ]]; then
    printf 'source databases:\n%s\nrestored databases:\n%s\n' "$SRC_DBS" "$NEW_DBS" >&2
    die "database list differs after restore. Original volume $VOLUME is untouched."
fi
for entry in ${SRC_TABLE_COUNTS[@]+"${SRC_TABLE_COUNTS[@]}"}; do
    db="${entry%%=*}"; want="${entry##*=}"
    got=$(docker exec "pgupg-new-$TS" psql -U "$SUPERUSER" -d "$db" -tAc \
        "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')")
    [[ "$got" == "$want" ]] || die "table count mismatch in '$db': source=$want restored=$got. Original volume $VOLUME is untouched."
done
NEW_MIGRATIONS=$(docker exec "pgupg-new-$TS" psql -U "$SUPERUSER" -d "$SUPERUSER" -tAc \
    "SELECT count(*) FROM _sqlx_migrations" 2>/dev/null || echo "n/a")
[[ "$NEW_MIGRATIONS" == "$SRC_MIGRATIONS" ]] \
    || die "_sqlx_migrations row count mismatch: source=$SRC_MIGRATIONS restored=$NEW_MIGRATIONS. Original volume $VOLUME is untouched."
NEW_SUPER=$(docker exec "pgupg-new-$TS" psql -U "$SUPERUSER" -tAc \
    "SELECT rolname FROM pg_roles WHERE oid = 10")
[[ "$NEW_SUPER" == "$SUPERUSER" ]] \
    || die "bootstrap superuser changed: $SUPERUSER -> $NEW_SUPER. Original volume $VOLUME is untouched."
ok "verified: $(printf '%s ' ${SRC_TABLE_COUNTS[@]+"${SRC_TABLE_COUNTS[@]}"})_sqlx_migrations=$NEW_MIGRATIONS superuser=$NEW_SUPER"

docker stop "pgupg-new-$TS" >/dev/null

# ---------------------------------------------------------------------------
# 5. Swap the verified cluster into the volume the compose expects.
#    Safe: the pre-upgrade bytes live in $SNAPSHOT and the SQL in $DUMP_FILE.
# ---------------------------------------------------------------------------
log "5/5 swapping the verified PostgreSQL $NEW_MAJOR cluster into $VOLUME"
docker run --rm -v "$VOLUME":/to -v "$SCRATCH":/from:ro --entrypoint sh "$PG_IMAGE" -c '
    set -e
    find /to -mindepth 1 -delete
    cd /from && cp -a . /to/
' || die "swap failed. Recover with: docker run --rm -v $SNAPSHOT:/from:ro -v $VOLUME:/to $PG_IMAGE sh -c 'find /to -mindepth 1 -delete; cd /from && cp -a . /to/'"

SWAPPED=$(docker run --rm -v "$VOLUME":/pgdata:ro --entrypoint sh "$PG_IMAGE" \
    -c 'tr -d "[:space:]" < /pgdata/PG_VERSION')
[[ "$SWAPPED" == "$NEW_MAJOR" ]] || die "post-swap PG_VERSION is '$SWAPPED', expected $NEW_MAJOR."
docker volume rm "$SCRATCH" >/dev/null 2>&1 || warn "could not remove scratch volume $SCRATCH"

printf '\n%bPostgreSQL %s -> %s complete.%b\n\n' "$c_green" "$OLD_MAJOR" "$NEW_MAJOR" "$c_reset"
cat <<DONE
  Data volume    : $VOLUME  (now PostgreSQL $NEW_MAJOR)
  Rollback volume: $SNAPSHOT  (PostgreSQL $OLD_MAJOR — kept, delete when satisfied)
  SQL dump       : $BACKUP_ABS/$(basename "$DUMP_FILE")

  Start the stack:  docker compose -f $COMPOSE_FILE up -d
  Then validate:    scripts/smoke-open-core.sh -f $COMPOSE_FILE

  To roll back (stack stopped), restore the snapshot and re-pin the old major:
      docker run --rm -v $SNAPSHOT:/from:ro -v $VOLUME:/to $PG_IMAGE \\
        sh -c 'find /to -mindepth 1 -delete; cd /from && cp -a . /to/'
DONE
