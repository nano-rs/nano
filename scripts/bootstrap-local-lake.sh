#!/usr/bin/env bash
#
# Bring a LOCAL, host-run OCSF lake to the point where the product can start.
#
# scripts/start-microservices-dev.sh runs api/search/jobs and every lake binary
# from source on the host. What it cannot do by itself is stand up the lake's
# INFRASTRUCTURE and the one-time bootstrap artifacts, which in a deployment are
# containers built from first-party images. This script does exactly that, from
# third-party images plus binaries built from this checkout — no ghcr.io/nano-rs
# image is pulled or needed.
#
# It is idempotent: every step is a no-op when already satisfied, so it is safe
# to re-run before each dev session. `--lake` calls it for you.
#
# Steps
#   1. infrastructure   PostgreSQL, Dragonfly, RustFS, Hydra, OpenFGA, Lakekeeper
#                       (docker-compose.opensource.yml + docker-compose.localdev.yml)
#   2. object bucket    the Bronze/warehouse bucket in RustFS
#   3. PostgreSQL       the product schema (postgres_migrator, built here)
#   4. catalog          Lakekeeper warehouse + OIDC clients (lake_catalog_bootstrap)
#   5. chDB             the native query library for THIS platform, digest-verified
#   6. worker config    worker.json pinned to the host chDB + host compiler
#
# Usage: scripts/bootstrap-local-lake.sh [--print-env] [--skip-infra] [--reset-db]
#   --print-env   emit the resulting KEY=VALUE lines on stdout and nothing else
#   --reset-db    DROP and recreate the dev database first. Needed after a
#                 migration file changes under an already-migrated dev database
#                 (sqlx refuses: "migration N was previously applied but has
#                 been modified"). Destroys local dev data only.
#
# Everything it creates lives under .state/lake/ and in the compose project;
# nothing is written outside the repo.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

PRINT_ENV=0
SKIP_INFRA=0
RESET_DB=0
for arg in "$@"; do
    case "$arg" in
        --print-env) PRINT_ENV=1 ;;
        --skip-infra) SKIP_INFRA=1 ;;
        --reset-db) RESET_DB=1 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

BASE_COMPOSE="docker-compose.opensource.yml"
DEV_COMPOSE="docker-compose.localdev.yml"
STATE="$REPO_ROOT/.state/lake"
CONFIG_DIR="$STATE/config"
CHDB_DIR="$STATE/chdb"

# stdout is reserved for --print-env; everything human goes to stderr.
say()  { (( PRINT_ENV )) || printf '\033[34m==>\033[0m %s\n' "$*" >&2; }
ok()   { (( PRINT_ENV )) || printf '  \033[32mok\033[0m   %s\n' "$*" >&2; }
die()  { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is required."
command -v cargo  >/dev/null 2>&1 || die "cargo is required (the lake binaries are built from source)."
[[ -f "$BASE_COMPOSE" ]] || die "$BASE_COMPOSE not found — run from the repo root."
[[ -f "$DEV_COMPOSE"  ]] || die "$DEV_COMPOSE not found (the loopback port overlay)."
[[ -f .env ]] || die ".env not found. Generate one first (see docs/getting-started/open-core-operations.md)."

set -a; . ./.env; set +a
# docker-compose.opensource.yml requires NANO_VERSION; a dev .env predating
# the pin gets the release images.lock names (the dev services are third-party
# images, so the value only has to satisfy interpolation).
if [[ -z "${NANO_VERSION:-}" ]]; then
    NANO_VERSION=$(./scripts/nano-release-pin.sh) || die "images.lock has no '# Release:' line"
    export NANO_VERSION
fi
: "${NANO_LAKE_TENANT_ID:=default}"
: "${NANO_LAKE_BRONZE_BUCKET:=nano-lake}"
: "${NANO_LAKE_EVENT_TABLE:=default.events}"
: "${NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX:=s3://${NANO_LAKE_BRONZE_BUCKET}/warehouse/default/events/}"
: "${NANO_DEV_POSTGRES_PORT:=5432}"
: "${NANO_DEV_CATALOG_PORT:=8181}"
: "${NANO_DEV_OIDC_PORT:=4444}"
: "${NANO_DEV_OBJECT_PORT:=9000}"

CATALOG_URI="http://127.0.0.1:${NANO_DEV_CATALOG_PORT}/catalog"
OIDC_TOKEN_URI="http://127.0.0.1:${NANO_DEV_OIDC_PORT}/oauth2/token"
S3_ENDPOINT="http://127.0.0.1:${NANO_DEV_OBJECT_PORT}"
WORKER_SOURCE="${S3_ENDPOINT}/${NANO_LAKE_BRONZE_BUCKET}/warehouse/default/events"
mkdir -p "$CONFIG_DIR" "$CHDB_DIR" "$STATE/generations" \
         "$STATE/enrichment-cache" "$STATE/bronze-uid-cache/${NANO_LAKE_TENANT_ID}" \
         "$STATE/enrichment/ip-context" "$STATE/enrichment/ioc" "$STATE/enrichment/identity" \
         "$STATE/vector-dynamic/sources/parsers" "$STATE/vector-dynamic/sources/configs"

dc() { docker compose -f "$BASE_COMPOSE" -f "$DEV_COMPOSE" "$@"; }

# ---------------------------------------------------------------- 1. infra
if (( ! SKIP_INFRA )); then
    say "1/6 infrastructure (third-party images only)"
    # --no-deps: the dependency chain reaches lake-otel / lake-object-init, which
    # are FIRST-PARTY images. In host-dev those roles are binaries we run
    # ourselves, so pulling them would fail for no reason. Start the third-party
    # services explicitly, in dependency order.
    # EVERY service is started with --no-deps, deliberately. The dependency
    # chain runs lake-profile-guard, a DEPLOYMENT-time check that requires
    # NANO_LAKE_WORKER_SOURCE to address the object store by its container name.
    # Host-dev addresses it over loopback, so the guard would correctly refuse.
    # Driving the graph here keeps .env deployment-correct and the guard honest.
    oneshot() {   # run a one-shot to completion, tolerating "already done"
        COMPOSE_PROFILES=lake dc up -d --no-deps "$1" >/dev/null 2>&1 || true
        local cid; cid="$(COMPOSE_PROFILES=lake dc ps -aq "$1" 2>/dev/null | head -1)"
        [[ -n "$cid" ]] && docker wait "$cid" >/dev/null 2>&1 || true
    }
    wait_healthy() {   # by compose service: most services have no fixed container_name
        local service="$1" cid
        for _ in $(seq 1 90); do
            cid="$(COMPOSE_PROFILES=lake dc ps -q "$service" 2>/dev/null | head -1)"
            [[ -n "$cid" && "$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)" == "healthy" ]] && return 0
            sleep 1
        done
        return 1
    }

    COMPOSE_PROFILES=lake dc up -d --no-deps postgres >/dev/null 2>&1 || die "postgres failed to start"
    wait_healthy postgres || die "postgres never became healthy"
    oneshot lake-postgres-init
    COMPOSE_PROFILES=lake dc up -d --no-deps dragonfly lake-object-store >/dev/null 2>&1 \
        || die "dragonfly/object store failed to start"
    wait_healthy lake-object-store || die "the object store never became healthy"
    oneshot lake-oidc-migrate
    COMPOSE_PROFILES=lake dc up -d --no-deps lake-oidc >/dev/null 2>&1 || die "hydra failed to start"
    wait_healthy lake-oidc || die "hydra never became healthy"
    oneshot lake-authz-migrate
    COMPOSE_PROFILES=lake dc up -d --no-deps lake-authz >/dev/null 2>&1 || die "openfga failed to start"
    oneshot lake-catalog-migrate
    COMPOSE_PROFILES=lake dc up -d --no-deps lake-catalog >/dev/null 2>&1 || die "catalog failed to start"
    for _ in $(seq 1 90); do
        curl -fsS -o /dev/null "http://127.0.0.1:${NANO_DEV_CATALOG_PORT}/health" 2>/dev/null && break
        sleep 1
    done
    curl -fsS -o /dev/null "http://127.0.0.1:${NANO_DEV_CATALOG_PORT}/health" 2>/dev/null \
        || die "the Iceberg catalog never became healthy (docker logs nano-lake-catalog)"
    ok "postgres, dragonfly, rustfs, hydra, openfga, lakekeeper up"
else
    ok "infrastructure step skipped (--skip-infra)"
fi

# ---------------------------------------------------------------- 2. bucket
say "2/6 object bucket ${NANO_LAKE_BRONZE_BUCKET}"
OBJECT_STORE_CID="$(COMPOSE_PROFILES=lake dc ps -q lake-object-store 2>/dev/null | head -1)"
NET="$(docker inspect "$OBJECT_STORE_CID" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null)"
[[ -n "$NET" ]] || die "lake-object-store is not running"
docker run --rm --network "$NET" \
    -e AWS_ACCESS_KEY_ID="$NANO_LAKE_ACCESS_KEY_ID" \
    -e AWS_SECRET_ACCESS_KEY="$NANO_LAKE_SECRET_ACCESS_KEY" \
    -e AWS_DEFAULT_REGION=us-east-1 --entrypoint sh amazon/aws-cli:latest -c "
        aws --endpoint-url http://lake-object-store:9000 s3api head-bucket --bucket ${NANO_LAKE_BRONZE_BUCKET} 2>/dev/null && exit 0
        aws --endpoint-url http://lake-object-store:9000 s3api create-bucket --bucket ${NANO_LAKE_BRONZE_BUCKET} >/dev/null
        aws --endpoint-url http://lake-object-store:9000 s3api put-bucket-versioning \
            --bucket ${NANO_LAKE_BRONZE_BUCKET} --versioning-configuration Status=Enabled >/dev/null
    " >/dev/null 2>&1 || die "could not create the ${NANO_LAKE_BRONZE_BUCKET} bucket"
ok "bucket ready"

# ---------------------------------------------------------------- 3. postgres schema
say "3/6 PostgreSQL schema"
cargo build --features enterprise -p nanosiem-api --bin postgres_migrator >/dev/null 2>&1 \
    || die "could not build postgres_migrator"
PG_URL="postgres://${POSTGRES_USER:-nanosiem}:${POSTGRES_PASSWORD}@localhost:${NANO_DEV_POSTGRES_PORT}/${POSTGRES_DB:-nanosiem}"
PG_ADMIN_URL="postgres://${POSTGRES_USER:-nanosiem}:${POSTGRES_PASSWORD}@localhost:${NANO_DEV_POSTGRES_PORT}/postgres"
if (( RESET_DB )); then
    say "    --reset-db: dropping ${POSTGRES_DB:-nanosiem}"
    docker run --rm -e PGPASSWORD="$POSTGRES_PASSWORD" --network host postgres:18 \
        psql "$PG_ADMIN_URL" -v ON_ERROR_STOP=1 \
        -c "DROP DATABASE IF EXISTS ${POSTGRES_DB:-nanosiem} WITH (FORCE)" \
        -c "CREATE DATABASE ${POSTGRES_DB:-nanosiem} OWNER ${POSTGRES_USER:-nanosiem}" >/dev/null 2>&1 \
        || die "could not recreate the dev database"
fi
migrate_log="$(mktemp "${TMPDIR:-/tmp}/nano-migrate.XXXXXX")"
if ! DATABASE_URL="$PG_URL" ./target/debug/postgres_migrator >"$migrate_log" 2>&1; then
    if grep -q 'previously applied but has been modified' "$migrate_log"; then
        grep -o 'migration [0-9]* was previously applied but has been modified' "$migrate_log" \
            | tail -1 | sed 's/^/  /' >&2
        rm -f "$migrate_log"
        die "a migration file changed after it was applied to this dev database.
  sqlx refuses to continue. This dev database holds no production data, so the
  fix is to recreate it:

      scripts/bootstrap-local-lake.sh --reset-db

  (NEVER do this against a deployment — there, a modified applied migration is a
  forward-only violation that has to be resolved in the migration files.)"
    fi
    tail -5 "$migrate_log" >&2; rm -f "$migrate_log"
    die "PostgreSQL migrations failed"
fi
rm -f "$migrate_log"
ok "product schema applied"

# ---------------------------------------------------------------- 4. catalog
say "4/6 Iceberg catalog bootstrap"
cargo build --features enterprise -p nanosiem-lake-worker \
    --bin lake_catalog_bootstrap --bin lake_worker_config_bootstrap >/dev/null 2>&1 \
    || die "could not build the lake bootstrap binaries"
# Run on the HOST: the binary was just built here and is native to this
# platform, so it cannot be mounted into a Linux container on macOS. The
# overlay publishes Hydra's admin + token ports on loopback for exactly this.
# Idempotent — re-registering existing clients is a no-op.
./target/debug/lake_catalog_bootstrap \
        --hydra-admin-uri "http://127.0.0.1:${NANO_DEV_OIDC_ADMIN_PORT:-4445}" \
        --hydra-token-uri "$OIDC_TOKEN_URI" \
        --client-id nano-lakekeeper --client-secret-env NANO_LAKEKEEPER_OPERATOR_CLIENT_SECRET \
        --runtime-client-id nano-lakekeeper-runtime \
        --runtime-client-secret-env NANO_LAKEKEEPER_RUNTIME_CLIENT_SECRET \
        --scope lakekeeper --audience lakekeeper \
        --catalog-management-uri "http://127.0.0.1:${NANO_DEV_CATALOG_PORT}" \
        --warehouse-config "$REPO_ROOT/config/lake/warehouse.json" \
        --storage-access-key-env NANO_LAKE_ACCESS_KEY_ID \
        --storage-secret-key-env NANO_LAKE_SECRET_ACCESS_KEY \
        --allow-insecure-http >/dev/null 2>&1 \
    || die "catalog bootstrap failed (docker logs nano-lake-catalog / nano-lake-oidc)"
ok "warehouse + OIDC clients ready"

# ---------------------------------------------------------------- 5. chDB
# The Dockerfile fetches a Linux artifact; a host worker needs its own platform's
# build of the SAME pinned version, or worker.json pins a library that cannot be
# loaded. Version comes from the Dockerfile so the two can never drift.
say "5/6 native chDB library"
CHDB_VERSION="$(grep -oE '^ARG CHDB_CORE_VERSION=[0-9.]+' Dockerfile | head -1 | cut -d= -f2)"
[[ -n "$CHDB_VERSION" ]] || die "could not read CHDB_CORE_VERSION from the Dockerfile"
case "$(uname -s)/$(uname -m)" in
    Darwin/arm64)  CHDB_ASSET="macos-arm64-libchdb.tar.gz" ;;
    Darwin/x86_64) CHDB_ASSET="macos-x86_64-libchdb.tar.gz" ;;
    Linux/aarch64|Linux/arm64) CHDB_ASSET="linux-aarch64-libchdb.tar.gz" ;;
    Linux/x86_64)  CHDB_ASSET="linux-x86_64-libchdb.tar.gz" ;;
    *) die "no chDB build for $(uname -s)/$(uname -m)" ;;
esac
CHDB_LIB="$CHDB_DIR/libchdb.so"     # the archive uses this name on every platform
CHDB_STAMP="$CHDB_DIR/.version"
if [[ ! -s "$CHDB_LIB" || "$(cat "$CHDB_STAMP" 2>/dev/null)" != "${CHDB_VERSION}/${CHDB_ASSET}" ]]; then
    say "    downloading chdb-core v${CHDB_VERSION} (${CHDB_ASSET}, ~100-175 MB, once)"
    curl -fsSL -o "$CHDB_DIR/$CHDB_ASSET" \
        "https://github.com/chdb-io/chdb-core/releases/download/v${CHDB_VERSION}/${CHDB_ASSET}" \
        || die "could not download $CHDB_ASSET"
    tar xzf "$CHDB_DIR/$CHDB_ASSET" -C "$CHDB_DIR" || die "could not extract $CHDB_ASSET"
    rm -f "$CHDB_DIR/$CHDB_ASSET"
    [[ -s "$CHDB_LIB" ]] || die "the archive did not contain libchdb"
    chmod 0555 "$CHDB_LIB"
    printf '%s/%s' "$CHDB_VERSION" "$CHDB_ASSET" > "$CHDB_STAMP"
fi
ok "chDB v${CHDB_VERSION} at $CHDB_LIB"

# ---------------------------------------------------------------- 6. worker config
say "6/6 worker configuration"
cargo build --features enterprise -p nanosiem-core --bin lake_query_compile >/dev/null 2>&1 \
    || die "could not build lake_query_compile"
./target/debug/lake_worker_config_bootstrap \
    --output "$CONFIG_DIR/worker.json" \
    --tenant-id "$NANO_LAKE_TENANT_ID" \
    --source "$WORKER_SOURCE" \
    --compiler "$REPO_ROOT/target/debug/lake_query_compile" \
    --native-library "$CHDB_LIB" \
    --hmac-key "$CONFIG_DIR/entity-hmac.key" --hmac-key-env NANO_LAKE_ENTITY_HMAC_KEY \
    --query-token "$CONFIG_DIR/query-token" --query-token-env NANO_LAKE_QUERY_TOKEN \
    --enrichment-token "$CONFIG_DIR/enrichment-token" --enrichment-token-env NANO_LAKE_ENRICHMENT_TOKEN \
    --otel-ingest-token "$CONFIG_DIR/otel-ingest-token" --otel-ingest-token-env NANO_OTEL_LAKE_INGEST_TOKEN \
    --otel-query-token "$CONFIG_DIR/otel-query-token" --otel-query-token-env NANO_OTEL_LAKE_QUERY_TOKEN \
    --max-query-bytes "${NANO_LAKE_MAX_QUERY_BYTES:-1073741824}" \
    --max-memory-bytes "${NANO_LAKE_MAX_MEMORY_BYTES:-2147483648}" \
    --max-execution-seconds 120 --threads 4 \
    --s3-access-key-env NANO_LAKE_ACCESS_KEY_ID --s3-secret-key-env NANO_LAKE_SECRET_ACCESS_KEY \
    >/dev/null 2>&1 || die "worker config bootstrap failed"
ok "worker.json written to $CONFIG_DIR/worker.json"

# ---------------------------------------------------------------- 6b. digest drift
# worker.json PINS the sha256 of the query compiler and the native chDB library,
# and the worker refuses to load a config whose pins do not match the files
# ("artifact digest mismatch"). In a deployment those binaries only change with a
# new image plus a generation activation, so the pin is a genuine integrity
# control. In development they are rebuilt constantly — any change to
# nanosiem-core rebuilds lake_query_compile — which would otherwise wedge the
# worker after every code change.
#
# Reconcile ONLY the two artifact digests, in place. The generation id, the
# source manifest and every sidecar pointer are left untouched, so this cannot
# paper over a genuine generation mismatch: it re-pins the same artifacts at
# their current bytes, exactly what an activation would do for a new build.
python3 - "$CONFIG_DIR/worker.json" "$REPO_ROOT/target/debug/lake_query_compile" "$CHDB_LIB" >&2 <<'DIGEST_PY'
import hashlib, json, pathlib, sys

config_path, compiler_path, native_path = (pathlib.Path(a) for a in sys.argv[1:4])

def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

config = json.loads(config_path.read_text())
changed = []
for key, path in (("compiler", compiler_path), ("native_library", native_path)):
    entry = config.get(key)
    if not isinstance(entry, dict) or not path.is_file():
        continue
    actual = sha256(path)
    if entry.get("sha256") != actual:
        entry["sha256"] = actual
        entry["path"] = str(path)
        changed.append(key)
if changed:
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    print(" ".join(changed))
DIGEST_PY
drift="$(python3 - "$CONFIG_DIR/worker.json" "$REPO_ROOT/target/debug/lake_query_compile" "$CHDB_LIB" <<'CHECK_PY'
import hashlib, json, pathlib, sys
config_path, compiler_path, native_path = (pathlib.Path(a) for a in sys.argv[1:4])
def sha256(path):
    d = hashlib.sha256()
    with open(path, "rb") as h:
        for c in iter(lambda: h.read(1024 * 1024), b""):
            d.update(c)
    return d.hexdigest()
config = json.loads(config_path.read_text())
bad = [k for k, p in (("compiler", compiler_path), ("native_library", native_path))
       if isinstance(config.get(k), dict) and p.is_file()
       and config[k].get("sha256") != sha256(p)]
print(",".join(bad))
CHECK_PY
)"
[[ -z "$drift" ]] && ok "artifact digests match the built binaries" \
                  || die "artifact digest drift persists for: $drift"

cat <<ENV
NANO_SCHEMA_PROFILE=ocsf
NANO_LOG_QUERY_BACKEND=lake
NANO_LAKE_WORKER_CONFIG=$CONFIG_DIR/worker.json
NANO_LAKE_TENANT_ID=$NANO_LAKE_TENANT_ID
NANO_LAKE_BRONZE_BUCKET=$NANO_LAKE_BRONZE_BUCKET
NANO_LAKE_EVENT_TABLE=$NANO_LAKE_EVENT_TABLE
NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX=$NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX
NANO_LAKE_WORKER_SOURCE=$WORKER_SOURCE
NANO_LAKE_CATALOG_URI=$CATALOG_URI
NANO_LAKE_CATALOG_WAREHOUSE=${NANO_LAKE_CATALOG_WAREHOUSE:-nano}
NANO_LAKE_CATALOG_OAUTH_SERVER_URI=$OIDC_TOKEN_URI
NANO_LAKE_CATALOG_OAUTH_SCOPE=${NANO_LAKE_CATALOG_OAUTH_SCOPE:-lakekeeper}
NANO_LAKE_CATALOG_OAUTH_AUDIENCE=${NANO_LAKE_CATALOG_OAUTH_AUDIENCE:-lakekeeper}
NANO_LAKE_CATALOG_CREDENTIAL=nano-lakekeeper-runtime:${NANO_LAKEKEEPER_RUNTIME_CLIENT_SECRET}
NANO_LAKE_CATALOG_CREDENTIAL_ENV=NANO_LAKE_CATALOG_CREDENTIAL
NANO_LAKE_S3_ENDPOINT=$S3_ENDPOINT
NANO_LAKE_S3_ACCESS_KEY_ENV=NANO_LAKE_ACCESS_KEY_ID
NANO_LAKE_S3_SECRET_KEY_ENV=NANO_LAKE_SECRET_ACCESS_KEY
NANO_LAKE_S3_DEFAULT_CREDENTIALS=false
NANO_LAKE_S3_PATH_STYLE_ACCESS=true
NANO_LAKE_BRONZE_STORE_ID=${NANO_LAKE_BRONZE_STORE_ID:-rustfs:open-core:bronze-v2}
NANO_LAKE_GENERATIONS_ROOT=$STATE/generations
NANO_LAKE_ENTITY_HMAC_KEY_FILE=$CONFIG_DIR/entity-hmac.key
VECTOR_CONFIG_DIR=$STATE/vector-dynamic
VECTOR_SOURCES_RUNTIME_PATH=$STATE/vector-dynamic/sources
VECTOR_CONTAINER_NAME=${NANO_DEV_VECTOR_CONTAINER:-nano-vector}
VECTOR_METRICS_URL=http://127.0.0.1:${NANO_DEV_VECTOR_METRICS_PORT:-9598}/metrics
SKIP_VECTOR_VALIDATION=true
NANO_LAKE_ENRICHMENT_TOKEN_FILE=$CONFIG_DIR/enrichment-token
NANO_LAKE_ENRICHMENT_COORDINATOR_URL=http://127.0.0.1:${NANO_DEV_ENRICHMENT_PORT:-3016}
NANO_OTEL_LAKE_INGEST_URL=http://127.0.0.1:${NANO_DEV_OTEL_INGEST_PORT:-3014}
NANO_OTEL_LAKE_QUERY_URL=http://127.0.0.1:${NANO_DEV_OTEL_INGEST_PORT:-3014}
VECTOR_ENRICHMENT_INGEST_URL=http://127.0.0.1:${NANO_DEV_VECTOR_ENRICHMENT_PORT:-8090}/
NANO_LAKE_QUERY_TOKEN_FILE=$CONFIG_DIR/query-token
NANO_LAKE_ENRICHMENT_COORDINATOR_TOKEN_FILE=$CONFIG_DIR/enrichment-token
NANO_OTEL_LAKE_QUERY_TOKEN_FILE=$CONFIG_DIR/otel-query-token
NANO_OTEL_LAKE_INGEST_TOKEN_FILE=$CONFIG_DIR/otel-ingest-token
NANO_LAKE_ENRICHMENT_IOC_DIR=$STATE/enrichment/ioc
NANO_LAKE_ENRICHMENT_IDENTITY_DIR=$STATE/enrichment/identity
NANO_LAKE_ENRICHMENT_IP_CONTEXT_DIR=$STATE/enrichment/ip-context
NANO_LAKE_ENRICHMENT_CACHE_DIRECTORY=$STATE/enrichment-cache
NANO_LAKE_BRONZE_UID_CACHE_DIRECTORY=$STATE/bronze-uid-cache/$NANO_LAKE_TENANT_ID
NANO_DEV_ENRICHMENT_PORT=${NANO_DEV_ENRICHMENT_PORT:-3016}
NANO_DEV_OTEL_INGEST_PORT=${NANO_DEV_OTEL_INGEST_PORT:-3014}
NANO_LAKE_EVENT_PUBLISH_ENABLED=true
NANO_LAKE_GENERATION_MANAGER_ENABLED=true
NANO_DEV_REUSE_INFRA=true
NANO_DEV_POSTGRES_CONTAINER=nano-postgres
NANO_DEV_DRAGONFLY_CONTAINER=nano-dragonfly
NANO_DEV_VECTOR_CONTAINER=nano-vector
DATABASE_URL=postgres://${POSTGRES_USER:-nanosiem}:${POSTGRES_PASSWORD}@localhost:${NANO_DEV_POSTGRES_PORT}/${POSTGRES_DB:-nanosiem}
ENV
