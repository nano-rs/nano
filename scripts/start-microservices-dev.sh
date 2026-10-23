#!/bin/bash
set -e

# Create a new process group for this script
# This ensures all child processes can be killed together
set -m

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    cat >&2 <<'USAGE'
usage: ./scripts/start-microservices-dev.sh [--lake | --shadow | --clickhouse] [--no-lake-autoconfig]

  --lake        run against the RustFS/Iceberg object lake (chDB query worker;
                the default).
                If a containerized lake is running, derives every NANO_LAKE_*
                setting from it. If not, bootstraps a local one first
                (scripts/bootstrap-local-lake.sh): third-party infrastructure in
                Docker, PostgreSQL schema, Iceberg catalog, the native chDB
                library for this platform, and worker.json — then runs every
                nano process from source. No environment assembly either way.
  --shadow      same discovery, but only shadow-route OCSF log queries.
  --clickhouse  force the legacy ClickHouse backend (unsupported).
  --no-lake-autoconfig
                keep the backend but skip discovery; you supply
                NANO_LAKE_WORKER_CONFIG / NANO_LAKE_TENANT_ID / … yourself.
  --check       resolve and print the backend configuration, then exit WITHOUT
                starting containers or services. Use this to confirm a --lake
                run will find the control plane before committing to a boot.

Environment still wins over .env; these flags win over both.
USAGE
}

# NAN-2361: the lake backend needs NANO_LAKE_WORKER_CONFIG, NANO_LAKE_TENANT_ID,
# NANO_LAKE_BRONZE_BUCKET and the RustFS credentials, all of which live inside
# the lake-runtime Docker volume and the compose project's .env. Assembling them
# by hand for every local run is the reason nobody ran the lake path locally.
# `--lake` derives the whole set from the running control plane instead.
CLI_QUERY_BACKEND=""
LAKE_AUTOCONFIG=1
CONFIG_CHECK_ONLY=0
LAKE_ENRICHMENT_COORDINATOR_PGID=""
LAKE_OTEL_INGEST_PGID=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --lake)       CLI_QUERY_BACKEND="lake"; shift ;;
        --shadow)     CLI_QUERY_BACKEND="shadow"; shift ;;
        --clickhouse) CLI_QUERY_BACKEND="clickhouse"; shift ;;
        --no-lake-autoconfig) LAKE_AUTOCONFIG=0; shift ;;
        --check)      CONFIG_CHECK_ONLY=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) echo -e "${RED}unknown argument: $1${NC}" >&2; usage; exit 64 ;;
    esac
done

echo -e "${GREEN}🚀 NanoSIEM Microservices Development Startup${NC}"
echo "================================================"

# Load .env file if it exists (for local overrides)
if [ -f .env ]; then
    echo -e "${YELLOW}Loading environment from .env...${NC}"
    set -a
    source .env
    set +a
fi

# Database connection settings. Keep the historical local default, but do not
# overwrite an explicit endpoint. Parallel lake/open-core validation stacks
# commonly publish PostgreSQL on a different host port.
export DATABASE_URL="${DATABASE_URL:-postgres://nanosiem:nanosiem@localhost:5432/nanosiem}"
export CLICKHOUSE_URL="http://localhost:8123"
export CLICKHOUSE_DATABASE="nanosiem"
export CLICKHOUSE_USER="nanosiem"
export CLICKHOUSE_PASSWORD="nanosiem"
# NAN-2001: the two read-only raw-SQL feature identities. DualPool is fail-closed
# — the API/search/jobs services refuse to boot without these. They match the CH
# users that clickhouse/users.d creates via `from_env` (the compose CH env
# defaults CLICKHOUSE_RAWSQL_PASSWORD to ${CLICKHOUSE_PASSWORD}=nanosiem, so the
# CH-side password and these must agree). Exported so the app services inherit
# them (and re-listed per-service below to match this script's explicit style).
export CLICKHOUSE_RAWSQL_PASSWORD="${CLICKHOUSE_RAWSQL_PASSWORD:-nanosiem}"
export CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD="${CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD:-nanosiem}"

# Authentication settings
# JWT_SECRET must be the same across all services for token validation
# For development, we use a secure 64-character random secret
# IMPORTANT: In production, set JWT_SECRET environment variable before running
if [ -z "$JWT_SECRET" ]; then
    # Generate a secure development JWT secret (64 characters)
    export JWT_SECRET="dev-e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"
    echo -e "${YELLOW}⚠️  Using generated development JWT_SECRET${NC}"
    echo -e "${YELLOW}   For production, set JWT_SECRET environment variable${NC}"
fi
# NAN-1355: allow the built-in public dev encryption key when none is set, so local
# dev boots even if a credential-encryption path initializes. Production never sets
# this (real secrets are required and the boot fails closed without them).
export NANOSIEM_ALLOW_DEFAULT_KEYS="${NANOSIEM_ALLOW_DEFAULT_KEYS:-true}"
# Set AUTH_ENABLED=false to disable authentication (development only)
export AUTH_ENABLED="${AUTH_ENABLED:-true}"

# NAN-1514: agentic investigation tool-loop. On by default in dev so the new
# research->act->observe->pivot loop drives pivt investigations here; set
# NANOSIEM_INVESTIGATION_TOOL_LOOP=false (env or .env) to fall back to the
# legacy single-shot path. Production leaves this unset (off by default).
export NANOSIEM_INVESTIGATION_TOOL_LOOP="${NANOSIEM_INVESTIGATION_TOOL_LOOP:-true}"

# Encryption key settings
# For development, we enable dev mode which uses a default key
# IMPORTANT: In production, set NANOSIEM_ENCRYPTION_KEY to a secure 32-byte value
if [ -z "$NANOSIEM_ENCRYPTION_KEY" ]; then
    export NANOSIEM_DEV_MODE="true"
    echo -e "${YELLOW}⚠️  No NANOSIEM_ENCRYPTION_KEY set, enabling dev mode${NC}"
    echo -e "${YELLOW}   For production, set NANOSIEM_ENCRYPTION_KEY in .env${NC}"
else
    export NANOSIEM_DEV_MODE="${NANOSIEM_DEV_MODE:-false}"
    echo -e "${GREEN}✓${NC} Using NANOSIEM_ENCRYPTION_KEY from environment"
fi

# CORS settings
# For development, allow localhost origins. In production, set specific origins.
# Organization tier restriction (unrestricted = no limits, hobby/startup/growth/team/starter/pro/enterprise)
export NANO_TIER="${NANO_TIER:-unrestricted}"

# Deployment mode (selfhosted, managed, demo)
export DEPLOYMENT_MODE="${DEPLOYMENT_MODE:-selfhosted}"

# NAN-2361 / NAN-3491: log-query backend. `lake` (the default) runs against the
# RustFS/Iceberg object lake through the chDB query worker; with no running
# containerized lake it bootstraps a local one (scripts/bootstrap-local-lake.sh).
# `clickhouse` (and `shadow`) are the unsupported legacy ClickHouse stack.
# Precedence: CLI flag > inherited shell environment > .env > default.
if [ -n "$CLI_QUERY_BACKEND" ]; then
    NANO_LOG_QUERY_BACKEND="$CLI_QUERY_BACKEND"
fi
export NANO_LOG_QUERY_BACKEND="${NANO_LOG_QUERY_BACKEND:-lake}"

# Active schema profile (NAN-1241): `ocsf` (canonical OCSF 1.9; required by the
# lake backend) or `udm` (legacy ClickHouse only). Exported here so BOTH the API
# and the search microservice pick it up. Defaults to `ocsf`, except on the
# legacy `clickhouse` backend, where it keeps its historical `udm` default.
#   ./scripts/start-microservices-dev.sh                 # lake + OCSF (default)
#   ./scripts/start-microservices-dev.sh --clickhouse    # legacy ClickHouse + UDM
# NOTE: OCSF on the legacy ClickHouse backend requires the `nanosiem.ocsf_logs`
# table (the API fail-fasts at boot otherwise) — see clickhouse/ocsf/init.sql.
if [ "$NANO_LOG_QUERY_BACKEND" = "clickhouse" ]; then
    export NANO_SCHEMA_PROFILE="${NANO_SCHEMA_PROFILE:-udm}"
else
    export NANO_SCHEMA_PROFILE="${NANO_SCHEMA_PROFILE:-ocsf}"
fi

# The lake backend is OCSF-only. Selecting it via --lake/--shadow implies the
# profile rather than making the operator remember to set both.
if [ -n "$CLI_QUERY_BACKEND" ] && [ "$CLI_QUERY_BACKEND" != "clickhouse" ]; then
    export NANO_SCHEMA_PROFILE=ocsf
fi
if [ "$NANO_LOG_QUERY_BACKEND" = "clickhouse" ] && [ "$NANO_SCHEMA_PROFILE" != "udm" ]; then
    echo -e "${YELLOW}🧬 Schema profile: ${NANO_SCHEMA_PROFILE} (requires nanosiem.${NANO_SCHEMA_PROFILE}_logs to exist)${NC}"
fi

# Everything the lake backend needs that the worker config already states.
# Pure file reads — no Docker, so an operator-supplied NANO_LAKE_WORKER_CONFIG
# works with nothing else set and without a running control plane.
lake_derive_from_config() {
    if [ -z "${NANO_LAKE_TENANT_ID:-}" ]; then
        # Assigned separately so a python3 failure is visible rather than
        # masked by export's own exit status.
        local derived_tenant
        derived_tenant="$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1])).get("assigned_tenant_id", ""))' "$NANO_LAKE_WORKER_CONFIG")" || derived_tenant=""
        export NANO_LAKE_TENANT_ID="$derived_tenant"
    fi
    [ -n "${NANO_LAKE_TENANT_ID:-}" ] || {
        echo -e "${RED}❌ worker config has no assigned_tenant_id and NANO_LAKE_TENANT_ID is unset${NC}"
        exit 1
    }
    if [ -z "${NANO_LAKE_BRONZE_BUCKET:-}" ]; then
        NANO_LAKE_BRONZE_BUCKET="$(python3 -c '
import json, sys, urllib.parse
cfg = json.load(open(sys.argv[1]))
src = (cfg.get("tenant") or {}).get("source") or ""
if src.startswith("s3://"):
    print(src[5:].split("/")[0])
else:
    path = urllib.parse.urlparse(src).path.lstrip("/")
    print(path.split("/")[0] if path else "")' "$NANO_LAKE_WORKER_CONFIG")"
        [ -n "$NANO_LAKE_BRONZE_BUCKET" ] && export NANO_LAKE_BRONZE_BUCKET
    fi
}

lake_report() {
    echo -e "${GREEN}✓${NC} tenant: ${NANO_LAKE_TENANT_ID}   bronze bucket: ${NANO_LAKE_BRONZE_BUCKET:-<unset>}"
    if [ -n "${NANO_LAKE_ACCESS_KEY_ID:-}" ]; then
        echo -e "${GREEN}✓${NC} RustFS credentials present"
    else
        echo -e "${YELLOW}⚠️  No RustFS credentials in scope — the Vector sink will render workload-role auth${NC}"
    fi
    # NANO_LAKE_SCHEMA_MANIFEST is deliberately left unset: the worker config
    # points at the host copy, and setting both makes them a pair that must
    # agree on every promotion.
}

lake_autoconfigure() {
    local container port worker_json refresh_out refresh_worker_url
    echo -e "${BLUE}🔎 Discovering the local lake control plane…${NC}"

    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}❌ --lake needs docker to read the running lake control plane${NC}"
        exit 1
    fi

    # Prefer an explicit override, then the compose service label (works for the
    # shipped open-core project and any differently-named one), then the
    # container_name docker-compose.opensource.yml assigns.
    container="${NANO_LAKE_QUERY_CONTAINER:-}"
    if [ -n "${NANO_LAKE_WORKER_CONFIG:-}" ] && [ -s "${NANO_LAKE_WORKER_CONFIG}" ]; then
        # An operator-supplied config is authoritative; only fill the gaps
        # around it, and do not go near Docker to do that.
        echo -e "${GREEN}✓${NC} worker config (from environment): $NANO_LAKE_WORKER_CONFIG"
        lake_derive_from_config
        lake_report
        return 0
    fi
    if [ -z "$container" ]; then
        container="$(docker ps --filter 'label=com.docker.compose.service=lake-query-worker' \
            --format '{{.Names}}' | head -1)"
    fi
    if [ -z "$container" ] && docker ps --format '{{.Names}}' | grep -qx 'nano-lake-query-worker'; then
        container="nano-lake-query-worker"
    fi
    if [ -z "$container" ]; then
        # No containerized lake: this is the normal local-development shape —
        # third-party infrastructure in Docker, every nano process from source
        # on this host. Stand the infrastructure and the one-time bootstrap
        # artifacts up ourselves. Idempotent, so it is safe on every run.
        echo -e "${YELLOW}   No containerized lake worker — bootstrapping a local one.${NC}"
        if [ ! -x ./scripts/bootstrap-local-lake.sh ]; then
            echo -e "${RED}❌ scripts/bootstrap-local-lake.sh is missing${NC}"
            exit 1
        fi
        local bootstrap_env
        bootstrap_env="$(mktemp "${TMPDIR:-/tmp}/nano-lake-env.XXXXXX")"
        if ! ./scripts/bootstrap-local-lake.sh > "$bootstrap_env"; then
            rm -f "$bootstrap_env"
            echo -e "${RED}❌ Local lake bootstrap failed (see the messages above).${NC}"
            exit 1
        fi
        # Applied AFTER .env on purpose: these are the host-facing values
        # (loopback catalog/object-store URLs, host worker.json). .env keeps the
        # container-facing values a real deployment needs.
        set -a
        # shellcheck disable=SC1090
        . "$bootstrap_env"
        set +a
        rm -f "$bootstrap_env"
        echo -e "${GREEN}✓${NC} local lake ready (config: $NANO_LAKE_WORKER_CONFIG)"
        lake_report
        return 0
    fi

    # NOTE: this URL is ONLY for reading the containerized worker's schema. It is
    # deliberately not NANO_LAKE_QUERY_URL — this script builds and runs its own
    # host worker on NANO_LAKE_QUERY_LISTEN (127.0.0.1:3010), and repointing the
    # product at the container would leave two workers serving one config.
    port="$(docker port "$container" 3015/tcp 2>/dev/null | head -1 | sed 's/.*://')"
    refresh_worker_url="http://127.0.0.1:${port:-3015}"
    if [ -z "$port" ]; then
        echo -e "${YELLOW}⚠️  $container publishes no host port for 3015; the schema refresh cross-check needs one.${NC}"
        echo -e "${YELLOW}   docker-compose.opensource.yml publishes 127.0.0.1:3015 — older projects may not.${NC}"
    fi
    echo -e "${GREEN}✓${NC} query worker: $container (reading schema from $refresh_worker_url)"

    # The worker config and its OCSF source manifest live inside the
    # nano-lake-runtime volume, so a host process cannot read the container
    # paths. refresh-host-lake-schema.sh copies both out and rewrites the
    # manifest pointer, cross-checking the generation against worker /health so
    # a promotion racing this start is caught rather than silently mis-schema'd.
    if [ -z "${NANO_LAKE_WORKER_CONFIG:-}" ]; then
        if [ ! -x ./scripts/refresh-host-lake-schema.sh ]; then
            echo -e "${RED}❌ scripts/refresh-host-lake-schema.sh is missing; cannot materialize a host worker config${NC}"
            exit 1
        fi
        if ! refresh_out="$(./scripts/refresh-host-lake-schema.sh --quiet \
                --container "$container" --worker-url "$refresh_worker_url" 2>&1)"; then
            echo -e "${RED}❌ Could not refresh the host lake schema from $container:${NC}"
            echo "$refresh_out" | sed 's/^/   /'
            echo -e "${YELLOW}   The worker must be serving a promoted generation. Check:${NC} docker logs $container"
            exit 1
        fi
        worker_json="$(printf '%s\n' "$refresh_out" | tail -1)"
        export NANO_LAKE_WORKER_CONFIG="$worker_json"
    fi
    [ -s "$NANO_LAKE_WORKER_CONFIG" ] || {
        echo -e "${RED}❌ NANO_LAKE_WORKER_CONFIG is empty or missing: $NANO_LAKE_WORKER_CONFIG${NC}"
        exit 1
    }
    echo -e "${GREEN}✓${NC} worker config: $NANO_LAKE_WORKER_CONFIG"

    lake_derive_from_config
    container_env() {
        docker inspect "$container" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
            | awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; exit }'
    }
    if [ -z "${NANO_LAKE_ACCESS_KEY_ID:-}" ]; then
        NANO_LAKE_ACCESS_KEY_ID="$(container_env NANO_LAKE_ACCESS_KEY_ID)"
        [ -n "$NANO_LAKE_ACCESS_KEY_ID" ] && export NANO_LAKE_ACCESS_KEY_ID
    fi
    if [ -z "${NANO_LAKE_SECRET_ACCESS_KEY:-}" ]; then
        NANO_LAKE_SECRET_ACCESS_KEY="$(container_env NANO_LAKE_SECRET_ACCESS_KEY)"
        [ -n "$NANO_LAKE_SECRET_ACCESS_KEY" ] && export NANO_LAKE_SECRET_ACCESS_KEY
    fi
    if [ -z "${NANO_LAKE_BRONZE_BUCKET:-}" ]; then
        NANO_LAKE_BRONZE_BUCKET="$(container_env NANO_LAKE_BRONZE_BUCKET)"
        if [ -z "$NANO_LAKE_BRONZE_BUCKET" ]; then
            # Fall back to the bucket in the worker's own event-table source.
            NANO_LAKE_BRONZE_BUCKET="$(python3 -c '
import json, sys, urllib.parse
cfg = json.load(open(sys.argv[1]))
src = (cfg.get("tenant") or {}).get("source") or ""
if src.startswith("s3://"):
    print(src[5:].split("/")[0])
else:
    path = urllib.parse.urlparse(src).path.lstrip("/")
    print(path.split("/")[0] if path else "")' "$NANO_LAKE_WORKER_CONFIG")"
        fi
        [ -n "$NANO_LAKE_BRONZE_BUCKET" ] && export NANO_LAKE_BRONZE_BUCKET
    fi
    if [ -z "${NANO_LAKE_OBJECT_ENDPOINT:-}" ]; then
        NANO_LAKE_OBJECT_ENDPOINT="$(container_env NANO_LAKE_OBJECT_ENDPOINT)"
        [ -n "$NANO_LAKE_OBJECT_ENDPOINT" ] && export NANO_LAKE_OBJECT_ENDPOINT
    fi

    lake_report
}

# S3-compatible stores such as RustFS use static credentials in local and
# open-core deployments. The API renders the sink, while Vector resolves the
# credential values at runtime, so both sides need one explicit contract bit.
# AWS deployments leave the credentials empty and retain workload-role auth.
if [ -n "${NANO_LAKE_ACCESS_KEY_ID:-}" ] || [ -n "${NANO_LAKE_SECRET_ACCESS_KEY:-}" ]; then
    if [ -z "${NANO_LAKE_ACCESS_KEY_ID:-}" ] || [ -z "${NANO_LAKE_SECRET_ACCESS_KEY:-}" ]; then
        echo -e "${RED}❌ Both NANO_LAKE_ACCESS_KEY_ID and NANO_LAKE_SECRET_ACCESS_KEY are required for static lake sink auth${NC}"
        exit 1
    fi
    export NANO_LAKE_SINK_STATIC_AUTH="${NANO_LAKE_SINK_STATIC_AUTH:-true}"
elif [ "$NANO_LOG_QUERY_BACKEND" = "lake" ] && [ "$DEPLOYMENT_MODE" != "managed" ]; then
    # The API renders only references to Vector's credential environment. It
    # does not need the credential values itself. Local/open-core Vector may
    # already have its RustFS credentials from Compose, so lake mode must not
    # silently regenerate the sink as workload-role auth just because this
    # shell does not carry those secrets.
    export NANO_LAKE_SINK_STATIC_AUTH="${NANO_LAKE_SINK_STATIC_AUTH:-true}"
else
    export NANO_LAKE_SINK_STATIC_AUTH="${NANO_LAKE_SINK_STATIC_AUTH:-false}"
fi
if [ "$NANO_LOG_QUERY_BACKEND" != "clickhouse" ] && [ "$LAKE_AUTOCONFIG" = "1" ] \
   && { [ -z "${NANO_LAKE_WORKER_CONFIG:-}" ] || [ -z "${NANO_LAKE_TENANT_ID:-}" ] \
        || { [ "$NANO_LOG_QUERY_BACKEND" = "lake" ] && [ -z "${NANO_LAKE_BRONZE_BUCKET:-}" ]; }; }; then
    lake_autoconfigure
fi

case "$NANO_LOG_QUERY_BACKEND" in
    clickhouse) ;;
    shadow|lake)
        if [ "$NANO_SCHEMA_PROFILE" != "ocsf" ]; then
            echo -e "${RED}❌ ${NANO_LOG_QUERY_BACKEND} query mode requires NANO_SCHEMA_PROFILE=ocsf${NC}"
            exit 1
        fi
        export NANO_LAKE_QUERY_URL="${NANO_LAKE_QUERY_URL:-http://127.0.0.1:3010}"
        export NANO_LAKE_QUERY_LISTEN="${NANO_LAKE_QUERY_LISTEN:-127.0.0.1:3010}"
        export NANO_LAKE_QUERY_TIMEOUT_SECS="${NANO_LAKE_QUERY_TIMEOUT_SECS:-130}"
        # Rust is the only lake query worker runtime (the NAN-2361 Python
        # reference worker was removed in NAN-3491).
        export NANO_LAKE_WORKER_RUNTIME="${NANO_LAKE_WORKER_RUNTIME:-rust}"
        if [ "$NANO_LAKE_WORKER_RUNTIME" != "rust" ]; then
            echo -e "${RED}❌ Invalid NANO_LAKE_WORKER_RUNTIME: ${NANO_LAKE_WORKER_RUNTIME} (expected rust)${NC}"
            exit 1
        fi
        if [ -z "${NANO_LAKE_WORKER_CONFIG:-}" ] || [ -z "${NANO_LAKE_TENANT_ID:-}" ]; then
            echo -e "${RED}❌ ${NANO_LOG_QUERY_BACKEND} query mode requires NANO_LAKE_WORKER_CONFIG and NANO_LAKE_TENANT_ID${NC}"
            exit 1
        fi
        export NANO_LAKE_WORKER_CONFIG
        export NANO_LAKE_TENANT_ID
        if [ "$NANO_LOG_QUERY_BACKEND" = "lake" ]; then
            if [ -z "${NANO_LAKE_BRONZE_BUCKET:-}" ]; then
                echo -e "${RED}❌ lake mode requires NANO_LAKE_BRONZE_BUCKET${NC}"
                exit 1
            fi
            # NAN-2361: the product resolves the OCSF manifest from
            # NANO_LAKE_SCHEMA_MANIFEST *or* the worker config
            # (schema::resolve_lake_schema_manifest_candidates), and
            # refresh-host-lake-schema.sh explicitly tells you to leave the env
            # var unset so the config is the single source. Requiring both here
            # made that documented recipe unrunnable. Require one of them.
            # Mirror the product's rule exactly (nanosiem-core/src/schema/mod.rs
            # worker_config_is_bootstrap_seed): a manifest is required UNLESS the
            # worker config still carries the "bootstrap-pending" marker, which is
            # the one window before generation 1 exists. Being stricter here than
            # the product would block the very first start of a fresh lake.
            if [ -z "${NANO_LAKE_SCHEMA_MANIFEST:-}" ] \
               && ! python3 -c '
import json, os, sys
cfg = json.load(open(sys.argv[1]))
if cfg.get("generation_id") == "bootstrap-pending":
    sys.exit(0)                      # pre-first-generation: manifest not due yet
path = ((cfg.get("tenant") or {}).get("source_manifest") or {}).get("path") or ""
sys.exit(0 if path and os.path.isfile(path) else 1)' "$NANO_LAKE_WORKER_CONFIG" 2>/dev/null; then
                echo -e "${RED}❌ lake mode needs an OCSF source manifest: either set NANO_LAKE_SCHEMA_MANIFEST, or use a worker config whose tenant.source_manifest.path exists on this host.${NC}"
                echo -e "${YELLOW}   ./scripts/refresh-host-lake-schema.sh writes one; --lake does it for you.${NC}"
                exit 1
            fi
            # A dedicated Vector can inherit the tenant assigned to its query
            # worker. Shared gateways stamp %tenant_id per authenticated event.
            export NANO_TENANT_ID="${NANO_TENANT_ID:-$NANO_LAKE_TENANT_ID}"
            export NANO_LAKE_BRONZE_BUCKET
            export NANO_LAKE_SCHEMA_MANIFEST
            export NANO_LAKE_EVENT_PUBLISH_ENABLED="${NANO_LAKE_EVENT_PUBLISH_ENABLED:-false}"
            if [ "$NANO_LAKE_EVENT_PUBLISH_ENABLED" = "true" ]; then
                export NANO_LAKE_GENERATION_MANAGER_ENABLED="${NANO_LAKE_GENERATION_MANAGER_ENABLED:-true}"
                for required in \
                    NANO_LAKE_BRONZE_STORE_ID NANO_LAKE_EVENT_TABLE \
                    NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX \
                    NANO_LAKE_CATALOG_URI NANO_LAKE_CATALOG_WAREHOUSE \
                    NANO_LAKE_CATALOG_CREDENTIAL_ENV; do
                    if [ -z "${!required:-}" ]; then
                        echo -e "${RED}❌ Native event publication requires $required${NC}"
                        exit 1
                    fi
                done
                export NANO_LAKE_S3_DEFAULT_CREDENTIALS="${NANO_LAKE_S3_DEFAULT_CREDENTIALS:-false}"
                if [ -z "${NANO_LAKE_S3_PATH_STYLE_ACCESS:-}" ]; then
                    if [ "$NANO_LAKE_S3_DEFAULT_CREDENTIALS" = "true" ]; then
                        export NANO_LAKE_S3_PATH_STYLE_ACCESS=false
                    else
                        export NANO_LAKE_S3_PATH_STYLE_ACCESS=true
                    fi
                else
                    export NANO_LAKE_S3_PATH_STYLE_ACCESS
                fi
                if [ "$NANO_LAKE_S3_DEFAULT_CREDENTIALS" != "true" ] && [ "$NANO_LAKE_S3_DEFAULT_CREDENTIALS" != "false" ]; then
                    echo -e "${RED}❌ NANO_LAKE_S3_DEFAULT_CREDENTIALS must be true or false${NC}"
                    exit 1
                fi
                if [ "$NANO_LAKE_S3_PATH_STYLE_ACCESS" != "true" ] && [ "$NANO_LAKE_S3_PATH_STYLE_ACCESS" != "false" ]; then
                    echo -e "${RED}❌ NANO_LAKE_S3_PATH_STYLE_ACCESS must be true or false${NC}"
                    exit 1
                fi
                if [ "$NANO_LAKE_S3_DEFAULT_CREDENTIALS" = "true" ]; then
                    if [ -n "${NANO_LAKE_S3_ACCESS_KEY_ENV:-}" ] || [ -n "${NANO_LAKE_S3_SECRET_KEY_ENV:-}" ] || [ -n "${NANO_LAKE_S3_SESSION_TOKEN_ENV:-}" ]; then
                        echo -e "${RED}❌ AWS workload identity cannot be combined with Nano static S3 credential environment names${NC}"
                        exit 1
                    fi
                else
                    for required in NANO_LAKE_S3_ENDPOINT NANO_LAKE_S3_ACCESS_KEY_ENV NANO_LAKE_S3_SECRET_KEY_ENV; do
                        if [ -z "${!required:-}" ]; then
                            echo -e "${RED}❌ Static S3 event publication requires $required${NC}"
                            exit 1
                        fi
                    done
                fi
                secret_env_names=("$NANO_LAKE_CATALOG_CREDENTIAL_ENV")
                if [ "$NANO_LAKE_S3_DEFAULT_CREDENTIALS" = "false" ]; then
                    secret_env_names+=("$NANO_LAKE_S3_ACCESS_KEY_ENV" "$NANO_LAKE_S3_SECRET_KEY_ENV")
                    if [ -n "${NANO_LAKE_S3_SESSION_TOKEN_ENV:-}" ]; then
                        secret_env_names+=("$NANO_LAKE_S3_SESSION_TOKEN_ENV")
                    fi
                fi
                for secret_env_name in "${secret_env_names[@]}"; do
                    if [ -z "${!secret_env_name:-}" ]; then
                        echo -e "${RED}❌ Native event publication credential environment $secret_env_name is unset${NC}"
                        exit 1
                    fi
                done
                if [ -n "${NANO_IPINFO_MMDB_SHA256:-}" ] && [ -z "${NANO_IPINFO_MMDB_PATH:-}" ]; then
                    echo -e "${RED}❌ NANO_IPINFO_MMDB_SHA256 requires NANO_IPINFO_MMDB_PATH${NC}"
                    exit 1
                fi
                if [ -n "${NANO_IPINFO_MMDB_SHA256:-}" ]; then
                    if [ ! -s "$NANO_IPINFO_MMDB_PATH" ]; then
                        echo -e "${RED}❌ The digest-pinned Bronze IPinfo MMDB path is missing or empty${NC}"
                        exit 1
                    fi
                fi
                if [ -n "${NANO_LAKE_IOC_SNAPSHOT_PATH:-}" ] || [ -n "${NANO_LAKE_IOC_SNAPSHOT_SHA256:-}" ]; then
                    if [ -z "${NANO_LAKE_IOC_SNAPSHOT_PATH:-}" ] || [ -z "${NANO_LAKE_IOC_SNAPSHOT_SHA256:-}" ] || [ ! -s "$NANO_LAKE_IOC_SNAPSHOT_PATH" ]; then
                        echo -e "${RED}❌ Bronze IOC enrichment requires a non-empty NANO_LAKE_IOC_SNAPSHOT_PATH and its NANO_LAKE_IOC_SNAPSHOT_SHA256${NC}"
                        exit 1
                    fi
                fi
                if [ "$NANO_LAKE_GENERATION_MANAGER_ENABLED" = "true" ]; then
                    for required in NANO_LAKE_GENERATIONS_ROOT NANO_LAKE_ENTITY_HMAC_KEY_FILE NANO_LAKE_WORKER_SOURCE; do
                        if [ -z "${!required:-}" ]; then
                            echo -e "${RED}❌ Native generation management requires $required${NC}"
                            exit 1
                        fi
                    done
                    if [ ! -s "$NANO_LAKE_ENTITY_HMAC_KEY_FILE" ]; then
                        echo -e "${RED}❌ Native generation HMAC key file is missing or empty${NC}"
                        exit 1
                    fi
                fi
            fi
        fi
        ;;
    *)
        echo -e "${RED}❌ Invalid NANO_LOG_QUERY_BACKEND: ${NANO_LOG_QUERY_BACKEND} (expected clickhouse, shadow, or lake)${NC}"
        exit 1
        ;;
esac

# Air-gap mode (NAN-1201). AIRGAP_MODE=true runs the stack as a zero-egress
# deployment: the marketplace hides cloud-install / repo-sync, badges providers
# "available offline" vs "requires connectivity", surfaces import-from-file, and
# the enrichment/repo-sync endpoints refuse cleanly instead of attempting egress.
# Signed offline bundles are verified against the embedded Ed25519 public key.
#   ./scripts/start-microservices-dev.sh                # normal
#   AIRGAP_MODE=true ./scripts/start-microservices-dev.sh
export AIRGAP_MODE="${AIRGAP_MODE:-false}"

# Air-gap bundle signing PUBLIC key (NAN-1210), embedded by nanosiem-core
# build.rs at compile time so verify_bundle trusts it. OPTIONAL in dev: a debug
# build keeps the dev placeholder key active (the refuse-placeholder guard only
# fires in release), so you can sign test bundles with the dev seed (32 bytes of
# 0x01) and they verify with nothing injected. To test with the REAL key, set
# AIRGAP_BUNDLE_PUBLIC_KEY_HEX (64 hex chars) — e.g. pull it from Doppler:
#   AIRGAP_BUNDLE_PUBLIC_KEY_HEX=$(doppler secrets get AIRGAP_BUNDLE_PUBLIC_KEY_HEX \
#       --project nano-platform --config dev_gke --plain) \
#       AIRGAP_MODE=true ./scripts/start-microservices-dev.sh
# An empty value is treated as "not set" so build.rs doesn't try to decode it.
if [ -n "${AIRGAP_BUNDLE_PUBLIC_KEY_HEX:-}" ]; then
    export AIRGAP_BUNDLE_PUBLIC_KEY_HEX
else
    unset AIRGAP_BUNDLE_PUBLIC_KEY_HEX
fi

if [ "$AIRGAP_MODE" = "true" ]; then
    echo -e "${YELLOW}🔒 AIRGAP_MODE enabled — offline-only marketplace/enrichment${NC}"
    if [ -n "${AIRGAP_BUNDLE_PUBLIC_KEY_HEX:-}" ]; then
        echo -e "${GREEN}✓${NC} Embedding injected AIRGAP_BUNDLE_PUBLIC_KEY_HEX at build time"
    else
        echo -e "${YELLOW}   No key injected — debug build uses the dev placeholder (sign test bundles with the dev seed 0x01..01)${NC}"
    fi
fi

export CORS_ORIGINS="${CORS_ORIGINS:-http://localhost:5173,http://localhost:3000,http://localhost:3001,http://localhost:3002}"
export NRT_LAG_BUFFER_SECS="${NRT_LAG_BUFFER_SECS:-60}"
export NRT_MAX_BATCH_SIZE="${NRT_MAX_BATCH_SIZE:-100000}"
export NRT_MAX_CONCURRENT_RULES="${NRT_MAX_CONCURRENT_RULES:-10}"
export NRT_JITTER_MAX_SECS="${NRT_JITTER_MAX_SECS:-30}"

# Skip the jobs process when validating an interactive query backend against a
# deliberately small fixture. Search/API/frontend still run as the real stack;
# scheduled detections are exercised separately against a production-shaped
# corpus so fixture schema gaps cannot create noisy failed rule runs.
export NANO_DEV_SKIP_JOBS="${NANO_DEV_SKIP_JOBS:-false}"

# Disk pressure settings (automatic partition eviction when disk fills up)
# Watermarks are fractions (0.0-1.0) of total disk space
export DISK_PRESSURE_CHECK_INTERVAL_SECS="${DISK_PRESSURE_CHECK_INTERVAL_SECS:-30}"
export DISK_PRESSURE_HIGH_WATERMARK="${DISK_PRESSURE_HIGH_WATERMARK:-0.60}"
export DISK_PRESSURE_LOW_WATERMARK="${DISK_PRESSURE_LOW_WATERMARK:-0.50}"
export DISK_PRESSURE_CRITICAL_THRESHOLD="${DISK_PRESSURE_CRITICAL_THRESHOLD:-0.85}"
export DISK_PRESSURE_EMERGENCY_THRESHOLD="${DISK_PRESSURE_EMERGENCY_THRESHOLD:-0.90}"
export DISK_PRESSURE_PAUSE_INGESTION="${DISK_PRESSURE_PAUSE_INGESTION:-false}"

# Service health check URLs for Main API
export SEARCH_SERVICE_URL="http://localhost:3002/health"

# Cloudflare AI Gateway settings — these reach the internet, so SKIP them in
# air-gap mode. A real air-gap install has no CLOUDFLARE_AI_GATEWAY_URL; AI runs
# only via an on-prem provider base_url (Settings → AI providers, NAN-1207).
if [ "$AIRGAP_MODE" = "true" ]; then
    echo -e "${YELLOW}   AIRGAP_MODE: not setting Cloudflare AI Gateway env — configure an on-prem AI endpoint in Settings → AI providers${NC}"
else
    # NAN-2228: CF_AIG_AUTH_TOKEN must come from the environment. It previously
    # carried a working token as a shell default, and this script is the one
    # file under scripts/ that `tools/sync-to-nano-mirror.sh` preserves — so
    # that default was published verbatim to the public mirror. Never inline a
    # credential here again; anything in this file is public by design.
    #
    # Unset is not fatal: the stack starts fine without AI, and most dev work
    # does not need it. Warn and continue rather than blocking `pnpm dev`.
    export CLOUDFLARE_AI_GATEWAY_URL="${CLOUDFLARE_AI_GATEWAY_URL:-}"
    export CF_AIG_AUTH_TOKEN="${CF_AIG_AUTH_TOKEN:-}"

    if [ -z "$CF_AIG_AUTH_TOKEN" ] || [ -z "$CLOUDFLARE_AI_GATEWAY_URL" ]; then
        echo -e "${YELLOW}   AI features disabled — set CLOUDFLARE_AI_GATEWAY_URL and CF_AIG_AUTH_TOKEN to enable them.${NC}"
        echo -e "${YELLOW}   Both live in the team password manager; export them in your shell or a local .env (never commit them).${NC}"
    fi
fi

# AI behaviour flags. Both are read directly from process env at the call
# site; we set them explicitly here so dev runs are reproducible regardless
# of whatever happens to be in the shell that launched the script.
#
# NANOSIEM_ANTHROPIC_NATIVE (NAN-645/647): route Anthropic chat through
#   `/anthropic/v1/messages` instead of the OpenAI-compat shim. Required
#   for `cache_control` markers to actually reach Anthropic. ON by default
#   everywhere (NAN-647 flipped the binary default after live verification
#   confirmed ~60% cost reduction). Override with `=0` for A/B comparison
#   or rollback.
export NANOSIEM_ANTHROPIC_NATIVE="${NANOSIEM_ANTHROPIC_NATIVE:-1}"
#
# NANOSIEM_PARSER_TOOL_LOOP (NAN-632): enable the multi-turn tool-use
#   parser-gen loop. OFF by default — the post-NAN-642/643 single-shot
#   path with edit-block patches is the proven default; the tool loop is
#   parked until we have a reason to re-evaluate. Set to `1` to opt in.
export NANOSIEM_PARSER_TOOL_LOOP="${NANOSIEM_PARSER_TOOL_LOOP:-0}"

# Docs search (NAN-4103): pivt grounds product answers on the nano-docs-public
# AI Search instance via the docs-search Worker. DOCS_SEARCH_TOKEN is the
# Worker caller token (NOT a Cloudflare token); it has no default, so docs
# grounding stays off locally unless you export it. Off under AIRGAP_MODE.
export DOCS_SEARCH_URL="${DOCS_SEARCH_URL:-https://docs-search.nano.rs}"
export DOCS_SEARCH_TOKEN="${DOCS_SEARCH_TOKEN:-}"

# Log directory
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"
if [ "$NANO_LOG_QUERY_BACKEND" != "clickhouse" ]; then
    export NANO_LAKE_QUERY_TOKEN_FILE="${NANO_LAKE_QUERY_TOKEN_FILE:-$LOG_DIR/lake-query-token}"
    export NANO_LAKE_HOT_TAIL_MANIFEST="${NANO_LAKE_HOT_TAIL_MANIFEST:-$PWD/$LOG_DIR/lake-hot-tail.json}"
    # The staged-tail manager writes the publication heartbeat as a SIBLING of
    # its manifest; the query worker validates against it (compose passes the
    # same pair). Derive it so the two can never drift apart.
    export NANO_LAKE_HOT_TAIL_PUBLICATION_HEALTH="${NANO_LAKE_HOT_TAIL_PUBLICATION_HEALTH:-${NANO_LAKE_HOT_TAIL_MANIFEST%.json}.health.json}"

    # Both consumers below start ONLY under the lake backend, so the strict
    # checks stay scoped to it — a --shadow run must not be failed by them.
    if [ "$NANO_LOG_QUERY_BACKEND" = "lake" ]; then
        # NAN-2361: the enrichment coordinator AND the risk publisher keep their
        # authoritative state in the object store instead of the node volume
        # (spot-safety: a reclaimed node used to take the IOC/identity/ip-context
        # stores and the risk ledger with it). Both resolve it through
        # `AuthoritativeObjectStore::from_env`, which reuses the durable-result S3
        # client — a DIFFERENT env prefix (NANO_LAKE_RESULT_S3_*) from the
        # NANO_LAKE_S3_* set this script already discovers. Map one onto the other
        # rather than making the operator supply both.
        #
        # Set HERE, in the shared lake defaults, not next to a single consumer: the
        # risk publisher starts well before the enrichment coordinator, so a block
        # scoped to the coordinator leaves the risk publisher without the env.
        if [ -z "${NANO_LAKE_AUTHORITATIVE_STATE_STORE:-}" ]; then
            if [ -z "${NANO_LAKE_BRONZE_BUCKET:-}" ]; then
                echo -e "${RED}✗${NC} authoritative state store needs NANO_LAKE_BRONZE_BUCKET"
                exit 1
            fi
            export NANO_LAKE_AUTHORITATIVE_STATE_STORE="s3://${NANO_LAKE_BRONZE_BUCKET}/authoritative-state-v1"
        fi
        export NANO_LAKE_RESULT_S3_REGION="${NANO_LAKE_RESULT_S3_REGION:-${NANO_LAKE_S3_REGION:-us-east-1}}"
        if [ -n "${NANO_LAKE_S3_ENDPOINT:-}" ]; then
            export NANO_LAKE_RESULT_S3_ENDPOINT="${NANO_LAKE_RESULT_S3_ENDPOINT:-$NANO_LAKE_S3_ENDPOINT}"
        fi
        export NANO_LAKE_RESULT_S3_DEFAULT_CREDENTIALS="${NANO_LAKE_RESULT_S3_DEFAULT_CREDENTIALS:-${NANO_LAKE_S3_DEFAULT_CREDENTIALS:-false}}"
        # Path-style is how RustFS is addressed locally; the result client spells the
        # same choice as its inverse.
        if [ "${NANO_LAKE_S3_PATH_STYLE_ACCESS:-true}" = "true" ]; then
            export NANO_LAKE_RESULT_S3_VIRTUAL_HOST_STYLE="${NANO_LAKE_RESULT_S3_VIRTUAL_HOST_STYLE:-false}"
        else
            export NANO_LAKE_RESULT_S3_VIRTUAL_HOST_STYLE="${NANO_LAKE_RESULT_S3_VIRTUAL_HOST_STYLE:-true}"
        fi
        # Static credentials arrive INDIRECTLY: NANO_LAKE_S3_ACCESS_KEY_ENV holds the
        # NAME of the variable carrying the key. The result client wants the value.
        if [ "$NANO_LAKE_RESULT_S3_DEFAULT_CREDENTIALS" = "false" ]; then
            if [ -n "${NANO_LAKE_S3_ACCESS_KEY_ENV:-}" ] && [ -z "${NANO_LAKE_RESULT_S3_ACCESS_KEY_ID:-}" ]; then
                export NANO_LAKE_RESULT_S3_ACCESS_KEY_ID="${!NANO_LAKE_S3_ACCESS_KEY_ENV:-}"
            fi
            if [ -n "${NANO_LAKE_S3_SECRET_KEY_ENV:-}" ] && [ -z "${NANO_LAKE_RESULT_S3_SECRET_ACCESS_KEY:-}" ]; then
                export NANO_LAKE_RESULT_S3_SECRET_ACCESS_KEY="${!NANO_LAKE_S3_SECRET_KEY_ENV:-}"
            fi
            for required in NANO_LAKE_RESULT_S3_ACCESS_KEY_ID NANO_LAKE_RESULT_S3_SECRET_ACCESS_KEY; do
                if [ -z "${!required:-}" ]; then
                    echo -e "${RED}✗${NC} authoritative state store requires $required"
                    exit 1
                fi
            done
        fi

        # NAN-2361: risk (RBA) was dark locally for one reason — the risk publisher
        # is gated on NANO_LAKE_RISK_SNAPSHOT_MANIFEST and NOTHING ever set it, so
        # `lake_risk_publish` never started, no risk snapshot reached the
        # generation's worker.json, and every `dataset=risk` query was rejected with
        # "risk queries are not configured for this tenant" — including the seeded
        # RBA detection rule, which failed on its 5-minute schedule forever.
        #
        # The publisher self-bootstraps an empty ledger from this path on a fresh
        # tenant (`bootstrap_empty_snapshot`) and reuses it forever after, so a
        # default is all that was missing. The filename is load-bearing: the
        # publisher rejects anything not named risk-serving-snapshot.json, and the
        # parent directory becomes its snapshot output directory.
        export NANO_LAKE_RISK_SNAPSHOT_MANIFEST="${NANO_LAKE_RISK_SNAPSHOT_MANIFEST:-$PWD/.state/lake/risk/risk-serving-snapshot.json}"
    fi
fi

# Cleanup function
cleanup() {
    if [ "${CLEANUP_RUNNING:-false}" = "true" ]; then
        return
    fi
    CLEANUP_RUNNING=true
    trap - SIGINT SIGTERM EXIT
    echo -e "\n${YELLOW}Shutting down services...${NC}"

    # `set -m` puts every background pipeline in its own process group. `$!`
    # names the final `tee`, not the Rust service on the left side, so killing
    # only `$!` orphaned API/search/jobs. Stop each exact recorded job group.
    echo "Stopping service process groups..."
    for service_pgid in "$API_PGID" "$SEARCH_PGID" "$JOBS_PGID" "$FRONTEND_PGID" "$LAKE_QUERY_PGID" "$LAKE_RISK_PUBLISHER_PGID" "$LAKE_BRONZE_PUBLISHER_PGID" "$LAKE_TAIL_MANAGER_PGID" "$LAKE_TAIL_PACKER_PGID" "$LAKE_TAIL_COMPACTOR_PGID" "$LAKE_EVENT_PUBLISHER_PGID" "$LAKE_GENERATION_MANAGER_PGID" "$LAKE_ENRICHMENT_COORDINATOR_PGID" "$LAKE_OTEL_INGEST_PGID"; do
        if [[ "$service_pgid" =~ ^[0-9]+$ ]]; then
            kill -TERM -- "-$service_pgid" 2>/dev/null || true
        fi
    done
    sleep 2
    for service_pgid in "$API_PGID" "$SEARCH_PGID" "$JOBS_PGID" "$FRONTEND_PGID" "$LAKE_QUERY_PGID" "$LAKE_RISK_PUBLISHER_PGID" "$LAKE_BRONZE_PUBLISHER_PGID" "$LAKE_TAIL_MANAGER_PGID" "$LAKE_TAIL_PACKER_PGID" "$LAKE_TAIL_COMPACTOR_PGID" "$LAKE_EVENT_PUBLISHER_PGID" "$LAKE_GENERATION_MANAGER_PGID" "$LAKE_ENRICHMENT_COORDINATOR_PGID" "$LAKE_OTEL_INGEST_PGID"; do
        if [[ "$service_pgid" =~ ^[0-9]+$ ]]; then
            kill -KILL -- "-$service_pgid" 2>/dev/null || true
        fi
    done
    
    # Also explicitly kill known PIDs if they're still running
    for pid in "$API_PID" "$SEARCH_PID" "$JOBS_PID" "$FRONTEND_PID" "$LAKE_QUERY_PID" "$LAKE_RISK_PUBLISHER_PID" "$LAKE_BRONZE_PUBLISHER_PID" "$LAKE_TAIL_MANAGER_PID" "$LAKE_TAIL_PACKER_PID" "$LAKE_TAIL_COMPACTOR_PID" "$LAKE_EVENT_PUBLISHER_PID" "$LAKE_GENERATION_MANAGER_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "Force killing PID $pid..."
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    
    echo -e "${GREEN}All services stopped.${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# Check dependencies
check_dependency() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}❌ $1 is not installed${NC}"
        return 1
    fi
    echo -e "${GREEN}✓${NC} $1 found"
    return 0
}

if [ "$CONFIG_CHECK_ONLY" = "1" ]; then
    echo
    echo -e "${GREEN}Resolved configuration (--check: nothing was started)${NC}"
    echo "  NANO_SCHEMA_PROFILE      = ${NANO_SCHEMA_PROFILE}"
    echo "  NANO_LOG_QUERY_BACKEND   = ${NANO_LOG_QUERY_BACKEND}"
    if [ "$NANO_LOG_QUERY_BACKEND" != "clickhouse" ]; then
        echo "  NANO_LAKE_QUERY_URL      = ${NANO_LAKE_QUERY_URL:-<unset>}"
        echo "  NANO_LAKE_WORKER_CONFIG  = ${NANO_LAKE_WORKER_CONFIG:-<unset>}"
        echo "  NANO_LAKE_TENANT_ID      = ${NANO_LAKE_TENANT_ID:-<unset>}"
        echo "  NANO_LAKE_BRONZE_BUCKET  = ${NANO_LAKE_BRONZE_BUCKET:-<unset>}"
        echo "  NANO_LAKE_SCHEMA_MANIFEST= ${NANO_LAKE_SCHEMA_MANIFEST:-<unset, resolved from the worker config>}"
        echo "  RustFS credentials       = $([ -n "${NANO_LAKE_ACCESS_KEY_ID:-}" ] && echo present || echo absent)"
    fi
    echo
    trap - EXIT
    exit 0
fi

echo -e "\n${YELLOW}Checking dependencies...${NC}"
check_dependency docker || exit 1
check_dependency cargo || exit 1
check_dependency npm || exit 1
if [ "$NANO_LOG_QUERY_BACKEND" != "clickhouse" ]; then
    check_dependency openssl || exit 1
    if [ ! -s "$NANO_LAKE_QUERY_TOKEN_FILE" ]; then
        umask 077
        openssl rand -hex 32 > "$NANO_LAKE_QUERY_TOKEN_FILE"
        echo -e "${GREEN}✓${NC} Generated local lake-query bearer token"
    fi
fi

# Start the control-plane and ingest dependencies. Canonical lake mode has no
# ClickHouse process; shadow/legacy modes retain the existing dependency.
# worktrees can reuse the main checkout's already-running named containers;
# Compose otherwise treats the worktree directory as a different project and
# collides with those explicit container names.
export NANO_DEV_REUSE_INFRA="${NANO_DEV_REUSE_INFRA:-false}"
echo -e "\n${YELLOW}Starting infrastructure services...${NC}"
if [ "$NANO_DEV_REUSE_INFRA" = "true" ]; then
    NANO_DEV_POSTGRES_CONTAINER="${NANO_DEV_POSTGRES_CONTAINER:-nanosiem-postgres}"
    NANO_DEV_POSTGRES_USER="${NANO_DEV_POSTGRES_USER:-nanosiem}"
    NANO_DEV_POSTGRES_PASSWORD="${NANO_DEV_POSTGRES_PASSWORD:-nanosiem}"
    NANO_DEV_POSTGRES_DB="${NANO_DEV_POSTGRES_DB:-nanosiem}"
    NANO_DEV_CLICKHOUSE_CONTAINER="${NANO_DEV_CLICKHOUSE_CONTAINER:-nanosiem-clickhouse}"
    NANO_DEV_VECTOR_CONTAINER="${NANO_DEV_VECTOR_CONTAINER:-nanosiem-vector}"
    NANO_DEV_DRAGONFLY_CONTAINER="${NANO_DEV_DRAGONFLY_CONTAINER:-nanosiem-dragonfly}"
    infra_containers=("$NANO_DEV_POSTGRES_CONTAINER" "$NANO_DEV_VECTOR_CONTAINER" "$NANO_DEV_DRAGONFLY_CONTAINER")
    if [ "$NANO_LOG_QUERY_BACKEND" != "lake" ]; then
        infra_containers+=("$NANO_DEV_CLICKHOUSE_CONTAINER")
    fi
    for container in "${infra_containers[@]}"; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" != "true" ]; then
            echo -e "${RED}❌ Reused infrastructure container is not running: $container${NC}"
            exit 1
        fi
    done
    echo -e "${GREEN}✓${NC} Reusing running infrastructure containers from the main checkout"
else
    if [ "$NANO_LOG_QUERY_BACKEND" = "lake" ]; then
        docker compose up -d postgres vector dragonfly prometheus grafana postgres-exporter
    else
        docker compose up -d postgres clickhouse vector dragonfly prometheus grafana postgres-exporter
    fi
fi

# Wait for PostgreSQL to be ready
echo -e "${YELLOW}Waiting for PostgreSQL to be ready...${NC}"
until if [ "$NANO_DEV_REUSE_INFRA" = "true" ]; then
    docker exec \
        -e PGPASSWORD="$NANO_DEV_POSTGRES_PASSWORD" \
        "$NANO_DEV_POSTGRES_CONTAINER" \
        psql -U "$NANO_DEV_POSTGRES_USER" -d "$NANO_DEV_POSTGRES_DB" -tAc 'SELECT 1' \
        > /dev/null 2>&1
else
    docker compose exec -T postgres pg_isready -U nanosiem -d nanosiem > /dev/null 2>&1
fi; do
    echo -n "."
    sleep 1
done
echo -e "\n${GREEN}✓${NC} PostgreSQL is ready"

if [ "$NANO_LOG_QUERY_BACKEND" != "lake" ]; then
    echo -e "${YELLOW}Waiting for ClickHouse to be ready...${NC}"
    until curl -s http://localhost:8123/ping 2>/dev/null | grep -q "Ok."; do
        echo -n "."
        sleep 1
    done
    echo -e "\n${GREEN}✓${NC} ClickHouse is ready"

    # Create ClickHouse database if it doesn't exist (using admin credentials)
    echo -e "${YELLOW}Initializing ClickHouse database...${NC}"
    CLICKHOUSE_ADMIN_USER="${CLICKHOUSE_ADMIN_USER:-nanosiem_admin}"
    CLICKHOUSE_ADMIN_PASSWORD="${CLICKHOUSE_ADMIN_PASSWORD:-nanosiem_admin_secret}"
    curl -s "http://localhost:8123/?user=${CLICKHOUSE_ADMIN_USER}&password=${CLICKHOUSE_ADMIN_PASSWORD}" \
      -d "CREATE DATABASE IF NOT EXISTS ${CLICKHOUSE_DATABASE}" > /dev/null 2>&1 \
      && echo -e "${GREEN}✓${NC} ClickHouse database '${CLICKHOUSE_DATABASE}' ready" \
      || echo -e "${RED}✗${NC} Failed to create ClickHouse database (will retry on API startup)"
else
    echo -e "${GREEN}✓${NC} Canonical lake mode does not require ClickHouse"
fi

# Build mode: use DEBUG=1 for faster compilation (default), RELEASE=1 for optimized builds
if [ "${RELEASE:-0}" = "1" ]; then
    BUILD_MODE="--release"
    TARGET_DIR="release"
    echo -e "\n${YELLOW}Building services (release mode - this may take a while)...${NC}"
else
    BUILD_MODE=""
    TARGET_DIR="debug"
    echo -e "\n${YELLOW}Building services (debug mode - faster compilation)...${NC}"
fi

# Edition — single knob driving both backend cargo features and frontend
# vite alias. Default is `enterprise` (full surface). Set EDITION=open to
# run the end-to-end open-core stack: backend without the enterprise crate
# (cases, incidents, melod, risk, notebooks, tuning AI, custom + agent
# enrichment, AI-driven siem health) and frontend with @/enterprise/* aliased
# to no-op stubs (NAN-745).
EDITION="${EDITION:-enterprise}"
case "$EDITION" in
    enterprise|open) ;;
    *)
        echo -e "${RED}❌ Invalid EDITION: $EDITION (expected 'open' or 'enterprise')${NC}"
        exit 1
        ;;
esac
echo -e "${YELLOW}⚙  Edition: ${EDITION}${NC}"

# Cargo features. The edition flag controls whether the enterprise crate is
# compiled in. FEATURES env var still supported for additional cargo features
# (e.g. tracing-otel) that compose with the edition.
FEATURE_FLAG=""
EXTRA_FEATURES="${FEATURES:-}"
if [ "$EDITION" = "enterprise" ]; then
    if [ -n "$EXTRA_FEATURES" ]; then
        FEATURE_FLAG="--features enterprise,${EXTRA_FEATURES}"
    else
        FEATURE_FLAG="--features enterprise"
    fi
elif [ -n "$EXTRA_FEATURES" ]; then
    FEATURE_FLAG="--features ${EXTRA_FEATURES}"
fi
if [ -n "$EXTRA_FEATURES" ]; then
    echo -e "${YELLOW}⚙  Extra cargo features: ${EXTRA_FEATURES}${NC}"
fi

# Every binary launched below must be part of this build. Relying on a stale
# `nanosiem-jobs` or `clickhouse_migrator` left by an earlier checkout makes a
# clean development install fail late, or worse, run code from a different
# schema generation.
set +e
cargo build -p nanosiem-api -p nanosiem-search $BUILD_MODE $FEATURE_FLAG 2>&1 | tail -5
build_status=${PIPESTATUS[0]}
set -e
[ "$build_status" -eq 0 ] || { echo -e "${RED}✗${NC} API/Search build failed"; exit "$build_status"; }
if [ "$NANO_LOG_QUERY_BACKEND" != "clickhouse" ]; then
    # `--bin` filters every package named in one Cargo invocation. Keeping the
    # compiler and worker in a single command therefore skipped the worker and
    # could launch an arbitrarily old binary from target/. Build both targets
    # explicitly so a clean start always speaks the current worker protocol.
    set +e
    cargo build -p nanosiem-core --bin lake_query_compile $BUILD_MODE $FEATURE_FLAG 2>&1 | tail -5
    compiler_build_status=${PIPESTATUS[0]}
    cargo build -p nanosiem-lake-worker $BUILD_MODE 2>&1 | tail -5
    worker_build_status=${PIPESTATUS[0]}
    set -e
    [ "$compiler_build_status" -eq 0 ] || { echo -e "${RED}✗${NC} Lake compiler build failed"; exit "$compiler_build_status"; }
    [ "$worker_build_status" -eq 0 ] || { echo -e "${RED}✗${NC} Lake worker build failed"; exit "$worker_build_status"; }
fi
echo -e "${GREEN}✓${NC} Build complete"

if [ "$NANO_LOG_QUERY_BACKEND" != "clickhouse" ]; then
    if [ "${NANO_LAKE_EXTERNAL_WORKER:-false}" = "true" ]; then
        LAKE_QUERY_PID=""
        LAKE_QUERY_PGID=""
        if ! curl -fsS "${NANO_LAKE_QUERY_URL%/}/health" > /dev/null 2>&1; then
            echo -e "${RED}✗${NC} External lake worker is not healthy at ${NANO_LAKE_QUERY_URL%/}"
            exit 1
        fi
        echo -e "${GREEN}✓${NC} Using externally supervised lake query worker at ${NANO_LAKE_QUERY_URL%/}"
    else
        echo -e "\n${YELLOW}Starting tenant-pinned ${NANO_LAKE_WORKER_RUNTIME} lake query worker on ${NANO_LAKE_QUERY_LISTEN}...${NC}"
        if curl -fsS "${NANO_LAKE_QUERY_URL%/}/health" > /dev/null 2>&1; then
            echo -e "${RED}✗${NC} A lake query worker is already serving ${NANO_LAKE_QUERY_URL%/}; stop the stale launcher before starting another"
            exit 1
        fi
        "./target/${TARGET_DIR}/nanosiem-lake-worker" \
            --config "$NANO_LAKE_WORKER_CONFIG" \
            --listen "$NANO_LAKE_QUERY_LISTEN" \
            --auth-token-file "$NANO_LAKE_QUERY_TOKEN_FILE" \
            --hot-tail-manifest "$NANO_LAKE_HOT_TAIL_MANIFEST" \
            --hot-tail-publication-health "$NANO_LAKE_HOT_TAIL_PUBLICATION_HEALTH" \
            --executor-connections "${NANO_LAKE_EXECUTOR_CONNECTIONS:-2}" \
            > "$LOG_DIR/lake-query.log" 2>&1 &
        LAKE_QUERY_PID=$!
        LAKE_QUERY_PGID=$(ps -o pgid= "$LAKE_QUERY_PID" | tr -d ' ')
        LAKE_QUERY_READY=0
        for _ in $(seq 1 60); do
            # Check the process we just launched before accepting the health URL.
            # Otherwise an older worker still listening on that URL can make a
            # failed replacement look healthy and leave Search pinned to the stale
            # generation.
            if ! kill -0 "$LAKE_QUERY_PID" 2>/dev/null; then
                # Before generation 1 the seed worker config is INTENTIONALLY not
                # runnable — nanosiem-lake-worker/src/config.rs: the query worker
                # restarts until lake_generation_activate atomically replaces it.
                # Treating that as fatal here aborted the very bootstrap that
                # produces the generation, so a fresh lake could never start.
                if python3 -c '
import json, sys
sys.exit(0 if json.load(open(sys.argv[1])).get("generation_id") == "bootstrap-pending" else 1)' \
                    "$NANO_LAKE_WORKER_CONFIG" 2>/dev/null; then
                    echo -e "${YELLOW}⚠️  Lake query worker cannot start yet — no generation has been promoted.${NC}"
                    echo -e "${YELLOW}   Expected on a fresh lake. It will be started by the generation manager${NC}"
                    echo -e "${YELLOW}   once the first events are ingested and generation 1 activates.${NC}"
                    LAKE_QUERY_PID=""
                    LAKE_QUERY_PGID=""
                    break
                fi
                echo -e "${RED}✗${NC} Lake query worker exited during startup (see $LOG_DIR/lake-query.log)"
                exit 1
            fi
            if curl -fsS "${NANO_LAKE_QUERY_URL%/}/health" > /dev/null 2>&1; then
                if ! kill -0 "$LAKE_QUERY_PID" 2>/dev/null; then
                    echo -e "${RED}✗${NC} Lake health URL is served by a stale worker; the replacement exited (see $LOG_DIR/lake-query.log)"
                    exit 1
                fi
                LAKE_QUERY_READY=1
                break
            fi
            sleep 1
        done
        # Same bootstrap-window exemption as the startup guard above: with no
        # promoted generation there is deliberately no runnable worker, so
        # "not healthy" is the expected state rather than a failure.
        if [ "$LAKE_QUERY_READY" -ne 1 ] && [ -z "${LAKE_QUERY_PID:-}" ]; then
            echo -e "${YELLOW}   Continuing without a query worker; searches will fail until generation 1 lands.${NC}"
        elif [ "$LAKE_QUERY_READY" -ne 1 ]; then
            echo -e "${RED}✗${NC} Lake query worker did not become healthy (see $LOG_DIR/lake-query.log)"
            exit 1
        else
            echo -e "${GREEN}✓${NC} Lake query worker ready (PID: $LAKE_QUERY_PID, mode: $NANO_LOG_QUERY_BACKEND, runtime: $NANO_LAKE_WORKER_RUNTIME)"
        fi
    fi

    if [ "$NANO_LOG_QUERY_BACKEND" = "lake" ] && [ -n "${NANO_LAKE_RISK_SNAPSHOT_MANIFEST:-}" ]; then
        echo -e "\n${YELLOW}Starting durable finding-outbox publisher...${NC}"
        "./target/${TARGET_DIR}/lake_risk_publish" \
            --database-url "$DATABASE_URL" \
            --tenant-id "$NANO_LAKE_TENANT_ID" \
            --worker-config "$NANO_LAKE_WORKER_CONFIG" \
            --bootstrap-manifest "$NANO_LAKE_RISK_SNAPSHOT_MANIFEST" \
            --poll-seconds "${NANO_LAKE_RISK_PUBLISH_POLL_SECS:-2}" \
            > "$LOG_DIR/lake-risk-publisher.log" 2>&1 &
        LAKE_RISK_PUBLISHER_PID=$!
        LAKE_RISK_PUBLISHER_PGID=$(ps -o pgid= -p "$LAKE_RISK_PUBLISHER_PID" | tr -d ' ')
        sleep 1
        if ! kill -0 "$LAKE_RISK_PUBLISHER_PID" 2>/dev/null; then
            echo -e "${RED}✗${NC} Lake risk publisher exited during startup (see $LOG_DIR/lake-risk-publisher.log)"
            exit 1
        fi
        echo -e "${GREEN}✓${NC} Lake risk publisher ready (PID: $LAKE_RISK_PUBLISHER_PID)"
    fi

    if [ "$NANO_LOG_QUERY_BACKEND" = "lake" ] && [ "${NANO_LAKE_EVENT_PUBLISH_ENABLED:-false}" = "true" ]; then
        echo -e "\n${YELLOW}Starting native OCSF Iceberg event publisher...${NC}"
        EVENT_CREDENTIAL_ARGS=()
        CATALOG_AUTH_ARGS=(
            --catalog-credential-env "$NANO_LAKE_CATALOG_CREDENTIAL_ENV"
            --catalog-oauth-scope "${NANO_LAKE_CATALOG_OAUTH_SCOPE:-lakekeeper}"
        )
        if [ -n "${NANO_LAKE_CATALOG_OAUTH_AUDIENCE:-}" ]; then
            CATALOG_AUTH_ARGS+=(--catalog-oauth-audience "$NANO_LAKE_CATALOG_OAUTH_AUDIENCE")
        fi
        if [ -n "${NANO_LAKE_CATALOG_OAUTH_SERVER_URI:-}" ]; then
            CATALOG_AUTH_ARGS+=(--catalog-oauth-server-uri "$NANO_LAKE_CATALOG_OAUTH_SERVER_URI")
        fi
        if [ -n "${NANO_LAKE_CATALOG_REALM:-}" ]; then
            CATALOG_AUTH_ARGS+=(--catalog-realm "$NANO_LAKE_CATALOG_REALM")
        fi
        LAKE_S3_ARGS=(--s3-region "${NANO_LAKE_S3_REGION:-us-east-1}")
        if [ -n "${NANO_LAKE_S3_ENDPOINT:-}" ]; then
            LAKE_S3_ARGS+=(--s3-endpoint "$NANO_LAKE_S3_ENDPOINT")
        fi
        if [ "$NANO_LAKE_S3_DEFAULT_CREDENTIALS" = "true" ]; then
            LAKE_S3_ARGS+=(--s3-default-credentials)
        else
            LAKE_S3_ARGS+=(--s3-access-key-env "$NANO_LAKE_S3_ACCESS_KEY_ENV")
            LAKE_S3_ARGS+=(--s3-secret-key-env "$NANO_LAKE_S3_SECRET_KEY_ENV")
            if [ -n "${NANO_LAKE_S3_SESSION_TOKEN_ENV:-}" ]; then
                LAKE_S3_ARGS+=(--s3-session-token-env "$NANO_LAKE_S3_SESSION_TOKEN_ENV")
            fi
        fi
        if [ "$NANO_LAKE_S3_PATH_STYLE_ACCESS" = "false" ]; then
            LAKE_S3_ARGS+=(--s3-virtual-host-style)
        fi
        if [ "${NANO_LAKE_CATALOG_VENDED_CREDENTIALS:-false}" = "true" ]; then
            EVENT_CREDENTIAL_ARGS+=(--vended-credentials)
        fi
        BRONZE_ENRICHMENT_ARGS=()
        if [ -n "${NANO_IPINFO_MMDB_PATH:-}" ]; then
            BRONZE_ENRICHMENT_ARGS+=(--ipinfo-mmdb "$NANO_IPINFO_MMDB_PATH")
            if [ -n "${NANO_IPINFO_MMDB_SHA256:-}" ]; then
                BRONZE_ENRICHMENT_ARGS+=(--ipinfo-sha256 "$NANO_IPINFO_MMDB_SHA256")
            fi
        fi
        if [ -n "${NANO_LAKE_IOC_SNAPSHOT_PATH:-}" ]; then
            BRONZE_ENRICHMENT_ARGS+=(--ioc-snapshot "$NANO_LAKE_IOC_SNAPSHOT_PATH")
            BRONZE_ENRICHMENT_ARGS+=(--ioc-sha256 "$NANO_LAKE_IOC_SNAPSHOT_SHA256")
        fi
        if [ "${#BRONZE_ENRICHMENT_ARGS[@]}" -gt 0 ]; then
            if [ -z "${NANO_LAKE_ENRICHMENT_CACHE_DIRECTORY:-}" ]; then
                echo -e "${RED}✗${NC} Bronze enrichment requires NANO_LAKE_ENRICHMENT_CACHE_DIRECTORY"
                exit 1
            fi
            BRONZE_ENRICHMENT_ARGS+=(--enrichment-cache-directory "$NANO_LAKE_ENRICHMENT_CACHE_DIRECTORY")
        fi

        # Vector acknowledges only after its versioned bronze object is
        # durable. This Rust coordinator pins those exact versions, validates
        # canonical OCSF 1.9, and publishes exact-version Parquet into a signed
        # staged tail. Only the compactor advances Iceberg with sized appends.
        # NAN-2361: the enrichment coordinator and the OTLP lake ingest are part
        # of the lake data path — Vector's sinks POST to them — but this script
        # never started them, so a host-run lake had Vector retrying forever
        # against services that existed only in the compose file. Both tolerate a
        # pre-first-generation worker config (verified: the coordinator reports
        # {"status":"ok","tenant_pinned":true} on a bootstrap-pending config).
        mkdir -p "$NANO_LAKE_ENRICHMENT_IOC_DIR" "$NANO_LAKE_ENRICHMENT_IDENTITY_DIR" \
                 "$NANO_LAKE_ENRICHMENT_IP_CONTEXT_DIR"
        echo -e "\n${YELLOW}Starting lake enrichment coordinator...${NC}"
        "./target/${TARGET_DIR}/lake_enrichment_coordinator" \
            --listen "127.0.0.1:${NANO_DEV_ENRICHMENT_PORT:-3016}" \
            --auth-token-file "$NANO_LAKE_ENRICHMENT_TOKEN_FILE" \
            --output-directory "$NANO_LAKE_ENRICHMENT_IOC_DIR" \
            --identity-directory "$NANO_LAKE_ENRICHMENT_IDENTITY_DIR" \
            --ip-context-directory "$NANO_LAKE_ENRICHMENT_IP_CONTEXT_DIR" \
            --worker-config "$NANO_LAKE_WORKER_CONFIG" \
            --tenant-id "$NANO_LAKE_TENANT_ID" \
            --snapshot-id "${NANO_LAKE_IOC_SNAPSHOT_ID:-ioc-default-current}" \
            > "$LOG_DIR/lake-enrichment-coordinator.log" 2>&1 &
        LAKE_ENRICHMENT_COORDINATOR_PID=$!
        LAKE_ENRICHMENT_COORDINATOR_PGID=$(ps -o pgid= -p "$LAKE_ENRICHMENT_COORDINATOR_PID" | tr -d ' ')
        echo -e "${GREEN}✓${NC} enrichment coordinator on 127.0.0.1:${NANO_DEV_ENRICHMENT_PORT:-3016}"

        echo -e "\n${YELLOW}Starting lake OTLP ingest...${NC}"
        # NAN-2361: this service was started by the stack but never CONFIGURED
        # by it. `lake_otel_ingest` hard-requires the tenant, both OTLP table
        # idents and their locations, the chDB library, and the Iceberg catalog
        # settings (see its `Config::from_env`); the launcher passed only a
        # listen address — and even that under a name the binary never reads
        # (`NANO_OTEL_LAKE_INGEST_LISTEN` vs `NANO_OTEL_LAKE_LISTEN`), so it
        # worked purely because the default matched. A stock `--lake` run
        # therefore started this process and it exited on the first missing
        # variable, which nothing noticed because the success line below was
        # printed unconditionally. Everything here derives from values the lake
        # bootstrap already establishes, so the local dev path matches the
        # deployment paths (docker-compose.opensource.yml, the scale benchmarks)
        # that always set them.
        #
        # The OTLP tables live beside the events table, in its namespace and
        # under its parent location — derived rather than hardcoded so a
        # non-`default` tenant works without editing this block.
        otel_namespace="${NANO_LAKE_EVENT_TABLE%%.*}"
        otel_location_root="${NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX%/}"
        otel_location_root="${otel_location_root%/*}"
        # Both chDB values come from the worker config the launcher resolved
        # above, so the OTLP service loads the same verified library as the
        # query worker instead of a second, unpinned copy.
        otel_chdb_path="$(jq -r '.native_library.path' "$NANO_LAKE_WORKER_CONFIG")"
        otel_chdb_sha="$(jq -r '.native_library.sha256' "$NANO_LAKE_WORKER_CONFIG")"

        NANO_OTEL_LAKE_LISTEN="127.0.0.1:${NANO_DEV_OTEL_INGEST_PORT:-3014}" \
        NANO_OTEL_LAKE_TENANT_ID="${NANO_OTEL_LAKE_TENANT_ID:-$NANO_LAKE_TENANT_ID}" \
        NANO_OTEL_SPANS_TABLE="${NANO_OTEL_SPANS_TABLE:-${otel_namespace}.otel_spans}" \
        NANO_OTEL_SPANS_LOCATION="${NANO_OTEL_SPANS_LOCATION:-${otel_location_root}/otel_spans/}" \
        NANO_OTEL_METRICS_TABLE="${NANO_OTEL_METRICS_TABLE:-${otel_namespace}.otel_metrics}" \
        NANO_OTEL_METRICS_LOCATION="${NANO_OTEL_METRICS_LOCATION:-${otel_location_root}/otel_metrics/}" \
        NANO_CHDB_LIBRARY_PATH="${NANO_CHDB_LIBRARY_PATH:-$otel_chdb_path}" \
        NANO_CHDB_LIBRARY_SHA256="${NANO_CHDB_LIBRARY_SHA256:-$otel_chdb_sha}" \
        NANO_ICEBERG_CATALOG_URI="${NANO_ICEBERG_CATALOG_URI:-$NANO_LAKE_CATALOG_URI}" \
        NANO_ICEBERG_WAREHOUSE="${NANO_ICEBERG_WAREHOUSE:-$NANO_LAKE_CATALOG_WAREHOUSE}" \
        NANO_ICEBERG_CREDENTIAL="${NANO_ICEBERG_CREDENTIAL:-${NANO_LAKE_CATALOG_CREDENTIAL:-}}" \
        NANO_ICEBERG_OAUTH_SCOPE="${NANO_ICEBERG_OAUTH_SCOPE:-${NANO_LAKE_CATALOG_OAUTH_SCOPE:-}}" \
        NANO_ICEBERG_OAUTH_AUDIENCE="${NANO_ICEBERG_OAUTH_AUDIENCE:-${NANO_LAKE_CATALOG_OAUTH_AUDIENCE:-}}" \
        NANO_ICEBERG_OAUTH_SERVER_URI="${NANO_ICEBERG_OAUTH_SERVER_URI:-${NANO_LAKE_CATALOG_OAUTH_SERVER_URI:-}}" \
        NANO_ICEBERG_S3_ENDPOINT="${NANO_ICEBERG_S3_ENDPOINT:-${NANO_LAKE_S3_ENDPOINT:-}}" \
        NANO_ICEBERG_S3_REGION="${NANO_ICEBERG_S3_REGION:-${NANO_LAKE_S3_REGION:-us-east-1}}" \
        NANO_ICEBERG_S3_ACCESS_KEY="${NANO_LAKE_ACCESS_KEY_ID:-}" \
        NANO_ICEBERG_S3_SECRET_KEY="${NANO_LAKE_SECRET_ACCESS_KEY:-}" \
        NANO_ICEBERG_S3_PATH_STYLE="${NANO_ICEBERG_S3_PATH_STYLE:-${NANO_LAKE_S3_PATH_STYLE_ACCESS:-true}}" \
        NANO_ICEBERG_S3_DEFAULT_CREDENTIALS="${NANO_ICEBERG_S3_DEFAULT_CREDENTIALS:-${NANO_LAKE_S3_DEFAULT_CREDENTIALS:-false}}" \
        "./target/${TARGET_DIR}/lake_otel_ingest" \
            > "$LOG_DIR/lake-otel-ingest.log" 2>&1 &
        LAKE_OTEL_INGEST_PID=$!
        LAKE_OTEL_INGEST_PGID=$(ps -o pgid= -p "$LAKE_OTEL_INGEST_PID" | tr -d ' ')

        # Gate on the service actually answering, like every sibling lake
        # service does. Without this the stack reported a tick for a process
        # that had already exited, and the failure only surfaced much later as
        # a 503 from the Observability pages.
        otel_ingest_ready=0
        for _ in $(seq 1 30); do
            if ! kill -0 "$LAKE_OTEL_INGEST_PID" 2>/dev/null; then
                echo -e "${RED}✗${NC} OTLP lake ingest exited during startup"
                tail -n 20 "$LOG_DIR/lake-otel-ingest.log" >&2 || true
                exit 1
            fi
            if curl -fsS --max-time 2 \
                "http://127.0.0.1:${NANO_DEV_OTEL_INGEST_PORT:-3014}/health" >/dev/null 2>&1; then
                otel_ingest_ready=1
                break
            fi
            sleep 1
        done
        if [ "$otel_ingest_ready" -ne 1 ]; then
            echo -e "${RED}✗${NC} OTLP lake ingest did not become healthy"
            tail -n 20 "$LOG_DIR/lake-otel-ingest.log" >&2 || true
            exit 1
        fi
        echo -e "${GREEN}✓${NC} OTLP lake ingest on 127.0.0.1:${NANO_DEV_OTEL_INGEST_PORT:-3014}"

        echo -e "\n${YELLOW}Starting Vector bronze OCSF staged-tail publisher...${NC}"
        # The five-second Vector flush plus this one-second discovery backstop
        # keeps low-rate events inside the interactive freshness envelope.
        # High-rate deployments fill the byte/event batch first and scale by shard.
        "./target/${TARGET_DIR}/lake_bronze_publish" \
            --database-url "$DATABASE_URL" \
            --tenant-id "$NANO_LAKE_TENANT_ID" \
            --bronze-store-id "$NANO_LAKE_BRONZE_STORE_ID" \
            --bronze-bucket "$NANO_LAKE_BRONZE_BUCKET" \
            --table "$NANO_LAKE_EVENT_TABLE" \
            --table-location-prefix "$NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX" \
            --catalog-uri "$NANO_LAKE_CATALOG_URI" \
            --warehouse "$NANO_LAKE_CATALOG_WAREHOUSE" \
            "${CATALOG_AUTH_ARGS[@]}" \
            --max-files "${NANO_LAKE_BRONZE_PUBLISH_MAX_FILES:-500}" \
            --max-rows "${NANO_LAKE_BRONZE_PUBLISH_MAX_ROWS:-65536}" \
            --poll-seconds "${NANO_LAKE_BRONZE_PUBLISH_POLL_SECS:-1}" \
            "${LAKE_S3_ARGS[@]}" \
            "${EVENT_CREDENTIAL_ARGS[@]}" \
            "${BRONZE_ENRICHMENT_ARGS[@]}" \
            > "$LOG_DIR/lake-bronze-publisher.log" 2>&1 &
        LAKE_BRONZE_PUBLISHER_PID=$!
        LAKE_BRONZE_PUBLISHER_PGID=$(ps -o pgid= -p "$LAKE_BRONZE_PUBLISHER_PID" | tr -d ' ')
        sleep 1
        if ! kill -0 "$LAKE_BRONZE_PUBLISHER_PID" 2>/dev/null; then
            echo -e "${RED}✗${NC} Lake bronze publisher exited during startup (see $LOG_DIR/lake-bronze-publisher.log)"
            exit 1
        fi
        echo -e "${GREEN}✓${NC} Lake bronze publisher ready (PID: $LAKE_BRONZE_PUBLISHER_PID)"

        "./target/${TARGET_DIR}/lake_staged_tail_manage" \
            --database-url "$DATABASE_URL" \
            --tenant-id "$NANO_LAKE_TENANT_ID" \
            --table "$NANO_LAKE_EVENT_TABLE" \
            --table-location-prefix "$NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX" \
            --worker-config "$NANO_LAKE_WORKER_CONFIG" \
            --output "$NANO_LAKE_HOT_TAIL_MANIFEST" \
            --catalog-uri "$NANO_LAKE_CATALOG_URI" \
            --warehouse "$NANO_LAKE_CATALOG_WAREHOUSE" \
            "${CATALOG_AUTH_ARGS[@]}" \
            "${LAKE_S3_ARGS[@]}" \
            --committed-max-objects "${NANO_LAKE_HOT_TAIL_COMMITTED_MAX_OBJECTS:-2048}" \
            --max-objects "${NANO_LAKE_HOT_TAIL_MAX_OBJECTS:-2048}" \
            --max-bytes "${NANO_LAKE_HOT_TAIL_MAX_BYTES:-1073741824}" \
            --poll-seconds "${NANO_LAKE_HOT_TAIL_POLL_SECS:-0.5}" \
            > "$LOG_DIR/lake-tail-manager.log" 2>&1 &
        LAKE_TAIL_MANAGER_PID=$!
        LAKE_TAIL_MANAGER_PGID=$(ps -o pgid= -p "$LAKE_TAIL_MANAGER_PID" | tr -d ' ')
        sleep 1
        if ! kill -0 "$LAKE_TAIL_MANAGER_PID" 2>/dev/null; then
            echo -e "${RED}✗${NC} Lake staged-tail manager exited during startup (see $LOG_DIR/lake-tail-manager.log)"
            exit 1
        fi
        echo -e "${GREEN}✓${NC} Lake staged-tail manager ready (PID: $LAKE_TAIL_MANAGER_PID)"

        # Keep the seconds-visible exact tail cheap to scan without forcing an
        # Iceberg commit or derivative rebuild for every writer flush. The
        # packer physically merges only already-admitted immutable Parquet and
        # swaps the signed-tail object set in one database transaction.
        # MAX_AGE is also the closed-hour watermark grace; it must remain above
        # the Vector flush interval so the last ordinary flush joins the hour's
        # final sized pack.
        "./target/${TARGET_DIR}/lake_tail_pack" \
            --database-url "$DATABASE_URL" \
            --tenant-id "$NANO_LAKE_TENANT_ID" \
            --table "$NANO_LAKE_EVENT_TABLE" \
            --table-location-prefix "$NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX" \
            --catalog-uri "$NANO_LAKE_CATALOG_URI" \
            --warehouse "$NANO_LAKE_CATALOG_WAREHOUSE" \
            "${CATALOG_AUTH_ARGS[@]}" \
            --target-objects "${NANO_LAKE_TAIL_PACK_TARGET_OBJECTS:-4}" \
            --max-objects "${NANO_LAKE_TAIL_PACK_MAX_OBJECTS:-256}" \
            --max-bytes "${NANO_LAKE_TAIL_PACK_MAX_BYTES:-134217728}" \
            --max-age-seconds "${NANO_LAKE_TAIL_PACK_MAX_AGE_SECS:-60}" \
            --poll-seconds "${NANO_LAKE_TAIL_PACK_POLL_SECS:-2}" \
            "${LAKE_S3_ARGS[@]}" \
            "${EVENT_CREDENTIAL_ARGS[@]}" \
            > "$LOG_DIR/lake-tail-packer.log" 2>&1 &
        LAKE_TAIL_PACKER_PID=$!
        LAKE_TAIL_PACKER_PGID=$(ps -o pgid= -p "$LAKE_TAIL_PACKER_PID" | tr -d ' ')
        sleep 1
        if ! kill -0 "$LAKE_TAIL_PACKER_PID" 2>/dev/null; then
            echo -e "${RED}✗${NC} Lake tail packer exited during startup (see $LOG_DIR/lake-tail-packer.log)"
            exit 1
        fi
        echo -e "${GREEN}✓${NC} Lake tail packer ready (PID: $LAKE_TAIL_PACKER_PID)"

        "./target/${TARGET_DIR}/lake_tail_compact" \
            --database-url "$DATABASE_URL" \
            --tenant-id "$NANO_LAKE_TENANT_ID" \
            --table "$NANO_LAKE_EVENT_TABLE" \
            --table-location-prefix "$NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX" \
            --catalog-uri "$NANO_LAKE_CATALOG_URI" \
            --warehouse "$NANO_LAKE_CATALOG_WAREHOUSE" \
            "${CATALOG_AUTH_ARGS[@]}" \
            --target-bytes "${NANO_LAKE_COMPACTION_TARGET_BYTES:-134217728}" \
            --max-age-seconds "${NANO_LAKE_COMPACTION_MAX_AGE_SECS:-900}" \
            --max-objects "${NANO_LAKE_COMPACTION_MAX_OBJECTS:-4096}" \
            --poll-seconds "${NANO_LAKE_COMPACTION_POLL_SECS:-2}" \
            "${LAKE_S3_ARGS[@]}" \
            "${EVENT_CREDENTIAL_ARGS[@]}" \
            > "$LOG_DIR/lake-tail-compactor.log" 2>&1 &
        LAKE_TAIL_COMPACTOR_PID=$!
        LAKE_TAIL_COMPACTOR_PGID=$(ps -o pgid= -p "$LAKE_TAIL_COMPACTOR_PID" | tr -d ' ')
        sleep 1
        if ! kill -0 "$LAKE_TAIL_COMPACTOR_PID" 2>/dev/null; then
            echo -e "${RED}✗${NC} Lake tail compactor exited during startup (see $LOG_DIR/lake-tail-compactor.log)"
            exit 1
        fi
        echo -e "${GREEN}✓${NC} Lake tail compactor ready (PID: $LAKE_TAIL_COMPACTOR_PID)"

        "./target/${TARGET_DIR}/lake_event_publish" \
            --database-url "$DATABASE_URL" \
            --tenant-id "$NANO_LAKE_TENANT_ID" \
            --table "$NANO_LAKE_EVENT_TABLE" \
            --table-location-prefix "$NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX" \
            --catalog-uri "$NANO_LAKE_CATALOG_URI" \
            --warehouse "$NANO_LAKE_CATALOG_WAREHOUSE" \
            "${CATALOG_AUTH_ARGS[@]}" \
            --poll-seconds "${NANO_LAKE_EVENT_PUBLISH_POLL_SECS:-2}" \
            "${LAKE_S3_ARGS[@]}" \
            "${EVENT_CREDENTIAL_ARGS[@]}" \
            > "$LOG_DIR/lake-event-publisher.log" 2>&1 &
        LAKE_EVENT_PUBLISHER_PID=$!
        LAKE_EVENT_PUBLISHER_PGID=$(ps -o pgid= -p "$LAKE_EVENT_PUBLISHER_PID" | tr -d ' ')
        sleep 1
        if ! kill -0 "$LAKE_EVENT_PUBLISHER_PID" 2>/dev/null; then
            echo -e "${RED}✗${NC} Lake event publisher exited during startup (see $LOG_DIR/lake-event-publisher.log)"
            exit 1
        fi
        echo -e "${GREEN}✓${NC} Lake event publisher ready (PID: $LAKE_EVENT_PUBLISHER_PID)"

        if [ "${NANO_LAKE_GENERATION_MANAGER_ENABLED:-true}" = "true" ]; then
            echo -e "\n${YELLOW}Starting native Iceberg generation manager...${NC}"
            # The manager promotes only explicit `nano.generation-ready=true`
            # snapshots emitted by compaction/rewrite. Live Bronze append
            # snapshots remain in the bounded signed hot tail and must never
            # trigger a full derivative rebuild per flush.
            GENERATION_CREDENTIAL_ARGS=()
            if [ "${NANO_LAKE_CATALOG_VENDED_CREDENTIALS:-false}" = "true" ]; then
                GENERATION_CREDENTIAL_ARGS+=(--vended-credentials)
            fi
            "./target/${TARGET_DIR}/lake_generation_manage" \
                --database-url "$DATABASE_URL" \
                --tenant-id "$NANO_LAKE_TENANT_ID" \
                --table "$NANO_LAKE_EVENT_TABLE" \
                --table-location-prefix "$NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX" \
                --worker-source "$NANO_LAKE_WORKER_SOURCE" \
                --catalog-uri "$NANO_LAKE_CATALOG_URI" \
                --warehouse "$NANO_LAKE_CATALOG_WAREHOUSE" \
                "${CATALOG_AUTH_ARGS[@]}" \
                --worker-config "$NANO_LAKE_WORKER_CONFIG" \
                --worker-health-url "${NANO_LAKE_QUERY_URL%/}/health" \
                --generations-root "$NANO_LAKE_GENERATIONS_ROOT" \
                --hmac-key-file "$NANO_LAKE_ENTITY_HMAC_KEY_FILE" \
                --hot-tail-manifest "$NANO_LAKE_HOT_TAIL_MANIFEST" \
                --hot-tail-max-objects "${NANO_LAKE_HOT_TAIL_MAX_OBJECTS:-2048}" \
                --hot-tail-max-bytes "${NANO_LAKE_HOT_TAIL_MAX_BYTES:-1073741824}" \
                --max-memory-bytes "${NANO_LAKE_MAX_MEMORY_BYTES:-2147483648}" \
                --key-id "${NANO_LAKE_ENTITY_HMAC_KEY_ID:-nano-entity-v1}" \
                --threads "${NANO_LAKE_GENERATION_THREADS:-4}" \
                --heap-bytes "${NANO_LAKE_GENERATION_HEAP_BYTES:-268435456}" \
                --poll-seconds "${NANO_LAKE_GENERATION_POLL_SECS:-2}" \
                --minimum-promotion-interval-seconds "${NANO_LAKE_GENERATION_MIN_PROMOTION_INTERVAL_SECS:-900}" \
                --activation-wait-seconds "${NANO_LAKE_GENERATION_ACTIVATION_WAIT_SECS:-60}" \
                --activation-binary "$PWD/target/${TARGET_DIR}/lake_generation_activate" \
                "${LAKE_S3_ARGS[@]}" \
                "${GENERATION_CREDENTIAL_ARGS[@]}" \
                > "$LOG_DIR/lake-generation-manager.log" 2>&1 &
            LAKE_GENERATION_MANAGER_PID=$!
            LAKE_GENERATION_MANAGER_PGID=$(ps -o pgid= -p "$LAKE_GENERATION_MANAGER_PID" | tr -d ' ')
            sleep 1
            if ! kill -0 "$LAKE_GENERATION_MANAGER_PID" 2>/dev/null; then
                echo -e "${RED}✗${NC} Lake generation manager exited during startup (see $LOG_DIR/lake-generation-manager.log)"
                exit 1
            fi
            echo -e "${GREEN}✓${NC} Lake generation manager ready (PID: $LAKE_GENERATION_MANAGER_PID)"
        fi
    fi
fi

# Apply ClickHouse migrations before starting services.
# nanosiem-api refuses to start if any migration in clickhouse/ is unapplied
# (see nanosiem-api/src/state/constructors.rs). The migrator is idempotent —
# already-applied migrations are skipped.
if [ "$NANO_LOG_QUERY_BACKEND" != "lake" ]; then
    echo -e "\n${YELLOW}Applying ClickHouse migrations...${NC}"
    DATABASE_URL="$DATABASE_URL" \
    CLICKHOUSE_URL="$CLICKHOUSE_URL" \
    CLICKHOUSE_DATABASE="$CLICKHOUSE_DATABASE" \
    CLICKHOUSE_USER="$CLICKHOUSE_USER" \
    CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD" \
    CLICKHOUSE_RAWSQL_PASSWORD="$CLICKHOUSE_RAWSQL_PASSWORD" \
    CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD="$CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD" \
    CLICKHOUSE_ADMIN_USER="${CLICKHOUSE_ADMIN_USER:-nanosiem_admin}" \
    CLICKHOUSE_ADMIN_PASSWORD="${CLICKHOUSE_ADMIN_PASSWORD:-nanosiem_admin_secret}" \
    RUST_LOG="${RUST_LOG:-info}" \
    ./target/$TARGET_DIR/clickhouse_migrator 2>&1 | tee "$LOG_DIR/migrator.log"
    # tee swallows the migrator's exit code; recover it via PIPESTATUS so set -e fires.
    [ ${PIPESTATUS[0]} -eq 0 ] || { echo -e "${RED}✗${NC} ClickHouse migrations failed (see $LOG_DIR/migrator.log)"; exit 1; }
    echo -e "${GREEN}✓${NC} ClickHouse migrations up to date"
else
    echo -e "${GREEN}✓${NC} Skipping ClickHouse migrations in canonical lake mode"
fi

# Start Search Service
echo -e "\n${YELLOW}Starting Search Service on port 3002...${NC}"
DATABASE_URL="$DATABASE_URL" \
CLICKHOUSE_URL="$CLICKHOUSE_URL" \
CLICKHOUSE_DATABASE="$CLICKHOUSE_DATABASE" \
CLICKHOUSE_USER="$CLICKHOUSE_USER" \
CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD" \
CLICKHOUSE_RAWSQL_PASSWORD="$CLICKHOUSE_RAWSQL_PASSWORD" \
CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD="$CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD" \
JWT_SECRET="$JWT_SECRET" \
AUTH_ENABLED="$AUTH_ENABLED" \
NANOSIEM_ENCRYPTION_KEY="$NANOSIEM_ENCRYPTION_KEY" \
NANOSIEM_DEV_MODE="$NANOSIEM_DEV_MODE" \
CORS_ORIGINS="$CORS_ORIGINS" \
REDIS_URL="${REDIS_URL:-redis://localhost:6379}" \
RUST_LOG=info \
./target/$TARGET_DIR/nanosiem-search 2>&1 | tee "$LOG_DIR/search.log" &
SEARCH_PID=$!
SEARCH_PGID=$(ps -o pgid= "$SEARCH_PID" | tr -d ' ')
echo -e "${GREEN}✓${NC} Search Service started (PID: $SEARCH_PID)"

# NAN-2202: the jobs service runs the leader schedulers that PUSH to Vector —
# identity sync onto the enrichment lane, and collector runs onto the ingest lane.
# Both default to the in-cluster hostname `http://vector:8080/`, which does not
# resolve for a native dev process, so every push failed with a bare connection
# error. The API block below has always set these; jobs never did.
#
# Keep comments OUT of the `VAR=x \` chain below: a comment terminates the
# command, so everything above it degrades to plain shell assignments the child
# never sees. `bash -n` does not catch it.
# Start Jobs Service (background tasks: detection, enrichment, tuning, cleanup)
if [ "$NANO_DEV_SKIP_JOBS" = "true" ]; then
    JOBS_PID=""
    JOBS_PGID=""
    echo -e "\n${YELLOW}Skipping Jobs Service (NANO_DEV_SKIP_JOBS=true)${NC}"
else
echo -e "\n${YELLOW}Starting Jobs Service on port 3003...${NC}"
DATABASE_URL="$DATABASE_URL" \
CLICKHOUSE_URL="$CLICKHOUSE_URL" \
CLICKHOUSE_DATABASE="$CLICKHOUSE_DATABASE" \
CLICKHOUSE_USER="$CLICKHOUSE_USER" \
CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD" \
CLICKHOUSE_RAWSQL_PASSWORD="$CLICKHOUSE_RAWSQL_PASSWORD" \
CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD="$CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD" \
JWT_SECRET="$JWT_SECRET" \
AUTH_ENABLED="$AUTH_ENABLED" \
NANOSIEM_ENCRYPTION_KEY="$NANOSIEM_ENCRYPTION_KEY" \
NANOSIEM_DEV_MODE="$NANOSIEM_DEV_MODE" \
REDIS_URL="${REDIS_URL:-redis://localhost:6379}" \
CLOUDFLARE_AI_GATEWAY_URL="$CLOUDFLARE_AI_GATEWAY_URL" \
CF_AIG_AUTH_TOKEN="$CF_AIG_AUTH_TOKEN" \
NANOSIEM_ANTHROPIC_NATIVE="$NANOSIEM_ANTHROPIC_NATIVE" \
NANOSIEM_PARSER_TOOL_LOOP="$NANOSIEM_PARSER_TOOL_LOOP" \
DISK_PRESSURE_CHECK_INTERVAL_SECS="$DISK_PRESSURE_CHECK_INTERVAL_SECS" \
DISK_PRESSURE_HIGH_WATERMARK="$DISK_PRESSURE_HIGH_WATERMARK" \
DISK_PRESSURE_LOW_WATERMARK="$DISK_PRESSURE_LOW_WATERMARK" \
DISK_PRESSURE_CRITICAL_THRESHOLD="$DISK_PRESSURE_CRITICAL_THRESHOLD" \
DISK_PRESSURE_EMERGENCY_THRESHOLD="$DISK_PRESSURE_EMERGENCY_THRESHOLD" \
DISK_PRESSURE_PAUSE_INGESTION="$DISK_PRESSURE_PAUSE_INGESTION" \
DEPLOYMENT_MODE="$DEPLOYMENT_MODE" \
AIRGAP_MODE="$AIRGAP_MODE" \
NANO_TIER="$NANO_TIER" \
JOBS_PORT=3003 \
LEADER_ELECTION_ENABLED=true \
VECTOR_INGEST_URL="${VECTOR_INGEST_URL:-http://localhost:8080/}" \
VECTOR_AUTH_TOKEN="${VECTOR_AUTH_TOKEN:-nanosiem-default-token}" \
RUST_LOG="${RUST_LOG:-info}" \
./target/$TARGET_DIR/nanosiem-jobs 2>&1 | tee "$LOG_DIR/jobs.log" &
JOBS_PID=$!
JOBS_PGID=$(ps -o pgid= "$JOBS_PID" | tr -d ' ')
echo -e "${GREEN}✓${NC} Jobs Service started (PID: $JOBS_PID)"
fi

# Start Main API
echo -e "${YELLOW}Starting Main API on port 3000...${NC}"
DATABASE_URL="$DATABASE_URL" \
CLICKHOUSE_URL="$CLICKHOUSE_URL" \
CLICKHOUSE_DATABASE="$CLICKHOUSE_DATABASE" \
CLICKHOUSE_USER="$CLICKHOUSE_USER" \
CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD" \
CLICKHOUSE_RAWSQL_PASSWORD="$CLICKHOUSE_RAWSQL_PASSWORD" \
CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD="$CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD" \
JWT_SECRET="$JWT_SECRET" \
AUTH_ENABLED="$AUTH_ENABLED" \
NANOSIEM_ENCRYPTION_KEY="$NANOSIEM_ENCRYPTION_KEY" \
NANOSIEM_DEV_MODE="$NANOSIEM_DEV_MODE" \
CLICKHOUSE_ADMIN_USER="${CLICKHOUSE_ADMIN_USER:-nanosiem_admin}" \
CLICKHOUSE_ADMIN_PASSWORD="${CLICKHOUSE_ADMIN_PASSWORD:-nanosiem_admin_secret}" \
CORS_ORIGINS="$CORS_ORIGINS" \
REDIS_URL="${REDIS_URL:-redis://localhost:6379}" \
NRT_ENABLED="$NRT_ENABLED" \
NRT_CYCLE_INTERVAL_SECS="$NRT_CYCLE_INTERVAL_SECS" \
NRT_LAG_BUFFER_SECS="$NRT_LAG_BUFFER_SECS" \
NRT_MAX_BATCH_SIZE="$NRT_MAX_BATCH_SIZE" \
NRT_MAX_CONCURRENT_RULES="$NRT_MAX_CONCURRENT_RULES" \
NRT_JITTER_MAX_SECS="$NRT_JITTER_MAX_SECS" \
SEARCH_SERVICE_URL="$SEARCH_SERVICE_URL" \
CLOUDFLARE_AI_GATEWAY_URL="$CLOUDFLARE_AI_GATEWAY_URL" \
CF_AIG_AUTH_TOKEN="$CF_AIG_AUTH_TOKEN" \
NANOSIEM_ANTHROPIC_NATIVE="$NANOSIEM_ANTHROPIC_NATIVE" \
NANOSIEM_PARSER_TOOL_LOOP="$NANOSIEM_PARSER_TOOL_LOOP" \
DOCS_SEARCH_URL="$DOCS_SEARCH_URL" \
DOCS_SEARCH_TOKEN="$DOCS_SEARCH_TOKEN" \
DISK_PRESSURE_CHECK_INTERVAL_SECS="$DISK_PRESSURE_CHECK_INTERVAL_SECS" \
DISK_PRESSURE_HIGH_WATERMARK="$DISK_PRESSURE_HIGH_WATERMARK" \
DISK_PRESSURE_LOW_WATERMARK="$DISK_PRESSURE_LOW_WATERMARK" \
DISK_PRESSURE_CRITICAL_THRESHOLD="$DISK_PRESSURE_CRITICAL_THRESHOLD" \
DISK_PRESSURE_EMERGENCY_THRESHOLD="$DISK_PRESSURE_EMERGENCY_THRESHOLD" \
DISK_PRESSURE_PAUSE_INGESTION="$DISK_PRESSURE_PAUSE_INGESTION" \
DEPLOYMENT_MODE="$DEPLOYMENT_MODE" \
AIRGAP_MODE="$AIRGAP_MODE" \
NANO_TIER="$NANO_TIER" \
SKIP_VECTOR_VALIDATION="${SKIP_VECTOR_VALIDATION:-false}" \
VECTOR_INGEST_URL="${VECTOR_INGEST_URL:-http://localhost:8080/}" \
VECTOR_AUTH_TOKEN="${VECTOR_AUTH_TOKEN:-nanosiem-default-token}" \
RUST_LOG="${RUST_LOG:-nanosiem_core::melod=debug,info}" \
./target/$TARGET_DIR/nanosiem-api 2>&1 | tee "$LOG_DIR/api.log" &
API_PID=$!
API_PGID=$(ps -o pgid= "$API_PID" | tr -d ' ')
echo -e "${GREEN}✓${NC} Main API started (PID: $API_PID)"

# Wait for services to be ready with retries
echo -e "\n${YELLOW}Waiting for services to be ready...${NC}"

# Check service health with retries
check_service() {
    local name=$1
    local url=$2
    local max_retries=${3:-30}  # Default 30 retries (30 seconds)
    local retries=0

    echo -n "  Waiting for $name"
    while [ $retries -lt $max_retries ]; do
        if curl -s "$url" > /dev/null 2>&1; then
            echo -e " ${GREEN}✓${NC}"
            return 0
        fi
        echo -n "."
        sleep 1
        retries=$((retries + 1))
    done
    echo -e " ${RED}✗${NC} (timeout after ${max_retries}s)"
    return 1
}

# Wait for both services with generous timeout for slow starts
# Use || true to prevent set -e from killing the script on slow startup
SEARCH_READY=0
JOBS_READY=0
API_READY=0

if check_service "Search Service" "http://localhost:3002/health" 60; then
    SEARCH_READY=1
fi

if [ "$NANO_DEV_SKIP_JOBS" = "true" ]; then
    JOBS_READY=1
elif check_service "Jobs Service" "http://localhost:3003/health" 60; then
    JOBS_READY=1
fi

if check_service "Main API" "http://localhost:3000/health" 60; then
    API_READY=1
fi

if [ $SEARCH_READY -eq 0 ] || [ $JOBS_READY -eq 0 ] || [ $API_READY -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Some services may still be starting up. Check logs for details.${NC}"
    echo -e "${YELLOW}   The script will continue - services should become available shortly.${NC}"
fi

# Start Frontend
# Vite binds 0.0.0.0 by DEFAULT so other devices on the LAN can reach
# http://<your-ip>:5173. The Rust services already bind 0.0.0.0, so Vite was the
# only thing keeping the stack localhost-only — and its dev proxy is what makes
# a remote browser work without configuring VITE_API_URL (same-origin /api/*
# forwarded server-side to :3000/:3002).
#
# Set EXPOSE_LAN=0 to go back to localhost-only. Worth doing on untrusted
# networks: NANOSIEM_ALLOW_DEFAULT_KEYS defaults to true here, so an exposed
# :3000 is reachable by anyone who can route to this host.
echo -e "\n${YELLOW}Starting Frontend on port 5173 (edition: ${EDITION})...${NC}"
cd nanosiem-web
VITE_HOST_FLAG=""
if [ "${EXPOSE_LAN:-1}" = "1" ]; then
    VITE_HOST_FLAG="-- --host"
    LAN_IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')"
    if [ -n "$LAN_IP" ]; then
        echo -e "${GREEN}✓${NC} LAN exposed — reachable at http://${LAN_IP}:5173 (EXPOSE_LAN=0 to disable)"
    else
        echo -e "${GREEN}✓${NC} LAN exposed — Vite binding 0.0.0.0 (EXPOSE_LAN=0 to disable)"
    fi
else
    echo -e "${YELLOW}EXPOSE_LAN=0 — Vite is localhost-only${NC}"
fi
VITE_EDITION="$EDITION" npm run dev $VITE_HOST_FLAG > "../$LOG_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!
FRONTEND_PGID=$(ps -o pgid= "$FRONTEND_PID" | tr -d ' ')
cd ..
echo -e "${GREEN}✓${NC} Frontend started (PID: $FRONTEND_PID)"

echo -e "\n${GREEN}================================================"
echo -e "✅ All services are running!"
echo -e "================================================${NC}"
echo ""
if [ "$DEPLOYMENT_MODE" = "demo" ]; then
    echo -e "${YELLOW}  Mode: DEMO (session-scoped ephemeral users)${NC}"
    echo "  Demo page:     http://localhost:5173/demo"
    echo ""
fi
echo -e "${BLUE}Service URLs:${NC}"
echo "  Main API:       http://localhost:3000 (HTTP-only)"
if [ "$NANO_DEV_SKIP_JOBS" = "true" ]; then
    echo "  Jobs Service:   skipped (NANO_DEV_SKIP_JOBS=true)"
else
    echo "  Jobs Service:   http://localhost:3003 (background tasks)"
fi
echo "  Search Service: http://localhost:3002"
if [ "$NANO_LOG_QUERY_BACKEND" != "clickhouse" ]; then
    echo "  Lake Query:     $NANO_LAKE_QUERY_URL ($NANO_LOG_QUERY_BACKEND)"
fi
echo "  Frontend:       http://localhost:5173"
echo "  AI Gateway:     Cloudflare AI Gateway (configure CLOUDFLARE_AI_GATEWAY_URL)"
echo "  Vector:         http://localhost:8080 (ingestion)"
echo "  Prometheus:     http://localhost:9090"
echo "  Grafana:        http://localhost:3001 (admin/nanosiem)"
echo ""
echo -e "${BLUE}Logs:${NC}"
echo "  Main API:       $LOG_DIR/api.log"
echo "  Jobs Service:   $LOG_DIR/jobs.log"
echo "  Search Service: $LOG_DIR/search.log"
if [ "$NANO_LOG_QUERY_BACKEND" != "clickhouse" ]; then
    echo "  Lake Query:     $LOG_DIR/lake-query.log"
    if [ -n "${NANO_LAKE_RISK_SNAPSHOT_MANIFEST:-}" ]; then
        echo "  Risk Publisher: $LOG_DIR/lake-risk-publisher.log"
    fi
    if [ "${NANO_LAKE_EVENT_PUBLISH_ENABLED:-false}" = "true" ]; then
        echo "  Bronze Publisher: $LOG_DIR/lake-bronze-publisher.log"
        echo "  Event Publisher: $LOG_DIR/lake-event-publisher.log"
        if [ "${NANO_LAKE_GENERATION_MANAGER_ENABLED:-true}" = "true" ]; then
            echo "  Generation Manager: $LOG_DIR/lake-generation-manager.log"
        fi
    fi
fi
echo "  Frontend:       $LOG_DIR/frontend.log"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop all services${NC}"
echo ""
echo -e "${BLUE}Process IDs:${NC}"
echo "  Main API:       $API_PID"
if [ "$NANO_DEV_SKIP_JOBS" != "true" ]; then
    echo "  Jobs Service:   $JOBS_PID"
fi
echo "  Search Service: $SEARCH_PID"
echo "  Frontend:       $FRONTEND_PID"
echo ""

# Keep the script running and wait for signals
# Using wait without arguments waits for all background jobs
wait
