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

echo -e "${GREEN}🚀 NanoSIEM Microservices Development Startup${NC}"
echo "================================================"

# Load .env file if it exists (for local overrides)
if [ -f .env ]; then
    echo -e "${YELLOW}Loading environment from .env...${NC}"
    set -a
    source .env
    set +a
fi

# Database connection settings
export DATABASE_URL="postgres://nanosiem:nanosiem@localhost:5432/nanosiem"
export CLICKHOUSE_URL="http://localhost:8123"
export CLICKHOUSE_DATABASE="nanosiem"
export CLICKHOUSE_USER="nanosiem"
export CLICKHOUSE_PASSWORD="nanosiem"

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
# Set AUTH_ENABLED=false to disable authentication (development only)
export AUTH_ENABLED="${AUTH_ENABLED:-true}"

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

export CORS_ORIGINS="${CORS_ORIGINS:-http://localhost:5173,http://localhost:3000,http://localhost:3001,http://localhost:3002}"
export NRT_LAG_BUFFER_SECS="${NRT_LAG_BUFFER_SECS:-60}"
export NRT_MAX_BATCH_SIZE="${NRT_MAX_BATCH_SIZE:-100000}"
export NRT_MAX_CONCURRENT_RULES="${NRT_MAX_CONCURRENT_RULES:-10}"
export NRT_JITTER_MAX_SECS="${NRT_JITTER_MAX_SECS:-30}"

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

# Cloudflare AI Gateway settings
export CLOUDFLARE_AI_GATEWAY_URL="${CLOUDFLARE_AI_GATEWAY_URL:-https://gateway.ai.cloudflare.com/v1/156f6c44a634420513a63a3929ea201d/nano}"
export CF_AIG_AUTH_TOKEN="${CF_AIG_AUTH_TOKEN:-cfut_YyrNMUOzJ2PD8CPioBxmXnZrqEMXfJZCpj9zU90Rdc8f74ab}"

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

# Docs RAG settings (product documentation retrieval for AI chat)
export DOCS_RAG_URL="${DOCS_RAG_URL:-https://siem-rag.nano.rs}"
export DOCS_RAG_TOKEN="${DOCS_RAG_TOKEN:-nsiem-docs-ca25fd841aa2213987887249055be498}"

# Log directory
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Shutting down services...${NC}"
    
    # Kill all processes in this process group
    # This ensures we catch all child processes, including those spawned by npm
    echo "Killing all child processes..."
    
    # Get the process group ID
    PGID=$(ps -o pgid= $$ | grep -o '[0-9]*')
    
    # Kill the entire process group (except this script)
    if [ -n "$PGID" ]; then
        # List processes we're about to kill (for debugging)
        echo "Processes in group $PGID:"
        ps -g "$PGID" -o pid,ppid,pgid,command | grep -v "ps -g" || true
        
        # Kill all processes in the group except the current shell
        pkill -TERM -g "$PGID" 2>/dev/null || true
        
        # Give processes time to shut down gracefully
        sleep 2
        
        # Force kill any remaining processes
        pkill -KILL -g "$PGID" 2>/dev/null || true
    fi
    
    # Also explicitly kill known PIDs if they're still running
    for pid in "$API_PID" "$SEARCH_PID" "$JOBS_PID" "$FRONTEND_PID"; do
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

echo -e "\n${YELLOW}Checking dependencies...${NC}"
check_dependency docker || exit 1
check_dependency cargo || exit 1
check_dependency npm || exit 1

# Start PostgreSQL, ClickHouse, Vector, LiteLLM, and Monitoring Stack
echo -e "\n${YELLOW}Starting infrastructure services...${NC}"
docker compose up -d postgres clickhouse vector dragonfly prometheus grafana postgres-exporter

# Wait for PostgreSQL to be ready
echo -e "${YELLOW}Waiting for PostgreSQL to be ready...${NC}"
until docker compose exec -T postgres pg_isready -U nanosiem -d nanosiem > /dev/null 2>&1; do
    echo -n "."
    sleep 1
done
echo -e "\n${GREEN}✓${NC} PostgreSQL is ready"

# Wait for ClickHouse to be ready
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
# run the end-to-end open-core stack: backend without nanosiem-enterprise
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

# Cargo features. The edition flag controls whether nanosiem-enterprise is
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

cargo build -p nanosiem-api -p nanosiem-search $BUILD_MODE $FEATURE_FLAG 2>&1 | tail -5
echo -e "${GREEN}✓${NC} Build complete"

# Apply ClickHouse migrations before starting services.
# nanosiem-api refuses to start if any migration in clickhouse/ is unapplied
# (see nanosiem-api/src/state/constructors.rs). The migrator is idempotent —
# already-applied migrations are skipped.
echo -e "\n${YELLOW}Applying ClickHouse migrations...${NC}"
DATABASE_URL="$DATABASE_URL" \
CLICKHOUSE_URL="$CLICKHOUSE_URL" \
CLICKHOUSE_DATABASE="$CLICKHOUSE_DATABASE" \
CLICKHOUSE_USER="$CLICKHOUSE_USER" \
CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD" \
CLICKHOUSE_ADMIN_USER="${CLICKHOUSE_ADMIN_USER:-nanosiem_admin}" \
CLICKHOUSE_ADMIN_PASSWORD="${CLICKHOUSE_ADMIN_PASSWORD:-nanosiem_admin_secret}" \
RUST_LOG="${RUST_LOG:-info}" \
./target/$TARGET_DIR/clickhouse_migrator 2>&1 | tee "$LOG_DIR/migrator.log"
# tee swallows the migrator's exit code; recover it via PIPESTATUS so set -e fires.
[ ${PIPESTATUS[0]} -eq 0 ] || { echo -e "${RED}✗${NC} ClickHouse migrations failed (see $LOG_DIR/migrator.log)"; exit 1; }
echo -e "${GREEN}✓${NC} ClickHouse migrations up to date"

# Start Search Service
echo -e "\n${YELLOW}Starting Search Service on port 3002...${NC}"
DATABASE_URL="$DATABASE_URL" \
CLICKHOUSE_URL="$CLICKHOUSE_URL" \
CLICKHOUSE_DATABASE="$CLICKHOUSE_DATABASE" \
CLICKHOUSE_USER="$CLICKHOUSE_USER" \
CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD" \
JWT_SECRET="$JWT_SECRET" \
AUTH_ENABLED="$AUTH_ENABLED" \
NANOSIEM_ENCRYPTION_KEY="$NANOSIEM_ENCRYPTION_KEY" \
NANOSIEM_DEV_MODE="$NANOSIEM_DEV_MODE" \
CORS_ORIGINS="$CORS_ORIGINS" \
REDIS_URL="${REDIS_URL:-redis://localhost:6379}" \
RUST_LOG=info \
./target/$TARGET_DIR/nanosiem-search 2>&1 | tee "$LOG_DIR/search.log" &
SEARCH_PID=$!
echo -e "${GREEN}✓${NC} Search Service started (PID: $SEARCH_PID)"

# Start Jobs Service (background tasks: detection, enrichment, tuning, cleanup)
echo -e "\n${YELLOW}Starting Jobs Service on port 3003...${NC}"
DATABASE_URL="$DATABASE_URL" \
CLICKHOUSE_URL="$CLICKHOUSE_URL" \
CLICKHOUSE_DATABASE="$CLICKHOUSE_DATABASE" \
CLICKHOUSE_USER="$CLICKHOUSE_USER" \
CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD" \
JWT_SECRET="$JWT_SECRET" \
AUTH_ENABLED="$AUTH_ENABLED" \
NANOSIEM_ENCRYPTION_KEY="$NANOSIEM_ENCRYPTION_KEY" \
NANOSIEM_DEV_MODE="$NANOSIEM_DEV_MODE" \
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
NANO_TIER="$NANO_TIER" \
JOBS_PORT=3003 \
LEADER_ELECTION_ENABLED=true \
RUST_LOG="${RUST_LOG:-info}" \
./target/$TARGET_DIR/nanosiem-jobs 2>&1 | tee "$LOG_DIR/jobs.log" &
JOBS_PID=$!
echo -e "${GREEN}✓${NC} Jobs Service started (PID: $JOBS_PID)"

# Start Main API
echo -e "${YELLOW}Starting Main API on port 3000...${NC}"
DATABASE_URL="$DATABASE_URL" \
CLICKHOUSE_URL="$CLICKHOUSE_URL" \
CLICKHOUSE_DATABASE="$CLICKHOUSE_DATABASE" \
CLICKHOUSE_USER="$CLICKHOUSE_USER" \
CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD" \
JWT_SECRET="$JWT_SECRET" \
AUTH_ENABLED="$AUTH_ENABLED" \
NANOSIEM_ENCRYPTION_KEY="$NANOSIEM_ENCRYPTION_KEY" \
NANOSIEM_DEV_MODE="$NANOSIEM_DEV_MODE" \
CLICKHOUSE_ADMIN_USER="${CLICKHOUSE_ADMIN_USER:-nanosiem_admin}" \
CLICKHOUSE_ADMIN_PASSWORD="${CLICKHOUSE_ADMIN_PASSWORD:-nanosiem_admin_secret}" \
CORS_ORIGINS="$CORS_ORIGINS" \
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
DOCS_RAG_URL="$DOCS_RAG_URL" \
DOCS_RAG_TOKEN="$DOCS_RAG_TOKEN" \
DISK_PRESSURE_CHECK_INTERVAL_SECS="$DISK_PRESSURE_CHECK_INTERVAL_SECS" \
DISK_PRESSURE_HIGH_WATERMARK="$DISK_PRESSURE_HIGH_WATERMARK" \
DISK_PRESSURE_LOW_WATERMARK="$DISK_PRESSURE_LOW_WATERMARK" \
DISK_PRESSURE_CRITICAL_THRESHOLD="$DISK_PRESSURE_CRITICAL_THRESHOLD" \
DISK_PRESSURE_EMERGENCY_THRESHOLD="$DISK_PRESSURE_EMERGENCY_THRESHOLD" \
DISK_PRESSURE_PAUSE_INGESTION="$DISK_PRESSURE_PAUSE_INGESTION" \
DEPLOYMENT_MODE="$DEPLOYMENT_MODE" \
NANO_TIER="$NANO_TIER" \
SKIP_VECTOR_VALIDATION="${SKIP_VECTOR_VALIDATION:-false}" \
VECTOR_INGEST_URL="${VECTOR_INGEST_URL:-http://localhost:8080/}" \
VECTOR_AUTH_TOKEN="${VECTOR_AUTH_TOKEN:-nanosiem-default-token}" \
RUST_LOG="${RUST_LOG:-nanosiem_core::melod=debug,info}" \
./target/$TARGET_DIR/nanosiem-api 2>&1 | tee "$LOG_DIR/api.log" &
API_PID=$!
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

if check_service "Jobs Service" "http://localhost:3003/health" 60; then
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
# `EXPOSE_LAN=1` binds Vite to 0.0.0.0 so other devices on the LAN can hit
# http://<your-ip>:5173 (Rust services already bind to 0.0.0.0). Off by default
# to keep the dev server localhost-only.
echo -e "\n${YELLOW}Starting Frontend on port 5173 (edition: ${EDITION})...${NC}"
cd nanosiem-web
VITE_HOST_FLAG=""
if [ "${EXPOSE_LAN:-0}" = "1" ]; then
    VITE_HOST_FLAG="-- --host"
    echo -e "${YELLOW}⚠️  EXPOSE_LAN=1 — Vite binding to 0.0.0.0${NC}"
fi
VITE_EDITION="$EDITION" npm run dev $VITE_HOST_FLAG > "../$LOG_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!
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
echo "  Jobs Service:   http://localhost:3003 (background tasks)"
echo "  Search Service: http://localhost:3002"
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
echo "  Frontend:       $LOG_DIR/frontend.log"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop all services${NC}"
echo ""
echo -e "${BLUE}Process IDs:${NC}"
echo "  Main API:       $API_PID"
echo "  Jobs Service:   $JOBS_PID"
echo "  Search Service: $SEARCH_PID"
echo "  Frontend:       $FRONTEND_PID"
echo ""

# Keep the script running and wait for signals
# Using wait without arguments waits for all background jobs
wait
