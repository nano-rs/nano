#!/usr/bin/env bash
#
# NanoSIEM Benchmark Runner
#
# Orchestrates ingestion, search, and concurrent analyst benchmarks.
# Collects results and prints a unified summary.
#
# Usage:
#   ./benchmarks/run-benchmark.sh [OPTIONS]
#
# Options:
#   --all              Run all benchmarks (default)
#   --ingest           Run ingestion benchmark only
#   --search           Run search benchmark only
#   --concurrent       Run concurrent analyst benchmark only
#   --blast            Use log-blaster for ingestion (requires cargo)
#   --blast-eps NUM    Target EPS for blast mode (default: 10000)
#   --blast-duration M Duration in minutes for blast mode (default: 2)
#   --time-range RANGE Search time range: 1h, 24h, 7d, 30d (default: 24h)
#   --analysts NUM     Number of simulated analysts (default: 5)
#   --vector-url URL   Vector HTTP endpoint (default: http://localhost:8080)
#   --search-url URL   Search service URL (default: http://localhost:3002)
#   --api-key KEY      API key for search auth
#   --jwt-token TOKEN  JWT token for search auth
#   --help             Show this help message

set -euo pipefail

# Defaults
RUN_INGEST=false
RUN_SEARCH=false
RUN_CONCURRENT=false
USE_BLAST=false
BLAST_EPS=10000
BLAST_DURATION=2
TIME_RANGE="24h"
ANALYSTS=5
VECTOR_URL="http://localhost:8080"
SEARCH_URL="http://localhost:3002"
API_KEY="${API_KEY:-}"
JWT_TOKEN="${JWT_TOKEN:-}"
VECTOR_AUTH_TOKEN="${VECTOR_AUTH_TOKEN:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --all)           RUN_INGEST=true; RUN_SEARCH=true; RUN_CONCURRENT=true; shift ;;
    --ingest)        RUN_INGEST=true; shift ;;
    --search)        RUN_SEARCH=true; shift ;;
    --concurrent)    RUN_CONCURRENT=true; shift ;;
    --blast)         USE_BLAST=true; shift ;;
    --blast-eps)     BLAST_EPS="$2"; shift 2 ;;
    --blast-duration) BLAST_DURATION="$2"; shift 2 ;;
    --time-range)    TIME_RANGE="$2"; shift 2 ;;
    --analysts)      ANALYSTS="$2"; shift 2 ;;
    --vector-url)    VECTOR_URL="$2"; shift 2 ;;
    --search-url)    SEARCH_URL="$2"; shift 2 ;;
    --api-key)       API_KEY="$2"; shift 2 ;;
    --jwt-token)     JWT_TOKEN="$2"; shift 2 ;;
    --help)
      head -25 "$0" | tail -22
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Default to --all if nothing specified
if ! $RUN_INGEST && ! $RUN_SEARCH && ! $RUN_CONCURRENT; then
  RUN_INGEST=true
  RUN_SEARCH=true
  RUN_CONCURRENT=true
fi

# Check prerequisites
check_command() {
  if ! command -v "$1" &>/dev/null; then
    echo "ERROR: $1 is required but not found. Install it first."
    echo "  k6: https://k6.io/docs/get-started/installation/"
    echo "  cargo: https://rustup.rs/"
    exit 1
  fi
}

check_command k6
if $USE_BLAST; then
  check_command cargo
fi

# Validate auth for search benchmarks
if ($RUN_SEARCH || $RUN_CONCURRENT) && [[ -z "$API_KEY" && -z "$JWT_TOKEN" ]]; then
  echo "WARNING: No API_KEY or JWT_TOKEN set. Search benchmarks will likely fail."
  echo "  Set via: --api-key <key> or --jwt-token <token> or API_KEY env var"
  echo ""
fi

mkdir -p "$RESULTS_DIR"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║            NanoSIEM Benchmark Suite                          ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Vector URL:    ${VECTOR_URL}"
echo "║  Search URL:    ${SEARCH_URL}"
echo "║  Time Range:    ${TIME_RANGE}"
echo "║  Analysts:      ${ANALYSTS}"
echo "║  Benchmarks:    $(echo "$RUN_INGEST $RUN_SEARCH $RUN_CONCURRENT" | sed 's/true/yes/g; s/false/no/g' | awk '{print "ingest="$1" search="$2" concurrent="$3}')"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Ingestion Benchmark ───────────────────────────────────────────

if $RUN_INGEST; then
  echo "━━━ Ingestion Benchmark ━━━"

  if $USE_BLAST; then
    echo "Using log-blaster (blast mode, ${BLAST_EPS} EPS, ${BLAST_DURATION}m)"
    BLAST_ARGS="--vector ${VECTOR_URL} --blast --eps ${BLAST_EPS} --duration ${BLAST_DURATION} --quiet"
    if [[ -n "$VECTOR_AUTH_TOKEN" ]]; then
      BLAST_ARGS="${BLAST_ARGS} --token ${VECTOR_AUTH_TOKEN}"
    fi

    cd "${SCRIPT_DIR}/.."
    cargo run --release -p log-blaster -- $BLAST_ARGS 2>&1 | tee "${RESULTS_DIR}/blast.log"
    cd "$SCRIPT_DIR"

    echo ""
    echo "log-blaster results saved to ${RESULTS_DIR}/blast.log"
  else
    echo "Using k6 (ramping VUs, ~2 min)"
    VECTOR_URL="$VECTOR_URL" \
    VECTOR_AUTH_TOKEN="$VECTOR_AUTH_TOKEN" \
    BATCH_SIZE=100 \
      k6 run "${SCRIPT_DIR}/k6/ingestion.js" 2>&1
  fi

  echo ""
fi

# ─── Search Benchmark ──────────────────────────────────────────────

if $RUN_SEARCH; then
  echo "━━━ Search Benchmark ━━━"
  echo "Time range: ${TIME_RANGE}, 3 VUs, 90s"

  SEARCH_URL="$SEARCH_URL" \
  API_KEY="$API_KEY" \
  JWT_TOKEN="$JWT_TOKEN" \
  TIME_RANGE="$TIME_RANGE" \
    k6 run "${SCRIPT_DIR}/k6/search.js" 2>&1

  echo ""
fi

# ─── Concurrent Analyst Benchmark ──────────────────────────────────

if $RUN_CONCURRENT; then
  echo "━━━ Concurrent Analyst Benchmark ━━━"
  echo "${ANALYSTS} analysts, 120s"

  SEARCH_URL="$SEARCH_URL" \
  API_URL="${VECTOR_URL%:*}:3000" \
  API_KEY="$API_KEY" \
  JWT_TOKEN="$JWT_TOKEN" \
  ANALYSTS="$ANALYSTS" \
    k6 run "${SCRIPT_DIR}/k6/concurrent.js" 2>&1

  echo ""
fi

# ─── ClickHouse System Metrics (if available) ──────────────────────

echo "━━━ ClickHouse Query Stats ━━━"
CLICKHOUSE_URL="${CLICKHOUSE_URL:-http://localhost:8123}"
CLICKHOUSE_USER="${CLICKHOUSE_USER:-default}"
CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"

CH_QUERY="SELECT
  count() as total_queries,
  round(avg(query_duration_ms)) as avg_duration_ms,
  quantile(0.95)(query_duration_ms) as p95_duration_ms,
  quantile(0.99)(query_duration_ms) as p99_duration_ms,
  round(avg(read_rows)) as avg_rows_read,
  formatReadableSize(avg(read_bytes)) as avg_data_read,
  formatReadableSize(avg(memory_usage)) as avg_memory
FROM system.query_log
WHERE event_time >= now() - INTERVAL 10 MINUTE
  AND type = 'QueryFinish'
  AND query_kind = 'Select'
  AND databases = ['nanosiem']
FORMAT PrettyCompact"

if curl -sf "${CLICKHOUSE_URL}/ping" &>/dev/null; then
  curl -sf "${CLICKHOUSE_URL}" \
    --user "${CLICKHOUSE_USER}:${CLICKHOUSE_PASSWORD}" \
    --data-binary "$CH_QUERY" 2>/dev/null || echo "(Could not query ClickHouse system.query_log)"
else
  echo "(ClickHouse not reachable at ${CLICKHOUSE_URL} - skipping system metrics)"
fi

echo ""

# ─── Storage Stats (if ClickHouse available) ───────────────────────

echo "━━━ Storage Stats ━━━"
STORAGE_QUERY="SELECT
  formatReadableSize(sum(bytes_on_disk)) as total_disk,
  formatReadableSize(sum(data_uncompressed_bytes)) as total_uncompressed,
  round(sum(data_uncompressed_bytes) / sum(bytes_on_disk), 2) as compression_ratio,
  sum(rows) as total_rows
FROM system.parts
WHERE database = 'nanosiem' AND active
FORMAT PrettyCompact"

if curl -sf "${CLICKHOUSE_URL}/ping" &>/dev/null; then
  curl -sf "${CLICKHOUSE_URL}" \
    --user "${CLICKHOUSE_USER}:${CLICKHOUSE_PASSWORD}" \
    --data-binary "$STORAGE_QUERY" 2>/dev/null || echo "(Could not query storage stats)"
else
  echo "(ClickHouse not reachable - skipping storage stats)"
fi

echo ""
echo "━━━ Results saved to ${RESULTS_DIR}/ ━━━"
echo "Done."
