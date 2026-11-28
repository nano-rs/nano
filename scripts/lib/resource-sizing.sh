#!/usr/bin/env bash
# NAN-4997: deterministic host resource sizing for compose installs.
#
# This is the single source of sizing arithmetic for the open-core single-node
# installer and the enterprise role inventory renderer. It deliberately uses
# Bash 3-compatible constructs: macOS ships Bash 3.2, and open-core must not
# gain a Python dependency merely to size a host.
# shellcheck disable=SC2034 # values are consumed through validated indirect expansion
set -euo pipefail

format="env"
topology=single
roles=app,ingest,clickhouse,postgres
cpu_cores=""
memory_mib=""
shards=1
vector_data_capacity_bytes=""
vector_data_free_bytes=""
override_env=""
server_output=""
users_output=""
cli_overrides=""
planned_gb_per_day=""
ingest_path=""
avg_event_bytes=""
vector_sources=""
edition=open
app_hosts=1
postgres_mib=""
postgres_shared_mib=""
operator_env=""
pg_pool_plan_only=""

# NAN-5345: planned-volume tiers. Large-deployment settings apply only when
# the operator declares a planned daily volume that needs them; an install
# without one keeps the host-only sizing below. Host size still caps every
# number. Boundaries sit between the Helm presets' nominal volumes (100 GB,
# 1 TB, 10 TB/day): at or above LARGE the ~1 TB/day tier applies, at or above
# XLARGE the >=10 TB/day tier.
PLANNED_TIER_LARGE_MIN_GB_PER_DAY=300
PLANNED_TIER_XLARGE_MIN_GB_PER_DAY=3000
# Vector CPU from the planned event rate (NAN-5372): parse cost is mostly per
# event, so vCPU = peak factor x events/s / events per core, with events/s =
# GB/day x 1e9 / 86400 / average event size. Raw: re-measured 2026-11-13 on
# nano Vector 0.61.0-nano.11 with the 16 shipped OCSF parsers (after the
# credential precheck, raw-text redaction and parsers#67): 1,950-6,500
# events/s per core; 1,900 is just under the slowest realistic parsers (Okta
# 1,950 at ~1.1 KB, Palo Alto 2,527 at ~280 B). Pre-shaped OCSF (Tenzir/Cribl
# door): ship-only Vector does 90-120k events/s per core; planned at half of
# that for bursts. The average event size defaults to 1,000 B (mixed feeds);
# ~300 B for firewall/flow, ~2,000 B for EDR. At the default that is ~13 vCPU
# per TB/day raw. The Helm chart (sizing.*) and the nano-deploy skill's size.py
# carry the same constants; a test keeps them equal.
VECTOR_PEAK_FACTOR=2
VECTOR_RAW_EVENTS_PER_CORE=1900
VECTOR_PRESHAPED_EVENTS_PER_CORE=45000
DEFAULT_AVG_EVENT_BYTES=1000
# NAN-5193: Vector holds about 1 GiB at 16 deployed sources. Every size gets
# at least that (when the host has room above the other roles' floors), plus
# an allowance per source beyond 16 when the operator declares more.
VECTOR_BASE_MEMORY_MIB=1024
VECTOR_BASE_SOURCES=16
VECTOR_MIB_PER_EXTRA_SOURCE=64
# Raw parsing at >=1 TB/day: readers run 8-12 GiB (2 GiB OOM-looped).
VECTOR_LARGE_TIER_MEMORY_MIB=8192
# NAN-5433: the enterprise Evidence Pack runs inside nano-api and refuses to
# start without enough free memory under the API's limit (about 2x a pack's
# measured peak: 166 MiB for 30 days, 232 MiB for 365, over an idle API of
# about 210 MiB). The proportional split gave a 10 GiB host 449 MiB, so on an
# enterprise install the API gets at least this much where co-located
# PostgreSQL (above 512 MiB) or ClickHouse (above its floor) can fund it.
# Open-core installs have no Evidence Pack and keep the proportional split.
ENTERPRISE_API_MIN_MIB=1024
# NAN-5506: nano-api idles at about 210 MiB, so the old 160 MiB service floor
# (a 4 GiB single node) left it restart-looping with no hint why. Open core's
# API gets at least this much, funded like the enterprise floor; a host that
# cannot fund the floor for its edition is refused with the RAM shortfall
# instead of rendering a limit nano-api cannot boot in.
OPEN_API_MIN_MIB=384
# NAN-5506: the enterprise refusal point. ENTERPRISE_API_MIN_MIB stays the
# funded target, but a host that ends a few MiB under it (12 GiB + monitoring:
# 1022 MiB, ClickHouse held at its 6 GiB feed floor) still runs a pack. The pack
# needs a busy API (~300 MiB) plus a 400-day pack's headroom (~239 MiB); below
# this it cannot run, so the host is refused rather than sized.
ENTERPRISE_API_REFUSE_MIB=640
# NAN-5822: the most the PostgreSQL pool floor may take back from an enterprise
# API above its funded target, as its last source (enterprise + monitoring on
# 8-12.6 GiB, where ClickHouse is at its floor). 768 MiB still leaves a busy
# API (~300 MiB) more than the 400-day pack's ~239 MiB of headroom, while
# pools below their floors would starve nano-jobs' advisory-lock connections.
PG_FLOOR_API_FLOOR_MIB=768
# NAN-5668 / NAN-5746: nano-jobs runs every leader scheduler (content channels,
# the MITRE catalog, repository syncs, enrichment, retention) and every
# scheduled detection rule. The proportional 15% app share gave an 8 GB single
# node 214 MiB (155 MiB with monitoring), OOM-looping on the 53 MB MITRE
# ATT&CK catalog until NAN-5668 added a 384 MiB floor. During v2.0.34 RC2
# validation on a 4 vCPU / 8 GB single-node box, a 400k-event Sysmon flood
# peaked at 356 MiB under that 384 MiB cap (28 MiB headroom). Raising the floor
# to 512 MiB matches the Compose fallback and Helm request, gives 156 MiB
# (30.5%) of headroom over the flood peak, and is funded from co-located
# PostgreSQL / ClickHouse headroom without raising host minimums.
JOBS_MIN_MIB=512
# NAN-5506: a nano-api CPU limit below a quarter core starves its start-up
# (migration checks, cache warm-up) past the health-check window. Funded from
# a co-located ClickHouse share above its 500m floor, then PostgreSQL above
# 250m; a host that cannot fund it is refused.
API_MIN_MCPU=250

fail() {
    printf 'resource sizing error: %s\n' "$*" >&2
    exit 2
}

# NAN-5822: PostgreSQL connection pools sized from the PostgreSQL memory budget.
#
# A warm PostgreSQL backend keeps 9-19 MiB of private memory (catalog and plan
# caches; pools keep idle backends for PG_IDLE_TIMEOUT, 600 s) on top of
# shared_buffers. Measured on an e2e stack: 45 backends plus 128 MiB
# shared_buffers filled a 512 MiB cgroup and the kernel OOM-killed a backend,
# which resets every session. So every backend that can exist is budgeted at
# PG_BACKEND_MIB (a third over the measured 9 MiB average):
#   - PG_SERVER_PROCESSES: postmaster, checkpointer, background writer, WAL
#     writer, autovacuum launcher and its 3 workers, logical replication
#     launcher;
#   - PG_OPERATOR_SLOTS: the migrator, psql, backups;
#   - per app host, PG_APP_DEDICATED_SESSIONS outside the pools (backup
#     mutation fence, two case_changes listeners, three license watchers,
#     leader election) and the four pools: nano-jobs, nano-api, nano-search,
#     connector-runner.
# nano-jobs gets the largest pool: it pins pooled connections for session
# advisory locks across long ClickHouse and network I/O (MITRE sync, install
# leases, usage report, ingestion pause, rule runtime locks; up to ~5 at
# once) while 10 concurrent detection rules and the leader schedulers query
# alongside them, so its floor of 10 keeps at least 5 free under that load.
# nano-api serves short request queries (floor 8), nano-search reads settings
# and saved searches (floor 6). Above the floors the surplus goes 2:2:1 to
# jobs:api:search, each capped at the historical 20.
PG_BACKEND_MIB=12
PG_SERVER_PROCESSES=9
PG_OPERATOR_SLOTS=3
PG_APP_DEDICATED_SESSIONS=7
PG_CONNECTOR_POOL=4
PG_JOBS_POOL_MIN=10
PG_API_POOL_MIN=8
PG_SEARCH_POOL_MIN=6
PG_POOL_MAX=20

# shared_buffers for a PostgreSQL budget (MiB).
pg_shared_buffers_mib() {
    local shared=$(( $1 / 4 ))
    (( shared < 128 )) && shared=128
    (( shared > 32768 )) && shared=32768
    printf '%s\n' "$shared"
}

# Backends a PostgreSQL budget (MiB) holds after shared_buffers ($2 MiB when
# given, else the sized quarter of the budget).
pg_backend_capacity() {
    local shared="${2:-}"
    [[ -n "$shared" ]] || shared=$(pg_shared_buffers_mib "$1")
    local capacity=$(( ($1 - shared) / PG_BACKEND_MIB ))
    (( capacity < 0 )) && capacity=0
    printf '%s\n' "$capacity"
}

# Smallest PostgreSQL budget (MiB) whose floors fit APP_HOSTS app hosts.
pg_budget_floor_mib() {
    local app_hosts="$1" per_host need mib
    per_host=$(( PG_APP_DEDICATED_SESSIONS + PG_CONNECTOR_POOL + PG_JOBS_POOL_MIN + PG_API_POOL_MIN + PG_SEARCH_POOL_MIN ))
    need=$(( (PG_SERVER_PROCESSES + PG_OPERATOR_SLOTS + app_hosts * per_host) * PG_BACKEND_MIB ))
    mib=$(( (need * 4 + 2) / 3 ))
    (( mib / 4 < 128 )) && mib=$(( need + 128 ))
    while (( $(pg_backend_capacity "$mib") * PG_BACKEND_MIB < need )); do mib=$(( mib + 1 )); done
    printf '%s\n' "$mib"
}

# Pools for PG_MIB of PostgreSQL shared by APP_HOSTS app hosts (optional
# SHARED_MIB: an explicit shared_buffers). Sets
# pg_plan_jobs/api/search/connector, pg_plan_min (PG_MIN_CONNECTIONS),
# pg_plan_capacity (backends the budget holds) and pg_plan_underfunded (1 when
# the budget is below pg_budget_floor_mib and the pools were shrunk to fit).
pg_pool_plan() {
    local pg_mib="$1" app_hosts="$2" per_host surplus
    pg_plan_capacity=$(pg_backend_capacity "$pg_mib" "${3:-}")
    per_host=$(( (pg_plan_capacity - PG_SERVER_PROCESSES - PG_OPERATOR_SLOTS) / app_hosts - PG_APP_DEDICATED_SESSIONS ))
    pg_plan_connector=$PG_CONNECTOR_POOL
    per_host=$(( per_host - pg_plan_connector ))
    pg_plan_underfunded=0
    if (( per_host >= PG_JOBS_POOL_MIN + PG_API_POOL_MIN + PG_SEARCH_POOL_MIN )); then
        surplus=$(( per_host - PG_JOBS_POOL_MIN - PG_API_POOL_MIN - PG_SEARCH_POOL_MIN ))
        pg_plan_jobs=$(( PG_JOBS_POOL_MIN + surplus * 2 / 5 ))
        pg_plan_api=$(( PG_API_POOL_MIN + surplus * 2 / 5 ))
        (( pg_plan_jobs > PG_POOL_MAX )) && pg_plan_jobs=$PG_POOL_MAX
        (( pg_plan_api > PG_POOL_MAX )) && pg_plan_api=$PG_POOL_MAX
        pg_plan_search=$(( per_host - pg_plan_jobs - pg_plan_api ))
        (( pg_plan_search > PG_POOL_MAX )) && pg_plan_search=$PG_POOL_MAX
    else
        # Below the floor (an existing small install, an operator's smaller
        # POSTGRES_MEM_LIMIT): shrink the pools in the floor ratio so the
        # backends still fit, and say so.
        pg_plan_underfunded=1
        (( per_host < 4 )) && per_host=4
        # One feed run plus the runner's two bookkeeping connections.
        pg_plan_connector=3
        per_host=$(( per_host + PG_CONNECTOR_POOL - pg_plan_connector ))
        pg_plan_jobs=$(( per_host * PG_JOBS_POOL_MIN / (PG_JOBS_POOL_MIN + PG_API_POOL_MIN + PG_SEARCH_POOL_MIN) ))
        pg_plan_api=$(( per_host * PG_API_POOL_MIN / (PG_JOBS_POOL_MIN + PG_API_POOL_MIN + PG_SEARCH_POOL_MIN) ))
        (( pg_plan_jobs < 2 )) && pg_plan_jobs=2
        (( pg_plan_api < 1 )) && pg_plan_api=1
        pg_plan_search=$(( per_host - pg_plan_jobs - pg_plan_api ))
        (( pg_plan_search < 1 )) && pg_plan_search=1
    fi
    pg_plan_min=2
    (( pg_plan_search <= 8 )) && pg_plan_min=1
    return 0
}

usage() {
    cat <<'EOF'
Usage: resource-sizing.sh [options]
  --topology single|role
  --roles app,ingest,clickhouse,keeper,postgres,tenzir,monitoring
  --cpu CORES                  Override detected logical CPUs (tests/inventory)
  --memory-mib MIB             Override detected RAM (tests/inventory)
  --shards COUNT               ClickHouse shard count (for per-shard buffers)
  --vector-data-capacity-bytes BYTES
                               Filesystem capacity backing VECTOR_DATA_DIR
  --vector-data-free-bytes BYTES
                               Free space on that filesystem now (NAN-5446;
                               probed with the capacity when that is probed)
  --override-env PATH          Apply sizing keys from an operator .env
  --override KEY=VALUE         Apply an inventory override (repeatable)
  --server-output PATH         Write the ClickHouse server override XML
  --users-output PATH          Write the ClickHouse profile override XML
  --format env                 Emit stable KEY=VALUE lines (default)
  --planned-gb-per-day GB      Planned daily volume (NANO_PLANNED_GB_PER_DAY);
                               unset or 0 keeps host-only sizing (NAN-5345)
  --ingest-path raw|preshaped  How events arrive (NANO_INGEST_PATH): raw logs
                               parsed by nano's Vector (default) or pre-shaped
                               OCSF (Tenzir/Cribl; default with --roles tenzir)
  --avg-event-bytes BYTES      Average event size (NANO_AVG_EVENT_BYTES, default
                               1000): ~300 firewall/flow, ~2000 EDR. Turns the
                               planned volume into events/s for Vector CPU
  --vector-sources COUNT       Planned deployed log sources (NANO_VECTOR_SOURCES,
                               default 16) for Vector's memory allowance
  (NAN-5636: NANO_CLICKHOUSE_DATA_CAPACITY_BYTES / NANO_CLICKHOUSE_DATA_FREE_BYTES
   give the ClickHouse data filesystem for the spill caps when it is not the
   Docker root filesystem the probes measure.)
  --edition open|enterprise    Install edition (default open). Enterprise gives
                               the API at least 1 GiB for the Evidence Pack
                               where co-located roles can fund it (NAN-5433)
  --operator-env PATH          Apply only the operator lines of an install .env
                               (outside its NANO AUTO SIZING block) as overrides
  --app-hosts COUNT            Hosts running the app role against this
                               PostgreSQL (default 1; NAN-5822)
  --postgres-mib MIB           PostgreSQL budget of the remote PostgreSQL an
                               app-only host connects to; sizes its pools
                               (NAN-5822). Unset keeps 20-wide pools. With the
                               postgres role too (HA), the app pools fit the
                               smaller of the two
  --postgres-shared-mib MIB    That PostgreSQL's shared_buffers (default: a
                               quarter of --postgres-mib)
  --pg-pool-plan MIB           Print only the PostgreSQL settings and pools a
                               PostgreSQL budget of MIB holds, then exit
                               (Compose defaults, Helm values, e2e)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --topology) [[ $# -ge 2 ]] || fail "--topology needs a value"; topology="$2"; shift 2 ;;
        --roles) [[ $# -ge 2 ]] || fail "--roles needs a value"; roles="$2"; shift 2 ;;
        --cpu) [[ $# -ge 2 ]] || fail "--cpu needs a value"; cpu_cores="$2"; shift 2 ;;
        --memory-mib) [[ $# -ge 2 ]] || fail "--memory-mib needs a value"; memory_mib="$2"; shift 2 ;;
        --shards) [[ $# -ge 2 ]] || fail "--shards needs a value"; shards="$2"; shift 2 ;;
        --vector-data-capacity-bytes)
            [[ $# -ge 2 ]] || fail "--vector-data-capacity-bytes needs a value"
            vector_data_capacity_bytes="$2"
            shift 2 ;;
        --vector-data-free-bytes)
            [[ $# -ge 2 ]] || fail "--vector-data-free-bytes needs a value"
            vector_data_free_bytes="$2"
            shift 2 ;;
        --override-env) [[ $# -ge 2 ]] || fail "--override-env needs a path"; override_env="$2"; shift 2 ;;
        --operator-env) [[ $# -ge 2 ]] || fail "--operator-env needs a path"; operator_env="$2"; shift 2 ;;
        --override)
            [[ $# -ge 2 && "$2" == *=* ]] || fail "--override needs KEY=VALUE"
            cli_overrides="${cli_overrides}${cli_overrides:+
}$2"
            shift 2 ;;
        --server-output) [[ $# -ge 2 ]] || fail "--server-output needs a path"; server_output="$2"; shift 2 ;;
        --users-output) [[ $# -ge 2 ]] || fail "--users-output needs a path"; users_output="$2"; shift 2 ;;
        --format) [[ $# -ge 2 ]] || fail "--format needs a value"; format="$2"; shift 2 ;;
        --planned-gb-per-day)
            [[ $# -ge 2 ]] || fail "--planned-gb-per-day needs a value"
            planned_gb_per_day="$2"; shift 2 ;;
        --ingest-path) [[ $# -ge 2 ]] || fail "--ingest-path needs a value"; ingest_path="$2"; shift 2 ;;
        --avg-event-bytes)
            [[ $# -ge 2 ]] || fail "--avg-event-bytes needs a value"
            avg_event_bytes="$2"; shift 2 ;;
        --vector-sources) [[ $# -ge 2 ]] || fail "--vector-sources needs a value"; vector_sources="$2"; shift 2 ;;
        --edition) [[ $# -ge 2 ]] || fail "--edition needs a value"; edition="$2"; shift 2 ;;
        --app-hosts) [[ $# -ge 2 ]] || fail "--app-hosts needs a value"; app_hosts="$2"; shift 2 ;;
        --postgres-mib) [[ $# -ge 2 ]] || fail "--postgres-mib needs a value"; postgres_mib="$2"; shift 2 ;;
        --postgres-shared-mib) [[ $# -ge 2 ]] || fail "--postgres-shared-mib needs a value"; postgres_shared_mib="$2"; shift 2 ;;
        --pg-pool-plan) [[ $# -ge 2 ]] || fail "--pg-pool-plan needs a value"; pg_pool_plan_only="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown option $1" ;;
    esac
done

[[ "$topology" == single || "$topology" == role ]] || fail "--topology must be single or role"
[[ "$format" == env ]] || fail "only --format env is supported"
[[ "$edition" == open || "$edition" == enterprise ]] || fail "--edition must be open or enterprise"
[[ "$shards" =~ ^[1-9][0-9]*$ ]] || fail "--shards must be a positive integer"
[[ "$app_hosts" =~ ^[1-9][0-9]*$ ]] || fail "--app-hosts must be a positive integer"
[[ -z "$postgres_mib" || "$postgres_mib" =~ ^[1-9][0-9]*$ ]] || fail "--postgres-mib must be a positive integer"
[[ -z "$postgres_shared_mib" || "$postgres_shared_mib" =~ ^[1-9][0-9]*$ ]] || fail "--postgres-shared-mib must be a positive integer"

# NAN-5822: the PostgreSQL settings for one budget, for every consumer that
# does not run the full host sizing (Compose defaults, Helm values, e2e).
if [[ -n "$pg_pool_plan_only" ]]; then
    [[ "$pg_pool_plan_only" =~ ^[1-9][0-9]*$ ]] || fail "--pg-pool-plan must be a positive integer"
    pg_pool_plan "$pg_pool_plan_only" "$app_hosts"
    plan_shared=$(pg_shared_buffers_mib "$pg_pool_plan_only")
    plan_connections=$(( pg_plan_capacity - PG_SERVER_PROCESSES ))
    (( plan_connections < 10 )) && plan_connections=10
    printf 'POSTGRES_MEM_LIMIT=%sM\n' "$pg_pool_plan_only"
    printf 'POSTGRES_MAX_CONNECTIONS=%s\n' "$plan_connections"
    printf 'POSTGRES_SHARED_BUFFERS=%sMB\n' "$plan_shared"
    printf 'POSTGRES_EFFECTIVE_CACHE_SIZE=%sMB\n' "$(( pg_pool_plan_only * 3 / 4 ))"
    plan_work=$(( (pg_pool_plan_only - plan_shared) / (plan_connections * 4) ))
    (( plan_work < 1 )) && plan_work=1
    (( plan_work > 64 )) && plan_work=64
    printf 'POSTGRES_WORK_MEM=%sMB\n' "$plan_work"
    printf 'PG_MAX_CONNECTIONS=%s\n' "$pg_plan_api"
    printf 'PG_MIN_CONNECTIONS=%s\n' "$pg_plan_min"
    printf 'NANO_API_PG_MAX_CONNECTIONS=%s\n' "$pg_plan_api"
    printf 'NANO_JOBS_PG_MAX_CONNECTIONS=%s\n' "$pg_plan_jobs"
    printf 'NANO_SEARCH_PG_MAX_CONNECTIONS=%s\n' "$pg_plan_search"
    printf 'NANO_CONNECTOR_PG_MAX_CONNECTIONS=%s\n' "$pg_plan_connector"
    printf 'NANO_PG_BUDGET_FLOOR_MIB=%s\n' "$(pg_budget_floor_mib "$app_hosts")"
    printf 'NANO_PG_UNDERFUNDED=%s\n' "$pg_plan_underfunded"
    exit 0
fi

# This file is the one source of truth for both the rendered graph inventory
# and Vector's exact per-buffer floor. Helm carries a mechanically synced copy.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
buffer_manifest="$script_dir/../../config/vector/disk-buffer-budget.env"
[[ -r "$buffer_manifest" ]] \
    || fail "Vector disk-buffer contract is missing: $buffer_manifest (release bundle is incomplete)"
while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
        VECTOR_DISK_BUFFER_MIN_BYTES=*|VECTOR_DISK_BUFFER_STATIC_COUNT=*|VECTOR_DISK_BUFFER_PIPELINE_SHARDED_COUNT=*|VECTOR_DISK_BUFFER_ENRICHMENT_SHARDED_COUNT=*)
            key=${line%%=*}; value=${line#*=}
            [[ "$value" =~ ^[1-9][0-9]*$ ]] || fail "invalid $key in $buffer_manifest"
            printf -v "$key" '%s' "$value"
            ;;
        ''|'#'*) ;;
        *) fail "unsupported line in Vector disk-buffer contract: $line" ;;
    esac
done < "$buffer_manifest"
for key in VECTOR_DISK_BUFFER_MIN_BYTES VECTOR_DISK_BUFFER_STATIC_COUNT VECTOR_DISK_BUFFER_PIPELINE_SHARDED_COUNT VECTOR_DISK_BUFFER_ENRICHMENT_SHARDED_COUNT; do
    [[ "${!key:-}" =~ ^[1-9][0-9]*$ ]] || fail "$buffer_manifest does not define $key"
done

detect_cpu() {
    local detected=""
    # Docker Desktop can expose fewer CPUs than the physical macOS/Windows
    # host. Prefer the daemon's usable capacity so generated cgroup limits fit
    # the machine that will actually run the stack.
    if command -v docker >/dev/null 2>&1; then
        detected=$(docker info --format '{{.NCPU}}' 2>/dev/null || true)
    fi
    if [[ ! "$detected" =~ ^[1-9][0-9]*$ ]] && command -v getconf >/dev/null 2>&1; then
        detected=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    fi
    if [[ ! "$detected" =~ ^[1-9][0-9]*$ ]] && command -v sysctl >/dev/null 2>&1; then
        detected=$(sysctl -n hw.logicalcpu 2>/dev/null || true)
    fi
    [[ "$detected" =~ ^[1-9][0-9]*$ ]] || detected=2
    printf '%s\n' "$detected"
}

detect_memory_mib() {
    local kb="" bytes=""
    if command -v docker >/dev/null 2>&1; then
        bytes=$(docker info --format '{{.MemTotal}}' 2>/dev/null || true)
    fi
    if [[ "$bytes" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s\n' "$(( (bytes + 524288) / 1048576 ))"
        return
    fi
    kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)
    if [[ "$kb" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s\n' "$(( (kb + 512) / 1024 ))"
        return
    fi
    if command -v sysctl >/dev/null 2>&1; then
        bytes=$(sysctl -n hw.memsize 2>/dev/null || true)
    fi
    if [[ "$bytes" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s\n' "$(( (bytes + 524288) / 1048576 ))"
        return
    fi
    # Historical safe fallback: enough to preserve the 2 GiB ClickHouse floor.
    printf '4096\n'
}

# Capacity (and free space) of the filesystem a fresh Docker named volume lands
# on, measured from inside the daemon with the digest-pinned image of compose
# service $1 (its images.lock repo prefix $2), mounted at $3. NAN-5636: also
# run with ClickHouse's own image on a ClickHouse host, so a host without
# Vector never pulls the Vector image just to measure its disk.
detect_docker_volume_capacity_bytes() {
    local service="$1" lock_prefix="$2" mount_path="$3"
    local docker_root="" capacity_kib="" free_kib="" probe_image="" locked_probe_image=""
    local compose_file="" images_lock=""
    command -v docker >/dev/null 2>&1 || return 1
    docker_root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)
    [[ -n "$docker_root" ]] || return 1

    # DockerRootDir belongs to the daemon, not necessarily this installer
    # namespace (Docker Desktop, DOCKER_HOST, rootless and remote daemons all
    # make a host-side df wrong). Resolve the already-required digest-pinned
    # Vector image from the shipped Compose file and cross-check it against the
    # release lock before execution. A fresh anonymous local volume is mounted
    # at Vector's real data path, so the daemon reports the named-volume
    # filesystem without exposing any existing Docker data. `--rm` removes the
    # anonymous volume with the throwaway container. The image contains
    # coreutils `df`; no mutable tag is used.
    compose_file="$script_dir/../../docker-compose.opensource.yml"
    [[ -r "$compose_file" ]] || return 1
    probe_image=$(awk -v svc="  $service:" '
        $0 == svc { in_svc = 1; next }
        in_svc && /^  [^ ]/ { exit }
        in_svc && /^[[:space:]]+image:[[:space:]]+/ {
            sub(/^[[:space:]]+image:[[:space:]]+/, "")
            print
            exit
        }
    ' "$compose_file")
    [[ "$probe_image" =~ @sha256:[0-9a-f]{64}$ ]] || return 1
    for images_lock in \
        "$script_dir/../../images.lock" \
        "$script_dir/../../images.enterprise.lock"; do
        [[ -r "$images_lock" ]] || continue
        locked_probe_image=$(awk -v prefix="$lock_prefix" '
            index($1, prefix) == 1 && $2 ~ /^sha256:[0-9a-f]+$/ {
                print $1 "@" $2
                exit
            }
        ' "$images_lock")
        [[ "$locked_probe_image" == "$probe_image" ]] && break
    done
    [[ "$locked_probe_image" == "$probe_image" ]] || return 1
    capacity_kib=$(docker run --rm \
        --network none \
        --read-only \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --mount "type=volume,dst=$mount_path" \
        --entrypoint /bin/df \
        "$probe_image" -Pk "$mount_path" 2>/dev/null \
        | awk 'NR == 2 { print $2, $4 }') || return 1
    # NAN-5446: df's Available column is the free space right now; the Vector
    # budget must fit what is free today, not only the install-time capacity.
    free_kib=${capacity_kib#* }
    capacity_kib=${capacity_kib%% *}
    [[ "$capacity_kib" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ "$free_kib" =~ ^[0-9]+$ ]] || free_kib=""
    if [[ -n "$free_kib" ]]; then
        printf '%s %s\n' "$(( capacity_kib * 1024 ))" "$(( free_kib * 1024 ))"
    else
        printf '%s\n' "$(( capacity_kib * 1024 ))"
    fi
}

[[ -n "$cpu_cores" ]] || cpu_cores="${NANO_SIZING_CPU_CORES:-}"
[[ -n "$memory_mib" ]] || memory_mib="${NANO_SIZING_MEMORY_MIB:-}"
[[ -n "$cpu_cores" ]] || cpu_cores=$(detect_cpu)
[[ -n "$memory_mib" ]] || memory_mib=$(detect_memory_mib)
[[ "$cpu_cores" =~ ^[1-9][0-9]*$ ]] || fail "CPU cores must be a positive integer"
[[ "$memory_mib" =~ ^[1-9][0-9]*$ ]] || fail "memory MiB must be a positive integer"
# A nominal 4 GiB VM reports roughly 3.8-3.9 GiB after firmware/kernel
# reservations. Accept that real-world range while rejecting smaller hosts.
(( memory_mib >= 3840 )) || fail "nano requires a host with at least 4 GiB RAM"

has_role() {
    case ",$roles," in
        *,$1,*) return 0 ;;
        *) return 1 ;;
    esac
}

for role in ${roles//,/ }; do
    case "$role" in
        app|ingest|clickhouse|keeper|postgres|tenzir|monitoring) ;;
        *) fail "unknown role $role" ;;
    esac
done

[[ -n "$planned_gb_per_day" ]] || planned_gb_per_day="${NANO_PLANNED_GB_PER_DAY:-}"
[[ -n "$planned_gb_per_day" ]] || planned_gb_per_day=0
[[ "$planned_gb_per_day" =~ ^[0-9]{1,7}$ ]] \
    || fail "planned volume must be a whole number of GB per day (0 or unset = not declared)"
planned_gb_per_day=$(( 10#$planned_gb_per_day ))
[[ -n "$ingest_path" ]] || ingest_path="${NANO_INGEST_PATH:-}"
if [[ -z "$ingest_path" ]]; then
    # The bundled Tenzir node is the pre-shaped OCSF door.
    if has_role tenzir; then ingest_path=preshaped; else ingest_path=raw; fi
fi
[[ "$ingest_path" == raw || "$ingest_path" == preshaped ]] \
    || fail "ingest path must be raw or preshaped"
[[ -n "$avg_event_bytes" ]] || avg_event_bytes="${NANO_AVG_EVENT_BYTES:-}"
[[ -n "$avg_event_bytes" ]] || avg_event_bytes=$DEFAULT_AVG_EVENT_BYTES
[[ "$avg_event_bytes" =~ ^[0-9]{2,6}$ ]] && (( 10#$avg_event_bytes >= 50 )) \
    || fail "average event size must be a whole number of bytes, 50-999999"
avg_event_bytes=$(( 10#$avg_event_bytes ))
[[ -n "$vector_sources" ]] || vector_sources="${NANO_VECTOR_SOURCES:-}"
[[ -n "$vector_sources" ]] || vector_sources=$VECTOR_BASE_SOURCES
[[ "$vector_sources" =~ ^[1-9][0-9]{0,4}$ ]] || fail "Vector source count must be a positive integer"
if (( planned_gb_per_day >= PLANNED_TIER_XLARGE_MIN_GB_PER_DAY )); then
    sizing_tier=xlarge
elif (( planned_gb_per_day >= PLANNED_TIER_LARGE_MIN_GB_PER_DAY )); then
    sizing_tier=large
elif (( planned_gb_per_day > 0 )); then
    sizing_tier=base
else
    sizing_tier=none
fi
tiered=0
[[ "$sizing_tier" == large || "$sizing_tier" == xlarge ]] && tiered=1

[[ -n "$vector_data_capacity_bytes" ]] \
    || vector_data_capacity_bytes="${NANO_VECTOR_DATA_CAPACITY_BYTES:-}"
vector_data_storage_mode="${NANO_VECTOR_DATA_STORAGE_MODE:-named}"
explicit_vector_data_capacity="$vector_data_capacity_bytes"
case "$vector_data_storage_mode" in
    named|bind) ;;
    *) fail "NANO_VECTOR_DATA_STORAGE_MODE must be named or bind" ;;
esac
if has_role ingest; then
    if [[ -z "$vector_data_capacity_bytes" && "$vector_data_storage_mode" == bind ]]; then
        fail "Vector data uses bind/external storage whose capacity differs from DockerRootDir; set NANO_VECTOR_DATA_CAPACITY_BYTES or pass --vector-data-capacity-bytes"
    fi
    if [[ -z "$vector_data_capacity_bytes" ]]; then
        detected_vector_data=$(detect_docker_volume_capacity_bytes vector 'ghcr.io/nano-rs/vector:' /var/lib/vector) \
            || fail "cannot query the Docker daemon for the filesystem capacity backing Vector; set NANO_VECTOR_DATA_CAPACITY_BYTES or pass --vector-data-capacity-bytes"
        vector_data_capacity_bytes=${detected_vector_data%% *}
        if [[ -z "$vector_data_free_bytes" && "$detected_vector_data" == *" "* ]]; then
            vector_data_free_bytes=${detected_vector_data#* }
        fi
    fi
else
    # Inactive-profile values are emitted for stable compose interpolation but
    # no Vector process runs on this host. Keep them deterministic without
    # requiring Docker storage discovery on app/database-only roles.
    [[ -n "$vector_data_capacity_bytes" ]] || vector_data_capacity_bytes=68719476736
fi
[[ "$vector_data_capacity_bytes" =~ ^[1-9][0-9]*$ ]] \
    || fail "Vector data filesystem capacity must be a positive integer byte count"
[[ -n "$vector_data_free_bytes" ]] || vector_data_free_bytes="${NANO_VECTOR_DATA_FREE_BYTES:-}"
[[ -z "$vector_data_free_bytes" || "$vector_data_free_bytes" =~ ^[0-9]+$ ]] \
    || fail "Vector data filesystem free space must be a non-negative integer byte count"

# NAN-5636: the filesystem holding ClickHouse's data (its named volume, on the
# Docker root filesystem), for the spill caps below. Set explicitly with
# NANO_CLICKHOUSE_DATA_CAPACITY_BYTES (and NANO_CLICKHOUSE_DATA_FREE_BYTES);
# else the Vector measurement when Vector's named volume shares that
# filesystem (ingest on this host, or an explicit capacity with named Vector
# storage); else, on a ClickHouse host without ingest, a best-effort probe
# with ClickHouse's own pinned image. Unknown keeps the caps memory-sized.
ch_data_capacity_bytes="${NANO_CLICKHOUSE_DATA_CAPACITY_BYTES:-}"
ch_data_free_bytes="${NANO_CLICKHOUSE_DATA_FREE_BYTES:-}"
if has_role clickhouse && [[ -z "$ch_data_capacity_bytes" ]]; then
    if [[ "$vector_data_storage_mode" == named ]] && { has_role ingest || [[ -n "$explicit_vector_data_capacity" ]]; }; then
        ch_data_capacity_bytes=$vector_data_capacity_bytes
        ch_data_free_bytes=$vector_data_free_bytes
    elif ! has_role ingest; then
        if detected_ch_data=$(detect_docker_volume_capacity_bytes clickhouse 'clickhouse/clickhouse-server:' /var/lib/clickhouse); then
            ch_data_capacity_bytes=${detected_ch_data%% *}
            [[ "$detected_ch_data" == *" "* ]] && ch_data_free_bytes=${detected_ch_data#* }
        fi
    fi
fi
[[ -z "$ch_data_capacity_bytes" || "$ch_data_capacity_bytes" =~ ^[1-9][0-9]*$ ]] \
    || fail "NANO_CLICKHOUSE_DATA_CAPACITY_BYTES must be a positive integer byte count"
[[ -z "$ch_data_free_bytes" || "$ch_data_free_bytes" =~ ^[0-9]+$ ]] \
    || fail "NANO_CLICKHOUSE_DATA_FREE_BYTES must be a non-negative integer byte count"

# NAN-5446: the disk-pressure pause threshold (DISK_PRESSURE_PAUSE_THRESHOLD,
# a fraction, default 0.92) in per-mille. The invoking environment wins over
# the operator .env, matching Compose interpolation.
disk_pressure_pause_value="${DISK_PRESSURE_PAUSE_THRESHOLD:-}"
if [[ -z "$disk_pressure_pause_value" && -n "$override_env" && -f "$override_env" ]]; then
    disk_pressure_pause_value=$(awk -F= '
        { sub(/\r$/, "") }
        $1 == "DISK_PRESSURE_PAUSE_THRESHOLD" { value = substr($0, 31) }
        END { gsub(/^["\047]|["\047]$/, "", value); print value }
    ' "$override_env")
fi
[[ -n "$disk_pressure_pause_value" ]] || disk_pressure_pause_value=0.92
[[ "$disk_pressure_pause_value" =~ ^0?\.[0-9]+$ ]] \
    || fail "DISK_PRESSURE_PAUSE_THRESHOLD must be a fraction such as 0.92 (got '$disk_pressure_pause_value')"
disk_pressure_pause_digits="${disk_pressure_pause_value#*.}000"
disk_pressure_pause_permille=$(( 10#${disk_pressure_pause_digits:0:3} ))
(( disk_pressure_pause_permille > 0 && disk_pressure_pause_permille < 1000 )) \
    || fail "DISK_PRESSURE_PAUSE_THRESHOLD must be between 0 and 1"

min() { (( $1 < $2 )) && printf '%s\n' "$1" || printf '%s\n' "$2"; }
max() { (( $1 > $2 )) && printf '%s\n' "$1" || printf '%s\n' "$2"; }
clamp() { max "$2" "$(min "$1" "$3")"; }
ceil_div() { printf '%s\n' "$(( ($1 + $2 - 1) / $2 ))"; }

memory_string() {
    if (( $1 % 1024 == 0 )); then
        printf '%sG\n' "$(( $1 / 1024 ))"
    else
        printf '%sM\n' "$1"
    fi
}

cpu_string() {
    if (( $1 % 1000 == 0 )); then
        printf '%s\n' "$(( $1 / 1000 ))"
    else
        printf '%d.%03d\n' "$(( $1 / 1000 ))" "$(( $1 % 1000 ))"
    fi
}

bytes_from_mib() { printf '%s\n' "$(( $1 * 1048576 ))"; }

# "2.550" -> 2550 (millicores); inverse of cpu_string for validated values.
mcpu_from_cpu_string() {
    local whole="${1%%.*}" fraction=""
    [[ "$1" == *.* ]] && fraction="${1#*.}"
    fraction="${fraction}000"
    fraction="${fraction:0:3}"
    printf '%s\n' "$(( 10#$whole * 1000 + 10#$fraction ))"
}

# Leave the OS 10%, at least 384 MiB and at most 8 GiB. The remainder is one
# shared budget on a co-located install; a dedicated role receives the whole
# host remainder instead of inheriting the old single-node "RAM - 4 GiB" cap.
os_reserve_mib=$(( memory_mib / 10 ))
(( os_reserve_mib < 384 )) && os_reserve_mib=384
(( os_reserve_mib > 8192 )) && os_reserve_mib=8192
allocatable_mib=$(( memory_mib - os_reserve_mib ))
# NAN-5250: a host that also runs the monitoring role (Prometheus, Grafana and
# exporters) sets that stack's fixed limits aside first, so the nano roles are
# sized from what is left and the monitoring stack can never take their memory.
# Keep in step with the monitoring services' limits in the Compose files.
monitoring_reserve_mib="${NANO_MONITORING_RESERVE_MIB:-1024}"
[[ "$monitoring_reserve_mib" =~ ^[0-9]+$ ]] || fail "NANO_MONITORING_RESERVE_MIB must be a non-negative integer"
has_role monitoring && allocatable_mib=$(( allocatable_mib - monitoring_reserve_mib ))

ch_weight=0; pg_weight=0; ingest_weight=0; app_weight=0; keeper_weight=0; tenzir_weight=0
has_role clickhouse && ch_weight=55
has_role postgres && pg_weight=12
has_role ingest && ingest_weight=13
has_role app && app_weight=20
has_role keeper && keeper_weight=5
has_role tenzir && tenzir_weight=5
weight_total=$(( ch_weight + pg_weight + ingest_weight + app_weight + keeper_weight + tenzir_weight ))
(( weight_total > 0 )) || fail "at least one role is required"

ch_mib=$(( allocatable_mib * ch_weight / weight_total ))
pg_mib=$(( allocatable_mib * pg_weight / weight_total ))
ingest_mib=$(( allocatable_mib * ingest_weight / weight_total ))
app_mib=$(( allocatable_mib * app_weight / weight_total ))
keeper_mib=$(( allocatable_mib * keeper_weight / weight_total ))
tenzir_mib=$(( allocatable_mib * tenzir_weight / weight_total ))
has_role clickhouse && (( ch_mib < 2048 )) && ch_mib=2048
has_role postgres && (( pg_mib < 312 )) && pg_mib=312
has_role ingest && (( ingest_mib < 312 )) && ingest_mib=312
has_role app && (( app_mib < 800 )) && app_mib=800
has_role keeper && (( keeper_mib < 384 )) && keeper_mib=384
has_role tenzir && (( tenzir_mib < 512 )) && tenzir_mib=512
# NAN-5822: the smallest PostgreSQL budget whose pool floors fit the app
# hosts it serves. The Vector target and the API and jobs floors below still
# borrow PostgreSQL down to 512 MiB, exactly as before (they outrank the pool
# floor: shrunk pools still fit, an API below its floor does not boot); the
# last step then tops PostgreSQL back up to this floor, from ClickHouse first.
pg_floor_mib=512
if has_role postgres; then
    pg_floor_mib=$(pg_budget_floor_mib "$app_hosts")
    (( pg_floor_mib < 512 )) && pg_floor_mib=512
fi

reduce_memory_budget() {
    local variable="$1" floor="$2" current reducible take
    current=${!variable}
    reducible=$(( current - floor ))
    (( reducible > 0 && memory_excess > 0 )) || return 0
    take=$reducible
    (( take > memory_excess )) && take=$memory_excess
    printf -v "$variable" '%s' "$(( current - take ))"
    memory_excess=$(( memory_excess - take ))
}

memory_total=$(( ch_mib + pg_mib + ingest_mib + app_mib + keeper_mib + tenzir_mib ))
memory_excess=$(( memory_total - allocatable_mib ))
if (( memory_excess > 0 )); then
    reduce_memory_budget app_mib 800
    reduce_memory_budget ingest_mib 312
    reduce_memory_budget pg_mib 312
    reduce_memory_budget keeper_mib 384
    reduce_memory_budget tenzir_mib 512
    reduce_memory_budget ch_mib 2048
fi
(( memory_excess <= 0 )) || fail "host RAM cannot satisfy role minimums"
memory_total=$(( ch_mib + pg_mib + ingest_mib + app_mib + keeper_mib + tenzir_mib ))
memory_remainder=$(( allocatable_mib - memory_total ))
if has_role clickhouse; then ch_mib=$(( ch_mib + memory_remainder ))
elif has_role app; then app_mib=$(( app_mib + memory_remainder ))
elif has_role ingest; then ingest_mib=$(( ingest_mib + memory_remainder ))
elif has_role postgres; then pg_mib=$(( pg_mib + memory_remainder ))
elif has_role keeper; then keeper_mib=$(( keeper_mib + memory_remainder ))
else tenzir_mib=$(( tenzir_mib + memory_remainder ))
fi

# The 12 GiB single-node class is documented to run nano's signed platform
# feeds, whose ClickHouse dictionaries need 6 GiB. The weighted split lands
# 60 MiB short (6084M), so transfer that small amount from the co-located app
# share while preserving every role floor. Larger hosts already clear 6 GiB;
# dedicated-role sizing still receives its full host allocation above.
if [[ "$topology" == "single" ]] && has_role clickhouse \
    && (( memory_mib >= 12288 && ch_mib < 6144 )); then
    enrichment_shortfall=$(( 6144 - ch_mib ))
    memory_excess=$enrichment_shortfall
    reduce_memory_budget app_mib 800
    reduce_memory_budget ingest_mib 312
    reduce_memory_budget pg_mib 312
    reduce_memory_budget keeper_mib 384
    reduce_memory_budget tenzir_mib 512
    (( memory_excess == 0 )) || fail "host RAM cannot satisfy the 6 GiB ClickHouse platform-feed floor"
    ch_mib=$(( ch_mib + enrichment_shortfall ))
fi

# NAN-5193 / NAN-5345: Vector's memory target. The ingest role's 85% Vector
# share must reach the target; the shortfall comes only from co-located
# PostgreSQL above 512 MiB, then the app share down to its floor, never from
# ClickHouse. A host with nothing to give keeps its proportional share.
vector_target_mib=$VECTOR_BASE_MEMORY_MIB
(( vector_sources > VECTOR_BASE_SOURCES )) && vector_target_mib=$(( vector_target_mib + (vector_sources - VECTOR_BASE_SOURCES) * VECTOR_MIB_PER_EXTRA_SOURCE ))
if (( tiered )) && [[ "$ingest_path" == raw ]] && (( vector_target_mib < VECTOR_LARGE_TIER_MEMORY_MIB )); then
    vector_target_mib=$VECTOR_LARGE_TIER_MEMORY_MIB
fi
if has_role ingest; then
    ingest_target_mib=$(( (vector_target_mib * 100 + 84) / 85 ))
    if (( ingest_mib < ingest_target_mib )); then
        vector_shortfall=$(( ingest_target_mib - ingest_mib ))
        memory_excess=$vector_shortfall
        reduce_memory_budget pg_mib 512
        reduce_memory_budget app_mib 800
        ingest_mib=$(( ingest_mib + vector_shortfall - memory_excess ))
        memory_excess=0
    fi
fi

total_mcpu=$(( cpu_cores * 1000 ))
ch_mcpu=$(( total_mcpu * ch_weight / weight_total ))
pg_mcpu=$(( total_mcpu * pg_weight / weight_total ))
ingest_mcpu=$(( total_mcpu * ingest_weight / weight_total ))
app_mcpu=$(( total_mcpu * app_weight / weight_total ))
keeper_mcpu=$(( total_mcpu * keeper_weight / weight_total ))
tenzir_mcpu=$(( total_mcpu * tenzir_weight / weight_total ))
has_role clickhouse && (( ch_mcpu < 500 )) && ch_mcpu=500
has_role postgres && (( pg_mcpu < 250 )) && pg_mcpu=250
has_role ingest && (( ingest_mcpu < 250 )) && ingest_mcpu=250
has_role app && (( app_mcpu < 250 )) && app_mcpu=250
has_role keeper && (( keeper_mcpu < 250 )) && keeper_mcpu=250
has_role tenzir && (( tenzir_mcpu < 250 )) && tenzir_mcpu=250

reduce_cpu_budget() {
    local variable="$1" floor="$2" current reducible take
    current=${!variable}
    reducible=$(( current - floor ))
    (( reducible > 0 && cpu_excess > 0 )) || return 0
    take=$reducible
    (( take > cpu_excess )) && take=$cpu_excess
    printf -v "$variable" '%s' "$(( current - take ))"
    cpu_excess=$(( cpu_excess - take ))
}

cpu_total=$(( ch_mcpu + pg_mcpu + ingest_mcpu + app_mcpu + keeper_mcpu + tenzir_mcpu ))
cpu_excess=$(( cpu_total - total_mcpu ))
if (( cpu_excess > 0 )); then
    reduce_cpu_budget app_mcpu 250
    reduce_cpu_budget pg_mcpu 250
    reduce_cpu_budget ingest_mcpu 250
    reduce_cpu_budget keeper_mcpu 250
    reduce_cpu_budget tenzir_mcpu 250
    reduce_cpu_budget ch_mcpu 500
fi
(( cpu_excess <= 0 )) || fail "host CPUs cannot satisfy role minimums"
cpu_total=$(( ch_mcpu + pg_mcpu + ingest_mcpu + app_mcpu + keeper_mcpu + tenzir_mcpu ))
cpu_remainder=$(( total_mcpu - cpu_total ))
if has_role clickhouse; then ch_mcpu=$(( ch_mcpu + cpu_remainder ))
elif has_role app; then app_mcpu=$(( app_mcpu + cpu_remainder ))
elif has_role ingest; then ingest_mcpu=$(( ingest_mcpu + cpu_remainder ))
elif has_role postgres; then pg_mcpu=$(( pg_mcpu + cpu_remainder ))
elif has_role keeper; then keeper_mcpu=$(( keeper_mcpu + cpu_remainder ))
else tenzir_mcpu=$(( tenzir_mcpu + cpu_remainder ))
fi

# Stable fallbacks for inactive profiles keep emitted output complete; those
# containers are profile-gated and never consume the current host's budget.
(( ch_mib > 0 )) || ch_mib=2048
(( pg_mib > 0 )) || pg_mib=512
(( ingest_mib > 0 )) || ingest_mib=512
(( app_mib > 0 )) || app_mib=1024
(( keeper_mib > 0 )) || keeper_mib=512
(( tenzir_mib > 0 )) || tenzir_mib=512
(( ch_mcpu > 0 )) || ch_mcpu=1000
(( pg_mcpu > 0 )) || pg_mcpu=500
(( ingest_mcpu > 0 )) || ingest_mcpu=500
(( app_mcpu > 0 )) || app_mcpu=1000
(( keeper_mcpu > 0 )) || keeper_mcpu=500
(( tenzir_mcpu > 0 )) || tenzir_mcpu=500

# Split the app role budget across concurrently-running services. Floors are
# paid for by API/search headroom, so the sum remains inside the role budget.
api_mib=$(( app_mib * 35 / 100 ))
search_mib=$(( app_mib * 25 / 100 ))
jobs_mib=$(( app_mib * 15 / 100 ))
valkey_mib=$(( app_mib * 12 / 100 ))
web_mib=$(( app_mib * 8 / 100 ))
nginx_mib=$(( app_mib - api_mib - search_mib - jobs_mib - valkey_mib - web_mib ))
(( api_mib < 160 )) && api_mib=160
(( search_mib < 128 )) && search_mib=128
(( jobs_mib < 96 )) && jobs_mib=96
(( valkey_mib < 320 )) && valkey_mib=320
(( web_mib < 64 )) && web_mib=64
(( nginx_mib < 32 )) && nginx_mib=32
app_service_total=$(( api_mib + search_mib + jobs_mib + valkey_mib + web_mib + nginx_mib ))
app_service_excess=$(( app_service_total - app_mib ))
if (( app_service_excess > 0 )); then
    take=$(( api_mib - 160 )); (( take > app_service_excess )) && take=$app_service_excess
    api_mib=$(( api_mib - take )); app_service_excess=$(( app_service_excess - take ))
    take=$(( search_mib - 128 )); (( take > app_service_excess )) && take=$app_service_excess
    search_mib=$(( search_mib - take )); app_service_excess=$(( app_service_excess - take ))
    take=$(( jobs_mib - 96 )); (( take > app_service_excess )) && take=$app_service_excess
    jobs_mib=$(( jobs_mib - take )); app_service_excess=$(( app_service_excess - take ))
    take=$(( nginx_mib - 32 )); (( take > app_service_excess )) && take=$app_service_excess
    nginx_mib=$(( nginx_mib - take )); app_service_excess=$(( app_service_excess - take ))
fi
(( app_service_excess <= 0 )) || fail "app role RAM is below service minimums"
api_mib=$(( api_mib + (app_mib - api_mib - search_mib - jobs_mib - valkey_mib - web_mib - nginx_mib) ))

# NAN-5433: enterprise API floor for the Evidence Pack (ENTERPRISE_API_MIN_MIB).
# Done here, before the ClickHouse and PostgreSQL settings below are derived
# from their budgets. Funded only by co-located roles on this host, in the
# order the Vector target uses: PostgreSQL down to 512 MiB, then ClickHouse
# down to its floor (the 6 GiB platform-feed floor where that applies). Vector's target and the other app services are
# left alone. NAN-5506: open core is funded the same way up to OPEN_API_MIN_MIB,
# and a host that still cannot fund its edition's floor is refused below
# (after operator overrides), never rendered with an API that cannot boot.
# The opt-in connector-runner (pull-feeds profile) keeps the proportional API
# share: the floor is for the pack, which runs only inside nano-api.
api_share_mib=$api_mib
api_min_mib=$OPEN_API_MIN_MIB
api_refuse_mib=$OPEN_API_MIN_MIB
if [[ "$edition" == enterprise ]]; then
    api_min_mib=$ENTERPRISE_API_MIN_MIB
    api_refuse_mib=$ENTERPRISE_API_REFUSE_MIB
fi
if has_role app && (( api_mib < api_min_mib )); then
    api_shortfall=$(( api_min_mib - api_mib ))
    memory_excess=$api_shortfall
    has_role postgres && reduce_memory_budget pg_mib 512
    if has_role clickhouse; then
        ch_floor_mib=2048
        [[ "$topology" == single ]] && (( memory_mib >= 12288 )) && ch_floor_mib=6144
        reduce_memory_budget ch_mib "$ch_floor_mib"
    fi
    api_mib=$(( api_mib + api_shortfall - memory_excess ))
    memory_excess=0
fi

# NAN-5668: nano-jobs floor (JOBS_MIN_MIB). Best effort, never a refusal,
# funded in this order: co-located PostgreSQL down to 512 MiB, ClickHouse down
# to its floor (as the API floor above), then Vector down to its own target
# and nano-search down to 256 MiB. It comes AFTER the API floor so it can never
# turn an accepted host into a refused one or shrink the API; the last two
# sources only matter where the enterprise Evidence Pack already took
# PostgreSQL and ClickHouse to their floors (12 GiB with monitoring, or hosts
# below the 8 GB minimum). A host that still cannot fund it keeps the rest.
if has_role app && (( jobs_mib < JOBS_MIN_MIB )); then
    jobs_shortfall=$(( JOBS_MIN_MIB - jobs_mib ))
    memory_excess=$jobs_shortfall
    has_role postgres && reduce_memory_budget pg_mib 512
    if has_role clickhouse; then
        ch_floor_mib=2048
        [[ "$topology" == single ]] && (( memory_mib >= 12288 )) && ch_floor_mib=6144
        reduce_memory_budget ch_mib "$ch_floor_mib"
    fi
    has_role ingest && reduce_memory_budget ingest_mib "$ingest_target_mib"
    reduce_memory_budget search_mib 256
    jobs_mib=$(( jobs_mib + jobs_shortfall - memory_excess ))
    memory_excess=0
fi

# NAN-5822: PostgreSQL up to its pool floor, funded as the jobs floor is:
# ClickHouse down to its floor (the 6 GiB platform-feed floor where that
# applies), then Vector down to its target and nano-search down to 256 MiB,
# then an enterprise API down to PG_FLOOR_API_FLOOR_MIB. A host that still
# cannot fund it (below the 8 GB minimum) gets pools shrunk to fit, with a
# warning.
if has_role postgres && (( pg_mib < pg_floor_mib )); then
    pg_shortfall=$(( pg_floor_mib - pg_mib ))
    memory_excess=$pg_shortfall
    if has_role clickhouse; then
        ch_floor_mib=2048
        [[ "$topology" == single ]] && (( memory_mib >= 12288 )) && ch_floor_mib=6144
        reduce_memory_budget ch_mib "$ch_floor_mib"
    fi
    has_role ingest && reduce_memory_budget ingest_mib "$ingest_target_mib"
    has_role app && reduce_memory_budget search_mib 256
    has_role app && [[ "$edition" == enterprise ]] && reduce_memory_budget api_mib "$PG_FLOOR_API_FLOOR_MIB"
    pg_mib=$(( pg_mib + pg_shortfall - memory_excess ))
    memory_excess=0
fi

ch_cores=$(ceil_div "$ch_mcpu" 1000)
ch_cores=$(clamp "$ch_cores" 2 64)
if (( ch_mib <= 4096 )); then
    ch_background_pool=2
    ch_background_ratio=2
    # NAN-5296: never 2. With two threads one stuck flush pair held the whole
    # pool and every later insert queued behind it without a timeout.
    ch_async_threads=4
    ch_concurrent=50
    ch_concurrent_insert=20
    ch_concurrent_select=30
    ch_background_schedule=4
else
    ch_background_pool=$(clamp "$(( ch_cores * 2 ))" 4 64)
    (( ch_cores >= 8 )) && ch_background_ratio=4 || ch_background_ratio=2
    ch_async_threads=$(clamp "$(( (ch_cores + 1) / 2 ))" 4 32)
    ch_concurrent=$(clamp "$(( ch_cores * 25 ))" 50 1600)
    ch_concurrent_insert=$(clamp "$(( ch_cores * 8 ))" 20 512)
    ch_concurrent_select=$(clamp "$(( ch_cores * 19 ))" 30 1200)
    ch_background_schedule=$(clamp "$(( ch_cores * 4 ))" 4 256)
fi
ch_background_fetch=$(clamp "$(( (ch_cores + 1) / 2 ))" 1 16)
ch_background_move=$ch_background_fetch
ch_background_common=$(clamp "$ch_cores" 2 32)

ch_mark_mib=$(clamp "$(( ch_mib * 4 / 100 ))" 128 10240)
ch_uncompressed_mib=$(clamp "$(( ch_mib * 4 / 100 ))" 128 8192)
ch_index_mark_mib=$(clamp "$(( ch_mib * 2 / 100 ))" 64 5120)
ch_index_uncompressed_mib=$(clamp "$(( ch_mib * 2 / 100 ))" 64 5120)
ch_default_memory_mib=$(clamp "$(( ch_mib * 32 / 100 ))" 512 102400)
ch_user_memory_mib=$(clamp "$(( ch_mib * 50 / 100 ))" 768 143360)
ch_analytics_memory_mib=$(clamp "$(( ch_mib * 45 / 100 ))" 768 153600)
ch_realtime_memory_mib=$(clamp "$(( ch_mib * 15 / 100 ))" 256 20480)
ch_ingestion_memory_mib=$(clamp "$(( ch_mib * 20 / 100 ))" 384 32768)
ch_admin_memory_mib=$(clamp "$(( ch_mib * 60 / 100 ))" 1024 204800)
ch_analytics_user_memory_mib=$(clamp "$(( ch_mib * 70 / 100 ))" 1024 184320)
ch_realtime_user_memory_mib=$(clamp "$(( ch_mib * 25 / 100 ))" 512 40960)
ch_ingestion_user_memory_mib=$(clamp "$(( ch_mib * 35 / 100 ))" 512 57344)
ch_admin_user_memory_mib=$(clamp "$(( ch_mib * 70 / 100 ))" 1024 225280)

# The compose baseline reserves 20% of the ClickHouse cgroup for allocator and
# process overhead. At the 2 GiB minimum that leaves only 1.6 GiB for tracked
# allocations, and even 0.85 can intermittently reject the bundled IP trie's
# 256 MiB allocation while RSS is around 1.4-1.6 GiB. Give only that smallest
# class a 0.99 tracked limit; its 2 GiB cgroup remains the hard boundary. The
# bundled cold-start workload peaks below that boundary, while a lower tracked
# limit rejects the dictionary before the cgroup is actually exhausted.
# Larger classes retain the conservative long-standing 0.8 ratio.
ch_server_memory_ratio=0.8
(( ch_mib <= 2048 )) && ch_server_memory_ratio=0.99

pg_cores=$(ceil_div "$pg_mcpu" 1000)
# NAN-5822: connection pools from the PostgreSQL budget (pg_pool_plan above).
# A postgres host plans for the app hosts it serves; an app-only host plans
# from the remote PostgreSQL budget it is given (--postgres-mib), and keeps
# the historical 20-wide pools when that is unknown.
size_pg_pools() { # $1 = PostgreSQL budget MiB ("" = unknown), $2 = shared_buffers MiB (optional)
    local needed
    pg_connections=$(clamp "$(( pg_cores * 50 ))" 100 1000)
    if [[ -z "$1" ]]; then
        pg_pool_api=$PG_POOL_MAX; pg_pool_jobs=$PG_POOL_MAX; pg_pool_search=$PG_POOL_MAX
        pg_pool_connector=$PG_CONNECTOR_POOL; pg_pool_min=2
        return 0
    fi
    pg_pool_plan "$1" "$app_hosts" "${2:-}"
    pg_pool_api=$pg_plan_api; pg_pool_jobs=$pg_plan_jobs; pg_pool_search=$pg_plan_search
    pg_pool_connector=$pg_plan_connector; pg_pool_min=$pg_plan_min
    if (( pg_plan_underfunded )); then
        # NAN-5892: name the exact setting and value, not just the problem.
        local floor_mib how
        floor_mib=$(pg_budget_floor_mib "$app_hosts")
        if [[ "$topology" == single ]]; then
            how="set POSTGRES_MEM_LIMIT=${floor_mib}M (or more) below the \"# END NANO AUTO SIZING\" line in .env (raise your own line there if you already set one) and re-run install.sh on this host, or use a larger host or fewer co-located roles"
        else
            # Role-split (review P2-1): PostgreSQL runs on the postgres host,
            # sized from the inventory, not from this host's .env.
            how="give the PostgreSQL host POSTGRES_MEM_LIMIT=${floor_mib}M (or more) in the inventory (that host's resources or overrides), re-render the inventory with render-inventory.py and roll it out, or use a larger PostgreSQL host"
        fi
        printf 'resource sizing warning: PostgreSQL has %s MiB, below the %s MiB its connection pools need for %s app host(s); pools are shrunk to fit (nano-jobs %s, nano-api %s, nano-search %s), so background jobs can wait for a database connection. To fix it, %s.\n' \
            "$1" "$floor_mib" "$app_hosts" "$pg_pool_jobs" "$pg_pool_api" "$pg_pool_search" "$how" >&2
    fi
    if has_role postgres; then
        # Never accept more sessions than the budget holds: past it the server
        # refuses a connection instead of being OOM-killed.
        needed=$(( app_hosts * (pg_pool_api + pg_pool_jobs + pg_pool_search + pg_pool_connector + PG_APP_DEDICATED_SESSIONS) + PG_OPERATOR_SLOTS ))
        (( pg_connections < needed )) && pg_connections=$needed
        (( pg_connections > pg_plan_capacity - PG_SERVER_PROCESSES )) && pg_connections=$(( pg_plan_capacity - PG_SERVER_PROCESSES ))
        # A budget too small for even the server processes (an operator's
        # tiny POSTGRES_MEM_LIMIT) still gets a usable, positive setting.
        (( pg_connections < 10 )) && pg_connections=10
    fi
    return 0
}
# An app host given another PostgreSQL's budget (an app-only host, or an HA
# member that may not lead) sizes its pools for it; a postgres host keeps the
# max_connections its own budget holds.
apply_remote_pool_plan() {
    local own_connections=$pg_connections
    [[ -n "$postgres_mib" ]] && has_role app || return 0
    size_pg_pools "$postgres_mib" "$postgres_shared_mib"
    has_role postgres && pg_connections=$own_connections
    return 0
}
if has_role postgres; then
    size_pg_pools "$pg_mib"
    apply_remote_pool_plan
elif has_role app; then
    size_pg_pools "$postgres_mib" "$postgres_shared_mib"
else
    size_pg_pools ""
fi
pg_shared_mib=$(clamp "$(( pg_mib / 4 ))" 128 32768)
pg_effective_mib=$(clamp "$(( pg_mib * 3 / 4 ))" 256 98304)
pg_work_mib=$(( (pg_mib - pg_shared_mib) / (pg_connections * 4) ))
pg_work_mib=$(clamp "$pg_work_mib" 1 64)

vector_mib=$(( ingest_mib * 85 / 100 ))
(( vector_mib < 256 )) && vector_mib=256
vector_mcpu=$(( ingest_mcpu * 85 / 100 ))
(( vector_mcpu < 200 )) && vector_mcpu=200
vector_cores=$(ceil_div "$vector_mcpu" 1000)
vector_concurrency=$(clamp "$vector_cores" 2 6)
# NAN-5345: sink concurrency 6 at ~1 TB/day and 12 at >=10 TB/day, capped at
# two in-flight requests per Vector core on this host.
vector_concurrency_cap=$(max 2 "$(( vector_cores * 2 ))")
case "$sizing_tier" in
    large) vector_concurrency=$(min 6 "$vector_concurrency_cap") ;;
    xlarge) vector_concurrency=$(min 12 "$vector_concurrency_cap") ;;
esac
vector_buffer_mib=$(clamp "$(( vector_mib * 2 ))" 2048 32768)
vector_desired_buffer_bytes=$(bytes_from_mib "$vector_buffer_mib")

# Vector validates the SUM of every disk buffer against the total capacity of
# the filesystem containing data_dir. Reserve two independent 10% domains for
# Docker/image churn and filesystem safety (each at least 4 GiB). A co-located
# ClickHouse role additionally owns 25% (at least 8 GiB) because its data and
# merge scratch share Docker's filesystem. The remaining amount is a ceiling;
# memory sizing may deliberately choose a smaller backlog.
vector_docker_reserve_bytes=$(( vector_data_capacity_bytes / 10 ))
(( vector_docker_reserve_bytes < 4294967296 )) && vector_docker_reserve_bytes=4294967296
vector_safety_reserve_bytes=$(( vector_data_capacity_bytes / 10 ))
(( vector_safety_reserve_bytes < 4294967296 )) && vector_safety_reserve_bytes=4294967296
vector_clickhouse_reserve_bytes=0
if has_role clickhouse; then
    vector_clickhouse_reserve_bytes=$(( vector_data_capacity_bytes / 4 ))
    (( vector_clickhouse_reserve_bytes < 8589934592 )) && vector_clickhouse_reserve_bytes=8589934592
fi
vector_reserved_bytes=$(( vector_docker_reserve_bytes + vector_safety_reserve_bytes + vector_clickhouse_reserve_bytes ))
vector_buffer_count=$(( VECTOR_DISK_BUFFER_STATIC_COUNT + (VECTOR_DISK_BUFFER_PIPELINE_SHARDED_COUNT + VECTOR_DISK_BUFFER_ENRICHMENT_SHARDED_COUNT) * shards ))
vector_minimum_total_bytes=$(( VECTOR_DISK_BUFFER_MIN_BYTES * vector_buffer_count ))
vector_allocatable_bytes=$(( vector_data_capacity_bytes - vector_reserved_bytes ))
(( vector_allocatable_bytes >= vector_minimum_total_bytes )) || fail \
    "Vector data filesystem has ${vector_data_capacity_bytes} bytes, but the rendered ${vector_buffer_count}-buffer graph needs at least ${vector_minimum_total_bytes} bytes plus ${vector_reserved_bytes} bytes reserved headroom; expand the filesystem or reduce shard count before starting Vector"
(( vector_desired_buffer_bytes < vector_minimum_total_bytes )) \
    && vector_desired_buffer_bytes=$vector_minimum_total_bytes
vector_buffer_budget_bytes=$vector_desired_buffer_bytes
(( vector_buffer_budget_bytes > vector_allocatable_bytes )) \
    && vector_buffer_budget_bytes=$vector_allocatable_bytes

# NAN-5446: a full shared disk must never be reached by Vector's own buffers.
# Vector only fills its buffers while ClickHouse refuses writes, and on a host
# where ClickHouse shares the filesystem ingestion pauses at
# DISK_PRESSURE_PAUSE_THRESHOLD. What Vector already accepted must still fit in
# what is left above that point, less 1 GiB for PostgreSQL WAL and logs.
# Otherwise Vector hits ENOSPC before its max_size, stops every source and
# restart-loops. The capacity reserves above are an install-time snapshot that
# ClickHouse growth eats into; this bound is not.
vector_pause_headroom_bytes=0
if has_role clickhouse; then
    vector_pause_headroom_bytes=$(( vector_data_capacity_bytes * (1000 - disk_pressure_pause_permille) / 1000 - 1073741824 ))
    (( vector_pause_headroom_bytes < 0 )) && vector_pause_headroom_bytes=0
    if (( vector_buffer_budget_bytes > vector_pause_headroom_bytes )); then
        vector_buffer_budget_bytes=$vector_pause_headroom_bytes
    fi
fi
# NAN-5446: and it must fit in the space that is free now (less the safety
# reserve), not only in the install-time capacity: an upgrade on a disk that
# has since filled must not size a backlog the disk cannot hold.
if [[ -n "$vector_data_free_bytes" ]]; then
    vector_free_budget_bytes=$(( vector_data_free_bytes - vector_safety_reserve_bytes ))
    (( vector_free_budget_bytes < 0 )) && vector_free_budget_bytes=0
    (( vector_buffer_budget_bytes > vector_free_budget_bytes )) \
        && vector_buffer_budget_bytes=$vector_free_budget_bytes
fi
if (( vector_buffer_budget_bytes < vector_minimum_total_bytes )); then
    vector_free_note=""
    [[ -n "$vector_data_free_bytes" ]] && vector_free_note=" (${vector_data_free_bytes} bytes free now)"
    printf 'resource sizing warning: the Vector disk buffers need at least %s bytes, but only %s bytes fit below the %s disk-pressure pause threshold and in the free space%s. Using the minimum; grow the disk or free space so Vector cannot fill it while ClickHouse refuses writes.\n' \
        "$vector_minimum_total_bytes" "$vector_buffer_budget_bytes" \
        "$disk_pressure_pause_value" "$vector_free_note" >&2
    vector_buffer_budget_bytes=$vector_minimum_total_bytes
fi
vector_buffer_component_bytes=$(( vector_buffer_budget_bytes / vector_buffer_count ))
(( vector_buffer_component_bytes >= VECTOR_DISK_BUFFER_MIN_BYTES )) || fail \
    "Vector per-buffer allocation ${vector_buffer_component_bytes} is below its ${VECTOR_DISK_BUFFER_MIN_BYTES}-byte minimum"
# Integer division leaves a few bytes intentionally unallocated. Emit the
# exact sum Vector will validate, not the pre-division ceiling.
vector_buffer_budget_bytes=$(( vector_buffer_component_bytes * vector_buffer_count ))
vector_headroom_bytes=$(( vector_data_capacity_bytes - vector_buffer_budget_bytes ))
if (( vector_mib <= 512 )); then
    vector_batch_bytes=8388608; vector_batch_events=10000
elif (( vector_mib <= 1024 )); then
    vector_batch_bytes=16777216; vector_batch_events=25000
elif (( vector_mib <= 4096 )); then
    vector_batch_bytes=52428800; vector_batch_events=50000
else
    vector_batch_bytes=104857600; vector_batch_events=100000
fi
vector_memory_buffer_events=$(clamp "$(( vector_batch_events * 2 ))" 50000 500000)

api_mcpu=$(( app_mcpu * 35 / 100 )); (( api_mcpu < 100 )) && api_mcpu=100
search_mcpu=$(( app_mcpu * 25 / 100 )); (( search_mcpu < 75 )) && search_mcpu=75
jobs_mcpu=$(( app_mcpu * 15 / 100 )); (( jobs_mcpu < 50 )) && jobs_mcpu=50
valkey_mcpu=$(( app_mcpu * 12 / 100 )); (( valkey_mcpu < 50 )) && valkey_mcpu=50
web_mcpu=$(( app_mcpu * 8 / 100 )); (( web_mcpu < 25 )) && web_mcpu=25
nginx_mcpu=$(( app_mcpu - api_mcpu - search_mcpu - jobs_mcpu - valkey_mcpu - web_mcpu ))
(( nginx_mcpu < 25 )) && nginx_mcpu=25
app_cpu_excess=$(( api_mcpu + search_mcpu + jobs_mcpu + valkey_mcpu + web_mcpu + nginx_mcpu - app_mcpu ))
if (( app_cpu_excess > 0 )); then
    take=$(( api_mcpu - 100 )); (( take > app_cpu_excess )) && take=$app_cpu_excess
    api_mcpu=$(( api_mcpu - take )); app_cpu_excess=$(( app_cpu_excess - take ))
    take=$(( search_mcpu - 75 )); (( take > app_cpu_excess )) && take=$app_cpu_excess
    search_mcpu=$(( search_mcpu - take )); app_cpu_excess=$(( app_cpu_excess - take ))
fi
(( app_cpu_excess <= 0 )) || fail "app role CPUs are below service minimums"
api_mcpu=$(( api_mcpu + (app_mcpu - api_mcpu - search_mcpu - jobs_mcpu - valkey_mcpu - web_mcpu - nginx_mcpu) ))
if [[ "$topology" == role ]] && has_role app; then
    # The role compose runs two app edges and, unless ingest is co-located, an
    # app-side ClickHouse proxy. Fund every 25m nginx floor inside app_mcpu
    # before dividing the shared edge allocation; integer rounding must not
    # let the emitted per-container limits exceed the host CPU budget.
    if has_role ingest; then app_edge_instances=2; else app_edge_instances=3; fi
    app_edge_cpu_floor=$(( app_edge_instances * 25 ))
    if (( nginx_mcpu < app_edge_cpu_floor )); then
        app_edge_cpu_shortfall=$(( app_edge_cpu_floor - nginx_mcpu ))
        (( api_mcpu - app_edge_cpu_shortfall >= 100 )) \
            || fail "app role CPUs are below edge service minimums"
        api_mcpu=$(( api_mcpu - app_edge_cpu_shortfall ))
        nginx_mcpu=$app_edge_cpu_floor
    fi
fi

# NAN-5506: nano-api CPU floor (API_MIN_MCPU). A 2 vCPU single node splits to
# about 0.13 CPU for the API; move the difference from co-located ClickHouse
# (down to its 500m floor), then PostgreSQL (down to 250m). The host total is
# unchanged. Refused below, after overrides, if it still falls short.
if has_role app && (( api_mcpu < API_MIN_MCPU )); then
    cpu_excess=$(( API_MIN_MCPU - api_mcpu ))
    api_cpu_shortfall=$cpu_excess
    has_role clickhouse && reduce_cpu_budget ch_mcpu 500
    has_role postgres && reduce_cpu_budget pg_mcpu 250
    api_mcpu=$(( api_mcpu + api_cpu_shortfall - cpu_excess ))
    cpu_excess=0
fi

CLICKHOUSE_MEM_LIMIT=$(memory_string "$ch_mib")
CLICKHOUSE_CPU_LIMIT=$(cpu_string "$ch_mcpu")
CLICKHOUSE_MAX_THREADS=$ch_cores
CLICKHOUSE_ANALYTICS_MAX_THREADS=$(clamp "$(( ch_cores * 2 ))" 2 64)
CLICKHOUSE_REALTIME_MAX_THREADS=$(clamp "$(( (ch_cores + 1) / 2 ))" 2 32)
CLICKHOUSE_INGEST_MAX_THREADS=$(clamp "$ch_cores" 2 16)
CLICKHOUSE_MAX_INSERT_THREADS=$(clamp "$ch_cores" 2 16)
CLICKHOUSE_BACKGROUND_POOL_SIZE=$ch_background_pool
CLICKHOUSE_BACKGROUND_MERGES_MUTATIONS_CONCURRENCY_RATIO=$ch_background_ratio
CLICKHOUSE_BACKGROUND_SCHEDULE_POOL_SIZE=$ch_background_schedule
CLICKHOUSE_BACKGROUND_FETCHES_POOL_SIZE=$ch_background_fetch
CLICKHOUSE_BACKGROUND_MOVE_POOL_SIZE=$ch_background_move
CLICKHOUSE_BACKGROUND_COMMON_POOL_SIZE=$ch_background_common
CLICKHOUSE_MAX_CONCURRENT_QUERIES=$ch_concurrent
CLICKHOUSE_MAX_CONCURRENT_INSERT_QUERIES=$ch_concurrent_insert
CLICKHOUSE_MAX_CONCURRENT_SELECT_QUERIES=$ch_concurrent_select
CLICKHOUSE_ASYNC_INSERT_THREADS=$ch_async_threads
CLICKHOUSE_MARK_CACHE_SIZE=$(bytes_from_mib "$ch_mark_mib")
CLICKHOUSE_UNCOMPRESSED_CACHE_SIZE=$(bytes_from_mib "$ch_uncompressed_mib")
CLICKHOUSE_INDEX_MARK_CACHE_SIZE=$(bytes_from_mib "$ch_index_mark_mib")
CLICKHOUSE_INDEX_UNCOMPRESSED_CACHE_SIZE=$(bytes_from_mib "$ch_index_uncompressed_mib")
CLICKHOUSE_MAX_MEMORY_USAGE=$(bytes_from_mib "$ch_default_memory_mib")
CLICKHOUSE_MAX_MEMORY_USAGE_FOR_USER=$(bytes_from_mib "$ch_user_memory_mib")
CLICKHOUSE_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO=$ch_server_memory_ratio
CLICKHOUSE_ANALYTICS_MAX_MEMORY_USAGE=$(bytes_from_mib "$ch_analytics_memory_mib")
CLICKHOUSE_REALTIME_MAX_MEMORY_USAGE=$(bytes_from_mib "$ch_realtime_memory_mib")
CLICKHOUSE_INGEST_MAX_MEMORY_USAGE=$(bytes_from_mib "$ch_ingestion_memory_mib")
CLICKHOUSE_ADMIN_MAX_MEMORY_USAGE=$(bytes_from_mib "$ch_admin_memory_mib")
CLICKHOUSE_ANALYTICS_MAX_MEMORY_USAGE_FOR_USER=$(bytes_from_mib "$ch_analytics_user_memory_mib")
CLICKHOUSE_REALTIME_MAX_MEMORY_USAGE_FOR_USER=$(bytes_from_mib "$ch_realtime_user_memory_mib")
CLICKHOUSE_INGEST_MAX_MEMORY_USAGE_FOR_USER=$(bytes_from_mib "$ch_ingestion_user_memory_mib")
CLICKHOUSE_ADMIN_MAX_MEMORY_USAGE_FOR_USER=$(bytes_from_mib "$ch_admin_user_memory_mib")
# NAN-5636: spill caps, derived after the overrides below (they follow an
# overridden CLICKHOUSE_MAX_MEMORY_USAGE). Empty = not set by an override.
CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_QUERY=""
CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_USER=""
CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE=""

POSTGRES_MEM_LIMIT=$(memory_string "$pg_mib")
POSTGRES_CPU_LIMIT=$(cpu_string "$pg_mcpu")
POSTGRES_MAX_CONNECTIONS=$pg_connections
POSTGRES_SHARED_BUFFERS="${pg_shared_mib}MB"
POSTGRES_EFFECTIVE_CACHE_SIZE="${pg_effective_mib}MB"
POSTGRES_WORK_MEM="${pg_work_mib}MB"
PG_MAX_CONNECTIONS=$pg_pool_api
PG_MIN_CONNECTIONS=$pg_pool_min
NANO_API_PG_MAX_CONNECTIONS=$pg_pool_api
NANO_JOBS_PG_MAX_CONNECTIONS=$pg_pool_jobs
NANO_SEARCH_PG_MAX_CONNECTIONS=$pg_pool_search
NANO_CONNECTOR_PG_MAX_CONNECTIONS=$pg_pool_connector

VECTOR_MEM_LIMIT=$(memory_string "$vector_mib")
VECTOR_CPU_LIMIT=$(cpu_string "$vector_mcpu")
VECTOR_CLICKHOUSE_REQUEST_CONCURRENCY=$vector_concurrency
VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES=$vector_buffer_budget_bytes
VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES_PER_SHARD=$vector_buffer_component_bytes
VECTOR_DISK_BUFFER_TOTAL_BUDGET_BYTES=$vector_buffer_budget_bytes
VECTOR_DISK_BUFFER_COUNT=$vector_buffer_count
VECTOR_DISK_BUFFER_MAX_BYTES=$vector_buffer_component_bytes
VECTOR_DATA_CAPACITY_BYTES=$vector_data_capacity_bytes
VECTOR_DISK_HEADROOM_BYTES=$vector_headroom_bytes
VECTOR_BATCH_MAX_BYTES=$vector_batch_bytes
VECTOR_BATCH_MAX_EVENTS=$vector_batch_events
VECTOR_MEMORY_BUFFER_MAX_EVENTS=$vector_memory_buffer_events

NANO_API_MEM_LIMIT=$(memory_string "$api_mib")
NANO_API_CPU_LIMIT=$(cpu_string "$api_mcpu")
NANO_SEARCH_MEM_LIMIT=$(memory_string "$search_mib")
NANO_SEARCH_CPU_LIMIT=$(cpu_string "$search_mcpu")
NANO_JOBS_MEM_LIMIT=$(memory_string "$jobs_mib")
NANO_JOBS_CPU_LIMIT=$(cpu_string "$jobs_mcpu")
VALKEY_MEM_LIMIT=$(memory_string "$valkey_mib")
VALKEY_CPU_LIMIT=$(cpu_string "$valkey_mcpu")
# maxmemory counts the dataset only; the remaining 20% covers client buffers,
# fragmentation and the I/O threads' working memory.
valkey_maxmemory_mib=$(max 64 "$(( valkey_mib * 80 / 100 ))")
VALKEY_MAXMEMORY="${valkey_maxmemory_mib}mb"
# io-threads counts the main thread; 1 disables I/O threading. Valkey only
# offloads socket I/O to them, so beyond 4 there is nothing left to gain here.
VALKEY_IO_THREADS=$(clamp "$(ceil_div "$valkey_mcpu" 1000)" 1 4)
NANO_WEB_MEM_LIMIT=$(memory_string "$web_mib")
NANO_WEB_CPU_LIMIT=$(cpu_string "$web_mcpu")
nginx_instance_mib=$nginx_mib
nginx_instance_mcpu=$nginx_mcpu
if [[ "$topology" == role ]] && has_role app; then
    # Role compose has public + internal app edges. When ingest is elsewhere,
    # its local ClickHouse proxy is the third app-side nginx instance.
    if has_role ingest; then nginx_divisor=2; else nginx_divisor=3; fi
    nginx_instance_mib=$(max 16 "$(( nginx_mib / nginx_divisor ))")
    nginx_instance_mcpu=$(max 25 "$(( nginx_mcpu / nginx_divisor ))")
fi
NANO_NGINX_MEM_LIMIT=$(memory_string "$nginx_instance_mib")
NANO_NGINX_CPU_LIMIT=$(cpu_string "$nginx_instance_mcpu")
CONNECTOR_MEM_LIMIT=$(memory_string "$(max 256 "$api_share_mib")")
CONNECTOR_CPU_LIMIT=$(cpu_string "$(max 250 "$api_mcpu")")
NANO_MIGRATE_MEM_LIMIT=$(memory_string "$(max 256 "$jobs_mib")")
NANO_MIGRATE_CPU_LIMIT=$(cpu_string "$(max 250 "$jobs_mcpu")")
if [[ "$topology" == role ]] && has_role ingest; then
    ingest_sidecar_count=4 # consumer, tap, ingest edge, ClickHouse proxy
else
    ingest_sidecar_count=1 # only tap is present in the single-node compose
fi
ingest_sidecar_mib=$(( (ingest_mib - vector_mib) / ingest_sidecar_count ))
(( ingest_sidecar_mib < 32 )) && ingest_sidecar_mib=32
ingest_sidecar_mcpu=$(( (ingest_mcpu - vector_mcpu) / ingest_sidecar_count ))
(( ingest_sidecar_mcpu < 25 )) && ingest_sidecar_mcpu=25
NANO_VECTOR_TAP_MEM_LIMIT=$(memory_string "$ingest_sidecar_mib")
NANO_VECTOR_TAP_CPU_LIMIT=$(cpu_string "$ingest_sidecar_mcpu")
NANO_VECTOR_CONSUMER_MEM_LIMIT=$(memory_string "$ingest_sidecar_mib")
NANO_VECTOR_CONSUMER_CPU_LIMIT=$(cpu_string "$ingest_sidecar_mcpu")
NANO_INGEST_EDGE_MEM_LIMIT=$(memory_string "$ingest_sidecar_mib")
NANO_INGEST_EDGE_CPU_LIMIT=$(cpu_string "$ingest_sidecar_mcpu")
if [[ "$topology" == role ]] && has_role ingest; then
    NANO_CLICKHOUSE_PROXY_MEM_LIMIT=$(memory_string "$ingest_sidecar_mib")
    NANO_CLICKHOUSE_PROXY_CPU_LIMIT=$(cpu_string "$ingest_sidecar_mcpu")
elif [[ "$topology" == role ]] && has_role app; then
    NANO_CLICKHOUSE_PROXY_MEM_LIMIT=$(memory_string "$nginx_instance_mib")
    NANO_CLICKHOUSE_PROXY_CPU_LIMIT=$(cpu_string "$nginx_instance_mcpu")
else
    NANO_CLICKHOUSE_PROXY_MEM_LIMIT=64M
    NANO_CLICKHOUSE_PROXY_CPU_LIMIT=0.25
fi
KEEPER_MEM_LIMIT=$(memory_string "$keeper_mib")
KEEPER_CPU_LIMIT=$(cpu_string "$keeper_mcpu")
TENZIR_MEM_LIMIT=$(memory_string "$tenzir_mib")
TENZIR_CPU_LIMIT=$(cpu_string "$tenzir_mcpu")
NANO_SIZING_DIR=.nano-generated/sizing
NANO_DETECTED_CPU_CORES=$cpu_cores
NANO_DETECTED_MEMORY_MIB=$memory_mib
NANO_SIZING_TOPOLOGY=$topology

SIZING_KEYS='CLICKHOUSE_MEM_LIMIT CLICKHOUSE_CPU_LIMIT CLICKHOUSE_MAX_THREADS CLICKHOUSE_ANALYTICS_MAX_THREADS CLICKHOUSE_REALTIME_MAX_THREADS CLICKHOUSE_INGEST_MAX_THREADS CLICKHOUSE_MAX_INSERT_THREADS CLICKHOUSE_BACKGROUND_POOL_SIZE CLICKHOUSE_BACKGROUND_MERGES_MUTATIONS_CONCURRENCY_RATIO CLICKHOUSE_BACKGROUND_SCHEDULE_POOL_SIZE CLICKHOUSE_BACKGROUND_FETCHES_POOL_SIZE CLICKHOUSE_BACKGROUND_MOVE_POOL_SIZE CLICKHOUSE_BACKGROUND_COMMON_POOL_SIZE CLICKHOUSE_MAX_CONCURRENT_QUERIES CLICKHOUSE_MAX_CONCURRENT_INSERT_QUERIES CLICKHOUSE_MAX_CONCURRENT_SELECT_QUERIES CLICKHOUSE_ASYNC_INSERT_THREADS CLICKHOUSE_MARK_CACHE_SIZE CLICKHOUSE_UNCOMPRESSED_CACHE_SIZE CLICKHOUSE_INDEX_MARK_CACHE_SIZE CLICKHOUSE_INDEX_UNCOMPRESSED_CACHE_SIZE CLICKHOUSE_MAX_MEMORY_USAGE CLICKHOUSE_MAX_MEMORY_USAGE_FOR_USER CLICKHOUSE_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO CLICKHOUSE_ANALYTICS_MAX_MEMORY_USAGE CLICKHOUSE_ANALYTICS_MAX_MEMORY_USAGE_FOR_USER CLICKHOUSE_REALTIME_MAX_MEMORY_USAGE CLICKHOUSE_REALTIME_MAX_MEMORY_USAGE_FOR_USER CLICKHOUSE_INGEST_MAX_MEMORY_USAGE CLICKHOUSE_INGEST_MAX_MEMORY_USAGE_FOR_USER CLICKHOUSE_ADMIN_MAX_MEMORY_USAGE CLICKHOUSE_ADMIN_MAX_MEMORY_USAGE_FOR_USER CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_QUERY CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_USER CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE POSTGRES_MEM_LIMIT POSTGRES_CPU_LIMIT POSTGRES_MAX_CONNECTIONS POSTGRES_SHARED_BUFFERS POSTGRES_EFFECTIVE_CACHE_SIZE POSTGRES_WORK_MEM PG_MAX_CONNECTIONS PG_MIN_CONNECTIONS NANO_API_PG_MAX_CONNECTIONS NANO_JOBS_PG_MAX_CONNECTIONS NANO_SEARCH_PG_MAX_CONNECTIONS NANO_CONNECTOR_PG_MAX_CONNECTIONS VECTOR_MEM_LIMIT VECTOR_CPU_LIMIT VECTOR_CLICKHOUSE_REQUEST_CONCURRENCY VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES_PER_SHARD VECTOR_DISK_BUFFER_TOTAL_BUDGET_BYTES VECTOR_DISK_BUFFER_COUNT VECTOR_DISK_BUFFER_MAX_BYTES VECTOR_DATA_CAPACITY_BYTES VECTOR_DISK_HEADROOM_BYTES VECTOR_BATCH_MAX_BYTES VECTOR_BATCH_MAX_EVENTS VECTOR_MEMORY_BUFFER_MAX_EVENTS NANO_API_MEM_LIMIT NANO_API_CPU_LIMIT NANO_SEARCH_MEM_LIMIT NANO_SEARCH_CPU_LIMIT NANO_JOBS_MEM_LIMIT NANO_JOBS_CPU_LIMIT VALKEY_MEM_LIMIT VALKEY_CPU_LIMIT VALKEY_MAXMEMORY VALKEY_IO_THREADS NANO_WEB_MEM_LIMIT NANO_WEB_CPU_LIMIT NANO_NGINX_MEM_LIMIT NANO_NGINX_CPU_LIMIT CONNECTOR_MEM_LIMIT CONNECTOR_CPU_LIMIT NANO_MIGRATE_MEM_LIMIT NANO_MIGRATE_CPU_LIMIT NANO_VECTOR_TAP_MEM_LIMIT NANO_VECTOR_TAP_CPU_LIMIT NANO_VECTOR_CONSUMER_MEM_LIMIT NANO_VECTOR_CONSUMER_CPU_LIMIT NANO_INGEST_EDGE_MEM_LIMIT NANO_INGEST_EDGE_CPU_LIMIT NANO_CLICKHOUSE_PROXY_MEM_LIMIT NANO_CLICKHOUSE_PROXY_CPU_LIMIT KEEPER_MEM_LIMIT KEEPER_CPU_LIMIT TENZIR_MEM_LIMIT TENZIR_CPU_LIMIT NANO_SIZING_DIR NANO_DETECTED_CPU_CORES NANO_DETECTED_MEMORY_MIB NANO_SIZING_TOPOLOGY'

is_sizing_key() {
    case " $SIZING_KEYS " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

validate_override() {
    local key="$1" value="$2"
    case "$key" in
        CLICKHOUSE_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO)
            [[ "$value" =~ ^(0\.[0-9]*[1-9][0-9]*|1(\.0+)?)$ ]] \
                || fail "$key must be greater than 0 and no greater than 1" ;;
        *_CPU_LIMIT)
            [[ "$value" =~ ^([1-9][0-9]*(\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)$ ]] \
                || fail "$key must be a positive CPU count" ;;
        *_MEM_LIMIT)
            [[ "$value" =~ ^[1-9][0-9]*([KMGT]i?[Bb]?|[kmgt])$ ]] || fail "$key must be a Docker memory value such as 4G or 512M" ;;
        POSTGRES_SHARED_BUFFERS|POSTGRES_EFFECTIVE_CACHE_SIZE|POSTGRES_WORK_MEM|VALKEY_MAXMEMORY)
            [[ "$value" =~ ^[1-9][0-9]*(kB|MB|GB|mb)$ ]] || fail "$key has an invalid memory setting" ;;
        NANO_SIZING_DIR|NANO_SIZING_TOPOLOGY|NANO_DETECTED_CPU_CORES|NANO_DETECTED_MEMORY_MIB|\
        VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES|VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES_PER_SHARD|\
        VECTOR_DISK_BUFFER_TOTAL_BUDGET_BYTES|VECTOR_DISK_BUFFER_COUNT|\
        VECTOR_DISK_BUFFER_MAX_BYTES|VECTOR_DATA_CAPACITY_BYTES|VECTOR_DISK_HEADROOM_BYTES)
            fail "$key is generated metadata and cannot be overridden" ;;
        *)
            [[ "$value" =~ ^[1-9][0-9]*$ ]] || fail "$key must be a positive integer" ;;
    esac
}

apply_override() {
    local key="$1" value="$2"
    is_sizing_key "$key" || fail "unsupported override key $key"
    validate_override "$key" "$value"
    printf -v "$key" '%s' "$value"
    # NAN-5822: a key from the installer-managed block is the installer's own
    # output, not an operator choice: it sets the value but never counts as
    # an override (so values derived from an overridden key still follow it).
    (( override_tracks )) && overridden_keys="$overridden_keys $key "
    # NAN-5514: remember where an explicit nano-api limit came from, so a
    # too-small one is blamed on the setting, not on the host.
    [[ "$key" == NANO_API_MEM_LIMIT ]] && api_mem_set_in="${override_origin:-an override}"
    return 0
}

# NAN-5082: Valkey replaced Dragonfly. An operator override written under the
# old Dragonfly key still applies to its Valkey successor. A Valkey key always
# wins over its legacy spelling, whatever order they appear in.
legacy_sizing_key() {
    case "$1" in
        DRAGONFLY_MEM_LIMIT) printf 'VALKEY_MEM_LIMIT' ;;
        DRAGONFLY_CPU_LIMIT) printf 'VALKEY_CPU_LIMIT' ;;
        DRAGONFLY_MAXMEMORY) printf 'VALKEY_MAXMEMORY' ;;
        DRAGONFLY_PROACTOR_THREADS) printf 'VALKEY_IO_THREADS' ;;
        *) return 1 ;;
    esac
}

apply_legacy_overrides() {
    local legacy successor value
    for legacy in DRAGONFLY_MEM_LIMIT DRAGONFLY_CPU_LIMIT DRAGONFLY_MAXMEMORY DRAGONFLY_PROACTOR_THREADS; do
        successor=$(legacy_sizing_key "$legacy")
        value=$("$@" "$legacy" "$successor") || continue
        [[ -n "$value" ]] && apply_override "$successor" "$value"
    done
    return 0
}

# Prints the legacy key's last value from the override env, unless the same
# file also sets the Valkey key (which the main loop below then applies).
legacy_value_from_file() {
    awk -F= -v legacy="$1" -v successor="$2" '
        { sub(/\r$/, "") }
        $1 == successor { has_successor = 1 }
        $1 == legacy { value = substr($0, length(legacy) + 2) }
        END {
            if (has_successor || value == "") exit 1
            gsub(/^["\047]|["\047]$/, "", value)
            print value
        }
    ' "$override_env"
}

legacy_value_from_environment() {
    [[ -z "$(printenv "$2" 2>/dev/null || true)" ]] || return 1
    printenv "$1" 2>/dev/null
}

# NAN-5514: the nano-api limit this host's sizing computed, before overrides.
sized_api_mem_limit="$NANO_API_MEM_LIMIT"
api_mem_set_in=""
overridden_keys=" "
override_tracks=1
# NAN-5822: keys set by the operator's own .env lines (--operator-env). The
# block install.sh writes keeps this host's sized value for them (the
# operator line below the block wins), while everything derived from them
# follows the override.
operator_keys=" "
for key in $SIZING_KEYS; do
    printf -v "presized_$key" '%s' "${!key}"
done

# Apply the sizing keys of an .env file. MODE all: every line, the managed
# block's untracked (install.sh pass 2, nano upgrade). MODE operator: only the
# lines outside the block (install.sh pass 1).
apply_env_file_overrides() {
    local path="$1" mode="$2" line key value in_block=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line%$'\r'}
        case "$line" in
            '# BEGIN NANO AUTO SIZING'*) in_block=1; continue ;;
            '# END NANO AUTO SIZING'*) in_block=0; continue ;;
        esac
        [[ "$line" == *=* ]] || continue
        (( in_block )) && [[ "$mode" == operator ]] && continue
        key=${line%%=*}; value=${line#*=}
        is_sizing_key "$key" || continue
        case "$key" in
            NANO_SIZING_DIR|NANO_SIZING_TOPOLOGY|NANO_DETECTED_CPU_CORES|NANO_DETECTED_MEMORY_MIB|\
            VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES|VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES_PER_SHARD|\
            VECTOR_DISK_BUFFER_TOTAL_BUDGET_BYTES|VECTOR_DISK_BUFFER_COUNT|\
            VECTOR_DISK_BUFFER_MAX_BYTES|VECTOR_DATA_CAPACITY_BYTES|VECTOR_DISK_HEADROOM_BYTES) continue ;;
        esac
        value=${value#\"}; value=${value%\"}; value=${value#\'}; value=${value%\'}
        [[ -n "$value" ]] || continue
        override_tracks=$(( in_block ? 0 : 1 ))
        apply_override "$key" "$value"
        override_tracks=1
        if [[ "$mode" == operator ]]; then operator_keys="$operator_keys $key "; fi
    done < "$path"
    return 0
}
override_origin=""
if [[ -n "$override_env" ]]; then
    [[ -f "$override_env" ]] || fail "override env does not exist: $override_env"
    override_origin="$override_env"
    apply_legacy_overrides legacy_value_from_file
    apply_env_file_overrides "$override_env" all
fi
if [[ -n "$operator_env" ]]; then
    [[ -f "$operator_env" ]] || fail "operator env does not exist: $operator_env"
    override_origin="$operator_env"
    apply_env_file_overrides "$operator_env" operator
fi

# The invoking environment is the normal one-shot override path. It wins over
# .env, matching Docker Compose interpolation semantics.
override_origin="the environment"
apply_legacy_overrides legacy_value_from_environment
for key in $SIZING_KEYS; do
    case "$key" in
        NANO_SIZING_DIR|NANO_SIZING_TOPOLOGY|NANO_DETECTED_CPU_CORES|NANO_DETECTED_MEMORY_MIB|\
        VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES|VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES_PER_SHARD|\
        VECTOR_DISK_BUFFER_TOTAL_BUDGET_BYTES|VECTOR_DISK_BUFFER_COUNT|\
        VECTOR_DISK_BUFFER_MAX_BYTES|VECTOR_DATA_CAPACITY_BYTES|VECTOR_DISK_HEADROOM_BYTES) continue ;;
    esac
    value=$(printenv "$key" 2>/dev/null || true)
    [[ -n "$value" ]] && apply_override "$key" "$value"
done

if [[ -n "$cli_overrides" ]]; then
    override_origin="--override"
    while IFS= read -r assignment; do
        [[ -n "$assignment" ]] || continue
        apply_override "${assignment%%=*}" "${assignment#*=}"
    done <<< "$cli_overrides"
fi

# NAN-5506: refuse, with the shortfall, a nano-api limit it cannot boot in.
# Checked on the final values, so an explicit operator override still wins.
# NANO_SKIP_HOST_MINIMUMS=1 (set by the operator, or by install.sh for a host
# that already runs nano) renders the limits anyway with a warning.
api_floor_fail() {
    if [[ "${NANO_SKIP_HOST_MINIMUMS:-0}" == "1" ]]; then
        printf 'resource sizing warning: %s (NANO_SKIP_HOST_MINIMUMS=1: sizing it anyway)\n' "$*" >&2
    else
        fail "$*"
    fi
}
mib_from_memory_string() { # Docker memory value -> MiB (rounded down); "" when unparseable
    local v="$1" n unit
    [[ "$v" =~ ^([1-9][0-9]*)([KkMmGgTt]?)(i?[Bb]?)$ ]] || return 0
    n=${BASH_REMATCH[1]}; unit=${BASH_REMATCH[2]}
    case "$unit" in
        [Kk]) printf '%s\n' "$(( n / 1024 ))" ;;
        [Mm]) printf '%s\n' "$n" ;;
        [Gg]) printf '%s\n' "$(( n * 1024 ))" ;;
        [Tt]) printf '%s\n' "$(( n * 1048576 ))" ;;
        *) printf '%s\n' "$(( n / 1048576 ))" ;;
    esac
}
# NAN-5822: a PostgreSQL limit from an override (an operator line, or the
# installed block during nano upgrade) re-derives everything sized from the
# PostgreSQL budget that was not itself overridden, so the pools always fit
# the limit PostgreSQL actually runs with.
is_overridden() { case "$overridden_keys" in *" $1 "*) return 0 ;; esac; return 1; }
set_unless_overridden() { is_overridden "$1" || printf -v "$1" '%s' "$2"; }
if has_role postgres && { is_overridden POSTGRES_MEM_LIMIT || is_overridden POSTGRES_SHARED_BUFFERS; }; then
    overridden_pg_mib=$(mib_from_memory_string "$POSTGRES_MEM_LIMIT")
    effective_shared_mib=""
    if is_overridden POSTGRES_SHARED_BUFFERS; then
        case "$POSTGRES_SHARED_BUFFERS" in
            *GB) effective_shared_mib=$(( ${POSTGRES_SHARED_BUFFERS%GB} * 1024 )) ;;
            *MB|*mb) effective_shared_mib=${POSTGRES_SHARED_BUFFERS%??} ;;
            *kB) effective_shared_mib=$(( ${POSTGRES_SHARED_BUFFERS%kB} / 1024 )) ;;
        esac
    fi
    if [[ -n "$overridden_pg_mib" ]]; then
        pg_mib=$overridden_pg_mib
        size_pg_pools "$pg_mib" "$effective_shared_mib"
        pg_shared_mib=$(clamp "$(( pg_mib / 4 ))" 128 32768)
        [[ -n "$effective_shared_mib" ]] && pg_shared_mib=$effective_shared_mib
        pg_effective_mib=$(clamp "$(( pg_mib * 3 / 4 ))" 256 98304)
        pg_work_mib=$(clamp "$(( (pg_mib - pg_shared_mib) / (pg_connections * 4) ))" 1 64)
        set_unless_overridden POSTGRES_MAX_CONNECTIONS "$pg_connections"
        set_unless_overridden POSTGRES_SHARED_BUFFERS "${pg_shared_mib}MB"
        set_unless_overridden POSTGRES_EFFECTIVE_CACHE_SIZE "${pg_effective_mib}MB"
        set_unless_overridden POSTGRES_WORK_MEM "${pg_work_mib}MB"
        apply_remote_pool_plan
        set_unless_overridden PG_MAX_CONNECTIONS "$pg_pool_api"
        set_unless_overridden PG_MIN_CONNECTIONS "$pg_pool_min"
        set_unless_overridden NANO_API_PG_MAX_CONNECTIONS "$pg_pool_api"
        set_unless_overridden NANO_JOBS_PG_MAX_CONNECTIONS "$pg_pool_jobs"
        set_unless_overridden NANO_SEARCH_PG_MAX_CONNECTIONS "$pg_pool_search"
        set_unless_overridden NANO_CONNECTOR_PG_MAX_CONNECTIONS "$pg_pool_connector"
    fi
fi

if has_role app; then
    final_api_mib=$(mib_from_memory_string "$NANO_API_MEM_LIMIT")
    if [[ -n "$final_api_mib" ]] && (( final_api_mib < api_refuse_mib )); then
        api_need_what="nano-api needs at least ${api_refuse_mib} MiB (${api_min_mib} MiB recommended)"
        (( api_refuse_mib == api_min_mib )) && api_need_what="nano-api needs at least ${api_min_mib} MiB"
        [[ "$edition" == enterprise ]] && api_need_what="${api_need_what} on an enterprise install (Evidence Pack, NAN-5433)"
        api_effect="it would not stay up (it idles at about 210 MiB)"
        (( final_api_mib >= OPEN_API_MIN_MIB )) && api_effect="the Evidence Pack would refuse to run"
        sized_api_mib=$(mib_from_memory_string "$sized_api_mem_limit")
        if [[ -n "$api_mem_set_in" && "$NANO_API_MEM_LIMIT" != "$sized_api_mem_limit" ]] \
            && [[ -n "$sized_api_mib" ]] && (( sized_api_mib >= api_refuse_mib )); then
            # An explicit setting, not the host: name it and the floor.
            api_floor_fail "NANO_API_MEM_LIMIT=${NANO_API_MEM_LIMIT} (set in ${api_mem_set_in}) is below nano-api's minimum of ${api_refuse_mib} MiB${edition:+ on an ${edition} install}; ${api_effect}. Remove that setting so the installer sizes nano-api for this host (${sized_api_mem_limit}), or raise it to at least ${api_refuse_mib}M."
        else
            api_floor_fail "${api_need_what}, but this host's ${memory_mib} MiB of RAM leaves it only ${final_api_mib} MiB ($(( api_refuse_mib - final_api_mib )) MiB short) after the OS reserve and the other roles' minimums (roles ${roles}); ${api_effect}. Use a larger host (nano's minimum is 8 GB RAM, 16 GB with the enrichment feeds on) or move roles to other hosts."
        fi
    fi
    final_api_mcpu=$(mcpu_from_cpu_string "$NANO_API_CPU_LIMIT")
    if (( final_api_mcpu < API_MIN_MCPU )); then
        api_floor_fail "nano-api needs at least $(cpu_string "$API_MIN_MCPU") CPU, but this host's ${cpu_cores} CPU leave it only ${NANO_API_CPU_LIMIT} after the other roles' minimums (roles ${roles}). Use a host with more CPUs (nano's minimum is 2 vCPU) or move roles to other hosts."
    fi
fi

# NAN-5636: temporary data on disk. A GROUP BY / ORDER BY past the spill
# ratio (query_limits.xml) writes its overflow under /var/lib/clickhouse/tmp,
# on the same disk as the events, and nothing bounded it: one broad hunt could
# fill the disk and stop ingestion. A query may now spill at most 4x its memory
# limit (the spill exists so a query can finish past its memory, not so it can
# use the disk), all of one user's running queries twice that, and the whole
# server twice that again. Where the ClickHouse disk is known (its named
# volume sits on the Docker root filesystem the Vector probe measured: ingest
# and clickhouse on this host, named Vector storage), the caps are also held
# to 10 %, 20 % and 25 % of it. Over a cap the query fails on its own
# (TOO_MANY_ROWS_OR_BYTES); the server and every other query keep running.
# The server total matters: ClickHouse 26.10 counts an external ORDER BY only
# against it, not the per-query or per-user caps (measured on 26.10.4.207: a
# 236 MB sort spill ran past a 1 MiB per-query cap, a 3 MiB server cap
# stopped it). The per-query and per-user caps bound GROUP BY spills.
# Where the free space is known too (measured now, not at install), the
# server total is also held to half of it: on a disk already well into its
# retention, 25 % of the capacity can be more than is left. Otherwise the 25 %
# is headroom to keep free when sizing retention. An override wins for its
# own key; the derived keys follow it.
CH_TEMP_DISK_FLOOR_BYTES=1073741824
ch_temp_set_query=$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_QUERY
ch_temp_set_user=$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_USER
ch_temp_set_server=$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE
ch_temp_query=${ch_temp_set_query:-$(( CLICKHOUSE_MAX_MEMORY_USAGE * 4 ))}
if [[ -z "$ch_temp_set_query" && -n "$ch_data_capacity_bytes" ]]; then
    ch_temp_query=$(min "$ch_temp_query" "$(( ch_data_capacity_bytes / 10 ))")
fi
ch_temp_user=${ch_temp_set_user:-$(( ch_temp_query * 2 ))}
if [[ -z "$ch_temp_set_user" && -n "$ch_data_capacity_bytes" ]]; then
    ch_temp_user=$(min "$ch_temp_user" "$(( ch_data_capacity_bytes / 5 ))")
fi
ch_temp_server=${ch_temp_set_server:-$(( ch_temp_user * 2 ))}
if [[ -z "$ch_temp_set_server" ]]; then
    [[ -n "$ch_data_capacity_bytes" ]] && ch_temp_server=$(min "$ch_temp_server" "$(( ch_data_capacity_bytes / 4 ))")
    [[ -n "$ch_data_free_bytes" ]] && ch_temp_server=$(min "$ch_temp_server" "$(( ch_data_free_bytes / 2 ))")
fi
[[ -z "$ch_temp_set_user" ]] && ch_temp_user=$(min "$ch_temp_user" "$ch_temp_server")
[[ -z "$ch_temp_set_query" ]] && ch_temp_query=$(min "$ch_temp_query" "$ch_temp_user")
[[ -z "$ch_temp_set_query" ]] && ch_temp_query=$(max "$ch_temp_query" "$CH_TEMP_DISK_FLOOR_BYTES")
[[ -z "$ch_temp_set_user" ]] && ch_temp_user=$(max "$ch_temp_user" "$ch_temp_query")
[[ -z "$ch_temp_set_server" ]] && ch_temp_server=$(max "$ch_temp_server" "$ch_temp_user")
CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_QUERY=$ch_temp_query
CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_USER=$ch_temp_user
CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE=$ch_temp_server
if (( ch_temp_query > ch_temp_user || ch_temp_user > ch_temp_server )); then
    printf 'resource sizing warning: the ClickHouse spill caps should grow per query <= per user <= server (CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_QUERY=%s, _FOR_USER=%s, CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE=%s); the smallest one applies first\n' \
        "$ch_temp_query" "$ch_temp_user" "$ch_temp_server" >&2
fi

# ClickHouse 26.10 rejects a server configuration when its fixed MergeTree
# admission thresholds exceed the autosized merge/mutation slot count
# (background_pool_size * concurrency_ratio). Scale those thresholds down for
# small hosts while retaining the upstream defaults at 64 or more slots. Leave
# at least one slot available for foreground/background work.
ch_merge_slots=$(( CLICKHOUSE_BACKGROUND_POOL_SIZE * CLICKHOUSE_BACKGROUND_MERGES_MUTATIONS_CONCURRENCY_RATIO ))
ch_merge_threshold_max=$(( ch_merge_slots - 1 ))
(( ch_merge_threshold_max < 1 )) && ch_merge_threshold_max=1
ch_lower_merge_threshold=$(( (ch_merge_slots + 3) / 4 ))
(( ch_lower_merge_threshold > 8 )) && ch_lower_merge_threshold=8
(( ch_lower_merge_threshold > ch_merge_threshold_max )) && ch_lower_merge_threshold=$ch_merge_threshold_max
ch_mutation_threshold=$(( (ch_merge_slots * 5 + 7) / 8 ))
(( ch_mutation_threshold > 20 )) && ch_mutation_threshold=20
(( ch_mutation_threshold > ch_merge_threshold_max )) && ch_mutation_threshold=$ch_merge_threshold_max
ch_optimize_threshold=$(( (ch_merge_slots * 25 + 31) / 32 ))
(( ch_optimize_threshold > 25 )) && ch_optimize_threshold=25
(( ch_optimize_threshold > ch_merge_threshold_max )) && ch_optimize_threshold=$ch_merge_threshold_max

# NAN-5345: ClickHouse tier settings. Each block is empty below the ~1 TB/day
# tier, so an install without a planned volume renders exactly as before.
tier_server_lines=""
tier_merge_tree_lines=""
tier_ingestion_lines=""
if (( tiered )); then
    if [[ "$sizing_tier" == xlarge ]]; then
        ch_parts_to_delay=5000; ch_parts_to_throw=10000; ch_flush_max_ms=10000
    else
        ch_parts_to_delay=2000; ch_parts_to_throw=4000; ch_flush_max_ms=5000
    fi
    # Merges stop taking new work above half of the server's memory, so a
    # merge backlog at volume cannot crowd out inserts and queries.
    tier_server_lines="  <merges_mutations_memory_usage_to_ram_ratio>0.5</merges_mutations_memory_usage_to_ram_ratio>
"
    # Server merge_tree defaults: they apply to every table, so a table
    # rebuilt by a migration keeps them (table-level ALTERs do not).
    tier_merge_tree_lines="    <parts_to_delay_insert>$ch_parts_to_delay</parts_to_delay_insert>
    <parts_to_throw_insert>$ch_parts_to_throw</parts_to_throw_insert>
"
    # Adaptive flush between 1 s and the tier ceiling, with larger buffers.
    # async_insert_busy_timeout_ms is the ceiling's alias the base profile sets.
    tier_ingestion_lines="      <async_insert_use_adaptive_busy_timeout>1</async_insert_use_adaptive_busy_timeout>
      <async_insert_busy_timeout_min_ms>1000</async_insert_busy_timeout_min_ms>
      <async_insert_busy_timeout_ms>$ch_flush_max_ms</async_insert_busy_timeout_ms>
      <async_insert_max_data_size>268435456</async_insert_max_data_size>
"
fi

# NAN-5915: lighter ClickHouse system logging on small hosts. ClickHouse
# advises turning off metric_log, asynchronous_metric_log and text_log under
# 16 GB; clickhouse/config.d/system_logs.xml keeps them on for every size.
# Under 8 GiB of ClickHouse memory (the final limit, an override included):
#   * text_log is removed. Nothing in nano reads it; the same warnings stay
#     in the server log files.
#   * metric_log samples every 60 s instead of 10 s and both metric logs
#     flush every 60 s instead of 7.5 s: 8x fewer small parts to write and
#     merge. They stay on because SIEM Health's shard-skew probe reads them
#     (nanosiem-core siem_health/shard_skew.rs, 5-minute buckets), and 60 s
#     samples still fill those buckets.
# A later config.d file merges element by element, so these keep the
# database, table and TTL from system_logs.xml. 8 GiB and up: unchanged.
CH_LIGHT_SYSTEM_LOGS_BELOW_MIB=8192
ch_final_mib=$(mib_from_memory_string "$CLICKHOUSE_MEM_LIMIT")
[[ -n "$ch_final_mib" ]] || ch_final_mib=$ch_mib
small_system_log_lines=""
if (( ch_final_mib < CH_LIGHT_SYSTEM_LOGS_BELOW_MIB )); then
    small_system_log_lines='  <text_log remove="1"/>
  <metric_log>
    <collect_interval_milliseconds>60000</collect_interval_milliseconds>
    <flush_interval_milliseconds>60000</flush_interval_milliseconds>
  </metric_log>
  <asynchronous_metric_log>
    <flush_interval_milliseconds>60000</flush_interval_milliseconds>
  </asynchronous_metric_log>
'
fi

if [[ -n "$server_output" ]]; then
    mkdir -p "$(dirname "$server_output")"
    cat > "$server_output" <<EOF
<?xml version="1.0"?>
<!-- Generated by scripts/lib/resource-sizing.sh (NAN-4997). -->
<clickhouse>
  <max_server_memory_usage_to_ram_ratio>$CLICKHOUSE_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO</max_server_memory_usage_to_ram_ratio>
  <mark_cache_size>$CLICKHOUSE_MARK_CACHE_SIZE</mark_cache_size>
  <uncompressed_cache_size>$CLICKHOUSE_UNCOMPRESSED_CACHE_SIZE</uncompressed_cache_size>
  <index_mark_cache_size>$CLICKHOUSE_INDEX_MARK_CACHE_SIZE</index_mark_cache_size>
  <index_uncompressed_cache_size>$CLICKHOUSE_INDEX_UNCOMPRESSED_CACHE_SIZE</index_uncompressed_cache_size>
  <background_pool_size>$CLICKHOUSE_BACKGROUND_POOL_SIZE</background_pool_size>
  <background_merges_mutations_concurrency_ratio>$CLICKHOUSE_BACKGROUND_MERGES_MUTATIONS_CONCURRENCY_RATIO</background_merges_mutations_concurrency_ratio>
  <background_schedule_pool_size>$CLICKHOUSE_BACKGROUND_SCHEDULE_POOL_SIZE</background_schedule_pool_size>
  <background_fetches_pool_size>$CLICKHOUSE_BACKGROUND_FETCHES_POOL_SIZE</background_fetches_pool_size>
  <background_move_pool_size>$CLICKHOUSE_BACKGROUND_MOVE_POOL_SIZE</background_move_pool_size>
  <background_common_pool_size>$CLICKHOUSE_BACKGROUND_COMMON_POOL_SIZE</background_common_pool_size>
${tier_server_lines}  <merge_tree>
    <number_of_free_entries_in_pool_to_lower_max_size_of_merge>$ch_lower_merge_threshold</number_of_free_entries_in_pool_to_lower_max_size_of_merge>
    <number_of_free_entries_in_pool_to_execute_mutation>$ch_mutation_threshold</number_of_free_entries_in_pool_to_execute_mutation>
    <number_of_free_entries_in_pool_to_execute_optimize_entire_partition>$ch_optimize_threshold</number_of_free_entries_in_pool_to_execute_optimize_entire_partition>
${tier_merge_tree_lines}  </merge_tree>
  <max_concurrent_queries>$CLICKHOUSE_MAX_CONCURRENT_QUERIES</max_concurrent_queries>
  <max_concurrent_insert_queries>$CLICKHOUSE_MAX_CONCURRENT_INSERT_QUERIES</max_concurrent_insert_queries>
  <max_concurrent_select_queries>$CLICKHOUSE_MAX_CONCURRENT_SELECT_QUERIES</max_concurrent_select_queries>
  <concurrent_threads_scheduler>round_robin</concurrent_threads_scheduler>
  <async_insert_threads>$CLICKHOUSE_ASYNC_INSERT_THREADS</async_insert_threads>
  <max_temporary_data_on_disk_size>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE</max_temporary_data_on_disk_size>
${small_system_log_lines}</clickhouse>
EOF
    chmod 644 "$server_output"
fi

if [[ -n "$users_output" ]]; then
    mkdir -p "$(dirname "$users_output")"
    cat > "$users_output" <<EOF
<?xml version="1.0"?>
<!-- Generated by scripts/lib/resource-sizing.sh (NAN-4997). -->
<clickhouse>
  <profiles>
    <default>
      <max_memory_usage>$CLICKHOUSE_MAX_MEMORY_USAGE</max_memory_usage>
      <max_memory_usage_for_user>$CLICKHOUSE_MAX_MEMORY_USAGE_FOR_USER</max_memory_usage_for_user>
      <max_threads>$CLICKHOUSE_MAX_THREADS</max_threads>
      <max_insert_threads>$CLICKHOUSE_MAX_INSERT_THREADS</max_insert_threads>
      <max_temporary_data_on_disk_size_for_query>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_QUERY</max_temporary_data_on_disk_size_for_query>
      <max_temporary_data_on_disk_size_for_user>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_USER</max_temporary_data_on_disk_size_for_user>
    </default>
    <dict_source>
      <max_temporary_data_on_disk_size_for_query>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_USER</max_temporary_data_on_disk_size_for_query>
    </dict_source>
    <search>
      <constraints><max_temporary_data_on_disk_size_for_query><min>1</min><max>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_QUERY</max></max_temporary_data_on_disk_size_for_query><max_temporary_data_on_disk_size_for_user><min>1</min><max>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_USER</max></max_temporary_data_on_disk_size_for_user></constraints>
    </search>
    <analytics>
      <max_memory_usage>$CLICKHOUSE_ANALYTICS_MAX_MEMORY_USAGE</max_memory_usage>
      <max_memory_usage_for_user>$CLICKHOUSE_ANALYTICS_MAX_MEMORY_USAGE_FOR_USER</max_memory_usage_for_user>
      <max_threads>$CLICKHOUSE_ANALYTICS_MAX_THREADS</max_threads>
      <max_temporary_data_on_disk_size_for_query>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_QUERY</max_temporary_data_on_disk_size_for_query>
      <max_temporary_data_on_disk_size_for_user>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_USER</max_temporary_data_on_disk_size_for_user>
    </analytics>
    <realtime>
      <max_memory_usage>$CLICKHOUSE_REALTIME_MAX_MEMORY_USAGE</max_memory_usage>
      <max_memory_usage_for_user>$CLICKHOUSE_REALTIME_MAX_MEMORY_USAGE_FOR_USER</max_memory_usage_for_user>
      <max_threads>$CLICKHOUSE_REALTIME_MAX_THREADS</max_threads>
      <max_temporary_data_on_disk_size_for_query>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_QUERY</max_temporary_data_on_disk_size_for_query>
      <max_temporary_data_on_disk_size_for_user>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_USER</max_temporary_data_on_disk_size_for_user>
    </realtime>
    <ingestion>
      <max_memory_usage>$CLICKHOUSE_INGEST_MAX_MEMORY_USAGE</max_memory_usage>
      <max_memory_usage_for_user>$CLICKHOUSE_INGEST_MAX_MEMORY_USAGE_FOR_USER</max_memory_usage_for_user>
      <max_threads>$CLICKHOUSE_INGEST_MAX_THREADS</max_threads>
      <max_insert_threads>$CLICKHOUSE_INGEST_MAX_THREADS</max_insert_threads>
      <max_temporary_data_on_disk_size_for_query>0</max_temporary_data_on_disk_size_for_query>
      <max_temporary_data_on_disk_size_for_user>0</max_temporary_data_on_disk_size_for_user>
${tier_ingestion_lines}    </ingestion>
    <admin>
      <max_memory_usage>$CLICKHOUSE_ADMIN_MAX_MEMORY_USAGE</max_memory_usage>
      <max_memory_usage_for_user>$CLICKHOUSE_ADMIN_MAX_MEMORY_USAGE_FOR_USER</max_memory_usage_for_user>
      <max_threads>$CLICKHOUSE_ANALYTICS_MAX_THREADS</max_threads>
      <max_temporary_data_on_disk_size_for_query>0</max_temporary_data_on_disk_size_for_query>
      <max_temporary_data_on_disk_size_for_user>0</max_temporary_data_on_disk_size_for_user>
    </admin>
    <rawsql>
      <max_memory_usage>$CLICKHOUSE_MAX_MEMORY_USAGE</max_memory_usage>
      <max_memory_usage_for_user>$CLICKHOUSE_MAX_MEMORY_USAGE_FOR_USER</max_memory_usage_for_user>
      <max_threads>$CLICKHOUSE_MAX_THREADS</max_threads>
      <max_temporary_data_on_disk_size_for_query>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_QUERY</max_temporary_data_on_disk_size_for_query>
      <max_temporary_data_on_disk_size_for_user>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_USER</max_temporary_data_on_disk_size_for_user>
      <constraints><max_threads><max>$CLICKHOUSE_MAX_THREADS</max></max_threads><max_temporary_data_on_disk_size_for_query><min>1</min><max>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_QUERY</max></max_temporary_data_on_disk_size_for_query><max_temporary_data_on_disk_size_for_user><min>1</min><max>$CLICKHOUSE_MAX_TEMPORARY_DATA_ON_DISK_SIZE_FOR_USER</max></max_temporary_data_on_disk_size_for_user></constraints>
    </rawsql>
  </profiles>
</clickhouse>
EOF
    chmod 644 "$users_output"
fi

for key in $SIZING_KEYS; do
    case "$operator_keys" in
        # (Keys only derived after the overrides, such as the ClickHouse
        # spill caps, have no pre-override value: those print the final one.)
        *" $key "*) presized="presized_$key"; printf '%s=%s\n' "$key" "${!presized:-${!key}}" ;;
        *) printf '%s=%s\n' "$key" "${!key}" ;;
    esac
done

# NAN-5345: planning keys exist only when the operator declared a volume, so
# an install without one emits exactly the keys it always did.
if (( planned_gb_per_day > 0 )); then
    printf 'NANO_SIZING_PLANNED_GB_PER_DAY=%s\n' "$planned_gb_per_day"
    printf 'NANO_SIZING_INGEST_PATH=%s\n' "$ingest_path"
    printf 'NANO_SIZING_TIER=%s\n' "$sizing_tier"
    # Prevalence *_final_refresh cadence (clickhouse_migrator, NAN-5345): each
    # run scans the recent working set, so it runs less often at volume.
    # Without this key the migrator converges on the shipped 10 minutes, so
    # clearing the volume resets a cadence a large tier lengthened.
    case "$sizing_tier" in
        xlarge) printf 'NANO_PREVALENCE_REFRESH_MINUTES=60\n' ;;
        large) printf 'NANO_PREVALENCE_REFRESH_MINUTES=30\n' ;;
        *) printf 'NANO_PREVALENCE_REFRESH_MINUTES=10\n' ;;
    esac
    if has_role ingest; then
        if [[ "$ingest_path" == raw ]]; then
            events_per_core=$VECTOR_RAW_EVENTS_PER_CORE
        else
            events_per_core=$VECTOR_PRESHAPED_EVENTS_PER_CORE
        fi
        # Average events/s first, so the products stay well inside 64 bits.
        planned_eps=$(ceil_div "$(( planned_gb_per_day * 1000000000 ))" "$(( 86400 * avg_event_bytes ))")
        needed_vector_mcpu=$(ceil_div "$(( VECTOR_PEAK_FACTOR * planned_eps * 1000 ))" "$events_per_core")
        printf 'NANO_SIZING_AVG_EVENT_BYTES=%s\n' "$avg_event_bytes"
        printf 'NANO_SIZING_EVENTS_PER_SEC=%s\n' "$planned_eps"
        # Capacity is what this host's Vector may use after any override.
        host_vector_mcpu=$(mcpu_from_cpu_string "$VECTOR_CPU_LIMIT")
        printf 'NANO_SIZING_VECTOR_VCPU_NEEDED=%s\n' "$(ceil_div "$needed_vector_mcpu" 1000)"
        printf 'NANO_SIZING_VECTOR_VCPU_PER_HOST=%s\n' "$VECTOR_CPU_LIMIT"
        printf 'NANO_SIZING_INGEST_HOSTS_NEEDED=%s\n' "$(max 1 "$(ceil_div "$needed_vector_mcpu" "$host_vector_mcpu")")"
    fi
    if (( tiered )); then
        # Compose parity with the Helm presets' 5 s Vector batch timeout.
        printf 'VECTOR_BATCH_TIMEOUT_SECS=5\n'
    fi
fi
