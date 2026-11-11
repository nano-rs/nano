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
override_env=""
server_output=""
users_output=""
cli_overrides=""

fail() {
    printf 'resource sizing error: %s\n' "$*" >&2
    exit 2
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
  --override-env PATH          Apply sizing keys from an operator .env
  --override KEY=VALUE         Apply an inventory override (repeatable)
  --server-output PATH         Write the ClickHouse server override XML
  --users-output PATH          Write the ClickHouse profile override XML
  --format env                 Emit stable KEY=VALUE lines (default)
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
        --override-env) [[ $# -ge 2 ]] || fail "--override-env needs a path"; override_env="$2"; shift 2 ;;
        --override)
            [[ $# -ge 2 && "$2" == *=* ]] || fail "--override needs KEY=VALUE"
            cli_overrides="${cli_overrides}${cli_overrides:+
}$2"
            shift 2 ;;
        --server-output) [[ $# -ge 2 ]] || fail "--server-output needs a path"; server_output="$2"; shift 2 ;;
        --users-output) [[ $# -ge 2 ]] || fail "--users-output needs a path"; users_output="$2"; shift 2 ;;
        --format) [[ $# -ge 2 ]] || fail "--format needs a value"; format="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown option $1" ;;
    esac
done

[[ "$topology" == single || "$topology" == role ]] || fail "--topology must be single or role"
[[ "$format" == env ]] || fail "only --format env is supported"
[[ "$shards" =~ ^[1-9][0-9]*$ ]] || fail "--shards must be a positive integer"

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

detect_vector_data_capacity_bytes() {
    local docker_root="" capacity_kib="" probe_image="" locked_probe_image=""
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
    probe_image=$(awk '
        /^  vector:$/ { in_vector = 1; next }
        in_vector && /^  [^ ]/ { exit }
        in_vector && /^[[:space:]]+image:[[:space:]]+/ {
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
        locked_probe_image=$(awk '
            $1 ~ /^ghcr\.io\/nano-rs\/vector:/ && $2 ~ /^sha256:[0-9a-f]+$/ {
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
        --mount type=volume,dst=/var/lib/vector \
        --entrypoint /bin/df \
        "$probe_image" -Pk /var/lib/vector 2>/dev/null \
        | awk 'NR == 2 { print $2 }') || return 1
    [[ "$capacity_kib" =~ ^[1-9][0-9]*$ ]] || return 1
    printf '%s\n' "$(( capacity_kib * 1024 ))"
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

[[ -n "$vector_data_capacity_bytes" ]] \
    || vector_data_capacity_bytes="${NANO_VECTOR_DATA_CAPACITY_BYTES:-}"
vector_data_storage_mode="${NANO_VECTOR_DATA_STORAGE_MODE:-named}"
case "$vector_data_storage_mode" in
    named|bind) ;;
    *) fail "NANO_VECTOR_DATA_STORAGE_MODE must be named or bind" ;;
esac
if has_role ingest; then
    if [[ -z "$vector_data_capacity_bytes" && "$vector_data_storage_mode" == bind ]]; then
        fail "Vector data uses bind/external storage whose capacity differs from DockerRootDir; set NANO_VECTOR_DATA_CAPACITY_BYTES or pass --vector-data-capacity-bytes"
    fi
    [[ -n "$vector_data_capacity_bytes" ]] \
        || vector_data_capacity_bytes=$(detect_vector_data_capacity_bytes) \
        || fail "cannot query the Docker daemon for the filesystem capacity backing Vector; set NANO_VECTOR_DATA_CAPACITY_BYTES or pass --vector-data-capacity-bytes"
else
    # Inactive-profile values are emitted for stable compose interpolation but
    # no Vector process runs on this host. Keep them deterministic without
    # requiring Docker storage discovery on app/database-only roles.
    [[ -n "$vector_data_capacity_bytes" ]] || vector_data_capacity_bytes=68719476736
fi
[[ "$vector_data_capacity_bytes" =~ ^[1-9][0-9]*$ ]] \
    || fail "Vector data filesystem capacity must be a positive integer byte count"

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

ch_cores=$(ceil_div "$ch_mcpu" 1000)
ch_cores=$(clamp "$ch_cores" 2 64)
if (( ch_mib <= 4096 )); then
    ch_background_pool=2
    ch_background_ratio=2
    ch_async_threads=2
    ch_concurrent=50
    ch_concurrent_insert=20
    ch_concurrent_select=30
    ch_background_schedule=4
else
    ch_background_pool=$(clamp "$(( ch_cores * 2 ))" 4 64)
    (( ch_cores >= 8 )) && ch_background_ratio=4 || ch_background_ratio=2
    ch_async_threads=$(clamp "$(( (ch_cores + 1) / 2 ))" 2 32)
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
if has_role app && has_role postgres && (( memory_mib <= 4096 )); then
    # Three co-located application processes use this pool cap independently.
    # 3x8 leaves ample server slots for migrations, autovacuum and operators.
    pg_connections=50
    pg_pool_max=8
    pg_pool_min=1
else
    pg_connections=$(clamp "$(( pg_cores * 50 ))" 100 1000)
    pg_pool_max=20
    pg_pool_min=2
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

POSTGRES_MEM_LIMIT=$(memory_string "$pg_mib")
POSTGRES_CPU_LIMIT=$(cpu_string "$pg_mcpu")
POSTGRES_MAX_CONNECTIONS=$pg_connections
POSTGRES_SHARED_BUFFERS="${pg_shared_mib}MB"
POSTGRES_EFFECTIVE_CACHE_SIZE="${pg_effective_mib}MB"
POSTGRES_WORK_MEM="${pg_work_mib}MB"
PG_MAX_CONNECTIONS=$pg_pool_max
PG_MIN_CONNECTIONS=$pg_pool_min

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
CONNECTOR_MEM_LIMIT=$(memory_string "$(max 256 "$api_mib")")
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

SIZING_KEYS='CLICKHOUSE_MEM_LIMIT CLICKHOUSE_CPU_LIMIT CLICKHOUSE_MAX_THREADS CLICKHOUSE_ANALYTICS_MAX_THREADS CLICKHOUSE_REALTIME_MAX_THREADS CLICKHOUSE_INGEST_MAX_THREADS CLICKHOUSE_MAX_INSERT_THREADS CLICKHOUSE_BACKGROUND_POOL_SIZE CLICKHOUSE_BACKGROUND_MERGES_MUTATIONS_CONCURRENCY_RATIO CLICKHOUSE_BACKGROUND_SCHEDULE_POOL_SIZE CLICKHOUSE_BACKGROUND_FETCHES_POOL_SIZE CLICKHOUSE_BACKGROUND_MOVE_POOL_SIZE CLICKHOUSE_BACKGROUND_COMMON_POOL_SIZE CLICKHOUSE_MAX_CONCURRENT_QUERIES CLICKHOUSE_MAX_CONCURRENT_INSERT_QUERIES CLICKHOUSE_MAX_CONCURRENT_SELECT_QUERIES CLICKHOUSE_ASYNC_INSERT_THREADS CLICKHOUSE_MARK_CACHE_SIZE CLICKHOUSE_UNCOMPRESSED_CACHE_SIZE CLICKHOUSE_INDEX_MARK_CACHE_SIZE CLICKHOUSE_INDEX_UNCOMPRESSED_CACHE_SIZE CLICKHOUSE_MAX_MEMORY_USAGE CLICKHOUSE_MAX_MEMORY_USAGE_FOR_USER CLICKHOUSE_MAX_SERVER_MEMORY_USAGE_TO_RAM_RATIO CLICKHOUSE_ANALYTICS_MAX_MEMORY_USAGE CLICKHOUSE_ANALYTICS_MAX_MEMORY_USAGE_FOR_USER CLICKHOUSE_REALTIME_MAX_MEMORY_USAGE CLICKHOUSE_REALTIME_MAX_MEMORY_USAGE_FOR_USER CLICKHOUSE_INGEST_MAX_MEMORY_USAGE CLICKHOUSE_INGEST_MAX_MEMORY_USAGE_FOR_USER CLICKHOUSE_ADMIN_MAX_MEMORY_USAGE CLICKHOUSE_ADMIN_MAX_MEMORY_USAGE_FOR_USER POSTGRES_MEM_LIMIT POSTGRES_CPU_LIMIT POSTGRES_MAX_CONNECTIONS POSTGRES_SHARED_BUFFERS POSTGRES_EFFECTIVE_CACHE_SIZE POSTGRES_WORK_MEM PG_MAX_CONNECTIONS PG_MIN_CONNECTIONS VECTOR_MEM_LIMIT VECTOR_CPU_LIMIT VECTOR_CLICKHOUSE_REQUEST_CONCURRENCY VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES_PER_SHARD VECTOR_DISK_BUFFER_TOTAL_BUDGET_BYTES VECTOR_DISK_BUFFER_COUNT VECTOR_DISK_BUFFER_MAX_BYTES VECTOR_DATA_CAPACITY_BYTES VECTOR_DISK_HEADROOM_BYTES VECTOR_BATCH_MAX_BYTES VECTOR_BATCH_MAX_EVENTS VECTOR_MEMORY_BUFFER_MAX_EVENTS NANO_API_MEM_LIMIT NANO_API_CPU_LIMIT NANO_SEARCH_MEM_LIMIT NANO_SEARCH_CPU_LIMIT NANO_JOBS_MEM_LIMIT NANO_JOBS_CPU_LIMIT VALKEY_MEM_LIMIT VALKEY_CPU_LIMIT VALKEY_MAXMEMORY VALKEY_IO_THREADS NANO_WEB_MEM_LIMIT NANO_WEB_CPU_LIMIT NANO_NGINX_MEM_LIMIT NANO_NGINX_CPU_LIMIT CONNECTOR_MEM_LIMIT CONNECTOR_CPU_LIMIT NANO_MIGRATE_MEM_LIMIT NANO_MIGRATE_CPU_LIMIT NANO_VECTOR_TAP_MEM_LIMIT NANO_VECTOR_TAP_CPU_LIMIT NANO_VECTOR_CONSUMER_MEM_LIMIT NANO_VECTOR_CONSUMER_CPU_LIMIT NANO_INGEST_EDGE_MEM_LIMIT NANO_INGEST_EDGE_CPU_LIMIT NANO_CLICKHOUSE_PROXY_MEM_LIMIT NANO_CLICKHOUSE_PROXY_CPU_LIMIT KEEPER_MEM_LIMIT KEEPER_CPU_LIMIT TENZIR_MEM_LIMIT TENZIR_CPU_LIMIT NANO_SIZING_DIR NANO_DETECTED_CPU_CORES NANO_DETECTED_MEMORY_MIB NANO_SIZING_TOPOLOGY'

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

if [[ -n "$override_env" ]]; then
    [[ -f "$override_env" ]] || fail "override env does not exist: $override_env"
    apply_legacy_overrides legacy_value_from_file
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line%$'\r'}
        [[ "$line" == *=* ]] || continue
        key=${line%%=*}; value=${line#*=}
        is_sizing_key "$key" || continue
        case "$key" in
            NANO_SIZING_DIR|NANO_SIZING_TOPOLOGY|NANO_DETECTED_CPU_CORES|NANO_DETECTED_MEMORY_MIB|\
            VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES|VECTOR_CLICKHOUSE_BUFFER_MAX_BYTES_PER_SHARD|\
            VECTOR_DISK_BUFFER_TOTAL_BUDGET_BYTES|VECTOR_DISK_BUFFER_COUNT|\
            VECTOR_DISK_BUFFER_MAX_BYTES|VECTOR_DATA_CAPACITY_BYTES|VECTOR_DISK_HEADROOM_BYTES) continue ;;
        esac
        value=${value#\"}; value=${value%\"}; value=${value#\'}; value=${value%\'}
        [[ -n "$value" ]] && apply_override "$key" "$value"
    done < "$override_env"
fi

# The invoking environment is the normal one-shot override path. It wins over
# .env, matching Docker Compose interpolation semantics.
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
    while IFS= read -r assignment; do
        [[ -n "$assignment" ]] || continue
        apply_override "${assignment%%=*}" "${assignment#*=}"
    done <<< "$cli_overrides"
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
  <merge_tree>
    <number_of_free_entries_in_pool_to_lower_max_size_of_merge>$ch_lower_merge_threshold</number_of_free_entries_in_pool_to_lower_max_size_of_merge>
    <number_of_free_entries_in_pool_to_execute_mutation>$ch_mutation_threshold</number_of_free_entries_in_pool_to_execute_mutation>
    <number_of_free_entries_in_pool_to_execute_optimize_entire_partition>$ch_optimize_threshold</number_of_free_entries_in_pool_to_execute_optimize_entire_partition>
  </merge_tree>
  <max_concurrent_queries>$CLICKHOUSE_MAX_CONCURRENT_QUERIES</max_concurrent_queries>
  <max_concurrent_insert_queries>$CLICKHOUSE_MAX_CONCURRENT_INSERT_QUERIES</max_concurrent_insert_queries>
  <max_concurrent_select_queries>$CLICKHOUSE_MAX_CONCURRENT_SELECT_QUERIES</max_concurrent_select_queries>
  <concurrent_threads_scheduler>round_robin</concurrent_threads_scheduler>
  <async_insert_threads>$CLICKHOUSE_ASYNC_INSERT_THREADS</async_insert_threads>
</clickhouse>
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
    </default>
    <analytics>
      <max_memory_usage>$CLICKHOUSE_ANALYTICS_MAX_MEMORY_USAGE</max_memory_usage>
      <max_memory_usage_for_user>$CLICKHOUSE_ANALYTICS_MAX_MEMORY_USAGE_FOR_USER</max_memory_usage_for_user>
      <max_threads>$CLICKHOUSE_ANALYTICS_MAX_THREADS</max_threads>
    </analytics>
    <realtime>
      <max_memory_usage>$CLICKHOUSE_REALTIME_MAX_MEMORY_USAGE</max_memory_usage>
      <max_memory_usage_for_user>$CLICKHOUSE_REALTIME_MAX_MEMORY_USAGE_FOR_USER</max_memory_usage_for_user>
      <max_threads>$CLICKHOUSE_REALTIME_MAX_THREADS</max_threads>
    </realtime>
    <ingestion>
      <max_memory_usage>$CLICKHOUSE_INGEST_MAX_MEMORY_USAGE</max_memory_usage>
      <max_memory_usage_for_user>$CLICKHOUSE_INGEST_MAX_MEMORY_USAGE_FOR_USER</max_memory_usage_for_user>
      <max_threads>$CLICKHOUSE_INGEST_MAX_THREADS</max_threads>
      <max_insert_threads>$CLICKHOUSE_INGEST_MAX_THREADS</max_insert_threads>
    </ingestion>
    <admin>
      <max_memory_usage>$CLICKHOUSE_ADMIN_MAX_MEMORY_USAGE</max_memory_usage>
      <max_memory_usage_for_user>$CLICKHOUSE_ADMIN_MAX_MEMORY_USAGE_FOR_USER</max_memory_usage_for_user>
      <max_threads>$CLICKHOUSE_ANALYTICS_MAX_THREADS</max_threads>
    </admin>
    <rawsql>
      <max_memory_usage>$CLICKHOUSE_MAX_MEMORY_USAGE</max_memory_usage>
      <max_memory_usage_for_user>$CLICKHOUSE_MAX_MEMORY_USAGE_FOR_USER</max_memory_usage_for_user>
      <max_threads>$CLICKHOUSE_MAX_THREADS</max_threads>
      <constraints><max_threads><max>$CLICKHOUSE_MAX_THREADS</max></max_threads></constraints>
    </rawsql>
  </profiles>
</clickhouse>
EOF
    chmod 644 "$users_output"
fi

for key in $SIZING_KEYS; do
    printf '%s=%s\n' "$key" "${!key}"
done
