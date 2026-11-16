# shellcheck shell=bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Host size check (NAN-5506). install.sh sources this file and runs
# nano_host_minimums_gate before any prompt or .env write, so a host that is
# too small fails in the first second with a plain sentence instead of after
# every prompt (resource sizing's Vector disk error) or not at all (a 160 MiB
# nano-api that restart-loops).
#
# These numbers are the single source of truth for the installer; the
# app.nano.rs portal and the "Size the host" docs table show the same ones.
#
# Hard floor, refused (a host that already runs nano only gets a warning):
#   * fewer than 2 vCPU (4 when app and ClickHouse share the host with Keeper
#     or Tenzir, e.g. the ocsf+tenzir single node: resource sizing cannot fit
#     every service's CPU floor on 2)
#   * less than 8 GB RAM (MemTotal under 7.5 GiB; firmware and the kernel keep
#     a few percent of a nominal 8 GB VM) on a host that runs ClickHouse, or
#     an app host that also runs ingest or Tenzir
#   * less than 16 GB RAM (MemTotal under 15 GiB) on a host that runs
#     ClickHouse beside the app, ingest, PostgreSQL or Tenzir roles while the
#     enrichment feeds are on (PLATFORM_FEEDS_AUTO_UPDATE not false): their
#     ClickHouse dictionaries need CLICKHOUSE_MEM_LIMIT=6G, and resource sizing
#     only gives ClickHouse 6 GiB on such a host from 12 GiB up
#   * less than 4 GB RAM (resource sizing's own 3840 MiB class floor) on any
#     other role-split host (app, ingest, PostgreSQL, Keeper, Tenzir alone or
#     app beside PostgreSQL), plus 1 GB when it also runs monitoring
#   * less than 40 GB free on the filesystem holding Docker's data
#     (`docker info -f '{{.DockerRootDir}}'`, where Vector's named volume and
#     ClickHouse live) on a host that runs ClickHouse; 20 GB on other hosts.
#     Resource sizing needs at least 18 GiB of capacity there for Vector's
#     buffers and its fixed 16 GiB of reserves beside ClickHouse.
#     When Vector's data is on other storage (NANO_VECTOR_DATA_CAPACITY_BYTES,
#     NANO_VECTOR_DATA_FREE_BYTES), that declared size is checked too.
#
# Recommended for the planned volume (NANO_PLANNED_GB_PER_DAY; warning only,
# single-host installs): up to 5 GB/day 4 vCPU / 16 GB, up to 15 GB/day
# 8 / 32, up to 50 GB/day 16 / 64, up to 100 GB/day 16-32 / 64-128, above
# that a role-split or Kubernetes install. Disk for retention x volume is
# install.sh's report_retention_fit (scripts/lib/retention-sizing.sh).
#
# CPU and RAM are measured the way resource-sizing.sh measures them:
# NANO_SIZING_CPU_CORES / NANO_SIZING_MEMORY_MIB when set, then the Docker
# daemon (NCPU, MemTotal), then nproc/getconf or /proc/meminfo, then sysctl.
#
# NANO_SKIP_HOST_MINIMUMS=1 installs anyway, with a loud warning; such a host
# is unsupported. Test seam: NANO_HOST_MEMINFO_PATH replaces /proc/meminfo
# when NANO_INSTALLER_TEST_MODE=1; tests fake docker, nproc and df on PATH.
#
# The caller provides log/ok/warn/fail (install.sh's).

NANO_HOST_MIN_CPU=2
# App and ClickHouse beside Keeper or Tenzir (the ocsf+tenzir single node).
NANO_HOST_MIN_CPU_CROWDED=4
NANO_HOST_MIN_RAM_GB=8
NANO_HOST_MIN_RAM_MIB=7680
NANO_HOST_MIN_ENRICHMENT_RAM_GB=16
NANO_HOST_MIN_ENRICHMENT_RAM_MIB=15360
NANO_HOST_MIN_SMALL_ROLE_RAM_GB=4
NANO_HOST_MIN_SMALL_ROLE_RAM_MIB=3840
NANO_HOST_MIN_MONITORING_RAM_MIB=1024
NANO_HOST_MIN_DISK_GB=40
NANO_HOST_MIN_SMALL_ROLE_DISK_GB=20
# NAN-5509: Docker 29's containerd image store keeps images in containerd's
# root (/var/lib/containerd), not under DockerRootDir. When that is another
# filesystem it must hold one release's images plus the next upgrade's.
NANO_HOST_MIN_IMAGE_DISK_GB=20
# Single-node / all-in-one roles when install.sh runs without --role.
NANO_HOST_SINGLE_NODE_ROLES=app,ingest,clickhouse,postgres

# GiB with one decimal ("9.6") from a MiB count.
nano_host_min_gb_from_mib() {
    local tenths=$(( ($1 * 10 + 512) / 1024 ))
    printf '%d.%d\n' "$(( tenths / 10 ))" "$(( tenths % 10 ))"
}

nano_host_min_has_role() {
    case ",$1," in *,"$2",*) return 0 ;; *) return 1 ;; esac
}

nano_host_min_detect_cpu() {
    local detected="${NANO_SIZING_CPU_CORES:-}"
    if [[ ! "$detected" =~ ^[1-9][0-9]*$ ]] && command -v docker >/dev/null 2>&1; then
        detected=$(docker info --format '{{.NCPU}}' </dev/null 2>/dev/null || true)
    fi
    if [[ ! "$detected" =~ ^[1-9][0-9]*$ ]] && command -v nproc >/dev/null 2>&1; then
        detected=$(nproc 2>/dev/null || true)
    fi
    if [[ ! "$detected" =~ ^[1-9][0-9]*$ ]] && command -v getconf >/dev/null 2>&1; then
        detected=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    fi
    if [[ ! "$detected" =~ ^[1-9][0-9]*$ ]] && command -v sysctl >/dev/null 2>&1; then
        detected=$(sysctl -n hw.logicalcpu 2>/dev/null || true)
    fi
    [[ "$detected" =~ ^[1-9][0-9]*$ ]] && printf '%s\n' "$detected"
}

nano_host_min_detect_memory_mib() {
    local bytes="" kb="" meminfo=/proc/meminfo
    if [[ "${NANO_SIZING_MEMORY_MIB:-}" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s\n' "$NANO_SIZING_MEMORY_MIB"
        return
    fi
    if command -v docker >/dev/null 2>&1; then
        bytes=$(docker info --format '{{.MemTotal}}' </dev/null 2>/dev/null || true)
    fi
    if [[ "$bytes" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s\n' "$(( (bytes + 524288) / 1048576 ))"
        return
    fi
    if [[ "${NANO_INSTALLER_TEST_MODE:-0}" == "1" && -n "${NANO_HOST_MEMINFO_PATH:-}" ]]; then
        meminfo="$NANO_HOST_MEMINFO_PATH"
    fi
    kb=$(awk '/^MemTotal:/ { print $2; exit }' "$meminfo" 2>/dev/null || true)
    if [[ "$kb" =~ ^[1-9][0-9]*$ ]]; then
        printf '%s\n' "$(( (kb + 512) / 1024 ))"
        return
    fi
    bytes=""
    command -v sysctl >/dev/null 2>&1 && bytes=$(sysctl -n hw.memsize 2>/dev/null || true)
    [[ "$bytes" =~ ^[1-9][0-9]*$ ]] && printf '%s\n' "$(( (bytes + 524288) / 1048576 ))"
}

# Free KiB on the filesystem holding PATH (df's Available column), or nothing.
nano_host_min_free_kib() {
    local free
    [[ -e "$1" ]] || return 0
    free=$(df -Pk "$1" 2>/dev/null | awk 'NR == 2 { print $4 }')
    [[ "$free" =~ ^[0-9]+$ ]] && printf '%s\n' "$free"
}

# Mount point and device of the filesystem holding PATH ("<mount> <device>").
nano_host_min_mount() {
    df -Pk "$1" 2>/dev/null | awk 'NR == 2 { print $6, $1 }'
}

# containerd's root directory when Docker stores images in containerd (the
# containerd image store, the default from Docker 29), else nothing.
# NANO_CONTAINERD_ROOT overrides the path read from /etc/containerd/config.toml.
nano_host_min_containerd_root() {
    local status root=""
    command -v docker >/dev/null 2>&1 || return 0
    status=$(docker info --format '{{json .DriverStatus}}' </dev/null 2>/dev/null || true)
    [[ "$status" == *io.containerd.snapshotter* ]] || return 0
    if [[ -n "${NANO_CONTAINERD_ROOT:-}" ]]; then
        root="$NANO_CONTAINERD_ROOT"
    elif [[ -r /etc/containerd/config.toml ]]; then
        root=$(awk -F'"' '/^[[:space:]]*root[[:space:]]*=/ { print $2; exit }' /etc/containerd/config.toml)
    fi
    printf '%s\n' "${root:-/var/lib/containerd}"
}

# The commands that grow a filesystem after its disk was enlarged, for the
# filesystem holding PATH ("" when its device is not a plain partition).
nano_host_min_grow_hint() {
    local mount device disk part
    read -r mount device <<<"$(nano_host_min_mount "$1")"
    [[ -n "$device" ]] || return 0
    if [[ "$device" =~ ^(/dev/(nvme[0-9]+n[0-9]+|mmcblk[0-9]+))p([0-9]+)$ ]]; then
        disk="${BASH_REMATCH[1]}" part="${BASH_REMATCH[3]}"
    elif [[ "$device" =~ ^(/dev/[a-z]+)([0-9]+)$ ]]; then
        disk="${BASH_REMATCH[1]}" part="${BASH_REMATCH[2]}"
    else
        return 0
    fi
    printf 'sudo growpart %s %s, then sudo resize2fs %s (ext4) or sudo xfs_growfs %s (XFS)\n' "$disk" "$part" "$device" "$mount"
}

# True unless PLATFORM_FEEDS_AUTO_UPDATE turns the enrichment feeds off. On a
# single node the environment wins over .env, as in Docker Compose
# interpolation (install.sh then records it in .env).
nano_host_min_feeds_on() {
    local env_file="${1:-.env}" value="${PLATFORM_FEEDS_AUTO_UPDATE:-}"
    # A role-split cluster shares one .env; install.sh records a value given
    # for the run only on a single node, so only the shared file counts there.
    [[ "${MULTI_NODE:-0}" == "1" ]] && value=""
    if [[ -z "$value" && -f "$env_file" ]]; then
        value=$(awk -F= '
            { sub(/\r$/, "") }
            $1 == "PLATFORM_FEEDS_AUTO_UPDATE" { value = substr($0, 28) }
            END { gsub(/["\047 \t]/, "", value); print value }
        ' "$env_file")
    fi
    case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
        0|false|no|off) return 1 ;;
        *) return 0 ;;
    esac
}

# Sets HM_CPU, HM_RAM_MIB, HM_RAM_GB, HM_DISK_GB, HM_ENRICHMENT (1 when the
# 16 GB enrichment floor applies) and HM_HOST (a description) for ROLES.
nano_host_min_requirements() {
    local roles="$1" others=0 role
    HM_CPU=$NANO_HOST_MIN_CPU
    HM_ENRICHMENT=0
    for role in app ingest postgres tenzir; do
        nano_host_min_has_role "$roles" "$role" && others=1
    done
    if nano_host_min_has_role "$roles" clickhouse && nano_host_min_has_role "$roles" app \
        && { nano_host_min_has_role "$roles" keeper || nano_host_min_has_role "$roles" tenzir; }; then
        # Resource sizing cannot fit every service's CPU floor on 2 vCPU here.
        HM_CPU=$NANO_HOST_MIN_CPU_CROWDED
    fi
    if nano_host_min_has_role "$roles" clickhouse; then
        HM_RAM_MIB=$NANO_HOST_MIN_RAM_MIB
        HM_RAM_GB=$NANO_HOST_MIN_RAM_GB
        HM_DISK_GB=$NANO_HOST_MIN_DISK_GB
        (( others )) && HM_ENRICHMENT=1
    elif nano_host_min_has_role "$roles" app \
        && { nano_host_min_has_role "$roles" ingest || nano_host_min_has_role "$roles" tenzir; }; then
        # The app share alone must fund nano-api (1 GiB on enterprise) beside
        # Vector's ~1.2 GiB target; resource sizing refuses a 4 GB app+ingest host.
        HM_RAM_MIB=$NANO_HOST_MIN_RAM_MIB
        HM_RAM_GB=$NANO_HOST_MIN_RAM_GB
        HM_DISK_GB=$NANO_HOST_MIN_SMALL_ROLE_DISK_GB
    else
        HM_RAM_MIB=$NANO_HOST_MIN_SMALL_ROLE_RAM_MIB
        HM_RAM_GB=$NANO_HOST_MIN_SMALL_ROLE_RAM_GB
        HM_DISK_GB=$NANO_HOST_MIN_SMALL_ROLE_DISK_GB
        if nano_host_min_has_role "$roles" monitoring; then
            HM_RAM_MIB=$(( HM_RAM_MIB + NANO_HOST_MIN_MONITORING_RAM_MIB ))
            HM_RAM_GB=$(( HM_RAM_GB + NANO_HOST_MIN_MONITORING_RAM_MIB / 1024 ))
        fi
    fi
    if [[ "$roles" == "$NANO_HOST_SINGLE_NODE_ROLES" ]]; then
        HM_HOST="a single-node install"
    elif [[ "$roles" == "$NANO_HOST_SINGLE_NODE_ROLES,tenzir" ]]; then
        HM_HOST="a single-node install with the bundled Tenzir node"
    else
        HM_HOST="a host with role(s) $roles"
    fi
}

# Recommended "CPU RAM_GB label" for a planned GB/day (docs "Size the host").
nano_host_min_recommended() {
    local gb="$1"
    if (( gb <= 0 )); then return 0
    elif (( gb <= 5 )); then printf '4 16 up to 5 GB/day\n'
    elif (( gb <= 15 )); then printf '8 32 6-15 GB/day\n'
    elif (( gb <= 50 )); then printf '16 64 16-50 GB/day\n'
    elif (( gb <= 100 )); then printf '16 64 50-100 GB/day (16-32 vCPU / 64-128 GB)\n'
    else printf '32 128 over 100 GB/day\n'
    fi
}

# True when this install directory already runs nano: a .env and at least one
# container (any state) or volume of its Compose project.
nano_host_min_existing_install() {
    local dir="$1" project="${COMPOSE_PROJECT_NAME:-}" ids="" file
    [[ -f "$dir/.env" ]] || return 1
    command -v docker >/dev/null 2>&1 || return 1
    # The role env (a role-split host) is read last, so it wins.
    for file in "$dir/.env" "$dir/.nano-role.env"; do
        [[ -z "${COMPOSE_PROJECT_NAME:-}" && -f "$file" ]] || continue
        ids=$(awk -F= '
            { sub(/\r$/, "") }
            $1 == "COMPOSE_PROJECT_NAME" { value = substr($0, 22) }
            END { gsub(/["\047 \t]/, "", value); print value }
        ' "$file" 2>/dev/null || true)
        [[ -n "$ids" ]] && project=$ids
    done
    ids=""
    [[ -n "$project" ]] || project=$(basename "$dir" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
    ids=$(docker ps -aq --filter "label=com.docker.compose.project=$project" </dev/null 2>/dev/null || true)
    [[ -n "$ids" ]] && return 0
    ids=$(docker ps -aq --filter "label=com.docker.compose.project.working_dir=$dir" </dev/null 2>/dev/null || true)
    [[ -n "$ids" ]] && return 0
    # After `docker compose down` (or a rebuilt host with restored volumes) the
    # data volumes remain; a copied role-split .env has none.
    ids=$(docker volume ls -q --filter "label=com.docker.compose.project=$project" </dev/null 2>/dev/null || true)
    [[ -n "$ids" ]]
}

# Fills HM_PROBLEMS (refusals) and HM_NOTES (warnings) for ROLES, an install
# directory (for .env) and the Docker data directory ("" when unknown).
nano_host_min_evaluate() {
    local roles="$1" env_file="$2" docker_root="$3"
    local cpu mem free_kib free_mib need_mib vector_bytes feeds=1 gb
    HM_PROBLEMS=()
    HM_NOTES=()
    HM_DISK_SHORT=()
    nano_host_min_requirements "$roles"
    nano_host_min_feeds_on "$env_file" || feeds=0
    cpu=$(nano_host_min_detect_cpu || true)
    mem=$(nano_host_min_detect_memory_mib || true)
    HM_DETECTED_CPU=$cpu
    HM_DETECTED_MEM_MIB=$mem

    if [[ -z "$cpu" ]]; then
        HM_NOTES+=("Could not count this host's CPUs; skipped the ${HM_CPU} vCPU minimum.")
    elif (( cpu < HM_CPU )); then
        HM_PROBLEMS+=("nano needs at least ${HM_CPU} vCPU for ${HM_HOST}; this host has ${cpu}.")
    fi

    if [[ -z "$mem" ]]; then
        HM_NOTES+=("Could not read this host's RAM; skipped the ${HM_RAM_GB} GB minimum.")
    else
        gb=$(nano_host_min_gb_from_mib "$mem")
        if (( mem < HM_RAM_MIB )); then
            if (( HM_ENRICHMENT && feeds )); then
                HM_PROBLEMS+=("nano needs at least ${HM_RAM_GB} GB RAM for ${HM_HOST} (${NANO_HOST_MIN_ENRICHMENT_RAM_GB} GB with the enrichment feeds on); this host has ${gb} GB.")
            else
                HM_PROBLEMS+=("nano needs at least ${HM_RAM_GB} GB RAM for ${HM_HOST}; this host has ${gb} GB.")
            fi
        elif (( HM_ENRICHMENT && mem < NANO_HOST_MIN_ENRICHMENT_RAM_MIB )); then
            if (( feeds )); then
                HM_PROBLEMS+=("Enrichment needs ${NANO_HOST_MIN_ENRICHMENT_RAM_GB} GB RAM; this host has ${gb} GB. Use a larger host, or set PLATFORM_FEEDS_AUTO_UPDATE=false for a lab install.")
            else
                HM_NOTES+=("This host has ${gb} GB RAM: enough for a lab install with the enrichment feeds off (PLATFORM_FEEDS_AUTO_UPDATE=false), not for production. Events get no geo/ASN, Tor or ThreatFox enrichment; turning the feeds on needs ${NANO_HOST_MIN_ENRICHMENT_RAM_GB} GB.")
            fi
        fi
    fi

    need_mib=$(( HM_DISK_GB * 1024 ))
    if [[ -z "$docker_root" ]]; then
        HM_NOTES+=("Could not ask Docker where it keeps its data; skipped the ${HM_DISK_GB} GB free-disk minimum (resource sizing still checks Vector's disk).")
    else
        free_kib=$(nano_host_min_free_kib "$docker_root" || true)
        if [[ -z "$free_kib" ]]; then
            # Docker Desktop, rootless or a remote daemon: the path is not on
            # this machine. Resource sizing measures it from inside Docker.
            HM_NOTES+=("Docker's data directory ${docker_root} is not visible from this shell (Docker Desktop or a remote daemon); skipped the ${HM_DISK_GB} GB free-disk minimum.")
        else
            free_mib=$(( free_kib / 1024 ))
            if (( free_mib < need_mib )); then
                HM_PROBLEMS+=("nano needs at least ${HM_DISK_GB} GB free on ${docker_root}'s filesystem for ${HM_HOST}; this host has $(nano_host_min_gb_from_mib "$free_mib") GB.")
                HM_DISK_SHORT+=("$docker_root")
            fi
        fi
        # NAN-5509: the containerd image store pulls images into containerd's
        # root. On its own (smaller) filesystem, the pull ran out of space
        # after the gate had passed.
        local containerd_root containerd_free_kib
        containerd_root=$(nano_host_min_containerd_root)
        if [[ -n "$containerd_root" && -n "$free_kib" ]] \
            && [[ "$(nano_host_min_mount "$containerd_root")" != "$(nano_host_min_mount "$docker_root")" ]]; then
            containerd_free_kib=$(nano_host_min_free_kib "$containerd_root" || true)
            if [[ -n "$containerd_free_kib" ]] && (( containerd_free_kib / 1024 < NANO_HOST_MIN_IMAGE_DISK_GB * 1024 )); then
                HM_PROBLEMS+=("Docker keeps images in containerd's store at ${containerd_root}, on a different filesystem from ${docker_root}; nano needs at least ${NANO_HOST_MIN_IMAGE_DISK_GB} GB free there for its images, and it has $(nano_host_min_gb_from_mib "$(( containerd_free_kib / 1024 ))") GB.")
                HM_DISK_SHORT+=("$containerd_root")
            fi
        fi
    fi
    if nano_host_min_has_role "$roles" ingest; then
        vector_bytes="${NANO_VECTOR_DATA_FREE_BYTES:-${NANO_VECTOR_DATA_CAPACITY_BYTES:-}}"
        if [[ "$vector_bytes" =~ ^[0-9]+$ ]] && (( vector_bytes / 1048576 < need_mib )); then
            HM_PROBLEMS+=("nano needs at least ${HM_DISK_GB} GB free for Vector's data (NANO_VECTOR_DATA_FREE_BYTES / NANO_VECTOR_DATA_CAPACITY_BYTES); this host declares $(nano_host_min_gb_from_mib "$(( vector_bytes / 1048576 ))") GB.")
        fi
    fi
}

# install.sh's entry point. ROLES is the role list ("" = single node), DIR the
# install directory. Refuses an undersized fresh install; warns on an existing
# install, in prepare-only mode, or with NANO_SKIP_HOST_MINIMUMS=1.
nano_host_minimums_gate() {
    local roles="${1:-}" dir="$2" docker_root="" problem note mode=refuse profile
    if [[ -z "$roles" ]]; then
        roles=$NANO_HOST_SINGLE_NODE_ROLES
        # The bundled Tenzir node runs on the ocsf+tenzir single node.
        profile="${NANO_SCHEMA_PROFILE:-}"
        if [[ -z "$profile" && -f "$dir/.env" ]]; then
            profile=$(awk -F= '
                { sub(/\r$/, "") }
                $1 == "NANO_SCHEMA_PROFILE" { value = substr($0, 21) }
                END { gsub(/["\047 \t]/, "", value); print value }
            ' "$dir/.env")
        fi
        [[ "$profile" == ocsf+tenzir ]] && roles="$roles,tenzir"
        # An installed ocsf+tenzir node records ocsf plus the tenzir profile.
        if [[ "$roles" != *,tenzir && -f "$dir/.env" ]] \
            && grep -qE '^COMPOSE_PROFILES=.*tenzir' "$dir/.env"; then
            roles="$roles,tenzir"
        fi
    fi
    # shellcheck disable=SC2034 # read by install.sh (the post-prompt Tenzir check)
    HM_ROLES=$roles
    if command -v docker >/dev/null 2>&1; then
        docker_root=$(docker info --format '{{.DockerRootDir}}' </dev/null 2>/dev/null || true)
    fi
    nano_host_min_evaluate "$roles" "$dir/.env" "$docker_root"
    for note in "${HM_NOTES[@]+"${HM_NOTES[@]}"}"; do warn "$note"; done
    if (( ${#HM_PROBLEMS[@]} == 0 )); then
        ok "Host size: ${HM_DETECTED_CPU:-?} vCPU, $(nano_host_min_gb_from_mib "${HM_DETECTED_MEM_MIB:-0}") GB RAM meets the minimum for ${HM_HOST}"
        return 0
    fi
    case "$(printf '%s' "${NANO_SKIP_HOST_MINIMUMS:-0}" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) export NANO_SKIP_HOST_MINIMUMS=1 ;;
    esac
    if [[ "${NANO_SKIP_HOST_MINIMUMS:-0}" == "1" ]]; then
        mode=skip
    elif nano_host_min_existing_install "$dir"; then
        mode=existing
    elif [[ "${NANO_PREPARE_ONLY:-0}" == "1" ]]; then
        mode=prepare
    fi
    for problem in "${HM_PROBLEMS[@]}"; do
        if [[ "$mode" == refuse ]]; then
            printf '%s\n' "  - $problem" >&2
        else
            warn "$problem"
        fi
    done
    case "$mode" in
        skip)
            warn "NANO_SKIP_HOST_MINIMUMS=1: installing on a host below nano's minimum. This host is UNSUPPORTED: containers are sized below what they need and may restart-loop or lose data under load." ;;
        existing)
            # Resource sizing then renders this host's limits as before
            # (with a warning) instead of refusing an installed host.
            export NANO_SKIP_HOST_MINIMUMS=1
            warn "This host already runs nano, so the installer continues. It is below nano's minimum: move it to a larger host." ;;
        prepare)
            warn "Prepare-only run: nothing is refused now, but installing on this host will be." ;;
        *)
            nano_host_min_refusal_hints "$dir" >&2
            fail "This host is below nano's minimum size (above). Nothing was installed$([[ -d "$dir/.git" || -f "$dir/.nano-bundle" ]] && printf ' (the sources are in %s)' "$dir"). Use a larger host (on Docker Desktop, raise its CPU and memory under Settings > Resources), or install anyway (unsupported) with NANO_SKIP_HOST_MINIMUMS=1 as shown above." ;;
    esac
}

# NAN-5509: the exact commands to act on a refusal. `VAR=1 curl ... | bash`
# sets VAR for curl, not for the installer: the variable goes after the pipe.
nano_host_min_rerun() {
    local dir="$1" assignment="$2"
    if [[ -f "$dir/.nano-bundle" ]]; then
        printf '      cd %s && %s ./install.sh\n' "$dir" "$assignment"
    else
        printf '      curl -fsSL https://get.nano.rs | %s bash\n' "$assignment"
        printf '   or cd %s && %s ./install.sh\n' "$dir" "$assignment"
    fi
}

nano_host_min_refusal_hints() {
    local dir="$1" problem path grow seen=" "
    for problem in "${HM_PROBLEMS[@]}"; do
        if [[ "$problem" == *PLATFORM_FEEDS_AUTO_UPDATE=false* ]]; then
            printf '  A lab install with the enrichment feeds off fits this host:\n'
            nano_host_min_rerun "$dir" PLATFORM_FEEDS_AUTO_UPDATE=false
            break
        fi
    done
    for path in "${HM_DISK_SHORT[@]+"${HM_DISK_SHORT[@]}"}"; do
        [[ "$seen" == *" $path "* ]] && continue
        seen+="$path "
        grow=$(nano_host_min_grow_hint "$path")
        printf '  Short on disk at %s? If you resized the disk, grow the filesystem too%s. If the space is on another disk, mount it there (or move Docker'"'"'s data-root onto it).\n' \
            "$path" "${grow:+: $grow}"
    done
    printf '  To install anyway on this host (unsupported):\n'
    nano_host_min_rerun "$dir" NANO_SKIP_HOST_MINIMUMS=1
}

# Warns when a single-host install is smaller than the docs recommend for its
# planned volume (GB/day; 0 = not declared). Never refuses.
nano_host_minimums_recommend() {
    local gb="${1:-0}" roles="${2:-}" rec cpu mem want_cpu want_gb label
    [[ "$gb" =~ ^[0-9]+$ ]] || return 0
    [[ -z "$roles" || "$roles" == "$NANO_HOST_SINGLE_NODE_ROLES" ]] || return 0
    rec=$(nano_host_min_recommended "$gb")
    [[ -n "$rec" ]] || return 0
    read -r want_cpu want_gb label <<<"$rec"
    cpu=$(nano_host_min_detect_cpu || true)
    mem=$(nano_host_min_detect_memory_mib || true)
    [[ -n "$cpu" && -n "$mem" ]] || return 0
    # Same slack as the floors: a nominal N GB host reports about 94 % of it.
    if (( cpu < want_cpu || mem < want_gb * 1024 * 15 / 16 )); then
        if (( gb > 100 )); then
            warn "At ${gb} GB/day plan at least ${want_cpu} vCPU / ${want_gb} GB RAM on one host, and from about 1 TB/day a role-split or Kubernetes install; this host has ${cpu} vCPU / $(nano_host_min_gb_from_mib "$mem") GB. nano will install; watch ClickHouse CPU and memory in SIEM Health."
        else
            warn "For ${label} the docs recommend ${want_cpu} vCPU / ${want_gb} GB RAM; this host has ${cpu} vCPU / $(nano_host_min_gb_from_mib "$mem") GB (planned ${gb} GB/day). nano will install; watch ClickHouse CPU and memory in SIEM Health and grow the host if it falls behind."
        fi
    fi
}
