#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# nano Self-run host preflight. READ-ONLY: it changes nothing on the host.
#
# Run it on a target host over SSH from the operator's workstation:
#   ssh -o BatchMode=yes USER@HOST 'bash -s' -- [options] < preflight.sh
#
# Options:
#   --topology single|ha3       (default single)
#   --roles app,ingest,...      roles this host will run (ha3; informational + AVX2/compose rules)
#   --min-cpu N                 required logical CPUs           (default 4)
#   --min-mem-gib N             required RAM in GiB              (default 14)
#   --min-disk-gib N            required free GiB for Docker data (default 50)
#   --ports 80,443,8088         TCP ports that must be free (default by topology/roles)
#   --peers 10.0.0.2,10.0.0.3   other node addresses to test reachability (TCP 22)
#   --install-dir DIR           (default ~/nano) where the bundle will be extracted
#
# Output: one line per check, "CHECK <name> <PASS|WARN|FAIL> <detail>", then
# "SUMMARY pass=N warn=N fail=N". Exit status 0 when there is no FAIL, 1 otherwise.
set -u
LC_ALL=C
export LC_ALL

topology=single roles="" min_cpu=4 min_mem=14 min_disk=50 ports="" peers="" install_dir="$HOME/nano"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --topology) topology="$2"; shift 2 ;;
        --roles) roles="$2"; shift 2 ;;
        --min-cpu) min_cpu="$2"; shift 2 ;;
        --min-mem-gib) min_mem="$2"; shift 2 ;;
        --min-disk-gib) min_disk="$2"; shift 2 ;;
        --ports) ports="$2"; shift 2 ;;
        --peers) peers="$2"; shift 2 ;;
        --install-dir) install_dir="$2"; shift 2 ;;
        --) shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[[ -z "$roles" && "$topology" == single ]] && roles=app,ingest,clickhouse,postgres
if [[ -z "$ports" ]]; then
    case "$topology" in
        single) ports=80,443,8080,8088 ;;
        *)
            ports=""
            [[ ",$roles," == *,app,* ]] && ports+="80,3000,"
            [[ ",$roles," == *,ingest,* ]] && ports+="80,8687,"
            [[ ",$roles," == *,postgres,* ]] && ports+="5432,"
            [[ ",$roles," == *,clickhouse,* ]] && ports+="8123,9000,9009,9363,"
            [[ ",$roles," == *,keeper,* ]] && ports+="9181,9234,"
            ports=${ports%,}
            ;;
    esac
fi

pass=0 warn=0 fail=0
row() { # name status detail
    printf 'CHECK %-16s %-4s %s\n' "$1" "$2" "$3"
    case "$2" in PASS) pass=$((pass+1)) ;; WARN) warn=$((warn+1)) ;; FAIL) fail=$((fail+1)) ;; esac
}
have() { command -v "$1" >/dev/null 2>&1; }
vercmp_ge() { # $1 >= $2 (dotted numeric)
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]
}

printf 'HOST %s user=%s topology=%s roles=%s\n' "$(hostname 2>/dev/null)" "$(id -un)" "$topology" "$roles"

# --- identity / privileges --------------------------------------------------
if [[ $(id -u) -eq 0 ]]; then
    row user FAIL "connected as root; use a non-root user with sudo (install.sh must not run as root or with sudo)"
else
    row user PASS "$(id -un) (uid $(id -u))"
fi
if have sudo && sudo -n true 2>/dev/null; then
    row sudo PASS "passwordless sudo available (only used for approved steps)"
elif have sudo; then
    row sudo WARN "sudo needs a password; approved privileged steps must be run interactively by the operator"
else
    row sudo WARN "sudo not installed; Docker install, firewall and TLS staging need root"
fi

# --- OS / virtualization ----------------------------------------------------
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    row os PASS "${PRETTY_NAME:-$ID} kernel $(uname -r) arch $(uname -m)"
else
    row os WARN "no /etc/os-release; kernel $(uname -r)"
fi
[[ "$(uname -s)" == Linux ]] || row platform FAIL "$(uname -s) is not Linux"
virt=$(systemd-detect-virt 2>/dev/null || true)
case "$virt" in
    lxc|lxc-libvirt|openvz) row virt WARN "container ($virt): Docker needs nesting enabled; ClickHouse in LXC is fine for labs, prefer a VM for production" ;;
    ""|none) row virt PASS "bare metal or unknown" ;;
    *) row virt PASS "$virt" ;;
esac

# --- CPU -------------------------------------------------------------------
cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 0)
if (( cpus >= min_cpu )); then row cpu PASS "$cpus logical CPUs (need $min_cpu)"
else row cpu FAIL "$cpus logical CPUs, need $min_cpu"; fi
needs_avx2=0
[[ ",$roles," == *,clickhouse,* || ",$roles," == *,keeper,* ]] && needs_avx2=1
if [[ "$(uname -m)" == x86_64 && $needs_avx2 == 1 ]]; then
    if grep -qw avx2 /proc/cpuinfo 2>/dev/null; then row avx2 PASS "AVX2 present (required by ClickHouse/Keeper)"
    else row avx2 FAIL "no AVX2: ClickHouse 26.6+ needs it (on Proxmox/VMware set CPU type host or x86-64-v3)"; fi
fi

# --- memory (smallest of physical and cgroup limit) ------------------------
mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
mem_bytes=$((mem_kib * 1024))
for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes; do
    if [[ -r $f ]]; then
        lim=$(cat "$f")
        [[ "$lim" =~ ^[0-9]+$ ]] && (( lim < mem_bytes )) && mem_bytes=$lim
    fi
done
mem_gib=$((mem_bytes / 1024 / 1024 / 1024))
if (( mem_gib >= min_mem )); then row memory PASS "${mem_gib} GiB (need $min_mem)"
else row memory FAIL "${mem_gib} GiB, need $min_mem"; fi
if (( mem_gib < 14 )) && [[ ",$roles," == *,clickhouse,* ]]; then
    row enrichment WARN "under 14 GiB: the installer may size ClickHouse below the 6 GB the geo/ASN enrichment dictionaries need (a 12 GiB host measured 6084M); plan CLICKHOUSE_MEM_LIMIT=6G or PLATFORM_FEEDS_AUTO_UPDATE=false with the operator"
fi

# --- disk --------------------------------------------------------------------
docker_root=/var/lib/docker
if have docker && docker info >/dev/null 2>&1; then
    dr=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null) && [[ -n "$dr" ]] && docker_root=$dr
fi
probe=$docker_root
while [[ ! -e "$probe" && "$probe" != / ]]; do probe=$(dirname "$probe"); done
read -r disk_total disk_free < <(df -Pk "$probe" 2>/dev/null | awk 'NR==2 {print int($2/1048576), int($4/1048576)}')
disk_total=${disk_total:-0} disk_free=${disk_free:-0}
if (( disk_free >= min_disk )); then row disk PASS "$probe: ${disk_free} GiB free of ${disk_total} GiB (need $min_disk)"
else row disk FAIL "$probe: ${disk_free} GiB free of ${disk_total} GiB, need $min_disk"; fi
home_free=$(df -Pk "$HOME" 2>/dev/null | awk 'NR==2 {print int($4/1048576)}')
(( ${home_free:-0} >= 5 )) || row disk-home WARN "$HOME has ${home_free:-0} GiB free; the bundle and backups staging need space"

# --- tools -------------------------------------------------------------------
missing=""
for t in curl openssl tar python3 ss; do have "$t" || missing+="$t "; done
[[ "$topology" == single ]] && { have git || missing+="git "; }
if [[ -z "$missing" ]]; then row tools PASS "curl openssl tar python3 ss$([[ $topology == single ]] && echo ' git')"
else row tools FAIL "missing: $missing"; fi
if have python3; then
    pv=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)
    vercmp_ge "${pv:-0}" 3.8 || row python FAIL "python3 $pv is older than 3.8"
fi

# --- docker --------------------------------------------------------------------
if have docker; then
    dv=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
    if [[ -z "$dv" ]]; then
        if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
            row docker FAIL "docker CLI present but the daemon is not reachable (is it running?)"
        else
            row docker FAIL "docker CLI present but $(id -un) cannot reach the daemon (add the user to the docker group, then log in again)"
        fi
    else
        if vercmp_ge "$dv" 24.0; then row docker PASS "Docker Engine $dv"
        else row docker WARN "Docker Engine $dv is old; 24+ recommended"; fi
        if docker info 2>/dev/null | grep -qi 'rootless'; then row docker-mode WARN "rootless Docker: not the tested path"; fi
    fi
    cv=$(docker compose version --short 2>/dev/null | sed 's/^v//' | cut -d- -f1)
    if [[ -z "$cv" ]]; then
        row compose FAIL "docker compose v2 plugin missing"
    elif [[ "$topology" != single ]] && ! vercmp_ge "$cv" 2.24.4; then
        row compose FAIL "Compose $cv; role-split installs need 2.24.4+"
    else
        row compose PASS "Compose $cv"
    fi
else
    row docker FAIL "Docker Engine not installed (install from Docker's official repository for $(. /etc/os-release 2>/dev/null; echo "${ID:-this OS}"))"
fi

# --- time sync -----------------------------------------------------------------
if have timedatectl && timedatectl show >/dev/null 2>&1; then
    ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
    if [[ "$ntp" == yes ]]; then row time PASS "NTP synchronized ($(date -u +%FT%TZ))"
    else row time WARN "NTP not synchronized per timedatectl ($(date -u +%FT%TZ)); upgrades refuse unsynchronized clocks"; fi
elif have chronyc && chronyc tracking >/dev/null 2>&1; then
    row time PASS "chrony tracking ($(date -u +%FT%TZ))"
else
    row time WARN "cannot verify time sync ($(date -u +%FT%TZ)); compare with the other hosts"
fi

# --- ports -----------------------------------------------------------------------
if have ss; then
    busy=""
    IFS=, read -r -a plist <<< "$ports"
    for p in "${plist[@]}"; do
        [[ -z "$p" ]] && continue
        if ss -Hltn "sport = :$p" 2>/dev/null | grep -q .; then
            owner=$(ss -Hltnp "sport = :$p" 2>/dev/null | grep -o 'users:(("[^"]*' | head -1 | sed 's/users:(("//')
            busy+="$p(${owner:-?}) "
        fi
    done
    if [[ -z "$busy" ]]; then row ports PASS "free: $ports"
    else row ports WARN "in use: $busy- fine only if they belong to an existing nano install on this host"; fi
fi

# --- existing install --------------------------------------------------------------
if [[ -f "$install_dir/.env" ]]; then
    mode=$(stat -c '%a' "$install_dir/.env" 2>/dev/null)
    ver=$(awk -F= '$1=="NANO_VERSION"{v=$2} END{print v}' "$install_dir/.env" 2>/dev/null)
    ed=$(awk -F= '$1=="NANO_EDITION"{v=$2} END{print v}' "$install_dir/.env" 2>/dev/null)
    role=""; [[ -f "$install_dir/.nano-role.env" ]] && role=" role-split"
    row existing WARN "existing install at $install_dir (edition=${ed:-?} version=${ver:-?}${role}, .env mode $mode): re-run/upgrade path, not a fresh install"
else
    row existing PASS "no install at $install_dir"
fi

# --- peers -------------------------------------------------------------------------
if [[ -n "$peers" ]]; then
    IFS=, read -r -a plist <<< "$peers"
    for peer in "${plist[@]}"; do
        if timeout 3 bash -c "exec 3<>/dev/tcp/$peer/22" 2>/dev/null; then row "peer:$peer" PASS "TCP 22 reachable"
        else row "peer:$peer" FAIL "TCP 22 unreachable from this host (private network/firewall)"; fi
    done
fi

# --- outbound ------------------------------------------------------------------------
if have curl; then
    for url in https://api.nano.rs https://us-central1-docker.pkg.dev/v2/; do
        code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' "$url" 2>/dev/null || true)
        if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then row "egress" PASS "$url -> HTTP $code"
        else row "egress" WARN "$url unreachable (fine only for an air-gapped install)"; fi
    done
fi

printf 'SUMMARY pass=%d warn=%d fail=%d\n' "$pass" "$warn" "$fail"
(( fail == 0 ))
