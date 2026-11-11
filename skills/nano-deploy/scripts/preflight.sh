#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# nano Self-run host preflight. READ-ONLY: it changes nothing on the host.
#
# Run it on a target host over SSH from the operator's workstation:
#   ssh -o BatchMode=yes USER@HOST 'bash -s' -- [options] < preflight.sh
#
# Exposure probe (run on a machine OUTSIDE the cluster, e.g. the workstation):
#   bash preflight.sh --exposure-probe 203.0.113.10,203.0.113.11 [--ports 5432,6379]
#   Tries every port that must never be reachable from outside the cluster and
#   WARNs for each one that answers. Docker-published ports bypass UFW/INPUT.
#
# Options:
#   --topology single|ha|ha3    single node, or role split (ha; ha3 is the same, kept for old notes)
#   --roles app,ingest,...      roles this host will run (role split); add "lb" for an HAProxy host
#   --min-cpu N                 required logical CPUs           (default: from the roles, see below)
#   --min-mem-gib N             required RAM in GiB              (default: from the roles)
#   --min-disk-gib N            required FREE GiB for Docker data (single node default 50)
#   --min-disk-size-gib N       required SIZE in GiB of the Docker data filesystem, as plan.py
#                               counts it (role split default: from the roles)
#   --print-minimums            print the minimums these options resolve to, and exit
#   --lab                       evaluation/test cluster: below-production size is a WARN, not a FAIL
#   --ports 80,443,8088         TCP ports that must be free (default by topology/roles)
#   --peers 10.0.0.2,10.0.0.3   other node addresses to test reachability (TCP 22)
#   --install-dir DIR           (default ~/nano) where the bundle will be extracted
#   --airgap                    images come from a local bundle; registry egress is informational
#
# Role-split default minimums are plan.py's volume-independent floors, added up
# per role the way the planner stacks roles (a test keeps the two equal). For a
# real plan, run each host with the exact flags `plan.py ... --preflight-args`
# prints: they carry that host's requirement at your volume. RAM minimums are
# in GiB as the OS reports them: 87.5 % of the nominal GB (a 16 GB VM shows ~15).
#   clickhouse 4 vCPU/32 GB/100 GiB (+2 vCPU with ingest) · postgres(+keeper) 4/14/100
#   app 4/16/50 · ingest 4/16/128 · keeper alone 1/4/0 · lb alone 2/2/10 (nothing extra beside postgres)
#   single node: 4 vCPU / 14 GiB / 50 GiB free (pass size.py's numbers)
#
# Output: one line per check, "CHECK <name> <PASS|WARN|FAIL> <detail>", then
# "SUMMARY pass=N warn=N fail=N". Exit status 0 when there is no FAIL, 1 otherwise.
set -u
LC_ALL=C
export LC_ALL

topology=single roles="" min_cpu="" min_mem="" min_disk="" min_disk_size="" ports="" peers="" install_dir="$HOME/nano" airgap=0
lab=0 probe="" print_minimums=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --topology) topology="$2"; shift 2 ;;
        --roles) roles="$2"; shift 2 ;;
        --min-cpu) min_cpu="$2"; shift 2 ;;
        --min-mem-gib) min_mem="$2"; shift 2 ;;
        --min-disk-gib) min_disk="$2"; shift 2 ;;
        --min-disk-size-gib) min_disk_size="$2"; shift 2 ;;
        --print-minimums) print_minimums=1; shift ;;
        --ports) ports="$2"; shift 2 ;;
        --peers) peers="$2"; shift 2 ;;
        --install-dir) install_dir="$2"; shift 2 ;;
        --airgap) airgap=1; shift ;;
        --lab) lab=1; shift ;;
        --exposure-probe) probe="$2"; shift 2 ;;
        --) shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[[ "$topology" == ha3 ]] && topology=ha
case "$topology" in single|ha) ;; *) echo "unknown topology: $topology (single or ha)" >&2; exit 2 ;; esac

pass=0 warn=0 fail=0
row() { # name status detail
    printf 'CHECK %-16s %-4s %s\n' "$1" "$2" "$3"
    case "$2" in PASS) pass=$((pass+1)) ;; WARN) warn=$((warn+1)) ;; FAIL) fail=$((fail+1)) ;; esac
}
have() { command -v "$1" >/dev/null 2>&1; }
tcp_open() { # host port: exit 0 when a TCP connection succeeds within ~2 s
    if have python3; then
        python3 -c 'import socket,sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close()
except OSError:
    sys.exit(1)' "$1" "$2" 2>/dev/null
    elif have timeout; then
        timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
    else
        bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
    fi
}

# Ports that only the cluster (or, for 80, only the load balancer) may reach.
SENSITIVE_PORTS=80,3000,8687,5432,8008,2379,2380,6379,26379,8123,9000,9009,9363,9181,9234
port_name() {
    case "$1" in
        80) echo "app/ingest edge (load balancer only)" ;; 3000) echo "private API" ;; 8687) echo "Vector tap relay" ;;
        5432) echo PostgreSQL ;; 8008) echo "Patroni REST" ;; 2379|2380) echo etcd ;; 6379) echo Valkey ;;
        26379) echo Sentinel ;; 8123|9000|9009|9363) echo ClickHouse ;; 9181|9234) echo Keeper ;; *) echo "port $1" ;;
    esac
}

if [[ -n "$probe" ]]; then
    printf 'PROBE from %s (must be a machine outside the cluster)\n' "$(hostname 2>/dev/null)"
    IFS=, read -r -a targets <<< "$probe"
    IFS=, read -r -a plist <<< "${ports:-$SENSITIVE_PORTS}"
    for target in "${targets[@]}"; do
        [[ -z "$target" ]] && continue
        open=""
        for p in "${plist[@]}"; do
            [[ -z "$p" ]] && continue
            tcp_open "$target" "$p" && open+="$p($(port_name "$p")) "
        done
        if [[ -z "$open" ]]; then
            row "exposed:$target" PASS "none of ${ports:-$SENSITIVE_PORTS} answer from this machine"
        else
            row "exposed:$target" WARN "REACHABLE from this non-cluster address: ${open}- restrict them in DOCKER-USER (bridge ports) and UFW (ClickHouse/Keeper); 80 is fine only if this machine is the load balancer"
        fi
    done
    printf 'SUMMARY pass=%d warn=%d fail=%d\n' "$pass" "$warn" "$fail"
    exit 0
fi

has_role() { [[ ",$roles," == *,$1,* ]]; }
[[ -z "$roles" && "$topology" == single ]] && roles=app,ingest,clickhouse,postgres
# Default minimums. Role split: plan.py's floors (CH_MIN_VCPU, CH_MIN_MEM_GIB,
# CH_EXTRA_GIB, APP_MIN, the smallest PG_TIERS row + Keeper + HA state, the
# dedicated-ingest floor), summed per role as the planner stacks them. Nominal
# GB here; the RAM check uses 87.5 % of it (plan.py MEM_REPORTED_FACTOR).
def_cpu=0 def_mem_gb=0 def_size=0
floor_add() { def_cpu=$((def_cpu + $1)); def_mem_gb=$((def_mem_gb + $2)); def_size=$((def_size + $3)); }
if [[ "$topology" == ha ]]; then
    if has_role clickhouse; then floor_add 4 32 100; has_role ingest && floor_add 2 0 0; fi
    has_role postgres && floor_add 4 14 100                       # + Keeper, etcd, Valkey, Sentinel
    has_role app && floor_add 4 16 50
    has_role ingest && ! has_role clickhouse && floor_add 4 16 128
    has_role keeper && ! has_role postgres && ! has_role clickhouse && floor_add 1 4 0
    # HAProxy beside PostgreSQL is already in the postgres floor; alone it is a small VM.
    if (( def_cpu == 0 )); then if has_role lb; then floor_add 2 2 10; else floor_add 4 16 50; fi; fi
    def_mem=$((def_mem_gb * 875 / 1000))
    min_disk_size=${min_disk_size:-$def_size}
    min_disk=${min_disk:-0}
else
    def_cpu=4 def_mem=14
    min_disk=${min_disk:-50}
fi
min_cpu=${min_cpu:-$def_cpu} min_mem=${min_mem:-$def_mem} min_disk_size=${min_disk_size:-0}
if (( print_minimums )); then
    printf 'MINIMUMS cpu=%s mem_gib=%s disk_free_gib=%s disk_size_gib=%s\n' "$min_cpu" "$min_mem" "$min_disk" "$min_disk_size"
    exit 0
fi
# Below the minimum: FAIL in production, WARN (named lab exception) with --lab.
short=FAIL; (( lab )) && short=WARN
if [[ -z "$ports" ]]; then
    case "$topology" in
        single) ports=80,443,8080,8088 ;;
        *)
            ports=""
            [[ ",$roles," == *,app,* ]] && ports+="80,3000,"
            [[ ",$roles," == *,ingest,* ]] && ports+="80,8687,"
            # Full HA (three postgres hosts) adds Patroni, etcd, Valkey and Sentinel on them.
            [[ ",$roles," == *,postgres,* ]] && ports+="5432,8008,2379,2380,6379,26379,"
            [[ ",$roles," == *,lb,* ]] && ports+="443,"
            [[ ",$roles," == *,clickhouse,* ]] && ports+="8123,9000,9009,9363,"
            [[ ",$roles," == *,keeper,* ]] && ports+="9181,9234,"
            ports=${ports%,}
            ;;
    esac
fi

vercmp_ge() { # $1 >= $2 (dotted numeric)
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]
}

printf 'HOST %s user=%s topology=%s roles=%s minimums=%s vCPU/%s GiB/disk %s GiB size, %s GiB free%s\n' \
    "$(hostname 2>/dev/null)" "$(id -un)" "$topology" "$roles" "$min_cpu" "$min_mem" "$min_disk_size" "$min_disk" \
    "$( (( lab )) && echo ' LAB (not for production)')"

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
else row cpu "$short" "$cpus logical CPUs, need $min_cpu$( (( lab )) && echo ' (lab exception)')"; fi
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
else row memory "$short" "${mem_gib} GiB, need $min_mem$( (( lab )) && echo ' (lab exception)')"; fi
if (( mem_gib < 14 )) && [[ ",$roles," == *,clickhouse,* ]]; then
    row enrichment WARN "under 14 GiB: the installer may size ClickHouse below the 6 GB the geo/ASN enrichment dictionaries need (a 12 GiB host measured 6084M); plan CLICKHOUSE_MEM_LIMIT=6G or PLATFORM_FEEDS_AUTO_UPDATE=false with the operator"
fi

# --- disk --------------------------------------------------------------------
docker_root=/var/lib/docker
if have docker && docker info >/dev/null 2>&1; then
    dr=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null) && [[ -n "$dr" ]] && docker_root=$dr
fi
dprobe=$docker_root
while [[ ! -e "$dprobe" && "$dprobe" != / ]]; do dprobe=$(dirname "$dprobe"); done
read -r disk_total disk_free < <(df -Pk "$dprobe" 2>/dev/null | awk 'NR==2 {print int($2/1048576), int($4/1048576)}')
disk_total=${disk_total:-0} disk_free=${disk_free:-0}
# Size (what plan.py counts) and free space are separate minimums; 0 means "not checked".
if (( disk_total >= min_disk_size && disk_free >= min_disk )); then
    row disk PASS "$dprobe: ${disk_total} GiB, ${disk_free} GiB free (need size $min_disk_size, free $min_disk)"
else
    row disk "$short" "$dprobe: ${disk_total} GiB, ${disk_free} GiB free; need size $min_disk_size, free $min_disk$( (( lab )) && echo ' (lab exception)')"
fi
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
    vercmp_ge "${pv:-0}" 3.9 || row python FAIL "python3 $pv is older than 3.9 (nano's upgrade and backup tools need 3.9 or later)"
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

# --- exposure: Docker-published ports bypass UFW ------------------------------------
# A role-split host publishes app, ingest, PostgreSQL, Patroni, etcd, Valkey and
# Sentinel through Docker, which UFW/INPUT never sees. On a host with a public
# address those ports reach the internet unless DOCKER-USER restricts them.
if [[ "$topology" == ha ]] && ! [[ "$roles" == lb ]]; then
    public=""
    if have ip; then
        while read -r addr; do
            addr=${addr%/*}
            case "$addr" in
                10.*|192.168.*|127.*|169.254.*|fe80:*|fd*|fc*|::1) continue ;;
                172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) continue ;;
            esac
            public+="$addr "
        done < <(ip -o addr show scope global 2>/dev/null | awk '{print $4}')
    fi
    filtered=unknown
    if have iptables && sudo -n true 2>/dev/null; then
        rules=$(sudo -n iptables -S DOCKER-USER 2>/dev/null || true)
        if grep -q -- '-j NANO-DOCKER' <<< "$rules" || grep -q -- '--ctorigdstport.*-j DROP' <<< "$rules"; then filtered=yes
        else filtered=no; fi
        # The earlier documented pattern dropped every packet to the port, so this
        # host's own containers could no longer connect OUT to another host's
        # PostgreSQL/etcd/Valkey (Patroni replication, etcd peering).
        nano=$(sudo -n iptables -S NANO-DOCKER 2>/dev/null || true)
        if grep -- '--ctorigdstport.*-j DROP' <<< "$rules"$'\n'"$nano" | grep -qv -- '--ctstate NEW' \
            || { [[ -n "$nano" ]] && ! grep -q -- '-i br-+ -j RETURN' <<< "$nano"; }; then
            row firewall-pattern WARN "DOCKER-USER has an earlier nano firewall pattern whose drops are not limited to NEW inbound connections from outside (the first version also stopped this host's containers connecting out to other hosts on those ports). Replace it with plan.py --firewall-script"
        fi
        if [[ "$filtered" == yes ]] && have systemctl && ! systemctl is-enabled nano-docker-firewall.service >/dev/null 2>&1; then
            row firewall-persist WARN "DOCKER-USER rules are not installed as nano-docker-firewall.service: they are lost at the next reboot. Apply plan.py --firewall-script"
        fi
    fi
    if have dpkg-query && dpkg-query -W -f='${Status}' iptables-persistent 2>/dev/null | grep -q 'install ok installed' \
        && ! dpkg-query -W -f='${Status}' ufw 2>/dev/null | grep -q 'install ok installed'; then
        row firewall-ufw WARN "iptables-persistent is installed and ufw is not (installing it removes ufw on Ubuntu/Debian): the ClickHouse/Keeper ufw rules are gone. Remove iptables-persistent, reinstall ufw, re-run plan.py --firewall-script"
    fi
    if ! have ip; then
        row exposure WARN "cannot list this host's addresses (no ip command); if it has a public address, Docker-published ports bypass UFW: apply plan.py --firewall-script and run --exposure-probe from outside"
    elif [[ -z "$public" && "$filtered" == yes ]]; then
        row exposure PASS "no public address on this host's interfaces and DOCKER-USER filters published ports (a cloud 1:1 NAT or floating IP is invisible from inside: verify with --exposure-probe from outside)"
    elif [[ -z "$public" ]]; then
        # Cloud 1:1 NAT (and floating IPs) map a public address to a
        # private interface address. Nothing on the host shows it, so "no public
        # address" is not evidence that Docker-published ports are unreachable.
        row exposure WARN "no public address on this host's interfaces, but a cloud 1:1 NAT or floating IP cannot be detected from inside the host. If the host is reachable on a public address, Docker-published ports bypass UFW: apply plan.py --firewall-script and run --exposure-probe <public addresses> from outside"
    elif [[ "$filtered" == yes ]]; then
        row exposure PASS "public address ${public% }; DOCKER-USER filters published ports (verify with --exposure-probe from outside)"
    elif [[ "$filtered" == no ]]; then
        row exposure WARN "public address ${public% } and DOCKER-USER has no nano rules: Docker-published ports (PostgreSQL, Valkey, etcd, Patroni, Sentinel, app/ingest) will bypass UFW and be reachable from the internet. Apply plan.py --firewall-script before installing"
    else
        row exposure WARN "public address ${public% }; cannot read DOCKER-USER without sudo. Docker-published ports bypass UFW: confirm the DOCKER-USER rules (plan.py --firewall-script) and run --exposure-probe from outside"
    fi
fi

# --- UFW and this host's own containers ----------------------------------------------
# ClickHouse, Keeper and etcd peers are reached on each host's private address,
# including from containers on the SAME host (clickhouse-proxy, Patroni). Those
# packets arrive from a Docker bridge (docker0, br-*). A default-deny UFW without
# an allow for the bridges drops them silently: the local ClickHouse replica is
# marked DOWN in clickhouse-proxy, nothing looks wrong, and losing the OTHER
# replica later stops every write.
if [[ "$topology" == ha ]] && ! [[ "$roles" == lb ]] && have ufw; then
    if sudo -n true 2>/dev/null; then
        ufw_status=$(sudo -n ufw status verbose 2>/dev/null || true)
        if ! grep -q '^Status: active' <<< "$ufw_status"; then
            row ufw PASS "UFW inactive (filter with DOCKER-USER and your own host firewall)"
        elif ! grep -qi 'deny (incoming)\|reject (incoming)' <<< "$ufw_status"; then
            row ufw PASS "UFW active, incoming policy not deny"
        elif grep -q ' on docker0' <<< "$ufw_status" && grep -q ' on br-+' <<< "$ufw_status"; then
            row ufw PASS "UFW default-deny with allows for docker0 and br-+ (this host's containers reach its own address)"
        else
            row ufw WARN "UFW denies incoming by default and has no allow for docker0/br-+: this host's own containers cannot reach its ClickHouse, Keeper or etcd ports on its private address. clickhouse-proxy then marks the LOCAL replica DOWN, and losing the other replica stops every write. Apply plan.py --firewall-script (it adds 'ufw allow in on docker0|br-+ to any port ...')"
        fi
    elif grep -qs '^ENABLED=yes' /etc/ufw/ufw.conf; then
        row ufw WARN "UFW is enabled; cannot read its rules without sudo. Make sure it allows docker0 and br-+ to the ClickHouse/Keeper/etcd ports (plan.py --firewall-script), or this host's own replica is silently unreachable"
    fi
fi

# --- outbound ------------------------------------------------------------------------
# Every registry host the installer and upgrades pull from (third-party images
# are NOT mirrored into the customer registry). Hosts come from the image
# locks in the bundle; each registry also needs its auth/blob hosts.
registry_hosts() {
    local lock hosts="" ref host
    for lock in "$install_dir/images.enterprise.customer.lock" "$install_dir/images.enterprise.lock" "$install_dir/images.lock"; do
        [[ -f "$lock" ]] || continue
        while read -r ref _; do
            [[ -z "$ref" || "$ref" == \#* ]] && continue
            host=${ref%%/*}
            [[ "$ref" == */* && ( "$host" == *.* || "$host" == *:* ) ]] || host=docker.io
            hosts+=" $host"
        done < "$lock"
    done
    # No bundle yet: the hosts the current enterprise release pulls from.
    # Role split also pulls etcd from quay.io (full HA).
    if [[ -z "$hosts" ]]; then
        hosts=" us-central1-docker.pkg.dev docker.io ghcr.io"
        [[ "$topology" == ha ]] && hosts+=" quay.io"
    fi
    for host in $hosts; do
        case "$host" in
            docker.io) printf '%s\n' registry-1.docker.io auth.docker.io production.cloudflare.docker.com ;;
            ghcr.io) printf '%s\n' ghcr.io pkg-containers.githubusercontent.com ;;
            quay.io) printf '%s\n' quay.io cdn01.quay.io cdn02.quay.io cdn03.quay.io ;;
            *) printf '%s\n' "$host" ;;
        esac
    done | sort -u
}
if have curl; then
    code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' https://api.nano.rs 2>/dev/null || true)
    if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then row "egress" PASS "https://api.nano.rs -> HTTP $code"
    else row "egress" WARN "https://api.nano.rs unreachable (licence check-in; fine only for an offline licence)"; fi
    # A blocked registry makes `docker compose pull` hang rather than fail
    # rather than fail, so test each host's HTTPS here, in seconds.
    while read -r host; do
        [[ -n "$host" ]] || continue
        code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' "https://$host/v2/" 2>/dev/null || true)
        if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then row "registry:$host" PASS "HTTPS reachable (HTTP $code)"
        elif (( airgap )); then row "registry:$host" WARN "HTTPS unreachable (expected for an air-gapped install)"
        else row "registry:$host" FAIL "outbound HTTPS to $host is blocked; image pulls will hang. Allow it (directly or via HTTPS_PROXY) or use the air-gapped bundle"; fi
    done < <(registry_hosts)
fi

printf 'SUMMARY pass=%d warn=%d fail=%d\n' "$pass" "$warn" "$fail"
(( fail == 0 ))
