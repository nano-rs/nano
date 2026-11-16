#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# nano public benchmark: thin run script. Everything heavy is existing nano
# tooling: the enterprise bundle's install.sh and role-split renderer, the
# nano-deploy helpers (fetch-bundle, make-private-ca, admin-credentials),
# tools/log-blaster, and k6. This script only sequences them over SSH and
# turns the run into one results JSON (lib/collect.py).
#
#   benchmarks/public/run.sh <step> --topology benchmarks/public/topology/<name>/hosts.env [options]
#
# Steps (in order; each is safe to re-run):
#   prep        data disk -> /var/lib/docker, host firewall (cluster + operator only)
#   install     enterprise bundle, inventory, private TLS, shared .env, install.sh by role
#   content     parsers + log sources + ingest tokens + detection set + API key (+ Agent Lane tokens)
#   tools       build log-blaster (seeded) and install k6 on the blaster host(s)
#   smoke       one marker through every source; checks ingest -> searchable
#   socday      steady ingest at --gb-per-day + k6 SOC mix, for --duration
#   ceiling     stepped ramp until an SLO breaks (lag p99 > 60 s, loss, or errors)
#   collect     pull run artifacts + ClickHouse metrics -> results/<run>.json
#   all-dry     prep install content tools smoke socday ceiling (dry-run sizes)
#
# Secrets (license, admin password, ingest/API/Agent Lane tokens, registry
# credential) live only on the hosts in 0600 files. They are streamed host to
# host through this workstation's SSH pipes and are never printed or written
# locally. The private CA key stays in --pki (keep it out of the repo).
# Paths like "~/nano/.env" are expanded on the remote host, not here.
# shellcheck disable=SC2088
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DEPLOY="$REPO/skills/nano-deploy/scripts"

STEP="${1:-}"; shift || true
TOPOLOGY="" ; PKI="" ; ENROLL_FROM="" ; RUN_ID="" ; DURATION="10m" ; GBPD="50"
PROFILE="" ; AGENTS=0 ; OUT_DIR="$HERE/results" ; DURATION_SET=0 ; GBPD_SET=0 ; AGENTS_SET=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --topology) TOPOLOGY="$2"; shift 2 ;;
    --pki) PKI="$2"; shift 2 ;;
    --enrollment-cmd) ENROLL_FROM="$2"; shift 2 ;;   # a command that prints enrollment.env to stdout
    --run-id) RUN_ID="$2"; shift 2 ;;
    --duration) DURATION="$2"; DURATION_SET=1; shift 2 ;;
    --gb-per-day) GBPD="$2"; GBPD_SET=1; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --agents) AGENTS="$2"; AGENTS_SET=1; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    -h|--help) sed -n 2,30p "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ -n "$STEP" && -n "$TOPOLOGY" ]] || { sed -n 2,30p "$0"; exit 2; }
# shellcheck disable=SC1090
. "$TOPOLOGY"
: "${BENCH_NAME:?}" "${SSH_KEY:?}" "${APP:?}" "${CH:?}" "${INGEST:?}" "${BLASTER:?}"
# A profile (profiles/*.json) sets the seeded blaster and load parameters;
# explicit CLI flags still win.
if [[ -n "$PROFILE" ]]; then
  [[ -f "$PROFILE" ]] || PROFILE="$HERE/profiles/$PROFILE.json"
  CLI_DURATION="$DURATION"; CLI_AGENTS="$AGENTS"
  eval "$(python3 -c 'import json,shlex,sys
for k, v in json.load(open(sys.argv[1])).items():
    if k.isupper(): print(f"{k}={shlex.quote(str(v))}")' "$PROFILE")"
  [[ "$DURATION_SET" == 1 ]] && DURATION="$CLI_DURATION"
  [[ "$AGENTS_SET" == 1 ]] && AGENTS="$CLI_AGENTS"
  [[ "$GBPD_SET" == 1 ]] || GBPD="${GB_PER_DAY:-$GBPD}"
fi
SSH_USER="${SSH_USER:-ubuntu}"
NANO_VERSION="${NANO_VERSION:-2.0.23}"
SEED="${SEED:-20261114}"
RUN_ID="${RUN_ID:-${BENCH_NAME}-$(date -u +%Y%m%dT%H%M%SZ)}"
# The run id lands in file names and ClickHouse string literals: keep it plain.
[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "--run-id may only use letters, digits, '.', '_' and '-'" >&2; exit 2; }
read -r -a CH_HOSTS <<<"$CH"; read -r -a INGEST_HOSTS <<<"$INGEST"; read -r -a BLASTERS <<<"$BLASTER"
NANO_HOSTS=("$APP" "${CH_HOSTS[@]}" "${INGEST_HOSTS[@]}")
ALL_HOSTS=("${NANO_HOSTS[@]}" "${BLASTERS[@]}")
KH="${KNOWN_HOSTS:-$(dirname "$SSH_KEY")/known_hosts}"
SSHO=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KH" -o ConnectTimeout=15 -o ServerAliveInterval=30)
LOCK="images.enterprise.customer.lock"
# From 2.0.30 the enterprise install.sh defaults to the customer lock and logs
# in to the registry itself with the license in .env (a private temporary
# DOCKER_CONFIG; ~/.docker is never touched). 2.0.29 and earlier need the lock
# named and a docker login on every host first.
ver_ge() { # $1 >= $2, dotted numeric
  local x="${1#v}" y="${2#v}" a b i
  [[ "${x%%-*}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "NANO_VERSION must look like 2.0.30 (got '$1')" >&2; exit 2; }
  IFS=. read -r -a a <<<"${x%%-*}"; IFS=. read -r -a b <<<"${y%%-*}"
  for i in 0 1 2; do
    (( 10#${a[i]:-0} > 10#${b[i]:-0} )) && return 0
    (( 10#${a[i]:-0} < 10#${b[i]:-0} )) && return 1
  done
  return 0
}
if ver_ge "$NANO_VERSION" 2.0.30; then SELF_LOGIN=1; LOCK_ENV=""; else SELF_LOGIN=0; LOCK_ENV="NANO_IMAGES_LOCK=$LOCK"; fi

say() { printf '\033[1m[%s %s]\033[0m %s\n' "$(date -u +%H:%M:%S)" "$STEP" "$*"; }
r() { local h="$1"; shift; ssh "${SSHO[@]}" "$SSH_USER@$h" "$@"; }
# Stream a file between hosts without it touching this workstation's disk.
pipe() { r "$1" "cat $2" | r "$3" "umask 077 && cat > $4.tmp && chmod ${5:-600} $4.tmp && mv $4.tmp $4"; }
# Cluster traffic uses each VM's private address (Spot vs2 VMs share a 10/8
# provider network; SSH goes to the public one). Cached per topology.
PRIV_CACHE="${OUT_DIR:-$HERE/results}/.priv-$BENCH_NAME"
priv() {
  local ip="$1" p
  p="$(awk -v k="$ip" '$1==k{print $2}' "$PRIV_CACHE" 2>/dev/null | head -1)"
  if [[ -z "$p" ]]; then
    p="$(r "$ip" 'ip -4 route get 1.1.1.1 | sed -n "s/.* src \([0-9.]*\).*/\1/p"')"
    [[ -n "$p" ]] || p="$ip"
    mkdir -p "$(dirname "$PRIV_CACHE")"; echo "$ip $p" >> "$PRIV_CACHE"
  fi
  echo "$p"
}
privs() { local h out=(); for h in "$@"; do out+=("$(priv "$h")"); done; echo "${out[*]}"; }
hostname_of() { # name used in the inventory for an address
  local ip="$1" i
  [[ "$ip" == "$APP" ]] && { echo app1; return; }
  for i in "${!CH_HOSTS[@]}"; do [[ "${CH_HOSTS[$i]}" == "$ip" ]] && { echo "ch$((i + 1))"; return; }; done
  for i in "${!INGEST_HOSTS[@]}"; do [[ "${INGEST_HOSTS[$i]}" == "$ip" ]] && { echo "ing$((i + 1))"; return; }; done
}

# ---------------------------------------------------------------------------
step_prep() {
  local me; me="$(curl -fsS https://api.ipify.org)"
  local allow; allow="${ALL_HOSTS[*]} $(privs "${ALL_HOSTS[@]}") $me"
  for h in "${ALL_HOSTS[@]}"; do
    say "prep $h (allow: cluster + operator $me)"
    r "$h" "sudo bash -s -- $allow" <<'EOF'
set -euo pipefail
until [ -e /var/lib/nano-bench-ready ]; do sleep 5; done        # cloud-init: Docker installed
# Spot VMs carry a large unformatted local disk (xvde); put Docker on it.
if ! mountpoint -q /var/lib/docker; then
  disk=$(lsblk -dnpo NAME,SIZE,TYPE | awk '$3=="disk"{print $1}' | while read -r d; do
    # Only a blank disk: unmounted, no partitions, no filesystem signature.
    [ -z "$(lsblk -no MOUNTPOINT "$d" | tr -d '[:space:]')" ] && [ "$(lsblk -nro NAME "$d" | wc -l)" -eq 1 ] \
      && [ -z "$(blkid -p -o value -s TYPE "$d" 2>/dev/null)" ] && [ "$(lsblk -bdno SIZE "$d")" -gt 50000000000 ] && echo "$d"; done | head -1 || true)
  if [ -n "$disk" ]; then
    systemctl stop docker docker.socket containerd || true
    mkfs.ext4 -q -F -L nanodata "$disk"
    mkdir -p /var/lib/docker
    echo "LABEL=nanodata /var/lib/docker ext4 defaults,noatime,nofail 0 2" >> /etc/fstab
    mount /var/lib/docker
    systemctl start containerd docker
  fi
fi
# Host firewall: hosts sit on public addresses (Spot has no private network), so
# everything inbound is limited to the cluster members and the operator. Docker
# published ports bypass INPUT, so the same list guards DOCKER-USER.
iptables -N NANO-BENCH 2>/dev/null || iptables -F NANO-BENCH
iptables -A NANO-BENCH -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A NANO-BENCH -i lo -j RETURN
iptables -A NANO-BENCH -s 172.16.0.0/12 -j RETURN
for ip in "$@"; do iptables -A NANO-BENCH -s "$ip" -j RETURN; done
iptables -A NANO-BENCH -p tcp --dport 22 -j RETURN
iptables -A NANO-BENCH -j DROP
iface=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
iptables -C INPUT -i "$iface" -j NANO-BENCH 2>/dev/null || iptables -I INPUT 1 -i "$iface" -j NANO-BENCH
iptables -N DOCKER-USER 2>/dev/null || true
iptables -C DOCKER-USER -i "$iface" -j NANO-BENCH 2>/dev/null || iptables -I DOCKER-USER 1 -i "$iface" -j NANO-BENCH
echo "prep ok: docker on $(findmnt -no SOURCE /var/lib/docker || echo rootfs), $(nproc) vCPU, $(free -g | awk '/Mem/{print $2}') GiB"
EOF
  done
}

# ---------------------------------------------------------------------------
render_inventory() { # -> stdout; addresses are the hosts' own (public) IPs
  local lane=""; [[ "${AGENTLANE:-0}" == 1 ]] && lane="$(privs "${BLASTERS[@]}")"
  python3 - "$BENCH_NAME" "$DEPLOYMENT_ID" "$(priv "$APP")" "$(privs "${CH_HOSTS[@]}")" "$(privs "${INGEST_HOSTS[@]}")" "${CH_LAYOUT:-shards}" "$lane" <<'PY'
import sys
name, dep, app, ch, ing, layout, lane = sys.argv[1:]
lane = lane.split()
ch, ing = ch.split(), ing.split()
# Keeper: one on app1 for a single ClickHouse node; three (app1, ch1, ch2) when
# ClickHouse is sharded or replicated, as the renderer requires.
keepers = [app] + (ch[:2] if len(ch) >= 2 else [])
L = ["# nano public benchmark inventory (generated by benchmarks/public/run.sh)",
     "version: 1", "cluster:", f"  name: {name}", f"  deployment_id: {dep}", "  tls:",
     "    cert: /var/lib/nano/tls/staged/server.crt", "    key: /var/lib/nano/tls/staged/server.key",
     "    ca: /var/lib/nano/tls/staged/ca.crt", "    server_name: nano-private.bench.internal",
     f"  app_hostname: {app}", f"  ingest_hostname: {ing[0]}"]
if lane:
    # Agent Lane listener on ch1, open to the load generators (the agents) only.
    L += ["agentlane:", "  enabled: true", f"  allow_cidrs: [{', '.join(ip + '/32' for ip in lane)}]",
          "  tls:", "    cert: /etc/nano/agentlane/fullchain.pem", "    key: /etc/nano/agentlane/privkey.pem"]
L.append("hosts:")
def host(n, ip, roles, extra=()):
    k = keepers.index(ip) + 1 if ip in keepers else None
    if k:
        roles = roles + ["keeper"]
    L.extend([f"  - name: {n}", f"    id: {name}-{n}", f"    address: {ip}", f"    roles: [{', '.join(roles)}]", *extra])
    if k:
        L.append(f'    keeper: {{"id": {k}}}')
host("app1", app, ["app", "postgres"])
for i, ip in enumerate(ch, 1):
    shard, rep = (i, 1) if layout == "shards" else (1, i)
    host(f"ch{i}", ip, ["clickhouse"], [f'    clickhouse: {{"shard": {shard}, "replica": {rep}}}']
         + (["    agentlane: true"] if lane and i == 1 else []))
for i, ip in enumerate(ing, 1):
    host(f"ing{i}", ip, ["ingest"])
print("\n".join(L))
PY
}

roles_of() {
  local ip="$1" n; n="$(hostname_of "$ip")"
  case "$n" in
    app1) echo "app,postgres,keeper" ;;
    ch1|ch2) [[ ${#CH_HOSTS[@]} -ge 2 ]] && echo "clickhouse,keeper" || echo "clickhouse" ;;
    ch*) echo "clickhouse" ;;
    ing*) echo "ingest" ;;
  esac
}

step_install() {
  [[ -n "$ENROLL_FROM" ]] || { echo "--enrollment-cmd is required (prints LICENSE_URL/LICENSE_TOKEN/NANO_DEPLOYMENT_ID)" >&2; exit 2; }
  [[ -n "$PKI" ]] || { echo "--pki DIR is required (private CA output, kept off the repo)" >&2; exit 2; }
  say "enrollment -> app host (streamed, never printed)"
  bash -c "$ENROLL_FROM" | r "$APP" 'umask 077 && cat > ~/enrollment.env'
  DEPLOYMENT_ID="$(r "$APP" 'sed -n "s/^NANO_DEPLOYMENT_ID=//p" ~/enrollment.env')"
  [[ -n "$DEPLOYMENT_ID" ]] || { echo "no NANO_DEPLOYMENT_ID in enrollment" >&2; exit 1; }

  say "fetch + verify nano-compose-enterprise-$NANO_VERSION on the app host"
  r "$APP" 'mkdir -p ~/bundle' && r "$APP" "cat > ~/fetch-bundle.sh" < "$DEPLOY/fetch-bundle.sh"
  local cred_arg=""
  [[ "$SELF_LOGIN" == 1 ]] || cred_arg="--registry-cred ~/.nano-registry-cred"
  r "$APP" "bash ~/fetch-bundle.sh --enrollment ~/enrollment.env --version $NANO_VERSION --out ~/bundle $cred_arg" | tail -3
  for h in "${NANO_HOSTS[@]}"; do
    if [[ "$h" != "$APP" ]]; then
      r "$APP" "cat ~/bundle/nano-compose-enterprise-$NANO_VERSION.tar.gz" | r "$h" "cat > ~/nano-compose-enterprise-$NANO_VERSION.tar.gz"
      [[ "$SELF_LOGIN" == 1 ]] || pipe "$APP" "~/.nano-registry-cred" "$h" "~/.nano-registry-cred"
    else
      r "$h" "cp ~/bundle/nano-compose-enterprise-$NANO_VERSION.tar.gz ~/"
    fi
    r "$h" "set -e; [ -d ~/nano ] || { tar -xzf ~/nano-compose-enterprise-$NANO_VERSION.tar.gz -C ~ && mv ~/nano-$NANO_VERSION ~/nano; }"
    if [[ "$SELF_LOGIN" == 1 ]]; then
      echo "$h: bundle ok (install.sh logs in to the registry with the license)"
    else
      r "$h" "docker login us-central1-docker.pkg.dev -u oauth2accesstoken --password-stdin < ~/.nano-registry-cred >/dev/null && echo \"$h: bundle + registry ok\""
    fi
  done

  say "inventory (same bytes everywhere)"
  local inv; inv="$(render_inventory)"
  for h in "${NANO_HOSTS[@]}"; do
    printf '%s\n' "$inv" | r "$h" 'umask 077 && cat > ~/inventory.yaml && sudo install -d -m 0755 /etc/nano &&
      sudo install -m 0600 -o "$(id -un)" -g "$(id -gn)" ~/inventory.yaml /etc/nano/inventory.yaml && rm ~/inventory.yaml && sha256sum /etc/nano/inventory.yaml | cut -c1-16'
  done

  say "private TLS (CA key stays in $PKI)"
  if [[ ! -f "$PKI/server.crt" ]]; then
    local ips=(); for h in "${NANO_HOSTS[@]}"; do ips+=(--ip "$(priv "$h")"); done
    bash "$DEPLOY/make-private-ca.sh" --out "$PKI" --server-name nano-private.bench.internal "${ips[@]}" >/dev/null
  fi
  for h in "${NANO_HOSTS[@]}"; do
    for f in server.crt server.key ca.crt; do r "$h" "umask 077 && cat > ~/$f" < "$PKI/$f"; done
    r "$h" 'set -e; sudo install -d -m 0700 -o root -g root /root/nano-pki
      for f in server.crt server.key ca.crt; do sudo install -m 0600 -o root -g root ~/$f /root/nano-pki/$f; rm -f ~/$f; done
      sudo ~/nano/scripts/nano-tls-stage --cert /root/nano-pki/server.crt --key /root/nano-pki/server.key \
        --ca /root/nano-pki/ca.crt --output /var/lib/nano/tls/staged --installer-user "$(id -un)" >/dev/null && echo tls-staged'
  done

  say "admin credentials + shared .env (prepared on app1, streamed to the others)"
  r "$APP" "bash -s -- --email bench-admin@nano.example --name 'Benchmark Admin'" < "$DEPLOY/admin-credentials.sh"
  r "$APP" "cd ~/nano && set -a && . ~/.nano-admin-credentials && set +a &&
    NANO_HOST_NAME=app1 NANO_BASE_URL=http://$(priv "$APP") NANO_PREPARE_ONLY=1 $LOCK_ENV \
    ./install.sh --role $(roles_of "$APP") --inventory /etc/nano/inventory.yaml" 2>&1 | tail -5
  r "$APP" 'cat ~/nano/apply-enrollment.sh >/dev/null 2>&1 || true'
  r "$APP" "cat > ~/apply-enrollment.sh" < "$DEPLOY/apply-enrollment.sh"
  r "$APP" 'bash ~/apply-enrollment.sh --env ~/nano/.env --from ~/enrollment.env' | tail -2
  for h in "${NANO_HOSTS[@]}"; do [[ "$h" == "$APP" ]] || pipe "$APP" "~/nano/.env" "$h" "~/nano/.env"; done

  if [[ "${AGENTLANE:-0}" == 1 ]]; then
    say "Agent Lane listener certificate for ch1 (its own key, separate from the cluster PKI)"
    local ch1="${CH_HOSTS[0]}"
    [[ -f "$PKI/agentlane/server.crt" ]] || bash "$DEPLOY/make-private-ca.sh" --out "$PKI/agentlane" \
      --server-name agentlane.bench.internal --ip "$(priv "$ch1")" >/dev/null
    r "$ch1" 'umask 077 && cat > ~/al.crt' < "$PKI/agentlane/server.crt"
    r "$ch1" 'umask 077 && cat > ~/al.key' < "$PKI/agentlane/server.key"
    r "$ch1" 'set -e; sudo install -d -m 0755 /etc/nano/agentlane
      sudo install -m 0644 -o root -g root ~/al.crt /etc/nano/agentlane/fullchain.pem
      sudo install -m 0600 -o root -g root ~/al.key /etc/nano/agentlane/privkey.pem; rm -f ~/al.crt ~/al.key; echo agentlane-cert-staged'
  fi

  local t0; ENV_CHANGED_AFTER=()
  for h in "${CH_HOSTS[@]}" "$APP" "${INGEST_HOSTS[@]}"; do
    local n roles; n="$(hostname_of "$h")"; roles="$(roles_of "$h")"
    [[ "$h" == "$APP" ]] || true
    t0=$(date +%s)
    say "install.sh on $n ($roles)"
    if ! r "$h" "cd ~/nano && { [ -f ~/.nano-admin-credentials ] && set -a && . ~/.nano-admin-credentials && set +a; } ;
      NANO_HOST_NAME=$n $LOCK_ENV ./install.sh --role $roles --inventory /etc/nano/inventory.yaml" > "$OUT_DIR/.install-$n.log" 2>&1; then
      # First run on an Agent Lane listener host renders the firewall and stops
      # until root applies it (documented sequence); anything else is fatal.
      if [[ "${AGENTLANE:-0}" == 1 && "$n" == ch1 ]] && grep -q "listener firewall is not-applied" "$OUT_DIR/.install-$n.log"; then
        say "ch1 rendered the Agent Lane listener; applying its firewall next"
      else
        tail -40 "$OUT_DIR/.install-$n.log"; exit 1
      fi
    fi
    tail -2 "$OUT_DIR/.install-$n.log"; echo "  $n installed in $(( $(date +%s) - t0 ))s"
    if [[ "${AGENTLANE:-0}" == 1 && "$n" == ch1 ]]; then
      # The documented listener sequence: render, root firewall apply, install again.
      say "Agent Lane: nano-agentlane-host apply on ch1, then install.sh again"
      r "$h" 'sudo bash ~/nano/deploy/compose/agentlane/nano-agentlane-host apply ~/nano' > "$OUT_DIR/.agentlane-apply.log" 2>&1 \
        || { tail -30 "$OUT_DIR/.agentlane-apply.log"; exit 1; }
      r "$h" "cd ~/nano && NANO_HOST_NAME=$n $LOCK_ENV ./install.sh --role $roles --inventory /etc/nano/inventory.yaml" \
        > "$OUT_DIR/.install-$n-agentlane.log" 2>&1 || { tail -40 "$OUT_DIR/.install-$n-agentlane.log"; exit 1; }
      tail -2 "$OUT_DIR/.install-$n-agentlane.log"
    fi
    # The installer can record new shared keys (e.g. NANO_LICENSE_MODE on the
    # app host). Its rule: stream that host's .env to every other host before
    # the next install.sh run anywhere, and re-run the hosts already installed.
    if grep -q "shared .env changed on this host" "$OUT_DIR/.install-$n.log"; then
      say "$n changed the shared .env: streaming it to every host"
      local o; for o in "${NANO_HOSTS[@]}"; do [[ "$o" == "$h" ]] || pipe "$h" "~/nano/.env" "$o" "~/nano/.env"; done
      ENV_CHANGED_AFTER+=("$n")
    fi
  done
  # Hosts installed before the change get one more (idempotent) run.
  if [[ ${#ENV_CHANGED_AFTER[@]} -gt 0 ]]; then
    for h in "${CH_HOSTS[@]}"; do
      local n; n="$(hostname_of "$h")"; say "re-run install.sh on $n with the final .env"
      r "$h" "cd ~/nano && NANO_HOST_NAME=$n $LOCK_ENV ./install.sh --role $(roles_of "$h") --inventory /etc/nano/inventory.yaml" \
        > "$OUT_DIR/.install-$n-2.log" 2>&1 || { tail -40 "$OUT_DIR/.install-$n-2.log"; exit 1; }
    done
  fi
  for h in "${NANO_HOSTS[@]}"; do echo "  $(hostname_of "$h") .env $(r "$h" 'sha256sum ~/nano/.env | cut -c1-16')"; done
}

# ---------------------------------------------------------------------------
step_content() {
  say "content (parsers, sources, tokens, $(python3 -c "import json;print(json.load(open('$HERE/detections/rules.json'))['count'])") rules, API key)"
  r "$APP" 'mkdir -p ~/bench && chmod 700 ~/bench'
  r "$APP" 'cat > ~/bench/setup_content.py' < "$HERE/lib/setup_content.py"
  r "$APP" 'cat > ~/bench/rules.json' < "$HERE/detections/rules.json"
  r "$APP" "python3 -I ~/bench/setup_content.py --out ~/bench --rules ~/bench/rules.json --agentlane $AGENTS --run-tag ${RUN_ID//[^A-Za-z0-9]/}"
  for b in "${BLASTERS[@]}"; do
    r "$b" 'mkdir -p ~/bench && chmod 700 ~/bench'
    for f in tokens.json api.env; do pipe "$APP" "~/bench/$f" "$b" "~/bench/$f"; done
    [[ "$AGENTS" -gt 0 ]] && pipe "$APP" "~/bench/agentlane.json" "$b" "~/bench/agentlane.json" || true
  done
  mkdir -p "$OUT_DIR/$RUN_ID"
  r "$APP" 'cat ~/bench/content.json' > "$OUT_DIR/$RUN_ID/content.json"
  r "$APP" 'cat ~/bench/content-rules.json 2>/dev/null' > "$OUT_DIR/$RUN_ID/content-rules.json" || rm -f "$OUT_DIR/$RUN_ID/content-rules.json"
}

# ---------------------------------------------------------------------------
step_tools() {
  local src; src="$(mktemp -d)"
  export COPYFILE_DISABLE=1   # macOS tar: no extended-attribute headers
  # Minimal two-crate workspace: the root manifest's [workspace.*] tables plus
  # event-core and log-blaster, so the blaster builds without the whole repo.
  python3 - "$REPO/Cargo.toml" > "$src/Cargo.toml" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
keep, out, cur = ("workspace.package", "workspace.dependencies", "profile.release"), [], None
for line in text.splitlines():
    m = re.match(r"^\[([^\]]+)\]\s*$", line)
    if m:
        cur = m.group(1)
        if cur in keep:
            out.append(line)
        continue
    if cur in keep:
        out.append(line)
print('[workspace]\nresolver = "2"\nmembers = ["tools/event-core", "tools/log-blaster"]\n')
print("\n".join(out))
PY
  for b in "${BLASTERS[@]}"; do
    say "build log-blaster on $b (rust:1 container) + k6"
    tar -C "$REPO" -czf - Cargo.lock rust-toolchain.toml tools/event-core tools/log-blaster -C "$src" Cargo.toml \
      | r "$b" 'rm -rf ~/lb && mkdir -p ~/lb && tar -xzf - -C ~/lb'
    r "$b" 'set -e; cd ~/lb && docker run --rm -v "$PWD":/src -w /src -e CARGO_HOME=/src/.cargo rust:1-bookworm \
        bash -c "rustup show >/dev/null 2>&1; cargo build --release -p log-blaster 2>&1 | tail -2" &&
      sudo install -m 0755 target/release/log-blaster /usr/local/bin/log-blaster && log-blaster --help | head -1'
    r "$b" 'set -e; command -v k6 >/dev/null || { curl -fsSL https://github.com/grafana/k6/releases/download/v0.54.0/k6-v0.54.0-linux-amd64.tar.gz | tar -xz -C /tmp && sudo install -m 0755 /tmp/k6-v0.54.0-linux-amd64/k6 /usr/local/bin/k6; }; k6 version'
    tar -C "$REPO" -czf - benchmarks/public/k6 benchmarks/public/dashboards benchmarks/results/soc_ir_corpus.json skills/nano-agentlane/references/recipes.sql \
      | r "$b" 'rm -rf ~/k6w && mkdir -p ~/k6w && tar -xzf - -C ~/k6w'
  done
  rm -rf "$src"
}

# ---------------------------------------------------------------------------
# hoststat: 5 s samples of CPU busy %, memory used %, docker disk used %, load.
start_hoststat() {
  for h in "${ALL_HOSTS[@]}"; do
    r "$h" "mkdir -p ~/bench && pkill -f '[n]ano-bench-hoststat' || true; nohup bash ~/bench/hoststat.sh ~/bench/hoststat-$RUN_ID-$SCENARIO.csv >/dev/null 2>&1 &" < /dev/null
  done
}
push_hoststat() { for h in "${ALL_HOSTS[@]}"; do r "$h" 'mkdir -p ~/bench && cat > ~/bench/hoststat.sh' < "$HERE/lib/hoststat.sh"; done; }
stop_hoststat() { for h in "${ALL_HOSTS[@]}"; do r "$h" 'pkill -f "[n]ano-bench-hoststat" || true'; done; }

# Run one blast phase on every blaster process, spread across ingest hosts.
# $1 eps (total), $2 seconds, $3 phase label
blast() {
  local eps="$1" secs="$2" label="$3" procs="${BLAST_PROCS:-1}" n=0 total
  total=$(( ${#BLASTERS[@]} * procs ))
  for b in "${BLASTERS[@]}"; do
    for ((p = 0; p < procs; p++)); do
      # ACTIVE_INGEST=N sends to the first N ingest hosts only (the "add one
      # ingest host" comparison without reinstalling the cluster).
      local active="${ACTIVE_INGEST:-${#INGEST_HOSTS[@]}}"
      local ing; ing="$(priv "${INGEST_HOSTS[$(( n % active ))]}")"
      local rid="$RUN_ID-$label-p$n"
      r "$b" "nohup log-blaster --vector http://$ing/ingest/ --tokens-file ~/bench/tokens.json --blast \
          --eps $(( eps / total )) --threads ${BLAST_THREADS:-8} --batch-size ${BLAST_BATCH:-500} \
          --assets ${ASSETS:-5000} --chain-interval-secs 0 --seed $(( SEED + n )) --run-id $rid --duration-secs $secs \
          --summary-json ~/bench/blaster-$rid.json --max-retries 3 -q > ~/bench/blaster-$rid.log 2>&1 &" < /dev/null
      n=$((n + 1))
    done
  done
}

# Poll in short SSH sessions: a dropped connection during a 4 h run must not
# end the wait (the senders and k6 run under nohup on the hosts).
wait_remote() { # host, shell test that is true while the work is still running
  local h="$1" t="$2"
  while :; do
    r "$h" "for i in \$(seq 1 60); do $t || exit 0; sleep 5; done; exit 3" < /dev/null && return 0
    sleep 5
  done
}
wait_blasters() { local b; for b in "${BLASTERS[@]}"; do wait_remote "$b" 'pgrep -x log-blaster >/dev/null'; done; }

step_smoke() {
  say "smoke: 30 s at 50 eps through every source, then marker count"
  push_hoststat
  blast 50 30 smoke
  wait_blasters
  sleep 20
  python3 "$HERE/lib/collect.py" --topology "$TOPOLOGY" --run-id "$RUN_ID" --phases smoke --out "$OUT_DIR" --quick
}

step_socday() {
  SCENARIO=socday
  local eps; eps=$(python3 -c "print(round($GBPD * 1e9 / 86400 / ${AVG_EVENT_BYTES:-980}))")
  local secs; secs=$(python3 -c "import re;m=re.fullmatch(r'(\d+)([smh])','$DURATION');print(int(m[1])*{'s':1,'m':60,'h':3600}[m[2]])")
  say "socday: $GBPD GB/day ~= $eps eps for $DURATION, k6 SOC mix (agents=$AGENTS)"
  push_hoststat; start_hoststat
  date -u +%FT%TZ > "$OUT_DIR/.socday-start-$RUN_ID"
  blast "$eps" "$secs" "socday"
  local b="${BLASTERS[0]}"
  # k6 runs detached on the load generator (the run lasts hours); we poll it.
  r "$b" "cd ~/k6w/benchmarks/public/k6 && set -a && . ~/bench/api.env && set +a &&
    { APP_URL=http://$(priv "$APP") DURATION=$DURATION ANALYSTS=${ANALYSTS:-5} DASHBOARDS=${DASHBOARD_VIEWERS:-3} AGENTS=$AGENTS \
    NAL_TOKENS_FILE=\$( [ $AGENTS -gt 0 ] && echo ~/bench/agentlane.json ) NAL_TABLE_SUFFIX=${NAL_TABLE_SUFFIX:-} \
    RESULTS_FILE=\$HOME/bench/k6-socday-$RUN_ID.json nohup setsid k6 run --quiet soc_mix.js > ~/bench/k6-socday-$RUN_ID.log 2>&1 < /dev/null &
    echo \$! > ~/bench/k6-socday-$RUN_ID.pid; }" < /dev/null
  wait_remote "$b" "kill -0 \$(cat ~/bench/k6-socday-$RUN_ID.pid) 2>/dev/null"
  wait_blasters
  stop_hoststat
  python3 "$HERE/lib/collect.py" --topology "$TOPOLOGY" --run-id "$RUN_ID" --phases socday --scenario socday \
    --gb-per-day "$GBPD" --out "$OUT_DIR"
}

step_ceiling() {
  SCENARIO=ceiling
  # Stepped ramp. Each step holds STEP_SECS, then 60 s of drain before the
  # step's SLO check; the first failed step ends the ramp.
  local eps="${START_EPS:-2000}" step="${STEP_EPS:-2000}" secs="${STEP_SECS:-300}" max="${MAX_EPS:-500000}" i=0 phases=()
  push_hoststat; start_hoststat
  while (( eps <= max )); do
    i=$((i + 1)); local label; label="ceil$(printf %02d $i)-$eps"
    say "ceiling step $i: $eps eps for ${secs}s"
    blast "$eps" "$secs" "$label"
    # Analysts keep hunting during every step: query latency at this load.
    r "${BLASTERS[0]}" "cd ~/k6w/benchmarks/public/k6 && set -a && . ~/bench/api.env && set +a &&
      APP_URL=http://$(priv "$APP") DURATION=${secs}s ANALYSTS=${CEILING_ANALYSTS:-2} DASHBOARDS=0 AGENTS=0 \
      RESULTS_FILE=\$HOME/bench/k6-$RUN_ID-$label.json k6 run --quiet soc_mix.js > ~/bench/k6-$RUN_ID-$label.log 2>&1 || true"
    wait_blasters; sleep "${DRAIN_SECS:-60}"
    phases+=("$label")
    if ! python3 "$HERE/lib/collect.py" --topology "$TOPOLOGY" --run-id "$RUN_ID" --phases "$label" --out "$OUT_DIR" --slo-check; then
      say "SLO broke at $eps eps: ramp ends"; break
    fi
    eps=$((eps + step))
  done
  stop_hoststat
  python3 "$HERE/lib/collect.py" --topology "$TOPOLOGY" --run-id "$RUN_ID" --phases "$(IFS=,; echo "${phases[*]}")" \
    --scenario ceiling --out "$OUT_DIR"
}

# shellcheck disable=SC2120  # extra collect.py flags, when called from another step
step_collect() { python3 "$HERE/lib/collect.py" --topology "$TOPOLOGY" --run-id "$RUN_ID" --out "$OUT_DIR" "$@"; }

mkdir -p "$OUT_DIR"
case "$STEP" in
  prep) step_prep ;;
  install) step_install ;;
  content) step_content ;;
  tools) step_tools ;;
  smoke) step_smoke ;;
  socday) step_socday ;;
  ceiling) step_ceiling ;;
  collect) step_collect ;;
  all-dry) step_prep; step_install; step_content; step_tools; step_smoke
           DURATION=10m step_socday; START_EPS=1000 STEP_EPS=1000 STEP_SECS=120 MAX_EPS=4000 step_ceiling ;;
  *) echo "unknown step $STEP" >&2; exit 2 ;;
esac
say "done (run id $RUN_ID)"
