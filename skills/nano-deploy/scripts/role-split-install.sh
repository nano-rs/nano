#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Role-split host prep and install over SSH, from a workstation. Moved out of
# benchmarks/public/run.sh (which now sources this file) so the public
# benchmark and `scripts/nano cluster` (enterprise) run the same install path:
# the enterprise bundle from the license API, one inventory, a private CA
# staged with nano-tls-stage, the shared .env prepared on app1 and streamed to
# every host, then install.sh by role (ClickHouse, app, ingest).
#
#   role-split-install.sh prep    --topology FILE [--out DIR]
#   role-split-install.sh install --topology FILE --pki DIR --enrollment-cmd CMD [--out DIR]
#   role-split-install.sh resync  --topology FILE [--out DIR]
#       after a change to app1's shared .env (e.g. a new Vector-native sender from
#       `scripts/nano vector-client-cert`): stream it to every host and re-run
#       install.sh on the ingest hosts (multi-node guide, Step 5).
#   role-split-install.sh upgrade --topology FILE --enrollment-cmd CMD [--dry-run] [--out DIR]
#       NANO_VERSION is the target. The documented enterprise role-split upgrade
#       (docs/administration/upgrade-v2.md): the signed package fetched with the
#       license values and extracted over the install directory on every host,
#       a backup key at the same path everywhere, private SSH from app1 (the
#       coordinator) to every peer, then `scripts/nano upgrade --inventory ...`
#       on app1 (a dry run first; --dry-run stops after it).
#   role-split-install.sh add-ingest --topology FILE --pki DIR [--out DIR]
#       INGEST lists the new host(s) last. The documented "add an ingest host"
#       sequence (nano-deploy operate.md): re-issue the private certificate
#       from the same CA, the new inventory on every host, app1 acknowledges
#       the ingest-only topology change (--accept-topology-migration <old>),
#       its .env goes to every host, then install.sh on the new host(s) and a
#       rerun on every other host.
#
# The topology file is shell (the benchmark hosts.env format):
#   BENCH_NAME (or CLUSTER_NAME), SSH_KEY, [SSH_USER=ubuntu], [KNOWN_HOSTS],
#   APP (one address), CH and INGEST (space-separated addresses), [BLASTER],
#   [NANO_VERSION], [CH_LAYOUT=shards|replicas] or [CH_REPLICAS=N], [AGENTLANE]
# Optional, all defaulting to the benchmark's values:
#   TLS_SERVER_NAME     private cluster TLS name   (nano-private.bench.internal)
#   TLS_EXTRA_SANS      more SANs, "IP:a DNS:b"    (load balancer addresses/names)
#   APP_HOSTNAME / INGEST_HOSTNAME   inventory hostnames (app1 / ing1 private address)
#   BASE_URL            NANO_BASE_URL for the prepare step (http://<app1 private>)
#   TRUSTED_PROXY_CIDRS inventory cluster.trusted_proxy_cidrs, space-separated
#   ADMIN_EMAIL / ADMIN_NAME   first admin (bench-admin@nano.example)
#   INSTALL_ENV         non-secret KEY=VALUE words exported to every install.sh run
#   READY_MARKER        file cloud-init touches when Docker is installed
#   HOST_FIREWALL       1: iptables allow-list (cluster + operator), 0: the cloud firewall does it
#   PREP_ALLOW_CIDRS    more sources the host firewall allows
#
# Secrets (license, admin password, registry credential) live only on the
# hosts in 0600 files. They are streamed host to host through this
# workstation's SSH pipes and are never printed or written locally. The
# private CA key stays in --pki.
#
# Sourced (benchmarks/public/run.sh): defines the functions and returns; the
# caller has already loaded the topology and set STEP, OUT_DIR, PKI and
# ENROLL_FROM.
# Remote paths ("~/nano/.env") and remote command strings expand on the host,
# on purpose:
# shellcheck disable=SC2088,SC2016,SC2029
set -euo pipefail

RSI_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="${DEPLOY:-$RSI_HERE}"

rsi_load() { # after the topology is sourced
  NAME="${BENCH_NAME:-${CLUSTER_NAME:?topology needs BENCH_NAME or CLUSTER_NAME}}"
  : "${SSH_KEY:?}" "${APP:?}" "${CH:?}" "${INGEST:?}"
  SSH_USER="${SSH_USER:-ubuntu}"
  NANO_VERSION="${NANO_VERSION:-2.0.23}"
  read -r -a CH_HOSTS <<<"$CH"; read -r -a INGEST_HOSTS <<<"$INGEST"; read -r -a BLASTERS <<<"${BLASTER:-}"
  NANO_HOSTS=("$APP" "${CH_HOSTS[@]}" "${INGEST_HOSTS[@]}")
  ALL_HOSTS=("${NANO_HOSTS[@]}" "${BLASTERS[@]}")
  KH="${KNOWN_HOSTS:-$(dirname "$SSH_KEY")/known_hosts}"
  SSHO=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KH" -o ConnectTimeout=15 -o ServerAliveInterval=30 -o LogLevel=ERROR)
  LOCK="images.enterprise.customer.lock"
  # From 2.0.30 the enterprise install.sh (and scripts/nano upgrade) default to
  # the customer lock and log in to the registry themselves with the license in
  # .env (a private temporary DOCKER_CONFIG; ~/.docker is never touched). 2.0.29
  # and earlier need the lock named and a docker login on every host first.
  if ver_ge "$NANO_VERSION" 2.0.30; then SELF_LOGIN=1; LOCK_ENV=""; else SELF_LOGIN=0; LOCK_ENV="NANO_IMAGES_LOCK=$LOCK "; fi
  PRIV_CACHE="${OUT_DIR:?}/.priv-$NAME"
  read -r -a INSTALL_ENV_WORDS <<<"${INSTALL_ENV:-}"
  local kv
  for kv in "${INSTALL_ENV_WORDS[@]}"; do
    [[ "$kv" =~ ^[A-Z][A-Z0-9_]*=[A-Za-z0-9._:/,@-]*$ ]] || { echo "INSTALL_ENV: '$kv' is not KEY=plain-value" >&2; exit 2; }
  done
}

ver_ge() { # $1 >= $2, dotted numeric
  local x="${1#v}" y="${2#v}" a b i
  [[ "$x" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] || { echo "NANO_VERSION must look like 2.0.30 (got '$1')" >&2; exit 2; }
  IFS=. read -r -a a <<<"${x%%-*}"; IFS=. read -r -a b <<<"${y%%-*}"
  for i in 0 1 2; do
    (( 10#${a[i]:-0} > 10#${b[i]:-0} )) && return 0
    (( 10#${a[i]:-0} < 10#${b[i]:-0} )) && return 1
  done
  return 0
}
say() { printf '\033[1m[%s %s]\033[0m %s\n' "$(date -u +%H:%M:%S)" "${STEP:-}" "$*"; }
r() { local h="$1"; shift; ssh "${SSHO[@]}" "$SSH_USER@$h" "$@"; }
# Stream a file between hosts without it touching this workstation's disk.
pipe() { r "$1" "cat $2" | r "$3" "umask 077 && cat > $4.tmp && chmod ${5:-600} $4.tmp && mv $4.tmp $4"; }
# Cluster traffic uses each VM's private address; SSH goes to the public one.
# Cached per topology.
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
# install.sh with the extra (non-secret) environment, e.g. a bind address.
install_env() { local kv words=""; for kv in "${INSTALL_ENV_WORDS[@]}"; do words+="$kv "; done; printf '%s' "$words"; }

# ---------------------------------------------------------------------------
step_prep() {
  local me allow
  me="$(curl -fsS https://api.ipify.org)"
  allow="${ALL_HOSTS[*]} $(privs "${ALL_HOSTS[@]}") $me ${PREP_ALLOW_CIDRS:-}"
  local h
  for h in "${ALL_HOSTS[@]}"; do
    say "prep $h (host firewall ${HOST_FIREWALL:-1}; allow: cluster + operator $me)"
    r "$h" "sudo bash -s -- ${READY_MARKER:-/var/lib/nano-bench-ready} ${HOST_FIREWALL:-1} $allow" <<'EOF'
set -euo pipefail
marker="$1" firewall="$2"; shift 2
until [ -e "$marker" ]; do sleep 5; done        # cloud-init: Docker installed
# The SSH user runs docker (registry login, install.sh): docker group, effective
# from its next SSH session.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] && ! id -nG "$SUDO_USER" | grep -qw docker; then
  # OS Login users come from NSS, not /etc/passwd: gpasswd handles both.
  gpasswd -a "$SUDO_USER" docker >/dev/null
fi
# A large blank disk (cloud data disk, local instance disk) holds Docker's data root.
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
if [ "$firewall" = 1 ]; then
# Host firewall: hosts sit on public addresses (some clouds give VMs no private network), so
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
fi
echo "prep ok: docker on $(findmnt -no SOURCE /var/lib/docker || echo rootfs), $(nproc) vCPU, $(free -g | awk '/Mem/{print $2}') GiB"
EOF
  done
}

# ---------------------------------------------------------------------------
render_inventory() { # -> stdout; addresses are the hosts' private ones
  local lane=""; [[ "${AGENTLANE:-0}" == 1 ]] && lane="$(privs "${BLASTERS[@]}")"
  local app_priv ing_privs; app_priv="$(priv "$APP")"; ing_privs="$(privs "${INGEST_HOSTS[@]}")"
  python3 - "$NAME" "$DEPLOYMENT_ID" "$app_priv" "$(privs "${CH_HOSTS[@]}")" "$ing_privs" "${CH_LAYOUT:-shards}" "$lane" \
    "${TLS_SERVER_NAME:-nano-private.bench.internal}" "${APP_HOSTNAME:-$app_priv}" "${INGEST_HOSTNAME:-${ing_privs%% *}}" \
    "${CH_REPLICAS:-}" "${TRUSTED_PROXY_CIDRS:-}" <<'PY'
import sys
name, dep, app, ch, ing, layout, lane, tls_name, app_hn, ing_hn, replicas, trusted = sys.argv[1:]
lane = lane.split()
ch, ing = ch.split(), ing.split()
# Keeper: one on app1 for a single ClickHouse node; three (app1, ch1, ch2) when
# ClickHouse is sharded or replicated, as the renderer requires.
keepers = [app] + (ch[:2] if len(ch) >= 2 else [])
L = ["# nano role-split inventory (generated by skills/nano-deploy/scripts/role-split-install.sh)",
     "version: 1", "cluster:", f"  name: {name}", f"  deployment_id: {dep}", "  tls:",
     "    cert: /var/lib/nano/tls/staged/server.crt", "    key: /var/lib/nano/tls/staged/server.key",
     "    ca: /var/lib/nano/tls/staged/ca.crt", f"    server_name: {tls_name}",
     f"  app_hostname: {app_hn}", f"  ingest_hostname: {ing_hn}"]
if trusted.split():
    L.append(f"  trusted_proxy_cidrs: [{', '.join(trusted.split())}]")
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
    if replicas:   # shards x replicas, replicas numbered contiguously per shard
        r = int(replicas)
        shard, rep = (i - 1) // r + 1, (i - 1) % r + 1
    else:
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
  [[ -n "${ENROLL_FROM:-}" ]] || { echo "--enrollment-cmd is required (prints LICENSE_URL/LICENSE_TOKEN/NANO_DEPLOYMENT_ID)" >&2; exit 2; }
  [[ -n "${PKI:-}" ]] || { echo "--pki DIR is required (private CA output, kept off the repo)" >&2; exit 2; }
  local env; env="$(install_env)"
  say "enrollment -> app host (streamed, never printed)"
  bash -c "$ENROLL_FROM" | r "$APP" 'umask 077 && cat > ~/enrollment.env'
  DEPLOYMENT_ID="$(r "$APP" 'sed -n "s/^NANO_DEPLOYMENT_ID=//p" ~/enrollment.env')"
  [[ -n "$DEPLOYMENT_ID" ]] || { echo "no NANO_DEPLOYMENT_ID in enrollment" >&2; exit 1; }

  say "fetch + verify nano-compose-enterprise-$NANO_VERSION on the app host"
  r "$APP" 'mkdir -p ~/bundle' && r "$APP" "cat > ~/fetch-bundle.sh" < "$DEPLOY/fetch-bundle.sh"
  local cred_arg=""
  [[ "$SELF_LOGIN" == 1 ]] || cred_arg="--registry-cred ~/.nano-registry-cred"
  r "$APP" "bash ~/fetch-bundle.sh --enrollment ~/enrollment.env --version $NANO_VERSION --out ~/bundle $cred_arg" | tail -3
  local h
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
    local ips=() san; for h in "${NANO_HOSTS[@]}"; do ips+=(--ip "$(priv "$h")"); done
    for san in ${TLS_EXTRA_SANS:-}; do
      case "$san" in IP:*) ips+=(--ip "${san#IP:}") ;; DNS:*) ips+=(--dns "${san#DNS:}") ;; *) echo "TLS_EXTRA_SANS: $san is not IP:... or DNS:..." >&2; exit 2 ;; esac
    done
    bash "$DEPLOY/make-private-ca.sh" --out "$PKI" --server-name "${TLS_SERVER_NAME:-nano-private.bench.internal}" "${ips[@]}" >/dev/null
  fi
  for h in "${NANO_HOSTS[@]}"; do
    for f in server.crt server.key ca.crt; do r "$h" "umask 077 && cat > ~/$f" < "$PKI/$f"; done
    r "$h" 'set -e; sudo install -d -m 0700 -o root -g root /root/nano-pki
      for f in server.crt server.key ca.crt; do sudo install -m 0600 -o root -g root ~/$f /root/nano-pki/$f; rm -f ~/$f; done
      sudo ~/nano/scripts/nano-tls-stage --cert /root/nano-pki/server.crt --key /root/nano-pki/server.key \
        --ca /root/nano-pki/ca.crt --output /var/lib/nano/tls/staged --installer-user "$(id -un)" >/dev/null && echo tls-staged'
  done

  say "admin credentials + shared .env (prepared on app1, streamed to the others)"
  r "$APP" "bash -s -- --email ${ADMIN_EMAIL:-bench-admin@nano.example} --name '${ADMIN_NAME:-Benchmark Admin}'" < "$DEPLOY/admin-credentials.sh"
  r "$APP" "cd ~/nano && set -a && . ~/.nano-admin-credentials && set +a &&
    ${env}NANO_HOST_NAME=app1 NANO_BASE_URL=${BASE_URL:-http://$(priv "$APP")} NANO_PREPARE_ONLY=1 ${LOCK_ENV}\
    ./install.sh --role $(roles_of "$APP") --inventory /etc/nano/inventory.yaml" 2>&1 | tail -5
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
    t0=$(date +%s)
    say "install.sh on $n ($roles)"
    if ! r "$h" "cd ~/nano && { [ -f ~/.nano-admin-credentials ] && set -a && . ~/.nano-admin-credentials && set +a; } ;
      ${env}NANO_HOST_NAME=$n ${LOCK_ENV}./install.sh --role $roles --inventory /etc/nano/inventory.yaml" > "$OUT_DIR/.install-$n.log" 2>&1; then
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
      r "$h" "cd ~/nano && ${env}NANO_HOST_NAME=$n ${LOCK_ENV}./install.sh --role $roles --inventory /etc/nano/inventory.yaml" \
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
      r "$h" "cd ~/nano && ${env}NANO_HOST_NAME=$n ${LOCK_ENV}./install.sh --role $(roles_of "$h") --inventory /etc/nano/inventory.yaml" \
        > "$OUT_DIR/.install-$n-2.log" 2>&1 || { tail -40 "$OUT_DIR/.install-$n-2.log"; exit 1; }
    done
  fi
  for h in "${NANO_HOSTS[@]}"; do echo "  $(hostname_of "$h") .env $(r "$h" 'sha256sum ~/nano/.env | cut -c1-16')"; done
}

step_resync() {
  local env h n; env="$(install_env)"
  say "stream app1's shared .env to every host"
  for h in "${NANO_HOSTS[@]}"; do [[ "$h" == "$APP" ]] || pipe "$APP" "~/nano/.env" "$h" "~/nano/.env"; done
  for h in "${INGEST_HOSTS[@]}"; do
    n="$(hostname_of "$h")"
    say "re-run install.sh on $n ($(roles_of "$h"))"
    r "$h" "cd ~/nano && ${env}NANO_HOST_NAME=$n ${LOCK_ENV}./install.sh --role $(roles_of "$h") --inventory /etc/nano/inventory.yaml" \
      > "$OUT_DIR/.resync-$n.log" 2>&1 || { tail -40 "$OUT_DIR/.resync-$n.log"; exit 1; }
    tail -1 "$OUT_DIR/.resync-$n.log"
  done
  for h in "${NANO_HOSTS[@]}"; do echo "  $(hostname_of "$h") .env $(r "$h" 'sha256sum ~/nano/.env | cut -c1-16')"; done
}

step_upgrade() {
  [[ -n "${ENROLL_FROM:-}" ]] || { echo "--enrollment-cmd is required" >&2; exit 2; }
  local h home bundle
  home="$(r "$APP" 'printf %s "$HOME"')"
  bundle="nano-compose-enterprise-$NANO_VERSION.tar.gz"
  say "fetch + verify $bundle on app1 (license values streamed, removed after)"
  bash -c "$ENROLL_FROM" | r "$APP" 'umask 077 && cat > ~/enrollment.env'
  r "$APP" "cat > ~/fetch-bundle.sh" < "$DEPLOY/fetch-bundle.sh"
  local cred_arg=""
  [[ "$SELF_LOGIN" == 1 ]] || cred_arg="--registry-cred ~/.nano-registry-cred"
  r "$APP" "bash ~/fetch-bundle.sh --enrollment ~/enrollment.env --version $NANO_VERSION --out ~/bundle $cred_arg; rc=\$?; rm -f ~/enrollment.env; exit \$rc" | tail -3
  say "coordinator SSH: app1 -> every peer (private addresses, key usable only from app1)"
  r "$APP" 'set -e; [ -f ~/.ssh/nano_coordinator ] || ssh-keygen -q -t ed25519 -N "" -C nano-upgrade-coordinator -f ~/.ssh/nano_coordinator
    grep -q "IdentityFile ~/.ssh/nano_coordinator" ~/.ssh/config 2>/dev/null || printf "Host 10.*\n  IdentityFile ~/.ssh/nano_coordinator\n" >> ~/.ssh/config
    chmod 600 ~/.ssh/config'
  local pub; pub="$(r "$APP" 'cat ~/.ssh/nano_coordinator.pub')"
  local from="${COORDINATOR_FROM:-$(priv "$APP")}" hk
  [[ "$from" =~ ^[0-9.]+(/[0-9]+)?$ ]] || { echo "COORDINATOR_FROM must be an IPv4 address or CIDR" >&2; exit 2; }
  for h in "${NANO_HOSTS[@]}"; do
    printf 'from="%s" %s\n' "$from" "$pub" | r "$h" 'umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys
      line=$(cat); grep -qF "${line#* }" ~/.ssh/authorized_keys || printf "%s\n" "$line" >> ~/.ssh/authorized_keys'
    # Peer host keys read over this workstation's pinned connection, not ssh-keyscan (no trust on first use).
    hk="$(r "$h" 'cat /etc/ssh/ssh_host_ed25519_key.pub' | awk '{print $1" "$2}')"
    [[ "$hk" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+$ ]] || { echo "$(hostname_of "$h"): no ed25519 host key" >&2; exit 1; }
    printf '%s %s\n' "$(priv "$h")" "$hk" | r "$APP" 'umask 077; touch ~/.ssh/known_hosts; line=$(cat)
      grep -qxF "$line" ~/.ssh/known_hosts || { ssh-keygen -R "${line%% *}" >/dev/null 2>&1; printf "%s\n" "$line" >> ~/.ssh/known_hosts; }'
  done
  say "backup key (same path on every host for the run; a copy kept in the cluster state directory)"
  r "$APP" "[ -f ~/nano-backup-key.pem ] || { cd ~/nano && scripts/nano backup-keygen --output ~/nano-backup-key.pem >/dev/null; }; chmod 600 ~/nano-backup-key.pem"
  # It decrypts the backups the coordinator takes: escrowed off the hosts now,
  # removed from every host when the rollout completes.
  ( umask 077; r "$APP" 'cat ~/nano-backup-key.pem' > "$OUT_DIR/../nano-backup-key.pem.tmp" && mv "$OUT_DIR/../nano-backup-key.pem.tmp" "$OUT_DIR/../nano-backup-key.pem" )
  say "package to every host, extracted over the install directory; registry login"
  for h in "${NANO_HOSTS[@]}"; do
    if [[ "$h" != "$APP" ]]; then
      r "$h" 'mkdir -p ~/bundle'
      # The coordinator verifies the signed checksum next to the package on every host.
      local f; for f in "$bundle" "$bundle.sha256" "$bundle.sha256.sig"; do
        r "$APP" "cat ~/bundle/$f" | r "$h" "cat > ~/bundle/$f"
      done
      [[ "$SELF_LOGIN" == 1 ]] || pipe "$APP" "~/.nano-registry-cred" "$h" "~/.nano-registry-cred"
      pipe "$APP" "~/nano-backup-key.pem" "$h" "~/nano-backup-key.pem"
    fi
    r "$h" "set -e; tar -xzf ~/bundle/$bundle -C ~/nano --strip-components=1
            mkdir -p -m 700 ~/nano-upgrade-backups; echo \"\$(hostname): package $NANO_VERSION extracted\""
    [[ "$SELF_LOGIN" == 1 ]] || r "$h" "docker login us-central1-docker.pkg.dev -u oauth2accesstoken --password-stdin < ~/.nano-registry-cred >/dev/null"
  done
  local args="--inventory /etc/nano/inventory.yaml --bundle $home/bundle/$bundle --remote-bundle $home/bundle/$bundle --remote-install-dir $home/nano --backup-key-file $home/nano-backup-key.pem --backup-output $home/nano-upgrade-backups"
  say "scripts/nano upgrade --dry-run on app1 (the coordinator)"
  r "$APP" "cd ~/nano && scripts/nano upgrade $args --dry-run" > "$OUT_DIR/.upgrade-dry-run.log" 2>&1 \
    || { tail -60 "$OUT_DIR/.upgrade-dry-run.log"; exit 1; }
  tail -15 "$OUT_DIR/.upgrade-dry-run.log"
  [[ "${UPGRADE_DRY_RUN:-0}" == 1 ]] && return 0
  coordinator_run "$args"
  say "rollout complete: removing the coordinator key and the backup key from every host"
  for h in "${NANO_HOSTS[@]}"; do
    printf '%s\n' "$pub" | r "$h" 'line=$(cat); [ -f ~/.ssh/authorized_keys ] || exit 0
      grep -vF "${line#* }" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp || true
      chmod 600 ~/.ssh/authorized_keys.tmp && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys; rm -f ~/nano-backup-key.pem'
    [[ "$SELF_LOGIN" == 1 ]] || r "$h" 'docker logout us-central1-docker.pkg.dev >/dev/null 2>&1 || true'
  done
}

# The coordinator runs DETACHED on app1 (nohup) so a dropped workstation
# session cannot hang it up mid-rollout; this follows its log until it exits.
# A run that is already going (this command re-run after a drop) is followed,
# not started again; an incomplete journal from a failed run is resumed.
# Every fd of the background job is redirected (the whole list, not only
# nohup's command), so the ssh session returns at once instead of staying
# attached until the coordinator exits.
coordinator_start() {
  r "$APP" "rm -f ~/nano-upgrade.rc; ( cd ~/nano && exec nohup bash -c 'scripts/nano upgrade $1 > ~/nano-upgrade.log 2>&1; echo \$? > ~/nano-upgrade.rc' ) > /dev/null 2>&1 < /dev/null &"
}

coordinator_run() {
  local args="$1" rc mode=""
  # [n]: the pattern must not match the remote shell running this very pgrep.
  if r "$APP" 'pgrep -f "[n]ano-upgrade.py" >/dev/null'; then
    say "a coordinator run is already going on app1: following it"
  else
    if r "$APP" 'ls ~/nano/upgrade-journal/*.json >/dev/null 2>&1 && grep -L "\"run_completed\"" ~/nano/upgrade-journal/*.json 2>/dev/null | grep -qv manual-backup-fence'; then
      mode="--resume"; say "an incomplete upgrade journal exists on app1: resuming it (scripts/nano upgrade --resume)"
    fi
    say "scripts/nano upgrade $mode on app1, detached (log: $OUT_DIR/.upgrade.log)"
    coordinator_start "$args $mode"
  fi
  until rc="$(r "$APP" 'cat ~/nano-upgrade.rc 2>/dev/null')" && [[ -n "$rc" ]]; do
    sleep 20
    r "$APP" 'cat ~/nano-upgrade.log 2>/dev/null' > "$OUT_DIR/.upgrade.log" || true
    # No exit code and no coordinator process: it died without writing one.
    r "$APP" 'pgrep -f "[n]ano-upgrade.py" >/dev/null || [ -s ~/nano-upgrade.rc ]' \
      || { rc="$(r "$APP" 'cat ~/nano-upgrade.rc 2>/dev/null')"; rc="${rc:-lost}"; break; }
  done
  r "$APP" 'cat ~/nano-upgrade.log' > "$OUT_DIR/.upgrade.log"
  if [[ "$rc" != 0 ]] && [[ -z "$mode" ]] && grep -q "incomplete upgrade journal" "$OUT_DIR/.upgrade.log"; then
    say "the coordinator found an incomplete journal: resuming it"
    coordinator_start "$args --resume"
    until rc="$(r "$APP" 'cat ~/nano-upgrade.rc 2>/dev/null')" && [[ -n "$rc" ]]; do sleep 20; done
    r "$APP" 'cat ~/nano-upgrade.log' > "$OUT_DIR/.upgrade.log"
  fi
  [[ "$rc" == 0 ]] || { tail -60 "$OUT_DIR/.upgrade.log"; echo "scripts/nano upgrade on app1 failed (exit $rc); log: $OUT_DIR/.upgrade.log" >&2; exit 1; }
  tail -15 "$OUT_DIR/.upgrade.log"
}

step_add_ingest() {
  [[ -n "${PKI:-}" && -s "$PKI/ca.key" ]] || { echo "--pki DIR with the cluster CA is required" >&2; exit 2; }
  local env h n old cand accept="" new_hosts=() ips=() san; env="$(install_env)"
  # The caller names the hosts being added (ADD_INGEST_HOSTS, inventory names),
  # so a resumed run knows them even after their install directory exists.
  for h in "${INGEST_HOSTS[@]}"; do
    [[ " ${ADD_INGEST_HOSTS:-} " == *" $(hostname_of "$h") "* ]] && new_hosts+=("$h")
  done
  [[ ${#new_hosts[@]} -gt 0 ]] || { echo "ADD_INGEST_HOSTS names no ingest host of the topology" >&2; exit 2; }
  say "ingest host(s) being added: ${ADD_INGEST_HOSTS}"
  say "re-issue the private certificate from the same CA (every address)"
  for h in "${NANO_HOSTS[@]}"; do ips+=(--ip "$(priv "$h")"); done
  for san in ${TLS_EXTRA_SANS:-}; do
    case "$san" in IP:*) ips+=(--ip "${san#IP:}") ;; DNS:*) ips+=(--dns "${san#DNS:}") ;; esac
  done
  bash "$DEPLOY/make-private-ca.sh" --out "$PKI" --reissue --server-name "${TLS_SERVER_NAME:-nano-private.bench.internal}" "${ips[@]}" >/dev/null
  for h in "${new_hosts[@]}"; do
    say "bundle + registry credential -> $h"
    local b; b="$(r "$APP" "ls -1 ~/bundle/nano-compose-enterprise-$NANO_VERSION.tar.gz ~/nano-compose-enterprise-$NANO_VERSION.tar.gz 2>/dev/null | head -1")"
    [[ -n "$b" ]] || { echo "app1 has no nano-compose-enterprise-$NANO_VERSION.tar.gz (the installed version)" >&2; exit 1; }
    r "$APP" "cat $b" | r "$h" "cat > ~/$(basename "$b")"
    r "$h" "set -e; [ -d ~/nano ] || { rm -rf ~/nano.extract && mkdir -p ~/nano.extract && tar -xzf ~/$(basename "$b") -C ~/nano.extract --strip-components=1 && mv ~/nano.extract ~/nano; }"
    if [[ "$SELF_LOGIN" == 0 ]]; then
      pipe "$APP" "~/.nano-registry-cred" "$h" "~/.nano-registry-cred"
      r "$h" "docker login us-central1-docker.pkg.dev -u oauth2accesstoken --password-stdin < ~/.nano-registry-cred >/dev/null"
    fi
  done
  say "inventory + private TLS on every host"
  DEPLOYMENT_ID="$(r "$APP" 'sed -n "s/^NANO_DEPLOYMENT_ID=//p" ~/nano/.env')"
  local inv; inv="$(render_inventory)"
  for h in "${NANO_HOSTS[@]}"; do
    printf '%s\n' "$inv" | r "$h" 'umask 077 && cat > ~/inventory.yaml && sudo install -d -m 0755 /etc/nano &&
      sudo install -m 0600 -o "$(id -un)" -g "$(id -gn)" ~/inventory.yaml /etc/nano/inventory.yaml && rm ~/inventory.yaml'
    for f in server.crt server.key ca.crt; do r "$h" "umask 077 && cat > ~/$f" < "$PKI/$f"; done
    r "$h" 'set -e; sudo install -d -m 0700 -o root -g root /root/nano-pki
      for f in server.crt server.key ca.crt; do sudo install -m 0600 -o root -g root ~/$f /root/nano-pki/$f; rm -f ~/$f; done
      sudo ~/nano/scripts/nano-tls-stage --cert /root/nano-pki/server.crt --key /root/nano-pki/server.key \
        --ca /root/nano-pki/ca.crt --output /var/lib/nano/tls/staged --installer-user "$(id -un)" >/dev/null && echo "$(hostname): tls-staged"'
  done
  old="$(r "$APP" 'sed -n "s/^NANO_DEPLOYMENT_IDENTITY_SHA256=//p" ~/nano/.env')"
  [[ "$old" =~ ^[0-9a-f]{64}$ ]] || { echo "app1 records no NANO_DEPLOYMENT_IDENTITY_SHA256" >&2; exit 1; }
  cand="$(r "$APP" "cd ~/nano && NANO_HOST_NAME=app1 python3 -I deploy/compose/render-inventory.py --inventory /etc/nano/inventory.yaml --roles $(roles_of "$APP") --identity-only --override-env .env </dev/null" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')"
  [[ "$cand" =~ ^[0-9a-f]{64}$ ]] || { echo "could not compute the new topology identity on app1" >&2; exit 1; }
  if [[ "$cand" != "$old" ]]; then
    accept="--accept-topology-migration $old"
    say "app1: acknowledge the ingest-only topology change (existing identity ${old:0:12}..., new ${cand:0:12}...)"
  else
    say "app1: the topology change is already recorded (identity ${cand:0:12}...); re-running app1"
  fi
  r "$APP" "cd ~/nano && { [ -f ~/.nano-admin-credentials ] && set -a && . ~/.nano-admin-credentials && set +a; } ;
    ${env}NANO_HOST_NAME=app1 ${LOCK_ENV}./install.sh --role $(roles_of "$APP") --inventory /etc/nano/inventory.yaml \
    $accept" > "$OUT_DIR/.add-ingest-app1.log" 2>&1 || { tail -40 "$OUT_DIR/.add-ingest-app1.log"; exit 1; }
  for h in "${NANO_HOSTS[@]}"; do [[ "$h" == "$APP" ]] || pipe "$APP" "~/nano/.env" "$h" "~/nano/.env"; done
  for h in "${new_hosts[@]}" "${CH_HOSTS[@]}" "${INGEST_HOSTS[@]}"; do
    n="$(hostname_of "$h")"
    [[ " ${done_hosts:-} " == *" $n "* ]] && continue
    done_hosts="${done_hosts:-} $n"
    say "install.sh on $n ($(roles_of "$h"))"
    r "$h" "cd ~/nano && ${env}NANO_HOST_NAME=$n ${LOCK_ENV}./install.sh --role $(roles_of "$h") --inventory /etc/nano/inventory.yaml" \
      > "$OUT_DIR/.add-ingest-$n.log" 2>&1 || { tail -40 "$OUT_DIR/.add-ingest-$n.log"; exit 1; }
    tail -1 "$OUT_DIR/.add-ingest-$n.log"
  done
  # Each new host answers on its own before it goes behind the load balancer.
  for h in "${new_hosts[@]}"; do
    r "$APP" "curl -fsS -m 10 -o /dev/null http://$(priv "$h")/healthz" \
      || { echo "$(hostname_of "$h") does not answer /healthz after its install" >&2; exit 1; }
    say "$(hostname_of "$h"): /healthz ok"
  done
  for h in "${NANO_HOSTS[@]}"; do echo "  $(hostname_of "$h") .env $(r "$h" 'sha256sum ~/nano/.env | cut -c1-16')"; done
}

# ---------------------------------------------------------------------------
# Sourced: stop here (the caller loads the topology and calls rsi_load).
[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

STEP="${1:-}"; shift || true
TOPOLOGY="" ; PKI="" ; ENROLL_FROM="" ; OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --topology) TOPOLOGY="$2"; shift 2 ;;
    --pki) PKI="$2"; shift 2 ;;
    --enrollment-cmd) ENROLL_FROM="$2"; shift 2 ;;   # a command that prints enrollment.env to stdout
    --out) OUT_DIR="$2"; shift 2 ;;
    --dry-run) UPGRADE_DRY_RUN=1; shift ;;
    -h|--help) sed -n 2,40p "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ -n "$STEP" && -n "$TOPOLOGY" ]] || { sed -n 2,40p "$0"; exit 2; }
OUT_DIR="${OUT_DIR:-$(dirname "$TOPOLOGY")}"
# shellcheck disable=SC1090
. "$TOPOLOGY"
rsi_load
mkdir -p "$OUT_DIR"
case "$STEP" in
  prep) step_prep ;;
  install) step_install ;;
  resync) step_resync ;;
  add-ingest) step_add_ingest ;;
  upgrade) step_upgrade ;;
  *) echo "unknown step $STEP (prep | install | resync | add-ingest | upgrade)" >&2; exit 2 ;;
esac
say "done"
