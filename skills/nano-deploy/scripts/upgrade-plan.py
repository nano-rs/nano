#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only upgrade planner for a nano install: what you run now, what the latest
release is, what blocks the upgrade, and the exact ordered steps for THIS install.

Runs on the operator's workstation (standard library only). It changes nothing,
and never prints a secret: it reads NANO_VERSION and a sha256 of each host's
.env, never the file.

  # Compose, role split (every host in the inventory, over SSH):
  python3 -I scripts/upgrade-plan.py compose --inventory ./nano-deploy-work/inventory.yaml \\
      [--ssh-user ubuntu] [--ssh-config ./ssh.cfg] [--ssh-target address|name]
  # Compose, single node:
  python3 -I scripts/upgrade-plan.py compose --host ubuntu@nano.example.com
  # Helm:
  python3 -I scripts/upgrade-plan.py helm --namespace nano [--release nano] [--context CTX]

Common options:
  --target X.Y.Z    plan for this release (default: the latest, from
                    GET https://api.nano.rs/api/releases/latest)
  --policy FILE|URL the TARGET package's deploy/release/upgrade-policy.json
                    (minimum source version, required stops). Without it the
                    policy is not checked here; `scripts/nano upgrade --dry-run`
                    enforces it anyway.
  --json            machine-readable result

It detects the install type (single node, multi-node HA, Helm), the version on
every host or workload, the license state (including the "upgrade required"
lock), health and free disk, then prints the path for this install:
  - from v2.0.10 or later: `scripts/nano upgrade` (Compose) with the package;
  - from v2.0.9 or earlier: re-run the installer host by host (HA: ClickHouse
    hosts, PostgreSQL replicas, then the leader's host after moving the
    PostgreSQL and Valkey primaries, then app hosts);
  - Helm: `helm pull --untar` of the new chart and `helm upgrade` with the same
    value files and --wait.
Exit 0 = plan printed (or already up to date), 1 = a blocker must be fixed
first (the plan says which), 2 = usage error or nothing could be read.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field

LATEST_URL = "https://api.nano.rs/api/releases/latest"
UPGRADE_DOC = "https://nano.rs/docs/releases/upgrading"
SCRIPTS_NANO_UPGRADE_FROM = (2, 0, 10)   # first release whose scripts/nano does registry upgrades
# Targets whose own `scripts/nano upgrade` dry run fails on every
# cluster (false positives); plan the installer rerun instead.
UPGRADER_DRY_RUN_BROKEN = {
    "2.0.11": ("v2.0.11's `scripts/nano upgrade` dry run fails on every cluster (registry-login on "
               "ghcr.io; ledger-clickhouse ocsf/193,194 on OCSF), both false positives fixed in v2.0.12: "
               "re-run the installer host by host instead, or upgrade straight to v2.0.12 "
               "(known-issues.md, 2.0.11)"),
}
DISK_FAIL_BYTES = 10 * 1024 ** 3
DISK_WARN_USE_PCT = 85
VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")

# Read-only probe, run on each Compose host with `sh -s -- INSTALL_DIR`. Prints
# key=value lines. Never prints .env content: only NANO_VERSION and a digest.
PROBE = r"""
D=${1:-$HOME/nano}
case "$D" in "~/"*) D="$HOME/${D#\~/}" ;; esac
echo "hostname=$(hostname 2>/dev/null)"
if ! cd "$D" 2>/dev/null; then echo "error=install directory $D not found"; exit 0; fi
echo "install_dir=$PWD"
if [ -f .env ]; then
  echo "version=$(awk -F= '$1=="NANO_VERSION"{v=$2} END{gsub(/["\047\r ]/,"",v); print v}' .env)"
  echo "env_sha=$(sha256sum .env 2>/dev/null | cut -c1-64)"
else
  echo "error=no .env in $PWD"
fi
if [ -f .nano-role.env ]; then
  echo "role_split=1"
  echo "roles=$(sed -n 's/^NANO_ROLE_PROFILES=//p' .nano-role.env | tr -d '"')"
  echo "member=$(sed -n 's/^NANO_HOST_ID=//p' .nano-role.env | tr -d '"')"
fi
if docker version --format '{{.Server.Version}}' >/dev/null 2>&1 </dev/null; then
  echo "docker=up"
  root=$(docker info --format '{{.DockerRootDir}}' </dev/null 2>/dev/null)
  [ -n "$root" ] || root=/var/lib/docker
  echo "docker_root=$root"
  echo "disk=$(df -Pk "$root" 2>/dev/null | awk 'NR==2{print $4*1024, $5}')"
  bad=$(docker ps -a --filter label=com.docker.compose.project --format '{{.Names}}|{{.State}}|{{.Status}}' </dev/null 2>/dev/null \
    | awk -F'|' '$2=="restarting" || $3 ~ /unhealthy/ || ($2=="exited" && $3 !~ /^Exited \(0\)/) {print $1}' | paste -sd, -)
  echo "unhealthy=$bad"
  echo "running=$(docker ps --filter label=com.docker.compose.project --format x </dev/null 2>/dev/null | wc -l | tr -d ' ')"
  pg=$(docker ps --filter label=com.docker.compose.service=postgres-ha --filter status=running --format '{{.Names}}' </dev/null | head -1)
  if [ -n "$pg" ]; then
    echo "patroni=$(docker exec "$pg" patronictl -c /run/patroni/patroni.yml list -f json </dev/null 2>/dev/null | tr -d '\n')"
  else
    pg=$(docker ps --filter label=com.docker.compose.service=postgres --filter status=running --format '{{.Names}}' </dev/null | head -1)
  fi
  if [ -n "$pg" ]; then
    lic=$(printf '%s\n' "SELECT status, valid, COALESCE(locked_reason, ''), COALESCE(last_checked_at::text, '') FROM license_status ORDER BY updated_at DESC NULLS LAST LIMIT 1;" \
      | docker exec -i "$pg" sh -c 'psql -X -At -F "|" -U "${POSTGRES_USER:-${PATRONI_SUPERUSER_USERNAME:-nanosiem}}" -d "${POSTGRES_DB:-nanosiem}"' 2>/dev/null | head -1)
    echo "license=$lic"
  fi
  vk=$(docker ps --filter label=com.docker.compose.service=valkey-ha --filter status=running --format '{{.Names}}' </dev/null | head -1)
  if [ -n "$vk" ]; then
    echo "valkey_role=$(docker exec "$vk" valkey-cli --tls --insecure --cert /etc/nano/tls/server.crt --key /etc/nano/tls/server.key -p 6379 info replication </dev/null 2>/dev/null | tr -d '\r' | sed -n 's/^role://p')"
  fi
elif docker version 2>&1 </dev/null | grep -qi "permission denied"; then
  echo "docker=no-access"
else
  echo "docker=down"
fi
"""


def parse_version(text: str | None) -> tuple[int, int, int] | None:
    match = VERSION_RE.match((text or "").strip().lstrip("v"))
    return tuple(int(x) for x in match.groups()) if match else None  # type: ignore[return-value]


def vstr(version: tuple[int, int, int] | None) -> str:
    return ".".join(map(str, version)) if version else "unknown"


@dataclass
class Unit:
    """One Compose host or one Kubernetes workload."""
    name: str
    target: str = ""
    roles: list[str] = field(default_factory=list)
    version: str = ""
    env_sha: str = ""
    docker: str = ""
    disk_free: int | None = None
    disk_use_pct: int | None = None
    unhealthy: list[str] = field(default_factory=list)
    patroni: list[dict] | None = None
    member: str = ""
    valkey_role: str = ""
    license: dict | None = None
    error: str = ""


@dataclass
class Finding:
    level: str      # PASS, WARN, FAIL (FAIL = blocker)
    check: str
    detail: str


# --- inputs ----------------------------------------------------------------------------
def parse_inventory(text: str) -> list[dict]:
    """hosts[] of the generated inventory.yaml subset: name, address, roles."""
    hosts: list[dict] = []
    in_hosts = False
    current: dict | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not raw.startswith(" ") and not raw.startswith("-"):
            in_hosts = line.strip() == "hosts:"
            continue
        if not in_hosts:
            continue
        stripped = line.strip()
        if stripped.startswith("- "):
            current = {}
            hosts.append(current)
            stripped = stripped[2:].strip()
        if current is None or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        value = value.strip()
        if key == "roles":
            current["roles"] = [r.strip() for r in value.strip("[]").split(",") if r.strip()]
        elif key in ("name", "address", "id"):
            current[key] = value.strip("\"'")
    return [h for h in hosts if h.get("name")]


def http_json(url: str, timeout: float = 15) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "nano-deploy-upgrade-plan"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def load_policy(source: str | None) -> dict | None:
    if not source:
        return None
    if source.startswith(("https://", "http://")):
        return http_json(source)
    with open(source, encoding="utf-8") as fh:
        return json.load(fh)


def run(cmd: list[str], stdin: str | None = None, timeout: float = 120) -> tuple[int, str, str]:
    try:
        done = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        return done.returncode, done.stdout, done.stderr
    except (OSError, subprocess.TimeoutExpired) as err:
        return 127, "", f"{type(err).__name__}: {err}"


def parse_probe(unit: Unit, text: str) -> None:
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        value = value.strip()
        if key == "version":
            unit.version = value
        elif key == "env_sha":
            unit.env_sha = value
        elif key == "roles" and value and not unit.roles:   # the inventory's roles win
            unit.roles = sorted(r for r in value.split(",") if r)
        elif key == "member":
            unit.member = value
        elif key == "docker":
            unit.docker = value
        elif key == "disk" and value:
            parts = value.split()
            if parts and parts[0].isdigit():
                unit.disk_free = int(parts[0])
            if len(parts) > 1 and parts[1].rstrip("%").isdigit():
                unit.disk_use_pct = int(parts[1].rstrip("%"))
        elif key == "unhealthy" and value:
            unit.unhealthy = [c for c in value.split(",") if c]
        elif key == "patroni" and value:
            try:
                members = json.loads(value)
                unit.patroni = [m for m in members if isinstance(m, dict)] if isinstance(members, list) else None
            except ValueError:
                unit.patroni = None
        elif key == "valkey_role":
            unit.valkey_role = value
        elif key == "license" and value:
            fields = value.split("|")
            fields += [""] * (4 - len(fields))
            unit.license = {"status": fields[0], "valid": fields[1] in ("t", "true"),
                            "locked_reason": fields[2], "last_checked_at": fields[3]}
        elif key == "error":
            unit.error = value


def probe_compose(units: list[Unit], ssh_base: list[str], install_dir: str) -> None:
    for unit in units:
        cmd = ssh_base + [unit.target, "sh -s -- " + shlex.quote(install_dir)]
        code, out, err = run(cmd, stdin=PROBE)
        if code != 0 and not out.strip():
            unit.error = f"ssh failed: {(err or out).strip().splitlines()[-1][:160] if (err or out).strip() else code}"
            continue
        parse_probe(unit, out)


def kubectl(base: list[str], *args: str, stdin: str | None = None) -> tuple[int, str, str]:
    return run(base + list(args), stdin=stdin, timeout=90)


def probe_helm(base: list[str], release: str) -> list[Unit]:
    code, out, err = kubectl(base, "get", "deploy,statefulset", "-l", f"app.kubernetes.io/instance={release}", "-o", "json")
    if code != 0:
        raise RuntimeError(f"kubectl get deploy,statefulset failed: {(err or out).strip()[:200]}")
    units: list[Unit] = []
    for item in json.loads(out or "{}").get("items", []):
        meta = item.get("metadata", {})
        labels = meta.get("labels", {}) or {}
        spec, status = item.get("spec", {}), item.get("status", {})
        want = int(spec.get("replicas", 1) or 0)
        ready = int(status.get("readyReplicas", 0) or 0)
        unit = Unit(name=f"{item.get('kind', '').lower()}/{meta.get('name', '?')}",
                    roles=[labels.get("app.kubernetes.io/component", "")],
                    version=str(labels.get("app.kubernetes.io/version", "")).lstrip("v"))
        if ready < want:
            unit.unhealthy = [f"{ready}/{want} ready"]
        units.append(unit)
    code, out, _ = kubectl(base, "get", "pods", "-l", f"app.kubernetes.io/instance={release},app.kubernetes.io/component=postgres",
                           "-o", "jsonpath={.items[0].metadata.name}")
    pod = out.strip() if code == 0 else ""
    if pod:
        sql = ("SELECT status, valid, COALESCE(locked_reason, ''), COALESCE(last_checked_at::text, '') "
               "FROM license_status ORDER BY updated_at DESC NULLS LAST LIMIT 1;\n")
        code, out, _ = kubectl(base, "exec", "-i", pod, "--", "sh", "-c",
                               'psql -X -At -F "|" -U "${POSTGRES_USER:-nanosiem}" -d "${POSTGRES_DB:-nanosiem}"', stdin=sql)
        holder = Unit(name="license")
        if code == 0 and out.strip():
            parse_probe(holder, "license=" + out.strip().splitlines()[0])
        code, df, _ = kubectl(base, "exec", pod, "--", "df", "-Pk", "/var/lib/postgresql/data")
        for unit in units:
            if unit.roles == ["postgres"]:
                unit.license = holder.license
                rows = df.strip().splitlines() if code == 0 else []
                if len(rows) >= 2:
                    parts = rows[1].split()
                    if len(parts) >= 5 and parts[3].isdigit():
                        unit.disk_free = int(parts[3]) * 1024
                        unit.disk_use_pct = int(parts[4].rstrip("%")) if parts[4].rstrip("%").isdigit() else None
    return units


# --- analysis --------------------------------------------------------------------------
def leader_of(units: list[Unit]) -> str:
    for unit in units:
        for member in unit.patroni or []:
            if member.get("Role") == "Leader":
                return str(member.get("Member", ""))
    return ""


def assess(kind: str, units: list[Unit], latest: dict | None, target: tuple | None, policy: dict | None) -> dict:
    findings: list[Finding] = []
    reachable = [u for u in units if not u.error]
    for unit in units:
        if unit.error:
            findings.append(Finding("FAIL", f"reach:{unit.name}", unit.error))
    versions = {u.name: parse_version(u.version) for u in reachable}
    known = [v for v in versions.values() if v]
    current = min(known) if known else None
    if known and len(set(known)) > 1:
        detail = ", ".join(f"{name}={vstr(v)}" for name, v in sorted(versions.items()))
        findings.append(Finding("FAIL", "versions", f"hosts run different releases ({detail}): finish the previous "
                                "upgrade first (the lowest is planned from)"))
    elif known:
        findings.append(Finding("PASS", "versions", f"every {'workload' if kind == 'helm' else 'host'} runs {vstr(current)}"))
    else:
        findings.append(Finding("FAIL", "versions", "no version could be read (NANO_VERSION in .env / the chart label)"))

    if kind != "helm":
        shas = {u.env_sha for u in reachable if u.env_sha}
        if len(reachable) > 1:
            if len(shas) == 1:
                findings.append(Finding("PASS", "env", f".env identical on all {len(reachable)} hosts (sha256 {next(iter(shas))[:12]})"))
            else:
                groups: dict[str, list[str]] = {}
                for u in reachable:
                    groups.setdefault(u.env_sha[:12] or "missing", []).append(u.name)
                findings.append(Finding("FAIL", "env", ".env differs between hosts: " + "; ".join(
                    f"{sha}: {', '.join(names)}" for sha, names in groups.items())
                    + ". Copy the current .env (the host that last changed it) to every host first"))
        for u in reachable:
            if u.docker == "down":
                findings.append(Finding("FAIL", f"health:{u.name}", "Docker is not running"))
            elif u.docker == "no-access":
                findings.append(Finding("FAIL", f"access:{u.name}", "the SSH user cannot use Docker (not in the "
                                        "docker group), so health, disk and the license were not read on this "
                                        "host: connect as the install owner (--ssh-user)"))
    for u in reachable:
        if u.unhealthy:
            findings.append(Finding("FAIL", f"health:{u.name}", "not healthy: " + ", ".join(u.unhealthy)))
        if u.disk_free is not None:
            gib = u.disk_free / 1024 ** 3
            if u.disk_free < DISK_FAIL_BYTES:
                findings.append(Finding("FAIL", f"disk:{u.name}", f"{gib:.1f} GiB free: the backup and new images need more"))
            elif (u.disk_use_pct or 0) >= DISK_WARN_USE_PCT:
                findings.append(Finding("WARN", f"disk:{u.name}", f"{gib:.1f} GiB free ({u.disk_use_pct}% used)"))
    if not any(f.check.startswith(("health:", "reach:", "access:")) for f in findings):
        findings.append(Finding("PASS", "health", "Docker up and no restarting, failed or unhealthy containers"
                                if kind != "helm" else "every workload has its replicas ready"))

    license_state = next((u.license for u in reachable if u.license), None)
    upgrade_required = False
    if license_state is None:
        findings.append(Finding("WARN", "license", "not read (no PostgreSQL reachable here): check Settings → License"))
    else:
        reason = license_state.get("locked_reason") or ""
        upgrade_required = "upgrade" in reason.lower()
        if upgrade_required:
            findings.append(Finding("WARN", "license", f"LOCKED: {reason}. Push ingest (HTTP, HEC, OTLP), search "
                                    "over stored data and scheduled rules keep running, and local admins can sign "
                                    "in and manage the license; SSO sign-in, pull collectors, cases, SOAR and AI "
                                    "are stopped. This upgrade is the fix: the upgraded API checks in when it "
                                    "starts and the lock clears"))
        elif reason or not license_state.get("valid"):
            findings.append(Finding("WARN", "license", f"status={license_state.get('status')} "
                                    f"valid={license_state.get('valid')} reason={reason or '-'}: fix the license; "
                                    "the upgrade dry run checks it"))
        else:
            findings.append(Finding("PASS", "license", f"status={license_state.get('status')} last check-in "
                                    f"{license_state.get('last_checked_at') or 'unknown'}"))

    latest_version = parse_version((latest or {}).get("version"))
    target = target or latest_version
    if target is None:
        findings.append(Finding("FAIL", "release", "no target: the latest release could not be read; pass --target X.Y.Z"))
    stops: list[str] = []
    if policy and target and current:
        entry = (policy.get("releases") or {}).get(vstr(target)) or policy.get("default") or {}
        min_from = parse_version(entry.get("min_from_version"))
        if min_from and current < min_from:
            findings.append(Finding("FAIL", "policy", f"{vstr(target)} upgrades only from {vstr(min_from)} or later; "
                                    f"upgrade to {entry.get('previous_supported_version') or vstr(min_from)} first"))
        stops = [s for s in entry.get("required_stops") or []
                 if (sv := parse_version(s)) and current < sv < target]
        findings.append(Finding("PASS" if not stops else "WARN", "policy",
                                f"from {vstr(current)} to {vstr(target)}: minimum source "
                                f"{entry.get('min_from_version') or 'any'}, "
                                + (f"required stop(s) {', '.join(stops)}: upgrade to each in turn" if stops
                                   else "no required stops")))
    elif target and current:
        findings.append(Finding("WARN", "policy", "not checked here (pass --policy <target package>/deploy/release/"
                                "upgrade-policy.json); `scripts/nano upgrade --dry-run` enforces it"))

    if kind == "helm":
        path = "helm"
    elif current and current >= SCRIPTS_NANO_UPGRADE_FROM:
        path = "nano-upgrade"
    else:
        path = "rerun"
    forced_rerun = False
    if path == "nano-upgrade" and target and vstr(target) in UPGRADER_DRY_RUN_BROKEN:
        # That release's own upgrader refuses every cluster with
        # false positives; its installer rerun works.
        path = "rerun"
        forced_rerun = True
        findings.append(Finding("WARN", "known-issue", UPGRADER_DRY_RUN_BROKEN[vstr(target)]))
    return {
        "kind": kind, "current": vstr(current), "target": vstr(target), "latest": latest or {},
        "up_to_date": bool(current and target and current >= target),
        "path": path, "forced_rerun": forced_rerun, "stops": stops, "upgrade_required_lock": upgrade_required,
        "pg_leader": leader_of(reachable),
        "valkey_master": next((u.name for u in reachable if u.valkey_role == "master"), ""),
        "findings": [asdict(f) for f in findings],
        "units": [asdict(u) for u in units],
        "blocked": any(f.level == "FAIL" for f in findings),
    }


# --- steps -----------------------------------------------------------------------------
def ssh_cmd(name: str) -> str:
    return f"ssh {name}"


def compose_steps(result: dict, units: list[Unit], install_dir: str) -> list[str]:
    target = result["target"]
    package = f"nano-compose-enterprise-{target}.tar.gz"
    role_split = len(units) > 1 or any(u.roles for u in units)
    by_role = lambda role: [u for u in units if role in u.roles]   # noqa: E731
    app_hosts = by_role("app")
    first_app = (app_hosts or units)[0].name
    inv = " --inventory /etc/nano/inventory.yaml" if role_split else ""
    steps = [
        f"Precheck: on every host `python3 -I - --install-dir {install_dir} < scripts/cluster-health.py` "
        "(role split) and `smoke-test.py` must PASS. Read the release notes and known-issues.md.",
        f"Download and verify the package: `bash scripts/fetch-bundle.sh --enrollment ./nano-deploy-work/enrollment.env "
        f"--version {target}` (must print VERIFIED). Copy {package} with its .sha256 and .sha256.sig to the same "
        "path on every host, e.g. /srv/nano/releases/.",
    ]
    if result["path"] == "nano-upgrade":
        steps += [
            f"On every host, extract it over the install directory (keeps .env, .nano-role.env and generated state): "
            f"`tar -xzf /srv/nano/releases/{package} --strip-components=1 -C {install_dir}`.",
            "On every host, log in to the registry with a fresh pull credential (about one hour), right before the run.",
        ]
        cmd = (f"cd {install_dir} && scripts/nano upgrade{inv} --bundle /srv/nano/releases/{package}"
               + (f" --remote-bundle /srv/nano/releases/{package} --remote-install-dir {install_dir}" if role_split else "")
               + " --backup-key-file /secure/nano-backup/operator.pem"
               + (f" --backup-output /mnt/nano-backups/upgrade-{target}" if role_split else ""))
        # The upgrade drains ingest hosts (2+) and app hosts (2+).
        drains = len(by_role("ingest")) > 1 or len(by_role("app")) > 1
        if drains:
            cmd += " --lb-drain-command /usr/local/sbin/nano-lb-drain --lb-rejoin-command /usr/local/sbin/nano-lb-rejoin"
        if role_split:
            # None of these exist after a fresh install.
            steps.append(
                f"Prerequisites (upgrade.md, Path A): non-interactive SSH from {first_app} to every other host; "
                + ("the drain/rejoin hooks at /usr/local/sbin/nano-lb-drain and nano-lb-rejoin on every app and "
                   "ingest host, mapping inventory names to the load balancer's server names (start from "
                   "deploy/compose/examples/load-balancer/nano-lb-hook); on each load balancer, "
                   "nano-lb-haproxy (beside the hook) as the nano-lb key's forced command, never `sudo socat` "
                   "itself; each HAProxy's runtime socket at `level admin`. The dry run drains and rejoins "
                   "each of those hosts through the hooks to prove it." if drains else "")
            )
        steps += [
            f"Dry run (read-only; verifies the signature, policy, registry pulls, disk, license) on {first_app}: "
            f"`{ssh_cmd(first_app)} '{cmd} --dry-run'`. Every row must pass; never bypass a gate.",
            f"Ask, then run it for real: `{ssh_cmd(first_app)} '{cmd}'`. It takes the mandatory backup and rolls "
            + ("Keeper → ClickHouse → PostgreSQL (replicas, switchover, old leader; Valkey master moved first) → "
               "migrations → app → ingest, one host at a time." if role_split else "the stack."),
            "If it stops: fix the cause (usually an expired registry login), then re-run with `--resume` and the same "
            "package. Never delete upgrade-journal/.",
        ]
    else:
        lock = "NANO_IMAGES_LOCK=images.enterprise.customer.lock"
        if not role_split:
            steps += [
                f"Back up: `{ssh_cmd(first_app)} 'cd {install_dir} && scripts/nano backup --key-file "
                "/secure/nano-backup/operator.pem --output /mnt/backup/nano-pre-" + target + "'`.",
                f"Extract the package over {install_dir}, log in to the registry, then re-run the installer: "
                f"`{ssh_cmd(first_app)} 'cd {install_dir} && {lock} ./install.sh'`.",
            ]
        else:
            steps.append(f"Back up: `{ssh_cmd(first_app)} 'cd {install_dir} && scripts/nano backup-set --inventory "
                         "/etc/nano/inventory.yaml --backup-key-file /secure/nano-backup/operator.pem --backup-output "
                         f"/mnt/backup/nano-pre-{target}'`.")
            steps.append(f"On every host: extract the package over {install_dir} and log in to the registry.")
            leader = result["pg_leader"]
            pg_hosts = by_role("postgres")
            members = {u.name: u.member for u in pg_hosts}
            pg_order = sorted(pg_hosts, key=lambda u: (u.member == leader and bool(leader), u.name))
            order = [u for u in units if "clickhouse" in u.roles and "postgres" not in u.roles]
            order += pg_order
            order += [u for u in app_hosts if u not in order]
            order += [u for u in units if u not in order]
            first = True
            for u in order:
                roles = ",".join(u.roles) or "<its roles>"
                pre: list[str] = []
                if "ingest" in u.roles or "app" in u.roles:
                    pre.append("take it out of the load balancer and wait for the drain")
                if u.valkey_role == "master":
                    pre.append("move the Valkey master off it first (rerunning a PostgreSQL host restarts its Valkey "
                               "and Sentinel): `valkey-cli ... -p 26379 SENTINEL failover nano` in its valkey-sentinel "
                               "container (upgrade.md, Path B), then wait until "
                               "`SENTINEL get-master-addr-by-name nano` names another host")
                if leader and members.get(u.name) == leader:
                    pre.append(f"it holds the PostgreSQL leader ({leader}): the {target} installer switches over to the "
                               "synchronous standby before recreating it; check `patronictl list` afterwards")
                text = (f"{u.name}: " + ("; ".join(pre) + "; then " if pre else "")
                        + f"`{ssh_cmd(u.name)} 'cd {install_dir} && NANO_HOST_NAME={u.name} {lock} ./install.sh "
                        f"--role {roles} --inventory /etc/nano/inventory.yaml'`; cluster-health.py must PASS"
                        + ("; put it back in the load balancer" if ("ingest" in u.roles or "app" in u.roles) else "")
                        + ".")
                steps.append(text)
                if first:
                    steps.append(f"Copy {u.name}'s .env to every other host NOW: its rerun changed NANO_VERSION (it "
                                 "prints 'The shared .env changed'). Check `sha256sum .env` matches everywhere before "
                                 "the next host.")
                    first = False
            steps.append("Keeper runs on the PostgreSQL hosts and ingest on the ClickHouse hosts in the planner's "
                         "layout: each rerun above upgrades every role on that host; never pass a narrower --role.")
    steps += [
        "Verify: cluster-health.py PASS on every host, smoke-test.py PASS, every host reports NANO_VERSION="
        f"{target} (re-run this planner), and `sha256sum .env` is identical on every host.",
        "Reversible: the image swap (`scripts/nano rollback` while the schema is unchanged). Not reversible: database "
        "migrations are forward-only; after they run, going back means restoring the pre-upgrade backup.",
    ]
    return steps


def helm_steps(result: dict, namespace: str, release: str) -> list[str]:
    target = result["target"]
    return [
        f"Precheck: `python3 -I scripts/k8s-health.py --namespace {namespace} --release {release}` and smoke-test.py "
        "against both hostnames must PASS. Read the release notes (new ClickHouse operator CRDs?).",
        f"Back up: `helm get values {release} -n {namespace} -o yaml` and the chart version, the nano-secrets Secret "
        "(out of band, encrypted), PostgreSQL (managed snapshot, or pg_dump from the bundled pod) and ClickHouse "
        "(BACKUP ... TO S3 per shard, or PVC snapshots).",
        f"Pull the new chart into a FRESH directory: `rm -rf nano && helm pull \"$CHART\" --version {target} --untar` "
        "(the old ./nano's values-customer-images.yaml pins the old image digests).",
        "Apply new CRDs first if the release notes say so (`kubectl apply --server-side -f nano/crds/...`).",
        f"Dry run: `helm upgrade {release} ./nano -n {namespace} -f <the SAME value files, in the SAME order> "
        "--dry-run=server` and review the diff.",
        f"Upgrade: `helm upgrade {release} ./nano -n {namespace} -f <same files, same order> --wait --timeout 20m`. "
        "Migrations run as a pre-upgrade hook.",
        f"Verify: k8s-health.py PASS, smoke-test.py PASS, and every workload labelled app.kubernetes.io/version={target} "
        "(re-run this planner).",
        "Reversible: nothing after the migration hook ran. `helm rollback` across a schema change is not supported: "
        "roll forward, or restore the backup (nano.rs/docs/getting-started/kubernetes#upgrade-recovery).",
    ]


# --- output ----------------------------------------------------------------------------
def render(result: dict, steps: list[str]) -> str:
    out: list[str] = []
    latest = result["latest"]
    head = f"You're on {result['current']}; latest is {latest.get('version', 'unknown')}"
    if result["target"] != latest.get("version"):
        head += f"; planning for {result['target']}"
    out.append(head + ".")
    if latest.get("summary"):
        out.append(f"What changes in {latest.get('version')}: {latest['summary']}")
    if latest.get("securityRelease"):
        out.append("This release includes security fixes: upgrading is recommended.")
    if latest.get("releaseNotesUrl"):
        out.append(f"Release notes: {latest['releaseNotesUrl']}  Upgrade guide: {latest.get('upgradeUrl') or UPGRADE_DOC}")
    out.append("")
    kind = {"single": "single node (Compose)", "ha": "multi-node HA (Compose role split)", "helm": "Kubernetes (Helm)"}
    out.append(f"Install: {kind[result['install_type']]}")
    for unit in result["units"]:
        extra = []
        if unit["roles"] and unit["roles"] != [""]:
            extra.append("roles=" + ",".join(unit["roles"]))
        if unit["disk_free"] is not None:
            extra.append(f"free={unit['disk_free'] / 1024 ** 3:.0f}GiB")
        if unit["valkey_role"] == "master":
            extra.append("valkey=master")
        if result["pg_leader"] and unit["member"] == result["pg_leader"]:
            extra.append("pg=leader")
        out.append(f"  {unit['name']:<28} {unit['version'] or '?':<10} {' '.join(extra)}"
                   + (f"  ERROR {unit['error']}" if unit["error"] else ""))
    out.append("")
    for f in result["findings"]:
        out.append(f"{f['level']:<4} {f['check']:<18} {f['detail']}")
    out.append("")
    if result["up_to_date"]:
        out.append(f"UP TO DATE: {result['current']} is the target release. Nothing to do.")
        return "\n".join(out) + "\n"
    label = {"nano-upgrade": "from v2.0.10 or later: scripts/nano upgrade with the package",
             "rerun": ("re-run the installer host by host (this target's scripts/nano upgrade has a known issue)"
                       if result.get("forced_rerun") else
                       "from v2.0.9 or earlier: re-run the installer host by host"),
             "helm": "Helm: pull the new chart, upgrade with the same values"}[result["path"]]
    if result["stops"]:
        out.append(f"Required stops: upgrade to {', '.join(result['stops'])} first, then to {result['target']}; "
                   "re-run this planner after each.")
    out.append(f"Path: {label}")
    for i, step in enumerate(steps, 1):
        out.append(f"{i:>2}. {step}")
    out.append("")
    out.append("UPGRADE-PLAN " + ("BLOCKED: fix every FAIL above first" if result["blocked"] else "READY"))
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="kind", required=True)
    compose = sub.add_parser("compose", help="Docker Compose install (single node or role split)")
    where = compose.add_mutually_exclusive_group(required=True)
    where.add_argument("--inventory", help="the cluster's inventory.yaml (role split)")
    where.add_argument("--host", help="single node: [user@]host")
    compose.add_argument("--ssh-user")
    compose.add_argument("--ssh-config")
    compose.add_argument("--ssh-option", action="append", default=[], help="extra ssh -o option (repeatable)")
    compose.add_argument("--ssh-target", choices=["address", "name"], default="address",
                         help="connect to each inventory host by its address (default) or its name (ssh config alias)")
    compose.add_argument("--install-dir", default="~/nano")
    helm = sub.add_parser("helm", help="Kubernetes install from the Helm chart")
    helm.add_argument("--namespace", required=True)
    helm.add_argument("--release", default="nano")
    helm.add_argument("--context")
    for p in (compose, helm):
        p.add_argument("--target", help="plan for this release (default: the latest)")
        p.add_argument("--latest-url", default=LATEST_URL)
        p.add_argument("--policy", help="the target package's upgrade-policy.json (path or URL)")
        p.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    target = parse_version(a.target) if a.target else None
    if a.target and not target:
        print(f"upgrade-plan: --target must be X.Y.Z (got {a.target!r})", file=sys.stderr)
        return 2
    latest: dict | None = None
    try:
        latest = http_json(a.latest_url)
    except (urllib.error.URLError, OSError, ValueError) as err:
        print(f"upgrade-plan: cannot read the latest release from {a.latest_url}: {err}", file=sys.stderr)
        if not target:
            print("upgrade-plan: pass --target X.Y.Z to plan without it", file=sys.stderr)
            return 2
    try:
        policy = load_policy(a.policy)
    except (OSError, ValueError, urllib.error.URLError) as err:
        print(f"upgrade-plan: cannot read the upgrade policy {a.policy}: {err}", file=sys.stderr)
        return 2

    if a.kind == "compose":
        ssh_base = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
        if a.ssh_config:
            ssh_base += ["-F", a.ssh_config]
        for option in a.ssh_option:
            ssh_base += ["-o", option]
        if a.inventory:
            try:
                with open(a.inventory, encoding="utf-8") as fh:
                    hosts = parse_inventory(fh.read())
            except OSError as err:
                print(f"upgrade-plan: {err}", file=sys.stderr)
                return 2
            if not hosts:
                print(f"upgrade-plan: no hosts in {a.inventory}", file=sys.stderr)
                return 2
            units = []
            for h in hosts:
                dest = h.get("address") if a.ssh_target == "address" else h["name"]
                if a.ssh_user and "@" not in str(dest):
                    dest = f"{a.ssh_user}@{dest}"
                units.append(Unit(name=h["name"], target=str(dest), roles=sorted(h.get("roles", []))))
        else:
            units = [Unit(name=a.host.split("@")[-1], target=a.host)]
        probe_compose(units, ssh_base, a.install_dir)
        if all(u.error for u in units):
            print("upgrade-plan: no host could be read:\n  " + "\n  ".join(f"{u.name}: {u.error}" for u in units),
                  file=sys.stderr)
            return 2
        result = assess("compose", units, latest, target, policy)
        result["install_type"] = "ha" if len(units) > 1 else "single"
        steps = compose_steps(result, units, a.install_dir)
    else:
        base = ["kubectl"] + (["--context", a.context] if a.context else []) + ["-n", a.namespace]
        try:
            units = probe_helm(base, a.release)
        except (RuntimeError, ValueError) as err:
            print(f"upgrade-plan: {err}", file=sys.stderr)
            return 2
        if not units:
            print(f"upgrade-plan: no workloads of release {a.release} in namespace {a.namespace}", file=sys.stderr)
            return 2
        result = assess("helm", units, latest, target, policy)
        result["install_type"] = "helm"
        steps = helm_steps(result, a.namespace, a.release)
    result["steps"] = [] if result["up_to_date"] else steps
    if a.json:
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        sys.stdout.write(render(result, steps))
    return 1 if result["blocked"] and not result["up_to_date"] else 0


if __name__ == "__main__":
    sys.exit(main())
