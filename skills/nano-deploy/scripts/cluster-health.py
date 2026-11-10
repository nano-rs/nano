#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only cluster health for a role-split host: Keeper, ClickHouse, the host's
own HAProxy gateways, and PostgreSQL/etcd/Valkey failover.

Run it ON every role-split host (standard library only):

  ssh USER@HOST 'python3 -I - --install-dir ~/nano' < cluster-health.py

It reads the host's rendered .nano-role.env (addresses, ports, TLS paths) and the
ClickHouse admin password from .env (the credential the product's own upgrade
preflight uses for these read-only system-table SELECTs), verifies the private CA,
and never prints a secret. It runs SELECT statements only.

Checks:
  keeper   ruok == imok and mntr state (leader/follower), synced followers on the leader
  ch       system.clusters for cluster 'default' (every replica listed, no errors),
           system.replicas (no read-only tables, no expired sessions, absolute_delay <= 30 s,
           the predicate the upgrade preflight uses), Keeper reachable from ClickHouse,
           and the distributed DDL queue.
  proxy    every HAProxy gateway running on this host (clickhouse-proxy, app-api-proxy,
           ingest-proxy, postgres-router, valkey-router), read from its runtime socket
           with `docker exec ... socat` ("show stat"). clickhouse-proxy, app-api-proxy and
           ingest-proxy need every backend server UP, and THIS host's own ClickHouse
           replica is reported first: when it is DOWN while the others are UP, the host's
           containers cannot reach the host's own address (typically a host firewall that
           blocks Docker bridges; see the Host firewall guide). The PostgreSQL and Valkey
           routers need exactly one member UP (the leader / master). System tables can
           look healthy while a gateway has silently lost a replica; this catches it.
  pg-ha    on postgres hosts with failover: Patroni has one Leader and, in synchronous
           mode, a Sync Standby, every member running/streaming with lag under 16 MiB;
           etcd endpoint health across the cluster; Sentinel quorum for the Valkey master.
Exit 0 = healthy, 1 = a check failed, 3 = inconclusive (re-run), 2 = not a role-split host / usage error.
"""
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

FAILS: list[str] = []
INCONCLUSIVE: list[str] = []


def row(check: str, ok: bool | None, detail: str) -> None:
    status = "PASS" if ok else ("WARN" if ok is None else "FAIL")
    if ok is False:
        FAILS.append(check)
    print(f"{status:<4} {check:<14} {detail}", flush=True)


def read_env(path: str) -> dict:
    out: dict = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                    v = v[1:-1]
                out[k.strip()] = v
    return out


def keeper(role: dict, tls: bool) -> None:
    address = role.get("NANO_HOST_ADDRESS", "127.0.0.1")
    port = int(role.get("NANO_KEEPER_CLIENT_PORT", "9181"))

    def four(cmd: bytes) -> str:
        raw = socket.create_connection((address, port), timeout=5)
        try:
            conn = raw
            if tls:
                ctx = ssl.create_default_context(cafile=role["NANO_TLS_CA"])
                ctx.load_cert_chain(certfile=role["NANO_TLS_CERT"], keyfile=role["NANO_TLS_KEY"])
                conn = ctx.wrap_socket(raw, server_hostname=role.get("NANO_TLS_SERVER_NAME") or address)
            conn.settimeout(5)
            conn.sendall(cmd)
            chunks = []
            while True:
                block = conn.recv(4096)
                if not block:
                    break
                chunks.append(block)
            return b"".join(chunks).decode("utf-8", "replace").strip()
        finally:
            raw.close()

    try:
        ok = four(b"ruok").lower() == "imok"
        metrics = dict(line.split(None, 1) for line in four(b"mntr").splitlines() if len(line.split(None, 1)) == 2)
    except (OSError, ssl.SSLError, KeyError) as err:
        row("keeper", False, f"{address}:{port} probe failed: {type(err).__name__}: {err}")
        return
    state = metrics.get("zk_server_state", "?")
    detail = f"{address}:{port} ruok={'imok' if ok else 'NO'} state={state}"
    healthy = ok and state in {"leader", "follower", "standalone"}
    if state == "leader":
        synced = metrics.get("zk_synced_followers", "?")
        detail += f" synced_followers={synced}"
        healthy = healthy and synced.isdigit() and int(synced) >= 1
    row("keeper", healthy, detail)


def clickhouse(role: dict, env: dict, tls: bool) -> None:
    address = role.get("NANO_HOST_ADDRESS", "127.0.0.1")
    port = role.get("NANO_CLICKHOUSE_PUBLISH_HTTP_PORT") or role.get("NANO_CLICKHOUSE_HTTP_PORT") or "8123"
    scheme = "https" if tls else "http"
    # Same credential and read-only SELECTs as the product's own upgrade preflight
    # (scripts/nano upgrade --dry-run): the runtime `nanosiem` user intentionally
    # cannot read system.clusters / system.replicas. The value is never printed.
    password = env.get("CLICKHOUSE_ADMIN_PASSWORD", "")
    auth = base64.b64encode(f"nanosiem_admin:{password}".encode()).decode()
    password = ""
    ctx = ssl.create_default_context(cafile=role.get("NANO_TLS_CA")) if tls else None

    def query(sql: str) -> list[dict]:
        url = f"{scheme}://{address}:{port}/?" + urllib.parse.urlencode({"default_format": "JSONEachRow"})
        req = urllib.request.Request(url, data=sql.encode(), method="POST", headers={"Authorization": "Basic " + auth})
        with urllib.request.urlopen(req, timeout=90, context=ctx) as resp:
            return [json.loads(x) for x in resp.read().decode().splitlines() if x.strip()]

    try:
        nodes = query("SELECT shard_num, replica_num, host_address, errors_count FROM system.clusters "
                      "WHERE cluster = 'default' ORDER BY shard_num, replica_num")
    except (urllib.error.URLError, OSError, ssl.SSLError) as err:
        body = ""
        if isinstance(err, urllib.error.HTTPError):
            body = err.read().decode("utf-8", "replace")[:160]
        row("ch-connect", False, f"{scheme}://{address}:{port} failed: {err} {body}")
        return
    errs = sum(int(n.get("errors_count", 0)) for n in nodes)
    row("ch-cluster", bool(nodes) and errs == 0,
        "cluster default: " + ", ".join(f"s{n['shard_num']}r{n['replica_num']}={n['host_address']}" for n in nodes)
        + f" errors={errs}")
    try:
        # Same lag predicate as the product's upgrade preflight. Avoid active_replicas /
        # total_replicas: they cost a Keeper round trip per table and time out on small hosts.
        rep = query("SELECT count() AS tables, countIf(is_readonly) AS readonly, countIf(is_session_expired) AS expired, "
                    "max(absolute_delay) AS max_delay, sum(queue_size) AS queue, "
                    "countIf(is_readonly OR is_session_expired OR absolute_delay > 30) AS bad FROM system.replicas")[0]
        ok = int(rep["tables"]) > 0 and int(rep["bad"]) == 0
        row("ch-replicas", ok, f"replicated tables={rep['tables']} readonly={rep['readonly']} expired={rep['expired']} "
            f"max_delay={rep['max_delay']}s queue={rep['queue']} unhealthy={rep['bad']}")
    except TimeoutError:
        INCONCLUSIVE.append("ch-replicas")
        row("ch-replicas", None, "system.replicas did not answer within 90 s: INCONCLUSIVE, not healthy. It can block "
            "behind table locks on a busy, small host; re-run in a few minutes, and check system.processes if it persists")
    except (urllib.error.URLError, OSError, ssl.SSLError) as err:
        row("ch-replicas", False, f"system.replicas query failed: {type(err).__name__}: {err}")
    try:
        zk = query("SELECT count() AS n FROM system.zookeeper WHERE path = '/clickhouse'")[0]
        row("ch-keeper", True, f"ClickHouse reads Keeper (/clickhouse children={zk['n']})")
    except (urllib.error.URLError, OSError, ssl.SSLError) as err:
        row("ch-keeper", False, f"system.zookeeper query failed: {err}")
    try:
        ddl = query("SELECT count() AS pending FROM system.distributed_ddl_queue "
                    "WHERE status NOT IN ('Finished','Removing')")[0]
        row("ch-ddl", int(ddl["pending"]) == 0 or None, f"distributed DDL not finished: {ddl['pending']}")
    except (urllib.error.URLError, OSError, ssl.SSLError) as err:
        row("ch-ddl", None, f"distributed_ddl_queue not readable: {err}")


# --- the host's own HAProxy gateways ------------------------------------------
# Services rendered as HAProxy with `stats socket /tmp/haproxy.sock` (render-inventory.py,
# render_ha.py). "all" = every backend server must be UP; "one" = exactly one member UP.
GATEWAYS = {"clickhouse-proxy": "all", "app-api-proxy": "all", "ingest-proxy": "all",
            "postgres-router": "one", "valkey-router": "one"}
SOCKET_CMD = 'echo "show stat" | socat stdio /tmp/haproxy.sock'
PG_LAG_LIMIT_BYTES = 16 * 1024 * 1024


def docker(args: list[str], timeout: float = 20) -> tuple[int, str]:
    """Run the docker CLI (the installer user is in the docker group). Never raises."""
    try:
        done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
        return done.returncode, done.stdout if done.returncode == 0 else (done.stderr or done.stdout)
    except (OSError, subprocess.TimeoutExpired) as err:
        return 127, f"{type(err).__name__}: {err}"


def service_container(service: str, run=docker) -> str | None:
    code, out = run(["ps", "--filter", f"label=com.docker.compose.service={service}",
                     "--filter", "status=running", "--format", "{{.Names}}"])
    names = [n for n in out.split() if n] if code == 0 else []
    return names[0] if names else None


def parse_show_stat(text: str) -> dict[str, list[tuple[str, str]]]:
    """HAProxy `show stat` CSV -> {backend: [(server, status)]} for server rows only."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith("# "):
        raise ValueError("not HAProxy show stat output")
    reader = csv.DictReader(io.StringIO("\n".join([lines[0][2:]] + lines[1:])))
    out: dict[str, list[tuple[str, str]]] = {}
    for rec in reader:
        if rec.get("type") == "2":               # 0 frontend, 1 backend, 2 server
            out.setdefault(rec["pxname"], []).append((rec["svname"], (rec.get("status") or "").strip()))
    return out


def is_up(status: str) -> bool:
    return status.startswith("UP") or status == "no check"


def judge_gateway(service: str, backends: dict[str, list[tuple[str, str]]], local_server: str | None) -> tuple[bool, str]:
    """(healthy, detail) for one gateway's backend table."""
    if GATEWAYS[service] == "one":
        # Exactly one distinct member may be UP, counted across ALL backends. postgres-router has one
        # backend listing every member; valkey-router has one backend per (member, Sentinel pair), each
        # with that member as its only server, so a replica's backends are 0/1 UP by design.
        total: dict[str, int] = {}
        up: dict[str, int] = {}
        for servers in backends.values():
            for name, st in servers:
                total[name] = total.get(name, 0) + 1
                if is_up(st):
                    up[name] = up.get(name, 0) + 1
        leaders = sorted(up)
        parts = [f"{n}={'UP' if n in up else 'DOWN'}"
                 + (f" ({up.get(n, 0)}/{total[n]} of its backends)" if total[n] > 1 else "")
                 for n in sorted(total, key=lambda n: (n not in up, n))]
        detail = ", ".join(parts) or "no backends"
        if not leaders:
            detail += " -> no member UP: writes through this router are refused"
        elif len(leaders) > 1:
            detail += f" -> {len(leaders)} members UP at once ({', '.join(leaders)}): split routing"
        return len(leaders) == 1, detail
    state: dict[str, str] = {}
    for servers in backends.values():          # a server appears in several backends; worst state wins
        for name, st in servers:
            if not is_up(st) or name not in state:
                state[name] = st
    down = sorted(n for n, st in state.items() if not is_up(st))
    order = sorted(state, key=lambda n: (n != local_server, n))
    detail = ", ".join(f"{n}{'(local)' if n == local_server else ''}={state[n]}" for n in order) or "no servers"
    if local_server and local_server in down and len(down) < len(state):
        detail += (" -> THIS HOST'S OWN replica is DOWN while others are UP: its containers cannot reach the "
                   "host's own address. Check the host firewall lets Docker bridges (docker0, br-*) reach this "
                   "host's private address (Host firewall guide); until then, losing the other replica stops writes")
    elif down:
        detail += f" -> DOWN: {', '.join(down)}"
    return not down and bool(state), detail


def gateways(role: dict, run=docker) -> None:
    shard, replica = role.get("NANO_CLICKHOUSE_SHARD"), role.get("NANO_CLICKHOUSE_REPLICA")
    local = f"ch-s{shard}-r{replica}" if shard and replica else None
    found = 0
    for service in GATEWAYS:
        name = service_container(service, run)
        if not name:
            continue
        found += 1
        code, out = run(["exec", name, "sh", "-c", SOCKET_CMD])
        try:
            if code != 0:
                raise ValueError(out.strip()[:160])
            backends = parse_show_stat(out)
        except ValueError as err:
            row(f"gw:{service}", False, f"cannot read {service}'s runtime socket: {err}")
            continue
        ok, detail = judge_gateway(service, backends, local if service == "clickhouse-proxy" else None)
        row(f"gw:{service}", ok, detail)
    if not found:
        code, out = run(["version", "--format", "{{.Server.Version}}"])
        if code != 0:
            row("gateways", None, f"docker not usable here ({out.strip()[:120]}); gateway backends NOT checked")


def judge_patroni(members: list[dict], sync_expected: bool) -> tuple[bool, str]:
    roles = [str(m.get("Role", "")).lower() for m in members]
    leaders = roles.count("leader")
    sync = sum(1 for r in roles if r.replace("_", " ") == "sync standby")
    bad = [m.get("Member") for m in members
           if str(m.get("State", "")).lower() not in ("running", "streaming")
           or (isinstance(m.get("Lag in MB"), (int, float)) and m["Lag in MB"] * 1024 * 1024 > PG_LAG_LIMIT_BYTES)]
    ok = leaders == 1 and not bad and (sync >= 1 or not sync_expected) and len(members) >= 2
    detail = " ".join(f"{m.get('Member')}={m.get('Role')}/{m.get('State')}/lag={m.get('Lag in MB', 0)}MB" for m in members)
    if leaders != 1:
        detail += f" -> {leaders} leaders"
    if sync_expected and not sync:
        detail += " -> no Sync Standby (synchronous_mode on)"
    if bad:
        detail += f" -> unhealthy: {', '.join(map(str, bad))}"
    return ok, detail


def patroni_synchronous(role: dict) -> bool:
    """Read synchronous_mode from the rendered patroni.yml (JSON). Default: on, as the inventory default."""
    path = os.path.join(role.get("NANO_GENERATED_DIR", ""), "ha", "patroni.yml")
    try:
        with open(path, encoding="utf-8") as fh:
            config = json.load(fh)
        dcs = config.get("bootstrap", {}).get("dcs", config)
        return bool(dcs.get("synchronous_mode", True))
    except (OSError, ValueError, AttributeError):
        return True


def postgres_ha(role: dict, run=docker) -> None:
    pg = service_container("postgres-ha", run)
    if not pg:
        return                                   # one postgres host: no failover stack to check
    code, out = run(["exec", pg, "patronictl", "-c", "/run/patroni/patroni.yml", "list", "-f", "json"], timeout=30)
    try:
        members = json.loads(out) if code == 0 else None
    except ValueError:
        members = None
    if not isinstance(members, list):
        row("pg-patroni", False, f"patronictl list failed: {out.strip()[:160]}")
    else:
        sync_expected = patroni_synchronous(role)
        ok, detail = judge_patroni(members, sync_expected)
        row("pg-patroni", ok, detail)
    etcd = service_container("etcd", run)
    if etcd:
        code, out = run(["exec", etcd, "/usr/local/bin/etcdctl", "--endpoints=https://127.0.0.1:2379",
                         "--cacert=/etc/nano/tls/ca.crt", "--cert=/etc/nano/tls/server.crt",
                         "--key=/etc/nano/tls/server.key", "--insecure-skip-tls-verify",
                         "--command-timeout=5s", "endpoint", "health", "--cluster", "-w", "json"], timeout=30)
        try:
            health = json.loads(out) if out.strip().startswith("[") else []
        except ValueError:
            health = []
        healthy = sum(1 for h in health if h.get("health"))
        row("pg-etcd", bool(health) and healthy == len(health),
            f"etcd members healthy {healthy}/{len(health)}" + ("" if health else f": {out.strip()[:120]}"))
    sentinel = service_container("valkey-sentinel", run)
    if sentinel:
        code, out = run(["exec", sentinel, "valkey-cli", "--tls", "--insecure", "--cert", "/etc/nano/tls/server.crt",
                         "--key", "/etc/nano/tls/server.key", "-p", "26379", "sentinel", "ckquorum", "nano"])
        row("pg-sentinel", code == 0 and out.strip().startswith("OK"), f"sentinel ckquorum nano: {out.strip()[:120]}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--install-dir", default="~/nano")
    a = ap.parse_args()
    d = os.path.expanduser(a.install_dir)
    role_path = os.path.join(d, ".nano-role.env")
    if not os.path.isfile(role_path):
        print(f"{role_path} not found: not a role-split host (single node: use smoke-test.py)", file=sys.stderr)
        return 2
    role = read_env(role_path)
    env = read_env(os.path.join(d, ".env"))
    roles = set(role.get("NANO_ROLE_PROFILES", "").split(","))
    tls = role.get("NANO_PRIVATE_TLS") == "true"
    print(f"HOST {role.get('NANO_HOST_NAME')} roles={','.join(sorted(roles))} private_tls={tls}")
    if "keeper" in roles:
        keeper(role, tls)
    if "clickhouse" in roles:
        clickhouse(role, env, tls)
    gateways(role)
    if "postgres" in roles:
        postgres_ha(role)
    verdict = "FAIL" if FAILS else ("INCONCLUSIVE" if INCONCLUSIVE else "PASS")
    print(f"CLUSTER-HEALTH {verdict} failed={len(FAILS)} inconclusive={len(INCONCLUSIVE)}")
    return 1 if FAILS else (3 if INCONCLUSIVE else 0)


if __name__ == "__main__":
    sys.exit(main())
