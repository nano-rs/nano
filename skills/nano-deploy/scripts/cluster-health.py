#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only ClickHouse replica and Keeper quorum health for a role-split host.

Run it ON a host that has the clickhouse and/or keeper role (standard library only):

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
Exit 0 = healthy, 1 = a check failed, 3 = inconclusive (re-run), 2 = not a role-split host / usage error.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
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
    verdict = "FAIL" if FAILS else ("INCONCLUSIVE" if INCONCLUSIVE else "PASS")
    print(f"CLUSTER-HEALTH {verdict} failed={len(FAILS)} inconclusive={len(INCONCLUSIVE)}")
    return 1 if FAILS else (3 if INCONCLUSIVE else 0)


if __name__ == "__main__":
    sys.exit(main())
