"""A realistic, deterministic OCSF dataset for the deep Search / Dashboards /
Notebooks workflows (NAN-5684).

Three source types, the way a small SOC sees them:

- ``<prefix>_auth``  Authentication (3002): logons from a fleet of
  workstations and servers, a brute-force burst against one account, and one
  service account logging on once from an outside address.
- ``<prefix>_net``   Network Activity (4001): outbound flows with ports,
  protocols and byte counts, mostly to a handful of busy destinations plus one
  destination seen exactly once.
- ``<prefix>_proc``  Process Activity (1007): process launches with command
  lines, parents and SHA-256 hashes, including one binary seen once on one
  host (a rare hash for the rarity scatter).
- ``<prefix>_dns``   DNS Activity (4003): lookups of a few busy domains from
  every host, plus one domain looked up once from one host.

The events span the last 72 hours (hour-of-day weighted, so a timechart has a
day/night shape) with a dense tail in the last 30 minutes, which keeps the
default search window populated. Rows are written into
``nanosiem.ocsf_logs_raw`` as ``{event, source_type}``, exactly the shape
Vector and Tenzir write; the ingest materialized views (promoted columns,
prevalence) run on them as on any other ingest. Nothing here is UDM.

Everything is generated from a seeded PRNG, and the ground truth (per-user,
per-host, per-port counts, the rare values) is computed from the same rows, so
the scenarios compare the UI with the API AND with what was sent.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from nano_e2e.stack import Stack

HOURS = 72
RECENT_MINUTES = 30

USERS = [
    "alice.nguyen", "bob.okafor", "carol.diaz", "dave.kim", "erin.walsh", "frank.ito", "grace.lund",
    "heidi.park", "ivan.rossi", "judy.chen", "mallory.fox", "oscar.berg", "peggy.shah", "trent.cole",
]
WORKSTATIONS = [f"ws-{i:02d}" for i in range(1, 19)]
SERVERS = ["dc-01", "dc-02", "file-01", "web-01", "db-01", "jump-01"]
HOSTS = WORKSTATIONS + SERVERS
PUBLIC_DSTS = ["203.0.113.10", "203.0.113.20", "198.51.100.7", "198.51.100.44", "192.0.2.80"]
PORTS = [(443, 6, 0.55), (80, 6, 0.12), (53, 17, 0.18), (22, 6, 0.05), (3389, 6, 0.04), (445, 6, 0.06)]
PROCESSES = [
    ("chrome.exe", "explorer.exe", '"C:\\Program Files\\Google\\Chrome\\chrome.exe" --type=renderer'),
    ("outlook.exe", "explorer.exe", '"C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE"'),
    ("powershell.exe", "explorer.exe", "powershell.exe -NoProfile -Command Get-ChildItem"),
    ("svchost.exe", "services.exe", "svchost.exe -k netsvcs -p"),
    ("cmd.exe", "explorer.exe", "cmd.exe /c whoami"),
    ("teams.exe", "explorer.exe", '"C:\\Users\\Public\\Teams\\current\\Teams.exe"'),
]
DOMAINS = ["login.microsoftonline.com", "update.googleapis.com", "slack-edge.com", "github.com", "outlook.office365.com"]
BRUTE_USER = "judy.chen"
BRUTE_FAILURES = 40


@dataclass
class SocData:
    """The seeded dataset's identity and ground truth."""

    tag: str
    auth: str  # source_type values
    net: str
    proc: str
    dns: str
    start: datetime  # earliest event
    end: datetime  # latest event
    total: int
    by_source: dict[str, int]
    auth_by_user: dict[str, int]
    auth_failures_by_user: dict[str, int]
    auth_by_host: dict[str, int]
    net_by_port: dict[int, int]
    net_by_dst: dict[str, int]
    net_bytes_out_by_host: dict[str, int]
    proc_by_name: dict[str, int]
    dns_by_domain: dict[str, int]
    proc_hash: dict[str, str]  # process name -> sha256
    private_src_auth: int  # auth events whose src_endpoint.ip is RFC1918
    rare_user: str
    rare_ip: str
    rare_process: str
    rare_process_host: str
    rare_dst: str
    rare_hash: str
    rare_domain: str
    rare_domain_host: str
    recent_by_source: dict[str, int] = field(default_factory=dict)

    @property
    def sources(self) -> list[str]:
        return [self.auth, self.net, self.proc, self.dns]

    def where(self, *sources: str) -> str:
        """The nPL filter selecting the seeded rows of the given source types."""
        names = sources or tuple(self.sources)
        if len(names) == 1:
            return f'source_type="{names[0]}"'
        return "(" + " OR ".join(f'source_type="{s}"' for s in names) + ")"

    def window(self) -> dict[str, str]:
        """A time range covering every seeded event (API `time_range`)."""
        return {
            "start": (self.start - timedelta(minutes=5)).isoformat(),
            "end": (self.end + timedelta(minutes=10)).isoformat(),
        }


def _hour_weight(t: datetime) -> float:
    """Business hours are busy, nights are quiet: the timechart has a shape."""
    h = t.hour
    return 1.0 if 8 <= h < 19 else 0.25


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _private(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.")) or any(ip.startswith(f"172.{n}.") for n in range(16, 32))


def build(tag: str, now: datetime | None = None, seed: int = 5684) -> tuple[SocData, list[dict[str, Any]]]:
    """(ground truth, ingest rows) for one dataset. Pure: no I/O."""
    rng = random.Random(seed)
    now = (now or datetime.now(UTC)).replace(microsecond=0)
    prefix = f"deep_{tag}"
    auth_st, net_st, proc_st, dns_st = f"{prefix}_auth", f"{prefix}_net", f"{prefix}_proc", f"{prefix}_dns"
    proc_hash = {name: sha256(f"nano-e2e-deep:{name}") for name, _, _ in PROCESSES}
    host_ip = {h: f"10.20.{i // 200}.{i % 200 + 10}" for i, h in enumerate(HOSTS)}
    user_host = {u: WORKSTATIONS[i % len(WORKSTATIONS)] for i, u in enumerate(USERS)}
    rows: list[dict[str, Any]] = []
    seq = 0

    def emit(source_type: str, t: datetime, event: dict[str, Any]) -> None:
        nonlocal seq
        seq += 1
        event.setdefault("metadata", {})
        event["metadata"].update(
            {
                "uid": f"{prefix}-{seq}",
                "version": "1.8.0",
                "log_source": source_type,
                "product": {"name": "nano-e2e-deep", "vendor_name": "nano"},
            }
        )
        event["time"] = int(t.timestamp() * 1000)
        rows.append({"source_type": source_type, "event": event, "_t": t})

    def auth(t: datetime, user: str, src_ip: str, host: str, ok: bool) -> None:
        emit(
            auth_st,
            t,
            {
                "class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201,
                "class_name": "Authentication", "activity_name": "Logon",
                "severity_id": 1 if ok else 3, "status_id": 1 if ok else 2,
                "status": "Success" if ok else "Failure",
                "actor": {"user": {"name": user}}, "user": {"name": user},
                "src_endpoint": {"ip": src_ip}, "device": {"hostname": host, "ip": host_ip[host]},
                "message": f"{'Successful' if ok else 'Failed'} logon for {user} on {host} from {src_ip}",
            },
        )

    def flow(t: datetime, host: str, dst: str, port: int, proto: int, bout: int, bin_: int) -> None:
        emit(
            net_st,
            t,
            {
                "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106,
                "class_name": "Network Activity", "activity_name": "Traffic", "severity_id": 1,
                "src_endpoint": {"ip": host_ip[host], "port": 49152 + (seq % 10000)},
                "dst_endpoint": {"ip": dst, "port": port},
                "connection_info": {"protocol_num": proto},
                "traffic": {"bytes_out": bout, "bytes_in": bin_},
                "device": {"hostname": host, "ip": host_ip[host]},
                "message": f"{host} -> {dst}:{port} out={bout} in={bin_}",
            },
        )

    def proc(t: datetime, host: str, user: str, name: str, parent: str, cmd: str, digest: str = "") -> None:
        emit(
            proc_st,
            t,
            {
                "class_uid": 1007, "category_uid": 1, "activity_id": 1, "type_uid": 100701,
                "class_name": "Process Activity", "activity_name": "Launch", "severity_id": 1,
                "actor": {"user": {"name": user}},
                "process": {
                    "name": name, "cmd_line": cmd, "pid": 1000 + seq % 60000,
                    "file": {
                        "path": f"C:\\Windows\\System32\\{name}",
                        "hashes": [{"algorithm_id": 3, "algorithm": "SHA-256",
                                    "value": digest or proc_hash.get(name, sha256(name))}],
                    },
                    "parent_process": {"name": parent},
                },
                "device": {"hostname": host, "ip": host_ip[host]},
                "message": f"{user} launched {name} on {host}",
            },
        )

    def dns(t: datetime, host: str, domain: str) -> None:
        emit(
            dns_st,
            t,
            {
                "class_uid": 4003, "category_uid": 4, "activity_id": 1, "type_uid": 400301,
                "class_name": "DNS Activity", "activity_name": "Query", "severity_id": 1,
                "src_endpoint": {"ip": host_ip[host]}, "dst_endpoint": {"ip": "10.20.0.53", "port": 53},
                "query": {"hostname": domain, "type": "A", "class": "IN"},
                "device": {"hostname": host, "ip": host_ip[host]},
                "message": f"{host} resolved {domain}",
            },
        )

    def pick_port() -> tuple[int, int]:
        r = rng.random()
        acc = 0.0
        for port, proto, w in PORTS:
            acc += w
            if r <= acc:
                return port, proto
        return PORTS[0][0], PORTS[0][1]

    # The background: every 20 minutes over 72 hours, a hour-weighted batch.
    t = now - timedelta(hours=HOURS)
    while t < now - timedelta(minutes=RECENT_MINUTES):
        w = _hour_weight(t)
        for _ in range(max(1, int(6 * w))):
            u = rng.choice(USERS)
            host = user_host[u] if rng.random() < 0.8 else rng.choice(SERVERS)
            src = host_ip[user_host[u]] if rng.random() < 0.85 else rng.choice(PUBLIC_DSTS[:3])
            auth(t + timedelta(seconds=rng.randint(0, 1100)), u, src, host, rng.random() > 0.08)
        for _ in range(max(1, int(8 * w))):
            host = rng.choice(HOSTS)
            port, proto = pick_port()
            dst = rng.choice(PUBLIC_DSTS) if rng.random() < 0.85 else host_ip[rng.choice(SERVERS)]
            flow(t + timedelta(seconds=rng.randint(0, 1100)), host, dst, port, proto,
                 rng.randint(200, 50_000), rng.randint(500, 400_000))
        for _ in range(max(1, int(4 * w))):
            u = rng.choice(USERS)
            name, parent, cmd = rng.choice(PROCESSES)
            proc(t + timedelta(seconds=rng.randint(0, 1100)), user_host[u], u, name, parent, cmd)
        for _ in range(max(1, int(5 * w))):
            dns(t + timedelta(seconds=rng.randint(0, 1100)), rng.choice(HOSTS), rng.choice(DOMAINS))
        t += timedelta(minutes=20)

    # A dense tail in the last 30 minutes, so the default window has data.
    for i in range(60):
        tt = now - timedelta(seconds=30 * (60 - i))
        u = USERS[i % len(USERS)]
        auth(tt, u, host_ip[user_host[u]], user_host[u], True)
        port, proto = pick_port()
        flow(tt, user_host[u], PUBLIC_DSTS[i % len(PUBLIC_DSTS)], port, proto, 1000 + i, 5000 + i)
        if i % 2 == 0:
            name, parent, cmd = PROCESSES[i % len(PROCESSES)]
            proc(tt, user_host[u], u, name, parent, cmd)
        dns(tt, HOSTS[i % len(HOSTS)], DOMAINS[i % len(DOMAINS)])

    # The brute force: 40 failures in 10 minutes against one account, 6 h ago.
    burst = now - timedelta(hours=6)
    for i in range(BRUTE_FAILURES):
        auth(burst + timedelta(seconds=15 * i), BRUTE_USER, "198.51.100.66", "jump-01", False)

    # The rare ones (each exactly once).
    rare_user, rare_ip = f"svc-backup-{tag}", "185.220.101.9"
    auth(now - timedelta(hours=30), rare_user, rare_ip, "file-01", True)
    rare_process, rare_host = f"rare-{tag}.exe", "ws-07"
    rare_hash = sha256(f"nano-e2e-deep:rare:{tag}")
    proc(now - timedelta(hours=20), rare_host, "mallory.fox", rare_process, "powershell.exe",
         f"C:\\Users\\Public\\{rare_process} -enc SQBFAFgA", digest=rare_hash)
    # The rare binary also runs once in the recent window, so the rarity
    # scatter (which auto-loads for windows <= 4h) has a rare dot to show.
    proc(now - timedelta(minutes=10), rare_host, "mallory.fox", rare_process, "powershell.exe",
         f"C:\\Users\\Public\\{rare_process} -enc SQBFAFgA", digest=rare_hash)
    rare_domain, rare_domain_host = f"c2-{tag}.badexample.net", "ws-07"
    dns(now - timedelta(minutes=12), rare_domain_host, rare_domain)
    rare_dst = "45.83.64.1"
    flow(now - timedelta(hours=12), "ws-07", rare_dst, 8443, 6, 2_500_000, 900)

    # Ground truth from the very rows that are written.
    by_source = Counter(r["source_type"] for r in rows)
    a = [r["event"] for r in rows if r["source_type"] == auth_st]
    n = [r["event"] for r in rows if r["source_type"] == net_st]
    p = [r["event"] for r in rows if r["source_type"] == proc_st]
    d = [r["event"] for r in rows if r["source_type"] == dns_st]
    bytes_out: Counter[str] = Counter()
    for e in n:
        bytes_out[e["device"]["hostname"]] += e["traffic"]["bytes_out"]
    recent_cut = now - timedelta(minutes=RECENT_MINUTES)
    truth = SocData(
        tag=tag, auth=auth_st, net=net_st, proc=proc_st, dns=dns_st,
        start=min(r["_t"] for r in rows), end=max(r["_t"] for r in rows), total=len(rows),
        by_source=dict(by_source),
        auth_by_user=dict(Counter(e["actor"]["user"]["name"] for e in a)),
        auth_failures_by_user=dict(Counter(e["actor"]["user"]["name"] for e in a if e["status_id"] == 2)),
        auth_by_host=dict(Counter(e["device"]["hostname"] for e in a)),
        net_by_port=dict(Counter(e["dst_endpoint"]["port"] for e in n)),
        net_by_dst=dict(Counter(e["dst_endpoint"]["ip"] for e in n)),
        net_bytes_out_by_host=dict(bytes_out),
        proc_by_name=dict(Counter(e["process"]["name"] for e in p)),
        dns_by_domain=dict(Counter(e["query"]["hostname"] for e in d)),
        proc_hash=proc_hash,
        private_src_auth=sum(1 for e in a if _private(e["src_endpoint"]["ip"])),
        rare_user=rare_user, rare_ip=rare_ip, rare_process=rare_process, rare_process_host=rare_host,
        rare_dst=rare_dst, rare_hash=rare_hash, rare_domain=rare_domain, rare_domain_host=rare_domain_host,
        recent_by_source=dict(Counter(r["source_type"] for r in rows if r["_t"] >= recent_cut)),
    )
    return truth, rows


def insert(stack: Stack, rows: list[dict[str, Any]], batch: int = 2000) -> None:
    """Write the rows into the ingest view (what Vector writes), synchronously."""
    if not stack.ch_url:
        raise RuntimeError("seeding needs the stack's ClickHouse (a throwaway stack, not --target existing)")
    for i in range(0, len(rows), batch):
        body = "\n".join(
            json.dumps({"source_type": r["source_type"], "event": r["event"]}) for r in rows[i : i + batch]
        )
        resp = httpx.post(
            stack.ch_url,
            params={"query": "INSERT INTO nanosiem.ocsf_logs_raw (source_type, event) "
                             "SETTINGS async_insert = 0 FORMAT JSONEachRow"},
            content=body.encode(),
            auth=(stack.ch_admin_user, stack.ch_admin_password),
            timeout=120,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"seeding insert failed: HTTP {resp.status_code}: {resp.text[:500]}")


def existing_anchor(stack: Stack, tag: str) -> datetime | None:
    """The `now` an earlier seed of this tag was built with (a kept stack that
    is re-run), so the same rows are not written twice and the ground truth's
    window still covers them. The dense tail's last auth event is now - 30 s."""
    resp = httpx.post(
        stack.ch_url,
        content=(f"SELECT toUnixTimestamp64Milli(max(timestamp)), count() FROM nanosiem.ocsf_logs "
                 f"WHERE source_type = 'deep_{tag}_auth' FORMAT TSV").encode(),
        auth=(stack.ch_admin_user, stack.ch_admin_password),
        timeout=60,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"seed anchor query failed: HTTP {resp.status_code}: {resp.text[:300]}")
    ms, n = resp.text.split()
    if int(n) == 0:
        return None
    return datetime.fromtimestamp(int(ms) / 1000, UTC) + timedelta(seconds=30)
