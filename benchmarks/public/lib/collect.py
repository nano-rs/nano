#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Turn a benchmark run into one results JSON (schema/results.schema.json).

Runs on the operator workstation. Reads, over SSH:
  * blaster summaries   ~/bench/blaster-<run>-<phase>-p<N>.json   (what was sent)
  * k6 summaries        ~/bench/k6-<scenario>-<run>.json           (query latency)
  * host samples        ~/bench/hoststat-<run>-<scenario>.csv      (CPU/mem/disk)
  * ClickHouse          stored events, raw bytes (OCSF `raw_data`: the original
                        record as received), ingest lag, markers, signals
                        (clickhouse-client inside the ClickHouse container, as
                        the admin user whose password is already in that
                        container's environment; nothing secret leaves the host)

  collect.py --topology hosts.env --run-id R --phases socday --scenario socday --gb-per-day 50
  collect.py --topology hosts.env --run-id R --phases ceil01-2000 --slo-check   # exit 1 on SLO breach

SLOs (ceiling): ingest-to-searchable lag p99 <= 60 s; zero loss (stored >=
accepted, and every accepted marker stored exactly once); sender errors
< 0.1 % of events.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import os
import shlex
import statistics
import subprocess
import sys

BENCH_SOURCES = ("windows_sysmon", "windows_event", "conduit_proxy", "apache_access", "aws_cloudtrail")
LAG_P99_SLO_MS = 60_000
ERROR_SLO = 0.001


def load_topology(path: str) -> dict:
    env: dict = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = os.path.expandvars(v.strip().strip('"').strip("'"))
    env["_dir"] = os.path.dirname(os.path.abspath(path))
    return env


class Hosts:
    def __init__(self, t: dict) -> None:
        self.t = t
        self.app = t["APP"]
        self.ch = t["CH"].split()
        self.ingest = t["INGEST"].split()
        self.blasters = t["BLASTER"].split()
        self.user = t.get("SSH_USER", "ubuntu")
        kh = t.get("KNOWN_HOSTS") or os.path.join(os.path.dirname(t["SSH_KEY"]), "known_hosts")
        self.ssh = ["ssh", "-i", t["SSH_KEY"], "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
                    "-o", f"UserKnownHostsFile={kh}", "-o", "ConnectTimeout=15", "-o", "BatchMode=yes"]

    def names(self) -> dict:
        n = {self.app: "app1"}
        n.update({ip: f"ch{i}" for i, ip in enumerate(self.ch, 1)})
        n.update({ip: f"ing{i}" for i, ip in enumerate(self.ingest, 1)})
        n.update({ip: f"blaster{i}" for i, ip in enumerate(self.blasters, 1)})
        return n

    def run(self, host: str, cmd: str, stdin: str | None = None, check: bool = True) -> str:
        p = subprocess.run(self.ssh + [f"{self.user}@{host}", cmd], input=stdin, capture_output=True, text=True)
        if check and p.returncode != 0:
            raise RuntimeError(f"{host}: {cmd[:80]}: {p.stderr.strip()[:300]}")
        return p.stdout

    def ch_query(self, sql: str) -> list[dict]:
        # Role-split ClickHouse speaks TLS only (private CA, SAN = inventory
        # address), so connect to the host's own private address and trust
        # the CA the server already has mounted.
        conf = ("<config><openSSL><client><caConfig>/etc/nano/tls/ca.crt</caConfig>"
                "<verificationMode>strict</verificationMode></client></openSSL></config>")
        cmd = ("c=$(docker ps --format '{{.Names}}' | grep -E 'clickhouse(-server)?(-1)?$' | grep -v keeper | head -1); "
               "ip=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \\([0-9.]*\\).*/\\1/p'); "
               f"docker exec -i -e CH_HOST=\"$ip\" \"$c\" sh -c '"
               f"if [ -f /etc/nano/tls/ca.crt ]; then echo \"{conf}\" > /tmp/nano-bench-client.xml; "
               "set -- --secure --port 9000 --host \"$CH_HOST\" --config-file /tmp/nano-bench-client.xml; fi; "
               "clickhouse-client \"$@\" --user nanosiem_admin --password \"$CLICKHOUSE_ADMIN_PASSWORD\" "
               "--format JSON --output_format_json_quote_64bit_integers=0'")
        out = self.run(self.ch[0], cmd, stdin=sql)
        return json.loads(out).get("data", []) if out.strip() else []


def iso(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def chts(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def pct(values: list[float], q: float):
    if not values:
        return None
    v = sorted(values)
    return round(v[min(len(v) - 1, int(round((len(v) - 1) * q)))], 2)


def blaster_summaries(h: Hosts, run_id: str, phase: str) -> list[dict]:
    out = []
    for b in h.blasters:
        pattern = f"~/bench/blaster-{run_id}-{phase}-p*.json"
        text = h.run(b, "python3 -c " + shlex.quote(
            "import glob, json, os, sys; print(json.dumps([json.load(open(f)) for f in "
            f"sorted(glob.glob(os.path.expanduser({pattern!r})))]))"), check=False)
        try:
            out.extend(json.loads(text or "[]"))
        except ValueError:
            pass
    return out


def phase_metrics(h: Hosts, run_id: str, phase: str, table: str, quick: bool) -> dict:
    sums = blaster_summaries(h, run_id, phase)
    if not sums:
        return {"label": phase, "error": "no blaster summary found"}
    start = min(iso(s["started_at"]) for s in sums)
    end = max(iso(s["ended_at"]) for s in sums)
    sent = sum(s["events_sent"] for s in sums)
    failed = sum(s["events_failed"] for s in sums)
    msent = sum(s["markers_sent"] for s in sums)
    secs = max((end - start).total_seconds(), 1e-9)
    w0, w1 = chts(start - dt.timedelta(seconds=10)), chts(end + dt.timedelta(seconds=10))
    src = ", ".join(f"'{s}'" for s in BENCH_SOURCES)
    rows = h.ch_query(f"""
        SELECT source_type, count() AS events, sum(length(raw_data)) AS raw_bytes,
               quantiles(0.5, 0.95, 0.99)(dateDiff('millisecond', timestamp, _inserted_at)) AS lag,
               max(dateDiff('millisecond', timestamp, _inserted_at)) AS lag_max
        FROM nanosiem.{table}
        WHERE timestamp BETWEEN '{w0}' AND '{w1}' AND source_type IN ({src})
        GROUP BY source_type ORDER BY source_type""")
    stored = sum(int(r["events"]) for r in rows)
    raw_bytes = sum(int(r["raw_bytes"]) for r in rows)
    lag = h.ch_query(f"""
        SELECT quantiles(0.5, 0.95, 0.99)(dateDiff('millisecond', timestamp, _inserted_at)) AS q,
               max(dateDiff('millisecond', timestamp, _inserted_at)) AS mx
        FROM nanosiem.{table}
        WHERE timestamp BETWEEN '{w0}' AND '{w1}' AND source_type IN ({src})""")
    q = (lag[0]["q"] if lag else [None, None, None])
    run_like = f"{run_id}-{phase}-p"
    mk = h.ch_query(f"""
        SELECT count() AS rows,
               uniqExact(JSONExtractString(raw_data, 'nanobench_run'), JSONExtractUInt(raw_data, 'nanobench_seq')) AS uniq
        FROM nanosiem.{table}
        WHERE timestamp BETWEEN '{w0}' AND '{w1}' AND source_type = 'bench_marker'
          AND position(raw_data, '{run_like}') > 0""")
    mrows, muniq = (int(mk[0]["rows"]), int(mk[0]["uniq"])) if mk else (0, 0)
    eps = sent / secs
    lag_ok = q[2] is not None and q[2] <= LAG_P99_SLO_MS
    loss_ok = stored >= sent and mrows == msent and muniq == msent
    err_ok = (failed / max(sent + failed, 1)) < ERROR_SLO
    m = {
        "label": phase,
        "window": {"start": start.isoformat(), "end": end.isoformat(), "seconds": round(secs, 1)},
        "target_eps": sum(s["target_eps"] for s in sums),
        "sender": {"processes": len(sums), "events_sent": sent, "events_failed": failed, "achieved_eps": round(eps, 1),
                   "seed": sorted({s.get("seed") for s in sums})},
        "stored": {"events": stored, "raw_bytes": raw_bytes,
                   "avg_event_bytes": round(raw_bytes / stored, 1) if stored else None,
                   "by_source": {r["source_type"]: int(r["events"]) for r in rows}},
        "throughput": {"eps": round(stored / secs, 1),
                       "gb_per_day": round(raw_bytes / secs * 86400 / 1e9, 2)},
        "ingest_lag_ms": {"p50": q[0], "p95": q[1], "p99": q[2], "max": lag[0]["mx"] if lag else None},
        "markers": {"sent": msent, "stored_rows": mrows, "stored_unique": muniq,
                    "exactly_once": mrows == msent == muniq},
        "slo": {"lag_p99_ok": lag_ok, "zero_loss": loss_ok, "errors_ok": err_ok, "pass": lag_ok and loss_ok and err_ok},
    }
    if not quick:
        m["storage"] = storage(h, table)
    return m


def storage(h: Hosts, table: str) -> dict:
    base = table.replace("_distributed", "")
    r = h.ch_query(f"""
        SELECT sum(rows) AS rows, sum(data_compressed_bytes) AS compressed, sum(data_uncompressed_bytes) AS uncompressed
        FROM system.parts WHERE database = 'nanosiem' AND table = '{base}' AND active""")
    if not r or not int(r[0]["rows"] or 0):
        return {}
    c, u = int(r[0]["compressed"]), int(r[0]["uncompressed"])
    return {"rows_on_ch1": int(r[0]["rows"]), "compressed_bytes": c, "uncompressed_bytes": u,
            "compression_ratio": round(u / c, 2) if c else None}


def detections(h: Hosts, start: dt.datetime, end: dt.datetime, table: str) -> dict:
    """Event-to-alert latency from the findings nano writes (OCSF class 2004,
    source_type `findings`): time from the newest event a finding covers
    (`unmapped.last_seen_time`) to the finding being stored (`_inserted_at`).
    It includes the rule's schedule interval by design."""
    w0, w1 = chts(start - dt.timedelta(seconds=10)), chts(end + dt.timedelta(minutes=10))
    rt = "toString(unmapped.realtime) = 'true'"
    lat = ("dateDiff('millisecond', parseDateTime64BestEffortOrNull(toString(unmapped.last_seen_time), 3), "
           "_inserted_at)")
    try:
        r = h.ch_query(f"""
            SELECT count() AS findings, uniqExact(toString(unmapped.rule_id)) AS rules_fired,
                   countIf({rt}) AS realtime_findings,
                   quantilesIf(0.5, 0.95, 0.99)({lat}, NOT ({rt})) AS sched,
                   quantilesIf(0.5, 0.95, 0.99)({lat}, {rt}) AS realtime
            FROM nanosiem.{table}
            WHERE source_type = 'findings' AND timestamp BETWEEN '{w0}' AND '{w1}'
              AND startsWith(toString(unmapped.rule_name), 'bench-')""")
    except RuntimeError as e:
        return {"error": str(e)[:300]}
    if not r:
        return {}
    q = lambda v: {"p50": v[0], "p95": v[1], "p99": v[2]}  # noqa: E731
    return {"findings": int(r[0]["findings"]), "rules_fired": int(r[0]["rules_fired"]),
            "realtime_findings": int(r[0]["realtime_findings"]),
            "event_to_alert_ms": {"scheduled": q(r[0]["sched"]), "realtime": q(r[0]["realtime"])}}


def host_stats(h: Hosts, run_id: str, scenario: str, start: dt.datetime, end: dt.datetime) -> dict:
    out = {}
    for ip, name in h.names().items():
        text = h.run(ip, f"cat ~/bench/hoststat-{shlex.quote(run_id)}-{shlex.quote(scenario)}.csv 2>/dev/null",
                     check=False)
        def num(r):
            try:
                return all(float(r[k]) >= 0 for k in ("unix_ts", "cpu_busy_pct", "mem_used_pct", "net_rx_bytes"))
            except (TypeError, ValueError):
                return False  # a torn line (sampler restarted mid-write)
        rows = [r for r in csv.DictReader(io.StringIO(text))
                if num(r) and start.timestamp() <= float(r["unix_ts"]) <= end.timestamp()]
        if not rows:
            continue
        cpu = [float(r["cpu_busy_pct"]) for r in rows]
        mem = [float(r["mem_used_pct"]) for r in rows]
        disk = [float(r["disk_used_pct"] or 0) for r in rows]
        dt_s = float(rows[-1]["unix_ts"]) - float(rows[0]["unix_ts"]) or 1
        out[name] = {"samples": len(rows), "cpu_busy_pct": {"p50": pct(cpu, .5), "p95": pct(cpu, .95), "max": max(cpu)},
                     "mem_used_pct": {"p50": pct(mem, .5), "max": max(mem)},
                     "disk_used_pct_end": disk[-1],
                     "net_rx_mbps": round((int(rows[-1]["net_rx_bytes"]) - int(rows[0]["net_rx_bytes"])) * 8 / dt_s / 1e6, 1),
                     "net_tx_mbps": round((int(rows[-1]["net_tx_bytes"]) - int(rows[0]["net_tx_bytes"])) * 8 / dt_s / 1e6, 1),
                     "headroom": {"cpu_pct": round(100 - pct(cpu, .95), 1), "mem_pct": round(100 - max(mem), 1),
                                  "disk_pct": round(100 - disk[-1], 1)}}
    return out


def topology_block(t: dict, h: Hosts) -> dict:
    pricing = {}
    pf = t.get("PRICING_FILE")
    if pf:
        pf = pf if os.path.isabs(pf) else os.path.join(t["_dir"], pf)
        with open(pf, encoding="utf-8") as fh:
            pricing = json.load(fh)
    hosts = []
    for ip, name in h.names().items():
        meta = dict(pricing.get(name, {}))
        role = "app" if name.startswith("app") else "clickhouse" if name.startswith("ch") else \
            "ingest" if name.startswith("ing") else "load-generator"
        hosts.append({"name": name, "role": role, **meta})
    nano_cost = sum(x.get("market_usd_per_hour", 0) for x in hosts if x["role"] != "load-generator")
    return {"name": t.get("BENCH_NAME"), "provider": t.get("PROVIDER", "Rackspace Spot"),
            "region": t.get("REGION"), "hosts": hosts,
            "nano_usd_per_hour_market": round(nano_cost, 4),
            "nano_usd_per_hour_bid_ceiling": round(sum(x.get("bid_usd_per_hour", 0) for x in hosts
                                                       if x["role"] != "load-generator"), 4),
            "clickhouse_layout": t.get("CH_LAYOUT", "shards")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--topology", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--phases", default="", help="comma-separated phase labels")
    ap.add_argument("--scenario", default="adhoc", choices=["adhoc", "ceiling", "socday"])
    ap.add_argument("--gb-per-day", type=float)
    ap.add_argument("--out", required=True)
    ap.add_argument("--quick", action="store_true", help="print phase metrics only")
    ap.add_argument("--slo-check", action="store_true", help="exit 1 if the phase breaks an SLO")
    a = ap.parse_args()

    t = load_topology(a.topology)
    h = Hosts(t)
    table = "ocsf_logs_distributed" if len(h.ch) > 1 else "ocsf_logs"
    phases = [p for p in a.phases.split(",") if p]
    pm = [phase_metrics(h, a.run_id, p, table, a.quick or a.slo_check) for p in phases]
    if a.quick or a.slo_check:
        print(json.dumps(pm, indent=1))
        if a.slo_check:
            return 0 if all(p.get("slo", {}).get("pass") for p in pm) else 1
        return 0

    good = [p for p in pm if "window" in p]
    start = min(iso(p["window"]["start"]) for p in good) if good else dt.datetime.now(dt.timezone.utc)
    end = max(iso(p["window"]["end"]) for p in good) if good else start
    topo = topology_block(t, h)
    res = {
        "schema": "nano-benchmark/result@1",
        "run_id": a.run_id,
        "scenario": a.scenario,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "nano_version": t.get("NANO_VERSION"),
        "schema_profile": "ocsf",
        "topology": topo,
        "dataset": {"generator": "tools/log-blaster", "seed_base": int(t.get("SEED", "20261114")),
                    "assets": int(t.get("ASSETS", "5000")), "lateral_chains": False,
                    "source_mix": {"windows_sysmon": .60, "windows_event": .10, "conduit_proxy": .12,
                                   "apache_access": .10, "aws_cloudtrail": .08}},
        "phases": pm,
        "hosts": host_stats(h, a.run_id, a.scenario, start, end),
    }
    if a.scenario == "socday":
        k6 = h.run(h.blasters[0], f"cat ~/bench/k6-socday-{shlex.quote(a.run_id)}.json 2>/dev/null", check=False)
        res["queries"] = json.loads(k6) if k6.strip() else {"error": "no k6 summary"}
        res["queries"].get("config", {}).pop("app_url", None)  # results never carry addresses
        res["detections"] = detections(h, start, end, table)
        # Rule-set load report; a later --rules-only load supersedes the first.
        for name in ("content-rules.json", "content.json"):
            try:
                with open(os.path.join(a.out, a.run_id, name), encoding="utf-8") as fh:
                    res["detections"]["rule_set"] = json.load(fh).get("rules")
                break
            except (OSError, ValueError):
                continue
        res["target_gb_per_day"] = a.gb_per_day
    if a.scenario == "ceiling":
        for p in pm:  # analysts hunting during each step
            k6 = h.run(h.blasters[0], f"cat ~/bench/k6-{shlex.quote(a.run_id)}-{shlex.quote(p['label'])}.json 2>/dev/null",
                       check=False)
            if k6.strip():
                q = json.loads(k6)
                p["queries_at_load"] = {"search_by_tier": q.get("search_by_tier"), "error_rates": q.get("error_rates")}
        passed = [p for p in pm if p.get("slo", {}).get("pass")]
        broke = next((p for p in pm if not p.get("slo", {}).get("pass")), None)
        best = max(passed, key=lambda p: p["throughput"]["eps"]) if passed else None
        res["ceiling"] = {
            "sustained_eps": best["throughput"]["eps"] if best else None,
            "sustained_gb_per_day": best["throughput"]["gb_per_day"] if best else None,
            "lag_ms_at_ceiling": best["ingest_lag_ms"] if best else None,
            "broke_at": {"label": broke["label"], "target_eps": broke.get("target_eps"),
                         "slo": broke.get("slo")} if broke else None,
        }
    gbpd = None
    if a.scenario == "ceiling" and res.get("ceiling", {}).get("sustained_gb_per_day"):
        gbpd = res["ceiling"]["sustained_gb_per_day"]
    elif good:
        gbpd = good[-1]["throughput"]["gb_per_day"]
    if gbpd and topo["nano_usd_per_hour_market"]:
        res["cost"] = {"usd_per_hour": topo["nano_usd_per_hour_market"],
                       "usd_per_day": round(topo["nano_usd_per_hour_market"] * 24, 3),
                       "usd_per_gb_ingested": round(topo["nano_usd_per_hour_market"] * 24 / gbpd, 5),
                       "basis": "Spot market price at provisioning; nano hosts only (load generators excluded)"}
    d = os.path.join(a.out, a.run_id)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{a.scenario}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)
    print(f"wrote {path}")
    print(json.dumps({k: res.get(k) for k in ("ceiling", "cost")} | {"phases": [
        {k: p.get(k) for k in ("label", "throughput", "ingest_lag_ms", "markers", "slo")} for p in pm]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
