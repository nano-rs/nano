#!/usr/bin/env python3
"""Copy rows from the OCSF 1.8 store (ocsf_logs_legacy_v179) into the
version-agnostic ocsf_logs (NAN-4903, docs/design/OCSF-CLICKHOUSE.md §9.1).

Migration 180 RENAMEs the 1.8 `ocsf_logs` aside instead of dropping it; this is
the explicit, operator-run copy. It never runs at boot.

What is copied, and what is NOT
  * Only the main table. The 21 MVs on the new `ocsf_logs` write to the SAME
    aggregate targets the 1.8 MVs wrote to (prevalence, entity, identity, cloud,
    per-source telemetry), and migration 180 kept those targets' rows. Every
    legacy row is therefore already counted there, from its original ingest.
    Firing the MVs again would double every additive aggregate (events, bytes,
    total_count, event_count, identity rows), so the copy never goes through an
    MV on `ocsf_logs`.
  * Each legacy row is rebuilt into an OCSF object from the 1.8 columns (the 1.8
    `event` was EPHEMERAL): dotted names become nested keys, empty values are
    dropped, paths that cross an array (`answers.rdata`, `resources.uid`, …) are
    wrapped back into the array shape from the embedded contract, and
    `*.hashes.sha256` becomes a SHA-256 `hashes[]` element. nano-derived columns
    (prevalence, `enrichments.*`, `*_unified`, `time_dt`, `event_bytes`) are
    re-derived. Legacy `id`, `timestamp` and `source_type` are kept.

How one UTC day is published (atomic, idempotent, MV-free)
  1. `SYSTEM SYNC REPLICA` the legacy table and `ocsf_logs` on the node this
     runs against: that node's legacy replica is the ONE source of the day.
  2. Presence check: how many of the day's legacy ids are already in
     `ocsf_logs`. All of them → the day is done (a crash after publish); none →
     publish; anything else → refuse (a partition was changed by hand).
  3. Rebuild the day into a private staging table with the exact structure of
     `ocsf_logs` and NO MVs on it (`ocsf_backfill_stage_raw` → a copy of
     `ocsf_logs_raw_mv` → `ocsf_backfill_stage`), so the promoted columns are
     derived by the production MV body.
  4. `ALTER TABLE ocsf_logs ATTACH PARTITION ID '<yyyymmdd>' FROM
     ocsf_backfill_stage` with `alter_sync = 2`: one replicated log entry, all
     parts or none, every replica waits for it, and partition operations fire no
     MVs. ATTACH adds to the partition, so live rows already in it (the cutover
     day) are untouched.
  5. Verify the day's count on EVERY replica of this shard, then record it in
     the replicated `ocsf_legacy_backfill_days` table.
  A crash at any point leaves either nothing or the whole day published; the
  next run (from any replica of the shard) sees which by step 2.

Clusters: the legacy table is per shard. Run once per shard, against any one
replica of it (`CH_URL`). A per-shard Keeper lock (a ReplicatedMergeTree with a
fixed replica name under /clickhouse/nano_locks/<shard>/) stops two runs on the
same shard; after a crash, release it with --break-lock on the node that held it.

After every day is copied, `clickhouse_migrator drop-ocsf-legacy` re-checks
each day by id and drops the legacy table only with --confirm (NAN-4918).

usage (on a single-host compose install, `scripts/nano ocsf-backfill [args]`
finds ClickHouse and passes the credentials; elsewhere set them yourself):
  CH_URL=http://127.0.0.1:8123 CH_USER=nanosiem_admin CH_PASSWORD=… \\
    scripts/ocsf-legacy-backfill.py [--from 2026-01-01] [--to 2026-11-01] [--dry-run]
    [--cluster nanosiem_cluster] [--break-lock] [--order newest-first] [--contract FILE]
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import gzip
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
# The embedded OCSF contract(s): a source checkout and the open-core tree
# (get.nano.rs) keep them under nanosiem-core; the compose bundles, which ship
# no source, carry a byte-identical copy under scripts/lib/ocsf_contracts
# (NAN-5559, deploy/release/bundle-manifest.txt; test_ocsf_legacy_backfill.py
# checks the copy). The first directory holding a file name wins. --contract
# overrides both.
CONTRACT_DIRS = (ROOT / "nanosiem-core/src/schema/ocsf_contracts", ROOT / "scripts/lib/ocsf_contracts")
CONTRACTS: list[pathlib.Path] = []


def find_contracts(explicit: list[str] | None) -> list[pathlib.Path]:
    """The contract files, or exit. Without one, array paths (`answers.rdata`,
    `resources.uid`, ...) would be written as objects, not arrays, and every
    promoted array column of the copied rows would come back empty: the copy
    must never run that way (NAN-5559)."""
    if explicit:
        found = [pathlib.Path(p) for p in explicit]
    else:
        by_name: dict[str, pathlib.Path] = {}
        for d in CONTRACT_DIRS:
            for p in sorted(d.glob("ocsf-*-contract.json.gz")):
                by_name.setdefault(p.name, p)
        found = [by_name[n] for n in sorted(by_name)]
    usable = []
    for path in found:
        try:
            c = json.load(gzip.open(path))
        except (OSError, ValueError) as e:
            raise SystemExit(f"cannot read the OCSF contract {path}: {e}")
        if not isinstance(c, dict) or not c.get("classes") or not c.get("objects"):
            raise SystemExit(f"{path} is not an OCSF contract (no classes/objects)")
        usable.append(path)
    if not usable:
        raise SystemExit(
            "no OCSF contract found (looked in " + ", ".join(str(d) for d in CONTRACT_DIRS) + "). "
            "Run this script from the release tree it ships in, or pass --contract <ocsf-1.9.0-contract.json.gz>. "
            "Nothing was copied.")
    return usable


def plan_days(first: dt.date, last: dt.date, order: str) -> list[dt.date]:
    """Every UTC day from first to last (inclusive), in the requested order."""
    days = [first + dt.timedelta(days=k) for k in range((last - first).days + 1)]
    if order == "newest-first":
        days.reverse()
    return days


DB = "nanosiem"
LEGACY = f"{DB}.ocsf_logs_legacy_v179"
TARGET = f"{DB}.ocsf_logs"
RAW_MV = "ocsf_logs_raw_mv"
PROGRESS = f"{DB}.ocsf_legacy_backfill_days"
STAGE = f"{DB}.ocsf_backfill_stage"
STAGE_RAW = f"{DB}.ocsf_backfill_stage_raw"
STAGE_MV = f"{DB}.ocsf_backfill_stage_mv"
LOCK = f"{DB}.ocsf_backfill_lock"
LOCK_ZK = "/clickhouse/nano_locks/{shard}/ocsf_legacy_backfill"
LOCK_REPLICA = "holder"
# Test hook (scripts/ocsf-bench/backfill_cluster_check.sh): exit hard right after
# the ATTACH of this day, before verification and progress, like a killed process.
CRASH_AFTER_ATTACH = os.environ.get("OCSF_BACKFILL_CRASH_AFTER_ATTACH", "")

# Not OCSF attributes (or re-derived by the new MV): never copied into `event`.
# 1.8 column names that are not the OCSF attribute name.
RENAMED = {"activity": "activity_name"}
SKIP = {"timestamp", "time_dt", "_inserted_at", "id", "source_type", "event_bytes", "unmapped"}
SKIP_PREFIXES = ("enrichments.", "prevalence_")


class ChError(Exception):
    pass


def qtry(sql: str) -> str:
    url = os.environ.get("CH_URL", "http://127.0.0.1:8123").rstrip("/") + "/"
    auth = f"{os.environ.get('CH_USER', 'default')}:{os.environ.get('CH_PASSWORD', '')}"
    req = urllib.request.Request(url, data=sql.encode(), headers={
        "Authorization": "Basic " + base64.b64encode(auth.encode()).decode()})
    try:
        return urllib.request.urlopen(req, timeout=3600).read().decode()
    except urllib.error.HTTPError as e:
        raise ChError(e.read().decode()[:1500])


def q(sql: str) -> str:
    try:
        return qtry(sql)
    except ChError as e:
        raise SystemExit(f"ClickHouse error: {e}\n-- SQL:\n{sql[:1500]}")


def scalar(sql: str) -> str:
    return q(sql).strip()


def ident(name: str) -> str:
    return "`" + name.replace("\\", "\\\\").replace("`", "\\`") + "`"


def lit(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def load_contract_top():
    """Union of class attributes and objects across the embedded contracts."""
    top, objects = {}, {}
    for path in CONTRACTS:
        c = json.load(gzip.open(path))
        for cls in c["classes"].values():
            for k, v in cls.get("attributes", {}).items():
                top.setdefault(k, v)
        for name, obj in c["objects"].items():
            objects.setdefault(name, obj.get("attributes", {}))
    return top, objects


def array_split(path: str, top, objects):
    """(prefix, rest, leaf_array) for the first array on `path`, or None.

    prefix = segments up to and including the first array-of-objects segment;
    leaf_array = the last segment itself is an array of scalars.
    """
    level = top
    segs = path.split(".")
    for i, seg in enumerate(segs):
        attr = level.get(seg)
        if attr is None:
            return None
        last = i + 1 == len(segs)
        if attr.get("is_array"):
            if last:
                return (".".join(segs), "", True)
            return (".".join(segs[: i + 1]), ".".join(segs[i + 1:]), False)
        obj = objects.get(attr.get("object_type") or "")
        if obj is None:
            return None
        level = obj
    return None


def build_event_expr(columns: list[tuple[str, str]]) -> str:
    """SQL expression rebuilding the OCSF `event` JSON from legacy columns."""
    top, objects = load_contract_top()
    scalars: list[str] = []
    groups: dict[str, list[tuple[str, str]]] = {}
    parts: list[str] = []
    for name, ctype in columns:
        if name in SKIP or name.startswith(SKIP_PREFIXES):
            continue
        is_num = ctype.split("(")[0] in {"UInt8", "UInt16", "UInt32", "UInt64", "Int8", "Int16",
                                         "Int32", "Int64", "Float32", "Float64"}
        col = ident(name)
        name = RENAMED.get(name, name)
        if ctype.startswith("Array("):
            parts.append(f"if(notEmpty({col}), formatRowNoNewline('JSONEachRow', {col} AS {ident(name)}), '{{}}')")
            continue
        empty = f"{col} = 0" if is_num else f"{col} = ''"
        val = f"if({empty}, NULL, {col})"
        if name.endswith(".hashes.sha256"):
            owner = name[: -len(".sha256")]
            parts.append(
                f"if({col} = '', '{{}}', formatRowNoNewline('JSONEachRow', "
                f"[CAST(tuple(3, 'SHA-256', {col}), 'Tuple(algorithm_id Int32, algorithm String, value String)')] AS {ident(owner)}))"
            )
            continue
        split = array_split(name, top, objects)
        if split is None:
            scalars.append(f"{val} AS {ident(name)}")
        elif split[2]:
            parts.append(f"if({empty}, '{{}}', formatRowNoNewline('JSONEachRow', [{col}] AS {ident(name)}))")
        else:
            groups.setdefault(split[0], []).append((split[1], val, empty))
    for prefix, members in groups.items():
        # One element per legacy row: the 1.8 store kept a single value per
        # path. Nested members (`a.b` below the array) are written as dotted keys
        # inside the element; CAST(... AS JSON) folds them into objects.
        keyed = ", ".join(f"{val} AS {ident(rest)}" for rest, val, _ in members)
        any_set = " OR ".join(f"NOT ({empty})" for _, _, empty in members)
        head = json.dumps({prefix: 0})[:-2]  # '{"<prefix>":'
        parts.append(
            f"if({any_set}, concat({lit(head + '[')}, formatRowNoNewline('JSONEachRow', {keyed}), ']}}'), '{{}}')"
        )
    base = f"formatRowNoNewline('JSONEachRow', {', '.join(scalars)}, toUnixTimestamp64Milli(timestamp) AS `time`, unmapped AS `unmapped`)"
    merged = ", ".join([base] + parts)
    return f"CAST(jsonMergePatch({merged}) AS JSON)"




class Topology:
    """Single node, or one shard of an explicit cluster (ocsf_logs is Replicated)."""

    def __init__(self, cluster_arg: str | None):
        engine = scalar(f"SELECT engine FROM system.tables WHERE database = '{DB}' AND name = 'ocsf_logs'")
        if not engine:
            raise SystemExit(f"{TARGET} does not exist: run the migrator first")
        self.replicated = engine.startswith("Replicated")
        self.cluster = None
        self.shard_macro = None
        self.replicas = 1
        if not self.replicated:
            return
        self.shard_macro = scalar("SELECT getMacro('shard')")
        cluster = cluster_arg or os.environ.get("CLICKHOUSE_CLUSTER", "").strip()
        if not cluster:
            cluster = scalar(
                "SELECT cluster FROM system.clusters WHERE cluster NOT IN ('_all_databases', 'system') "
                "GROUP BY cluster HAVING count() > 1 AND max(is_local) = 1 ORDER BY count() DESC, cluster LIMIT 1")
        if not cluster:
            raise SystemExit("ocsf_logs is replicated but no cluster was found: pass --cluster")
        shard_num = scalar(f"SELECT shard_num FROM system.clusters WHERE cluster = {lit(cluster)} AND is_local = 1 LIMIT 1")
        if not shard_num:
            raise SystemExit(f"this node is not a member of cluster {cluster!r}")
        self.cluster = cluster
        self.replicas = int(scalar(
            f"SELECT count() FROM system.clusters WHERE cluster = {lit(cluster)} AND shard_num = {int(shard_num)}"))

    def table_engine(self, family: str, args: str, zk_path: str, replica: str) -> str:
        """`family(args)`, or its Replicated form with an explicit zk path on a cluster."""
        if not self.replicated:
            return f"{family}({args})"
        rep = f"{lit(zk_path)}, {lit(replica)}" + (f", {args}" if args else "")
        return f"Replicated{family}({rep})"

    def per_replica_counts(self, where: str) -> dict[str, int]:
        """Count of the day's legacy ids in ocsf_logs on every replica of this shard."""
        ids = f"(SELECT id FROM {LEGACY} WHERE {where})"
        if not self.replicated:
            return {"local": int(scalar(f"SELECT count() FROM {TARGET} WHERE {where} AND id IN {ids}"))}
        rows = q(
            f"SELECT getMacro('shard'), hostName(), count() FROM clusterAllReplicas({lit(self.cluster)}, {TARGET}) "
            f"WHERE {where} AND id GLOBAL IN {ids} GROUP BY 1, 2 FORMAT TSV")
        out = {}
        for line in rows.splitlines():
            shard, host, n = line.split("\t")
            if shard == self.shard_macro:
                out[host] = int(n)
        return out


def acquire_lock(topo: Topology) -> None:
    engine = topo.table_engine("MergeTree", "", LOCK_ZK, LOCK_REPLICA)
    try:
        qtry(f"CREATE TABLE {LOCK} (x UInt8) ENGINE = {engine} ORDER BY x")
    except ChError as e:
        if "ALREADY_EXISTS" in str(e) or "already exists" in str(e):
            raise SystemExit(
                "another backfill run holds the lock for this shard. If none is running (a crash), "
                "rerun with --break-lock against the node that held it.")
        raise SystemExit(f"ClickHouse error taking the lock: {e}")


def release_lock() -> None:
    q(f"DROP TABLE IF EXISTS {LOCK} SYNC")


def break_lock(topo: Topology) -> None:
    if scalar(f"EXISTS TABLE {LOCK}") == "1":
        drop_staging()  # a crashed run on this node also left its staging tables
        release_lock()
        print("lock released")
        return
    if not topo.replicated:
        print("no lock held")
        return
    zk = LOCK_ZK.replace("{shard}", topo.shard_macro)
    try:
        qtry(f"SYSTEM DROP REPLICA {lit(LOCK_REPLICA)} FROM ZKPATH {lit(zk)}")
        print(f"lock released ({zk})")
    except ChError as e:
        raise SystemExit(f"could not release {zk} from this node ({e}). The lock table lives on the node "
                         f"that held it: run --break-lock against that node.")


def create_staging() -> None:
    """MV-free copy of ocsf_logs, fed through a private copy of ocsf_logs_raw_mv."""
    drop_staging()
    ddl = q(f"SHOW CREATE TABLE {TARGET} FORMAT TSVRaw")
    ddl, n = re.subn(r"^CREATE TABLE nanosiem\.ocsf_logs\b", f"CREATE TABLE {STAGE}", ddl)
    if n != 1:
        raise SystemExit(f"unexpected SHOW CREATE TABLE {TARGET} output")
    # Plain engine: the staging table is local to this node; ATTACH PARTITION
    # ships its parts to the other replicas through the replication log.
    ddl = re.sub(r"ENGINE = Replicated(\w*)MergeTree\('[^']*', '[^']*'(?:, )?", r"ENGINE = \1MergeTree(", ddl)
    ddl = ddl.replace("MergeTree()", "MergeTree")
    q(ddl)
    q(f"CREATE TABLE {STAGE_RAW} AS {DB}.ocsf_logs_raw ENGINE = Null")
    body = q(f"SELECT as_select FROM system.tables WHERE database = '{DB}' AND name = '{RAW_MV}' FORMAT TSVRaw").strip()
    body, n = re.subn(r"\bnanosiem\.ocsf_logs_raw\b(?!_)", STAGE_RAW, body)
    if not body or n == 0:
        raise SystemExit(f"could not read the body of {DB}.{RAW_MV}")
    q(f"CREATE MATERIALIZED VIEW {STAGE_MV} TO {STAGE} AS {body}")


def drop_staging() -> None:
    for t in (STAGE_MV, STAGE_RAW, STAGE):
        q(f"DROP TABLE IF EXISTS {t} SYNC")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="start", help="first UTC day (default: oldest legacy row)")
    ap.add_argument("--to", dest="end", help="last UTC day, inclusive (default: newest legacy row)")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and the INSERT for the first day")
    ap.add_argument("--cluster", help="cluster name (default: CLICKHOUSE_CLUSTER, else detected)")
    ap.add_argument("--break-lock", action="store_true", help="release a lock left by a crashed run, then exit")
    ap.add_argument("--contract", action="append",
                    help="OCSF contract file (ocsf-*-contract.json.gz); default: the one shipped beside this script")
    ap.add_argument("--order", choices=("oldest-first", "newest-first"), default="oldest-first",
                    help="day order (default oldest-first). newest-first makes the most recent history "
                         "searchable first; a rerun in either order skips the days already recorded")
    a = ap.parse_args()

    if q(f"EXISTS TABLE {LEGACY}").strip() != "1":
        print(f"{LEGACY} does not exist: nothing to backfill")
        return
    topo = Topology(a.cluster)
    if a.break_lock:
        break_lock(topo)
        return
    CONTRACTS[:] = find_contracts(a.contract)
    if topo.replicated:
        ro = scalar(f"SELECT is_readonly FROM system.replicas WHERE database = '{DB}' AND table = 'ocsf_logs_legacy_v179'")
        if ro == "1":
            raise SystemExit("the legacy replica on this node is read-only: run against a healthy replica")
    cols = [tuple(l.split("\t")) for l in q(
        f"SELECT name, type FROM system.columns WHERE database = '{DB}' AND table = 'ocsf_logs_legacy_v179' "
        f"AND default_kind NOT IN ('MATERIALIZED', 'ALIAS', 'EPHEMERAL') ORDER BY position FORMAT TSV").splitlines()]
    event_expr = build_event_expr(cols)
    lo, hi = q(f"SELECT toDate(min(timestamp)), toDate(max(timestamp)) FROM {LEGACY} FORMAT TSV").split()
    if q(f"SELECT count() FROM {LEGACY}").strip() == "0":
        print("legacy table is empty")
        return
    day = dt.date.fromisoformat(a.start or lo)
    last = dt.date.fromisoformat(a.end or hi)

    def day_where(d: dt.date) -> str:
        d0, d1 = d.isoformat(), (d + dt.timedelta(days=1)).isoformat()
        return f"timestamp >= toDateTime64({lit(d0)}, 3, 'UTC') AND timestamp < toDateTime64({lit(d1)}, 3, 'UTC')"

    def insert_sql(where: str) -> str:
        return (f"INSERT INTO {STAGE_RAW} (event, timestamp, source_type, id) "
                f"SELECT {event_expr}, timestamp, source_type, id FROM {LEGACY} WHERE {where} "
                # The JSON keys are aliases named like the legacy columns;
                # without this an alias would shadow its own column in the
                # other expressions (`[email.to] AS email.to` vs `email.to = ''`).
                # CAST(String AS JSON) would otherwise infer DateTime for
                # date-looking strings and coerce the other values of that
                # path in the block (measured: unmapped "1" -> 2026-01-01).
                # A retried day must never be swallowed by insert dedup
                # (ocsf_logs carries non_replicated_deduplication_window).
                f"SETTINGS async_insert = 0, prefer_column_name_to_alias = 1, "
                f"input_format_try_infer_dates = 0, input_format_try_infer_datetimes = 0, "
                f"insert_deduplicate = 0, deduplicate_blocks_in_dependent_materialized_views = 0")

    if a.dry_run:
        print(f"topology: {'cluster ' + topo.cluster + ' shard ' + topo.shard_macro if topo.replicated else 'single node'}")
        print(f"days: {day} to {last} ({(last - day).days + 1}), {a.order}")
        recorded = set()
        if scalar(f"EXISTS TABLE {PROGRESS}") == "1":
            recorded = set(q(f"SELECT day FROM {PROGRESS} FINAL FORMAT TSV").split())
            print(f"already copied (skipped): {len(recorded)} day(s)")
        for current in plan_days(day, last, a.order):
            if current.isoformat() in recorded:
                continue
            want = int(scalar(f"SELECT count() FROM {LEGACY} WHERE {day_where(current)}"))
            print(f"{current}: {want} legacy rows")
            if want:
                print(insert_sql(day_where(current)))
                return
        return

    acquire_lock(topo)
    try:
        progress_engine = topo.table_engine(
            "ReplacingMergeTree", "done_at", f"/clickhouse/tables/{{shard}}/{DB}/ocsf_legacy_backfill_days", "{replica}")
        q(f"CREATE TABLE IF NOT EXISTS {PROGRESS} (day Date, rows UInt64, done_at DateTime DEFAULT now()) "
          f"ENGINE = {progress_engine} ORDER BY day")
        if topo.replicated:
            for t in (PROGRESS, LEGACY, TARGET):
                q(f"SYSTEM SYNC REPLICA {t}")
        done = set(q(f"SELECT day FROM {PROGRESS} FINAL FORMAT TSV").split())
        create_staging()
        total = 0
        days = plan_days(day, last, a.order)
        started = time.monotonic()
        for current in days:
            d0, where = current.isoformat(), day_where(current)
            if d0 in done:
                continue
            day_started = time.monotonic()
            want = int(scalar(f"SELECT count() FROM {LEGACY} WHERE {where}"))
            if want == 0:
                q(f"INSERT INTO {PROGRESS} (day, rows) VALUES ({lit(d0)}, 0)")
                continue
            present = int(scalar(
                f"SELECT count() FROM {TARGET} WHERE {where} AND id IN (SELECT id FROM {LEGACY} WHERE {where})"))
            if present == 0:
                q(f"TRUNCATE TABLE {STAGE} SYNC")
                q(insert_sql(where))
                staged = int(scalar(f"SELECT count() FROM {STAGE}"))
                parts = q(f"SELECT DISTINCT partition_id FROM system.parts WHERE database = '{DB}' "
                          f"AND table = 'ocsf_backfill_stage' AND active FORMAT TSV").split()
                pid = d0.replace("-", "")
                if staged != want or parts != [pid]:
                    raise SystemExit(f"{d0}: staged {staged} of {want} rows in partitions {parts}; nothing published")
                q(f"ALTER TABLE {TARGET} ATTACH PARTITION ID {lit(pid)} FROM {STAGE} SETTINGS alter_sync = 2")
                if CRASH_AFTER_ATTACH == d0:
                    os._exit(3)
                total += want
            elif present != want:
                raise SystemExit(
                    f"{d0}: {present} of {want} legacy rows are already in {TARGET} (neither none nor all). "
                    f"The day was changed outside this script: nothing was copied for it. Contact nano support.")
            counts = topo.per_replica_counts(where)
            if len(counts) != topo.replicas or any(n != want for n in counts.values()):
                raise SystemExit(f"{d0}: per-replica counts {counts}, expected {want} on {topo.replicas} replica(s); "
                                 f"not recorded, rerun after replication catches up")
            q(f"INSERT INTO {PROGRESS} (day, rows) VALUES ({lit(d0)}, {want})")
            print(f"{d0}: {want} rows" + ("" if present == 0 else " (already published; recorded)")
                  + f" ({time.monotonic() - day_started:.1f} s)", flush=True)
        print(f"done: {total} rows copied in {time.monotonic() - started:.0f} s")
    finally:
        drop_staging()
        release_lock()


if __name__ == "__main__":
    main()
