"""Ingest the first-party OCSF sample corpus into a kept stack (NAN-5291).

The corpus is the one the OCSF publish gate checks (NAN-5079,
nanosiem-core/tests/first_party_parser_samples_ocsf.rs): the `samples:` of
every `parsers-ocsf/*/parser.yaml` in nano-rs/parsers (~787 samples, ~67
parsers). It is read from the stack's OWN synced copy of that repository
(`/api/parser-repositories/{id}/parsers`, `raw_content`), so the samples
always match the parsers the stack runs.

The normal ingest path, end to end:
1. import each parser LINKED from the followed nano-rs/parsers repository as a
   Splunk-HEC log source and publish it (the publish runs the OCSF gate);
2. wait for Vector's reloads to settle;
3. POST every sample to Vector HEC with the platform ingest token and
   `sourcetype=<lane>` (the parser's first match value), the way the connector
   runner delivers; the raw line is the event, as the gate feeds it;
4. count rows per lane through the search API over a wide window and report
   lanes that landed nothing (resent once: a reload can strand events).

Samples keep their NATIVE timestamps (some are years old): search with a wide
time range (`--start 2000-01-01T00:00:00Z`) to see them all.

    e2e/.venv/bin/python -m nano_e2e.corpus [--run <id>] [--only okta,apache] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nano_e2e import feeds_live, ingest
from nano_e2e.client import Journal, Nano, expect
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually, vector_reloads_quiet

CORPUS_DIR = "parsers-ocsf/"
_LANE = re.compile(r"[A-Za-z0-9_.:-]+")


@dataclass
class CorpusParser:
    path: str
    name: str
    lanes: list[str]
    samples: list[str]
    source_id: str = ""
    error: str = ""
    sent: int = 0
    landed: int = 0
    classes: dict[str, int] = field(default_factory=dict)

    @property
    def lane(self) -> str:
        return self.lanes[0] if self.lanes else ""


def corpus_from_listing(listing: list[dict[str, Any]]) -> list[CorpusParser]:
    """Parsers under parsers-ocsf/ that carry samples, from a repository's
    parser listing (pure: selftested)."""
    out: list[CorpusParser] = []
    for item in listing:
        p = item.get("parser", item)
        path = str(p.get("file_path", ""))
        if not path.startswith(CORPUS_DIR) or not path.endswith("parser.yaml"):
            continue
        try:
            doc = yaml.safe_load(p.get("raw_content") or "") or {}
        except yaml.YAMLError:
            continue
        samples = [str(s["raw"]) for s in doc.get("samples") or [] if isinstance(s, dict) and s.get("raw")]
        lanes = [str(v) for v in doc.get("match_values") or []]
        # The lane is interpolated into nPL and a HEC sourcetype: identifiers only.
        if not samples or not lanes or not all(_LANE.fullmatch(v) for v in lanes):
            continue
        out.append(
            CorpusParser(
                path=path,
                name=str(doc.get("name") or p.get("name") or path),
                lanes=lanes,
                samples=samples,
            )
        )
    return sorted(out, key=lambda c: c.path)


def platform_token(stack: Stack) -> str:
    """The platform ingest token (multiplex route `*`) from the run's 0600
    compose.env; never printed."""
    for line in (stack.run_dir / "compose.env").read_text().splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "NANO_PLATFORM_INGEST_TOKEN":
            return value.strip().strip("'\"")
    raise RuntimeError("NANO_PLATFORM_INGEST_TOKEN missing from the run's compose.env")


def lane_count(nano: Nano, lane: str) -> tuple[int, dict[str, int]]:
    body = nano.search(
        f'metadata.log_source="{lane}" | stats count by class_uid',
        limit=1000,
        minutes_back=60 * 24 * 365 * 30,
    )
    classes: Counter[str] = Counter()
    for row in body.get("results") or []:
        classes[str(row.get("class_uid"))] += int(row.get("count") or 0)
    return sum(classes.values()), dict(classes)


def vector_state(stack: Stack) -> dict[str, Any]:
    """The stack's Vector container state ({} when not a docker Vector)."""
    import subprocess

    proc = subprocess.run(  # noqa: S603 - fixed argv, our own container
        [
            "docker",
            "inspect",
            f"{stack.project}-vector",
            "--format",
            "{{json .State}}|{{.HostConfig.Memory}}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        return {}
    state, _, mem = proc.stdout.strip().partition("|")
    return json.loads(state) | {"memory_limit": int(mem or 0)}


def require_vector(stack: Stack) -> None:
    """Fail with the cause when Vector is down: the whole first-party OCSF
    library in one topology needs more than the compose default
    VECTOR_MEM_LIMIT (512M) and gets OOM-killed mid-publish (NAN-5291)."""
    st = vector_state(stack)
    if not st or st.get("Running"):
        return
    limit = st.get("memory_limit", 0) // (1024 * 1024)
    cause = "OOM-killed" if st.get("OOMKilled") else f"exited ({st.get('ExitCode')})"
    raise RuntimeError(
        f"Vector is {cause} (memory limit {limit} MiB) with {stack.project}'s published parsers. "
        "Bring the stack up with more Vector memory (VECTOR_MEM_LIMIT=3G scripts/e2e.sh up|run ...), "
        f"or `docker update --memory 3g --memory-swap 3g {stack.project}-vector && "
        f"docker start {stack.project}-vector`, then rerun (imports are reused), or use --only."
    )


def install(nano: Nano, parsers: list[CorpusParser], deploy_timeout: float = 1800, log: Any = print) -> None:
    """Import + publish every parser LINKED (idempotent: reuses an import),
    then wait for all of them to deploy. Two phases: each publish re-renders
    Vector with every parser so far, so deploys slow down as the corpus grows;
    waiting per parser would serialise those reloads."""
    repo = feeds_live.parsers_repo(nano)
    listed = expect(
        nano.api.get(f"/api/parser-repositories/{repo['id']}/parsers", params={"limit": 1000}), 200
    )
    linked = {p.get("file_path"): p.get("linked_log_source_id") for p in listed}
    for c in parsers:
        try:
            source_id = linked.get(c.path)
            if not source_id:
                res = expect(
                    nano.api.post(
                        f"/api/parser-repositories/{repo['id']}/parsers/import/{c.path}",
                        json={"import_type": "linked", "ingestion_method": "splunk_hec"},
                    ),
                    200,
                )
                source_id = res.get("log_source_id") or res.get("id")
            c.source_id = str(source_id)
            src = expect(nano.api.get(f"/api/log-sources/{c.source_id}"), 200)
            if not (src.get("deployed") and src.get("enabled")):
                res = expect(nano.api.post(f"/api/log-sources/{c.source_id}/publish", json={"acknowledge_unattested": True}, timeout=600), 200)
                if res.get("success") is not True:
                    raise RuntimeError(f"publish refused: {str(res)[:300]}")
            log(f"  published {c.name} ({len(c.samples)} samples, lanes {','.join(c.lanes)})")
        except Exception as exc:  # noqa: BLE001 - one parser failing the gate is a finding, not a stop
            c.error = f"{type(exc).__name__}: {str(exc)[:300]}"
            log(f"  FAILED {c.name}: {c.error}")

    def undeployed() -> list[CorpusParser]:
        out = []
        for c in parsers:
            if c.error:
                continue
            src = expect(nano.api.get(f"/api/log-sources/{c.source_id}"), 200)
            if not (src.get("deployed") and src.get("enabled")):
                out.append(c)
        return out

    try:
        eventually(
            undeployed,
            timeout=deploy_timeout,
            interval=15,
            desc="corpus parsers deployed",
            ok=lambda p: not p,
        )
    except AssertionError:
        for c in undeployed():
            c.error = f"not deployed after {deploy_timeout:.0f}s"
            log(f"  NOT DEPLOYED {c.name}")


def send(stack: Stack, token: str, c: CorpusParser) -> None:
    for raw in c.samples:
        r = ingest.hec(stack.hec_url, token, raw, sourcetype=c.lane)
        if r.status_code != 200:
            raise RuntimeError(f"HEC {r.status_code} for {c.name}: {r.text[:200]}")
        c.sent += 1


def run(
    stack: Stack, only: set[str] | None = None, wait: float = 240, log: Any = print
) -> list[CorpusParser]:
    nano = Nano(stack.api_url, stack.search_url, {"X-API-Key": stack.api_key}, Journal(None))
    try:
        repo = feeds_live.parsers_repo(nano)
        listing = expect(
            nano.api.get(f"/api/parser-repositories/{repo['id']}/parsers", params={"limit": 1000}), 200
        )
        parsers = corpus_from_listing(listing)
        if only:
            parsers = [c for c in parsers if c.name in only or c.path.split("/")[1] in only]
        log(f"corpus: {len(parsers)} parsers, {sum(len(c.samples) for c in parsers)} samples")
        install(nano, parsers, log=log)
        ready = [c for c in parsers if not c.error]
        require_vector(stack)
        log(f"waiting for Vector reloads to settle ({len(ready)} parsers published)")
        vector_reloads_quiet(stack.project, timeout=600)
        token = platform_token(stack)
        for c in ready:
            send(stack, token, c)
        log(f"sent {sum(c.sent for c in ready)} samples; waiting for them to land")

        def pending() -> list[CorpusParser]:
            out = []
            for c in ready:
                c.landed, c.classes = lane_count(nano, c.lane)
                if c.landed == 0:
                    out.append(c)
            return out

        missing: list[CorpusParser] = []
        try:
            eventually(
                pending, timeout=wait, interval=10, desc="every corpus lane searchable", ok=lambda p: not p
            )
        except AssertionError:
            missing = pending()
        if missing:
            log(f"resending {len(missing)} lane(s) with no rows (a reload can strand events)")
            vector_reloads_quiet(stack.project, timeout=300)
            for c in missing:
                send(stack, token, c)
            try:
                eventually(
                    pending, timeout=wait, interval=10, desc="resent lanes searchable", ok=lambda p: not p
                )
            except AssertionError:
                pass
        for c in ready:
            c.landed, c.classes = lane_count(nano, c.lane)
        return parsers
    finally:
        nano.close()


def summary(parsers: list[CorpusParser]) -> str:
    lines = []
    classes: Counter[str] = Counter()
    for c in parsers:
        classes.update(c.classes)
        if c.error:
            state = "ERROR " + c.error
        elif c.landed == 0:
            state = "EMPTY"
        elif c.landed < c.sent:
            state = f"PARTIAL ({c.sent - c.landed} not searchable: dropped, deduped or outside retention)"
        else:
            state = "ok"
        if "0" in c.classes:
            state += f"  [{c.classes['0']} row(s) fell back to Base Event class 0]"
        lines.append(f"  {c.name:32} lane={c.lane:22} sent={c.sent:3} rows={c.landed:4} {state}")
    bad = [c for c in parsers if c.error or c.landed == 0]
    head = (
        f"corpus: {len(parsers)} parsers, {sum(c.sent for c in parsers)} sent, "
        f"{sum(c.landed for c in parsers)} rows, {len(classes)} OCSF classes, "
        f"{len(bad)} parser(s) with nothing"
    )
    return "\n".join([head, *lines])


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr] - progress when piped
    ap = argparse.ArgumentParser(prog="nano_e2e.corpus", description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--run", help="e2e run id (default: the current kept stack)")
    ap.add_argument("--stack-env", help="explicit stack.env path")
    ap.add_argument("--only", help="comma-separated parser names or parsers-ocsf/<dir> names")
    ap.add_argument("--wait", type=float, default=240, help="seconds to wait for rows to land")
    ap.add_argument("--json", type=Path, help="write the per-parser result here")
    args = ap.parse_args(argv)
    from nano_e2e import stackenv

    stack = stackenv.load(args.run, args.stack_env)
    only = {s.strip() for s in args.only.split(",")} if args.only else None
    started = time.monotonic()
    parsers = run(stack, only, args.wait)
    print(summary(parsers))
    print(f"took {time.monotonic() - started:.0f}s")
    if args.json:
        args.json.write_text(json.dumps([asdict(c) | {"samples": len(c.samples)} for c in parsers], indent=2))
    return 0 if parsers and all(not c.error and c.landed for c in parsers) else 1


if __name__ == "__main__":
    sys.exit(main())
