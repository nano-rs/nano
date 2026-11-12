"""Field-name invariant checker for OCSF stacks (NAN-5291).

nano is OCSF-canonical. UDM names are still ACCEPTED (silently aliased) by the
query layer, but no surface may SUGGEST or SHOW one as if it were a field of
this tenant. This module collects every field name a user is shown or offered
and checks each against the live schema:

- API surfaces: `/api/schema/fields`, `/api/fields/ext` (spill + extended
  buckets), `/api/search/field-stats`, `/api/me/field-usage`, the suggestions
  in `/api/rules/validate` messages, `/api/rule-repositories/coverage` and each
  repository's rule `requires_fields` / `coverage_missing_fields`.
- UI surfaces (optional, through the puppeteer driver): search autocomplete,
  the results field sidebar, the rule editor's autocomplete and validation
  text, and the dashboard panel editor's query autocomplete and field hints.

The universe the names are judged against is read from the stack itself:
`system.columns` of `ocsf_logs`, the JSON paths actually present in `event` and
`unmapped`, plus the embedded OCSF contract (nanosiem-core) for valid nested
paths that have no data yet. UDM names come from `/api/udm/fields` (falling
back to the web bundle's `udm-fields.ts`).

Invariants (one Violation per surface/name/kind):
- `doubled-segment`  a repeated adjacent path segment (`unmapped.unmapped.x`)
- `ext-prefix`       the UDM spill prefix `ext.` on an OCSF tenant
- `unmapped-absent`  `unmapped.<k>` where no row carries key `<k>`
- `udm-alias`        a known UDM name that is not an OCSF path, shown/offered
- `not-in-schema`    not a column, not a present path, not an OCSF path
- `udm-era-column`   (warn) a physical UDM-era column (`source_type`) shown as a field

Run against a kept stack:
    e2e/.venv/bin/python -m nano_e2e.field_invariants [--run <id>] [--ui] [--json out.json]
or as a scenario: `scripts/e2e.sh run field_invariants --run <id>`.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "nanosiem-core" / "src" / "schema" / "ocsf_contracts" / "ocsf-1.9.0-contract.json.gz"
UDM_FIELDS_TS = ROOT / "nanosiem-web" / "src" / "lib" / "udm-fields.ts"

# Physical columns of ocsf_logs that are UDM-era routing/bookkeeping, not OCSF
# attributes. They exist (queries on them work), but a field list that offers
# them as fields is drift: `metadata.log_source` is the OCSF lane.
UDM_ERA_COLUMNS = frozenset({"source_type"})
# Internal bookkeeping columns nobody should be shown as a field.
INTERNAL_COLUMNS = frozenset({"_inserted_at", "id", "event"})

ERROR_KINDS = ("doubled-segment", "ext-prefix", "unmapped-absent", "udm-alias", "not-in-schema")
WARN_KINDS = ("udm-era-column", "internal-column")

_QUOTED = re.compile(r"'([A-Za-z_][A-Za-z0-9_.]*)'")
_SUGGESTION_TAIL = re.compile(r"(?:Did you mean|Available fields include)\s+(.*)$")


# ---------------------------------------------------------------- model
@dataclass(frozen=True)
class Seen:
    """A field name a surface showed or suggested."""

    surface: str
    name: str
    context: str = ""


@dataclass(frozen=True)
class Violation:
    kind: str
    surface: str
    name: str
    detail: str
    context: str = ""

    @property
    def severity(self) -> str:
        return "warn" if self.kind in WARN_KINDS else "error"


class OcsfContract:
    """Lazy path resolution over the embedded OCSF contract: `a.b.c` is valid
    when some class has attribute `a` whose object type has `b`, and so on."""

    def __init__(self, contract: dict[str, Any]):
        self._classes = [c.get("attributes", {}) for c in contract.get("classes", {}).values()]
        self._objects = {k: v.get("attributes", {}) for k, v in contract.get("objects", {}).items()}
        self.version = str(contract.get("version", ""))

    @classmethod
    def load(cls, path: Path = CONTRACT) -> OcsfContract | None:
        if not path.is_file():
            return None
        with gzip.open(path, "rt") as f:
            return cls(json.load(f))

    @lru_cache(maxsize=8192)  # noqa: B019 - instances live for one check run
    def has_path(self, name: str) -> bool:
        parts = name.split(".")
        return any(self._resolve(attrs, parts) for attrs in self._classes)

    def _resolve(self, attrs: dict[str, Any], parts: list[str]) -> bool:
        for i, seg in enumerate(parts):
            spec = attrs.get(seg)
            if spec is None:
                return False
            if i == len(parts) - 1:
                return True
            obj = spec.get("object_type")
            if not obj or obj not in self._objects:
                return False
            attrs = self._objects[obj]
        return True


@dataclass
class Universe:
    """What exists on this stack."""

    schema: str
    schema_api: set[str] = field(default_factory=set)  # /api/schema/fields names
    columns: set[str] = field(default_factory=set)  # system.columns of ocsf_logs
    event_paths: set[str] = field(default_factory=set)  # JSONAllPaths(event)
    unmapped_keys: set[str] = field(default_factory=set)  # JSONAllPaths(unmapped)
    udm_names: set[str] = field(default_factory=set)
    contract: OcsfContract | None = None
    allow: set[str] = field(default_factory=set)

    def is_ocsf_path(self, name: str) -> bool:
        """Canonical OCSF: a promoted column, a path present in `event`, or a
        path the OCSF contract defines."""
        if name in self.event_paths or (name in self.columns and name not in UDM_ERA_COLUMNS):
            return True
        return bool(self.contract and self.contract.has_path(name))

    def exists(self, name: str) -> bool:
        return self.is_ocsf_path(name) or name in self.columns or name in self.schema_api


# ---------------------------------------------------------------- invariants
def doubled_segment(name: str) -> str | None:
    parts = name.split(".")
    for a, b in zip(parts, parts[1:], strict=False):
        if a == b:
            return f"{a}.{b}"
    return None


def check_name(name: str, u: Universe) -> list[tuple[str, str]]:
    """(kind, detail) for every invariant `name` breaks."""
    out: list[tuple[str, str]] = []
    if name in u.allow:
        return out
    parts = name.split(".")
    if any(not p for p in parts):
        return [("not-in-schema", "empty path segment")]
    dup = doubled_segment(name)
    if dup:
        out.append(("doubled-segment", f"repeated adjacent segment '{dup}'"))
    head = parts[0]
    if head == "ext":
        out.append(
            ("ext-prefix", "UDM spill prefix 'ext.' shown on an OCSF tenant (OCSF spill is 'unmapped.')")
        )
        return out
    if head == "unmapped" and len(parts) > 1:
        key = name[len("unmapped.") :]
        if key not in u.unmapped_keys and not dup:
            out.append(("unmapped-absent", f"no row carries unmapped key '{key}'"))
        return out
    if name in INTERNAL_COLUMNS:
        out.append(("internal-column", "internal bookkeeping column offered as a field"))
        return out
    if name in UDM_ERA_COLUMNS:
        out.append(("udm-era-column", "UDM-era routing column; OCSF lane is metadata.log_source"))
        return out
    if u.is_ocsf_path(name):
        return out
    if name in u.udm_names:
        out.append(("udm-alias", "UDM name presented as a field; not an OCSF path on this tenant"))
    elif not u.exists(name) and not dup:
        out.append(("not-in-schema", "not a column, not a present event path, not an OCSF contract path"))
    return out


def check(seen: Iterable[Seen], u: Universe) -> list[Violation]:
    out: list[Violation] = []
    done: set[tuple[str, str]] = set()
    for s in seen:
        name = s.name.strip()
        if not name or (s.surface, name) in done:
            continue
        done.add((s.surface, name))
        for kind, detail in check_name(name, u):
            out.append(Violation(kind, s.surface, name, detail, s.context))
    return out


def suggestions_in(message: str) -> list[str]:
    """Field names a validation message SUGGESTS (after "Did you mean" /
    "Available fields include"); the echoed offending name is not a suggestion."""
    m = _SUGGESTION_TAIL.search(message)
    return _QUOTED.findall(m.group(1)) if m else []


# ---------------------------------------------------------------- universe from a stack
def ch_query(stack: Any, sql: str, timeout: float = 120) -> list[dict[str, Any]]:
    r = httpx.post(
        stack.ch_url,
        params={"database": "nanosiem", "default_format": "JSONEachRow", "max_execution_time": "110"},
        content=sql.encode(),
        auth=(stack.ch_admin_user, stack.ch_admin_password),
        timeout=timeout,
    )
    r.raise_for_status()
    return [json.loads(line) for line in r.text.splitlines() if line.strip()]


def udm_names_from_ts(path: Path = UDM_FIELDS_TS) -> set[str]:
    if not path.is_file():
        return set()
    text = path.read_text()
    start = text.find("UDM_COLUMNS")
    block = text[start : text.find("])", start)] if start >= 0 else ""
    return set(re.findall(r"'([a-z0-9_]+)'", block))


def load_universe(stack: Any, api: Any) -> Universe:
    from nano_e2e.client import expect

    body = expect(api.get("/api/schema/fields"), 200)
    u = Universe(schema=str(body.get("schema", "")), schema_api={f["name"] for f in body.get("fields", [])})
    u.columns = {
        r["name"]
        for r in ch_query(
            stack, "SELECT name FROM system.columns WHERE database = 'nanosiem' AND table = 'ocsf_logs'"
        )
    }
    u.event_paths = {
        r["p"] for r in ch_query(stack, "SELECT DISTINCT arrayJoin(JSONAllPaths(event)) AS p FROM ocsf_logs")
    }
    u.unmapped_keys = {
        r["p"]
        for r in ch_query(stack, "SELECT DISTINCT arrayJoin(JSONAllPaths(unmapped)) AS p FROM ocsf_logs")
    }
    udm = api.get("/api/udm/fields")
    if udm.status_code == 200:
        for f in udm.json().get("fields", []):
            u.udm_names.update(x for x in (f.get("name"), f.get("column_name")) if x)
    u.udm_names |= udm_names_from_ts()
    u.contract = OcsfContract.load()
    return u


# ---------------------------------------------------------------- API collectors
def wide_range(years: int = 30) -> tuple[str, str]:
    """Corpus samples keep their native (often old) timestamps."""
    now = datetime.now(UTC)
    return (now - timedelta(days=365 * years)).isoformat(), (now + timedelta(days=1)).isoformat()


# Probe queries for the rule validator: UDM names, OCSF typos, and a doubled
# prefix. Only the SUGGESTIONS in the answers are checked.
VALIDATE_PROBES = (
    'src_ip="203.0.113.7"',
    'dest_ip="203.0.113.7" | stats count by user',
    'process_name="cmd.exe" command_line="*whoami*"',
    'src_endpoint.ipp="203.0.113.7"',
    'actor.usr.name="alice"',
    'unmapped.unmapped.foo="x"',
    'file_hash="abc" | stats count by file_path',
)


def collect_api(stack: Any, api: Any, search: Any, note: Callable[[str], None] = print) -> list[Seen]:
    """Every field name the API hands a UI to show or suggest."""
    seen: list[Seen] = []
    start, end = wide_range()

    def surface(name: str, fn: Callable[[], Iterable[Seen]]) -> None:
        try:
            got = list(fn())
            seen.extend(got)
            note(f"  {name}: {len(got)} names")
        except Exception as exc:  # noqa: BLE001 - one broken surface must not hide the others
            note(f"  {name}: SKIPPED ({type(exc).__name__}: {str(exc)[:200]})")

    def schema_fields() -> Iterable[Seen]:
        body = api.get("/api/schema/fields").json()
        return [Seen("api:/api/schema/fields", f["name"]) for f in body.get("fields", [])]

    def ext(bucket: str) -> Callable[[], Iterable[Seen]]:
        def run() -> Iterable[Seen]:
            out = []
            for params in ({"bucket": bucket}, {"bucket": bucket, "query": "*", "start": start, "end": end}):
                r = api.post("/api/fields/ext", json=params)
                r.raise_for_status()
                for key in r.json():
                    # spill keys are BARE; the UI shows and queries them as unmapped.<key>
                    shown = f"unmapped.{key}" if bucket == "spill" else str(key)
                    out.append(Seen(f"api:/api/fields/ext[{bucket}]", shown, f"raw={key}"))
            return out

        return run

    def field_stats() -> Iterable[Seen]:
        r = search.post(
            "/api/search/field-stats",
            json={"query": "*", "start": start, "end": end},
            headers={"x-nano-cache-bypass": "1"},
        )
        r.raise_for_status()
        return [Seen("api:/api/search/field-stats", f["name"]) for f in r.json().get("fields", [])]

    def field_usage() -> Iterable[Seen]:
        body = api.get("/api/me/field-usage").json()
        return [Seen("api:/api/me/field-usage", n, k) for k in ("recent", "popular") for n in body.get(k, [])]

    def validate() -> Iterable[Seen]:
        out = []
        for q in VALIDATE_PROBES:
            r = api.post("/api/rules/validate", json={"query": q})
            r.raise_for_status()
            body = r.json()
            msgs = list(body.get("errors") or []) + [body.get("warning") or ""]
            msgs += list(body.get("warnings") or body.get("field_warnings") or [])
            for msg in msgs:
                for name in suggestions_in(str(msg)):
                    out.append(Seen("api:/api/rules/validate", name, f"probe={q}"))
        return out

    def coverage() -> Iterable[Seen]:
        body = api.get("/api/rule-repositories/coverage").json()
        return [
            Seen("api:/api/rule-repositories/coverage", m["field"], "most_missing_fields")
            for m in body.get("most_missing_fields", [])
        ]

    def repo_rules() -> Iterable[Seen]:
        out = []
        repos = api.get("/api/rule-repositories").json()
        repos = repos if isinstance(repos, list) else repos.get("repositories", repos.get("items", []))
        for repo in repos:
            rid = repo.get("id")
            r = api.get(f"/api/rule-repositories/{rid}/rules", params={"limit": 5000})
            if r.status_code != 200:
                continue
            for item in r.json():
                rule = item.get("rule", item)
                ctx = f"repo={repo.get('name')} rule={rule.get('file_path') or rule.get('name')}"
                for key in ("requires_fields", "coverage_missing_fields"):
                    for n in rule.get(key) or []:
                        out.append(Seen(f"api:/api/rule-repositories/rules[{key}]", n, ctx))
        return out

    surface("schema fields", schema_fields)
    surface("ext spill keys", ext("spill"))
    surface("ext extended paths", ext("extended"))
    surface("field stats", field_stats)
    surface("field usage", field_usage)
    surface("rule validate suggestions", validate)
    surface("rule-repo coverage", coverage)
    surface("rule-repo rules", repo_rules)
    return seen


# ---------------------------------------------------------------- UI collectors
AUTOCOMPLETE_PREFIXES = ("src", "dst", "dest", "user", "actor.", "process", "unmapped.", "ext.", "metadata.")


def collect_ui(page: Any, note: Callable[[str], None] = print) -> list[Seen]:
    """Names the browser shows: autocomplete, the results sidebar, the rule
    editor, the dashboard panel editor. `page` is a logged-in nano_e2e.ui.UiPage."""
    seen: list[Seen] = []
    start, end = wide_range()
    editor = {"css": ".cm-content"}

    def surface(name: str, fn: Callable[[], Iterable[Seen]]) -> None:
        try:
            got = list(fn())
            seen.extend(got)
            note(f"  {name}: {len(got)} names")
        except Exception as exc:  # noqa: BLE001 - UI surfaces are best-effort, reported
            note(f"  {name}: SKIPPED ({type(exc).__name__}: {str(exc).splitlines()[0][:200]})")

    def complete(label: str, prefixes: Iterable[str] = AUTOCOMPLETE_PREFIXES) -> list[Seen]:
        out = []
        for p in prefixes:
            for opt in page.op("autocomplete", find=editor, text=p):
                out.append(Seen(label, opt["label"], f"typed={p!r} detail={opt.get('detail', '')}"))
        return out

    def search_autocomplete() -> Iterable[Seen]:
        page.goto("/search")
        page.wait_for(editor, timeout_ms=30_000)
        return complete("ui:search autocomplete")

    def sidebar() -> Iterable[Seen]:
        from nano_e2e.explore import run_search

        run_search(page, "*", start, end)
        return [Seen("ui:search results sidebar", n) for n in page.op("sidebar_fields")]

    def rule_editor() -> Iterable[Seen]:
        page.goto("/rules/editor/new")
        page.wait_for(editor, timeout_ms=30_000)
        out = complete("ui:rule editor autocomplete")
        page.editor_fill(editor, 'src_ip="203.0.113.7" | stats count by user')
        try:  # a UDM name may validate silently ("Valid", no hint): that is itself worth a look
            page.wait_text({"re": "Did you mean|Available fields include|no OCSF mapping"}, timeout_ms=8_000)
        except Exception:  # noqa: BLE001
            note("    rule editor: no field hint/warning shown for a UDM-name query (API warns; UI silent?)")
        for text in page.texts({"text": {"re": "Did you mean|Available fields include"}}):
            out += [Seen("ui:rule editor validation", n, text[:160]) for n in suggestions_in(text)]
        out += [Seen("ui:rule editor field hint", h) for h in page.op("field_hints")]
        return out

    def dashboard_panel() -> Iterable[Seen]:
        page.goto("/dashboards")
        page.click(
            {"role": "button", "name": {"re": "^(New|Create) dashboard", "flags": "i"}}, timeout_ms=15_000
        )
        page.wait_for({"role": "dialog"}, timeout_ms=10_000)
        out = [Seen("ui:dashboard field hint", h) for h in page.op("field_hints")]
        if page.count(editor):
            out += complete("ui:dashboard query autocomplete", ("src", "user", "actor."))
        return out

    surface("search autocomplete", search_autocomplete)
    surface("results sidebar", sidebar)
    surface("rule editor", rule_editor)
    surface("dashboard editor", dashboard_panel)
    return seen


# ---------------------------------------------------------------- report
def report(violations: list[Violation], seen: list[Seen], u: Universe) -> str:
    surfaces = sorted({s.surface for s in seen})
    lines = [
        f"field-invariants: schema={u.schema} names={len({s.name for s in seen})} surfaces={len(surfaces)} "
        f"columns={len(u.columns)} event_paths={len(u.event_paths)} unmapped_keys={len(u.unmapped_keys)} "
        f"udm_names={len(u.udm_names)} contract={u.contract.version if u.contract else 'none'}",
    ]
    errors = [v for v in violations if v.severity == "error"]
    warns = [v for v in violations if v.severity == "warn"]
    lines.append(f"{len(errors)} error(s), {len(warns)} warning(s)")
    for v in sorted(violations, key=lambda v: (v.severity, v.kind, v.surface, v.name)):
        ctx = f"  [{v.context}]" if v.context else ""
        lines.append(f"  {v.severity.upper():5} {v.kind:16} {v.surface:44} {v.name}  -- {v.detail}{ctx}")
    return "\n".join(lines)


def run(stack: Any, *, ui: bool = False, persona: str | None = None, out: Path | None = None) -> int:
    from nano_e2e.client import Http, Journal

    journal = Journal(out.with_suffix(".api.jsonl") if out else None)
    headers = {"X-API-Key": stack.api_key}
    api = Http(stack.api_url, headers, journal)
    search = Http(stack.search_url, headers, journal)
    try:
        print("loading the live schema universe")
        u = load_universe(stack, api)
        if u.schema != "ocsf":
            print(f"stack schema is {u.schema!r}: the field invariants apply to OCSF stacks only")
            return 2
        print("collecting API surfaces")
        seen = collect_api(stack, api, search)
        if ui:
            print("collecting UI surfaces")
            from nano_e2e import explore

            with explore.session(
                stack, persona=persona, out=(out.parent if out else stack.artifact_dir)
            ) as page:
                seen += collect_ui(page)
    finally:
        api.close()
        search.close()
    violations = check(seen, u)
    print(report(violations, seen, u))
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "violations": [asdict(v) | {"severity": v.severity} for v in violations],
                    "seen": [asdict(s) for s in seen],
                },
                indent=2,
            )
        )
        print(f"wrote {out}")
    return 1 if any(v.severity == "error" for v in violations) else 0


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr] - progress when piped
    ap = argparse.ArgumentParser(prog="nano_e2e.field_invariants", description=__doc__.split("\n\n")[0])
    ap.add_argument("--run", help="e2e run id (default: the current kept stack)")
    ap.add_argument("--stack-env", help="explicit stack.env path")
    ap.add_argument("--ui", action="store_true", help="also collect UI surfaces through the browser driver")
    ap.add_argument("--persona", help="log the UI in as this persona (default: the stack admin)")
    ap.add_argument("--json", type=Path, help="write violations + every collected name here")
    args = ap.parse_args(argv)
    from nano_e2e import stackenv

    stack = stackenv.load(args.run, args.stack_env)
    return run(stack, ui=args.ui, persona=args.persona, out=args.json)


if __name__ == "__main__":
    sys.exit(main())
