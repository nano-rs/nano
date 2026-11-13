"""Connector pull feeds against REAL vendor tenants (NAN-4961).

The stack runs `nano-connector-runner` exactly as shipped (`--profile
connector-live`: no test seam), so every vendor request goes to the real
tenant under the spec's host policy. Collector feeds deliver into lanes that
need a deployed HEC parser; here that parser is the vendor's real OCSF parser,
imported LINKED from the nano-rs/parsers repository the install follows
(NAN-4940), never the harness's lane parser, so "events land with the right
OCSF class and fields" is a statement about the shipped parser.

Feed lifecycle helpers (create, run now, wait for a run, checkpoint view) are
plain API calls; the scenarios drive the same flow in the browser where the
issue asks for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from nano_e2e.client import Nano, expect
from nano_e2e.waits import eventually

PARSERS_REPO = "nano-rs/parsers"


@dataclass(frozen=True)
class VendorParser:
    """A first-party OCSF parser in nano-rs/parsers and the lanes it claims."""

    path: str
    name: str
    lanes: tuple[str, ...]


OKTA_PARSER = VendorParser("parsers-ocsf/okta/parser.yaml", "okta_ocsf", ("okta",))
GWS_PARSER = VendorParser(
    "parsers-ocsf/google_workspace/parser.yaml", "google_workspace_ocsf", ("gws_login", "gws_admin", "gws_token")
)
SLACK_PARSER = VendorParser("parsers-ocsf/slack_access/parser.yaml", "slack_access_ocsf", ("slack_access_log",))


def _items(body: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(body, list):
        return body
    for k in keys:
        if isinstance(body.get(k), list):
            return body[k]
    return []


def parsers_repo(nano: Nano) -> dict[str, Any]:
    """The followed nano-rs/parsers repository, synced (a fresh install
    registers and syncs it on boot, NAN-4940)."""

    def find() -> dict[str, Any] | None:
        repos = _items(expect(nano.api.get("/api/parser-repositories"), 200), "repositories", "items")
        return next(
            (
                r
                for r in repos
                if PARSERS_REPO in f"{r.get('name', '')} {r.get('url', '')} {r.get('repository_url', '')}"
                and r.get("last_sync_status") == "success"
            ),
            None,
        )

    return eventually(find, timeout=300, interval=5, desc=f"{PARSERS_REPO} registered and synced")


def ensure_vendor_parser(nano: Nano, parser: VendorParser) -> str:
    """Import `parser` LINKED from nano-rs/parsers as a HEC log source (idempotent:
    an existing import is reused) and publish it. Returns the log source id."""
    repo = parsers_repo(nano)
    listed = _items(
        expect(nano.api.get(f"/api/parser-repositories/{repo['id']}/parsers", params={"search": parser.name}), 200)
    )
    entry = next((p for p in listed if p.get("file_path") == parser.path or p.get("name") == parser.name), None)
    assert entry, f"{parser.path} is not in {PARSERS_REPO} (listed: {[p.get('file_path') for p in listed]})"
    source_id = entry.get("linked_log_source_id")
    if not source_id:
        res = expect(
            nano.api.post(
                f"/api/parser-repositories/{repo['id']}/parsers/import/{parser.path}",
                json={"import_type": "linked", "ingestion_method": "splunk_hec"},
            ),
            200,
        )
        source_id = res.get("log_source_id") or res.get("id")
    src = expect(nano.api.get(f"/api/log-sources/{source_id}"), 200)
    missing = [lane for lane in parser.lanes if lane not in (src.get("match_values") or [])]
    assert not missing, f"imported {parser.name} does not claim lanes {missing}: {src.get('match_values')}"
    if not (src.get("deployed") and src.get("enabled")):
        res = expect(nano.api.post(f"/api/log-sources/{source_id}/publish", json={"acknowledge_unattested": True}), 200)
        assert res.get("success") is True, f"publishing {parser.name} failed: {res}"
    eventually(
        lambda: expect(nano.api.get(f"/api/log-sources/{source_id}"), 200),
        timeout=120,
        desc=f"{parser.name} deployed",
        ok=lambda s: bool(s.get("deployed")) and bool(s.get("enabled")),
    )
    return str(source_id)


# ---------------------------------------------------------------- feeds
def create_feed(nano: Nano, body: dict[str, Any]) -> dict[str, Any]:
    created = expect(nano.api.post("/api/connector-feeds", json=body), 200, 201)
    return created.get("feed", created)


def feed_by_name(nano: Nano, name: str) -> dict[str, Any] | None:
    items = _items(expect(nano.api.get("/api/connector-feeds"), 200), "feeds", "items")
    return next((f for f in items if f.get("name") == name), None)


def detail(nano: Nano, feed_id: str) -> dict[str, Any]:
    return expect(nano.api.get(f"/api/connector-feeds/{feed_id}"), 200)


def run_now(nano: Nano, feed_id: str) -> None:
    """Pause + resume: resume schedules the next run immediately."""
    expect(nano.api.patch(f"/api/connector-feeds/{feed_id}", json={"enabled": False}), 200, 204)
    expect(nano.api.patch(f"/api/connector-feeds/{feed_id}", json={"enabled": True}), 200, 204)


def finished_runs(d: dict[str, Any]) -> list[dict[str, Any]]:
    return [r for r in d.get("runs") or [] if r.get("finished_at")]


def wait_run(
    nano: Nano, feed_id: str, *, after: int, timeout: float = 240, status: str | None = "success"
) -> dict[str, Any]:
    """Wait until the feed has more than `after` finished runs (and, when
    `status` is set, the newest one has it). Returns the feed detail."""

    def ok(d: dict[str, Any]) -> bool:
        runs = finished_runs(d)
        if len(runs) <= after or d["feed"].get("running"):
            return False
        return status is None or runs[0].get("status") == status

    return eventually(
        lambda: detail(nano, feed_id),
        timeout=timeout,
        interval=5,
        desc=f"feed {feed_id} run #{after + 1}" + (f" with status {status}" if status else ""),
        ok=ok,
    )


def wait_failed(nano: Nano, feed_id: str, timeout: float = 240) -> dict[str, Any]:
    return eventually(
        lambda: detail(nano, feed_id),
        timeout=timeout,
        interval=5,
        desc=f"feed {feed_id} reports a failed run",
        ok=lambda d: d["feed"].get("last_status") == "failed",
    )


def checkpoints(d: dict[str, Any]) -> dict[str, int]:
    return {c["stream_id"]: int(c.get("commits") or 0) for c in d.get("checkpoints") or []}


def rotate(nano: Nano, credential_id: str, credentials: dict[str, str]) -> dict[str, Any]:
    return expect(
        nano.api.post(
            f"/api/credentials/{credential_id}/rotate",
            json={"credentials": credentials, "note": "nano-e2e NAN-4961 rotate"},
        ),
        200,
    )


def rotate_and_prove(
    nano: Nano, feed_id: str, credential_id: str, refused: dict[str, str], good: dict[str, str], step: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Rotate the feed's credential to a REFUSED secret (the next run must fail:
    the rotation is live on the very next run, no feed edit or restart), then
    to `good` (the next run must succeed). Returns (failed run detail, good)."""
    v0 = rotate(nano, credential_id, refused)["version"]["version_number"]
    before = len(finished_runs(detail(nano, feed_id)))
    run_now(nano, feed_id)
    bad = wait_run(nano, feed_id, after=before, status="failed")
    step("rotated to a refused secret: next run failed", version=v0, error=bad["feed"].get("last_error"))
    v1 = rotate(nano, credential_id, good)["version"]["version_number"]
    assert v1 > v0, (v0, v1)
    before = len(finished_runs(bad))
    run_now(nano, feed_id)
    ok = wait_run(nano, feed_id, after=before)
    step("rotated to the new real secret: next run succeeded", version=v1, run=finished_runs(ok)[0])
    assert ok["feed"].get("consecutive_failures") == 0, ok["feed"]
    return bad, ok


def delete_feed(nano: Nano, feed_id: str) -> None:
    r = nano.api.delete(f"/api/connector-feeds/{feed_id}")
    assert r.status_code in (200, 204, 404), f"delete feed {feed_id} -> {r.status_code}: {r.text[:300]}"


# ---------------------------------------------------------------- directory
def directory_users(nano: Nano, provider_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    page = 1
    while True:
        body = expect(
            nano.api.get("/api/identity/users", params={"provider_id": provider_id, "page": page, "page_size": 200}),
            200,
        )
        rows = _items(body, "users", "items")
        out.extend(rows)
        total = int(body.get("total") or 0) if isinstance(body, dict) else len(rows)
        if not rows or len(out) >= total:
            return out
        page += 1


# ---------------------------------------------------------------- browser
def ui_create_feed(
    page: Any, label: str, name: str, config: dict[str, str], secrets: dict[str, str], gws_key_json: str = ""
) -> None:
    """Pull feeds > New pull feed: connector, name, config fields, a NEW
    credential entered inline (secret fields typed with secret=True: scrubbed
    from artifacts, blanked before screenshots), Create feed."""
    import re

    from nano_e2e import ui_pull
    from nano_e2e.ui import field, rx

    page.goto(ui_pull.PULL_FEEDS_PATH)
    page.wait_for({"testid": "pull-feeds-page"}, timeout_ms=60_000)
    page.click({"role": "button", "name": rx("New pull feed")})
    dlg = {"role": "dialog"}
    page.choose({"role": "combobox", "within": dlg, "nth": 0}, rx(f"^{re.escape(label)}"))
    fields = [field({"placeholder": "Okta production", "within": dlg}, name)]
    for key, value in config.items():
        # Optional fields render as "<KEY> (optional)".
        fields.append(field({"labelAfter": key, "exact": False, "within": dlg}, value))
    if gws_key_json:
        fields.append(field({"css": "textarea[placeholder^='{\"type\"']", "within": dlg}, gws_key_json, secret=True))
    for key, value in secrets.items():
        fields.append(field({"labelAfter": key, "within": dlg}, value, secret=True))
    page.fill(*fields)
    page.click({"role": "button", "name": "Create feed", "within": dlg})
    page.wait_for(dlg, gone=True, timeout_ms=30_000)


def ui_feed_row(page: Any, name: str) -> dict[str, str]:
    """The feed's Pull feeds row, by column header (fresh load)."""
    from nano_e2e import ui_pull

    page.goto(ui_pull.PULL_FEEDS_PATH)
    page.wait_for({"testid": "pull-feeds-page"}, timeout_ms=60_000)
    return page.op("row_cells", contains=name, within={"testid": "pull-feeds-region"}, timeout=60_000)


# ---------------------------------------------------------------- collector scenario
@dataclass
class Collector:
    """One collector connector's real-tenant scenario inputs."""

    connector: str  # spec slug
    label: str  # New pull feed > Connector option (display name prefix)
    parser: VendorParser
    config: dict[str, str]
    secrets: dict[str, str]  # credential fields, entered inline in the UI
    rotate_secrets: dict[str, str]  # the rotate step's new version
    bad_secrets: dict[str, str]  # a credential the vendor refuses
    refused: tuple[str, ...]  # substrings of a clear "credential refused" error (lowercase)
    classes: frozenset[int]  # OCSF class_uids the parser may emit for this vendor
    gws_key_json: str = ""  # Google Workspace: the key goes in the textarea


def lane_query(parser: VendorParser) -> str:
    """nPL for every event of the parser's lanes (OCSF metadata.log_source)."""
    lanes = " OR ".join(f'metadata.log_source="{lane}"' for lane in parser.lanes)
    return f"({lanes})" if len(parser.lanes) > 1 else lanes


def row_get(row: dict[str, Any], dotted: str) -> Any:
    """A field of a search row: flat dotted key, or nested objects, or the
    `event` JSON an OCSF row carries."""
    import json as _json

    if dotted in row:
        return row[dotted]
    cur: Any = row
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            cur = None
            break
    if cur is not None:
        return cur
    ev = row.get("event")
    if isinstance(ev, str):
        try:
            ev = _json.loads(ev)
        except ValueError:
            return None
    return row_get(ev, dotted) if isinstance(ev, dict) else None
