"""Zero-clicks fresh install (NAN-5763): shared helpers.

NAN-5755 (playbooks never reached the library) and NAN-5757 (recon never ran)
shipped because every scenario that looked at that content called the sync or
recon endpoint itself first. The zero-clicks suite boots a fresh stack, lets
data flow, touches NOTHING that delivers content, and then asserts the content
arrived on its own.

Rules for a zero-clicks scenario:

- Read only. Two guards prove it. `guard_api_writes()` refuses, in this
  process, every non-GET API request outside `ALLOWED_WRITES` (the data-flow
  source), so no helper can click. The last scenario asserts the audit log
  (complete, not degraded) holds none of `FORBIDDEN_ACTIONS` from a person or
  API key, which covers anything outside the process.
- Every wait shares ONE budget (`deadline()`), counted from the first wait of
  the session, so the suite is bounded however many things are missing. A wait
  pinned to a known bug gets its own bounded slice (`settle(..., until=)`) and
  runs last, so it cannot starve the healthy checks.
- A wait that runs out reports the symptom (counts, statuses), never a bare
  timeout, so a `known_bug` signature can match the bug itself.

`scripts/e2e.sh run zero_clicks` owns a fresh stack and exports
`E2E_ZERO_CLICKS=1`; anywhere else (`run all`, a reused stack) the scenarios
skip, because another scenario may already have clicked.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

import httpx
import pytest

from nano_e2e import ingest
from nano_e2e.client import Journal, Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.runid import route_key
from nano_e2e.stack import Stack

T = TypeVar("T")

# One budget for the whole suite. Content channels check 20 s after the jobs
# leader starts; the playbook scheduler (NAN-5755) staggers 60 s and then
# retries every 60 s; scheduled recon (NAN-5757) waits for data, then ticks.
BUDGET_S = float(os.environ.get("E2E_ZERO_CLICKS_BUDGET_S") or 900)
# Per-scenario pytest timeout: the whole budget plus slack for the reads.
TEST_TIMEOUT_S = int(BUDGET_S) + 300

# Every audit action that populates content (nanosiem-core/src/audit/
# actions.rs plus the SOAR catalog / pack actions): none may have a user or API
# key as its actor. The leader's own runs are audited with no actor. The manual
# playbook-repository endpoints (sync, import, import-all, sync-and-import, and
# repository create / update) emit the same actions with the caller as actor
# (NAN-5784).
FORBIDDEN_ACTIONS = (
    # content channels
    "content_channels_checked", "content_channel_imported", "content_channel_updated", "auto_sync_configured",
    # rules and parsers
    "rule_repo_synced", "rule_imported", "rule_batch_imported", "rules_imported",
    "parser_repo_synced", "parser_imported", "parser_batch_imported",
    # playbooks and hunts
    "playbook_repo_created", "playbook_repo_updated",
    "playbook_repo_synced", "playbook_library_delivered", "playbook_import_refreshed",
    "playbook_import_update_applied", "playbook_import_restored", "hunt_created",
    # recon
    "hunt_recon_ran", "hunt_profile_saved", "hunt_drafts_created", "hunt_source_capability_bound",
    # catalogs
    "marketplace_sync_triggered", "marketplace_repo_synced", "enrichment_synced",
    "model_catalog_synced", "mitre_catalog_synced",
    "soar_catalog_imported", "soar_pack_installed", "soar_pack_upgraded", "soar_pack_updates_applied",
)

# The only API writes a zero-clicks session makes: logging in and pointing one
# log source (with its ingest token) at the stack, then removing it.
ALLOWED_WRITES = (
    ("POST", re.compile(r"^/api/auth/login$")),
    ("POST", re.compile(r"^/api/log-sources$")),
    ("POST", re.compile(r"^/api/log-sources/[^/]+/publish$")),
    ("DELETE", re.compile(r"^/api/log-sources/[^/]+$")),
    ("POST", re.compile(r"^/api/ingest-tokens$")),
    ("POST", re.compile(r"^/api/ingest-tokens/[^/]+/revoke$")),
)

_deadline: float | None = None


def require_fresh_stack() -> None:
    if os.environ.get("E2E_ZERO_CLICKS") != "1":
        pytest.skip(
            "zero-clicks needs a stack nothing has touched: run `scripts/e2e.sh run zero_clicks` "
            "(it owns a fresh stack and runs alone)"
        )


def deadline() -> float:
    """The suite's single deadline (monotonic), fixed by the first call."""
    global _deadline
    if _deadline is None:
        _deadline = time.monotonic() + BUDGET_S
    return _deadline


def elapsed() -> float:
    return round(BUDGET_S - (deadline() - time.monotonic()), 1)


def settle(
    read: Callable[[], T], accept: Callable[[T], bool], *, interval: float = 5.0, until: float | None = None
) -> tuple[T, bool]:
    """Poll `read` until `accept` holds or the deadline passes: the shared one,
    or `until` (monotonic) for a wait with its own bounded slice.

    Returns `(last value, accepted)` and never raises on timeout: the caller
    asserts with the symptom. Product errors from `read` (an unexpected HTTP
    status) propagate at once."""
    end = deadline() if until is None else until
    while True:
        value = read()
        if accept(value):
            return value, True
        if time.monotonic() >= end:
            return value, False
        time.sleep(min(interval, max(0.0, end - time.monotonic())) or 0.1)


def rows(body: Any, key: str) -> list[dict[str, Any]]:
    if isinstance(body, dict):
        value = body.get(key, [])
        return value if isinstance(value, list) else []
    return body if isinstance(body, list) else []


def channel_status(nano: Nano) -> dict[str, Any]:
    return api_expect(nano.api.get("/api/content/channels"), 200)


def channels(nano: Nano) -> dict[str, dict[str, Any]]:
    return {entry["channel"]: entry for entry in channel_status(nano).get("channels", [])}


def channel_problems(channel: dict[str, Any] | None) -> str | None:
    """Why a channel is not installed and applied (None when it is)."""
    if channel is None:
        return "not subscribed"
    if not channel.get("installed"):
        return f"not installed (last check {channel.get('last_check_status')}: {channel.get('last_error')})"
    if channel.get("apply_pending") or channel.get("apply_error"):
        return f"installed, not applied ({channel.get('apply_error') or 'apply pending'})"
    return None


def official_repo(nano: Nano, path: str, suffix: str) -> dict[str, Any] | None:
    body = api_expect(nano.api.get(path), 200)
    for entry in rows(body, "repositories"):
        if str(entry.get("url", "")).rstrip("/").endswith(suffix):
            return entry
    return None


def _audit(nano: Nano, action: str) -> list[dict[str, Any]]:
    """Every audit row for `action`; fails on a degraded or truncated read."""
    logs: list[dict[str, Any]] = []
    while True:
        body = api_expect(
            nano.api.get("/api/audit", params={"action": action, "limit": 1000, "offset": len(logs)}), 200
        )
        assert not body.get("degraded"), (
            f"the audit store is degraded ({body.get('degraded_reason')}): the no-clicks premise cannot be checked"
        )
        page = body.get("logs") or []
        logs.extend(page)
        total = int(body.get("total") or 0)
        if not page or len(logs) >= total:
            assert len(logs) >= total, f"audit read for {action} incomplete: {len(logs)} of {total}"
            return logs


def manual_content_actions(nano: Nano) -> list[dict[str, Any]]:
    """Audit entries for FORBIDDEN_ACTIONS that a user or API key performed.

    The audit store must be answering: the run's own first-run setup and its
    data-flow source publish have to be there, or an empty result proves
    nothing."""
    for baseline in ("system_initialized", "log_source_published"):
        assert _audit(nano, baseline), f"no {baseline} row in the audit log: the audit store is not recording this run"
    hits: list[dict[str, Any]] = []
    for action in FORBIDDEN_ACTIONS:
        for entry in _audit(nano, action):
            user = entry.get("user_id")
            if entry.get("api_key_id") or (user and user != "system"):
                hits.append({k: entry.get(k) for k in ("action", "user_id", "user_name", "api_key_name", "timestamp")})
    return hits


# ---------------------------------------------------------------- in-process write guard
blocked_writes: list[str] = []
_guard_on = False


def guard_api_writes(api_url: str) -> Callable[[], None] | None:
    """Refuse every non-GET request to the API outside ALLOWED_WRITES, from any
    client in this process (Nano, a helper's own httpx). Returns the undo, or
    None when the guard is already installed (by the other module's fixture)."""
    global _guard_on
    if _guard_on:
        return None
    _guard_on = True
    api = httpx.URL(api_url)
    original = httpx.Client.send

    def send(self: httpx.Client, request: httpx.Request, *args: Any, **kwargs: Any) -> httpx.Response:
        url = request.url
        if (
            request.method not in ("GET", "HEAD", "OPTIONS")
            and (url.host, url.port) == (api.host, api.port)
            and not any(request.method == m and rx.match(url.path) for m, rx in ALLOWED_WRITES)
        ):
            blocked_writes.append(f"{request.method} {url.path}")
            raise AssertionError(f"zero-clicks: {request.method} {url.path} is a click; this suite only reads")
        return original(self, request, *args, **kwargs)

    httpx.Client.send = send  # type: ignore[method-assign]

    def undo() -> None:
        global _guard_on
        httpx.Client.send = original  # type: ignore[method-assign]
        _guard_on = False

    return undo


# ---------------------------------------------------------------- data flowing
# "A fresh install with data flowing" is a customer pointing a shipper at a
# source: one log source with its own ingest token, OCSF Authentication (3002)
# events every few seconds for the whole session. Creating a source delivers
# no content; scheduled recon (NAN-5757) waits for exactly this. The route key
# ends in `_okta` so recon can infer `identity.authentication` for it.
FLOW_PARSER = """
parsed, err = parse_json(string(.message) ?? "")
if err == null && is_object(parsed) && exists(parsed.class_uid) {{
  . = merge(., object!(parsed), deep: true)
  del(.message)
}}
.metadata.log_source = "{lane}"
"""


def _auth_event(i: int, lane: str) -> str:
    return json.dumps({
        "class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "severity_id": 1,
        "time": int(time.time() * 1000), "status_id": 1, "status": "Success",
        "user": {"name": f"zero-clicks-user-{i % 5}"}, "src_endpoint": {"ip": f"10.57.63.{i % 200 + 1}"},
        "metadata": {"version": "1.8.0", "product": {"name": "okta", "vendor_name": "Okta"}, "log_source": lane},
        "message": f"nan-5763 zero clicks login {i}",
    })


@dataclass
class DataFlow:
    source_type: str
    sent: int = 0
    accepted: int = 0
    _stop: threading.Event = field(default_factory=threading.Event)


_flow: DataFlow | None = None


def start_data_flow(stack: Stack) -> tuple[DataFlow, Callable[[], None] | None]:
    """Start (once per session) the source + background sender. Returns the
    flow and, for the caller that started it, the teardown."""
    global _flow
    if _flow is not None:
        return _flow, None
    nano = Nano(stack.api_url, stack.search_url, {"X-API-Key": stack.api_key}, Journal(None))
    lane = f"{route_key('zero-clicks', 'flow')}_okta"
    src = nano.create_draft_source(name=lane, route_key=lane, parser_vrl=FLOW_PARSER.format(lane=lane))
    cred, token = nano.issue_token(src["id"], name=f"{lane}-tok")
    # NAN-5079: a custom parser's first publish needs an OCSF sample or an
    # audited unattested acknowledgement. Publishing a SOURCE's own parser is
    # not a content-channel action.
    published = api_expect(
        nano.api.post(f"/api/log-sources/{src['id']}/publish", json={"acknowledge_unattested": True}), 200
    )
    assert published.get("success") is True, f"publishing the data-flow source failed: {published}"
    flow = DataFlow(source_type=lane)

    def pump() -> None:
        i = 0
        while not flow._stop.is_set():
            for _ in range(10):
                i += 1
                flow.sent += 1
                try:
                    if ingest.hec(stack.hec_url, token, _auth_event(i, lane)).status_code == 200:
                        flow.accepted += 1
                except Exception:  # noqa: BLE001,S110 - a token reload blip; keep pumping
                    pass
            flow._stop.wait(5)

    thread = threading.Thread(target=pump, name="zero-clicks-data-flow", daemon=True)
    thread.start()
    _flow = flow

    def stop() -> None:
        global _flow
        flow._stop.set()
        thread.join(timeout=30)
        try:
            nano.revoke_token(cred)
        except Exception:  # noqa: BLE001,S110 - best-effort teardown
            pass
        nano.delete_source(src["id"])
        nano.close()
        _flow = None

    return flow, stop


def data_flow_fixture(stack: Stack):  # noqa: ANN201 - a generator for a pytest fixture
    """Body of the suites' session `data_flowing` fixture (idempotent)."""
    require_fresh_stack()
    undo = guard_api_writes(stack.api_url)
    flow, stop = start_data_flow(stack)
    yield flow
    if stop is not None:
        stop()
    if undo is not None:
        undo()
