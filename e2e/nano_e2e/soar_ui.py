"""Shared helpers for the SOAR browser scenarios (v2.0.34, NAN-5681).

- `psql`: one SQL statement against the stack's own PostgreSQL (alerts are
  seeded straight into `alerts`, the insert path detections use; the outbox
  trigger enqueues them for alert-triggered flows), as in the storm scenario.
- `switch_soar`: Settings > SOAR in the browser (the API refuses the switch to
  an API key).
- `persona`: a throwaway role/group/user with explicit permissions, a session
  (JWT) client acting as that person, and their logged-in browser page.
  Flows act as their saver, so a flow saved through this session is a
  person's flow (an API-key flow is AI-originated and gates its writes).
- Flow-editor ops: open a flow, open the Blocks palette, add a block, pick a
  Select option in the inspector.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from nano_e2e import ui as uilib
from nano_e2e.client import Journal, Nano, expect
from nano_e2e.rbac import LimitedUser, limited_user
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

TERMINAL = {"succeeded", "failed", "canceled", "ambiguous", "skipped", "timed_out"}
EDITOR = {"testid": "flow-editor"}
INSPECTOR = {"testid": "flow-inspector"}


def psql(query: str) -> str:
    """Run SQL (stdin, never argv) against the stack's PostgreSQL; stdout trimmed."""
    parsed = urlparse(os.environ["DATABASE_URL"])
    env = {**os.environ, "PGPASSWORD": unquote(parsed.password or "")}
    out = subprocess.run(  # noqa: S603 - fixed argv; SQL on stdin
        [
            "psql",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",  # noqa: S607
            "--host",
            parsed.hostname or "127.0.0.1",
            "--port",
            str(parsed.port or 5432),
            "--username",
            unquote(parsed.username or ""),
            "--dbname",
            parsed.path.lstrip("/"),
            "--file",
            "-",
        ],
        input=query,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert out.returncode == 0, out.stderr[-2000:]
    return out.stdout.strip()


def sql_text(value: str) -> str:
    """A SQL string literal for harness-generated values (markers, ids)."""
    return "'" + value.replace("'", "''") + "'"


def seed_alert(
    user: str, severity: str = "high", sources: tuple[str, ...] = ("okta",), case_id: str | None = None
) -> str:
    """One alert whose matched event names `user` (flows match on
    `flow_input.alert.entities.user`); returns its id."""
    events = '[{"user": "' + user + '"}]'
    arr = "ARRAY[" + ",".join(sql_text(s) for s in sources) + "]::text[]"
    case = sql_text(uuid_of(case_id)) + "::uuid" if case_id else "NULL"
    out = psql(
        "INSERT INTO alerts (severity, matched_events, source_types, case_id) "  # noqa: S608
        f"VALUES ({sql_text(severity)}, {sql_text(events)}::jsonb, {arr}, {case}) RETURNING id;"
    )
    return out.splitlines()[0].strip()


def switch_soar(ui: uilib.Driver, stack: Stack, out: Path, on: bool) -> None:
    """Settings > SOAR: the audited switch, as the stack's own (harness) admin."""
    p = uilib.UiPage.open(ui, out, "soar switch")
    failed = True
    try:
        uilib.login(p, stack.admin_email, stack.admin_password)
        p.goto("/settings/soar")
        p.fill(uilib.field({"role": "textbox", "name": "Reason", "exact": True}, "nano-e2e NAN-5681"))
        if on:
            p.click({"role": "button", "name": "Turn SOAR on"}, timeout_ms=30_000)
        else:
            p.click({"role": "button", "name": "Turn SOAR off"}, timeout_ms=30_000)
            p.click({"role": "button", "name": "Turn off", "exact": True, "within": {"role": "alertdialog"}})
        p.wait_text("on" if on else "off", timeout_ms=30_000)
        failed = False
    finally:
        p.finish(failed)


@contextmanager
def soar_session(ui: uilib.Driver, stack: Stack) -> Iterator[None]:
    """SOAR on for every SOAR scenario of the pytest session, switched once and
    restored to what it was when the SESSION ends (fixture `soar_on_session`,
    tests/enterprise/ui/conftest.py). Per-scenario switching cancelled other
    scenarios' runs in flight on a shared stack (`soar_disabled`)."""
    client = Nano(stack.api_url, stack.search_url, {"X-API-Key": stack.api_key}, Journal(None))
    try:
        was = bool(expect(client.api.get("/api/soar/settings"), 200)["soar_enabled"])
        if not was:
            switch_soar(ui, stack, stack.artifact_dir / "ui-soar-on", True)
            eventually(
                lambda: expect(client.api.get("/api/soar/settings"), 200)["soar_enabled"],
                timeout=30,
                desc="SOAR on in the API",
                ok=bool,
            )
        yield
        if not was:
            switch_soar(ui, stack, stack.artifact_dir / "ui-soar-off", False)
    finally:
        client.close()


@dataclass
class Persona:
    user: LimitedUser
    id: str
    api: Nano  # a session (JWT) client acting as this person
    page: uilib.UiPage


def user_id(nano: Nano, email: str) -> str:
    users = expect(nano.api.get("/api/users"), 200)
    rows = users["users"] if isinstance(users, dict) else users
    return next(u["id"] for u in rows if u.get("email") == email)


@contextmanager
def persona(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir: Path, label: str, permissions: list[str]
) -> Iterator[Persona]:
    """A throwaway person (never the install admin), their session client and
    their logged-in browser context."""
    journal = Journal(artifact_dir / f"{label}.jsonl")
    with limited_user(stack, label, permissions, journal) as user:
        login = Nano(stack.api_url, stack.search_url, {}, journal)
        jwt = login.login(user.email, user.password)
        login.close()
        client = Nano(stack.api_url, stack.search_url, {"Authorization": f"Bearer {jwt}"}, journal)
        page = uilib.UiPage.open(ui, artifact_dir / f"ui-{label}", label)
        failed = True
        try:
            uilib.login(page, user.email, user.password)
            yield Persona(user, user_id(nano, user.email), client, page)
            failed = False
        finally:
            page.finish(failed)
            client.close()


class Cleanup:
    """LIFO teardown that runs every action and reports the first error."""

    def __init__(self) -> None:
        self._fns: list[tuple[str, Callable[[], Any]]] = []

    def add(self, what: str, fn: Callable[[], Any]) -> None:
        self._fns.append((what, fn))

    def close(self) -> None:
        errors: list[str] = []
        for what, fn in reversed(self._fns):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - every action runs; reported below
                errors.append(f"{what}: {exc}")
        self._fns.clear()
        if errors:
            print("WARNING: cleanup errors: " + "; ".join(errors))


def save_flow(client: Nano, cleanup: Cleanup, admin: Nano, body: dict[str, Any]) -> dict[str, Any]:
    """POST a flow as `client`; the harness admin archives+deletes it afterwards."""
    resp = client.api.post("/api/soar/flows", json=body)
    flow = expect(resp, 200, 201)
    cleanup.add(f"flow {flow['id']}", lambda: admin.api.delete(f"/api/soar/flows/{flow['id']}"))
    return flow


def run_of(nano: Nano, run_id: str) -> dict[str, Any]:
    return expect(nano.api.get(f"/api/soar/runs/{run_id}"), 200)


def steps_of(nano: Nano, run_id: str) -> list[dict[str, Any]]:
    return expect(nano.api.get(f"/api/soar/runs/{run_id}/steps"), 200)["steps"]


def flow_runs(nano: Nano, flow_id: str, pages: int = 5) -> list[dict[str, Any]]:
    """Recent runs of one flow, newest first (the list API has no flow filter,
    so pages of the newest runs are scanned)."""
    out: list[dict[str, Any]] = []
    for page in range(pages):
        body = expect(nano.api.get("/api/soar/runs", params={"limit": 100, "offset": page * 100}), 200)
        runs = body["runs"] if isinstance(body, dict) else body
        out += [r for r in runs if r.get("flow_id") == flow_id]
        if len(runs) < 100:
            break
    return out


def wait_run(nano: Nano, run_id: str, timeout: float = 180) -> dict[str, Any]:
    return eventually(
        lambda: run_of(nano, run_id),
        timeout=timeout,
        interval=2,
        desc=f"run {run_id} terminal",
        ok=lambda r: r["status"] in TERMINAL,
    )


# ---------------------------------------------------------------- editor ops
def open_flow(page: uilib.UiPage, flow_id: str) -> None:
    page.goto(f"/automation/flows/{flow_id}")
    page.wait_for(EDITOR, timeout_ms=30_000)


def open_palette(page: uilib.UiPage) -> None:
    if page.count({"testid": "flow-palette"}) == 0:
        page.click({"role": "button", "name": "Blocks", "within": EDITOR})
    page.wait_for({"testid": "flow-palette"})


def add_block(page: uilib.UiPage, label: str) -> None:
    """Click a palette row (inserts after the selected step and selects it)."""
    open_palette(page)
    page.click({"testid": "palette-row", "has": label, "within": {"testid": "flow-palette"}})


def select_step(page: uilib.UiPage, step_id: str) -> None:
    page.click({"css": f'[data-testid="flow-step"][data-step-id="{step_id}"]'})
    page.wait_for(INSPECTOR)


def pick(page: uilib.UiPage, label: str, option: str | dict[str, str], exact: bool = True) -> None:
    """A Radix Select in the inspector (trigger aria-label = the field label)."""
    page.choose({"role": "combobox", "name": label, "exact": True, "within": INSPECTOR}, option, exact=exact)


def type_field(page: uilib.UiPage, label: str, value: str) -> None:
    page.fill(uilib.field({"css": f'[aria-label="{label}"]', "within": INSPECTOR}, value))


def save_draft(page: uilib.UiPage) -> None:
    page.click({"role": "button", "name": "Save draft", "exact": True, "within": EDITOR})
    page.wait_text("unsaved", gone=True, timeout_ms=30_000)


# ---------------------------------------------------------------- SQL probes
# Values are harness-generated (uuids, markers) and quoted by sql_text.
def set_flow_status(flow_id: str, status: str) -> None:
    """Force a flow's status (e.g. a flow live from before a save-time check)."""
    psql(f"UPDATE soar_flows SET status = {sql_text(status)} WHERE id = {sql_text(flow_id)}::uuid;")  # noqa: S608


def cases_titled(prefix: str) -> int:
    return int(psql(f"SELECT count(*) FROM cases WHERE title LIKE {sql_text(prefix + '%')};"))  # noqa: S608


def cases_keyed(key: str) -> int:
    return int(psql(f"SELECT count(*) FROM cases WHERE grouping_key = {sql_text(key)};"))  # noqa: S608


def alert_case(alert_id: str) -> str:
    """The alert's case id ('' when none)."""
    return psql(f"SELECT coalesce(case_id::text, '') FROM alerts WHERE id = {sql_text(alert_id)}::uuid;")  # noqa: S608


def restrict_source(source_type: str, on: bool) -> None:
    if on:
        value = sql_text(source_type)
        psql(f"INSERT INTO restricted_source_types (source_type) VALUES ({value}) ON CONFLICT DO NOTHING;")  # noqa: S608
    else:
        psql(f"DELETE FROM restricted_source_types WHERE source_type = {sql_text(source_type)};")  # noqa: S608


_TYPEID_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"


def typeid(prefix: str, value: str) -> str:
    """The TypeID the API shows for a UUID (`alert_01h…`): Crockford base32 of
    the 128-bit value in 26 characters."""
    n = int(value.replace("-", ""), 16)
    out = []
    for _ in range(26):
        out.append(_TYPEID_ALPHABET[n & 31])
        n >>= 5
    return f"{prefix}_{''.join(reversed(out))}"


def pick_test_alert(page: uilib.UiPage, dialog: dict[str, Any], alert_id: str) -> None:
    """In the Run test dialog: Real alert, then the seeded alert's row.

    A row shows `shortId` of the TypeID (`alert_XX`: only ~8 bits) and the
    alert's creation second, so match BOTH, and refuse an ambiguous pick
    instead of clicking the first of several rows."""
    page.click({"role": "tab", "name": "Real alert", "exact": True, "within": dialog})
    short = typeid("alert", alert_id)[:8]
    when = "to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')"
    query = f"SELECT {when} FROM alerts WHERE id = {sql_text(uuid_of(alert_id))}::uuid;"  # noqa: S608
    created = psql(query).strip()
    pattern = re.escape(short) + r".*" + re.escape(f"{created} UTC")
    row = {"role": "radio", "has": uilib.rx(pattern), "within": dialog}
    eventually(
        lambda: page.count(row), timeout=30, interval=1, desc="the seeded alert in Recent alerts", ok=bool
    )
    n = page.count(row)
    assert n == 1, f"{n} Recent alerts rows match {short} at {created} UTC: refusing an ambiguous pick"
    page.click(row)


def uuid_of(value: str | None) -> str:
    """A UUID string from a UUID or a TypeID (`case_7f…`); '' for None."""
    if not value:
        return ""
    if "_" not in value:
        return value.lower()
    n = 0
    for ch in value.rsplit("_", 1)[1]:
        n = (n << 5) | _TYPEID_ALPHABET.index(ch)
    h = f"{n:032x}"
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def api_test_run(client: Nano, flow_id: str, alert_id: str) -> dict[str, Any]:
    """A test (test-mode) run of a saved flow against a real alert, through the
    API the editor's Run test uses; returns the run once terminal."""
    res = expect(
        client.api.post(f"/api/soar/flows/{flow_id}/test", json={"alert_id": uuid_of(alert_id)}),
        200,
        201,
        202,
    )
    run = res.get("run", res)
    return wait_run(client, run["id"])


@contextmanager
def admin_session(stack: Stack, artifact_dir: Path) -> Iterator[Nano]:
    """The throwaway stack's own admin as an interactive session (a saver who
    may read every source), never an API key."""
    journal = Journal(artifact_dir / "admin-session.jsonl")
    login = Nano(stack.api_url, stack.search_url, {}, journal)
    try:
        jwt = login.login(stack.admin_email, stack.admin_password)
    finally:
        login.close()
    client = Nano(stack.api_url, stack.search_url, {"Authorization": f"Bearer {jwt}"}, journal)
    try:
        yield client
    finally:
        client.close()
