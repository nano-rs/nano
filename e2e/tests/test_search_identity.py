"""nano-search runs every user-facing query as `nanosiem_search` (NAN-5484).

NAN-5470 gave interactive search its own ClickHouse identity. Compose and Helm
set nano-search's CLICKHOUSE_USER to it, but a launcher that keeps
CLICKHOUSE_USER=nanosiem and passes CLICKHOUSE_SEARCH_PASSWORD (the native local
stack, start-microservices-dev.sh) left every search on `nanosiem` while the
boot log named `nanosiem_search`.

Behavioral: for both launch shapes, run a non-stream search (POST /api/search,
histogram + count + results), a stream search (POST /api/search/stream) and a
field-stats request, each with a unique marker, then read `system.query_log`
and assert that every query carrying the marker ran as `nanosiem_search`.

Native app mode only: the app-user launch shape is a native-runner knob
(E2E_SEARCH_CH_LAUNCH=app-user, scripts/e2e.sh native_start).
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from nano_e2e.client import Nano, expect
from nano_e2e.stack import Stack

SEARCH_USER = "nanosiem_search"


def _ch(stack: Stack, sql: str) -> str:
    r = httpx.post(
        stack.ch_url,
        content=sql.encode(),
        auth=(stack.ch_admin_user, stack.ch_admin_password),
        timeout=120,
    )
    assert r.status_code == 200, f"{r.status_code}: {r.text[:800]}"
    return r.text.strip()


def _window() -> dict[str, str]:
    now = datetime.now(UTC)
    return {"start": (now - timedelta(days=1)).isoformat(), "end": (now + timedelta(minutes=5)).isoformat()}


def _run_searches(nano: Nano, marker: str) -> None:
    window = _window()
    # One search term per path: the stream path derives its ClickHouse query
    # ids server-side, so the path is told apart by the SQL text, not the id.
    base = {
        "limit": 50,
        "use_cache": False,
        "time_range": window,
    }
    headers = {"x-nano-cache-bypass": "1"}
    # Non-stream: histogram + count + results (field stats separate, as the UI).
    expect(
        nano.search_http.post(
            "/api/search",
            json={**base, "query": f"{marker}post", "skip_histogram": False, "skip_field_stats": True},
            headers=headers,
        ),
        200,
    )
    # Stream (SSE): the path the Search page uses.
    r = nano.search_http.post(
        "/api/search/stream",
        json={**base, "query": f"{marker}sse", "skip_histogram": False, "skip_field_stats": True},
        headers={**headers, "accept": "text/event-stream"},
    )
    assert r.status_code == 200, f"stream search: {r.status_code} {r.text[:400]}"
    # Field stats (the sidebar's request).
    expect(
        nano.search_http.post(
            "/api/search/field-stats",
            json={"query": f"{marker}fs", "start": window["start"], "end": window["end"]},
            headers=headers,
        ),
        200,
    )


PATHS = ("post", "sse", "fs")


def _query_users(stack: Stack, marker: str) -> list[tuple[str, str]]:
    """(user, path) for every finished SELECT carrying one of the markers."""
    deadline = time.monotonic() + 60
    rows: list[tuple[str, str]] = []
    while time.monotonic() < deadline:
        _ch(stack, "SYSTEM FLUSH LOGS")
        out = _ch(
            stack,
            "SELECT user, multiIf("
            + ", ".join(f"position(query, '{marker}{p}') > 0, '{p}'" for p in PATHS)
            + ", '?') FROM system.query_log "
            "WHERE event_time > now() - INTERVAL 15 MINUTE AND type = 'QueryFinish' "
            f"AND query_kind = 'Select' AND position(query, '{marker}') > 0 "
            "AND position(query, 'system.query_log') = 0 FORMAT TSV",
        )
        rows = [tuple(line.split("\t", 1)) for line in out.splitlines() if line]  # type: ignore[misc]
        if all(any(p == path for _, path in rows) for p in PATHS):
            return rows
        time.sleep(2)
    return rows


def _assert_search_identity(stack: Stack, nano: Nano, shape: str) -> None:
    marker = f"e2eident{uuid.uuid4().hex[:12]}"
    _run_searches(nano, marker)
    rows = _query_users(stack, marker)
    by_path = {p: [u for u, path in rows if path == p] for p in PATHS}
    for path, users in by_path.items():
        assert users, f"[{shape}] no query_log rows for the {path} search (rows: {rows})"
    wrong = [(u, q) for u, q in rows if u != SEARCH_USER]
    assert not wrong, f"[{shape}] nano-search queries not run as {SEARCH_USER}: {wrong}"


def test_search_queries_run_as_the_search_identity(stack: Stack, nano: Nano) -> None:
    if stack.app_mode != "native":
        pytest.skip("the app-user launch shape is a native-runner knob")
    # Shape 1: as compose/Helm launch it (CLICKHOUSE_USER=nanosiem_search).
    _assert_search_identity(stack, nano, "compose")
    # Shape 2: as the native local stack launches it (CLICKHOUSE_USER=nanosiem +
    # CLICKHOUSE_SEARCH_PASSWORD). Restore the default shape afterwards.
    log = stack.run_dir / "pids" / "search.log"
    boot_line = "nano-search runs its queries as the interactive search identity"
    switched_before = log.read_text(errors="replace").count(boot_line) if log.exists() else 0
    try:
        stack.svc("restart", "search", env={"E2E_SEARCH_CH_LAUNCH": "app-user"})
        _assert_search_identity(stack, nano, "local-stack")
        # Guard against a vacuous pass: the restart really launched nano-search
        # in the app-user shape (only that shape logs the switch).
        switched_after = log.read_text(errors="replace").count(boot_line)
        assert switched_after > switched_before, "the app-user launch did not take effect"
    finally:
        stack.svc("restart", "search")
