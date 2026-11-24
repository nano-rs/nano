"""Log source lifecycle (NAN-5765): delete sources that sent data, then check
every page that summarizes log sources, not only the Log Sources list.

NAN-5760 shipped because the delete tests stopped at the primary list: SIEM
Health kept reporting deleted sources as silent. The module fixture publishes
three token-bound sources, sends real events through each (HEC, an OCSF
parser), checks that the summaries list them, then deletes one alone and two
in one bulk request (no further events). Each scenario checks one summary:

- log source health (`/api/log-sources/health-series`, the per-source
  series, ingestion history) and the Log Sources page;
- the Unassigned list: a deleted source that stopped sending is not offered
  as a new "unassigned" stream;
- Search: the events are history, still searchable, with no error;
- the Home dashboard (its ingestion widgets read the registry);
- the onboarding checklist's "first feed" step agrees with the registry.

SIEM Health (`removed_sources`, the stale-feed health event) is enterprise-
only: tests/enterprise/ui/test_lifecycle_log_source_health.py, on the same
setup (nano_e2e.lifecycle_sources).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from nano_e2e import deep, lifecycle, schema
from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.lifecycle_sources import Deleted, _live_sources, _series, deleted_sources
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

VIEWER = (
    "log_sources:view",
    "search:view",
    "search:execute",
    "settings:view",
    "detections:view",
    "dashboards:view",
)



@pytest.fixture(scope="module")
def deleted(stack: Stack) -> Iterator[Deleted]:
    if not schema.is_ocsf():
        pytest.skip("the lifecycle sources parse to OCSF")
    with deleted_sources(stack, "tests/ui/test_lifecycle_log_source.py") as d:
        yield d


@pytest.fixture(scope="module")
def _viewer(stack: Stack, ui: uilib.Driver) -> Iterator[deep.ModulePersona]:
    with deep.module_persona(stack, ui, "ls-lifecycle", VIEWER) as persona:
        yield persona


@pytest.fixture
def viewer(_viewer, request) -> Iterator[deep.Analyst]:
    with deep.analyst_for(_viewer, request) as a:
        yield a


# ---------------------------------------------------------------- log source health
def test_log_source_health_drops_deleted_sources(nano: Nano, deleted: Deleted, viewer: deep.Analyst) -> None:
    lifecycle.absent(lambda: _series(nano), deleted.needles, what="GET /api/log-sources/health-series")
    lifecycle.absent(
        lambda: api_expect(nano.api.get("/api/log-sources/ingestion-history", params={"hours": 24}), 200),
        deleted.needles, what="GET /api/log-sources/ingestion-history",
    )
    for s in deleted.all:
        r = nano.api.get(f"/api/log-sources/{s.id}/health-series", params={"hours": 24})
        assert r.status_code == 404, f"per-source health of deleted {s.id}: {r.status_code} {r.text[:200]}"
    lifecycle.absent(lambda: _live_sources(nano), deleted.needles, what="GET /api/log-sources")

    page = viewer.page
    since = page.now_ms()
    page.goto("/ingestion/log-sources")
    region = {"testid": "log-sources-table-region"}
    page.wait_for(region, timeout_ms=60_000)
    # Loaded: the page fetched the registry and shows every source it holds.
    live = [str(x.get("name")) for x in _live_sources(nano)][:5]
    lifecycle.page_loaded(page, "/api/log-sources", since, controls=live)
    # The feed table only: the Unassigned panel is its own scenario below.
    text = " ".join(page.texts(region))
    for extra in page.texts({"testid": "unassigned-sources"}):
        text = text.replace(extra, "")
    assert not [s.name for s in deleted.all if s.name in text], "Log Sources lists a deleted source"
    assert not deep.new_page_errors(viewer)


# ---------------------------------------------------------------- unassigned
def test_unassigned_list_does_not_offer_deleted_sources(nano: Nano, deleted: Deleted, viewer: deep.Analyst,
                                                        timeline) -> None:
    keys = {src.route_key for src in deleted.all}
    body = api_expect(nano.api.get("/api/log-sources/unassigned"), 200)
    offered = lifecycle.mentions(body.get("sources") or [], keys)
    timeline.step("unassigned", offered=offered)
    page = viewer.page
    since = page.now_ms()
    page.goto("/ingestion/log-sources")
    page.wait_for({"testid": "log-sources-table-region"}, timeout_ms=60_000)
    lifecycle.page_loaded(page, "/api/log-sources/unassigned", since)
    # Loaded: the panel shows as many keys as the API offers.
    n = len(api_expect(nano.api.get("/api/log-sources/unassigned"), 200).get("sources") or [])
    eventually(lambda: page.count({"testid": "unassigned-key"}), timeout=30, interval=1,
               desc=f"the Unassigned panel to list the API's {n} keys", ok=lambda c: c == n)
    rows = page.texts({"testid": "unassigned-key"})
    shown = [k for k in sorted(keys) if any(k in r for r in rows)]
    timeline.step("unassigned panel", shown=shown)
    if shown:
        deep.photo_bug(page, "unassigned-lists-deleted-sources")
    assert not offered and not shown, (
        f"deleted sources offered as unassigned streams: API {offered[:6]}, page {shown}"
    )


# ---------------------------------------------------------------- search
def test_search_keeps_deleted_sources_events_as_history(nano: Nano, deleted: Deleted, viewer: deep.Analyst) -> None:
    for s in deleted.all:
        assert nano.rows(f'actor.user.name="{s.user}"', limit=5, minutes_back=120), f"{s.name}: history lost"
    query = f'actor.user.name="{deleted.single.user}"'
    total = deep.search(viewer.page, None, query)
    assert total >= 1, f"the deleted source's events are not searchable in the UI ({total})"
    assert deep.warnings_only(viewer.page)
    assert not deep.new_page_errors(viewer)


# ---------------------------------------------------------------- dashboards / onboarding
def test_home_and_onboarding_follow_the_registry(nano: Nano, deleted: Deleted, viewer: deep.Analyst) -> None:
    page = viewer.page
    since = page.now_ms()
    page.goto("/")
    # Loaded: Home fetched the registry-backed ingestion history.
    home = lifecycle.page_loaded(page, "/api/log-sources/ingestion-history", since)
    assert not [s.name for s in deleted.all if s.name in home], "Home lists a deleted source"

    status = api_expect(viewer.client.api.get("/api/onboarding/status"), 200)
    assert bool(status.get("has_log_sources")) == bool(_live_sources(nano)), status
    page.goto("/getting-started")
    page.wait_text("Source connected" if status.get("has_log_sources") else "No sources yet", exact=False,
                   timeout_ms=30_000)
    assert not deep.new_page_errors(viewer)
