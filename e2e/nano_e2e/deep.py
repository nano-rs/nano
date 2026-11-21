"""Shared steps for the deep Search / Dashboards / Notebooks workflows (NAN-5684).

The scenarios act as throwaway analysts (explicit permissions, never the
install admin) on the seeded `soc` dataset, and compare what the page shows
with the API and with the seeded ground truth.

Known product bugs live in their own narrow scenarios marked
`xfail(strict=True, reason=...)`, which assert the correct behaviour through
`bug_assert`: the page is photographed (scenario artifacts, plus
`E2E_BUG_SCREENSHOT_DIR` when set) before the assertion fails.
"""

from __future__ import annotations

import os
import re
import shutil
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nano_e2e import ui as uilib
from nano_e2e.cleanup import CleanupStack
from nano_e2e.soc_seed import SocData
from nano_e2e.waits import eventually

ANALYST = (
    "search:view",
    "search:execute",
    "search:save",
    "prevalence:view",
    "dashboards:view",
    "dashboards:create",
    "dashboards:edit",
    "dashboards:delete",
)

RESULTS = {"testid": "results-count"}
EDITOR = {"css": ".search-console-input-shell .cm-content"}


def window_params(soc: SocData) -> str:
    w = soc.window()
    return f"&start={w['start'].replace('+00:00', 'Z')}&end={w['end'].replace('+00:00', 'Z')}"


def search(page: uilib.UiPage, soc: SocData | None, query: str, extra: str = "", expect_error: bool = False) -> int:
    """Open a shared link to `query` over the seeded window (or the page
    default with soc=None), run it (the linked-query prompt asks first), and
    wait until it completed or failed. Returns the header total (0 on error)."""
    from urllib.parse import quote

    page.goto(f"/search?q={quote(query, safe='')}&run=true" + (window_params(soc) if soc else "") + extra)
    prompt = {"testid": "linked-query-run-prompt"}
    done, failed = {"testid": "search-complete"}, {"testid": "search-error-drawer"}

    def state() -> str | None:
        # A completed run can still carry an advisory (some are styled as
        # errors, e.g. "dedup … may cause memory exhaustion"): done wins.
        if page.count(done):
            return "done"
        if page.count(failed) and page.attr(failed, "data-severity") == "error":
            return "error"
        if page.count(prompt):
            return "prompt"
        return None

    first = eventually(state, timeout=60, interval=0.3, desc="the linked query to run or prompt", ok=bool)
    if first == "prompt":
        page.click({"css": '[data-testid="linked-query-run-prompt"] button'})
        first = eventually(state, timeout=60, interval=0.3, desc="the query to finish",
                           ok=lambda v: v in ("done", "error"))
    if first == "error":
        if not expect_error:
            raise AssertionError(f"search failed: {page.texts({'testid': 'search-error-message'})}")
        return 0
    assert not expect_error, "the query was expected to fail but completed"
    return shown_total(page)


def shown_total(page: uilib.UiPage, timeout_ms: int = 60_000) -> int:
    """The run's total: the results header's when it has one, else the
    status bar's hit count (aggregate views render their own header)."""
    page.wait_for({"testid": "search-complete"}, timeout_ms=timeout_ms)
    if page.count(RESULTS):
        return int(page.attr(RESULTS, "data-total") or 0)
    return int(page.attr({"testid": "search-hit-count"}, "data-total") or 0)


def warnings_only(page: uilib.UiPage) -> bool:
    """No error in the drawer (advisory warnings are fine)."""
    drawer = {"testid": "search-error-drawer"}
    return not page.count(drawer) or page.attr(drawer, "data-severity") != "error"


def display_type(page: uilib.UiPage) -> str:
    return (page.attr(RESULTS, "data-display-type") or "") if page.count(RESULTS) else ""


def editor_query(page: uilib.UiPage) -> str:
    return page.editor_text(EDITOR).strip()


def run_mark(page: uilib.UiPage) -> int:
    """The current run's sequence number (0 before the first run). Take it
    BEFORE the action that starts a run, then `wait_new_results(page, mark)`."""
    done = {"testid": "search-complete"}
    if not page.count(done):
        return 0
    return int(page.attr(done, "data-run-seq") or 0)


def run_editor(page: uilib.UiPage, query: str) -> int:
    """Type a query in the editor and press the Run button (an in-page run)."""
    mark = run_mark(page)
    page.editor_fill(EDITOR, query)
    page.click({"testid": "search-run"})
    return wait_new_results(page, mark)


def wait_new_results(page: uilib.UiPage, mark: int, timeout: float = 60) -> int:
    """Wait until a run NEWER than `mark` (from `run_mark`) completed, then
    return its total. The page numbers its runs (`data-run-seq` on "Query
    complete"), so a stale completion or a late companion request
    (field-stats, history) from the previous run can never satisfy the wait."""
    eventually(
        lambda: run_mark(page),
        timeout=timeout,
        interval=0.25,
        desc=f"a search run after #{mark} to complete",
        ok=lambda seq: seq > mark,
    )
    return shown_total(page)


def table(page: uilib.UiPage) -> tuple[list[str], list[list[str]]]:
    """(header, rows) of the results table, without the unlabeled action
    column (copy-row) some table views lead with."""
    header, rows = uilib.table_rows(page)
    keep = [i for i, h in enumerate(header) if h.strip()]
    return [header[i] for i in keep], [[r[i] for i in keep if i < len(r)] for r in rows if r]


def as_int(cell: str) -> int:
    return int(re.sub(r"[^\d-]", "", cell) or 0)


def bug_dir() -> Path | None:
    d = os.environ.get("E2E_BUG_SCREENSHOT_DIR", "")
    return Path(d) if d else None


def photo_bug(page: uilib.UiPage, slug: str) -> None:
    """Photograph a bug as it shows (`<slug>.png`, also into
    E2E_BUG_SCREENSHOT_DIR when set), before later steps change the page."""
    try:
        shot = page.screenshot(f"bug-{slug}.png")
        target = bug_dir()
        if target:
            target.mkdir(parents=True, exist_ok=True)
            shutil.copy(shot, target / f"{slug}.png")
    except Exception as exc:  # noqa: BLE001 - the bug is reported either way
        print(f"WARNING: could not photograph bug {slug}: {exc}")


def bug_assert(page: uilib.UiPage | None, ok: bool, slug: str, symptom: str) -> None:
    """Assert `ok` (the correct behaviour) inside `known_bug(...)`. When the
    bug shows, the page is photographed (`<slug>.png`) first. The failure
    message is the observed SYMPTOM (counts, values), which the `known_bug`
    signature must match precisely: never a static prefix."""
    if ok:
        return
    if page is not None:
        photo_bug(page, slug)
    raise AssertionError(symptom)


def api_rows(client: Any, soc: SocData, query: str, limit: int = 1000) -> list[dict[str, Any]]:
    return client.rows(query, limit=limit, time_range=soc.window())


def api_total(client: Any, soc: SocData, query: str) -> int:
    return int(client.search(query, limit=1, time_range=soc.window())["total_count"])


@dataclass
class ModulePersona:
    """One logged-in analyst for a test module, with a refreshable API token."""

    persona: Any
    refresh_token: str
    issued: float


@contextmanager
def module_persona(stack, ui: uilib.Driver, label: str, permissions) -> Iterator[ModulePersona]:
    """One throwaway analyst for a whole test module. Every login counts
    against the install's login rate limit (429 after a burst), so the deep
    modules log in once each instead of once per scenario. The API client's
    access token is refreshed by `analyst_for` before it can expire (15 min)."""
    from nano_e2e.client import Journal, Nano
    from nano_e2e.personas import login_persona

    admin = Nano(stack.api_url, stack.search_url, {"X-API-Key": stack.api_key}, Journal(None))
    out = stack.artifact_dir / "scenarios" / f"deep-persona-{label}"
    try:
        with login_persona(stack, admin, ui, out, label, permissions) as persona:
            mp = ModulePersona(persona, persona.refresh_token, time.monotonic())
            yield mp
    finally:
        admin.close()


def _set_bearer(client: Any, token: str) -> None:
    for http in (client.api, client.search_http):
        http._client.headers["Authorization"] = f"Bearer {token}"  # noqa: SLF001 - harness-owned client


REFRESH_AFTER = 600.0  # seconds; access tokens live 900


def _refresh(mp: ModulePersona) -> None:
    if time.monotonic() - mp.issued < REFRESH_AFTER:
        return
    from nano_e2e.client import expect

    body = expect(mp.persona.client.api.post("/api/auth/refresh", json={"refresh_token": mp.refresh_token}), 200)
    tokens = body.get("tokens", body)
    _set_bearer(mp.persona.client, tokens["access_token"])
    mp.refresh_token = tokens.get("refresh_token") or mp.refresh_token
    mp.issued = time.monotonic()


@dataclass
class Analyst:
    """One scenario's view of the module's analyst: the shared browser page
    and API client, a fresh cleanup stack, and the scenario's start time
    (page errors are judged from there)."""

    page: uilib.UiPage
    client: Any
    cleanup: CleanupStack
    since: int


# Per-viewer UI preferences a scenario may change (chart type, inspector
# mode, pins, the tab's run memory). Auth is a cookie, not storage.
PREF_STORAGE = "all"


@contextmanager
def analyst_for(mp: ModulePersona, request) -> Iterator[Analyst]:
    """Per-scenario isolation on top of the module persona: refreshed token,
    browser storage reset, own cleanup, page-error window, and on failure a
    screenshot plus page.html / network.jsonl named after the scenario."""
    _refresh(mp)
    page = mp.persona.page
    page.goto("/")
    page.op("storage_clear")
    page.goto("/")
    a = Analyst(page=page, client=mp.persona.client, cleanup=CleanupStack(), since=page.now_ms())
    try:
        yield a
    finally:
        try:
            photograph_failure(page, request)
        finally:
            a.cleanup.close()


def new_page_errors(analyst: Analyst) -> list[str]:
    """Uncaught page errors since THIS scenario started (not the module's)."""
    events = analyst.page.events_since(analyst.since)
    return [e["text"] for e in events["console"] if e["type"] == "pageerror"]


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_.")[:80] or "scenario"


def photograph_failure(page: uilib.UiPage, request) -> None:
    """Persona pages are closed by `login_persona`, which cannot see a test
    failure: take the failure screenshot, page.html and network.jsonl here."""
    rep = getattr(request.node, "rep_call", None)
    if rep is not None and rep.failed:
        name = _safe(request.node.name)
        try:
            page.screenshot(f"failure-{name}.png")
            page.op("dump", name=f"failure-{name}")
        except Exception as exc:  # noqa: BLE001 - diagnostics only
            print(f"WARNING: no failure diagnostics: {exc}")
