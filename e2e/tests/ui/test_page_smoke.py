"""Every top-level page loads (NAN-5681).

One logged-in browser walks every surface the coverage manifest marks
`"smoke": true` (e2e/coverage/ui-surfaces.json; the release preflight keeps
that manifest in step with App.tsx and the rail). For each page:

- the route renders (no "This page failed to load" boundary, not the client-side
  404 page, not bounced to /login or /denied) and its main content is not empty;
- no error toast (sonner `data-type=error` or a destructive toast);
- no console error and no failed request on any path, assets included (an
  /api 403 is allowed: a surface the user may not use; a request aborted by the
  navigation is not a failure).

The walk is soft: every page is visited, `smoke/smoke-results.json` and a
screenshot per page land in the scenario's artifacts, and the test fails at the
end naming every unhealthy page. Enterprise-only pages are skipped on an open
stack (tests/ui/test_edition_affordances.py covers the open placeholders).
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.stack import Stack

MANIFEST = Path(__file__).resolve().parents[2] / "coverage" / "ui-surfaces.json"
ALLOWED_STATUS = {403}
# Known answers that are not failures, each with its reason.
KNOWN = (
    # A query explanation cache MISS is answered 404 by design (NAN-4928, NAN-5596).
    (404, "/api/search/explanation/lookup"),
    # (No /api/siem-health/reports/latest entry: since NAN-5683 the status bar
    # asks with `allow_empty=true`, so a fresh install's "no report yet" is a
    # 200 + null, never a 404 — a 404 there is a failure on every page.)
    # SOAR settings ask for pack updates; 409 = no signed catalog installed yet.
    (409, "/api/soar/packs/upstream-updates"),
)
ERROR_TOAST = {"css": "[data-sonner-toast][data-type=error], li.destructive[data-state=open]"}
ROUTE_ERROR = {"testid": "route-error"}
NOT_FOUND = {"testid": "not-found-404"}


def smoke_paths(edition: str) -> list[str]:
    surfaces = json.loads(MANIFEST.read_text())["surfaces"]
    return [
        path
        for path, entry in sorted(surfaces.items())
        if entry.get("smoke") and (edition == "enterprise" or entry.get("edition") != "enterprise")
    ]


def _settle(page: uilib.UiPage) -> None:
    try:
        page.wait_text(uilib.rx(r"^Loading\b.*…?$"), exact=False, timeout_ms=20_000, gone=True)
    except uilib.UiError:
        pass
    time.sleep(1.0)


def _visit(page: uilib.UiPage, path: str, since: int, slug: str) -> dict[str, Any]:
    page.goto(path)
    _settle(page)
    url = page.url
    problems: list[str] = []
    if re.search(r"/(login|denied)(\?|$)", url):
        problems.append(f"bounced to {url}")
    if page.count(NOT_FOUND):
        problems.append("rendered the client-side 404 page (route not matched)")
    if page.count(ROUTE_ERROR):
        problems.append("route error boundary: " + page.texts(ROUTE_ERROR)[0][:200])
    if page.count(ERROR_TOAST):
        problems.append("error toast: " + " | ".join(t[:160] for t in page.texts(ERROR_TOAST)))
    main = page.main_text().strip()
    if len(main) < 20:
        problems.append(f"main content is empty ({main!r})")
    events = page.events_since(since)
    # Every failed request counts, on any path (a missing JS chunk or asset
    # too), except a navigation abort, a 403 from /api (a surface the user may
    # not use) and the KNOWN answers above.
    failed = [
        f"{n['status'] or n['failed']} {n['url']}"
        for n in events["network"]
        if not (n["failed"] and "ERR_ABORTED" in str(n["failed"]))
        and not (n["status"] in ALLOWED_STATUS and "/api/" in n["url"])
        and not any(n["status"] == code and frag in n["url"] for code, frag in KNOWN)
    ]
    # Chrome's "Failed to load resource" line repeats a network event judged
    # above; every other console error counts.
    console = [
        c["text"][:300] for c in events["console"] if not c["text"].startswith("Failed to load resource")
    ]
    if console:
        problems.append(f"{len(console)} console error(s): {console[:3]}")
    if failed:
        problems.append(f"{len(failed)} failed request(s): {failed[:5]}")
    shot = str(page.screenshot(f"smoke-{slug}.png", full_page=False))
    return {"path": path, "url": url, "ok": not problems, "problems": problems, "screenshot": shot}


def test_every_top_level_page_loads_clean(
    stack: Stack, page: uilib.UiPage, artifact_dir: Path, timeline
) -> None:
    paths = smoke_paths(stack.edition)
    assert len(paths) >= 40, f"the manifest marks only {len(paths)} pages for smoke: {MANIFEST}"
    out = artifact_dir / "smoke"
    out.mkdir(parents=True, exist_ok=True)
    only = os.environ.get("E2E_SMOKE_ONLY")  # a regex, to re-walk a few pages while iterating
    results: list[dict[str, Any]] = []
    for path in paths:
        if only and not re.search(only, path):
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-") or "home"
        since = page.now_ms()
        try:
            rec = _visit(page, path, since, slug)
        except uilib.UiError as exc:
            rec = {"path": path, "ok": False, "problems": [f"driver: {exc}"[:400]]}
        results.append(rec)
        (out / "smoke-results.json").write_text(json.dumps(results, indent=2))
    bad = [r for r in results if not r["ok"]]
    timeline.step("smoke", pages=len(results), unhealthy=[r["path"] for r in bad])
    assert not bad, "unhealthy pages:\n" + "\n".join(
        f"- {r['path']}: {'; '.join(r['problems'])}" for r in bad
    )


LATEST_HEALTH = "/api/siem-health/reports/latest"


def test_latest_health_report_is_never_a_404(stack: Stack, nano: Nano, page: uilib.UiPage, timeline) -> None:
    """NAN-5683: a fresh install has no SIEM Health report yet. The status bar
    asks for the latest one on every page with `allow_empty=true`, so "no
    report yet" is a 200 + null, and the console shows no 404 for it. Holds on
    any stack: with a report the same request is a 200 + the report."""
    # API contract: the opt-in empty state, and the unchanged default.
    empty_ok = nano.api.get(LATEST_HEALTH, params={"allow_empty": "true"})
    assert empty_ok.status_code == 200, f"{empty_ok.status_code} {empty_ok.text[:200]}"
    report = empty_ok.json()
    default = nano.api.get(LATEST_HEALTH)
    assert default.status_code == (404 if report is None else 200), (default.status_code, report is None)

    # Browser: a full reload (the status bar's query is cached across in-app
    # navigation, and login already loaded the shell) and a second page; every
    # latest-report request is answered 200.
    since = page.now_ms()
    page.reload()
    _settle(page)
    page.goto("/rules")
    _settle(page)
    requested = page.requests_containing(LATEST_HEALTH, since_ms=since)
    assert requested, "the status bar never asked for the latest SIEM Health report"
    assert all("allow_empty=true" in url for url in requested), requested
    # events_since lists only failed requests (>= 400 or no response).
    events = page.events_since(since)
    bad = [f"{n['status'] or n['failed']} {n['url']}" for n in events["network"] if LATEST_HEALTH in n["url"]]
    assert not bad, f"latest SIEM Health report requests failed: {bad}"
    noisy = [c["text"][:200] for c in events["console"] if "siem-health" in c["text"]]
    assert not noisy, f"console errors for siem-health: {noisy}"
    timeline.step("latest health", report="none yet" if report is None else "present", calls=len(requested))
