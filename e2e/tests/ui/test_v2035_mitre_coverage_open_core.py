"""MITRE Coverage in open core: detections, telemetry and gaps, no hunt layer
(v2.0.35, NAN-5850).

The unified coverage page is AGPL; its hunt layer, recon census, bindings and
Run recon are enterprise. As the install admin (every permission, so only the
edition decides):

- open edition: the Detections and Gaps views only (no Hunts / Both segment,
  no hunted window, no Hunted or Detected + hunted legend entry);
  ?view=hunts and ?view=both fall back to Detections with a note; the
  Telemetry tab lists data components and has no census, bindings or Run
  recon; the Gaps tab and its chips work; the panel has no Hunts section;
  no Rule ideas rail entry; the moved hunt pages (/rules/ideas,
  /settings/hunts, /hunts/knowledge, /hunts/leads/decisions) are gated like
  every other enterprise surface;
- enterprise edition: the same page with the hunt layer on and all four views
  (the full behaviour is tests/enterprise/ui/test_v2035_unified_mitre_coverage.py).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.hunt_coverage import wait_catalog
from nano_e2e.edition import PLACEHOLDER, UNLICENSED
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

PAGE = {"testid": "mitre-coverage-page"}
MOVED = ["/rules/ideas", "/settings/hunts", "/settings/hunts/charter", "/hunts/knowledge", "/hunts/leads/decisions"]


def _open(page: uilib.UiPage, query: str = "") -> None:
    page.goto("/rules/coverage" + (f"?{query}" if query else ""))
    page.wait_for(PAGE, timeout_ms=30_000)


def _gated(page: uilib.UiPage) -> bool:
    text = eventually(page.main_text, timeout=30, interval=1, desc="the gated page renders",
                      ok=lambda t: len(t) > 40 and not re.fullmatch(r"(Loading[.…]*\s*)+", t))
    return page.count(UNLICENSED) > 0 or PLACEHOLDER in text or "Access Denied" in text


def test_v2035_mitre_coverage_without_the_hunt_layer(stack: Stack, nano: Nano, page: uilib.UiPage, timeline) -> None:
    wait_catalog(nano)
    page.viewport(1440, 900)
    _open(page)
    if stack.edition != "open":
        assert page.attr(PAGE, "data-hunt-layer") == "on", "enterprise admin: the hunt layer is off"
        for v in ("detections", "hunts", "both", "gaps"):
            assert page.count({"testid": f"coverage-view-{v}"}) == 1, f"enterprise: no {v} segment"
        assert page.attr({"testid": "coverage-view-both"}, "aria-checked") == "true", "enterprise default is not Both"
        return

    problems: list[str] = []
    if page.attr(PAGE, "data-hunt-layer") != "off":
        problems.append("the hunt layer is on")
    for v in ("hunts", "both"):
        if page.count({"testid": f"coverage-view-{v}"}):
            problems.append(f"a {v} segment")
    for v in ("detections", "gaps"):
        if not page.count({"testid": f"coverage-view-{v}"}):
            problems.append(f"no {v} segment")
    if page.attr({"testid": "coverage-view-detections"}, "aria-checked") != "true":
        problems.append("the default view is not Detections")
    for absent in ("coverage-filter-hunted", "coverage-legend-hunted", "coverage-legend-both", "run-recon",
                   "coverage-recon-meta", "coverage-stat-hunted"):
        if page.count({"testid": absent, "visible": False}):
            problems.append(f"open core renders {absent}")
    for present in ("coverage-filter-mode", "coverage-filter-source", "coverage-filter-tactic",
                    "coverage-legend-detected", "coverage-legend-huntable", "coverage-legend-blind"):
        if not page.count({"testid": present}):
            problems.append(f"no {present}")
    page.screenshot("coverage-open-matrix.png", full_page=False)

    for view in ("hunts", "both"):
        _open(page, f"view={view}")
        page.wait_for({"testid": "coverage-view-fallback"}, timeout_ms=10_000)
        if page.attr({"testid": "coverage-view-detections"}, "aria-checked") != "true":
            problems.append(f"?view={view} does not fall back to Detections")

    # Gaps: view chips and the tab.
    _open(page, "view=gaps")
    for chip in ("huntable_no_rule", "rule_no_telemetry", "no_coverage"):
        if not page.count({"testid": f"coverage-gap-chip-{chip}"}):
            problems.append(f"Gaps view: no {chip} chip")
    page.click({"testid": "coverage-gap-chip-no_coverage"})
    eventually(lambda: parse_qs(urlparse(page.url).query).get("gap"), timeout=10, interval=0.2,
               desc="gap=no_coverage in the URL", ok=lambda g: g == ["no_coverage"])
    page.click({"testid": "coverage-tab-gaps"})
    page.wait_for({"css": '[data-testid="coverage-gaps-table"], [data-testid="coverage-gaps-empty"]'}, timeout_ms=30_000)
    page.screenshot("coverage-open-gaps.png", full_page=False)

    # Telemetry: data components only.
    page.click({"testid": "coverage-tab-telemetry"})
    page.wait_for({"testid": "coverage-telemetry"}, timeout_ms=30_000)
    if not page.count({"testid": "coverage-telemetry-components"}):
        problems.append("Telemetry tab: no data components")
    for absent in ("coverage-telemetry-enterprise", "census-table", "bindings-table", "coverage-recon-strip", "run-recon"):
        if page.count({"testid": absent, "visible": False}):
            problems.append(f"Telemetry tab renders {absent}")
    page.screenshot("coverage-open-telemetry.png", full_page=False)

    # Panel: no Hunts section; an open-core next step is Draft rule.
    _open(page)
    cells = eventually(lambda: page.attrs({"css": '[data-testid^="coverage-cell-"]'}, "data-testid"),
                       timeout=30, interval=0.5, desc="matrix cells", ok=bool)
    tid = (cells[0] or "").removeprefix("coverage-cell-")
    _open(page, f"tech={tid}")
    page.wait_for({"testid": "coverage-panel"}, timeout_ms=30_000)
    if page.count({"testid": "coverage-panel-hunts", "visible": False}):
        problems.append("the panel renders a Hunts section")
    for action in ("review_idea", "draft_from_findings", "hunt_first"):
        if page.count({"testid": f"coverage-panel-action-{action}"}):
            problems.append(f"the panel offers {action}")

    # Rail and the moved enterprise pages.
    if page.count({"css": '[data-testid="app-rail"] a[href="/rules/ideas"]', "visible": False}):
        problems.append("a Rule ideas rail entry")
    for path in MOVED:
        page.goto(path)
        if not _gated(page):
            problems.append(f"{path}: not gated in open core: {page.main_text()[:200]}")
    timeline.step("open core coverage", problems=problems)
    assert not problems, "open-core MITRE coverage (NAN-5850):\n" + "\n".join(problems)
