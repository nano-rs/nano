"""The Hunts rail group exists only where hunts do (v2.0.35, NAN-5844).

Hunts is a rail group (Hunts, Findings, Escalations, Actors, Knowledge;
NAN-5850 replaced "Hunt settings" with Knowledge) gated on the enterprise `hunts` capability and `hunts:view`. As the
install admin (every permission, so only the capability decides):

- open edition: no Hunts group, header, flyout or link to any /hunts route
  anywhere in the rail, expanded (every group opened in turn) or collapsed
  (every section flyout hovered);
- open edition, NAN-5850: no Rule ideas entry under Detections and no
  Hunting section in Settings either;
- enterprise edition: the group is there with its five entries (the full
  behaviour is tests/enterprise/ui/test_v2035_hunts_rail_nav.py).
"""

from __future__ import annotations

import pytest

from nano_e2e import ui as uilib
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

RAIL_HUNT_LINKS = {"css": '[data-testid="app-rail"] a[href^="/hunts"]', "visible": False}
TOGGLES = {"css": '[data-testid="app-rail"] nav button:has(svg.lucide-chevron-down)'}
HUNTS = ["/hunts", "/hunts/leads", "/hunts/escalations", "/hunts/actors", "/hunts/knowledge"]
# NAN-5850: hunt surfaces that moved out of the Hunts group.
MOVED_LINKS = {"css": '[data-testid="app-rail"] a[href="/rules/ideas"], [data-testid="settings-rail"] a[href^="/settings/hunts"]', "visible": False}


def _hunts_anywhere(page: uilib.UiPage) -> list[str]:
    found = []
    if page.count(RAIL_HUNT_LINKS):
        found.append(f"rail links {page.attrs(RAIL_HUNT_LINKS, 'href')}")
    if page.count({"testid": "nav-hunts", "visible": False}):
        found.append("the nav-hunts group")
    if page.count({"role": "button", "name": uilib.rx("^Hunts"), "within": {"testid": "app-rail"}}):
        found.append("a Hunts section header")
    if page.count(MOVED_LINKS):
        found.append(f"moved hunt links {page.attrs(MOVED_LINKS, 'href')}")
    return found


def test_v2035_hunts_rail_group_only_with_the_hunts_capability(stack: Stack, page: uilib.UiPage, timeline) -> None:
    page.viewport(1440, 900)
    page.goto("/")
    page.wait_for({"testid": "app-rail"}, timeout_ms=30_000)
    if stack.edition != "open":
        page.goto("/hunts")
        page.wait_for({"testid": "nav-hunts-items"}, timeout_ms=30_000)
        hrefs = page.attrs({"css": '[data-testid="nav-hunts-items"] a'}, "href")
        assert hrefs == HUNTS, f"enterprise: Hunts group hrefs {hrefs}"
        return

    problems = _hunts_anywhere(page)
    # Expanded: the groups are an accordion; clicking every toggle once visits each.
    for i in range(page.count(TOGGLES)):
        page.click({**TOGGLES, "nth": i})
        problems += [f"after opening group {i}: {p}" for p in _hunts_anywhere(page)]
    # Collapsed: no Hunts trigger, and no section flyout lists a hunts route.
    page.click({"role": "button", "name": "Toggle sidebar", "exact": True})
    # The rail animates its width; hover only once it settled.
    eventually(lambda: page.rect({"testid": "app-rail"})["width"], timeout=10, interval=0.2,
               desc="rail collapsed", ok=lambda w: w < 60)
    if page.count({"testid": "nav-hunts-trigger", "visible": False}):
        problems.append("collapsed: a Hunts flyout trigger")
    triggers = {"css": '[data-testid="app-rail"] nav button[aria-haspopup="menu"]'}
    for i in range(page.count(triggers)):
        page.hover({**triggers, "nth": i})
        flyout_hunts = page.count({"css": '[role="menu"] a[href^="/hunts"], [role="menu"] a[href="/rules/ideas"]', "visible": False})
        if flyout_hunts:
            problems.append(f"collapsed: flyout {i} lists a hunts link")
    page.click({"role": "button", "name": "Toggle sidebar", "exact": True})
    # Settings: no Hunting section (its button carries the section's description).
    page.goto("/settings")
    page.wait_for({"testid": "settings-rail"}, timeout_ms=30_000)
    if page.count({"role": "button", "name": uilib.rx("^Hunting"), "within": {"testid": "settings-rail"}}):
        problems.append("settings rail: a Hunting section")
    problems += [f"settings: {p}" for p in _hunts_anywhere(page)]
    timeline.step("open-core-rail", problems=problems)
    assert not problems, "open core shows Hunts navigation:\n" + "\n".join(problems)
