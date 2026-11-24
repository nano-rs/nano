"""No dead enterprise affordances in the open build (NAN-4937; cf. NAN-2356).

Open edition: every enterprise-only surface is either absent (its route
redirects to a working page) or shows an entitlement panel. Since NAN-5310
(#9388) a capability-gated route renders `LicensedFeatureUnavailable`
("<Feature> is not licensed ... Open/core features, ingest, search, and stored
data remain available", testid `licensed-feature-unavailable`); a stubbed page
with no capability gate still renders the open-build placeholder ("Available
in nano paid plans"). None renders blank, an error boundary, or an uncaught
page error. Every link in the left rail opens a page with content.

Enterprise edition: the same routes mount the real page (never the open-build
placeholder or the license panel), so a stripped stub or a capability
regression can't silently ship in the paid build.
"""

from __future__ import annotations

import re

import pytest

from nano_e2e import ui as uilib
from nano_e2e.edition import PLACEHOLDER, SSO_PANEL, UNLICENSED, UNLICENSED_COPY
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

BROKEN = re.compile(r"Something went wrong|Unexpected Application Error|Failed to fetch dynamically", re.I)

# Every route App.tsx mounts from @/enterprise/pages (stubbed in the open build).
ENTERPRISE_ROUTES = [
    "/risk",
    "/risk/watchlists",
    "/automation",
    "/automation/flows",
    "/rules/ioc-lists",
    "/rules/tuning",
    "/cases/search",
    "/playbooks",
    "/playbooks/repositories",
    "/notebooks",
    "/settings/ai",
    "/settings/risk",
    "/settings/soar",
    "/settings/cases",
    "/settings/cases/queues",
    "/settings/oidc",
    "/enrichments/custom/new",
    "/integrations/custom/new",
]


def _settle(page: uilib.UiPage) -> str:
    """Main text once the route stopped loading (spinners, lazy chunks)."""
    return eventually(
        page.main_text,
        timeout=30,
        interval=1,
        desc="the page to render content",
        ok=lambda t: len(t) > 40 and not re.fullmatch(r"(Loading[.…]*\s*)+", t),
    )


@pytest.mark.parametrize("path", ENTERPRISE_ROUTES)
def test_enterprise_route_by_edition(stack: Stack, page: uilib.UiPage, path: str, timeline) -> None:
    page.goto(path)
    text = _settle(page)
    url = page.url
    timeline.step("rendered", url=url, head=text[:160])
    assert not BROKEN.search(text), f"{path}: error page: {text[:300]}"
    assert not page.page_errors(), f"{path}: uncaught page errors: {page.page_errors()}"
    unlicensed = page.count(UNLICENSED) > 0
    if unlicensed:
        assert re.search(r"\S is not licensed", text) and UNLICENSED_COPY in text, (
            f"{path}: license panel without its copy: {text[:300]}"
        )
    gated = PLACEHOLDER in text or SSO_PANEL in text or unlicensed
    if stack.edition == "open":
        if not gated and "Access Denied" in text:
            # Absent from the rail (test_every_rail_link_opens_a_page), but a
            # direct URL tells the ADMIN they lack a permission instead of
            # showing the entitlement panel: the open build never defines the
            # enterprise permission its route guard checks.
            pytest.xfail(
                f"product finding (NAN-4937): open build answers {path} with 'Access Denied … you don't have "
                "permission' for the admin instead of the 'Available in nano paid plans' panel"
            )
        moved = path not in url
        assert gated or moved, f"{path}: open build shows neither the entitlement panel nor a redirect: {text[:300]}"
    else:
        assert PLACEHOLDER not in text, f"{path}: the enterprise build serves the open-build placeholder"
        assert not unlicensed, f"{path}: the enterprise build shows the license panel: {text[:300]}"


def test_every_rail_link_opens_a_page(stack: Stack, page: uilib.UiPage, timeline) -> None:
    page.goto("/")
    _settle(page)
    # Expand collapsible rail groups so nested links are visible.
    for label in ("Ingestion", "Rules", "Cases"):
        btn = {"role": "button", "name": label, "exact": True, "within": {"css": "aside, nav"}}
        if page.count(btn):
            page.click(btn)
    hrefs = sorted(
        {
            h
            for h in (
                page.attr({"css": "aside a[href], nav a[href]", "nth": i}, "href")
                for i in range(page.count({"css": "aside a[href], nav a[href]"}))
            )
            if h and h.startswith("/") and not h.startswith("//")
        }
    )
    timeline.step("rail links", hrefs=hrefs)
    assert len(hrefs) >= 5, hrefs
    bad = []
    for h in hrefs:
        page.goto(h)
        try:
            text = _settle(page)
        except AssertionError:
            bad.append(f"{h}: blank")
            continue
        if BROKEN.search(text):
            bad.append(f"{h}: error page")
        if stack.edition != "open" and PLACEHOLDER in text:
            bad.append(f"{h}: placeholder in the enterprise build")
        if stack.edition != "open" and page.count(UNLICENSED):
            bad.append(f"{h}: license panel in the enterprise build")
    errors = page.page_errors()
    timeline.step("visited", bad=bad, page_errors=errors[:5])
    assert not bad, bad
    assert not errors, errors[:5]
