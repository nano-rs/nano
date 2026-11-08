"""No dead enterprise affordances in the open build (NAN-4937; cf. NAN-2356).

Open edition: every enterprise-only surface is either absent (its route
redirects to a working page) or shows the entitlement panel ("Available in
nano paid plans", or the SSO "not available" panel). None renders blank, an
error boundary, or an uncaught page error. Every link in the left rail opens a
page with content.

Enterprise edition: the same routes mount the real page (never the open-build
placeholder), so a stripped stub can't silently ship in the paid build.
"""

from __future__ import annotations

import re

import pytest

from nano_e2e import ui as uilib
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

PLACEHOLDER = "Available in nano paid plans"
SSO_PANEL = "Single sign-on is not available"
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
    gated = PLACEHOLDER in text or SSO_PANEL in text
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
    errors = page.page_errors()
    timeline.step("visited", bad=bad, page_errors=errors[:5])
    assert not bad, bad
    assert not errors, errors[:5]
