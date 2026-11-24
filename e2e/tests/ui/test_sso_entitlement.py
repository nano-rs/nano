"""SSO visibility by edition (NAN-4930, on clickhouse/dev).

- open edition: Settings > SSO refuses with the v2 license panel ("Single
  sign-on is not licensed": the `sso` capability gate in App.tsx renders
  `LicensedFeatureUnavailable` before `SsoRouteGate`, NAN-5310/NAN-5747), and
  the providers API lists none;
- enterprise: every licensed entitlement includes SSO (the compatibility check
  is tests/enterprise/ui/test_sso_plan.py).

The login page never shows an SSO button when no provider is configured
(none is, on a probe stack), in either edition.
"""

from __future__ import annotations

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.edition import SSO_PANEL, UNLICENSED, UNLICENSED_TESTID, wait_unlicensed
from nano_e2e.stack import Stack


def _providers(nano: Nano) -> list:
    r = nano.api.get("/api/auth/oidc/providers")
    return r.json() if r.status_code == 200 else []


def test_login_shows_no_sso_without_providers(anon_page: uilib.UiPage) -> None:
    anon_page.goto("/login")
    anon_page.wait_for({"css": "form input:not([disabled])"}, timeout_ms=30_000)
    assert anon_page.count({"css": '[aria-label="Single sign-on providers"]'}) == 0
    assert anon_page.count({"role": "button", "name": uilib.rx("^Continue with ")}) == 0


def test_build_capability_gates_sso(stack: Stack, nano: Nano, page: uilib.UiPage, timeline) -> None:
    """Open: the build has no SSO. Enterprise: the build is never the reason."""
    page.goto("/settings/oidc")
    if stack.edition == "open":
        wait_unlicensed(page, "Single sign-on")
        license_link = {"css": f'[data-testid="{UNLICENSED_TESTID}"] a[href="/settings/license"]'}
        assert page.count(license_link) == 0, "open build links to a license it cannot install"
        assert _providers(nano) == []
        timeline.step("open: SSO not in this build")
        return
    page.wait_for({"role": "heading"}, timeout_ms=30_000)
    assert page.count(UNLICENSED) == 0, "enterprise build shows the license panel for SSO"
    assert not page.contains("This deployment does not include"), "enterprise build reports no SSO"
    assert not page.contains(SSO_PANEL), "enterprise build shows the SSO not-available notice"
    timeline.step("enterprise: build includes SSO")
