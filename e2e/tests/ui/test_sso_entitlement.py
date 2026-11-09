"""SSO visibility by edition (NAN-4930, on clickhouse/dev).

- open edition: Settings > SSO says the deployment does not include SSO, and
  the providers API lists none;
- enterprise: every licensed entitlement includes SSO (the compatibility check
  is tests/enterprise/ui/test_sso_plan.py).

The login page never shows an SSO button when no provider is configured
(none is, on a probe stack), in either edition.
"""

from __future__ import annotations

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.stack import Stack

UNAVAILABLE = "Single sign-on is not available"


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
        page.wait_text(UNAVAILABLE, timeout_ms=30_000)
        page.wait_text("This deployment does not include", exact=False)
        assert _providers(nano) == []
        timeline.step("open: SSO not in this build")
        return
    page.wait_for({"role": "heading"}, timeout_ms=30_000)
    assert not page.contains("This deployment does not include"), "enterprise build reports no SSO"
    timeline.step("enterprise: build includes SSO")
