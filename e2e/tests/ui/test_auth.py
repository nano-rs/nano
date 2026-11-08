"""First-run setup, login and logout in the browser.

First-run setup runs ONCE per stack, before any scenario needs the admin API
key: `scripts/e2e.sh run ui` brings its stack up with `--defer-admin`, and the
session's `stack` fixture performs setup on /setup in a real browser
(nano_e2e.firstrun). This scenario asserts that outcome against the API.
"""

from __future__ import annotations

import httpx
import pytest

from nano_e2e import firstrun
from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.stack import Stack


def test_first_run_setup_in_browser(stack: Stack, anon_page: uilib.UiPage) -> None:
    res = firstrun.RESULT
    if not res.deferred:
        pytest.skip(
            "this stack was initialized at `up` (no --defer-admin); first-run setup is exercised by "
            "`scripts/e2e.sh run ui` on a stack it brings up itself"
        )
    assert not res.ui_error, f"first-run setup in the browser failed: {res.ui_error}"
    assert res.via == "ui", res
    assert res.status_before and not res.status_before.get("initialized"), res.status_before
    assert res.status_after and res.status_after.get("initialized") is True, res.status_after

    # The setup page is one-shot: it now sends the visitor to /login...
    anon_page.goto("/setup")
    anon_page.wait_url(r"/login")
    # ...and the API refuses a second initialize.
    again = httpx.post(
        f"{stack.api_url}/api/setup/initialize",
        json={"email": "second@e2e.invalid", "name": "x", "password": "Another-Passw0rd!x"},
        timeout=10,
    )
    assert again.status_code in (403, 409), again.text


def test_login_shows_the_admin_then_logout(stack: Stack, nano: Nano, anon_page: uilib.UiPage) -> None:
    uilib.login(anon_page, stack.admin_email, stack.admin_password)
    # The account the UI shows is the one the API says this session is.
    jwt = nano.login(stack.admin_email, stack.admin_password)
    me = api_expect(
        httpx.get(f"{stack.api_url}/api/auth/me", headers={"Authorization": f"Bearer {jwt}"}), 200
    )
    anon_page.wait_text(me["name"])
    # A session survives a reload (refresh cookie -> new access token).
    anon_page.reload()
    anon_page.wait_text(me["name"])
    assert "/login" not in anon_page.url

    # Logout from the user menu: back to /login, and a reload stays out
    # (the refresh cookie no longer works).
    anon_page.click({"text": me["name"], "exact": True})
    anon_page.click({"text": uilib.rx("^(Sign out|Log out)$", "i")})
    anon_page.wait_url(r"/login")
    anon_page.goto("/search")
    anon_page.wait_url(r"/login")


def test_login_wrong_password_stays_out(stack: Stack, anon_page: uilib.UiPage) -> None:
    uilib.login_attempt(anon_page, stack.admin_email, "definitely-not-the-password-e2e")
    # The terminal counts the failed attempt, and the API agrees it was a 401.
    anon_page.wait_text("attempt 1/5")
    assert "/login" in anon_page.url
    r = httpx.post(
        f"{stack.api_url}/api/auth/login",
        json={"email": stack.admin_email, "password": "definitely-not-the-password-e2e"},
        timeout=10,
    )
    assert r.status_code == 401, r.text
