"""NAN-5483: a signed-out load of /login makes no failing request.

The SPA used to probe `POST /api/auth/refresh` on every page load; for a
visitor with no refresh cookie that is a 400 `missing_token`, which the
browser logs in red. The API now sets a JS-readable `nano_session` presence
cookie alongside the HttpOnly refresh cookie and the SPA only probes when it
is there. This scenario loads the login page signed out, then signs in,
reloads (the session must survive: the probe runs and succeeds), signs out and
reloads again (no probe, still no failing request).

Every failing request and console error seen is written to
`signed_out_events.json` in the scenario's artifact dir.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.stack import Stack

REFRESH = "/api/auth/refresh"


def _settle(page: uilib.UiPage) -> None:
    page.wait_for({"css": "form input:not([disabled])"})
    # The silent probe and the login page's public fetches run on mount.
    time.sleep(3)


def _events(page: uilib.UiPage, since: int) -> dict[str, Any]:
    return page.op("events_since", since=since)


def test_signed_out_login_load_has_no_failing_requests(
    stack: Stack, nano: Nano, anon_page: uilib.UiPage, artifact_dir: Path
) -> None:
    t0 = anon_page.now_ms()
    anon_page.goto("/login")
    _settle(anon_page)
    first = _events(anon_page, t0)
    probes = anon_page.requests_containing(REFRESH, since_ms=t0)
    api_requests = anon_page.requests_containing("/api/", since_ms=t0)

    # Sign in, then reload: the refresh cookie (and its presence cookie)
    # restores the session through the probe.
    uilib.login(anon_page, stack.admin_email, stack.admin_password)
    t1 = anon_page.now_ms()
    anon_page.reload()
    anon_page.wait_for({"css": "form input"}, gone=True)
    time.sleep(2)
    assert "/login" not in anon_page.url
    signed_in_probes = anon_page.requests_containing(REFRESH, since_ms=t1)
    signed_in = _events(anon_page, t1)

    # That reload ROTATED the refresh cookie; the presence cookie must have
    # been re-issued with it, or this second reload would skip the probe and
    # drop the user on /login.
    t1b = anon_page.now_ms()
    anon_page.reload()
    anon_page.wait_for({"css": "form input"}, gone=True)
    time.sleep(2)
    assert "/login" not in anon_page.url, "session lost after a refresh rotation"
    assert anon_page.requests_containing(REFRESH, since_ms=t1b), "no probe after rotation"

    # Sign out from the user menu (the API clears both cookies), reload:
    # back on /login with no probe and no failing request.
    jwt = nano.login(stack.admin_email, stack.admin_password)
    me = api_expect(
        httpx.get(f"{stack.api_url}/api/auth/me", headers={"Authorization": f"Bearer {jwt}"}), 200
    )
    anon_page.click({"text": me["name"], "exact": True})
    anon_page.click({"text": uilib.rx("^(Sign out|Log out)$", "i")})
    anon_page.wait_url(r"/login")
    t2 = anon_page.now_ms()
    anon_page.reload()
    _settle(anon_page)
    after_logout = _events(anon_page, t2)
    after_logout_probes = anon_page.requests_containing(REFRESH, since_ms=t2)

    (artifact_dir / "signed_out_events.json").write_text(
        json.dumps(
            {
                "signed_out_load": first,
                "signed_out_api_requests": api_requests,
                "signed_out_refresh_probes": probes,
                "signed_in_reload": signed_in,
                "signed_in_refresh_probes": signed_in_probes,
                "after_logout_load": after_logout,
                "after_logout_refresh_probes": after_logout_probes,
            },
            indent=2,
        )
    )
    print(json.dumps({"signed_out_load": first, "after_logout_load": after_logout}, indent=2))

    assert probes == [], f"signed-out load still probes {REFRESH}: {probes}"
    bad = [n for n in first["network"] if "/api/" in n["url"]]
    assert bad == [], f"signed-out /login load had failing API requests: {bad}"
    assert signed_in_probes, "a signed-in reload must still restore the session via refresh"
    assert not [n for n in signed_in["network"] if REFRESH in n["url"]], signed_in["network"]
    assert after_logout_probes == [], f"post-logout load still probes {REFRESH}: {after_logout_probes}"
    bad = [n for n in after_logout["network"] if "/api/" in n["url"]]
    assert bad == [], f"post-logout /login load had failing API requests: {bad}"


def _set_cookies(resp: httpx.Response) -> dict[str, str]:
    """name -> full Set-Cookie line, from the raw response headers."""
    out: dict[str, str] = {}
    for line in resp.headers.get_list("set-cookie"):
        out[line.split("=", 1)[0].strip()] = line
    return out


def _value(line: str) -> str:
    return line.split(";", 1)[0].split("=", 1)[1]


def _max_age(line: str) -> int:
    for part in line.split(";"):
        k, _, v = part.strip().partition("=")
        if k.lower() == "max-age":
            return int(v)
    raise AssertionError(f"no Max-Age in {line!r}")


def test_server_pairs_presence_cookie_with_refresh_cookie(stack: Stack) -> None:
    """The server, not just the browser, keeps `nano_session` in lockstep with
    the refresh cookie: issued on login, re-issued on rotation, cleared on
    logout (read from each response's Set-Cookie headers)."""
    # Stateless calls (no cookie jar): every Cookie header is the one we send.
    def post(path: str, **kw: Any) -> httpx.Response:
        return httpx.post(f"{stack.api_url}{path}", timeout=15, **kw)

    login = post(
        "/api/auth/login", json={"email": stack.admin_email, "password": stack.admin_password}
    )
    assert login.status_code == 200, login.text
    sc = _set_cookies(login)
    assert "refresh_token" in sc and "nano_session" in sc, list(sc)
    assert _value(sc["nano_session"]) == "1"
    assert "httponly" not in sc["nano_session"].lower(), sc["nano_session"]
    assert _max_age(sc["nano_session"]) == _max_age(sc["refresh_token"]) > 0
    refresh_token = _value(sc["refresh_token"])

    # Rotation: a fresh refresh cookie AND a fresh presence cookie.
    rotated = post(
        "/api/auth/refresh", json={}, headers={"Cookie": f"refresh_token={refresh_token}"}
    )
    assert rotated.status_code == 200, rotated.text
    sc = _set_cookies(rotated)
    assert "refresh_token" in sc, f"refresh did not rotate the cookie: {list(sc)}"
    assert _value(sc["refresh_token"]) not in ("", refresh_token)
    assert "nano_session" in sc, f"rotation dropped the presence cookie: {list(sc)}"
    assert _value(sc["nano_session"]) == "1"
    assert _max_age(sc["nano_session"]) == _max_age(sc["refresh_token"]) > 0
    access = rotated.json()["access_token"]
    refresh_token = _value(sc["refresh_token"])

    # Logout: the server clears both.
    out = post(
        "/api/auth/logout",
        json={},
        headers={"Authorization": f"Bearer {access}", "Cookie": f"refresh_token={refresh_token}"},
    )
    assert out.status_code == 204, out.text
    sc = _set_cookies(out)
    for name in ("refresh_token", "nano_session"):
        assert name in sc, f"logout did not clear {name}: {list(sc)}"
        assert _value(sc[name]) == "" and _max_age(sc[name]) == 0, sc[name]
    assert "Path=/;" in sc["nano_session"] or sc["nano_session"].rstrip().endswith("Path=/"), sc["nano_session"]

    # And the 400 contract for an API caller with nothing to refresh stays.
    bare = post("/api/auth/refresh", json={})
    assert bare.status_code == 400, bare.text
