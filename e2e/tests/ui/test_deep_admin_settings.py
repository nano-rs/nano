"""Admin and settings workflows in the browser (NAN-5686).

The acting admin is a throwaway user holding the built-in Admin role (never
the install's own admin). Every step asserts what the product persisted, and
the never-real credentials are dummy values:

- users: Invite user (temporary password shown once, and it signs in),
  Disable (sign-in refused), Enable (sign-in works), Delete (404);
- the users drawer hides actions the viewer cannot take, and offers no
  Disable/Delete on the viewer's own account;
- custom roles: Create role with chosen permissions == the role API; a user
  in a group with it gets exactly those (+ Everyone) in /api/auth/me; Delete;
- API keys: created in the UI and used on search; Revoke makes it 401; Delete;
- MFA: TOTP enrollment driven with a code computed from the shown secret; the
  status API says enabled; password-only login now needs the second factor,
  which the computed code passes;
- sessions: a user's session revoked from the Sessions tab can no longer
  refresh;
- retention: raise and restore the event retention (the reduce confirm);
- SIEM Health: Run health check produces a report == the latest-report API;
  the backup card and license page say what their APIs say;
- notifications: a bad URL is refused with a clear validation message; a
  dummy endpoint channel is created, its test delivery fails visibly, delete;
- AI providers (enterprise): tests/enterprise/ui/test_deep_admin_enterprise.py.
"""

from __future__ import annotations

import base64
import json
import hashlib
import hmac
import secrets
import struct
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from nano_e2e import rbac_matrix as rm
from nano_e2e import ui as uilib
from nano_e2e.client import Journal, Nano, expect, time_range
from nano_e2e.rbac import edition_permissions, role_browser, role_user, typeid_uuid
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

ADMIN_ROLE = rm.builtin_roles()["Admin"]
READONLY_ROLE = rm.builtin_roles()["ReadOnly"]
EVERYONE_GROUP = "00000000-0000-0000-0000-000000000001"


def totp(secret_b32: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    """RFC 6238 (SHA1), the parameters nanosiem-core/src/auth/mfa.rs uses."""
    key = base64.b32decode(secret_b32.replace(" ", "").upper() + "=" * (-len(secret_b32.replace(" ", "")) % 8))
    counter = int((at if at is not None else time.time()) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def _fresh_code(secret: str) -> str:
    # Never type a code in the last 3 s of its window (it could expire in flight).
    if 30 - (time.time() % 30) < 3:
        eventually(lambda: 30 - (time.time() % 30), timeout=5, interval=0.5, desc="next TOTP window", ok=lambda r: r > 25)
    return totp(secret)


def _login_status(stack: Stack, email: str, password: str) -> httpx.Response:
    return httpx.post(f"{stack.api_url}/api/auth/login", json={"email": email, "password": password}, timeout=30)


def _users(nano: Nano) -> list[dict[str, Any]]:
    body = expect(nano.api.get("/api/users"), 200)
    return body.get("users", body) if isinstance(body, dict) else body


@pytest.fixture
def admin(stack: Stack, ui: uilib.Driver, artifact_dir, request) -> Iterator[tuple[uilib.UiPage, Nano, Any]]:
    """A throwaway Admin-role user, logged in in the browser and over the API."""
    with role_browser(stack, ui, artifact_dir, "deep-admin", [ADMIN_ROLE], request) as session:
        yield session


def _open_user(page: uilib.UiPage, email: str) -> None:
    page.goto("/settings/access-control?tab=users")
    page.fill(uilib.field({"placeholder": "Search users, email, group…"}, email))
    page.click({"role": "button", "name": uilib.rx(re_escape(email))})
    page.wait_for({"css": 'aside[aria-label="User details"]'})


def re_escape(s: str) -> str:
    import re

    return re.escape(s)


DRAWER = {"css": 'aside[aria-label="User details"]'}


TOASTS = {"css": "[data-sonner-toast], li[data-state=open]"}


def _drawer_action(page: uilib.UiPage, label: str, confirm: str, toast: str) -> None:
    # The previous result toast sits over the drawer's footer buttons: let it go.
    page.wait_for(TOASTS, timeout_ms=30_000, gone=True)
    page.click({"role": "button", "name": label, "exact": True, "within": DRAWER})
    page.click({"role": "button", "name": confirm, "exact": True, "within": {"role": "alertdialog"}})
    page.wait_text(toast, exact=False, timeout_ms=30_000)


def test_users_invite_disable_enable_delete(stack: Stack, nano: Nano, admin, ui: uilib.Driver, timeline) -> None:
    page, client, _ = admin
    email = f"deep-invite-{secrets.token_hex(3)}@e2e.invalid"
    page.goto("/settings/access-control?tab=users")
    page.click({"role": "button", "name": "Invite user", "exact": True})
    page.fill(uilib.field({"placeholder": "person@acme.io"}, email))
    page.click({"role": "button", "name": "Create user", "exact": True})
    page.wait_text("User created", exact=False, timeout_ms=30_000)
    temp = page.texts({"testid": "invite-temp-password"})[0].strip()
    ui.register_secret(temp)
    created = next((u for u in _users(client) if u.get("email") == email), None)
    assert created is not None, "the invited user is not in the users API"
    uid = str(created["id"])
    try:
        assert _login_status(stack, email, temp).status_code == 200, "the temporary password does not sign in"
        page.click({"role": "button", "name": "Close", "exact": True})
        timeline.step("invited", user=uid)

        _open_user(page, email)
        _drawer_action(page, "Disable", "Disable", "User disabled")
        assert expect(client.api.get(f"/api/users/{uid}"), 200)["status"] == "disabled"
        refused = _login_status(stack, email, temp)
        assert refused.status_code in (401, 403), refused.text[:300]
        _drawer_action(page, "Enable", "Enable", "User enabled")
        assert expect(client.api.get(f"/api/users/{uid}"), 200)["status"] == "active"
        assert _login_status(stack, email, temp).status_code == 200
        _drawer_action(page, "Delete", "Delete", "User deleted")
        eventually(lambda: client.api.get(f"/api/users/{uid}").status_code, timeout=15, desc="user gone",
                   ok=lambda s: s == 404)
        timeline.step("disable/enable/delete")
    finally:
        expect(nano.api.delete(f"/api/users/{uid}"), 200, 204, 404)


def test_users_drawer_own_account_offers_no_disable_or_delete(admin, timeline) -> None:
    """An admin's own row offers no Disable/Delete (UserDrawer's `isSelf`)."""
    page, _, me = admin
    _open_user(page, me.email)
    own = [t.strip() for t in page.texts({"role": "button", "within": DRAWER}) if t.strip() in ("Disable", "Delete")]
    page.screenshot("users-drawer-self-actions.png", full_page=False)
    timeline.step("own account drawer", offered=own)
    assert not own, f"own account offers {own}"


def test_users_drawer_view_only_viewer_gets_no_actions(
    stack: Stack, nano: Nano, admin, ui: uilib.Driver, artifact_dir, timeline
) -> None:
    """A users:view-only viewer sees no Edit / Disable / Delete: Edit and
    Delete are no-ops for them and Disable is refused by the API."""
    _, _, me = admin
    role = expect(nano.api.post("/api/roles", json={"name": f"e2e-users-viewer-{secrets.token_hex(3)}",
                                                    "description": "nano-e2e", "permissions": ["users:view"]}), 200, 201)
    try:
        with role_user(stack, "users-viewer", [str(role["id"])], Journal(artifact_dir / "viewer.jsonl")) as viewer:
            ui.register_secret(viewer.password)
            vpage = uilib.UiPage.open(ui, artifact_dir / "ui-viewer", name="users-viewer")
            try:
                uilib.login(vpage, viewer.email, viewer.password)
                _open_user(vpage, me.email)
                offered = [t.strip() for t in vpage.texts({"role": "button", "within": DRAWER})
                           if t.strip() in ("Edit", "Disable", "Delete", "Enable")]
                vpage.screenshot("users-drawer-viewer-actions.png", full_page=False)
                if "Disable" in offered:
                    vpage.click({"role": "button", "name": "Disable", "exact": True, "within": DRAWER})
                    vpage.click({"role": "button", "name": "Disable", "exact": True, "within": {"role": "alertdialog"}})
                    eventually(lambda: vpage.count({"css": "[data-sonner-toast], li[data-state=open]"}), timeout=15,
                               desc="a result toast")
                    vpage.screenshot("users-drawer-viewer-disable-refused.png", full_page=False)
                # Whatever the drawer offered, the target is untouched.
                assert expect(nano.api.get(f"/api/users/{me.user_id}"), 200)["status"] == "active"
                timeline.step("viewer drawer", offered=offered)
                assert not offered, f"users:view-only viewer is offered {offered}"
            finally:
                vpage.finish(False)
    finally:
        expect(nano.api.delete(f"/api/roles/{role['id']}"), 200, 204, 404)


def test_custom_role_create_assign_effective_and_delete(stack: Stack, nano: Nano, admin, ui: uilib.Driver, artifact_dir, timeline) -> None:
    page, client, _ = admin
    name = f"e2e Threat Hunter {secrets.token_hex(2)}"
    # `hunts:view` is enterprise-only: an open build has no checkbox for it.
    chosen = edition_permissions(nano.api, ["hunts:view", "search:execute", "lookup:create"], stack.edition)
    page.goto("/settings/access-control?tab=roles")
    page.click({"css": 'button[title="New role"]'})
    page.fill(uilib.field({"placeholder": "e.g. Threat Hunter"}, name),
              uilib.field({"placeholder": "One-line summary"}, "nano-e2e custom role (NAN-5686)"))
    for perm in chosen:
        page.click({"role": "checkbox", "name": uilib.rx(rf"^{re_escape(perm)}\b")})
    page.click({"role": "button", "name": "Create role", "exact": True})
    page.wait_text("Role created", exact=False, timeout_ms=30_000)
    roles = expect(client.api.get("/api/roles"), 200)["roles"]
    role = next(r for r in roles if r["name"] == name)
    try:
        assert sorted(role["permissions"]) == sorted(chosen), role["permissions"]
        everyone = expect(client.api.get(f"/api/groups/{EVERYONE_GROUP}"), 200)
        ev_ids = {str(x.get("id", x)) if isinstance(x, dict) else str(x) for x in everyone.get("roles", everyone.get("role_ids", []))}
        ev_perms = {p for r in roles if str(r["id"]) in ev_ids for p in r["permissions"]}
        with role_user(stack, "custom-role", [str(role["id"])], Journal(artifact_dir / "custom.jsonl")) as u:
            jwt = Nano(stack.api_url, stack.search_url, {}, Journal(None)).login(u.email, u.password)
            me = httpx.get(f"{stack.api_url}/api/auth/me", headers={"Authorization": f"Bearer {jwt}"}, timeout=30).json()
            assert set(me["permissions"]) == set(chosen) | ev_perms, sorted(set(me["permissions"]) ^ (set(chosen) | ev_perms))
        timeline.step("custom role effective", perms=sorted(chosen))
        page.goto("/settings/access-control?tab=roles")
        page.fill(uilib.field({"placeholder": "Filter roles…"}, name))
        page.click({"text": name, "exact": True})
        page.click({"role": "button", "name": "Delete role", "exact": True})
        page.click({"role": "button", "name": "Delete", "exact": True, "within": {"role": "alertdialog"}})
        eventually(lambda: client.api.get(f"/api/roles/{role['id']}").status_code, timeout=15, desc="role deleted",
                   ok=lambda s: s == 404)
    finally:
        expect(nano.api.delete(f"/api/roles/{role['id']}"), 200, 204, 404)


def test_api_key_create_use_revoke_delete(stack: Stack, nano: Nano, admin, ui: uilib.Driver, timeline) -> None:
    page, client, _ = admin
    name = f"e2e-deep-key-{secrets.token_hex(3)}"
    page.goto("/settings/access-control?tab=api-keys")
    page.click({"css": 'button[title="New API key"]'})
    page.fill(uilib.field({"placeholder": "e.g. ci-deploy-robot"}, name))
    page.click({"role": "button", "name": uilib.rx(r"^Custom")})
    page.fill(uilib.field({"placeholder": "Filter scopes…"}, "search:"))
    page.click({"role": "checkbox", "name": uilib.rx(r"^search:view\b")})
    page.click({"role": "checkbox", "name": uilib.rx(r"^search:execute\b")})
    page.click({"role": "button", "name": "Create key", "exact": True})
    # The reveal-once card, by test id (its copy changes with the glossary).
    page.wait_for({"testid": "api-key-reveal-card"})
    key = page.texts({"testid": "api-key-reveal"})[0].strip()
    ui.register_secret(key)
    keys = expect(client.api.get("/api/api-keys"), 200)
    items = keys.get("api_keys", keys.get("keys", keys)) if isinstance(keys, dict) else keys
    row = next(k for k in items if k.get("name") == name)
    try:
        assert sorted(row.get("permissions") or []) == ["search:execute", "search:view"], row
        search = httpx.post(f"{stack.search_url}/api/search", headers={"X-API-Key": key}, timeout=30, json={
            "query": "*", "limit": 1, "skip_histogram": True, "skip_field_stats": True, "use_cache": False,
            "time_range": time_range(15)})
        assert search.status_code == 200, search.text[:300]
        denied = httpx.get(f"{stack.api_url}/api/users", headers={"X-API-Key": key}, timeout=30)
        assert denied.status_code == 403, denied.status_code
        page.click({"role": "button", "name": uilib.rx("I've stored it")})
        page.click({"css": f'[data-testid="api-key-row"][data-key-id="{row["id"]}"]'})
        page.click({"role": "button", "name": "Revoke", "exact": True})
        page.click({"role": "button", "name": "Revoke", "exact": True, "within": {"role": "alertdialog"}})
        page.wait_text("Key revoked", exact=False, timeout_ms=30_000)
        eventually(lambda: httpx.get(f"{stack.api_url}/api/auth/me", headers={"X-API-Key": key}, timeout=30).status_code,
                   timeout=30, desc="revoked key refused", ok=lambda s: s == 401)
        page.click({"role": "button", "name": "Delete key", "exact": True})
        page.click({"role": "button", "name": "Delete", "exact": True, "within": {"role": "alertdialog"}})
        page.wait_text("Key deleted", exact=False, timeout_ms=30_000)
        assert client.api.get(f"/api/api-keys/{row['id']}").status_code == 404
        timeline.step("api key lifecycle")
    finally:
        # A session deletes keys (an API key may only manage itself).
        expect(client.api.delete(f"/api/api-keys/{row['id']}"), 200, 204, 404)


def test_mfa_totp_enrollment_and_second_factor(stack: Stack, ui: uilib.Driver, artifact_dir, timeline) -> None:
    with role_user(stack, "deep-mfa", [READONLY_ROLE], Journal(artifact_dir / "mfa-user.jsonl")) as user:
        ui.register_secret(user.password)
        page = uilib.UiPage.open(ui, artifact_dir / "ui-mfa", name="mfa")
        failed = True
        try:
            uilib.login(page, user.email, user.password)
            page.goto("/settings/user")
            page.click({"role": "button", "name": "Enable two-factor authentication", "exact": True})
            page.wait_for({"css": 'img[alt="TOTP QR Code"]'}, timeout_ms=30_000)
            page.click({"role": "button", "name": uilib.rx("Enter key manually")})
            secret = page.texts({"testid": "mfa-secret"})[0].strip()
            ui.register_secret(secret)
            page.click({"role": "button", "name": "Continue", "exact": True})
            page.fill(uilib.field({"placeholder": "000000"}, _fresh_code(secret)))
            if page.count({"role": "button", "name": "Verify", "exact": True}):
                try:
                    page.click({"role": "button", "name": "Verify", "exact": True}, timeout_ms=3_000)
                except uilib.UiError:
                    pass  # auto-submitted at 6 digits
            page.wait_text(uilib.rx("backup codes"), exact=False, timeout_ms=30_000)
            page.click({"text": uilib.rx("^I have saved these backup codes")})
            page.click({"role": "button", "name": "Done", "exact": True})
            # NAN-5827: assert the durable state, not the "MFA enabled" toast.
            # The toast lives 4 s and the per-op layout check (NAN-5762) can
            # outlast it before this wait starts. A reload proves the server,
            # not just local state, reports MFA on.
            disable = {"role": "button", "name": "Disable MFA", "exact": True}
            page.wait_for(disable, timeout_ms=30_000)
            page.reload()
            page.wait_for(disable, timeout_ms=30_000)
            enable = {"role": "button", "name": "Enable two-factor authentication", "exact": True}
            assert not page.count(enable)
            status = page.session_fetch("GET", "/api/auth/mfa/status")
            assert status["json"]["mfa_enabled"] is True, status
            timeline.step("mfa enrolled")

            first = _login_status(stack, user.email, user.password)
            body = first.json()
            token = body.get("challenge_token") or (body.get("mfa") or {}).get("challenge_token")
            assert first.status_code == 200 and token and not (body.get("tokens") or {}).get("access_token"), \
                f"password-only login after MFA enrollment: {first.status_code} {sorted(body)}"
            ui.register_secret(token)
            bad = httpx.post(f"{stack.api_url}/api/auth/mfa/challenge", json={"challenge_token": token, "code": "000000"
                             if totp(secret) != "000000" else "111111"}, timeout=30)
            assert bad.status_code in (400, 401, 403), bad.status_code
            ok = httpx.post(f"{stack.api_url}/api/auth/mfa/challenge",
                            json={"challenge_token": token, "code": _fresh_code(secret)}, timeout=30)
            assert ok.status_code == 200 and ok.json().get("tokens", {}).get("access_token"), ok.status_code
            timeline.step("second factor enforced")
            failed = False
        finally:
            page.finish(failed)


def test_session_revoked_from_sessions_tab(stack: Stack, admin, artifact_dir, timeline) -> None:
    page, client, _ = admin
    with role_user(stack, "deep-session", [READONLY_ROLE], Journal(artifact_dir / "session-user.jsonl")) as user:
        login = httpx.post(f"{stack.api_url}/api/auth/login", json={"email": user.email, "password": user.password},
                           timeout=30)
        assert login.status_code == 200
        refresh = login.json()["tokens"].get("refresh_token")
        sessions = expect(client.api.get("/api/sessions"), 200)
        rows = sessions.get("sessions", sessions) if isinstance(sessions, dict) else sessions
        mine = [s for s in rows if str(s.get("user_id")) in (user.user_id, user.user_id.split("_")[-1])]
        assert mine, "the user's session is not listed"
        sid = str(mine[0]["id"])
        page.goto("/settings/access-control?tab=sessions")
        page.click({"role": "button", "name": "Revoke", "exact": True,
                    "within": {"css": f'[data-testid="session-row"][data-session-id="{sid}"]'}})
        page.click({"role": "button", "name": "Revoke", "exact": True, "within": {"role": "alertdialog"}})
        page.wait_text("Session revoked", exact=False, timeout_ms=30_000)
        eventually(lambda: client.api.get(f"/api/sessions/{sid}").status_code, timeout=15, desc="session gone",
                   ok=lambda s: s == 404)
        if refresh:
            r = httpx.post(f"{stack.api_url}/api/auth/refresh", json={"refresh_token": refresh}, timeout=30)
            assert r.status_code in (400, 401, 403), f"a revoked session still refreshes: {r.status_code}"
        timeline.step("session revoked", session=sid)


def _ttl(client: Nano) -> int:
    return int(expect(client.api.get("/api/settings/storage/overview"), 200)["clickhouse"]["ttl_days"])


def test_retention_raise_and_restore(stack: Stack, nano: Nano, admin, timeline) -> None:
    page, client, _ = admin
    original = _ttl(client)
    page.goto("/settings/storage?tab=clickhouse")
    page.wait_for({"testid": "retention-current"}, timeout_ms=30_000)
    shown = page.texts({"testid": "retention-current"})[0]
    assert int("".join(ch for ch in shown if ch.isdigit()) or 0) == original, (shown, original)
    box = {"role": "textbox", "name": "Retention in days", "exact": True}
    if not page.count(box):
        box = {"css": 'input[aria-label="Retention in days"]'}
    try:
        page.fill(uilib.field(box, "0"))
        save = {"role": "button", "name": "Save", "exact": True}
        assert page.attr(save, "disabled") is not None, "Save is offered for a 0-day retention"
        page.fill(uilib.field(box, str(original + 1)))
        page.click(save)
        page.wait_text("Retention updated", exact=False, timeout_ms=60_000)
        eventually(lambda: _ttl(client), timeout=30, desc="retention persisted", ok=lambda t: t == original + 1)
        timeline.step("retention raised", to=original + 1)
        # Reducing goes through the confirm dialog.
        page.fill(uilib.field(box, str(original)))
        page.click(save)
        page.click({"role": "button", "name": "Reduce retention", "exact": True})
        page.wait_text("Retention updated", exact=False, timeout_ms=60_000)
        eventually(lambda: _ttl(client), timeout=30, desc="retention reduced back", ok=lambda t: t == original)
        timeline.step("retention reduced", to=original)
    finally:
        # Whatever happened in the browser, the global setting goes back (API).
        if _ttl(nano) != original:
            expect(client.api.put("/api/settings/storage/clickhouse/retention",
                                  json={"retention_days": original}), 200, 204)
        assert _ttl(nano) == original, "retention was not restored"


def test_health_backup_and_license_pages_match_their_apis(stack: Stack, nano: Nano, page: uilib.UiPage, timeline) -> None:
    """As the harness's own admin (a health report pins its trigger user;
    deleting that user is NAN-5721, covered on its own below)."""
    client = nano
    page.goto("/platform/health")
    page.click({"role": "button", "name": uilib.rx(r"^Run (first )?health check$")})
    report = eventually(lambda: client.api.get("/api/siem-health/reports/latest"), timeout=180, interval=3,
                        desc="a health report", ok=lambda r: r.status_code == 200).json()
    status = str(report.get("status") or report.get("overall_status") or "")
    score = report.get("overall_score")
    page.wait_text(uilib.rx(r"^Pipeline is"), exact=False, timeout_ms=60_000)
    headline = " ".join(page.texts({"role": "heading", "name": uilib.rx(r"^Pipeline is")}))
    # The "Score" label is a glossary <Term> (its own element), so read the
    # number by test id and compare it with the API's overall_score.
    shown = eventually(lambda: page.texts({"testid": "siem-health-overall-score"}), timeout=30, interval=0.5,
                       desc="the shown health score", ok=lambda v: len(v) == 1 and v[0].strip() == str(score))
    assert shown[0].strip() == str(score), (shown, score)
    timeline.step("siem health", status=status, score=score, headline=headline)

    backup = client.api.get("/api/system/backup-status")
    page.goto("/settings")
    page.wait_text("Last backup", exact=False, timeout_ms=30_000)
    if backup.status_code != 200:
        page.wait_text("Backup status unavailable", exact=False)
    timeline.step("backup card", api=backup.status_code)

    if stack.edition == "enterprise":
        lic = expect(client.api.get("/api/license"), 200)
        page.goto("/settings/license")
        page.wait_text("Offline License", exact=True, timeout_ms=30_000)
        page.wait_text(str(lic.get("runtime_state") or lic["state"]), exact=True, timeout_ms=30_000)
        upd = client.api.get("/api/license/update")
        timeline.step("license", state=lic.get("state"), update=upd.status_code)


def test_notification_channel_validation_and_test_delivery(stack: Stack, admin, timeline) -> None:
    page, client, _ = admin
    name = f"e2e-deep-hook-{secrets.token_hex(3)}"
    page.goto("/settings/notifications")
    page.click({"testid": "add-channel"})
    page.click({"role": "button", "name": uilib.rx(r"^Generic")})
    page.fill(uilib.field({"placeholder": "e.g. SOC on-call"}, name),
              uilib.field({"placeholder": "https://example.com/hook"}, "not a url"))
    page.click({"role": "button", "name": "Create channel", "exact": True})
    page.wait_text(uilib.rx("URL must"), exact=False, timeout_ms=15_000)
    assert not any(h.get("name") == name for h in _hooks(client))
    page.fill(uilib.field({"placeholder": "https://example.com/hook"}, "https://example.com/nano-e2e-hook"))
    page.click({"role": "button", "name": "Create channel", "exact": True})
    hook = eventually(lambda: next((h for h in _hooks(client) if h.get("name") == name), None), timeout=30,
                      desc="channel persisted")
    try:
        assert "example.com" in json.dumps(hook), hook
        page.wait_text(name, exact=False, timeout_ms=30_000)
        row = {"role": "row", "has": name}
        page.click({"css": 'button[title="Send test"]', "within": row})
        page.wait_text(uilib.rx("Test (failed|delivered)"), exact=False, timeout_ms=60_000)
        assert page.count({"text": uilib.rx("^Test failed")}) >= 1, "a dummy endpoint reported delivered"
        page.click({"css": 'button[title="Delete"]', "within": row})
        page.click({"role": "button", "name": "Delete", "exact": True, "within": {"role": "alertdialog"}})
        eventually(lambda: [h for h in _hooks(client) if h.get("name") == name], timeout=30, desc="deleted",
                   ok=lambda x: not x)
        timeline.step("notification channel", id=hook["id"])
    finally:
        expect(client.api.delete(f"/api/settings/webhooks/{hook['id']}"), 200, 204, 404)


def _hooks(client: Nano) -> list[dict[str, Any]]:
    body = expect(client.api.get("/api/settings/webhooks"), 200)
    return body.get("webhooks", body) if isinstance(body, dict) else body


def test_delete_user_who_ran_a_health_check(stack: Stack, nano: Nano, artifact_dir, timeline) -> None:
    """A user who triggered a SIEM health report can still be deleted."""
    from nano_e2e.personas import _psql_json

    role = expect(nano.api.post("/api/roles", json={"name": f"e2e-health-runner-{secrets.token_hex(3)}",
                                                    "description": "nano-e2e", "permissions": ["settings:system"]}),
                  200, 201)
    try:
        with role_user(stack, "health-runner", [str(role["id"])], Journal(artifact_dir / "runner.jsonl")) as user:
            uid = typeid_uuid(user.user_id)
            try:
                jwt = Nano(stack.api_url, stack.search_url, {}, Journal(None)).login(user.email, user.password)
                trig = httpx.post(f"{stack.api_url}/api/siem-health/reports/trigger",
                                  headers={"Authorization": f"Bearer {jwt}"}, json={}, timeout=60)
                assert trig.status_code in (200, 201, 202), trig.text[:300]
                eventually(lambda: _psql_json(f"SELECT count(*) FROM siem_health_reports WHERE triggered_by = '{uid}'"),
                           timeout=120, interval=3, desc="the report names its trigger user", ok=lambda n: (n or 0) >= 1)
                report_ids = _psql_json(f"SELECT coalesce(json_agg(id), '[]'::json) FROM siem_health_reports "
                                        f"WHERE triggered_by = '{uid}'") or []
                assert report_ids, "the trigger user's health report was not found"
                resp = nano.api.delete(f"/api/users/{user.user_id}")
                timeline.step("delete health-runner", status=resp.status_code)
                assert resp.status_code in (200, 204), \
                    f"deleting a user who triggered a SIEM health report answers {resp.status_code}"
                # NAN-5721: the report survives its author's deletion, unattributed.
                ids = ",".join(f"'{i}'" for i in report_ids)
                survivors = _psql_json(f"SELECT count(*) FROM siem_health_reports WHERE id IN ({ids}) "
                                       "AND triggered_by IS NULL")
                assert survivors == len(report_ids), \
                    f"{len(report_ids)} report(s) by the deleted user, {survivors} survived unattributed"
            finally:
                # Let the throwaway user's own cleanup succeed on this stack.
                _psql_json(f"WITH u AS (UPDATE siem_health_reports SET triggered_by = NULL WHERE triggered_by = '{uid}' "
                           "RETURNING 1) SELECT count(*) FROM u")
    finally:
        expect(nano.api.delete(f"/api/roles/{role['id']}"), 200, 204, 404)
