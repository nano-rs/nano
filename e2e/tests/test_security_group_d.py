"""Security review (2026-11-08), group D: black-box exploit regressions.

Every scenario drives the PUBLIC HTTP API only (plus one read of the users
table for the reset-token case), so the same file runs unchanged against the
pre-fix build (each scenario FAILS there: the exploit succeeds) and the fixed
build (each PASSES). Attackers are low-privilege principals, never the admin.

  1. NAN-5027  a delegated users:edit role rewrites an Admin's password/email
  2. NAN-5014  an admin password reset leaves the old session/tokens alive
  3. NAN-5029  an API key clears its own expiry
  4. NAN-5044  a demoted owner's key keeps a permission the owner lost
  5. NAN-5044  an apikeys:edit holder raises another user's key above its owner
  6. NAN-5048  the reset token read from the database is redeemable
  7. NAN-5027  a users:edit role demotes an Admin through PUT /users/{id}/groups
  8. NAN-5027  a groups:edit role strips the Admin role from an admins group
  (9. NAN-5027, a local password set before an SSO link still signing in
      afterwards, is enterprise-only: tests/enterprise/test_security_group_d_sso.py)

Run: scripts/e2e.sh run security_group_d
"""

from __future__ import annotations

import os
import secrets
import subprocess
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from nano_e2e.client import Http, expect
from nano_e2e.security_world import World, strong_password as _pw
from nano_e2e.security_world import world  # noqa: F401 - the fixture

# Probe permissions: each maps to a GET that requires exactly it. A scenario
# picks one the relevant principal does NOT hold through the Everyone baseline,
# so the result does not depend on how the built-in ReadOnly role is seeded.
PROBES: dict[str, str] = {
    "apikeys:view": "/api/api-keys",
    "groups:view": "/api/groups",
    "users:view": "/api/users",
}


def _second_admin(world: World) -> tuple[dict[str, Any], dict[str, Any]]:
    """A second Admin (fresh group bound to the built-in Admin role), so a
    pre-fix run cannot break the stack admin the other scenarios sign in with.
    Returns (user, group)."""
    admin_role = next(r for r in expect(world.admin.get("/api/roles"), 200)["roles"] if r["name"] == "Admin")
    tag = f"e2e-secd-admin2-{secrets.token_hex(3)}"
    group = expect(
        world.admin.post("/api/groups", json={"name": tag, "description": "group D", "role_ids": [admin_role["id"]]}),
        200,
        201,
    )
    user = expect(
        world.admin.post(
            "/api/users",
            json={"email": f"{tag}@e2e.invalid", "name": tag, "password": _pw(), "group_ids": [group["id"]]},
        ),
        200,
        201,
    )
    world.cleanup.register_http(f"{tag} group", lambda: world.admin.delete(f"/api/groups/{group['id']}"))
    world.cleanup.register_http(f"{tag} user", lambda: world.admin.delete(f"/api/users/{user['id']}"))
    return user, group


def _lacking(held: set[str]) -> str:
    for perm in PROBES:
        if perm not in held:
            return perm
    pytest.fail(f"every probe permission is in the baseline: {sorted(held)}")


# ---------------------------------------------------------------------------
# 1. NAN-5027
# ---------------------------------------------------------------------------


def test_delegated_users_edit_cannot_take_over_an_admin(world: World) -> None:
    # A second Admin (built-in Admin role), so the pre-fix run cannot break the
    # stack admin the other scenarios sign in with.
    admin_role = next(r for r in expect(world.admin.get("/api/roles"), 200)["roles"] if r["name"] == "Admin")
    tag = f"e2e-secd-admin2-{secrets.token_hex(3)}"
    group = expect(
        world.admin.post("/api/groups", json={"name": tag, "description": "group D", "role_ids": [admin_role["id"]]}),
        200,
        201,
    )
    target = expect(
        world.admin.post(
            "/api/users",
            json={"email": f"{tag}@e2e.invalid", "name": tag, "password": _pw(), "group_ids": [group["id"]]},
        ),
        200,
        201,
    )
    world.cleanup.register_http(f"{tag} group", lambda: world.admin.delete(f"/api/groups/{group['id']}"))
    world.cleanup.register_http(f"{tag} user", lambda: world.admin.delete(f"/api/users/{target['id']}"))

    helpdesk = world.principal("helpdesk", ["users:view", "users:edit"])
    hd = world.session(helpdesk)
    try:
        r = hd.put(f"/api/users/{target['id']}", json={"password": _pw()})
        assert r.status_code == 403, f"users:edit set an Admin's password: {r.status_code} {r.text[:300]}"
        r = hd.put(f"/api/users/{target['id']}", json={"email": f"pwned-{secrets.token_hex(3)}@e2e.invalid"})
        assert r.status_code == 403, f"users:edit changed an Admin's email: {r.status_code} {r.text[:300]}"
    finally:
        hd.close()


# ---------------------------------------------------------------------------
# 2. NAN-5014
# ---------------------------------------------------------------------------


def test_admin_password_reset_kills_the_old_session(world: World) -> None:
    victim = world.principal("victim", ["search:view"])
    tokens = world.login(victim)["tokens"]
    # Tokens carry second-resolution iat; make sure the reset lands later.
    time.sleep(1.2)
    expect(world.admin.put(f"/api/users/{victim.id}", json={"password": _pw()}), 200)

    r = world.anon.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401, f"pre-reset refresh token still works: {r.status_code} {r.text[:300]}"
    old = Http(world.stack.api_url, {"Authorization": f"Bearer {tokens['access_token']}"}, world.journal)
    try:
        r = old.get("/api/auth/me")
        assert r.status_code == 401, f"pre-reset access token still works: {r.status_code}"
    finally:
        old.close()
    # The admin who reset it is not signed out.
    expect(world.admin.get("/api/auth/me"), 200)


# ---------------------------------------------------------------------------
# 3. NAN-5029
# ---------------------------------------------------------------------------


def test_api_key_cannot_clear_its_own_expiry(world: World) -> None:
    expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    created = world.key(world.admin, ["apikeys:edit", "apikeys:view"], expires_at=expires, rate_limit=60)
    key = world.key_client(created)
    try:
        r = key.put(f"/api/api-keys/{created['id']}", json={"expires_at": None})
        assert r.status_code == 403, f"key removed its own expiry: {r.status_code} {r.text[:300]}"
        r = key.put(f"/api/api-keys/{created['id']}", json={"rate_limit": None})
        assert r.status_code == 403, f"key removed its own rate limit: {r.status_code} {r.text[:300]}"
    finally:
        key.close()
    row = expect(world.admin.get(f"/api/api-keys/{created['id']}"), 200)
    assert row.get("expires_at") and row.get("rate_limit") == 60, row


# ---------------------------------------------------------------------------
# 4. NAN-5044 (demotion)
# ---------------------------------------------------------------------------


def test_demoted_owners_key_loses_the_removed_permission(world: World) -> None:
    owner = world.principal("owner", ["apikeys:create", *PROBES])
    s = world.session(owner)
    try:
        created = world.key(s, list(PROBES))
    finally:
        s.close()
    key = world.key_client(created)
    try:
        # Demote: drop the owner's privileged group (Everyone stays).
        expect(world.admin.put(f"/api/users/{owner.id}/groups", json={"group_ids": []}), 200)
        probe = _lacking(world.perms_of(owner))
        r = key.get(PROBES[probe])
        assert r.status_code == 403, f"key kept {probe} after its owner lost it: {r.status_code}"
    finally:
        key.close()


# ---------------------------------------------------------------------------
# 5. NAN-5044 (cross-user edit)
# ---------------------------------------------------------------------------


def test_apikeys_edit_cannot_raise_a_key_above_its_owner(world: World) -> None:
    owner = world.principal("keyowner", ["apikeys:create"])
    probe = _lacking(world.perms_of(owner))
    editor = world.principal("keyeditor", ["apikeys:create", "apikeys:edit", "apikeys:view", *PROBES])
    s = world.session(owner)
    try:
        created = world.key(s, ["apikeys:create"])
    finally:
        s.close()
    ed = world.session(editor)
    try:
        r = ed.put(f"/api/api-keys/{created['id']}", json={"permissions": ["apikeys:create", probe]})
        assert r.status_code == 403, f"editor raised the key above its owner ({probe}): {r.status_code} {r.text[:300]}"
    finally:
        ed.close()
    row = expect(world.admin.get(f"/api/api-keys/{created['id']}"), 200)
    assert probe not in row["permissions"], row


# ---------------------------------------------------------------------------
# 6. NAN-5048
# ---------------------------------------------------------------------------


def _stored_reset_token(email: str) -> str:
    """The raw `users.password_reset_token` value, as a database reader sees it.
    `email` is generated by the scenario (no quotes)."""
    assert "'" not in email
    out = subprocess.run(
        ["psql", os.environ["DATABASE_URL"], "-XtA", "-v", "ON_ERROR_STOP=1", "-c",
         f"SELECT coalesce(password_reset_token, '') FROM users WHERE email = '{email}'"],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def test_reset_token_read_from_the_database_is_not_redeemable(world: World) -> None:
    victim = world.principal("resetvictim", ["search:view"])
    expect(world.anon.post("/api/auth/password/reset-request", json={"email": victim.email}), 200)
    stored = _stored_reset_token(victim.email)
    assert stored, "reset-request stored no token"
    r = world.anon.post("/api/auth/password/reset", json={"token": stored, "new_password": _pw()})
    assert r.status_code == 400, f"the database value redeemed a password reset: {r.status_code} {r.text[:300]}"


# ---------------------------------------------------------------------------
# 7. NAN-5027 — PUT /api/users/{id}/groups
# ---------------------------------------------------------------------------


def test_delegated_users_edit_cannot_demote_an_admin_via_groups(world: World) -> None:
    target, admins_group = _second_admin(world)
    helpdesk = world.principal("helpdesk-groups", ["users:view", "users:edit"])
    hd = world.session(helpdesk)
    try:
        r = hd.put(f"/api/users/{target['id']}/groups", json={"group_ids": []})
        assert r.status_code == 403, f"users:edit demoted an Admin: {r.status_code} {r.text[:300]}"
    finally:
        hd.close()
    groups = [g["id"] for g in expect(world.admin.get(f"/api/users/{target['id']}"), 200)["groups"]]
    assert admins_group["id"] in groups, groups


# ---------------------------------------------------------------------------
# 8. NAN-5027 sweep — PUT /api/groups/{id}/roles
# ---------------------------------------------------------------------------


def test_groups_edit_cannot_strip_admin_from_an_admins_group(world: World) -> None:
    _, admins_group = _second_admin(world)
    editor = world.principal("group-editor", ["groups:view", "groups:edit"])
    ed = world.session(editor)
    try:
        r = ed.put(f"/api/groups/{admins_group['id']}/roles", json={"role_ids": []})
        assert r.status_code == 403, f"groups:edit stripped the Admin role: {r.status_code} {r.text[:300]}"
    finally:
        ed.close()
    roles = [r["name"] for r in expect(world.admin.get(f"/api/groups/{admins_group['id']}"), 200)["roles"]]
    assert "Admin" in roles, roles
