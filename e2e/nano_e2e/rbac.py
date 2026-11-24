"""Throwaway users with a chosen permission set (role -> group -> user), for
UI permission scenarios. Everything is created through the API as the admin
session and deleted afterwards."""

from __future__ import annotations

import random
import secrets
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass

import httpx

from nano_e2e.cleanup import CleanupStack
from nano_e2e.client import Http, Journal, expect
from nano_e2e.stack import Stack


def permission_catalog(api: Http) -> set[str]:
    """Every permission this build defines (`GET /api/permissions`): the core
    set plus whatever the enterprise extension registers."""
    body = expect(api.get("/api/permissions"), 200)
    items = body.get("permissions", body) if isinstance(body, dict) else body
    return {str(p["id"] if isinstance(p, dict) else p) for p in items}


def edition_permissions(api: Http, wanted: Sequence[str], edition: str) -> list[str]:
    """`wanted`, as this build can grant it (NAN-5747).

    Persona and role scenarios declare the full enterprise permission set. An
    open build does not define the enterprise permissions (`hunts:view`,
    `soar:run`, ...), and creating a role with one is refused, so on open the
    set is narrowed to the server's catalog. On enterprise every permission
    must exist: a missing one is drift in the product or the test, not
    something to drop quietly."""
    catalog = permission_catalog(api)
    missing = [p for p in wanted if p not in catalog]
    if edition != "open":
        assert not missing, f"permissions not in this {edition} build's /api/permissions: {missing}"
    return [p for p in wanted if p in catalog]


@dataclass
class LimitedUser:
    email: str
    password: str
    permissions: list[str]


def _grant_retry(call: Callable[[], httpx.Response], attempts: int = 6) -> httpx.Response:
    """Run one RBAC write, retrying 409 grant_authority_changed: another
    scenario's role/group/user write raced the grant check, and the product
    asks the caller to retry (NAN-5681, parallel UI runs). Jittered backoff."""
    resp = call()
    for n in range(attempts - 1):
        if resp.status_code != 409 or "grant_authority_changed" not in resp.text:
            return resp
        time.sleep(0.5 * (n + 1) + random.uniform(0, 0.5))  # noqa: S311 - jitter, not crypto
        resp = call()
    return resp


@contextmanager
def limited_user(stack: Stack, label: str, permissions: list[str], journal: Journal) -> Iterator[LimitedUser]:
    from nano_e2e.client import Nano

    jwt = Nano(stack.api_url, stack.search_url, {}, journal).login(stack.admin_email, stack.admin_password)
    admin = Http(stack.api_url, {"Authorization": f"Bearer {jwt}"}, journal)
    tag = f"e2e-{label}-{secrets.token_hex(3)}"
    cleanup = CleanupStack()
    try:
        role_body = {"name": tag, "description": "nano-e2e (NAN-4937)", "permissions": permissions}
        role = expect(_grant_retry(lambda: admin.post("/api/roles", json=role_body)), 200, 201)
        cleanup.register_http(
            "limited-user role", lambda: _grant_retry(lambda: admin.delete(f"/api/roles/{role['id']}"))
        )
        group_body = {"name": tag, "description": "nano-e2e (NAN-4937)", "role_ids": [role["id"]]}
        group = expect(_grant_retry(lambda: admin.post("/api/groups", json=group_body)), 200, 201)
        cleanup.register_http(
            "limited-user group", lambda: _grant_retry(lambda: admin.delete(f"/api/groups/{group['id']}"))
        )
        password = "E2e-" + secrets.token_hex(12) + "!"
        body = {"email": f"{tag}@e2e.invalid", "name": tag, "password": password, "group_ids": [group["id"]]}
        user = expect(_grant_retry(lambda: admin.post("/api/users", json=body)), 200, 201)
        cleanup.register_http(
            "limited-user account", lambda: _grant_retry(lambda: admin.delete(f"/api/users/{user['id']}"))
        )
        yield LimitedUser(email=f"{tag}@e2e.invalid", password=password, permissions=permissions)
    finally:
        try:
            cleanup.close()
        finally:
            admin.close()


@dataclass
class RoleUser:
    email: str
    password: str
    user_id: str
    group_id: str


@contextmanager
def role_user(stack: Stack, label: str, role_ids: list[str], journal: Journal) -> Iterator[RoleUser]:
    """A throwaway user whose only group carries existing role(s) (a built-in
    role, or a custom role the scenario made). Every user is also in the
    "Everyone" system group; group and user are deleted afterwards."""
    from nano_e2e.client import Nano

    jwt = Nano(stack.api_url, stack.search_url, {}, journal).login(stack.admin_email, stack.admin_password)
    admin = Http(stack.api_url, {"Authorization": f"Bearer {jwt}"}, journal)
    tag = f"e2e-{label}-{secrets.token_hex(3)}".lower()
    cleanup = CleanupStack()
    try:
        group_body = {"name": tag, "description": "nano-e2e (NAN-5686)", "role_ids": role_ids}
        group = expect(_grant_retry(lambda: admin.post("/api/groups", json=group_body)), 200, 201)
        cleanup.register_http(
            "role-user group", lambda: _grant_retry(lambda: admin.delete(f"/api/groups/{group['id']}"))
        )
        password = "E2e-" + secrets.token_hex(12) + "!"
        body = {"email": f"{tag}@e2e.invalid", "name": tag, "password": password, "group_ids": [group["id"]]}
        user = expect(_grant_retry(lambda: admin.post("/api/users", json=body)), 200, 201)
        cleanup.register_http(
            "role-user account", lambda: _grant_retry(lambda: admin.delete(f"/api/users/{user['id']}"))
        )
        yield RoleUser(email=body["email"], password=password, user_id=str(user["id"]), group_id=str(group["id"]))
    finally:
        try:
            cleanup.close()
        finally:
            admin.close()


@contextmanager
def role_browser(stack: Stack, driver, artifact_dir, label: str, role_ids: list[str], request=None):
    """`role_user` logged in through the login UI and over the API:
    yields (page, client, user). Ends the browser context and deletes the user.
    Pass the fixture's `request` so a failed test keeps failure.png/page.html."""
    from nano_e2e import ui as uilib
    from nano_e2e.client import Nano

    with role_user(stack, label, role_ids, Journal(artifact_dir / f"{label}-user.jsonl")) as user:
        driver.register_secret(user.password)
        page = uilib.UiPage.open(driver, artifact_dir / f"ui-{label}", name=label)
        failed = True
        client = None
        try:
            uilib.login(page, user.email, user.password)
            jwt = Nano(stack.api_url, stack.search_url, {}, Journal(None)).login(user.email, user.password)
            client = Nano(stack.api_url, stack.search_url, {"Authorization": f"Bearer {jwt}"},
                          Journal(artifact_dir / f"{label}-api.jsonl"))
            yield page, client, user
            rep = getattr(getattr(request, "node", None), "rep_call", None)
            failed = bool(rep is not None and rep.failed)
        finally:
            if client is not None:
                client.close()
            page.finish(failed)


_CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz"


def typeid_uuid(value: str) -> str:
    """The UUID inside a TypeID (`grp_01h…`): some endpoints take the bare UUID."""
    import uuid

    suffix = value.rsplit("_", 1)[-1]
    if len(suffix) == 36:
        return suffix
    assert len(suffix) == 26, f"not a TypeID: {value!r}"
    n = 0
    for ch in suffix:
        n = n * 32 + _CROCKFORD.index(ch)
    return str(uuid.UUID(int=n))
