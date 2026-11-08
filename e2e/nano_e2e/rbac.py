"""Throwaway users with a chosen permission set (role -> group -> user), for
UI permission scenarios. Everything is created through the API as the admin
session and deleted afterwards."""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from nano_e2e.client import Http, Journal, expect
from nano_e2e.cleanup import CleanupStack
from nano_e2e.stack import Stack


@dataclass
class LimitedUser:
    email: str
    password: str
    permissions: list[str]


@contextmanager
def limited_user(stack: Stack, label: str, permissions: list[str], journal: Journal) -> Iterator[LimitedUser]:
    from nano_e2e.client import Nano

    jwt = Nano(stack.api_url, stack.search_url, {}, journal).login(stack.admin_email, stack.admin_password)
    admin = Http(stack.api_url, {"Authorization": f"Bearer {jwt}"}, journal)
    tag = f"e2e-{label}-{secrets.token_hex(3)}"
    cleanup = CleanupStack()
    try:
        role = expect(
            admin.post(
                "/api/roles", json={"name": tag, "description": "nano-e2e (NAN-4937)", "permissions": permissions}
            ),
            200,
            201,
        )
        cleanup.register_http("limited-user role", lambda: admin.delete(f"/api/roles/{role['id']}"))
        group = expect(
            admin.post(
                "/api/groups", json={"name": tag, "description": "nano-e2e (NAN-4937)", "role_ids": [role["id"]]}
            ),
            200,
            201,
        )
        cleanup.register_http("limited-user group", lambda: admin.delete(f"/api/groups/{group['id']}"))
        password = "E2e-" + secrets.token_hex(12) + "!"
        user = expect(
            admin.post(
                "/api/users",
                json={
                    "email": f"{tag}@e2e.invalid",
                    "name": tag,
                    "password": password,
                    "group_ids": [group["id"]],
                },
            ),
            200,
            201,
        )
        cleanup.register_http("limited-user account", lambda: admin.delete(f"/api/users/{user['id']}"))
        yield LimitedUser(email=f"{tag}@e2e.invalid", password=password, permissions=permissions)
    finally:
        try:
            cleanup.close()
        finally:
            admin.close()
