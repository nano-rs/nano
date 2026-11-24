"""Shared world for the security group D black-box scenarios (NAN-5027
regressions): an admin session plus throwaway principals, all removed
afterwards. Used by tests/test_security_group_d.py and, for the
enterprise-only SSO scenario, tests/enterprise/test_security_group_d_sso.py
(the open-core mirror strips tests/enterprise/, NAN-5869)."""

from __future__ import annotations

import os
import secrets
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from nano_e2e.cleanup import CleanupStack
from nano_e2e.client import Http, Journal, Nano, expect
from nano_e2e.stack import Stack


def strong_password() -> str:
    return "Sd-" + secrets.token_hex(10) + "!aA1"


@dataclass
class Principal:
    id: str
    email: str
    password: str
    group_id: str


class World:
    """Admin session + throwaway principals, all removed afterwards."""

    def __init__(self, stack: Stack, journal: Journal):
        self.stack = stack
        self.journal = journal
        self.cleanup = CleanupStack()
        jwt = Nano(stack.api_url, stack.search_url, {}, journal).login(stack.admin_email, stack.admin_password)
        self.admin = Http(stack.api_url, {"Authorization": f"Bearer {jwt}"}, journal)
        self.anon = Http(stack.api_url, {}, journal)
        self.admin_id = expect(self.admin.get("/api/auth/me"), 200)["id"]

    def close(self) -> None:
        try:
            self.cleanup.close()
        finally:
            self.admin.close()
            self.anon.close()

    def principal(self, label: str, permissions: list[str]) -> Principal:
        tag = f"e2e-secd-{label}-{secrets.token_hex(3)}"
        role = expect(
            self.admin.post("/api/roles", json={"name": tag, "description": "group D", "permissions": permissions}),
            200,
            201,
        )
        group = expect(
            self.admin.post("/api/groups", json={"name": tag, "description": "group D", "role_ids": [role["id"]]}),
            200,
            201,
        )
        password = strong_password()
        user = expect(
            self.admin.post(
                "/api/users",
                json={"email": f"{tag}@e2e.invalid", "name": tag, "password": password, "group_ids": [group["id"]]},
            ),
            200,
            201,
        )
        # LIFO: user, then group, then role.
        self.cleanup.register_http(f"{tag} role", lambda: self.admin.delete(f"/api/roles/{role['id']}"))
        self.cleanup.register_http(f"{tag} group", lambda: self.admin.delete(f"/api/groups/{group['id']}"))
        self.cleanup.register_http(f"{tag} user", lambda: self.admin.delete(f"/api/users/{user['id']}"))
        return Principal(id=user["id"], email=f"{tag}@e2e.invalid", password=password, group_id=group["id"])

    def login(self, p: Principal) -> dict[str, Any]:
        return expect(self.anon.post("/api/auth/login", json={"email": p.email, "password": p.password}), 200)

    def session(self, p: Principal) -> Http:
        tok = self.login(p)["tokens"]["access_token"]
        return Http(self.stack.api_url, {"Authorization": f"Bearer {tok}"}, self.journal)

    def key(self, owner: Http, permissions: list[str], **extra: Any) -> dict[str, Any]:
        body = {"name": f"e2e-secd-{secrets.token_hex(3)}", "permissions": permissions, **extra}
        created = expect(owner.post("/api/api-keys", json=body), 200, 201)
        self.cleanup.register_http("group D key", lambda: self.admin.delete(f"/api/api-keys/{created['id']}"))
        return created

    def key_client(self, created: dict[str, Any]) -> Http:
        return Http(self.stack.api_url, {"X-API-Key": created["key"]}, self.journal)

    def perms_of(self, p: Principal) -> set[str]:
        s = self.session(p)
        try:
            return set(expect(s.get("/api/auth/me"), 200).get("permissions", []))
        finally:
            s.close()


@pytest.fixture
def world(stack: Stack, artifact_dir: Path) -> Iterator[World]:
    w = World(stack, Journal(artifact_dir / "api.jsonl"))
    try:
        yield w
    finally:
        w.close()


def psql(sql: str) -> str:
    """Run one statement against the stack's Postgres (DATABASE_URL)."""
    out = subprocess.run(
        ["psql", os.environ["DATABASE_URL"], "-XtA", "-v", "ON_ERROR_STOP=1", "-c", sql],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()
