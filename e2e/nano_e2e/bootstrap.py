"""First-run bootstrap of a fresh e2e stack (called by `scripts/e2e.sh up`).

Creates the local admin through the setup endpoint, logs in, and mints an admin
API key carrying the admin's permissions. Writes NANOSIEM_API_KEY and
NANO_ADMIN_EMAIL to $E2E_OUT (0600). Never prints a secret.

With `up --defer-admin` the runner skips this; the scenarios perform first-run
setup (the UI suite does it in a browser) and then call `mint_admin_key` /
`write_admin_env` themselves (nano_e2e.firstrun).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import httpx


class BootstrapError(RuntimeError):
    pass


def initialize(c: httpx.Client, email: str, password: str) -> bool:
    """Run first-run setup through the API. True when this call initialized it."""
    status = c.get("/api/setup/status").json()
    if status.get("initialized"):
        return False
    r = c.post("/api/setup/initialize", json={"email": email, "name": "e2e admin", "password": password})
    if r.status_code not in (200, 409):
        raise BootstrapError(f"setup/initialize -> {r.status_code}: {r.text[:500]}")
    return r.status_code == 200


def mint_admin_key(c: httpx.Client, email: str, password: str) -> str:
    """Log in as the admin and mint an API key with the admin's permissions."""
    r = c.post("/api/auth/login", json={"email": email, "password": password})
    if r.status_code != 200:
        raise BootstrapError(f"login -> {r.status_code}: {r.text[:500]}")
    login = r.json()
    jwt = login["tokens"]["access_token"]
    perms = login["user"].get("permissions") or []
    r = c.post(
        "/api/api-keys",
        headers={"Authorization": f"Bearer {jwt}"},
        json={
            "name": f"nano-e2e-admin-{int(time.time())}",
            "description": "nano-e2e scenario harness (throwaway stack)",
            "permissions": perms,
        },
    )
    if r.status_code != 201:
        raise BootstrapError(f"api-keys create -> {r.status_code}: {r.text[:500]}")
    return r.json()["key"]


def write_admin_env(out: Path, key: str, email: str) -> None:
    old = os.umask(0o077)
    try:
        out.write_text(f"NANOSIEM_API_KEY={key}\nNANO_ADMIN_EMAIL={email}\n")
    finally:
        os.umask(old)


def main() -> int:
    api = os.environ["E2E_API_URL"].rstrip("/")
    email = os.environ["E2E_ADMIN_EMAIL"]
    password = os.environ["E2E_ADMIN_PASSWORD"]
    out = Path(os.environ["E2E_OUT"])
    c = httpx.Client(base_url=api, timeout=60)
    try:
        initialize(c, email, password)
        key = mint_admin_key(c, email, password)
    except BootstrapError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    write_admin_env(out, key, email)
    return 0


if __name__ == "__main__":
    sys.exit(main())
