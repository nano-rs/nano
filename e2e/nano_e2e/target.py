"""Run selected scenarios against an EXISTING stack (NAN-5586).

`scripts/e2e.sh run <suite> --target existing` points the harness at a stack it
did not create (a developer's local tenant): no `up`, no `down`, no service
restarts. It is opt-in per scenario: only tests marked
``@pytest.mark.existing_target`` run; every other scenario is skipped, because
the rest of the suite assumes a throwaway stack it may reset.

The target is described by environment variables (the runner sets defaults):

- ``E2E_TARGET=existing``
- ``E2E_TARGET_WEB_URL``    the SPA (default http://localhost:5173)
- ``E2E_TARGET_API_URL``    the API (default http://localhost:3000)
- ``E2E_TARGET_SEARCH_URL`` the search service (default http://localhost:3002)
- ``E2E_TARGET_HEC_URL``    Vector's HEC endpoint (default http://127.0.0.1:8088)
- ``E2E_TARGET_CREDS_FILE`` a 0600 ``key=value`` file outside the repository:
  ``email``, ``password`` and ``api_key`` of the user the scenarios act as (never
  the install's admin), optionally ``lane_token`` (an ingest token for HEC).

The credentials are read in code and placed only in this process's environment
under the names the harness already scrubs (``NANOSIEM_API_KEY``,
``NANO_ADMIN_PASSWORD``, ``E2E_TARGET_HEC_TOKEN``); they are never printed.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_REQUIRED = ("email", "password", "api_key")


def existing() -> bool:
    return os.environ.get("E2E_TARGET", "") == "existing"


def read_creds(path: str | os.PathLike[str]) -> dict[str, str]:
    """Parse the creds file; refuse one other users can read or one inside the repo."""
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(f"E2E_TARGET_CREDS_FILE not found: {p}")
    if p.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(f"E2E_TARGET_CREDS_FILE must be mode 0600: {p}")
    if ROOT in p.parents:
        raise PermissionError("E2E_TARGET_CREDS_FILE must live outside the repository")
    out: dict[str, str] = {}
    for line in p.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    missing = [k for k in _REQUIRED if not out.get(k)]
    if missing:
        raise ValueError(f"E2E_TARGET_CREDS_FILE lacks {', '.join(missing)}")
    short = [k for k in ("password", "api_key", "lane_token") if out.get(k) and len(out[k]) < 8]
    if short:
        # The artifact guard only scrubs values of 8+ characters.
        raise ValueError(f"E2E_TARGET_CREDS_FILE: {', '.join(short)} shorter than 8 characters")
    forbidden = {e.strip().lower() for e in os.environ.get("E2E_TARGET_FORBIDDEN_EMAILS", "admin@nano.local").split(",")}
    if out["email"].strip().lower() in forbidden:
        raise PermissionError("E2E_TARGET_CREDS_FILE names the install's admin: act as a dedicated non-admin user")
    return out


_LOADED = "E2E_TARGET_CREDS_LOADED"


def load_env() -> None:
    """Export the acting user's credentials into this process (idempotent).
    Always from the creds file: a key or admin password already exported in
    the developer's shell must never be the identity the walk acts as."""
    if not existing() or os.environ.get(_LOADED) == "1":
        return
    for stale in ("NANOSIEM_API_KEY", "NANO_ADMIN_EMAIL", "NANO_ADMIN_PASSWORD", "E2E_TARGET_HEC_TOKEN"):
        os.environ.pop(stale, None)
    creds = read_creds(os.environ.get("E2E_TARGET_CREDS_FILE", ""))
    os.environ["NANO_ADMIN_EMAIL"] = creds["email"]
    os.environ["NANO_ADMIN_PASSWORD"] = creds["password"]
    os.environ["NANOSIEM_API_KEY"] = creds["api_key"]
    if creds.get("lane_token"):
        os.environ["E2E_TARGET_HEC_TOKEN"] = creds["lane_token"]
    os.environ[_LOADED] = "1"
