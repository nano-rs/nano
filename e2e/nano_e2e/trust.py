"""NAN-5771: the ONE check that a running stack's compiled content trust is
what the run recorded (E2E_TRUST). `scripts/e2e.sh` (after its own admin
bootstrap, on reuse, after `svc restart api`) and `nano_e2e.firstrun` (after
a deferred first-run setup mints the admin key) both call this module, so the
two paths cannot drift.

It fails closed. The only tolerated failure is HTTP 404 on a published image
(`--app image:<tag>`), which means the image predates the endpoint. A 500, a
401/403, a network error, a non-JSON or non-object body, a body without
`trust`, or a mismatch always fails. Stdlib only: the runner calls it with the
system python3 (`python3 -m nano_e2e.trust`), like `nano_e2e.c05_license`.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PATH = "/api/content/channels"
LABELS = ("production", "production+acceptance")


class TrustMismatch(RuntimeError):
    """The stack's trust is unverified or not what the run recorded."""


def _probe(api: str, key: str, timeout: float) -> tuple[int | None, object, str]:
    """(HTTP status or None on a network error, parsed body or None, error text)."""
    req = urllib.request.Request(f"{api.rstrip('/')}{PATH}", headers={"X-API-Key": key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - loopback stack URL
            raw = r.read()
            status = r.status
    except urllib.error.HTTPError as exc:
        return exc.code, None, f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError) as exc:
        return None, None, f"{type(exc).__name__}"
    try:
        return status, json.loads(raw), ""
    except ValueError:
        return status, None, "body is not JSON"


def check(api: str, key: str, want: str, app_mode: str, *, attempts: int = 5, delay: float = 2.0,
          timeout: float = 15.0) -> str:
    """Returns the verified label, or "" when a published image predates the
    endpoint (404). Raises TrustMismatch otherwise."""
    if not want:
        raise TrustMismatch("the run records no E2E_TRUST (created before NAN-5771): use --fresh")
    if want not in LABELS:
        raise TrustMismatch(f"the run records an unknown E2E_TRUST {want!r}")
    if not key:
        raise TrustMismatch("no admin API key to verify trust with")
    problem = ""
    for attempt in range(1, max(1, attempts) + 1):
        status, body, err = _probe(api, key, timeout)
        if status == 404 and app_mode == "image":
            return ""
        if status == 200 and isinstance(body, dict):
            got = body.get("trust")
            if isinstance(got, str) and got:
                if got != want:
                    raise TrustMismatch(f"stack trust mismatch: API reports {got!r}, the run recorded {want!r}")
                return got
            problem = "the reply has no trust field"
        elif status == 200:
            problem = err or "the reply is not a JSON object"
        else:
            problem = err or f"HTTP {status}"
        if status in (401, 403):
            break  # auth is not transient
        if attempt < attempts:
            time.sleep(delay)
    raise TrustMismatch(f"trust not verified: GET {PATH} failed ({problem}); expected {want}")


def _read_key(admin_env: Path) -> str:
    try:
        lines = admin_env.read_text().splitlines()
    except OSError:
        return ""
    for line in lines:
        if line.startswith("NANOSIEM_API_KEY="):
            return line.split("=", 1)[1]
    return ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python3 -m nano_e2e.trust")
    p.add_argument("--api", required=True)
    # The key is read from the 0600 admin.env, never passed on argv (ps).
    p.add_argument("--admin-env", required=True, type=Path)
    p.add_argument("--want", default="")
    p.add_argument("--app-mode", default="native")
    p.add_argument("--attempts", type=int, default=5)
    a = p.parse_args(argv)
    try:
        got = check(a.api, _read_key(a.admin_env), a.want, a.app_mode, attempts=a.attempts)
    except TrustMismatch as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if not got:
        print(f"published image predates {PATH} (404): trust not verified via the API; expected {a.want}")
        return 2
    print(got)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
