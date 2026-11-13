"""Deferred first-run setup (`scripts/e2e.sh up --defer-admin`, which `run ui`
uses on a stack it owns).

The stack comes up with no admin. Before any scenario needs the API key, the
session's `stack` fixture calls `ensure_admin()`:

- With the web UI available (E2E_WEB_DIST), first-run setup is performed IN
  THE BROWSER on /setup (the "first-run setup" UI scenario). Its outcome is
  recorded in `RESULT` and asserted by `tests/ui/test_auth.py`; if the UI flow
  fails, setup falls back to the API so the rest of the session still runs,
  and the UI scenario reports the failure.
- Without it, setup goes through the API (same as `up` would have done).

Then the admin API key is minted, written to the run's admin.env (0600, read
by the runner's secret scrubber) and into stack.env, so a later `run --run
<id>` reuses the stack like any other. On an enterprise stack with
NANO_E2E_C05_LICENSE_FILE set, the offline C05 license is then imported
(NAN-5331), exactly as `up` does when it creates the admin itself.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import httpx

from nano_e2e import bootstrap, c05_license


@dataclass
class FirstRun:
    deferred: bool = False
    via: str = ""  # "ui" | "api" | "" (not deferred: `up` did it)
    ui_error: str = ""
    status_before: dict | None = None
    status_after: dict | None = None


RESULT = FirstRun()


def _rewrite_stack_env(path: Path, key: str) -> None:
    lines = []
    for line in path.read_text().splitlines():
        if line.startswith("NANOSIEM_API_KEY="):
            line = f"NANOSIEM_API_KEY={key}"
        elif line.startswith("E2E_ADMIN_DEFERRED="):
            line = "E2E_ADMIN_DEFERRED=done"
        lines.append(line)
    old = os.umask(0o077)
    try:
        tmp = path.with_suffix(".tmp")
        tmp.write_text("\n".join(lines) + "\n")
        tmp.replace(path)
    finally:
        os.umask(old)


def ensure_admin() -> FirstRun:
    """Idempotent. Sets NANOSIEM_API_KEY in os.environ when it was deferred."""
    if os.environ.get("E2E_ADMIN_DEFERRED") != "1" or os.environ.get("NANOSIEM_API_KEY"):
        return RESULT
    RESULT.deferred = True
    api = os.environ["NANOSIEM_API_URL"].rstrip("/")
    search = os.environ["NANOSIEM_SEARCH_URL"].rstrip("/")
    email = os.environ["NANO_ADMIN_EMAIL"]
    password = os.environ["NANO_ADMIN_PASSWORD"]
    run_dir = Path(os.environ["E2E_RUN_DIR"])
    artifacts = Path(os.environ["E2E_ARTIFACT_DIR"]) / "scenarios" / "first-run-setup"
    c = httpx.Client(base_url=api, timeout=60)
    try:
        before: dict = c.get("/api/setup/status").json()
        RESULT.status_before = before
        dist = os.environ.get("E2E_WEB_DIST", "")
        if not before.get("initialized") and dist:
            try:
                _setup_in_browser(Path(dist), api, search, email, password, artifacts)
                RESULT.via = "ui"
            except Exception as exc:  # noqa: BLE001 - recorded; the UI scenario fails on it
                RESULT.ui_error = f"{type(exc).__name__}: {exc}"
        if not c.get("/api/setup/status").json().get("initialized"):
            bootstrap.initialize(c, email, password, os.environ.get("NANO_SETUP_TOKEN", ""))
            RESULT.via = RESULT.via or "api"
        RESULT.status_after = c.get("/api/setup/status").json()
        key = bootstrap.mint_admin_key(c, email, password)
    finally:
        c.close()
    bootstrap.write_admin_env(run_dir / "admin.env", key, email)
    stack_env = run_dir / "stack.env"
    if stack_env.is_file():
        _rewrite_stack_env(stack_env, key)
    os.environ["NANOSIEM_API_KEY"] = key
    os.environ["E2E_ADMIN_DEFERRED"] = "done"
    # NAN-5331: `up --defer-admin` leaves the C05 import to us (it needs the
    # admin). Same contract as the runner: active license, or fail loudly.
    c05_license.import_from_env(api, key, os.environ.get("E2E_EDITION", ""))
    return RESULT


def _setup_in_browser(dist: Path, api: str, search: str, email: str, password: str, out: Path) -> None:
    from nano_e2e import ui
    from nano_e2e.web import site_for

    out.mkdir(parents=True, exist_ok=True)
    web = site_for(dist, api, search, out / "web-proxy.log").start()
    driver = None
    page = None
    failed = True
    try:
        driver = ui.Driver(web.url, out / "ui-driver.log")
        page = ui.UiPage.open(driver, out / "ui", name="first-run setup")
        ui.first_run_setup(page, "e2e admin", email, password, os.environ.get("NANO_SETUP_TOKEN", ""))
        # The success screen redirects to /login; the admin can log in.
        ui.login(page, email, password)
        failed = False
    finally:
        try:
            if page is not None:
                page.finish(failed)
        finally:
            if driver is not None:
                driver.close()
            web.stop()
