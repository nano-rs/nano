"""Browser fixtures for UI scenarios (NAN-4937), shared by `tests/ui/` and
`tests/enterprise/ui/` (import them into a conftest).

- `web`: the edition build of nanosiem-web (E2E_WEB_DIST, built by
  `scripts/e2e.sh run ui`) served with same-origin routing to api/search.
- `ui`: the puppeteer driver (one Chrome) for the session.
- `page`: a fresh browser context per scenario, logged in through the login
  UI as the stack's admin. `anon_page`: the same, logged out.
- On failure: failure.png, page.html, network.jsonl and console.log in the
  scenario's artifact dir (`.../artifacts/scenarios/<test>/ui/`). The
  `rep_setup` / `rep_call` attributes come from tests/conftest.py's hook.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from nano_e2e import ui as uilib
from nano_e2e.stack import Stack
from nano_e2e.web import EdgeSite, WebServer, site_for


def _failed(request: pytest.FixtureRequest) -> bool:
    for when in ("setup", "call"):
        rep = getattr(request.node, f"rep_{when}", None)
        if rep is not None and rep.failed:
            return True
    return False


class ExistingSite:
    """`--target existing`: the stack's own web server (nothing to start)."""

    def __init__(self, url: str) -> None:
        self.url = url

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None


@pytest.fixture(scope="session")
def web(stack: Stack) -> Iterator[WebServer | EdgeSite | ExistingSite]:
    if stack.target == "existing":
        yield ExistingSite(stack.edge_url)
        return
    dist = os.environ.get("E2E_WEB_DIST", "")
    if not dist:
        pytest.fail(
            "E2E_WEB_DIST is not set: run the UI suite through `scripts/e2e.sh run ui`, which builds "
            "nanosiem-web for the stack's edition",
            pytrace=False,
        )
    # Through the stack's nginx edge (the shipped config) when it has one.
    server = site_for(Path(dist), stack.api_url, stack.search_url, stack.artifact_dir / "web-proxy.log")
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(scope="session")
def ui(web: WebServer | EdgeSite, stack: Stack) -> Iterator[uilib.Driver]:
    driver = uilib.Driver(web.url, stack.artifact_dir / "ui-driver.log")
    try:
        yield driver
    finally:
        driver.close()


@pytest.fixture
def anon_page(ui: uilib.Driver, artifact_dir: Path, request: pytest.FixtureRequest) -> Iterator[uilib.UiPage]:
    page = uilib.UiPage.open(ui, artifact_dir / "ui", name=request.node.nodeid)
    try:
        yield page
    finally:
        page.finish(_failed(request))


@pytest.fixture
def page(
    ui: uilib.Driver, stack: Stack, artifact_dir: Path, request: pytest.FixtureRequest
) -> Iterator[uilib.UiPage]:
    """Logged in through the login UI (per scenario: refresh tokens rotate, so
    contexts never share a session)."""
    page = uilib.UiPage.open(ui, artifact_dir / "ui", name=request.node.nodeid)
    try:
        uilib.login(page, stack.admin_email, stack.admin_password)
    except Exception:
        if stack.target == "existing":
            try:
                page.end_session()  # a login can half-succeed: never leave a session behind
            except Exception:  # noqa: BLE001,S110 - best effort; the failure itself is raised
                pass
        page.finish(True)
        raise
    try:
        yield page
    finally:
        if stack.target == "existing":
            # Someone else's stack: end this context's own session (only it).
            try:
                ended = page.end_session()
                if ended.get("status") not in (200, 204):
                    print(f"WARNING: could not end the walk's own session on the target: {ended}")
            except Exception as exc:  # noqa: BLE001 - best effort; the browser context closes anyway
                print(f"WARNING: could not end the walk's own session on the target: {exc}")
        page.finish(_failed(request))
