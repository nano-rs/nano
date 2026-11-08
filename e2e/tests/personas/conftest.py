"""Persona journeys share canonical UI fixtures, artifacts, and strict cleanup."""

import os

import pytest

from nano_e2e import ui as uilib
from nano_e2e.cleanup import CleanupStack
from nano_e2e.client import expect
from nano_e2e.fixtures_ui import anon_page, page, ui, web  # noqa: F401
from nano_e2e.personas import configure_persona_ai, restore_persona_ai, snapshot_persona_ai
from nano_e2e.waits import eventually


def _switch_soar(driver, stack, nano, out, on: bool) -> None:
    """Use the audited interactive-admin switch; API keys cannot change it."""
    current = bool(expect(nano.api.get("/api/soar/settings"), 200)["soar_enabled"])
    if current == on:
        return
    switch_page = uilib.UiPage.open(driver, out, "persona SOAR switch")
    failed = True
    try:
        uilib.login(switch_page, stack.admin_email, stack.admin_password)
        switch_page.goto("/settings/soar")
        switch_page.fill(
            uilib.field({"role": "textbox", "name": "Reason", "exact": True}, "nano-e2e NAN-4995")
        )
        if on:
            switch_page.click({"role": "button", "name": "Turn SOAR on", "exact": True}, timeout_ms=30_000)
        else:
            switch_page.click({"role": "button", "name": "Turn SOAR off", "exact": True}, timeout_ms=30_000)
            switch_page.click(
                {
                    "role": "button",
                    "name": "Turn off",
                    "exact": True,
                    "within": {"role": "alertdialog"},
                }
            )
        eventually(
            lambda: bool(expect(nano.api.get("/api/soar/settings"), 200)["soar_enabled"]),
            timeout=30,
            interval=0.2,
            desc=f"SOAR {'enabled' if on else 'disabled'} by interactive admin",
            ok=lambda enabled: enabled == on,
        )
        failed = False
    finally:
        switch_page.finish(failed)


class PersonaCleanup:
    """Register name/route-based cleanup as soon as a browser create succeeds."""

    def __init__(self, nano) -> None:
        self.nano = nano
        self.actions = CleanupStack()

    @staticmethod
    def _items(body, *keys: str):
        if isinstance(body, list):
            return body
        for key in keys:
            if isinstance(body.get(key), list):
                return body[key]
        return []

    def dashboard(self, name: str) -> None:
        def remove() -> None:
            body = expect(self.nano.api.get("/api/dashboards"), 200, 404)
            if body is None:
                return
            for item in self._items(body, "dashboards", "items"):
                if item.get("name") == name:
                    expect(self.nano.api.delete(f"/api/dashboards/{item['id']}"), 200, 204, 404)

        self.actions.register(f"dashboard {name}", remove)

    def rule(self, name: str) -> None:
        def remove() -> None:
            body = expect(self.nano.api.get("/api/rules"), 200, 404)
            if body is None:
                return
            for item in self._items(body, "rules", "items"):
                if item.get("name") == name:
                    expect(self.nano.api.delete(f"/api/rules/{item['id']}"), 200, 204, 404)

        self.actions.register(f"rule {name}", remove)

    def case(self, case_id: str) -> None:
        self.actions.register_http(f"case {case_id}", lambda: self.nano.api.delete(f"/api/cases/{case_id}"))

    def soar_flow(self, flow_id: str) -> None:
        self.actions.register_http(
            f"SOAR flow {flow_id}", lambda: self.nano.api.delete(f"/api/soar/flows/{flow_id}")
        )

    def oidc_provider(self, provider_id: str) -> None:
        self.actions.register_http(
            f"OIDC provider {provider_id}",
            lambda: self.nano.api.delete(f"/api/settings/oidc/{provider_id}"),
        )

    def api_key(self, key_id: str) -> None:
        self.actions.register_http(
            f"API key {key_id}", lambda: self.nano.api.delete(f"/api/api-keys/{key_id}")
        )

    def role(self, name: str) -> None:
        def remove() -> None:
            body = expect(self.nano.api.get("/api/roles"), 200, 404)
            if body is None:
                return
            for item in self._items(body, "roles", "items"):
                if item.get("name") == name:
                    expect(self.nano.api.delete(f"/api/roles/{item['id']}"), 200, 204, 404)

        self.actions.register(f"role {name}", remove)

    def source(self, route_key: str) -> None:
        def remove() -> None:
            body = expect(self.nano.api.get("/api/log-sources"), 200, 404)
            if body is None:
                return
            for item in self._items(body, "log_sources", "items"):
                if route_key in (item.get("match_values") or []):
                    expect(self.nano.api.delete(f"/api/log-sources/{item['id']}"), 200, 204, 404)

        self.actions.register(f"source route {route_key}", remove)

    def token(self, route_key: str) -> None:
        def remove() -> None:
            body = expect(self.nano.api.get("/api/ingest-tokens"), 200, 404)
            if body is None:
                return
            for item in self._items(body, "tokens", "credentials"):
                if item.get("route_key") == route_key and item.get("state") != "revoked":
                    expect(
                        self.nano.api.post(f"/api/ingest-tokens/{item['credential_id']}/revoke"),
                        200,
                        204,
                        404,
                    )

        self.actions.register(f"ingest token route {route_key}", remove)


@pytest.fixture
def persona_cleanup(nano):
    cleanup = PersonaCleanup(nano)
    yield cleanup
    cleanup.actions.close()


@pytest.fixture
def persona_ai(nano):
    snapshot = snapshot_persona_ai(nano)
    try:
        yield configure_persona_ai(nano)
    finally:
        restore_persona_ai(nano, snapshot)


@pytest.fixture
def persona_soar(nano, ui, stack, artifact_dir, persona_cleanup):  # noqa: F811 - pytest fixture
    if os.environ.get("E2E_EDITION") == "open":
        yield False
        return
    was_enabled = bool(expect(nano.api.get("/api/soar/settings"), 200)["soar_enabled"])
    if not was_enabled:
        persona_cleanup.actions.register(
            "restore SOAR setting",
            lambda: _switch_soar(ui, stack, nano, artifact_dir / "ui-soar-restore", False),
        )
        _switch_soar(ui, stack, nano, artifact_dir / "ui-soar-enable", True)
    yield bool(expect(nano.api.get("/api/soar/settings"), 200)["soar_enabled"])
