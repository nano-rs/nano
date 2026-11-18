"""Persona journeys share canonical UI fixtures, artifacts, and strict cleanup."""

import os

import pytest

from nano_e2e import ui as uilib
from nano_e2e.client import expect
from nano_e2e.fixtures_ui import anon_page, page, ui, web  # noqa: F401
from nano_e2e.personas import PersonaCleanup, configure_persona_ai, restore_persona_ai, snapshot_persona_ai
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
