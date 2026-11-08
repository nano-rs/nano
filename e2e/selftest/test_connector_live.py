"""NAN-4961: the `connector-live` profile runs nano-connector-runner exactly as
shipped (no test seam), never together with the mock, and only the
`connectors` suite gets it by default. Credential loaders skip with the
variable names and never put a secret in a repr."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest


def _bash(runner: Path, script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", f'set -euo pipefail; source "{runner}"; {script}'],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_live_connector_env_has_no_test_seam(runner: Path, tmp_path: Path) -> None:
    run = tmp_path / "run"
    (run / "pids").mkdir(parents=True)
    (run / "run.env").write_text("E2E_HEC_PORT=4001\nE2E_MOCK_VENDOR_PORT=4002\nE2E_PROFILES=connector-live\n")
    out = _bash(runner, f'RUN_DIR="{run}"; PROJECT=nanoe2e-x; write_connector_env; run_has_runner && echo RUNNER')
    assert out.returncode == 0, out.stderr
    env = (run / "connector.env").read_text()
    assert "CONNECTOR_TEST_MODE" not in env and "CONNECTOR_TEST_MOCK_URL" not in env
    assert "CONNECTOR_HEC_URL=http://127.0.0.1:4001" in env
    assert not any(w in env for w in ("PASSWORD", "SECRET", "TOKEN=", "ENCRYPTION_KEY"))
    assert stat.S_IMODE((run / "connector.env").stat().st_mode) == 0o600
    assert "RUNNER" in out.stdout


@pytest.mark.parametrize("args", [["--profile", "mock-vendor", "--profile", "connector-live"]])
def test_live_and_mock_are_exclusive(runner: Path, args: list[str]) -> None:
    out = subprocess.run(["bash", str(runner), "status", *args], capture_output=True, text=True, timeout=30)
    assert out.returncode != 0 and "exclusive" in out.stderr


def test_live_needs_native(runner: Path) -> None:
    out = subprocess.run(
        ["bash", str(runner), "up", "--app", "docker", "--profile", "connector-live"],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "E2E_NEW_RUN_ID": "sel-0000bbbb"},
    )
    assert out.returncode != 0
    assert "--profile connector-live needs --app native" in out.stderr or "docker daemon not reachable" in out.stderr


def test_connectors_suite_selection(runner: Path) -> None:
    out = _bash(runner, "POSITIONAL=(connectors); suite_paths; only_suite connectors && echo ONLY")
    assert out.returncode == 0, out.stderr
    assert any(line.endswith("/e2e/tests/connectors") for line in out.stdout.splitlines())
    assert "ONLY" in out.stdout


def test_tenant_loaders_skip_with_names_and_hide_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    from nano_e2e import creds

    for k in list(os.environ):
        if k.startswith(("NANO_E2E_ENTRA_", "OKTA_", "NANO_E2E_GWS_", "NANO_E2E_SLACK_")):
            monkeypatch.delenv(k)
    for loader, name in ((creds.entra, "NANO_E2E_ENTRA_CLIENT_SECRET"), (creds.okta, "OKTA_API_TOKEN"),
                         (creds.gws, "NANO_E2E_GWS_SA_JSON"), (creds.slack, "NANO_E2E_SLACK_USER_TOKEN")):
        got, why = loader()
        assert got is None and name in why
    monkeypatch.setenv("OKTA_ORG_URL", "https://dev-1-admin.okta.com/admin")
    monkeypatch.setenv("OKTA_API_TOKEN", "00secret-value-xyz")
    okta, _ = creds.okta()
    assert okta is not None and okta.domain == "dev-1.okta.com"
    assert "00secret-value-xyz" not in repr(okta)
    monkeypatch.setenv("NANO_E2E_ENTRA_TENANT_ID", "t")
    monkeypatch.setenv("NANO_E2E_ENTRA_CLIENT_ID", "c")
    monkeypatch.setenv("NANO_E2E_ENTRA_CLIENT_SECRET", "entra-secret-value")
    entra, _ = creds.entra()
    assert entra is not None and "entra-secret-value" not in repr(entra)
