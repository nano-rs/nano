"""`--target existing` (NAN-5586): the credentials file is guarded and the
acting user's secrets land only under env names the harness scrubs."""

from __future__ import annotations

import os

import pytest

from nano_e2e import target


def _write(path, text: str, mode: int = 0o600):
    path.write_text(text)
    os.chmod(path, mode)
    return path


def test_creds_file_must_be_0600(tmp_path) -> None:
    f = _write(tmp_path / "c.txt", "email=a@b\npassword=pw-123456789\napi_key=key-123456789\n", 0o644)
    with pytest.raises(PermissionError):
        target.read_creds(f)


def test_creds_file_needs_the_user(tmp_path) -> None:
    f = _write(tmp_path / "c.txt", "email=a@b\npassword=p\n")
    with pytest.raises(ValueError, match="api_key"):
        target.read_creds(f)


def test_creds_file_inside_the_repo_is_refused() -> None:
    inside = target.ROOT / "target" / "e2e-selftest-creds.txt"
    inside.parent.mkdir(parents=True, exist_ok=True)
    try:
        _write(inside, "email=a@b\npassword=pw-123456789\napi_key=key-123456789\n")
        with pytest.raises(PermissionError, match="outside the repository"):
            target.read_creds(inside)
    finally:
        inside.unlink(missing_ok=True)


def test_load_env_exports_under_scrubbed_names(tmp_path, monkeypatch) -> None:
    f = _write(tmp_path / "c.txt", "# local\nemail=walker@example.test\npassword=pw-123456789\napi_key=key-123456789\n"
               "lane_token=tok-123456789\n")
    for k in ("NANOSIEM_API_KEY", "NANO_ADMIN_PASSWORD", "NANO_ADMIN_EMAIL", "E2E_TARGET_HEC_TOKEN",
              "E2E_TARGET_CREDS_LOADED"):
        monkeypatch.setenv(k, "shell-value-123")  # recorded, so the test restores the real env
    monkeypatch.delenv("E2E_TARGET_CREDS_LOADED")
    monkeypatch.setenv("E2E_TARGET", "existing")
    monkeypatch.setenv("E2E_TARGET_CREDS_FILE", str(f))
    target.load_env()
    assert os.environ["NANO_ADMIN_EMAIL"] == "walker@example.test"
    assert os.environ["NANO_ADMIN_PASSWORD"] == "pw-123456789"
    assert os.environ["NANOSIEM_API_KEY"] == "key-123456789"
    assert os.environ["E2E_TARGET_HEC_TOKEN"] == "tok-123456789"
    from nano_e2e import artifact_guard

    secrets = artifact_guard.env_secrets()
    assert {"pw-123456789", "key-123456789", "tok-123456789"} <= set(secrets)


def test_load_env_is_a_noop_without_the_target(monkeypatch) -> None:
    monkeypatch.setenv("E2E_TARGET", "own")
    monkeypatch.setenv("NANOSIEM_API_KEY", "x")
    monkeypatch.delenv("NANOSIEM_API_KEY")
    target.load_env()
    assert "NANOSIEM_API_KEY" not in os.environ


def test_creds_file_naming_the_admin_is_refused(tmp_path) -> None:
    f = _write(tmp_path / "c.txt", "email=Admin@nano.local\npassword=pw-123456789\napi_key=key-123456789\n")
    with pytest.raises(PermissionError, match="admin"):
        target.read_creds(f)


def test_short_secrets_are_refused(tmp_path) -> None:
    f = _write(tmp_path / "c.txt", "email=a@b\npassword=short\napi_key=key-123456789\n")
    with pytest.raises(ValueError, match="password"):
        target.read_creds(f)
