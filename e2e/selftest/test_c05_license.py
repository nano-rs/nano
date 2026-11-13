"""NAN-5331: pinned installation identity + offline C05 license import.

No stack: the seeding SQL is checked for its guards, the runner's wiring is
exercised by sourcing scripts/e2e.sh with a fake `dc`, and the import runs
against a stdlib stub API. Every failure path is checked for NOT echoing the
license file's contents.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from nano_e2e import artifact_guard, c05_license
from nano_e2e.c05_license import LicenseError

SENTINEL = "c05-sentinel-signature-do-not-print-0123456789abcdef"
IID, OID = "e2e-install-01", "e2e-org-01"


@pytest.fixture
def license_file(tmp_path: Path) -> Path:
    p = tmp_path / "trial.c05.json"
    p.write_text(json.dumps({"claims": {"order_id": "o"}, "key_id": "k", "signature": SENTINEL}))
    p.chmod(0o600)
    return p


def _env(**kw: str) -> dict[str, str]:
    return {k: v for k, v in kw.items()}


# ---------------------------------------------------------------- env validation
def test_identity_unset_is_none() -> None:
    assert c05_license.pinned_identity({}) is None


def test_identity_pinned() -> None:
    env = _env(NANO_E2E_INSTALLATION_ID=IID, NANO_E2E_INSTALLATION_ORG_ID=OID)
    assert c05_license.pinned_identity(env) == (IID, OID)


@pytest.mark.parametrize(
    "env",
    [
        {"NANO_E2E_INSTALLATION_ID": IID},
        {"NANO_E2E_INSTALLATION_ORG_ID": OID},
        {"NANO_E2E_INSTALLATION_ID": "Upper", "NANO_E2E_INSTALLATION_ORG_ID": OID},
        {"NANO_E2E_INSTALLATION_ID": IID, "NANO_E2E_INSTALLATION_ORG_ID": "-lead"},
        {"NANO_E2E_INSTALLATION_ID": "a" * 65, "NANO_E2E_INSTALLATION_ORG_ID": OID},
        {"NANO_E2E_INSTALLATION_ID": "x'; DROP TABLE t;--", "NANO_E2E_INSTALLATION_ORG_ID": OID},
    ],
)
def test_identity_rejected(env: dict[str, str]) -> None:
    with pytest.raises(LicenseError):
        c05_license.pinned_identity(env)


def test_license_file_ok(license_file: Path, tmp_path: Path) -> None:
    assert SENTINEL.encode() in c05_license.read_license_file(license_file, tmp_path / "repo")


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_license_file_must_be_private(license_file: Path, mode: int) -> None:
    license_file.chmod(mode)
    with pytest.raises(LicenseError, match="0600") as exc:
        c05_license.read_license_file(license_file)
    assert SENTINEL not in str(exc.value)


def test_license_file_symlink_refused(license_file: Path, tmp_path: Path) -> None:
    link = tmp_path / "link.json"
    link.symlink_to(license_file)
    with pytest.raises(LicenseError):
        c05_license.read_license_file(link)


def test_license_file_inside_repo_refused(license_file: Path) -> None:
    with pytest.raises(LicenseError, match="outside the repository"):
        c05_license.read_license_file(license_file, license_file.parent)


def test_license_file_relative_and_empty_refused(tmp_path: Path) -> None:
    with pytest.raises(LicenseError, match="absolute"):
        c05_license.read_license_file("trial.json")
    empty = tmp_path / "empty.json"
    empty.touch()
    empty.chmod(0o600)
    with pytest.raises(LicenseError, match="bytes"):
        c05_license.read_license_file(empty)


# ---------------------------------------------------------------- seeding logic
def test_seed_sql_is_guarded_and_parameterised() -> None:
    sql = c05_license.SEED_SQL
    assert sql.count("BEGIN;") == 1 and sql.count("COMMIT;") == 1
    assert (
        "LOCK TABLE sovereign_license_installation, sovereign_license_state, sovereign_license_audit" in sql
    )
    # Never rebinds an installation that already holds license or ledger state.
    assert "NOT EXISTS (SELECT 1 FROM sovereign_license_state)" in sql
    assert "NOT EXISTS (SELECT 1 FROM sovereign_license_audit)" in sql
    # Ids are psql-quoted variables, never harness-interpolated text.
    assert ":'iid'" in sql and ":'oid'" in sql
    assert "\\set ON_ERROR_STOP on" in sql
    assert "BEGIN READ ONLY;" in c05_license.IDS_SQL


def test_check_seeded() -> None:
    row = c05_license.check_seeded(f"{IID}|{OID}|false\n", (IID, OID))
    assert row.licensed is False
    with pytest.raises(LicenseError, match="already holds license state"):
        c05_license.check_seeded("other-id|other-org|true\n", (IID, OID))
    for bad in ("", f"{IID}|{OID}|false\n{IID}|{OID}|false", f"{IID}|{OID}", "A|b|true"):
        with pytest.raises(LicenseError):
            c05_license.check_seeded(bad, (IID, OID))


def _bash(runner: Path, script: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    base = {k: v for k, v in os.environ.items() if not k.startswith("NANO_E2E_")}
    return subprocess.run(
        ["bash", "-c", f'set -euo pipefail; source "{runner}"; {script}'],
        env={**base, **env},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


FAKE_DC = 'dc() { cat > "$CAP_SQL"; printf "%s\\n" "$@" > "$CAP_ARGS"; printf "%s\\n" "$FAKE_ROW"; }; '


def _wire_env(tmp_path: Path, row: str, **kw: str) -> dict[str, str]:
    return {
        "CAP_SQL": str(tmp_path / "sql"),
        "CAP_ARGS": str(tmp_path / "args"),
        "FAKE_ROW": row,
        "E2E_EDITION": "enterprise",
        **kw,
    }


def test_runner_seeds_pinned_identity(runner: Path, tmp_path: Path) -> None:
    env = _wire_env(
        tmp_path, f"{IID}|{OID}|false", NANO_E2E_INSTALLATION_ID=IID, NANO_E2E_INSTALLATION_ORG_ID=OID
    )
    r = _bash(runner, FAKE_DC + "seed_installation_identity", env)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "sql").read_text() == c05_license.SEED_SQL
    args = (tmp_path / "args").read_text().split("\n")
    assert args[:3] == ["exec", "-T", "postgres"]
    assert f"iid={IID}" in args and f"oid={OID}" in args
    assert "identity pinned" in r.stderr


def test_runner_seed_refusal_fails_loudly(runner: Path, tmp_path: Path) -> None:
    env = _wire_env(
        tmp_path, "random-uuid|other-org|true", NANO_E2E_INSTALLATION_ID=IID, NANO_E2E_INSTALLATION_ORG_ID=OID
    )
    r = _bash(runner, FAKE_DC + "seed_installation_identity", env)
    assert r.returncode != 0
    assert "already holds license state" in r.stderr


@pytest.mark.parametrize("extra", [{}, {"E2E_EDITION": "open"}])
def test_runner_seed_noop_without_pin_or_on_open(runner: Path, tmp_path: Path, extra: dict[str, str]) -> None:
    env = _wire_env(tmp_path, "unused|unused|false", **extra)
    if extra:
        env |= {"NANO_E2E_INSTALLATION_ID": IID, "NANO_E2E_INSTALLATION_ORG_ID": OID}
    r = _bash(runner, FAKE_DC + "seed_installation_identity", env)
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "sql").exists()


def test_runner_env_check_refuses_half_pinned(runner: Path, tmp_path: Path) -> None:
    r = _bash(runner, "license_env_check", {"NANO_E2E_INSTALLATION_ID": IID})
    assert r.returncode != 0
    assert "must be set together" in r.stderr


def test_runner_env_check_refuses_open_license_file(runner: Path, license_file: Path) -> None:
    license_file.chmod(0o644)
    r = _bash(runner, "license_env_check", {"NANO_E2E_C05_LICENSE_FILE": str(license_file)})
    assert r.returncode != 0
    assert "0600" in r.stderr and SENTINEL not in r.stderr + r.stdout


def test_runner_license_ids_parses_row(runner: Path, tmp_path: Path) -> None:
    r = _bash(runner, f'printf "%s\\n" "{IID}|{OID}|true" | license_py parse-ids', {})
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == [
        f"installation_id={IID}",
        f"organization_id={OID}",
        "license_installed=yes",
    ]


# ---------------------------------------------------------------- import
class _StubApi(BaseHTTPRequestHandler):
    status: dict = {}
    import_code = 200
    seen: dict = {}

    def log_message(self, *_: object) -> None:
        pass

    def _send(self, code: int, doc: dict) -> None:
        body = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length", 0))
        type(self).seen = {
            "path": self.path,
            "key": self.headers.get("X-API-Key"),
            "body": self.rfile.read(n),
        }
        if self.import_code != 200:
            self._send(self.import_code, {"error": {"message": "binding refused"}})
        else:
            self._send(200, self.status)

    def do_GET(self) -> None:  # noqa: N802
        self._send(200, self.status)


@pytest.fixture
def stub_api():
    srv = HTTPServer(("127.0.0.1", 0), _StubApi)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _StubApi.import_code = 200
    _StubApi.status = {
        "state": "active",
        "valid": True,
        "mode": "offline",
        "installation_id": IID,
        "organization_id": OID,
        "license_id": "lic-1",
    }
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


def test_import_sends_exact_file_as_admin(stub_api: str, license_file: Path) -> None:
    status = c05_license.import_license(stub_api, "nano_key", str(license_file), want=(IID, OID))
    assert status["license_id"] == "lic-1"
    assert _StubApi.seen["path"] == "/api/license/import"
    assert _StubApi.seen["key"] == "nano_key"
    assert _StubApi.seen["body"] == license_file.read_bytes()


@pytest.mark.parametrize(
    ("status", "import_code", "match"),
    [
        (
            {"state": "locked", "valid": False, "mode": "offline", "locked_reason": "No license"},
            200,
            "NOT active",
        ),
        (
            {
                "state": "active",
                "valid": True,
                "mode": "offline",
                "installation_id": "x",
                "organization_id": OID,
            },
            200,
            "different installation",
        ),
        ({}, 409, "409: binding refused"),
    ],
)
def test_import_fails_loudly(
    stub_api: str, license_file: Path, status: dict, import_code: int, match: str
) -> None:
    _StubApi.status = status
    _StubApi.import_code = import_code
    with pytest.raises(LicenseError, match=match) as exc:
        c05_license.import_license(stub_api, "nano_key", str(license_file), want=(IID, OID))
    assert SENTINEL not in str(exc.value)


def test_import_cli_never_prints_contents(stub_api: str, license_file: Path, tmp_path: Path) -> None:
    admin = tmp_path / "admin.env"
    admin.write_text("NANOSIEM_API_KEY=nano_key\n")
    _StubApi.status = {"state": "locked", "valid": False, "mode": "offline"}
    e2e = Path(c05_license.__file__).resolve().parents[1]
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("NANO_E2E_")},
        "E2E_API_URL": stub_api,
        "E2E_ADMIN_ENV": str(admin),
        "NANO_E2E_C05_LICENSE_FILE": str(license_file),
    }
    r = subprocess.run(
        ["python3", "-m", "nano_e2e.c05_license", "import", "--repo-root", str(tmp_path / "repo")],
        cwd=e2e,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode == 1
    assert "E2E-LICENSE: license NOT active" in r.stderr
    assert SENTINEL not in r.stdout + r.stderr


def test_import_from_env_skips_open_and_unset(license_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NANO_E2E_C05_LICENSE_FILE", raising=False)
    assert c05_license.import_from_env("http://127.0.0.1:9", "k", "enterprise") is None
    monkeypatch.setenv("NANO_E2E_C05_LICENSE_FILE", str(license_file))
    assert c05_license.import_from_env("http://127.0.0.1:9", "k", "open") is None


# ---------------------------------------------------------------- artifact scrub
def test_guard_scrubs_license_file_contents_in_place(license_file: Path, tmp_path: Path) -> None:
    run = tmp_path / "run"
    arts = run / "artifacts"
    arts.mkdir(parents=True)
    (arts / "log.txt").write_text(f"request body: {license_file.read_text()}\n")
    (arts / "api.jsonl").write_text(json.dumps({"request": license_file.read_text()}) + "\n")
    assert (
        artifact_guard.main(["scrub", str(arts), "--run-dir", str(run), "--secret-file", str(license_file)])
        == 0
    )
    for name in ("log.txt", "api.jsonl"):
        text = (arts / name).read_text()
        assert SENTINEL not in text and "<redacted>" in text
    # Never copied into the run dir's registry.
    assert not (run / artifact_guard.REGISTRY).exists()
