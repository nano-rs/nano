"""The native stack gives the server hunt runner a non-loopback HOST IP (NAN-5732).

Native jobs reaches ClickHouse on 127.0.0.1, and Agent Lane refuses a loopback
HOST IP, so without NANO_HUNTS_RUNNER_CIDR every server sweep stays queued.
`write_app_env` asks ClickHouse which address it sees. These tests source the
runner and drive the probe and `write_app_env` with a fake ``curl`` that drains
and records its stdin and argv (no Docker, no stack).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/e2e.sh"
SECRET = "s3cr3t-ch-password-0123456789abcdef"
CH_PORT = "18123"


class FakeCurl:
    """A ``curl`` on PATH that drains stdin (no SIGPIPE under pipefail),
    records its argv and stdin, then answers or fails as configured."""

    def __init__(self, tmp_path: Path, answer: str | None) -> None:
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.argv_log = tmp_path / "curl-argv.txt"
        self.stdin_log = tmp_path / "curl-stdin.txt"
        reply = f"printf '%s\\n' '{answer}'" if answer is not None else "exit 7"
        script = self.bin / "curl"
        script.write_text(
            "#!/usr/bin/env bash\n"
            f'cat > "{self.stdin_log}"\n'
            f'printf "%s\\n" "$@" > "{self.argv_log}"\n'
            f"{reply}\n"
        )
        script.chmod(0o755)

    @property
    def called(self) -> bool:
        return self.argv_log.exists()

    def argv(self) -> list[str]:
        return self.argv_log.read_text().splitlines()

    def stdin(self) -> str:
        return self.stdin_log.read_text()


def _bash(script: str, curl: FakeCurl, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    base = {k: v for k, v in os.environ.items() if k != "NANO_HUNTS_RUNNER_CIDR"}
    return subprocess.run(  # noqa: S603 - fixed argv
        ["bash", "-c", f'set -euo pipefail; source "{RUNNER}"; {script}'],
        env={**base, "PATH": f"{curl.bin}:{os.environ['PATH']}", **(env or {})},
        capture_output=True, text=True, timeout=60, check=False,
    )


def _assert_secret_only_on_stdin(curl: FakeCurl) -> None:
    argv = curl.argv()
    assert SECRET not in "\n".join(argv), "the ClickHouse password leaked into curl argv"
    i = argv.index("-K")
    assert argv[i + 1] == "-", "curl must read its config from stdin"
    assert f"http://127.0.0.1:{CH_PORT}/" in argv
    assert f'header = "X-ClickHouse-Key: {SECRET}"' in curl.stdin()
    assert 'header = "X-ClickHouse-User: nanosiem"' in curl.stdin()


@pytest.mark.parametrize(("answer", "expected"), [
    ("::ffff:172.22.0.1", "172.22.0.1"),   # Docker bridge gateway, IPv4-mapped
    ("192.168.65.1", "192.168.65.1"),      # Docker Desktop
    ("::ffff:127.0.0.1", ""),              # loopback is exactly what Agent Lane refuses
    ("::1", ""),
])
def test_probe_maps_the_clickhouse_client_address(tmp_path: Path, answer: str, expected: str) -> None:
    curl = FakeCurl(tmp_path, answer)
    done = _bash(f'native_hunts_runner_cidr {CH_PORT}; echo "<rc=$?>"', curl, {"CLICKHOUSE_PASSWORD": SECRET})
    assert done.returncode == 0, done.stderr
    assert done.stdout == f"{expected}<rc=0>\n"
    _assert_secret_only_on_stdin(curl)


def test_probe_failure_is_empty_and_never_aborts(tmp_path: Path) -> None:
    curl = FakeCurl(tmp_path, None)
    done = _bash(f'native_hunts_runner_cidr {CH_PORT}; echo "<rc=$?>"', curl, {"CLICKHOUSE_PASSWORD": SECRET})
    assert done.returncode == 0, done.stderr
    assert done.stdout == "<rc=0>\n"
    _assert_secret_only_on_stdin(curl)


# ----------------------------------------------------------------------------- write_app_env

COMPOSE_ENV_KEYS = (
    "POSTGRES_PASSWORD", "CLICKHOUSE_ADMIN_PASSWORD", "CLICKHOUSE_VECTOR_PASSWORD",
    "CLICKHOUSE_RAWSQL_PASSWORD", "CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD", "CLICKHOUSE_SEARCH_PASSWORD",
    "CLICKHOUSE_DICT_PASSWORD", "JWT_SECRET", "NANOSIEM_ENCRYPTION_KEY", "VECTOR_AUTH_TOKEN",
    "NANO_PLATFORM_INGEST_TOKEN", "NANO_OTLP_EDGE_KEY", "NANO_VERSION",
)


def _write_app_env(tmp_path: Path, curl: FakeCurl, env: dict[str, str] | None = None):
    run = tmp_path / "run"
    run.mkdir()
    (run / "compose.env").write_text(
        f"CLICKHOUSE_PASSWORD={SECRET}\n" + "".join(f"{k}=x\n" for k in COMPOSE_ENV_KEYS))
    (run / "run.env").write_text(f"E2E_CH_HTTP_PORT={CH_PORT}\nE2E_PROFILES=\n")
    # The globals cmd_up sets before write_app_env in a real run.
    done = _bash(f'RUN_DIR="{run}"; PROJECT=nanoe2e-selftest; EDITION=enterprise; NANO_SCHEMA_PROFILE=ocsf; '
                 f'RUST_LOG=info; write_app_env', curl, env)
    app_env = run / "app.env"
    return done, (app_env.read_text() if app_env.exists() else "")


def test_write_app_env_exports_the_probed_address(tmp_path: Path) -> None:
    curl = FakeCurl(tmp_path, "::ffff:172.22.0.1")
    done, app_env = _write_app_env(tmp_path, curl)
    assert done.returncode == 0, done.stderr
    assert "export NANO_HUNTS_RUNNER_CIDR=172.22.0.1\n" in app_env
    _assert_secret_only_on_stdin(curl)


def test_write_app_env_shell_value_wins_without_probing(tmp_path: Path) -> None:
    curl = FakeCurl(tmp_path, "::ffff:172.22.0.1")
    done, app_env = _write_app_env(tmp_path, curl, {"NANO_HUNTS_RUNNER_CIDR": "10.9.8.7"})
    assert done.returncode == 0, done.stderr
    assert "export NANO_HUNTS_RUNNER_CIDR=10.9.8.7\n" in app_env
    assert "172.22.0.1" not in app_env
    assert not curl.called, "a shell-set NANO_HUNTS_RUNNER_CIDR must not probe ClickHouse"


def test_write_app_env_failed_probe_only_warns(tmp_path: Path) -> None:
    curl = FakeCurl(tmp_path, None)
    done, app_env = _write_app_env(tmp_path, curl)
    assert done.returncode == 0, done.stderr
    assert "could not read the address ClickHouse sees" in done.stderr
    assert "NANO_HUNTS_RUNNER_CIDR" not in app_env
    assert "export CLICKHOUSE_URL=" in app_env, "the rest of app.env is still written"
