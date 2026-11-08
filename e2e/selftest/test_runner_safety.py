"""scripts/e2e.sh safety properties, exercised by sourcing the real runner.

P1-1  native pid files are bound to (pid, start time, owner token): a reused
      pid, or a dev service built from the same target dir, is never signalled.
P2-6  the ClickHouse admin password never appears in a process's argv.
P1-2  `gc --hours 0` is refused.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

C_SLEEPER = "#include <unistd.h>\nint main(void){sleep(300);return 0;}\n"


def _bash(runner: Path, script: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Source the runner (functions only, no dispatch) and run `script`."""
    return subprocess.run(
        ["bash", "-c", f'set -euo pipefail; source "{runner}"; {script}'],
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.fixture
def fake_target(tmp_path: Path) -> Path:
    """A fake CARGO_TARGET_DIR holding a compiled long sleeper (a native
    binary, so macOS `ps -E` shows its environment like the real services)."""
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        pytest.skip("no C compiler to build the sleeper helper")
    target = tmp_path / "target"
    (target / "debug").mkdir(parents=True)
    src = tmp_path / "s.c"
    src.write_text(C_SLEEPER)
    subprocess.run([cc, "-o", str(target / "debug" / "nanosiem-api"), str(src)], check=True)
    return target


def _spawn(exe: Path, env: dict[str, str] | None = None) -> subprocess.Popen:
    p = subprocess.Popen([str(exe)], env={**os.environ, **(env or {})}, start_new_session=True)
    time.sleep(0.5)
    return p


def _alive(p: subprocess.Popen) -> bool:
    return p.poll() is None


def _cleanup(*procs: subprocess.Popen) -> None:
    for p in procs:
        if _alive(p):
            p.send_signal(signal.SIGKILL)
            p.wait()


def _run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "run"
    (d / "pids").mkdir(parents=True)
    return d


def _start_time(runner: Path, pid: int, env: dict[str, str]) -> str:
    return _bash(runner, f"proc_start {pid}", env).stdout.strip()


def test_owned_process_is_stopped(runner: Path, fake_target: Path, tmp_path: Path) -> None:
    env = {"CARGO_TARGET_DIR": str(fake_target)}
    token = "a" * 32
    p = _spawn(fake_target / "debug" / "nanosiem-api", {"E2E_PROC_OWNER": token})
    try:
        run = _run_dir(tmp_path)
        start = _start_time(runner, p.pid, env)
        (run / "pids" / "api.pid").write_text(f"{p.pid}\t{start}\t{token}\n")
        r = _bash(runner, f'RUN_DIR="{run}"; native_stop TERM api', env)
        assert r.returncode == 0, r.stderr
        p.wait(timeout=10)
        assert not _alive(p), "owned process must be stopped"
        assert not (run / "pids" / "api.pid").exists()
    finally:
        _cleanup(p)


def test_dev_service_from_same_target_dir_is_never_signalled(
    runner: Path, fake_target: Path, tmp_path: Path
) -> None:
    """Same binary path, same pid in the file (as after a crash + pid reuse),
    but no owner token in its environment: a developer's own nanosiem-api."""
    env = {"CARGO_TARGET_DIR": str(fake_target)}
    p = _spawn(fake_target / "debug" / "nanosiem-api")  # no E2E_PROC_OWNER
    try:
        run = _run_dir(tmp_path)
        start = _start_time(runner, p.pid, env)
        (run / "pids" / "api.pid").write_text(f"{p.pid}\t{start}\t{'b' * 32}\n")
        r = _bash(runner, f'RUN_DIR="{run}"; native_stop TERM api; native_stop KILL api', env)
        assert r.returncode == 0, r.stderr
        time.sleep(0.5)
        assert _alive(p), "a process without our owner token must never be signalled"
    finally:
        _cleanup(p)


def test_reused_pid_with_different_start_time_is_never_signalled(
    runner: Path, fake_target: Path, tmp_path: Path
) -> None:
    env = {"CARGO_TARGET_DIR": str(fake_target)}
    token = "c" * 32
    p = _spawn(fake_target / "debug" / "nanosiem-api", {"E2E_PROC_OWNER": token})
    try:
        run = _run_dir(tmp_path)
        (run / "pids" / "api.pid").write_text(f"{p.pid}\tMon Jan  1 00:00:00 2001\t{token}\n")
        r = _bash(runner, f'RUN_DIR="{run}"; native_stop TERM api', env)
        assert r.returncode == 0, r.stderr
        time.sleep(0.5)
        assert _alive(p), "start-time mismatch (pid reuse) must never be signalled"
    finally:
        _cleanup(p)


def test_legacy_single_pid_file_is_never_signalled(runner: Path, fake_target: Path, tmp_path: Path) -> None:
    env = {"CARGO_TARGET_DIR": str(fake_target)}
    p = _spawn(fake_target / "debug" / "nanosiem-api", {"E2E_PROC_OWNER": "d" * 32})
    try:
        run = _run_dir(tmp_path)
        (run / "pids" / "api.pid").write_text(f"{p.pid}\n")
        _bash(runner, f'RUN_DIR="{run}"; native_stop TERM api', env)
        time.sleep(0.5)
        assert _alive(p)
    finally:
        _cleanup(p)


def test_clickhouse_admin_password_not_in_argv(runner: Path, tmp_path: Path) -> None:
    run = _run_dir(tmp_path)
    secret = "s3cr3t-admin-password-0123456789abcdef"
    (run / "compose.env").write_text(f"CLICKHOUSE_ADMIN_PASSWORD={secret}\n")
    (run / "run.env").write_text("E2E_CH_HTTP_PORT=1\n")
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    argv_log = tmp_path / "argv.txt"
    (fakebin / "curl").write_text(f'#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "{argv_log}"\n')
    (fakebin / "curl").chmod(0o755)
    r = _bash(
        runner,
        f'RUN_DIR="{run}"; ch_admin "SELECT 1"',
        {"PATH": f"{fakebin}:{os.environ['PATH']}"},
    )
    assert r.returncode == 0, r.stderr
    argv = argv_log.read_text()
    assert secret not in argv, "admin password leaked into curl argv"
    cfg = run / "ch-admin.curlrc"
    assert "-K" in argv and str(cfg) in argv
    assert oct(cfg.stat().st_mode & 0o777) == "0o600"
    assert secret in cfg.read_text()


@pytest.mark.parametrize("hours", ["0", "-1", "abc"])
def test_gc_refuses_unsafe_cutoff(runner: Path, hours: str) -> None:
    r = subprocess.run([str(runner), "gc", "--hours", hours], capture_output=True, text=True, check=False)
    assert r.returncode != 0
    assert "--hours" in r.stderr
