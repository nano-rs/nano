"""`scripts/e2e.sh gc --sweep` (NAN-5884 review): a host-level sweep for e2e
leftovers on shared RC hosts. It refuses while any e2e stack runs, and only
ever removes dangling, unlabeled, anonymous (64-hex) volumes. A fake
`docker` on PATH records what it is asked to do."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/e2e.sh"
ANON = "a" * 64
LABELED = "b" * 64

FAKE = f"""#!/usr/bin/env bash
echo "$*" >> "$FAKE_LOG"
case "$1 $2" in
  "ps --filter") cat "$FAKE_RUNNING" ;;
  "volume ls") printf '%s\\n' {ANON} {LABELED} my_named_volume ;;
  "volume inspect") case "${{@: -1}}" in {ANON}) echo 0 ;; *) echo 2 ;; esac ;;
  "volume rm") ;;
  *) ;;
esac
"""


def _sweep(tmp_path: Path, running: str, *args: str) -> tuple[subprocess.CompletedProcess[str], str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "docker").write_text(FAKE)
    (bin_dir / "docker").chmod(0o755)
    (tmp_path / "running").write_text(running)
    log = tmp_path / "docker.log"
    log.write_text("")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_LOG": str(log),
           "FAKE_RUNNING": str(tmp_path / "running"), "TMPDIR": str(tmp_path)}
    done = subprocess.run(
        ["bash", "-c", f'source "{RUNNER}"; GC_SWEEP=1; SWEEP_FORCE={1 if "--force" in args else 0}; cmd_gc'],
        capture_output=True, text=True, env=env, timeout=60,
    )
    return done, log.read_text()


def test_the_sweep_refuses_while_a_lane_is_running(tmp_path: Path) -> None:
    done, log = _sweep(tmp_path, "nanoe2e-run1\n")
    assert done.returncode != 0 and "sweep only in an idle window" in done.stderr
    assert "volume rm" not in log


def test_the_sweep_removes_only_unlabeled_anonymous_volumes(tmp_path: Path) -> None:
    done, log = _sweep(tmp_path, "")
    assert done.returncode == 0, done.stderr
    removed = [line for line in log.splitlines() if line.startswith("volume rm")]
    assert removed == [f"volume rm {ANON}"], log
    # --force sweeps even with a lane up (the operator's call).
    done, log = _sweep(tmp_path, "nanoe2e-run1\n", "--force")
    assert done.returncode == 0, done.stderr


def test_the_guard_and_the_sweep_against_the_real_process_table() -> None:
    """Review r2: with the real `ps`, the leak guard never lists its own
    filter (no false leak), still catches this run's orphan, and the sweep
    removes a stale e2e profile while keeping one in use. The shell test
    does the work; it runs on macOS and Linux alike."""
    done = subprocess.run(
        ["bash", str(ROOT / "scripts/tests/leak-guard-live.test.sh")],
        capture_output=True, text=True, timeout=120,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "leak guard live tests: PASS" in done.stdout
