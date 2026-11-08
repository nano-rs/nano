"""`scripts/e2e.sh gc` removes only stacks this checkout started (NAN-4937).

`gc --cloud --hours 1` once removed every local `nanoe2e-*` stack older than an
hour, including another lane's live stack. The local selection
(`gc_local_targets`) is exercised by sourcing the real runner and feeding it
docker label lines; `--cloud` must never reach the local path. No docker, no
cloud credentials.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

RUNNER = Path(__file__).resolve().parents[2] / "scripts" / "e2e.sh"
OLD, CUTOFF = 1000, 2000


def _targets(lines: list[str], e2e_home: Path, all_local: bool = False) -> list[str]:
    script = (
        f'source "{RUNNER}"; E2E_HOME="{e2e_home}"; GC_ALL_LOCAL={int(all_local)}; '
        f'printf "%s\\n" "$E2E_GC_LINES" | gc_local_targets {CUTOFF}'
    )
    # No positional args: sourcing the runner parses "$@" as its command line.
    r = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
        env={**os.environ, "E2E_GC_LINES": "\n".join(lines)},
    )
    return r.stdout.split()


def _root() -> str:
    return str(RUNNER.resolve().parents[1])


def test_only_this_checkouts_stacks_are_selected(tmp_path: Path) -> None:
    mine, theirs = "nanoe2e-dan-aaaa1111", "nanoe2e-dan-bbbb2222"
    lines = [f"{mine} {OLD} {_root()}", f"{theirs} {OLD} /Users/someone/other-worktree"]
    assert _targets(lines, tmp_path) == [mine]


def test_unlabelled_stack_needs_a_run_dir_in_this_checkout(tmp_path: Path) -> None:
    known, unknown = "nanoe2e-dan-cccc3333", "nanoe2e-dan-dddd4444"
    (tmp_path / known.removeprefix("nanoe2e-")).mkdir()
    lines = [f"{known} {OLD}", f"{unknown} {OLD}"]
    assert _targets(lines, tmp_path) == [known]


def test_young_stacks_and_foreign_projects_are_never_selected(tmp_path: Path) -> None:
    lines = [f"nanoe2e-dan-eeee5555 {CUTOFF + 10} {_root()}", f"nanoch-clickhouse {OLD} {_root()}"]
    assert _targets(lines, tmp_path) == []
    assert _targets(lines, tmp_path, all_local=True) == []


def test_all_local_is_the_explicit_override(tmp_path: Path) -> None:
    theirs = "nanoe2e-dan-ffff6666"
    lines = [f"{theirs} {OLD} /Users/someone/other-worktree"]
    assert _targets(lines, tmp_path) == []
    assert _targets(lines, tmp_path, all_local=True) == [theirs]


def test_cloud_gc_never_reaches_the_local_path() -> None:
    """In cmd_gc the --cloud branch returns before any docker call."""
    body = RUNNER.read_text().split("cmd_gc() {", 1)[1].split("\n}\n", 1)[0]
    cloud, local = body.split("if (( GC_CLOUD )); then", 1)[1].split("return 0", 1)
    assert "docker" not in cloud, "the --cloud branch touches docker"
    assert "gc_local_targets" in local and "docker rm" in local
