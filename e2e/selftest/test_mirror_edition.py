"""P1-4: the open-core mirror keeps scripts/e2e.sh, and in the stripped tree
(no nanosiem-enterprise) the runner must default to EDITION=open, so the
documented quick start builds and tests the edition that exists."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def test_stripped_tree_runner_defaults_to_open(root: Path, tmp_path: Path) -> None:
    strip = root / "tools" / "sync-to-nano-mirror.sh"
    if not strip.exists():
        pytest.skip("already the stripped tree (no strip script)")
    mirror = tmp_path / "mirror"
    subprocess.run(["bash", str(strip), str(root), str(mirror)], check=True, capture_output=True, timeout=600)
    assert (mirror / "scripts" / "e2e.sh").exists()
    assert not (mirror / "nanosiem-enterprise").exists()
    assert not (mirror / "e2e" / "tests" / "enterprise").exists()
    assert not (mirror / "e2e" / "selftest" / "test_soar_closeout_plumbing.py").exists()
    r = subprocess.run(
        ["bash", "scripts/e2e.sh", "doctor"],
        cwd=mirror,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert "edition: open (default for this tree: open)" in r.stderr, r.stderr[-2000:]
    # And enterprise is refused there rather than failing deep in cargo.
    r = subprocess.run(
        ["bash", "scripts/e2e.sh", "doctor", "--edition", "enterprise"],
        cwd=mirror,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode != 0 and "needs nanosiem-enterprise" in r.stderr


def test_full_tree_runner_defaults_to_enterprise(root: Path) -> None:
    if not (root / "nanosiem-enterprise").is_dir():
        pytest.skip("stripped tree")
    r = subprocess.run(
        ["bash", "scripts/e2e.sh", "doctor"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert "edition: enterprise (default for this tree: enterprise)" in r.stderr, r.stderr[-2000:]
