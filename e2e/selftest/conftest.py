"""Harness selftests: prove the runner's and the harness's own safety
properties (process ownership, GC ownership, coverage gating, isolation,
secret handling) WITHOUT a stack or cloud credentials. Run with
`scripts/e2e.sh selftest` or `cd e2e && .venv/bin/python -m pytest selftest`."""

from __future__ import annotations

from pathlib import Path

import pytest

E2E = Path(__file__).resolve().parents[1]
ROOT = E2E.parent
RUNNER = ROOT / "scripts" / "e2e.sh"


@pytest.fixture
def root() -> Path:
    return ROOT


@pytest.fixture
def runner() -> Path:
    return RUNNER
