"""Attach a standalone tool to a KEPT e2e stack (NAN-5291).

The persona-exploration tools (`nano_e2e.explore`, `nano_e2e.field_invariants`,
`nano_e2e.corpus`) run outside pytest against a stack that `scripts/e2e.sh up`
or `run ... --keep` left behind. They read the same stack.env the scenarios
read, located the same way the runner does (`scripts/e2e.sh env [--run <id>]`),
so a tool can never point at a stack the runner does not own (the nanoch-* dev
stack has no stack.env).

Values are loaded into this process's environment only; nothing is printed.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from nano_e2e.stack import Stack

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "e2e.sh"


def parse(text: str) -> dict[str, str]:
    """KEY=VALUE lines of a stack.env (written with printf '%s=%s', unquoted)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.replace("_", "").isalnum():
            out[key] = value
    return out


def locate(run_id: str | None = None, env_file: str | None = None) -> Path:
    """The stack.env path: explicit file, $E2E_STACK_ENV, else the runner's answer."""
    explicit = env_file or os.environ.get("E2E_STACK_ENV", "")
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise FileNotFoundError(f"stack.env not found: {path}")
        return path
    argv = [str(RUNNER), "env"] + (["--run", run_id] if run_id else [])
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603
    if proc.returncode != 0:
        raise RuntimeError(
            "no kept e2e stack found (`scripts/e2e.sh env` failed). Bring one up with "
            "`scripts/e2e.sh run personas --fresh --keep ...` or `scripts/e2e.sh up`; "
            f"pass --run <id> to pick one. Runner said: {proc.stderr.strip()[-400:]}"
        )
    return Path(proc.stdout.strip().splitlines()[-1])


def load(run_id: str | None = None, env_file: str | None = None) -> Stack:
    """Load the stack's env into os.environ and return its Stack."""
    values = parse(locate(run_id, env_file).read_text())
    os.environ.update(values)
    return Stack.from_env()
