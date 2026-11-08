"""Deterministic run markers and cloud resource names.

Every event a scenario sends carries a marker derived from the run id and the
test's node id, and every assertion filters by it, so no test ever reads
another test's (or another run's) rows. Cloud resources are named
`nano-e2e-<runid>-<kind>-<hash>` so `scripts/e2e.sh gc --cloud` can find
stragglers by prefix.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets

CLOUD_PREFIX = "nano-e2e-"

# One nonce per pytest session: re-running a test against the same live stack
# (`run --run <id>`) must not read the previous attempt's rows, and AWS refuses
# to recreate a queue name for 60s after deleting it. Pin with E2E_SESSION to
# reproduce names exactly.
SESSION = os.environ.get("E2E_SESSION") or secrets.token_hex(3)


def run_id() -> str:
    return os.environ.get("E2E_RUN_ID", "local-00000000")


def _digest(*parts: str, n: int = 8) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:n]


def marker(nodeid: str, label: str = "") -> str:
    """`nano-e2e-<runid>-<hash>`: unique per (run, session, test, label)."""
    return f"{CLOUD_PREFIX}{run_id()}-{_digest(SESSION, nodeid, label)}"


def route_key(nodeid: str, label: str = "") -> str:
    """A log-source route key / source_type: lowercase identifier, unique per test."""
    return f"e2e_{_digest(run_id(), SESSION, nodeid, label, n=10)}"


def cloud_name(kind: str, nodeid: str, max_len: int = 63) -> str:
    """Cloud resource name: lowercase, [a-z0-9-], <= max_len, prefixed nano-e2e-<runid>."""
    kind = re.sub(r"[^a-z0-9-]", "-", kind.lower())
    name = f"{CLOUD_PREFIX}{run_id()}-{kind}-{_digest(SESSION, nodeid, kind, n=6)}"
    return name[:max_len].rstrip("-")


# ---------------------------------------------------------------- ownership
# Every cloud resource the harness creates carries these tags/labels (or the
# provider's equivalent). GC deletes ONLY resources carrying all three, whose
# run is not active and whose creation stamp is past the cutoff: the name
# prefix alone never authorizes a deletion.
OWNER_TAG = "nano-e2e"
RUN_TAG = "nano-e2e-run"
CREATED_TAG = "nano-e2e-created"
MIN_GC_HOURS = 1


def owner_tags() -> dict[str, str]:
    import time

    return {OWNER_TAG: "1", RUN_TAG: run_id(), CREATED_TAG: str(int(time.time()))}


def gc_eligible(name: str, tags: dict[str, str], *, cutoff_epoch: float, exclude_runs: set[str]) -> bool:
    """True only for a resource this harness provably created, for a run that is
    not active, older than the cutoff."""
    if not name.startswith(CLOUD_PREFIX) or tags.get(OWNER_TAG) != "1":
        return False
    run = tags.get(RUN_TAG, "")
    if not run or run in exclude_runs or not name.startswith(f"{CLOUD_PREFIX}{run}-"):
        return False
    try:
        created = int(tags.get(CREATED_TAG, ""))
    except ValueError:
        return False
    return 0 < created < cutoff_epoch
