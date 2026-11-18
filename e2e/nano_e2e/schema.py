"""The stack's schema profile, as the scenarios see it (NAN-5593).

OCSF is the default: nano is OCSF-only for new installs, and `scripts/e2e.sh`
brings stacks up with `NANO_SCHEMA_PROFILE=ocsf` unless the caller sets
`NANO_SCHEMA_PROFILE=udm` explicitly. stack.env carries the stack's profile
into the pytest process.
"""

from __future__ import annotations

import os

DEFAULT_PROFILE = "ocsf"


def profile() -> str:
    return os.environ.get("NANO_SCHEMA_PROFILE") or DEFAULT_PROFILE


def is_ocsf() -> bool:
    return profile().startswith("ocsf")
