#!/usr/bin/env python3
"""Record the PostgreSQL HA cluster's system identifier in the shared .env (NAN-5214).

The bootstrap member refuses to initdb an install whose shared .env names a
system identifier, even when its own state volume and every peer are gone.
install.sh and nano-upgrade call this after a member runs:

    pg_controldata -D <data> | python3 -I pg_ha_system_id.py <.env>

Exit 0 and print `recorded <id>` (appended; copy .env to every host) or
`unchanged <id>`. Exit 3 when .env already names a DIFFERENT identifier (never
overwritten: this host holds another cluster's data). Exit 4 when the input
has no identifier yet (the member is still cloning or waiting).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

KEY = "NANO_PG_HA_SYSTEM_ID"


class SystemIdConflict(Exception):
    pass


def parse_system_id(controldata: str) -> str | None:
    match = re.search(r"^Database system identifier:\s*(\d+)\s*$", controldata, re.MULTILINE)
    return match.group(1) if match else None


def recorded_value(env_text: str) -> str | None:
    value = None
    for line in env_text.splitlines():
        if line.startswith(f"{KEY}="):
            value = line.split("=", 1)[1].strip().strip("\"'") or None
    return value


def decide(existing: str | None, observed: str) -> str:
    """'record' or 'unchanged'; raises SystemIdConflict when they differ."""
    if existing is None:
        return "record"
    if existing == observed:
        return "unchanged"
    raise SystemIdConflict(
        f"the shared .env records {KEY}={existing} but this member's data is cluster {observed}"
    )


def main() -> int:
    env_path = Path(sys.argv[1])
    observed = parse_system_id(sys.stdin.read())
    if observed is None:
        print("pending")
        return 4
    try:
        action = decide(recorded_value(env_path.read_text(encoding="utf-8")), observed)
    except SystemIdConflict as error:
        print(f"conflict {error}")
        return 3
    if action == "record":
        text = env_path.read_text(encoding="utf-8")
        separator = "" if text.endswith("\n") or not text else "\n"
        # Append (as install.sh does): keeps a symlinked .env a link and its mode.
        with env_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{separator}{KEY}={observed}\n")
        print(f"recorded {observed}")
    else:
        print(f"unchanged {observed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
