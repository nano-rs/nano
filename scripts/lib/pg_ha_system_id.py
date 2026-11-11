#!/usr/bin/env python3
"""Record the PostgreSQL HA cluster's system identifier in the shared .env (NAN-5214).

The bootstrap member refuses to initdb an install whose shared .env names a
system identifier, even when its own state volume and every peer are gone.
install.sh and nano-upgrade call this after a member runs:

    pg_controldata -D <data> | python3 -I pg_ha_system_id.py <.env>

Exit 0 and print `recorded <id>` (written in place; copy .env to every host) or
`unchanged <id>`. Exit 3 when .env already names a DIFFERENT identifier (never
overwritten: this host holds another cluster's data). Exit 4 when the input
has no identifier yet (the member is still cloning or waiting).
"""

from __future__ import annotations

import contextlib
import os
import re
import sys
import tempfile
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


def record(env_path: Path, observed: str) -> None:
    """Write KEY=observed without reordering the file (NAN-5251).

    A key that is absent is appended (a symlinked .env stays a link and keeps
    its mode). An empty assignment already in the file (`KEY=`) is replaced
    where it stands, through an atomic rewrite of the link's target that keeps
    its mode and owner, so the key never appears twice.
    """
    text = env_path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    present = [i for i, line in enumerate(lines) if line.startswith(f"{KEY}=")]
    if not present:
        separator = "" if text.endswith("\n") or not text else "\n"
        with env_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{separator}{KEY}={observed}\n")
        return
    first = present[0]
    lines[first] = f"{KEY}={observed}\n"
    kept = [line for i, line in enumerate(lines) if i == first or i not in present]
    target = env_path.resolve()
    stat = target.stat()
    fd, tmp = tempfile.mkstemp(prefix=".env.tmp.", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("".join(kept))
        os.chmod(tmp, stat.st_mode & 0o7777)
        with contextlib.suppress(PermissionError):
            os.chown(tmp, stat.st_uid, stat.st_gid)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


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
        record(env_path, observed)
        print(f"recorded {observed}")
    else:
        print(f"unchanged {observed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
