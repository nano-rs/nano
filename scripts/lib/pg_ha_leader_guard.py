#!/usr/bin/env python3
"""Pick a switchover candidate before install.sh recreates a Patroni leader (NAN-5263).

A rerun of install.sh on a role-split host recreates every selected service,
including this host's postgres-ha member. Recreating the LEADER costs a failover
(a leader-key timeout of up to 20 s plus promotion) instead of a planned
switchover of about a second. install.sh therefore moves the leader first:

    patronictl -c /run/patroni/patroni.yml list -f json \
        | python3 -I pg_ha_leader_guard.py <this member's name>

Prints one line and exits 0:
  `keep`              this member is not the leader (or the list is empty)
  `alone`             this member leads and no healthy replica can take over
  `switch <member>`   this member leads; switch over to <member> first
Exits 2 on unreadable input.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def _lag_ok(member: dict[str, Any]) -> bool:
    lag = member.get("Replay Lag", member.get("Lag in MB", 0))
    return lag in (0, "0", None, "")


def decide(members: list[dict[str, Any]], me: str) -> str:
    leaders = [m for m in members if m.get("Role") == "Leader"]
    if len(leaders) != 1 or leaders[0].get("Member") != me:
        return "keep"
    healthy = [
        m for m in members
        if m.get("Member") != me
        and m.get("State") == "streaming"
        and _lag_ok(m)
        and m.get("Role") in ("Sync Standby", "Replica", "Quorum Standby")
    ]
    if not healthy:
        return "alone"
    # A synchronous standby already holds every acknowledged commit.
    healthy.sort(key=lambda m: (m.get("Role") != "Sync Standby", str(m.get("Member"))))
    return f"switch {healthy[0].get('Member')}"


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1]:
        print("usage: pg_ha_leader_guard.py MEMBER", file=sys.stderr)
        return 2
    try:
        members = json.loads(sys.stdin.read() or "[]")
    except json.JSONDecodeError:
        print("patronictl returned invalid JSON", file=sys.stderr)
        return 2
    if not isinstance(members, list):
        print("patronictl returned an invalid member list", file=sys.stderr)
        return 2
    print(decide([m for m in members if isinstance(m, dict)], sys.argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
