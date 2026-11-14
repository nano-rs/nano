#!/usr/bin/env python3
"""Decisions for pinning nano's single-host Compose network (NAN-5387).

ClickHouse users accept connections only from loopback and the networks nano's
own services run on (NAN-5367, scripts/lib/clickhouse_networks.py). Without a
pinned subnet that list had to be Docker's whole address pools, because
`docker compose down && up` may give the network a different subnet from them.
With Docker's built-in pools that is 172.16.0.0/12 and 192.168.0.0/16: every
host on a 192.168.x LAN passed ClickHouse's network check.

install.sh (scripts/lib/network-pin.sh) therefore creates nano's default
network itself, with a fixed subnet, instead of letting Compose create it. A
network Compose did not create carries no Compose config hash, so EVERY
Compose invocation (install.sh, scripts/nano, nano upgrade, a bare
`docker compose -f docker-compose.opensource.yml up -d`) reuses it as it is,
and `docker compose down` leaves it in place. No overlay is involved, so no
Compose command can replace the network behind install.sh's back. That
matters beyond the allow-list: Compose reconnects the containers it does not
recreate WITHOUT their service DNS aliases when it replaces a network.

This module holds the pure decisions; network-pin.sh runs the Docker commands.

CLI:
    compose_network_pin.py plan-config --compose-config FILE
        -> "pinnable<TAB><default network name><TAB><project>" or
           "managed<TAB><name nano's own network would have><TAB><project><TAB><reason>"
    compose_network_pin.py choose [--recorded CIDR] [--existing "CIDR ..."] [--allocated CIDR]
        -> the subnet to pin; exit 3 (reason on stderr) when none is usable
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

SKIP = 3
# Narrower than a /28 leaves too few addresses for nano's ~20 containers plus
# recreations; wider than a /8 is not a pin.
MIN_PREFIX, MAX_PREFIX = 8, 28
# Labels on the network install.sh creates. Compose (v2.24+) refuses a network
# whose com.docker.compose.network label names another network; the project
# label is deliberately absent so `docker compose down` does not remove it.
PIN_LABEL = "sh.nano.network-pin"
COMPOSE_NETWORK_LABEL = "com.docker.compose.network"


class PinError(ValueError):
    pass


def project_network(config: dict) -> str:
    """The name Compose gives the project's default network: <project>_default."""
    project = config.get("name") if isinstance(config, dict) else None
    if not isinstance(project, str) or not project:
        raise PinError("the Compose config has no project name")
    return f"{project}_default"


def network_name(config: dict) -> str:
    """The `default` network's name, when nano may pin it."""
    networks = config.get("networks") if isinstance(config, dict) else None
    if not isinstance(networks, dict) or "default" not in networks:
        raise PinError("the Compose config declares no default network")
    extra = sorted(name for name in networks if name != "default")
    if extra:
        raise PinError(f"the Compose files declare other networks ({', '.join(extra)}); nano does not pin them")
    net = networks.get("default") or {}
    if net.get("external"):
        raise PinError("the default network is external (operator-managed)")
    driver = net.get("driver")
    if driver not in (None, "", "bridge"):
        raise PinError(f"the default network uses the {driver!r} driver")
    for entry in ((net.get("ipam") or {}).get("config") or []):
        if isinstance(entry, dict) and entry.get("subnet"):
            raise PinError(f"an overlay already pins the default network to {entry['subnet']}")
    if net.get("enable_ipv6"):
        raise PinError("the default network has IPv6 enabled")
    name = net.get("name")
    if not isinstance(name, str) or not name:
        raise PinError("the default network has no name in the Compose config")
    return name


def plan_config(config: dict) -> list[str]:
    """`["pinnable", name, project]` or `["managed", nano's network, project, reason]`."""
    project = project_network(config).removesuffix("_default")
    try:
        return ["pinnable", network_name(config), project]
    except PinError as reason:
        # Where nano's pinned network lives, so install.sh can release it
        # when the operator's Compose files take the network over.
        return ["managed", project_network(config), project, str(reason)]


def valid_subnet(value: str, label: str) -> str:
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise PinError(f"{label} {value!r} is not a CIDR") from None
    if net.version != 4:
        raise PinError(f"{label} {value!r} is not IPv4")
    if not MIN_PREFIX <= net.prefixlen <= MAX_PREFIX:
        raise PinError(f"{label} {value!r} must be a /{MIN_PREFIX} to /{MAX_PREFIX}")
    return str(net)


def choose(recorded: str = "", existing: str = "", allocated: str = "") -> str:
    """The subnet to pin, in order: recorded, the live network's, newly allocated."""
    if recorded.strip():
        return valid_subnet(recorded, "NANO_COMPOSE_SUBNET")
    live = existing.split()
    if live:
        if len(live) != 1:
            raise PinError(f"the existing network has several subnets ({' '.join(live)})")
        return valid_subnet(live[0], "the existing network's subnet")
    if allocated.strip():
        return valid_subnet(allocated, "the subnet Docker allocated")
    raise PinError("no subnet recorded, in use, or allocated")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p_plan = sub.add_parser("plan-config")
    p_plan.add_argument("--compose-config", required=True, type=Path)
    p_choose = sub.add_parser("choose")
    p_choose.add_argument("--recorded", default="")
    p_choose.add_argument("--existing", default="")
    p_choose.add_argument("--allocated", default="")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan-config":
            try:
                config = json.loads(args.compose_config.read_text(encoding="utf-8") or "{}")
            except (OSError, ValueError) as error:
                raise PinError(f"unreadable Compose config: {error}") from None
            print("\t".join(plan_config(config)))
        else:
            print(choose(args.recorded, args.existing, args.allocated))
    except PinError as error:
        print(f"compose network pin: {error}", file=sys.stderr)
        return SKIP
    return 0


if __name__ == "__main__":
    sys.exit(main())
