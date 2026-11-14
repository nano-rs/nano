#!/usr/bin/env python3
"""Render the per-user ClickHouse <networks> override (NAN-5367).

Every ClickHouse user nano defines (clickhouse/users.d/nanosiem-users.xml)
accepts connections only from the networks this file lists. The checked-in
XML carries a safe fallback (loopback + private address space); each Compose
deployment path renders a later-loading users.d file that REPLACES every
user's <networks> with the addresses that deployment actually uses:

  * single-host Compose (install.sh): loopback + the Docker address pools the
    Compose network is allocated from. The pools, not the network's current
    subnet, because `docker compose down && up` may allocate a different
    subnet from the same pools, and a stale subnet would lock the app out.
  * role-split (render-inventory.py): loopback + every inventory host address,
    plus the local Docker pools on a host that also runs bridge-network
    services which reach ClickHouse through the host address.

Operators who point an external direct-OCSF writer (Tenzir, Cribl) at
ClickHouse from outside those networks add it to the ingest allow-list, which
widens ONLY `nanosiem_ingest`. An any-address entry (prefix length 0) is
refused everywhere.

CLI (install.sh):
    clickhouse_networks.py --users-xml clickhouse/users.d/nanosiem-users.xml \
        --output .nano-generated/clickhouse/networks.xml \
        --docker-pools-json "$(docker info --format '{{json .DefaultAddressPools}}')" \
        [--network CIDR ...] [--ingest-networks "cidr,cidr"]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

INGEST_USER = "nanosiem_ingest"
LOOPBACK = ("127.0.0.1", "::1")
# Docker's built-in default-address-pools (used when the daemon has none
# configured): 172.17.0.0/16 for the default bridge, 172.18-31.0.0/16 and
# 192.168.0.0/16 (in /20s) for user-defined networks such as Compose's.
DOCKER_DEFAULT_POOLS = ("172.16.0.0/12", "192.168.0.0/16")
# Inventory/host names are DNS names: ClickHouse matches <host> by forward
# resolution. Same character set as render-inventory.py's NAME_RE.
_HOST_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$")


class NetworkError(ValueError):
    pass


def normalize(entry: str, label: str = "network") -> tuple[str, str]:
    """Return ("ip", canonical) for an IP/CIDR or ("host", name) for a DNS name.

    Refuses anything that would admit every address.
    """
    value = entry.strip()
    if not value:
        raise NetworkError(f"{label}: empty entry")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        if value.lower() in {"*", "any", "localhost"} or not _HOST_RE.fullmatch(value) or value[-1] == ".":
            raise NetworkError(f"{label}: {value!r} is not an IP, CIDR or DNS name") from None
        if re.fullmatch(r"[0-9.]+", value):
            raise NetworkError(f"{label}: {value!r} is not a valid IPv4 address or CIDR") from None
        return ("host", value.lower())
    if network.prefixlen == 0 or network.is_unspecified:
        raise NetworkError(
            f"{label}: {value!r} admits every address; list the specific networks instead"
        )
    if network.num_addresses == 1:
        return ("ip", str(network.network_address))
    return ("ip", str(network))


def split_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [part for part in re.split(r"[,\s]+", value.strip()) if part]


def docker_pools(pools_json: str | None) -> list[str]:
    """CIDRs Docker allocates network subnets from (`docker info` DefaultAddressPools)."""
    text = (pools_json or "").strip()
    if not text or text in {"null", "<no value>", "[]"}:
        return list(DOCKER_DEFAULT_POOLS)
    try:
        pools = json.loads(text)
    except json.JSONDecodeError:
        # An older Docker without the field, or a wrapper that printed
        # something else: Docker's built-in pools are the safe answer.
        print(f"clickhouse networks: unreadable Docker address pools ({text[:80]!r}); "
              "using Docker's defaults", file=sys.stderr)
        return list(DOCKER_DEFAULT_POOLS)
    out: list[str] = []
    for pool in pools if isinstance(pools, list) else []:
        base = pool.get("Base") if isinstance(pool, dict) else None
        if not isinstance(base, str):
            raise NetworkError(f"docker address pools: unexpected entry {pool!r}")
        out.append(base)
    # Configured pools REPLACE Docker's defaults for new networks, but a
    # network created before the change keeps its old subnet; the caller adds
    # the live subnets too.
    return out or list(DOCKER_DEFAULT_POOLS)


def compose_ipam_subnets(config_path: Path | None) -> list[str]:
    """Subnets pinned by IPAM in `docker compose config --format json` output.

    An unreadable or empty file yields none (the Docker pools still apply).
    """
    if config_path is None:
        return []
    try:
        cfg = json.loads(config_path.read_text(encoding="utf-8") or "{}")
    except (OSError, ValueError):
        return []
    out: list[str] = []
    for net in (cfg.get("networks") or {}).values() if isinstance(cfg, dict) else []:
        for entry in ((net or {}).get("ipam") or {}).get("config") or []:
            subnet = (entry or {}).get("subnet") if isinstance(entry, dict) else None
            if isinstance(subnet, str) and subnet:
                out.append(subnet)
    return out


def users_with_networks(users_xml: Path) -> list[str]:
    """The users the base users.d file defines (each gets a <networks> override)."""
    root = ET.parse(users_xml).getroot()
    users = root.find("users")
    if users is None:
        raise NetworkError(f"{users_xml}: no <users> element")
    names = [user.tag for user in users if isinstance(user.tag, str) and user.find("password") is not None]
    if not names:
        raise NetworkError(f"{users_xml}: defines no password-authenticated users")
    return names


def _dedupe(entries: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    out = []
    for item in entries:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def build(
    users: list[str],
    networks: list[str],
    ingest_networks: list[str] | None = None,
    *,
    comment: str = "",
) -> ET.Element:
    """users.d XML that replaces every listed user's <networks>."""
    common = _dedupe([normalize(n) for n in (*LOOPBACK, *networks)])
    ingest_extra = [normalize(n, "ingest network") for n in (ingest_networks or [])]
    root = ET.Element("clickhouse")
    if comment:
        root.append(ET.Comment(f" {comment} "))
    users_el = ET.SubElement(root, "users")
    for user in users:
        entries = common + ingest_extra if user == INGEST_USER else common
        nets = ET.SubElement(ET.SubElement(users_el, user), "networks", replace="replace")
        for kind, value in _dedupe(entries):
            ET.SubElement(nets, kind).text = value
    return root


def write(root: ET.Element, path: Path) -> bool:
    """Write atomically-enough for a bind mount; return True when content changed.

    Compose bind-mounts this single file, so it is rewritten IN PLACE (a rename
    would leave the container on the old inode). ClickHouse reloads users.d
    within seconds of the change.
    """
    ET.indent(root, space="  ")
    text = '<?xml version="1.0"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        with open(path, "r+", encoding="utf-8") as handle:
            handle.seek(0)
            handle.write(text)
            handle.truncate()
    else:
        fd, tmp = tempfile.mkstemp(prefix=".networks.", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--users-xml", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--docker-pools-json", default=None,
                        help="`docker info --format '{{json .DefaultAddressPools}}'` output")
    parser.add_argument("--network", action="append", default=[],
                        help="extra network for every user (e.g. a custom Compose subnet)")
    parser.add_argument("--compose-config", type=Path, default=None,
                        help="`docker compose config --format json` output: IPAM subnets are admitted")
    parser.add_argument("--ingest-networks", default="",
                        help="comma/space separated allow-list for nanosiem_ingest only")
    args = parser.parse_args(argv)
    try:
        users = users_with_networks(args.users_xml)
        networks = (
            docker_pools(args.docker_pools_json)
            + compose_ipam_subnets(args.compose_config)
            + list(args.network)
        )
        root = build(
            users,
            networks,
            split_list(args.ingest_networks),
            comment="Generated by install.sh (scripts/lib/clickhouse_networks.py, NAN-5367). Do not edit; "
            "set NANO_CLICKHOUSE_INGEST_ALLOWED_NETWORKS in .env and re-run install.sh.",
        )
        changed = write(root, args.output)
    except (NetworkError, ET.ParseError, OSError) as error:
        print(f"clickhouse networks: {error}", file=sys.stderr)
        return 1
    print("changed" if changed else "unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
