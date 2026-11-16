#!/usr/bin/env python3
"""Render the per-user ClickHouse <networks> override (NAN-5367).

Every ClickHouse user nano defines (clickhouse/users.d/nanosiem-users.xml)
accepts connections only from the networks this file lists. The checked-in
XML carries a safe fallback (loopback + private address space); each Compose
deployment path renders a later-loading users.d file that REPLACES every
user's <networks> with the addresses that deployment actually uses:

  * single-host Compose (install.sh): loopback + the subnet install.sh pins
    nano's Compose network to (NAN-5387, scripts/lib/compose_network_pin.py:
    `--compose-subnet`), plus the network's live subnets. Where the operator's
    Compose files manage the network themselves (nothing pinned), the Docker
    address pools the network is allocated from instead: the pools, not the
    network's current subnet, because `docker compose down && up` may allocate
    a different subnet from the same pools, and a stale subnet would lock the
    app out.
  * role-split (render-inventory.py): loopback + every inventory host address,
    plus the local Docker pools on a host that also runs bridge-network
    services which reach ClickHouse through the host address.

Operators who point an external direct-OCSF writer (Tenzir, Cribl) at
ClickHouse from outside those networks add it to the ingest allow-list, which
widens ONLY `nanosiem_ingest`. An any-address entry (prefix length 0) is
refused everywhere.

CLI:
    clickhouse_networks.py --users-xml clickhouse/users.d/nanosiem-users.xml \
        --output .nano-generated/clickhouse/networks.xml \
        [--workload-template clickhouse/workload-users/nanosiem-workload-users.xml \
         --workload-env-file .env --users-dir-output .nano-generated/clickhouse/users.d] \
        (--compose-subnet CIDR | --docker-pools-json "$(docker info --format '{{json .DefaultAddressPools}}')") \
        [--network CIDR ...] [--ingest-networks "cidr,cidr"]

    install.sh and `scripts/nano upgrade` (NAN-5435) let it read Docker itself,
    so both render the same list from the same inputs:
    clickhouse_networks.py --users-xml ... --output ... [--compose-subnet CIDR] \
        [--ingest-networks ...] --from-docker -- <docker compose args...>
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
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


def _user_elements(users_xml: Path) -> list[ET.Element]:
    root = ET.parse(users_xml).getroot()
    users = root.find("users")
    if users is None:
        raise NetworkError(f"{users_xml}: no <users> element")
    found = [user for user in users if isinstance(user.tag, str) and user.find("password") is not None]
    if not found:
        raise NetworkError(f"{users_xml}: defines no password-authenticated users")
    return found


def users_with_networks(*users_xml: Path) -> list[str]:
    """The users the given users.d files define (each gets a <networks> override)."""
    names: list[str] = []
    for path in users_xml:
        for user in _user_elements(path):
            if user.tag not in names:
                names.append(user.tag)
    return names


WORKLOAD_PLACEHOLDER = "rendered by scripts/lib/clickhouse_networks.py"


def dotenv_values(path: Path) -> dict[str, str]:
    """KEY=VALUE lines of a .env (last wins, surrounding quotes removed)."""
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key] = value
    return values


def workload_users(
    template: Path, env: dict[str, str], networks: list[str],
    per_user: dict[str, list[str]] | None = None,
) -> ET.Element:
    """NAN-5470: the workload identities as a complete users.d file.

    The template (clickhouse/workload-users/nanosiem-workload-users.xml) names
    each password's .env key in `<password from_env=...>`; ClickHouse would
    load an unset `from_env` password as EMPTY (verified on 26.10). This
    renders the SHA-256 of the value instead, so the file never depends on the
    container's environment: it is safe to load live, at any time, before or
    after ClickHouse is recreated. A missing or empty password is an error,
    never a user without one. `networks` replaces the template's fallback
    list (the same one every other nano user gets)."""
    import hashlib

    root = ET.parse(template).getroot()
    users = root.find("users")
    if users is None:
        raise NetworkError(f"{template}: no <users> element")
    for user in users:
        if not isinstance(user.tag, str):
            continue
        password = user.find("password")
        key = password.get("from_env", "") if password is not None else ""
        value = env.get(key, "") if key else ""
        if not value.strip():
            raise NetworkError(f"{user.tag}: {key or 'its password key'} is not set in .env (install.sh generates it)")
        if "$" in value:
            # Compose interpolates `$` in .env values, so the app would log in
            # with a different password than the one hashed here.
            raise NetworkError(f"{key} contains '$', which Docker Compose interpolates; set a value without '$' "
                               "(install.sh generates hex values)")
        user.remove(password)
        ET.SubElement(user, "password_sha256_hex").text = hashlib.sha256(value.encode()).hexdigest()
        # `per_user` narrows one user's list (role-split: nanosiem_dict only
        # from the ClickHouse servers, which run the dictionary sources).
        own = (per_user or {}).get(user.tag, networks)
        if own:
            old = user.find("networks")
            if old is not None:
                user.remove(old)
            nets = ET.SubElement(user, "networks")
            for kind, entry in _dedupe(own):
                ET.SubElement(nets, kind).text = entry
    # Comments in the template (documentation) stay in the source tree.
    for parent in [root, users]:
        for child in list(parent):
            if not isinstance(child.tag, str):
                parent.remove(child)
    root.insert(0, ET.Comment(f" {WORKLOAD_PLACEHOLDER} from clickhouse/workload-users (NAN-5470). Do not edit. "))
    return root


def rehash_workload(template: Path, env: dict[str, str], rendered: Path) -> bool:
    """NAN-5470: set the password hashes of an already rendered workload file
    from `env`, keeping its networks (a restore that replaced .env on a
    role-split ClickHouse host, whose networks render-inventory.py chose).
    A missing user or password is an error. Returns True when it changed."""
    import hashlib

    keys = {}
    template_users = ET.parse(template).getroot().find("users")
    for user in template_users if template_users is not None else []:
        if isinstance(user.tag, str) and user.find("password") is not None:
            keys[user.tag] = user.find("password").get("from_env", "")
    root = ET.parse(rendered).getroot()
    users = root.find("users")
    for name, key in keys.items():
        user = users.find(name) if users is not None else None
        if user is None or user.find("password_sha256_hex") is None:
            raise NetworkError(f"{rendered}: no rendered {name}; re-run the inventory render")
        value = env.get(key, "")
        if not value.strip() or "$" in value:
            raise NetworkError(f"{key} is missing, empty or contains '$' in .env")
        user.find("password_sha256_hex").text = hashlib.sha256(value.encode()).hexdigest()
    return write(root, rendered)


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


# NAN-5470: the rendered users.d that ClickHouse mounts (single node). Built
# from the shipped clickhouse/users.d plus the workload identities, under
# .nano-generated/, which no installer package contains: extracting a package
# (tar unlinks and recreates every shipped file) never touches it.
# NAN-5494: the networks and sizing files are copied INTO it as plain files
# (scripts/lib/clickhouse_config_dirs.py), never bind-mounted over a file in
# it: a file mounted over a placeholder is detached when the placeholder is
# replaced, and ClickHouse then reloads the placeholder (every user widened to
# the private ranges, sizing reverted).
WORKLOAD_FILE_NAME = "nanosiem-workload-users.xml"


def _config_dirs():
    """scripts/lib/clickhouse_config_dirs.py (loaded by path: `python3 -I`
    leaves the script directory off sys.path)."""
    import importlib.util

    name = "nano_clickhouse_config_dirs"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parent / "clickhouse_config_dirs.py")
    if spec is None or spec.loader is None:
        raise NetworkError("scripts/lib/clickhouse_config_dirs.py is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _xml_bytes(root: ET.Element) -> bytes:
    ET.indent(root, space="  ")
    return ('<?xml version="1.0"?>\n' + ET.tostring(root, encoding="unicode") + "\n").encode()


def sync_users_dir(
    source: Path, output: Path, workload: ET.Element | None,
    *, networks: Path | None = None, env_file: Path | None = None,
) -> bool:
    """Publish `output`: the shipped users.d plus the networks and sizing
    files and the workload identities, all copied in (clickhouse_config_dirs.py
    builds the tree beside the live one and swaps it in, so a running
    ClickHouse never reads a half-written or changed tree).

    `networks` is the rendered allow-list; the sizing file is found from
    `env_file` (NANO_SIZING_DIR, relative to the .env's directory). Returns
    True when anything changed."""
    module = _config_dirs()
    root = env_file.parent if env_file is not None else output.parent
    env = module.dotenv_values(env_file) if env_file is not None else {}
    try:
        return module.assemble_users(
            root, env, output=output, source=source, networks=networks,
            workload=_xml_bytes(workload) if workload is not None else b"",
        )
    except module.AssembleError as error:
        raise NetworkError(str(error)) from None


CLICKHOUSE_CONTAINER = "nano-clickhouse"


def _docker(arguments: list[str]) -> str:
    """stdout of a docker command, "" when it fails (the caller's fallbacks apply)."""
    try:
        result = subprocess.run(
            ["docker", *arguments], stdin=subprocess.DEVNULL, capture_output=True,
            text=True, timeout=120, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def discover_docker(compose_args: list[str], scratch_dir: Path) -> tuple[str, list[str], Path]:
    """Read the Docker inputs of a single-host render (NAN-5435).

    Returns the daemon's address pools (`docker info` JSON), the live subnets
    of the networks nano's ClickHouse container runs on, and the effective
    Compose config written to a file in `scratch_dir` (IPAM subnets an overlay
    pins are admitted, so a fresh install and a down/up after a subnet change
    are covered, not only a running container's current network). The config
    is interpolated (it carries .env secrets), so `scratch_dir` is a private
    temporary directory outside the install tree that the caller removes.
    """
    pools_json = _docker(["info", "--format", "{{json .DefaultAddressPools}}"]).strip()
    live: list[str] = []
    network_ids = _docker([
        "inspect", CLICKHOUSE_CONTAINER, "--format",
        "{{range .NetworkSettings.Networks}}{{.NetworkID}} {{end}}",
    ]).split()
    for network_id in network_ids:
        for subnet in _docker([
            "network", "inspect", network_id, "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}",
        ]).split():
            if re.fullmatch(r"[0-9A-Fa-f:.]+/[0-9]+", subnet):
                live.append(subnet)
    fd, name = tempfile.mkstemp(prefix=".nano-compose-config.", dir=scratch_dir)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(_docker(["compose", *compose_args, "config", "--format", "json"]))
    return pools_json, live, Path(name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--users-xml", type=Path, action="append",
                        help="a users file whose users get the override (repeatable; required unless "
                        "--rehash-workload)")
    parser.add_argument("--rehash-workload", type=Path, default=None,
                        help="NAN-5470: only update the password hashes of this rendered workload file "
                        "from --workload-env-file (keeps its networks)")
    parser.add_argument("--workload-template", type=Path, default=None,
                        help="NAN-5470: clickhouse/workload-users/nanosiem-workload-users.xml")
    parser.add_argument("--workload-env-file", type=Path, default=None,
                        help="the .env holding the workload passwords (read, never printed)")
    parser.add_argument("--workload-output", type=Path, default=None,
                        help="where to write the rendered workload identities")
    parser.add_argument("--users-dir-output", type=Path, default=None,
                        help="NAN-5470: render the users.d ClickHouse mounts (the first --users-xml's "
                        "directory plus the workload identities) into this directory")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--docker-pools-json", default=None,
                        help="`docker info --format '{{json .DefaultAddressPools}}'` output")
    parser.add_argument("--compose-subnet", default="",
                        help="the subnet nano's Compose network is pinned to; replaces the Docker pools")
    parser.add_argument("--network", action="append", default=[],
                        help="extra network for every user (e.g. a custom Compose subnet)")
    parser.add_argument("--compose-config", type=Path, default=None,
                        help="`docker compose config --format json` output: IPAM subnets are admitted")
    parser.add_argument("--ingest-networks", default="",
                        help="comma/space separated allow-list for nanosiem_ingest only")
    parser.add_argument("--from-docker", action="store_true",
                        help="read the pools, ClickHouse's live subnets and the Compose config from "
                        "Docker; the arguments after `--` are the `docker compose` arguments")
    parser.add_argument("compose_args", nargs="*", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.rehash_workload is not None:
        if args.workload_template is None or args.workload_env_file is None:
            parser.error("--rehash-workload needs --workload-template and --workload-env-file")
        try:
            changed = rehash_workload(args.workload_template, dotenv_values(args.workload_env_file),
                                      args.rehash_workload)
        except (NetworkError, ET.ParseError, OSError) as error:
            print(f"clickhouse networks: {error}", file=sys.stderr)
            return 1
        print("changed" if changed else "unchanged")
        return 0
    if not args.users_xml or args.output is None:
        parser.error("--users-xml and --output are required")
    if args.compose_args and not args.from_docker:
        parser.error("compose arguments are only accepted with --from-docker")
    if not args.from_docker:
        return render(args)
    if args.docker_pools_json is not None or args.compose_config is not None:
        parser.error("--from-docker reads the pools and the Compose config itself")
    # mkdtemp is private (0700), outside the install tree, and always removed.
    with tempfile.TemporaryDirectory(prefix="nano-compose-config.") as scratch:
        args.docker_pools_json, live, args.compose_config = discover_docker(
            args.compose_args, Path(scratch),
        )
        args.network = [*live, *args.network]
        return render(args)


def render(args: argparse.Namespace) -> int:
    """Render and write the allow-list from parsed CLI arguments."""
    try:
        users = users_with_networks(*args.users_xml)
        # NAN-5387: a pinned network cannot move, so its subnet replaces the
        # Docker pools (which, unconfigured, include all of 192.168.0.0/16).
        pinned = args.compose_subnet.strip()
        networks = (
            ([pinned] if pinned else docker_pools(args.docker_pools_json))
            + compose_ipam_subnets(args.compose_config)
            + list(args.network)
        )
        root = build(
            users,
            networks,
            split_list(args.ingest_networks),
            comment="Generated by install.sh or scripts/nano upgrade (scripts/lib/clickhouse_networks.py, "
            "NAN-5367). Do not edit; "
            "set NANO_CLICKHOUSE_INGEST_ALLOWED_NETWORKS in .env and re-run install.sh.",
        )
        workload = None
        if args.workload_template is not None:
            if args.workload_env_file is None or (args.workload_output is None and args.users_dir_output is None):
                raise NetworkError(
                    "--workload-template needs --workload-env-file and --workload-output or --users-dir-output"
                )
            common = [normalize(n) for n in (*LOOPBACK, *networks)]
            workload = workload_users(args.workload_template, dotenv_values(args.workload_env_file), common)
        changed = write(root, args.output)
        if workload is not None and args.workload_output is not None:
            changed = write(workload, args.workload_output) or changed
        if args.users_dir_output is not None:
            changed = sync_users_dir(
                args.users_xml[0].parent, args.users_dir_output, workload,
                networks=args.output, env_file=args.workload_env_file,
            ) or changed
    except (NetworkError, ET.ParseError, OSError) as error:
        print(f"clickhouse networks: {error}", file=sys.stderr)
        return 1
    print("changed" if changed else "unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
