#!/usr/bin/env python3
"""Assemble the config.d and users.d ClickHouse mounts (single host, NAN-5494).

ClickHouse on a single-host Compose install mounts exactly two configuration
DIRECTORIES, both under .nano-generated/, which no installer package contains:

    .nano-generated/clickhouse/config.d  ->  /etc/clickhouse-server/config.d
    .nano-generated/clickhouse/users.d   ->  /etc/clickhouse-server/users.d

Each is the shipped directory (clickhouse/config.d, clickhouse/users.d,
including any operator drop-in placed there) plus the per-install files
install.sh and `scripts/nano upgrade` render, copied in as plain files:

    config.d/zzzz-nano-sizing.xml    <- .nano-generated/sizing/clickhouse-config.xml
    config.d/zzz-nano-tiering.xml    <- .nano-generated/clickhouse/tiering.xml
    users.d/zzzz-nano-sizing.xml     <- .nano-generated/sizing/clickhouse-users.xml
    users.d/zzzz-nano-networks.xml   <- .nano-generated/clickhouse/networks.xml
    users.d/nanosiem-workload-users.xml  (rendered by clickhouse_networks.py)

Why: up to v2.0.28 Compose bind-mounted each rendered file as a SINGLE FILE
over a placeholder the package shipped inside the mounted directory. Extracting
a package (tar unlinks and recreates every shipped file) detaches such a mount
on Linux, and ClickHouse hot-reloads the empty placeholder: the network pin
widened to every private range and the sizing limits reverted (NAN-5494,
NAN-5479). The shipped placeholder names (LEGACY_MOUNT_TARGETS) are no longer
in any installer package (`exclude` rows in the release bundle manifest), so
an extract over a pre-v2.0.29 server leaves its single-file mounts attached.

Publishing never changes what a RUNNING ClickHouse reads: a changed directory
is built complete beside the live one and swapped in by rename. The running
container's bind mount follows the old directory's inode, so it keeps reading
the complete previous tree (kept under .nano-generated/clickhouse/.retired/
until no running container can still be using it) until it is recreated.
NANO_CLICKHOUSE_CONFIG_SHA256 (the digest of both directories, recorded in
.env and passed to the clickhouse service) changes with the content, so the
next `docker compose up` recreates ClickHouse onto the new tree.

Fail closed: the Compose files default to these directories and refuse to
create them (create_host_path: false), and clickhouse-preflight refuses a
directory without the ASSEMBLED_STAMP this module writes. A manual
`docker compose up` before this release assembled them (an extracted package,
not yet upgraded; a v2.0.28 users.d still holding the empty networks
placeholder) refuses to start ClickHouse instead of widening it.

One nested mount target remains, on the GENERATED config.d only: the v2.0.23-
v2.0.35 Agent Lane overlay (docker-compose.agentlane.yml) mounted its listener
over config.d/zz-agentlane-listener.xml, which every assembled tree
carries as an inert target and no package ships. Since v2.0.36 (NAN-5880)
nothing mounts it any more: install.sh and `nano upgrade` drop that overlay,
and the target stays inert.

NAN-5880: on an ENTERPRISE install (NANO_EDITION=enterprise in the .env) the
assembled config.d also carries zz-agentlane-gate.xml, copied from
deploy/compose/agentlane/clickhouse-gate-listener.xml: the loopback-only
(127.0.0.1:18444) plain HTTP listener the Agent Lane gate forwards to. The
open edition never gets it (and its bundle has no deploy/ to copy it from).

Operator drop-ins: put them in clickhouse/config.d or clickhouse/users.d under
a name the package does not ship (e.g. zz-local-*.xml). Files placed directly
in .nano-generated/ are replaced by the next assemble.

CLI:
    clickhouse_config_dirs.py --root INSTALL_DIR [--env-file FILE] [--record-env]
        [--config-output DIR] [--users-output DIR]
Prints `changed` or `unchanged`, then `sha256=<digest>`. --record-env writes
NANO_CLICKHOUSE_CONFIG_DIR, NANO_CLICKHOUSE_USERS_DIR and
NANO_CLICKHOUSE_CONFIG_SHA256 into the .env. Reads only non-secret files.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping, Union

CONFIG_DIR = ".nano-generated/clickhouse/config.d"
USERS_DIR = ".nano-generated/clickhouse/users.d"
SHIPPED_CONFIG_DIR = "clickhouse/config.d"
SHIPPED_USERS_DIR = "clickhouse/users.d"
WORKLOAD_FILE_NAME = "nanosiem-workload-users.xml"
SIZING_DIR_DEFAULT = ".nano-generated/sizing"
ASSEMBLED_STAMP = ".nano-assembled"
RETIRED_DIR = ".retired"
ENV_CONFIG_DIR = "NANO_CLICKHOUSE_CONFIG_DIR"
ENV_USERS_DIR = "NANO_CLICKHOUSE_USERS_DIR"
ENV_DIGEST = "NANO_CLICKHOUSE_CONFIG_SHA256"

# name in the mounted directory -> (.env key, default source, file inside a
# directory-valued key). The .env keys are the ones Compose files up to
# v2.0.28 interpolated into their single-file mounts, so an install keeps
# whatever sources its .env already names.
CONFIG_OVERLAYS: dict[str, tuple[str, str, str]] = {
    "zzzz-nano-sizing.xml": ("NANO_SIZING_DIR", SIZING_DIR_DEFAULT, "clickhouse-config.xml"),
    "zzz-nano-tiering.xml": ("NANO_CLICKHOUSE_TIERING_FILE", ".nano-generated/clickhouse/tiering.xml", ""),
}
USERS_OVERLAYS: dict[str, tuple[str, str, str]] = {
    "zzzz-nano-sizing.xml": ("NANO_SIZING_DIR", SIZING_DIR_DEFAULT, "clickhouse-users.xml"),
    "zzzz-nano-networks.xml": ("NANO_CLICKHOUSE_NETWORKS_FILE", ".nano-generated/clickhouse/networks.xml", ""),
}
# Nested-mount targets inside the GENERATED config.d (see the module doc).
CONFIG_MOUNT_TARGETS = ("zz-agentlane-listener.xml",)
# NAN-5880: the Agent Lane gate upstream listener (enterprise only).
AGENTLANE_GATE_FILE = "zz-agentlane-gate.xml"
AGENTLANE_GATE_SOURCE = "deploy/compose/agentlane/clickhouse-gate-listener.xml"
# Files the shipped directories still hold as single-file mount targets for
# pre-v2.0.29 Compose files. Kept byte-identical in git (a git-checkout update
# never rewrites an unchanged file), never in a package, never copied: their
# active content comes from the overlays above.
LEGACY_MOUNT_TARGETS: dict[str, tuple[str, ...]] = {
    SHIPPED_CONFIG_DIR: ("zzzz-nano-sizing.xml", "zzz-nano-tiering.xml", "zz-agentlane-listener.xml"),
    SHIPPED_USERS_DIR: ("zzzz-nano-sizing.xml", "zzzz-nano-networks.xml"),
}
INERT = (
    b'<?xml version="1.0"?>\n'
    b"<!-- Generated by scripts/lib/clickhouse_config_dirs.py: nothing rendered for this file. -->\n"
    b"<clickhouse/>\n"
)
# Container destinations whose running containers may still read a retired tree.
_MOUNT_DESTINATIONS = ("/etc/clickhouse-server/config.d", "/etc/clickhouse-server/users.d", "/config.d")
_RETIRED_RE = re.compile(r"^(config\.d|users\.d)-(\d{8}T\d{6}\d{6}Z)-\d+$")

Overlay = Union[Path, bytes, None]


class AssembleError(RuntimeError):
    pass


def dotenv_values(path: Path) -> dict[str, str]:
    """KEY=VALUE lines of a .env (last wins, surrounding quotes removed)."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
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


def overlay_sources(
    root: Path, env: Mapping[str, str], table: Mapping[str, tuple[str, str, str]],
) -> dict[str, Path]:
    """name -> host file each overlay is copied from (it may not exist)."""
    sources: dict[str, Path] = {}
    for name, (key, default, inner) in table.items():
        value = (env.get(key) or "").strip() or default
        path = Path(value)
        if not path.is_absolute():
            path = root / path
        sources[name] = path / inner if inner else path
    return sources


def _overlay_bytes(overlay: Overlay) -> bytes:
    if isinstance(overlay, bytes):
        return overlay
    if overlay is None or not overlay.is_file():
        return INERT
    try:
        return overlay.read_bytes()
    except OSError as error:
        raise AssembleError(f"cannot read {overlay}: {error}") from None


def _stamp(files: Mapping[str, bytes]) -> bytes:
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode() + b"\0" + hashlib.sha256(files[name]).digest())
    return json.dumps({"format": "nano-clickhouse-assembled-v1", "sha256": digest.hexdigest()}).encode() + b"\n"


def _live_files(output: Path) -> dict[str, bytes] | None:
    if not output.is_dir() or not (output / ASSEMBLED_STAMP).is_file():
        return None
    try:
        return {item.name: item.read_bytes() for item in output.iterdir() if item.suffix == ".xml" and item.is_file()}
    except OSError:
        return None


def _now_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _running_mount_creation_times() -> list[dt.datetime] | None:
    """Creation times of running containers that mount a ClickHouse config
    directory; None when Docker cannot be asked (then nothing is pruned)."""
    try:
        ids = subprocess.run(
            ["docker", "ps", "-q"], capture_output=True, text=True, timeout=30, check=True,
            stdin=subprocess.DEVNULL,
        ).stdout.split()
        if not ids:
            return []
        inspected = json.loads(subprocess.run(
            ["docker", "inspect", *ids], capture_output=True, text=True, timeout=60, check=True,
            stdin=subprocess.DEVNULL,
        ).stdout or "[]")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
    times = []
    for container in inspected:
        mounts = container.get("Mounts") or []
        if not any(m.get("Destination") in _MOUNT_DESTINATIONS for m in mounts if isinstance(m, dict)):
            continue
        created = str(container.get("Created", ""))
        match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?", created)
        if not match:
            return None
        fraction = (match.group(2) or ".0")[1:7].ljust(6, "0")
        times.append(dt.datetime.strptime(f"{match.group(1)}.{fraction}", "%Y-%m-%dT%H:%M:%S.%f")
                     .replace(tzinfo=dt.timezone.utc))
    return times


def prune_retired(parent: Path) -> None:
    """Remove retired trees no running container can still be reading: a
    tree retired at T is unused once every running container that mounts a
    ClickHouse config directory was created after T. Unknown keeps them."""
    retired = parent / RETIRED_DIR
    if not retired.is_dir():
        return
    entries = [(item, _RETIRED_RE.match(item.name)) for item in retired.iterdir()]
    entries = [(item, match) for item, match in entries if match]
    if not entries:
        return
    created = _running_mount_creation_times()
    if created is None:
        return
    for item, match in entries:
        when = dt.datetime.strptime(match.group(2), "%Y%m%dT%H%M%S%fZ").replace(tzinfo=dt.timezone.utc)
        if all(time > when for time in created):
            shutil.rmtree(item, ignore_errors=True)


def publish_dir(output: Path, files: Mapping[str, bytes]) -> bool:
    """Make `output` hold exactly `files` (+ the stamp). Unchanged: nothing is
    touched. Changed: a complete tree is built beside it and swapped in by
    rename; the previous tree is retired, never modified."""
    if _live_files(output) == dict(files):
        return False
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    try:
        for name, data in sorted(files.items()):
            (staging / name).write_bytes(data)
            os.chmod(staging / name, 0o644)
        (staging / ASSEMBLED_STAMP).write_bytes(_stamp(files))
        os.chmod(staging / ASSEMBLED_STAMP, 0o644)
        os.chmod(staging, 0o755)
        if output.exists() or output.is_symlink():
            retired = output.parent / RETIRED_DIR
            retired.mkdir(mode=0o755, exist_ok=True)
            os.replace(output, retired / f"{output.name}-{_now_stamp()}-{os.getpid()}")
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    prune_retired(output.parent)
    return True


def dir_files(
    source: Path,
    overlays: Mapping[str, Overlay],
    *,
    keep: Mapping[str, bytes] | None = None,
    mount_targets: tuple[str, ...] = (),
    skip: tuple[str, ...] = (),
) -> dict[str, bytes]:
    """The shipped `source` *.xml files (minus `skip`), the `overlays` (a
    path to copy, rendered bytes, or None / a missing path for an inert
    file), `keep` (files another writer owns) and inert `mount_targets`."""
    if not source.is_dir():
        raise AssembleError(f"shipped directory missing: {source}")
    keep = dict(keep or {})
    reserved = set(overlays) | set(keep) | set(mount_targets) | set(skip)
    files = {
        item.name: item.read_bytes() for item in sorted(source.iterdir())
        if item.is_file() and item.suffix == ".xml" and item.name not in reserved
    }
    for name, overlay in overlays.items():
        files[name] = _overlay_bytes(overlay)
    files.update(keep)
    for name in mount_targets:
        files[name] = INERT
    return files


def users_files(
    root: Path, env: Mapping[str, str], *, source: Path | None = None,
    networks: Overlay = None, workload: bytes | None = None, live: Path | None = None,
) -> dict[str, bytes]:
    """users.d: shipped users + networks/sizing overlays + the workload
    identities (`workload` bytes; None keeps the file the live tree has)."""
    overlays: dict[str, Overlay] = dict(overlay_sources(root, env, USERS_OVERLAYS))
    if networks is not None:
        overlays["zzzz-nano-networks.xml"] = networks
    keep: dict[str, bytes] = {}
    if workload is not None:
        # b"": the caller renders no workload identities (the file goes).
        if workload:
            keep[WORKLOAD_FILE_NAME] = workload
    else:
        existing = (live or root / USERS_DIR) / WORKLOAD_FILE_NAME
        if existing.is_file():
            keep[WORKLOAD_FILE_NAME] = existing.read_bytes()
    return dir_files(source or root / SHIPPED_USERS_DIR, overlays, keep=keep,
                     skip=LEGACY_MOUNT_TARGETS[SHIPPED_USERS_DIR] + (WORKLOAD_FILE_NAME,))


def agentlane_gate_overlay(root: Path, env: Mapping[str, str]) -> dict[str, Overlay]:
    """NAN-5880: the gate's loopback listener, on enterprise installs only.

    An enterprise tree without the source file (an incomplete bundle) gets no
    listener: the gate then has no upstream and stays closed (install.sh also
    leaves the gate out of such a bundle). Never an open fallback.
    """
    if (env.get("NANO_EDITION") or "").strip() != "enterprise":
        return {}
    source = root / AGENTLANE_GATE_SOURCE
    if not source.is_file():
        return {}
    return {AGENTLANE_GATE_FILE: source}


def config_files(root: Path, env: Mapping[str, str]) -> dict[str, bytes]:
    overlays: dict[str, Overlay] = dict(overlay_sources(root, env, CONFIG_OVERLAYS))
    overlays.update(agentlane_gate_overlay(root, env))
    return dir_files(root / SHIPPED_CONFIG_DIR, overlays,
                     mount_targets=CONFIG_MOUNT_TARGETS, skip=LEGACY_MOUNT_TARGETS[SHIPPED_CONFIG_DIR])


def assemble_users(
    root: Path, env: Mapping[str, str], *, output: Path | None = None, source: Path | None = None,
    networks: Overlay = None, workload: bytes | None = None,
) -> bool:
    output = output or root / USERS_DIR
    return publish_dir(output, users_files(root, env, source=source, networks=networks,
                                           workload=workload, live=output))


def assemble_config(root: Path, env: Mapping[str, str], *, output: Path | None = None) -> bool:
    return publish_dir(output or root / CONFIG_DIR, config_files(root, env))


def assemble(root: Path, env: Mapping[str, str], *, config_output: Path | None = None,
             users_output: Path | None = None) -> bool:
    # users.d first: a config.d with the stamp means both were assembled.
    changed = assemble_users(root, env, output=users_output)
    return assemble_config(root, env, output=config_output) or changed


def digest(*directories: Path) -> str:
    """sha256 over the assembled directories' names and contents."""
    value = hashlib.sha256()
    for directory in directories:
        value.update(directory.name.encode() + b"\0")
        for item in sorted(directory.iterdir()) if directory.is_dir() else []:
            if item.is_file() and (item.suffix == ".xml" or item.name == ASSEMBLED_STAMP):
                value.update(item.name.encode() + b"\0" + hashlib.sha256(item.read_bytes()).digest())
    return value.hexdigest()


def record_env(env_file: Path, values: Mapping[str, str]) -> bool:
    """Set KEY=value lines in the .env (replace or append), atomically, mode kept."""
    text = env_file.read_text(encoding="utf-8") if env_file.is_file() else ""
    lines = text.splitlines()
    current = dotenv_values(env_file)
    if all(current.get(key) == value for key, value in values.items()):
        return False
    kept = [line for line in lines if not any(re.match(rf"^\s*(export\s+)?{re.escape(k)}=", line) for k in values)]
    kept.extend(f"{key}={value}" for key, value in values.items())
    mode = env_file.stat().st_mode & 0o777 if env_file.exists() else 0o600
    fd, tmp = tempfile.mkstemp(prefix=".env.", dir=env_file.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(kept) + "\n")
        os.chmod(tmp, mode)
        os.replace(tmp, env_file)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, required=True, help="the install directory (or source tree)")
    parser.add_argument("--env-file", type=Path, default=None, help="its .env (default: ROOT/.env)")
    parser.add_argument("--config-output", type=Path, default=None, help=f"default: ROOT/{CONFIG_DIR}")
    parser.add_argument("--users-output", type=Path, default=None, help=f"default: ROOT/{USERS_DIR}")
    parser.add_argument("--record-env", action="store_true",
                        help=f"record {ENV_CONFIG_DIR}, {ENV_USERS_DIR} and {ENV_DIGEST} in the .env")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    env_file = args.env_file or root / ".env"
    config_output = args.config_output or root / CONFIG_DIR
    users_output = args.users_output or root / USERS_DIR
    try:
        changed = assemble(root, dotenv_values(env_file), config_output=config_output, users_output=users_output)
        value = digest(config_output, users_output)
        if args.record_env:
            def relative(path: Path) -> str:
                try:
                    return "./" + str(path.resolve().relative_to(root))
                except ValueError:
                    return str(path.resolve())
            record_env(env_file, {
                ENV_CONFIG_DIR: relative(config_output), ENV_USERS_DIR: relative(users_output), ENV_DIGEST: value,
            })
    except (AssembleError, OSError) as error:
        print(f"clickhouse config dirs: {error}", file=sys.stderr)
        return 1
    print("changed" if changed else "unchanged")
    print(f"sha256={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
