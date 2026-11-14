#!/usr/bin/env python3
"""List Compose services whose single-file bind mounts are stale (NAN-5397).

A single-file bind mount pins the file's inode when the container is created.
An upgrade that replaces the file (install.sh's `git reset --hard`, a release
bundle unpack, a renderer that writes a new file and renames it over the old
one) leaves the running container reading the OLD file, and Compose does not
recreate the container because its definition did not change. nginx then
reloads its old config, Prometheus keeps its old scrape config, ClickHouse its
old sizing, and the upgrade still reports success.

Usage: compose_stale_mounts.py --root INSTALL_DIR CONTAINER_ID...
       compose_stale_mounts.py --root INSTALL_DIR --prune-overlay OVERLAY...

For each container, every bind mount whose host source is a regular file under
INSTALL_DIR (at most 4 MiB) is compared byte for byte with what the container
reads at the mount destination. The service name of each container that reads
different content is printed once per line on stdout; a short note per stale
mount goes to stderr. A container or mount that cannot be read is skipped:
this reports only what it can prove.

The container side is read with `docker exec cat`, inside the container's own
mount namespace. `docker cp` cannot be used: the daemon serves it by binding
the mount's Source PATH again, so it returns the new file even while the
container still reads the old inode. On Docker Desktop the replaced file
vanishes from the container instead ("No such file"), which is stale too.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys

MAX_FILE_BYTES = 4 * 1024 * 1024
SERVICE_LABEL = "com.docker.compose.service"


def _docker(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["docker", *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL, timeout=timeout, check=False,
    )


def host_file_digest(path: pathlib.Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def read_container_file(container: str, destination: str) -> tuple[str, bytes]:
    """("ok", bytes) for what `container` reads at `destination`; ("missing", b"")
    when the container cannot see a file there (a replaced bind-mounted file on
    Docker Desktop); ("unknown", b"") when it cannot be read.

    "unknown" covers an image without `cat` (distroless), a file the container
    user cannot read, a stopped container and a timeout. Callers skip such a
    mount: it is never reported stale, so a service whose image has no `cat`
    is not recreated by this check (only a definition change recreates it)."""
    try:
        result = subprocess.run(
            ["docker", "exec", container, "cat", "--", destination],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown", b""
    if result.returncode == 0:
        return "ok", result.stdout
    if b"No such file or directory" in result.stderr and b"OCI runtime" not in result.stderr:
        return "missing", b""
    return "unknown", b""


def file_mounts_under(mounts: object, root: pathlib.Path) -> list[tuple[pathlib.Path, str]]:
    """(host file, container destination) for each single-file bind mount of
    a regular file under `root`."""
    selected: list[tuple[pathlib.Path, str]] = []
    for mount in mounts if isinstance(mounts, list) else []:
        if not isinstance(mount, dict) or mount.get("Type") != "bind":
            continue
        source = pathlib.Path(str(mount.get("Source", "")))
        destination = str(mount.get("Destination", ""))
        if not source.is_absolute() or not destination.startswith("/"):
            continue
        try:
            resolved = source.resolve()
            if not resolved.is_file() or resolved.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if resolved != root and root not in resolved.parents:
            continue
        selected.append((resolved, destination))
    return selected


def stale_services(root: pathlib.Path, containers: list[str]) -> list[str]:
    stale: list[str] = []
    for container in containers:
        try:
            inspected = _docker("inspect", "--format", "{{json .}}", container, timeout=30)
            info = json.loads(inspected.stdout or b"{}") if inspected.returncode == 0 else {}
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            continue
        if not isinstance(info, dict):
            continue
        labels = (info.get("Config") or {}).get("Labels") or {}
        service = labels.get(SERVICE_LABEL, "") if isinstance(labels, dict) else ""
        if not service or service in stale:
            continue
        for source, destination in file_mounts_under(info.get("Mounts"), root):
            host = host_file_digest(source)
            state, seen = read_container_file(container, destination)
            if host is None or state == "unknown":
                continue
            if state == "missing" or hashlib.sha256(seen).hexdigest() != host:
                print(f"note: {service} reads an outdated {destination} (host file {source})", file=sys.stderr)
                stale.append(service)
                break
    return stale


CONTROL_DIR = ".nano-v2-control"
TRANSITION_RECORD = ".nano-legacy-transition.json"
SETTLED_TRANSITION_STATES = frozenset({"complete", "archived"})


def prune_control_pins(install_dir: pathlib.Path, overlay: pathlib.Path) -> list[str]:
    """Drop the canonical-config binds a legacy transition pinned in `overlay`.

    nano-upgrade's legacy transition writes docker-compose.legacy-preserved.yml
    (JSON) with every bundle-owned bind pointing at the authenticated control
    copy, .nano-v2-control/<bundle sha>/<path>, so the canonical tree could be
    published atomically. After the transition those pins freeze the config at
    that bundle forever: later upgrades update <install>/<path>, never the pin.
    Older upgraders also pinned the single-file nginx.conf mount, which the
    directory-mounted nginx (NAN-5397) cannot replace.

    Removes each bind whose source is <install>/.nano-v2-control/<sha>/<path>
    when <install>/<path> exists as the same kind (file or directory); the base
    Compose file's own mount then applies. Data binds and anything outside the
    control copy are kept. Does nothing while a transition is still in
    progress, or when the overlay is not the JSON the upgrader writes. Returns
    "service:target" for each dropped bind."""
    install_dir = install_dir.resolve()
    record_path = install_dir / TRANSITION_RECORD
    if record_path.is_file():
        try:
            state = json.loads(record_path.read_text(encoding="utf-8")).get("state")
        except (OSError, ValueError, AttributeError):
            return []
        if state not in SETTLED_TRANSITION_STATES:
            return []
    if overlay.is_symlink() or not overlay.is_file():
        return []
    try:
        model = json.loads(overlay.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    services = model.get("services") if isinstance(model, dict) else None
    if not isinstance(services, dict):
        return []
    control = install_dir / CONTROL_DIR
    dropped: list[str] = []
    for name in list(services):
        service = services[name]
        volumes = service.get("volumes") if isinstance(service, dict) else None
        if not isinstance(volumes, list):
            continue
        kept = []
        for volume in volumes:
            source = pathlib.Path(str(volume.get("source", ""))) if isinstance(volume, dict) else None
            if source is not None and source.is_absolute():
                source = source.resolve()
            if (
                source is not None and volume.get("type") == "bind"
                and source.is_absolute() and control in source.parents
            ):
                relative = source.relative_to(control).parts[1:]
                published = install_dir.joinpath(*relative) if relative else None
                if published is not None and (
                    (source.is_file() and published.is_file())
                    or (source.is_dir() and published.is_dir())
                    or (not source.exists() and published.exists())
                ):
                    dropped.append(f"{name}:{volume.get('target', '')}")
                    continue
            kept.append(volume)
        if len(kept) == len(volumes):
            continue
        if kept:
            service["volumes"] = kept
        else:
            del service["volumes"]
            if not service:
                del services[name]
    if dropped:
        temporary = overlay.with_name(f".{overlay.name}.prune")
        temporary.write_text(json.dumps(model, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temporary, overlay.stat().st_mode & 0o777)
        os.replace(temporary, overlay)
    return dropped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument(
        "--prune-overlay", type=pathlib.Path, action="append", default=[],
        help="drop control-copy config pins from this legacy-preserved overlay (see prune_control_pins)",
    )
    parser.add_argument("containers", nargs="*")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.prune_overlay:
        for overlay in args.prune_overlay:
            for entry in prune_control_pins(root, overlay if overlay.is_absolute() else root / overlay):
                print(f"note: {overlay.name}: dropped the pinned config mount {entry}", file=sys.stderr)
        return 0
    for service in stale_services(root, [c for c in args.containers if c]):
        print(service)
    return 0


if __name__ == "__main__":
    sys.exit(main())
