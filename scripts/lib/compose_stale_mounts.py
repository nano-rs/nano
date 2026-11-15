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
       compose_stale_mounts.py --root INSTALL_DIR --guard-tenzir-pipeline CONTAINER

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


# NAN-5411: tenzir/pipeline.tql is the one shipped file install.sh tells
# operators to edit (the bundled Tenzir node's pipeline). Extracting a release
# package over the install directory replaces it, and the next `up -d` (a new
# Tenzir image) or the stale-mount recreate above starts Tenzir on the shipped
# file: the operator's pipeline would be gone without a word. Until the old
# container is recreated it still reads the operator's file (the old inode),
# so that is the last moment the edit can be recovered.
TENZIR_PIPELINE = pathlib.PurePosixPath("tenzir/pipeline.tql")
TENZIR_PIPELINE_DESTINATION = "/pipeline.tql"
# sha256 of every tenzir/pipeline.tql nano has shipped (git log --
# tenzir/pipeline.tql). A running pipeline with one of these digests is
# unedited. Add the new digest whenever the file changes;
# scripts/tests/test_compose_stale_mounts.py fails until it is listed.
SHIPPED_TENZIR_PIPELINE_SHA256 = frozenset({
    "e605ec3f513f1e3bec84019e6593506ee58e0e2f9b0c37da8312ce421cb8ae91",  # NAN-1604
    "6cd7b4c53cdc67b3f26527b83d10b3120a6ceeee07871fc6b3fa04fd51942ed8",  # NAN-1788
    "cc9fe93da3d216e627db38c43c4a4764dd582afb47ecf45e3e46897f38337ad1",  # NAN-1827
    "352dc3f3716d7aa531878cea6a393c02a72c814f211edee04e9927eb412fa528",  # NAN-1839
    "2edeb3f1d1aa002d180a0b9da388c45d995cf664af3ee413cc62915750ed4006",  # NAN-5345
    "29478f154305574de8ec1087c109fdb7e6dba7cb89709f8f47748efd2d83721a",  # NAN-5352 (v2.0.26)
    "1f1eee114524fbfa2289e80d274508b2e28380b15240d14f87c1d7d87907bb85",  # NAN-5411 (Tenzir 6.22)
})


class OperatorFileReplaced(Exception):
    """The release package replaced an operator-edited file (message: what to do)."""


def guard_tenzir_pipeline(root: pathlib.Path, container: str) -> str:
    """Refuse to go on when the release package replaced an edited pipeline.

    Compares what the running Tenzir `container` reads at /pipeline.tql with
    <root>/tenzir/pipeline.tql. When they differ, the running one is not a
    shipped version (the operator edited it) and the host file is a shipped
    version (the package overwrote it), the running pipeline is saved to
    tenzir/pipeline.tql.bak and OperatorFileReplaced is raised: once the
    container is recreated the edit is gone. Re-running after that proceeds
    (the .bak already holds exactly the running pipeline). Anything this
    cannot prove (no such container, not running, unreadable) passes.
    Returns a one-line status."""
    host_path = root / TENZIR_PIPELINE
    try:
        host = host_path.read_bytes()
    except OSError:
        return "no tenzir/pipeline.tql in the install directory"
    state, running = read_container_file(container, TENZIR_PIPELINE_DESTINATION)
    if state != "ok":
        return f"{container} is not running or its pipeline cannot be read; nothing to compare"
    if running == host:
        return "the running Tenzir pipeline is the one in the install directory"
    digest = hashlib.sha256(running).hexdigest()
    if digest in SHIPPED_TENZIR_PIPELINE_SHA256:
        return "the running Tenzir pipeline is an unedited shipped version; the new one applies"
    if hashlib.sha256(host).hexdigest() not in SHIPPED_TENZIR_PIPELINE_SHA256:
        return "tenzir/pipeline.tql was edited since Tenzir started; it applies on recreate"
    # pipeline.tql.bak, or (when that holds something else) a digest-named one.
    candidates = (
        host_path.with_name(host_path.name + ".bak"),
        host_path.with_name(f"{host_path.name}.bak.{digest[:12]}"),
    )
    for backup in candidates:
        try:
            if backup.is_file() and backup.read_bytes() == running:
                return (
                    f"WARNING: your edited Tenzir pipeline was replaced by the shipped one; "
                    f"it is kept in {backup} (continuing with the shipped pipeline)"
                )
        except OSError:
            pass
    backup = candidates[1] if candidates[0].exists() else candidates[0]
    # 0600: an operator pipeline can carry sink credentials (to_splunk hec_token, ...).
    temporary = backup.with_name(f".{backup.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(running)
    os.chmod(temporary, 0o600)
    os.replace(temporary, backup)
    raise OperatorFileReplaced(
        f"The release package replaced your edited {TENZIR_PIPELINE} with the shipped "
        f"pipeline, and recreating Tenzir would discard your version. It is saved to "
        f"{backup}. Review it against the new {TENZIR_PIPELINE} (Tenzir 6.18 to 6.20 changes: "
        "HTTPS hostname checks on to_http/to_splunk/..., client-certificate trust of "
        "accept_*, the legacy executor is gone), then either copy your version back "
        f"(cp {backup} {host_path}) or keep the shipped one, and re-run. A re-run "
        "with the backup in place continues."
    )


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
    parser.add_argument(
        "--guard-tenzir-pipeline", metavar="CONTAINER",
        help="refuse (exit 3) when the release package replaced an edited tenzir/pipeline.tql "
        "that CONTAINER still runs; saves it to tenzir/pipeline.tql.bak (see guard_tenzir_pipeline)",
    )
    parser.add_argument("containers", nargs="*")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.guard_tenzir_pipeline:
        try:
            print(guard_tenzir_pipeline(root, args.guard_tenzir_pipeline), file=sys.stderr)
        except OperatorFileReplaced as error:
            print(str(error), file=sys.stderr)
            return 3
        return 0
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
