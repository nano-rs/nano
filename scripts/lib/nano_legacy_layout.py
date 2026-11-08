#!/usr/bin/env python3
"""Read-only resolver for the retired managed-enterprise Compose layout.

The legacy platform renderer predates the v2 edition/version fields.  Its
mutable IMAGE_TAG is not evidence.  This module therefore qualifies a layout
only when every running application's immutable image ID maps to a repository
digest in exactly one retained N-1 lock, and when Docker's Compose labels bind
those containers to the exact files being rendered.

No environment value or rendered Compose model is printed by this module.
Callers may retain those values in memory to build the post-backup transition.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
from typing import Any, Protocol, Sequence


SEMVER_RE = re.compile(r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LOCK_NAME_RE = re.compile(
    r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)-(?P<edition>open|enterprise)(?:-(?P<arch>amd64|arm64))?\.lock$"
)
REQUIRED_SERVICES = ("postgres", "clickhouse", "vector", "api", "jobs", "search", "web")
LOCKED_APP_SERVICES = ("api", "jobs", "search", "web")
PERSISTENT_TARGETS = {
    ("postgres", "/var/lib/postgresql/data"),
    ("clickhouse", "/var/lib/clickhouse"),
    ("vector", "/etc/vector/dynamic"),
    ("vector", "/var/lib/vector"),
    ("api", "/app/data"),
    ("api", "/etc/vector/dynamic"),
    ("api", "/app/config/vector"),
    ("jobs", "/app/data"),
    ("prometheus", "/prometheus"),
}
APP_REPOSITORY_SUFFIXES = {
    "api": ("/nano-api", "/nanosiem-api"),
    "jobs": ("/nano-jobs", "/nanosiem-jobs"),
    "search": ("/nano-search", "/nanosiem-search"),
    "web": ("/nano-web", "/nanosiem-web"),
}


class LegacyLayoutError(RuntimeError):
    """A bounded, operator-safe legacy-layout refusal."""


class CommandRunner(Protocol):
    def run(
        self, arguments: Sequence[str], *, timeout: int = 120,
        input_text: str | None = None, check: bool = True,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


class SubprocessRunner:
    def run(
        self, arguments: Sequence[str], *, timeout: int = 120,
        input_text: str | None = None, check: bool = True,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                list(arguments), text=True, input=input_text,
                capture_output=True, timeout=timeout, check=check, env=env,
            )
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or "").strip().splitlines()
            bounded = detail[-1][:300] if detail else "command failed"
            raise LegacyLayoutError(bounded) from error
        except subprocess.TimeoutExpired as error:
            raise LegacyLayoutError(
                f"legacy layout command timed out after {timeout} seconds"
            ) from error
        except OSError as error:
            raise LegacyLayoutError(
                f"cannot execute legacy layout command: {pathlib.Path(arguments[0]).name}"
            ) from error


@dataclasses.dataclass(frozen=True)
class LockedImage:
    service: str
    repository: str
    digest: str


@dataclasses.dataclass(frozen=True)
class LegacyArchiveInput:
    """A qualified bind root that the physical legacy backup will archive."""

    path: pathlib.Path
    source_bytes: int
    entry_count: int
    archive_bytes_upper_bound: int

    def safe_record(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "source_bytes": self.source_bytes,
            "entry_count": self.entry_count,
            "archive_bytes_upper_bound": self.archive_bytes_upper_bound,
        }


@dataclasses.dataclass(frozen=True)
class LegacyResolution:
    install_dir: pathlib.Path
    env_file: pathlib.Path
    compose_files: tuple[pathlib.Path, ...]
    project_name: str
    version: str
    edition: str
    architecture: str
    schema_profile: str
    lock_file: pathlib.Path
    image_ids: dict[str, str]
    data_sources: tuple[pathlib.Path, ...]
    base_model: dict[str, Any]
    merged_model: dict[str, Any]
    archive_inputs: tuple[LegacyArchiveInput, ...] = ()

    def safe_record(self) -> dict[str, Any]:
        """Metadata safe for a journal/manifest; never includes env values."""
        return {
            "format": "nano-legacy-layout-v1",
            "version": self.version,
            "edition": self.edition,
            "architecture": self.architecture,
            "schema_profile": self.schema_profile,
            "project_name": self.project_name,
            "compose_files": [path.name for path in self.compose_files],
            "lock_file": self.lock_file.name,
            "image_ids": dict(sorted(self.image_ids.items())),
            "data_sources": [str(path) for path in self.data_sources],
            "physical_archives": [item.safe_record() for item in self.archive_inputs],
        }


def _regular_owned(path: pathlib.Path, label: str) -> pathlib.Path:
    try:
        info = path.lstat()
    except OSError as error:
        raise LegacyLayoutError(f"{label} is missing: {path}") from error
    if path.is_symlink() or not path.is_file():
        raise LegacyLayoutError(f"{label} must be a regular non-symlink: {path}")
    if info.st_uid != os.getuid():
        raise LegacyLayoutError(f"{label} is not owned by uid {os.getuid()}: {path}")
    return path


def _environment_values(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise LegacyLayoutError(f"cannot read environment file: {path}") from error
    for line in lines:
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        value = value.rstrip("\r")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def _valid_started_transition(
    path: pathlib.Path, compose_files: Sequence[pathlib.Path],
) -> bool:
    try:
        _regular_owned(path, "legacy transition intent")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (LegacyLayoutError, OSError, json.JSONDecodeError):
        return False
    if not isinstance(value, dict):
        return False
    source = value.get("source")
    if not isinstance(source, dict):
        return False
    return bool(
        value.get("format") == "nano-legacy-transition-v1"
        and value.get("state") == "started"
        and re.fullmatch(r"[0-9a-f]{64}", str(value.get("bundle_sha256", "")))
        and SEMVER_RE.fullmatch(str(value.get("target_version", "")))
        and source.get("format") == "nano-legacy-layout-v1"
        and source.get("compose_files") == [item.name for item in compose_files]
    )


def _active_bridge_intent(
    path: pathlib.Path, compose_files: Sequence[pathlib.Path],
) -> dict[str, Any] | None:
    """Return a bounded bridge claim that may qualify a mixed-image resume.

    The claim is not image evidence.  It merely identifies the two retained
    locks that every running application must still match independently.
    """
    try:
        _regular_owned(path, "legacy bridge intent")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (LegacyLayoutError, OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    if not (
        value.get("format") == "nano-legacy-bridge-v1"
        and value.get("state") in {"started", "image-tag-published"}
        and value.get("source_version") == "0.1.702"
        and value.get("target_version") == "0.1.703"
        and value.get("edition") in {"open", "enterprise"}
        and value.get("architecture") in {"amd64", "arm64"}
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", str(value.get("run_id", "")))
        and re.fullmatch(r"[0-9a-f]{64}", str(value.get("bundle_sha256", "")))
        and value.get("compose_files") == [item.name for item in compose_files]
        and LOCK_NAME_RE.fullmatch(str(value.get("source_lock", "")))
        and LOCK_NAME_RE.fullmatch(str(value.get("target_lock", "")))
    ):
        return None
    return value


def _compose_arguments(
    install_dir: pathlib.Path, env_file: pathlib.Path,
    compose_files: Sequence[pathlib.Path],
) -> list[str]:
    arguments = [
        "docker", "compose", "--project-directory", str(install_dir),
        "--env-file", str(env_file),
    ]
    for compose_file in compose_files:
        arguments.extend(("-f", str(compose_file)))
    return arguments


def _render_model(
    runner: CommandRunner, arguments: Sequence[str], *, label: str,
) -> dict[str, Any]:
    result = runner.run([*arguments, "config", "--format", "json"], timeout=60)
    try:
        model = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LegacyLayoutError(f"{label} Compose render did not return JSON") from error
    if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
        raise LegacyLayoutError(f"{label} Compose render has no service model")
    return model


def _parse_lock(path: pathlib.Path) -> tuple[str, str, str, dict[str, LockedImage]]:
    name = LOCK_NAME_RE.fullmatch(path.name)
    if name is None:
        raise LegacyLayoutError(f"unsupported legacy lock name: {path.name}")
    version = name.group("version")
    edition = name.group("edition")
    architecture = name.group("arch") or "multiarch"
    header = ""
    images: dict[str, LockedImage] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise LegacyLayoutError(f"cannot read legacy lock: {path.name}") from error
    for line in lines:
        if line.startswith("# Release:"):
            header = line.split(":", 1)[1].strip().removeprefix("v")
            continue
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 2 or not IMAGE_ID_RE.fullmatch(fields[1]):
            raise LegacyLayoutError(f"invalid legacy lock entry: {path.name}")
        reference, digest = fields
        repository = reference.rsplit(":", 1)[0]
        matches = [
            service for service, suffixes in APP_REPOSITORY_SUFFIXES.items()
            if any(repository.endswith(suffix) for suffix in suffixes)
        ]
        if not matches:
            # Full retained release locks also pin PostgreSQL, ClickHouse,
            # cache, ingest, and proxy images. They remain immutable backup
            # inputs but do not participate in app-version classification.
            continue
        if len(matches) != 1 or matches[0] in images:
            raise LegacyLayoutError(f"legacy lock does not uniquely identify app services: {path.name}")
        service = matches[0]
        images[service] = LockedImage(service, repository, digest)
    if header != version or set(images) != set(LOCKED_APP_SERVICES):
        raise LegacyLayoutError(f"legacy lock is incomplete or has a mismatched release: {path.name}")
    return version, edition, architecture, images


def _image_repository(reference: str) -> str:
    without_digest = reference.split("@", 1)[0]
    tail = without_digest.rsplit("/", 1)[-1]
    if ":" in tail:
        return without_digest.rsplit(":", 1)[0]
    return without_digest


def _persistent_data_sources(
    model: dict[str, Any], install_dir: pathlib.Path,
) -> tuple[pathlib.Path, ...]:
    services = model.get("services")
    if not isinstance(services, dict):
        raise LegacyLayoutError("legacy Compose model has no service model")
    sources: set[pathlib.Path] = set()
    found: set[tuple[str, str]] = set()
    for service_name, raw_service in services.items():
        if not isinstance(raw_service, dict):
            raise LegacyLayoutError(f"legacy service is not an object: {service_name}")
        volumes = raw_service.get("volumes") or []
        if not isinstance(volumes, list):
            raise LegacyLayoutError(f"legacy service volumes are invalid: {service_name}")
        for raw_volume in volumes:
            if not isinstance(raw_volume, dict):
                raise LegacyLayoutError(
                    f"legacy service volume is not rendered long syntax: {service_name}"
                )
            key = (service_name, str(raw_volume.get("target", "")))
            if key not in PERSISTENT_TARGETS:
                continue
            if raw_volume.get("type") != "bind":
                raise LegacyLayoutError(
                    f"legacy persistent volume is not a bind mount: {service_name}:{key[1]}"
                )
            source_value = raw_volume.get("source")
            if not isinstance(source_value, str) or not pathlib.Path(source_value).is_absolute():
                raise LegacyLayoutError(
                    f"legacy persistent bind source is not absolute: {service_name}:{key[1]}"
                )
            source = pathlib.Path(source_value)
            try:
                resolved = source.resolve(strict=True)
            except OSError as error:
                raise LegacyLayoutError(
                    f"legacy persistent bind source is missing: {service_name}:{key[1]}"
                ) from error
            if source.is_symlink() or not resolved.is_dir():
                raise LegacyLayoutError(
                    f"legacy persistent bind source is not a directory: {service_name}:{key[1]}"
                )
            if resolved in {pathlib.Path("/"), pathlib.Path("/mnt"), pathlib.Path("/var")}:
                raise LegacyLayoutError("legacy persistent bind source is dangerously broad")
            if (
                resolved == install_dir
                or resolved in install_dir.parents
                or install_dir in resolved.parents
            ):
                raise LegacyLayoutError(
                    "legacy persistent bind source overlaps the installation control tree"
                )
            sources.add(resolved)
            found.add(key)
    required = {
        ("postgres", "/var/lib/postgresql/data"),
        ("clickhouse", "/var/lib/clickhouse"),
        ("vector", "/var/lib/vector"),
        ("api", "/app/data"),
    }
    missing = sorted(required - found)
    if missing:
        detail = ", ".join(f"{service}:{target}" for service, target in missing)
        raise LegacyLayoutError(f"legacy layout lacks persistent data mounts: {detail}")
    ordered = tuple(sorted(sources, key=str))
    for index, source in enumerate(ordered):
        if any(other in source.parents for other in ordered if other != source):
            raise LegacyLayoutError(
                f"legacy persistent bind sources overlap: {source}"
            )
    return ordered


def _archive_input(path: pathlib.Path) -> LegacyArchiveInput:
    """Measure a bind tree without following links or reading file contents.

    The tar bound includes rounded regular-file payloads plus four KiB of
    metadata allowance per entry and a full tar record.  It is intentionally
    conservative and is suitable for pre-backup disk planning; the signed
    backup records the actual archive sizes after creation.
    """
    source_bytes = 0
    rounded_payload_bytes = 0
    entry_count = 1  # GNU/BSD tar both emit the root `.` directory entry.
    pending = [path]
    try:
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    info = entry.stat(follow_symlinks=False)
                    entry_count += 1
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(pathlib.Path(entry.path))
                    elif stat.S_ISREG(info.st_mode):
                        source_bytes += info.st_size
                        rounded_payload_bytes += ((info.st_size + 511) // 512) * 512
                    elif stat.S_ISLNK(info.st_mode):
                        try:
                            target = pathlib.Path(entry.path).resolve(strict=True)
                        except OSError as error:
                            raise LegacyLayoutError(
                                f"legacy physical archive contains a dangling link: {path}"
                            ) from error
                        if target != path and path not in target.parents:
                            raise LegacyLayoutError(
                                f"legacy physical archive contains an external link: {path}"
                            )
                    else:
                        raise LegacyLayoutError(
                            f"legacy physical archive contains an unsupported entry: {path}"
                        )
    except LegacyLayoutError:
        raise
    except OSError as error:
        raise LegacyLayoutError(
            f"cannot measure legacy physical archive source: {path}"
        ) from error
    raw_bound = rounded_payload_bytes + entry_count * 4096 + 10240
    archive_bound = ((raw_bound + 10239) // 10240) * 10240
    return LegacyArchiveInput(path, source_bytes, entry_count, archive_bound)


def _container_identity(
    runner: CommandRunner, compose: Sequence[str], service: str,
    expected_files: tuple[pathlib.Path, ...], install_dir: pathlib.Path,
) -> tuple[str, str, str, frozenset[str]]:
    result = runner.run([*compose, "ps", "-q", service], timeout=30)
    containers = [line for line in result.stdout.splitlines() if line]
    if len(containers) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", containers[0]):
        raise LegacyLayoutError(f"legacy Compose service is not uniquely running: {service}")
    inspected = runner.run([
        "docker", "inspect", "--format",
        "{{.State.Running}}\t{{.Image}}\t{{.Config.Image}}\t"
        "{{index .Config.Labels \"com.docker.compose.project\"}}\t"
        "{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}\t"
        "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}",
        containers[0],
    ], timeout=30)
    fields = inspected.stdout.strip().split("\t")
    if len(fields) != 6 or fields[0] != "true" or not IMAGE_ID_RE.fullmatch(fields[1]):
        raise LegacyLayoutError(f"cannot prove immutable running identity for service: {service}")
    image_id, image_ref, project, working_dir, raw_files = fields[1:]
    try:
        actual_working = pathlib.Path(working_dir).resolve(strict=True)
    except OSError as error:
        raise LegacyLayoutError(f"service {service} has an invalid Compose working directory") from error
    if actual_working != install_dir:
        raise LegacyLayoutError(f"service {service} belongs to a different Compose working directory")
    try:
        actual_files = tuple(pathlib.Path(item).resolve(strict=True) for item in raw_files.split(","))
    except OSError as error:
        raise LegacyLayoutError(f"service {service} has an invalid Compose file label") from error
    if actual_files != expected_files:
        raise LegacyLayoutError(f"service {service} was not created from the qualified legacy Compose files")
    if not project or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project):
        raise LegacyLayoutError(f"service {service} has an invalid Compose project identity")
    image_inspected = runner.run([
        "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image_id,
    ], timeout=30)
    try:
        raw_digests = json.loads(image_inspected.stdout)
    except json.JSONDecodeError as error:
        raise LegacyLayoutError(f"cannot prove registry digest for service: {service}") from error
    if not isinstance(raw_digests, list) or not all(isinstance(value, str) for value in raw_digests):
        raise LegacyLayoutError(f"cannot prove registry digest for service: {service}")
    repo_digests = frozenset(raw_digests)
    return image_id, image_ref, project, repo_digests


def resolve_legacy_layout(
    install_dir: pathlib.Path, lock_dir: pathlib.Path,
    runner: CommandRunner | None = None,
) -> LegacyResolution:
    runner = runner or SubprocessRunner()
    try:
        install = install_dir.expanduser().resolve(strict=True)
    except OSError as error:
        raise LegacyLayoutError(f"legacy install directory is missing: {install_dir}") from error
    env_file = _regular_owned(install / ".env", "legacy environment file")
    base_file = _regular_owned(install / "docker-compose.yml", "legacy Compose file")
    override = install / "docker-compose.override.yml"
    compose_files = (base_file,)
    if override.exists() or override.is_symlink():
        compose_files += (_regular_owned(override, "legacy Compose override"),)
    canonical = install / "docker-compose.opensource.yml"
    restored_marker = install / ".nano-legacy-layout-restored"
    transition_intent = install / ".nano-legacy-transition.json"
    bridge_intent = _active_bridge_intent(
        install / ".nano-legacy-bridge.json", compose_files,
    )
    if (
        canonical.exists()
        and not restored_marker.exists()
        and not _valid_started_transition(transition_intent, compose_files)
    ):
        raise LegacyLayoutError("canonical Compose layout already exists; legacy qualification is ambiguous")

    env = _environment_values(env_file)
    if env.get("NANO_VERSION") or env.get("NANO_EDITION"):
        raise LegacyLayoutError("legacy layout unexpectedly contains canonical version/edition fields")
    if not env.get("IMAGE_TAG"):
        raise LegacyLayoutError("legacy layout has no IMAGE_TAG marker")
    schema = env.get("NANO_SCHEMA_PROFILE", "udm")
    if schema not in {"udm", "ocsf"}:
        raise LegacyLayoutError("legacy layout has an invalid schema profile")

    compose = _compose_arguments(install, env_file, compose_files)
    base_compose = _compose_arguments(install, env_file, (base_file,))
    base_model = _render_model(runner, base_compose, label="base legacy")
    merged_model = _render_model(runner, compose, label="merged legacy")
    data_sources = _persistent_data_sources(merged_model, install)
    archive_inputs = tuple(_archive_input(path) for path in data_sources)
    services = merged_model["services"]
    missing = sorted(set(REQUIRED_SERVICES) - set(services))
    if missing:
        raise LegacyLayoutError(f"legacy Compose model lacks required services: {', '.join(missing)}")

    expected_files = tuple(path.resolve(strict=True) for path in compose_files)
    image_ids: dict[str, str] = {}
    image_refs: dict[str, str] = {}
    image_repo_digests: dict[str, frozenset[str]] = {}
    projects: set[str] = set()
    for service in REQUIRED_SERVICES:
        image_id, image_ref, project, repo_digests = _container_identity(
            runner, compose, service, expected_files, install,
        )
        projects.add(project)
        if service in LOCKED_APP_SERVICES:
            image_ids[service] = image_id
            image_refs[service] = image_ref
            image_repo_digests[service] = repo_digests
    if len(projects) != 1:
        raise LegacyLayoutError("legacy services disagree on Compose project identity")

    matches: list[tuple[pathlib.Path, str, str, str]] = []
    try:
        candidates = sorted(lock_dir.glob("v*-*.lock"))
    except OSError as error:
        raise LegacyLayoutError("cannot enumerate retained legacy locks") from error
    for lock_file in candidates:
        try:
            _regular_owned(lock_file, "legacy image lock")
            version, edition, architecture, locked = _parse_lock(lock_file)
        except LegacyLayoutError:
            continue
        if all(
            _image_repository(image_refs[service]) == locked[service].repository
            and f"{locked[service].repository}@{locked[service].digest}"
            in image_repo_digests[service]
            for service in LOCKED_APP_SERVICES
        ):
            matches.append((lock_file, version, edition, architecture))
    if len(matches) == 1:
        lock_file, version, edition, architecture = matches[0]
    elif not matches and bridge_intent is not None:
        source_lock = lock_dir / str(bridge_intent["source_lock"])
        target_lock = lock_dir / str(bridge_intent["target_lock"])
        try:
            _regular_owned(source_lock, "legacy bridge source lock")
            _regular_owned(target_lock, "legacy bridge target lock")
            source_version, source_edition, source_arch, source_images = _parse_lock(source_lock)
            target_version, target_edition, target_arch, target_images = _parse_lock(target_lock)
        except LegacyLayoutError as error:
            raise LegacyLayoutError("legacy bridge resume locks are invalid") from error
        claimed_arch = str(bridge_intent["architecture"])
        if not (
            source_version == bridge_intent["source_version"]
            and target_version == bridge_intent["target_version"]
            and source_edition == target_edition == bridge_intent["edition"]
            and source_arch in {"multiarch", claimed_arch}
            and target_arch in {"multiarch", claimed_arch}
        ):
            raise LegacyLayoutError("legacy bridge resume locks do not match its durable intent")
        selections: set[str] = set()
        for service in LOCKED_APP_SERVICES:
            current_repository = _image_repository(image_refs[service])
            matched = []
            for label, locked in (
                ("source", source_images[service]),
                ("target", target_images[service]),
            ):
                if (
                    current_repository == locked.repository
                    and f"{locked.repository}@{locked.digest}" in image_repo_digests[service]
                ):
                    matched.append(label)
            if len(matched) != 1:
                raise LegacyLayoutError(
                    f"legacy bridge resume cannot qualify running image for service: {service}"
                )
            selections.add(matched[0])
        if selections != {"source", "target"}:
            raise LegacyLayoutError("legacy bridge resume is not a mixed source/target rollout")
        lock_file = source_lock
        version = source_version
        edition = source_edition
        architecture = source_arch
    else:
        raise LegacyLayoutError("running immutable app image IDs do not match exactly one retained legacy lock")
    if not SEMVER_RE.fullmatch(version):
        raise LegacyLayoutError("qualified legacy lock has an invalid semantic version")
    return LegacyResolution(
        install_dir=install, env_file=env_file, compose_files=compose_files,
        project_name=next(iter(projects)), version=version, edition=edition,
        architecture=architecture, schema_profile=schema, lock_file=lock_file,
        image_ids=image_ids, data_sources=data_sources,
        base_model=base_model, merged_model=merged_model,
        archive_inputs=archive_inputs,
    )


def _main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--install-dir", required=True)
    parser.add_argument("--lock-dir", required=True)
    parser.add_argument("--nul", action="store_true")
    args = parser.parse_args()
    resolution = resolve_legacy_layout(pathlib.Path(args.install_dir), pathlib.Path(args.lock_dir))
    if not args.nul:
        raise LegacyLayoutError("the resolver only exposes its bounded NUL interface")
    fields = [
        resolution.version, resolution.edition, resolution.schema_profile,
        resolution.project_name, str(len(resolution.compose_files)),
        *(str(path) for path in resolution.compose_files),
        str(len(resolution.data_sources)),
        *(str(path) for path in resolution.data_sources),
    ]
    sys.stdout.buffer.write(b"\0".join(field.encode("utf-8") for field in fields) + b"\0")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except LegacyLayoutError as error:
        print(f"nano: {error}", file=sys.stderr)
        raise SystemExit(1)
