#!/usr/bin/env python3
"""Safe, journaled compose upgrade orchestration for nano (NAN-5000)."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import datetime as dt
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import platform
import re
import secrets
import selectors
import shlex
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Callable, Iterable, Sequence


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_INSTALL_DIR = SCRIPT_DIR.parent
SEMVER_RE = re.compile(r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
ROLES = {"keeper", "clickhouse", "postgres", "ingest", "app", "monitoring"}
# NAN-5250: RAM the optional monitoring role (Prometheus, Grafana, exporters)
# needs when a release manifest predates it. Matches the Compose limits and
# resource-sizing.sh's NANO_MONITORING_RESERVE_MIB default.
MONITORING_ROLE_MIN_BYTES = 1024 * 1024 * 1024

_LEGACY_SPEC = importlib.util.spec_from_file_location(
    "nano_legacy_layout", SCRIPT_DIR / "lib/nano_legacy_layout.py"
)
if _LEGACY_SPEC is None or _LEGACY_SPEC.loader is None:
    raise RuntimeError("cannot load the legacy layout resolver")
nano_legacy_layout = importlib.util.module_from_spec(_LEGACY_SPEC)
sys.modules[_LEGACY_SPEC.name] = nano_legacy_layout
_LEGACY_SPEC.loader.exec_module(nano_legacy_layout)
_LEGACY_BRIDGE_SPEC = importlib.util.spec_from_file_location(
    "nano_legacy_bridge", SCRIPT_DIR / "lib/nano_legacy_bridge.py"
)
if _LEGACY_BRIDGE_SPEC is None or _LEGACY_BRIDGE_SPEC.loader is None:
    raise RuntimeError("cannot load the legacy bridge policy")
nano_legacy_bridge = importlib.util.module_from_spec(_LEGACY_BRIDGE_SPEC)
sys.modules[_LEGACY_BRIDGE_SPEC.name] = nano_legacy_bridge
_LEGACY_BRIDGE_SPEC.loader.exec_module(nano_legacy_bridge)
_STALE_MOUNTS_SPEC = importlib.util.spec_from_file_location(
    "compose_stale_mounts", SCRIPT_DIR / "lib/compose_stale_mounts.py"
)
if _STALE_MOUNTS_SPEC is None or _STALE_MOUNTS_SPEC.loader is None:
    raise RuntimeError("cannot load the stale bind-mount check")
compose_stale_mounts = importlib.util.module_from_spec(_STALE_MOUNTS_SPEC)
sys.modules[_STALE_MOUNTS_SPEC.name] = compose_stale_mounts
_STALE_MOUNTS_SPEC.loader.exec_module(compose_stale_mounts)
ROLE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "keeper": (),
    "clickhouse": ("keeper",),
    "postgres": (),
    "migration": ("clickhouse", "postgres"),
    "app": ("migration",),
    "ingest": ("app",),
    # NAN-5250: metrics only; rolled last so it watches the upgrade.
    "monitoring": ("ingest",),
}


def _embedded_lab_key_ids() -> tuple[str, ...]:
    """Read the build-embedded TEST roots; runtime flags cannot create one."""
    path = SCRIPT_DIR / "lib/nano_bundle.py"
    spec = importlib.util.spec_from_file_location("_nano_upgrade_bundle", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load release verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return tuple(root.key_id for root in module.EMBEDDED_LAB_ROOTS)


EMBEDDED_LAB_KEY_IDS = _embedded_lab_key_ids()


def dependency_order(dependencies: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    unknown = {
        dependency
        for required in dependencies.values()
        for dependency in required
        if dependency not in dependencies
    }
    if unknown:
        raise RuntimeError(f"role dependency graph names unknown roles: {sorted(unknown)}")
    pending = dict(dependencies)
    ordered: list[str] = []
    while pending:
        ready = next((
            role for role, required in pending.items()
            if all(dependency in ordered for dependency in required)
        ), None)
        if ready is None:
            raise RuntimeError("role dependency graph contains a cycle")
        ordered.append(ready)
        del pending[ready]
    return tuple(ordered)


ROLE_ORDER = dependency_order(ROLE_DEPENDENCIES)
APP_SERVICES = (
    # NAN-5213: valkey-proxy replaces the local dragonfly on a host of a
    # multi-app-host cluster (the shared Valkey is on the PostgreSQL host).
    "dragonfly", "valkey-proxy",
    # NAN-5214: host-local HAProxy routers to the Patroni leader (`postgres`)
    # and the Sentinel-elected Valkey master (`dragonfly`).
    "postgres-router", "valkey-router",
    # NAN-5215: the app host's HAProxy to the ingest hosts. NAN-5282: without
    # it here the app rollout never selected it, so a re-rendered
    # haproxy/ingest-proxy.cfg (NAN-5279 F1) never reached the running proxy.
    "ingest-proxy",
    "clickhouse-proxy", "nano-api", "nano-jobs", "connector-runner",
    "nano-search", "nano-web", "nginx", "app-internal-edge",
    # NAN-5204: the opt-in automatic-backup service runs the api image; a
    # rollout recreates it only when it is running.
    "nano-backup",
)
INGEST_SERVICES = (
    "app-api-proxy", "vector", "vector-config-consumer", "vector-tap", "ingest-edge", "clickhouse-proxy",
)
APP_EDGE_SERVICES = ("nginx", "app-internal-edge")
LEGACY_MANAGED_OTLP_CONFIG_SHA256 = (
    "1a14ffd1d41df60fa7e414593ae430c1bf6e0a3b0ecab0905e322b943b9521a7"
)
# Background app processes can create cross-store work while a recovery set is
# captured. Current API images reject/drain unsafe methods through the shared
# PostgreSQL mutation fence, so only the two background producers are stopped.
# An older API image has no capability marker and is conservatively included in
# this exact set, which also protects upgrades from the pre-fence release.
BACKUP_WRITER_SERVICES = ("nano-api", "nano-jobs", "connector-runner")
BACKUP_MUTATION_CAPABILITY = "/usr/local/share/nano/capabilities/backup-mutation-fence-v1"
ROLE_SERVICES: dict[str, tuple[str, ...]] = {
    # NAN-5214: with two postgres hosts the Keeper hosts are the etcd and
    # Sentinel witnesses.
    "keeper": ("keeper", "etcd", "valkey-sentinel"),
    "clickhouse": ("clickhouse",),
    # NAN-5214: the Patroni member, its etcd member and the Sentinel-managed
    # Valkey member/Sentinel replace postgres / valkey / valkey-edge.
    "postgres": (
        "postgres", "postgres-ha", "etcd", "valkey", "valkey-edge", "valkey-ha", "valkey-sentinel",
    ),
    "migration": ("clickhouse-proxy",),
    "ingest": INGEST_SERVICES,
    "app": APP_SERVICES,
    "monitoring": ("prometheus", "alertmanager", "grafana", "redis-exporter"),
}


def exact_role_services(
    role: str, services: Iterable[str], *, writers_only: bool = False,
) -> list[str]:
    if writers_only:
        if role == "app":
            allowed = BACKUP_WRITER_SERVICES
        elif role == "ingest":
            allowed = INGEST_SERVICES
        else:
            raise UpgradeError(f"cannot select writers for non-writer role {role}")
    else:
        try:
            allowed = ROLE_SERVICES[role]
        except KeyError as error:
            raise UpgradeError(f"unsupported rollout role: {role}") from error
    requested = list(services)
    if len(requested) != len(set(requested)):
        raise UpgradeError(f"duplicate service in exact {role} service set")
    unexpected = sorted(set(requested) - set(allowed))
    if unexpected:
        raise UpgradeError(
            f"invalid service in exact {role} service set: {', '.join(unexpected)}"
        )
    return [service for service in allowed if service in requested]
# Keep in lockstep with scripts/lib/nano_bundle.py: bundle loading and upgrade
# preflight must select the same per-role payloads. Unknown future components
# remain selected everywhere so an older preflight never underestimates space.
BUNDLE_IMAGE_ROLES: dict[str, frozenset[str]] = {
    "api": frozenset({"app", "ingest"}),
    "search": frozenset({"app"}),
    "jobs": frozenset({"app"}),
    "web": frozenset({"app"}),
    "connector-runner": frozenset({"app"}),
    "backup": frozenset({"app"}),
    "postgres": frozenset({"postgres"}),
    # NAN-5214: PostgreSQL HA (Patroni member, etcd DCS, HAProxy routers).
    "postgres-ha": frozenset({"postgres"}),
    "etcd": frozenset({"postgres", "keeper"}),
    "haproxy": frozenset({"app", "ingest", "clickhouse", "postgres", "keeper"}),
    "clickhouse-server": frozenset({"clickhouse"}),
    "clickhouse-keeper": frozenset({"keeper"}),
    # The shared/HA Valkey and Sentinels live on postgres (and witness Keeper) hosts.
    "valkey": frozenset({"app", "postgres", "keeper"}),
    # Pre-NAN-5082 releases (legacy N-1 locks) still carry Dragonfly.
    "dragonfly": frozenset({"app"}),
    "vector": frozenset({"ingest"}),
    "curl": frozenset({"ingest"}),
    "nginx": frozenset({"app", "ingest", "clickhouse", "postgres"}),
    "tenzir": frozenset({"ingest"}),
    # NAN-5250: the optional monitoring role. node-exporter runs on every host
    # of a cluster that has a monitoring host; the rest only on that host.
    "node-exporter": frozenset({"app", "ingest", "clickhouse", "keeper", "postgres", "monitoring"}),
    "prometheus": frozenset({"monitoring"}),
    "grafana": frozenset({"monitoring"}),
    "redis_exporter": frozenset({"monitoring"}),
    "alertmanager": frozenset({"monitoring"}),
}
INSTALL_OPERATION_RESERVE_BYTES = 256 * 1024**2
DOCKER_OPERATION_RESERVE_BYTES = 1024**3
ENRICHMENT_CONTROL_TREE_GUIDE = "docs/administration/upgrade-v2.md"


def check_enrichment_control_tree(install_dir: pathlib.Path) -> str:
    """Refuse a binary-only upgrade that lacks the v2 enrichment endpoint."""
    listener = install_dir / "config/vector/04-enrichment-source.toml"
    routes = (
        install_dir / "config/nginx/nginx.opensource.conf",
        install_dir / "deploy/compose/config/nginx.ingest.conf.template",
    )
    try:
        listener_text = listener.read_text(encoding="utf-8")
    except OSError:
        listener_text = ""
    listener_ready = (
        "[sources.enrichment_ingest]" in listener_text
        and 'address = "0.0.0.0:8090"' in listener_text
    )
    route_ready = False
    for route in routes:
        try:
            text = route.read_text(encoding="utf-8")
        except OSError:
            continue
        if "location = /enrichment" in text and ":8090" in text:
            route_ready = True
            break
    if not listener_ready or not route_ready:
        missing = []
        if not listener_ready:
            missing.append("Vector :8090 enrichment listener")
        if not route_ready:
            missing.append("nginx /enrichment route")
        raise UpgradeError(
            "installed control tree is not enrichment-ready (missing "
            + " and ".join(missing)
            + "). Refusing a binary-only upgrade that would break identity sync. "
            "Overlay the full signed v2 control package first; see "
            + ENRICHMENT_CONTROL_TREE_GUIDE
        )
    return "installed control tree exposes Vector :8090 and nginx /enrichment"


def _ratio_bytes(value: int, raw: object, label: str) -> int:
    ratio = json_object(raw, label)
    numerator = ratio.get("numerator")
    denominator = ratio.get("denominator")
    if (
        not isinstance(numerator, int) or isinstance(numerator, bool) or numerator <= 0
        or not isinstance(denominator, int) or isinstance(denominator, bool) or denominator <= 0
    ):
        raise UpgradeError(f"{label} must contain positive integer numerator/denominator")
    return (value * numerator + denominator - 1) // denominator


def _positive_policy_bytes(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise UpgradeError(f"{label} must be a positive integer")
    return value


def _format_bytes(value: int) -> str:
    return f"{value / 1024**3:.2f} GiB ({value} bytes)"


@dataclasses.dataclass(frozen=True)
class BackupArchiveInput:
    """One item copied into the plaintext backup payload.

    ``ratio_field`` names the signed expansion ratio used to turn measured
    source bytes into a conservative archive size.  A value of ``None`` means
    the caller already measured the bytes that will be archived; this is the
    merge point for legacy physical bind-mount snapshots.
    """

    label: str
    source_bytes: int
    ratio_field: str | None = None
    native_destination: str | None = None


@dataclasses.dataclass(frozen=True)
class BackupArchiveEstimate:
    label: str
    archive_bytes: int
    native_destination: str | None


@dataclasses.dataclass(frozen=True)
class MigrationSource:
    label: str
    source_bytes: int


@dataclasses.dataclass(frozen=True)
class MigrationEstimate:
    label: str
    source_bytes: int
    headroom_bytes: int


@dataclasses.dataclass(frozen=True)
class FilesystemSpace:
    identity: str
    available_bytes: int


@dataclasses.dataclass(frozen=True)
class DatabaseStorage:
    role: str
    source_bytes: int
    data_filesystem: FilesystemSpace


@dataclasses.dataclass(frozen=True)
class DiskPlan:
    backup_archives: tuple[BackupArchiveEstimate, ...]
    backup_payload_bytes: int
    backup_tmp_peak_bytes: int
    backup_output_bytes: int
    bundle_working_bytes: int
    image_load_bytes: int
    migrations: tuple[MigrationEstimate, ...]
    safety_min_bytes: int
    safety_ratio_numerator: int
    safety_ratio_denominator: int

    @property
    def migration_headroom_bytes(self) -> int:
        return sum(item.headroom_bytes for item in self.migrations)

    def native_backup_bytes(self, destination: str) -> int:
        return sum(
            item.archive_bytes for item in self.backup_archives
            if item.native_destination == destination
        )

    def safety_margin(self, source_bytes: int) -> int:
        ratio_bytes = (
            source_bytes * self.safety_ratio_numerator
            + self.safety_ratio_denominator - 1
        ) // self.safety_ratio_denominator
        return max(self.safety_min_bytes, ratio_bytes)

    def detail(self) -> str:
        archives = ",".join(
            f"{item.label}={item.archive_bytes}" for item in self.backup_archives
        ) or "none"
        migrations = ",".join(
            f"{item.label}={item.headroom_bytes}" for item in self.migrations
        ) or "none"
        return (
            f"backup-archives=[{archives}], backup-payload={self.backup_payload_bytes}, "
            f"backup-tmp-peak={self.backup_tmp_peak_bytes}, "
            f"backup-output={self.backup_output_bytes}, "
            f"bundle-working={self.bundle_working_bytes}, "
            f"image-load={self.image_load_bytes}, migration-headroom={self.migration_headroom_bytes}, "
            f"migrations=[{migrations}], safety-per-mutation-filesystem="
            f"max({self.safety_min_bytes},ceil(source-bytes*"
            f"{self.safety_ratio_numerator}/{self.safety_ratio_denominator})) bytes"
        )


def disk_plan(
    requires: dict[str, Any], *, bundle_bytes: int, image_sizes: Sequence[int],
    backup_archives: Sequence[BackupArchiveInput],
    migration_sources: Sequence[MigrationSource], prepared: bool,
) -> DiskPlan:
    raw = requires.get("disk")
    if raw is None:
        minimum = requires.get("min_disk_bytes", 0)
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 0:
            raise UpgradeError("manifest requires.min_disk_bytes is invalid")
        selected = [] if prepared else list(image_sizes)
        return DiskPlan(
            backup_archives=(),
            backup_payload_bytes=0,
            backup_tmp_peak_bytes=0,
            backup_output_bytes=0,
            bundle_working_bytes=INSTALL_OPERATION_RESERVE_BYTES + max(selected, default=0),
            image_load_bytes=DOCKER_OPERATION_RESERVE_BYTES + sum(selected),
            migrations=(),
            safety_min_bytes=minimum,
            safety_ratio_numerator=1,
            safety_ratio_denominator=1 << 62,
        )

    policy = json_object(raw, "manifest.requires.disk")
    fixed_backup = _positive_policy_bytes(
        policy.get("backup_fixed_overhead_bytes"),
        "manifest.requires.disk.backup_fixed_overhead_bytes",
    )
    install_working = _positive_policy_bytes(
        policy.get("install_working_bytes"),
        "manifest.requires.disk.install_working_bytes",
    )
    image_overhead = _positive_policy_bytes(
        policy.get("image_load_overhead_bytes"),
        "manifest.requires.disk.image_load_overhead_bytes",
    )
    migration_minimum = _positive_policy_bytes(
        policy.get("migration_min_headroom_bytes"),
        "manifest.requires.disk.migration_min_headroom_bytes",
    )
    safety_minimum = _positive_policy_bytes(
        policy.get("safety_min_bytes"),
        "manifest.requires.disk.safety_min_bytes",
    )
    archive_estimates: list[BackupArchiveEstimate] = []
    archive_labels: set[str] = set()
    for item in backup_archives:
        if not item.label or item.label in archive_labels:
            raise UpgradeError("backup archive inputs must have unique non-empty labels")
        if item.source_bytes < 0:
            raise UpgradeError(f"backup archive input {item.label} has invalid bytes")
        archive_labels.add(item.label)
        archive_bytes = item.source_bytes
        if item.ratio_field is not None:
            if item.ratio_field not in {
                "backup_postgres_ratio", "backup_clickhouse_ratio",
            }:
                raise UpgradeError(
                    f"backup archive input {item.label} has an unsupported signed ratio"
                )
            archive_bytes = _ratio_bytes(
                item.source_bytes, policy.get(item.ratio_field),
                f"manifest.requires.disk.{item.ratio_field}",
            )
        archive_estimates.append(BackupArchiveEstimate(
            item.label, archive_bytes, item.native_destination,
        ))
    payload_bytes = fixed_backup + sum(
        item.archive_bytes for item in archive_estimates
    ) if archive_estimates else 0

    migration_estimates: list[MigrationEstimate] = []
    migration_labels: set[str] = set()
    for source in migration_sources:
        if not source.label or source.label in migration_labels:
            raise UpgradeError("migration sources must have unique non-empty labels")
        if source.source_bytes < 0:
            raise UpgradeError(f"migration source {source.label} has invalid bytes")
        migration_labels.add(source.label)
        migration_estimates.append(MigrationEstimate(
            source.label,
            source.source_bytes,
            max(
                migration_minimum,
                _ratio_bytes(
                    source.source_bytes, policy.get("migration_data_ratio"),
                    "manifest.requires.disk.migration_data_ratio",
                ),
            ),
        ))
    safety_ratio = json_object(
        policy.get("safety_data_ratio"),
        "manifest.requires.disk.safety_data_ratio",
    )
    safety_numerator = safety_ratio.get("numerator")
    safety_denominator = safety_ratio.get("denominator")
    if (
        not isinstance(safety_numerator, int) or isinstance(safety_numerator, bool)
        or safety_numerator <= 0
        or not isinstance(safety_denominator, int) or isinstance(safety_denominator, bool)
        or safety_denominator <= 0
    ):
        raise UpgradeError(
            "manifest.requires.disk.safety_data_ratio must contain positive integer "
            "numerator/denominator"
        )
    selected = [] if prepared else list(image_sizes)
    return DiskPlan(
        backup_archives=tuple(archive_estimates),
        backup_payload_bytes=payload_bytes,
        # The payload files and the uncompressed payload.tar coexist until
        # OpenSSL finishes writing the final encrypted output.
        backup_tmp_peak_bytes=payload_bytes * 2,
        backup_output_bytes=payload_bytes,
        bundle_working_bytes=install_working + (0 if prepared else bundle_bytes),
        image_load_bytes=image_overhead + sum(selected),
        migrations=tuple(migration_estimates),
        safety_min_bytes=safety_minimum,
        safety_ratio_numerator=safety_numerator,
        safety_ratio_denominator=safety_denominator,
    )


def role_ram_requirement(requires: dict[str, Any], roles: Iterable[str]) -> tuple[int, str]:
    raw = requires.get("ram")
    if raw is None:
        required = requires.get("min_ram_bytes", 0)
        if not isinstance(required, int) or isinstance(required, bool) or required < 0:
            raise UpgradeError("manifest requires.min_ram_bytes is invalid")
        return required, "legacy signed minimum"
    policy = json_object(raw, "manifest.requires.ram")
    absolute = _positive_policy_bytes(
        policy.get("absolute_min_bytes"), "manifest.requires.ram.absolute_min_bytes"
    )
    reserve = _positive_policy_bytes(
        policy.get("os_reserve_bytes"), "manifest.requires.ram.os_reserve_bytes"
    )
    role_minimums = json_object(
        policy.get("role_min_bytes"), "manifest.requires.ram.role_min_bytes"
    )
    selected: list[str] = []
    role_total = 0
    for role in sorted(set(roles)):
        raw_minimum = role_minimums.get(role)
        if raw_minimum is None and role == "monitoring":
            # A manifest signed before NAN-5250 has no monitoring entry.
            raw_minimum = MONITORING_ROLE_MIN_BYTES
        minimum = _positive_policy_bytes(
            raw_minimum, f"manifest.requires.ram.role_min_bytes.{role}"
        )
        selected.append(f"{role}={minimum}")
        role_total += minimum
    required = max(absolute, reserve + role_total)
    return required, (
        f"max(absolute={absolute}, os-reserve={reserve} + roles[{', '.join(selected)}]={role_total})"
    )


def _mountinfo_value(value: str) -> str:
    return re.sub(
        r"\\(040|011|012|134)",
        lambda match: {"040": " ", "011": "\t", "012": "\n", "134": "\\"}[
            match.group(1)
        ],
        value,
    )


def cgroup_memory_limits(
    cgroup_text: str,
    mountinfo_text: str,
    read_text: Callable[[pathlib.Path], str],
) -> list[tuple[int, str]]:
    """Return bounded memory limits from the process cgroup and all ancestors."""
    memberships: list[tuple[str, pathlib.PurePosixPath]] = []
    for line in cgroup_text.splitlines():
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        hierarchy, controllers, raw_path = fields
        if hierarchy == "0" and not controllers:
            version = "cgroup2"
        elif "memory" in controllers.split(","):
            version = "cgroup"
        else:
            continue
        path = pathlib.PurePosixPath(raw_path)
        if not path.is_absolute() or ".." in path.parts:
            continue
        memberships.append((version, path))

    mounts: list[tuple[str, pathlib.PurePosixPath, pathlib.Path]] = []
    for line in mountinfo_text.splitlines():
        try:
            left, right = line.split(" - ", 1)
        except ValueError:
            continue
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < 5 or len(right_fields) < 3:
            continue
        version = right_fields[0]
        if version not in {"cgroup", "cgroup2"}:
            continue
        if version == "cgroup":
            options = set(right_fields[2].split(","))
            options.update(left_fields[5:])
            if "memory" not in options and "memory" not in left_fields[4].split("/"):
                continue
        root = pathlib.PurePosixPath(_mountinfo_value(left_fields[3]))
        mount = pathlib.Path(_mountinfo_value(left_fields[4]))
        if root.is_absolute() and mount.is_absolute():
            mounts.append((version, root, mount))

    limits: list[tuple[int, str]] = []
    visited: set[pathlib.Path] = set()
    for version, membership in memberships:
        candidates: list[tuple[int, pathlib.PurePosixPath, pathlib.Path]] = []
        for mount_version, root, mount in mounts:
            if mount_version != version:
                continue
            try:
                membership.relative_to(root)
            except ValueError:
                continue
            candidates.append((len(root.parts), root, mount))
        if not candidates:
            continue
        _, root, mount = max(candidates, key=lambda item: item[0])
        relative = membership.relative_to(root)
        current = mount.joinpath(*relative.parts)
        filename = "memory.max" if version == "cgroup2" else "memory.limit_in_bytes"
        while current == mount or mount in current.parents:
            limit_path = current / filename
            if limit_path not in visited:
                visited.add(limit_path)
                try:
                    raw = read_text(limit_path).strip()
                except OSError:
                    raw = ""
                if raw != "max" and raw.isdigit():
                    limit = int(raw)
                    if 0 < limit < (1 << 60):
                        limits.append((limit, f"cgroup:{limit_path}"))
            if current == mount:
                break
            current = current.parent
    return limits


# Bundle manifest v1 has no profile-specific migration group. Bind the exact
# separately namespaced profile history to the active schema profile instead
# of to one target release number. A later signed target still carries the
# shared migration index, while these rows describe legitimate source state;
# every unknown namespace/version and every checksum drift remains rejected.
#
# NAN-5269: the list is derived from the target control tree's
# per-profile migrations directory (shipped in the signed package, the same
# files the target images apply), never hand-maintained. A hand-kept list
# that stopped at ocsf/190 refused every v2.0.10 OCSF cluster (193, 194).
# Versions and checksums follow the Rust migrator exactly: the filename
# prefix before the first `_`, namespaced `<profile>/`, and the SHA-256 of
# the file bytes.
PROFILE_MIGRATION_DIRS: dict[str, str] = {"ocsf": "clickhouse/ocsf/migrations"}
_PROFILE_MIGRATION_FILENAME = re.compile(r"^([0-9]+[a-z]*)_.+\.sql$")


def profile_ledger_allowlist(root: pathlib.Path, profile: str) -> dict[str, str]:
    """The exact `<profile>/<version>` -> sha256 rows the target can hold."""
    relative = PROFILE_MIGRATION_DIRS.get(profile)
    if relative is None:
        return {}
    directory = root / relative
    if not directory.is_dir():
        raise RuntimeError(f"{profile} ClickHouse migrations are missing from the control tree: {directory}")
    result: dict[str, str] = {}
    for path in sorted(directory.iterdir()):
        match = _PROFILE_MIGRATION_FILENAME.fullmatch(path.name)
        if match is None or not path.is_file():
            continue
        version = f"{profile}/{match.group(1)}"
        if version in result:
            raise RuntimeError(f"{directory} repeats migration version {version}")
        result[version] = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    if not result:
        raise RuntimeError(f"{profile} ClickHouse migrations directory is empty: {directory}")
    return result


PROFILE_LEDGER_ALLOWLIST: dict[str, dict[str, str]] = {
    "ocsf": profile_ledger_allowlist(SCRIPT_DIR.parent, "ocsf"),
    "udm": {},
}
def _clickhouse_baseline_allowlist() -> dict[str, str]:
    """Load the exact fresh-install seed contract shared with the Rust migrator."""
    path = SCRIPT_DIR.parent / "clickhouse/baseline_migrations.json"
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot load ClickHouse baseline contract: {path}") from error
    if not isinstance(value, list) or not value:
        raise RuntimeError("ClickHouse baseline contract must be a non-empty array")
    result: dict[str, str] = {}
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"version", "name"}:
            raise RuntimeError("ClickHouse baseline contract contains an invalid entry")
        version = entry["version"]
        name = entry["name"]
        if (
            not isinstance(version, str)
            or re.fullmatch(r"[0-9]+[a-z]*", version) is None
            or not isinstance(name, str)
            or re.fullmatch(r"[a-z0-9_]+", name) is None
            or version in result
        ):
            raise RuntimeError("ClickHouse baseline contract contains an invalid migration")
        result[version] = ""
    return result


# Fresh ClickHouse installs seed these exact versions into `_migrations` with
# empty checksums. The Rust migrator and this upgrade validator consume the same
# checked-in contract, so a later baseline addition cannot silently become an
# upgrade incompatibility. Rows remain optional for older upgraded tenants.
CLICKHOUSE_BASELINE_ALLOWLIST = _clickhouse_baseline_allowlist()


class UpgradeError(RuntimeError):
    """An operator-safe failure (never contains secret values)."""


# Values nano shipped as defaults or examples (config/known-public-secrets.txt,
# kinds vector_install_token and vector_config_delivery_token; a test keeps
# them in sync). nano-api refuses them for Vector config delivery (NAN-5148).
PUBLIC_VECTOR_INSTALL_TOKENS = frozenset({
    "CHANGE_ME", "CHANGE_ME_GENERATED", "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32",
    "nanosiem-default-token", "your-secret-token",
})
PUBLIC_VECTOR_CONFIG_DELIVERY_TOKENS = frozenset({
    "CHANGE_ME", "CHANGE_ME_GENERATED", "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32",
})


def check_vector_config_delivery_credential(env: dict[str, str]) -> str:
    """Refuse an upgrade after which this role-split host's Vector config
    delivery would be off (NAN-5148).

    nano-api checks NANO_VECTOR_CONFIG_DELIVERY_TOKEN and, before v2.1, falls
    back to the forwarder install token, but never to a publicly known one.
    The ingest host's consumer presents the delivery token, else the install
    token. `nano upgrade` does not change .env, so what is here now is what the
    upgraded services get. Values are compared, never reported.
    """
    dedicated = env.get("NANO_VECTOR_CONFIG_DELIVERY_TOKEN", "").strip()
    install = env.get("VECTOR_AUTH_TOKEN", "").strip()
    if dedicated and dedicated not in PUBLIC_VECTOR_CONFIG_DELIVERY_TOKENS:
        return "dedicated Vector config delivery token present"
    # NAN-5042: strict delivery is opt-in. nano-api (the app host) enforces
    # it, from the shared .env this host also carries a copy of; `prepare`
    # pins an upgraded role-split .env without the key to false, so only an
    # operator's explicit `true` makes the private fallback unusable.
    strict = env.get("NANO_VECTOR_CONFIG_DELIVERY_STRICT", "").strip().lower() == "true"
    if not dedicated and install and install not in PUBLIC_VECTOR_INSTALL_TOKENS and not strict:
        return (
            "Vector config delivery uses the install-token fallback (deprecated, "
            "refused from v2.1): add NANO_VECTOR_CONFIG_DELIVERY_TOKEN to the shared .env"
        )
    if dedicated:
        problem = "NANO_VECTOR_CONFIG_DELIVERY_TOKEN in .env is a placeholder"
    elif install and install not in PUBLIC_VECTOR_INSTALL_TOKENS:
        problem = (
            "this host's .env has no NANO_VECTOR_CONFIG_DELIVERY_TOKEN and sets "
            "NANO_VECTOR_CONFIG_DELIVERY_STRICT=true, so nano-api refuses its install token"
        )
    else:
        problem = (
            "this host's .env has no NANO_VECTOR_CONFIG_DELIVERY_TOKEN and its "
            "VECTOR_AUTH_TOKEN is publicly known, which nano-api refuses"
        )
    raise UpgradeError(
        f"Vector config delivery would stop after this upgrade: {problem}. "
        "Fix: on the app host run `NANO_PREPARE_ONLY=1 ./install.sh --inventory "
        "<inventory> --role <its roles>` (it generates the token into .env; or "
        "append NANO_VECTOR_CONFIG_DELIVERY_TOKEN=$(openssl rand -hex 32) to .env "
        "yourself), securely copy that .env to every inventory host, then re-run "
        "nano upgrade. See docs/getting-started/docker-deployment.md"
    )


def check_vector_install_token(env: dict[str, str], role_split: bool) -> str:
    """Refuse a role-split upgrade whose .env still holds a publicly known
    VECTOR_AUTH_TOKEN (NAN-5013).

    nano-api refuses a public install token on every ingest lane since v2.0.6.
    A single-node prepare replaces it with a generated value
    ([`rotate_public_install_token`]); a role-split cluster must share one
    value, so it is generated once on the app host and copied, never per host.
    Values are compared, never reported.
    """
    install = env.get("VECTOR_AUTH_TOKEN", "").strip()
    if not install or install not in PUBLIC_VECTOR_INSTALL_TOKENS:
        return "VECTOR_AUTH_TOKEN is not a known public value"
    if not role_split:
        return (
            "VECTOR_AUTH_TOKEN is publicly known; prepare replaces it with a generated "
            "value (senders still using the public token get HTTP 401)"
        )
    raise UpgradeError(
        "VECTOR_AUTH_TOKEN in this host's .env is publicly known, which nano refuses for "
        "ingest from v2.0.6. Fix, on the app host: replace the VECTOR_AUTH_TOKEN line in "
        ".env with a generated value (`openssl rand -hex 32`), or run the install.sh from "
        "the NEW release bundle (the installed one keeps the public token) as "
        "`NANO_PREPARE_ONLY=1 ./install.sh --inventory <inventory> --role <its roles>`; "
        "then securely copy that .env to every inventory host and re-run nano upgrade. "
        "Senders using named ingest tokens keep working; senders still sending the public "
        "token get HTTP 401"
    )


def rotate_public_install_token(env_file: "EnvFile") -> bool:
    """Replace a publicly known VECTOR_AUTH_TOKEN with a generated one
    (single-node prepare, NAN-5013). Idempotent: a generated value is never
    public, so a resumed prepare changes nothing. The services recreated by
    the rollout read the new value; nano-api republishes Vector's tokens file
    from it, and named per-source tokens (hashes in PostgreSQL) are untouched."""
    install = env_file.values().get("VECTOR_AUTH_TOKEN", "").strip()
    if install not in PUBLIC_VECTOR_INSTALL_TOKENS:
        return False
    env_file.replace("VECTOR_AUTH_TOKEN", secrets.token_hex(32))
    return True


def pin_compatible_delivery_mode(env_file: "EnvFile") -> bool:
    """Write NANO_VECTOR_CONFIG_DELIVERY_STRICT=false into an upgraded
    role-split .env that has no such key (NAN-5042). Strict delivery refuses
    the install token once the dedicated token exists; a consumer whose .env
    predates the token is then refused, stops refreshing its readiness, and
    the load balancer drops that ingest host. Fresh installs write true.
    Idempotent; an operator's explicit value is never changed."""
    if "NANO_VECTOR_CONFIG_DELIVERY_STRICT" in env_file.values():
        return False
    env_file.replace("NANO_VECTOR_CONFIG_DELIVERY_STRICT", "false")
    return True


def pin_legacy_schema_profile(env_file: "EnvFile") -> bool:
    """Write NANO_SCHEMA_PROFILE=udm into an upgraded .env that has no value
    for it (NAN-5271). Until v2.0.12 an unset profile resolved to UDM in the
    compose files and in the services, so such an install holds UDM data. The
    new release defaults an unset profile to OCSF; recording the value the
    install already runs keeps it on UDM. Idempotent; an explicit value
    (udm or ocsf) is never changed. Same rule as install.sh (NAN-4903)."""
    if env_file.values().get("NANO_SCHEMA_PROFILE", "").strip():
        return False
    env_file.replace("NANO_SCHEMA_PROFILE", "udm")
    return True


def eprint(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def semver(value: str) -> tuple[int, int, int]:
    match = SEMVER_RE.fullmatch(value.strip())
    if not match:
        raise UpgradeError(f"invalid release version {value!r}; expected X.Y.Z")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def canonical_version(value: str) -> str:
    parsed = semver(value)
    return ".".join(str(part) for part in parsed)


def json_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UpgradeError(f"{label} must be a JSON object")
    return value


def safe_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SAFE_NAME_RE.fullmatch(value):
        raise UpgradeError(f"{label} contains unsupported characters")
    return value


def siem_health_finding_signatures(snapshot: dict[str, Any]) -> set[str]:
    findings = snapshot.get("findings", [])
    if not isinstance(findings, list):
        raise UpgradeError("SIEM Health findings are not an array")
    signatures: set[str] = set()
    for finding in findings:
        item = json_object(finding, "SIEM Health finding")
        title = item.get("title")
        priority = item.get("priority", "")
        if not isinstance(title, str) or not isinstance(priority, str):
            raise UpgradeError("SIEM Health finding title or priority is invalid")
        # Mirror the product's finding-signature normalization: volatile
        # numbers, common punctuation, whitespace, and priority changes do not
        # turn one pre-existing condition into a new finding.
        normalized: list[str] = []
        previous_space = True
        for character in title.lower():
            if character.isascii() and character.isdigit():
                continue
            if character in ".,%()":
                continue
            if character.isspace() or character in "-:;\"'":
                if not previous_space:
                    normalized.append(" ")
                    previous_space = True
                continue
            normalized.append(character)
            previous_space = False
        signatures.add("".join(normalized).strip())
    return signatures


def env_seconds(name: str, default: int, maximum: int = 3600) -> int:
    raw = os.environ.get(name, "")
    try:
        value = int(raw) if raw.strip() else default
    except ValueError as error:
        raise UpgradeError(f"{name} must be a whole number of seconds") from error
    return max(0, min(value, maximum))


def _parse_report_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # PostgreSQL may print a two-digit offset (+00); fromisoformat wants +00:00.
    match = re.fullmatch(r"(.*[+-])(\d{2})", text)
    if match:
        text = f"{match.group(1)}{match.group(2)}:00"
    # Older Pythons accept only 3 or 6 fractional digits.
    match = re.fullmatch(r"([^.]*)\.(\d+)(.*)", text)
    if match:
        text = f"{match.group(1)}.{match.group(2)[:6].ljust(6, '0')}{match.group(3)}"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def siem_health_report_is_fresh(
    before: dict[str, Any], after: dict[str, Any], since: str | None,
) -> bool:
    """NAN-5279 F5: is `after` a report generated after the upgrade?

    The gate used to read the latest report straight after the rollout, which
    was normally the pre-upgrade report itself (the scheduler runs 5 minutes
    after the API leader starts, then every 12 hours), so it compared a report
    with itself. A report is stale when it is the baseline report, when it was
    created before `since` (the start of the application rollout), or when
    none exists yet."""
    status = str(after.get("status", ""))
    if status == "not-present":
        return True  # this release has no SIEM Health; nothing to wait for
    if status == "no-report-yet":
        return False
    after_id, before_id = after.get("id"), before.get("id")
    if after_id and before_id and after_id == before_id:
        return False
    created = _parse_report_time(after.get("created_at"))
    threshold = _parse_report_time(since) if since else None
    if created is not None and threshold is not None:
        return created >= threshold
    return True


def wait_for_fresh_siem_health(
    fetch: Callable[[], dict[str, Any]],
    before: dict[str, Any],
    since: str | None,
    wait_seconds: int,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    poll_seconds: int = 15,
) -> tuple[dict[str, Any], bool]:
    """Poll for a post-upgrade SIEM Health report for at most `wait_seconds`.
    Returns (latest report, fresh)."""
    deadline = clock() + max(0, wait_seconds)
    after = fetch()
    announced = False
    while not siem_health_report_is_fresh(before, after, since):
        remaining = deadline - clock()
        if remaining <= 0:
            return after, False
        if not announced:
            eprint(
                f"==> {utc_now()} waiting up to {int(remaining)}s for a SIEM Health report "
                f"generated after the upgrade (the latest is from "
                f"{after.get('created_at') or 'before the upgrade'})"
            )
            announced = True
        sleep(min(poll_seconds, max(1.0, remaining)))
        after = fetch()
    return after, True


def gate_siem_health_regressions(
    before: dict[str, Any], after: dict[str, Any], override_reason: str | None = None,
) -> dict[str, Any]:
    before_status = str(before.get("status", "not-present"))
    after_status = str(after.get("status", "not-present"))
    regressions: list[str] = []
    if after_status == "critical" and before_status != "critical":
        regressions.append(f"status worsened from {before_status} to critical")
    if after_status == "critical":
        new_findings = sorted(
            siem_health_finding_signatures(after)
            - siem_health_finding_signatures(before)
        )
        if new_findings:
            regressions.append(f"new critical-report findings: {', '.join(new_findings)}")
    if regressions and not override_reason:
        raise UpgradeError(
            "SIEM Health regressed after upgrade: " + "; ".join(regressions)
        )
    return {
        "before": before,
        "after": after,
        "regressions": regressions,
        "override": bool(regressions and override_reason),
    }


def check_backup_output_writable(output: pathlib.Path) -> str:
    """NAN-5285 (v2.0.13 retest F1): the upgrade's backup writes each
    component's archive on the host that owns it (the PostgreSQL dump on the
    current leader, wherever it is), under ``--backup-output``. A parent that
    exists only on the coordinator passed the dry run and then stopped the real
    run at ``backup:consistent-set`` with ``mkdir: Permission denied``.

    Passes when ``output`` is a writable directory, or when its nearest
    existing ancestor is a directory this user can create entries in (the
    backup's own ``mkdir -p`` will then succeed). Otherwise raises with the
    exact command that fixes this host."""
    output = pathlib.Path(output)
    if not output.is_absolute():
        output = pathlib.Path.cwd() / output
    ancestor = output
    while not ancestor.exists() and ancestor != ancestor.parent:
        ancestor = ancestor.parent
    try:
        import grp
        import pwd
        user = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
    except (ImportError, KeyError):
        user, group = str(os.getuid()), str(os.getgid())
    fix_dir = output if ancestor == output else output.parent
    fix = (
        f"on this host run: sudo install -d -o {user} -g {group} -m 0700 {fix_dir} "
        "(create it on every postgres host: the backup is written on the "
        "PostgreSQL leader, which can be any of them)"
    )
    if not ancestor.is_dir():
        raise UpgradeError(f"backup output {output}: {ancestor} is not a directory; {fix}")
    if not os.access(ancestor, os.W_OK | os.X_OK):
        raise UpgradeError(
            f"backup output {output}: {ancestor} is not writable by {user}; {fix}"
        )
    if ancestor == output:
        return f"{output} is writable"
    return f"{output} will be created under {ancestor}"


def legacy_backup_retention_check(
    backup_output: str | None, install_dir: pathlib.Path,
) -> Check:
    backup_value = str(backup_output or "")
    if not backup_value:
        return Check(
            "legacy-backup-retention", False,
            "legacy transition requires an explicit independent --backup-output",
            "single",
        )
    backup_path = pathlib.Path(backup_value).expanduser().resolve()
    install_root = install_dir.resolve()
    independent = backup_path != install_root and install_root not in backup_path.parents
    detail = (
        "explicit backup destination is outside the mutable install tree"
        if independent else
        "legacy transition backup destination must be outside the install tree"
    )
    return Check("legacy-backup-retention", independent, detail, "single")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        return json_object(json.loads(secure_read_text(path, str(path))), str(path))
    except (OSError, json.JSONDecodeError) as error:
        raise UpgradeError(f"cannot read JSON from {path}: {type(error).__name__}") from error


def write_json_atomic(path: pathlib.Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


class ManualBackupFence:
    """Single durable recovery record for a manual recovery-set fence."""

    def __init__(self, install_dir: pathlib.Path):
        self.path = install_dir / "upgrade-journal" / "manual-backup-fence.json"
        self.value: dict[str, Any] | None = None

    def exists(self) -> bool:
        return self.path.exists() or self.path.is_symlink()

    def load(self) -> dict[str, Any]:
        if not self.exists():
            raise UpgradeError("manual backup fence record does not exist")
        value = read_json(self.path)
        if value.get("version") != 1 or not isinstance(value.get("run_id"), str):
            raise UpgradeError("manual backup fence recovery record is invalid")
        self.value = value
        return value

    def begin(self, value: dict[str, Any]) -> None:
        if self.exists():
            raise UpgradeError(
                "an unrecovered manual backup fence exists; recover it before starting a new operation"
            )
        self.value = {"version": 1, **value}
        write_json_atomic(self.path, self.value)

    def phase(self, phase: str) -> None:
        if self.value is None:
            raise UpgradeError("manual backup fence was not initialized")
        self.value = {**self.value, "phase": phase, "updated_at": utc_now()}
        write_json_atomic(self.path, self.value)

    def complete(self) -> None:
        if not self.exists():
            self.value = None
            return
        self.path.unlink()
        directory = os.open(
            self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.value = None

def secure_read_text(
    path: pathlib.Path, label: str, *, maximum_bytes: int | None = None,
) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise UpgradeError(f"cannot securely open {label}: {path}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise UpgradeError(f"{label} must be a uid-owned regular file with mode 0600: {path}")
        if maximum_bytes is not None and not 0 < info.st_size <= maximum_bytes:
            raise UpgradeError(f"{label} exceeds its bounded size: {path}")
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            descriptor = -1
            value = source.read(None if maximum_bytes is None else maximum_bytes + 1)
            if maximum_bytes is not None and len(value.encode("utf-8")) > maximum_bytes:
                raise UpgradeError(f"{label} grew beyond its bounded size: {path}")
            return value
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def recover_legacy_backup_services(
    install_dir: pathlib.Path, runner: Runner,
) -> bool:
    """Restart the exact service set journaled before a legacy physical backup."""
    path = install_dir / ".nano-legacy-backup-recovery.json"
    if not (path.exists() or path.is_symlink()):
        return False
    try:
        value = json.loads(secure_read_text(
            path, "legacy backup recovery journal", maximum_bytes=65536,
        ))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise UpgradeError("legacy backup recovery journal is invalid") from error
    if (
        value.get("format") != "nano-legacy-backup-recovery-v1"
        or value.get("install_dir") != str(install_dir)
    ):
        raise UpgradeError("legacy backup recovery journal identity is invalid")
    raw_compose = value.get("compose_files")
    if not isinstance(raw_compose, list) or len(raw_compose) not in {1, 2}:
        raise UpgradeError("legacy backup recovery Compose plan is invalid")
    expected_names = ["docker-compose.yml"]
    if len(raw_compose) == 2:
        expected_names.append("docker-compose.override.yml")
    compose_files: list[pathlib.Path] = []
    if len(raw_compose) != len(expected_names):  # zip strict mode needs Python 3.10
        raise UpgradeError("legacy compose file list changed while it was read")
    for raw, expected_name in zip(raw_compose, expected_names):
        if not isinstance(raw, str):
            raise UpgradeError("legacy backup recovery Compose plan is invalid")
        compose = pathlib.Path(raw)
        if (
            compose != install_dir / expected_name
            or compose.is_symlink()
            or not compose.is_file()
        ):
            raise UpgradeError("legacy backup recovery Compose file is unsafe")
        compose_files.append(compose)
    services = value.get("services")
    if (
        not isinstance(services, list) or not services
        or len(set(services)) != len(services)
        or not all(
            isinstance(service, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", service)
            for service in services
        )
    ):
        raise UpgradeError("legacy backup recovery service plan is invalid")
    env_file = install_dir / ".env"
    if env_file.is_symlink() or not env_file.is_file():
        raise UpgradeError("legacy backup recovery environment is unsafe")
    compose = [
        "docker", "compose", "--project-directory", str(install_dir),
        "--env-file", str(env_file),
    ]
    for compose_file in compose_files:
        compose.extend(("-f", str(compose_file)))
    runner.run([*compose, "start", *services], timeout=300)
    running = set(runner.run(
        [*compose, "ps", "--status", "running", "--services"], timeout=60,
    ).stdout.splitlines())
    missing = sorted(set(services) - running)
    if missing:
        raise UpgradeError(
            "legacy backup recovery could not restart the exact service set: "
            + ", ".join(missing)
        )
    path.unlink()
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return True


def test_compose_override_arguments(install_dir: pathlib.Path) -> list[str]:
    """Return the build-bound N-1 overlay without coupling layout selection."""
    raw_override = os.environ.get("NANO_UPGRADE_TEST_COMPOSE_OVERRIDE", "")
    if not raw_override:
        return []
    if os.environ.get("NANO_NON_RELEASE_BUILD") != "1":
        raise UpgradeError(
            "NANO_UPGRADE_TEST_COMPOSE_OVERRIDE requires one embedded TEST root in a non-release build"
        )
    embedded_test_root_key_id(install_dir)
    override = pathlib.Path(raw_override).expanduser()
    if not override.is_absolute() or override.is_symlink() or not override.is_file():
        raise UpgradeError(
            "NANO_UPGRADE_TEST_COMPOSE_OVERRIDE must be an absolute regular non-symlink file"
        )
    return ["-f", str(override.resolve())]


def embedded_test_root_key_id(install_dir: pathlib.Path) -> str:
    """Authenticate a non-release install through its build-embedded TEST root."""
    if len(EMBEDDED_LAB_KEY_IDS) != 1:
        raise UpgradeError("TEST-only rehearsal requires one embedded TEST root")
    marker = install_dir / ".nano-test-upgrade-root"
    expected_key_id = EMBEDDED_LAB_KEY_IDS[0]
    try:
        marker_value = secure_read_text(
            marker, "embedded TEST-root marker", maximum_bytes=256,
        )
    except UnicodeDecodeError as error:
        raise UpgradeError("embedded TEST-root marker must be UTF-8") from error
    if marker_value != f"{expected_key_id}\n":
        raise UpgradeError(
            "embedded TEST-root marker does not match the build-embedded lab key id"
        )
    return expected_key_id


def vector_validation_arguments(
    current_layout: bool, *, managed_legacy_layout: bool = False,
) -> list[str]:
    """Keep the v2 and v0.1.703 Vector CLI contracts independently testable."""
    if current_layout:
        return [
            "exec", "-T", "vector", "vector",
            "--dangerously-allow-env-var-interpolation", "validate", "--no-environment",
            "--config-dir", "/etc/vector/config",
            "--config-dir", "/etc/vector/runtime/current/parsers",
            "--config-dir", "/etc/vector/runtime/current/configs",
            "/etc/vector/runtime/reload.toml",
        ]
    return [
        "exec", "-T", "vector", "vector", "validate", "--no-environment",
        "--config-dir", "/etc/vector/config" if managed_legacy_layout else "/etc/vector",
        "--config-dir", "/etc/vector/dynamic/sources/parsers",
        "--config-dir", "/etc/vector/dynamic/sources/configs",
    ]


def secure_append_line(path: pathlib.Path, encoded: str, label: str) -> None:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise UpgradeError(f"cannot securely open {label}: {path}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise UpgradeError(f"{label} must be a uid-owned regular file with mode 0600: {path}")
        with os.fdopen(descriptor, "a", encoding="utf-8") as output:
            descriptor = -1
            output.write(encoded + "\n")
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


ENV_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=")


def collapse_env_duplicates(lines: list[str]) -> list[str]:
    """Keep one assignment per key: the LAST one (the value Compose uses), at the
    first one's position. An earlier installer (v2.0.8) could leave two
    NANO_LICENSE_MODE lines; same rule as install.sh's nano_env_collapse_duplicates.

    Lines inside an installer-managed block (``# BEGIN NANO ...`` / ``# END NANO
    ...``) are neither counted nor rewritten: a key there plus an operator line
    below it is the documented override, not a duplicate (NAN-5282). The kept
    line goes at the first outside occurrence after the key's last block
    assignment, never above it, or the block value would take effect."""
    managed: set[int] = set()
    in_block = False
    for index, line in enumerate(lines):
        if line.startswith("# BEGIN NANO "):
            in_block = True
        elif line.startswith("# END NANO "):
            in_block = False
        elif in_block:
            managed.add(index)
    last: dict[str, str] = {}
    counts: dict[str, int] = {}
    anchor: dict[str, int] = {}
    block_line: dict[str, int] = {}
    for index, line in enumerate(lines):
        match = ENV_ASSIGNMENT.match(line)
        if not match:
            continue
        key = match.group(1)
        if index in managed:
            block_line[key] = index
            continue
        counts[key] = counts.get(key, 0) + 1
        last[key] = re.sub(r"^export\s+", "", line.lstrip())
        if key not in anchor or anchor[key] < block_line.get(key, -1):
            anchor[key] = index
    out: list[str] = []
    for index, line in enumerate(lines):
        match = ENV_ASSIGNMENT.match(line)
        if not match or index in managed:
            out.append(line)
            continue
        key = match.group(1)
        if counts[key] < 2:
            out.append(line)
        elif index == anchor[key]:
            out.append(last[key])
    return out


def _managed_env_lines(lines: list[str]) -> set[int]:
    """Indexes of lines inside installer-managed ``# BEGIN NANO`` blocks."""
    managed: set[int] = set()
    in_block = False
    for index, line in enumerate(lines):
        if line.startswith("# BEGIN NANO "):
            in_block = True
        elif line.startswith("# END NANO "):
            in_block = False
        elif in_block:
            managed.add(index)
    return managed


def duplicate_env_keys(lines: list[str]) -> list[str]:
    """Keys (never values) assigned more than once outside managed blocks, in
    first-seen order: what ``collapse_env_duplicates`` will collapse."""
    managed = _managed_env_lines(lines)
    counts: dict[str, int] = {}
    for index, line in enumerate(lines):
        match = ENV_ASSIGNMENT.match(line)
        if match and index not in managed:
            counts[match.group(1)] = counts.get(match.group(1), 0) + 1
    return [key for key, count in counts.items() if count > 1]


def set_env_keys_in_place(lines: list[str], replacements: dict[str, str]) -> list[str]:
    """Set each key where it already is (NAN-5285, v2.0.13 retest F6).

    The upgrade used to delete a replaced key and append it, so NANO_VERSION
    moved from line 1 to the end and every upgrade reordered an operator's
    .env. Now the assignment that takes effect (the last outside a managed
    block, else the last inside one) is rewritten in its line; any other
    assignment of the key is dropped, as before. Only a key the file does not
    have is appended. Same rule as install.sh's nano_env_set_keys."""
    managed = _managed_env_lines(lines)
    target: dict[str, int] = {}
    target_managed: dict[str, bool] = {}
    for index, line in enumerate(lines):
        match = ENV_ASSIGNMENT.match(line)
        if not match or match.group(1) not in replacements:
            continue
        key = match.group(1)
        inside = index in managed
        if key in target and not target_managed[key] and inside:
            continue  # an outside assignment already wins over the block
        target[key] = index
        target_managed[key] = inside
    out: list[str] = []
    for index, line in enumerate(lines):
        match = ENV_ASSIGNMENT.match(line)
        if match and match.group(1) in replacements:
            key = match.group(1)
            if target[key] == index:
                out.append(f"{key}={replacements[key]}")
            continue
        out.append(line)
    out.extend(f"{key}={value}" for key, value in replacements.items() if key not in target)
    return out


class EnvFile:
    def __init__(self, path: pathlib.Path):
        self.path = path
        self._validate()

    def _validate(self) -> None:
        try:
            info = self.path.lstat()
        except OSError as error:
            raise UpgradeError(f"required environment file is missing: {self.path}") from error
        if self.path.is_symlink() or not self.path.is_file():
            raise UpgradeError(f"environment file must be a regular non-symlink: {self.path}")
        if info.st_uid != os.getuid():
            raise UpgradeError(f"environment file is not owned by uid {os.getuid()}: {self.path}")
        if info.st_mode & 0o077:
            raise UpgradeError(f"environment file must have mode 0600: {self.path}")

    def values(self) -> dict[str, str]:
        result: dict[str, str] = {}
        lines = secure_read_text(self.path, "environment file").splitlines()
        for line in lines:
            if not line or line.lstrip().startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                continue
            value = value.rstrip("\r")
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            result[key] = value
        return result

    def replace(self, key: str, value: str) -> None:
        self.replace_many({key: value})

    def replace_many(self, replacements: dict[str, str]) -> None:
        if not replacements:
            return
        for key, value in replacements.items():
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
                raise UpgradeError("unsafe environment key")
            if "\n" in value or "\r" in value:
                raise UpgradeError("unsafe environment value")
        lines = secure_read_text(self.path, "environment file").splitlines()
        collapsed = duplicate_env_keys(lines)
        if collapsed:
            eprint(
                "Collapsed duplicate .env line(s) for "
                f"{', '.join(collapsed)} (kept the value in effect)"
            )
        kept = set_env_keys_in_place(collapse_env_duplicates(lines), replacements)
        descriptor, temporary = tempfile.mkstemp(prefix=".env.upgrade.", dir=self.path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                output.write("\n".join(kept) + "\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(descriptor)
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise


@dataclasses.dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str
    node: str = "local"

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class Node:
    name: str
    address: str
    roles: frozenset[str]
    clickhouse_shard: int | None = None
    clickhouse_replica: int | None = None
    keeper_id: int | None = None
    ssh_user: str | None = None
    ssh_port: int = 22
    ssh_identity: str | None = None
    host_id: str | None = None


@dataclasses.dataclass
class RunState:
    run_id: str
    journal: pathlib.Path
    events: list[dict[str, Any]]

    @property
    def done_steps(self) -> set[str]:
        completed: set[str] = set()
        for event in self.events:
            if event.get("event") == "step_done":
                completed.add(str(event["step"]))
            elif event.get("event") == "step_reset":
                completed.discard(str(event["step"]))
        return completed

    @property
    def started_steps(self) -> set[str]:
        return {
            str(event["step"])
            for event in self.events
            if event.get("event") == "step_started" and "step" in event
        }

    def latest(self, event_name: str) -> dict[str, Any] | None:
        return next((event for event in reversed(self.events) if event.get("event") == event_name), None)


class Journal:
    def __init__(self, install_dir: pathlib.Path):
        self.directory = install_dir / "upgrade-journal"

    def ensure_directory(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            info = self.directory.lstat()
        except OSError as error:
            raise UpgradeError(f"cannot inspect upgrade journal directory: {self.directory}") from error
        if self.directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise UpgradeError(f"upgrade journal directory must be a uid-owned non-symlink directory: {self.directory}")
        if info.st_mode & 0o077:
            raise UpgradeError(f"upgrade journal directory must have mode 0700: {self.directory}")

    def create(self, run_id: str, initial: dict[str, Any]) -> RunState:
        self.ensure_directory()
        path = self.directory / f"{run_id}.jsonl"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError as error:
            raise UpgradeError(f"upgrade journal already exists: {path}") from error
        os.close(descriptor)
        state = RunState(run_id, path, [])
        self.append(state, "run_started", **initial)
        return state

    def append(self, state: RunState, event: str, **fields: Any) -> None:
        record = {"at": utc_now(), "event": event, "run_id": state.run_id, **fields}
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"))
        secure_append_line(state.journal, encoded, "upgrade journal")
        state.events.append(record)

    @staticmethod
    def _terminal(events: Sequence[dict[str, Any]]) -> bool:
        return any(
            event.get("event") in {"run_completed", "rollback_completed", "run_abandoned"}
            for event in events
        )

    def find_latest_incomplete(self) -> RunState | None:
        if not self.directory.exists():
            return None
        self.ensure_directory()
        candidates = sorted(
            self.directory.glob("upgrade-*.jsonl"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        for path in candidates:
            events = self._events(path)
            if events and not self._terminal(events):
                return RunState(path.stem, path, events)
        return None

    def load_latest_incomplete(self) -> RunState:
        state = self.find_latest_incomplete()
        if state is not None:
            return state
        raise UpgradeError("no incomplete upgrade journal exists to resume")

    def load_latest_completed(self) -> RunState:
        if not self.directory.exists():
            raise UpgradeError("no completed upgrade journal exists")
        self.ensure_directory()
        candidates = sorted(
            self.directory.glob("upgrade-*.jsonl"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        for path in candidates:
            events = self._events(path)
            if any(event.get("event") == "run_completed" for event in events) and not any(
                event.get("event") == "rollback_completed" for event in events
            ):
                return RunState(path.stem, path, events)
        raise UpgradeError("no completed, non-rolled-back upgrade journal exists")

    @staticmethod
    def _events(path: pathlib.Path) -> list[dict[str, Any]]:
        if path.is_symlink() or not path.is_file():
            raise UpgradeError(f"invalid journal file: {path}")
        events: list[dict[str, Any]] = []
        try:
            for number, line in enumerate(secure_read_text(path, "upgrade journal").splitlines(), 1):
                value = json_object(json.loads(line), f"{path}:{number}")
                events.append(value)
        except (OSError, json.JSONDecodeError) as error:
            raise UpgradeError(f"invalid upgrade journal: {path}") from error
        return events


class Runner:
    @staticmethod
    def _safe_command_label(argv: Sequence[str]) -> str:
        """Identify a failed operation without echoing paths, SQL, or secrets."""
        program = pathlib.Path(argv[0]).name
        if program != "docker" or len(argv) < 2:
            return program
        if argv[1] == "compose":
            operations = {
                "config", "down", "exec", "logs", "ps", "rm", "run", "stop", "up",
            }
            operation = next((value for value in argv[2:] if value in operations), "operation")
            label = f"docker compose {operation}"
            if operation in {"run", "up"}:
                safe_services = set().union(*ROLE_SERVICES.values(), {"clickhouse-migrate"})
                selected = sorted({value for value in argv[2:] if value in safe_services})
                if selected:
                    label += f" ({','.join(selected)})"
            return label
        if argv[1] == "image" and len(argv) >= 3 and argv[2] in {"inspect", "load", "tag"}:
            return f"docker image {argv[2]}"
        if argv[1] in {"inspect", "load", "tag"}:
            return f"docker {argv[1]}"
        return "docker"

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: int = 60,
        input_text: str | None = None,
        check: bool = True,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                list(argv),
                input=input_text,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise UpgradeError(
                f"command timed out after {timeout}s: {self._safe_command_label(argv)}"
            ) from error
        except OSError as error:
            raise UpgradeError(
                f"cannot execute required command: {self._safe_command_label(argv)}"
            ) from error
        if check and result.returncode != 0:
            raise UpgradeError(
                f"command failed (exit {result.returncode}): {self._safe_command_label(argv)}"
            )
        return result


# The online checker auto-locks a cache older than this (nanosiem-core
# license/checker.rs STALE_LICENSE_DAYS); the preflight uses the same bound.
ONLINE_LICENSE_STALE_DAYS = 14


def parse_role_env(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    EnvFile(path)
    for number, line in enumerate(secure_read_text(path, "role environment file").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise UpgradeError(f"invalid role environment line {number}")
        key, encoded = line.split("=", 1)
        try:
            value = json.loads(encoded)
        except json.JSONDecodeError as error:
            raise UpgradeError(f"invalid role environment value on line {number}") from error
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not isinstance(value, str):
            raise UpgradeError(f"invalid role environment entry on line {number}")
        values[key] = value
    return values


class LocalOps:
    def __init__(self, install_dir: pathlib.Path, nano_cli: pathlib.Path, runner: Runner | None = None):
        self.install_dir = install_dir.resolve()
        self.nano_cli = nano_cli.resolve()
        self.runner = runner or Runner()
        self.env_file = EnvFile(self.install_dir / ".env")
        self.env = self.env_file.values()
        self.role_env = parse_role_env(self.install_dir / ".nano-role.env")
        self.legacy_layout: Any | None = None
        self._legacy_transition_rollout = False
        self._legacy_bridge_rollout = False
        self.transition_record = self.install_dir / ".nano-legacy-transition.json"
        self.bridge_record = self.install_dir / ".nano-legacy-bridge.json"
        transition = read_json(self.transition_record) if self.transition_record.is_file() else {}
        bridge = read_json(self.bridge_record) if self.bridge_record.is_file() else {}
        if (
            bridge.get("format") == "nano-legacy-bridge-v1"
            and bridge.get("state") in {"started", "image-tag-published"}
        ):
            self._legacy_bridge_rollout = True
        canonical_version_value = self.env.get("NANO_VERSION", "")
        canonical_ready = bool(
            canonical_version_value
            and (self.install_dir / "docker-compose.opensource.yml").is_file()
        )
        if not self.role_env and not canonical_ready:
            try:
                self.legacy_layout = nano_legacy_layout.resolve_legacy_layout(
                    self.install_dir,
                    self.nano_cli.parent.parent / "deploy/release/legacy",
                    self.runner,
                )
            except nano_legacy_layout.LegacyLayoutError as error:
                if transition.get("format") == "nano-legacy-transition-v1":
                    raise UpgradeError(
                        "incomplete legacy transition cannot resolve either its source or target layout"
                    ) from error
                raise UpgradeError(str(error)) from error
        self.roles = frozenset(filter(None, self.role_env.get("NANO_ROLE_PROFILES", "").split(",")))
        if not self.roles:
            self.roles = frozenset({"clickhouse", "postgres", "ingest", "app"})
        # NAN-5214: a Patroni member when the inventory has 2+ postgres hosts.
        self.pg_ha = self.role_env.get("NANO_POSTGRES_HA") == "true"
        self.pg_service = "postgres-ha" if self.pg_ha else "postgres"
        self.host_name = self.role_env.get("NANO_HOST_NAME", "single")
        if self.legacy_layout is not None:
            self.edition = self.legacy_layout.edition
            qualified_version = canonical_version(self.legacy_layout.version)
            try:
                self.version = nano_legacy_bridge.effective_runtime_version(
                    qualified_version, self.env.get("IMAGE_TAG", ""), bridge,
                    edition=self.edition,
                )
            except nano_legacy_bridge.LegacyBridgeError as error:
                raise UpgradeError(str(error)) from error
            self.schema_profile = self.legacy_layout.schema_profile
        else:
            self.edition = self.env.get("NANO_EDITION", "open")
            self.version = canonical_version(self.env.get("NANO_VERSION", ""))
            self.schema_profile = self.env.get("NANO_SCHEMA_PROFILE", "udm")
        self.compose_args = self._compose_args()

    def _resource_roles(self) -> frozenset[str]:
        """Return the services that contribute signed resource minima.

        Topology roles remain sourced from ``.nano-role.env``.  On the
        single-node layout, Tenzir is an optional Compose profile rather than
        a topology role, so both the effective environment and the rendered
        service model must say it is enabled before its floor is charged.
        """
        roles = set(self.roles)
        if getattr(self, "role_env", {}):
            return frozenset(roles)
        profiles = os.environ.get(
            "COMPOSE_PROFILES", getattr(self, "env", {}).get("COMPOSE_PROFILES", "")
        )
        enabled = {item.strip() for item in profiles.split(",") if item.strip()}
        if "tenzir" in enabled or "*" in enabled:
            if not self._service_exists("tenzir"):
                raise UpgradeError(
                    "COMPOSE_PROFILES enables tenzir but rendered Compose has no tenzir service"
                )
            roles.add("tenzir")
        return frozenset(roles)

    def runtime_identity(self) -> dict[str, Any]:
        def coordinate(name: str) -> int | None:
            raw = self.role_env.get(name, "")
            if not raw:
                return None
            if not raw.isdigit() or int(raw) < 1:
                raise UpgradeError(f"rendered runtime identity has invalid {name}")
            return int(raw)

        return {
            "host_name": self.host_name,
            "host_id": self.role_env.get("NANO_HOST_ID") or None,
            "address": self.role_env.get(
                "NANO_HOST_ADDRESS",
                self.role_env.get("NANO_CLUSTER_BIND_ADDRESS", "127.0.0.1"),
            ),
            "roles": sorted(self.roles),
            "clickhouse_shard": coordinate("NANO_CLICKHOUSE_SHARD"),
            "clickhouse_replica": coordinate("NANO_CLICKHOUSE_REPLICA"),
            "keeper_id": coordinate("NANO_KEEPER_ID"),
            "deployment_id": self.role_env.get("NANO_DEPLOYMENT_ID", "single"),
            "deployment_identity_sha256": self.role_env.get(
                "NANO_DEPLOYMENT_IDENTITY_SHA256", "single"
            ),
            "version": self.version,
            "edition": self.edition,
        }

    def legacy_physical_archive_inputs(
        self,
    ) -> tuple[nano_legacy_layout.LegacyArchiveInput, ...]:
        """Expose qualified bind roots and conservative bytes to disk planning."""
        if getattr(self, "legacy_layout", None) is None:
            return ()
        return self.legacy_layout.archive_inputs

    def _legacy_compose_args(self) -> list[str]:
        if self.legacy_layout is None:
            raise UpgradeError("legacy Compose arguments requested for a canonical layout")
        arguments = [
            "docker", "compose", "--project-directory", str(self.install_dir),
            "--env-file", str(self.install_dir / ".env"),
        ]
        for compose in self.legacy_layout.compose_files:
            arguments.extend(("-f", str(compose)))
        return arguments

    def _with_preserved_compose_overlays(self, arguments: list[str]) -> list[str]:
        overlays = self.env.get("NANO_COMPOSE_OVERLAYS", "").split()
        for overlay in overlays:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml", overlay):
                raise UpgradeError("NANO_COMPOSE_OVERLAYS contains an invalid file name")
            path = self.install_dir / overlay
            if path.is_symlink() or not path.is_file():
                raise UpgradeError(f"NANO_COMPOSE_OVERLAYS file is missing or symbolic: {overlay}")
            arguments.extend(("-f", str(path)))
        return arguments

    def _compose_args(self) -> list[str]:
        if self.legacy_layout is not None:
            arguments = self._legacy_compose_args()
        elif self.role_env:
            compose = self.install_dir / "deploy/compose/docker-compose.enterprise.yml"
            if not compose.is_file():
                raise UpgradeError("role-split compose file is missing")
            arguments = [
                # Match scripts/nano's installed-layout invocation. Anchoring
                # Compose at the enterprise file's directory resolves its
                # ../../docker-compose.opensource.yml extend to the install
                # root on a real /opt/nano host.
                "docker", "compose", "--project-directory", str(compose.parent),
                "--env-file", str(self.install_dir / ".env"),
                "--env-file", str(self.install_dir / ".nano-role.env"),
                "-f", str(compose),
            ]
        else:
            compose = self.install_dir / "docker-compose.opensource.yml"
            if not compose.is_file():
                raise UpgradeError("single-node compose file is missing")
            arguments = self._with_preserved_compose_overlays([
                "docker", "compose", "--project-directory", str(compose.parent),
                "--env-file", str(self.install_dir / ".env"), "-f", str(compose),
            ])

        # Kept separate from layout selection so the legacy-layout lane can
        # compose its production overlays without replacing this N-1 seam.
        arguments.extend(test_compose_override_arguments(self.install_dir))
        return arguments

    def compose(
        self, arguments: Sequence[str], *, timeout: int = 120,
        input_text: str | None = None, check: bool = True,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self.runner.run(
            [*self.compose_args, *arguments], timeout=timeout,
            input_text=input_text, check=check, env=env,
        )

    def _safe_service_failure(self, result: subprocess.CompletedProcess[str]) -> str:
        """Return one bounded child diagnostic after removing configured secrets."""
        output = "\n".join((result.stdout or "", result.stderr or ""))
        for key, value in self.env.items():
            if value and re.search(r"PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL", key, re.I):
                output = output.replace(value, "[REDACTED]")
        output = re.sub(r"(://[^:/\s]+:)[^@\s]+(@)", r"\1[REDACTED]\2", output)
        output = re.sub(
            r"(?i)(password|secret|token|credential)(\s*[=:]\s*)[^\s,;]+",
            r"\1\2[REDACTED]",
            output,
        )
        lines = [re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
                 for line in output.splitlines() if line.strip()]
        actionable = [
            line for line in lines
            if "DB::Exception:" in line or re.search(r"\b(error|failed|failure)\b", line, re.I)
        ]
        return (actionable[-1] if actionable else f"process exited {result.returncode}")[:500]

    def _configured_services(self) -> set[str]:
        """Services this host's Compose project actually runs.

        NAN-5213: a multi-app host keeps the `dragonfly` service defined but
        scaled to zero (`deploy.replicas: 0`, the shared Valkey replaces it);
        `config --services` still lists it, which would make preflight probe
        and post-verify wait for a container that never exists.
        """
        result = self.compose(["config", "--format", "json"], timeout=30)
        try:
            services = json.loads(result.stdout).get("services")
        except (ValueError, AttributeError):
            services = None
        if not isinstance(services, dict):
            # Not JSON (an older Compose): treat the output as a name list.
            return set(result.stdout.split())
        active: set[str] = set()
        for name, spec in services.items():
            replicas = None
            if isinstance(spec, dict):
                deploy = spec.get("deploy")
                if isinstance(deploy, dict):
                    replicas = deploy.get("replicas")
                if replicas is None:
                    replicas = spec.get("scale")
            try:
                if replicas is not None and int(replicas) == 0:
                    continue
            except (TypeError, ValueError):
                pass
            active.add(str(name))
        return active

    def _service_exists(self, service: str) -> bool:
        return service in self._configured_services()

    def _running_services(self, candidates: Iterable[str]) -> list[str]:
        allowed = list(dict.fromkeys(candidates))
        result = self.compose(
            ["--profile", "*", "ps", "--status", "running", "--services"],
            timeout=30,
        )
        running = set(result.stdout.split())
        return [service for service in allowed if service in running]

    @staticmethod
    def _exact_role_services(
        role: str, services: Iterable[str], *, writers_only: bool = False,
    ) -> list[str]:
        return exact_role_services(role, services, writers_only=writers_only)

    def running_writers(self, role: str) -> dict[str, Any]:
        candidates = self._exact_role_services(role, (), writers_only=True)
        # Empty input above validates the role; use the complete allowlist for
        # the profile-inclusive running-state snapshot.
        if role == "app":
            candidates = list(BACKUP_WRITER_SERVICES)
        else:
            candidates = list(INGEST_SERVICES)
        return {"role": role, "services": self._running_services(candidates)}

    def api_mutation_fence_capable(self) -> bool:
        if "app" not in self.roles or not self._service_exists("nano-api"):
            return False
        result = self.compose(
            ["exec", "-T", "nano-api", "test", "-f", BACKUP_MUTATION_CAPABILITY],
            timeout=30, check=False,
        )
        return result.returncode == 0

    def set_api_mutation_fence(self, active: bool, owner: str) -> dict[str, Any]:
        safe_name(owner, "backup mutation fence owner")
        if "postgres" not in self.roles:
            raise UpgradeError("API mutation fence must be changed on the PostgreSQL host")
        if active:
            query = (
                "UPDATE backup_mutation_fence SET active=true, "
                f"owner='{owner}', activated_at=clock_timestamp() "
                "WHERE singleton=true RETURNING owner"
            )
        else:
            query = (
                "UPDATE backup_mutation_fence SET active=false, owner=NULL, "
                "activated_at=NULL WHERE singleton=true RETURNING 'cleared'"
            )
        result = self._pg_query(query)
        if not result:
            raise UpgradeError("PostgreSQL backup mutation fence row is missing")
        return {"active": active, "owner": owner if active else None}

    def _monitoring_enabled(self) -> bool:
        """NAN-5250: the inventory has a monitoring host (the renderer's flag)."""
        role_env = getattr(self, "role_env", None) or {}
        return role_env.get("NANO_MONITORING_ENABLED") == "true"

    def _service_expected(self, service: str) -> bool:
        if service == "vector-tap" and not self.env.get("NANO_VECTOR_TAP_TOKEN"):
            return False
        return self._service_exists(service)

    def _service_container(self, service: str) -> str:
        result = self.compose(["ps", "-q", service], timeout=30)
        container = result.stdout.strip().splitlines()
        if len(container) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", container[0]):
            raise UpgradeError(f"compose service is not uniquely running: {service}")
        return container[0]

    def _wait_container(self, service: str, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        last = "missing"
        while time.monotonic() < deadline:
            with contextlib.suppress(UpgradeError):
                container = self._service_container(service)
                result = self.runner.run(
                    ["docker", "inspect", "--format", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", container],
                    timeout=20,
                )
                last = result.stdout.strip()
                if last in {"running", "running healthy"}:
                    return
                if last.startswith("exited") or last.startswith("dead"):
                    break
            time.sleep(2)
        raise UpgradeError(f"service {service} did not become healthy within {timeout}s (state {last})")

    def _wait_services(self, services: Iterable[str], timeout: int) -> list[str]:
        selected = list(dict.fromkeys(services))
        for service in selected:
            self._wait_container(service, timeout)
        return selected

    def _ch_query(
        self, query: str, timeout: int = 60, *, retry_memory_pressure: bool = False,
    ) -> str:
        if not self._service_exists("clickhouse"):
            raise UpgradeError("ClickHouse service is not present")
        port = self.role_env.get("NANO_CLICKHOUSE_NATIVE_PORT", "9000")
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise UpgradeError("rendered ClickHouse native port is invalid")
        host = self.role_env.get("NANO_CLICKHOUSE_REMOTE_ADDRESS", "127.0.0.1")
        if not SAFE_HOST_RE.fullmatch(host):
            raise UpgradeError("rendered ClickHouse address is invalid")
        password = self.env.get("CLICKHOUSE_ADMIN_PASSWORD", "")
        if not password:
            raise UpgradeError("ClickHouse admin credential is missing")
        secure = self.role_env.get("NANO_PRIVATE_TLS") == "true"
        server_name = self.role_env.get("NANO_TLS_SERVER_NAME", "")
        if secure and not SAFE_HOST_RE.fullmatch(server_name):
            raise UpgradeError("rendered ClickHouse TLS server name is invalid")
        script = r'''
IFS= read -r nano_clickhouse_password
[ -n "$nano_clickhouse_password" ] || { echo "ClickHouse admin credential is empty" >&2; exit 1; }
escaped=$(printf '%s' "$nano_clickhouse_password" | sed \
  -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')
umask 077
config=$(mktemp)
trap 'rm -f "$config"' EXIT HUP INT TERM
if [ "$4" = true ]; then
  cat >"$config" <<EOF
<clickhouse>
  <password>$escaped</password>
  <openSSL>
    <client>
      <caConfig>/etc/nano/tls/ca.crt</caConfig>
      <verificationMode>strict</verificationMode>
      <loadDefaultCAFile>false</loadDefaultCAFile>
      <invalidCertificateHandler><name>RejectCertificateHandler</name></invalidCertificateHandler>
    </client>
  </openSSL>
</clickhouse>
EOF
  exec clickhouse-client --config-file "$config" --secure --tls-sni-override "$5" \
    --host "$1" --port "$2" --user nanosiem_admin --format TSVRaw --query "$3"
fi
printf '<clickhouse><password>%s</password></clickhouse>\n' "$escaped" >"$config"
exec clickhouse-client --config-file "$config" --host "$1" --port "$2" \
  --user nanosiem_admin --format TSVRaw --query "$3"
'''
        arguments = [
            "exec", "-T", "clickhouse", "env", "-u", "CLICKHOUSE_ADMIN_PASSWORD",
            "bash", "-ec", script, "nano-upgrade", host, port, query,
            str(secure).lower(), server_name,
        ]
        if not retry_memory_pressure:
            result = self.compose(
                arguments, timeout=timeout, input_text=password + "\n",
            )
            return result.stdout.strip()

        # Immediately after migration/app rollout, the managed legacy memory
        # profile can transiently reject even this tiny ledger SELECT with
        # ClickHouse code 241 while async-insert flushes release their memory.
        # Only the read-only ledger caller enables this bounded retry; no
        # mutation or general ClickHouse command is ever replayed here.
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UpgradeError(
                    f"read-only ClickHouse ledger remained memory constrained for {timeout}s"
                )
            result = self.compose(
                arguments,
                timeout=max(1, int(remaining)),
                input_text=password + "\n",
                check=False,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            if result.returncode != 241:
                raise UpgradeError(
                    f"command failed (exit {result.returncode}): docker compose exec"
                )
            time.sleep(min(2, max(0, deadline - time.monotonic())))

    def _pg_query(self, query: str, timeout: int = 60) -> str:
        user = self.env.get("POSTGRES_USER", "nanosiem")
        database = self.env.get("POSTGRES_DB", "nanosiem")
        result = self.compose(
            ["exec", "-T", self.pg_service, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", database, "-At", "-F", "\t", "-c", query],
            timeout=timeout,
        )
        return result.stdout.strip()

    def _selected_image_sizes(self, manifest: dict[str, Any]) -> list[int]:
        images = manifest.get("images", [])
        if not isinstance(images, list):
            raise UpgradeError("manifest images must be an array")
        selected: list[int] = []
        roles = self._resource_roles()
        for image in images:
            entry = json_object(image, "manifest image")
            name = entry.get("name")
            size = entry.get("size")
            if not isinstance(name, str) or not name:
                raise UpgradeError("manifest image name is invalid")
            if not isinstance(size, int) or size < 0:
                raise UpgradeError("manifest image size is invalid")
            image_roles = BUNDLE_IMAGE_ROLES.get(name)
            if image_roles is None or not roles or image_roles & roles:
                if manifest.get("source") == "registry" and self._registry_image_present(entry):
                    # NAN-5251: a pull of an image already here by its signed
                    # digest (unchanged third-party images, a resumed run)
                    # writes nothing; the plan size is only an estimate.
                    size = 0
                selected.append(size)
        return selected

    def _bundle_load(self, bundle: pathlib.Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        load_environment = dict(env or os.environ)
        # The loader selects this host's images from its roles; pass them
        # explicitly instead of relying on the worker's working directory.
        if getattr(self, "role_env", None) and getattr(self, "roles", None):
            load_environment.setdefault("NANO_ROLE_PROFILES", ",".join(sorted(self.roles)))
        return self.runner.run(
            [str(self.nano_cli), "bundle", "load", str(bundle),
             *bundle_cli_arguments(bundle, self.env.get("NANO_IMAGE_PREFIX", ""))],
            timeout=7200,
            env=load_environment,
            check=False,
        )

    def _registry_auth_probe(self, manifest: dict[str, Any]) -> str:
        """Ask the registry itself: a cached image never proves the login works."""
        private = private_registry_images(manifest)
        if not private:
            return ""
        ref, digest = str(private[0]["ref"]), str(private[0]["digest"])
        head, _, last = ref.rpartition("/")
        target = f"{head}/{last.split(':', 1)[0]}@{digest}"
        probe = self.runner.run(
            ["docker", "buildx", "imagetools", "inspect", "--raw", target],
            timeout=60, check=False,
        )
        if probe.returncode == 0:
            return f"registry accepted this host's credential for {head.split('/', 1)[0]}"
        detail = " ".join((probe.stderr or "").split())
        if (
            "unknown command" in detail
            or "is not a docker command" in detail
            or ("buildx" in detail and "not found" in detail)
        ):
            return ""  # no buildx: the digest pulls below are the auth test
        raise UpgradeError(
            f"the registry refused this host's credential for {target.split('@', 1)[0]} "
            f"({detail[-160:] or f'exit {probe.returncode}'}): log in again with a fresh "
            "pull credential from app.nano.rs, then rerun"
        )

    def _pull_registry_images(self, bundle: pathlib.Path, manifest: dict[str, Any] | None = None) -> str:
        auth = self._registry_auth_probe(manifest or {})
        pulled = self._bundle_load(bundle)
        if pulled.returncode != 0:
            reason = (pulled.stderr or "").strip().splitlines()
            raise UpgradeError(
                f"{reason[-1] if reason else f'image pull failed (exit {pulled.returncode})'}"
            )
        summary = (pulled.stdout or "").strip().splitlines()
        result = summary[-1] if summary else "pulled this host's images by signed digest"
        return f"{auth}; {result}" if auth else result

    def _registry_image_present(self, entry: dict[str, Any]) -> bool:
        ref, digest = str(entry.get("ref", "")), str(entry.get("digest", ""))
        if not ref or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            return False
        head, _, last = ref.rpartition("/")
        repository = f"{head}/{last.split(':', 1)[0]}" if head else last.split(":", 1)[0]
        try:
            result = self.runner.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", f"{repository}@{digest}"],
                timeout=30, check=False,
            )
        except UpgradeError:
            return False
        return result.returncode == 0

    @staticmethod
    def _filesystem_space(
        path: pathlib.Path, *, nearest_existing: bool = False,
    ) -> tuple[str, int]:
        probe = pathlib.Path(os.path.abspath(path))
        while nearest_existing and not probe.exists():
            if probe.parent == probe:
                raise UpgradeError(f"cannot identify filesystem for {path}")
            probe = probe.parent
        status = probe.stat()
        usage = shutil.disk_usage(probe)
        return f"device:{status.st_dev}", usage.free

    @staticmethod
    def _container_path(raw: str, label: str) -> str:
        if not raw or "\n" in raw or "\r" in raw:
            raise UpgradeError(f"cannot resolve {label} path")
        path = pathlib.PurePosixPath(raw)
        if not path.is_absolute() or ".." in path.parts:
            raise UpgradeError(f"cannot resolve {label} path")
        return str(path)

    def _docker_root_dir(self) -> str:
        if hasattr(self, "_docker_root_path"):
            return str(self._docker_root_path)
        root = self.runner.run(
            ["docker", "info", "--format", "{{.DockerRootDir}}"], timeout=30
        ).stdout.strip()
        if root and ("\n" in root or not pathlib.PurePosixPath(root).is_absolute()):
            raise UpgradeError("Docker daemon returned an invalid storage root")
        self._docker_root_path = root
        return root

    def _service_filesystem_space(self, service: str, path: str) -> FilesystemSpace:
        path = self._container_path(path, f"{service} filesystem")
        result = self.compose(["exec", "-T", service, "df", "-Pk", path], timeout=30)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        fields = lines[-1].split() if lines else []
        if len(fields) < 4 or not fields[3].isdigit():
            raise UpgradeError(f"cannot parse {service} filesystem free space")
        available = int(fields[3]) * 1024
        daemon_identity = f"docker-device:{fields[0]}"

        container = self.compose(["ps", "-q", service], timeout=30).stdout.strip()
        if not container or "\n" in container:
            raise UpgradeError(f"cannot identify running {service} container")
        inspected = self.runner.run(
            ["docker", "inspect", container, "--format", "{{json .Mounts}}"],
            timeout=30,
        )
        try:
            mounts = json.loads(inspected.stdout)
        except json.JSONDecodeError as error:
            raise UpgradeError(f"cannot inspect {service} storage mounts") from error
        if not isinstance(mounts, list):
            raise UpgradeError(f"cannot inspect {service} storage mounts")
        matching: list[tuple[int, str]] = []
        for value in mounts:
            if not isinstance(value, dict):
                continue
            destination = value.get("Destination")
            source = value.get("Source")
            if not isinstance(destination, str) or not isinstance(source, str):
                continue
            destination = destination.rstrip("/") or "/"
            if path == destination or (
                destination != "/" and path.startswith(destination + "/")
            ):
                matching.append((len(destination), source))
        if matching:
            source = max(matching)[1]
            docker_root = self._docker_root_dir()
            if docker_root and (
                source == docker_root
                or source.startswith(docker_root.rstrip("/") + "/")
            ):
                # Docker Desktop and remote daemons expose the volume's real
                # device to the container but hide the daemon host path from
                # the coordinator.  Sources nested below DockerRootDir still
                # share its capacity, so merge their simultaneous allocations.
                return FilesystemSpace(f"docker-root:{docker_root}", available)
        return FilesystemSpace(daemon_identity, available)

    def _docker_filesystem_space(self) -> FilesystemSpace:
        root = self._docker_root_dir()
        services = self._configured_services()
        probe = next((
            service
            for service in (*APP_SERVICES, *INGEST_SERVICES, "postgres", "clickhouse", "keeper")
            if service in services
        ), None)
        if probe is None:
            raise UpgradeError("cannot prove free space in Docker storage")
        space = self._service_filesystem_space(probe, "/")
        if root:
            return FilesystemSpace(f"docker-root:{root}", space.available_bytes)
        return space

    def _database_storage(
        self,
    ) -> tuple[dict[str, DatabaseStorage], FilesystemSpace | None]:
        stores: dict[str, DatabaseStorage] = {}
        clickhouse_backup: FilesystemSpace | None = None
        if "postgres" in self.roles:
            raw = self._pg_query("SELECT pg_database_size(current_database())")
            if not raw.isdigit():
                raise UpgradeError("cannot measure PostgreSQL recovery-set source bytes")
            data_path = self._container_path(
                self._pg_query("SHOW data_directory"), "PostgreSQL data",
            )
            stores["postgres"] = DatabaseStorage(
                "postgres", int(raw),
                self._service_filesystem_space(self.pg_service, data_path),
            )
        if "clickhouse" in self.roles:
            raw = self._ch_query(
                "SELECT coalesce(sum(bytes_on_disk),0) FROM system.parts "
                "WHERE active AND database='nanosiem'"
            )
            if not raw.isdigit():
                raise UpgradeError("cannot measure ClickHouse recovery-set source bytes")
            data_path = self._container_path(
                self._ch_query("SELECT path FROM system.disks WHERE name='default'"),
                "ClickHouse default disk",
            )
            if getattr(self, "legacy_layout", None) is not None:
                # v0.1.703 has no dedicated backups disk. The mandatory
                # native archive is created briefly on the qualified default
                # bind mount before it is copied into the encrypted payload.
                backup_path = data_path
            else:
                backup_path = self._container_path(
                    self._ch_query("SELECT path FROM system.disks WHERE name='backups'"),
                    "ClickHouse backups disk",
                )
            stores["clickhouse"] = DatabaseStorage(
                "clickhouse", int(raw),
                self._service_filesystem_space("clickhouse", data_path),
            )
            clickhouse_backup = self._service_filesystem_space(
                "clickhouse", backup_path,
            )
        return stores, clickhouse_backup

    def _backup_archive_inputs(
        self, stores: dict[str, DatabaseStorage],
    ) -> tuple[BackupArchiveInput, ...]:
        """Describe every item the backup command will place in its payload.

        The legacy-layout transition can append exact-size physical snapshot
        entries here after it inventories qualified persistent bind mounts.
        """
        archives: list[BackupArchiveInput] = []
        postgres = stores.get("postgres")
        if postgres is not None:
            archives.append(BackupArchiveInput(
                "postgres-dump", postgres.source_bytes, "backup_postgres_ratio",
            ))
        clickhouse = stores.get("clickhouse")
        # NAN-5202: the default backup holds no ClickHouse data, so it needs
        # no native-archive space. The legacy transition still captures it.
        if clickhouse is not None and (
            getattr(self, "legacy_layout", None) is not None
            or getattr(self, "include_clickhouse_data", False)
        ):
            destination = (
                "clickhouse-data"
                if getattr(self, "legacy_layout", None) is not None
                else "clickhouse-backups"
            )
            archives.append(BackupArchiveInput(
                "clickhouse-archive", clickhouse.source_bytes,
                "backup_clickhouse_ratio", destination,
            ))
        for index, item in enumerate(self.legacy_physical_archive_inputs()):
            archives.append(BackupArchiveInput(
                f"legacy-physical-{index:03d}", item.archive_bytes_upper_bound,
            ))
        return tuple(archives)

    def _check_disk(
        self, manifest: dict[str, Any], bundle: pathlib.Path, prepared: bool = False,
    ) -> str:
        requires = json_object(manifest.get("requires", {}), "manifest.requires")
        image_sizes = self._selected_image_sizes(manifest)
        stores, clickhouse_backup = self._database_storage()
        try:
            bundle_bytes = bundle.stat().st_size
        except OSError as error:
            raise UpgradeError("cannot measure the verified release bundle") from error
        if bundle_bytes < 0:
            raise UpgradeError("verified release bundle has an invalid size")
        plan = disk_plan(
            requires, bundle_bytes=bundle_bytes, image_sizes=image_sizes,
            backup_archives=self._backup_archive_inputs(stores),
            migration_sources=tuple(
                MigrationSource(role, store.source_bytes)
                for role, store in stores.items()
            ),
            prepared=prepared,
        )
        filesystems: dict[str, dict[str, Any]] = {}

        def add_filesystem(
            label: str, space: FilesystemSpace, needed: int,
            mutation: tuple[str, int] | None = None,
        ) -> None:
            current = filesystems.setdefault(
                space.identity,
                {"labels": [], "available": space.available_bytes, "needed": 0,
                 "mutation_sources": {}},
            )
            current["labels"].append(label)
            current["available"] = min(
                int(current["available"]), space.available_bytes,
            )
            current["needed"] = int(current["needed"]) + needed
            if mutation is not None:
                mutation_label, source_bytes = mutation
                sources = current["mutation_sources"]
                sources[mutation_label] = max(int(sources.get(mutation_label, 0)), source_bytes)

        install_identity, install_free = self._filesystem_space(self.install_dir)
        add_filesystem(
            "install+bundle-scratch", FilesystemSpace(install_identity, install_free),
            plan.bundle_working_bytes,
        )

        if plan.backup_payload_bytes:
            backup_output = pathlib.Path(
                getattr(self, "backup_output", self.install_dir / "backups")
            )
            backup_identity, backup_free = self._filesystem_space(
                backup_output, nearest_existing=True,
            )
            add_filesystem(
                "recovery-set-output", FilesystemSpace(backup_identity, backup_free),
                plan.backup_output_bytes,
            )
            tmp_path = pathlib.Path(os.environ.get("TMPDIR") or "/tmp")
            tmp_identity, tmp_free = self._filesystem_space(tmp_path)
            add_filesystem(
                "backup-payload+tar", FilesystemSpace(tmp_identity, tmp_free),
                plan.backup_tmp_peak_bytes,
            )
        native_clickhouse = (
            plan.native_backup_bytes("clickhouse-backups")
            + plan.native_backup_bytes("clickhouse-data")
        )
        if native_clickhouse:
            if clickhouse_backup is None:
                raise UpgradeError("cannot resolve ClickHouse backups disk")
            clickhouse_source = stores["clickhouse"].source_bytes
            add_filesystem(
                "clickhouse-native-backup", clickhouse_backup, native_clickhouse,
                ("clickhouse", clickhouse_source),
            )

        add_filesystem(
            "docker-image-load", self._docker_filesystem_space(),
            plan.image_load_bytes, ("images", 0),
        )
        for migration in plan.migrations:
            store = stores.get(migration.label)
            if store is None:
                raise UpgradeError(f"cannot resolve {migration.label} data filesystem")
            add_filesystem(
                f"{migration.label}-migration", store.data_filesystem,
                migration.headroom_bytes,
                (migration.label, migration.source_bytes),
            )

        details: list[str] = []
        for filesystem in filesystems.values():
            label = "+".join(str(item) for item in filesystem["labels"])
            available = int(filesystem["available"])
            needed = int(filesystem["needed"])
            mutation_sources = filesystem["mutation_sources"]
            safety = plan.safety_margin(sum(int(value) for value in mutation_sources.values())) \
                if mutation_sources else 0
            required = needed + safety
            if available < required:
                missing = required - available
                raise UpgradeError(
                    f"{label} requires {_format_bytes(required)}, has {_format_bytes(available)}; "
                    f"missing {_format_bytes(missing)}; computed {plan.detail()}"
                )
            details.append(
                f"{label}={available}/{required}(working={needed},safety={safety})"
            )
        return "; ".join(details) + f"; computed {plan.detail()}"

    def _ram_capacity_bytes(self) -> tuple[int, str]:
        pages = os.sysconf("SC_PHYS_PAGES")
        size = os.sysconf("SC_PAGE_SIZE")
        physical = int(pages) * int(size)
        candidates = [(physical, "physical")]
        try:
            cgroup_text = pathlib.Path("/proc/self/cgroup").read_text(encoding="ascii")
            mountinfo_text = pathlib.Path("/proc/self/mountinfo").read_text(encoding="ascii")
        except OSError:
            pass
        else:
            candidates.extend(cgroup_memory_limits(
                cgroup_text,
                mountinfo_text,
                lambda path: path.read_text(encoding="ascii"),
            ))
        daemon = self.runner.run(
            ["docker", "info", "--format", "{{.MemTotal}}"],
            timeout=30, check=False,
        )
        daemon_total = daemon.stdout.strip()
        if daemon.returncode != 0 or not daemon_total.isdigit() or int(daemon_total) <= 0:
            raise UpgradeError("cannot determine Docker daemon memory capacity")
        candidates.append((int(daemon_total), "docker-daemon"))
        return min(candidates, key=lambda item: item[0])

    def _check_ram(self, manifest: dict[str, Any]) -> str:
        requires = json_object(manifest.get("requires", {}), "manifest.requires")
        roles = self._resource_roles()
        required, formula = role_ram_requirement(requires, roles)
        total, source = self._ram_capacity_bytes()
        if total < required:
            missing = required - total
            raise UpgradeError(
                f"roles {','.join(sorted(roles))} require {_format_bytes(required)} RAM, "
                f"host has {_format_bytes(total)} ({source}); missing {_format_bytes(missing)}; "
                f"computed {formula}"
            )
        return (
            f"host has {_format_bytes(total)} RAM ({source}); roles "
            f"{','.join(sorted(roles))} require {_format_bytes(required)}; computed {formula}"
        )

    def _check_cpu(self, manifest: dict[str, Any]) -> str:
        requires = json_object(manifest.get("requires", {}), "manifest.requires")
        by_role = json_object(requires.get("cpu_features_by_role", {}), "manifest CPU requirements")
        needed: set[str] = set()
        for role in self.roles:
            values = by_role.get(role, [])
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                raise UpgradeError(f"invalid CPU feature list for role {role}")
            needed.update(value.lower() for value in values)
        if not needed:
            return "no role-specific CPU features required"
        machine = platform.machine().lower()
        if machine in {"aarch64", "arm64"}:
            # The v1 release policy names AVX2 for ClickHouse/Keeper because
            # that is the x86-64 image floor. Native ARM64 images do not expose
            # or require x86 instruction flags.
            needed.discard("avx2")
            if not needed:
                return "x86-64 AVX2 requirement is not applicable to ARM64"
        flags: set[str] = set()
        cpuinfo = pathlib.Path("/proc/cpuinfo")
        if cpuinfo.is_file():
            for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.lower().startswith(("flags", "features")) and ":" in line:
                    flags.update(line.split(":", 1)[1].lower().split())
        elif sys.platform == "darwin":
            result = self.runner.run(["sysctl", "-n", "machdep.cpu.features", "machdep.cpu.leaf7_features"], timeout=20)
            flags.update(result.stdout.lower().split())
        else:
            raise UpgradeError("cannot inspect CPU features on this host")
        missing = sorted(needed - flags)
        if missing:
            raise UpgradeError(f"missing CPU feature(s): {', '.join(missing)}")
        return "required features present"

    def _check_ntp(self) -> str:
        if shutil.which("timedatectl"):
            result = self.runner.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=20, check=False)
            if result.returncode == 0 and result.stdout.strip().lower() == "yes":
                return "systemd-timesyncd reports synchronized"
        if shutil.which("chronyc"):
            result = self.runner.run(["chronyc", "tracking"], timeout=20, check=False)
            if result.returncode == 0 and "Leap status" in result.stdout and "Not synchronised" not in result.stdout:
                return "chrony reports synchronized"
        if sys.platform == "darwin" and pathlib.Path("/bin/launchctl").is_file():
            result = self.runner.run(
                ["/bin/launchctl", "print", "system/com.apple.timed"], timeout=20, check=False
            )
            if result.returncode == 0 and "state = running" in result.stdout:
                return "macOS timed service reports running"
        raise UpgradeError("NTP synchronization could not be proven")

    def _check_ports(self) -> str:
        expected = set(self.compose(["ps", "-q"], timeout=30).stdout.split())
        config = json.loads(self.compose(["config", "--format", "json"], timeout=30).stdout)
        services = json_object(config.get("services", {}), "compose services")
        checked = 0
        for service in services.values():
            entry = json_object(service, "compose service")
            for port in entry.get("ports") or []:
                item = json_object(port, "compose port")
                published = item.get("published")
                if published is None:
                    continue
                result = self.runner.run(
                    ["docker", "ps", "--filter", f"publish={published}", "--format", "{{.ID}}"], timeout=20
                )
                owners = set(result.stdout.split())
                unexpected = {owner for owner in owners if not any(container.startswith(owner) for container in expected)}
                if unexpected:
                    raise UpgradeError(f"published port {published} is owned by an unexpected container")
                checked += 1
        return f"{checked} published port binding(s) are free or owned by this install"

    def _check_compose(self) -> str:
        self.compose(["config", "--quiet"], timeout=60)
        return "rendered compose configuration validates"

    def _check_postgres(self) -> str:
        blocked = self._pg_query(
            "SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND wait_event_type='Lock' "
            "AND clock_timestamp()-query_start > interval '60 seconds'"
        )
        if blocked != "0":
            raise UpgradeError(f"{blocked or 'unknown'} PostgreSQL session(s) have long-running lock waits")
        return "reachable; no lock wait older than 60 seconds"

    def _online_license_tuple(self) -> str:
        """Classify the license tuple nano-api boots with (NAN-5121).

        Mirrors ``ApiConfig::online_license_config``: AIRGAP_MODE, or no URL and no token, is the
        C05 authority (``"none"``); URL, token and deployment id all populated
        is the online authority (``"complete"``); anything else is a partial
        tuple the API refuses (``"partial"``). The values are resolved the way
        Compose hands them to nano-api: ``LICENSE_TOKEN`` falls back to the
        legacy ``DEPLOYMENT_TOKEN``, and on a role-split host the rendered
        license deployment id (NAN-5120) or the inventory deployment id stands
        in for ``NANO_DEPLOYMENT_ID``.
        """
        env = getattr(self, "env", None) or {}
        role_env = getattr(self, "role_env", None) or {}
        # ApiConfig selects C05 under AIRGAP_MODE whatever tuple is left over
        # (nanosiem-api config.rs online_license_config; "true" or "1" only).
        if env.get("AIRGAP_MODE", "") in {"true", "1"}:
            return "none"

        def value(*candidates: str) -> str:
            for candidate in candidates:
                text = candidate.strip()
                if text:
                    return text
            return ""

        url = value(env.get("LICENSE_URL", ""))
        token = value(env.get("LICENSE_TOKEN", ""), env.get("DEPLOYMENT_TOKEN", ""))
        if not url and not token:
            return "none"
        deployment = value(
            role_env.get("NANO_LICENSE_DEPLOYMENT_ID", ""),
            role_env.get("NANO_DEPLOYMENT_ID", ""),
            env.get("NANO_DEPLOYMENT_ID", ""),
        )
        return "complete" if url and token and deployment else "partial"

    def _check_license(self, test_rehearsal: bool = False, target_version: str = "") -> str:
        if self.edition != "enterprise":
            return "open edition does not require a C05 license"
        tuple_state = self._online_license_tuple()
        if tuple_state == "partial":
            raise UpgradeError(
                "online license tuple is incomplete: LICENSE_URL, LICENSE_TOKEN and "
                "NANO_DEPLOYMENT_ID must all be set (or none, for a C05 license)"
            )
        if tuple_state == "complete":
            # Online authority: the API admits on the cached check-in, never on
            # C05 state, which an online install does not have (NAN-5121).
            row = self._pg_query(
                "SELECT status || E'\\t' || valid::text || E'\\t' || "
                "COALESCE((expires_at > clock_timestamp())::text,'true') || E'\\t' || "
                "COALESCE(offline, FALSE)::text || E'\\t' || "
                "COALESCE((last_checked_at > clock_timestamp() - "
                f"interval '{ONLINE_LICENSE_STALE_DAYS} days')::text,'false') || E'\\t' || "
                # 'r:' keeps an empty reason from being trimmed off the row.
                "'r:' || replace(replace(COALESCE(locked_reason,''),E'\\t',' '),E'\\n',' ') "
                "FROM license_status WHERE id=TRUE"
            )
            fields = row.split("\t")
            if len(fields) == 5:
                fields.append("r:")
            upgrade_gate = (
                len(fields) == 6
                and fields[5].startswith("r:")
                and is_selfrun_upgrade_gate(fields[0], fields[1], fields[5][2:], target_version)
            )
            if (
                len(fields) != 6
                or (
                    not upgrade_gate
                    and (
                        fields[0] not in {"active", "grace_period"}
                        or fields[1:3] != ["true", "true"]
                    )
                )
            ):
                raise UpgradeError("online license check-in is not active and unexpired")
            if fields[3] != "false":
                raise UpgradeError(
                    "license cache was written by an offline import, but this install "
                    "is configured for online licensing"
                )
            if fields[4] != "true":
                raise UpgradeError(
                    "online license has not checked in successfully within "
                    f"{ONLINE_LICENSE_STALE_DAYS} days; restore reachability to the "
                    "license server before upgrading"
                )
            if upgrade_gate:
                # NAN-5251: app.nano.rs locks Self-run v2 builds below the
                # licensed minimum until they upgrade; this upgrade is the cure.
                return (
                    f"license locked only by the Self-run upgrade-required gate; "
                    f"upgrading to {target_version} clears it at the next check-in"
                )
            return f"license status {fields[0]}; authority online"
        row = self._pg_query(
            "SELECT status || E'\\t' || valid::text || E'\\t' || "
            "COALESCE((expires_at > clock_timestamp())::text,'true') FROM license_status WHERE id=TRUE"
        )
        fields = row.split("\t")
        if len(fields) != 3 or fields[0] not in {"active", "grace_period"} or fields[1:] != ["true", "true"]:
            raise UpgradeError("C05 cached license is not active and unexpired")
        sovereign = self._pg_query(
            "SELECT (to_regclass('sovereign_license_state') IS NOT NULL)::text"
        )
        c05 = "legacy"
        if sovereign == "true":
            c05 = self._pg_query(
                "SELECT CASE WHEN EXISTS (SELECT 1 FROM sovereign_license_state "
                "WHERE singleton=TRUE AND grace_until > clock_timestamp()) "
                "THEN 'valid' ELSE 'invalid' END"
            )
        elif sovereign == "invalid":
            # Preserve the isolated preflight-test contract from the C05 gate;
            # production's to_regclass probe returns only true/false.
            c05 = "invalid"
        elif sovereign != "false":
            raise UpgradeError("cannot determine C05 license schema state")
        if c05 == "invalid":
            if test_rehearsal:
                key_id = embedded_test_root_key_id(self.install_dir)
                return (
                    f"license status {fields[0]}; authority TEST-only rehearsal "
                    f"root {key_id} (no license state written)"
                )
            raise UpgradeError("C05 license state is missing or expired")
        return f"license status {fields[0]}; authority {c05}"

    def _check_clickhouse(self) -> str:
        cluster = self.role_env.get("CLICKHOUSE_CLUSTER", self.env.get("CLICKHOUSE_CLUSTER", ""))
        if cluster:
            safe_name(cluster, "ClickHouse cluster")
            expected = self._ch_query(f"SELECT count() FROM system.clusters WHERE cluster='{cluster}'")
            answered = self._ch_query(f"SELECT count() FROM clusterAllReplicas('{cluster}', system.one)")
            if expected != answered or expected in {"", "0"}:
                raise UpgradeError(f"ClickHouse cluster answered {answered or '0'}/{expected or '0'} replicas")
        else:
            expected = answered = "1"
        # Every ClickHouse inventory node runs this preflight with its local
        # admin credential. Keep the reachability probe cluster-wide, but read
        # privileged system metadata locally: clusterAllReplicas fans out with
        # the runtime user configured in remote_servers, which intentionally
        # cannot read system.mutations or system.replicas.
        mutations = self._ch_query("SELECT count() FROM system.mutations WHERE NOT is_done")
        ddl = (
            self._ch_query(
                "SELECT count() FROM system.distributed_ddl_queue "
                "WHERE status NOT IN ('Finished','Removing')"
            )
            if cluster
            else "0"
        )
        replicas = self._ch_query(
            "SELECT count() FROM system.replicas "
            "WHERE is_readonly OR is_session_expired OR absolute_delay > 30"
        )
        if any(value not in {"", "0"} for value in (mutations, ddl, replicas)):
            raise UpgradeError(f"ClickHouse pending mutations={mutations}, DDL={ddl}, lagging replicas={replicas}")
        return f"{answered}/{expected} replicas reachable; no mutations, DDL, or lag >30s"

    def _check_keeper(self) -> str:
        if "keeper" not in self.roles:
            return "no Keeper role on this host"
        port = int(self.role_env.get("NANO_KEEPER_CLIENT_PORT", "9181"))
        # NANO_CLUSTER_BIND_ADDRESS is commonly 0.0.0.0. It is a listener
        # wildcard, never a routable peer identity. The renderer pins the
        # host's private inventory address separately.
        address = self.role_env.get("NANO_HOST_ADDRESS", "127.0.0.1")
        if not SAFE_HOST_RE.fullmatch(address) or address in {"0.0.0.0", "::", "*"}:
            raise UpgradeError("rendered Keeper private address is invalid")
        use_tls = self.role_env.get("NANO_PRIVATE_TLS") == "true"

        def four_letter(command: bytes) -> str:
            try:
                raw = socket.create_connection((address, port), timeout=5)
                with contextlib.closing(raw):
                    connection: socket.socket
                    if use_tls:
                        ca_file = self.role_env.get("NANO_TLS_CA", "")
                        cert_file = self.role_env.get("NANO_TLS_CERT", "")
                        key_file = self.role_env.get("NANO_TLS_KEY", "")
                        if not all((ca_file, cert_file, key_file)):
                            raise UpgradeError("Keeper mTLS CA, client certificate, or key is missing")
                        context = ssl.create_default_context(cafile=ca_file)
                        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
                        connection = context.wrap_socket(
                            raw, server_hostname=self.role_env.get("NANO_TLS_SERVER_NAME")
                        )
                    else:
                        connection = raw
                    connection.settimeout(5)
                    connection.sendall(command)
                    chunks: list[bytes] = []
                    while True:
                        block = connection.recv(4096)
                        if not block:
                            break
                        chunks.append(block)
                        if sum(len(chunk) for chunk in chunks) > 64 * 1024:
                            raise UpgradeError("Keeper four-letter response is unexpectedly large")
                    return b"".join(chunks).decode("utf-8", "replace").strip()
            except OSError as error:
                raise UpgradeError(f"Keeper {command.decode('ascii')} probe failed") from error

        if four_letter(b"ruok").lower() != "imok":
            raise UpgradeError("Keeper did not answer imok")
        metrics: dict[str, str] = {}
        for line in four_letter(b"mntr").splitlines():
            fields = line.split(None, 1)
            if len(fields) == 2:
                metrics[fields[0]] = fields[1]
        state = metrics.get("zk_server_state", "")
        if state not in {"leader", "follower", "standalone"}:
            raise UpgradeError(f"Keeper mntr returned an unhealthy server state: {state or 'missing'}")
        generated = self.role_env.get("NANO_GENERATED_DIR", "")
        keeper_config = pathlib.Path(generated) / "keeper/keeper.xml" if generated else None
        members = 1
        if keeper_config and keeper_config.is_file():
            try:
                members = len(ET.parse(keeper_config).findall(".//raft_configuration/server"))
            except (ET.ParseError, OSError) as error:
                raise UpgradeError("cannot validate rendered Keeper quorum configuration") from error
        if members > 1 and state == "leader":
            synced = metrics.get("zk_synced_followers", "")
            if not synced.isdigit() or int(synced) < members // 2:
                raise UpgradeError(f"Keeper leader has {synced or 'unknown'}/{members - 1} synced followers")
        return f"ruok=imok; mntr state={state}; configured members={members}"

    # ---- NAN-5279 F1: per-host rendered configuration -------------------
    #
    # install.sh renders each host's configuration (nginx edges, HAProxy
    # routers, ClickHouse/Keeper XML, Patroni/etcd/Valkey, monitoring) from
    # the inventory with deploy/compose/render-inventory.py into
    # .nano-generated and .nano-role.env. An upgrade used to keep the old
    # render, so a release whose fix lives in a template (v2.0.12's ingest
    # edge 503) never reached an upgraded cluster. The upgrade now re-renders
    # with the same renderer from the unpacked bundle, and recreates every
    # service whose mounted configuration changed.

    def _renderer(self) -> Any:
        path = self.install_dir / "deploy/compose/render-inventory.py"
        if not path.is_file():
            raise UpgradeError("deploy/compose/render-inventory.py is missing from this install")
        spec = importlib.util.spec_from_file_location("nano_render_inventory", path)
        if spec is None or spec.loader is None:
            raise UpgradeError("cannot load the inventory renderer")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _tree_files(root: pathlib.Path) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        if not root.is_dir():
            return files
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                files[path.relative_to(root).as_posix()] = path.read_bytes()
        return files

    @staticmethod
    def _render_diff(
        old_files: dict[str, bytes], new_files: dict[str, bytes],
        old_env: dict[str, str], new_env: dict[str, str], limit: int = 400,
    ) -> tuple[list[str], str]:
        import difflib

        changed: list[str] = []
        lines: list[str] = []
        for name in sorted(set(old_files) | set(new_files)):
            before, after = old_files.get(name), new_files.get(name)
            if before == after:
                continue
            changed.append(name)
            if name.startswith("tls/"):
                # Never print key material; say what changed.
                lines.append(f"--- .nano-generated/{name}: {'added' if before is None else 'removed' if after is None else 'changed'} (contents not shown)")
                continue
            try:
                old_text = (before or b"").decode("utf-8").splitlines(keepends=True)
                new_text = (after or b"").decode("utf-8").splitlines(keepends=True)
            except UnicodeDecodeError:
                lines.append(f"--- .nano-generated/{name}: binary file changed")
                continue
            lines.extend(
                line.rstrip("\n") for line in difflib.unified_diff(
                    old_text, new_text,
                    fromfile=f"a/.nano-generated/{name}" if before is not None else "/dev/null",
                    tofile=f"b/.nano-generated/{name}" if after is not None else "/dev/null",
                    n=2,
                )
            )
        for key in sorted(set(old_env) | set(new_env)):
            if old_env.get(key) != new_env.get(key):
                changed.append(f".nano-role.env:{key}")
                lines.append(f".nano-role.env: {key}: {old_env.get(key, '<unset>')!r} -> {new_env.get(key, '<unset>')!r}")
        if len(lines) > limit:
            lines = [*lines[:limit], f"... {len(lines) - limit} more diff lines not shown"]
        return changed, "\n".join(lines)

    def render_config(self, inventory_text: str, apply: bool, run_id: str = "") -> dict[str, Any]:
        """Re-render this host's configuration from the installed bundle.

        apply=False (dry run): render into scratch space and return the diff.
        apply=True: publish the render with the renderer's own transaction.
        The previous tree is kept as .nano-generated.previous (renamed, so the
        running containers keep reading it until their role is recreated, and
        rollback can restore it)."""
        if not getattr(self, "role_env", None):
            return {"host": self.host_name, "role_split": False, "changed": [], "diff": "", "applied": False}
        renderer = self._renderer()
        output = self.install_dir / ".nano-generated"
        env_output = self.install_dir / ".nano-role.env"
        retained = self.install_dir / ".nano-generated.previous"
        retained_env = self.install_dir / ".nano-role.env.previous"
        marker = self.install_dir / ".nano-generated.previous.json"
        marker_value = read_json(marker) if marker.is_file() else {}
        resumed = bool(
            apply and run_id and marker_value.get("run_id") == run_id and retained.is_dir()
        )
        current_tree = output if output.is_dir() else retained if resumed else output
        current_env_path = env_output if env_output.is_file() else retained_env
        roles = self.role_env.get("NANO_ROLE_PROFILES", "")
        if not roles:
            raise UpgradeError("the installed role environment does not record NANO_ROLE_PROFILES")
        scratch = pathlib.Path(tempfile.mkdtemp(prefix=".nano-render-", dir=self.install_dir))
        try:
            inventory = scratch / "inventory.yaml"
            descriptor = os.open(inventory, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(inventory_text)
            staged_output = scratch / "generated"
            staged_output.mkdir(mode=0o755)
            staged_output.chmod(0o755)
            staged_env = scratch / "role.env"
            try:
                renderer._render_host(
                    inventory, roles, staged_output, staged_env,
                    self.host_name, self.install_dir / ".env",
                    published_output=output.absolute(),
                )
            except Exception as error:  # InventoryError, OSError, ValueError
                raise UpgradeError(f"re-rendering this host's configuration failed: {error}") from error
            new_env = parse_role_env(staged_env)
            for key in ("NANO_DEPLOYMENT_ID", "NANO_HOST_ID", "NANO_DEPLOYMENT_IDENTITY_SHA256"):
                if self.role_env.get(key) and new_env.get(key) != self.role_env.get(key):
                    raise UpgradeError(
                        f"the inventory no longer matches this host's installed {key} "
                        f"({self.role_env.get(key)} -> {new_env.get(key)}); a topology change "
                        "needs the installer's --accept-topology-migration runbook, not an upgrade"
                    )
            old_env = parse_role_env(current_env_path) if current_env_path.is_file() else {}
            changed, diff = self._render_diff(
                self._tree_files(current_tree), self._tree_files(staged_output), old_env, new_env,
            )
            result = {
                "host": self.host_name, "role_split": True, "changed": changed,
                "diff": diff, "applied": False,
            }
            if not apply or (not changed and output.is_dir()):
                # Nothing to publish (a resumed step whose render already
                # landed ends here too: never republish a tree that recreated
                # containers may already be using).
                return result
            if resumed and output.exists():
                # Resumed with a differing live tree: keep it by rename too.
                superseded = self.install_dir / ".nano-generated.superseded"
                if superseded.exists():
                    shutil.rmtree(superseded)
                os.replace(output, superseded)
            elif not resumed:
                # Retire the previous render by RENAME: a running container's
                # bind mount follows the inode, so it keeps reading a complete
                # tree (ClickHouse would otherwise hot-reload an emptied
                # config.d) until its role is recreated onto the new one.
                if retained.exists() or retained.is_symlink():
                    shutil.rmtree(retained) if retained.is_dir() and not retained.is_symlink() else retained.unlink()
                write_json_atomic(marker, {
                    "run_id": run_id, "retained_at": utc_now(),
                    # Full precision: rollout recreates every container that
                    # started before this swap (_started_before_render_swap).
                    "swapped_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "version": getattr(self, "version", ""), "state": "retained",
                })
                if env_output.is_file():
                    shutil.copy2(env_output, retained_env)
                if output.exists():
                    os.replace(output, retained)
            renderer._publish_render(staged_output, output, staged_env, env_output)
            self.role_env = parse_role_env(env_output)
            self.compose_args = self._compose_args()
            result["applied"] = True
            return result
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def restore_previous_render(self, run_id: str) -> bool:
        """Rollback: put back the render the upgrade retired (same rename
        discipline, so the running containers keep their view)."""
        retained = self.install_dir / ".nano-generated.previous"
        retained_env = self.install_dir / ".nano-role.env.previous"
        marker = self.install_dir / ".nano-generated.previous.json"
        if not getattr(self, "role_env", None) or not marker.is_file() or not retained.is_dir():
            return False
        value = read_json(marker)
        if value.get("run_id") != run_id or value.get("state") != "retained":
            return False
        output = self.install_dir / ".nano-generated"
        env_output = self.install_dir / ".nano-role.env"
        rolled_back = self.install_dir / ".nano-generated.rolled-back"
        if rolled_back.exists():
            shutil.rmtree(rolled_back)
        if output.exists():
            os.replace(output, rolled_back)
        os.replace(retained, output)
        if retained_env.is_file():
            os.replace(retained_env, env_output)
        write_json_atomic(marker, {**value, "state": "restored", "restored_at": utc_now()})
        self.role_env = parse_role_env(env_output)
        self.compose_args = self._compose_args()
        return True

    def _mounted_digest(
        self, container: str, destination: str, exclude: frozenset[str] = frozenset(),
    ) -> str | None:
        import tarfile

        try:
            # Binary tar on stdout: the text-mode Runner cannot carry it.
            result = subprocess.run(
                ["docker", "cp", f"{container}:{destination}", "-"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0 or not result.stdout:
            return None
        digest = hashlib.sha256()
        try:
            with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
                members = sorted(
                    (
                        (member.name.split("/", 1)[1] if "/" in member.name else "", member)
                        for member in archive.getmembers() if member.isfile()
                    ),
                    key=lambda item: item[0],
                )
                for relative, member in members:
                    if relative in exclude:
                        continue  # a separate bind mount nested inside this one
                    extracted = archive.extractfile(member)
                    digest.update(relative.encode() + b"\0")
                    digest.update(extracted.read() if extracted is not None else b"")
        except tarfile.TarError:
            return None
        return digest.hexdigest()

    @staticmethod
    def _host_digest(source: pathlib.Path, exclude: frozenset[str] = frozenset()) -> str | None:
        digest = hashlib.sha256()
        if source.is_file():
            digest.update(b"\0")
            digest.update(source.read_bytes())
            return digest.hexdigest()
        if source.is_dir():
            files = sorted(
                (path.relative_to(source).as_posix(), path)
                for path in source.rglob("*") if path.is_file()
                and path.relative_to(source).as_posix() not in exclude
            )
            for relative, path in files:
                digest.update(relative.encode() + b"\0")
                digest.update(path.read_bytes())
            return digest.hexdigest()
        return None

    def _config_mounts_stale(self, service: str) -> bool:
        """True when a running container reads different configuration than
        its bind-mount source now holds on the host.

        Compose recreates a container only when its definition changes; a
        re-rendered file at the same path (or a bundle file replaced by the
        unpack) is not a definition change, and the container keeps the old
        inode. Only small renderer/bundle configuration is compared:
        .nano-generated, config/ and deploy/ under the install directory."""
        try:
            container = self._service_container(service)
        except UpgradeError:
            return False  # not running: `up` creates it from the new files
        inspected = self.runner.run(
            ["docker", "inspect", "--format", "{{json .Mounts}}", container], timeout=30, check=False,
        )
        try:
            mounts = json.loads(inspected.stdout or "[]")
        except json.JSONDecodeError:
            return False
        roots = [
            (self.install_dir / name).resolve()
            for name in (".nano-generated", "config", "deploy")
        ]
        generated_root = roots[0]
        if any(
            isinstance(mount, dict) and mount.get("Type") == "bind"
            and self._under(str(mount.get("Source", "")), generated_root)
            for mount in (mounts if isinstance(mounts, list) else [])
        ) and self._started_before_render_swap(container):
            # A container created before this upgrade published the new render
            # still has its .nano-generated mounts on the RETIRED tree (now
            # .nano-generated.previous), even when the content is identical.
            # The next upgrade deletes that tree, and a running container's
            # mount would empty under it (ClickHouse hot-reloads an empty
            # config.d, NAN-5126). Recreate it onto the published tree now,
            # under this role's rollout, as install.sh does after a render.
            eprint(f"note: {self.host_name}: {service} still mounts the retired configuration tree; recreating it")
            return True
        for mount in mounts if isinstance(mounts, list) else []:
            if not isinstance(mount, dict) or mount.get("Type") != "bind":
                continue
            source = pathlib.Path(str(mount.get("Source", "")))
            destination = str(mount.get("Destination", ""))
            if not source.is_absolute() or not destination.startswith("/"):
                continue
            try:
                resolved = source.resolve()
            except OSError:
                continue
            if not any(resolved == root or root in resolved.parents for root in roots):
                continue
            size = (
                resolved.stat().st_size if resolved.is_file()
                else sum(path.stat().st_size for path in resolved.rglob("*") if path.is_file())
                if resolved.is_dir() else 0
            )
            if size > 4 * 1024 * 1024:
                continue
            nested = frozenset(
                str(other.get("Destination", ""))[len(destination) + 1:]
                for other in mounts
                if isinstance(other, dict)
                and str(other.get("Destination", "")).startswith(destination.rstrip("/") + "/")
            )
            host = self._host_digest(resolved, nested)
            if resolved.is_file():
                # NAN-5397: `docker cp` re-binds the mount's Source path, so it
                # returns the NEW file while the container still reads the old
                # inode. Read a single-file mount from inside the container.
                state, content = compose_stale_mounts.read_container_file(container, destination)
                if state == "missing":
                    eprint(f"note: {self.host_name}: {service} no longer sees {destination}; recreating it")
                    return True
                seen = (
                    hashlib.sha256(b"\0" + content).hexdigest() if state == "ok" else None
                )
            else:
                seen = self._mounted_digest(container, destination, nested)
            if host is not None and seen is not None and host != seen:
                eprint(f"note: {self.host_name}: {service} reads an outdated {destination}; recreating it")
                return True
        return False

    @staticmethod
    def _under(source: str, root: pathlib.Path) -> bool:
        path = pathlib.Path(source)
        if not path.is_absolute():
            return False
        try:
            resolved = path.resolve()
        except OSError:
            return False
        return resolved == root or root in resolved.parents

    def _started_before_render_swap(self, container: str) -> bool:
        """True when `container` started before the render this host's
        upgrade published (the .nano-generated.previous.json marker), i.e.
        its bind mounts still resolve to the retired tree's inodes."""
        marker = self.install_dir / ".nano-generated.previous.json"
        if not marker.is_file():
            return False
        try:
            value = read_json(marker)
        except (OSError, ValueError, UpgradeError):
            return False
        if value.get("state") != "retained":
            return False
        swapped = _parse_report_time(value.get("swapped_at") or value.get("retained_at"))
        if swapped is None:
            return False
        inspected = self.runner.run(
            ["docker", "inspect", "--format", "{{.State.StartedAt}}", container],
            timeout=30, check=False,
        )
        started = _parse_report_time((inspected.stdout or "").strip())
        return started is not None and started < swapped

    def _recreate_args(self, services: Iterable[str]) -> list[str]:
        """`--force-recreate` when any of `services` runs outdated config."""
        if getattr(self, "_legacy_bridge_rollout", False) or getattr(self, "legacy_layout", None) is not None:
            return []
        return ["--force-recreate"] if any(self._config_mounts_stale(s) for s in services) else []

    def _check_runtime_config(self) -> str:
        validated: list[str] = []
        if "ingest" in self.roles and self._service_exists("vector"):
            current_layout = self.compose(
                ["exec", "-T", "vector", "test", "-f", "/etc/vector/runtime/reload.toml"],
                timeout=30,
                check=False,
            )
            # Pre-2.0 used an upstream Vector whose interpolation opt-in flag
            # did not exist. Keep both exact CLI contracts in the standalone
            # helper so a layout adapter cannot accidentally merge them.
            arguments = vector_validation_arguments(
                current_layout.returncode == 0,
                managed_legacy_layout=getattr(self, "legacy_layout", None) is not None,
            )
            self.compose(arguments, timeout=120)
            validated.append("Vector")
        edge = "nginx" if "app" in self.roles else "ingest-edge" if "ingest" in self.roles else ""
        if edge and self._service_exists(edge):
            self.compose(["exec", "-T", edge, "nginx", "-t"], timeout=30)
            validated.append(edge)
        return ", ".join(validated) + " configuration validates" if validated else "no runtime renderer on this role"

    def _drained_roles(self, require_lb_hooks: bool) -> list[str]:
        """NAN-5279: the roles on this host that the upgrade takes out of the
        load balancer: ingest when the cluster has several ingest hosts, app
        when it has several app hosts (see rollout / _drain_app_host)."""
        roles: list[str] = []
        if "ingest" in self.roles and require_lb_hooks:
            roles.append("ingest")
        role_env = getattr(self, "role_env", None) or {}
        if "app" in self.roles and int(role_env.get("NANO_APP_HOST_COUNT", "1") or "1") >= 2:
            roles.append("app")
        return roles

    def _check_lb_hooks(self, drained: Sequence[str] = ("ingest",), roundtrip: bool = False) -> str:
        """Both hooks are executable and, unless this is a resumed preflight,
        a real drain -> rejoin round trip through them succeeds.

        The round trip is what proves a restricted load-balancer key still
        drains: the example hook fails unless HAProxy confirms each state
        (NAN-5279 F6). It runs one host at a time (preflight is sequential),
        and a rejoin is always attempted after a drain."""
        configured = {
            kind: os.environ.get(f"NANO_UPGRADE_LB_{kind}_COMMAND", "")
            for kind in ("DRAIN", "REJOIN")
        }
        if "ingest" not in drained and not any(configured.values()):
            # An app host drains through its own /readyz (the LB health
            # check); the hooks are optional there.
            return (
                "app host: no drain/rejoin hooks configured; the drain relies on the "
                "load balancer health-checking /readyz"
            )
        for kind, value in configured.items():
            variable = f"NANO_UPGRADE_LB_{kind}_COMMAND"
            path = pathlib.Path(value)
            if not value or not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
                raise UpgradeError(f"{variable} must name an absolute executable")
        roles = "/".join(drained)
        if not roundtrip:
            return f"{roles} host: drain and rejoin hooks are executable"
        try:
            self._run_lb_hook_checked("drain", configured["DRAIN"])
        except UpgradeError as drain_error:
            # Rejoin even when the drain failed part-way (one LB of two).
            try:
                self._run_lb_hook_checked("rejoin", configured["REJOIN"])
            except UpgradeError as rejoin_error:
                raise UpgradeError(
                    f"{drain_error}; the rejoin also failed ({rejoin_error}), so "
                    f"{self.host_name} may be LEFT DRAINED on a load balancer. Run "
                    f"`{configured['REJOIN']} {self.host_name}` by hand before retrying"
                ) from drain_error
            raise
        try:
            self._run_lb_hook_checked("rejoin", configured["REJOIN"])
        except UpgradeError as rejoin_error:
            raise UpgradeError(
                f"{rejoin_error}. {self.host_name} is LEFT DRAINED from the load balancer; "
                f"no other host's hooks were exercised. Run `{configured['REJOIN']} "
                f"{self.host_name}` by hand once the hook works, then retry"
            ) from rejoin_error
        return (
            f"{roles} host: drain and rejoin hooks ran a live round trip "
            f"({pathlib.Path(configured['DRAIN']).name} -> {pathlib.Path(configured['REJOIN']).name})"
        )

    def _run_lb_hook_checked(self, kind: str, command: str) -> None:
        at = utc_now()
        started = time.monotonic()
        result = self.runner.run([command, self.host_name], timeout=120, check=False)
        self._record_lb_hook(kind, result.returncode, started, at)
        if result.returncode != 0:
            lines = [line.strip() for line in (result.stderr or "").splitlines() if line.strip()]
            detail = lines[-1][:300] if lines else f"exit {result.returncode}"
            raise UpgradeError(f"{kind} hook failed for {self.host_name}: {detail}")

    def preflight(
        self, manifest: dict[str, Any], bundle: pathlib.Path,
        require_lb_hooks: bool = False, prepared: bool = False,
        test_license_rehearsal: bool = False, lb_roundtrip: bool = True,
    ) -> list[Check]:
        checks: list[Check] = []

        def check(name: str, function: Callable[[], str]) -> None:
            try:
                checks.append(Check(name, True, function(), self.host_name))
            except (UpgradeError, OSError, ValueError, json.JSONDecodeError) as error:
                checks.append(Check(name, False, str(error), self.host_name))

        check("disk", lambda: self._check_disk(manifest, bundle, prepared))
        # NAN-5285 F1: every host that writes a backup component (PostgreSQL
        # on whichever member leads at backup time; ClickHouse only with
        # --include-clickhouse-data, see backup_components_for) needs a
        # writable --backup-output, not only the coordinator. A ClickHouse
        # host writes nothing by default, so it is not asked for the folder.
        if "postgres" in self.roles or (
            "clickhouse" in self.roles
            and getattr(self, "include_clickhouse_data", False)
        ):
            check(
                "backup-output",
                lambda: check_backup_output_writable(pathlib.Path(
                    getattr(self, "backup_output", self.install_dir / "backups")
                )),
            )
        if manifest.get("source") == "registry":
            check(
                "control-tree",
                lambda: check_registry_control_tree(self.install_dir, str(manifest.get("version", ""))),
            )
            if not prepared:
                login: list[str] = []

                def registry_login() -> str:
                    detail = check_registry_login(manifest)
                    login.append(detail)
                    return detail

                check("registry-login", registry_login)
                if login:
                    # NAN-5251: pull (and digest-check) this host's images now,
                    # before the backup and before any host restarts, so an
                    # expired or unreachable registry fails while nothing has
                    # changed. Pulling only fills the local image cache.
                    check("registry-pull", lambda: self._pull_registry_images(bundle, manifest))
        check("ram", lambda: self._check_ram(manifest))
        check("cpu", lambda: self._check_cpu(manifest))
        check("ntp", self._check_ntp)
        check("rendered-config", self._check_compose)
        check("runtime-config", self._check_runtime_config)
        check("ports", self._check_ports)
        # Role-split only: a single-node stack serves Vector its config from a
        # shared volume (NANO_VECTOR_CONFIG_DELIVERY=off), never over HTTP.
        if getattr(self, "role_env", None) and self.roles.intersection({"app", "ingest"}):
            check(
                "vector-config-delivery",
                lambda: check_vector_config_delivery_credential(self.env_file.values()),
            )
        if self.roles.intersection({"app", "ingest"}):
            check(
                "vector-install-token",
                lambda: check_vector_install_token(
                    self.env_file.values(), bool(getattr(self, "role_env", None)),
                ),
            )
        if self.roles.intersection({"app", "ingest"}):
            check(
                "enrichment-control-tree",
                lambda: check_enrichment_control_tree(
                    self.nano_cli.parent.parent
                    if getattr(self, "legacy_layout", None) is not None
                    else self.install_dir
                ),
            )
        if "postgres" in self.roles:
            check("postgres", self._check_postgres)
        if "clickhouse" in self.roles:
            check("clickhouse", self._check_clickhouse)
        if "keeper" in self.roles:
            check("keeper", self._check_keeper)
        # The authoritative cached license state lives in PostgreSQL. On a
        # role-split install the app host has no local postgres service, so
        # perform this cluster-wide gate on the database host.
        if "postgres" in self.roles:
            check(
                "license",
                lambda: self._check_license(
                    test_license_rehearsal, str(manifest.get("version", "")),
                ),
            )
        drained = self._drained_roles(require_lb_hooks)
        if drained:
            # NAN-5279 F7: every host the upgrade drains, app hosts included.
            roundtrip = (
                lb_roundtrip and not prepared
                and os.environ.get("NANO_UPGRADE_LB_HOOK_TEST", "1") != "0"
            )
            check("lb-hooks", lambda: self._check_lb_hooks(drained, roundtrip))
        # The round trip's hook calls are reported by the lb-hooks check (in
        # the journaled preflight); never attribute them to a later step.
        self._take_lb_hook_calls()
        return checks

    def ledger(self) -> dict[str, list[list[str]]]:
        result: dict[str, list[list[str]]] = {"postgres": [], "clickhouse": []}
        if "postgres" in self.roles:
            rows = self._pg_query(
                "SELECT version::text, encode(checksum,'hex') FROM _sqlx_migrations WHERE success ORDER BY version"
            )
            result["postgres"] = [line.split("\t", 1) for line in rows.splitlines() if line]
        if "clickhouse" in self.roles:
            rows = self._ch_query(
                "SELECT version,argMax(checksum,applied_at) FROM nanosiem._migrations GROUP BY version ORDER BY version",
                retry_memory_pressure=True,
            )
            result["clickhouse"] = [line.split("\t", 1) for line in rows.splitlines() if line]
        return result

    def backup_gate(self, run_id: str, action: str) -> dict[str, Any]:
        safe_name(run_id, "backup run id")
        root = self.install_dir / ".nano-backup-gates"
        gate = root / run_id

        def inspect_directory(path: pathlib.Path, label: str) -> None:
            try:
                info = path.lstat()
            except OSError as error:
                raise UpgradeError(f"cannot inspect {label}: {path}") from error
            if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise UpgradeError(f"{label} must be a uid-owned non-symlink directory: {path}")
            if info.st_mode & 0o077:
                raise UpgradeError(f"{label} must have mode 0700: {path}")

        if action == "prepare":
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            inspect_directory(root, "backup gate root")
            try:
                gate.mkdir(mode=0o700)
            except FileExistsError as error:
                raise UpgradeError(f"backup snapshot gate already exists: {gate}") from error
            inspect_directory(gate, "backup snapshot gate")
            return {"gate": str(gate)}

        inspect_directory(root, "backup gate root")
        inspect_directory(gate, "backup snapshot gate")
        markers: dict[str, bool] = {}
        for marker in ("preflight-ready", "start", "snapshot-ready", "abort"):
            path = gate / marker
            if path.is_symlink():
                raise UpgradeError(f"backup snapshot gate marker is a symlink: {path}")
            markers[marker.replace("-", "_")] = path.is_file()
        if action == "status":
            return {"gate": str(gate), **markers}
        if action in {"release", "abort"}:
            marker = gate / ("start" if action == "release" else "abort")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(marker, flags, 0o600)
            except FileExistsError:
                if marker.is_symlink() or not marker.is_file():
                    raise UpgradeError(f"invalid backup snapshot gate marker: {marker}")
            else:
                os.close(descriptor)
            return {"gate": str(gate), "action": action}
        if action == "cleanup":
            allowed = {"preflight-ready", "start", "snapshot-ready", "abort"}
            unexpected = [item.name for item in gate.iterdir() if item.name not in allowed]
            if unexpected:
                raise UpgradeError(
                    "backup snapshot gate contains unexpected entries: "
                    + ", ".join(sorted(unexpected))
                )
            shutil.rmtree(gate)
            with contextlib.suppress(OSError):
                root.rmdir()
            return {"gate": str(gate), "action": action}
        raise UpgradeError(f"unsupported backup gate action: {action}")

    def backup(
        self, key_file: pathlib.Path, output: pathlib.Path, run_id: str,
        epoch: str, role_split: bool, snapshot_gate: pathlib.Path | None = None,
        clickhouse_disk: str = "backups", component: str | None = None,
        include_clickhouse_data: bool = False,
    ) -> str:
        try:
            check_backup_output_writable(output)
        except UpgradeError as error:
            raise UpgradeError(
                f"host {getattr(self, 'host_name', 'single')}: {error}"
            ) from error
        arguments = [str(self.nano_cli), "backup", "--key-file", str(key_file), "--output", str(output), "--install-dir", str(self.install_dir)]
        if include_clickhouse_data:
            arguments.append("--include-clickhouse-data")
        if role_split:
            arguments.extend(["--recovery-set-id", run_id, "--quiesce-epoch", epoch])
        if snapshot_gate is not None:
            arguments.extend(["--snapshot-gate", str(snapshot_gate)])
        if component is not None:
            arguments.extend(["--component", component])
        arguments.extend(["--clickhouse-disk", clickhouse_disk])
        result = self.runner.run(arguments, timeout=7200, check=False)
        if result.returncode != 0:
            # The backup CLI disables xtrace before reading any credentials and
            # writes operator-safe diagnostics to stderr. Preserve only its
            # final bounded line so a remote coordinator can identify the
            # failed safety gate without copying an unbounded child log.
            lines = [line.strip() for line in result.stderr.splitlines() if line.strip()]
            database_errors = [line for line in lines if "DB::Exception:" in line]
            actionable = database_errors or [line for line in lines if line.startswith("nano:")]
            detail = (actionable[-1] if actionable else lines[-1])[:500] \
                if lines else "backup CLI returned no diagnostic"
            raise UpgradeError(f"backup failed (exit {result.returncode}): {detail}")
        return str(output)

    @staticmethod
    def _volume_entries(service: dict[str, Any], label: str) -> list[dict[str, Any]]:
        raw = service.get("volumes") or []
        if not isinstance(raw, list):
            raise UpgradeError(f"{label} volumes are not a list")
        entries: list[dict[str, Any]] = []
        for value in raw:
            if not isinstance(value, dict):
                raise UpgradeError(f"{label} volume is not a rendered long-syntax mount")
            source = value.get("source")
            target = value.get("target")
            mount_type = value.get("type")
            if not isinstance(source, str) or not isinstance(target, str) or not isinstance(mount_type, str):
                raise UpgradeError(f"{label} volume lacks source, target, or type")
            entries.append(value)
        return entries

    @staticmethod
    def _portable_volume(value: dict[str, Any], source: pathlib.Path | None = None) -> dict[str, Any]:
        allowed = {"type", "source", "target", "read_only", "consistency", "bind", "volume", "tmpfs"}
        result = {key: item for key, item in value.items() if key in allowed}
        if source is not None:
            result["source"] = str(source)
        return result

    def _legacy_override_semantics(self) -> list[str]:
        assert self.legacy_layout is not None
        if len(self.legacy_layout.compose_files) == 1:
            return []
        base_services = json_object(
            self.legacy_layout.base_model.get("services"), "base legacy services"
        )
        merged_services = json_object(
            self.legacy_layout.merged_model.get("services"), "merged legacy services"
        )
        if set(base_services) != set(merged_services):
            raise UpgradeError("legacy override adds or removes services; no safe v2 translation exists")
        normalized: list[str] = []
        image_services = {"api", "jobs", "search", "web", "clickhouse-migrate"}
        for service_name in sorted(base_services):
            base = json_object(base_services[service_name], f"base legacy service {service_name}")
            merged = json_object(merged_services[service_name], f"merged legacy service {service_name}")
            changed = sorted(
                key for key in set(base) | set(merged) if base.get(key) != merged.get(key)
            )
            if not changed:
                continue
            if changed != ["image"] or service_name not in image_services:
                raise UpgradeError(
                    f"legacy override changes unsupported {service_name} semantics: {', '.join(changed)}"
                )
            image = str(merged.get("image", ""))
            if "/nano-rs/nanosiem/nanosiem-" not in image:
                raise UpgradeError(
                    f"legacy override image for {service_name} is not the managed enterprise repository"
                )
            normalized.append(f"{service_name}:enterprise-image-selection")
        if not normalized:
            raise UpgradeError("legacy override exists but has no qualified semantic difference")
        return normalized

    def _canonical_image_prefix(self, control_root: pathlib.Path, target: str) -> str:
        lock = control_root / "images.enterprise.lock"
        if lock.is_symlink() or not lock.is_file():
            raise UpgradeError("authenticated enterprise control package lacks images.enterprise.lock")
        release = ""
        prefixes: set[str] = set()
        found: set[str] = set()
        required = {"api", "search", "jobs", "connector-runner", "web"}
        for line in lock.read_text(encoding="utf-8").splitlines():
            if line.startswith("# Release:"):
                release = line.split(":", 1)[1].strip().removeprefix("v")
            fields = line.split()
            if not fields or line.startswith("#"):
                continue
            if len(fields) != 2 or not re.fullmatch(r"sha256:[0-9a-f]{64}", fields[1]):
                raise UpgradeError("authenticated enterprise image lock contains an invalid entry")
            reference = fields[0]
            tail = reference.rsplit("/", 1)[-1]
            repository = reference.rsplit(":", 1)[0] if ":" in tail else reference
            matches = [name for name in required if repository.endswith(f"-{name}")]
            if len(matches) == 1:
                name = matches[0]
                if name in found:
                    raise UpgradeError("authenticated enterprise image lock contains a duplicate app image")
                found.add(name)
                prefixes.add(repository[: -(len(name) + 1)])
        if release != target or found != required or len(prefixes) != 1:
            raise UpgradeError("authenticated enterprise image lock does not match the target release")
        prefix = next(iter(prefixes))
        if prefix == "ghcr.io/nano-rs/nano":
            raise UpgradeError("authenticated enterprise image lock resolves to the open image prefix")
        return prefix

    def _copy_authenticated_control(
        self, control_root: pathlib.Path, destination: pathlib.Path, run_id: str,
        expected_bundle_sha256: str,
    ) -> None:
        marker = destination / ".nano-transition-control.json"
        if destination.exists():
            value = read_json(marker)
            if value != {
                "format": "nano-v2-control-v1", "run_id": run_id,
                "bundle_sha256": expected_bundle_sha256,
            }:
                raise UpgradeError("staged authenticated control tree does not match this transition")
            return
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        stage = destination.parent / f".{destination.name}.{run_id}.tmp"
        if stage.exists():
            intent = read_json(self.transition_record)
            if intent.get("run_id") != run_id or intent.get("bundle_sha256") != expected_bundle_sha256:
                raise UpgradeError("stale control staging directory is not owned by this transition")
            shutil.rmtree(stage)
        for path in control_root.rglob("*"):
            if path.is_symlink():
                raise UpgradeError("authenticated control package contains a symbolic link")
        ignored = shutil.ignore_patterns(".git", "target", ".nano-bundle-scratch", "backups", "upgrade-journal")
        shutil.copytree(control_root, stage, ignore=ignored)
        write_json_atomic(stage / marker.name, {
            "format": "nano-v2-control-v1", "run_id": run_id,
            "bundle_sha256": expected_bundle_sha256,
        })
        os.replace(stage, destination)

    def _build_legacy_transition_overlay(
        self, control_dir: pathlib.Path, transition_env: pathlib.Path,
        semantics: list[str],
    ) -> dict[str, Any]:
        assert self.legacy_layout is not None
        canonical_compose = control_dir / "docker-compose.opensource.yml"
        result = self.runner.run([
            "docker", "compose", "--project-directory", str(control_dir),
            "--env-file", str(transition_env),
            "-f", str(canonical_compose), "config", "--format", "json",
        ], timeout=60)
        try:
            canonical = json_object(json.loads(result.stdout), "canonical Compose render")
        except json.JSONDecodeError as error:
            raise UpgradeError("canonical Compose render did not return JSON") from error
        canonical_services = json_object(canonical.get("services"), "canonical services")
        legacy_services = json_object(
            self.legacy_layout.merged_model.get("services"), "legacy services"
        )
        overlay_services: dict[str, Any] = {}

        # Every bundle-owned bind is made absolute so the root canonical file
        # can be published atomically without replacing the legacy config tree.
        for service_name, raw_service in canonical_services.items():
            service = json_object(raw_service, f"canonical service {service_name}")
            mounts: list[dict[str, Any]] = []
            for volume in self._volume_entries(service, f"canonical service {service_name}"):
                if volume.get("type") != "bind":
                    continue
                source = pathlib.Path(str(volume["source"])).resolve()
                if control_dir == source or control_dir in source.parents:
                    mounts.append(self._portable_volume(volume, source))
            if mounts:
                overlay_services.setdefault(service_name, {})["volumes"] = mounts

        data_targets: dict[tuple[str, str], tuple[str, str]] = {
            ("postgres", "/var/lib/postgresql/data"): ("postgres", "/var/lib/postgresql/data"),
            ("clickhouse", "/var/lib/clickhouse"): ("clickhouse", "/var/lib/clickhouse"),
            ("clickhouse", "/var/log/clickhouse-server"): ("clickhouse", "/var/log/clickhouse-server"),
            ("vector", "/var/lib/vector"): ("vector", "/var/lib/vector"),
            ("vector", "/etc/vector/dynamic"): ("vector", "/etc/vector/dynamic"),
            ("api", "/app/data"): ("nano-api", "/app/data"),
            ("api", "/etc/vector/dynamic"): ("nano-api", "/etc/vector/dynamic"),
            ("api", "/app/config/vector"): ("nano-api", "/app/config/vector"),
            ("jobs", "/app/data"): ("nano-jobs", "/app/data"),
            ("jobs", "/etc/vector/dynamic"): ("nano-jobs", "/etc/vector/dynamic"),
            ("jobs", "/app/config/vector"): ("nano-jobs", "/app/config/vector"),
        }
        required = {
            ("postgres", "/var/lib/postgresql/data"),
            ("clickhouse", "/var/lib/clickhouse"),
            ("vector", "/var/lib/vector"),
            ("api", "/app/data"),
        }
        found: set[tuple[str, str]] = set()
        for legacy_service_name, raw_service in legacy_services.items():
            service = json_object(raw_service, f"legacy service {legacy_service_name}")
            for volume in self._volume_entries(service, f"legacy service {legacy_service_name}"):
                key = (legacy_service_name, str(volume["target"]))
                mapped = data_targets.get(key)
                if mapped is None:
                    continue
                if volume.get("type") != "bind":
                    raise UpgradeError(
                        f"legacy persistent mount is not a bind mount: {legacy_service_name}:{volume['target']}"
                    )
                source = pathlib.Path(str(volume["source"]))
                if not source.is_absolute():
                    raise UpgradeError("legacy rendered data mount is not absolute")
                try:
                    resolved_source = source.resolve(strict=True)
                except OSError as error:
                    raise UpgradeError("legacy persistent data source disappeared before transition") from error
                if (
                    source.is_symlink()
                    or not resolved_source.is_dir()
                    or resolved_source not in self.legacy_layout.data_sources
                ):
                    raise UpgradeError("legacy persistent data source changed before transition")
                target_service, target_path = mapped
                translated = self._portable_volume(volume, resolved_source)
                translated["target"] = target_path
                mounts = overlay_services.setdefault(target_service, {}).setdefault("volumes", [])
                mounts[:] = [item for item in mounts if item.get("target") != target_path]
                mounts.append(translated)
                found.add(key)
        missing = sorted(required - found)
        if missing:
            detail = ", ".join(f"{service}:{target}" for service, target in missing)
            raise UpgradeError(f"legacy layout lacks required persistent bind mounts: {detail}")
        return {
            "x-nano-legacy-transition": {
                "format": "nano-legacy-transition-overlay-v1",
                "override_semantics": semantics,
            },
            "services": overlay_services,
        }

    def _publish_control_entry(self, source: pathlib.Path, destination: pathlib.Path) -> None:
        if not source.exists():
            return
        if source.is_symlink():
            raise UpgradeError(f"authenticated control entry is symbolic: {source}")
        if source.is_dir():
            if destination.exists() and (destination.is_symlink() or not destination.is_dir()):
                raise UpgradeError(f"installed control path conflicts with a directory: {destination}")
            destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            for child in sorted(source.iterdir(), key=lambda path: path.name):
                self._publish_control_entry(child, destination / child.name)
            return
        if destination.exists():
            if destination.is_symlink() or not destination.is_file():
                raise UpgradeError(f"installed control path conflicts with a file: {destination}")
            if sha256_path(source) == sha256_path(destination):
                return
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = destination.parent / f".{destination.name}.legacy-transition.tmp"
        if temporary.exists():
            if temporary.is_dir():
                shutil.rmtree(temporary)
            else:
                temporary.unlink()
        shutil.copy2(source, temporary)
        os.chmod(temporary, source.stat().st_mode & 0o777)
        os.replace(temporary, destination)

    def _retire_legacy_orphans(self, record: dict[str, Any]) -> None:
        if record.get("legacy_services_retired") is True:
            return
        source = json_object(record.get("source"), "legacy transition source")
        raw_files = source.get("compose_files")
        if raw_files not in (["docker-compose.yml"], ["docker-compose.yml", "docker-compose.override.yml"]):
            raise UpgradeError("legacy transition has an invalid source Compose set")
        arguments = [
            "docker", "compose", "--project-directory", str(self.install_dir),
            "--env-file", str(self.install_dir / ".env"),
        ]
        for name in raw_files:
            path = self.install_dir / name
            if path.is_symlink() or not path.is_file():
                raise UpgradeError("legacy source Compose file disappeared during transition")
            arguments.extend(("-f", str(path)))
        # These legacy-only application/monitoring services would otherwise
        # keep writing beside nano-api/nano-jobs/nano-search after canonical
        # Compose takes ownership of the project.  Same-name infrastructure,
        # Vector, migrator, and nginx are deliberately left for the normal
        # dependency-ordered rollout to recreate in place.
        retired = ["api", "jobs", "search", "web", "node-exporter", "prometheus"]
        for action in (["stop", *retired], ["rm", "-f", "-s", *retired]):
            result = self.runner.run([*arguments, *action], timeout=180, check=False)
            if result.returncode != 0:
                detail = [line.strip() for line in result.stderr.splitlines() if line.strip()]
                suffix = detail[-1][:300] if detail else "Docker Compose failed"
                raise UpgradeError(f"cannot retire legacy-only services: {suffix}")
        record["legacy_services_retired"] = True
        write_json_atomic(self.transition_record, record)

    @staticmethod
    def _image_repository(reference: str) -> str:
        without_digest = reference.split("@", 1)[0]
        tail = without_digest.rsplit("/", 1)[-1]
        return without_digest.rsplit(":", 1)[0] if ":" in tail else without_digest

    def _docker_architecture(self) -> str:
        raw = self.runner.run(
            ["docker", "info", "--format", "{{.Architecture}}"], timeout=30,
        ).stdout.strip()
        aliases = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}
        try:
            return aliases[raw]
        except KeyError as error:
            raise UpgradeError(f"unsupported Docker host architecture: {raw or 'missing'}") from error

    def _legacy_bridge_environment_digest(self) -> str:
        values = self.env_file.values()
        values.pop("IMAGE_TAG", None)
        encoded = json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _legacy_bridge_control_hashes(self) -> dict[str, str]:
        if self.legacy_layout is None:
            raise UpgradeError("legacy bridge control hashes require a qualified legacy layout")
        return {
            path.name: sha256_path(path)
            for path in self.legacy_layout.compose_files
        }

    def _render_legacy_image_tag(self, version: str) -> dict[str, Any]:
        if self.legacy_layout is None:
            raise UpgradeError("legacy bridge rendering requires a qualified legacy layout")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".env.legacy-bridge.", dir=self.install_dir,
        )
        temporary = pathlib.Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output, self.env_file.path.open("rb") as source:
                shutil.copyfileobj(source, output)
                output.flush()
                os.fsync(output.fileno())
            EnvFile(temporary).replace("IMAGE_TAG", version)
            arguments = [
                "docker", "compose", "--project-directory", str(self.install_dir),
                "--env-file", str(temporary),
            ]
            for compose_file in self.legacy_layout.compose_files:
                arguments.extend(("-f", str(compose_file)))
            result = self.runner.run(
                [*arguments, "config", "--format", "json"], timeout=60,
            )
            try:
                return json_object(json.loads(result.stdout), "legacy bridge Compose render")
            except json.JSONDecodeError as error:
                raise UpgradeError("legacy bridge Compose render did not return JSON") from error
        finally:
            with contextlib.suppress(OSError):
                temporary.unlink()

    def _legacy_bridge_target_lock(
        self, architecture: str, images: dict[str, Any],
    ) -> pathlib.Path:
        if self.legacy_layout is None:
            raise UpgradeError("legacy bridge target lock requires a qualified legacy layout")
        suffix = "open" if self.legacy_layout.edition == "open" else f"enterprise-{architecture}"
        lock = self.nano_cli.parent.parent / "deploy/release/legacy" / f"v0.1.703-{suffix}.lock"
        try:
            nano_legacy_layout._regular_owned(lock, "legacy bridge target lock")
            version, edition, lock_arch, locked = nano_legacy_layout._parse_lock(lock)
        except nano_legacy_layout.LegacyLayoutError as error:
            raise UpgradeError("retained legacy bridge target lock is invalid") from error
        if not (
            version == nano_legacy_bridge.TARGET_VERSION
            and edition == self.legacy_layout.edition
            and lock_arch in {"multiarch", architecture}
        ):
            raise UpgradeError("retained legacy bridge target lock has the wrong identity")
        for service in nano_legacy_bridge.APP_SERVICES:
            image = images[service]
            if (
                locked[service].repository != self._image_repository(image.ref)
                or locked[service].digest != image.digest
            ):
                raise UpgradeError(
                    f"signed bridge image {service} differs from its retained target lock"
                )
        return lock

    def _claim_legacy_bridge(
        self, bundle: pathlib.Path, run_id: str, expected_bundle_sha256: str,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        if self.legacy_layout is None:
            raise UpgradeError("legacy bridge requires the qualified legacy Compose layout")
        if self.legacy_layout.version not in {
            nano_legacy_bridge.SOURCE_VERSION, nano_legacy_bridge.TARGET_VERSION,
        }:
            raise UpgradeError("legacy bridge resolver selected an unsupported source release")
        manifest = verify_manifest(
            self.nano_cli, bundle, self.runner, self.env.get("NANO_IMAGE_PREFIX", ""),
        )
        architecture = self._docker_architecture()
        try:
            images = nano_legacy_bridge.validate_manifest(
                manifest, edition=self.legacy_layout.edition,
                architecture=architecture,
            )
        except nano_legacy_bridge.LegacyBridgeError as error:
            raise UpgradeError(str(error)) from error
        if self.legacy_layout.architecture not in {"multiarch", architecture}:
            raise UpgradeError("qualified legacy source lock does not match the Docker host architecture")
        source_model = self._render_legacy_image_tag(nano_legacy_bridge.SOURCE_VERSION)
        target_model = self._render_legacy_image_tag(nano_legacy_bridge.TARGET_VERSION)
        try:
            nano_legacy_bridge.validate_rendered_transition(
                source_model, target_model, images,
            )
        except nano_legacy_bridge.LegacyBridgeError as error:
            raise UpgradeError(str(error)) from error

        existing = read_json(self.bridge_record) if self.bridge_record.is_file() else {}
        source_lock_name = (
            str(existing.get("source_lock", ""))
            if existing else self.legacy_layout.lock_file.name
        )
        source_lock = self.nano_cli.parent.parent / "deploy/release/legacy" / source_lock_name
        try:
            nano_legacy_layout._regular_owned(source_lock, "legacy bridge source lock")
            source_version, source_edition, source_arch, _ = nano_legacy_layout._parse_lock(source_lock)
        except nano_legacy_layout.LegacyLayoutError as error:
            raise UpgradeError("retained legacy bridge source lock is invalid") from error
        if not (
            source_version == nano_legacy_bridge.SOURCE_VERSION
            and source_edition == self.legacy_layout.edition
            and source_arch in {"multiarch", architecture}
        ):
            raise UpgradeError("retained legacy bridge source lock has the wrong identity")
        target_lock = self._legacy_bridge_target_lock(architecture, images)
        stable = {
            "format": "nano-legacy-bridge-v1",
            "run_id": run_id,
            "bundle_sha256": expected_bundle_sha256,
            "source_version": nano_legacy_bridge.SOURCE_VERSION,
            "target_version": nano_legacy_bridge.TARGET_VERSION,
            "edition": self.legacy_layout.edition,
            "architecture": architecture,
            "project_name": self.legacy_layout.project_name,
            "compose_files": [path.name for path in self.legacy_layout.compose_files],
            "source_lock": source_lock.name,
            "target_lock": target_lock.name,
            "environment_without_image_tag_sha256": self._legacy_bridge_environment_digest(),
            "control_sha256": self._legacy_bridge_control_hashes(),
            "images": [images[name].safe_record() for name in nano_legacy_bridge.APP_SERVICES],
        }
        if existing:
            if existing.get("state") not in {"started", "image-tag-published", "complete"}:
                raise UpgradeError("legacy bridge intent has an invalid state")
            comparable = {key: value for key, value in existing.items() if key not in {"state", "source"}}
            if comparable != stable:
                raise UpgradeError("legacy bridge intent does not match this signed upgrade")
            record = existing
        else:
            if self.legacy_layout.version != nano_legacy_bridge.SOURCE_VERSION:
                raise UpgradeError("target legacy images exist without a durable bridge intent")
            record = {
                **stable,
                "state": "started",
                "source": self.legacy_layout.safe_record(),
            }
            write_json_atomic(self.bridge_record, record)
        self._legacy_bridge_rollout = True
        return manifest, images, record

    def _bridge_images_from_record(self, record: dict[str, Any]) -> dict[str, Any]:
        manifest = {
            "version": record.get("target_version"),
            "edition": record.get("edition"),
            "architecture": record.get("architecture"),
            "requires": {"mandatory_backup": True},
            "images": record.get("images"),
        }
        try:
            return nano_legacy_bridge.validate_manifest(
                manifest,
                edition=str(record.get("edition", "")),
                architecture=str(record.get("architecture", "")),
            )
        except nano_legacy_bridge.LegacyBridgeError as error:
            raise UpgradeError("legacy bridge audit record is invalid") from error

    def _verify_loaded_bridge_images(self, images: dict[str, Any]) -> None:
        for service in nano_legacy_bridge.APP_SERVICES:
            image = images[service]
            result = self.runner.run([
                "docker", "image", "inspect", "--format",
                "{{.Id}}", image.ref,
            ], timeout=30)
            # The classic Docker image store exposes the archive's signed
            # config digest as .Id.  The containerd image store exposes the
            # signed registry/platform manifest digest for the same loaded
            # archive.  nano_bundle.load_bundle already binds both identities
            # to the SHA-verified archive before it publishes this tag.
            if result.stdout.strip() not in {image.platform_digest, image.digest}:
                raise UpgradeError(
                    f"loaded bridge image {service} does not match its signed platform identity"
                )

    def _publish_legacy_bridge(
        self, images: dict[str, Any], record: dict[str, Any],
    ) -> dict[str, Any]:
        self._verify_loaded_bridge_images(images)
        values = self.env_file.values()
        if values.get("NANO_VERSION") or values.get("NANO_EDITION"):
            raise UpgradeError("legacy bridge refuses canonical identity fields")
        if values.get("IMAGE_TAG") not in {
            nano_legacy_bridge.SOURCE_VERSION, nano_legacy_bridge.TARGET_VERSION,
        }:
            raise UpgradeError("legacy bridge environment has an unexpected IMAGE_TAG")
        if values.get("IMAGE_TAG") != nano_legacy_bridge.TARGET_VERSION:
            self.env_file.replace("IMAGE_TAG", nano_legacy_bridge.TARGET_VERSION)
        if self._legacy_bridge_environment_digest() != record.get(
            "environment_without_image_tag_sha256"
        ):
            raise UpgradeError("legacy bridge changed environment fields other than IMAGE_TAG")
        if self._legacy_bridge_control_hashes() != record.get("control_sha256"):
            raise UpgradeError("legacy bridge changed the legacy Compose control files")
        record["state"] = "image-tag-published"
        write_json_atomic(self.bridge_record, record)
        self.env = self.env_file.values()
        self.version = nano_legacy_bridge.TARGET_VERSION
        self._legacy_bridge_rollout = True
        return record

    def _canonicalize_legacy_layout(
        self, target: str, run_id: str, expected_bundle_sha256: str,
    ) -> dict[str, Any]:
        if self.legacy_layout is None:
            record = read_json(self.transition_record)
            if (
                record.get("format") == "nano-legacy-transition-v1"
                and record.get("run_id") == run_id
                and record.get("bundle_sha256") == expected_bundle_sha256
            ):
                if record.get("state") in {"started", "canonical-published"}:
                    if self.version != target:
                        raise UpgradeError("legacy transition target environment was not atomically published")
                    self.compose(["config", "--quiet"], timeout=60)
                    record["state"] = "canonical-published"
                    write_json_atomic(self.transition_record, record)
                    self._retire_legacy_orphans(record)
                    record["state"] = "complete"
                    write_json_atomic(self.transition_record, record)
                elif record.get("state") != "complete":
                    raise UpgradeError("legacy transition has an invalid journal state")
                staged_environment = (
                    self.install_dir / ".nano-v2-control" / expected_bundle_sha256 / ".env.transition"
                )
                if staged_environment.exists():
                    if staged_environment.is_symlink() or not staged_environment.is_file():
                        raise UpgradeError("legacy transition staged environment is unsafe")
                    staged_environment.unlink()
                self._legacy_transition_rollout = True
                return record
            raise UpgradeError("legacy transition intent is missing while resuming canonical prepare")
        control_root = self.nano_cli.parent.parent
        if (
            control_root == self.install_dir
            or control_root in self.install_dir.parents
            or self.install_dir in control_root.parents
        ):
            raise UpgradeError(
                "authenticated v2 control package must be extracted outside the legacy install tree"
            )
        marker = control_root / ".nano-edition"
        if marker.is_symlink() or not marker.is_file() or marker.read_text(encoding="utf-8").strip() != "enterprise":
            raise UpgradeError("authenticated control package is not the enterprise edition")
        bundle_marker = control_root / ".nano-bundle"
        if bundle_marker.is_symlink() or not bundle_marker.is_file():
            raise UpgradeError("authenticated control package marker is missing")
        prefix = self._canonical_image_prefix(control_root, target)
        semantics = self._legacy_override_semantics()
        record: dict[str, Any] = {
            "format": "nano-legacy-transition-v1",
            "state": "started",
            "run_id": run_id,
            "bundle_sha256": expected_bundle_sha256,
            "source": self.legacy_layout.safe_record(),
            "target_version": target,
            "overlay": "docker-compose.legacy-preserved.yml",
            "override_semantics": semantics,
        }
        if self.transition_record.exists():
            existing = read_json(self.transition_record)
            comparable = json.loads(json.dumps(existing))
            candidate = json.loads(json.dumps(record))
            for value in (comparable, candidate):
                value["state"] = "started"
                source = value.get("source")
                if isinstance(source, dict):
                    archives = source.get("physical_archives")
                    if isinstance(archives, list):
                        source["physical_archives"] = [
                            item.get("path") if isinstance(item, dict) else None
                            for item in archives
                        ]
            if comparable != candidate:
                raise UpgradeError("legacy transition intent does not match this upgrade")
            record = existing
        else:
            write_json_atomic(self.transition_record, record)

        control_dir = self.install_dir / ".nano-v2-control" / expected_bundle_sha256
        self._copy_authenticated_control(
            control_root, control_dir, run_id, expected_bundle_sha256,
        )
        generated = control_dir / "scripts/lib/generated-secrets.sh"
        if not generated.is_file():
            raise UpgradeError("authenticated control package lacks generated-secret backfill")
        transition_env = control_dir / ".env.transition"
        if not transition_env.exists():
            shutil.copy2(self.install_dir / ".env", transition_env)
            os.chmod(transition_env, 0o600)
        self.runner.run([
            "bash", "-c",
            'set -euo pipefail; source "$1"; nano_backfill_generated_secrets "$2" generate',
            "nano-legacy-transition", str(generated), str(transition_env),
        ], timeout=120)
        transition_env_file = EnvFile(transition_env)
        transition_env_file.replace_many({
            "NANO_VERSION": target,
            "NANO_EDITION": "enterprise",
            "NANO_IMAGE_PREFIX": prefix,
            "NANO_SCHEMA_PROFILE": self.legacy_layout.schema_profile,
            "COMPOSE_PROJECT_NAME": self.legacy_layout.project_name,
            "NANO_COMPOSE_OVERLAYS": "docker-compose.legacy-preserved.yml",
        })
        overlay = self._build_legacy_transition_overlay(
            control_dir, transition_env, semantics,
        )
        write_json_atomic(
            self.install_dir / "docker-compose.legacy-preserved.yml", overlay,
        )

        for name in (
            "scripts", "deploy", "migrations", "migrations/postgres-enterprise",
            "clickhouse", "clickhouse-enterprise", "config",
        ):
            source = control_dir / name
            destination = self.install_dir / name
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._publish_control_entry(source, destination)
        # Publish the full signed control tree, not just files referenced by
        # Compose.  A resume starts a fresh LocalOps instance and its preflight
        # validates enrichment listeners from install_dir/config before any
        # rollout can continue.
        for name in (".nano-bundle", ".nano-edition", "images.enterprise.lock"):
            self._publish_control_entry(control_dir / name, self.install_dir / name)
        self._publish_control_entry(
            control_dir / "docker-compose.opensource.yml",
            self.install_dir / "docker-compose.opensource.yml",
        )
        canonical = [
            "docker", "compose", "--project-directory", str(self.install_dir),
            "--env-file", str(self.install_dir / ".env"),
            "-f", str(self.install_dir / "docker-compose.opensource.yml"),
            "-f", str(self.install_dir / "docker-compose.legacy-preserved.yml"),
        ]
        canonical_validation = list(canonical)
        canonical_validation[canonical_validation.index(str(self.install_dir / ".env"))] = str(transition_env)
        self.runner.run([*canonical_validation, "config", "--quiet"], timeout=60)
        descriptor, environment_tmp = tempfile.mkstemp(
            prefix=".env.legacy-transition.", dir=self.install_dir,
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output, transition_env.open("rb") as source:
                shutil.copyfileobj(source, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(environment_tmp, self.install_dir / ".env")
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(descriptor)
            with contextlib.suppress(OSError):
                os.unlink(environment_tmp)
            raise
        self.runner.run([*canonical, "config", "--quiet"], timeout=60)
        record["state"] = "canonical-published"
        write_json_atomic(self.transition_record, record)
        self._retire_legacy_orphans(record)
        restored_marker = self.install_dir / ".nano-legacy-layout-restored"
        if restored_marker.exists():
            restored_marker.unlink()
        record["state"] = "complete"
        write_json_atomic(self.transition_record, record)
        transition_env.unlink()
        self.env = self.env_file.values()
        self.edition = "enterprise"
        self.version = target
        self.schema_profile = self.env.get("NANO_SCHEMA_PROFILE", "udm")
        self.legacy_layout = None
        self._legacy_transition_rollout = True
        self.compose_args = canonical
        return record

    def prepare(
        self, bundle: pathlib.Path, source: str, target: str, run_id: str,
        expected_bundle_sha256: str,
    ) -> dict[str, Any]:
        if sha256_path(bundle) != expected_bundle_sha256:
            raise UpgradeError("bundle digest changed after coordinator verification")
        legacy_bridge = nano_legacy_bridge.is_legacy_bridge(source, target)
        bridge_images: dict[str, Any] = {}
        bridge_record: dict[str, Any] = {}
        if legacy_bridge:
            # Manifest identity and host architecture are checked before even
            # the retained-image tags are created. A wrong-architecture bridge
            # therefore cannot load, tag, or select an image on this host.
            _, bridge_images, bridge_record = self._claim_legacy_bridge(
                bundle, run_id, expected_bundle_sha256,
            )
        current = getattr(self, "version", None)
        if current is None:
            current = canonical_version(self.env_file.values().get("NANO_VERSION", ""))
        if current not in {source, target}:
            raise UpgradeError(
                f"cannot resume prepare on {self.host_name}: installed {current}, "
                f"expected source {source} or target {target}"
            )
        containers = self.compose(["ps", "-q"], timeout=60).stdout.split()
        if not containers:
            raise UpgradeError("cannot retain previous images because this role has no running containers")
        retained_file = self.install_dir / "upgrade-journal" / f"{run_id}-{self.host_name}-images.json"
        if retained_file.exists():
            retained_value = read_json(retained_file)
            retained_raw = retained_value.get("images")
            if (
                retained_value.get("run_id") != run_id
                or retained_value.get("host") != self.host_name
                or retained_value.get("source_version") != source
                or retained_value.get("target_version") != target
                or retained_value.get("bundle_sha256") != expected_bundle_sha256
                or not isinstance(retained_raw, list)
            ):
                raise UpgradeError("retained-image prepare intent does not match this upgrade")
            retained = [json_object(item, "retained image") for item in retained_raw]
            for item in retained:
                tag = str(item.get("retained_tag", ""))
                expected_id = str(item.get("id", ""))
                if not tag.startswith(f"nano-upgrade-retained:{run_id}-{self.host_name}-"):
                    raise UpgradeError("retained-image prepare intent contains an invalid tag")
                result = self.runner.run(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", tag], timeout=30,
                )
                if result.stdout.strip() != expected_id or not expected_id.startswith("sha256:"):
                    raise UpgradeError("retained-image prepare intent no longer resolves to its image")
        else:
            if current == target:
                raise UpgradeError(
                    "target version is present without the retained-image prepare intent"
                )
            retained = []
            seen: set[str] = set()
            for container in containers:
                result = self.runner.run(
                    ["docker", "inspect", "--format", "{{.Image}}\t{{.Config.Image}}", container],
                    timeout=30,
                )
                fields = result.stdout.strip().split("\t", 1)
                if len(fields) != 2:
                    raise UpgradeError("cannot identify an active image before upgrade")
                image_id, image = fields
                if not image_id.startswith("sha256:"):
                    raise UpgradeError("cannot identify an active image before upgrade")
                if image_id in seen:
                    continue
                seen.add(image_id)
                tag = f"nano-upgrade-retained:{run_id}-{self.host_name}-{len(retained)}"
                # Deterministic tags make a SIGKILL after this mutation safe:
                # rerunning prepare overwrites the same tag with the same ID.
                self.runner.run(["docker", "image", "tag", image_id, tag], timeout=30)
                retained.append({"image": image, "id": image_id, "retained_tag": tag})
            write_json_atomic(retained_file, {
                "run_id": run_id,
                "host": self.host_name,
                "source_version": source,
                "target_version": target,
                "bundle_sha256": expected_bundle_sha256,
                "images": retained,
            })
        # Bundle load and atomic env replacement are both deliberately
        # idempotent. The coordinator journals step_started before invoking
        # this worker, and resume accepts source or target only for that
        # journaled prepare intent.
        load_environment = os.environ.copy()
        # Keep bundle-load scratch on the exact filesystem measured by
        # preflight. The loader streams one image archive at a time and removes
        # it on completion; it must not silently fall back to the SSH user's
        # home directory on remote workers.
        load_environment["NANO_BUNDLE_TMPDIR"] = str(
            self.install_dir / ".nano-bundle-scratch"
        )
        loaded = self._bundle_load(bundle, load_environment)
        if loaded.returncode != 0:
            # `nano bundle` prints one safe reason line (no credentials).
            reason = (loaded.stderr or "").strip().splitlines()
            action = "pull the release images" if is_compose_package(bundle) else "load the bundle images"
            raise UpgradeError(
                f"could not {action} on {self.host_name}: "
                f"{reason[-1] if reason else f'exit {loaded.returncode}'}"
            )
        if legacy_bridge:
            bridge_record = self._publish_legacy_bridge(
                bridge_images, bridge_record,
            )
            return {
                "retained_images": str(retained_file), "count": len(retained),
                "legacy_bridge": bridge_record,
            }
        transition: dict[str, Any] | None = None
        transition_record = getattr(
            self, "transition_record", self.install_dir / ".nano-legacy-transition.json",
        )
        if getattr(self, "legacy_layout", None) is not None or transition_record.is_file():
            transition = self._canonicalize_legacy_layout(
                target, run_id, expected_bundle_sha256,
            )
            current = self.version
        pruned_control_pins = self._prune_legacy_control_pins()
        # NAN-5013: single-node only (preflight refuses a public token on a
        # role-split host, whose cluster must share one generated value).
        rotated_install_token = False
        pinned_delivery_mode = False
        if getattr(self, "role_env", None):
            pinned_delivery_mode = pin_compatible_delivery_mode(self.env_file)
            if pinned_delivery_mode:
                self.env["NANO_VECTOR_CONFIG_DELIVERY_STRICT"] = "false"
                eprint(
                    "note: pinned NANO_VECTOR_CONFIG_DELIVERY_STRICT=false in .env (this "
                    "cluster predates strict Vector config delivery). Once every ingest "
                    "host's .env has NANO_VECTOR_CONFIG_DELIVERY_TOKEN, set it to true on "
                    "the app host and restart nano-api; v2.1 enforces it regardless."
                )
        else:
            rotated_install_token = rotate_public_install_token(self.env_file)
            if rotated_install_token:
                self.env["VECTOR_AUTH_TOKEN"] = self.env_file.values()["VECTOR_AUTH_TOKEN"]
                eprint(
                    "warning: VECTOR_AUTH_TOKEN was a publicly known default, which nano now "
                    "refuses; replaced it with a generated value in .env. Senders using named "
                    "ingest tokens keep working; senders still sending the public token get "
                    "HTTP 401 and need a named token (Ingestion > Ingest tokens)."
                )
        # NAN-5271: pin the profile an older install already runs before the
        # new release's OCSF default can apply to it.
        pinned_schema_profile = pin_legacy_schema_profile(self.env_file)
        if pinned_schema_profile:
            self.env["NANO_SCHEMA_PROFILE"] = "udm"
            self.schema_profile = "udm"
            eprint(
                "note: pinned NANO_SCHEMA_PROFILE=udm in .env (this install predates the "
                "schema choice and holds UDM data). Copy the updated .env to every host."
            )
        if current != target:
            self.env_file.replace("NANO_VERSION", target)
        verified = canonical_version(self.env_file.values().get("NANO_VERSION", ""))
        if verified != target:
            raise UpgradeError("prepare did not persist the verified target version")
        self.env["NANO_VERSION"] = target
        self.version = target
        return {
            "retained_images": str(retained_file), "count": len(retained),
            "legacy_transition": transition,
            "rotated_public_install_token": rotated_install_token,
            "pinned_compatible_delivery_mode": pinned_delivery_mode,
            "pinned_schema_profile": pinned_schema_profile,
            "pruned_control_pins": pruned_control_pins,
        }

    def _prune_legacy_control_pins(self) -> list[str]:
        """NAN-5397: a settled legacy transition's overlay pins every canonical
        config bind to .nano-v2-control/<sha>/, so later upgrades never reach
        those services (and an old pinned nginx.conf file mount blocks the
        directory-mounted nginx). Drop the pins; the base file's mounts apply.
        Not on the run that performs the transition (its rollout uses them)."""
        if getattr(self, "role_env", None) or getattr(self, "_legacy_transition_rollout", False):
            return []
        overlay = "docker-compose.legacy-preserved.yml"
        if overlay not in self.env.get("NANO_COMPOSE_OVERLAYS", "").split():
            return []
        dropped = compose_stale_mounts.prune_control_pins(self.install_dir, self.install_dir / overlay)
        for entry in dropped:
            eprint(f"note: {overlay}: dropped the pinned config mount {entry}")
        return dropped

    def _up_existing(
        self, services: Iterable[str], timeout: int, *, exact: bool = False,
    ) -> list[str]:
        selected = list(dict.fromkeys(services)) if exact else [
            service for service in services if self._service_expected(service)
        ]
        if selected:
            self.compose(
                ["up", "-d", "--no-deps", "--pull", "never", *self._recreate_args(selected), *selected],
                timeout=timeout,
            )
        return selected

    def _stop_exact(self, services: Iterable[str], timeout: int) -> list[str]:
        selected = list(dict.fromkeys(services))
        if selected:
            self.compose(["stop", "--timeout", str(min(timeout, 60)), *selected], timeout=timeout)
        return selected

    def _start_exact(self, services: Iterable[str], timeout: int) -> list[str]:
        selected = list(dict.fromkeys(services))
        if selected:
            # A backup fence must resume the exact containers it stopped. An
            # `up` here can recreate them when Compose notices unrelated
            # configuration drift, widening the writer outage and changing
            # runtime state during an otherwise read-only snapshot operation.
            self.compose(["start", *selected], timeout=timeout)
        return selected

    def _drain_vector(self, timeout: int) -> None:
        if not self._service_exists("vector"):
            return
        metrics_command = r"""
metrics=$(
  if command -v curl >/dev/null 2>&1; then
    curl -fsS http://127.0.0.1:9598/metrics
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- http://127.0.0.1:9598/metrics
  elif command -v bash >/dev/null 2>&1; then
    bash -ec 'exec 3<>/dev/tcp/127.0.0.1/9598
printf "GET /metrics HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" >&3
cat <&3'
  else
    echo "no HTTP client is available to inspect Vector buffers" >&2
    exit 127
  fi
)
printf '%s\n' "$metrics" | awk '$0 !~ /^#/ &&
  ($1 ~ /(^|_)vector_buffer_events(\{|$)/ ||
   $1 ~ /(^|_)vector_buffer_size_events(\{|$)/) &&
  $0 !~ /component_id="prometheus_metrics"/ {
  value = (NF >= 3 ? $(NF-1) : $NF)
  s += value; count += 1
} END {if (count == 0) {print "MISSING"; exit 3} print s+0}'
"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.compose(
                ["exec", "-T", "vector", "sh", "-ec", metrics_command],
                timeout=20,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip() in {"0", "0.0"}:
                return
            time.sleep(2)
        raise UpgradeError(f"Vector buffers did not drain within {timeout}s")

    def _stop_legacy_vector_gracefully(self, container: str, timeout: int) -> None:
        """Require Vector to finish its SIGTERM drain instead of being SIGKILLed."""
        if not re.fullmatch(r"[0-9a-f]{12,64}", container):
            raise UpgradeError("journaled legacy Vector container identity is invalid")
        running = self._running_services(("vector",))
        if running:
            if running != ["vector"] or self._service_container("vector") != container:
                raise UpgradeError("legacy Vector container changed during its drain")
            stop_timeout = min(timeout, 300)
            self.compose(
                ["stop", "--timeout", str(stop_timeout), "vector"],
                timeout=stop_timeout + 30,
            )
        result = self.runner.run(
            [
                "docker", "inspect", "--format",
                "{{.State.Status}}\t{{.State.ExitCode}}\t{{.State.OOMKilled}}",
                container,
            ],
            timeout=30,
            check=False,
        )
        if result.returncode != 0 or result.stdout.strip() != "exited\t0\tfalse":
            raise UpgradeError(
                "legacy Vector did not complete a clean acknowledged-event drain"
            )

    def _quiesce_legacy_vector_for_transition(self, timeout: int) -> None:
        """Drain and stop the old same-name Vector exactly once before conversion."""
        record = read_json(self.transition_record)
        if record.get("format") != "nano-legacy-transition-v1":
            raise UpgradeError("legacy transition audit record is invalid")
        phase = record.get("legacy_vector_quiesce")
        if phase == "complete":
            return
        if phase not in (None, "stopping"):
            raise UpgradeError("legacy Vector quiesce journal state is invalid")
        if phase is None:
            container = self._service_container("vector")
            record["legacy_vector_container"] = container
            record["legacy_vector_quiesce"] = "stopping"
            write_json_atomic(self.transition_record, record)
        else:
            container = record.get("legacy_vector_container")
            if not isinstance(container, str):
                raise UpgradeError("legacy Vector quiesce journal lacks its container identity")
        self._stop_legacy_vector_gracefully(container, timeout)
        record["legacy_vector_quiesce"] = "complete"
        write_json_atomic(self.transition_record, record)

    def _retire_legacy_managed_vector_config(self) -> dict[str, Any]:
        """Archive the old managed OTLP fragment before v2 Vector loads the bind."""
        record = read_json(self.transition_record)
        if record.get("format") != "nano-legacy-transition-v1":
            raise UpgradeError("legacy transition audit record is invalid")
        rendered = json_object(
            json.loads(self.compose(["config", "--format", "json"], timeout=60).stdout),
            "canonical Compose render",
        )
        services = json_object(rendered.get("services"), "canonical services")
        vector = json_object(services.get("vector"), "canonical vector service")
        roots = [
            pathlib.Path(str(volume["source"]))
            for volume in self._volume_entries(vector, "canonical vector service")
            if volume.get("type") == "bind" and volume.get("target") == "/etc/vector/dynamic"
        ]
        if len(roots) != 1:
            raise UpgradeError("canonical Vector does not have exactly one dynamic bind root")
        root = roots[0]
        try:
            resolved_root = root.resolve(strict=True)
        except OSError as error:
            raise UpgradeError("legacy Vector dynamic bind root disappeared") from error
        source = json_object(record.get("source"), "legacy transition source")
        qualified_roots = source.get("data_sources")
        if not isinstance(qualified_roots, list) or str(resolved_root) not in qualified_roots:
            raise UpgradeError("canonical Vector dynamic bind is not a qualified legacy data root")
        if root.is_symlink() or not resolved_root.is_dir():
            raise UpgradeError("legacy Vector dynamic bind root is unsafe")

        relative = pathlib.Path("sources/configs/03-otlp-source.toml")
        candidate = resolved_root / relative
        archive_dir = resolved_root / ".nano-v2-transition-managed"
        archived = archive_dir / relative.name
        marker = archive_dir / "manifest.json"
        marker_value = {
            "format": "nano-v2-retired-managed-vector-v1",
            "source": str(relative),
            "archive": str(pathlib.Path(archive_dir.name) / archived.name),
            "sha256": LEGACY_MANAGED_OTLP_CONFIG_SHA256,
        }

        candidate_present = candidate.exists() or candidate.is_symlink()
        if candidate_present:
            if candidate.is_symlink() or not candidate.is_file():
                raise UpgradeError("legacy managed Vector config is not a regular file")
            if sha256_path(candidate) != LEGACY_MANAGED_OTLP_CONFIG_SHA256:
                raise UpgradeError(
                    "legacy 03-otlp-source.toml differs from the qualified managed artifact"
                )
            size = candidate.stat().st_size
        elif not (archive_dir.exists() or archive_dir.is_symlink()):
            result = {"state": "absent", "source": str(relative)}
            record["legacy_managed_vector_config"] = result
            write_json_atomic(self.transition_record, record)
            return result

        if archive_dir.exists() or archive_dir.is_symlink():
            if archive_dir.is_symlink() or not archive_dir.is_dir():
                raise UpgradeError("legacy managed Vector archive path is unsafe")
            if marker.is_file() and not marker.is_symlink():
                if read_json(marker) != marker_value:
                    raise UpgradeError("legacy managed Vector archive marker is invalid")
            elif any(archive_dir.iterdir()) or not candidate_present:
                raise UpgradeError("legacy managed Vector archive directory is not owned by this transition")
            else:
                write_json_atomic(marker, marker_value)
        else:
            archive_dir.mkdir(mode=0o700)
            write_json_atomic(marker, marker_value)

        if candidate_present:
            if archived.exists() or archived.is_symlink():
                raise UpgradeError("legacy managed Vector config exists at both live and archive paths")
            os.replace(candidate, archived)
        elif archived.is_file() and not archived.is_symlink():
            if sha256_path(archived) != LEGACY_MANAGED_OTLP_CONFIG_SHA256:
                raise UpgradeError("archived legacy managed Vector config digest changed")
            size = archived.stat().st_size
        elif archived.exists() or archived.is_symlink():
            raise UpgradeError("archived legacy managed Vector config is unsafe")
        else:
            raise UpgradeError("legacy managed Vector archive marker lacks its artifact")

        result = {
            "state": "archived",
            "source": str(relative),
            "archive": str(pathlib.Path(archive_dir.name) / archived.name),
            "sha256": LEGACY_MANAGED_OTLP_CONFIG_SHA256,
            "bytes": size,
        }
        record["legacy_managed_vector_config"] = result
        write_json_atomic(self.transition_record, record)
        return result

    def _lb_hook(self, kind: str, required: bool) -> None:
        variable = f"NANO_UPGRADE_LB_{kind.upper()}_COMMAND"
        command = os.environ.get(variable, "")
        if not command and required:
            raise UpgradeError(f"{variable} is mandatory when inventory has multiple ingest hosts")
        if not command:
            return
        path = pathlib.Path(command)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise UpgradeError(f"{variable} must name an absolute executable")
        at = utc_now()
        started = time.monotonic()
        result = self.runner.run([str(path), self.host_name], timeout=120, check=False)
        self._record_lb_hook(kind, result.returncode, started, at)
        if result.returncode != 0:
            lines = [line.strip() for line in (result.stderr or "").splitlines() if line.strip()]
            detail = lines[-1][:300] if lines else f"exit {result.returncode}"
            raise UpgradeError(f"{kind} hook failed for {self.host_name}: {detail}")

    def _record_lb_hook(self, kind: str, returncode: int, started: float, at: str) -> None:
        """NAN-5285 (v2.0.13 retest F8): every drain/rejoin hook call goes into
        the upgrade journal (host, kind, exit code, duration; never the hook's
        output). The worker collects them here and returns them with the
        action's result; the coordinator journals one `lb_hook` event each."""
        calls = getattr(self, "_lb_hook_calls", None)
        if calls is None:
            calls = []
            self._lb_hook_calls = calls
        calls.append({
            "host": getattr(self, "host_name", "single"), "kind": kind,
            "rc": int(returncode), "at": at,
            "duration_ms": round((time.monotonic() - started) * 1000),
        })

    def _take_lb_hook_calls(self) -> list[dict[str, Any]]:
        calls = list(getattr(self, "_lb_hook_calls", None) or [])
        self._lb_hook_calls = []
        return calls

    def _with_lb_hooks(self, result: dict[str, Any]) -> dict[str, Any]:
        calls = self._take_lb_hook_calls()
        if calls:
            result["lb_hooks"] = calls
        return result

    def _env_seconds(self, name: str, default: int, maximum: int = 3600) -> int:
        return env_seconds(name, default, maximum)

    def _left_drained(self, error: UpgradeError) -> UpgradeError:
        """NAN-5279: a rollout that drained this host and then failed (its
        services, the probe or the rejoin) stops the upgrade with the host
        still out of the load balancer, and says so. Nothing drains another
        host: the coordinator rolls hosts one at a time and stops here."""
        calls = getattr(self, "_lb_hook_calls", None) or []
        made = "; ".join(
            f"{call['kind']} rc={call['rc']} at {call['at']}" for call in calls
        )
        hooks = f" (load-balancer hook calls on this host: {made})" if made else ""
        return UpgradeError(
            f"{error}{hooks}. {self.host_name} may still be DRAINED from the load balancer: the "
            "upgrade stopped before rejoining it and drained no other host. Fix the cause, "
            "then resume with `scripts/nano upgrade` (it re-runs this host's rollout and "
            "rejoins it), or rejoin it by hand with your rejoin hook"
        )

    def _edge_readyz_status(self) -> str:
        """HTTP status of this app host's own load-balancer health check."""
        result = self.compose(
            [
                "exec", "-T", "nginx", "sh", "-c",
                "wget -S -O /dev/null http://127.0.0.1:80/readyz 2>&1 "
                "| awk '/^ *HTTP\\//{code=$2} END{print code}'",
            ],
            timeout=30, check=False,
        )
        return result.stdout.strip()

    def _edge_client_requests_since(self, since: str) -> int:
        """Client requests the app edge logged since `since` (RFC 3339).

        The LB's /readyz checks are not logged, so any request line here is
        traffic the load balancer (or a direct client) still sends this host.
        """
        result = self.compose(
            ["logs", "--no-color", "--since", since, "nginx"], timeout=60, check=False,
        )
        return sum(
            1 for line in result.stdout.splitlines()
            if re.search(r'"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /', line)
            and not re.search(r'"[A-Z]+ /(readyz|healthz|api/health)[ ?]', line)
        )

    def _drain_app_host(self, selected: Iterable[str]) -> bool:
        """NAN-5213: take one of several app hosts out of the load balancer.

        The app edge's /readyz (the LB health check) returns 503 while
        /tmp/nano-drain exists in the nginx container. After proving that,
        wait until the edge stops receiving client requests for
        NANO_LB_DRAIN_QUIET_SECONDS (the LB has removed the host), for at most
        NANO_LB_DRAIN_SECONDS, then restart this host's services. A configured
        NANO_UPGRADE_LB_DRAIN_COMMAND runs too.
        """
        role_env = getattr(self, "role_env", None) or {}
        if int(role_env.get("NANO_APP_HOST_COUNT", "1") or "1") < 2:
            return False
        if "nginx" not in selected:
            return False
        self.compose(["exec", "-T", "nginx", "touch", "/tmp/nano-drain"], timeout=60)
        deadline = time.monotonic() + 30
        while self._edge_readyz_status() != "503":
            if time.monotonic() >= deadline:
                raise UpgradeError("the app edge did not report draining (/readyz 503) within 30s")
            time.sleep(1)
        self._lb_hook("drain", False)
        max_wait = self._env_seconds("NANO_LB_DRAIN_SECONDS", 30)
        quiet = self._env_seconds("NANO_LB_DRAIN_QUIET_SECONDS", 5)
        started = last_traffic = time.monotonic()
        since = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        while time.monotonic() - started < max_wait:
            time.sleep(1)
            now_stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if self._edge_client_requests_since(since):
                last_traffic = time.monotonic()
            since = now_stamp
            if time.monotonic() - last_traffic >= quiet:
                break
        return True

    def _rejoin_app_host(self) -> None:
        """Put a drained app host back and let the LB re-admit it.

        /readyz must answer 200 for NANO_LB_REJOIN_CHECKS consecutive checks;
        then hold NANO_LB_REJOIN_SECONDS (default 60, at least your LB's
        check interval x rise count) so the coordinator never drains the next
        app host while this one is still out of the pool.
        """
        # A recreated nginx starts without the marker; an unchanged one keeps
        # it until removed here.
        self.compose(["exec", "-T", "nginx", "rm", "-f", "/tmp/nano-drain"], timeout=60, check=False)
        needed = max(1, self._env_seconds("NANO_LB_REJOIN_CHECKS", 3, 100))
        consecutive = 0
        deadline = time.monotonic() + 300
        while consecutive < needed:
            if time.monotonic() >= deadline:
                raise UpgradeError("the app edge /readyz did not stay 200 after the restart")
            consecutive = consecutive + 1 if self._edge_readyz_status() == "200" else 0
            if consecutive < needed:
                time.sleep(1)
        self._lb_hook("rejoin", False)
        hold = self._env_seconds("NANO_LB_REJOIN_SECONDS", 60)
        if hold:
            time.sleep(hold)

    def _wait_app_readiness(
        self, services: Iterable[str], timeout: int,
    ) -> dict[str, Any]:
        self._wait_services(services, timeout)
        deadline = time.monotonic() + timeout
        last = "routed API probe was not attempted"
        while time.monotonic() < deadline:
            try:
                return self._probe_app_route()
            except (UpgradeError, OSError, ValueError, json.JSONDecodeError) as error:
                last = " ".join(str(error).split())[:300] or "routed API probe failed"
            time.sleep(2)
        raise UpgradeError(
            f"app/API dependency readiness gate did not become healthy within {timeout}s; "
            f"ingest consumers were not started (last probe: {last})"
        )

    def _up_app_services(
        self, services: Iterable[str], timeout: int, *, exact: bool = False,
    ) -> list[str]:
        selected = list(dict.fromkeys(services)) if exact else [
            service for service in services if self._service_expected(service)
        ]
        core = [service for service in selected if service not in APP_EDGE_SERVICES]
        edges = [service for service in APP_EDGE_SERVICES if service in selected]
        if core:
            self.compose(
                ["up", "-d", "--no-deps", "--pull", "never", *self._recreate_args(core), *core],
                timeout=timeout,
            )
            self._wait_services(core, timeout)
        if edges:
            # nginx resolves compose service names when its workers start.
            # Recreate the edges after nano-api is healthy so they cannot keep
            # a dead upstream address across an API container replacement.
            self.compose(
                ["up", "-d", "--no-deps", "--pull", "never", "--force-recreate", *edges],
                timeout=timeout,
            )
            self._wait_services(edges, timeout)
        return selected

    def _probe_ingest_consumer_readiness(self) -> str:
        # The previous-supported image may predate the tap relay's /healthz
        # route even though the current, mounted consumer implements the same
        # readiness contract. Prefer the relay verdict, then reproduce that
        # verdict inside the consumer from its shared runtime volumes. This is
        # a state gate, not a compatibility sleep: the marker is refreshed only
        # after the API's current generation and tokens have both synced and
        # Vector has acknowledged the generation through its metrics.
        probe = r'''
set -eu
if curl -fsS --max-time 3 http://127.0.0.1:8687/healthz >/dev/null 2>&1; then
  printf 'tap relay healthz ready\n'
  exit 0
fi
runtime=/etc/vector/runtime
tokens=/etc/vector/dynamic/ingest-tokens/tokens.json
ready="$runtime/.nano-ready"
installed_file="$runtime/.nano-generation"
[ -s "$ready" ] || { echo "consumer ready marker is missing" >&2; exit 11; }
set -- $(cat "$ready")
[ "$#" -eq 2 ] || { echo "consumer ready marker is malformed" >&2; exit 12; }
generation="$1"
written_at="$2"
case "$generation" in
  00000000000000000000|*[!0-9]*)
    echo "consumer ready generation is invalid" >&2; exit 13 ;;
esac
[ "${#generation}" -eq 20 ] || {
  echo "consumer ready generation is invalid" >&2; exit 13;
}
case "$written_at" in
  ''|*[!0-9]*) echo "consumer ready timestamp is invalid" >&2; exit 14 ;;
esac
now=$(date +%s)
[ "$written_at" -le $((now + 5)) ] && [ $((now - written_at)) -le 20 ] || {
  echo "consumer ready marker is stale" >&2; exit 15;
}
installed=$(tr -cd '0-9' < "$installed_file" 2>/dev/null || true)
[ "$installed" = "$generation" ] || {
  echo "consumer generation does not match the ready marker" >&2; exit 16;
}
[ -d "$runtime/generations/$generation" ] \
  && [ "$(readlink "$runtime/current" 2>/dev/null || true)" = "generations/$generation" ] || {
  echo "consumer current generation is not installed" >&2; exit 17;
}
[ -s "$tokens" ] \
  && grep -q '"version"[[:space:]]*:[[:space:]]*1' "$tokens" \
  && grep -q '"tokens"' "$tokens" || {
  echo "consumer tokens are not installed" >&2; exit 18;
}
curl -fsS --max-time 3 http://127.0.0.1:9598/metrics >/dev/null || {
  echo "Vector metrics are unavailable" >&2; exit 19;
}
curl -fsS --max-time 3 http://127.0.0.1:8686/health >/dev/null || {
  echo "Vector health is unavailable" >&2; exit 20;
}
printf 'consumer generation %s ready\n' "$generation"
'''
        result = self.compose(
            ["exec", "-T", "vector-config-consumer", "sh", "-ec", probe],
            timeout=20,
            check=False,
        )
        if result.returncode != 0:
            lines = [line.strip() for line in result.stderr.splitlines() if line.strip()]
            detail = lines[-1][:300] if lines else f"readiness probe exited {result.returncode}"
            raise UpgradeError(detail)
        return result.stdout.strip() or "consumer readiness confirmed"

    def _wait_ingest_consumer_ready(self, timeout: int) -> str:
        deadline = time.monotonic() + timeout
        last = "consumer readiness probe was not attempted"
        while True:
            try:
                return self._probe_ingest_consumer_readiness()
            except (UpgradeError, OSError, ValueError) as error:
                last = " ".join(str(error).split())[:300] or "consumer readiness probe failed"
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
        raise UpgradeError(
            "ingest consumer readiness gate did not confirm API-backed config and "
            f"token sync within {timeout}s after app/API recovery (last probe: {last})"
        )

    def _probe_ingest_edge_readiness(self) -> dict[str, Any]:
        # Probe the routed HEC health endpoint instead of relying on the
        # container health label. The previous-supported image predates the tap
        # relay /healthz route used by that label, but its HEC route is the real
        # data-plane dependency that must work before load-balancer rejoin.
        result = self.compose(
            ["exec", "-T", "ingest-edge", "sh", "-ec",
             'if command -v curl >/dev/null 2>&1; then '
             'curl -fsS --max-time 3 http://127.0.0.1/services/collector/health; '
             'elif command -v wget >/dev/null 2>&1; then '
             'wget -qO- -T 3 http://127.0.0.1/services/collector/health; '
             'else echo "ingest edge has no HTTP client" >&2; exit 127; fi'],
            timeout=20,
            check=False,
        )
        if result.returncode != 0:
            lines = [line.strip() for line in result.stderr.splitlines() if line.strip()]
            detail = lines[-1][:300] if lines else f"probe exited {result.returncode}"
            raise UpgradeError(f"ingest-edge routed HEC health probe failed: {detail}")
        health = json_object(json.loads(result.stdout), "ingest-edge routed HEC health response")
        if health.get("code") != 17 or health.get("text") != "HEC is healthy":
            raise UpgradeError("ingest-edge routed HEC health response is not healthy")
        return health

    def _wait_ingest_edge_ready(self, timeout: int) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last = "routed HEC health probe was not attempted"
        while time.monotonic() < deadline:
            try:
                return self._probe_ingest_edge_readiness()
            except (UpgradeError, OSError, ValueError, json.JSONDecodeError) as error:
                last = " ".join(str(error).split())[:300] or "routed HEC health probe failed"
            time.sleep(2)
        raise UpgradeError(
            f"ingest-edge route did not become ready within {timeout}s after consumer "
            f"config/token convergence; load-balancer rejoin was not attempted (last probe: {last})"
        )

    def _wait_ingest_readiness(self, services: Iterable[str], timeout: int) -> None:
        selected = list(dict.fromkeys(services))
        prerequisites = [
            service for service in selected
            if service not in {"vector-config-consumer", "ingest-edge"}
        ]
        self._wait_services(prerequisites, timeout)
        if "vector-config-consumer" in selected:
            self._wait_ingest_consumer_ready(timeout)
        if "ingest-edge" in selected:
            self._wait_services(("ingest-edge",), timeout)

    def _up_ingest_services(
        self, services: Iterable[str], timeout: int, *, exact: bool = False,
    ) -> list[str]:
        selected = list(dict.fromkeys(services)) if exact else [
            service for service in services if self._service_expected(service)
        ]
        before_edge = [service for service in selected if service != "ingest-edge"]
        if before_edge:
            self.compose(
                ["up", "-d", "--no-deps", "--pull", "never",
                 *self._recreate_args(before_edge), *before_edge],
                timeout=timeout,
            )
            self._wait_ingest_readiness(before_edge, timeout)
        if "ingest-edge" in selected:
            self.compose(
                ["up", "-d", "--no-deps", "--pull", "never",
                 *self._recreate_args(["ingest-edge"]), "ingest-edge"],
                timeout=timeout,
            )
            self._wait_ingest_edge_ready(timeout)
        return selected

    def quiesce(
        self, role: str, timeout: int, require_lb_hooks: bool = False,
        services: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        if services is None:
            selected = list(self.running_writers(role)["services"])
        else:
            selected = self._exact_role_services(role, services, writers_only=True)
        if role == "app":
            stopped = self._stop_exact(selected, timeout)
        elif role == "ingest":
            if "ingest-edge" in selected:
                self._lb_hook("drain", require_lb_hooks)
            if "vector" in selected:
                self._drain_vector(min(timeout, 300))
            stopped = self._stop_exact(selected, timeout)
        else:
            raise UpgradeError(f"cannot quiesce non-writer role {role}")
        return self._with_lb_hooks({"role": role, "services": stopped})

    def resume_writers(
        self, role: str, timeout: int, require_lb_hooks: bool = False,
        services: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        if services is None:
            raise UpgradeError("writer resume requires the exact journaled pre-fence service set")
        selected = self._exact_role_services(role, services, writers_only=True)
        if role == "app":
            started = self._start_exact(selected, timeout)
            dependency_probe = self._wait_app_readiness(started, timeout)
        elif role == "ingest":
            started = self._up_ingest_services(selected, timeout, exact=True)
            if "ingest-edge" in started:
                route_probe = self.smoke_ingest(f"nano-writer-resume-{uuid.uuid4()}")
                self._lb_hook("rejoin", require_lb_hooks)
        else:
            raise UpgradeError(f"cannot resume non-writer role {role}")
        result: dict[str, Any] = {"role": role, "services": started}
        if role == "app":
            result["dependency_probe"] = dependency_probe
        elif "ingest-edge" in started:
            result["route_probe"] = route_probe
        return self._with_lb_hooks(result)

    def migration_lock(self) -> Any:
        return PgMigrationLock(self, "migration")

    def upgrade_lock(self) -> Any:
        return PgMigrationLock(self, "upgrade")

    def backup_mutation_lock(self, timeout: int = 600) -> Any:
        return PgMigrationLock(self, "backup-mutation", acquire_timeout=timeout)

    def _rollout_legacy_bridge(self, role: str, timeout: int) -> dict[str, Any]:
        record = read_json(self.bridge_record)
        if (
            record.get("format") != "nano-legacy-bridge-v1"
            or record.get("state") not in {"image-tag-published", "complete"}
        ):
            raise UpgradeError("legacy bridge rollout has no durable prepared intent")
        if role in {"keeper", "clickhouse", "postgres", "ingest"}:
            preserved = {
                "keeper": (),
                "clickhouse": ("clickhouse",),
                "postgres": ("postgres",),
                "ingest": ("vector",),
            }[role]
            services = [service for service in preserved if self._service_exists(service)]
            self._wait_services(services, timeout)
            return {"services": services, "legacy_bridge_preserved": True}
        if role == "migration":
            migration = self.compose(
                ["run", "--rm", "--no-deps", "--pull", "never", "clickhouse-migrate"],
                timeout=timeout,
                check=False,
            )
            if migration.returncode != 0:
                raise UpgradeError(
                    f"ClickHouse migration failed: {self._safe_service_failure(migration)}"
                )
            return {"services": ["clickhouse-migrate"]}
        if role != "app":
            raise UpgradeError(f"unsupported legacy bridge rollout role: {role}")
        applications = list(nano_legacy_bridge.APP_SERVICES)
        self.compose(
            [
                "up", "-d", "--no-deps", "--pull", "never", "--force-recreate",
                *applications,
            ],
            timeout=timeout,
        )
        self._wait_services(applications, timeout)
        services = list(applications)
        if self._service_exists("nginx"):
            # Compose's legacy nginx resolves application container addresses
            # at startup. Recreate it only after all four signed apps are up.
            self.compose(
                [
                    "up", "-d", "--no-deps", "--pull", "never",
                    "--force-recreate", "nginx",
                ],
                timeout=timeout,
            )
            # A healthy nginx process can briefly reset a request while its
            # newly resolved upstream becomes ready.  Use the existing
            # deadline-bounded dependency readiness gate so a transient reset
            # retries, while a persistently broken route still fails rollout.
            self._wait_app_readiness(["nginx"], timeout)
            services.append("nginx")
        return {"services": services, "legacy_bridge_recreated": applications}

    def _post_verify_legacy_bridge(self, target: str, timeout: int) -> dict[str, Any]:
        record = read_json(self.bridge_record)
        if (
            record.get("format") != "nano-legacy-bridge-v1"
            or record.get("state") not in {"image-tag-published", "complete"}
            or record.get("target_version") != target
        ):
            raise UpgradeError("legacy bridge post-verification intent is invalid")
        values = self.env_file.values()
        if values.get("IMAGE_TAG") != target:
            raise UpgradeError("legacy bridge target IMAGE_TAG is not published")
        if values.get("NANO_VERSION") or values.get("NANO_EDITION"):
            raise UpgradeError("legacy bridge unexpectedly canonicalized the environment")
        if self._legacy_bridge_environment_digest() != record.get(
            "environment_without_image_tag_sha256"
        ):
            raise UpgradeError("legacy bridge changed environment fields other than IMAGE_TAG")
        if self._legacy_bridge_control_hashes() != record.get("control_sha256"):
            raise UpgradeError("legacy bridge changed the legacy Compose control files")
        images = self._bridge_images_from_record(record)
        source_model = self._render_legacy_image_tag(nano_legacy_bridge.SOURCE_VERSION)
        target_model = self._render_legacy_image_tag(nano_legacy_bridge.TARGET_VERSION)
        try:
            nano_legacy_bridge.validate_rendered_transition(
                source_model, target_model, images,
            )
        except nano_legacy_bridge.LegacyBridgeError as error:
            raise UpgradeError(str(error)) from error
        self._verify_loaded_bridge_images(images)
        for service in nano_legacy_bridge.APP_SERVICES:
            container = self._service_container(service)
            running = self.runner.run(
                ["docker", "inspect", "--format", "{{.Image}}", container],
                timeout=30,
            ).stdout.strip()
            if running not in {
                images[service].platform_digest, images[service].digest,
            }:
                raise UpgradeError(
                    f"legacy bridge service {service} is not running its signed platform image"
                )
        expected = [
            service for service in (
                "postgres", "clickhouse", "dragonfly", "vector",
                *nano_legacy_bridge.APP_SERVICES, "nginx",
            )
            if self._service_exists(service)
        ]
        health = self._wait_app_readiness(expected, timeout)
        record["state"] = "complete"
        write_json_atomic(self.bridge_record, record)
        self.version = target
        return {
            "release": target,
            "service_version": str(health.get("version", "unavailable")),
            "first_party_images": [images[name].ref for name in nano_legacy_bridge.APP_SERVICES],
            "legacy_bridge": True,
        }

    # ---- NAN-5214: PostgreSQL / Valkey HA member operations -------------

    def _patroni_members(self) -> list[dict[str, Any]]:
        result = self.compose(
            ["exec", "-T", "postgres-ha", "patronictl", "-c", "/run/patroni/patroni.yml", "list", "-f", "json"],
            timeout=60,
        )
        try:
            members = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as error:
            raise UpgradeError("patronictl returned invalid JSON") from error
        if not isinstance(members, list):
            raise UpgradeError("patronictl returned an invalid member list")
        return [member for member in members if isinstance(member, dict)]

    def pg_ha_status(self) -> dict[str, Any]:
        """This host's Patroni member, the leader, and replica health."""
        if not self.pg_ha:
            return {"ha": False, "leader": "postgres" in self.roles}
        member = self.role_env.get("NANO_HOST_ID", "")
        members = self._patroni_members()
        leader = next((m.get("Member") for m in members if m.get("Role") == "Leader"), None)
        return {
            "ha": True,
            "member": member,
            "leader": leader == member,
            "leader_member": leader,
            "members": [
                {
                    "member": str(m.get("Member", "")), "role": str(m.get("Role", "")),
                    "state": str(m.get("State", "")), "lag": m.get("Replay Lag"),
                }
                for m in members
            ],
        }

    def _wait_patroni_member(self, timeout: int) -> None:
        """Wait until this member is the running leader or a streaming replica
        with no replay lag, and the cluster has exactly one leader."""
        member = self.role_env.get("NANO_HOST_ID", "")
        deadline = time.monotonic() + timeout
        last = "unknown"
        while time.monotonic() < deadline:
            with contextlib.suppress(UpgradeError):
                members = self._patroni_members()
                leaders = [m for m in members if m.get("Role") == "Leader"]
                mine = next((m for m in members if m.get("Member") == member), None)
                if mine is not None:
                    last = f"{mine.get('Role')}/{mine.get('State')} lag={mine.get('Replay Lag')}"
                if len(leaders) == 1 and mine is not None:
                    lag = mine.get("Replay Lag", 0)
                    if mine.get("Role") == "Leader" and mine.get("State") == "running":
                        return
                    if mine.get("State") == "streaming" and lag in (0, "0", None):
                        return
            time.sleep(2)
        raise UpgradeError(f"Patroni member {member} did not rejoin within {timeout}s ({last})")

    def _valkey_cli(self, service: str, args: list[str], timeout: int = 30) -> str:
        return self.compose(
            ["exec", "-T", service, "valkey-cli", "--tls", "--insecure",
             "--cert", "/etc/nano/tls/server.crt", "--key", "/etc/nano/tls/server.key",
             "--raw", *args],
            timeout=timeout,
        ).stdout.strip()

    def _move_valkey_master_away(self, timeout: int) -> None:
        """Before restarting this host's Valkey master, have Sentinel promote
        a replica, so the restart costs one failover instead of an outage."""
        if not self._service_exists("valkey-ha"):
            return
        info = self._valkey_cli("valkey-ha", ["-p", "6379", "info", "replication"], timeout=30)
        if "role:master" not in info:
            return
        announce = self.role_env.get("NANO_VALKEY_HA_ANNOUNCE", "")
        sentinels = [item for item in self.role_env.get("NANO_VALKEY_SENTINELS", "").split(",") if item]
        name = self.role_env.get("NANO_VALKEY_MASTER_NAME", "nano")
        for target in sentinels:
            host, _, port = target.rpartition("@")
            reply = self._valkey_cli(
                "valkey-ha", ["-h", host, "-p", port, "SENTINEL", "failover", name], timeout=30,
            ) if host else ""
            if reply.startswith("OK"):
                break
        deadline = time.monotonic() + min(timeout, 120)
        while time.monotonic() < deadline:
            for target in sentinels:
                host, _, port = target.rpartition("@")
                with contextlib.suppress(UpgradeError):
                    addr = self._valkey_cli(
                        "valkey-ha", ["-h", host, "-p", port, "SENTINEL", "get-master-addr-by-name", name],
                        timeout=15,
                    ).splitlines()
                    if len(addr) == 2 and f"{addr[0]}:{addr[1]}" != announce:
                        return
            time.sleep(2)
        raise UpgradeError("Sentinel did not move the Valkey master off this host")

    def _rollout_postgres_ha_member(self, selected: list[str], timeout: int) -> list[str]:
        """Recreate this host's stateful HA members one at a time.

        The orchestrator calls this for replicas first and switches leadership
        away from a host before rolling it, so PostgreSQL stays writable.
        """
        status = self.pg_ha_status()
        if status["leader"] and len(status["members"]) > 1:
            raise UpgradeError(
                "refusing to recreate the Patroni leader; switch leadership to an upgraded replica first"
            )
        if "postgres-ha" in selected:
            # Before touching anything: a target image of another PostgreSQL
            # major would leave the member refusing to start.
            self.postgres_major_check()
        services: list[str] = []
        if any(name in selected for name in ("etcd", "valkey-sentinel", "valkey-ha")):
            # NAN-5243: move the Valkey master off this host BEFORE touching
            # any of its HA services. Recreating etcd/Sentinel first can leave
            # this host's master unreachable to its peers (but not to the app
            # routers): Sentinel then promotes elsewhere while it keeps taking
            # writes that the resync later discards.
            self._move_valkey_master_away(timeout)
        if "etcd" in selected:
            services += self._up_existing(["etcd"], timeout, exact=True)
            self._wait_container("etcd", timeout)
        if "valkey-sentinel" in selected:
            services += self._up_existing(["valkey-sentinel"], timeout, exact=True)
            self._wait_container("valkey-sentinel", timeout)
        if "valkey-ha" in selected:
            services += self._up_existing(["valkey-ha"], timeout, exact=True)
            self._wait_container("valkey-ha", timeout)
        if "postgres-ha" in selected:
            services += self._up_existing(["postgres-ha"], timeout, exact=True)
            self._wait_container("postgres-ha", timeout)
            self._wait_patroni_member(timeout)
            self._record_pg_ha_system_id()
        return services

    def _record_pg_ha_system_id(self) -> None:
        """Record the cluster's system identifier in the shared .env when
        absent; refuse when .env names a different cluster (NAN-5214)."""
        helper = _load_pg_ha_system_id()
        controldata = self.compose(
            ["exec", "-T", "postgres-ha", "pg_controldata", "-D", "/var/lib/postgresql/data"],
            timeout=60, check=False,
        ).stdout
        observed = helper.parse_system_id(controldata)
        if observed is None:
            return
        existing = self.env_file.values().get(helper.KEY) or None
        try:
            action = helper.decide(existing, observed)
        except helper.SystemIdConflict as error:
            raise UpgradeError(f"PostgreSQL HA identity mismatch: {error}") from error
        if action == "record":
            self.env_file.replace(helper.KEY, observed)
            eprint(
                f"Recorded {helper.KEY}={observed} in .env on {self.host_name}: "
                "copy the updated .env to every host."
            )

    def pg_switchover(self, candidate: str, timeout: int) -> dict[str, Any]:
        """Planned leader change to `candidate` (a streaming, upgraded member)."""
        safe_name(candidate, "switchover candidate")
        status = self.pg_ha_status()
        if not status.get("ha"):
            raise UpgradeError("switchover needs PostgreSQL HA")
        leader = status.get("leader_member")
        if leader == candidate:
            return {"leader": candidate, "switched": False}
        self.compose(
            ["exec", "-T", "postgres-ha", "patronictl", "-c", "/run/patroni/patroni.yml",
             "switchover", "--leader", str(leader), "--candidate", candidate, "--force"],
            timeout=min(timeout, 300),
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with contextlib.suppress(UpgradeError):
                members = self._patroni_members()
                roles = {m.get("Member"): (m.get("Role"), m.get("State")) for m in members}
                if roles.get(candidate) == ("Leader", "running") and sum(
                    1 for role, _ in roles.values() if role == "Leader"
                ) == 1:
                    return {"leader": candidate, "switched": True, "previous": leader}
            time.sleep(2)
        raise UpgradeError(f"switchover to {candidate} did not complete within {timeout}s")

    def postgres_major_check(self) -> str:
        """Refuse a PostgreSQL major-version change on an HA member.

        The data directory's PG_VERSION must match the target image's
        PG_MAJOR; a major upgrade is a documented offline procedure.
        """
        if not self.pg_ha or not self._service_exists("postgres-ha"):
            return "not an HA PostgreSQL member"
        data_major = self.compose(
            ["exec", "-T", "postgres-ha", "cat", "/var/lib/postgresql/data/PG_VERSION"], timeout=30,
        ).stdout.strip()
        image = self.compose(["config", "--images", "postgres-ha"], timeout=60).stdout.strip().splitlines()
        target_major = ""
        if image:
            inspected = self.runner.run(
                ["docker", "image", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", image[0]],
                timeout=30, check=False,
            )
            for line in inspected.stdout.splitlines():
                if line.startswith("PG_MAJOR="):
                    target_major = line.split("=", 1)[1].strip()
        if target_major and data_major and target_major != data_major:
            raise UpgradeError(
                f"PostgreSQL {data_major} -> {target_major} is a major-version upgrade; "
                "nano-upgrade refuses it on an HA cluster (see the self-run HA guide)"
            )
        return f"PostgreSQL major {data_major or '?'} unchanged"

    def rollout(self, role: str, timeout: int, require_lb_hooks: bool = False) -> dict[str, Any]:
        if getattr(self, "_legacy_bridge_rollout", False):
            return self._rollout_legacy_bridge(role, timeout)
        try:
            candidates = ROLE_SERVICES[role]
        except KeyError as error:
            raise UpgradeError(f"unsupported rollout role: {role}") from error
        legacy_transition_rollout = getattr(self, "_legacy_transition_rollout", False)
        if legacy_transition_rollout:
            # Legacy application services use different names (api -> nano-api,
            # and so on), and are deliberately retired before dependency-
            # ordered rollout. Select every service rendered by the canonical
            # target for this one transition instead of mistaking the absent
            # target containers for an operator-disabled service.
            selected = [service for service in candidates if self._service_expected(service)]
        else:
            selected = self._running_services(candidates)
        selected = self._exact_role_services(role, selected)
        if role == "keeper":
            services = self._up_existing(selected, timeout, exact=True)
            if services:
                self._wait_services(services, timeout)
                time.sleep(2)
                self._check_keeper()
        elif role == "clickhouse":
            services = selected
            if "clickhouse" in services:
                self.compose(
                    ["up", "-d", "--pull", "never", *self._recreate_args(["clickhouse"]), "clickhouse"],
                    timeout=timeout,
                )
                self._wait_container("clickhouse", timeout)
                self._check_clickhouse()
        elif role == "postgres" and self.pg_ha:
            services = self._rollout_postgres_ha_member(selected, timeout)
        elif role == "postgres":
            services = self._up_existing(selected, timeout, exact=True)
            if services:
                self._wait_container("postgres", timeout)
                self._check_postgres()
        elif role == "migration":
            proxies = self._up_existing(selected, timeout, exact=True)
            self._wait_services(proxies, timeout)
            migration = self.compose(
                ["run", "--rm", "--no-deps", "--pull", "never", "clickhouse-migrate"],
                timeout=timeout,
                check=False,
            )
            if migration.returncode != 0:
                raise UpgradeError(
                    f"ClickHouse migration failed: {self._safe_service_failure(migration)}"
                )
            services = [*proxies, "clickhouse-migrate"]
        elif role == "ingest":
            if "ingest-edge" in selected:
                self._lb_hook("drain", require_lb_hooks)
            try:
                if "vector" in selected:
                    if legacy_transition_rollout:
                        self._quiesce_legacy_vector_for_transition(min(timeout, 300))
                        self._retire_legacy_managed_vector_config()
                        # The legacy topology has no stable Vector namespace
                        # anchor. Canonical Vector and its tap both use
                        # network_mode: service:vector-netns, while the normal
                        # ingest rollout deliberately uses --no-deps. Create
                        # and gate that new dependency after the old Vector is
                        # drained, before either canonical process can start.
                        if self._service_exists("vector-netns"):
                            self.compose([
                                "up", "-d", "--no-deps", "--pull", "never",
                                "vector-netns",
                            ], timeout=timeout)
                            self._wait_container("vector-netns", timeout)
                    else:
                        self._drain_vector(min(timeout, 300))
                        # NAN-5250: the namespace anchor publishes Vector's
                        # ports (the monitoring host scrapes :9598 through it).
                        # Recreated only when its definition changed; Vector
                        # is drained and recreated right after.
                        if self._monitoring_enabled() and self._service_expected("vector-netns"):
                            self.compose([
                                "up", "-d", "--no-deps", "--pull", "never",
                                *self._recreate_args(["vector-netns"]), "vector-netns",
                            ], timeout=timeout)
                            self._wait_container("vector-netns", timeout)
                services = self._up_ingest_services(selected, timeout, exact=True)
                if "ingest-edge" in services:
                    route_probe = self.smoke_ingest(f"nano-rollout-{uuid.uuid4()}")
                if "ingest-edge" in services:
                    self._lb_hook("rejoin", require_lb_hooks)
            except UpgradeError as error:
                if "ingest-edge" in selected:
                    raise self._left_drained(error) from error
                raise
        elif role == "monitoring":
            # NAN-5250: Prometheus and Grafana carry no nano state; recreate
            # whatever this host runs and wait for it to be up.
            services = self._up_existing(selected, timeout, exact=True)
            if services:
                self._wait_services(services, timeout)
        elif role == "app":
            drained = False
            try:
                drained = self._drain_app_host(selected)
                services = self._up_app_services(selected, timeout, exact=True)
                if any(service in APP_EDGE_SERVICES for service in services):
                    dependency_probe = self._wait_app_readiness(services, timeout)
                else:
                    self._wait_services(services, timeout)
                if drained:
                    self._rejoin_app_host()
            except UpgradeError as error:
                if drained or "nginx" in selected and int(
                    (getattr(self, "role_env", None) or {}).get("NANO_APP_HOST_COUNT", "1") or "1"
                ) >= 2:
                    raise self._left_drained(error) from error
                raise
        # NAN-5250: node-exporter (with a monitoring host) runs on every host
        # beside whatever role this is; bring it to the target definition too.
        if role != "migration" and self._monitoring_enabled() and self._service_expected("node-exporter"):
            self.compose(
                ["up", "-d", "--no-deps", "--pull", "never",
                 *self._recreate_args(["node-exporter"]), "node-exporter"],
                timeout=timeout,
            )
            services = [*services, "node-exporter"]
        result = {"services": services}
        if role == "app" and any(service in APP_EDGE_SERVICES for service in services):
            result["dependency_probe"] = dependency_probe
        elif role == "ingest" and "ingest-edge" in services:
            result["route_probe"] = route_probe
        return self._with_lb_hooks(result)

    def post_verify(self, target: str, timeout: int) -> dict[str, Any]:
        if getattr(self, "_legacy_bridge_rollout", False):
            return self._post_verify_legacy_bridge(target, timeout)
        prefix = self.env.get("NANO_IMAGE_PREFIX", "ghcr.io/nano-rs/nano")
        images = self.compose(["config", "--images"], timeout=60).stdout.split()
        first_party = [image for image in images if image.startswith(f"{prefix}-")]
        wrong = [image for image in first_party if not image.endswith(f":{target}")]
        if wrong or ("app" in self.roles and not first_party):
            raise UpgradeError("rendered first-party image references do not all use the target release")
        expected: list[str] = []
        if "app" in self.roles:
            expected.extend(service for service in APP_SERVICES if self._service_expected(service))
        if "ingest" in self.roles:
            expected.extend(service for service in INGEST_SERVICES if self._service_expected(service))
        if "postgres" in self.roles and self._service_exists(self.pg_service):
            expected.append(self.pg_service)
        if "clickhouse" in self.roles and self._service_exists("clickhouse"):
            expected.append("clickhouse")
        if "keeper" in self.roles and self._service_exists("keeper"):
            expected.append("keeper")
        self._wait_services(expected, timeout)
        service_version = "unavailable"
        if "app" in self.roles:
            health = self._probe_app_route()
            service_version = str(health.get("version", "unavailable"))
        return {"release": target, "service_version": service_version, "first_party_images": first_party}

    def _probe_app_route(self) -> dict[str, Any]:
        internal_scheme = "https" if self.role_env.get("NANO_PRIVATE_TLS") == "true" else "http"
        legacy_bridge = getattr(self, "_legacy_bridge_rollout", False)
        nginx_url = (
            "https://127.0.0.1:443/api/users/me"
            if legacy_bridge
            else "http://127.0.0.1:80/api/health"
        )
        routes = [
            ("nginx", nginx_url),
            ("app-internal-edge", f"{internal_scheme}://127.0.0.1:3000/health"),
        ]
        routes = [(service, url) for service, url in routes if self._service_exists(service)]
        if not routes:
            raise UpgradeError("app role has no routable application edge")
        results: dict[str, dict[str, Any]] = {}
        for service, url in routes:
            if legacy_bridge and service == "nginx":
                # The preserved legacy nginx has no routed health endpoint.
                # Its authenticated /api/users/me route deterministically
                # returns 401 without a session, proving nginx -> API routing
                # without putting credentials into a process argument.
                probe = (
                    'response="$(wget -S -O /dev/null --no-check-certificate "$1" 2>&1 || true)"; '
                    'if ! printf "%s\\n" "$response" | grep -Eq '
                    "'HTTP/[0-9.]+ 401 Unauthorized'; then "
                    'printf "%s\\n" "$response" >&2; exit 1; fi; '
                    "printf '%s\\n' '{\"status\":\"healthy\",\"route_status\":401}'"
                )
            else:
                probe = (
                    'case "$1" in https://*) insecure=true ;; *) insecure=false ;; esac; '
                    'if command -v wget >/dev/null 2>&1; then '
                    '  if [ "$insecure" = true ]; then wget -qO- --no-check-certificate "$1"; '
                    '  else wget -qO- "$1"; fi; '
                    'elif command -v curl >/dev/null 2>&1; then '
                    '  if [ "$insecure" = true ]; then curl -kfsS "$1"; '
                    '  else curl -fsS "$1"; fi; '
                    'else echo "app edge has no HTTP client" >&2; exit 127; fi'
                )
            result = self.compose(
                ["exec", "-T", service, "sh", "-ec", probe, "nano-upgrade", url],
                timeout=30, check=False,
            )
            if result.returncode != 0:
                lines = [line.strip() for line in result.stderr.splitlines() if line.strip()]
                detail = lines[-1][:300] if lines else f"probe exited {result.returncode}"
                raise UpgradeError(f"{service} routed API probe failed: {detail}")
            health = json_object(
                json.loads(result.stdout), f"{service} routed API health response",
            )
            if health.get("status") not in {"ok", "healthy"}:
                raise UpgradeError(f"{service} routed API health response is not healthy")
            results[service] = health
        primary = results.get("nginx") or results["app-internal-edge"]
        return {**primary, "routes": results}

    def smoke_ingest(self, marker: str) -> dict[str, Any]:
        if "ingest" not in self.roles or not self._service_exists("vector"):
            raise UpgradeError("smoke ingest must run on an ingest host")
        token = self.env.get("NANO_PLATFORM_INGEST_TOKEN", "")
        if not token and self.env.get("NANO_INGEST_STATIC_FALLBACK") == "true":
            token = self.env.get("VECTOR_AUTH_TOKEN", "")
        if not token and getattr(self, "_legacy_bridge_rollout", False):
            # The preserved 0.1.703 layout predates the v2 platform-token
            # fields; its authenticated ingest contract is VECTOR_AUTH_TOKEN.
            token = self.env.get("VECTOR_AUTH_TOKEN", "")
        if not token:
            raise UpgradeError(
                "smoke ingest requires NANO_PLATFORM_INGEST_TOKEN, or VECTOR_AUTH_TOKEN "
                "on an explicitly static-fallback deployment"
            )
        edge_service = "ingest-edge" if self._service_exists("ingest-edge") else "nginx"
        if not self._service_exists(edge_service):
            raise UpgradeError("ingest role has no routable ingest edge")
        payload = json.dumps({"source_type": "nano_upgrade_smoke", "message": marker, "timestamp": utc_now()})
        script = r'''
IFS= read -r nano_smoke_token
[ -n "$nano_smoke_token" ] || { echo "smoke ingest credential is empty" >&2; exit 1; }
umask 077
auth_file=$(mktemp)
trap 'rm -f "$auth_file"' EXIT HUP INT TERM
printf 'Authorization: Bearer %s\n' "$nano_smoke_token" >"$auth_file"
if command -v curl >/dev/null 2>&1; then
  case "$2" in
    https://*)
      env -u NANO_PLATFORM_INGEST_TOKEN -u VECTOR_AUTH_TOKEN curl -kfsS \
        -H @"$auth_file" -H "Content-Type: application/json" --data "$1" "$2" >/dev/null
      ;;
    *)
      env -u NANO_PLATFORM_INGEST_TOKEN -u VECTOR_AUTH_TOKEN curl -fsS \
        -H @"$auth_file" -H "Content-Type: application/json" --data "$1" "$2" >/dev/null
      ;;
  esac
elif command -v nc >/dev/null 2>&1; then
  case "$2" in https://*) echo "ingest edge has no TLS HTTP client" >&2; exit 127 ;; esac
  response=$(
    printf "POST /ingest HTTP/1.0\r\nHost: 127.0.0.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s" \
      "$nano_smoke_token" "${#1}" "$1" | \
      env -u NANO_PLATFORM_INGEST_TOKEN -u VECTOR_AUTH_TOKEN nc 127.0.0.1 80
  )
  status=$(printf '%s\n' "$response" | sed -n '1p')
  case "$status" in *" 2"??*) ;; *) echo "ingest edge smoke returned: $status" >&2; exit 1 ;; esac
elif command -v bash >/dev/null 2>&1; then
  case "$2" in https://*) echo "ingest edge has no TLS HTTP client" >&2; exit 127 ;; esac
  printf '%s\n%s\n' "$nano_smoke_token" "$1" | \
    env -u NANO_PLATFORM_INGEST_TOKEN -u VECTOR_AUTH_TOKEN bash -ec '
IFS= read -r token
IFS= read -r payload
exec 3<>/dev/tcp/127.0.0.1/80
printf "POST /ingest HTTP/1.0\r\nHost: 127.0.0.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s" \
  "$token" "${#payload}" "$payload" >&3
IFS= read -r status <&3
case "$status" in *" 2"??*) exit 0 ;; *) echo "ingest edge smoke returned: $status" >&2; exit 1 ;; esac
'
else
  echo "no HTTP client is available for the ingest edge smoke" >&2
  exit 127
fi
'''
        ingest_url = (
            "https://127.0.0.1:443/ingest/"
            if getattr(self, "_legacy_bridge_rollout", False)
            else "http://127.0.0.1:80/ingest"
        )
        self.compose(
            ["exec", "-T", edge_service, "sh", "-ec", script, "nano-upgrade", payload,
             ingest_url],
            timeout=30, input_text=token + "\n",
        )
        return {"marker": marker, "accepted": True}

    def smoke_search(self, marker: str, timeout: int) -> dict[str, Any]:
        if "clickhouse" not in self.roles:
            raise UpgradeError("smoke search must run on a ClickHouse host")
        profile = self.env.get("NANO_SCHEMA_PROFILE", "udm")
        table = "ocsf_logs" if profile == "ocsf" else "logs"
        cluster = self.role_env.get("CLICKHOUSE_CLUSTER", self.env.get("CLICKHOUSE_CLUSTER", ""))
        source = f"nanosiem.{table}"
        if cluster:
            safe_name(cluster, "ClickHouse cluster")
            source = f"clusterAllReplicas('{cluster}', nanosiem.{table})"
        deadline = time.monotonic() + min(timeout, 120)
        while time.monotonic() < deadline:
            count = self._ch_query(
                f"SELECT count() FROM {source} WHERE timestamp > now()-INTERVAL 10 MINUTE "
                f"AND position(message,'{marker}') > 0"
            )
            if count not in {"", "0"}:
                return {"marker": marker, "rows": int(count)}
            time.sleep(2)
        raise UpgradeError("smoke marker did not become searchable after ingest")

    def siem_health(self) -> dict[str, Any]:
        if "postgres" not in self.roles:
            raise UpgradeError("SIEM Health verification must run on the PostgreSQL host")
        present = self._pg_query(
            "SELECT CASE WHEN to_regclass('siem_health_reports') IS NULL "
            "THEN 'false' ELSE 'true' END"
        )
        if present != "true":
            return {"status": "not-present", "findings": []}
        encoded = self._pg_query(
            "SELECT COALESCE((SELECT json_build_object("
            "'id',id::text,'status',overall_status,'score',overall_score,"
            "'created_at',created_at,'findings',recommendations)::text "
            "FROM siem_health_reports ORDER BY created_at DESC LIMIT 1),"
            "'{\"status\":\"no-report-yet\",\"findings\":[]}')"
        )
        try:
            snapshot = json_object(json.loads(encoded), "latest SIEM Health report")
        except json.JSONDecodeError as error:
            raise UpgradeError("latest SIEM Health report is invalid JSON") from error
        # Validate before the snapshot is admitted to the append-only journal.
        siem_health_finding_signatures(snapshot)
        return snapshot

    def audit(self, run_id: str, action: str, success: bool, details: dict[str, Any]) -> None:
        journal = Journal(self.install_dir)
        journal.ensure_directory()
        audit_path = journal.directory / "audit.jsonl"
        record = {
            "at": utc_now(), "action": action, "run_id": run_id, "success": success,
            "details": details,
        }
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"))
        secure_append_line(audit_path, encoded, "upgrade audit log")

    def rollback_preflight(self, previous: str, target: str) -> list[Check]:
        checks: list[Check] = []
        current = canonical_version(self.env_file.values().get("NANO_VERSION", ""))
        checks.append(Check(
            "rollback-version", current in {previous, target},
            f"current {current}; expected {target} or idempotent {previous}", self.host_name,
        ))
        render_env = os.environ.copy()
        render_env["NANO_VERSION"] = previous
        try:
            images = self.compose(["config", "--images"], timeout=60, env=render_env).stdout.split()
            missing: list[str] = []
            for image in images:
                result = self.runner.run(
                    ["docker", "image", "inspect", image], timeout=30, check=False,
                )
                if result.returncode != 0:
                    missing.append(image)
            checks.append(Check(
                "rollback-images", not missing,
                "all previous-version images are locally available"
                if not missing else f"missing previous images: {', '.join(sorted(set(missing)))}",
                self.host_name,
            ))
        except UpgradeError as error:
            checks.append(Check("rollback-images", False, str(error), self.host_name))
        return checks

    def rollback_role(
        self, role: str, previous: str, target: str, timeout: int,
        require_lb_hooks: bool = False, run_id: str = "",
    ) -> dict[str, Any]:
        current = canonical_version(self.env_file.values().get("NANO_VERSION", ""))
        if current not in {target, previous}:
            raise UpgradeError(
                f"cannot resume rollback on {self.host_name}: installed {current}, expected {target} or {previous}"
            )
        if current != previous:
            self.env_file.replace("NANO_VERSION", previous)
        self.env["NANO_VERSION"] = previous
        self.version = previous
        # NAN-5279: the previous release's rendered configuration goes back
        # with its images (once per host; later roles find it restored).
        restored = bool(run_id) and self.restore_previous_render(run_id)
        result = self.rollout(role, timeout, require_lb_hooks)
        return {"version": previous, "role": role, "restored_config": restored, **result}


class PgMigrationLock:
    """A live PostgreSQL advisory lock released with this psql process."""

    LOCK_IDS = {
        "upgrade": 5_000_001,
        "migration": 5_000_002,
        "backup-mutation": 5_000_003,
    }

    def __init__(
        self, ops: LocalOps, kind: str, *, acquire_timeout: float = 30,
    ):
        if kind not in self.LOCK_IDS:
            raise UpgradeError("invalid PostgreSQL advisory lock kind")
        self.ops = ops
        self.kind = kind
        self.acquire_timeout = acquire_timeout
        self.process: subprocess.Popen[str] | None = None

    def __enter__(self) -> "PgMigrationLock":
        user = self.ops.env.get("POSTGRES_USER", "nanosiem")
        database = self.ops.env.get("POSTGRES_DB", "nanosiem")
        argv = [
            *self.ops.compose_args, "exec", "-T", getattr(self.ops, "pg_service", "postgres"), "psql", "-X", "-qAt",
            "-v", "ON_ERROR_STOP=1", "-U", user, "-d", database,
        ]
        try:
            self.process = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
        except OSError as error:
            raise UpgradeError("cannot start PostgreSQL migration lock session") from error
        assert self.process.stdin is not None and self.process.stdout is not None
        marker_kind = self.kind.replace("-", "_").upper()
        locked = f"__NANO_{marker_kind}_LOCKED__"
        busy = f"__NANO_{marker_kind}_BUSY__"
        if self.kind == "backup-mutation":
            # The cluster flag has already rejected new unsafe requests. Wait
            # here until every shared API transaction lock drains.
            statement = (
                f"SELECT pg_advisory_lock({self.LOCK_IDS[self.kind]}), "
                f"'{locked}';\n"
            )
        else:
            statement = (
                f"SELECT CASE WHEN pg_try_advisory_lock({self.LOCK_IDS[self.kind]}) "
                f"THEN '{locked}' ELSE '{busy}' END;\n"
            )
        self.process.stdin.write(statement)
        self.process.stdin.flush()
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + self.acquire_timeout
        while self.process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                break
            line = self.process.stdout.readline()
            if locked in line:
                selector.close()
                return self
            if busy in line:
                break
        selector.close()
        self.__exit__(None, None, None)
        raise UpgradeError(f"could not acquire the live PostgreSQL {self.kind} lock")

    def __exit__(self, *_: Any) -> None:
        if self.process is None:
            return
        process = self.process
        self.process = None
        if process.stdin and not process.stdin.closed:
            with contextlib.suppress(OSError, ValueError):
                process.stdin.write("SELECT pg_advisory_unlock_all();\\q\n")
                process.stdin.flush()
                process.stdin.close()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
        if process.poll() is None:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
        if process.poll() is None:
            process.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                with contextlib.suppress(OSError, ValueError):
                    stream.close()


def load_inventory(path: pathlib.Path) -> tuple[list[Node], dict[str, Any]]:
    renderer = DEFAULT_INSTALL_DIR / "deploy/compose/render-inventory.py"
    if not renderer.is_file():
        raise UpgradeError("inventory parser is missing from this install")
    spec = importlib.util.spec_from_file_location("nano_inventory", renderer)
    if spec is None or spec.loader is None:
        raise UpgradeError("cannot load the inventory parser")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        raw = json_object(module._parse_yaml_subset(path.read_text(encoding="utf-8")), "inventory")
    except (OSError, ValueError) as error:
        raise UpgradeError(f"inventory validation failed: {error}") from error
    if raw.get("version") != 1:
        raise UpgradeError("inventory version must be 1")
    cluster = json_object(raw.get("cluster"), "inventory.cluster")
    cluster_user = cluster.get("ssh_user")
    if cluster_user is not None:
        safe_name(cluster_user, "cluster ssh_user")
    raw_hosts = raw.get("hosts")
    if not isinstance(raw_hosts, list) or not raw_hosts:
        raise UpgradeError("inventory hosts must be a non-empty array")
    nodes: list[Node] = []
    names: set[str] = set()
    host_ids: set[str] = set()
    for raw_host in raw_hosts:
        host = json_object(raw_host, "inventory host")
        name = safe_name(host.get("name"), "inventory host name")
        if name in names:
            raise UpgradeError(f"duplicate inventory host {name}")
        names.add(name)
        host_id = safe_name(host.get("id"), f"host {name} id")
        if host_id in host_ids:
            raise UpgradeError(f"duplicate inventory host id {host_id}")
        host_ids.add(host_id)
        address = host.get("address")
        if not isinstance(address, str) or not SAFE_HOST_RE.fullmatch(address):
            raise UpgradeError(f"host {name} has an invalid address")
        roles_raw = host.get("roles")
        if not isinstance(roles_raw, list) or not roles_raw or not all(isinstance(role, str) for role in roles_raw):
            raise UpgradeError(f"host {name} roles are invalid")
        roles = frozenset(roles_raw)
        if roles - ROLES:
            raise UpgradeError(f"host {name} has unknown roles: {', '.join(sorted(roles - ROLES))}")
        ch = host.get("clickhouse") or {}
        keeper = host.get("keeper") or {}
        ssh_user = host.get("ssh_user", cluster_user)
        if ssh_user is not None:
            safe_name(ssh_user, f"host {name} ssh_user")
        ssh_port = host.get("ssh_port", cluster.get("ssh_port", 22))
        if not isinstance(ssh_port, int) or isinstance(ssh_port, bool) or not 1 <= ssh_port <= 65535:
            raise UpgradeError(f"host {name} ssh_port is invalid")
        identity = host.get("ssh_identity", cluster.get("ssh_identity"))
        if identity is not None and (not isinstance(identity, str) or not pathlib.Path(identity).is_absolute()):
            raise UpgradeError(f"host {name} ssh_identity must be an absolute path")
        shard = ch.get("shard")
        replica = ch.get("replica")
        keeper_id = keeper.get("id")
        if "clickhouse" in roles:
            if not isinstance(shard, int) or isinstance(shard, bool) or shard < 1:
                raise UpgradeError(f"ClickHouse host {name} has an invalid shard")
            if not isinstance(replica, int) or isinstance(replica, bool) or replica < 1:
                raise UpgradeError(f"ClickHouse host {name} has an invalid replica")
        elif shard is not None or replica is not None:
            raise UpgradeError(f"non-ClickHouse host {name} cannot define ClickHouse coordinates")
        if "keeper" in roles:
            if not isinstance(keeper_id, int) or isinstance(keeper_id, bool) or keeper_id < 1:
                raise UpgradeError(f"Keeper host {name} has an invalid id")
        elif keeper_id is not None:
            raise UpgradeError(f"non-Keeper host {name} cannot define a Keeper id")
        nodes.append(Node(
            name=name, address=address, roles=roles,
            clickhouse_shard=shard, clickhouse_replica=replica,
            keeper_id=keeper_id, ssh_user=ssh_user, ssh_port=ssh_port,
            ssh_identity=identity, host_id=host_id,
        ))
    # NAN-5213: any number of stateless app hosts; still one PostgreSQL host.
    if not any("app" in node.roles for node in nodes):
        raise UpgradeError("inventory must contain at least one app host")
    # NAN-5214: two or three postgres hosts are a Patroni cluster.
    if sum("postgres" in node.roles for node in nodes) not in (1, 2, 3):
        raise UpgradeError("inventory must contain one, two or three postgres hosts")
    if not any("ingest" in node.roles for node in nodes) or not any("clickhouse" in node.roles for node in nodes):
        raise UpgradeError("inventory requires ingest and ClickHouse hosts")
    clickhouse_nodes = [node for node in nodes if "clickhouse" in node.roles]
    coordinates = [(node.clickhouse_shard, node.clickhouse_replica) for node in clickhouse_nodes]
    if len(coordinates) != len(set(coordinates)):
        raise UpgradeError("ClickHouse shard/replica coordinates must be unique")
    shards = sorted({int(node.clickhouse_shard) for node in clickhouse_nodes if node.clickhouse_shard is not None})
    if shards != list(range(1, len(shards) + 1)):
        raise UpgradeError("ClickHouse shard ids must be contiguous from 1")
    replica_sets = {
        shard: sorted(int(node.clickhouse_replica) for node in clickhouse_nodes if node.clickhouse_shard == shard and node.clickhouse_replica is not None)
        for shard in shards
    }
    expected_replicas = list(range(1, len(next(iter(replica_sets.values()))) + 1))
    if any(replicas != expected_replicas for replicas in replica_sets.values()):
        raise UpgradeError("every ClickHouse shard must have the same replicas, contiguous from 1")
    keeper_ids = sorted(int(node.keeper_id) for node in nodes if "keeper" in node.roles and node.keeper_id is not None)
    if keeper_ids != list(range(1, len(keeper_ids) + 1)):
        raise UpgradeError("Keeper ids must be unique and contiguous from 1")
    distributed_clickhouse = len(shards) > 1 or len(expected_replicas) > 1
    allowed_keeper_counts = {3} if distributed_clickhouse else {1, 3}
    if len(keeper_ids) not in allowed_keeper_counts:
        expected = "3" if distributed_clickhouse else "1 or 3"
        raise UpgradeError(f"inventory requires {expected} Keeper hosts for this ClickHouse topology")
    return nodes, cluster


def lb_hook_arguments(require_lb_hooks: bool) -> list[str]:
    """Worker arguments for the load-balancer hooks.

    NAN-5279: the configured hooks travel to every remote worker, not only
    when several ingest hosts make them mandatory: app hosts of a multi-app
    cluster drain through them too."""
    arguments = ["--require-lb-hooks"] if require_lb_hooks else []
    for kind in ("DRAIN", "REJOIN"):
        value = os.environ.get(f"NANO_UPGRADE_LB_{kind}_COMMAND", "")
        if value or require_lb_hooks:
            arguments.extend([f"--lb-{kind.lower()}-command", value])
    return arguments


class NodeExecutor:
    def __init__(
        self,
        node: Node,
        local_ops: LocalOps,
        runner: Runner,
        remote_install_dir: pathlib.Path,
        local_name: str,
    ):
        self.node = node
        self.local_ops = local_ops
        self.runner = runner
        self.remote_install_dir = remote_install_dir
        self.local = node.name == local_name or node.name == "single"
        self.backup_output = remote_install_dir / "backups"
        self.include_clickhouse_data = False

    def _remote(
        self, action: str, arguments: Sequence[str], timeout: int,
        input_text: str | None = None,
    ) -> Any:
        ssh, target, command = self._remote_command(action, arguments)
        result = self.runner.run(
            [*ssh, target, shlex.join(command)], timeout=timeout, check=False,
            **({"input_text": input_text} if input_text is not None else {}),
        )
        if result.returncode != 0:
            # Workers emit operator-safe errors on stderr. Keep only the final
            # bounded line so a coordinator can identify the failed host and
            # gate without copying an unbounded remote log.
            lines = [line.strip() for line in result.stderr.splitlines() if line.strip()]
            detail = lines[-1][:500] if lines else "worker returned no diagnostic"
            raise UpgradeError(
                f"host {self.node.name} {action} failed (exit {result.returncode}): {detail}"
            )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise UpgradeError(f"host {self.node.name} returned an invalid worker response") from error

    def _remote_command(self, action: str, arguments: Sequence[str]) -> tuple[list[str], str, list[str]]:
        target = f"{self.node.ssh_user}@{self.node.address}" if self.node.ssh_user else self.node.address
        ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(self.node.ssh_port)]
        if self.node.ssh_identity:
            ssh.extend(["-i", self.node.ssh_identity])
        command = [str(self.remote_install_dir / "scripts/nano"), "_upgrade-worker", action, "--install-dir", str(self.remote_install_dir), *arguments]
        return ssh, target, command

    def collect_backup(
        self, remote_output: pathlib.Path, local_output: pathlib.Path,
    ) -> pathlib.Path:
        if self.local:
            return remote_output
        if not remote_output.is_absolute() or any(
            ord(character) < 0x20 for character in str(remote_output)
        ):
            raise UpgradeError(
                f"host {self.node.name} returned an unsafe backup output path"
            )
        if local_output.is_dir() and all(
            (local_output / item).is_file()
            for item in ("manifest.json", "manifest.sig", "payload.cms")
        ):
            return local_output
        if local_output.exists() or local_output.is_symlink():
            raise UpgradeError(f"local backup collection target exists: {local_output}")
        local_output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = (
            f"{self.node.ssh_user}@{self.node.address}"
            if self.node.ssh_user else self.node.address
        )
        command = [
            "sftp", "-b", "-", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10", "-P", str(self.node.ssh_port),
        ]
        if self.node.ssh_identity:
            command.extend(["-i", self.node.ssh_identity])
        command.append(target)

        def quote(value: pathlib.Path) -> str:
            return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

        result = self.runner.run(
            command, timeout=7200, check=False,
            input_text=f"get -R {quote(remote_output)} {quote(local_output)}\n",
        )
        if result.returncode != 0:
            lines = [line.strip() for line in result.stderr.splitlines() if line.strip()]
            detail = lines[-1][:500] if lines else "sftp returned no diagnostic"
            raise UpgradeError(
                f"host {self.node.name} backup collection failed "
                f"(exit {result.returncode}): {detail}"
            )
        if not local_output.is_dir() or not all(
            (local_output / item).is_file()
            for item in ("manifest.json", "manifest.sig", "payload.cms")
        ):
            raise UpgradeError(
                f"host {self.node.name} backup collection is incomplete"
            )
        return local_output

    def migration_lock(self) -> Any:
        if self.local:
            return self.local_ops.migration_lock()
        return RemoteMigrationLock(self, "migration")

    def upgrade_lock(self) -> Any:
        if self.local:
            return self.local_ops.upgrade_lock()
        return RemoteMigrationLock(self, "upgrade")

    def backup_mutation_lock(self, timeout: int = 600) -> Any:
        if self.local:
            return self.local_ops.backup_mutation_lock(timeout)
        return RemoteMigrationLock(
            self, "backup-mutation", acquire_timeout=timeout,
        )

    def api_mutation_fence_capable(self) -> bool:
        if self.local:
            return self.local_ops.api_mutation_fence_capable()
        value = self._remote("api-mutation-capability", [], 60)
        if not isinstance(value, bool):
            raise UpgradeError(
                f"host {self.node.name} returned an invalid API mutation capability"
            )
        return value

    def set_api_mutation_fence(self, active: bool, owner: str) -> dict[str, Any]:
        if self.local:
            return self.local_ops.set_api_mutation_fence(active, owner)
        return json_object(
            self._remote(
                "api-mutation-fence",
                ["--run-id", owner, "--fence-action", "activate" if active else "clear"],
                120,
            ),
            "remote API mutation fence",
        )

    def runtime_identity(self) -> dict[str, Any]:
        if self.local:
            return self.local_ops.runtime_identity()
        return json_object(self._remote("identity", [], 60), "remote runtime identity")

    def preflight(
        self, manifest: dict[str, Any], bundle: pathlib.Path, remote_bundle: pathlib.Path,
        require_lb_hooks: bool, expected_bundle_sha256: str, prepared: bool = False,
        test_license_rehearsal: bool = False, lb_roundtrip: bool = True,
    ) -> list[Check]:
        if self.local:
            if sha256_path(bundle) != expected_bundle_sha256:
                raise UpgradeError("local bundle digest differs from the coordinator-verified bundle")
            self.local_ops.backup_output = self.backup_output
            self.local_ops.include_clickhouse_data = self.include_clickhouse_data
            return self.local_ops.preflight(
                manifest, bundle, require_lb_hooks, prepared,
                test_license_rehearsal, lb_roundtrip,
            )
        arguments = [
            "--bundle", str(remote_bundle),
            "--expected-bundle-sha256", expected_bundle_sha256,
            "--backup-output", str(self.backup_output),
        ]
        if prepared:
            arguments.append("--prepared")
        if self.include_clickhouse_data:
            arguments.append("--include-clickhouse-data")
        arguments.extend(lb_hook_arguments(require_lb_hooks))
        if test_license_rehearsal:
            arguments.append("--test-license-rehearsal")
        if not lb_roundtrip:
            arguments.append("--no-lb-roundtrip")
        value = self._remote("preflight", arguments, 600)
        if not isinstance(value, list):
            raise UpgradeError(f"host {self.node.name} returned invalid preflight results")
        return [Check(str(item["name"]), bool(item["passed"]), str(item["detail"]), self.node.name) for item in value]

    def ledger(self) -> dict[str, list[list[str]]]:
        if self.local:
            return self.local_ops.ledger()
        return json_object(self._remote("ledger", [], 120), "remote ledger")  # type: ignore[return-value]

    def pg_ha_status(self) -> dict[str, Any]:
        if self.local:
            return self.local_ops.pg_ha_status()
        return json_object(self._remote("pg-ha-status", [], 120), "remote PostgreSQL HA status")

    def pg_switchover(self, candidate: str, timeout: int) -> dict[str, Any]:
        if self.local:
            return self.local_ops.pg_switchover(candidate, timeout)
        return json_object(
            self._remote("pg-switchover", ["--candidate", candidate, "--timeout", str(timeout)], timeout + 120),
            "remote PostgreSQL switchover",
        )

    def backup_gate(self, run_id: str, action: str) -> dict[str, Any]:
        if self.local:
            return self.local_ops.backup_gate(run_id, action)
        return json_object(
            self._remote(
                "backup-gate",
                ["--run-id", run_id, "--gate-action", action],
                120,
            ),
            "remote backup gate",
        )

    def backup(
        self, key: pathlib.Path, output: pathlib.Path, run_id: str, epoch: str,
        role_split: bool, snapshot_gate: pathlib.Path | None = None,
        clickhouse_disk: str = "backups", component: str | None = None,
        include_clickhouse_data: bool = False,
    ) -> str:
        if self.local:
            return self.local_ops.backup(
                key, output, run_id, epoch, role_split, snapshot_gate,
                clickhouse_disk, component, include_clickhouse_data,
            )
        arguments = [
            "--backup-key-file", str(key), "--backup-output", str(output),
            "--run-id", run_id, "--quiesce-epoch", epoch,
        ]
        if include_clickhouse_data:
            arguments.append("--include-clickhouse-data")
        if snapshot_gate is not None:
            arguments.extend(["--snapshot-gate", str(snapshot_gate)])
        if component is not None:
            arguments.extend(["--component", component])
        arguments.extend(["--clickhouse-disk", clickhouse_disk])
        value = self._remote(
            "backup",
            arguments,
            7200,
        )
        return str(json_object(value, "remote backup")["backup"])

    def running_writers(self, role: str) -> dict[str, Any]:
        if self.local:
            return self.local_ops.running_writers(role)
        return json_object(
            self._remote("running-writers", ["--role", role], 60),
            "remote running writers",
        )

    def quiesce(
        self, role: str, timeout: int, require_lb_hooks: bool,
        services: Iterable[str],
    ) -> dict[str, Any]:
        if self.local:
            return self.local_ops.quiesce(
                role, timeout, require_lb_hooks, services=services,
            )
        arguments = ["--role", role, "--timeout", str(timeout)]
        for service in services:
            arguments.extend(["--service", service])
        arguments.extend(lb_hook_arguments(require_lb_hooks))
        return json_object(self._remote("quiesce", arguments, timeout + 60), "remote quiesce")

    def resume_writers(
        self, role: str, timeout: int, require_lb_hooks: bool,
        services: Iterable[str],
    ) -> dict[str, Any]:
        if self.local:
            return self.local_ops.resume_writers(
                role, timeout, require_lb_hooks, services=services,
            )
        arguments = ["--role", role, "--timeout", str(timeout)]
        for service in services:
            arguments.extend(["--service", service])
        arguments.extend(lb_hook_arguments(require_lb_hooks))
        return json_object(self._remote("resume-writers", arguments, timeout + 60), "remote writer resume")

    def prepare(
        self, bundle: pathlib.Path, remote_bundle: pathlib.Path, source: str,
        target: str, run_id: str, expected_bundle_sha256: str,
    ) -> dict[str, Any]:
        if self.local:
            return self.local_ops.prepare(
                bundle, source, target, run_id, expected_bundle_sha256,
            )
        return json_object(self._remote(
            "prepare",
            ["--bundle", str(remote_bundle), "--source", source, "--target", target,
             "--run-id", run_id,
             "--expected-bundle-sha256", expected_bundle_sha256],
            7200,
        ), "remote prepare")

    def render_config(self, inventory_text: str, apply: bool, run_id: str = "") -> dict[str, Any]:
        """NAN-5279 F1: re-render this host's configuration (see LocalOps)."""
        if self.local:
            return self.local_ops.render_config(inventory_text, apply, run_id)
        arguments = ["--run-id", run_id] if run_id else []
        if apply:
            arguments.append("--apply")
        # The inventory travels on stdin: hosts may keep their copy anywhere,
        # and every host must render from the coordinator's one inventory.
        return json_object(
            self._remote("render-config", arguments, 300, input_text=inventory_text),
            "remote render-config",
        )

    def rollout(self, role: str, timeout: int, require_lb_hooks: bool = False) -> dict[str, Any]:
        if self.local:
            return self.local_ops.rollout(role, timeout, require_lb_hooks)
        arguments = ["--role", role, "--timeout", str(timeout)]
        arguments.extend(lb_hook_arguments(require_lb_hooks))
        return json_object(self._remote("rollout", arguments, timeout + 60), "remote rollout")

    def post_verify(self, target: str, timeout: int) -> dict[str, Any]:
        if self.local:
            return self.local_ops.post_verify(target, timeout)
        return json_object(self._remote("post-verify", ["--target", target, "--timeout", str(timeout)], timeout + 60), "remote post-verify")

    def smoke_ingest(self, marker: str) -> dict[str, Any]:
        if self.local:
            return self.local_ops.smoke_ingest(marker)
        return json_object(self._remote("smoke-ingest", ["--marker", marker], 120), "remote smoke ingest")

    def smoke_search(self, marker: str, timeout: int) -> dict[str, Any]:
        if self.local:
            return self.local_ops.smoke_search(marker, timeout)
        return json_object(self._remote("smoke-search", ["--marker", marker, "--timeout", str(timeout)], timeout + 60), "remote smoke search")

    def siem_health(self) -> dict[str, Any]:
        if self.local:
            return self.local_ops.siem_health()
        return json_object(self._remote("siem-health", [], 120), "remote SIEM Health")

    def rollback_preflight(self, previous: str, target: str) -> list[Check]:
        if self.local:
            return self.local_ops.rollback_preflight(previous, target)
        value = self._remote(
            "rollback-preflight", ["--previous", previous, "--target", target], 120,
        )
        if not isinstance(value, list):
            raise UpgradeError(f"host {self.node.name} returned invalid rollback preflight results")
        return [
            Check(str(item["name"]), bool(item["passed"]), str(item["detail"]), self.node.name)
            for item in value
        ]

    def rollback(
        self, role: str, previous: str, target: str, timeout: int,
        require_lb_hooks: bool = False, run_id: str = "",
    ) -> dict[str, Any]:
        if self.local:
            return self.local_ops.rollback_role(
                role, previous, target, timeout, require_lb_hooks, run_id,
            )
        arguments = [
            "--role", role, "--previous", previous, "--target", target,
            "--timeout", str(timeout),
        ]
        if run_id:
            arguments.extend(["--run-id", run_id])
        arguments.extend(lb_hook_arguments(require_lb_hooks))
        return json_object(
            self._remote("rollback", arguments, timeout + 60), "remote rollback",
        )


class RemoteMigrationLock:
    """Hold a PostgreSQL host advisory-lock worker over SSH."""

    def __init__(
        self, executor: NodeExecutor, kind: str, *, acquire_timeout: float = 45,
    ):
        if kind not in PgMigrationLock.LOCK_IDS:
            raise UpgradeError("invalid remote PostgreSQL advisory lock kind")
        self.executor = executor
        self.kind = kind
        self.acquire_timeout = acquire_timeout
        self.marker = f"__NANO_REMOTE_{kind.replace('-', '_').upper()}_LOCKED__"
        self.process: subprocess.Popen[str] | None = None

    def __enter__(self) -> "RemoteMigrationLock":
        ssh, target, command = self.executor._remote_command(
            "hold-advisory-lock", [
                "--lock-kind", self.kind,
                "--timeout", str(self.acquire_timeout),
            ]
        )
        try:
            self.process = subprocess.Popen(
                [*ssh, target, shlex.join(command)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
        except OSError as error:
            raise UpgradeError(f"cannot start migration lock worker on {self.executor.node.name}") from error
        assert self.process.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + self.acquire_timeout + 15
        while self.process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                break
            line = self.process.stdout.readline()
            if self.marker in line:
                selector.close()
                return self
        selector.close()
        self.__exit__(None, None, None)
        raise UpgradeError(f"could not acquire migration lock on PostgreSQL host {self.executor.node.name}")

    def __exit__(self, *_: Any) -> None:
        if self.process is None:
            return
        process = self.process
        self.process = None
        if process.stdin and not process.stdin.closed:
            with contextlib.suppress(OSError, ValueError):
                process.stdin.close()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=10)
        if process.poll() is None:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
        if process.poll() is None:
            process.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                with contextlib.suppress(OSError, ValueError):
                    stream.close()


# NAN-5251 / NAN-5249: app.nano.rs answers a Self-run v2 build below the
# licensed minimum with this exact lock reason. It is the only lock the upgrade
# preflight accepts, and only for a target at or above that minimum.
SELFRUN_UPGRADE_GATE_REASON = (
    "Upgrade required: this release can't be licensed for Self-run. Install v"
)
SELFRUN_LICENSED_MINIMUM = (2, 0, 10)


def is_selfrun_upgrade_gate(status: str, valid: str, reason: str, target: str) -> bool:
    if status != "locked" or valid != "false":
        return False
    match = re.fullmatch(
        re.escape(SELFRUN_UPGRADE_GATE_REASON)
        + r"([0-9]+)\.([0-9]+)\.([0-9]+) or later\.",
        reason.strip(),
    )
    if match is None:
        return False
    minimum = tuple(int(part) for part in match.groups())
    try:
        target_key = semver(target)
    except (UpgradeError, ValueError):
        return False
    return target_key >= max(minimum, SELFRUN_LICENSED_MINIMUM)


def check_registry_control_tree(install_dir: pathlib.Path, target: str) -> str:
    """NAN-5251: a registry upgrade runs the target's Compose files and scripts.

    The image bundle carries only images; a registry upgrade has no images to
    carry, so the operator extracts the signed package over the install
    directory on every host first (it never contains .env or host state).
    """
    marker = install_dir / ".nano-bundle"
    try:
        value = marker.read_text(encoding="utf-8").strip() if marker.is_file() else ""
    except OSError as error:
        raise UpgradeError(f"cannot read {marker}") from error
    if value != f"nano compose release v{target}":
        found = value.rsplit(" ", 1)[-1] if value else "none"
        raise UpgradeError(
            f"install directory holds the {found} control tree, not v{target}. Verify "
            f"nano-compose-<edition>-{target}.tar.gz against its .sha256 and .sha256.sig "
            "(scripts/nano bundle verify <package>, or the Upgrade guide's check) and only "
            f"then extract it over {install_dir} on this host "
            f"(tar -xzf <package> --strip-components=1 -C {install_dir}); it keeps .env"
        )
    return f"control tree is v{target}"


def image_needs_registry_login(ref: str) -> bool:
    """NAN-5269: only nano's enterprise application images are private.

    They are the `nanosiem-*` repositories (nanosiem-api, -search, -jobs, ...)
    in the customer registry the license issues a pull credential for (or
    nano's own registry for internal builds). Everything else an enterprise
    package pins is public and pulls anonymously: Docker Hub and quay.io
    base images and nano's public ghcr.io/nano-rs/vector. Deciding by the
    `nano-rs` substring refused ghcr.io for every customer, who can never log
    in there. The registry-pull check still pulls every image by digest, so
    a repository that does need a credential still fails before any change.
    """
    head, _, last = ref.rpartition("/")
    if not head or "/" not in head:
        return False  # a Docker Hub name such as postgres:17 or a two-part Hub path
    repository = last.split("@", 1)[0].split(":", 1)[0]
    return repository.startswith("nanosiem-")


def private_registry_images(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if manifest.get("edition") != "enterprise":
        return []
    return [
        image for image in manifest.get("images", [])
        if isinstance(image, dict) and image_needs_registry_login(str(image.get("ref", "")))
    ]


def check_registry_login(manifest: dict[str, Any]) -> str:
    """Pulls happen mid-upgrade; refuse up front when no credential is configured."""
    if manifest.get("edition") != "enterprise":
        return "open images come from a public registry"
    registries = sorted({
        str(image.get("ref", "")).split("/", 1)[0]
        for image in private_registry_images(manifest)
    })
    if not registries:
        return "no private registry images"
    config_dir = pathlib.Path(os.environ.get("DOCKER_CONFIG") or pathlib.Path.home() / ".docker")
    try:
        config = json.loads((config_dir / "config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        config = {}
    if not isinstance(config, dict):
        config = {}
    if config.get("credsStore"):
        return f"credential store {config['credsStore']} configured (checked by registry-pull)"
    auths = config.get("auths") if isinstance(config.get("auths"), dict) else {}
    helpers = config.get("credHelpers") if isinstance(config.get("credHelpers"), dict) else {}
    missing = [
        registry for registry in registries
        if registry not in helpers and not any(
            key == registry or key.rstrip("/").endswith(f"//{registry}") for key in auths
        )
    ]
    if missing:
        raise UpgradeError(
            f"not logged in to {', '.join(missing)}: log in with a fresh registry credential "
            "from app.nano.rs on this host (it lasts about an hour), then rerun"
        )
    return f"logged in to {', '.join(registries)}"


COMPOSE_PACKAGE_RE = re.compile(
    r"^nano-compose-(open|enterprise)-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz$"
)


def is_compose_package(bundle: pathlib.Path) -> bool:
    """NAN-5251: the signed installer package, used for registry-pull upgrades."""
    return COMPOSE_PACKAGE_RE.fullmatch(bundle.name) is not None


def bundle_cli_arguments(bundle: pathlib.Path, image_prefix: str) -> list[str]:
    """Extra `nano bundle verify|load` arguments for a registry-pull package."""
    if is_compose_package(bundle) and image_prefix:
        return ["--image-prefix", image_prefix]
    return []


def verify_manifest(
    nano_cli: pathlib.Path, bundle: pathlib.Path, runner: Runner, image_prefix: str = "",
) -> dict[str, Any]:
    if bundle.is_symlink() or not bundle.is_file():
        raise UpgradeError(f"bundle must be a regular non-symlink file: {bundle}")
    if bundle.name.endswith(".tar.gz") and not is_compose_package(bundle):
        raise UpgradeError(
            f"{bundle.name} is not a nano release artifact; pass the signed image bundle "
            "nano-<version>-<edition>.tar or the signed installer package "
            "nano-compose-<edition>-<version>.tar.gz with its .sha256 and .sha256.sig beside it"
        )
    result = runner.run(
        [str(nano_cli), "bundle", "verify", str(bundle), "--json",
         *bundle_cli_arguments(bundle, image_prefix)],
        timeout=7200, check=False,
    )
    try:
        manifest = json_object(json.loads(result.stdout), "bundle verification result")
    except json.JSONDecodeError as error:
        raise UpgradeError(
            f"bundle verifier failed (exit {result.returncode}) for {bundle.name}"
        ) from error
    if result.returncode != 0 or "error" in manifest:
        # `nano bundle verify --json` reports a safe, user-facing reason.
        raise UpgradeError(
            f"cannot verify {bundle.name}: {manifest.get('error', f'exit {result.returncode}')}"
        )
    if manifest.get("schema_version") != 1:
        raise UpgradeError("bundle verifier returned an unsupported schema")
    canonical_version(str(manifest.get("version", "")))
    if manifest.get("edition") not in {"open", "enterprise"}:
        raise UpgradeError("bundle verifier returned an invalid edition")
    return manifest


def check_version_path(
    installed: str, manifest: dict[str, Any], edition: str, *, resuming: bool = False,
) -> list[Check]:
    checks: list[Check] = []
    target = canonical_version(str(manifest.get("version", "")))
    if manifest.get("edition") != edition:
        checks.append(Check("edition", False, f"installed {edition}, bundle {manifest.get('edition')}", "coordinator"))
    else:
        checks.append(Check("edition", True, f"{edition} matches", "coordinator"))
    if resuming and semver(target) == semver(installed):
        checks.append(Check("version-path", True, f"resuming partially applied target {target}", "coordinator"))
        return checks
    if semver(target) <= semver(installed):
        checks.append(Check("version-path", False, f"target {target} is not newer than installed {installed}", "coordinator"))
        return checks
    minimum = canonical_version(str(manifest.get("min_from_version", installed)))
    if semver(installed) < semver(minimum):
        checks.append(Check("version-path", False, f"target requires at least {minimum}; installed {installed}", "coordinator"))
        return checks
    # NAN-5354: the signer puts the PATH UNION in the manifest (every stop any
    # release up to the target requires, nano_bundle._required_stops_on_path),
    # so this check covers every release between the installed version and the
    # target, not only the target's own policy entry.
    stops = manifest.get("required_stops", [])
    if not isinstance(stops, list) or not all(isinstance(stop, str) for stop in stops):
        checks.append(Check("version-path", False, "manifest required_stops is invalid", "coordinator"))
        return checks
    skipped = sorted(
        (canonical_version(stop) for stop in stops if semver(installed) < semver(stop) < semver(target)),
        key=semver,
    )
    if skipped:
        checks.append(Check("version-path", False, f"required stop(s) would be skipped: {', '.join(skipped)}", "coordinator"))
    else:
        checks.append(Check("version-path", True, f"{installed} -> {target}; no required stop skipped", "coordinator"))
    return checks


def enforce_signed_backup_policy(
    manifest: dict[str, Any], *, skip_requested: bool = False, journal_skipped: bool = False
) -> bool:
    requires = json_object(manifest.get("requires", {}), "manifest requirements")
    mandatory = requires.get("mandatory_backup", False)
    if not isinstance(mandatory, bool):
        raise UpgradeError("manifest mandatory_backup requirement is invalid")
    if mandatory and skip_requested:
        raise UpgradeError(
            "this signed upgrade requires a backup; "
            "--skip-backup-I-understand is forbidden"
        )
    if mandatory and journal_skipped:
        raise UpgradeError(
            "the signed upgrade requires a backup, but the journal records "
            "a skipped backup"
        )
    return mandatory


def print_checks(checks: Sequence[Check]) -> None:
    widths = [4, 8, 18]
    rows = [("PASS" if check.passed else "FAIL", check.node, check.name, check.detail) for check in checks]
    for row in rows:
        widths[0] = max(widths[0], len(row[0]))
        widths[1] = max(widths[1], len(row[1]))
        widths[2] = max(widths[2], len(row[2]))
    print(f"{'RESULT':<{widths[0]}}  {'HOST':<{widths[1]}}  {'CHECK':<{widths[2]}}  DETAIL")
    for result, host, name, detail in rows:
        print(f"{result:<{widths[0]}}  {host:<{widths[1]}}  {name:<{widths[2]}}  {detail}")
    passed = sum(check.passed for check in checks)
    print(f"Preflight: {passed}/{len(checks)} PASS; {len(checks) - passed} FAIL")


def validate_manifest_ledgers(
    manifest: dict[str, Any], ledgers: Sequence[dict[str, list[list[str]]]], *,
    require_complete: bool = False, schema_profile: str = "udm",
) -> list[Check]:
    expected = json_object(manifest.get("migrations", {}), "manifest.migrations")
    checks: list[Check] = []
    edition = manifest.get("edition")
    groups = {
        "postgres": ("postgres", "postgres_enterprise") if edition == "enterprise" else ("postgres",),
        "clickhouse": ("clickhouse", "clickhouse_enterprise") if edition == "enterprise" else ("clickhouse",),
    }
    for engine, manifest_keys in groups.items():
        expected_map: dict[str, str] = {}
        optional_expected_map: dict[str, str] = {}

        def normalized_version(value: Any) -> str:
            version = str(value)
            # SQLx stores numeric migration versions as integers, while the
            # signed bundle derives them from filenames such as 001_init.sql.
            # Treat those two canonical spellings as the same migration; keep
            # ClickHouse suffixes/profile namespaces byte-exact.
            if engine == "postgres" and version.isdigit():
                return str(int(version))
            return version

        try:
            for manifest_key in manifest_keys:
                entries = expected.get(manifest_key, [])
                if not isinstance(entries, list):
                    raise UpgradeError(f"manifest {manifest_key} migration list is invalid")
                for entry in entries:
                    item = json_object(entry, f"manifest {manifest_key} migration")
                    version = normalized_version(item["version"])
                    checksum = str(item["checksum"]).lower()
                    if version in expected_map and expected_map[version] != checksum:
                        raise UpgradeError(f"manifest repeats migration {version} with different checksums")
                    expected_map[version] = checksum
            if engine == "clickhouse":
                optional_expected_map.update(CLICKHOUSE_BASELINE_ALLOWLIST)
                profile_entries = PROFILE_LEDGER_ALLOWLIST.get(schema_profile, {})
                for version, checksum in profile_entries.items():
                    expected_map[version] = checksum
        except (KeyError, UpgradeError) as error:
            checks.append(Check(f"ledger-{engine}", False, str(error), "coordinator"))
            continue
        def normalized_checksum(value: str) -> str:
            lowered = value.lower()
            if re.fullmatch(r"[0-9a-f]{64}", lowered):
                return f"sha256:{lowered}"
            if re.fullmatch(r"[0-9a-f]{96}", lowered):
                return f"sha384:{lowered}"
            return lowered

        actual: dict[str, str] = {}
        for ledger in ledgers:
            for version, checksum in ledger.get(engine, []):
                version = normalized_version(version)
                normalized = normalized_checksum(checksum)
                previous = actual.get(version)
                if previous is not None and previous != normalized:
                    checks.append(Check(f"ledger-{engine}", False, f"hosts disagree on migration {version}", "coordinator"))
                actual[version] = normalized

        drifted = sorted(
            version for version, checksum in actual.items()
            if (
                version in expected_map
                and not (
                    engine == "clickhouse"
                    and version in optional_expected_map
                    and checksum == ""
                )
                and expected_map[version] != checksum
            ) or (
                version not in expected_map
                and version in optional_expected_map
                and optional_expected_map[version] != checksum
            )
        )
        # ClickHouse init/overlay sentinels are updated and content-verified by
        # the migrator itself. They are not numbered migrations and therefore
        # do not appear in the release bundle's migration index.
        unknown = sorted(
            version for version in actual
            if version not in expected_map
            and version not in optional_expected_map
            and not (engine == "clickhouse" and version.startswith("__"))
        )
        unapplied = sorted(version for version in expected_map if version not in actual) if require_complete else []
        if drifted or unknown or unapplied:
            detail = "; ".join(filter(None, [
                f"checksum drift {','.join(drifted)}" if drifted else "",
                f"not in target {','.join(unknown)}" if unknown else "",
                f"not applied {','.join(unapplied)}" if unapplied else "",
            ]))
            checks.append(Check(f"ledger-{engine}", False, detail, "coordinator"))
        else:
            suffix = " and target-complete" if require_complete else ""
            checks.append(Check(f"ledger-{engine}", True, f"{len(actual)} applied entries are compatible{suffix}", "coordinator"))
    return checks


def bundle_for_version(args: argparse.Namespace, ops: LocalOps, runner: Runner) -> tuple[pathlib.Path, tempfile.TemporaryDirectory[str] | None]:
    if args.bundle:
        return pathlib.Path(args.bundle).expanduser().resolve(), None
    version = canonical_version(args.version)
    template = os.environ.get("NANO_BUNDLE_URL_TEMPLATE", "https://releases.nano.rs/nano-{version}-{edition}.tar")
    if set(re.findall(r"{([^{}]+)}", template)) - {"version", "edition"}:
        raise UpgradeError("NANO_BUNDLE_URL_TEMPLATE contains an unsupported placeholder")
    url = template.format(version=version, edition=ops.edition)
    temporary = tempfile.TemporaryDirectory(prefix="nano-upgrade-bundle-")
    destination = pathlib.Path(temporary.name) / f"nano-{version}-{ops.edition}.tar"
    try:
        with urllib.request.urlopen(url, timeout=120) as response, destination.open("wb") as output:
            shutil.copyfileobj(response, output)
    except OSError as error:
        temporary.cleanup()
        raise UpgradeError(
            f"could not download the image bundle for {version} from {url}. Enterprise image "
            "bundles are not published for registry installs: download the signed installer "
            f"package nano-compose-{ops.edition}-{version}.tar.gz (with .sha256 and .sha256.sig) "
            "with your license values, verify its signature, then extract it over the install "
            "directory on every host and pass the package with --bundle (see the Upgrade guide)"
        ) from error
    os.chmod(destination, 0o600)
    return destination, temporary


@contextlib.contextmanager
def preflight_progress(label: str, summary: Callable[[], str] | None = None) -> Any:
    """NAN-5285 (v2.0.13 retest F5): the preflight / dry run printed nothing
    until every host's checks were done (2.5-4.5 minutes over plain ssh: image
    pulls, hook round trips, renders). Stream one line when each phase starts
    and one when it ends, on stderr like the upgrade steps, so an operator
    sees progress as it happens."""
    started = time.monotonic()
    eprint(f"==> {utc_now()} preflight {label}: started")
    try:
        yield
    except BaseException:
        eprint(f"==> {utc_now()} preflight {label}: FAILED after {time.monotonic() - started:.0f}s")
        raise
    detail = ""
    if summary is not None:
        with contextlib.suppress(Exception):
            detail = f" ({summary()})"
    eprint(f"==> {utc_now()} preflight {label}: done in {time.monotonic() - started:.0f}s{detail}")


def run_step(journal: Journal, state: RunState, step: str, function: Callable[[], Any]) -> Any:
    if step in state.done_steps:
        eprint(f"==> resume: already completed {step}")
        previous = next(event for event in reversed(state.events) if event.get("event") == "step_done" and event.get("step") == step)
        return previous.get("result")
    journal.append(state, "step_started", step=step)
    # NAN-5279: one line per step as it starts and ends, so an operator
    # watching over plain SSH (no TTY) sees progress, not 12 silent minutes.
    eprint(f"==> {utc_now()} {step}: started")
    started = time.monotonic()
    try:
        result = function()
    except BaseException as error:
        journal.append(state, "step_failed", step=step, reason=str(error))
        eprint(f"==> {utc_now()} {step}: FAILED after {time.monotonic() - started:.0f}s")
        raise
    journal_lb_hook_calls(journal, state, step, result)
    journal.append(state, "step_done", step=step, result=result)
    eprint(f"==> {utc_now()} {step}: done in {time.monotonic() - started:.0f}s")
    return result


def journal_lb_hook_calls(journal: Journal, state: RunState, step: str, result: Any) -> None:
    """NAN-5285 F8: one `lb_hook` journal event per drain/rejoin hook call a
    step's worker made (host, kind, rc, duration). A resumed step that already
    completed is not re-run, so its calls are never journaled twice; a step
    re-run after a failure journals the calls it makes again."""
    if not isinstance(result, dict):
        return
    for call in result.get("lb_hooks") or []:
        if isinstance(call, dict):
            journal.append(
                state, "lb_hook", step=step,
                **{key: call[key] for key in ("host", "kind", "rc", "at", "duration_ms") if key in call},
            )


def sha256_path(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_bundle_digest(path: pathlib.Path, expected: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise UpgradeError("coordinator did not provide a valid expected bundle digest")
    if sha256_path(path) != expected:
        raise UpgradeError("bundle digest differs from the coordinator-verified bundle")


# NAN-5214: the current Patroni leader's node name. Every coordinator path that
# talks to "the PostgreSQL host" (fence, advisory locks, backups, ledger)
# takes node_sort(nodes, "postgres")[0], so resolving the leader once per
# command and sorting it first keeps those paths on the writable member.
PG_PRIMARY_NODE: str | None = None


def resolve_pg_primary(nodes: Sequence[Node], executors: dict[str, Any]) -> str | None:
    """Ask each postgres node's worker which one holds Patroni leadership."""
    global PG_PRIMARY_NODE
    postgres = sorted((node for node in nodes if "postgres" in node.roles), key=lambda node: node.name)
    if len(postgres) <= 1:
        PG_PRIMARY_NODE = postgres[0].name if postgres else None
        return PG_PRIMARY_NODE
    errors: list[str] = []
    for node in postgres:
        try:
            status = executors[node.name].pg_ha_status()
        except UpgradeError as error:
            errors.append(f"{node.name}: {error}")
            continue
        if status.get("leader"):
            PG_PRIMARY_NODE = node.name
            return node.name
    raise UpgradeError(
        "no postgres host reports Patroni leadership" + (f" ({'; '.join(errors)})" if errors else "")
    )


def roll_postgres_members(
    nodes: Sequence[Node],
    executors: dict[str, Any],
    journal: Any,
    state: Any,
    step: str,
    timeout: int,
    action: Callable[[Node], Any],
    before: Callable[[Node], None] | None = None,
) -> None:
    """NAN-5214: apply `action` to every Patroni member, replicas first.

    Before the leader's turn, leadership moves to a streaming (preferably
    synchronous) member that has already been handled, so PostgreSQL stays
    writable and a recreate never hits the primary.
    """
    members = node_sort(nodes, "postgres")
    leader_name = resolve_pg_primary(nodes, executors)
    ordered = [n for n in members if n.name != leader_name] + [n for n in members if n.name == leader_name]
    for node in ordered:
        if before is not None:
            before(node)
        if node.name == leader_name:
            def switch(node: Node = node) -> dict[str, Any]:
                status = executors[node.name].pg_ha_status()
                if not status.get("leader"):
                    return {"switched": False, "reason": "no longer the leader"}
                streaming = [
                    m for m in status.get("members", [])
                    if m.get("member") != status.get("member") and m.get("state") == "streaming"
                ]
                preferred = [m for m in streaming if m.get("role") == "Sync Standby"] or streaming
                if not preferred:
                    raise UpgradeError("no streaming replica can take PostgreSQL leadership")
                return executors[node.name].pg_switchover(str(preferred[0]["member"]), timeout)

            run_step(journal, state, f"switchover:{step}:{node.name}", switch)
        run_step(journal, state, f"{step}:postgres:{node.name}", lambda node=node: action(node))
    resolve_pg_primary(nodes, executors)


def _load_pg_ha_system_id() -> Any:
    """scripts/lib/pg_ha_system_id.py, shared with install.sh (NAN-5214)."""
    path = pathlib.Path(__file__).resolve().parent / "lib" / "pg_ha_system_id.py"
    spec = importlib.util.spec_from_file_location("nano_pg_ha_system_id", path)
    if spec is None or spec.loader is None:
        raise UpgradeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def node_sort(nodes: Iterable[Node], role: str) -> list[Node]:
    if role == "postgres" and PG_PRIMARY_NODE is not None:
        return sorted(
            (node for node in nodes if role in node.roles),
            key=lambda node: (node.name != PG_PRIMARY_NODE, node.name),
        )
    if role == "keeper":
        return sorted((node for node in nodes if role in node.roles), key=lambda node: node.keeper_id or 0)
    if role == "clickhouse":
        return sorted((node for node in nodes if role in node.roles), key=lambda node: (node.clickhouse_shard or 0, node.clickhouse_replica or 0))
    return sorted((node for node in nodes if role in node.roles), key=lambda node: node.name)


def role_node_pairs(
    nodes: Iterable[Node], roles: Iterable[str], *, dependents_first: bool = False,
) -> list[tuple[Node, str]]:
    selected = set(roles)
    ordered_roles = [role for role in ROLE_ORDER if role in selected]
    if selected != set(ordered_roles):
        raise UpgradeError(f"unknown dependency-ordered roles: {sorted(selected - set(ordered_roles))}")
    if dependents_first:
        ordered_roles.reverse()
    materialized = list(nodes)
    return [
        (node, role)
        for role in ordered_roles
        for node in node_sort(materialized, role)
    ]


@dataclasses.dataclass(frozen=True)
class BackupComponent:
    component_id: str
    kind: str
    node: Node


def backup_components_for(
    nodes: Sequence[Node], role_split: bool, include_clickhouse_data: bool = True,
) -> list[BackupComponent]:
    """Hosts that write a bundle. Without ClickHouse data (the NAN-5202
    default) a role-split set is the PostgreSQL component alone."""
    if not role_split:
        if len(nodes) != 1:
            raise UpgradeError("single-node backup requires exactly one host")
        return [BackupComponent("single", "auto", nodes[0])]
    postgres = node_sort(nodes, "postgres")
    clickhouse = [
        node for node in node_sort(nodes, "clickhouse")
        if node.clickhouse_replica == 1
    ]
    if not postgres:
        raise UpgradeError("consistent backup requires a PostgreSQL host")
    shards = {node.clickhouse_shard for node in clickhouse}
    expected = {
        node.clickhouse_shard for node in nodes if "clickhouse" in node.roles
    }
    if shards != expected:
        raise UpgradeError("consistent backup requires replica 1 for every ClickHouse shard")
    components = [BackupComponent("postgres", "postgres", postgres[0])]
    if not include_clickhouse_data:
        return components
    components.extend(
        BackupComponent(f"clickhouse-shard-{node.clickhouse_shard}", "clickhouse", node)
        for node in clickhouse
    )
    return components


def backup_nodes_for(
    nodes: Sequence[Node], role_split: bool, include_clickhouse_data: bool = True,
) -> list[Node]:
    """Compatibility view for callers that only need the selected hosts."""
    return [
        component.node
        for component in backup_components_for(nodes, role_split, include_clickhouse_data)
    ]


def create_consistent_backup_set(
    nodes: Sequence[Node], executors: dict[str, NodeExecutor], *,
    key: pathlib.Path, backup_root: pathlib.Path, run_id: str, epoch: str,
    role_split: bool, timeout: int, require_lb_hooks: bool,
    nano_cli: pathlib.Path, runner: Runner, clickhouse_disk: str = "backups",
    gate_run_id: str | None = None,
    record_event: Callable[..., None] | None = None,
    manual_fence: ManualBackupFence | None = None,
    manual_deployment: dict[str, Any] | None = None,
    manual_inventory: str = "",
    boundary_hook: Callable[[str], None] | None = None,
    include_clickhouse_data: bool = False,
) -> dict[str, Any]:
    """Capture one recovery set while the live ingest data plane stays online.

    By default (NAN-5202) no ClickHouse data is captured: PostgreSQL plus
    configuration only, and the ClickHouse schema is rebuilt from migrations
    on restore. ``include_clickhouse_data`` restores the full ClickHouse
    capture."""
    started = time.monotonic()
    emit = record_event or (lambda *_args, **_fields: None)

    def emit_lb_hooks(step: str, result: Any) -> None:
        # NAN-5285 F8: the drain/rejoin calls the backup's writer fence made.
        for call in (result.get("lb_hooks") or []) if isinstance(result, dict) else []:
            if isinstance(call, dict):
                emit("lb_hook", step=step, **{
                    key: call[key] for key in ("host", "kind", "rc", "at", "duration_ms")
                    if key in call
                })
    components = backup_components_for(nodes, role_split, include_clickhouse_data)
    writer_resume_pairs = role_node_pairs(nodes, ("app",)) if role_split else []
    writer_quiesce_pairs = (
        role_node_pairs(nodes, ("app",), dependents_first=True)
        if role_split else []
    )
    gates: dict[str, pathlib.Path] = {}
    futures: dict[str, concurrent.futures.Future[str]] = {}
    executor_pool: concurrent.futures.ThreadPoolExecutor | None = None
    writer_plans: dict[tuple[str, str], list[str]] = {}
    quiesced: list[tuple[Node, str]] = []
    resumed: set[tuple[str, str]] = set()
    writer_down_started: float | None = None
    writer_down_ms = 0
    primary_error: BaseException | None = None
    recovery = ""
    gate_id = safe_name(gate_run_id or run_id, "backup gate run id")
    backup_results: list[str] = []
    mutation_lease: Any | None = None
    mutation_active = False
    app_nodes = node_sort(nodes, "app") if role_split else []
    postgres_nodes = node_sort(nodes, "postgres") if role_split else []
    api_fence_capable = False

    def component_gate_id(component: BackupComponent) -> str:
        return safe_name(
            f"{gate_id}-{component.component_id}", "backup component gate run id",
        )

    def boundary(name: str) -> None:
        if manual_fence is not None:
            manual_fence.phase(name)
        if boundary_hook is not None:
            boundary_hook(name)

    def wait_for_gate(marker: str) -> None:
        deadline = time.monotonic() + timeout
        pending = {component.component_id for component in components}
        while pending:
            for component in components:
                if component.component_id not in pending:
                    continue
                future = futures[component.component_id]
                if future.done():
                    future.result()
                status = executors[component.node.name].backup_gate(
                    component_gate_id(component), "status",
                )
                if status.get(marker):
                    pending.remove(component.component_id)
            if pending and time.monotonic() >= deadline:
                raise UpgradeError(
                    f"timed out waiting for backup snapshot gate {marker.replace('_', '-')} "
                    f"on {', '.join(sorted(pending))}"
                )
            if pending:
                time.sleep(0.5)

    def resume_quiesced() -> list[str]:
        errors: list[str] = []
        for node, role in writer_resume_pairs:
            key_pair = (node.name, role)
            if key_pair not in {(item.name, item_role) for item, item_role in quiesced}:
                continue
            if key_pair in resumed:
                continue
            try:
                result = executors[node.name].resume_writers(
                    role, timeout, require_lb_hooks, writer_plans[key_pair],
                )
                resumed.add(key_pair)
                emit_lb_hooks("backup:writer-resume", result)
                emit("writer_resumed", node=node.name, role=role, result=result)
            except BaseException as error:
                errors.append(f"{node.name}/{role}: {error}")
        return errors

    try:
        if role_split:
            if not app_nodes or not postgres_nodes:
                raise UpgradeError(
                    "consistent backup requires at least one app host and a PostgreSQL host"
                )
            # NAN-5213: the PostgreSQL mutation fence is honoured by an API
            # only if its image has the capability. With several app hosts
            # every API must have it; otherwise every API is stopped.
            api_fence_capable = all(
                executors[node.name].api_mutation_fence_capable() for node in app_nodes
            )
            for component in components:
                result = executors[component.node.name].backup_gate(
                    component_gate_id(component), "prepare",
                )
                gate = pathlib.Path(str(result.get("gate", "")))
                if not gate.is_absolute():
                    raise UpgradeError(
                        f"host {component.node.name} returned an invalid backup snapshot gate"
                    )
                gates[component.component_id] = gate
                emit(
                    "backup_gate_prepared", node=component.node.name,
                    component=component.component_id, gate=str(gate),
                    gate_run_id=component_gate_id(component),
                )
        executor_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, len(components)),
            thread_name_prefix="nano-backup",
        )
        for component in components:
            output = backup_root / component.component_id if role_split else backup_root
            futures[component.component_id] = executor_pool.submit(
                executors[component.node.name].backup,
                key, output, run_id, epoch, role_split,
                gates.get(component.component_id), clickhouse_disk,
                component.kind if role_split else None,
                include_clickhouse_data,
            )
            emit(
                "component_backup_started", node=component.node.name,
                component=component.component_id, output=str(output),
            )

        if role_split:
            wait_for_gate("preflight_ready")
            for node, role in writer_quiesce_pairs:
                snapshot = executors[node.name].running_writers(role)
                raw_services = snapshot.get("services")
                if not isinstance(raw_services, list) or not all(
                    isinstance(service, str) for service in raw_services
                ):
                    raise UpgradeError(
                        f"host {node.name} returned an invalid running writer set"
                    )
                services = exact_role_services(role, raw_services, writers_only=True)
                if api_fence_capable:
                    services = [service for service in services if service != "nano-api"]
                writer_plans[(node.name, role)] = services
                emit(
                    "writer_quiesce_planned", node=node.name, role=role,
                    services=services,
                )
            emit(
                "api_mutation_fence_planned", capable=api_fence_capable,
                node=app_nodes[0].name,
                nodes=[node.name for node in app_nodes],
                fallback_stops_api=not api_fence_capable,
            )
            if manual_fence is not None:
                if manual_deployment is None:
                    raise UpgradeError("manual backup fence requires deployment identity")
                manual_fence.begin({
                    "run_id": run_id,
                    "phase": "planned",
                    "created_at": utc_now(),
                    "inventory": manual_inventory,
                    "deployment": manual_deployment,
                    "api_fence": api_fence_capable,
                    "postgres_node": postgres_nodes[0].name,
                    "gates": [
                        {
                            "component": component.component_id,
                            "node": component.node.name,
                            "gate_run_id": component_gate_id(component),
                        }
                        for component in components
                    ],
                    "writers": [
                        {"node": node, "role": role, "services": services}
                        for (node, role), services in sorted(writer_plans.items())
                    ],
                })
            boundary("planned")
            if api_fence_capable:
                executors[postgres_nodes[0].name].set_api_mutation_fence(True, run_id)
                mutation_active = True
                emit(
                    "api_mutation_fence_activated", node=postgres_nodes[0].name,
                    owner=run_id,
                )
                pending_mutation_lease = executors[
                    postgres_nodes[0].name
                ].backup_mutation_lock(timeout)
                pending_mutation_lease.__enter__()
                mutation_lease = pending_mutation_lease
                emit("api_mutations_drained", node=postgres_nodes[0].name)
            writer_down_started = time.monotonic()
            for node, role in writer_quiesce_pairs:
                key_pair = (node.name, role)
                # Resume the exact plan even if the stop command reports an
                # error after partially stopping a multi-service app role.
                # Starting an already-running planned writer is idempotent;
                # omitting a partially stopped one is a data-availability bug.
                quiesced.append((node, role))
                result = executors[node.name].quiesce(
                    role, timeout, require_lb_hooks, writer_plans[key_pair],
                )
                emit_lb_hooks("backup:writer-quiesce", result)
                emit("writer_quiesced", node=node.name, role=role, result=result)
            boundary("stopped")
            for component in components:
                executors[component.node.name].backup_gate(
                    component_gate_id(component), "release",
                )
                emit(
                    "backup_gate_released", node=component.node.name,
                    component=component.component_id,
                )
            boundary("released")
            wait_for_gate("snapshot_ready")
            resume_errors = resume_quiesced()
            writer_down_ms = round((time.monotonic() - writer_down_started) * 1000)
            if resume_errors:
                raise UpgradeError(
                    "backup snapshots completed but writer resume failed on "
                    + "; ".join(resume_errors)
                )
            boundary("resumed")
            if mutation_lease is not None:
                mutation_lease.__exit__(None, None, None)
                mutation_lease = None
            if mutation_active:
                executors[postgres_nodes[0].name].set_api_mutation_fence(False, run_id)
                mutation_active = False
                emit(
                    "api_mutation_fence_cleared", node=postgres_nodes[0].name,
                    owner=run_id,
                )

        remote_results = [
            futures[component.component_id].result() for component in components
        ]
        for component, result in zip(components, remote_results):
            local_output = (
                backup_root / component.component_id if role_split else backup_root
            )
            returned_output = pathlib.Path(result)
            if returned_output != local_output:
                raise UpgradeError(
                    f"host {component.node.name} returned backup path {returned_output}; "
                    f"expected {local_output}"
                )
            collected = executors[component.node.name].collect_backup(
                returned_output, local_output,
            )
            backup_results.append(str(collected))
            emit(
                "component_backup_completed", node=component.node.name,
                component=component.component_id,
                backup=str(collected), remote_backup=result,
            )
        if role_split:
            recovery_set = backup_root / "recovery-set"
            arguments = [
                str(nano_cli), "recovery-set-create", "--key-file", str(key),
                "--output", str(recovery_set),
            ]
            for backup in backup_results:
                arguments.extend(["--bundle", backup])
            runner.run(arguments, timeout=7200)
            recovery = str(recovery_set)
    except BaseException as error:
        primary_error = error
    finally:
        if primary_error is not None:
            for component in components:
                if component.component_id not in gates:
                    continue
                with contextlib.suppress(BaseException):
                    executors[component.node.name].backup_gate(
                        component_gate_id(component), "abort",
                    )
        resume_errors = resume_quiesced()
        mutation_errors: list[str] = []
        if mutation_lease is not None:
            try:
                mutation_lease.__exit__(None, None, None)
            except BaseException as error:
                mutation_errors.append(f"mutation lock release: {error}")
            mutation_lease = None
        if mutation_active:
            try:
                executors[postgres_nodes[0].name].set_api_mutation_fence(False, run_id)
                mutation_active = False
            except BaseException as error:
                mutation_errors.append(f"mutation fence clear: {error}")
        if executor_pool is not None:
            executor_pool.shutdown(wait=True, cancel_futures=False)
        cleanup_errors: list[str] = []
        for component in components:
            if component.component_id not in gates:
                continue
            try:
                executors[component.node.name].backup_gate(
                    component_gate_id(component), "cleanup",
                )
            except BaseException as error:
                cleanup_errors.append(
                    f"{component.node.name}/{component.component_id}: {error}"
                )
        if (
            manual_fence is not None
            and not resume_errors
            and not mutation_errors
            and not cleanup_errors
        ):
            manual_fence.complete()
        if primary_error is not None:
            details = []
            if resume_errors:
                details.append("writer resume failed on " + "; ".join(resume_errors))
            if mutation_errors:
                details.append("API mutation recovery failed: " + "; ".join(mutation_errors))
            if cleanup_errors:
                details.append("gate cleanup failed on " + "; ".join(cleanup_errors))
            if details:
                raise UpgradeError(
                    f"backup failed ({primary_error}); " + "; ".join(details)
                ) from primary_error
            raise primary_error
        if resume_errors:
            raise UpgradeError(
                "backup completed but writer resume failed on " + "; ".join(resume_errors)
            )
        if mutation_errors:
            raise UpgradeError(
                "backup completed but API mutation recovery failed: "
                + "; ".join(mutation_errors)
            )
        if cleanup_errors:
            raise UpgradeError(
                "backup completed but snapshot gate cleanup failed on "
                + "; ".join(cleanup_errors)
            )

    return {
        "backups": backup_results,
        "recovery_set": recovery,
        "writers": [
            {"node": node, "role": role, "services": services}
            for (node, role), services in sorted(writer_plans.items())
        ],
        "writers_down_ms": writer_down_ms,
        "total_ms": round((time.monotonic() - started) * 1000),
    }


def deployment_identity(
    nodes: Sequence[Node], *, role_split: bool, remote_install_dir: pathlib.Path,
) -> dict[str, Any]:
    document = {
        "role_split": role_split,
        "remote_install_dir": str(remote_install_dir),
        "nodes": [
            {
                "name": node.name,
                "host_id": node.host_id,
                "address": node.address,
                "roles": sorted(node.roles),
                "clickhouse_shard": node.clickhouse_shard,
                "clickhouse_replica": node.clickhouse_replica,
                "keeper_id": node.keeper_id,
                "ssh_user": node.ssh_user,
                "ssh_port": node.ssh_port,
                "ssh_identity": node.ssh_identity,
            }
            for node in sorted(nodes, key=lambda item: item.name)
        ],
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "document": document}


def recover_manual_backup_fence(
    fence: ManualBackupFence,
    nodes: Sequence[Node],
    executors: dict[str, NodeExecutor],
    deployment: dict[str, Any],
    *,
    timeout: int,
    require_lb_hooks: bool,
) -> bool:
    """Recover an exact manual plan left by coordinator death."""
    if not fence.exists():
        return False
    value = fence.load()
    if value.get("deployment") != deployment:
        raise UpgradeError(
            "unrecovered manual backup fence belongs to a different inventory/deployment"
        )
    by_name = {node.name: node for node in nodes}
    run_id = safe_name(str(value.get("run_id", "")), "manual backup fence run id")
    raw_gates = value.get("gates")
    raw_writers = value.get("writers")
    if not isinstance(raw_gates, list) or not isinstance(raw_writers, list):
        raise UpgradeError("manual backup fence recovery plan is invalid")
    gates: list[tuple[NodeExecutor, str, str]] = []
    for raw in raw_gates:
        item = json_object(raw, "manual backup component gate")
        node_name = str(item.get("node", ""))
        component = safe_name(str(item.get("component", "")), "backup component")
        gate_run_id = safe_name(str(item.get("gate_run_id", "")), "backup gate run id")
        if node_name not in by_name:
            raise UpgradeError("manual backup fence names a host absent from inventory")
        gates.append((executors[node_name], gate_run_id, component))
    writers: list[tuple[NodeExecutor, str, list[str]]] = []
    for raw in raw_writers:
        item = json_object(raw, "manual backup writer plan")
        node_name = str(item.get("node", ""))
        role = str(item.get("role", ""))
        raw_services = item.get("services")
        if (
            node_name not in by_name
            or role not in by_name[node_name].roles
            or not isinstance(raw_services, list)
            or not all(isinstance(service, str) for service in raw_services)
        ):
            raise UpgradeError("manual backup fence contains an invalid writer plan")
        writers.append((
            executors[node_name], role,
            exact_role_services(role, raw_services, writers_only=True),
        ))
    postgres_name = str(value.get("postgres_node", ""))
    if postgres_name not in by_name or "postgres" not in by_name[postgres_name].roles:
        raise UpgradeError("manual backup fence PostgreSQL host is absent from inventory")

    fence.phase("recovering")
    for executor, gate_run_id, _component in gates:
        executor.backup_gate(gate_run_id, "abort")
    for executor, role, services in writers:
        executor.resume_writers(role, timeout, require_lb_hooks, services)
    if value.get("api_fence") is True:
        # NAN-5214: the fence row lives on the PostgreSQL primary, which may
        # have moved since the journal recorded `postgres_node` (failover or
        # switchover). Clear it on the current Patroni leader.
        current = resolve_pg_primary(list(by_name.values()), executors) or postgres_name
        executors[current].set_api_mutation_fence(False, run_id)

    cleanup_errors: list[str] = []
    for executor, gate_run_id, component in gates:
        deadline = time.monotonic() + min(timeout, 30)
        while True:
            try:
                executor.backup_gate(gate_run_id, "cleanup")
                break
            except BaseException as error:
                if time.monotonic() >= deadline:
                    cleanup_errors.append(f"{component}: {error}")
                    break
                time.sleep(0.25)
    if cleanup_errors:
        raise UpgradeError(
            "manual backup fence could not clean component gates: "
            + "; ".join(cleanup_errors)
        )
    fence.complete()
    return True


def stable_runtime_identity(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "version"}


def runtime_identity_checks(
    node: Node,
    actual: dict[str, Any],
    manifest: dict[str, Any],
    *,
    source_version: str,
    target_version: str,
    prepare_started: bool,
    prepared: bool,
    recorded: dict[str, Any] | None,
    role_split: bool,
) -> list[Check]:
    checks: list[Check] = []

    def exact(name: str, observed: Any, expected: Any) -> None:
        if observed == expected:
            checks.append(Check(name, True, f"{observed!r} matches", node.name))
        else:
            checks.append(Check(name, False, f"expected {expected!r}; observed {observed!r}", node.name))

    exact("identity-host", actual.get("host_name"), node.name)
    exact("identity-host-id", actual.get("host_id"), node.host_id)
    exact("identity-address", actual.get("address"), node.address)
    exact("identity-roles", actual.get("roles"), sorted(node.roles))
    exact("identity-shard", actual.get("clickhouse_shard"), node.clickhouse_shard)
    exact("identity-replica", actual.get("clickhouse_replica"), node.clickhouse_replica)
    exact("identity-keeper", actual.get("keeper_id"), node.keeper_id)
    exact("identity-edition", actual.get("edition"), manifest.get("edition"))
    if role_split:
        deployment_id = actual.get("deployment_id")
        deployment_sha = actual.get("deployment_identity_sha256")
        deployment_ok = bool(
            isinstance(deployment_id, str) and SAFE_NAME_RE.fullmatch(deployment_id)
            and isinstance(deployment_sha, str) and re.fullmatch(r"[0-9a-f]{64}", deployment_sha)
        )
        checks.append(Check(
            "identity-deployment", deployment_ok,
            "rendered deployment identity is pinned" if deployment_ok else "rendered deployment identity is invalid",
            node.name,
        ))
    if recorded is not None:
        exact("identity-journal", stable_runtime_identity(actual), stable_runtime_identity(recorded))

    observed_version = str(actual.get("version", ""))
    expected_version = target_version if prepared else source_version
    if prepared:
        exact("identity-version", observed_version, expected_version)
    elif prepare_started:
        accepted = observed_version in {source_version, target_version}
        checks.append(Check(
            "identity-prepare-version", accepted,
            f"{observed_version} is journaled source-or-target"
            if accepted else (
                f"expected journaled source {source_version} or target {target_version}; "
                f"observed {observed_version}"
            ),
            node.name,
        ))
    else:
        for item in check_version_path(observed_version, manifest, str(actual.get("edition", ""))):
            checks.append(Check(f"worker-{item.name}", item.passed, item.detail, node.name))
        exact("identity-source-version", observed_version, expected_version)
    return checks


@contextlib.contextmanager
def acquire_process_lock(install_dir: pathlib.Path) -> Iterable[None]:
    try:
        descriptor = os.open(install_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as error:
        raise UpgradeError(f"cannot open install directory for upgrade locking: {install_dir}") from error
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(descriptor)
        raise UpgradeError("another live nano upgrade/rollback process holds the install lock") from error
    try:
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def make_executors(args: argparse.Namespace, ops: LocalOps, runner: Runner) -> tuple[list[Node], dict[str, NodeExecutor], bool]:
    for kind in ("drain", "rejoin"):
        value = getattr(args, f"lb_{kind}_command", None)
        if value:
            os.environ[f"NANO_UPGRADE_LB_{kind.upper()}_COMMAND"] = value
    if args.inventory:
        nodes, _ = load_inventory(pathlib.Path(args.inventory).expanduser().resolve())
        role_split = True
    elif ops.role_env:
        raise UpgradeError("role-split upgrade requires --inventory on the coordinator")
    else:
        nodes = [Node("single", "127.0.0.1", ops.roles)]
        role_split = False
    remote_install = pathlib.Path(args.remote_install_dir or str(ops.install_dir))
    executors = {
        node.name: NodeExecutor(node, ops, runner, remote_install, ops.host_name)
        for node in nodes
    }
    return nodes, executors, role_split


def validate_backup_runtime_identities(
    nodes: Sequence[Node], executors: dict[str, NodeExecutor],
) -> dict[str, dict[str, Any]]:
    identities: dict[str, dict[str, Any]] = {}
    common: set[tuple[Any, Any, Any, Any]] = set()
    for node in nodes:
        actual = executors[node.name].runtime_identity()
        expected = {
            "host_name": node.name,
            "host_id": node.host_id,
            "address": node.address,
            "roles": sorted(node.roles),
            "clickhouse_shard": node.clickhouse_shard,
            "clickhouse_replica": node.clickhouse_replica,
            "keeper_id": node.keeper_id,
        }
        drift = [
            f"{field} expected {value!r}, observed {actual.get(field)!r}"
            for field, value in expected.items()
            if actual.get(field) != value
        ]
        if drift:
            raise UpgradeError(
                f"backup inventory/runtime identity mismatch on {node.name}: "
                + "; ".join(drift)
            )
        deployment_id = actual.get("deployment_id")
        deployment_sha = actual.get("deployment_identity_sha256")
        if not isinstance(deployment_id, str) or not SAFE_NAME_RE.fullmatch(deployment_id):
            raise UpgradeError(f"host {node.name} has an invalid deployment id")
        if not isinstance(deployment_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", deployment_sha):
            raise UpgradeError(f"host {node.name} has an invalid deployment identity digest")
        common.add((
            deployment_id, deployment_sha,
            canonical_version(str(actual.get("version", ""))),
            actual.get("edition"),
        ))
        identities[node.name] = actual
    if len(common) != 1:
        raise UpgradeError(
            "backup workers disagree on deployment identity, release version, or edition"
        )
    return identities


def backup_set_command(args: argparse.Namespace) -> int:
    install_dir = pathlib.Path(args.install_dir).expanduser().resolve()
    nano_cli = pathlib.Path(args.nano_cli or SCRIPT_DIR / "nano").expanduser().resolve()
    raw_key = pathlib.Path(args.backup_key_file).expanduser()
    if raw_key.is_symlink() or not raw_key.is_file():
        raise UpgradeError("--backup-key-file must be a regular non-symlink file")
    key = raw_key.resolve()
    runner = Runner()
    ops = LocalOps(install_dir, nano_cli, runner)
    run_id = f"backup-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    raw_backup_root = pathlib.Path(
        args.backup_output or install_dir / "backups" / run_id
    ).expanduser()
    if raw_backup_root.is_symlink() or raw_backup_root.exists():
        raise UpgradeError(f"backup output already exists: {raw_backup_root}")
    backup_root = raw_backup_root.resolve()
    if backup_root.exists():
        raise UpgradeError(f"backup output already exists: {backup_root}")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", args.clickhouse_disk):
        raise UpgradeError("--clickhouse-disk is invalid")
    epoch = utc_now()
    with acquire_process_lock(install_dir):
        nodes, executors, role_split = make_executors(args, ops, runner)
        if not role_split:
            raise UpgradeError("backup-set requires a role-split --inventory")
        remote_install = pathlib.Path(args.remote_install_dir or str(install_dir))
        normalized_deployment = deployment_identity(
            nodes, role_split=True, remote_install_dir=remote_install,
        )
        manual_fence = ManualBackupFence(install_dir)
        require_lb_hooks = sum("ingest" in node.roles for node in nodes) > 1
        recovered = recover_manual_backup_fence(
            manual_fence, nodes, executors, normalized_deployment,
            timeout=args.timeout, require_lb_hooks=require_lb_hooks,
        )
        if recovered:
            eprint("Recovered an incomplete manual backup fence before starting a new backup.")
        identities = validate_backup_runtime_identities(nodes, executors)
        # NAN-5214: the Patroni leader sorts first (see resolve_pg_primary).
        resolve_pg_primary(nodes, executors)
        postgres_nodes = node_sort(nodes, "postgres")
        if not postgres_nodes:
            raise UpgradeError("backup-set requires a PostgreSQL host")
        try:
            with executors[postgres_nodes[0].name].upgrade_lock():
                summary = create_consistent_backup_set(
                    nodes, executors,
                    key=key, backup_root=backup_root, run_id=run_id, epoch=epoch,
                    role_split=True, timeout=args.timeout,
                    require_lb_hooks=require_lb_hooks,
                    nano_cli=nano_cli, runner=runner,
                    clickhouse_disk=args.clickhouse_disk,
                    include_clickhouse_data=getattr(args, "include_clickhouse_data", False),
                    manual_fence=manual_fence,
                    manual_deployment=normalized_deployment,
                    manual_inventory=str(pathlib.Path(args.inventory).expanduser().resolve()),
                )
        except BaseException as error:
            ops.audit(run_id, "nano_backup_set", False, {"reason": str(error)})
            raise
        ops.audit(
            run_id, "nano_backup_set", True,
            {
                "inventory_hosts": sorted(identities),
                "recovery_set": summary["recovery_set"],
                "writers_down_ms": summary["writers_down_ms"],
                "total_ms": summary["total_ms"],
            },
        )
    print(f"Backup set complete: {summary['recovery_set']}")
    print(
        "Backup timing: "
        f"writers_down_ms={summary['writers_down_ms']} total_ms={summary['total_ms']}"
    )
    return 0


def abandon_command(args: argparse.Namespace) -> int:
    install_dir = pathlib.Path(args.install_dir).expanduser().resolve()
    nano_cli = pathlib.Path(args.nano_cli or SCRIPT_DIR / "nano").expanduser().resolve()
    reason = str(args.abandon_reason or "").strip()
    if not reason or len(reason) > 500 or any(ord(character) < 0x20 for character in reason):
        raise UpgradeError("--abandon-reason must be a non-empty bounded printable explanation")
    runner = Runner()
    ops = LocalOps(install_dir, nano_cli, runner)
    with acquire_process_lock(install_dir):
        journal = Journal(install_dir)
        state = journal.load_latest_incomplete()
        if state.run_id != args.abandon_incomplete:
            raise UpgradeError(
                f"latest incomplete run is {state.run_id}; explicit abandon requested "
                f"{args.abandon_incomplete}"
            )
        started = state.latest("run_started") or {}
        if not args.inventory and started.get("inventory"):
            args.inventory = str(started["inventory"])
        if not args.remote_install_dir and started.get("remote_install_dir"):
            args.remote_install_dir = str(started["remote_install_dir"])
        nodes, executors, _ = make_executors(args, ops, runner)
        # NAN-5214: the Patroni leader sorts first (see resolve_pg_primary).
        resolve_pg_primary(nodes, executors)
        postgres_nodes = node_sort(nodes, "postgres")
        if not postgres_nodes:
            raise UpgradeError("abandon requires a PostgreSQL host")
        with executors[postgres_nodes[0].name].upgrade_lock():
            journal.append(
                state, "run_abandoned", reason=reason, reconciled_by_uid=os.getuid(),
                reconciled_on=socket.gethostname(),
            )
            ops.audit(
                state.run_id, "nano_upgrade_abandon", True,
                {"reason": reason, "reconciled_by_uid": os.getuid()},
            )
    print(f"Abandoned incomplete upgrade {state.run_id} after explicit reconciliation audit.")
    return 0


def upgrade_command(args: argparse.Namespace) -> int:
    install_dir = pathlib.Path(args.install_dir).expanduser().resolve()
    nano_cli = pathlib.Path(args.nano_cli or SCRIPT_DIR / "nano").expanduser().resolve()
    runner = Runner()
    recovery_path = install_dir / ".nano-legacy-backup-recovery.json"
    if recovery_path.exists() or recovery_path.is_symlink():
        if not args.resume:
            raise UpgradeError(
                "an interrupted legacy physical backup is pending; rerun with --resume"
            )
        with acquire_process_lock(install_dir):
            recover_legacy_backup_services(install_dir, runner)
        eprint("Recovered the exact legacy service set stopped by the interrupted backup.")
    ops = LocalOps(install_dir, nano_cli, runner)
    if args.test_license_rehearsal:
        if ops.edition != "enterprise":
            raise UpgradeError("--test-license-rehearsal is enterprise-only")
        embedded_test_root_key_id(install_dir)
    with acquire_process_lock(install_dir):
        state: RunState | None = None
        temporary: tempfile.TemporaryDirectory[str] | None = None
        cluster_lease: Any | None = None
        manual_fence = ManualBackupFence(install_dir)
        try:
            journal = Journal(install_dir)
            if manual_fence.exists():
                pending_manual = manual_fence.load()
                if args.dry_run:
                    raise UpgradeError(
                        "an unrecovered manual backup fence exists; run a non-dry upgrade "
                        "or backup-set with the recorded inventory to recover it"
                    )
                if not args.inventory and pending_manual.get("inventory"):
                    args.inventory = str(pending_manual["inventory"])
                pending_deployment = pending_manual.get("deployment")
                if not args.remote_install_dir and isinstance(pending_deployment, dict):
                    document = pending_deployment.get("document")
                    if isinstance(document, dict) and document.get("remote_install_dir"):
                        args.remote_install_dir = str(document["remote_install_dir"])
            if not args.resume and not args.dry_run:
                incomplete = journal.find_latest_incomplete()
                if incomplete is not None:
                    raise UpgradeError(
                        f"incomplete upgrade journal {incomplete.run_id} exists; resume it or use "
                        "the explicit audited abandon operation"
                    )
            if args.resume:
                state = journal.load_latest_incomplete()
                started = state.latest("run_started") or {}
                recorded_bundle = started.get("bundle")
                if args.bundle and pathlib.Path(args.bundle).resolve() != pathlib.Path(str(recorded_bundle)).resolve():
                    raise UpgradeError("--resume bundle differs from the journaled bundle")
                if not args.bundle and not args.version:
                    if recorded_bundle and pathlib.Path(str(recorded_bundle)).is_file():
                        args.bundle = recorded_bundle
                    else:
                        args.version = started.get("target_version")
                if not args.inventory and started.get("inventory"):
                    args.inventory = str(started["inventory"])
                if not args.remote_install_dir and started.get("remote_install_dir"):
                    args.remote_install_dir = str(started["remote_install_dir"])
                if not args.remote_bundle and started.get("remote_bundle"):
                    args.remote_bundle = str(started["remote_bundle"])
                if not args.backup_output and started.get("backup_output"):
                    args.backup_output = str(started["backup_output"])
                # The backup scope is part of the run: `--resume` keeps the
                # original choice even when the flag is not repeated.
                if started.get("include_clickhouse_data") is True:
                    args.include_clickhouse_data = True
            bundle, temporary = bundle_for_version(args, ops, runner)
            bundle_digest = sha256_path(bundle)
            manifest = verify_manifest(
                nano_cli, bundle, runner, ops.env.get("NANO_IMAGE_PREFIX", ""),
            )
            require_bundle_digest(bundle, bundle_digest)
            target = canonical_version(str(manifest["version"]))
            mandatory_backup = enforce_signed_backup_policy(
                manifest, skip_requested=args.skip_backup_I_understand
            )
            nodes, executors, role_split = make_executors(args, ops, runner)
            preflight_backup_root = pathlib.Path(
                args.backup_output or install_dir / "backups"
            ).expanduser().resolve()
            for node in nodes:
                executors[node.name].backup_output = (
                    preflight_backup_root / node.name if role_split else preflight_backup_root
                )
                executors[node.name].include_clickhouse_data = getattr(args, "include_clickhouse_data", False)
            remote_bundle = pathlib.Path(args.remote_bundle or str(bundle))
            remote_install = pathlib.Path(args.remote_install_dir or str(ops.install_dir))
            normalized_deployment = deployment_identity(
                nodes, role_split=role_split, remote_install_dir=remote_install,
            )
            require_lb_hooks = sum("ingest" in node.roles for node in nodes) > 1
            recovered_manual = recover_manual_backup_fence(
                manual_fence, nodes, executors, normalized_deployment,
                timeout=args.timeout, require_lb_hooks=require_lb_hooks,
            )
            if recovered_manual:
                eprint(
                    "Recovered an incomplete manual backup fence before starting the upgrade."
                )
            schema_profile = getattr(
                ops, "schema_profile", ops.env.get("NANO_SCHEMA_PROFILE", "udm")
            )

            if state is not None:
                expected_digest = (state.latest("run_started") or {}).get("bundle_sha256")
                if expected_digest and bundle_digest != expected_digest:
                    raise UpgradeError("resume bundle digest differs from the journaled bundle")
            started = state.latest("run_started") if state is not None else None
            started = started or {}
            source_version = canonical_version(str(started.get("installed_version", ops.version)))
            legacy_transition = (
                getattr(ops, "legacy_layout", None) is not None
                or bool(started.get("legacy_layout"))
            )
            if legacy_transition and role_split:
                raise UpgradeError("legacy managed layout transition supports only single-node Compose")
            if legacy_transition and args.skip_backup_I_understand:
                raise UpgradeError("legacy managed layout transition never permits the backup override")
            if state is not None and started.get("deployment") != normalized_deployment:
                raise UpgradeError("normalized inventory/deployment identity differs from the journal")
            runtime_identities = {}
            with preflight_progress(f"identity of {len(nodes)} host(s)"):
                for node in nodes:
                    runtime_identities[node.name] = executors[node.name].runtime_identity()
            recorded_workers = started.get("workers", {}) if state is not None else {}
            if not isinstance(recorded_workers, dict):
                raise UpgradeError("journaled worker identities are invalid")
            checks = check_version_path(ops.version, manifest, ops.edition, resuming=state is not None)
            if legacy_transition:
                checks.append(legacy_backup_retention_check(args.backup_output, install_dir))
            for node in nodes:
                recorded = recorded_workers.get(node.name)
                checks.extend(runtime_identity_checks(
                    node, runtime_identities[node.name], manifest,
                    source_version=source_version, target_version=target,
                    prepare_started=(
                        state is not None
                        and f"prepare:{node.name}" in state.started_steps
                    ),
                    prepared=state is not None and f"prepare:{node.name}" in state.done_steps,
                    recorded=json_object(recorded, f"journal worker {node.name}") if recorded is not None else None,
                    role_split=role_split,
                ))
            if role_split:
                rendered_clusters = {
                    (
                        identity.get("deployment_id"),
                        identity.get("deployment_identity_sha256"),
                    )
                    for identity in runtime_identities.values()
                }
                checks.append(Check(
                    "identity-cluster", len(rendered_clusters) == 1,
                    "all workers share one rendered deployment identity"
                    if len(rendered_clusters) == 1 else "workers disagree on rendered deployment identity",
                    "coordinator",
                ))
            ledgers: dict[str, dict[str, list[list[str]]]] = {}
            # The recovery-set consistency fence stops cross-store app/jobs
            # writers, but deliberately leaves every ingest edge and Vector
            # process online. Ingest writes only to ClickHouse; during the
            # ClickHouse snapshot's short internal writer gate, its existing
            # disk buffers absorb traffic. Draining all ingest roles here
            # caused a measured 219-second total HAProxy outage.
            # NAN-5214: the Patroni leader sorts first (see resolve_pg_primary).
            resolve_pg_primary(nodes, executors)
            postgres_nodes = node_sort(nodes, "postgres")
            if not postgres_nodes:
                raise UpgradeError("upgrade requires a PostgreSQL host")
            if not args.dry_run:
                cluster_lease = executors[postgres_nodes[0].name].upgrade_lock()
                cluster_lease.__enter__()
                if state is None:
                    incomplete = journal.find_latest_incomplete()
                    if incomplete is not None:
                        raise UpgradeError(
                            f"incomplete upgrade journal {incomplete.run_id} appeared while acquiring "
                            "the cluster lease; resume or explicitly abandon it"
                        )
            if state is not None and any(
                event.get("event") == "step_started" and event.get("step") == "backup:consistent-set"
                for event in state.events
            ) and "backup:consistent-set" not in state.done_steps:
                node_names = {node.name for node in nodes}
                recorded_plans_by_key: dict[
                    tuple[str, str], tuple[Node, str, list[str]]
                ] = {}
                for event in state.events:
                    if event.get("event") != "writer_quiesce_planned":
                        continue
                    node_name = str(event.get("node", ""))
                    role = str(event.get("role", ""))
                    key = (node_name, role)
                    if node_name not in node_names or role not in {"app", "ingest"}:
                        raise UpgradeError(
                            "journal contains an invalid quiesced writer identity"
                        )
                    node = next(item for item in nodes if item.name == node_name)
                    if role not in node.roles:
                        raise UpgradeError(
                            "journaled quiesced writer role no longer matches inventory"
                        )
                    raw_services = event.get("services")
                    if not isinstance(raw_services, list) or not all(
                        isinstance(service, str) for service in raw_services
                    ):
                        raise UpgradeError(
                            "journal contains an invalid exact writer service set"
                        )
                    services = exact_role_services(
                        role, raw_services, writers_only=True,
                    )
                    # A retried consistent-set step can journal a newer
                    # pre-fence snapshot. Recovery must honor the latest exact
                    # set, not resurrect a service absent from the retry.
                    recorded_plans_by_key[key] = (node, role, services)
                recorded_plans = list(recorded_plans_by_key.values())
                recovered: list[dict[str, Any]] = []
                for node, role, services in recorded_plans:
                    executors[node.name].resume_writers(
                        role, args.timeout, require_lb_hooks, services,
                    )
                    recovered.append({
                        "node": node.name, "role": role, "services": services,
                    })
                if recovered:
                    journal.append(
                        state, "writers_recovered_before_resume", pairs=recovered,
                    )
                activated_index = max(
                    (
                        index for index, event in enumerate(state.events)
                        if event.get("event") == "api_mutation_fence_activated"
                    ),
                    default=-1,
                )
                cleared_index = max(
                    (
                        index for index, event in enumerate(state.events)
                        if event.get("event") == "api_mutation_fence_cleared"
                    ),
                    default=-1,
                )
                if activated_index > cleared_index:
                    executors[postgres_nodes[0].name].set_api_mutation_fence(
                        False, state.run_id,
                    )
                    journal.append(
                        state, "api_mutation_fence_recovered_before_resume",
                        node=postgres_nodes[0].name,
                    )
            # NAN-5279: the lb-hooks check drains and rejoins each host for
            # real, one host at a time. After a failed round trip (a host may
            # be left drained) no further host is drained, so a broken hook
            # can never take every app or ingest host out of the pool.
            lb_roundtrip = os.environ.get("NANO_UPGRADE_LB_HOOK_TEST", "1") != "0"
            for node in nodes:
                node_checks: list[Check] = []

                def node_summary(results: list[Check] = node_checks) -> str:
                    failed = [check.name for check in results if not check.passed]
                    passed = len(results) - len(failed)
                    return f"{passed}/{len(results)} PASS" + (
                        f"; FAIL: {', '.join(failed)}" if failed else ""
                    )

                with preflight_progress(f"checks on {node.name}", node_summary):
                    node_checks.extend(executors[node.name].preflight(
                        manifest, bundle, remote_bundle, require_lb_hooks, bundle_digest,
                        prepared=state is not None and f"prepare:{node.name}" in state.done_steps,
                        test_license_rehearsal=args.test_license_rehearsal,
                        lb_roundtrip=lb_roundtrip,
                    ))
                checks.extend(node_checks)
                if lb_roundtrip and any(
                    check.name == "lb-hooks" and not check.passed for check in node_checks
                ):
                    lb_roundtrip = False
                    eprint(
                        f"WARNING: the load-balancer hook round trip failed on {node.name}; "
                        "the remaining hosts' hooks are checked without draining them"
                    )
                try:
                    ledgers[node.name] = executors[node.name].ledger()
                except (UpgradeError, OSError, ValueError, json.JSONDecodeError) as error:
                    checks.append(Check("migration-ledger", False, str(error), node.name))
                    ledgers[node.name] = {"postgres": [], "clickhouse": []}
            if role_split:
                # NAN-5285 F1: the coordinator collects every component's
                # archive under --backup-output too.
                try:
                    checks.append(Check(
                        "backup-output", True,
                        check_backup_output_writable(preflight_backup_root),
                        f"{ops.host_name} (coordinator)",
                    ))
                except UpgradeError as error:
                    checks.append(Check(
                        "backup-output", False, str(error), f"{ops.host_name} (coordinator)",
                    ))
            checks.extend(validate_manifest_ledgers(
                manifest, list(ledgers.values()), schema_profile=schema_profile,
            ))
            baseline_event = state.latest("preflight_passed") if state is not None else None
            recorded_baseline = (
                baseline_event.get("siem_health_before")
                if baseline_event is not None else None
            )
            if isinstance(recorded_baseline, dict):
                siem_health_before = recorded_baseline
            else:
                siem_health_before = executors[postgres_nodes[0].name].siem_health()
            checks.append(Check(
                "siem-health-baseline", True,
                f"recorded pre-upgrade status {siem_health_before.get('status', 'unknown')}",
                postgres_nodes[0].name,
            ))
            # NAN-5279 F1: preview each host's re-rendered configuration
            # (the upgrade publishes exactly this render after `prepare`).
            inventory_text = (
                pathlib.Path(args.inventory).expanduser().resolve().read_text(encoding="utf-8")
                if role_split and args.inventory else ""
            )
            render_diffs: list[tuple[str, str]] = []
            if role_split:
                for node in nodes:
                    try:
                        with preflight_progress(f"config render preview on {node.name}"):
                            preview = executors[node.name].render_config(inventory_text, False)
                    except (UpgradeError, OSError, ValueError, json.JSONDecodeError) as error:
                        checks.append(Check("config-render", False, str(error), node.name))
                        continue
                    changed = [str(item) for item in preview.get("changed", [])]
                    detail = (
                        f"{len(changed)} rendered file(s)/setting(s) change: "
                        + ", ".join(changed[:8]) + (" ..." if len(changed) > 8 else "")
                        if changed else "rendered configuration is unchanged"
                    )
                    checks.append(Check("config-render", True, detail, node.name))
                    if preview.get("diff"):
                        render_diffs.append((node.name, str(preview["diff"])))
            print_checks(checks)
            for host, diff in render_diffs:
                print(f"\n--- rendered configuration diff for {host} (applied by the upgrade) ---")
                print(diff)
            if any(not check.passed for check in checks):
                raise UpgradeError("preflight failed; no installation state was changed")
            if args.dry_run:
                print("Dry run complete: verification and all read-only preflight checks passed.")
                return 0

            if state is None:
                run_id = f"upgrade-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
                state = journal.create(run_id, {
                    "bundle": str(bundle), "bundle_sha256": bundle_digest,
                    "installed_version": ops.version, "target_version": target, "edition": ops.edition,
                    "manifest": manifest, "inventory": str(args.inventory or ""),
                    "remote_install_dir": str(remote_install), "remote_bundle": str(remote_bundle),
                    "deployment": normalized_deployment, "workers": runtime_identities,
                    "backup_skip_override": args.skip_backup_I_understand,
                    "legacy_layout": legacy_transition,
                    "backup_output": str(args.backup_output or ""),
                    "include_clickhouse_data": bool(getattr(args, "include_clickhouse_data", False)),
                })
                journal.append(
                    state, "preflight_passed",
                    checks=[check.as_dict() for check in checks], ledger_before=ledgers,
                    siem_health_before=siem_health_before,
                )
            else:
                started = state.latest("run_started") or {}
                if started.get("target_version") != target or started.get("edition") != ops.edition:
                    raise UpgradeError("resume target does not match the journal")
                run_id = state.run_id

            backup_root = pathlib.Path(
                args.backup_output or install_dir / "backups" / run_id
            ).expanduser().resolve()
            backup_results: list[str] = []
            recovery_set_result = ""
            backup_nodes = backup_nodes_for(nodes, role_split, getattr(args, "include_clickhouse_data", False))
            skipped_before = "backup-skipped" in state.done_steps
            if mandatory_backup:
                enforce_signed_backup_policy(manifest, journal_skipped=skipped_before)
            skip_backup = args.skip_backup_I_understand or skipped_before
            if skip_backup:
                eprint("WARNING: BACKUP SKIPPED BY EXPLICIT OPERATOR OVERRIDE --skip-backup-I-understand")
                run_step(journal, state, "backup-skipped", lambda: {"override": True})
            else:
                expected_backup_steps = {
                    "backup:consistent-set" if role_split
                    else f"backup:{backup_nodes[0].name}"
                }
                raw_key = args.backup_key_file or os.environ.get("NANO_BACKUP_KEY_FILE", "")
                if not expected_backup_steps <= state.done_steps and not raw_key:
                    raise UpgradeError("backup is mandatory; provide --backup-key-file or NANO_BACKUP_KEY_FILE")
                key = pathlib.Path(raw_key).expanduser().resolve() if raw_key else pathlib.Path("/already-completed")
                epoch_result = json_object(
                    run_step(
                        journal, state, "backup:quiesce-epoch",
                        lambda: {"epoch": utc_now()},
                    ),
                    "journaled backup quiesce epoch",
                )
                epoch = str(epoch_result.get("epoch", ""))
                if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", epoch):
                    raise UpgradeError("journaled backup quiesce epoch is invalid")

                attempts = 1 + sum(
                    event.get("event") == "step_started"
                    and event.get("step") == "backup:consistent-set"
                    for event in state.events
                )
                attempt_root = (
                    backup_root if attempts == 1
                    else backup_root / f"retry-{attempts}"
                )

                def create_backups() -> dict[str, Any]:
                    return create_consistent_backup_set(
                        nodes, executors,
                        key=key, backup_root=attempt_root, run_id=run_id,
                        epoch=epoch, role_split=role_split, timeout=args.timeout,
                        require_lb_hooks=require_lb_hooks,
                        nano_cli=nano_cli, runner=runner,
                        clickhouse_disk=(
                            "default" if legacy_transition else "backups"
                        ),
                        # A coordinator SIGKILL can leave the prior workers
                        # waiting on their old gates. A retry uses a distinct
                        # private gate while retaining the journaled recovery
                        # set ID and common epoch, so it cannot collide with
                        # or release an abandoned attempt.
                        gate_run_id=f"{run_id}-attempt-{attempts}",
                        include_clickhouse_data=getattr(args, "include_clickhouse_data", False),
                        record_event=lambda event, **fields: journal.append(
                            state, event, **fields,
                        ),
                    )

                if role_split:
                    backup_summary = run_step(journal, state, "backup:consistent-set", create_backups)
                    backup_summary_object = json_object(backup_summary, "backup summary")
                    backup_results = [str(item) for item in backup_summary_object.get("backups", [])]
                    recovery_set_result = str(backup_summary_object.get("recovery_set", ""))
                else:
                    backup_summary = run_step(
                        journal, state, f"backup:{backup_nodes[0].name}", create_backups,
                    )
                    backup_summary_object = json_object(backup_summary, "backup summary")
                    backup_results = [
                        str(item) for item in backup_summary_object.get("backups", [])
                    ]

            prepared: set[str] = set()

            def ensure_prepared(node: Node) -> None:
                """Load the target images, then (role-split) publish the
                host's re-rendered configuration before any of its roles roll."""
                if node.name in prepared:
                    return
                run_step(
                    journal, state, f"prepare:{node.name}",
                    lambda: executors[node.name].prepare(
                        bundle, remote_bundle, source_version, target, run_id,
                        bundle_digest,
                    ),
                )
                if role_split:
                    def render() -> dict[str, Any]:
                        result = executors[node.name].render_config(
                            inventory_text, True, run_id,
                        )
                        # The journal keeps what changed, not the diff text.
                        return {key: value for key, value in result.items() if key != "diff"}

                    run_step(journal, state, f"render-config:{node.name}", render)
                prepared.add(node.name)

            for role in ROLE_ORDER:
                if role == "migration":
                    app_nodes = node_sort(nodes, "app")
                    # NAN-5214: the migration lock must be held on the leader.
                    resolve_pg_primary(nodes, executors)
                    postgres_nodes = node_sort(nodes, "postgres")
                    if not app_nodes or not postgres_nodes:
                        raise UpgradeError("migration requires an app host and a PostgreSQL host")
                    # NAN-5213: migrations run once, from the first app host;
                    # the migrator also holds a cluster-wide PostgreSQL lock.
                    app_node = app_nodes[0]
                    postgres_node = postgres_nodes[0]
                    ensure_prepared(app_node)

                    def migrate() -> dict[str, Any]:
                        with executors[postgres_node.name].migration_lock():
                            return executors[app_node.name].rollout("migration", args.timeout, require_lb_hooks)

                    run_step(journal, state, f"rollout:migration:{app_node.name}", migrate)
                    continue
                selected_role = "app" if role == "migration" else role
                selected = node_sort(nodes, selected_role)
                if role == "postgres" and len(selected) > 1:
                    # NAN-5214: roll Patroni members replicas first, then move
                    # leadership to an upgraded replica and roll the old
                    # leader. The cluster lease is a session on the leader,
                    # which the switchover ends, so it is re-taken after.
                    if cluster_lease is not None:
                        cluster_lease.__exit__(None, None, None)
                        cluster_lease = None
                    def prepare_member(node: Node) -> None:
                        ensure_prepared(node)

                    roll_postgres_members(
                        nodes, executors, journal, state, "rollout", args.timeout,
                        lambda node: executors[node.name].rollout("postgres", args.timeout, require_lb_hooks),
                        before=prepare_member,
                    )
                    if not args.dry_run:
                        cluster_lease = executors[node_sort(nodes, "postgres")[0].name].upgrade_lock()
                        cluster_lease.__enter__()
                    continue
                for node in selected:
                    ensure_prepared(node)
                    run_step(
                        journal, state, f"rollout:{role}:{node.name}",
                        lambda node=node, role=role: executors[node.name].rollout(role, args.timeout, require_lb_hooks),
                    )

            ledger_after = {node.name: executors[node.name].ledger() for node in nodes}
            ledger_checks = validate_manifest_ledgers(
                manifest, list(ledger_after.values()), require_complete=True, schema_profile=schema_profile,
            )
            if any(not check.passed for check in ledger_checks):
                raise UpgradeError("post-migration ledger does not match the verified bundle manifest")
            post_results = []
            for node in nodes:
                if node.roles & {"app", "ingest", "postgres", "clickhouse"}:
                    post_results.append(run_step(
                        journal, state, f"post-verify:{node.name}",
                        lambda node=node: executors[node.name].post_verify(target, args.timeout),
                    ))
            previous_smoke = next(
                (
                    event.get("result", {}).get("marker")
                    for event in reversed(state.events)
                    if event.get("event") == "step_done" and event.get("step") == "post-verify:smoke-ingest"
                ),
                None,
            )
            marker = str(previous_smoke or f"nano-upgrade-{uuid.uuid4()}")
            ingest_node = node_sort(nodes, "ingest")[0]
            clickhouse_node = node_sort(nodes, "clickhouse")[0]
            postgres_node = node_sort(nodes, "postgres")[0]
            smoke_ingest = run_step(
                journal, state, "post-verify:smoke-ingest",
                lambda: executors[ingest_node.name].smoke_ingest(marker),
            )
            smoke_search = run_step(
                journal, state, "post-verify:smoke-search",
                lambda: executors[clickhouse_node.name].smoke_search(marker, args.timeout),
            )
            def verify_siem_health_regression() -> dict[str, Any]:
                # NAN-5279 F5: compare against a report generated after the
                # application rollout began, never the baseline report again.
                rollout_started = next(
                    (
                        str(event.get("at"))
                        for event in state.events
                        if event.get("event") == "step_started"
                        and str(event.get("step", "")).startswith(("rollout:migration:", "rollout:app:"))
                    ),
                    None,
                )
                after, fresh = wait_for_fresh_siem_health(
                    executors[postgres_node.name].siem_health,
                    siem_health_before, rollout_started,
                    env_seconds("NANO_UPGRADE_SIEM_HEALTH_WAIT_SECONDS", 600),
                )
                if not fresh:
                    eprint(
                        "WARNING: no SIEM Health report was generated after the upgrade within "
                        "the wait (NANO_UPGRADE_SIEM_HEALTH_WAIT_SECONDS); the regression gate "
                        "was NOT evaluated. Check Settings > SIEM Health once its next report runs."
                    )
                    return {
                        "before": siem_health_before, "after": after, "regressions": [],
                        "override": False, "compared": False,
                        "reason": "no post-upgrade SIEM Health report within the wait",
                    }
                result = gate_siem_health_regressions(
                    siem_health_before, after, args.allow_siem_health_regression,
                )
                result["compared"] = True
                if result["override"]:
                    details = {
                        "reason": args.allow_siem_health_regression,
                        "regressions": result["regressions"],
                        "before_report": siem_health_before.get("id"),
                        "after_report": after.get("id"),
                    }
                    journal.append(state, "siem_health_regression_overridden", **details)
                    ops.audit(
                        state.run_id, "nano_upgrade_siem_health_override", True, details,
                    )
                return result

            siem_health = run_step(
                journal, state, "post-verify:siem-health",
                verify_siem_health_regression,
            )
            installed_version = str(
                (state.latest("run_started") or {}).get("installed_version", ops.version)
            )
            journal.append(
                state, "run_completed", ledger_after=ledger_after, post_verify=post_results,
                smoke_ingest=smoke_ingest, smoke_search=smoke_search, siem_health=siem_health,
                backups=backup_results, recovery_set=recovery_set_result,
            )
            ops.audit(
                run_id, "nano_upgrade", True,
                {
                    "from": installed_version, "to": target,
                    "backup_skipped": skip_backup,
                    "siem_health_regression_override": bool(
                        siem_health.get("override")
                    ),
                },
            )
            print(f"Upgrade complete: {installed_version} -> {target}")
            print(f"Journal: {state.journal}")
            return 0
        except BaseException as error:
            if state is not None:
                with contextlib.suppress(Exception):
                    Journal(install_dir).append(state, "run_failed", reason=str(error), resume=f"scripts/nano upgrade --bundle <bundle> --resume")
                    ops.audit(state.run_id, "nano_upgrade", False, {"reason": str(error)})
                eprint(f"Upgrade stopped safely. Journal: {state.journal}")
                eprint("After correcting the reported cause, run: scripts/nano upgrade --bundle <same-bundle> --resume")
            raise
        finally:
            if cluster_lease is not None:
                cluster_lease.__exit__(None, None, None)
            if temporary is not None:
                temporary.cleanup()


def ledgers_equal(before: Any, after: Any) -> bool:
    return before == after


def ledger_map(value: Any, nodes: Sequence[Node], label: str) -> dict[str, Any]:
    if isinstance(value, dict):
        if set(value) != {node.name for node in nodes}:
            raise UpgradeError(f"{label} does not cover the pinned inventory")
        return value
    if isinstance(value, list) and len(value) == len(nodes):
        if len(nodes) != len(value):  # zip strict mode needs Python 3.10
            raise UpgradeError("parallel worker results do not match the host list")
        return {node.name: item for node, item in zip(nodes, value)}
    raise UpgradeError(f"{label} is not an all-node ledger snapshot")


def rollback_command(args: argparse.Namespace) -> int:
    install_dir = pathlib.Path(args.install_dir).expanduser().resolve()
    nano_cli = pathlib.Path(args.nano_cli or SCRIPT_DIR / "nano").expanduser().resolve()
    runner = Runner()
    ops = LocalOps(install_dir, nano_cli, runner)
    with acquire_process_lock(install_dir):
        journal = Journal(install_dir)
        state = journal.load_latest_completed()
        started = state.latest("run_started") or {}
        completed = state.latest("run_completed") or {}
        previous = canonical_version(str(started.get("installed_version", "")))
        target = canonical_version(str(started.get("target_version", "")))
        if not args.inventory and started.get("inventory"):
            args.inventory = str(started["inventory"])
        if not args.remote_install_dir and started.get("remote_install_dir"):
            args.remote_install_dir = str(started["remote_install_dir"])
        nodes, executors, role_split = make_executors(args, ops, runner)
        remote_install = pathlib.Path(args.remote_install_dir or str(ops.install_dir))
        pinned_deployment = deployment_identity(
            nodes, role_split=role_split, remote_install_dir=remote_install,
        )
        if started.get("deployment") != pinned_deployment:
            raise UpgradeError("rollback inventory/deployment identity differs from the upgrade journal")
        recorded_workers = started.get("workers")
        if not isinstance(recorded_workers, dict) or set(recorded_workers) != {node.name for node in nodes}:
            raise UpgradeError("rollback journal does not contain every pinned worker identity")

        checks: list[Check] = []
        live_identities: dict[str, dict[str, Any]] = {}
        for node in nodes:
            identity = executors[node.name].runtime_identity()
            live_identities[node.name] = identity
            recorded = json_object(recorded_workers[node.name], f"journal worker {node.name}")
            stable_match = stable_runtime_identity(identity) == stable_runtime_identity(recorded)
            checks.append(Check(
                "rollback-identity", stable_match,
                "worker identity matches the upgrade journal"
                if stable_match else "worker identity differs from the upgrade journal",
                node.name,
            ))
            current = str(identity.get("version", ""))
            checks.append(Check(
                "rollback-version", current in {target, previous},
                f"current {current}; expected {target} or idempotent {previous}", node.name,
            ))
            checks.extend(executors[node.name].rollback_preflight(previous, target))

        live_ledgers = {node.name: executors[node.name].ledger() for node in nodes}
        before_ledgers = ledger_map(
            (state.latest("preflight_passed") or {}).get("ledger_before"),
            nodes, "pre-upgrade ledger snapshot",
        )
        completed_ledgers = ledger_map(
            completed.get("ledger_after"), nodes, "completed-upgrade ledger snapshot",
        )
        live_matches_completed = ledgers_equal(live_ledgers, completed_ledgers)
        checks.append(Check(
            "rollback-live-ledger", live_matches_completed,
            "live all-node ledgers match the completed upgrade"
            if live_matches_completed else "live ledgers changed after the completed upgrade",
            "coordinator",
        ))
        print_checks(checks)
        backups = completed.get("backups") or []
        legacy_layout = bool(started.get("legacy_layout"))
        compatible = (
            live_matches_completed
            and ledgers_equal(before_ledgers, live_ledgers)
            and not legacy_layout
        )
        if not compatible:
            key = args.backup_key_file or "$NANO_BACKUP_KEY_FILE"
            if legacy_layout:
                eprint(
                    "Rollback refused: this run transitioned a signed legacy layout. "
                    "Return with the journal-bound backup and explicit legacy layout restore."
                )
            else:
                eprint(
                    "Rollback refused: live all-node migration ledgers are not exactly the "
                    "pre-upgrade schema. Signed bundle schema v1 declares no image-rollback exception."
                )
            recovery_set = str(completed.get("recovery_set") or "")
            if backups and recovery_set:
                eprint("Restore every role-split component with the signed recovery set:")
                for backup in backups:
                    eprint(
                        f"scripts/nano restore --key-file {key} --from {backup} "
                        f"--recovery-set {recovery_set} --force"
                    )
            elif backups:
                layout_option = " --restore-layout legacy" if legacy_layout else ""
                eprint(
                    f"Restore the mandatory backup instead: scripts/nano restore --key-file {key} "
                    f"--from {backups[0]} --force{layout_option}"
                )
            else:
                eprint("No upgrade backup was recorded; restore the separately proven backup used for the override.")
            return 3
        if any(not check.passed for check in checks):
            raise UpgradeError("rollback preflight failed; no installation state was changed")
        # NAN-5214: the Patroni leader sorts first (see resolve_pg_primary).
        resolve_pg_primary(nodes, executors)
        postgres_nodes = node_sort(nodes, "postgres")
        if not postgres_nodes:
            raise UpgradeError("rollback requires a PostgreSQL host")
        require_lb_hooks = sum("ingest" in node.roles for node in nodes) > 1
        try:
            with executors[postgres_nodes[0].name].upgrade_lock():
                if state.latest("rollback_started") is None:
                    journal.append(state, "rollback_started", from_version=target, to_version=previous)
                for role in reversed(ROLE_ORDER):
                    if role == "migration":
                        continue
                    if role == "postgres" and len(node_sort(nodes, role)) > 1:
                        roll_postgres_members(
                            nodes, executors, journal, state, "rollback", args.timeout,
                            lambda node: executors[node.name].rollback(
                                "postgres", previous, target, args.timeout, require_lb_hooks,
                                run_id=state.run_id,
                            ),
                        )
                        continue
                    for node in reversed(node_sort(nodes, role)):
                        run_step(
                            journal, state, f"rollback:{role}:{node.name}",
                            lambda node=node, role=role: executors[node.name].rollback(
                                role, previous, target, args.timeout, require_lb_hooks,
                                run_id=state.run_id,
                            ),
                        )
                for node in nodes:
                    run_step(
                        journal, state, f"rollback-post-verify:{node.name}",
                        lambda node=node: executors[node.name].post_verify(previous, args.timeout),
                    )
                journal.append(
                    state, "rollback_completed", version=previous,
                    live_ledgers=live_ledgers, workers=live_identities,
                )
                ops.audit(state.run_id, "nano_rollback", True, {"from": target, "to": previous})
                print(f"Rollback complete: {target} -> {previous}")
                return 0
        except BaseException as error:
            journal.append(state, "rollback_failed", reason=str(error))
            ops.audit(state.run_id, "nano_rollback", False, {"reason": str(error)})
            raise


def worker_command(args: argparse.Namespace) -> int:
    install_dir = pathlib.Path(args.install_dir).expanduser().resolve()
    nano_cli = install_dir / "scripts/nano"
    runner = Runner()
    for kind in ("drain", "rejoin"):
        value = getattr(args, f"lb_{kind}_command", None)
        if value:
            os.environ[f"NANO_UPGRADE_LB_{kind.upper()}_COMMAND"] = value
    ops = LocalOps(install_dir, nano_cli, runner)
    bundle = pathlib.Path(args.bundle).expanduser().resolve() if args.bundle else None
    if args.worker_action == "identity":
        value: Any = ops.runtime_identity()
    elif args.worker_action == "preflight":
        assert bundle is not None
        if args.backup_output:
            ops.backup_output = pathlib.Path(args.backup_output).expanduser()
        ops.include_clickhouse_data = getattr(args, "include_clickhouse_data", False)
        require_bundle_digest(bundle, args.expected_bundle_sha256)
        manifest = verify_manifest(
            nano_cli, bundle, runner, ops.env.get("NANO_IMAGE_PREFIX", ""),
        )
        require_bundle_digest(bundle, args.expected_bundle_sha256)
        value = [
            check.as_dict()
            for check in ops.preflight(
                manifest, bundle, args.require_lb_hooks, args.prepared,
                args.test_license_rehearsal, not args.no_lb_roundtrip,
            )
        ]
    elif args.worker_action == "ledger":
        value = ops.ledger()
    elif args.worker_action == "pg-ha-status":
        value = ops.pg_ha_status()
    elif args.worker_action == "pg-switchover":
        value = ops.pg_switchover(safe_name(args.candidate, "switchover candidate"), args.timeout)
    elif args.worker_action == "backup-gate":
        value = ops.backup_gate(args.run_id, args.gate_action)
    elif args.worker_action == "api-mutation-capability":
        value = ops.api_mutation_fence_capable()
    elif args.worker_action == "api-mutation-fence":
        value = ops.set_api_mutation_fence(
            args.fence_action == "activate", args.run_id,
        )
    elif args.worker_action == "backup":
        value = {"backup": ops.backup(
            pathlib.Path(args.backup_key_file), pathlib.Path(args.backup_output),
            args.run_id, args.quiesce_epoch, True,
            pathlib.Path(args.snapshot_gate) if args.snapshot_gate else None,
            args.clickhouse_disk, args.component or None,
            getattr(args, "include_clickhouse_data", False),
        )}
    elif args.worker_action == "running-writers":
        value = ops.running_writers(args.role)
    elif args.worker_action == "quiesce":
        value = ops.quiesce(
            args.role, args.timeout, args.require_lb_hooks, services=args.service,
        )
    elif args.worker_action == "resume-writers":
        value = ops.resume_writers(
            args.role, args.timeout, args.require_lb_hooks, services=args.service,
        )
    elif args.worker_action == "hold-advisory-lock":
        with PgMigrationLock(
            ops, args.lock_kind, acquire_timeout=args.timeout,
        ):
            marker_kind = args.lock_kind.replace("-", "_").upper()
            print(f"__NANO_REMOTE_{marker_kind}_LOCKED__", flush=True)
            sys.stdin.read()
        return 0
    elif args.worker_action == "prepare":
        assert bundle is not None
        require_bundle_digest(bundle, args.expected_bundle_sha256)
        manifest = verify_manifest(
            nano_cli, bundle, runner, ops.env.get("NANO_IMAGE_PREFIX", ""),
        )
        require_bundle_digest(bundle, args.expected_bundle_sha256)
        target = canonical_version(args.target)
        source = canonical_version(args.source)
        if canonical_version(str(manifest.get("version", ""))) != target:
            raise UpgradeError("worker bundle version differs from the coordinator target")
        value = ops.prepare(
            bundle, source, target, args.run_id, args.expected_bundle_sha256,
        )
    elif args.worker_action == "render-config":
        value = ops.render_config(sys.stdin.read(), args.apply, args.run_id)
    elif args.worker_action == "rollout":
        value = ops.rollout(args.role, args.timeout, args.require_lb_hooks)
    elif args.worker_action == "post-verify":
        value = ops.post_verify(canonical_version(args.target), args.timeout)
    elif args.worker_action == "smoke-ingest":
        value = ops.smoke_ingest(safe_name(args.marker, "smoke marker"))
    elif args.worker_action == "smoke-search":
        value = ops.smoke_search(safe_name(args.marker, "smoke marker"), args.timeout)
    elif args.worker_action == "siem-health":
        value = ops.siem_health()
    elif args.worker_action == "rollback-preflight":
        value = [
            check.as_dict()
            for check in ops.rollback_preflight(
                canonical_version(args.previous), canonical_version(args.target),
            )
        ]
    elif args.worker_action == "rollback":
        value = ops.rollback_role(
            args.role, canonical_version(args.previous), canonical_version(args.target),
            args.timeout, args.require_lb_hooks, args.run_id,
        )
    else:
        raise UpgradeError("unsupported worker action")
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="scripts/nano")
    commands = root.add_subparsers(dest="command", required=True)
    backup_set = commands.add_parser("backup-set")
    backup_set.add_argument("--inventory", required=True)
    backup_set.add_argument("--backup-key-file", required=True)
    backup_set.add_argument("--backup-output")
    backup_set.add_argument("--clickhouse-disk", default="backups")
    backup_set.add_argument(
        "--install-dir", default=os.environ.get("NANO_INSTALL_DIR", str(DEFAULT_INSTALL_DIR)),
    )
    backup_set.add_argument(
        "--include-clickhouse-data", "--include-events", dest="include_clickhouse_data",
        action="store_true",
        help="also back up every ClickHouse table (default: PostgreSQL and configuration only)",
    )
    backup_set.add_argument("--remote-install-dir")
    backup_set.add_argument("--lb-drain-command")
    backup_set.add_argument("--lb-rejoin-command")
    backup_set.add_argument("--timeout", type=int, default=600)
    backup_set.add_argument("--nano-cli", help=argparse.SUPPRESS)

    upgrade = commands.add_parser("upgrade")
    source = upgrade.add_mutually_exclusive_group(required=False)
    source.add_argument("--bundle")
    source.add_argument("--version")
    upgrade.add_argument("--dry-run", action="store_true")
    upgrade.add_argument("--skip-backup-I-understand", dest="skip_backup_I_understand", action="store_true")
    upgrade.add_argument("--resume", action="store_true")
    upgrade.add_argument("--abandon-incomplete", metavar="RUN_ID")
    upgrade.add_argument("--abandon-reason")
    upgrade.add_argument("--install-dir", default=os.environ.get("NANO_INSTALL_DIR", str(DEFAULT_INSTALL_DIR)))
    upgrade.add_argument("--inventory")
    upgrade.add_argument("--remote-install-dir")
    upgrade.add_argument("--remote-bundle")
    upgrade.add_argument("--backup-key-file")
    upgrade.add_argument("--backup-output")
    upgrade.add_argument(
        "--include-clickhouse-data", "--include-events", dest="include_clickhouse_data",
        action="store_true",
        help="also back up every ClickHouse table (default: PostgreSQL and configuration only)",
    )
    upgrade.add_argument("--lb-drain-command")
    upgrade.add_argument("--lb-rejoin-command")
    upgrade.add_argument(
        "--allow-siem-health-regression", metavar="REASON",
        help="audited emergency override for new post-upgrade critical SIEM Health findings",
    )
    upgrade.add_argument("--timeout", type=int, default=600)
    upgrade.add_argument("--nano-cli", help=argparse.SUPPRESS)
    upgrade.add_argument(
        "--test-license-rehearsal", action="store_true",
        help=(
            "TEST-root compose bundles only: allow a disposable lab to rehearse "
            "upgrade preflight without writing C05 state"
        ),
    )

    rollback = commands.add_parser("rollback")
    rollback.add_argument("--install-dir", default=os.environ.get("NANO_INSTALL_DIR", str(DEFAULT_INSTALL_DIR)))
    rollback.add_argument("--inventory")
    rollback.add_argument("--remote-install-dir")
    rollback.add_argument("--backup-key-file")
    rollback.add_argument("--lb-drain-command")
    rollback.add_argument("--lb-rejoin-command")
    rollback.add_argument("--timeout", type=int, default=600)
    rollback.add_argument("--nano-cli", help=argparse.SUPPRESS)

    worker = commands.add_parser("_upgrade-worker", help=argparse.SUPPRESS)
    worker.add_argument("worker_action", choices=("identity", "preflight", "ledger", "pg-ha-status", "pg-switchover", "backup-gate", "api-mutation-capability", "api-mutation-fence", "backup", "running-writers", "quiesce", "resume-writers", "hold-advisory-lock", "prepare", "render-config", "rollout", "post-verify", "smoke-ingest", "smoke-search", "siem-health", "rollback-preflight", "rollback"))
    worker.add_argument("--install-dir", required=True)
    worker.add_argument("--candidate", default="")
    worker.add_argument("--bundle")
    worker.add_argument("--expected-bundle-sha256", default="")
    worker.add_argument("--target", default="")
    worker.add_argument("--source", default="")
    worker.add_argument("--previous", default="")
    worker.add_argument("--run-id", default="")
    worker.add_argument("--quiesce-epoch", default="")
    worker.add_argument("--snapshot-gate", default="")
    worker.add_argument("--component", choices=("postgres", "clickhouse"), default="")
    worker.add_argument(
        "--gate-action", choices=("prepare", "status", "release", "abort", "cleanup"),
        default="status",
    )
    worker.add_argument(
        "--fence-action", choices=("activate", "clear"), default="clear",
    )
    worker.add_argument("--backup-key-file", default="")
    worker.add_argument("--backup-output", default="")
    worker.add_argument("--clickhouse-disk", default="backups")
    worker.add_argument("--include-clickhouse-data", action="store_true")
    worker.add_argument("--role", default="")
    worker.add_argument("--service", action="append", default=[])
    worker.add_argument(
        "--lock-kind", choices=("upgrade", "migration", "backup-mutation"),
        default="migration",
    )
    worker.add_argument("--marker", default="")
    worker.add_argument("--require-lb-hooks", action="store_true")
    worker.add_argument("--prepared", action="store_true")
    worker.add_argument("--apply", action="store_true")
    worker.add_argument("--no-lb-roundtrip", action="store_true")
    worker.add_argument("--test-license-rehearsal", action="store_true")
    worker.add_argument("--lb-drain-command")
    worker.add_argument("--lb-rejoin-command")
    worker.add_argument("--timeout", type=int, default=600)
    return root


def main() -> int:
    # NAN-5279: line-buffer stdout even when run without -u (scripts/nano
    # passes -u), so a non-TTY caller sees each result line as it is printed.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(line_buffering=True)
    args = parser().parse_args()
    if args.command == "backup-set":
        if args.timeout < 1:
            raise UpgradeError("--timeout must be positive")
        return backup_set_command(args)
    if args.command == "upgrade":
        if args.abandon_incomplete:
            if args.bundle or args.version or args.resume or args.dry_run:
                raise UpgradeError("--abandon-incomplete cannot be combined with an upgrade source, resume, or dry-run")
            return abandon_command(args)
        if args.abandon_reason:
            raise UpgradeError("--abandon-reason requires --abandon-incomplete")
        if not (args.bundle or args.version or args.resume):
            raise UpgradeError("upgrade requires --bundle, --version, or --resume")
        if args.timeout < 1:
            raise UpgradeError("--timeout must be positive")
        if args.allow_siem_health_regression is not None:
            reason = args.allow_siem_health_regression.strip()
            if not reason or len(reason) > 500 or any(ord(char) < 32 for char in reason):
                raise UpgradeError(
                    "--allow-siem-health-regression requires a 1-500 character audit reason"
                )
            args.allow_siem_health_regression = reason
        return upgrade_command(args)
    if args.command == "rollback":
        return rollback_command(args)
    return worker_command(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except UpgradeError as error:
        eprint(f"nano: {error}")
        raise SystemExit(1)
