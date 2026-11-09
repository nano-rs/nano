#!/usr/bin/env python3
"""Build, verify, and load nano release bundles (NAN-5000).

The verification path is deliberately offline: the only trust roots are the
public keys compiled into this file, and image payloads are streamed instead
of extracted. Production signing is available only to the private builder
entry point and delegates to GCP KMS through gcloud.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence


SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SIGNATURE_BYTES = 4096
MAX_MEMBERS = 4096
MAX_TEXT = 1024
MIGRATION_GROUPS = (
    "postgres",
    "clickhouse",
    "postgres_enterprise",
    "clickhouse_enterprise",
)
ROLES = frozenset({"app", "ingest", "clickhouse", "keeper", "postgres"})
RESOURCE_ROLES = ROLES | {"tenzir"}
ARCHITECTURES = frozenset({"amd64", "arm64"})

_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_STABLE_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_CHECKSUM = re.compile(r"^sha(?:256:[0-9a-f]{64}|384:[0-9a-f]{96})$")
_DOCKER_CONFIG = re.compile(
    r"^(?:blobs/sha256/([0-9a-f]{64})|([0-9a-f]{64})\.json)$"
)
_ARCHIVE_REF = re.compile(
    r"^nano-bundle\.invalid/([A-Za-z0-9][A-Za-z0-9._-]{0,127}):([0-9a-f]{32})$"
)


class BundleError(RuntimeError):
    """A safe, user-facing bundle failure."""


@dataclass(frozen=True)
class Root:
    key_id: str
    public_key_pem: bytes


# Ceremony 2026-11-05: projects/nano-rs/locations/global/keyRings/
# nano-release/cryptoKeys/release-signing-v1, EC_SIGN_ED25519, SOFTWARE.
# Rotation is additive: append the next public root and keep the old root until
# every still-supported bundle has aged out.
PRODUCTION_ROOTS: tuple[Root, ...] = (
    Root(
        key_id="release-signing-v1",
        public_key_pem=(
            b"-----BEGIN PUBLIC KEY-----\n"
            b"MCowBQYDK2VwAyEAQYUuvZPcBwXLcQgxCcZi+9S2CewrhdPy9ylKDkVjfIE=\n"
            b"-----END PUBLIC KEY-----\n"
        ),
    ),
)


def _load_embedded_lab_roots() -> tuple[Root, ...]:
    """Load the compose-bundle build product, never a runtime environment flag."""
    path = Path(__file__).with_name("nano_bundle_embedded_lab_root.json")
    try:
        raw = path.read_bytes()
        value = _unique_json(raw, path.name)
    except OSError as exc:
        raise BundleError(f"release verifier is missing embedded-root metadata: {path}") from exc
    if value is None:
        return ()
    if not isinstance(value, dict):
        raise BundleError("embedded TEST root metadata must be null or an object")
    _exact_keys(value, {"build_kind", "key_id", "public_key_pem"}, "embedded TEST root")
    if value["build_kind"] != "non-release-test":
        raise BundleError("embedded TEST root has an invalid build kind")
    key_id = _text(value["key_id"], "embedded TEST root key_id", _IDENTIFIER)
    if not key_id.startswith(("lab-", "test-")):
        raise BundleError("embedded TEST root key_id must begin with lab- or test-")
    public_value = value["public_key_pem"]
    if not isinstance(public_value, str) or not public_value or len(public_value) > 4096:
        raise BundleError("embedded TEST root public key must be a bounded PEM string")
    try:
        public_key = public_value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise BundleError("embedded TEST root public key must be ASCII PEM") from exc
    if not public_key.startswith(b"-----BEGIN PUBLIC KEY-----\n") \
        or not public_key.endswith(b"-----END PUBLIC KEY-----\n"):
        raise BundleError("embedded TEST root public key is not a bounded PEM public key")
    if any(root.key_id == key_id for root in PRODUCTION_ROOTS):
        raise BundleError("embedded TEST root collides with a production key id")
    return (Root(key_id=key_id, public_key_pem=public_key),)


@dataclass(frozen=True)
class VerifiedBundle:
    path: Path
    manifest: dict[str, Any]


@dataclass(frozen=True)
class ImageSource:
    name: str
    ref: str
    digest: str
    platform_digest: str
    archive_ref: str
    archive: Path


def _run(
    argv: Sequence[str],
    *,
    input_bytes: bytes | None = None,
    error: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        proc = subprocess.run(
            list(argv),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise BundleError(f"{error}: {argv[0]} is unavailable") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise BundleError(f"{error}{suffix}")
    return proc


def _unique_json(data: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise BundleError(f"{label} contains duplicate JSON key {key!r}")
            value[key] = item
        return value

    try:
        return json.loads(data, object_pairs_hook=pairs)
    except BundleError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"{label} is not valid UTF-8 JSON") from exc


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if extra:
            detail.append(f"unknown {', '.join(extra)}")
        raise BundleError(f"{label} fields are invalid ({'; '.join(detail)})")


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT:
        raise BundleError(f"{label} must be a non-empty bounded string")
    if any(ord(char) < 0x20 for char in value):
        raise BundleError(f"{label} contains a control character")
    if pattern is not None and not pattern.fullmatch(value):
        raise BundleError(f"{label} has an invalid format")
    return value


EMBEDDED_LAB_ROOTS = _load_embedded_lab_roots()
VERIFICATION_ROOTS = PRODUCTION_ROOTS + EMBEDDED_LAB_ROOTS


def _semver(value: Any, label: str) -> str:
    return _text(value, label, _SEMVER)


def _architecture(value: Any, label: str) -> str:
    checked = _text(value, label)
    aliases = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }
    normalized = aliases.get(checked.lower())
    if normalized not in ARCHITECTURES:
        raise BundleError(f"{label} must be amd64 or arm64")
    return normalized


def _validate_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BundleError("manifest must be a JSON object")
    expected = {
        "schema_version",
        "version",
        "edition",
        "architecture",
        "created_at",
        "git_sha",
        "images",
        "min_from_version",
        "required_stops",
        "migrations",
        "requires",
        "key_id",
    }
    _exact_keys(value, expected, "manifest")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise BundleError(f"unsupported manifest schema_version {value['schema_version']!r}")
    _semver(value["version"], "manifest.version")
    if value["edition"] not in {"open", "enterprise"}:
        raise BundleError("manifest.edition must be open or enterprise")
    _architecture(value["architecture"], "manifest.architecture")
    created = _text(value["created_at"], "manifest.created_at")
    if not created.endswith("Z"):
        raise BundleError("manifest.created_at must be UTC RFC3339")
    try:
        parsed = datetime.fromisoformat(created[:-1] + "+00:00")
    except ValueError as exc:
        raise BundleError("manifest.created_at must be UTC RFC3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise BundleError("manifest.created_at must be UTC RFC3339")
    _text(value["git_sha"], "manifest.git_sha", _GIT_SHA)
    _text(value["key_id"], "manifest.key_id", _IDENTIFIER)
    _semver(value["min_from_version"], "manifest.min_from_version")

    stops = value["required_stops"]
    if not isinstance(stops, list) or len(stops) > 64:
        raise BundleError("manifest.required_stops must be a bounded array")
    stop_values = [_semver(item, "manifest.required_stops[]") for item in stops]
    if len(stop_values) != len(set(stop_values)):
        raise BundleError("manifest.required_stops contains duplicates")

    images = value["images"]
    if not isinstance(images, list) or not images or len(images) > 256:
        raise BundleError("manifest.images must be a non-empty bounded array")
    names: set[str] = set()
    files: set[str] = set()
    refs: set[str] = set()
    archive_refs: set[str] = set()
    for index, image in enumerate(images):
        label = f"manifest.images[{index}]"
        if not isinstance(image, dict):
            raise BundleError(f"{label} must be an object")
        _exact_keys(
            image,
            {
                "name",
                "ref",
                "digest",
                "platform_digest",
                "archive_ref",
                "file",
                "sha256",
                "size",
            },
            label,
        )
        name = _text(image["name"], f"{label}.name", _IDENTIFIER)
        ref = _text(image["ref"], f"{label}.ref")
        digest = _text(image["digest"], f"{label}.digest", _SHA256)
        platform_digest = _text(
            image["platform_digest"], f"{label}.platform_digest", _SHA256
        )
        archive_ref = _text(image["archive_ref"], f"{label}.archive_ref")
        archive_match = _ARCHIVE_REF.fullmatch(archive_ref)
        if archive_match is None or archive_match.group(1) != name:
            raise BundleError(
                f"{label}.archive_ref must be an isolated tag for image {name}"
            )
        sha = _text(image["sha256"], f"{label}.sha256", re.compile(r"^[0-9a-f]{64}$"))
        file_name = _text(image["file"], f"{label}.file")
        if file_name != f"images/{name}.tar":
            raise BundleError(f"{label}.file must be images/{name}.tar")
        if type(image["size"]) is not int or image["size"] <= 0:
            raise BundleError(f"{label}.size must be a positive integer")
        if (
            name in names
            or ref in refs
            or archive_ref in archive_refs
            or file_name in files
        ):
            raise BundleError(
                "manifest.images contains a duplicate name, ref, archive_ref, or file"
            )
        names.add(name)
        refs.add(ref)
        archive_refs.add(archive_ref)
        files.add(file_name)
        _ = digest, platform_digest, sha

    migrations = value["migrations"]
    if not isinstance(migrations, dict):
        raise BundleError("manifest.migrations must be an object")
    _exact_keys(migrations, set(MIGRATION_GROUPS), "manifest.migrations")
    for group in MIGRATION_GROUPS:
        entries = migrations[group]
        if not isinstance(entries, list) or len(entries) > 10000:
            raise BundleError(f"manifest.migrations.{group} must be a bounded array")
        seen: set[str] = set()
        for index, entry in enumerate(entries):
            label = f"manifest.migrations.{group}[{index}]"
            if not isinstance(entry, dict):
                raise BundleError(f"{label} must be an object")
            _exact_keys(entry, {"version", "checksum"}, label)
            version = _text(entry["version"], f"{label}.version", _IDENTIFIER)
            _text(entry["checksum"], f"{label}.checksum", _CHECKSUM)
            if version in seen:
                raise BundleError(f"manifest.migrations.{group} repeats version {version}")
            seen.add(version)

    requires = value["requires"]
    if not isinstance(requires, dict):
        raise BundleError("manifest.requires must be an object")
    if "mandatory_backup" in requires and type(requires["mandatory_backup"]) is not bool:
        raise BundleError("manifest.requires.mandatory_backup must be a boolean")
    legacy_keys = {"cpu_features_by_role", "min_disk_bytes", "min_ram_bytes"}
    derived_keys = {"cpu_features_by_role", "disk", "ram"}
    requirement_keys = set(requires) - {"mandatory_backup"}
    if requirement_keys == legacy_keys:
        for field in ("min_disk_bytes", "min_ram_bytes"):
            if type(requires[field]) is not int or requires[field] <= 0:
                raise BundleError(f"manifest.requires.{field} must be a positive integer")
    elif requirement_keys == derived_keys:
        disk = requires["disk"]
        if not isinstance(disk, dict):
            raise BundleError("manifest.requires.disk must be an object")
        _exact_keys(
            disk,
            {
                "backup_postgres_ratio", "backup_clickhouse_ratio",
                "backup_fixed_overhead_bytes", "migration_data_ratio",
                "migration_min_headroom_bytes", "safety_data_ratio",
                "safety_min_bytes", "install_working_bytes",
                "image_load_overhead_bytes",
            },
            "manifest.requires.disk",
        )
        for field in (
            "backup_fixed_overhead_bytes", "migration_min_headroom_bytes",
            "safety_min_bytes", "install_working_bytes",
            "image_load_overhead_bytes",
        ):
            if type(disk[field]) is not int or disk[field] <= 0:
                raise BundleError(
                    f"manifest.requires.disk.{field} must be a positive integer"
                )
        for field in (
            "backup_postgres_ratio", "backup_clickhouse_ratio",
            "migration_data_ratio", "safety_data_ratio",
        ):
            ratio = disk[field]
            if not isinstance(ratio, dict):
                raise BundleError(f"manifest.requires.disk.{field} must be an object")
            _exact_keys(
                ratio, {"numerator", "denominator"},
                f"manifest.requires.disk.{field}",
            )
            if any(type(ratio[item]) is not int or ratio[item] <= 0 for item in ratio):
                raise BundleError(
                    f"manifest.requires.disk.{field} values must be positive integers"
                )

        ram = requires["ram"]
        if not isinstance(ram, dict):
            raise BundleError("manifest.requires.ram must be an object")
        _exact_keys(
            ram, {"absolute_min_bytes", "os_reserve_bytes", "role_min_bytes"},
            "manifest.requires.ram",
        )
        for field in ("absolute_min_bytes", "os_reserve_bytes"):
            if type(ram[field]) is not int or ram[field] <= 0:
                raise BundleError(
                    f"manifest.requires.ram.{field} must be a positive integer"
                )
        role_minimums = ram["role_min_bytes"]
        if not isinstance(role_minimums, dict) or not role_minimums:
            raise BundleError(
                "manifest.requires.ram.role_min_bytes must be a non-empty object"
            )
        _exact_keys(
            role_minimums, RESOURCE_ROLES,
            "manifest.requires.ram.role_min_bytes",
        )
        for role, minimum in role_minimums.items():
            _text(role, "manifest.requires.ram.role_min_bytes key", _IDENTIFIER)
            if type(minimum) is not int or minimum <= 0:
                raise BundleError(
                    f"manifest.requires.ram.role_min_bytes.{role} must be a positive integer"
                )
    else:
        raise BundleError(
            "manifest.requires must contain either the legacy min_disk_bytes/min_ram_bytes "
            "fields or the derived disk/ram policies"
        )
    features = requires["cpu_features_by_role"]
    if not isinstance(features, dict) or not features:
        raise BundleError("manifest.requires.cpu_features_by_role must be a non-empty object")
    for role, role_features in features.items():
        _text(role, "manifest.requires.cpu_features_by_role key", _IDENTIFIER)
        if not isinstance(role_features, list) or not role_features:
            raise BundleError(f"CPU features for role {role} must be a non-empty array")
        checked = [_text(item, f"CPU feature for role {role}", _IDENTIFIER) for item in role_features]
        if len(checked) != len(set(checked)):
            raise BundleError(f"CPU features for role {role} contain duplicates")
    return value


def _safe_member_name(raw: str) -> tuple[str, bool]:
    if not raw or "\x00" in raw or "\\" in raw or raw.startswith("/"):
        raise BundleError(f"unsafe tar member path {raw!r}")
    directory = raw.endswith("/")
    core = raw[:-1] if directory else raw
    parts = core.split("/")
    if not core or any(part in {"", ".", ".."} for part in parts):
        raise BundleError(f"unsafe tar member path {raw!r}")
    normalized = "/".join(parts)
    if raw not in {normalized, normalized + "/"}:
        raise BundleError(f"non-canonical tar member path {raw!r}")
    return normalized, directory


def _open_tar(path: Path) -> tarfile.TarFile:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise BundleError(f"cannot read bundle {path}") from exc
    if size < 1024 or size % 512 != 0:
        raise BundleError("bundle tar is truncated or not block-aligned")
    try:
        with path.open("rb") as handle:
            handle.seek(-1024, os.SEEK_END)
            if handle.read(1024) != b"\0" * 1024:
                raise BundleError("bundle tar is truncated or has trailing data")
        return tarfile.open(path, mode="r:")
    except BundleError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise BundleError("bundle tar is invalid or truncated") from exc


def _bounded_member_index(
    tf: tarfile.TarFile, label: str
) -> dict[str, tarfile.TarInfo]:
    found: dict[str, tarfile.TarInfo] = {}
    try:
        for count, member in enumerate(tf, start=1):
            if count > MAX_MEMBERS:
                raise BundleError(f"{label} has an invalid member count")
            name, _ = _safe_member_name(member.name)
            if name in found:
                raise BundleError(f"{label} repeats member {name}")
            found[name] = member
    except (OSError, tarfile.TarError) as exc:
        raise BundleError(f"{label} is invalid or truncated") from exc
    if not found:
        raise BundleError(f"{label} has an invalid member count")
    return found


def _members(tf: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    found = _bounded_member_index(tf, "bundle tar")
    for member in found.values():
        name, directory = _safe_member_name(member.name)
        if directory:
            if not member.isdir() or name not in {"images", "migrations"}:
                raise BundleError(f"unexpected tar directory {name}")
        elif not member.isreg():
            raise BundleError(f"tar member {name} is not a regular file")
    return found


def _read_member(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    maximum: int,
    label: str,
) -> bytes:
    if member.size < 0 or member.size > maximum:
        raise BundleError(f"{label} has an invalid size")
    try:
        handle = tf.extractfile(member)
        if handle is None:
            raise BundleError(f"cannot read {label}")
        data = handle.read(maximum + 1)
    except (OSError, tarfile.TarError) as exc:
        raise BundleError(f"{label} is truncated") from exc
    if len(data) != member.size:
        raise BundleError(f"{label} is truncated")
    return data


def _verify_signature(manifest: bytes, signature: bytes, root: Root) -> None:
    if len(signature) != 64:
        raise BundleError("manifest.sig is not an Ed25519 signature")
    with tempfile.TemporaryDirectory(prefix="nano-bundle-verify-") as tmp:
        public = Path(tmp, "root.pem")
        sig = Path(tmp, "manifest.sig")
        body = Path(tmp, "manifest.json")
        public.write_bytes(root.public_key_pem)
        sig.write_bytes(signature)
        body.write_bytes(manifest)
        try:
            proc = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    str(public),
                    "-sigfile",
                    str(sig),
                    "-in",
                    str(body),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError as exc:
            raise BundleError("openssl is required to verify release bundles") from exc
        if proc.returncode != 0:
            raise BundleError("manifest signature is invalid")


def _stream_hash(tf: tarfile.TarFile, member: tarfile.TarInfo, output: Any | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    try:
        source = tf.extractfile(member)
        if source is None:
            raise BundleError(f"cannot read {member.name}")
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            if output is not None:
                output.write(chunk)
    except (OSError, tarfile.TarError) as exc:
        raise BundleError(f"image payload {member.name} is truncated") from exc
    if total != member.size:
        raise BundleError(f"image payload {member.name} is truncated")
    return digest.hexdigest(), total


def verify_bundle(path: Path | str, roots: Sequence[Root] | None = None) -> VerifiedBundle:
    bundle = Path(path)
    roots = VERIFICATION_ROOTS if roots is None else roots
    root_ids = [root.key_id for root in roots]
    if not roots or len(root_ids) != len(set(root_ids)):
        raise BundleError("embedded release root set is invalid")
    with _open_tar(bundle) as tf:
        members = _members(tf)
        for required in ("manifest.json", "manifest.sig"):
            if required not in members or members[required].isdir():
                raise BundleError(f"bundle is missing {required}")
        manifest_bytes = _read_member(
            tf, members["manifest.json"], maximum=MAX_MANIFEST_BYTES, label="manifest.json"
        )
        signature = _read_member(
            tf, members["manifest.sig"], maximum=MAX_SIGNATURE_BYTES, label="manifest.sig"
        )
        manifest = _validate_manifest(_unique_json(manifest_bytes, "manifest.json"))
        root = next((item for item in roots if item.key_id == manifest["key_id"]), None)
        if root is None:
            raise BundleError(f"manifest uses unknown signing key {manifest['key_id']!r}")
        _verify_signature(manifest_bytes, signature, root)

        allowed = {"manifest.json", "manifest.sig", "images", "migrations"}
        for image in manifest["images"]:
            name = image["file"]
            allowed.add(name)
            member = members.get(name)
            if member is None or member.isdir():
                raise BundleError(f"bundle is missing image payload {name}")
            if member.size != image["size"]:
                raise BundleError(f"image payload {name} size does not match manifest")
            actual_sha, actual_size = _stream_hash(tf, member)
            if actual_size != image["size"] or actual_sha != image["sha256"]:
                raise BundleError(f"image payload {name} SHA-256 does not match manifest")

        migration_name = "migrations/index.json"
        if migration_name in members:
            allowed.add(migration_name)
            migration_bytes = _read_member(
                tf,
                members[migration_name],
                maximum=MAX_MANIFEST_BYTES,
                label=migration_name,
            )
            if _unique_json(migration_bytes, migration_name) != manifest["migrations"]:
                raise BundleError("migrations/index.json does not match the signed manifest")
        unexpected = sorted(name for name, member in members.items() if name not in allowed)
        if unexpected:
            raise BundleError(f"bundle contains unexpected member {unexpected[0]!r}")
    return VerifiedBundle(path=bundle, manifest=manifest)


def _role_file() -> str:
    env = os.environ.get("NANO_ROLE_PROFILES", "").strip()
    if env:
        return env
    path = Path(".nano-role.env")
    if not path.is_file():
        return ""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"NANO_ROLE_PROFILES", "COMPOSE_PROFILES"}:
                return value.strip().strip('"\'')
    except OSError as exc:
        raise BundleError("cannot read .nano-role.env") from exc
    return ""


def selected_roles(value: str | None = None) -> frozenset[str]:
    raw = _role_file() if value is None else value
    if not raw:
        return frozenset()
    roles = frozenset(item.strip() for item in raw.split(",") if item.strip())
    if not roles or not roles <= ROLES:
        unknown = sorted(roles - ROLES)
        raise BundleError(f"unknown host role(s): {', '.join(unknown) or raw}")
    return roles


_IMAGE_ROLES: dict[str, frozenset[str]] = {
    "api": frozenset({"app", "ingest"}),
    "search": frozenset({"app"}),
    "jobs": frozenset({"app"}),
    "web": frozenset({"app"}),
    "connector-runner": frozenset({"app"}),
    "postgres": frozenset({"postgres"}),
    "clickhouse-server": frozenset({"clickhouse"}),
    "clickhouse-keeper": frozenset({"keeper"}),
    "valkey": frozenset({"app"}),
    # Pre-NAN-5082 releases (legacy N-1 locks) still carry Dragonfly.
    "dragonfly": frozenset({"app"}),
    "vector": frozenset({"ingest"}),
    "curl": frozenset({"ingest"}),
    "nginx": frozenset({"app", "ingest", "clickhouse"}),
    "tenzir": frozenset({"ingest"}),
}


def _selected_image(name: str, roles: frozenset[str]) -> bool:
    if not roles:
        return True
    image_roles = _IMAGE_ROLES.get(name)
    # Unknown future components load everywhere until their role mapping is
    # added. That costs disk, but never strands an offline host without a
    # required image.
    return image_roles is None or bool(image_roles & roles)


def _docker_identity(docker: Sequence[str], ref: str) -> tuple[str, set[str]]:
    proc = _run(
        [*docker, "image", "inspect", ref],
        error=f"cannot inspect loaded image {ref}",
    )
    try:
        rows = json.loads(proc.stdout)
        row = rows[0]
        image_id = row["Id"]
        repo_digests = set(row.get("RepoDigests") or [])
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise BundleError(f"docker returned invalid metadata for {ref}") from exc
    return image_id, repo_digests


def _digest_matches(ref: str, digest: str, image_id: str, repo_digests: Iterable[str]) -> bool:
    if image_id == digest:
        return True
    repo = ref.rsplit("@", 1)[0].rsplit(":", 1)[0]
    return any(item == f"{repo}@{digest}" or item.endswith(f"@{digest}") for item in repo_digests)


def _docker_archive_metadata(path: Path, ref: str) -> tuple[str, str]:
    """Return the content identity and architecture docker load will expose.

    Docker's containerd image store reports an OCI manifest/index digest as
    ``image inspect .Id``, while the classic image store reports the config
    digest for the exact same ``docker save`` archive. The signed manifest
    keeps the release/registry digest; this independently derives and hashes
    the portable config identity from the already SHA-verified archive.
    """
    try:
        with tarfile.open(path, mode="r:*") as tf:
            found = _bounded_member_index(tf, "docker image archive")
            metadata = found.get("manifest.json")
            if metadata is None or not metadata.isreg():
                raise BundleError("docker image archive has no regular manifest.json")
            rows = _unique_json(
                _read_member(
                    tf,
                    metadata,
                    maximum=MAX_MANIFEST_BYTES,
                    label="docker image manifest.json",
                ),
                "docker image manifest.json",
            )
            if not isinstance(rows, list) or not rows:
                raise BundleError("docker image manifest.json must be a non-empty array")
            matches = []
            for row in rows:
                if not isinstance(row, dict):
                    raise BundleError("docker image manifest.json contains an invalid entry")
                tags = row.get("RepoTags")
                if isinstance(tags, list) and ref in tags:
                    matches.append(row)
            if len(matches) != 1:
                raise BundleError(f"docker image archive does not identify exactly one {ref}")
            config = matches[0].get("Config")
            if not isinstance(config, str):
                raise BundleError("docker image archive has an invalid config path")
            match = _DOCKER_CONFIG.fullmatch(config)
            if not match:
                raise BundleError("docker image archive has an invalid config path")
            expected = next(value for value in match.groups() if value is not None)
            config_member = found.get(config)
            if config_member is None or not config_member.isreg():
                raise BundleError("docker image archive config is missing or not a regular file")
            actual, _ = _stream_hash(tf, config_member)
            if actual != expected:
                raise BundleError("docker image archive config digest does not match its content")
            config_value = _unique_json(
                _read_member(
                    tf,
                    config_member,
                    maximum=MAX_MANIFEST_BYTES,
                    label="docker image config",
                ),
                "docker image config",
            )
            if not isinstance(config_value, dict):
                raise BundleError("docker image config must be an object")
            architecture = _architecture(
                config_value.get("architecture"), "docker image architecture"
            )
            if config_value.get("os") != "linux":
                raise BundleError("docker image operating system must be linux")
            return f"sha256:{actual}", architecture
    except BundleError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise BundleError("docker image archive is invalid or truncated") from exc


def _docker_archive_config_digest(path: Path, ref: str) -> str:
    """Compatibility helper for callers that only need the config identity."""
    return _docker_archive_metadata(path, ref)[0]


def _docker_host_architecture(docker: Sequence[str]) -> str:
    proc = _run(
        [*docker, "info", "--format", "{{.Architecture}}"],
        error="cannot determine Docker host architecture",
    )
    try:
        value = proc.stdout.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as exc:
        raise BundleError("Docker host architecture is not valid UTF-8") from exc
    return _architecture(value, "Docker host architecture")


def load_bundle(
    path: Path | str,
    roots: Sequence[Root] | None = None,
    *,
    roles: frozenset[str] | None = None,
    docker: Sequence[str] = ("docker",),
) -> list[str]:
    verified = verify_bundle(path, roots)
    bundle_architecture = _architecture(
        verified.manifest["architecture"], "manifest.architecture"
    )
    host_architecture = _docker_host_architecture(docker)
    if host_architecture != bundle_architecture:
        raise BundleError(
            f"bundle architecture {bundle_architecture} does not match "
            f"Docker host architecture {host_architecture}"
        )
    chosen_roles = selected_roles() if roles is None else roles
    selected = [
        image for image in verified.manifest["images"] if _selected_image(image["name"], chosen_roles)
    ]
    loaded: list[str] = []
    scratch_parent = Path(os.environ.get("NANO_BUNDLE_TMPDIR", Path.cwd()))
    scratch_parent.mkdir(parents=True, exist_ok=True)
    with _open_tar(verified.path) as tf, tempfile.TemporaryDirectory(
        prefix="nano-bundle-load-", dir=scratch_parent
    ) as tmp:
        members = _members(tf)
        for image in selected:
            target = Path(tmp, f"{image['name']}.tar")
            with target.open("wb") as output:
                os.chmod(target, 0o600)
                sha, size = _stream_hash(tf, members[image["file"]], output)
            if sha != image["sha256"] or size != image["size"]:
                raise BundleError(f"image payload {image['file']} changed during load")
            config_digest, image_architecture = _docker_archive_metadata(
                target, image["archive_ref"]
            )
            if config_digest != image["platform_digest"]:
                raise BundleError(
                    f"image payload {image['file']} platform digest does not match manifest"
                )
            if image_architecture != bundle_architecture:
                raise BundleError(
                    f"image payload {image['file']} architecture does not match manifest"
                )
            _run([*docker, "load", "--input", str(target)], error=f"docker load failed for {image['name']}")
            image_id, _ = _docker_identity(docker, image["archive_ref"])
            if image_id not in {image["platform_digest"], image["digest"]}:
                raise BundleError(
                    f"loaded image {image['archive_ref']} does not match a signed identity"
                )
            _run(
                [*docker, "tag", image["archive_ref"], image["ref"]],
                error=f"cannot tag loaded image {image['ref']}",
            )
            tagged_id, _ = _docker_identity(docker, image["ref"])
            if tagged_id != image_id:
                raise BundleError(f"loaded image {image['ref']} changed while it was tagged")
            _run(
                [*docker, "image", "rm", image["archive_ref"]],
                error=f"cannot remove isolated image tag {image['archive_ref']}",
            )
            loaded.append(image["name"])
    return loaded


def _sha_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _tar_bytes(tf: tarfile.TarFile, name: str, value: bytes, mtime: int, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(value)
    info.mtime = mtime
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    tf.addfile(info, io.BytesIO(value))


def _tar_file(tf: tarfile.TarFile, name: str, path: Path, mtime: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = path.stat().st_size
    info.mtime = mtime
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    with path.open("rb") as handle:
        tf.addfile(info, handle)


def create_bundle(
    output: Path,
    *,
    version: str,
    edition: str,
    architecture: str,
    created_at: str,
    git_sha: str,
    images: Sequence[ImageSource],
    min_from_version: str,
    required_stops: Sequence[str],
    migrations: dict[str, list[dict[str, str]]],
    requires: dict[str, Any],
    key_id: str,
    signer: Callable[[bytes], bytes],
    verification_root: Root,
    force: bool = False,
) -> Path:
    architecture = _architecture(architecture, "bundle architecture")
    if output.exists() and not force:
        raise BundleError(f"refusing to overwrite existing bundle {output}")
    image_manifest = []
    for image in sorted(images, key=lambda item: item.name):
        _text(image.name, "image name", _IDENTIFIER)
        if not image.archive.is_file():
            raise BundleError(f"image archive is missing: {image.archive}")
        archived_platform, archived_architecture = _docker_archive_metadata(
            image.archive, image.archive_ref
        )
        if archived_platform != image.platform_digest:
            raise BundleError(
                f"image archive {image.archive} does not match its platform digest"
            )
        if archived_architecture != architecture:
            raise BundleError(
                f"image archive {image.archive} architecture does not match bundle"
            )
        image_manifest.append(
            {
                "name": image.name,
                "ref": image.ref,
                "digest": image.digest,
                "platform_digest": image.platform_digest,
                "archive_ref": image.archive_ref,
                "file": f"images/{image.name}.tar",
                "sha256": _sha_file(image.archive),
                "size": image.archive.stat().st_size,
            }
        )
    manifest = _validate_manifest(
        {
            "schema_version": SCHEMA_VERSION,
            "version": version,
            "edition": edition,
            "architecture": architecture,
            "created_at": created_at,
            "git_sha": git_sha,
            "images": image_manifest,
            "min_from_version": min_from_version,
            "required_stops": list(required_stops),
            "migrations": migrations,
            "requires": requires,
            "key_id": key_id,
        }
    )
    body = _canonical_json(manifest)
    signature = signer(body)
    _verify_signature(body, signature, verification_root)
    try:
        timestamp = int(datetime.fromisoformat(created_at[:-1] + "+00:00").timestamp())
    except ValueError as exc:
        raise BundleError("created_at must be UTC RFC3339") from exc
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        with tarfile.open(temporary, mode="w", format=tarfile.PAX_FORMAT) as tf:
            _tar_bytes(tf, "manifest.json", body, timestamp)
            _tar_bytes(tf, "manifest.sig", signature, timestamp)
            for image, item in zip(sorted(images, key=lambda source: source.name), image_manifest, strict=True):
                _tar_file(tf, item["file"], image.archive, timestamp)
            _tar_bytes(tf, "migrations/index.json", _canonical_json(migrations), timestamp)
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    return output


def _migration_entries(path: Path, algorithm: str) -> list[dict[str, str]]:
    if not path.is_dir():
        return []
    entries = []
    for item in sorted(path.glob("*.sql")):
        match = re.match(r"^([0-9]+[a-z]*)_", item.name)
        if not match:
            continue
        entries.append(
            {"version": match.group(1), "checksum": f"{algorithm}:{_sha_file(item, algorithm)}"}
        )
    return entries


def collect_migrations(
    root: Path,
    edition: str,
    *,
    lab_upgrade_fixture: bool = False,
) -> dict[str, list[dict[str, str]]]:
    result = {
        "postgres": _migration_entries(root / "migrations/postgres", "sha384"),
        "clickhouse": _migration_entries(root / "clickhouse", "sha256"),
        "postgres_enterprise": [],
        "clickhouse_enterprise": [],
    }
    if edition == "enterprise":
        result["postgres_enterprise"] = _migration_entries(
            root / "migrations/postgres-enterprise", "sha384"
        )
        result["clickhouse_enterprise"] = _migration_entries(
            root / "clickhouse-enterprise", "sha256"
        )
    if lab_upgrade_fixture:
        fixture = (
            root
            / "scripts/tests/fixtures/upgrade/clickhouse/999999999lab_upgrade_probe.sql"
        )
        if not fixture.is_file():
            raise BundleError(f"lab upgrade migration fixture is missing: {fixture}")
        result["clickhouse"].append(
            {
                "version": "999999999lab",
                "checksum": f"sha256:{_sha_file(fixture, 'sha256')}",
            }
        )
    return result


def _release_core(value: str, label: str, *, stable: bool = False) -> tuple[int, int, int]:
    checked = _semver(value, label)
    match = _STABLE_VERSION.fullmatch(checked)
    if match is None:
        if stable:
            raise BundleError(f"{label} must be a stable X.Y.Z release")
        core = checked.split("+", 1)[0].split("-", 1)[0]
        match = _STABLE_VERSION.fullmatch(core)
    if match is None:  # pragma: no cover - _semver already constrains the shape
        raise BundleError(f"{label} has an invalid release core")
    return tuple(int(item) for item in match.groups())


def load_policy(
    path: Path, version: str, *, require_exact_release: bool = False
) -> tuple[str, list[str], dict[str, Any]]:
    try:
        value = _unique_json(path.read_bytes(), str(path))
    except OSError as exc:
        raise BundleError(f"cannot read upgrade policy {path}") from exc
    if not isinstance(value, dict):
        raise BundleError("upgrade policy must be an object")
    _exact_keys(value, {"schema_version", "default", "releases", "requires"}, "upgrade policy")
    if value["schema_version"] != 1:
        raise BundleError("unsupported upgrade policy schema")
    releases = value["releases"]
    if not isinstance(releases, dict):
        raise BundleError("upgrade policy releases must be an object")
    default = value["default"]
    if not isinstance(default, dict):
        raise BundleError("upgrade policy default must be an object")
    _exact_keys(default, {"min_from_version", "required_stops"}, "upgrade policy default")
    exact = releases.get(version)
    if require_exact_release and exact is None:
        raise BundleError(f"production signing requires releases[{version!r}] in upgrade policy")
    policy = exact if exact is not None else default
    if not isinstance(policy, dict):
        raise BundleError("upgrade policy release entry must be an object")
    expected_fields = {"min_from_version", "required_stops"}
    if exact is not None:
        expected_fields.add("previous_supported_version")
    _exact_keys(policy, expected_fields, "upgrade policy release")
    min_from = _semver(policy["min_from_version"], "upgrade policy min_from_version")
    stops = policy["required_stops"]
    if not isinstance(stops, list):
        raise BundleError("upgrade policy required_stops must be an array")
    checked_stops = [_semver(item, "upgrade policy required_stops[]") for item in stops]
    target_key = _release_core(
        version, "upgrade policy target version", stable=require_exact_release
    )
    minimum_key = _release_core(
        min_from, "upgrade policy min_from_version", stable=True
    )
    stop_keys = [
        _release_core(item, "upgrade policy required_stops[]", stable=True)
        for item in checked_stops
    ]
    if minimum_key >= target_key:
        raise BundleError("upgrade policy min_from_version must precede the target")
    if stop_keys != sorted(set(stop_keys)):
        raise BundleError("upgrade policy required_stops must be unique and ordered")
    if any(item <= minimum_key or item >= target_key for item in stop_keys):
        raise BundleError("upgrade policy required_stops must lie inside the supported range")
    if exact is not None:
        previous = _semver(
            policy["previous_supported_version"],
            "upgrade policy previous_supported_version",
        )
        previous_key = _release_core(
            previous, "upgrade policy previous_supported_version", stable=True
        )
        if previous_key < minimum_key or previous_key >= target_key:
            raise BundleError(
                "upgrade policy previous_supported_version must be in the supported range"
            )
    requires = value["requires"]
    # Reuse the manifest validator for the nested requirements object.
    probe = {
        "schema_version": 1,
        "version": version,
        "edition": "open",
        "architecture": "amd64",
        "created_at": "2000-01-01T00:00:00Z",
        "git_sha": "0" * 40,
        "images": [
            {
                "name": "probe",
                "ref": "probe:1",
                "digest": "sha256:" + "0" * 64,
                "platform_digest": "sha256:" + "1" * 64,
                "archive_ref": "nano-bundle.invalid/probe:" + "0" * 32,
                "file": "images/probe.tar",
                "sha256": "0" * 64,
                "size": 1,
            }
        ],
        "min_from_version": min_from,
        "required_stops": checked_stops,
        "migrations": {group: [] for group in MIGRATION_GROUPS},
        "requires": requires,
        "key_id": "probe",
    }
    _validate_manifest(probe)
    return min_from, checked_stops, requires


def _image_name(repo: str) -> str:
    name = repo.rsplit("/", 1)[-1].split(":", 1)[0]
    for prefix in ("nanosiem-", "nano-"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    if name == "dragonflydb":
        name = "dragonfly"
    if name == "curlimages":
        name = "curl"
    _text(name, "derived image name", _IDENTIFIER)
    return name


def _lock_images(path: Path, version: str) -> list[tuple[str, str, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise BundleError(f"cannot read image lock {path}") from exc
    header = next((line.removeprefix("# Release: v") for line in lines if line.startswith("# Release: v")), None)
    if header != version:
        raise BundleError(f"image lock release {header!r} does not match requested {version!r}")
    result = []
    names: set[str] = set()
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2 or not _SHA256.fullmatch(parts[1]):
            raise BundleError(f"invalid image lock line {line!r}")
        repo, digest = parts
        name = _image_name(repo)
        if name in names:
            raise BundleError(f"image lock derives duplicate name {name!r}")
        names.add(name)
        tagged = repo if ":" in repo.rsplit("/", 1)[-1] else f"{repo}:{version}"
        result.append((name, tagged, digest))
    if not result:
        raise BundleError("image lock contains no images")
    return result


def _explicit_image(spec: str) -> tuple[str, str, str | None]:
    name, separator, ref = spec.partition("=")
    if not separator:
        raise BundleError("--image must be NAME=REF or NAME=REF@sha256:DIGEST")
    _text(name, "--image name", _IDENTIFIER)
    _text(ref, "--image ref")
    digest = None
    if "@" in ref:
        ref, digest = ref.rsplit("@", 1)
        if not _SHA256.fullmatch(digest):
            raise BundleError("--image digest must be sha256:<64 lowercase hex>")
    return name, ref, digest


def _docker_sources(
    specs: Sequence[tuple[str, str, str | None]],
    directory: Path,
    *,
    pull: bool,
    architecture: str,
    source_specs: dict[str, tuple[str, str]] | None = None,
    docker: Sequence[str] = ("docker",),
) -> list[ImageSource]:
    architecture = _architecture(architecture, "bundle architecture")
    sources = []
    names: set[str] = set()
    for name, ref, expected in specs:
        if name in names:
            raise BundleError(f"duplicate image name {name!r}")
        names.add(name)
        source_ref = ref
        if source_specs is not None:
            try:
                source_ref, source_digest = source_specs[name]
            except KeyError as exc:
                raise BundleError(f"source image lock has no image {name!r}") from exc
            if expected != source_digest:
                raise BundleError(
                    f"source and delivery image locks disagree on digest for {name!r}"
                )
        immutable_ref = f"{source_ref}@{expected}" if expected else source_ref
        if pull:
            _run(
                [*docker, "pull", "--platform", f"linux/{architecture}", immutable_ref],
                error=f"cannot pull {immutable_ref} for linux/{architecture}",
            )
        image_id, repo_digests = _docker_identity(docker, immutable_ref)
        digest = expected or image_id
        if not _SHA256.fullmatch(digest):
            raise BundleError(f"docker returned invalid digest for {ref}")
        if expected and not _digest_matches(
            source_ref, expected, image_id, repo_digests
        ):
            raise BundleError(
                f"local image {source_ref} does not match locked digest {expected}"
            )
        archive_ref = f"nano-bundle.invalid/{name}:{uuid.uuid4().hex}"
        archive = directory / f"{name}.tar"
        tag_created = False
        try:
            _run(
                [*docker, "tag", image_id, archive_ref],
                error=f"cannot isolate image ID {image_id}",
            )
            tag_created = True
            tagged_id, _ = _docker_identity(docker, archive_ref)
            if tagged_id != image_id:
                raise BundleError(f"isolated image tag for {ref} has the wrong identity")
            with archive.open("wb") as output:
                proc = subprocess.run(
                    [*docker, "save", archive_ref],
                    stdout=output,
                    stderr=subprocess.PIPE,
                    check=False,
                )
            if proc.returncode != 0 or not archive.is_file() or archive.stat().st_size == 0:
                detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
                suffix = f": {detail[-1]}" if detail else ""
                raise BundleError(f"docker save failed for {ref}{suffix}")
            source_after, source_repo_digests = _docker_identity(docker, immutable_ref)
            tagged_after, _ = _docker_identity(docker, archive_ref)
            if source_after != image_id or tagged_after != image_id:
                raise BundleError(f"image {ref} changed while its archive was saved")
            if expected and not _digest_matches(
                source_ref, expected, source_after, source_repo_digests
            ):
                raise BundleError(
                    f"image {source_ref} lost its locked digest while saving"
                )
            platform_digest, archived_architecture = _docker_archive_metadata(
                archive, archive_ref
            )
            if archived_architecture != architecture:
                raise BundleError(
                    f"image {ref} architecture does not match requested {architecture}"
                )
            sources.append(
                ImageSource(
                    name=name,
                    ref=ref,
                    digest=digest,
                    platform_digest=platform_digest,
                    archive_ref=archive_ref,
                    archive=archive,
                )
            )
        except OSError as exc:
            raise BundleError(f"docker save failed for {ref}") from exc
        finally:
            if tag_created:
                active_error = sys.exc_info()[0] is not None
                try:
                    cleanup = subprocess.run(
                        [*docker, "image", "rm", archive_ref],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                except OSError as exc:
                    if not active_error:
                        raise BundleError(
                            f"cannot remove isolated image tag {archive_ref}"
                        ) from exc
                else:
                    if cleanup.returncode != 0 and not active_error:
                        raise BundleError(
                            f"cannot remove isolated image tag {archive_ref}"
                        )
    return sources


def _local_signer(private_key: Path) -> tuple[Callable[[bytes], bytes], Root]:
    if not private_key.is_file():
        raise BundleError(f"local signing key does not exist: {private_key}")
    public = _run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout"],
        error="cannot derive the local test public key",
    ).stdout

    def sign(body: bytes) -> bytes:
        # Ed25519 is a one-shot operation. OpenSSL 4 refuses stdin because it
        # cannot determine its size, so use a bounded temporary manifest file.
        with tempfile.TemporaryDirectory(prefix="nano-bundle-local-sign-") as tmp:
            source = Path(tmp, "manifest.json")
            source.write_bytes(body)
            return _run(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    str(private_key),
                    "-in",
                    str(source),
                ],
                error="local Ed25519 signing failed",
            ).stdout

    return sign, Root(key_id="local", public_key_pem=public)


def build_command(
    args: argparse.Namespace,
    *,
    signer: Callable[[bytes], bytes] | None = None,
    verification_root: Root | None = None,
    require_exact_policy: bool = False,
) -> Path:
    root = Path(args.repo_root).resolve()
    version = _semver(args.version, "--version")
    architecture = _architecture(
        args.architecture or platform.machine(), "--architecture"
    )
    key_id = _text(args.key_id, "--key-id", _IDENTIFIER)
    if (signer is None) != (verification_root is None):
        raise BundleError("builder signer and verification root must be supplied together")
    if signer is None:
        if not args.local_key:
            raise BundleError("--local-key is required for the public test builder")
        signer, local_root = _local_signer(Path(args.local_key))
        verification_root = Root(key_id=key_id, public_key_pem=local_root.public_key_pem)
    assert verification_root is not None
    if verification_root.key_id != key_id:
        raise BundleError("verification root key_id does not match --key-id")
    policy_path = Path(args.policy) if args.policy else root / "deploy/release/upgrade-policy.json"
    min_from, required_stops, requires = load_policy(
        policy_path, version, require_exact_release=require_exact_policy
    )
    created_at = args.created_at or datetime.now(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    git_sha = args.git_sha
    if not git_sha:
        git_sha = _run(
            ["git", "-C", str(root), "rev-parse", "HEAD"], error="cannot resolve git HEAD"
        ).stdout.decode().strip()
    output = Path(args.output or f"nano-{version}-{args.edition}.tar")
    if args.image_lock and args.image:
        raise BundleError("use --image-lock or --image, not both")
    if args.source_image_lock and not args.image_lock:
        raise BundleError("--source-image-lock requires --image-lock")
    if args.image_lock:
        specs = [(name, ref, digest) for name, ref, digest in _lock_images(Path(args.image_lock), version)]
    else:
        specs = [_explicit_image(item) for item in args.image]
    if not specs:
        raise BundleError("at least one --image or --image-lock is required")
    scratch_parent = Path(os.environ.get("NANO_BUNDLE_TMPDIR", output.parent or Path.cwd()))
    scratch_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nano-bundle-build-", dir=scratch_parent) as tmp:
        source_specs = None
        if args.source_image_lock:
            source_entries = _lock_images(Path(args.source_image_lock), version)
            source_specs = {
                name: (ref, digest) for name, ref, digest in source_entries
            }
            delivery_names = {name for name, _, _ in specs}
            if not delivery_names <= set(source_specs):
                raise BundleError(
                    "source image lock does not contain every delivery image name"
                )
            source_specs = {
                name: source_specs[name] for name in delivery_names
            }
        sources = _docker_sources(
            specs, Path(tmp), pull=args.pull, architecture=architecture,
            source_specs=source_specs,
        )
        return create_bundle(
            output,
            version=version,
            edition=args.edition,
            architecture=architecture,
            created_at=created_at,
            git_sha=git_sha,
            images=sources,
            min_from_version=min_from,
            required_stops=required_stops,
            migrations=collect_migrations(
                root,
                args.edition,
                lab_upgrade_fixture=args.lab_upgrade_migration_fixture,
            ),
            requires=requires,
            key_id=key_id,
            signer=signer,
            verification_root=verification_root,
            force=args.force,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nano bundle")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="verify a signed bundle offline")
    verify.add_argument("file")
    verify.add_argument("--json", action="store_true")
    load = commands.add_parser("load", help="verify, then load the host-role image subset")
    load.add_argument("file")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    json_error = "verify" in arguments and "--json" in arguments
    try:
        args = _parser().parse_args(arguments)
        if args.command == "verify":
            verified = verify_bundle(args.file)
            if args.json:
                print(json.dumps(verified.manifest, sort_keys=True, separators=(",", ":")))
            else:
                print(
                    f"verified nano {verified.manifest['version']} {verified.manifest['edition']} "
                    f"bundle ({len(verified.manifest['images'])} images)"
                )
        elif args.command == "load":
            loaded = load_bundle(args.file)
            role_text = _role_file() or "all"
            print(f"loaded {len(loaded)} image(s) for host roles: {role_text}")
        else:  # pragma: no cover - argparse enforces this
            raise BundleError("unknown bundle command")
        return 0
    except BundleError as exc:
        if json_error:
            print(json.dumps({"error": str(exc)}, sort_keys=True, separators=(",", ":")))
        else:
            print(f"nano bundle: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
