#!/usr/bin/env python3
"""Strict manifest handling for scripts/nano.

Restore code snapshots signed files before invoking this helper.  Each command
parses each supplied manifest exactly once and emits only validated fields.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from typing import Any


HEX64 = re.compile(r"[0-9a-f]{64}")
SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
SEMVER = re.compile(r"v?\d+\.\d+\.\d+")
EPOCH = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
ROLE = re.compile(r"[a-z][a-z0-9-]{0,31}")
TABLE = re.compile(r"[A-Za-z0-9_.-]{1,200}")
ENGINE = re.compile(r"(?:Replicated)?[A-Za-z]*MergeTree")


def fail(message: str) -> None:
    raise ValueError(message)


def need(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def uint(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def text(value: Any, pattern: re.Pattern[str], label: str) -> str:
    need(isinstance(value, str) and pattern.fullmatch(value) is not None, f"invalid {label}")
    return value


def read_json_once(path: pathlib.Path) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    value = json.loads(raw)
    need(isinstance(value, dict), f"{path.name} is not an object")
    return raw, value


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_time(value: Any, label: str) -> datetime:
    value = text(value, EPOCH, label)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def validate_bundle(value: dict[str, Any]) -> dict[str, Any]:
    need(value.get("format") == "nano-backup-v2", "unsupported bundle format")
    backup_id = text(value.get("backup_id"), SAFE, "backup id")
    created_at = text(value.get("created_at"), EPOCH, "created_at")
    parse_time(created_at, "created_at")
    version = text(value.get("nano_version"), SEMVER, "nano version")
    edition = value.get("edition")
    need(edition in {"open", "enterprise"}, "invalid edition")
    schema = value.get("schema_profile")
    need(schema in {"udm", "ocsf"}, "invalid schema profile")

    topology = value.get("topology")
    need(isinstance(topology, dict), "missing topology")
    mode = topology.get("mode")
    need(mode in {"single", "role-split"}, "invalid topology mode")
    deployment = text(topology.get("deployment_id"), SAFE, "deployment id")
    identity = topology.get("deployment_identity_sha256")
    if mode == "role-split":
        identity = text(identity, HEX64, "deployment identity")
    else:
        need(identity is None or (isinstance(identity, str) and not identity), "single topology has deployment identity")
        identity = ""
    host = text(topology.get("host_id"), SAFE, "host id")
    roles = topology.get("roles")
    need(isinstance(roles, list) and roles and all(isinstance(role, str) and ROLE.fullmatch(role) for role in roles), "invalid roles")
    shard = topology.get("clickhouse_shard")
    replica = topology.get("clickhouse_replica")
    shard_count = topology.get("clickhouse_shard_count")
    need(uint(shard) and shard > 0, "invalid shard")
    need(uint(replica) and replica > 0, "invalid replica")
    need(uint(shard_count) and shard_count >= shard, "invalid shard count")

    components = value.get("components")
    need(isinstance(components, dict), "missing components")
    pg = components.get("postgres")
    ch = components.get("clickhouse")
    config = components.get("configuration")
    need(isinstance(pg, dict) and isinstance(ch, dict) and isinstance(config, dict), "invalid components")
    need(isinstance(pg.get("included"), bool) and uint(pg.get("migration_version")) and uint(pg.get("source_bytes")), "invalid PostgreSQL component")
    need(isinstance(ch.get("included"), bool) and uint(ch.get("migration_version")) and uint(ch.get("source_bytes")), "invalid ClickHouse component")
    need(isinstance(config.get("included"), bool) and config["included"], "configuration component missing")
    need(isinstance(ch.get("external"), bool) and isinstance(ch.get("external_disk_encrypted"), bool), "invalid external flags")
    need(ch.get("scope") in {"host", "cluster"}, "invalid ClickHouse scope")
    disk = ch.get("disk")
    archive = ch.get("archive")
    if ch["included"]:
        disk = text(disk, NAME, "ClickHouse disk")
        archive = text(archive, SAFE, "ClickHouse archive")
        need(archive.endswith(".zip"), "ClickHouse archive is not zip")
        need(not ch["external"] or ch["external_disk_encrypted"], "external disk is not encrypted")
    else:
        need(disk is None and archive is None and not ch["external"] and not ch["external_disk_encrypted"], "excluded ClickHouse component has storage")
        disk = archive = ""
    base_id = ch.get("base_backup_id")
    base_sha = ch.get("base_payload_sha256")
    if base_id is None and base_sha is None:
        base_id = base_sha = ""
    else:
        base_id = text(base_id, SAFE, "base backup id")
        base_sha = text(base_sha, HEX64, "base payload digest")

    recovery = value.get("recovery_set")
    if mode == "role-split":
        need(isinstance(recovery, dict), "role-split bundle lacks recovery set")
        set_id = text(recovery.get("id"), SAFE, "recovery set id")
        quiesce_epoch = text(recovery.get("quiesce_epoch"), EPOCH, "quiesce epoch")
        parse_time(quiesce_epoch, "quiesce epoch")
    else:
        need(recovery is None, "single bundle has recovery set")
        set_id = quiesce_epoch = ""

    encryption = value.get("encryption")
    need(isinstance(encryption, dict), "missing encryption")
    need(encryption.get("format") == "CMS AuthEnvelopedData" and encryption.get("cipher") == "AES-256-GCM", "invalid encryption")
    fingerprint = text(str(encryption.get("recipient_certificate_sha256", "")).lower(), HEX64, "certificate fingerprint")

    payload = value.get("payload")
    need(isinstance(payload, dict) and payload.get("file") == "payload.cms", "invalid payload")
    payload_sha = text(payload.get("sha256"), HEX64, "payload digest")
    checksums = payload.get("plaintext_sha256")
    need(isinstance(checksums, dict) and checksums, "missing plaintext checksums")
    checked: dict[str, str] = {}
    for member, digest in checksums.items():
        need(isinstance(member, str) and member, "invalid payload member")
        path = pathlib.PurePosixPath(member)
        need(not path.is_absolute() and ".." not in path.parts, "unsafe payload member")
        checked[member] = text(digest, HEX64, "plaintext digest")

    return {
        "backup_id": backup_id,
        "created_at": created_at,
        "version": version.removeprefix("v"),
        "edition": edition,
        "schema": schema,
        "mode": mode,
        "deployment": deployment,
        "identity": identity,
        "host": host,
        "roles": ",".join(roles),
        "shard": shard,
        "replica": replica,
        "shard_count": shard_count,
        "pg_included": pg["included"],
        "pg_migration": pg["migration_version"],
        "pg_bytes": pg["source_bytes"],
        "ch_included": ch["included"],
        "ch_migration": ch["migration_version"],
        "ch_bytes": ch["source_bytes"],
        "disk": disk,
        "archive": archive,
        "external": ch["external"],
        "external_encrypted": ch["external_disk_encrypted"],
        "scope": ch["scope"],
        "base_id": base_id,
        "base_sha": base_sha,
        "set_id": set_id,
        "quiesce_epoch": quiesce_epoch,
        "payload_sha": payload_sha,
        "fingerprint": fingerprint,
        "checksums": checked,
    }


FIELD_ORDER = (
    "backup_id", "created_at", "version", "edition", "schema", "mode", "deployment", "identity", "host", "roles",
    "shard", "replica", "shard_count", "pg_included", "pg_migration", "pg_bytes", "ch_included", "ch_migration",
    "ch_bytes", "disk", "archive", "external", "external_encrypted", "scope", "base_id", "base_sha", "set_id",
    "quiesce_epoch", "payload_sha", "fingerprint", "manifest_sha",
)


def bool_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def parse_bundle_command(args: argparse.Namespace) -> None:
    raw, value = read_json_once(args.manifest)
    fields = validate_bundle(value)
    fields["manifest_sha"] = hashlib.sha256(raw).hexdigest()
    args.checksums.write_text(json.dumps(fields.pop("checksums"), sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(args.checksums, 0o600)
    for name in FIELD_ORDER:
        sys.stdout.buffer.write(bool_text(fields[name]).encode() + b"\0")


def verify_payload_command(args: argparse.Namespace) -> None:
    checksums = json.loads(args.checksums.read_text(encoding="utf-8"))
    need(isinstance(checksums, dict), "invalid checksum sidecar")
    actual: dict[str, pathlib.Path] = {}
    for path in args.payload.rglob("*"):
        if path.is_symlink():
            fail(f"symbolic link in payload: {path}")
        if path.is_file():
            actual[str(path.relative_to(args.payload))] = path
    missing = sorted(set(checksums) - set(actual))
    extra = sorted(set(actual) - set(checksums))
    need(not missing and not extra, f"payload member set mismatch (missing={missing}, extra={extra})")
    for name, path in actual.items():
        digest = sha256_file(path)
        need(digest == checksums[name], f"payload member checksum mismatch: {name}")


def split_engine_args(value: str) -> list[str]:
    if not value.strip():
        return []
    result: list[str] = []
    start = depth = 0
    quote: str | None = None
    escape = False
    for index, char in enumerate(value):
        if quote:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            need(depth >= 0, "unbalanced MergeTree engine arguments")
        elif char == "," and depth == 0:
            result.append(value[start:index].strip())
            start = index + 1
    need(quote is None and depth == 0, "unbalanced MergeTree engine arguments")
    result.append(value[start:].strip())
    need(all(result), "empty MergeTree engine argument")
    return result


def verification_engine(source_engine: str, engine_full: str) -> str:
    need(not any(char in engine_full for char in "\0\r\n;"), "unsafe MergeTree engine definition")
    match = re.match(r"^(Replicated)?([A-Za-z]*MergeTree)", engine_full)
    need(match is not None and match.group(0) == source_engine, "unsupported MergeTree engine definition")
    suffix = engine_full[match.end():]
    arguments: list[str] = []
    if suffix.startswith("("):
        depth = 0
        quote: str | None = None
        escape = False
        close: int | None = None
        for index, char in enumerate(suffix):
            if quote:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == quote:
                    quote = None
            elif char in "'\"":
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    close = index
                    break
        need(close is not None, "unbalanced MergeTree engine definition")
        arguments = split_engine_args(suffix[1:close])
        suffix = suffix[close + 1:]
    if match.group(1):
        need(len(arguments) >= 2, "replicated MergeTree lacks path and replica arguments")
        arguments = arguments[2:]
    engine = match.group(2) + ("(" + ", ".join(arguments) + ")" if arguments else "") + suffix
    need("ORDER BY" in engine, "MergeTree verification engine lacks sorting key")
    return engine


def verification_ddl_command(args: argparse.Namespace) -> None:
    database = text(args.database, NAME, "verification database")
    tables: dict[str, dict[str, Any]] = {}
    for line in args.schema.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        need(isinstance(value, dict), "ClickHouse schema entry is not an object")
        table = text(value.get("name"), TABLE, "ClickHouse schema table")
        engine = text(value.get("engine"), ENGINE, "ClickHouse schema engine")
        engine_full = value.get("engine_full")
        sorting_key = value.get("sorting_key")
        column = value.get("column_name")
        column_type = value.get("column_type")
        need(isinstance(engine_full, str) and isinstance(sorting_key, str), "invalid ClickHouse table schema")
        need(isinstance(column, str) and column and not any(char in column for char in "\0\r\n"), "invalid ClickHouse column name")
        need(isinstance(column_type, str) and column_type and
             not any(token in column_type for token in ("\0", "\r", "\n", ";", "--", "/*", "*/")),
             "unsafe ClickHouse column type")
        metadata = (engine, engine_full, sorting_key)
        entry = tables.setdefault(table, {"metadata": metadata, "columns": []})
        need(entry["metadata"] == metadata, "inconsistent ClickHouse table schema")
        need(all(existing[0] != column for existing in entry["columns"]), "duplicate ClickHouse column")
        entry["columns"].append((column, column_type))
    for table, entry in tables.items():
        engine, engine_full, _ = entry["metadata"]
        columns = ", ".join(f"`{name.replace('`', '``')}` {column_type}" for name, column_type in entry["columns"])
        ddl = f"CREATE TABLE `{database}`.`{table}` ({columns}) ENGINE = " + verification_engine(engine, engine_full)
        for item in (table, engine, ddl):
            sys.stdout.buffer.write(item.encode() + b"\0")
    need(bool(tables), "ClickHouse schema inventory is empty")


def recovery_component(fields: dict[str, Any], manifest_sha: str) -> dict[str, Any]:
    shards: list[int] = []
    if fields["ch_included"]:
        shards = (list(range(1, fields["shard_count"] + 1)) if fields["scope"] == "cluster" else [fields["shard"]])
    return {
        "backup_id": fields["backup_id"],
        "payload_sha256": fields["payload_sha"],
        "manifest_sha256": manifest_sha,
        "host_id": fields["host"],
        "roles": fields["roles"].split(","),
        "postgres": fields["pg_included"],
        "clickhouse": fields["ch_included"],
        "clickhouse_scope": fields["scope"] if fields["ch_included"] else None,
        "clickhouse_shards": shards,
    }


def create_set_command(args: argparse.Namespace) -> None:
    parsed: list[tuple[bytes, dict[str, Any]]] = []
    for path in args.manifests:
        raw, value = read_json_once(path)
        fields = validate_bundle(value)
        need(fields["mode"] == "role-split", "recovery set contains single-node bundle")
        need(fields["set_id"] == args.set_id and fields["quiesce_epoch"] == args.quiesce_epoch, "bundle recovery-set metadata mismatch")
        parsed.append((raw, fields))
    need(parsed, "recovery set is empty")
    first = parsed[0][1]
    for _, fields in parsed[1:]:
        need((fields["deployment"], fields["identity"], fields["edition"], fields["schema"], fields["version"]) ==
             (first["deployment"], first["identity"], first["edition"], first["schema"], first["version"]),
             "recovery set deployment metadata mismatch")
    pg = [fields for _, fields in parsed if fields["pg_included"]]
    ch = [fields for _, fields in parsed if fields["ch_included"]]
    need(all(fields["pg_included"] or fields["ch_included"] for _, fields in parsed),
         "recovery set contains an empty component bundle")
    need(len(pg) == 1, "recovery set requires exactly one PostgreSQL bundle")
    need(all(not fields["ch_included"] for fields in pg), "PostgreSQL bundle also contains ClickHouse")
    need(all(not fields["pg_included"] and fields["replica"] == 1 for fields in ch), "invalid ClickHouse component bundle")
    need(ch, "recovery set has no ClickHouse bundles")
    shard_count = ch[0]["shard_count"]
    need(all(fields["shard_count"] == shard_count for fields in ch), "ClickHouse shard-count mismatch")
    cluster = [fields for fields in ch if fields["scope"] == "cluster"]
    if cluster:
        need(len(cluster) == 1 and len(ch) == 1, "cluster bundle cannot be mixed with shard bundles")
    else:
        need(sorted(fields["shard"] for fields in ch) == list(range(1, shard_count + 1)), "recovery set lacks a shard or contains duplicates")
    created = [parse_time(fields["created_at"], "created_at") for _, fields in parsed]
    skew = int((max(created) - min(created)).total_seconds())
    need(skew <= args.max_skew, f"snapshot skew {skew}s exceeds {args.max_skew}s")
    document = {
        "format": "nano-recovery-set-v1",
        "recovery_set_id": args.set_id,
        "quiesce_epoch": args.quiesce_epoch,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "measured_snapshot_skew_seconds": skew,
        "deployment_id": first["deployment"],
        "deployment_identity_sha256": first["identity"],
        "nano_version": first["version"],
        "edition": first["edition"],
        "schema_profile": first["schema"],
        "clickhouse_shard_count": shard_count,
        "components": [recovery_component(fields, hashlib.sha256(raw).hexdigest()) for raw, fields in parsed],
    }
    args.output.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(args.output, 0o600)
    print(skew)


def validate_set_document(value: dict[str, Any]) -> dict[str, Any]:
    need(value.get("format") == "nano-recovery-set-v1", "unsupported recovery set format")
    set_id = text(value.get("recovery_set_id"), SAFE, "recovery set id")
    epoch = text(value.get("quiesce_epoch"), EPOCH, "quiesce epoch")
    parse_time(epoch, "quiesce epoch")
    parse_time(value.get("created_at"), "recovery set created_at")
    need(uint(value.get("measured_snapshot_skew_seconds")), "invalid recovery set skew")
    deployment = text(value.get("deployment_id"), SAFE, "deployment id")
    identity = text(value.get("deployment_identity_sha256"), HEX64, "deployment identity")
    version = text(value.get("nano_version"), SEMVER, "nano version").removeprefix("v")
    need(value.get("edition") in {"open", "enterprise"}, "invalid recovery set edition")
    need(value.get("schema_profile") in {"udm", "ocsf"}, "invalid recovery set schema")
    shard_count = value.get("clickhouse_shard_count")
    need(uint(shard_count) and shard_count > 0, "invalid recovery set shard count")
    components = value.get("components")
    need(isinstance(components, list) and len(components) >= 2, "invalid recovery set components")
    seen_ids: set[str] = set()
    pg_count = 0
    shards: list[int] = []
    for component in components:
        need(isinstance(component, dict), "invalid recovery component")
        backup_id = text(component.get("backup_id"), SAFE, "component backup id")
        need(backup_id not in seen_ids, "duplicate recovery component")
        seen_ids.add(backup_id)
        text(component.get("payload_sha256"), HEX64, "component payload digest")
        text(component.get("manifest_sha256"), HEX64, "component manifest digest")
        text(component.get("host_id"), SAFE, "component host id")
        roles = component.get("roles")
        need(isinstance(roles, list) and roles and all(isinstance(role, str) and ROLE.fullmatch(role) for role in roles), "invalid component roles")
        need(isinstance(component.get("postgres"), bool) and isinstance(component.get("clickhouse"), bool), "invalid component flags")
        need(component["postgres"] != component["clickhouse"], "recovery component must contain exactly one database component")
        if component["postgres"]:
            pg_count += 1
            need(not component["clickhouse"] and component.get("clickhouse_scope") is None and component.get("clickhouse_shards") == [], "invalid PostgreSQL component")
        if component["clickhouse"]:
            scope = component.get("clickhouse_scope")
            component_shards = component.get("clickhouse_shards")
            need(scope in {"host", "cluster"}, "invalid component scope")
            need(isinstance(component_shards, list) and component_shards and
                 all(uint(shard) and 0 < shard <= shard_count for shard in component_shards), "invalid component shards")
            need(component_shards == sorted(set(component_shards)), "duplicate component shard")
            if scope == "host":
                need(len(component_shards) == 1, "host component covers multiple shards")
            else:
                need(component_shards == list(range(1, shard_count + 1)), "cluster component is incomplete")
            shards.extend(component_shards)
            need(not component["postgres"], "combined recovery component")
    need(pg_count == 1 and sorted(shards) == list(range(1, shard_count + 1)), "incomplete recovery set")
    return {
        "set_id": set_id,
        "epoch": epoch,
        "deployment": deployment,
        "identity": identity,
        "version": version,
        "edition": value["edition"],
        "schema": value["schema_profile"],
        "shard_count": shard_count,
        "components": components,
    }


def validate_set_command(args: argparse.Namespace) -> None:
    _, value = read_json_once(args.recovery_set)
    fields = validate_set_document(value)
    expected = {
        "set_id": args.set_id,
        "epoch": args.quiesce_epoch,
        "deployment": args.deployment,
        "identity": args.identity,
        "version": args.version,
        "edition": args.edition,
        "schema": args.schema,
    }
    if args.ch:
        expected["shard_count"] = args.shard_count
    for key, expected_value in expected.items():
        need(fields[key] == expected_value, f"recovery set {key} mismatch")
    matches = [component for component in fields["components"] if component["backup_id"] == args.backup_id]
    need(len(matches) == 1, "bundle is not a member of recovery set")
    component = matches[0]
    need(component["payload_sha256"] == args.payload_sha and component["manifest_sha256"] == args.manifest_sha, "recovery component digest mismatch")
    need(component["host_id"] == args.host and component["postgres"] == args.pg and component["clickhouse"] == args.ch, "recovery component identity mismatch")
    if args.ch:
        need(args.shard in component["clickhouse_shards"], "recovery component shard mismatch")


def retention_command(args: argparse.Namespace) -> None:
    verified: list[tuple[str, pathlib.Path, dict[str, Any]]] = []
    for child in sorted(args.parent.iterdir()):
        if not child.is_dir() or child.is_symlink():
            continue
        manifest, signature, payload = child / "manifest.json", child / "manifest.sig", child / "payload.cms"
        if not all(path.is_file() and not path.is_symlink() for path in (manifest, signature, payload)):
            print(f"retention ignored incomplete bundle: {child}", file=sys.stderr)
            continue
        try:
            with tempfile.TemporaryDirectory(prefix="nano-retention-") as temp:
                temp_path = pathlib.Path(temp)
                snap_manifest, snap_signature = temp_path / "manifest.json", temp_path / "manifest.sig"
                shutil.copyfile(manifest, snap_manifest)
                shutil.copyfile(signature, snap_signature)
                result = subprocess.run(
                    ["openssl", "dgst", "-sha256", "-verify", str(args.public_key), "-signature", str(snap_signature), str(snap_manifest)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                need(result.returncode == 0, "signature verification failed")
                _, value = read_json_once(snap_manifest)
                fields = validate_bundle(value)
            need(sha256_file(payload) == fields["payload_sha"], "payload digest mismatch")
            if fields["edition"] == args.edition and fields["identity"] == args.identity and fields["host"] == args.host:
                verified.append((fields["created_at"], child, fields))
        except Exception as error:
            print(f"retention ignored unverified bundle: {child}: {error}", file=sys.stderr)
    verified.sort(key=lambda item: item[0], reverse=True)
    kept = {item[2]["backup_id"] for item in verified[: args.keep]}
    changed = True
    while changed:
        changed = False
        for _, _, fields in verified:
            if fields["backup_id"] in kept and fields["base_id"] and fields["base_id"] not in kept:
                need(any(candidate[2]["backup_id"] == fields["base_id"] for candidate in verified), f"verified base missing for {fields['backup_id']}")
                kept.add(fields["base_id"])
                changed = True
    for _, child, fields in verified:
        if fields["backup_id"] not in kept:
            sys.stdout.buffer.write(os.fsencode(child) + b"\0")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    parse = sub.add_parser("parse-bundle")
    parse.add_argument("manifest", type=pathlib.Path)
    parse.add_argument("checksums", type=pathlib.Path)
    parse.set_defaults(func=parse_bundle_command)
    verify = sub.add_parser("verify-payload")
    verify.add_argument("checksums", type=pathlib.Path)
    verify.add_argument("payload", type=pathlib.Path)
    verify.set_defaults(func=verify_payload_command)
    ddl = sub.add_parser("verification-ddl")
    ddl.add_argument("schema", type=pathlib.Path)
    ddl.add_argument("--database", required=True)
    ddl.set_defaults(func=verification_ddl_command)
    create = sub.add_parser("create-set")
    create.add_argument("--set-id", required=True)
    create.add_argument("--quiesce-epoch", required=True)
    create.add_argument("--max-skew", type=int, default=300)
    create.add_argument("--output", type=pathlib.Path, required=True)
    create.add_argument("manifests", nargs="+", type=pathlib.Path)
    create.set_defaults(func=create_set_command)
    validate = sub.add_parser("validate-set")
    validate.add_argument("recovery_set", type=pathlib.Path)
    validate.add_argument("--set-id", required=True)
    validate.add_argument("--quiesce-epoch", required=True)
    validate.add_argument("--deployment", required=True)
    validate.add_argument("--identity", required=True)
    validate.add_argument("--version", required=True)
    validate.add_argument("--edition", required=True)
    validate.add_argument("--schema", required=True)
    validate.add_argument("--shard-count", required=True, type=int)
    validate.add_argument("--backup-id", required=True)
    validate.add_argument("--payload-sha", required=True)
    validate.add_argument("--manifest-sha", required=True)
    validate.add_argument("--host", required=True)
    validate.add_argument("--pg", action="store_true")
    validate.add_argument("--ch", action="store_true")
    validate.add_argument("--shard", type=int, default=0)
    validate.set_defaults(func=validate_set_command)
    retention = sub.add_parser("retention")
    retention.add_argument("--parent", type=pathlib.Path, required=True)
    retention.add_argument("--keep", type=int, required=True)
    retention.add_argument("--edition", required=True)
    retention.add_argument("--identity", required=True)
    retention.add_argument("--host", required=True)
    retention.add_argument("--public-key", type=pathlib.Path, required=True)
    retention.set_defaults(func=retention_command)
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as error:
        print(f"nano manifest: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
