#!/usr/bin/env python3
"""Fail-closed policy helpers for the v0.1.702 legacy-layout bridge."""

from __future__ import annotations

import copy
import dataclasses
import re
from typing import Any


SOURCE_VERSION = "0.1.702"
TARGET_VERSION = "0.1.703"
APP_SERVICES = ("api", "jobs", "search", "web")
IMAGE_SERVICES = (*APP_SERVICES, "clickhouse-migrate")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class LegacyBridgeError(RuntimeError):
    """A signed bridge artifact or rendered legacy model is unsafe."""


@dataclasses.dataclass(frozen=True)
class BridgeImage:
    name: str
    ref: str
    digest: str
    platform_digest: str

    def safe_record(self) -> dict[str, str]:
        return dataclasses.asdict(self)


def is_legacy_bridge(source: str, target: str) -> bool:
    return source == SOURCE_VERSION and target == TARGET_VERSION


def effective_runtime_version(
    qualified_version: str, image_tag: str, record: dict[str, Any], *, edition: str,
) -> str:
    """Report the durable prepared version while a bridge rollout is resumable.

    The resolver intentionally continues to qualify the immutable running
    source images until rollout recreates them.  Once prepare has atomically
    published IMAGE_TAG and the durable intent, coordinator resume semantics
    require the target identity even though some or all old containers may
    still be running.
    """
    if record.get("state") != "image-tag-published":
        return qualified_version
    if not (
        record.get("format") == "nano-legacy-bridge-v1"
        and record.get("source_version") == SOURCE_VERSION
        and record.get("target_version") == TARGET_VERSION
        and record.get("edition") == edition
        and image_tag == TARGET_VERSION
        and qualified_version in {SOURCE_VERSION, TARGET_VERSION}
    ):
        raise LegacyBridgeError("published legacy bridge identity is inconsistent")
    return TARGET_VERSION


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LegacyBridgeError(f"{label} must be an object")
    return value


def validate_manifest(
    manifest: dict[str, Any], *, edition: str, architecture: str,
) -> dict[str, BridgeImage]:
    if manifest.get("version") != TARGET_VERSION or manifest.get("edition") != edition:
        raise LegacyBridgeError("signed bridge identity does not match the legacy deployment")
    if manifest.get("architecture") != architecture:
        raise LegacyBridgeError("signed bridge architecture does not match the Docker host")
    requires = _object(manifest.get("requires"), "signed bridge requirements")
    if requires.get("mandatory_backup") is not True:
        raise LegacyBridgeError("signed legacy bridge must require a backup")
    raw_images = manifest.get("images")
    if not isinstance(raw_images, list):
        raise LegacyBridgeError("signed bridge images must be an array")
    images: dict[str, BridgeImage] = {}
    for raw in raw_images:
        value = _object(raw, "signed bridge image")
        name = value.get("name")
        ref = value.get("ref")
        digest = value.get("digest")
        platform_digest = value.get("platform_digest")
        if name not in APP_SERVICES or name in images:
            raise LegacyBridgeError("signed bridge must contain each legacy application exactly once")
        if not isinstance(ref, str) or not ref.endswith(f":{TARGET_VERSION}"):
            raise LegacyBridgeError(f"signed bridge image {name} does not select the target tag")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise LegacyBridgeError(f"signed bridge image {name} has an invalid registry digest")
        if not isinstance(platform_digest, str) or not SHA256_RE.fullmatch(platform_digest):
            raise LegacyBridgeError(f"signed bridge image {name} has an invalid platform digest")
        images[name] = BridgeImage(name, ref, digest, platform_digest)
    if set(images) != set(APP_SERVICES):
        raise LegacyBridgeError("signed bridge application set is incomplete")
    if len({image.ref for image in images.values()}) != len(images):
        raise LegacyBridgeError("signed bridge application references are not unique")
    return images


def validate_rendered_transition(
    source_model: dict[str, Any], target_model: dict[str, Any],
    images: dict[str, BridgeImage],
) -> None:
    source = copy.deepcopy(_object(source_model, "source legacy Compose model"))
    target = copy.deepcopy(_object(target_model, "target legacy Compose model"))
    source_services = _object(source.get("services"), "source legacy services")
    target_services = _object(target.get("services"), "target legacy services")
    if set(source_services) != set(target_services):
        raise LegacyBridgeError("target IMAGE_TAG changes the legacy service set")
    for service in IMAGE_SERVICES:
        source_service = _object(source_services.get(service), f"source legacy service {service}")
        target_service = _object(target_services.get(service), f"target legacy service {service}")
        image_name = "api" if service == "clickhouse-migrate" else service
        expected = images[image_name].ref
        if target_service.get("image") != expected:
            raise LegacyBridgeError(
                f"target legacy service {service} does not select its signed bridge image"
            )
        if source_service.get("image") == expected:
            raise LegacyBridgeError(f"source legacy service {service} already selects the target image")
        target_service["image"] = source_service.get("image")
    if target != source:
        raise LegacyBridgeError("target IMAGE_TAG changes legacy Compose semantics beyond images")
