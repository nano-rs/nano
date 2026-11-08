"""Real-cloud test resources as pytest fixtures, shared by the pull suite and
the UI cloud-pull scenarios (import them into a conftest).

Created per test under the `nano-e2e-<runid>` prefix with ownership tags, and
ALWAYS torn down (finalizers run even when the scenario fails). Only per-run
resources are ever deleted; base resources (the Event Hubs namespace, the
storage account, projects, IAM) are never touched. Without credentials the
scenario SKIPs with the reason.
"""

from __future__ import annotations

import warnings
from collections.abc import Iterator
from typing import Any

import pytest

from nano_e2e import creds
from nano_e2e.cloud import aws, azure, gcp
from nano_e2e.runid import cloud_name


def _teardown(resource: Any) -> None:
    """Best-effort delete that never masks the scenario's own failure; a
    leftover is reported and `scripts/e2e.sh gc --cloud` sweeps it by prefix."""
    try:
        resource.delete()
    except Exception as exc:  # noqa: BLE001
        warnings.warn(
            f"E2E-INFRA: teardown of {resource!r} failed: {exc}; run `e2e.sh gc --cloud`", stacklevel=1
        )


@pytest.fixture
def aws_creds() -> creds.AwsCreds:
    c, reason = creds.aws()
    if c is None:
        pytest.skip(reason)
    return c


@pytest.fixture
def sqs_queue(aws_creds: creds.AwsCreds, request: pytest.FixtureRequest) -> Iterator[aws.SqsQueue]:
    q = aws.SqsQueue(aws_creds, cloud_name("q", request.node.nodeid, max_len=80))
    try:
        yield q.create()
    finally:
        _teardown(q)


@pytest.fixture
def s3_bucket(aws_creds: creds.AwsCreds, request: pytest.FixtureRequest) -> Iterator[aws.S3Bucket]:
    b = aws.S3Bucket(aws_creds, cloud_name("b", request.node.nodeid))
    try:
        yield b.create()
    finally:
        _teardown(b)


@pytest.fixture
def gcp_pubsub(request: pytest.FixtureRequest) -> Iterator[gcp.PubSub]:
    c, reason = creds.gcp()
    if c is None:
        pytest.skip(reason)
    ps = gcp.PubSub(c, cloud_name("t", request.node.nodeid), cloud_name("s", request.node.nodeid))
    try:
        yield ps.create()
    finally:
        _teardown(ps)


@pytest.fixture
def azure_hub(request: pytest.FixtureRequest) -> Iterator[azure.EventHub]:
    c, reason = creds.azure()
    if c is None:
        pytest.skip(reason)
    hub = azure.EventHub(
        c,
        name=cloud_name("eh", request.node.nodeid),
        container=cloud_name("ckpt", request.node.nodeid),
        consumer_group=cloud_name("cg", request.node.nodeid, max_len=50),
    )
    try:
        yield hub.create()
    finally:
        _teardown(hub)
