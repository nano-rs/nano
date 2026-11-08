"""Cloud pull provider adapters (the cloud side of nano_e2e.pull.PullProvider)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from nano_e2e import creds
from nano_e2e.client import Nano
from nano_e2e.cloud import aws, azure, gcp


def require_config_type(nano: Nano, config_type: str, where: str) -> None:
    """SKIP (with the reason) when this build does not offer the source type."""
    types = nano.source_config_types()
    if config_type not in types:
        pytest.skip(f"config_type {config_type!r} not offered by this build ({where}); have {sorted(types)}")


def _aws_keys(c: creds.AwsCreds, rotated: bool) -> dict[str, Any]:
    # A second key pair proves the swap; without one, rotate re-submits the
    # same pair, which still exercises rotate + redeploy.
    if rotated and c.rotate_access_key_id:
        return {"access_key_id": c.rotate_access_key_id, "secret_access_key": c.rotate_secret_access_key}
    return {"access_key_id": c.access_key_id, "secret_access_key": c.secret_access_key}


@dataclass
class AwsS3Sqs:
    creds: creds.AwsCreds
    bucket: aws.S3Bucket
    queue: aws.SqsQueue
    config_type: str = "aws_s3"
    credential_provider: str = "aws_s3"
    can_count_backlog: bool = True
    # Messages in flight when Vector stops come back after the SQS visibility
    # timeout, set explicitly below (NAN-4936; Vector's own default is 300s).
    redelivery_secs: float = 30
    _n: int = 0

    def credential_payload(self, rotated: bool = False) -> dict[str, Any]:
        return _aws_keys(self.creds, rotated)

    def connection_config(self) -> dict[str, Any]:
        return {
            "sqs_queue_url": self.queue.url,
            "region": self.creds.region,
            "poll_secs": 2,
            "visibility_timeout_secs": 30,
        }

    def publish(self, bodies: list[str]) -> None:
        # One object per publish: S3 -> event notification -> SQS -> Vector
        # reads the object. The real delivery path, nothing forged.
        self._n += 1
        self.bucket.put_lines(f"e2e/{self._n:05d}.ndjson", bodies)

    def backlog(self) -> int:
        return self.queue.depth()


@dataclass
class AwsSqsPayload:
    creds: creds.AwsCreds
    queue: aws.SqsQueue
    config_type: str = "aws_sqs"
    credential_provider: str = "aws_s3"  # both AWS config types bind an aws_s3 credential
    can_count_backlog: bool = True
    redelivery_secs: float = 30  # visibility_timeout_secs below

    def credential_payload(self, rotated: bool = False) -> dict[str, Any]:
        return _aws_keys(self.creds, rotated)

    def connection_config(self) -> dict[str, Any]:
        return {
            "queue_url": self.queue.url,
            "region": self.creds.region,
            "poll_secs": 2,
            "visibility_timeout_secs": 30,
        }

    def publish(self, bodies: list[str]) -> None:
        self.queue.send(bodies)

    def backlog(self) -> int:
        return self.queue.depth()


@dataclass
class GcpPubSub:
    creds: creds.GcpCreds
    ps: gcp.PubSub
    config_type: str = "gcp_pubsub"
    credential_provider: str = "gcp_pubsub"
    can_count_backlog: bool = False  # backlog lives in the subscription; not cheaply countable via REST
    redelivery_secs: float = 30  # ack_deadline_secs below

    def credential_payload(self, rotated: bool = False) -> dict[str, Any]:
        sa = self.creds.rotate_sa_json if rotated and self.creds.rotate_sa_json else self.creds.sa_json
        return {"credentials_json": sa}

    def connection_config(self) -> dict[str, Any]:
        return {"project": self.creds.project, "subscription": self.ps.subscription, "ack_deadline_secs": 30}

    def publish(self, bodies: list[str]) -> None:
        self.ps.publish(bodies)

    def backlog(self) -> int:
        return -1


@dataclass
class AzureEventHubs:
    hub: azure.EventHub
    config_type: str = "azure_event_hubs"
    credential_provider: str = "azure_event_hubs"
    can_count_backlog: bool = False
    redelivery_secs: float = 60  # replay from the last Blob checkpoint
    extra: dict[str, Any] = field(default_factory=dict)

    def credential_payload(self, rotated: bool = False) -> dict[str, Any]:
        return self.hub.credential_payload()

    def connection_config(self) -> dict[str, Any]:
        return self.hub.connection_config()

    def publish(self, bodies: list[str]) -> None:
        self.hub.send(bodies)

    def backlog(self) -> int:
        return -1
