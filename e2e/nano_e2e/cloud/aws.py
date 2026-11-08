"""Real AWS S3 + SQS test resources for the aws_s3 (S3 notifications via SQS)
and aws_sqs (message body is the log) pull sources."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from boto3.session import Session
from botocore.config import Config
from botocore.exceptions import ClientError

from nano_e2e.creds import AwsCreds
from nano_e2e.runid import CLOUD_PREFIX, gc_eligible, owner_tags

_CFG = Config(retries={"max_attempts": 8, "mode": "adaptive"}, connect_timeout=10, read_timeout=30)


def session(creds: AwsCreds) -> Session:
    return Session(
        aws_access_key_id=creds.access_key_id,
        aws_secret_access_key=creds.secret_access_key,
        region_name=creds.region,
    )


def _stamp() -> dict[str, str]:
    return owner_tags()


@dataclass
class SqsQueue:
    creds: AwsCreds
    name: str
    url: str = ""
    arn: str = ""
    _sqs: Any = field(default=None, repr=False)

    def create(self, policy: dict[str, Any] | None = None) -> SqsQueue:
        self._sqs = session(self.creds).client("sqs", config=_CFG)
        attrs = {"MessageRetentionPeriod": "3600", "VisibilityTimeout": "60"}
        if policy:
            attrs["Policy"] = json.dumps(policy)
        self.url = self._sqs.create_queue(QueueName=self.name, Attributes=attrs, tags=_stamp())["QueueUrl"]
        self.arn = self._sqs.get_queue_attributes(QueueUrl=self.url, AttributeNames=["QueueArn"])[
            "Attributes"
        ]["QueueArn"]
        return self

    def set_policy(self, policy: dict[str, Any]) -> None:
        self._sqs.set_queue_attributes(QueueUrl=self.url, Attributes={"Policy": json.dumps(policy)})

    def send(self, bodies: list[str]) -> None:
        for i in range(0, len(bodies), 10):
            chunk = bodies[i : i + 10]
            resp = self._sqs.send_message_batch(
                QueueUrl=self.url,
                Entries=[{"Id": str(n), "MessageBody": b} for n, b in enumerate(chunk)],
            )
            if resp.get("Failed"):
                raise RuntimeError(f"E2E-INFRA: SQS send failed: {resp['Failed']}")

    def depth(self) -> int:
        """Visible + in-flight messages (approximate, as SQS reports)."""
        a = self._sqs.get_queue_attributes(
            QueueUrl=self.url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        return int(a["ApproximateNumberOfMessages"]) + int(a["ApproximateNumberOfMessagesNotVisible"])

    def delete(self) -> None:
        if self._sqs and self.url:
            self._sqs.delete_queue(QueueUrl=self.url)


@dataclass
class S3Bucket:
    creds: AwsCreds
    name: str
    _s3: Any = field(default=None, repr=False)

    def create(self) -> S3Bucket:
        self._s3 = session(self.creds).client("s3", config=_CFG)
        kw: dict[str, Any] = {"Bucket": self.name}
        if self.creds.region != "us-east-1":
            kw["CreateBucketConfiguration"] = {"LocationConstraint": self.creds.region}
        self._s3.create_bucket(**kw)
        self._s3.get_waiter("bucket_exists").wait(Bucket=self.name)
        self._s3.put_bucket_tagging(
            Bucket=self.name, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _stamp().items()]}
        )
        return self

    def notify_queue(self, queue: SqsQueue) -> None:
        """Wire s3:ObjectCreated:* to the queue (native S3 event notifications:
        the real delivery path, no harness-forged S3 events)."""
        queue.set_policy(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "s3.amazonaws.com"},
                        "Action": "sqs:SendMessage",
                        "Resource": queue.arn,
                        "Condition": {"ArnLike": {"aws:SourceArn": f"arn:aws:s3:::{self.name}"}},
                    }
                ],
            }
        )
        self._s3.put_bucket_notification_configuration(
            Bucket=self.name,
            NotificationConfiguration={
                "QueueConfigurations": [{"QueueArn": queue.arn, "Events": ["s3:ObjectCreated:*"]}]
            },
        )

    def put_lines(self, key: str, lines: list[str]) -> None:
        self._s3.put_object(Bucket=self.name, Key=key, Body=("\n".join(lines) + "\n").encode())

    def delete(self) -> None:
        if not self._s3:
            return
        _empty_and_delete_bucket(self._s3, self.name)


def _empty_and_delete_bucket(s3: Any, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": objs, "Quiet": True})
    s3.delete_bucket(Bucket=name)


def gc(
    creds: AwsCreds, older_than: timedelta, exclude_runs: set[str] | frozenset[str] = frozenset()
) -> list[str]:
    """Delete harness-owned buckets/queues (ownership tags, inactive run, past
    the cutoff). Returns what was verifiably deleted."""
    cutoff = (datetime.now(UTC) - older_than).timestamp()
    sess = session(creds)
    s3 = sess.client("s3", config=_CFG)
    sqs = sess.client("sqs", config=_CFG)
    removed: list[str] = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        if not name.startswith(CLOUD_PREFIX):
            continue
        try:
            tagset = s3.get_bucket_tagging(Bucket=name).get("TagSet", [])
        except ClientError:
            continue  # untagged: not provably ours
        tags = {t["Key"]: t["Value"] for t in tagset}
        if gc_eligible(name, tags, cutoff_epoch=cutoff, exclude_runs=set(exclude_runs)):
            _empty_and_delete_bucket(s3, name)
            removed.append(f"s3://{name}")
    for url in sqs.list_queues(QueueNamePrefix=CLOUD_PREFIX).get("QueueUrls", []):
        name = url.rsplit("/", 1)[-1]
        tags = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
        if gc_eligible(name, tags, cutoff_epoch=cutoff, exclude_runs=set(exclude_runs)):
            sqs.delete_queue(QueueUrl=url)
            removed.append(url)
    return removed
