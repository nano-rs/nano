"""Real AWS pull: S3 object notifications via SQS (aws_s3) and SQS message
payloads (aws_sqs). Both run the full lifecycle in nano_e2e.pull."""

from __future__ import annotations

import pytest

from nano_e2e.providers import AwsS3Sqs, AwsSqsPayload
from nano_e2e.pull import run_lifecycle

pytestmark = [pytest.mark.cloud, pytest.mark.slow]


@pytest.mark.config_type("aws_s3", where="clickhouse/dev source configurations")
def test_aws_s3_sqs_lifecycle(nano, aws_creds, s3_bucket, sqs_queue, pull_run) -> None:
    s3_bucket.notify_queue(sqs_queue)
    report = run_lifecycle(pull_run(AwsS3Sqs(aws_creds, s3_bucket, sqs_queue)))
    assert report["distinct"] >= 40 * 2 + 20 + 20


@pytest.mark.config_type("aws_sqs", where="clickhouse/dev source configurations")
def test_aws_sqs_payload_lifecycle(nano, aws_creds, sqs_queue, pull_run) -> None:
    report = run_lifecycle(pull_run(AwsSqsPayload(aws_creds, sqs_queue)))
    assert report["distinct"] >= 40 * 2 + 20 + 20
