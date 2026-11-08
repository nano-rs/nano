"""Real GCP Pub/Sub pull (gcp_pubsub): full lifecycle in nano_e2e.pull.

Runs with a service-account key or authorized_user ADC (NAN-4935).
"""

from __future__ import annotations

import pytest

from nano_e2e.providers import GcpPubSub
from nano_e2e.pull import run_lifecycle

pytestmark = [pytest.mark.cloud, pytest.mark.slow]


@pytest.mark.config_type("gcp_pubsub", where="clickhouse/dev source configurations")
def test_gcp_pubsub_lifecycle(nano, gcp_pubsub, pull_run) -> None:
    # authorized_user ADC works since the nano-rs Vector fork's NAN-4935 auth
    # (0.61.0-nano.3); service-account keys keep working.
    report = run_lifecycle(pull_run(GcpPubSub(gcp_pubsub.creds, gcp_pubsub)))
    assert report["distinct"] >= 40 * 2 + 20 + 20
