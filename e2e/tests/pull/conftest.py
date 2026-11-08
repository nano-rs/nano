"""Cloud pull fixtures: real AWS / GCP / Azure test resources, created per test
under the `nano-e2e-<runid>` prefix and ALWAYS torn down (finalizers run even
when the scenario fails). Without credentials the scenario SKIPs with the
reason; without the product feature (config type absent) it SKIPs too."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from nano_e2e.client import Nano
from nano_e2e.fixtures_cloud import (  # noqa: F401 - fixtures
    aws_creds,
    azure_hub,
    gcp_pubsub,
    s3_bucket,
    sqs_queue,
)
from nano_e2e.providers import require_config_type
from nano_e2e.pull import PullRun
from nano_e2e.runid import route_key
from nano_e2e.stack import Stack

pytestmark = pytest.mark.cloud


# ---------------------------------------------------------------- fixtures
# Fixture order matters: scenarios request the cloud fixtures BEFORE pull_run,
# so teardown removes the nano source first and the queue/topic after it.


@pytest.fixture(autouse=True)
def _product_probe(request: pytest.FixtureRequest) -> None:
    """Autouse, so it runs BEFORE the cloud fixtures: a build without the source
    type skips for that reason, without touching the cloud."""
    m = request.node.get_closest_marker("config_type")
    if m:
        nano = request.getfixturevalue("nano")
        require_config_type(nano, m.args[0], m.kwargs.get("where", ""))


@pytest.fixture
def pull_run(stack: Stack, nano: Nano, mark: str, timeline, request: pytest.FixtureRequest) -> Iterator:
    """Factory for a PullRun bound to a provider; cleans up product objects."""
    runs: list[PullRun] = []

    def make(provider: Any) -> PullRun:
        run = PullRun(
            stack=stack,
            nano=nano,
            provider=provider,
            mark=mark,
            source_type=route_key(request.node.nodeid, "pull"),
            step=timeline.step,
        )
        runs.append(run)
        return run

    yield make
    for run in runs:
        run.cleanup()
