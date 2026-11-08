"""Real Azure Event Hubs pull (azure_event_hubs, NAN-4914-pull).

The Event Hubs source type arrives with the NAN-4914 pull port; on a build
without it the scenario SKIPs at the capability probe (the config type is not
offered), never passes vacuously. Event Hubs starts at `latest`, which the
lifecycle's warm-up probe handles.
"""

from __future__ import annotations

import pytest

from nano_e2e.providers import AzureEventHubs
from nano_e2e.pull import run_lifecycle

pytestmark = [pytest.mark.cloud, pytest.mark.slow]


@pytest.mark.config_type("azure_event_hubs", where="lands with NAN-4914-pull")
def test_azure_event_hubs_lifecycle(nano, azure_hub, pull_run) -> None:
    report = run_lifecycle(pull_run(AzureEventHubs(azure_hub)))
    assert report["distinct"] >= 40 * 2 + 20 + 20
