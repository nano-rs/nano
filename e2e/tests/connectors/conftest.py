"""Real-tenant connector pull feeds (NAN-4961): Okta, Google Workspace, Slack
and Entra, against the vendors themselves, never a mock.

`scripts/e2e.sh run connectors` brings up an OCSF stack whose
nano-connector-runner has NO test seam (`--profile connector-live`), builds
the web UI for the browser half of each scenario, and loads the tenant
credentials from Doppler or ~/.nan2361-secrets/e2e.env. A scenario whose
tenant credential is absent SKIPs naming the variables; on a stack without the
live runner every scenario SKIPs naming the profile.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from nano_e2e import feeds_live
from nano_e2e.client import Nano
from nano_e2e.fixtures_ui import page, ui, web  # noqa: F401 - fixtures
from nano_e2e.stack import Stack

pytestmark = pytest.mark.cloud


@pytest.fixture(scope="session")
def live_runner(stack: Stack) -> None:
    profiles = os.environ.get("E2E_PROFILES", "").split()
    if "connector-live" not in profiles:
        pytest.skip(
            "real-tenant connector feeds need the live runner: `scripts/e2e.sh run connectors` "
            f"(or `up --profile connector-live`); this stack runs profiles {profiles or 'none'}"
        )
    if not os.environ.get("NANO_SCHEMA_PROFILE", "udm").startswith("ocsf"):
        pytest.skip("the vendor parsers are OCSF: run on an ocsf stack (`run connectors` brings one up)")


@pytest.fixture
def feed_cleanup(nano: Nano) -> Iterator[list[str]]:
    """Feed ids to delete at teardown (identity feeds tombstone their users).
    Tenants are left intact."""
    ids: list[str] = []
    yield ids
    for fid in reversed(ids):
        feeds_live.delete_feed(nano, fid)
