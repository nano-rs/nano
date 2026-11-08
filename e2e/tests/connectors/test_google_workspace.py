"""Google Workspace audit (`google_workspace`) against nano's own Workspace,
READ-ONLY (it is production: the scenario generates nothing there).

Needs NANO_E2E_GWS_SA_JSON (a key of a service account with domain-wide
delegation for admin.reports.audit.readonly) and NANO_E2E_GWS_ADMIN_EMAIL (the
super-admin it impersonates); SKIPs naming them until present. The candidate
is the existing `nano-collector-gws@nano-rs.iam.gserviceaccount.com` (NAN-2200),
whose key is not on this machine.

The feed starts point-forward (activation - 5 min), so events land only if
someone signs in or an admin acts during the run: a sign-in to the Workspace
just before the run is enough (logins are allowed; nothing else is written).
Runs the shared collector flow with the shipped `google_workspace_ocsf`
parser; a rotate re-submits the same key as a new version (one key only).
"""

from __future__ import annotations

import json

import pytest

from nano_e2e import creds
from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.connector_scenario import assert_events_on_lane, run_collector
from nano_e2e.feeds_live import GWS_PARSER, Collector
from nano_e2e.stack import Stack

QUERY = 'metadata.product.name="Google Workspace"'
CLASSES = frozenset({3002, 3006, 3007, 6003, 6006})


@pytest.fixture
def gws(live_runner) -> creds.GwsCreds:
    c, why = creds.gws()
    if c is None:
        pytest.skip(why)
    return c


def test_google_workspace_feed(
    stack: Stack, nano: Nano, page: uilib.UiPage, gws: creds.GwsCreds, mark: str, feed_cleanup, timeline
) -> None:
    key = json.loads(gws.sa_json)
    secrets = {"PRIVATE_KEY": key["private_key"], "CLIENT_EMAIL": key["client_email"]}
    collector = Collector(
        connector="google_workspace",
        label="Google Workspace audit",
        parser=GWS_PARSER,
        config={"ADMIN_EMAIL": gws.admin_email, "STREAMS": gws.streams},
        secrets={},
        gws_key_json=gws.sa_json,
        rotate_secrets=secrets,
        # A syntactically valid key Google never issued: the token
        # exchange is refused (invalid_grant / invalid_client).
        bad_secrets={**secrets, "CLIENT_EMAIL": f"nano-e2e-{mark[-8:]}@nano-rs.iam.gserviceaccount.com"},
        refused=("invalid_grant", "invalid_client", "unauthorized_client", "401", "400"),
        classes=CLASSES,
    )
    result = run_collector(
        stack=stack,
        nano=nano,
        page=page,
        mark=mark,
        feed_cleanup=feed_cleanup,
        timeline=timeline,
        c=collector,
        query=QUERY,
    )
    assert_events_on_lane(nano, result, collector, timeline)
