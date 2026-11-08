"""Slack access logs (`slack`, team.accessLogs) against a real workspace,
READ-ONLY.

team.accessLogs needs a user token with the `admin` scope, which Slack offers
only on Business+ and Enterprise Grid; nano's own workspace is on Pro, where
the scope is not in the picker (NAN-2200). So this SKIPs until
NANO_E2E_SLACK_USER_TOKEN (and, on Grid, NANO_E2E_SLACK_TEAM_ID) is present.
The audit logs API (`/audit/v1/logs`) is Enterprise Grid only and no spec
pulls it.

Access-log rows are aggregates per (user, IP, user agent) with a date_last
watermark, so events land only when someone signs in during the run. Runs the
shared collector flow with the shipped `slack_access_ocsf` parser.
"""

from __future__ import annotations

import pytest

from nano_e2e import creds
from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.connector_scenario import assert_events_on_lane, run_collector
from nano_e2e.feeds_live import SLACK_PARSER, Collector
from nano_e2e.stack import Stack

QUERY = 'metadata.product.name="Slack"'
CLASSES = frozenset({3002})


@pytest.fixture
def slack(live_runner) -> creds.SlackCreds:
    c, why = creds.slack()
    if c is None:
        pytest.skip(why)
    return c


def test_slack_access_logs_feed(
    stack: Stack, nano: Nano, page: uilib.UiPage, slack: creds.SlackCreds, mark: str, feed_cleanup, timeline
) -> None:
    collector = Collector(
        connector="slack",
        label="Slack access logs",
        parser=SLACK_PARSER,
        config={"TEAM_ID": slack.team_id},
        secrets={"USER_TOKEN": slack.user_token},
        rotate_secrets={"USER_TOKEN": slack.user_token},
        bad_secrets={"USER_TOKEN": "xoxp-nano-e2e-wrong-" + "0" * 24},
        refused=("invalid_auth", "not_authed", "401"),
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
