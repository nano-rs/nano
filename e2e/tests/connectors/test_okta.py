"""Okta against a real developer org (OKTA_ORG_URL + OKTA_API_TOKEN in
e2e.env; SKIPs naming them until they are present).

- `okta_system_log`: the shared real-tenant collector flow
  (nano_e2e.connector_scenario) with the shipped `okta_ocsf` parser. Fresh
  activity is generated in the dev org first (one throwaway user created,
  deactivated and deleted: user.lifecycle.* -> User Management 3007), and the
  landed events must include exactly those, mapped (`user.name` = the login).
  The org's own System Log for the committed span is the truth set.
- `okta_users`: the identity feed writes exactly the org's users into the user
  directory, with group memberships; a second run duplicates nobody.
"""

from __future__ import annotations

from collections import Counter

import pytest

from nano_e2e import creds, feeds_live
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, row_text
from nano_e2e.connector_scenario import assert_events_on_lane, run_collector
from nano_e2e.feeds_live import OKTA_PARSER, Collector, row_get
from nano_e2e.stack import Stack
from nano_e2e.vendors_live import OktaTenant
from nano_e2e.waits import eventually

QUERY = 'metadata.product.vendor_name="Okta"'
# okta_ocsf: Authentication, User Management, Group Management, API Activity
# (and Base Event for an unparseable record, which must not happen here).
CLASSES = frozenset({3002, 3006, 3007, 6003})
REFUSED = ("401", "invalid token", "e0000011", "unauthorized")


@pytest.fixture
def okta(live_runner) -> tuple[creds.OktaCreds, OktaTenant]:
    c, why = creds.okta()
    if c is None:
        pytest.skip(why)
    return c, OktaTenant(c)


def test_okta_system_log_feed(
    stack: Stack,
    nano: Nano,
    page: uilib.UiPage,
    okta: tuple[creds.OktaCreds, OktaTenant],
    mark: str,
    feed_cleanup: list[str],
    timeline,
) -> None:
    c, tenant = okta
    made = tenant.generate_activity(mark[-8:])
    timeline.step("okta activity generated", user_id=made["user_id"])
    collector = Collector(
        connector="okta_system_log",
        label="Okta System Log",
        parser=OKTA_PARSER,
        config={"OKTA_DOMAIN": c.domain},
        secrets={"API_TOKEN": c.api_token},
        rotate_secrets={"API_TOKEN": c.rotate_api_token or c.api_token},
        bad_secrets={"API_TOKEN": "00nanoE2Ewrong" + "x" * 28},
        refused=REFUSED,
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
        vendor_uids=lambda since, until: {e["uuid"] for e in tenant.logs(since, until)},
        min_events=3,
    )
    # The generated lifecycle events landed, as User Management with the
    # target user as the subject (the admin token's user is the actor).
    mine = [r for r in result["rows"] if made["user_id"] in row_text(r)]
    kinds = Counter(int(row_get(r, "class_uid") or -1) for r in mine)
    timeline.step("generated events", count=len(mine), classes=dict(kinds))
    assert mine, "the generated user.lifecycle events never landed"
    assert set(kinds) == {3007}, f"user.lifecycle.* must be User Management (3007): {dict(kinds)}"
    assert all(str(row_get(r, "user.name") or "").lower() == made["login"].lower() for r in mine), [
        row_get(r, "user.name") for r in mine
    ]
    assert_events_on_lane(nano, result, collector, timeline)


def test_okta_users_directory_feed(
    nano: Nano,
    page: uilib.UiPage,
    okta: tuple[creds.OktaCreds, OktaTenant],
    mark: str,
    feed_cleanup: list[str],
    timeline,
) -> None:
    c, tenant = okta
    users = tenant.users()
    groups = tenant.groups()
    expected: dict[str, set[str]] = {}
    for gid, g in groups.items():
        for uid in tenant.group_members(gid):
            expected.setdefault(uid, set()).add(g["profile"]["name"])
    timeline.step("okta truth", users=len(users), groups=len(groups))

    name = f"{mark}-okta-users"
    page.driver.register_secret(c.api_token)
    feeds_live.ui_create_feed(page, "Okta directory", name, {"OKTA_DOMAIN": c.domain}, {"API_TOKEN": c.api_token})
    feed = eventually(lambda: feeds_live.feed_by_name(nano, name), timeout=30, desc="feed in the API")
    assert feed is not None
    feed_cleanup.append(feed["id"])
    assert feed["kind"] == "identity", feed

    d1 = feeds_live.wait_run(nano, feed["id"], after=0, timeout=300)
    synced = {u["external_id"]: u for u in feeds_live.directory_users(nano, feed["id"])}
    timeline.step("run 1", run=feeds_live.finished_runs(d1)[0], users=len(synced))
    assert set(synced) == set(users), (sorted(set(users) - set(synced))[:5], sorted(set(synced) - set(users))[:5])
    for uid, u in users.items():
        assert synced[uid].get("upn") == u["profile"]["login"], uid
    wrong = {u: w for u, w in expected.items() if not w <= set(synced[u].get("groups") or [])}
    assert not wrong, f"group memberships missing: {dict(list(wrong.items())[:3])}"

    feeds_live.run_now(nano, feed["id"])
    feeds_live.wait_run(nano, feed["id"], after=len(feeds_live.finished_runs(d1)))
    again = feeds_live.directory_users(nano, feed["id"])
    dupes = {k: n for k, n in Counter(u["external_id"] for u in again).items() if n > 1}
    assert not dupes, dupes
    row = feeds_live.ui_feed_row(page, name)
    assert row["status"].lower() == "healthy", row
