"""Connector pull feeds (NAN-4914 runner) end to end against the mock-vendor
profile: Okta, Google Workspace, Slack and the saas_api provider (Netskope).

nano-connector-runner polls `nano_e2e.mockvendor` through its sanctioned lab
seam (CONNECTOR_TEST_MODE + a loopback mock URL); every request still passes
the spec's vendor host policy. Per connector the scenario asserts:

- the feed is created only on top of a deployed lane parser;
- exactly the seeded events land, once each (paging is forced: page size 2);
- the vendor saw authenticated requests (the mock rejects bad credentials);
- the feed reports a successful run with the right event count;
- a feed with the wrong credential fails visibly (status + error), lands nothing.
"""

from __future__ import annotations

import re
from collections import Counter

import pytest

from nano_e2e import feeds
from nano_e2e.client import Nano, expect, row_text
from nano_e2e.mockvendor import MockVendor
from nano_e2e.waits import INGEST_VISIBLE, eventually

pytestmark = pytest.mark.mock_vendor

SEQ = re.compile(r"seq=(\d+)")
N = 5
# First run is due at creation; the runner ticks every 3 s in the profile.
FEED_RUN = 90.0


def _landed(nano: Nano, mark: str) -> Counter[int]:
    rows = nano.rows(f'"{mark}"', limit=500)
    return Counter(int(m.group(1)) for r in rows if (m := SEQ.search(row_text(r))))


def _feed(nano: Nano, feed_id: str) -> dict:
    return expect(nano.api.get(f"/api/connector-feeds/{feed_id}"), 200)


@pytest.fixture
def feed_cleanup(nano: Nano):
    ids: list[str] = []
    yield ids
    for fid in ids:
        nano.api.delete(f"/api/connector-feeds/{fid}")


@pytest.mark.parametrize("vendor", list(feeds.ADAPTERS))
def test_connector_feed_lands_vendor_events(
    nano: Nano, mock_vendor: MockVendor, mark: str, vendor: str, feed_cleanup, timeline
) -> None:
    adapter = feeds.ADAPTERS[vendor]()
    adapter.provision(mock_vendor, mark)
    adapter.seed(mock_vendor, mark, N)
    for lane in adapter.lanes:
        feeds.ensure_lane_source(nano, lane)
    timeline.step("lane parsers deployed", lanes=adapter.lanes)

    created = expect(
        nano.api.post("/api/connector-feeds", json=adapter.feed_body(f"{mark}-{vendor}")), 200, 201
    )
    feed = created.get("feed", created)
    feed_cleanup.append(feed["id"])
    timeline.step("feed created", id=feed["id"], source_type=feed.get("source_type"))

    seen = eventually(
        lambda: _landed(nano, mark),
        timeout=FEED_RUN + INGEST_VISIBLE,
        interval=5,
        desc=f"all {N} {vendor} events to land",
        ok=lambda c: set(c) >= set(range(N)),
    )
    detail = eventually(
        lambda: _feed(nano, feed["id"]),
        timeout=60,
        desc="feed reports a successful run",
        ok=lambda f: f.get("feed", f).get("last_status") == "success",
    )
    view = detail.get("feed", detail)
    runs = detail.get("runs") or []
    timeline.step(
        "landed",
        seen=dict(seen),
        status=view.get("last_status"),
        runs=runs[:2],
        vendor_requests=adapter.hits(mock_vendor),
    )
    assert set(seen) == set(range(N)), seen
    assert all(c == 1 for c in seen.values()), f"duplicated vendor events: {seen}"
    assert adapter.hits(mock_vendor) >= 1
    assert view.get("consecutive_failures") == 0, view
    assert sum(int(r.get("events") or 0) for r in runs if r.get("status") == "success") >= N, runs
    # The vendor events are the rows carrying a seeded `seq=`. The mark also
    # names the feed, so a free-text search for it also returns the platform
    # audit record of creating that feed (source_type=audit, searchable by
    # design and reliably written since NAN-4954); that row is not a vendor
    # event and says nothing about the connector's lanes (NAN-4980).
    rows = [r for r in nano.rows(f'"{mark}"', limit=50) if SEQ.search(row_text(r))]
    assert len(rows) == N, f"exactly the {N} vendor events: {len(rows)}"
    lanes = {str(r.get("source_type")) for r in rows}
    assert lanes <= set(adapter.lanes), f"events landed outside the connector's lanes: {lanes}"
    # On a UDM stack the parser's top-level marker field is not stored (only
    # metadata/ext/udm.* survive a DB parser); its metadata stamp is (NAN-4980).
    assert all(
        feeds.through_lane_parser(r, str(r.get("source_type"))) for r in rows
    ), f"events did not go through the lane parser: {rows[:1]}"


def test_connector_feed_bad_credential_fails_visibly(
    nano: Nano, mock_vendor: MockVendor, mark: str, feed_cleanup, timeline
) -> None:
    good = feeds.Okta()
    good.provision(mock_vendor, mark)
    good.seed(mock_vendor, mark, N)
    feeds.ensure_lane_source(nano, "okta")
    body = good.feed_body(f"{mark}-badcred")
    body["credentials"] = {"API_TOKEN": "00wrong" + "x" * 20}
    created = expect(nano.api.post("/api/connector-feeds", json=body), 200, 201)
    fid = created.get("feed", created)["id"]
    feed_cleanup.append(fid)

    view = eventually(
        lambda: _feed(nano, fid).get("feed", {}),
        timeout=FEED_RUN,
        desc="feed reports the failed run",
        ok=lambda f: f.get("last_status") == "failed",
    )
    timeline.step("failed as expected", error=view.get("last_error"))
    assert view.get("consecutive_failures", 0) >= 1, view
    assert "401" in (view.get("last_error") or ""), view
    assert not _landed(nano, mark), "a feed with a rejected credential must land nothing"
