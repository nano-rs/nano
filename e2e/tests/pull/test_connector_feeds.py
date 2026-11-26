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
# NAN-5903: a start that sets up log sources deploys them first (the OCSF
# sample check plus a Vector reload); a large parser takes over a minute on a
# debug build. The edge allows these paths 300 s.
SETUP_TIMEOUT = 300.0
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


def _hec_claimants(nano: Nano, lane: str) -> list[dict]:
    body = expect(nano.api.get("/api/log-sources"), 200)
    items = body if isinstance(body, list) else body.get("sources") or body.get("items") or []
    return [
        s
        for s in items
        if s.get("enabled")
        and str(s.get("source_type")).lower() in ("splunk_hec", "splunk", "hec")
        and lane in (s.get("match_values") or [])
    ]


# NAN-5903: per connector, the streams the one-submit create asks for. The
# Google Workspace set includes `saml`, which the catalog parser's own match
# values leave out, so the setup must widen its source.
ONE_SUBMIT_STREAMS = {
    "google_workspace": "login,admin,saml",
    "saas_api_netskope": "application,alert,audit",
}


@pytest.mark.parametrize("vendor", list(feeds.ADAPTERS))
def test_feed_one_submit_sets_up_its_log_sources(
    nano: Nano, mock_vendor: MockVendor, mark: str, vendor: str, feed_cleanup, timeline
) -> None:
    """NAN-5903: every bundled collector is created in ONE submit on a stack
    where its lanes have no log source. The create (with the UI's consent,
    `set_up_log_sources`) imports the connector's catalog OCSF parser as one
    HEC log source covering every lane, deploys it through the OCSF gate,
    audits it, and the vendor events land. A second feed reuses it."""
    adapter = feeds.ADAPTERS[vendor]()
    adapter.provision(mock_vendor, mark)
    adapter.seed(mock_vendor, mark, N)
    body = adapter.feed_body(f"{mark}-{vendor}-onesubmit")
    if vendor in ONE_SUBMIT_STREAMS:
        body["config"]["STREAMS"] = ONE_SUBMIT_STREAMS[vendor]
    plan = expect(
        nano.api.post("/api/connector-feeds/plan", json={"connector": adapter.connector, "config": body["config"]}),
        200,
    )
    lanes = sorted(plan["lanes"])
    # Precondition: zero log sources on these lanes (harness lane parsers and
    # any catalog / pull source an earlier scenario left).
    released = feeds.release_setup_sources(nano, lanes, adapter.connector)
    timeline.step("lanes released", released=released, lanes=lanes)
    try:
        plan = expect(
            nano.api.post("/api/connector-feeds/plan", json={"connector": adapter.connector, "config": body["config"]}),
            200,
        )
        timeline.step("plan", plan=plan)
        assert plan["missing_permissions"] == [], plan
        assert plan["changes_log_sources"] is True and plan["creates"] == 1, plan
        # Without consent the feed is refused, naming the lanes; nothing is written.
        refused = nano.api.post("/api/connector-feeds", json=body)
        assert refused.status_code == 400, refused.text
        err = refused.json().get("error", {})
        assert err.get("code") == "LOG_SOURCES_MISSING", refused.text
        assert sorted(err.get("details", {}).get("missing_lanes", [])) == lanes, refused.text

        created = expect(nano.api.post("/api/connector-feeds", json={**body, "set_up_log_sources": True}, timeout=SETUP_TIMEOUT), 201)
        feed_cleanup.append(created["id"])
        steps = created.get("log_sources") or []
        timeline.step("created in one submit", log_sources=steps)
        created_sources = [s["log_source_id"] for s in steps if s["action"] == "create"]
        assert len(created_sources) == 1, steps
        assert {lane for s in steps for lane in s["lanes"]} == set(lanes), steps
        for lane in lanes:
            claimants = _hec_claimants(nano, lane)
            assert len(claimants) == 1, f"exactly one enabled HEC source for {lane}: {claimants}"
            assert claimants[0].get("deployed"), claimants[0]

        # Audited per created source (audit delivery is asynchronous: poll).
        def audited(sid: str) -> bool:
            logs = expect(nano.api.get("/api/audit", params={"action": "log_source_created", "limit": 200}), 200)
            rows = logs.get("logs", logs) if isinstance(logs, dict) else logs
            return any(
                str(r.get("resource_id")) == sid and "connector_feed_setup" in str(r.get("details")) for r in rows
            )

        for sid in created_sources:
            eventually(lambda sid=sid: audited(sid), timeout=60, interval=2, desc=f"log_source_created audit for {sid}")

        seen = eventually(
            lambda: _landed(nano, mark),
            timeout=FEED_RUN + INGEST_VISIBLE + 120,
            interval=5,
            desc=f"all {N} {vendor} events to land",
            ok=lambda c: set(c) >= set(range(N)),
        )
        assert all(c == 1 for c in seen.values()), f"duplicated vendor events: {seen}"

        # Idempotent: the same lanes on a second feed reuse the source.
        again = expect(
            nano.api.post(
                "/api/connector-feeds",
                json={**body, "name": f"{mark}-{vendor}-onesubmit-2", "set_up_log_sources": True},
                timeout=SETUP_TIMEOUT,
            ),
            201,
        )
        feed_cleanup.append(again["id"])
        assert all(s["action"] == "reuse" for s in again.get("log_sources") or []), again
        timeline.step("second submit reused", log_sources=again.get("log_sources"))
    finally:
        for fid in list(feed_cleanup):
            nano.api.delete(f"/api/connector-feeds/{fid}")
        feed_cleanup.clear()
        # Lanes are shared by every scenario on the stack: give them back so
        # the harness lane parsers can claim them again (found by lane, so a
        # failure before the create's answer still cleans up).
        feeds.release_setup_sources(nano, lanes, adapter.connector)


@pytest.mark.parametrize("connector", ["okta_users", "entra_directory"])
def test_identity_feeds_need_no_log_source(nano: Nano, connector: str) -> None:
    """NAN-5903: an identity feed writes the user directory, not a lane: its
    plan sets up nothing."""
    plan = expect(nano.api.post("/api/connector-feeds/plan", json={"connector": connector, "config": {}}), 200)
    assert plan["lanes"] == [] and plan["log_sources"] == [] and plan["changes_log_sources"] is False, plan


def test_resume_with_missing_log_sources_is_refused_then_fixed(
    nano: Nano, mock_vendor: MockVendor, mark: str, feed_cleanup, timeline
) -> None:
    """NAN-5903: a paused feed whose lane source was deleted cannot be resumed
    into a lane that drops its events: the resume is refused with
    LOG_SOURCES_MISSING naming the lane, and Fix setup (the same call with
    `set_up_log_sources`) sets the source up again and resumes."""
    adapter = feeds.Okta()
    adapter.provision(mock_vendor, mark)
    lanes = list(adapter.lanes)
    feeds.release_setup_sources(nano, lanes, adapter.connector)
    try:
        created = expect(
            nano.api.post("/api/connector-feeds", json={**adapter.feed_body(f"{mark}-fix"), "set_up_log_sources": True}, timeout=SETUP_TIMEOUT),
            201,
        )
        fid = created["id"]
        feed_cleanup.append(fid)
        sources = sorted({s["log_source_id"] for s in created.get("log_sources") or [] if s.get("log_source_id")})
        expect(nano.api.patch(f"/api/connector-feeds/{fid}", json={"enabled": False}), 200)
        for sid in sources:
            feeds.delete_log_source(nano, sid)
        timeline.step("paused and its lane sources deleted", sources=sources)

        refused = nano.api.patch(f"/api/connector-feeds/{fid}", json={"enabled": True})
        assert refused.status_code == 400, refused.text
        err = refused.json().get("error", {})
        assert err.get("code") == "LOG_SOURCES_MISSING", refused.text
        assert err.get("details", {}).get("missing_lanes") == lanes, refused.text
        assert _feed(nano, fid).get("feed", {}).get("enabled") is False

        fixed = expect(
            nano.api.patch(f"/api/connector-feeds/{fid}", json={"enabled": True, "set_up_log_sources": True}, timeout=SETUP_TIMEOUT), 200
        )
        assert fixed.get("enabled") is True, fixed
        for lane in lanes:
            claimants = _hec_claimants(nano, lane)
            assert len(claimants) == 1 and claimants[0].get("deployed"), claimants
        timeline.step("fixed")
    finally:
        for f in list(feed_cleanup):
            nano.api.delete(f"/api/connector-feeds/{f}")
        feed_cleanup.clear()
        feeds.release_setup_sources(nano, lanes, adapter.connector)
