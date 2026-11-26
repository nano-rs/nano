"""Pull feeds (connector feeds, NAN-4914) set up in the web UI against the
mock-vendor profile: New pull feed → connector → config + secrets → Create
feed, for Okta, Google Workspace (service-account key) and Slack. The feed's
row (connector, lane, status, schedule) must equal the feed API, and exactly
the events the mock served must be what search shows in the API and the UI."""

from __future__ import annotations

import re
import secrets
import time
from collections import Counter
from typing import Any

import pytest

from nano_e2e import feeds, ui_pull
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, row_text
from nano_e2e.client import expect as api_expect
from nano_e2e.mockvendor import MockVendor
from nano_e2e.ui import field, rx
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually, vector_reloads_quiet

pytestmark = pytest.mark.mock_vendor

SEQ = re.compile(r"seq=(\d+)")
N = 5
# NAN-5903: a start that sets up log sources deploys them first (the OCSF
# sample check plus a Vector reload); a large parser takes over a minute on a
# debug build. The edge allows these paths 300 s.
SETUP_TIMEOUT = 300.0


def _feed_by_name(nano: Nano, name: str) -> dict | None:
    body = api_expect(nano.api.get("/api/connector-feeds"), 200)
    items = body if isinstance(body, list) else body.get("feeds", body.get("items", []))
    return next((f for f in items if f.get("name") == name), None)


# NAN-5903: fields are found by their config / credential key (the labels are
# plain English); a list field with known values is a checkbox group, set
# separately (CHOICES).
def _okta(a: Any) -> tuple[str, list[dict[str, Any]]]:
    return "Okta System Log", [
        ui_pull.feed_config_field("OKTA_DOMAIN", a.domain),
        ui_pull.feed_credential_field("API_TOKEN", a.token),
    ]


def _gws(a: Any) -> tuple[str, list[dict[str, Any]]]:
    return "Google Workspace audit", [
        ui_pull.feed_config_field("ADMIN_EMAIL", a.admin),
        field({"css": "textarea[placeholder^='{\"type\"']"}, a.sa.credentials_json(), secret=True),
    ]


def _slack(a: Any) -> tuple[str, list[dict[str, Any]]]:
    return "Slack access logs", [ui_pull.feed_credential_field("USER_TOKEN", a.token)]


# Only the lane the harness parser serves, so no log source setup is asked.
CHOICES = {"google_workspace": {"STREAMS": "login"}}


CASES = {
    "okta": (feeds.Okta, _okta),
    "google_workspace": (feeds.GoogleWorkspace, _gws),
    "slack": (feeds.Slack, _slack),
}


@pytest.mark.parametrize("vendor", list(CASES))
def test_ui_pull_feed(
    stack: Stack, page: uilib.UiPage, nano: Nano, mock_vendor: MockVendor, mark: str, vendor: str, timeline
) -> None:
    adapter_cls, form = CASES[vendor]
    adapter = adapter_cls()
    adapter.provision(mock_vendor, mark)
    adapter.seed(mock_vendor, mark, N)
    for lane in adapter.lanes:
        feeds.ensure_lane_source(nano, lane)
    # Start the feed only after the lane's Vector reloads settle (see the
    # stranding finding below and in the README).
    timeline.step("vector reloads settled", waited=round(vector_reloads_quiet(stack.project)))
    label, fields = form(adapter)
    name = f"{mark}-{vendor}-ui"
    try:
        layout = ui_pull.ingestion_layout(page)
        page.goto(ui_pull.pull_feeds_path(layout))
        if layout == ui_pull.LOG_SOURCES_TABS:
            page.wait_for({"testid": "pull-feeds-page"}, timeout_ms=60_000)
        page.click({"role": "button", "name": rx("New pull feed")})
        dlg = {"role": "dialog"}
        page.choose({"role": "combobox", "within": dlg, "nth": 0}, rx(f"^{re.escape(label)}"))
        page.fill(field({"placeholder": "Okta production", "within": dlg}, name))
        page.fill(*[{**f, "find": {**f["find"], "within": dlg}} for f in fields])
        for key, value in CHOICES.get(vendor, {}).items():
            ui_pull.set_feed_choices(page, key, value, dlg)
        ui_pull.submit_feed_form(page, dlg, expect_setup=False)
        timeline.step("ui: feed created", feed=name, connector=label)

        # The lane was just published, so Vector is still reloading: an event
        # the connector delivers (acked) during a reload can sit until a LATER
        # reload flushes it, ~2.5 min (README finding "Events stranded by a
        # Vector topology reload"). Allow for that, and record when it happens.
        created = time.monotonic()

        def landed() -> Counter[int]:
            return Counter(
                int(m.group(1)) for r in nano.rows(f'"{mark}"', limit=100) if (m := SEQ.search(row_text(r)))
            )

        seen = eventually(
            landed,
            timeout=240 + INGEST_VISIBLE,
            interval=5,
            desc=f"{N} {vendor} events",
            ok=lambda c: set(c) == set(range(N)),
        )
        if (late := time.monotonic() - created) > 90 + INGEST_VISIBLE:
            timeline.step("late arrival (stranded by a Vector reload)", seconds=round(late))
        assert all(c == 1 for c in seen.values()), seen
        api = eventually(
            lambda: _feed_by_name(nano, name),
            timeout=60,
            desc="feed API reports success",
            ok=lambda f: bool(f) and f.get("last_status") == "success",
        )
        assert api is not None
        timeline.step("api", status=api["last_status"], lane=api["source_type"])

        # The table row says what the API says (columns by header: NAN-4941
        # adds a credential column).
        page.reload()
        within = {"testid": "pull-feeds-region"} if layout == ui_pull.LOG_SOURCES_TABS else None
        row = page.op("row_cells", contains=name, within=within, timeout=60_000)
        timeline.step("ui row", cells=row)
        assert row["connector"].startswith(label), row
        # Fan-out feeds (GWS) report their lane as the spec template, e.g.
        # `gws_{{item}}`, in the API and the UI alike (NAN-4937 finding); the
        # UI must say what the API says.
        assert row["lane"] == api["source_type"], row
        assert row["status"].lower() == "healthy", row
        assert row["schedule"] == api["effective_schedule"], row

        uilib.run_search(page, f'"{mark}"')
        # == the API for the same query (the feed's own run records also
        # carry the marker in the feed name; the vendor events are checked
        # exactly above).
        assert uilib.results_count(page) == nano.search(f'"{mark}"')["total_count"]

        if layout == ui_pull.LOG_SOURCES_TABS:
            _row_actions(page, nano, mock_vendor, adapter, vendor, name, timeline)
    finally:
        f = _feed_by_name(nano, name)
        if f:
            nano.api.delete(f"/api/connector-feeds/{f['id']}")


def test_ui_new_pull_feed_is_a_right_flyout(
    stack: Stack, page: uilib.UiPage, nano: Nano, mock_vendor: MockVendor, mark: str, timeline
) -> None:
    """NAN-4970: "+ New pull feed" opens the shared right-side Sheet flyout
    (pinned to the right edge, full height), not a centered dialog, and the
    feed created from it against the mock vendor is what the feed API holds."""
    adapter = feeds.Okta()
    adapter.provision(mock_vendor, mark)
    for lane in adapter.lanes:
        feeds.ensure_lane_source(nano, lane)
    layout = ui_pull.ingestion_layout(page)
    if layout != ui_pull.LOG_SOURCES_TABS:
        pytest.skip("pre-NAN-4941 build: no Log Sources Pull feeds tab")
    name = f"{mark}-okta-flyout"
    sheet = {"testid": "new-pull-feed-sheet"}
    try:
        page.goto(ui_pull.PULL_FEEDS_PATH)
        page.wait_for({"testid": "pull-feeds-page"}, timeout_ms=60_000)
        page.click({"role": "button", "name": rx("New pull feed")})
        page.wait_for(sheet)
        assert page.attr(sheet, "role") == "dialog"
        # Wait out the slide-in, then read where it sits.
        box = eventually(
            lambda: page.rect(sheet),
            timeout=5,
            interval=0.2,
            desc="flyout settled at the right edge",
            ok=lambda r: abs(r["right"] - r["viewport_width"]) <= 1,
        )
        timeline.step("flyout geometry", **{k: round(v) for k, v in box.items()})
        assert abs(box["top"]) <= 1 and abs(box["bottom"] - box["viewport_height"]) <= 1, box
        assert box["left"] > box["viewport_width"] / 3, box  # a side panel, not a centered modal

        label, fields = _okta(adapter)
        page.choose({"role": "combobox", "within": sheet, "nth": 0}, rx(f"^{re.escape(label)}"))
        page.fill(field({"placeholder": "Okta production", "within": sheet}, name))
        page.fill(*[{**f, "find": {**f["find"], "within": sheet}} for f in fields])
        ui_pull.submit_feed_form(page, sheet, expect_setup=False)
        page.wait_text("Pull feed created", exact=False)
        api = eventually(lambda: _feed_by_name(nano, name), timeout=30, desc="feed in the API", ok=bool)
        assert api["connector"] == adapter.connector, api
        assert api["config"].get("OKTA_DOMAIN") == adapter.domain, api
        assert api["credential_id"], api
        assert "identity_allow_shrink" not in api["config"], api
        row = page.op("row_cells", contains=name, within={"testid": "pull-feeds-region"}, timeout=60_000)
        assert row["connector"].startswith(label), row
        timeline.step("created from the flyout", feed=api["id"])
    finally:
        f = _feed_by_name(nano, name)
        if f:
            nano.api.delete(f"/api/connector-feeds/{f['id']}")


def _row_actions(
    page: uilib.UiPage, nano: Nano, mock: MockVendor, adapter: Any, vendor: str, name: str, timeline
) -> None:
    """NAN-4941 row actions: pause / resume (== the feed API), reset a stream,
    and (Okta) rotate the credential from the row: the vendor then rejects the
    old token, and the next run authenticates with the new one."""
    region = {"testid": "pull-feeds-region"}
    row = {"role": "row", "name": rx(re.escape(name)), "within": region}
    page.goto(ui_pull.PULL_FEEDS_PATH)
    page.click({"role": "button", "name": "Pause", "within": row})
    page.wait_text("Feed paused", exact=False)
    eventually(
        lambda: _feed_by_name(nano, name),
        timeout=30,
        desc="paused in the API",
        ok=lambda f: bool(f) and f.get("enabled") is False,
    )
    assert page.row_cells(name, within=region)["status"].lower() == "paused"
    page.click({"role": "button", "name": "Resume", "within": row})
    page.wait_text("Feed resumed", exact=False)
    eventually(
        lambda: _feed_by_name(nano, name),
        timeout=30,
        desc="resumed in the API",
        ok=lambda f: bool(f) and f.get("enabled") is True,
    )
    timeline.step("pause/resume == API")

    page.click({"role": "button", "name": "Reset", "within": row})
    dlg = {"role": "alertdialog"}
    page.wait_text("Re-anchor a stream", exact=False)
    if page.count({"role": "combobox", "within": dlg}):
        # A time-window stream (fan-out feeds also list non-window checkpoints).
        page.click({"role": "combobox", "within": dlg, "nth": 0})
        window = {"role": "option", "name": rx("window", "i")}
        page.click(window if page.count(window) else {"role": "option", "name": rx(".")})
    page.click({"role": "button", "name": "Reset", "exact": True, "within": dlg})
    if vendor != "okta":
        # Only time-window streams WITHOUT fan-out can be re-anchored
        # (nano-connector service/reset.rs): Slack is a watermark program and
        # Google Workspace fans out per application. Refused, visibly.
        page.wait_text("Could not reset the stream", exact=False)
        timeline.step("reset refused for a stream that cannot be re-anchored")
    else:
        page.wait_text("Stream re-anchored", exact=False)
        timeline.step("stream re-anchored")

    if vendor != "okta":
        return
    new_token = "00e2erot" + secrets.token_hex(16)
    page.driver.register_secret(new_token)
    page.click({"role": "button", "name": "Rotate", "within": row})
    page.fill(
        field(
            {"css": "input[type=password]", "within": {"role": "dialog", "last": True}},
            new_token,
            secret=True,
        )
    )
    page.click({"role": "button", "name": rx("^Rotate & activate")})
    page.wait_text("Credential rotated", exact=False, timeout_ms=60_000)
    mock.okta_tenant(adapter.domain, new_token)  # the vendor now accepts only the new token
    since = time.time()
    # Pause + resume schedules the next run now.
    page.click({"role": "button", "name": "Pause", "within": row})
    page.wait_text("Feed paused", exact=False)
    page.click({"role": "button", "name": "Resume", "within": row})
    eventually(
        lambda: [h for h in mock.hits(adapter.domain, "/api/v1/logs") if h.t >= since],
        timeout=120,
        interval=3,
        desc="a run after the rotation",
        ok=lambda hs: any(h.status == 200 for h in hs),
    )
    feed = eventually(
        lambda: _feed_by_name(nano, name),
        timeout=60,
        desc="success after rotate",
        ok=lambda f: bool(f) and f.get("last_status") == "success",
    )
    timeline.step(
        "rotated from the row: next run authenticated with the new token", feed=feed and feed.get("id")
    )


def _gws_one_submit(
    page: uilib.UiPage, nano: Nano, mock_vendor: MockVendor, mark: str, timeline, *, via_marketplace: bool
) -> None:
    """A Google Workspace feed created in ONE submit on a stack where no
    Workspace lane has a log source, started from Pull feeds or from the
    Marketplace card (which hops to Pull feeds with the connector
    preselected). Streams is a multi-select with the usual apps ticked;
    Create feed asks first ("This will also create 1 log source"), then sets
    the source up from the catalog parser and creates the feed. The seeded
    sign-ins land."""
    adapter = feeds.GoogleWorkspace()
    adapter.provision(mock_vendor, mark)
    adapter.seed(mock_vendor, mark, N)
    defaults = ["login", "admin", "token", "drive", "groups", "saml", "user_accounts"]
    lanes = [f"gws_{s}" for s in defaults]
    # Precondition: zero log sources on these lanes.
    timeline.step("lanes released", released=feeds.release_setup_sources(nano, lanes, adapter.connector))
    name = f"{mark}-gws-onesubmit-{'mp' if via_marketplace else 'ui'}"
    sheet = {"testid": "new-pull-feed-sheet"}
    try:
        if via_marketplace:
            page.goto("/marketplace")
            card = {"css": "[data-mp-slug='collector:google_workspace']"}
            page.wait_for(card, timeout_ms=60_000)
            # The card has no form of its own: it hops to Pull feeds.
            page.click(card)
            page.wait_url(r"/ingestion/log-sources/pull-feeds", timeout_ms=30_000)
            page.wait_for(sheet, timeout_ms=30_000)
        else:
            page.goto(ui_pull.PULL_FEEDS_PATH)
            page.wait_for({"testid": "pull-feeds-page"}, timeout_ms=60_000)
            page.click({"role": "button", "name": rx("New pull feed")})
            page.wait_for(sheet)
            page.choose({"role": "combobox", "within": sheet, "nth": 0}, rx("^Google Workspace audit"))
        # Plain-English labels, never the raw keys; no jargon banner.
        assert page.count({"text": "Admin email to act as", "within": sheet}), "plain label"
        assert page.count({"text": "Which Workspace apps to collect", "within": sheet}), "plain label (and preselected)"
        for raw in ("ADMIN_EMAIL", "STREAMS"):
            assert not page.count({"text": raw, "exact": True, "within": sheet}), f"raw key {raw} shown"
        assert not page.count({"text": "HEC log source first", "exact": False, "within": sheet})
        assert page.count({"placeholder": "Default: every 5 minutes", "within": sheet})
        ticked = [
            v
            for v in page.attrs(
                {"css": "[data-testid='choices-STREAMS'] [data-choice][aria-checked='true']", "within": sheet}, "data-choice"
            )
            if v
        ]
        assert sorted(ticked) == sorted(defaults), ticked
        page.fill(
            field({"placeholder": "Okta production", "within": sheet}, name),
            *[{**f, "find": {**f["find"], "within": sheet}} for f in _gws(adapter)[1]],
        )
        shown = ui_pull.submit_feed_form(page, sheet, expect_setup=True)
        timeline.step("ui: confirmed setup and created", confirm=shown, via_marketplace=via_marketplace)
        page.wait_text("Created the log source", exact=False, timeout_ms=30_000)

        feed = eventually(lambda: _feed_by_name(nano, name), timeout=30, desc="feed in the API", ok=bool)
        assert feed is not None
        assert sorted(str(feed["config"]["STREAMS"]).split(",")) == sorted(defaults), feed["config"]
        body = api_expect(nano.api.get("/api/log-sources"), 200)
        items = body if isinstance(body, list) else body.get("sources") or body.get("items") or []
        for lane in lanes:
            claim = [s for s in items if s.get("enabled") and lane in (s.get("match_values") or [])]
            assert len(claim) == 1 and claim[0].get("deployed"), f"{lane}: {claim}"
        seen = eventually(
            lambda: Counter(
                int(m.group(1)) for r in nano.rows(f'"{mark}"', limit=100) if (m := SEQ.search(row_text(r)))
            ),
            timeout=240 + INGEST_VISIBLE,
            interval=5,
            desc=f"{N} Workspace sign-ins",
            ok=lambda c: set(c) == set(range(N)),
        )
        assert all(c == 1 for c in seen.values()), seen
    finally:
        f = _feed_by_name(nano, name)
        if f:
            nano.api.delete(f"/api/connector-feeds/{f['id']}")
        # Give the shared lanes back (found by lane: also after a mid-test failure).
        feeds.release_setup_sources(nano, lanes, adapter.connector)


def test_ui_google_workspace_feed_one_submit_sets_up_log_sources(
    stack: Stack, page: uilib.UiPage, nano: Nano, mock_vendor: MockVendor, mark: str, timeline
) -> None:
    """NAN-5903: the Pull feeds entry point, from zero log sources."""
    _gws_one_submit(page, nano, mock_vendor, mark, timeline, via_marketplace=False)


def test_ui_marketplace_hops_to_pull_feeds_and_sets_up_in_one_submit(
    stack: Stack, page: uilib.UiPage, nano: Nano, mock_vendor: MockVendor, mark: str, timeline
) -> None:
    """NAN-5903: the Marketplace entry point lands on Pull feeds with the
    connector preselected, from zero log sources."""
    _gws_one_submit(page, nano, mock_vendor, mark, timeline, via_marketplace=True)


def test_ui_resume_with_missing_log_sources_offers_fix_setup(
    stack: Stack, page: uilib.UiPage, nano: Nano, mock_vendor: MockVendor, mark: str, timeline
) -> None:
    """NAN-5903: resuming a feed whose lane source was deleted is refused
    ("Some log sources this feed needs are missing"); Fix setup confirms,
    sets the source up again and resumes the feed."""
    adapter = feeds.Okta()
    adapter.provision(mock_vendor, mark)
    lanes = list(adapter.lanes)
    feeds.release_setup_sources(nano, lanes, adapter.connector)
    name = f"{mark}-okta-fix-ui"
    try:
        created = api_expect(
            nano.api.post("/api/connector-feeds", json={**adapter.feed_body(name), "set_up_log_sources": True}, timeout=SETUP_TIMEOUT), 201
        )
        fid = created["id"]
        api_expect(nano.api.patch(f"/api/connector-feeds/{fid}", json={"enabled": False}), 200)
        for s in created.get("log_sources") or []:
            if s.get("log_source_id"):
                feeds.delete_log_source(nano, s["log_source_id"])
        region = {"testid": "pull-feeds-region"}
        page.goto(ui_pull.PULL_FEEDS_PATH)
        page.wait_for({"testid": "pull-feeds-page"}, timeout_ms=60_000)
        row = {"role": "row", "name": rx(re.escape(name)), "within": region}
        page.wait_for(row, timeout_ms=60_000)
        page.click({"role": "button", "name": "Resume", "within": row})
        banner = {"testid": "feed-fix-setup"}
        page.wait_for(banner, timeout_ms=30_000)
        page.wait_text("Some log sources this feed needs are missing", exact=False)
        page.click({"role": "button", "name": "Fix setup", "within": banner})
        page.wait_for({"testid": "feed-setup-confirm"}, timeout_ms=30_000)
        page.click({"role": "button", "name": "Set up and continue", "within": {"role": "alertdialog"}})
        page.wait_for(banner, gone=True, timeout_ms=240_000)
        feed = eventually(
            lambda: _feed_by_name(nano, name), timeout=30, desc="resumed in the API", ok=lambda f: bool(f) and f.get("enabled")
        )
        timeline.step("fixed from the UI", feed=feed and feed.get("id"))
        body = api_expect(nano.api.get("/api/log-sources"), 200)
        items = body if isinstance(body, list) else body.get("sources") or body.get("items") or []
        claim = [s for s in items if s.get("enabled") and lanes[0] in (s.get("match_values") or [])]
        assert len(claim) == 1 and claim[0].get("deployed"), claim
    finally:
        f = _feed_by_name(nano, name)
        if f:
            nano.api.delete(f"/api/connector-feeds/{f['id']}")
        feeds.release_setup_sources(nano, lanes, adapter.connector)
