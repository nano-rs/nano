"""The real-tenant collector scenario (NAN-4961), shared by Okta, Google
Workspace and Slack. One flow, parametrized by `feeds_live.Collector`:

1. the vendor's OCSF parser, imported LINKED from nano-rs/parsers, deployed
   on the vendor lanes (HEC);
2. the feed created in the browser (New pull feed, secret entered inline);
3. run 1 lands the vendor's events: every row carries one of the vendor's OCSF
   classes and the parser's product metadata; `vendor_uids` (the tenant's own
   answer for the same window) is a subset of what landed;
4. run 2 succeeds, advances a checkpoint, and no `metadata.uid` is duplicated;
5. a credential rotate is live on the next run (rotated to a refused secret
   the run fails; rotated to the new real one it succeeds again);
6. a feed with a refused credential fails visibly (API + row) while the good
   feed keeps running and Vector HEC stays healthy;
7. search in the UI shows what the search API shows.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from nano_e2e import feeds_live, ingest
from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.feeds_live import Collector, row_get
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually, vector_reloads_quiet

# Slowest spec cadence the scenario waits through for run 1 (GWS: */5, plus lag).
FIRST_RUN = 420.0


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def run_collector(
    *,
    stack: Stack,
    nano: Nano,
    page: uilib.UiPage,
    mark: str,
    feed_cleanup: list[str],
    timeline: Any,
    c: Collector,
    query: str,
    vendor_uids: Callable[[str, str], set[str]] | None = None,
    min_events: int = 1,
) -> dict[str, Any]:
    source_id = feeds_live.ensure_vendor_parser(nano, c.parser)
    timeline.step("vendor parser deployed", parser=c.parser.name, source=source_id, lanes=c.parser.lanes)
    timeline.step("vector reloads settled", waited=round(vector_reloads_quiet(stack.project)))

    name = f"{mark}-{c.connector}"
    for v in [*c.secrets.values(), *c.rotate_secrets.values(), c.gws_key_json]:
        if v:
            page.driver.register_secret(v)
    feeds_live.ui_create_feed(page, c.label, name, c.config, c.secrets, gws_key_json=c.gws_key_json)
    feed = eventually(lambda: feeds_live.feed_by_name(nano, name), timeout=30, desc="feed in the API")
    assert feed is not None
    feed_cleanup.append(feed["id"])
    created = datetime.fromisoformat(feed["created_at"].replace("Z", "+00:00"))
    timeline.step("ui: feed created", id=feed["id"], lane=feed.get("source_type"), created=feed["created_at"])
    assert feed.get("credential_id"), "the inline secret was not stored as a credential"

    # ---------------------------------------------------------------- run 1
    d1 = feeds_live.wait_run(nano, feed["id"], after=0, timeout=FIRST_RUN)
    cp1 = feeds_live.checkpoints(d1)
    timeline.step("run 1", run=feeds_live.finished_runs(d1)[0], checkpoints=cp1)
    rows = eventually(
        lambda: nano.rows(query, limit=2000, minutes_back=120),
        timeout=INGEST_VISIBLE + 120,
        interval=5,
        desc=f">= {min_events} {c.connector} events searchable",
        ok=lambda rs: len(rs) >= min_events,
    )
    classes = Counter(int(row_get(r, "class_uid") or -1) for r in rows)
    timeline.step("landed", events=len(rows), classes=dict(classes), sample=_sample(rows[0]))
    assert set(classes) <= c.classes, f"events outside the vendor's OCSF classes {sorted(c.classes)}: {dict(classes)}"
    for r in rows:
        assert row_get(r, "metadata.uid"), f"event without metadata.uid: {_sample(r)}"
        assert row_get(r, "time") or row_get(r, "timestamp"), f"event without a time: {_sample(r)}"

    # ---------------------------------------------------------------- run 2: checkpoint, duplicates
    feeds_live.run_now(nano, feed["id"])
    d2 = feeds_live.wait_run(nano, feed["id"], after=len(feeds_live.finished_runs(d1)))
    cp2 = feeds_live.checkpoints(d2)
    rows2 = nano.rows(query, limit=5000, minutes_back=120)
    uids = Counter(str(row_get(r, "metadata.uid")) for r in rows2)
    dupes = {u: n for u, n in uids.items() if n > 1}
    timeline.step("run 2", run=feeds_live.finished_runs(d2)[0], checkpoints=cp2, events=len(rows2))
    assert not dupes, f"{len(dupes)} vendor events landed more than once across two runs: {list(dupes.items())[:5]}"
    assert any(cp2.get(k, 0) > v for k, v in cp1.items()) or len(cp2) > len(cp1), (
        f"no checkpoint advanced between runs: {cp1} -> {cp2}"
    )
    if vendor_uids is not None:
        # The tenant's own answer for the committed span (first window start ..
        # the second run's start minus the spec lag) must all have landed.
        run2_start = datetime.fromisoformat(feeds_live.finished_runs(d2)[0]["started_at"].replace("Z", "+00:00"))
        want = vendor_uids(_iso(created - timedelta(seconds=300)), _iso(run2_start - timedelta(seconds=120)))
        missing = want - set(uids)
        timeline.step("vendor truth", vendor=len(want), missing=len(missing))
        assert not missing, f"{len(missing)} vendor events in the committed span never landed: {sorted(missing)[:5]}"

    # ---------------------------------------------------------------- rotate
    feeds_live.rotate_and_prove(
        nano, feed["id"], feed["credential_id"], c.bad_secrets, c.rotate_secrets, timeline.step
    )

    # ---------------------------------------------------------------- refused credential, isolated
    bad = feeds_live.create_feed(
        nano,
        {"name": f"{name}-badcred", "connector": c.connector, "config": c.config, "credentials": c.bad_secrets},
    )
    feed_cleanup.append(bad["id"])
    failed = feeds_live.wait_failed(nano, bad["id"], timeout=FIRST_RUN)["feed"]
    err = failed.get("last_error") or ""
    timeline.step("refused credential", error=err)
    assert any(s in err.lower() for s in c.refused), f"the error does not say the credential was refused: {err!r}"
    row = feeds_live.ui_feed_row(page, f"{name}-badcred")
    assert row["status"].lower() == "failed", row
    assert err[:40] in row["name"], f"the Pull feeds row does not show the error: {row}"
    before = len(feeds_live.finished_runs(feeds_live.detail(nano, feed["id"])))
    feeds_live.run_now(nano, feed["id"])
    feeds_live.wait_run(nano, feed["id"], after=before)
    assert ingest.hec_health(stack.hec_url) == 200, "Vector HEC unhealthy after the failing feed"
    good = feeds_live.ui_feed_row(page, name)
    timeline.step("good feed unaffected", row=good)
    assert good["status"].lower() == "healthy", good
    assert good["lane"] == feed["source_type"], good

    # ---------------------------------------------------------------- UI search == API
    uilib.run_search(page, query)
    api_total = nano.search(query, minutes_back=60)["total_count"]
    ui_total = uilib.results_count(page)
    timeline.step("ui search", ui=ui_total, api=api_total)
    assert ui_total == api_total, (ui_total, api_total)
    return {
        "feed": feed,
        "rows": rows2,
        "lanes_seen": Counter(str(row_get(r, "metadata.log_source")) for r in rows2),
    }


def assert_events_on_lane(nano: Nano, result: dict[str, Any], c: Collector, timeline: Any) -> None:
    """Last step of a scenario: the events are stored under the lane they
    arrived on (NAN-4963; they used to land as `unknown`). On OCSF the lane is
    `metadata.log_source`, stamped by the parser's generated lane step; the
    nPL field resolves to the row's routing column, so a lane search finds
    every landed event."""
    seen = result["lanes_seen"]
    timeline.step("lanes", seen=dict(seen), expected=c.parser.lanes)
    assert set(seen) <= set(c.parser.lanes), (
        f"{c.connector} events land with metadata.log_source {dict(seen)}, not their lane {c.parser.lanes}"
    )
    uids = {str(row_get(r, "metadata.uid")) for r in result["rows"]}
    on_lane = nano.rows(feeds_live.lane_query(c.parser), limit=5000, minutes_back=120)
    found = {str(row_get(r, "metadata.uid")) for r in on_lane}
    timeline.step("lane search", query=feeds_live.lane_query(c.parser), events=len(on_lane))
    missing = uids - found
    assert not missing, f"{len(missing)} landed events are not found by {feeds_live.lane_query(c.parser)!r}"


def _sample(row: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "class_uid",
        "metadata.uid",
        "metadata.product.name",
        "metadata.log_source",
        "actor.user.name",
        "user.name",
        "source_type",
    )
    return {k: row_get(row, k) for k in keys}
