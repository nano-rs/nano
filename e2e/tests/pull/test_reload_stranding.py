"""Pull-feed events accepted during a Vector topology reload must not be lost
(NAN-4937 finding; fixed by NAN-4936 / Vector 0.61.0-nano.4).

Observed in the UI runs: a feed that started while its lane's Vector config
was still reloading delivered 5 events (run status success, ingest acked) and
only 3-4 became searchable within 5.5 minutes; the rest sat until some LATER
reload flushed them, or never appeared.

This scenario provokes it on purpose: the Okta lane is recreated right before
the feed starts and republished back to back during its first run (each
publish rewrites Vector's config, and Vector reloads the lane's transforms).
Once the run reports success the churn stops, so NO later reload can flush
stranded events, and every acked event must then become searchable within the
normal ingest window.

Timing model (NAN-4980). A publish is a full Vector config deploy and takes
~10 s, while an unpaced first run (3 pages of 2) finishes in a few seconds, so
a wall-clock churn overlapped the run with at most one reload. The vendor mock
now paces the run instead: Okta page k is served only once the churn has
completed k+1 publishes, so every acked page is delivered after a reload and
while the next one is in flight, however long a publish takes. The feed is
created BEFORE the churn starts: a churn `PUT` un-deploys the lane until its
publish lands, and `POST /api/connector-feeds` (rightly) refuses a lane with
no deployed HEC source.

A plain (strict) test since NAN-4936 pinned Vector 0.61.0-nano.4, which fixes
the disk-buffer visibility stall behind the loss: any stranded event fails it.
"""

from __future__ import annotations

import re
import threading
import time
from collections import Counter

import pytest

from nano_e2e import feeds
from nano_e2e.client import Nano, expect, row_text
from nano_e2e.mockvendor import MockVendor
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

pytestmark = pytest.mark.mock_vendor

SEQ = re.compile(r"seq=(\d+)")
N = 6
# Reloads that must complete before each vendor page is served (page k waits
# for k+1 publishes). A publish is ~10 s; the gate must stay well inside the
# runner's 30 s vendor response-header timeout.
GATE_TIMEOUT = 25.0


def _landed(nano: Nano, mark: str) -> Counter[int]:
    return Counter(
        int(m.group(1)) for r in nano.rows(f'"{mark}"', limit=500) if (m := SEQ.search(row_text(r)))
    )


class _Churn:
    """Republish the LANE's own log source every `every` seconds (a Vector
    reload of the very transform the feed's events pass through) until
    stopped; the canonical lane parser is restored afterwards."""

    def __init__(self, nano: Nano, lane: str, src: str, every: float = 0.5):
        self.nano, self.lane, self.src, self.every = nano, lane, src, every
        self.stop = threading.Event()
        self.publishes = 0
        self.published = threading.Condition()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        i = 0
        while not self.stop.is_set():
            i += 1
            vrl = feeds.LANE_PARSER.format(lane=self.lane) + f"\n# churn {i}\n"
            self.nano.api.put(f"/api/log-sources/{self.src}", json={"parser_vrl": vrl})
            if self.nano.api.post(f"/api/log-sources/{self.src}/publish").status_code == 200:
                with self.published:
                    self.publishes += 1
                    self.published.notify_all()
            self.stop.wait(self.every)

    def wait_publishes(self, n: int, timeout: float) -> bool:
        """Block until `n` publishes have completed (False on timeout)."""
        with self.published:
            return self.published.wait_for(lambda: self.publishes >= n, timeout=timeout)

    def __enter__(self) -> _Churn:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop.set()
        self.thread.join(timeout=60)
        feeds.ensure_lane_source(self.nano, self.lane)  # canonical parser back


def test_pull_events_acked_during_reload_all_land(
    stack: Stack, nano: Nano, mock_vendor: MockVendor, mark: str, timeline
) -> None:
    adapter = feeds.Okta()
    adapter.provision(mock_vendor, mark)
    adapter.seed(mock_vendor, mark, N)
    # As in the UI runs that lost events: the lane is (re)created right before
    # the feed starts, and keeps reloading while the first run delivers.
    (lane,) = adapter.lanes
    old = feeds.ensure_lane_source(nano, lane)
    feeds.delete_log_source(nano, old)
    src = feeds.ensure_lane_source(nano, lane)
    churn = _Churn(nano, lane, src)
    pages = -(-N // mock_vendor.page_size)
    gated: list[tuple[int, int, bool]] = []

    def gate(host: str, index: int) -> None:
        # Hold page k until k+1 reloads have landed (the run cannot outrun the
        # churn); later requests (an empty tail page) pass straight through.
        if host == adapter.domain and index < pages:
            ok = churn.wait_publishes(index + 1, GATE_TIMEOUT)
            gated.append((index, churn.publishes, ok))

    feed_id = None
    mock_vendor.okta_page_gate = gate
    try:
        # Created before the churn starts: the source is deployed right now.
        created = expect(nano.api.post("/api/connector-feeds", json=adapter.feed_body(f"{mark}-reload")), 200, 201)
        feed_id = created.get("feed", created)["id"]
        with churn:
            run = eventually(
                lambda: expect(nano.api.get(f"/api/connector-feeds/{feed_id}"), 200),
                timeout=180,
                interval=3,
                desc="the feed's first run to succeed (during the churn)",
                ok=lambda f: f.get("feed", f).get("last_status") == "success",
            )
            runs = run.get("runs") or []
            acked = sum(int(r.get("events") or 0) for r in runs if r.get("status") == "success")
        mock_vendor.okta_page_gate = None
        timeline.step("run done during churn", acked=acked, publishes=churn.publishes, gated=gated, runs=runs[:1])
        assert acked >= N, f"the run did not deliver all {N} events: {runs[:1]}"
        assert churn.publishes >= 3, "the churn did not reload Vector during the run"

        # No reload after this point can flush a stranded event.
        settled = time.monotonic()
        try:
            seen = eventually(
                lambda: _landed(nano, mark),
                timeout=INGEST_VISIBLE + 60,
                interval=5,
                desc=f"all {N} acked events searchable with no further reload",
                ok=lambda c: set(c) >= set(range(N)),
            )
        except AssertionError:
            got = _landed(nano, mark)
            timeline.step("stranded", acked=acked, searchable=len(got), missing=sorted(set(range(N)) - set(got)))
            raise
        timeline.step("all landed", seconds=round(time.monotonic() - settled), seen=dict(seen))
    finally:
        mock_vendor.okta_page_gate = None
        if feed_id:
            nano.api.delete(f"/api/connector-feeds/{feed_id}")
