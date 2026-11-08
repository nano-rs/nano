"""Search in the browser (NAN-4927's search UX), on OCSF field names: the
product defaults to OCSF, so every query here uses `actor.user.name`,
`src_endpoint.ip`, `device.hostname`, `metadata.log_source`; one scenario
checks that the UDM-compat alias (`user=` → user_unified) still answers.

Events go through the session's OCSF lane (a published parser producing an
OCSF Authentication event). Every assertion compares what the page SHOWS to
what the search API returns for the same query and window.
"""

from __future__ import annotations

import re
import time
from collections import Counter

from nano_e2e import ingest
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, row_text
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

SEQ = re.compile(r"\bseq=(\d+)\b")


def _api_seqs(nano: Nano, mark: str) -> Counter[int]:
    return Counter(
        int(m.group(1)) for r in nano.rows(f'"{mark}"', limit=1000) if (m := SEQ.search(row_text(r)))
    )


def _ui_seqs(page: uilib.UiPage) -> Counter[int]:
    return Counter(int(m.group(1)) for t in uilib.result_rows_text(page) if (m := SEQ.search(t)))


def _send_users(stack: Stack, lane, mark: str, users: dict[str, int]) -> int:
    seq = 0
    for user, n in users.items():
        for _ in range(n):
            lane.send(stack, mark, user, f"203.0.113.{seq % 250 + 1}", f"host-{user}", note=f"seq={seq}")
            seq += 1
    return seq


def test_keyword_search_matches_api(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, page: uilib.UiPage, timeline
) -> None:
    n = _send_users(stack, ocsf_lane, mark, {f"kw-{mark[-6:]}": 7})
    api = eventually(
        lambda: _api_seqs(nano, mark),
        timeout=INGEST_VISIBLE,
        desc=f"{n} events via API",
        ok=lambda c: len(c) >= n,
    )
    api_total = nano.search(f'"{mark}"')["total_count"]
    timeline.step("api", total=api_total, seqs=sorted(api))

    uilib.run_search(page, f'"{mark}"')
    shown = uilib.results_count(page)
    ui = eventually(
        lambda: _ui_seqs(page), timeout=20, interval=1, desc="result rows rendered", ok=lambda c: c == api
    )
    timeline.step("ui", count=shown, seqs=sorted(ui))
    assert shown == api_total == n, f"UI count {shown} != API total {api_total} (sent {n})"
    assert ui == api


def test_raw_tab_prefers_ocsf_raw_data_and_shows_request_timing(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, page: uilib.UiPage, timeline
) -> None:
    """The inspector uses the preserved OCSF input, while the footer keeps
    server wall, rows-query execution, and fair-queue wait distinct."""
    # Vector-originated OCSF events intentionally use message as their raw
    # field. A spec-conformant direct producer supplies raw_data plus a separate
    # human summary, so send that shape through the lane to exercise the UI's
    # precedence rule without teaching the shared Vector fixture to duplicate
    # every event.
    raw_input = f"<134>1 2026-11-05T00:00:00Z raw-host nano - - marker={mark} raw-tab seq=0"
    sent = ingest.hec(
        stack.hec_url,
        ocsf_lane.token,
        {
            "message": f"{mark} authentication summary",
            "raw_data": raw_input,
            "user": f"raw-{mark[-6:]}",
            "ip": "203.0.113.77",
            "host": "raw-host",
        },
    )
    assert sent.status_code == 200, sent.text

    response = eventually(
        lambda: nano.search(f'"{mark}"', limit=10),
        timeout=INGEST_VISIBLE,
        desc="the raw-tab OCSF event and request timings",
        ok=lambda body: bool(body.get("results"))
        and isinstance(body.get("server_wall_ms"), int)
        and isinstance(body.get("queue_wait_ms"), int),
    )
    row = response["results"][0]
    raw_data = row.get("raw_data")
    message = row.get("message")
    assert raw_data == raw_input, row
    assert isinstance(message, str) and raw_data != message, (raw_data, message)
    assert response["server_wall_ms"] >= response["queue_wait_ms"] >= 0
    timeline.step(
        "api timing",
        server_wall_ms=response["server_wall_ms"],
        query_ms=response["execution_time_ms"],
        queue_wait_ms=response["queue_wait_ms"],
    )

    uilib.run_search(page, f'"{mark}"')
    for testid, label in (
        ("search-server-wall", "Server"),
        ("search-query-execution", "Query"),
        ("search-queue-wait", "Queue"),
    ):
        page.wait_for({"testid": testid}, timeout_ms=60_000)
        shown = " ".join(page.texts({"testid": testid}))
        assert re.fullmatch(rf"{label} (?:\d+ms|\d+\.\d{{2}}s)", shown), shown

    page.click({"role": "button", "name": "Open event in inspector", "nth": 0})
    page.wait_text("Event Inspector", exact=True)
    page.click({"role": "button", "name": "Raw", "exact": True})

    raw_shown = eventually(
        lambda: page.texts({"css": "pre"}),
        timeout=30,
        interval=1,
        desc="the hydrated OCSF raw_data in the Raw tab",
        ok=lambda values: raw_data in values,
    )
    timeline.step("raw tab", api_raw=raw_data, visible_pre=raw_shown)
    assert raw_data in raw_shown
    assert message not in raw_shown, "the summary message displaced OCSF raw_data"
    page.screenshot("raw-data-and-search-timing.png")


def test_stats_count_by_ocsf_field_matches_api(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, page: uilib.UiPage, timeline
) -> None:
    tag = mark[-6:]
    want = {f"alice-{tag}": 2, f"bob-{tag}": 3, f"carol-{tag}": 5}
    _send_users(stack, ocsf_lane, mark, want)
    query = f'"{mark}" | stats count by actor.user.name'

    def api_groups() -> dict[str, int]:
        return {str(r["actor.user.name"]): int(r["count"]) for r in nano.rows(query, limit=100)}

    api = eventually(
        api_groups, timeout=INGEST_VISIBLE, desc="all three users via API", ok=lambda g: g == want
    )
    timeline.step("api", groups=api)

    uilib.run_search(page, query)
    header, rows = uilib.table_rows(page)
    timeline.step("ui", header=header, rows=rows)
    assert header[:2] == ["actor.user.name", "count"], header
    shown = {r[0]: int(r[1].replace(",", "")) for r in rows if r and r[0]}
    assert shown == api, f"UI stats table {shown} != API {api}"


def test_udm_alias_user_still_answers(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, page: uilib.UiPage, timeline
) -> None:
    """`user=` is the UDM-compat alias (→ user_unified); on OCSF it must find
    exactly what `actor.user.name=` finds."""
    tag = mark[-6:]
    _send_users(stack, ocsf_lane, mark, {f"dave-{tag}": 3, f"erin-{tag}": 2})
    ocsf_q, alias_q = f'"{mark}" actor.user.name="dave-{tag}"', f'"{mark}" user="dave-{tag}"'
    ocsf = eventually(
        lambda: nano.search(ocsf_q)["total_count"],
        timeout=INGEST_VISIBLE,
        desc="OCSF field query",
        ok=lambda c: c == 3,
    )
    alias = nano.search(alias_q)["total_count"]
    timeline.step("api", ocsf=ocsf, alias=alias)
    assert alias == ocsf == 3, f"user= alias found {alias}, actor.user.name found {ocsf}"
    uilib.run_search(page, alias_q)
    assert uilib.results_count(page) == 3


def test_live_tail_shows_arrivals(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, page: uilib.UiPage, timeline
) -> None:
    user = f"tail-{mark[-6:]}"
    for i in range(3):
        ocsf_lane.send(stack, mark, user, "198.51.100.1", "tail-host", note=f"seq={i}")
    eventually(
        lambda: _api_seqs(nano, mark), timeout=INGEST_VISIBLE, desc="seed events", ok=lambda c: len(c) >= 3
    )

    uilib.run_search(page, f'"{mark}"')
    eventually(
        lambda: set(_ui_seqs(page)),
        timeout=20,
        interval=1,
        desc="seed rows shown",
        ok=lambda c: c == {0, 1, 2},
    )
    uilib.tail(page, "5s")
    timeline.step("tail on (5s)")

    # HEC keeps flowing while the tail runs: 3 waves of 4, then a burst of 5
    # events sharing ONE timestamp (same ms): the tail dedupes by event
    # identity, not time, so all 5 must arrive. The header count is sampled
    # throughout and must never blank or go backwards (prepend, not re-run).
    counts: list[int] = []
    seq = 100
    for wave in range(3):
        for i in range(seq, seq + 4):
            ocsf_lane.send(stack, mark, user, "198.51.100.2", "tail-host", note=f"seq={i} wave{wave}")
        seq += 4
        counts.append(uilib.results_count(page))
        time.sleep(2)
    burst_t = time.time()
    for i in range(seq, seq + 5):
        r = ingest.hec(
            stack.hec_url,
            ocsf_lane.token,
            {
                "message": f"{mark} seq={i} burst ocsf e2e",
                "user": user,
                "ip": "198.51.100.3",
                "host": "tail-host",
            },
            time=burst_t,
        )
        assert r.status_code == 200, r.text
    seq += 5
    sent = {0, 1, 2} | set(range(100, seq))

    def ui_now() -> Counter[int]:
        counts.append(uilib.results_count(page))
        return _ui_seqs(page)

    ui = eventually(
        ui_now,
        timeout=INGEST_VISIBLE + 30,
        interval=3,
        desc="every arrival (incl. the same-ms burst) in the tailing UI",
        ok=lambda c: set(c) >= sent,
    )
    api = _api_seqs(nano, mark)
    timeline.step("tail caught up", ui=len(ui), api=len(api), header_counts=counts)
    assert set(api) == sent, f"API sees {sorted(api)}"
    assert not {s: c for s, c in ui.items() if c > 1}, f"live tail rendered duplicates: {ui}"
    assert set(ui) == set(api)
    assert all(c > 0 for c in counts), f"the header count blanked during the tail: {counts}"
    assert counts == sorted(counts), f"the header count went backwards during the tail: {counts}"
    eventually(
        lambda: uilib.results_count(page), timeout=30, desc="header count == API", ok=lambda c: c == len(api)
    )
