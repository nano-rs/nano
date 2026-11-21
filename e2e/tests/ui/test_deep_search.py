"""Search the way a SOC analyst uses it, on a realistic OCSF dataset (NAN-5684).

The `soc` fixture seeds four source types (auth, network, process, DNS) over
72 hours: 24 hosts, 15 users, a brute-force burst, and values seen exactly
once (a service account, a binary and its hash, a destination, a domain).
Every scenario acts as a throwaway analyst with explicit permissions and
compares what the page SHOWS with the search API and with the seeded truth.

Covered: every result view (events, table, stats, timechart, the event
stream's bar/line/area charts, ranked bars), the field sidebar (top values,
include / exclude), the event inspector (fields, raw, JSON, copy), value
pivots (filter, exclude, group by, copy), nPL breadth, readable errors,
infinite-scroll pagination, the time picker (preset, absolute, drag-to-zoom),
saved queries, CSV export, search history, the compiled-SQL inspector, and
prevalence / rarity.
"""

from __future__ import annotations

import csv
import re
import io
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from nano_e2e import deep
from nano_e2e import ui as uilib
from nano_e2e.known_bugs import known_bug
from nano_e2e.client import Nano, expect
from nano_e2e.personas import login_persona
from nano_e2e.soc_seed import SocData
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually


@pytest.fixture(scope="module")
def _persona(stack: Stack, ui: uilib.Driver, soc: SocData):
    with deep.module_persona(stack, ui, "deep-analyst", deep.ANALYST) as persona:
        yield persona


@pytest.fixture
def analyst(_persona, request):
    """The module's analyst, isolated per scenario (deep.analyst_for)."""
    with deep.analyst_for(_persona, request) as a:
        yield a


def _fragment(url: str) -> dict[str, str]:
    frag = urlparse(url).fragment or urlparse(url).query
    return {k: v[0] for k, v in parse_qs(frag).items()}


# ---------------------------------------------------------------- result views


def test_events_view_matches_api_and_shows_a_first_page(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    query = f'source_type="{soc.net}"'
    total = deep.search(page, soc, query)
    api = deep.api_total(client, soc, query)
    timeline.step("events", shown=total, api=api, truth=soc.by_source[soc.net])
    assert total == api == soc.by_source[soc.net]
    assert deep.display_type(page) == "events"
    first_page = int(page.attr(deep.RESULTS, "data-shown") or 0)
    assert 0 < first_page < total, f"the first page should be a page, not {first_page} of {total}"
    page.wait_for({"testid": "results-load-more"})
    assert f"({first_page} of {total})" in " ".join(page.texts({"testid": "results-load-more"}))
    assert deep.new_page_errors(analyst) == []


def test_infinite_scroll_loads_each_event_once(analyst, soc: SocData, timeline) -> None:
    """Scroll like a person: the list keeps loading pages until every event
    is in, and never renders the same event twice."""
    page = analyst.page
    total = deep.search(page, soc, f'source_type="{soc.net}"')

    def scrolled() -> int:
        page.scroll_bottom()
        return int(page.attr(deep.RESULTS, "data-shown") or 0)

    loaded = eventually(scrolled, timeout=120, interval=0.5, desc="infinite scroll to load every page",
                        ok=lambda n: n >= total)
    texts = uilib.result_rows_text(page)
    dups = {t: c for t, c in Counter(texts).items() if c > 1}
    timeline.step("scrolled", loaded=loaded, rendered=len(texts), unique=len(set(texts)), dup_rows=len(dups))
    assert deep.new_page_errors(analyst) == []
    # Healthy preconditions (outside the pin): rows rendered, all events reached.
    assert texts and loaded >= total
    dup_rows = sum(c - 1 for c in dups.values())
    assert loaded == total and len(texts) == total and not dups, (
        f"scrolling loaded {loaded} rows for {total} events ({len(texts)} rendered; {dup_rows} duplicate rows)")


def test_table_command_shows_the_selected_columns(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    query = f'source_type="{soc.auth}" status="Failure" | table actor.user.name, device.hostname, src_endpoint.ip'
    total = deep.search(page, soc, query)
    header, rows = deep.table(page)
    timeline.step("table", header=header, rows=len(rows), total=total)
    assert header[:3] == ["actor.user.name", "device.hostname", "src_endpoint.ip"], header
    api = deep.api_rows(client, soc, query)
    assert total == len(api) == sum(soc.auth_failures_by_user.values())
    api_set = {(r["actor.user.name"], r["device.hostname"], r["src_endpoint.ip"]) for r in api}
    assert rows and all(tuple(r[:3]) in api_set for r in rows), "the table shows a row the API does not return"


def test_stats_by_user_with_sort_matches_ground_truth(analyst, soc: SocData, timeline) -> None:
    page = analyst.page
    query = f'source_type="{soc.auth}" | stats count by actor.user.name | sort -count'
    deep.search(page, soc, query)
    page.wait_text("Stats", exact=True)
    header, rows = deep.table(page)
    shown = {r[0]: deep.as_int(r[1]) for r in rows if r and r[0]}
    timeline.step("stats", header=header, shown=shown)
    assert header[:2] == ["actor.user.name", "count"], header
    assert shown == soc.auth_by_user
    counts = [deep.as_int(r[1]) for r in rows if r and r[0]]
    assert counts == sorted(counts, reverse=True), "sort -count did not order the rows"


def test_multi_aggregate_stats_by_port(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    query = (f'source_type="{soc.net}" | stats count, dc(device.hostname) AS hosts, '
             f'sum(traffic.bytes_out) AS out by dst_endpoint.port | sort dst_endpoint.port')
    deep.search(page, soc, query)
    header, rows = deep.table(page)
    timeline.step("multi-agg", header=header, rows=rows[:10])
    idx = {h: i for i, h in enumerate(header)}
    shown = {deep.as_int(r[idx["dst_endpoint.port"]]): deep.as_int(r[idx["count"]]) for r in rows if r}
    assert shown == soc.net_by_port
    api = {int(r["dst_endpoint.port"]): (int(r["hosts"]), int(r["out"])) for r in deep.api_rows(client, soc, query)}
    ui = {deep.as_int(r[idx["dst_endpoint.port"]]): (deep.as_int(r[idx["hosts"]]), deep.as_int(r[idx["out"]]))
          for r in rows if r}
    assert ui == api


def test_timechart_renders_buckets_and_span_chip_rewrites_the_query(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    query = f'source_type="{soc.auth}" | timechart span=1h count'
    deep.search(page, soc, query)
    page.wait_text("Timechart", exact=False)
    page.wait_for({"css": "main .recharts-area"})
    api = deep.api_rows(client, soc, query)
    assert sum(int(r.get("count", 0)) for r in api) == soc.by_source[soc.auth]
    timeline.step("1h buckets", buckets=len(api))
    # The span chip rewrites the query and re-runs it.
    before = deep.run_mark(page)
    page.click({"role": "button", "name": uilib.rx(r"^span\s*1h")})
    page.click({"role": "menuitem", "name": uilib.rx(r"^6h")})
    deep.wait_new_results(page, before)
    assert "span=6h" in deep.editor_query(page)
    api6 = deep.api_rows(client, soc, query.replace("span=1h", "span=6h"))
    timeline.step("6h buckets", buckets=len(api6))
    assert len(api6) < len(api)
    assert sum(int(r.get("count", 0)) for r in api6) == soc.by_source[soc.auth]
    # The table under the chart carries the same buckets.
    if page.count({"role": "button", "name": "Show table", "exact": True}):
        page.click({"role": "button", "name": "Show table", "exact": True})
    header, rows = deep.table(page)
    assert len(rows) == len(api6)
    assert sum(deep.as_int(r[header.index("count")]) for r in rows) == soc.by_source[soc.auth]


def test_timechart_shows_every_bucket(analyst, soc: SocData, timeline) -> None:
    """72 hourly buckets: the table under the chart has all of them."""
    page, client = analyst.page, analyst.client
    query = f'source_type="{soc.auth}" | timechart span=1h count'
    deep.search(page, soc, query)
    page.wait_text("Timechart", exact=False)
    if page.count({"role": "button", "name": "Show table", "exact": True}):
        page.click({"role": "button", "name": "Show table", "exact": True})
    api = deep.api_rows(client, soc, query)
    header, rows = deep.table(page)
    timeline.step("buckets", api=len(api), ui=len(rows))
    assert len(api) > 50
    assert rows, "the timechart table rendered no bucket at all"
    assert len(rows) == len(api), f"{len(rows)} buckets shown of {len(api)}"


def test_event_stream_chart_types_switch_and_persist(analyst, soc: SocData) -> None:
    page = analyst.page
    deep.search(page, soc, f'source_type="{soc.dns}"')
    chart = {"testid": "timeline-chart"}
    page.wait_for(chart)
    marks = {"Bar chart": ".recharts-bar", "Line chart": ".recharts-line", "Area chart": ".recharts-area"}
    for label, css in marks.items():
        page.click({"role": "button", "name": label, "exact": True})
        page.wait_for({"css": f'[data-testid="timeline-chart"] {css}'})
    page.reload()
    page.wait_for(chart, timeout_ms=60_000)
    page.wait_for({"css": '[data-testid="timeline-chart"] .recharts-area'})


def test_top_command_renders_ranked_bars(analyst, soc: SocData) -> None:
    page, client = analyst.page, analyst.client
    query = f'source_type="{soc.dns}" | top 5 query.hostname'
    deep.search(page, soc, query)
    api = deep.api_rows(client, soc, query)
    want = sorted(soc.dns_by_domain.items(), key=lambda kv: -kv[1])[:5]
    assert {r["query.hostname"]: int(r["count"]) for r in api} == dict(want)
    # The bars render after the run reports done: wait for every ranked
    # domain to be on the page.
    domains = [d for d, _ in want]
    shown = eventually(
        lambda: [d for d in domains if page.contains(d)],
        timeout=30,
        interval=0.5,
        desc="every top-5 domain in the ranked bars",
        ok=lambda xs: len(xs) == len(domains),
    )
    assert shown == domains, shown


# ---------------------------------------------------------------- nPL breadth

NPL_CASES = {
    "not_equal": ('source_type="{auth}" status!="Success"', lambda s: sum(s.auth_failures_by_user.values())),
    "regex": ('source_type="{auth}" actor.user.name=/^j.*/',
              lambda s: sum(n for u, n in s.auth_by_user.items() if u.startswith("j"))),
    "cidr_match": ('source_type="{auth}" | eval internal=cidr_match("10.0.0.0/8", src_endpoint.ip) '
                   '| where internal=true', lambda s: s.private_src_auth),
    "is_private_ip": ('source_type="{auth}" | eval priv=is_private_ip(src_endpoint.ip) | where priv=false',
                      lambda s: s.by_source[s.auth] - s.private_src_auth),
    "dedup": ('source_type="{auth}" | dedup actor.user.name', lambda s: len(s.auth_by_user)),
    "eventstats": ('source_type="{auth}" | eventstats count AS per_user by actor.user.name | where per_user < 2',
                   lambda s: sum(1 for n in s.auth_by_user.values() if n < 2)),
}


@pytest.mark.parametrize("case", sorted(NPL_CASES))
def test_npl_command_matches_api_and_truth(analyst, soc: SocData, case: str, timeline) -> None:
    page, client = analyst.page, analyst.client
    template, truth = NPL_CASES[case]
    query = template.format(auth=soc.auth, net=soc.net, proc=soc.proc, dns=soc.dns)
    shown = deep.search(page, soc, query)
    api = deep.api_total(client, soc, query)
    want = truth(soc)
    timeline.step(case, query=query, shown=shown, api=api, truth=want)
    assert shown == api == want


def test_rex_extracts_named_groups(analyst, soc: SocData, timeline) -> None:
    page = analyst.page
    query = (f'source_type="{soc.net}" | rex field=message ":(?<dport>[0-9]+) out=" '
             f'| stats count by dport')
    deep.search(page, soc, query)
    header, rows = deep.table(page)
    shown = {deep.as_int(r[0]): deep.as_int(r[1]) for r in rows if r and r[0]}
    timeline.step("rex", shown=shown)
    assert header[:2] == ["dport", "count"], header
    assert shown == soc.net_by_port


def test_sort_head_returns_exactly_n_rows(analyst, soc: SocData, timeline) -> None:
    """The analyst's "top 3 flows by bytes out": the exfil flow first, and
    exactly three rows."""
    page, client = analyst.page, analyst.client
    query = (f'source_type="{soc.net}" | sort -traffic.bytes_out | head 3 '
             f'| table device.hostname, dst_endpoint.ip, traffic.bytes_out')
    deep.search(page, soc, query)
    header, rows = deep.table(page)
    api = deep.api_rows(client, soc, query)
    timeline.step("top 3", api=api, ui=rows[:15])
    assert len(api) == 3 and api[0]["dst_endpoint.ip"] == soc.rare_dst
    # NAN-5693: exactly three rows, globally sorted: the exfil flow first.
    assert len(rows) == 3, f"{len(rows)} rows for `head 3`"
    assert rows[0][header.index("dst_endpoint.ip")] == soc.rare_dst


def test_join_correlates_logons_with_launches_per_host(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    query = (f'source_type="{soc.proc}" | stats count AS launches by device.hostname '
             f'| join device.hostname [search source_type="{soc.auth}" | stats count AS logons by device.hostname]')
    deep.search(page, soc, query)
    header, rows = deep.table(page)
    idx = {h: i for i, h in enumerate(header)}
    api = {r["device.hostname"]: (int(r["launches"]), int(r["logons"])) for r in deep.api_rows(client, soc, query)}
    assert api and all(logons == soc.auth_by_host.get(host) for host, (_, logons) in api.items())
    launches = {r[idx["device.hostname"]]: deep.as_int(r[idx["launches"]]) for r in rows}
    timeline.step("join", header=header, api=len(api))
    assert launches == {h: v[0] for h, v in api.items()}
    assert "logons" in idx, f"the join column logons is not shown: {header}"
    shown = {r[idx["device.hostname"]]: (deep.as_int(r[idx["launches"]]), deep.as_int(r[idx["logons"]])) for r in rows}
    assert shown == api


@pytest.fixture
def owners_lookup(nano: Nano, soc: SocData):
    """A CSV lookup table of workstation owners (odd = red team, even = blue)."""
    name = f"deep_owners_{soc.tag}"
    body = "hostname,owner\n" + "\n".join(f"ws-{i:02d},team-{'red' if i % 2 else 'blue'}" for i in range(1, 19))
    config = {"name": name, "format": "csv", "primary_key": "hostname", "mode": "replace"}
    expect(nano.api.post("/api/lookup-tables", files={"file": ("owners.csv", body.encode(), "text/csv")},
                         data={"config": json.dumps(config)}), 200, 201)
    red = sum(n for h, n in soc.auth_by_host.items() if h.startswith("ws-") and int(h[3:]) % 2)
    blue = sum(n for h, n in soc.auth_by_host.items() if h.startswith("ws-") and not int(h[3:]) % 2)
    yield name, {"team-red": red, "team-blue": blue}
    nano.api.delete(f"/api/lookup-tables/{name}")


def test_lookup_enriches_events_from_a_lookup_table(analyst, soc: SocData, owners_lookup, timeline) -> None:
    page = analyst.page
    name, want = owners_lookup
    deep.search(page, soc, f'source_type="{soc.auth}" | lookup {name} device.hostname | stats count by owner')
    header, rows = deep.table(page)
    shown = {r[header.index("owner")]: deep.as_int(r[header.index("count")]) for r in rows}
    timeline.step("lookup", shown=shown, want=want)
    assert {k: shown.get(k) for k in want} == want


def test_lookup_output_clause_enriches_events(analyst, soc: SocData, owners_lookup, timeline) -> None:
    page = analyst.page
    name, want = owners_lookup
    deep.search(page, soc,
                f'source_type="{soc.auth}" | lookup {name} device.hostname OUTPUT owner | stats count by owner')
    header, rows = deep.table(page)
    shown = {r[header.index("owner")]: deep.as_int(r[header.index("count")]) for r in rows}
    timeline.step("lookup OUTPUT", shown=shown, want=want)
    assert rows, "the lookup OUTPUT search rendered no row"
    assert {k: shown.get(k) for k in want} == want, f"OUTPUT counts wrong: {shown} != {want}"


# ---------------------------------------------------------------- errors


@pytest.mark.parametrize(
    "query,code",
    [
        ('source_type="x" | stats count by', "PARSE_ERROR"),
        ('source_type="x" | frobnicate everything', "PARSE_ERROR"),
        ('source_type="x" | eval y=nosuchfn(1)', None),
    ],
    ids=["dangling-by", "unknown-command", "unknown-function"],
)
def test_bad_queries_show_a_readable_error_and_the_page_recovers(analyst, soc: SocData, query: str, code) -> None:
    page = analyst.page
    deep.search(page, soc, query.replace('"x"', f'"{soc.auth}"'), expect_error=True)
    message = " ".join(page.texts({"testid": "search-error-message"}))
    if code:
        assert page.attr({"testid": "search-error-drawer"}, "data-error-code") == code
    assert message.strip(), "the error drawer is empty"
    for leak in ("panicked", "stack backtrace", "DB::Exception", "Code: ", "SELECT "):
        assert leak not in message, f"internal detail leaks into the error: {message[:300]}"
    assert deep.new_page_errors(analyst) == []
    # Fix the query in the editor: the error clears and results come back.
    total = deep.run_editor(page, f'source_type="{soc.auth}"')
    assert total == soc.by_source[soc.auth]
    page.wait_for({"testid": "search-error-drawer"}, gone=True)


# ---------------------------------------------------------------- sidebar, inspector, pivots


def test_sidebar_top_values_match_truth_and_include_exclude_rewrite_the_query(analyst, soc: SocData, timeline) -> None:
    page = analyst.page
    total = deep.search(page, soc, f'source_type="{soc.auth}"')
    want = {u: round(100 * n / total, 1) for u, n in soc.auth_by_user.items()}
    got = eventually(lambda: uilib.sidebar_field(page, "actor.user.name"), timeout=60, interval=2,
                     desc="settled actor.user.name values",
                     ok=lambda v: v.events == total and v.unique == len(soc.auth_by_user))
    timeline.step("sidebar", unique=got.unique, events=got.events, percent=got.percent)
    for user, pct in got.percent.items():
        assert abs(pct - want[user]) <= 0.1, (user, pct, want[user])

    target = "judy.chen"
    row = {"testid": "field-value-row", "css": None}
    row = {"css": f'[data-testid="field-value-row"][data-field="actor.user.name"][data-value="{target}"]'}
    page.click(row)
    before = deep.run_mark(page)
    page.click({"role": "menuitem", "name": "Add to filter"})
    shown = deep.wait_new_results(page, before)
    assert f'actor.user.name="{target}"' in deep.editor_query(page)
    assert shown == soc.auth_by_user[target]

    # Exclude from the same menu on a fresh run.
    deep.search(page, soc, f'source_type="{soc.auth}"')
    eventually(lambda: uilib.sidebar_field(page, "actor.user.name"), timeout=60, interval=2,
               desc="values", ok=lambda v: target in v.percent)
    page.click(row)
    before = deep.run_mark(page)
    page.click({"role": "menuitem", "name": "Exclude"})
    shown = deep.wait_new_results(page, before)
    assert f'actor.user.name!="{target}"' in deep.editor_query(page)
    assert shown == total - soc.auth_by_user[target]


def test_event_inspector_fields_raw_json_and_copy(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    query = f'source_type="{soc.proc}" process.name="{soc.rare_process}"'
    assert deep.search(page, soc, query) == 2
    page.click({"role": "button", "name": "Open event in inspector", "nth": 0})
    page.wait_for({"testid": "event-inspector"})
    page.click({"testid": "inspector-tab-json"})
    page.wait_for({"testid": "inspector-json"})
    shown = json.loads(page.texts({"testid": "inspector-json"})[0])
    flat = json.dumps(shown)
    for needle in (soc.rare_process, soc.rare_hash, soc.rare_process_host):
        assert needle in flat, f"{needle} missing from the inspector JSON"
    page.click({"testid": "inspector-copy-json"})
    copied = json.loads(page.clipboard())
    assert copied == shown
    page.click({"testid": "inspector-tab-raw"})
    page.click({"testid": "inspector-copy-raw"})
    raw = page.clipboard()
    assert soc.rare_process in raw
    page.click({"testid": "inspector-tab-fields"})
    page.wait_text(soc.rare_hash, exact=False)
    timeline.step("inspector", keys=sorted(shown)[:20])
    api = deep.api_rows(client, soc, query)
    assert {r.get("metadata.uid") for r in api} >= {shown.get("metadata.uid") or shown.get("metadata", {}).get("uid")}


def test_value_menu_pivots_group_by_and_copy(analyst, soc: SocData) -> None:
    page = analyst.page
    deep.search(page, soc, f'source_type="{soc.auth}" status="Failure"')
    value = {"css": '[data-testid="field-value"][data-field="device.hostname"]', "nth": 0}
    page.wait_for(value)
    host = page.texts(value)[0].strip()
    page.click(value)
    page.click({"role": "menuitem", "name": "Copy value"})
    assert page.clipboard() == host
    page.click(value)
    before = deep.run_mark(page)
    page.click({"role": "menuitem", "name": "Group by device.hostname"})
    deep.wait_new_results(page, before)
    q = deep.editor_query(page)
    assert "stats count by device.hostname" in q, q
    header, rows = deep.table(page)
    failures_by_host = {r[0]: deep.as_int(r[1]) for r in rows if r}
    assert failures_by_host.get("jump-01", 0) >= 40, failures_by_host


# ---------------------------------------------------------------- time


def test_time_picker_preset_absolute_range_and_drag_zoom(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    query = f'source_type="{soc.auth}"'
    deep.search(page, soc, query)

    # Relative preset.
    before = deep.run_mark(page)
    page.click({"testid": "time-range-trigger"})
    page.click({"css": '[data-testid="time-preset"][data-preset="Last 24 hours"]'})
    shown = deep.wait_new_results(page, before)
    assert _fragment(page.url).get("time") == "Last 24 hours"
    api24 = int(client.search(query, limit=1, minutes_back=24 * 60)["total_count"])
    assert abs(shown - api24) <= 2, (shown, api24)  # the window slides by seconds between the two
    assert shown < soc.by_source[soc.auth]
    timeline.step("24h", shown=shown, api=api24)

    # Absolute: yesterday 06:00-18:00 UTC.
    day = (soc.end - timedelta(days=1)).date()  # a day that holds seeded events
    start = datetime(day.year, day.month, day.day, 6, tzinfo=UTC)
    end = datetime(day.year, day.month, day.day, 18, tzinfo=UTC)
    ticks = {"css": '[data-testid="timeline-chart"] .recharts-cartesian-axis-tick'}
    ticks_24h = page.texts(ticks)
    page.click({"testid": "time-range-trigger"})
    page.fill(
        uilib.field({"testid": "time-from-date"}, day.isoformat()),
        uilib.field({"testid": "time-from-time"}, "06:00"),
        uilib.field({"testid": "time-to-date"}, day.isoformat()),
        uilib.field({"testid": "time-to-time"}, "18:00"),
    )
    before = deep.run_mark(page)
    page.click({"testid": "time-range-apply"})
    shown = deep.wait_new_results(page, before)
    frag = _fragment(page.url)
    timeline.step("absolute", frag=frag, shown=shown)
    assert frag.get("start", "").startswith(start.strftime("%Y-%m-%dT06:00")), frag
    assert frag.get("end", "").startswith(end.strftime("%Y-%m-%dT18:00")), frag
    api_abs = int(client.search(query, limit=1, time_range={"start": start.isoformat(), "end": end.isoformat()})
                  ["total_count"])
    assert shown == api_abs

    # Drag-zoom on the event stream (once it is drawn for the new window):
    # a narrower window, re-run, == API.
    eventually(lambda: page.texts(ticks), timeout=30, interval=0.5, desc="the event stream redrawn for the range",
               ok=lambda t: bool(t) and t != ticks_24h)
    page.screenshot("before-zoom.png")
    before = deep.run_mark(page)
    page.drag({"testid": "timeline-chart"}, (0.3, 0.5), (0.6, 0.5))
    zoomed = deep.wait_new_results(page, before)
    zf = _fragment(page.url)
    z_start, z_end = datetime.fromisoformat(zf["start"].replace("Z", "+00:00")), \
        datetime.fromisoformat(zf["end"].replace("Z", "+00:00"))
    timeline.step("zoom", frag=zf, shown=zoomed)
    assert start <= z_start < z_end <= end + timedelta(hours=1)
    assert (z_end - z_start) < (end - start)
    api_zoom = int(client.search(query, limit=1, time_range={"start": zf["start"], "end": zf["end"]})["total_count"])
    assert zoomed == api_zoom <= api_abs


# ---------------------------------------------------------------- saved queries, export, history


def _saved(client: Nano) -> list[dict]:
    body = expect(client.search_http.get("/api/search/saved/mine"), 200)
    return body if isinstance(body, list) else body.get("saved_searches", body.get("items", []))


def test_saved_query_save_and_load(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    query = f'source_type="{soc.auth}" status="Failure" | stats count by actor.user.name'
    deep.search(page, soc, query)
    name = f"deep failures {soc.tag}"
    page.click({"role": "button", "name": "Save", "exact": True})
    page.fill(uilib.field({"placeholder": "e.g. Failed console logins"}, name))
    page.click({"role": "button", "name": "Save query", "exact": True})
    page.wait_for({"placeholder": "e.g. Failed console logins"}, gone=True)
    saved = eventually(lambda: [s for s in _saved(client) if s.get("name") == name], timeout=15, interval=0.5,
                       desc="the saved query via the API", ok=lambda v: len(v) == 1)[0]
    analyst.cleanup.register_http(f"saved {saved['id']}",
                                  lambda: client.search_http.delete(f"/api/search/saved/{saved['id']}"))
    assert saved["query"] == query
    assert saved.get("time_range", {}).get("start"), saved

    # Load it from the palette on a blank search page.
    page.goto("/search")
    page.click({"role": "button", "name": "Saved queries", "exact": True})
    page.wait_for({"testid": "saved-queries-palette"})
    row = {"css": f'[data-testid="saved-query-row"][data-saved-query-id="{saved["id"]}"]'}
    page.wait_for(row)
    before = deep.run_mark(page)
    page.click(row)
    deep.wait_new_results(page, before)
    assert deep.editor_query(page) == query
    header, rows = deep.table(page)
    assert {r[0]: deep.as_int(r[1]) for r in rows if r} == soc.auth_failures_by_user
    timeline.step("loaded", id=saved["id"])


def test_saved_query_can_be_edited_and_deleted_in_the_ui(analyst, soc: SocData) -> None:
    page, client = analyst.page, analyst.client
    query = f'source_type="{soc.dns}"'
    name = f"deep edit {soc.tag}"
    created = expect(client.search_http.post("/api/search/saved", json={
        "name": name, "query": query, "query_mode": "piped", "time_range": soc.window(), "visibility": "private"}),
        200, 201)
    sid = created.get("id") or created.get("saved_search", {}).get("id")
    analyst.cleanup.register_http(f"saved {sid}", lambda: client.search_http.delete(f"/api/search/saved/{sid}"))
    page.goto("/search")
    page.click({"role": "button", "name": "Saved queries", "exact": True})
    row = {"css": f'[data-testid="saved-query-row"][data-saved-query-id="{sid}"]'}
    page.wait_for(row)
    page.hover(row)
    assert page.count({"role": "button", "name": "Run query", "within": row}) == 1
    edit = page.count({"role": "button", "name": "Edit query", "within": row})
    delete = page.count({"role": "button", "name": uilib.rx("^Delete"), "within": row})
    deep.bug_assert(page, edit > 0 and delete > 0, "saved-query-edit-delete-missing",
                    f"saved-query row offers edit={edit} delete={delete}")

    # NAN-5695: edit name, query and description in place; the API has them.
    page.click({"role": "button", "name": "Edit query", "within": row})
    form = {"testid": "saved-query-edit-form"}
    page.wait_for(form)
    renamed, requery = f"deep edited {soc.tag}", f'source_type="{soc.dns}" query.hostname="github.com"'
    page.fill(uilib.field({"css": f"#sq-edit-name-{sid}"}, renamed),
              uilib.field({"css": f"#sq-edit-query-{sid}"}, requery),
              uilib.field({"css": f"#sq-edit-desc-{sid}"}, "edited in the palette"))
    page.click({"role": "button", "name": "Save", "exact": True, "within": form})
    page.wait_for(form, gone=True)
    edited = eventually(lambda: [s for s in _saved(client) if s.get("id") == sid], timeout=15, interval=0.5,
                        desc="the edit via the API", ok=lambda v: len(v) == 1 and v[0].get("name") == renamed)[0]
    assert edited["query"] == requery and edited.get("description") == "edited in the palette"

    # Delete asks first, then removes it; the palette stays open.
    page.hover(row)
    page.click({"role": "button", "name": "Delete query", "within": row})
    dialog = {"role": "alertdialog"}
    page.wait_for(dialog)
    page.click({"role": "button", "name": "Delete", "exact": True, "within": dialog})
    eventually(lambda: [s for s in _saved(client) if s.get("id") == sid], timeout=15, interval=0.5,
               desc="the delete via the API", ok=lambda v: v == [])
    page.wait_for(row, gone=True)
    assert page.count({"testid": "saved-queries-palette"}) == 1
    assert deep.new_page_errors(analyst) == []


def test_saved_query_keeps_its_description(analyst, soc: SocData) -> None:
    page, client = analyst.page, analyst.client
    deep.search(page, soc, f'source_type="{soc.proc}"')
    name, description = f"deep desc {soc.tag}", "Process launches across the fleet"
    page.click({"role": "button", "name": "Save", "exact": True})
    page.fill(uilib.field({"placeholder": "e.g. Failed console logins"}, name),
              uilib.field({"placeholder": "Short explanation for your team"}, description))
    page.click({"role": "button", "name": "Save query", "exact": True})
    saved = eventually(lambda: [s for s in _saved(client) if s.get("name") == name], timeout=15, interval=0.5,
                       desc="saved", ok=lambda v: len(v) == 1)[0]
    analyst.cleanup.register_http(f"saved {saved['id']}",
                                  lambda: client.search_http.delete(f"/api/search/saved/{saved['id']}"))
    deep.bug_assert(page, saved.get("description") == description, "saved-query-description-dropped",
                    f"saved description is {saved.get('description')!r}")


def test_csv_export_of_events_and_stats(analyst, soc: SocData, timeline) -> None:
    page = analyst.page
    query = f'source_type="{soc.auth}" | stats count by actor.user.name'
    deep.search(page, soc, query)
    name, text = page.download({"css": 'main button[title="Export"]'})
    rows = list(csv.DictReader(io.StringIO(text)))
    timeline.step("stats csv", file=name, rows=len(rows))
    assert name.endswith(".csv")
    assert {r["actor.user.name"]: int(r["count"]) for r in rows} == soc.auth_by_user

    shown = deep.search(page, soc, f'source_type="{soc.proc}" device.hostname="{soc.rare_process_host}"')
    loaded = int(page.attr(deep.RESULTS, "data-shown") or 0)
    _, text = page.download({"testid": "export-csv"})
    rows = list(csv.DictReader(io.StringIO(text)))
    timeline.step("events csv", rows=len(rows), loaded=loaded, total=shown)
    assert len(rows) == loaded
    assert any(soc.rare_process in json.dumps(r) for r in rows) or loaded < shown


def test_timechart_export_downloads_the_buckets(analyst, soc: SocData) -> None:
    page = analyst.page
    deep.search(page, soc, f'source_type="{soc.auth}" | timechart span=6h count')
    page.wait_text("Timechart", exact=False)
    export = {"css": 'main button[title="Export"]'}
    assert page.count(export) == 1, "the timechart has no Export button"
    try:
        _, text = page.download(export, timeout_ms=10_000)
        problem = None if "count" in text.splitlines()[0] else f"timechart Export file has no count column: {text[:120]!r}"
    except uilib.UiError as exc:
        if "waiting for a download to be produced" not in str(exc):
            raise  # the click itself failed: a different regression
        problem = "timechart Export produced no file"
    assert deep.new_page_errors(analyst) == []
    deep.bug_assert(page, problem is None, "timechart-export-noop", problem or "")


def test_search_history_records_runs_and_recalls_a_query(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    first = f'source_type="{soc.dns}" query.hostname="github.com"'
    second = f'source_type="{soc.net}" dst_endpoint.port=3389'
    deep.search(page, soc, first)
    deep.run_editor(page, second)
    hist = eventually(lambda: expect(client.api.get("/api/search/history"), 200), timeout=15,
                      interval=0.5, desc="history via the API",
                      ok=lambda b: {first, second} <= {h.get("query", "").strip() for h in b.get("entries", [])})
    timeline.step("api history", n=len(hist.get("entries", [])))
    page.editor_fill(deep.EDITOR, "")
    page.press_key(deep.EDITOR, "Backspace")
    page.press_key(deep.EDITOR, "ArrowDown")
    page.wait_for({"testid": "search-history-dropdown"})
    items = page.attrs({"testid": "search-history-item"}, "title")
    assert first in items and second in items, items[:10]
    page.click({"testid": "search-history-item", "nth": items.index(first)})
    assert deep.editor_query(page) == first


def test_compiled_sql_has_one_where_and_no_explicit_prewhere(analyst, soc: SocData) -> None:
    """Inspect SQL shows the generated ClickHouse SQL; it must follow the
    single-WHERE rule (NAN-1412: no explicit PREWHERE)."""
    page = analyst.page
    deep.search(page, soc, f'source_type="{soc.auth}" status="Failure" | stats count by actor.user.name')
    page.click({"role": "button", "name": "More", "exact": True})
    page.click({"role": "menuitem", "name": "Inspect SQL"})
    page.wait_text("Compiled SQL", exact=False, timeout_ms=30_000)
    sql = eventually(page.main_text, timeout=30, interval=1, desc="compiled SQL text",
                     ok=lambda t: "SELECT" in t and "WHERE" in t)
    assert "PREWHERE" not in sql.upper()


# ---------------------------------------------------------------- prevalence and rarity


def _bulk_prevalence(client: Nano, artifact: str, window: str | None = None) -> dict:
    """The Prevalence API's record for one artifact (the API defaults to 24h)."""
    req = {"artifacts": [artifact]} | ({"window": window} if window else {})
    body = expect(client.api.post("/api/prevalence/bulk", json=req), 200)
    rows = [r for r in body.get("data", []) if r.get("artifact") == artifact]
    assert len(rows) == 1, f"the prevalence API has no single record for {artifact}: {body}"
    return rows[0]


def test_rarity_scatter_marks_the_rare_binary_and_clicks_through(analyst, soc: SocData, timeline) -> None:
    page, client = analyst.page, analyst.client
    now = soc.end  # the seeded tail, not wall-clock: kept-stack re-runs reuse the rows
    extra = f"&start={(now - timedelta(hours=1)).isoformat().replace('+00:00', 'Z')}" \
            f"&end={(now + timedelta(minutes=5)).isoformat().replace('+00:00', 'Z')}&view=rarity"
    uilib.run_search(page, f'source_type="{soc.proc}"', extra=extra)
    page.click({"testid": "timeline-tab-rarity"})
    dot = {"css": f'[data-testid="rarity-dot"][data-artifact="{soc.rare_hash}"]'}
    page.wait_for(dot, timeout_ms=90_000)
    rare = eventually(lambda: page.attr(dot, "data-rare"), timeout=60, interval=1,
                      desc="the rare hash's prevalence to load", ok=lambda v: v in ("true", "false"))
    hosts = page.attr(dot, "data-host-count")
    common = {"css": f'[data-testid="rarity-dot"][data-artifact="{soc.proc_hash["svchost.exe"]}"]'}
    common_hosts = page.attr(common, "data-host-count") if page.count(common) else None
    timeline.step("scatter", rare=rare, hosts=hosts, common_hosts=common_hosts)
    assert rare == "true" and hosts == "1"
    if common_hosts is not None:
        assert int(common_hosts) > 1
    page.screenshot("rarity-scatter.png")

    before = deep.run_mark(page)
    page.click(dot)
    shown = deep.wait_new_results(page, before)
    assert soc.rare_hash in deep.editor_query(page)
    assert shown >= 1
    assert all(soc.rare_process in r for r in uilib.result_rows_text(page))


def test_rarity_marks_only_the_rare_domain_on_ocsf_dns(analyst, soc: SocData, timeline) -> None:
    """v2.0.33 (NAN-5657): on OCSF DNS data, domains every host resolves are
    not RARE; the one domain a single host looked up once is."""
    page = analyst.page
    now = soc.end  # the seeded tail, not wall-clock: kept-stack re-runs reuse the rows
    extra = f"&start={(now - timedelta(hours=1)).isoformat().replace('+00:00', 'Z')}" \
            f"&end={(now + timedelta(minutes=5)).isoformat().replace('+00:00', 'Z')}&view=rarity"
    uilib.run_search(page, f'source_type="{soc.dns}"', extra=extra)
    page.click({"testid": "timeline-tab-rarity"})
    rare = {"css": f'[data-testid="rarity-dot"][data-artifact="{soc.rare_domain}"]'}
    page.wait_for(rare, timeout_ms=90_000)

    def marks() -> dict[str, str | None]:
        dots = page.attrs({"css": '[data-testid="rarity-dot"][data-artifact-type="domain"]'}, "data-artifact")
        flags = page.attrs({"css": '[data-testid="rarity-dot"][data-artifact-type="domain"]'}, "data-rare")
        return dict(zip(dots, flags))

    got = eventually(marks, timeout=60, interval=1, desc="domain prevalence loaded",
                     ok=lambda m: soc.rare_domain in m and all(v in ("true", "false") for v in m.values()))
    header = eventually(page.main_text, timeout=30, interval=1, desc="the rarity header counts",
                        ok=lambda t: re.search(r"(\d+)\s+rare\b", t, re.I) is not None)
    rare_n = int(re.search(r"(\d+)\s+rare\b", header, re.I).group(1))
    timeline.step("domains", marks=got, rare_badge=rare_n)
    assert got[soc.rare_domain] == "true"
    # Every host resolves the five busy domains: none of them is RARE (they
    # sit above the default "<= 10 hosts" plot filter), so the RARE badge
    # counts the one domain seen once.
    assert all(v == "false" for d, v in got.items() if d != soc.rare_domain), got
    assert rare_n == 1, f"{rare_n} artifacts marked RARE; only {soc.rare_domain} is rare"


def _inspector_json(page: uilib.UiPage) -> dict:
    page.click({"role": "button", "name": "Open event in inspector", "nth": 0})
    page.click({"testid": "inspector-tab-json"})
    page.wait_for({"testid": "inspector-json"})
    return json.loads(page.texts({"testid": "inspector-json"})[0])


PREV_KEYS = ("host_count", "is_rare", "prevalence_score", "prevalence_type", "prevalence_artifact", "total_occurrences")


def test_prevalence_filter_values_match_the_prevalence_api(analyst, soc: SocData, timeline) -> None:
    """`| prevalence hash_prevalence < N`: the rare binary's launches carry the
    Prevalence API's host count, rarity and score, the opened event shows
    exactly those values, and the filter keeps only the rare binary."""
    page, client = analyst.page, analyst.client
    truth = _bulk_prevalence(client, soc.rare_hash)
    assert truth["host_count"] == 1 and truth["is_rare"] is True and truth["total_occurrences"] == 2, truth

    query = f'source_type="{soc.proc}" process.name="{soc.rare_process}" | prevalence hash_prevalence < 5'
    shown = deep.search(page, soc, query)
    api = deep.api_rows(client, soc, query)
    assert shown == len(api) == 2
    for row in api:
        assert row["prevalence_artifact"] == soc.rare_hash and row["prevalence_type"] == "hash", row
        assert row["host_count"] == truth["host_count"] == 1
        assert bool(row["is_rare"]) is truth["is_rare"] is True
        assert row["prevalence_score"] == truth["prevalence_score"]
        assert row["total_occurrences"] == truth["total_occurrences"]
    inspected = _inspector_json(page)
    timeline.step("prevalence", api={k: api[0].get(k) for k in PREV_KEYS},
                  ui={k: inspected.get(k) for k in PREV_KEYS}, truth=truth)
    for key in PREV_KEYS:
        assert str(inspected.get(key)) == str(api[0][key]), f"{key}: UI {inspected.get(key)!r} != API {api[0][key]!r}"

    # Over the whole process source, `< 2` hosts keeps only the rare binary.
    deep.search(page, soc, f'source_type="{soc.proc}" | prevalence hash_prevalence < 2 | stats count by process.name')
    header, rows = deep.table(page)
    assert {r[0]: deep.as_int(r[1]) for r in rows} == {soc.rare_process: 2}, rows


def test_prevalence_enrich_true_matches_the_prevalence_api(analyst, soc: SocData, timeline) -> None:
    """`| prevalence enrich=true` (what the value menu's "Check prevalence" runs)
    must annotate rows like the Prevalence API does (NAN-5718): the rare binary
    as rare, and every decorated artifact (hash, domain, IP) with the API's
    host count, rarity and score."""
    page, client = analyst.page, analyst.client
    truth = _bulk_prevalence(client, soc.rare_hash)
    assert truth["host_count"] == 1 and truth["is_rare"] is True, truth
    query = f'source_type="{soc.proc}" process.name="{soc.rare_process}" | prevalence enrich=true'
    shown = deep.search(page, soc, query)
    api = deep.api_rows(client, soc, query)
    assert shown == len(api) == 2
    got = {k: api[0].get(k) for k in PREV_KEYS}
    timeline.step("enrich=true", api=got, truth=truth)
    for row in api:
        assert row["prevalence_artifact"] == soc.rare_hash and row["prevalence_type"] == "hash", row
        assert row["host_count"] == truth["host_count"], f"enrich=true host_count {row['host_count']} vs API {truth}"
        assert bool(row["is_rare"]) is truth["is_rare"]
        assert row["prevalence_score"] == truth["prevalence_score"]
        assert row["total_occurrences"] == truth["total_occurrences"]

    # Every artifact type the decoration picks agrees with the API for that
    # artifact at the same window (`enrich=true` defaults to 30d, the API to
    # 24h; the 72h seed's common binaries have hosts outside 24h): the rare DNS
    # lookup (domain, or its host's IP if rarer) and the process launches over
    # the whole source.
    for q in (f'source_type="{soc.dns}" query.hostname="{soc.rare_domain}" | prevalence enrich=true',
              f'source_type="{soc.proc}" | prevalence enrich=true | head 50'):
        rows = deep.api_rows(client, soc, q, limit=50)
        assert rows, q
        decorated = [r for r in rows if r.get("prevalence_artifact")]
        assert decorated, f"{q}: no row decorated: {rows[0]}"
        seen: dict[str, dict] = {}
        for row in decorated:
            art = row["prevalence_artifact"]
            want = seen.setdefault(art, _bulk_prevalence(client, art, "30d"))
            timeline.step("agree", query=q, artifact=art, type=row["prevalence_type"],
                          got={k: row.get(k) for k in ("host_count", "is_rare", "prevalence_score")}, want=want)
            assert row["host_count"] == want["host_count"], (q, art, row["host_count"], want)
            assert bool(row["is_rare"]) is want["is_rare"], (q, art, row["is_rare"], want)
            assert row["prevalence_score"] == want["prevalence_score"], (q, art, row["prevalence_score"], want)
        if "query.hostname" in q:
            assert soc.rare_domain in seen or any(r["prevalence_type"] == "ip" for r in decorated), seen


def test_prevalence_page_finds_the_rare_hash_and_pivots_to_its_events(analyst, soc: SocData, timeline) -> None:
    page = analyst.page
    page.goto("/prevalence")
    page.choose({"role": "combobox", "name": "Time window"}, "Last 7 days")
    page.fill(uilib.field({"placeholder": "Search artifacts, or paste a hash / IP / domain…"}, soc.rare_hash))
    page.wait_text(soc.rare_hash, exact=True, timeout_ms=60_000)
    page.wait_text(uilib.rx(r"^top hosts", "i"), exact=False, timeout_ms=60_000)  # the lookup card
    text = page.main_text()
    timeline.step("prevalence lookup", text=text[:600])
    for expect_shown in ("RARE", "1 host", "2 events", soc.rare_process_host, soc.rare_process, soc.proc):
        assert expect_shown in text, f"{expect_shown!r} not on the prevalence card"
    before = deep.run_mark(page)
    page.click({"role": "button", "name": "Search events", "nth": 0})
    page.wait_url(r"/search", timeout_ms=30_000)
    total = deep.wait_new_results(page, before)
    assert soc.rare_hash in deep.editor_query(page)
    timeline.step("pivot", query=deep.editor_query(page), total=total)
    assert deep.new_page_errors(analyst) == []
    assert total >= 1, f"the prevalence pivot found {total} events for the rare hash: {deep.editor_query(page)}"
    assert all(soc.rare_process in r for r in uilib.result_rows_text(page))
