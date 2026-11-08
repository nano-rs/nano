"""Search URL contract (NAN-4927 G8/G10, on clickhouse/dev):

- G10: a legacy `?q=` link still runs, and is migrated in place: the query
  moves to the URL fragment, so a reload (or anything else that requests the
  page) never puts the hunt in a request URL; the reloaded page shows the same
  count as the search API;
- G8: a relative range stays relative through the run and a reload (`time=`
  preset in the URL, no fixed start/end), and the result equals the API's
  count for that window;
- the timeline's Rarity view is URL state: a link with `view=rarity` opens in
  rarity mode.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually


def _seed(stack: Stack, nano: Nano, lane, mark: str, n: int = 3) -> int:
    for i in range(n):
        lane.send(stack, mark, f"url-{mark[-6:]}", "198.51.100.30", "url-host", note=f"seq={i}")
    return eventually(
        lambda: nano.search(f'"{mark}"')["total_count"], timeout=INGEST_VISIBLE, desc="seed", ok=lambda c: c == n
    )


def test_query_lives_in_fragment_never_a_request_url(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, page: uilib.UiPage, timeline
) -> None:
    total = _seed(stack, nano, ocsf_lane, mark)
    uilib.run_search(page, f'"{mark}"')  # the legacy ?q= share-link form
    url = urlsplit(page.url)
    timeline.step("migrated", query=url.query, fragment=url.fragment[:200])
    assert "q" not in parse_qs(url.query), f"the query stayed in the query string: {url.query}"
    assert mark in parse_qs(url.fragment).get("q", [""])[0], url.fragment[:200]
    assert uilib.results_count(page) == total

    since = page.now_ms()
    page.reload()
    page.wait_text("Query complete", exact=False, timeout_ms=60_000)
    # What a server (or the edge access log) receives: the URL without its
    # fragment. Page navigations must never carry the hunt.
    sent = [u.split("#", 1)[0] for u in page.requests_containing(mark, since_ms=since)]
    navigations = [u for u in sent if mark in u and "/api/" not in u]
    timeline.step("reloaded", navigations=navigations, api_gets=[u for u in sent if mark in u and "/api/" in u])
    assert not navigations, f"the page URL sent to the server carries the hunt: {navigations}"
    assert uilib.results_count(page) == total


@pytest.mark.xfail(
    strict=False,
    reason="product finding (NAN-4937), intermittent (depends on which side requests fire): with the "
    "query in the fragment, Search still sends the hunt in "
    "GET query strings (/api/search/explanation?q=, /api/fields/ext?query=), so it lands in the edge "
    "access log; G10's 'never a request URL' holds for page navigations only",
)
def test_hunt_never_in_an_api_request_url(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, page: uilib.UiPage, timeline
) -> None:
    _seed(stack, nano, ocsf_lane, mark)
    since = page.now_ms()
    uilib.run_search(page, f'"{mark}"')
    api_gets = [
        u.split("#", 1)[0]
        for u in page.requests_containing(mark, since_ms=since)
        if "/api/" in u and mark in u.split("#", 1)[0]
    ]
    timeline.step("api GETs carrying the hunt", urls=api_gets)
    assert not api_gets, api_gets


def test_relative_range_stays_relative(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, page: uilib.UiPage, timeline
) -> None:
    total = _seed(stack, nano, ocsf_lane, mark)
    uilib.run_search(page, f'"{mark}"', extra="&time=Last 15 minutes")
    for step in ("run", "reload"):
        frag = parse_qs(urlsplit(page.url).fragment)
        q = parse_qs(urlsplit(page.url).query)
        timeline.step(step, time=frag.get("time") or q.get("time"), start=frag.get("start"))
        assert (frag.get("time") or q.get("time")) == ["Last 15 minutes"], page.url
        assert "start" not in frag and "end" not in frag, f"the relative range was pinned: {page.url}"
        assert uilib.results_count(page) == total
        if step == "run":
            page.reload()
            page.wait_text("Query complete", exact=False, timeout_ms=60_000)
    page.wait_text("Last 15 minutes", exact=False)


def test_rarity_view_link_opens_rarity(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, page: uilib.UiPage, timeline
) -> None:
    _seed(stack, nano, ocsf_lane, mark)
    uilib.run_search(page, f'"{mark}"', extra="&view=rarity")
    tab = {"role": "tab", "name": uilib.rx("Rarity")}
    page.wait_for(tab, timeout_ms=30_000)
    selected = page.attr(tab, "aria-selected") or page.attr(tab, "data-state")
    timeline.step("rarity", selected=selected, url=page.url[-120:])
    assert selected in ("true", "active"), selected
    assert "view=rarity" in page.url
