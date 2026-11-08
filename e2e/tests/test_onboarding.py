"""Connect-first onboarding (NAN-4912) black-box: a draft source's token ingests
BEFORE any parser is published (events land unparsed as the route key, the
source reads "receiving, not parsed"); publishing the parser goes through the
real deploy path and parses new events."""

from __future__ import annotations

from nano_e2e import ingest
from nano_e2e.client import Nano, expect, row_text
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

# Root-replacing parser: the token's claim must survive `. = {..}`.
PARSER = '. = { "message": .message, "ext": { "e2e_parsed": "yes" } }'


def test_data_before_parser_publish(stack: Stack, nano: Nano, token_source, mark: str, timeline) -> None:
    src = token_source(warm=False)
    status = expect(nano.api.get(f"/api/log-sources/{src.source_id}/connect-status"), 200)
    assert status.get("state") == "awaiting_data", status
    timeline.step("connect status", state=status.get("state"), events_24h=status.get("events_24h"))

    accepted = {"n": 0}

    def send_pre_publish() -> int:
        i = accepted["n"]
        r = ingest.http(
            stack.vector_http_url,
            src.token,
            [{"message": f"{mark}-pre-{i} vpn connect"}],
        )
        if r.status_code == 200:
            accepted["n"] += 1
        return accepted["n"]

    eventually(
        send_pre_publish,
        timeout=INGEST_VISIBLE,
        interval=1,
        desc="Vector to accept three pre-publish events",
        ok=lambda n: n >= 3,
    )
    rows = eventually(
        lambda: nano.rows(f'"{mark}-pre"', limit=10),
        timeout=INGEST_VISIBLE,
        desc="pre-publish events searchable",
        ok=lambda rs: len(rs) >= 3,
    )
    assert all(r.get("source_type") == src.route_key for r in rows), rows
    assert not any("e2e_parsed" in row_text(r) for r in rows), "no parser yet, rows must be unparsed"
    timeline.step("3 unparsed events searchable before publish")

    status = eventually(
        lambda: expect(nano.api.get(f"/api/log-sources/{src.source_id}/connect-status"), 200),
        timeout=INGEST_VISIBLE,
        desc="connect status = receiving_unparsed",
        ok=lambda s: s.get("state") == "receiving_unparsed",
    )
    assert status.get("active_tokens") == 1, status
    timeline.step("connect status", state=status.get("state"), events_24h=status.get("events_24h"))

    expect(nano.api.put(f"/api/log-sources/{src.source_id}", json={"parser_vrl": PARSER}), 200)
    published = expect(nano.api.post(f"/api/log-sources/{src.source_id}/publish"), 200)
    assert published.get("success") is True, f"publish failed: {published}"
    timeline.step("parser published", message=published.get("message"))

    # After the deploy lands (stage, promote, reload), new events are parsed.
    n = {"i": 0}

    def send_and_read() -> list:
        n["i"] += 1
        m = f"{mark}-post-{n['i']}"
        assert (
            ingest.http(stack.vector_http_url, src.token, [{"message": f"{m} vpn connect"}]).status_code
            == 200
        )
        return [r for r in eventually(lambda: nano.rows(f'"{m}"', limit=5), timeout=INGEST_VISIBLE, desc=m)]

    rows = eventually(
        send_and_read,
        timeout=180,
        interval=3,
        desc="post-publish event parsed by the published parser",
        ok=lambda rs: any("e2e_parsed" in row_text(r) for r in rs),
    )
    assert rows[0].get("source_type") == src.route_key, rows[0]
    timeline.step("post-publish events parsed", attempts=n["i"])

    status = eventually(
        lambda: expect(nano.api.get(f"/api/log-sources/{src.source_id}/connect-status"), 200),
        timeout=INGEST_VISIBLE,
        desc="connect status = receiving",
        ok=lambda s: s.get("state") == "receiving",
    )
    timeline.step("connect status", state=status.get("state"), events_24h=status.get("events_24h"))
