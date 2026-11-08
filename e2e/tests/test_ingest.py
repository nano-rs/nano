"""Per-source ingest tokens (NAN-4907) black-box over the API and the real
Vector 0.61 fork: create source -> token -> HEC + HTTP -> searchable as the
token's source; a spoofed source type survives only as claimed_source_type;
rotate -> old 401 / new 200; revoke -> 401."""

from __future__ import annotations

from nano_e2e import ingest
from nano_e2e.client import Nano, row_text
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, VECTOR_RELOAD, eventually


def test_token_lifecycle(stack: Stack, nano: Nano, token_source, mark: str, timeline) -> None:
    src = token_source()
    timeline.step("source+token ready", route_key=src.route_key)

    hec_mark, http_mark, spoof_mark = f"{mark}-hec", f"{mark}-http", f"{mark}-spoof"
    r = ingest.hec(stack.hec_url, src.token, {"message": f"{hec_mark} user=alice action=login"})
    assert r.status_code == 200, r.text
    r = ingest.http(stack.vector_http_url, src.token, [{"message": f"{http_mark} user=bob action=logout"}])
    assert r.status_code == 200, r.text
    r = ingest.hec(
        stack.hec_url, src.token, {"message": f"{spoof_mark} spoof"}, sourcetype="e2e_spoofed_type"
    )
    assert r.status_code == 200, r.text
    timeline.step("sent HEC + HTTP + spoofed HEC")

    for m in (hec_mark, http_mark, spoof_mark):
        rows = eventually(
            lambda m=m: nano.rows(f'"{m}"', limit=10),
            timeout=INGEST_VISIBLE,
            desc=f"event {m} searchable",
        )
        assert len(rows) == 1, f"expected exactly one row for {m}, got {len(rows)}"
        assert rows[0].get("source_type") == src.route_key, f"token must decide the source: {rows[0]}"
    spoofed = nano.rows(f'"{spoof_mark}"', limit=10)[0]
    assert "e2e_spoofed_type" in row_text(spoofed), f"claimed_source_type not kept: {spoofed}"
    assert spoofed.get("source_type") != "e2e_spoofed_type"
    timeline.step("all three searchable as the token's source")

    # Scoped search by source_type returns exactly this source's events.
    scoped = nano.rows(f'source_type="{src.route_key}" "{mark}"', limit=50)
    assert {m for m in (hec_mark, http_mark, spoof_mark) if any(m in row_text(x) for x in scoped)} == {
        hec_mark,
        http_mark,
        spoof_mark,
    }

    # Unknown token: 401 on both edges.
    assert ingest.hec(stack.hec_url, "nit_" + "0" * 40, {"message": "nope"}).status_code == 401
    assert ingest.http(stack.vector_http_url, "nit_" + "0" * 40, [{"message": "nope"}]).status_code == 401

    # Rotate: new token works, old one is rejected within the reload window.
    _new_cred, new_tok = nano.rotate_token(src.credential_id)
    eventually(
        lambda: ingest.hec(stack.hec_url, new_tok, {"message": f"{mark}-rotated"}).status_code,
        timeout=VECTOR_RELOAD,
        interval=1,
        desc="rotated token accepted",
        ok=lambda s: s == 200,
    )
    eventually(
        lambda: ingest.hec(stack.hec_url, src.token, {"message": f"{mark}-old"}).status_code,
        timeout=VECTOR_RELOAD,
        interval=1,
        desc="rotated-away token rejected",
        ok=lambda s: s == 401,
    )
    timeline.step("rotate: new 200, old 401")

    # Revoke: the new token is rejected too.
    listing = nano.list_tokens()
    active = [
        t for t in listing["tokens"] if t.get("route_key") == src.route_key and t.get("state") == "active"
    ]
    assert len(active) == 1, f"exactly one active token expected after rotate: {active}"
    nano.revoke_token(active[0]["credential_id"])
    eventually(
        lambda: ingest.hec(stack.hec_url, new_tok, {"message": f"{mark}-revoked"}).status_code,
        timeout=VECTOR_RELOAD,
        interval=1,
        desc="revoked token rejected",
        ok=lambda s: s == 401,
    )
    timeline.step("revoke: 401")
    # Nothing sent after revocation may be stored.
    assert nano.rows(f'"{mark}-revoked"', limit=5) == []


def test_tokens_are_isolated_per_source(stack: Stack, nano: Nano, token_source, mark: str) -> None:
    a, b = token_source("a"), token_source("b")
    assert ingest.hec(stack.hec_url, a.token, {"message": f"{mark}-a"}).status_code == 200
    assert ingest.hec(stack.hec_url, b.token, {"message": f"{mark}-b"}).status_code == 200
    ra = eventually(lambda: nano.rows(f'"{mark}-a"', limit=5), timeout=INGEST_VISIBLE, desc="source A event")
    rb = eventually(lambda: nano.rows(f'"{mark}-b"', limit=5), timeout=INGEST_VISIBLE, desc="source B event")
    assert ra[0]["source_type"] == a.route_key and rb[0]["source_type"] == b.route_key
    # Revoking A leaves B untouched.
    nano.revoke_token(a.credential_id)
    eventually(
        lambda: ingest.hec(stack.hec_url, a.token, {"message": "x"}).status_code,
        timeout=VECTOR_RELOAD,
        interval=1,
        desc="A revoked",
        ok=lambda s: s == 401,
    )
    assert ingest.hec(stack.hec_url, b.token, {"message": f"{mark}-b2"}).status_code == 200
