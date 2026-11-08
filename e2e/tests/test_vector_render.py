"""Vector config rendering (NAN-4952 / NAN-4953) black-box.

NAN-4952: deploying a DRAFT log source used to write a parser file whose input
named a `source_router` route the router never emitted (every `source_type`
spelling other than `routed`/`vector` reached the router in the parser file
but not in the route table). Vector refused the reload, and because the deploy
had already enabled the draft, every later deploy of any source failed the same
way. Here: a draft deploys and goes live, then a normal source, then a parser
publish; and a deploy Vector refuses is reported as failed, rolled back and
does not poison the next deploy.

NAN-4953: tenant VRL is rendered into config the live Vector env-interpolates.
Here: interpolation syntax is refused at save with an explicit message, and VRL
that legitimately uses `$` (a regex anchor, a `$1` capture reference) runs
exactly as written.
"""

from __future__ import annotations

from typing import Any

from nano_e2e import ingest
from nano_e2e.client import Nano, expect, row_text
from nano_e2e.runid import route_key as make_route_key
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually


def _create(nano: Nano, name: str, source_type: str, vrl: str, *, draft: bool, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": name,
        "description": "nano-e2e vector render scenario (NAN-4952/4953)",
        "source_type": source_type,
        "parser_vrl": vrl,
        "match_values": [name],
        **extra,
    }
    if draft:
        body["lifecycle_status"] = "draft"
    return expect(nano.api.post("/api/log-sources", json=body), 200, 201)


def _token(nano: Nano, source_id: str, name: str) -> tuple[str, str]:
    return nano.issue_token(source_id, f"{name}-tok")


def _parsed_live(stack: Stack, nano: Nano, token: str, mark: str, label: str, expect_text: str) -> None:
    """Send fresh events through the source's token until one comes back
    carrying `expect_text` (the parser ran on it)."""
    n = {"i": 0}

    def send_and_read() -> list:
        n["i"] += 1
        m = f"{mark}-{label}-{n['i']}"
        r = ingest.http(stack.vector_http_url, token, [{"message": m}])
        assert r.status_code == 200, r.text
        return eventually(lambda: nano.rows(f'"{m}"', limit=5), timeout=INGEST_VISIBLE, desc=m)

    eventually(
        send_and_read,
        timeout=180,
        interval=3,
        desc=f"{label}: events parsed by the deployed parser",
        ok=lambda rs: any(expect_text in row_text(r) for r in rs),
    )


def test_draft_then_normal_then_publish_all_go_live(
    stack: Stack, nano: Nano, token_source, mark: str, request, timeline
) -> None:
    created: list[tuple[str, str]] = []
    try:
        # 1. A draft whose source_type is the accepted `http` alias: before
        #    NAN-4952 its parser file read `source_router.<name>` and the router
        #    had no such route.
        d_name = make_route_key(request.node.nodeid, "draft")
        draft = _create(nano, d_name, "http", '.message = "draft-parsed " + to_string!(.message)', draft=True)
        d_cred, d_tok = _token(nano, draft["id"], d_name)
        created.append((draft["id"], d_cred))
        res = expect(nano.api.post(f"/api/log-sources/{draft['id']}/deploy"), 200)
        assert res.get("success") is True, f"draft deploy failed: {res}"
        timeline.step("draft deployed", message=res.get("message"))
        _parsed_live(stack, nano, d_tok, mark, "draft", "draft-parsed")
        timeline.step("draft is live")

        # 2. A normal source deploys after it.
        n_name = make_route_key(request.node.nodeid, "normal")
        normal = _create(nano, n_name, "routed", '.message = "normal-parsed " + to_string!(.message)', draft=False)
        n_cred, n_tok = _token(nano, normal["id"], n_name)
        created.append((normal["id"], n_cred))
        res = expect(nano.api.post(f"/api/log-sources/{normal['id']}/deploy"), 200)
        assert res.get("success") is True, f"normal deploy after the draft failed: {res}"
        _parsed_live(stack, nano, n_tok, mark, "normal", "normal-parsed")
        timeline.step("normal source is live")

        # 3. A parser publish on another draft (the onboarding path).
        src = token_source("publish")
        expect(
            nano.api.put(
                f"/api/log-sources/{src.source_id}",
                json={"parser_vrl": '.message = "published-parsed " + to_string!(.message)'},
            ),
            200,
        )
        res = expect(nano.api.post(f"/api/log-sources/{src.source_id}/publish"), 200)
        assert res.get("success") is True, f"publish after the draft failed: {res}"
        _parsed_live(stack, nano, src.token, mark, "publish", "published-parsed")
        timeline.step("published parser is live")

        # The earlier two are still live (nothing was rolled back under them).
        _parsed_live(stack, nano, d_tok, mark, "draft-again", "draft-parsed")
        _parsed_live(stack, nano, n_tok, mark, "normal-again", "normal-parsed")
    finally:
        for source_id, cred in created:
            try:
                nano.revoke_token(cred)
            except Exception:  # noqa: BLE001,S110 - best-effort teardown
                pass
            nano.delete_source(source_id)


def test_refused_deploy_is_reported_rolled_back_and_does_not_poison_later_deploys(
    stack: Stack, nano: Nano, mark: str, request, timeline
) -> None:
    created: list[tuple[str, str | None]] = []
    try:
        # A draft whose sampling condition Vector cannot compile (the api does
        # not compile it; Vector refuses the whole config at reload).
        b_name = make_route_key(request.node.nodeid, "broken")
        broken = _create(nano, b_name, "routed", ".parsed = true", draft=True)
        created.append((broken["id"], None))
        # Sampling is set by update (create does not persist it).
        expect(
            nano.api.put(
                f"/api/log-sources/{broken['id']}",
                json={"sampling_ratio": 0.5, "sampling_exclude_condition": ".x =="},
            ),
            200,
        )
        res = expect(nano.api.post(f"/api/log-sources/{broken['id']}/deploy"), 200)
        assert res.get("success") is False, f"a config Vector refuses must not be reported live: {res}"
        timeline.step("refused deploy reported", message=res.get("message"))
        after = expect(nano.api.get(f"/api/log-sources/{broken['id']}"), 200)
        assert after.get("enabled") is False, f"the refused draft must be disabled again: {after}"
        assert after.get("lifecycle_status") == "draft", after

        # The next deploy of an unrelated source goes live.
        g_name = make_route_key(request.node.nodeid, "good")
        good = _create(nano, g_name, "routed", '.message = "good-parsed " + to_string!(.message)', draft=False)
        g_cred, g_tok = _token(nano, good["id"], g_name)
        created.append((good["id"], g_cred))
        res = expect(nano.api.post(f"/api/log-sources/{good['id']}/deploy"), 200)
        assert res.get("success") is True, f"a deploy after a refused one failed: {res}"
        _parsed_live(stack, nano, g_tok, mark, "good", "good-parsed")
        timeline.step("later deploy is live")
    finally:
        for source_id, cred in created:
            if cred:
                try:
                    nano.revoke_token(cred)
                except Exception:  # noqa: BLE001,S110 - best-effort teardown
                    pass
            nano.delete_source(source_id)


def test_interpolation_syntax_is_refused_and_dollar_vrl_runs_as_written(
    stack: Stack, nano: Nano, token_source, mark: str, timeline
) -> None:
    src = token_source("dollar")

    # Refused at save, naming the escape.
    for bad in ('.message = "${CLICKHOUSE_PASSWORD}"', '.message = "$VECTOR_AUTH_TOKEN"'):
        r = nano.api.put(f"/api/log-sources/{src.source_id}", json={"parser_vrl": bad})
        assert r.status_code in (400, 422), f"{bad!r} must be refused, got {r.status_code}: {r.text}"
        assert "environment-variable syntax" in r.text, r.text
    v = expect(
        nano.api.post("/api/log-sources/validate-vrl", json={"vrl_code": '.a = "${CLICKHOUSE_PASSWORD}"'}), 200
    )
    assert v.get("valid") is False, v
    timeline.step("interpolation syntax refused")

    # `$` that is not interpolation runs exactly as written: a regex anchor, a
    # numbered capture reference, and the documented literal form. Before
    # NAN-4953 Vector substituted `$1` from its own environment.
    vrl = (
        'm = to_string!(.message)\n'
        '.message = replace(m, r\'^(\\S+)$\', "cap-$1") + " lit-" + "$" + "{HOME}"'
    )
    expect(nano.api.put(f"/api/log-sources/{src.source_id}", json={"parser_vrl": vrl}), 200)
    res = expect(nano.api.post(f"/api/log-sources/{src.source_id}/publish"), 200)
    assert res.get("success") is True, f"publish failed: {res}"
    n = {"i": 0}

    def send_and_read() -> list:
        n["i"] += 1
        m = f"{mark}-dollar-{n['i']}"
        assert ingest.http(stack.vector_http_url, src.token, [{"message": m}]).status_code == 200
        return eventually(lambda: nano.rows(f'"cap-{m}"', limit=5), timeout=INGEST_VISIBLE, desc=m)

    rows = eventually(send_and_read, timeout=180, interval=3, desc="dollar VRL parsed")
    text = row_text(rows[0])
    assert "lit-${HOME}" in text, text
    timeline.step("dollar VRL ran as written", attempts=n["i"])
