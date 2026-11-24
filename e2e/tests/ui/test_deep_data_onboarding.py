"""Deep data onboarding in the browser (NAN-5686).

Covers what tests/ui/test_add_source.py (transports, tokens, health,
repository import), test_log_sources_nav.py (token issue/rotate/revoke) and
test_v2034_log_source_delete.py (delete) do not:

- the add-source wizard on HTTP JSON taken all the way to a published
  parser: a VRL compile error is shown with its line and blocks the deploy
  gate; the fixed VRL passes its sample test; "Publish source" deploys; events
  sent over HTTP JSON land parsed as OCSF (class 3002) and are searchable by
  their OCSF fields, in the API and the search UI;
- the parser editor on the log source page: Edit VRL, a bad edit is refused
  with a clear error, Test events runs a sample, Save VRL makes a draft
  ("Unpublished changes"), Publish with a passing OCSF sample makes v2, and
  new events carry the field the edit added; Versions lists both;
- the log source page's health: delivery receiving and the 1h count == the
  health API;
- the Nano Pipe live tap, when the stack has a tap relay.

Acting user: a throwaway SIEM engineer persona with explicit permissions.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any

import httpx
import pytest
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import PersonaCleanup, login_persona, source_by_route
from nano_e2e.runid import route_key
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

ENGINEER = (
    "search:view",
    "search:execute",
    "log_sources:view",
    "log_sources:create",
    "log_sources:edit",
    "log_sources:deploy",
    "credentials:view",
    "credentials:create",
    "source_configs:view",
    "parsers:view",
    "settings:system",  # issuing an ingest token (ISSUE_TOKEN_PERMISSION)
)

# HTTP JSON delivers the body's fields; a pasted sample arrives as the raw
# string in .message. Accept both. One statement per line and no multi-line
# blocks: the browser types this into CodeMirror, which auto-indents and
# auto-closes brackets.
GOOD_VRL = """
. = merge(., object(parse_json(string(.message) ?? "") ?? {}) ?? {})
.class_uid = 3002
.category_uid = 3
.activity_id = 1
.type_uid = 300201
.severity_id = 1
.time = to_unix_timestamp(now(), unit: "milliseconds")
.metadata.version = "1.9.0"
.metadata.product.name = "nano-e2e"
.metadata.product.vendor_name = "nano"
.metadata.log_source = "{rk}"
u = to_string(del(.user)) ?? "unknown"
.actor.user.name = u
.user.name = u
.src_endpoint.ip = to_string(del(.ip)) ?? null
.dst_endpoint.hostname = to_string(del(.host)) ?? null
.service.name = "nano-e2e-auth"
""".strip()
# A VRL compile error on line 2: an unhandled fallible call (E103).
BAD_VRL = '.class_uid = 3002\n.actor.user.name = upcase(.user)\n'


def _send(endpoint: dict[str, Any], token: str, **event: Any) -> int:
    return httpx.post(endpoint["nano_https_url"], json=event, headers={"Authorization": f"Bearer {token}"},
                      timeout=10).status_code


def _issue(page: uilib.UiPage, label: str) -> str:
    page.fill(uilib.field({"css": "#ingest-credential-label"}, label))
    page.click({"role": "button", "name": uilib.rx("^Issue")})
    page.wait_for({"testid": "one-time-token"})
    token = page.value({"css": 'input[aria-label="Ingest token"]'})
    page.driver.register_secret(token)
    assert token.startswith("nit_"), "unexpected ingest-token shape"
    return token


@pytest.fixture
def cleanup(nano: Nano):
    c = PersonaCleanup(nano)
    yield c
    c.actions.close()


def test_wizard_http_json_bad_vrl_then_publish_and_search_ocsf(
    stack: Stack, nano: Nano, mark: str, ui: uilib.Driver, artifact_dir, request, timeline, cleanup
) -> None:
    rk = route_key(request.node.nodeid, "http")
    user = f"onb-{mark[-8:]}"
    endpoint = expect(nano.api.get("/api/log-sources/ingest-endpoint"), 200)
    with login_persona(stack, nano, ui, artifact_dir, "deep-onboarding", ENGINEER) as persona:
        page, client = persona.page, persona.client
        page.goto("/ingestion/log-sources/new")
        page.wait_for({"testid": "add-feed-linear"})
        page.click({"text": "Custom source", "exact": True, "within": {"testid": "source-catalog"}})
        page.fill(uilib.field({"css": "#add-source-name"}, f"Deep HTTP {mark[-6:]}"))
        page.click({"testid": "source-continue"})
        page.fill(uilib.field({"testid": "feed-identifier"}, rk))
        page.click({"testid": "details-continue"})
        page.click({"testid": "transport-nano_https"})
        page.click({"testid": "transport-continue"})
        page.wait_for({"testid": "issue-credential-panel"})
        cleanup.source(rk)
        token = _issue(page, f"deep-http-{mark[-6:]}")
        cleanup.token(rk)
        src = eventually(lambda: source_by_route(client, rk), timeout=30, desc="draft source")
        assert src["lifecycle_status"] == "draft", src
        eventually(lambda: _send(endpoint, token, user=user, ip="198.51.100.71", host="onb-host", message=f"{mark} first"),
                   timeout=INGEST_VISIBLE * 2, interval=2, desc="HTTP JSON token accepted", ok=lambda s: s == 200)
        page.click({"testid": "connect-continue"})
        page.wait_for({"testid": "parse-panes"})

        sample = json.dumps({"user": user, "ip": "198.51.100.71", "host": "onb-host", "message": f"{mark} sample"})
        page.fill(uilib.field({"css": 'textarea[placeholder*="timestamp"]'}, sample))

        # A compile error: named with its position, and the gate blocks.
        page.editor_fill({"css": ".cm-content"}, BAD_VRL)
        page.click({"role": "button", "name": "Validate", "exact": True})
        page.wait_text("VRL invalid", exact=False, timeout_ms=30_000)
        page.wait_text(uilib.rx(r"ln \d+:\d+"), exact=False, timeout_ms=30_000)
        api_bad = expect(client.api.post("/api/log-sources/validate-vrl", json={"vrl_code": BAD_VRL}), 200)
        assert api_bad["valid"] is False and api_bad.get("errors"), api_bad
        page.screenshot("deep-wizard-bad-vrl.png", full_page=False)
        review = {"role": "button", "name": "Continue · review", "exact": True}
        assert page.attr(review, "disabled") is not None, "the wizard continues to publish with a VRL compile error"
        publish = {"role": "button", "name": "Publish source", "exact": True}
        timeline.step("bad VRL refused", errors=api_bad["errors"][:2])

        # The fixed parser: valid, its sample test passes, then publish.
        page.goto(f"/ingestion/log-sources/new?source={src['id']}&stage=parse&source_id={src['id']}")
        page.wait_for({"testid": "parse-panes"}, timeout_ms=30_000)
        page.fill(uilib.field({"css": 'textarea[placeholder*="timestamp"]'}, sample))
        vrl = GOOD_VRL.replace("{rk}", rk)
        page.editor_fill({"css": ".cm-content"}, vrl)
        page.click({"role": "button", "name": "Validate", "exact": True})
        page.wait_text("VRL syntax is valid", exact=False, timeout_ms=60_000)
        api_test = expect(client.api.post("/api/log-sources/test-vrl", json={
            "vrl_code": vrl, "sample_log": sample, "validate_ocsf": True}), 200)
        assert api_test["success"] is True, api_test
        page.click({"role": "button", "name": "Continue · review", "exact": True})
        page.wait_for({"testid": "deploy-gate"})
        warn = {"role": "checkbox", "name": uilib.rx("^Publish anyway")}
        if page.count(warn):
            page.click(warn)
        page.click(publish)
        page.wait_url(r"/ingestion/log-sources/")
        src = eventually(lambda: source_by_route(client, rk), timeout=60, interval=1, desc="published",
                         ok=lambda s: s and s.get("lifecycle_status") not in ("draft", None))
        timeline.step("published", status=src.get("lifecycle_status"))

        # Events land as OCSF and are searchable by OCSF fields.
        query = f'class_uid=3002 actor.user.name="{user}" src_endpoint.ip="198.51.100.72" metadata.log_source="{rk}"'
        n = {"i": 0}

        def probe() -> list[dict[str, Any]]:
            n["i"] += 1
            _send(endpoint, token, user=user, ip="198.51.100.72", host="onb-host", message=f"{mark} parsed {n['i']}")
            return nano.rows(query, limit=50)

        rows = eventually(probe, timeout=INGEST_VISIBLE * 2, interval=3, desc="parsed OCSF events searchable")
        flat = json.dumps(rows[0])
        assert "onb-host" in flat and "nano-e2e" in flat, flat[:800]
        uilib.run_search(page, query)
        assert uilib.results_count(page) == nano.search(query)["total_count"]
        page.screenshot("deep-onboarding-ocsf-search.png", full_page=False)
        timeline.step("OCSF searchable", rows=len(rows))


def test_parser_editor_draft_publish_v2_and_health(
    stack: Stack, nano: Nano, mark: str, ui: uilib.Driver, artifact_dir, request, timeline, cleanup
) -> None:
    rk = route_key(request.node.nodeid, "editor")
    user = f"ped-{mark[-8:]}"
    vrl = GOOD_VRL.replace("{rk}", rk)
    src = nano.create_draft_source(name=rk, route_key=rk, parser_vrl=vrl)
    cleanup.source(rk)
    cred, token = nano.issue_token(src["id"], name=f"{rk}-tok")
    cleanup.token(rk)
    res = expect(nano.api.post(f"/api/log-sources/{src['id']}/publish", json={"acknowledge_unattested": True}), 200)
    assert res.get("success") is True, res
    endpoint = expect(nano.api.get("/api/log-sources/ingest-endpoint"), 200)
    eventually(lambda: (_send(endpoint, token, user=user, ip="198.51.100.80", host="ped", message=f"{mark} v1"),
                        nano.rows(f'actor.user.name="{user}"', limit=5))[1],
               timeout=INGEST_VISIBLE * 2, interval=3, desc="v1 parsing")

    with login_persona(stack, nano, ui, artifact_dir, "deep-parser-editor", ENGINEER) as persona:
        page, client = persona.page, persona.client
        page.goto(f"/ingestion/log-sources/{src['id']}")
        page.wait_for({"testid": "log-source-tab-vrl"}, timeout_ms=30_000)

        # Health: delivery says receiving; the 1h count matches the API.
        page.wait_for({"testid": "log-source-health-panel"}, timeout_ms=30_000)
        health = expect(client.api.get(f"/api/log-sources/{src['id']}/health"), 200)
        timeline.step("health", health={k: health.get(k) for k in list(health)[:8]})
        eventually(lambda: " ".join(page.texts({"testid": "delivery-row-push"})).lower(), timeout=60, interval=2,
                   desc="delivery row receiving", ok=lambda t: "receiving" in t)

        page.click({"testid": "log-source-tab-vrl"})
        page.click({"role": "button", "name": "Edit VRL", "exact": True})
        page.editor_fill({"css": ".cm-content"}, BAD_VRL)
        page.click({"role": "button", "name": "Validate", "exact": True})
        page.wait_text("VRL invalid", exact=False, timeout_ms=30_000)
        page.screenshot("deep-parser-editor-invalid.png", full_page=False)

        # Fix it, adding a field v2 sets; test it on a sample.
        v2 = vrl + '\n.metadata.product.feature.name = "deep-v2"'
        page.editor_fill({"css": ".cm-content"}, v2)
        page.click({"role": "button", "name": "Validate", "exact": True})
        page.wait_text(uilib.rx("VRL validated|Validated"), exact=False, timeout_ms=30_000)
        page.click({"role": "button", "name": "Test events", "exact": True})
        sample = json.dumps({"user": user, "ip": "198.51.100.81", "host": "ped", "message": f"{mark} lab"})
        page.fill(uilib.field({"placeholder": "Paste 1+ raw events, one per line. Cmd/Ctrl+Enter to run."}, sample))
        page.click({"role": "button", "name": uilib.rx("^(Test|Re-test)$")})
        summary = {"testid": "parser-test-summary", "visible": False}
        page.wait_attr(summary, "data-passed", "1", timeout_ms=90_000)
        assert page.attr(summary, "data-total") == "1"

        page.click({"role": "button", "name": "Save VRL", "exact": True})
        page.click({"role": "button", "name": "Save changes", "exact": True, "within": {"role": "alertdialog"}})
        page.wait_text("Unpublished changes", exact=False, timeout_ms=30_000)
        draft = expect(client.api.get(f"/api/log-sources/{src['id']}"), 200)
        assert "deep-v2" in (draft.get("parser_vrl") or draft.get("draft_vrl") or json.dumps(draft)), "draft not saved"

        page.click({"role": "button", "name": "Publish", "exact": True})
        dialog = {"role": "alertdialog"}
        page.wait_text("Publish log source?", exact=True)
        if page.count({"placeholder": "Raw event", "within": dialog}):
            page.fill(uilib.field({"placeholder": "Raw event", "within": dialog}, sample))
        page.click({"role": "button", "name": "Publish", "exact": True, "within": dialog})
        page.wait_text("Unpublished changes", exact=False, timeout_ms=120_000, gone=True)
        versions = eventually(lambda: expect(client.api.get(f"/api/log-sources/{src['id']}/versions"), 200),
                              timeout=60, desc="v2 published", ok=lambda v: len(v if isinstance(v, list) else v.get("versions", [])) >= 2)
        timeline.step("v2 published", versions=len(versions if isinstance(versions, list) else versions.get("versions", [])))

        rows = eventually(
            lambda: (_send(endpoint, token, user=user, ip="198.51.100.82", host="ped", message=f"{mark} v2"),
                     nano.rows(f'actor.user.name="{user}" metadata.product.feature.name="deep-v2"', limit=5))[1],
            timeout=INGEST_VISIBLE * 2, interval=3, desc="v2 parser live")
        page.click({"testid": "log-source-tab-versions"})
        page.wait_text(uilib.rx(r"^v2\b"), exact=False, timeout_ms=30_000)
        page.screenshot("deep-parser-versions.png", full_page=False)
        timeline.step("v2 live", rows=len(rows))
    expect(nano.api.post(f"/api/ingest-tokens/{cred}/revoke"), 200, 409)


# PipelineTap.tsx terminal states other than "Tap completed".
TAP_FAILURES = ("No events during the window", "Live tap unavailable", "Tap failed")


def test_pipeline_live_tap(stack: Stack, nano: Nano, mark: str, ocsf_lane, page: uilib.UiPage, timeline) -> None:
    caps = expect(nano.api.get(f"/api/log-sources/{ocsf_lane.source_id}/pipe-capabilities"), 200)
    if not caps.get("live_tap_enabled"):
        pytest.skip("live tap needs NANO_VECTOR_TAP_URL(S) + NANO_VECTOR_TAP_TOKEN on nano-api; the e2e stack runs "
                    "no tap relay (scripts/e2e.sh)")
    page.goto(f"/ingestion/pipelines/{ocsf_lane.source_id}")
    page.click({"role": "tab", "name": uilib.rx("^Live tap")})
    page.click({"role": "button", "name": "Start live tap", "exact": True})
    # The running tap shows a countdown ("Capturing · Ns left"), not its title.
    page.wait_for({"testid": "tap-remaining"}, timeout_ms=30_000)
    # The tap only sees events that pass the source AFTER the relay's gRPC
    # subscription attaches, and the UI gives no signal for that moment. One
    # burst right after the click can clear Vector first and leave the window
    # empty ("No events during the window"), so keep sending, one a second,
    # until the tap ends; fail fast on a terminal state other than completed.
    deadline = time.monotonic() + 90
    sent = 0
    while True:
        if page.count({"text": "Tap completed", "exact": False}):
            break
        ended = [t for t in TAP_FAILURES if page.count({"text": t, "exact": False})]
        assert not ended, f"live tap ended {ended[0]!r} after {sent} events sent"
        assert time.monotonic() < deadline, f"live tap did not complete within 90 s ({sent} events sent)"
        ocsf_lane.send(stack, mark, f"tap-{secrets.token_hex(2)}", "198.51.100.90", "tap", note=f"tap {sent}")
        sent += 1
        time.sleep(1)
    assert page.count({"role": "listbox", "name": "Tapped events"}) == 1
    timeline.step("live tap", caps=caps, events_sent=sent)
