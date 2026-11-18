"""pivt proposes ingestion changes; the analyst applies them (NAN-5574).

Before NAN-5574 a chat message like "publish X" made pivt publish the log
source server-side, in-process and unaudited. Now pivt answers with a card
naming the target, nothing changes until Apply, Apply runs the REST publish
as the analyst, and an analyst without `log_sources:deploy` is never offered
the action.
"""

from __future__ import annotations

import pytest

from nano_e2e import schema
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import login_persona
from nano_e2e.runid import route_key
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

PIVT_CHAT = ("melod:chat", "melod:notebook", "notebooks:view", "notebooks:create", "notebooks:edit")
DEPLOYER_PERMISSIONS = (*PIVT_CHAT, "log_sources:view", "log_sources:deploy")
VIEWER_PERMISSIONS = (*PIVT_CHAT, "log_sources:view")

UDM_VRL = 'parsed = parse_json!(string!(.message))\n.message = string!(parsed.message)'
OCSF_VRL = """
parsed = parse_json!(string!(.message))
.class_uid = 3002
.category_uid = 3
.activity_id = 1
.type_uid = 300201
.severity_id = 1
.actor.user.name = string!(parsed.user)
.message = string!(parsed.message)
""".strip()

CARD = {"testid": "pivt-confirm-card"}
PROMPT = {"role": "textbox", "name": "Message pivt", "exact": True}


def _ocsf() -> bool:
    return schema.is_ocsf()


def _draft_status(nano: Nano, source_id: str) -> dict:
    return expect(nano.api.get(f"/api/log-sources/{source_id}/draft-status"), 200)


def _ask_pivt(page: uilib.UiPage, text: str) -> None:
    if page.count(PROMPT) == 0:
        page.click({"testid": "pivt-summon"})
    page.fill(uilib.field(PROMPT, text))
    page.press_key(PROMPT, "Enter")


@pytest.fixture
def seeded_source(nano: Nano, request, persona_cleanup):
    key = route_key(request.node.nodeid, "pivt-publish")
    persona_cleanup.source(key)
    created = expect(
        nano.api.post(
            "/api/log-sources",
            json={
                "name": key,
                "description": "NAN-5574 pivt publish proposal",
                "source_type": "routed",
                "parser_vrl": OCSF_VRL if _ocsf() else UDM_VRL,
                "match_field": "source_type",
                "match_values": [key],
            },
        ),
        200,
        201,
    )
    return created


def test_pivt_publish_is_a_proposal_the_analyst_applies(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline, persona_ai, seeded_source
) -> None:
    if persona_ai is None:
        pytest.skip("pivt is enterprise-only")
    source_id, name = seeded_source["id"], seeded_source["name"]
    assert _draft_status(nano, source_id).get("active_version_number") is None

    with login_persona(stack, nano, ui, artifact_dir, "pivt-deployer", DEPLOYER_PERMISSIONS) as persona:
        page = persona.page
        page.goto(f"/ingestion/log-sources/{source_id}")
        page.wait_text(name, exact=False)
        _ask_pivt(page, f"publish {name}")

        eventually(lambda: page.count(CARD), timeout=120, interval=0.5, desc="pivt publish proposal card", ok=bool)
        assert page.attr(CARD, "data-action") == "publish_log_source"
        card_text = "\n".join(page.texts(CARD))
        assert name in card_text and source_id in card_text, card_text
        # The proposal changed nothing.
        assert _draft_status(nano, source_id).get("active_version_number") is None
        page.screenshot("pivt-publish-proposal.png")
        timeline.step("pivt proposed publish", source=name, applied=False)

        page.click({"testid": "pivt-confirm-apply"})
        if _ocsf():
            # A first OCSF go-live needs a sample or an explicit acknowledgement
            # on the log source page; pivt must not acknowledge it for the
            # analyst, so the REST gate refuses and the card says so.
            eventually(
                lambda: page.count({"role": "alert", "within": CARD}),
                timeout=60,
                interval=0.5,
                desc="publish refusal shown on the card",
                ok=bool,
            )
            assert _draft_status(nano, source_id).get("active_version_number") is None
            page.screenshot("pivt-publish-ocsf-gate.png")
            timeline.step("pivt publish refused by the OCSF gate", source=name)
        else:
            eventually(
                lambda: page.count({"testid": "pivt-confirm-done"}),
                timeout=120,
                interval=0.5,
                desc="publish applied",
                ok=bool,
            )
            status = eventually(
                lambda: _draft_status(nano, source_id),
                timeout=30,
                interval=0.5,
                desc="published version",
                ok=lambda s: s.get("active_version_number") == 1,
            )
            assert status["has_draft_changes"] is False, status
            assert page.count({"testid": "pivt-confirm-verify"}) == 1
            page.screenshot("pivt-publish-applied.png")
            timeline.step("pivt publish applied through REST", source=name, version=1)


def test_pivt_offers_no_publish_without_deploy_permission(
    stack: Stack, nano: Nano, ui: uilib.Driver, artifact_dir, timeline, persona_ai, seeded_source
) -> None:
    if persona_ai is None:
        pytest.skip("pivt is enterprise-only")
    source_id, name = seeded_source["id"], seeded_source["name"]

    with login_persona(stack, nano, ui, artifact_dir, "pivt-viewer", VIEWER_PERMISSIONS) as persona:
        page = persona.page
        page.goto(f"/ingestion/log-sources/{source_id}")
        page.wait_text(name, exact=False)
        _ask_pivt(page, f"publish {name}")
        page.wait_text("permission to deploy log sources", exact=False, timeout_ms=120_000)
        assert page.count(CARD) == 0
        page.screenshot("pivt-publish-no-permission.png")
        # And the REST path pivt would use refuses this analyst too.
        refused = persona.client.api.post(f"/api/log-sources/{source_id}/publish", json={})
        assert refused.status_code == 403, refused.text[:500]
        assert _draft_status(nano, source_id).get("active_version_number") is None
        timeline.step("pivt publish not offered without log_sources:deploy", api=403)
