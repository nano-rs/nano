"""Incident responder: case evidence, handoff, two-person SOAR, and closure."""

from __future__ import annotations

import json
import os
import uuid
from contextlib import ExitStack
from typing import Any

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect, row_text
from nano_e2e.personas import (
    INCIDENT_APPROVER_PERMISSIONS,
    INCIDENT_RESPONDER_PERMISSIONS,
    login_persona,
)
from nano_e2e.stack import Stack
from nano_e2e.waits import DETECTION, INGEST_VISIBLE, eventually

TERMINAL = {"succeeded", "failed", "canceled", "ambiguous"}
TYPEID_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"


def _create_rule(nano: Nano, name: str, query: str) -> dict[str, Any]:
    return expect(
        nano.api.post(
            "/api/rules",
            json={
                "name": name,
                "description": "Persona incident fixture (NAN-4995)",
                "query": query,
                "severity": "high",
                "schedule_cron": "* * * * *",
                "mode": "alerting",
                "detection_mode": "scheduled",
                "lookback_minutes": 15,
            },
        ),
        200,
        201,
    )


def _case(client: Nano, case_id: str) -> dict[str, Any]:
    return expect(client.api.get(f"/api/cases/{case_id}"), 200)


def _notebook_entries(client: Nano, case_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    notebook = expect(client.api.get(f"/api/cases/{case_id}/notebook"), 200)
    if not notebook:
        return {}, []
    entries = expect(client.api.get(f"/api/notebooks/{notebook['id']}/entries"), 200)
    return notebook, entries


def _start_flow(page: uilib.UiPage, flow_id: str) -> str:
    page.goto(f"/automation/flows/{flow_id}")
    editor = {"testid": "flow-editor"}
    page.wait_for(editor, timeout_ms=30_000)
    page.click({"role": "button", "name": "Run", "exact": True, "within": editor})
    dialog = {"role": "dialog", "name": uilib.rx(r"^Run ")}
    page.wait_for(dialog)
    page.click({"role": "button", "name": "Run flow", "exact": True, "within": dialog})
    return page.wait_url(r"/automation/runs/[^/?#]+$").rstrip("/").rsplit("/", 1)[-1]


def _approval_card(page: uilib.UiPage, requester: str) -> dict[str, Any]:
    """The pending card for THIS run: a user-requested card names its requester
    ("you" to the requester). Never fall back to whichever card is first: on a
    kept stack another scenario's approval may still be pending (NAN-5333)."""
    page.goto("/automation/approvals")
    drawer = {"testid": "approvals-drawer"}
    named = {"testid": "approval-card", "has": requester, "within": drawer}
    eventually(
        lambda: page.count(named),
        timeout=60,
        interval=2,
        desc=f"pending responder playbook approval requested by {requester}",
        ok=lambda count: count == 1,
    )
    return named


def _typeid_uuid(value: str) -> str:
    """Decode the public TypeID to the UUID stored in structured audit rows."""
    suffix = value.rsplit("_", 1)[-1]
    if len(suffix) != 26:
        raise ValueError(f"invalid TypeID suffix: {value}")
    number = 0
    for character in suffix:
        number = (number << 5) | TYPEID_ALPHABET.index(character)
    return str(uuid.UUID(int=number))


def _audit_rows(nano: Nano, case_id: str) -> list[dict[str, Any]]:
    body = expect(nano.api.get("/api/audit", params={"limit": 200}), 200)
    case_uuid = _typeid_uuid(case_id)
    return [row for row in body["logs"] if row.get("resource_id") == case_uuid]


def test_incident_responder_journey(
    stack: Stack,
    nano: Nano,
    ocsf_lane,
    mark: str,
    ui: uilib.Driver,
    artifact_dir,
    timeline,
    persona_cleanup,
    persona_ai,
    persona_soar,
) -> None:
    edition = os.environ["E2E_EDITION"]
    if edition == "open":
        capabilities = expect(nano.api.get("/api/capabilities"), 200)["capabilities"]
        assert capabilities["cases"] is False
        assert capabilities["notebooks"] is False
        assert capabilities["playbooks"] is False
        assert "soar" not in capabilities
        assert nano.api.get("/api/cases").status_code == 404
        assert nano.api.get("/api/soar/settings").status_code == 404
        page = uilib.UiPage.open(ui, artifact_dir / "ui-incident-open", "incident responder open boundary")
        failed = True
        try:
            uilib.login(page, stack.admin_email, stack.admin_password)
            page.goto("/cases")
            page.wait_text("Available in nano paid plans", exact=False)
            page.goto("/automation")
            page.wait_text("Access Denied", exact=True)
            failed = False
        finally:
            page.finish(failed)
        timeline.step("incident capability boundary", edition=edition, ui="absent", api=404)
        return

    assert persona_ai in {"stub", "real"}
    assert persona_soar is True

    # Snapshot before mutation, register the finalizer immediately, and restore
    # the whole case configuration even when any later browser assertion fails.
    original_settings = expect(nano.api.get("/api/settings/cases"), 200)
    persona_cleanup.actions.register_http(
        "case settings",
        lambda: nano.api.put("/api/settings/cases", json=original_settings),
    )
    enabled = expect(
        nano.api.put(
            "/api/settings/cases",
            json={
                **original_settings,
                "auto_grouping_enabled": True,
                "auto_investigate_enabled": True,
            },
        ),
        200,
    )
    assert enabled["auto_grouping_enabled"] is True
    assert enabled["auto_investigate_enabled"] is True

    actor = f"responder-{mark[-6:]}"
    host = f"responder-host-{mark[-6:]}"
    ocsf_lane.send(stack, mark, actor, "203.0.113.77", host, note="persona incident evidence")
    eventually(
        lambda: nano.rows(f'"{mark}"', limit=10),
        timeout=INGEST_VISIBLE,
        desc="incident event searchable",
    )
    rule_name = f"persona_incident_{mark[-10:].replace('-', '_')}"
    rule = _create_rule(nano, rule_name, f'source_type="{ocsf_lane.lane}" "{mark}"')
    persona_cleanup.rule(rule_name)
    expect(nano.api.post(f"/api/rules/{rule['id']}/trigger"), 200)
    alerts = eventually(
        lambda: expect(nano.api.get("/api/alerts", params={"rule_id": rule["id"], "limit": 20}), 200),
        timeout=DETECTION,
        interval=3,
        desc="incident alert and case",
        ok=lambda values: any(
            item.get("case_id") and mark in row_text(item.get("matched_events")) for item in values
        ),
    )
    alert = next(
        item for item in alerts if item.get("case_id") and mark in row_text(item.get("matched_events"))
    )
    case_id = alert["case_id"]
    persona_cleanup.case(case_id)

    # The provider-bound shadow agents must leave their durable source marker,
    # narrative evidence, and extracted identity/host entities before a human
    # starts work.
    notebook, shadow_entries = eventually(
        lambda: _notebook_entries(nano, case_id),
        timeout=DETECTION,
        interval=3,
        desc="shadow investigation notebook",
        ok=lambda pair: any(
            entry.get("source") == "shadow_investigation"
            and mark in json.dumps(entry.get("content"), sort_keys=True)
            for entry in pair[1]
        ),
    )
    full_case = _case(nano, case_id)
    entity_text = json.dumps(full_case["entities"], sort_keys=True)
    assert actor in entity_text and host in entity_text, full_case["entities"]
    timeline.step(
        "shadow investigation",
        case=case_id,
        notebook=notebook["id"],
        entries=len(shadow_entries),
        entities=len(full_case["entities"]),
    )

    flow_name = f"Persona case response playbook {mark[-8:]}"
    flow = expect(
        nano.api.post(
            "/api/soar/flows",
            json={
                "name": flow_name,
                "status": "live",
                "trigger": {"on": "manual"},
                "definition": {
                    "summary": f"Two-person response for case {case_id}",
                    "value": {
                        "modules": [
                            {
                                "id": "approval",
                                "value": {
                                    "type": "approval",
                                    "prompt": f"Approve response for {case_id}?",
                                    "options": ["yes", "no"],
                                },
                            },
                            {"id": "record_response", "value": {"type": "identity"}},
                        ]
                    },
                },
            },
        ),
        200,
        201,
    )
    persona_cleanup.soar_flow(flow["id"])

    with ExitStack() as persona_sessions:
        responder = persona_sessions.enter_context(
            login_persona(stack, nano, ui, artifact_dir, "incident-responder", INCIDENT_RESPONDER_PERMISSIONS)
        )
        assert set(responder.permissions) == set(INCIDENT_RESPONDER_PERMISSIONS)
        assert "cases:delete" not in responder.permissions
        assert "soar:approve" not in responder.permissions
        responder_me = expect(responder.client.api.get("/api/auth/me"), 200)
        page = responder.page

        # Pick the generated alert in the list, then work its case workspace.
        page.goto("/alerts")
        page.wait_text(rule_name, exact=True, timeout_ms=60_000)
        page.click({"role": "row", "has": rule_name})
        page.wait_url(r"/alerts/[^/?#]+$")
        page.goto(f"/cases/{case_id}")
        page.wait_text(rule_name, exact=False, timeout_ms=60_000)
        page.wait_text(actor, exact=False, timeout_ms=60_000)
        page.wait_text("Shadow investigation completed", exact=False, timeout_ms=60_000)

        # Assign through the UI, add explicit notebook evidence, and compare the
        # visible workspace with its durable API representation.
        page.click({"role": "button", "name": uilib.rx("Unassigned")})
        page.click({"role": "button", "name": "Assign to me", "exact": True})
        eventually(
            lambda: _case(responder.client, case_id)["case"],
            timeout=30,
            desc="case assigned to responder",
            ok=lambda case: case.get("assigned_to") == responder_me["id"],
        )
        composer = {"role": "textbox", "name": uilib.rx("Ask the agent")}
        page.fill(uilib.field(composer, f"@evidence {mark} confirmed by responder"))
        page.press_key(composer, "Enter")
        _, entries = eventually(
            lambda: _notebook_entries(responder.client, case_id),
            timeout=30,
            interval=1,
            desc="responder evidence entry",
            ok=lambda pair: any(
                mark in json.dumps(entry.get("content"), sort_keys=True)
                and entry.get("source") != "shadow_investigation"
                for entry in pair[1]
            ),
        )
        page.wait_text(f"Evidence: {mark} confirmed by responder", exact=False)

        # Adjacent least-privilege boundary: responders close cases but cannot
        # delete them. The destructive UI is absent and the same JWT gets 403.
        assert page.count({"role": "button", "name": uilib.rx("Delete case")}) == 0
        forbidden = responder.client.api.delete(f"/api/cases/{case_id}")
        assert forbidden.status_code == 403, forbidden.text[:1000]
        timeline.step("forbidden case delete", ui="hidden", api=forbidden.status_code)

        approver = persona_sessions.enter_context(
            login_persona(stack, nano, ui, artifact_dir, "incident-approver", INCIDENT_APPROVER_PERMISSIONS)
        )
        # ExitStack is LIFO: removing the case first also removes its handoff,
        # so both strictly-cleaned persona accounts can then be deleted even if
        # a later browser assertion fails.
        persona_sessions.callback(lambda: expect(nano.api.delete(f"/api/cases/{case_id}"), 200, 204, 404))
        assert set(approver.permissions) == set(INCIDENT_APPROVER_PERMISSIONS)
        approver_me = expect(approver.client.api.get("/api/auth/me"), 200)

        # Actual peer handoff records sender/target provenance; the second
        # real browser verifies it, then that addressed user accepts it.
        handoff = expect(
            responder.client.api.post(
                f"/api/cases/{case_id}/handoff",
                json={
                    "target_user_id": approver_me["id"],
                    "target_group_id": None,
                    "target_label": approver_me["name"],
                    "reason": f"Validate evidence and approve response for {mark}",
                    "context_payload": {"notebook_id": notebook["id"], "alert_id": alert["id"]},
                },
            ),
            200,
            201,
        )
        approver.page.goto(f"/cases/{case_id}")
        approver.page.wait_text("handed off", exact=False, timeout_ms=60_000)
        expect(
            approver.client.api.post(f"/api/cases/{case_id}/handoff/{handoff['id']}/accept"),
            200,
        )
        approver.page.reload()
        approver.page.wait_text("accepted the handoff", exact=False, timeout_ms=60_000)
        timeline.step("peer handoff", sent=handoff["id"], accepted_by=approver_me["id"])

        # The responder starts the response playbook in the browser. Their
        # role cannot self-approve; the distinct approver browser decides.
        run_id = _start_flow(page, flow["id"])
        approvals = eventually(
            lambda: expect(
                nano.api.get("/api/soar/approvals", params={"status": "pending", "run_id": run_id}),
                200,
            )["approvals"],
            timeout=120,
            interval=2,
            desc="SOAR playbook suspended for approval",
            ok=lambda values: len(values) == 1,
        )
        assert len(approvals) == 1
        run = expect(nano.api.get(f"/api/soar/runs/{run_id}"), 200)
        assert run["status"] == "suspended", run
        assert run["requested_by_name"] == responder_me["name"], run
        requester_card = _approval_card(page, "you")
        assert page.count({"role": "button", "name": "Approve", "exact": True, "within": requester_card}) == 0

        card = _approval_card(approver.page, responder_me["name"])
        approver.page.click({"role": "radio", "name": "yes", "exact": True, "within": card})
        approver.page.click({"role": "button", "name": "Approve", "exact": True, "within": card})
        finished = eventually(
            lambda: expect(nano.api.get(f"/api/soar/runs/{run_id}"), 200),
            timeout=120,
            interval=2,
            desc="approved SOAR playbook terminal",
            ok=lambda value: value["status"] in TERMINAL,
        )
        decided = expect(
            nano.api.get("/api/soar/approvals", params={"status": "all", "run_id": run_id}), 200
        )["approvals"][0]
        assert finished["status"] == "succeeded", finished
        assert decided["status"] == "approved", decided
        assert decided["decided_by_name"] == approver_me["name"]
        assert decided["decided_by"] != run["requested_by"]
        timeline.step(
            "two-person SOAR", run=run_id, requester=run["requested_by"], approver=decided["decided_by"]
        )

        # Resolve, reopen, then use the guided close UI so both terminal
        # transitions and their immutable audit acknowledgement are proven.
        page.goto(f"/cases/{case_id}")
        current = _case(responder.client, case_id)["case"]["status"]
        page.click(
            {"role": "button", "name": "In progress" if current == "in_progress" else "Open", "exact": True}
        )
        page.click({"role": "button", "name": "Resolved", "exact": True})
        eventually(
            lambda: _case(responder.client, case_id)["case"]["status"],
            timeout=30,
            desc="case resolved",
            ok=lambda status: status == "resolved",
        )
        page.click({"role": "button", "name": "Reopen", "exact": True})
        eventually(
            lambda: _case(responder.client, case_id)["case"]["status"],
            timeout=30,
            desc="case reopened",
            ok=lambda status: status == "in_progress",
        )
        page.click({"role": "button", "name": "Close case", "exact": True})
        page.click({"role": "button", "name": uilib.rx("True positive")})
        page.click({"role": "checkbox", "name": "Confirm case resolution", "exact": True})
        close_confirm = {"role": "button", "name": "Close as True positive", "exact": True}
        eventually(
            lambda: page.attr(close_confirm, "disabled"),
            timeout=10,
            interval=0.2,
            desc="close confirmation enabled",
            ok=lambda disabled: disabled is None,
        )
        page.press_key(close_confirm, "Enter")
        final_case = eventually(
            lambda: _case(responder.client, case_id),
            timeout=30,
            desc="case closed",
            ok=lambda body: body["case"]["status"] == "closed",
        )
        events = final_case.get("workflow_events") or []
        event_kinds = [event["event_kind"] for event in events]
        assert "handoff_sent" in event_kinds and "handoff_accepted" in event_kinds, event_kinds
        assert "closed" in event_kinds, event_kinds
        assert any(
            event["event_kind"] == "status_changed"
            and event.get("from_status") == "resolved"
            and event.get("to_status") == "in_progress"
            for event in events
        ), events
        assert any(
            event["event_kind"] == "status_changed" and event.get("to_status") == "resolved"
            for event in events
        ), events

        expected_audit = {
            "case_assigned",
            "case_handoff_sent",
            "case_handoff_accepted",
            "case_status_changed",
        }
        audit = eventually(
            lambda: _audit_rows(nano, case_id),
            timeout=60,
            interval=3,
            desc="case audit trail",
            ok=lambda rows: expected_audit.issubset({row.get("action") for row in rows}),
        )
        soar_audit = eventually(
            lambda: expect(nano.api.get("/api/audit", params={"limit": 200}), 200)["logs"],
            timeout=60,
            interval=3,
            desc="SOAR audit trail",
            ok=lambda rows: {
                "soar_flow_run_requested",
                "soar_approval_decided",
                "soar_flow_run_finished",
            }.issubset({row.get("action") for row in rows}),
        )
        assert any(mark in json.dumps(entry.get("content"), sort_keys=True) for entry in entries)
        timeline.step(
            "case closed with audit",
            workflow=event_kinds,
            case_audit=sorted({str(row.get("action") or "") for row in audit}),
            soar_audit=sorted(
                {row.get("action") for row in soar_audit if row.get("action", "").startswith("soar_")}
            ),
        )
        responder.checkpoint("case-handoff-soar-close")
