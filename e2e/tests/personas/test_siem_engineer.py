"""SIEM engineer: settings, access control, source/token, custom + AI parser."""

from __future__ import annotations

import json
import os

from nano_e2e import ingest
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import (
    SIEM_ENGINEER_PERMISSIONS,
    issue_ingest_token,
    login_persona,
    source_by_route,
    start_push_source,
)
from nano_e2e.runid import route_key
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

CUSTOM_VRL = """
parsed = parse_json!(string!(.message))
.class_uid = 3002
.category_uid = 3
.activity_id = 1
.type_uid = 300201
.severity_id = 1
.actor.user.name = string!(parsed.user)
.src_endpoint.ip = string!(parsed.src_ip)
.device.hostname = string!(parsed.host)
.message = string!(parsed.message)
""".strip()


def _send_json(stack: Stack, token: str, marker: str, user: str) -> int:
    raw = json.dumps(
        {"message": marker, "user": user, "src_ip": "198.51.100.42", "host": "persona-siem-host"}
    )
    return ingest.hec(stack.hec_url, token, {"message": raw}).status_code


def test_siem_engineer_journey(
    stack: Stack, nano: Nano, mark: str, ui: uilib.Driver, artifact_dir, request, timeline,
    persona_cleanup, persona_ai,
) -> None:
    ai_mode = persona_ai
    original = expect(nano.api.get("/api/settings/prevalence"), 200)
    persona_cleanup.actions.register_http(
        "prevalence settings", lambda: nano.api.put("/api/settings/prevalence", json=original)
    )

    with login_persona(
        stack, nano, ui, artifact_dir, "siem-engineer", SIEM_ENGINEER_PERMISSIONS
    ) as persona:
        page = persona.page
        assert set(persona.permissions) == set(SIEM_ENGINEER_PERMISSIONS)
        assert "users:create" not in persona.permissions

        # Retention is checked against persisted settings, then the adjacent
        # enrichment/tracking scope is changed in the UI and restored.
        page.goto("/settings/prevalence")
        page.wait_text("Data retention period", exact=True)
        eventually(
            lambda: page.requests_containing("/api/settings/prevalence"),
            timeout=10,
            interval=0.1,
            desc="prevalence settings request to finish",
        )
        eventually(
            lambda: (
                page.value({"css": 'input[id$="-retention"]'}),
                page.count({"text": "Unsaved changes", "exact": True}),
                page.attr({"role": "button", "name": "Save changes", "exact": True}, "disabled"),
            ),
            timeout=10,
            interval=0.1,
            desc="prevalence form to reflect persisted settings",
            ok=lambda state: state == (str(original["retention_days"]), 0, ""),
        )
        page.click({"role": "switch", "name": "IP address tracking"})
        assert page.value({"css": 'input[id$="-retention"]'}) == str(original["retention_days"])
        page.click({"role": "button", "name": "Save changes", "exact": True})
        changed = eventually(
            lambda: expect(persona.client.api.get("/api/settings/prevalence"), 200),
            timeout=10,
            interval=0.1,
            desc="IP tracking setting saved through the browser",
            ok=lambda settings: settings["enable_ip_tracking"] is (not original["enable_ip_tracking"]),
        )
        assert changed["retention_days"] == original["retention_days"], changed
        assert changed["enable_ip_tracking"] is (not original["enable_ip_tracking"]), changed
        timeline.step("settings", retention=original["retention_days"], ip_tracking=changed["enable_ip_tracking"])
        expect(persona.client.api.put("/api/settings/prevalence", json=original), 200)

        # Create a role through Access Control and verify the server object.
        role_name = f"persona-role-{mark[-8:]}"
        page.goto("/settings/access-control?tab=roles")
        page.click({"css": 'button[title="New role"]'})
        page.fill(
            uilib.field({"css": 'input[placeholder="e.g. Threat Hunter"]'}, role_name),
            uilib.field({"css": 'input[placeholder="One-line summary"]'}, "Persona SIEM role"),
        )
        page.click({"role": "checkbox", "name": uilib.rx(r"^search:view\b")})
        page.click({"role": "button", "name": "Create role", "exact": True})
        page.wait_text("Role created", exact=False)
        persona_cleanup.role(role_name)
        roles = expect(persona.client.api.get("/api/roles"), 200)
        role_items = roles if isinstance(roles, list) else roles.get("roles", [])
        created_role = next(role for role in role_items if role.get("name") == role_name)
        created_role_id = created_role["id"]
        page.goto("/settings/access-control?tab=users")
        page.wait_for({"css": 'input[placeholder="Search users, email, group…"]'})
        assert page.count({"role": "button", "name": "Invite user", "exact": True}) == 0
        forbidden = persona.client.api.post(
            "/api/users",
            json={
                "email": f"forbidden-{mark[-8:]}@e2e.invalid",
                "name": "Forbidden invite",
                "password": "E2e-forbidden-user-123!",
                "group_ids": [],
            },
        )
        assert forbidden.status_code == 403, forbidden.text[:1000]
        timeline.step("forbidden user invite", ui="hidden", api=forbidden.status_code)
        timeline.step("users and roles", role=created_role_id)

        # Add source issues the ingest token in the browser, receives a sample,
        # validates hand-written VRL, then (enterprise) replaces it with a real
        # provider-boundary AI draft before publishing.
        rk = route_key(request.node.nodeid, "persona")
        start_push_source(page, f"Persona SIEM {mark[-8:]}", rk)
        persona_cleanup.source(rk)
        source = eventually(lambda: source_by_route(nano, rk), timeout=30, desc="persona draft source")
        assert source is not None
        source_id = source["id"]
        token = issue_ingest_token(page, f"persona-{mark[-8:]}")
        persona_cleanup.token(rk)
        tokens = expect(nano.api.get("/api/ingest-tokens"), 200)
        token_items = tokens if isinstance(tokens, list) else tokens.get("tokens", tokens.get("credentials", []))
        token_row = next(item for item in token_items if item.get("route_key") == rk and item.get("state") != "revoked")
        eventually(
            lambda: _send_json(stack, token, f"{mark}-sample", "custom-sample"),
            timeout=60,
            interval=1,
            desc="new ingest token accepted",
            ok=lambda status: status == 200,
        )
        page.click({"role": "button", "name": "Copy token"})
        page.click({"testid": "connect-continue"})
        page.wait_for({"testid": "parse-panes"})

        sample = json.dumps(
            {"message": f"{mark}-sample", "user": "custom-sample", "src_ip": "198.51.100.42", "host": "persona-siem-host"}
        )
        page.fill(uilib.field({"css": 'textarea[placeholder*="timestamp"]'}, sample))
        page.editor_fill({"css": ".cm-content"}, CUSTOM_VRL)
        page.click({"role": "button", "name": "Validate", "exact": True})
        page.wait_text("VRL syntax is valid", exact=False, timeout_ms=60_000)
        timeline.step("custom parser validated", lines=len(CUSTOM_VRL.splitlines()))

        if ai_mode:
            page.click({"role": "button", "name": "Regenerate", "exact": True})
            page.wait_text("Generating…", exact=True, timeout_ms=30_000)
            page.wait_text("Generating…", exact=True, timeout_ms=300_000, gone=True)
            page.wait_text("0 err", exact=False, timeout_ms=60_000)
            page.wait_text("1/1", exact=True, timeout_ms=60_000)
            page.wait_text("pass", exact=False, timeout_ms=60_000)
            timeline.step("AI parser generated", provider=ai_mode)
        else:
            assert page.count({"role": "button", "name": uilib.rx("Generate with pivt|Regenerate")}) == 0
            timeline.step("AI parser capability boundary", edition=os.environ["E2E_EDITION"], melod=False)

        page.click({"role": "button", "name": "Continue · review", "exact": True})
        page.wait_for({"testid": "deploy-gate"})
        warning = {"role": "checkbox", "name": uilib.rx("^Publish anyway")}
        if page.count(warning):
            page.click(warning)
        page.click({"role": "button", "name": "Publish source", "exact": True})
        page.wait_url(r"/ingestion/log-sources/")
        timeline.step("source published", source=source_id, token=token_row["token_prefix"])

        parsed_marker = f"{mark}-parsed"
        parsed_user = f"engineer-{mark[-6:]}"
        query = f'"{parsed_marker}" actor.user.name="{parsed_user}" metadata.log_source="{rk}"'

        def parsed_probe() -> list[dict]:
            # Publishing rewrites Vector's topology asynchronously. An event
            # accepted during that reload can be handled by the generic parser,
            # so submit a fresh probe on every poll until the deployed parser is
            # demonstrably active.
            if _send_json(stack, token, parsed_marker, parsed_user) != 200:
                return []
            return nano.rows(query, limit=20)

        rows = eventually(
            parsed_probe,
            timeout=INGEST_VISIBLE,
            interval=3,
            desc="AI/custom parsed OCSF fields searchable",
        )
        assert all(parsed_marker in json.dumps(row) for row in rows), rows
        uilib.run_search(page, query)
        assert uilib.results_count(page) == len(rows)

        page.goto("/platform/health")
        page.wait_for({"testid": "log-source-health-section"}, timeout_ms=60_000)
        eventually(
            lambda: " ".join(page.texts({"testid": "log-source-health-section"})),
            timeout=60,
            interval=2,
            desc="persona source in SIEM Health",
            ok=lambda text: rk in text or source["name"] in text,
        )
        timeline.step("search and SIEM Health verified", parsed=len(rows))
        persona.checkpoint("settings-source-parser-health")
