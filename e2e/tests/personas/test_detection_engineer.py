"""Detection engineer: authored + AI rules, lifecycle, signal, alert, and case."""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor

from nano_e2e import ingest
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect, row_text, time_range
from nano_e2e.personas import DETECTION_ENGINEER_PERMISSIONS, login_persona
from nano_e2e.stack import Stack
from nano_e2e.waits import DETECTION, INGEST_VISIBLE, eventually


def _rule_by_name(client: Nano, name: str) -> dict | None:
    body = expect(client.api.get("/api/rules"), 200)
    items = body if isinstance(body, list) else body.get("rules", body.get("items", []))
    return next((item for item in items if item.get("name") == name), None)


def _signal_rows(client: Nano, rule_name: str) -> list[dict]:
    response = expect(
        client.search_http.post(
            "/api/search/sql",
            json={
                "sql": (
                    "SELECT toString(id) AS id, toString(rule_id) AS rule_id, rule_name, severity, "
                    "source_type FROM signals ORDER BY timestamp DESC"
                ),
                "time_range": time_range(minutes_back=30),
                "limit": 20,
                "offset": 0,
            },
        ),
        200,
    )
    return [row for row in response.get("results") or [] if row.get("rule_name") == rule_name]


def _rule_transition_audit(nano: Nano, rule_name: str) -> list[dict]:
    body = expect(nano.api.get("/api/audit", params={"limit": 200}), 200)
    return [
        row
        for row in body["logs"]
        if row.get("resource_name") == rule_name
        and row.get("action")
        in {"rule_promoted", "rule_demoted", "rule_paused", "rule_resumed"}
    ]


def _choose_rule_action(page: uilib.UiPage, label: str) -> None:
    trigger = {"role": "button", "name": "Rule actions", "exact": True}
    item = {"role": "menuitem", "name": label, "exact": True}

    def choose() -> bool:
        try:
            if page.count(item) == 0:
                page.click(trigger)
            page.press_key(item, "Enter")
            return True
        except uilib.UiError as exc:
            if "detached from document" not in str(exc):
                raise
            return False

    eventually(choose, timeout=10, interval=0.1, desc=f"rule action {label}")


def _open_rule_actions(page: uilib.UiPage) -> None:
    trigger = {"role": "button", "name": "Rule actions", "exact": True}

    def open_menu() -> bool:
        try:
            page.click(trigger)
            return True
        except uilib.UiError as exc:
            if "detached from document" not in str(exc):
                raise
            return False

    eventually(open_menu, timeout=10, interval=0.1, desc="rule actions menu")


def test_detection_engineer_journey(
    stack: Stack,
    nano: Nano,
    token_source,
    mark: str,
    ui: uilib.Driver,
    artifact_dir,
    timeline,
    persona_cleanup,
    persona_ai,
) -> None:
    src = token_source()
    edition = os.environ["E2E_EDITION"]
    ai_mode = persona_ai
    manual_name = f"persona_detection_{mark[-10:].replace('-', '_')}"
    rule_yaml = "\n".join(
        [
            "---",
            f"title: {manual_name}",
            f'description: "Persona detection lifecycle for {mark}"',
            "author: nano-e2e",
            "severity: high",
            "mode: staging",
            "detection_mode: realtime",
            'mitre_tactics: "TA0001"',
            'mitre_techniques: "T1078"',
            "tags: persona, e2e",
            "---",
            "",
            f'source_type="{src.route_key}"',
        ]
    )

    with login_persona(
        stack, nano, ui, artifact_dir, "detection-engineer", DETECTION_ENGINEER_PERMISSIONS
    ) as persona:
        page = persona.page
        assert set(persona.permissions) == set(DETECTION_ENGINEER_PERMISSIONS)
        assert "detections:delete" not in persona.permissions

        # Author an nPL rule in the real editor. Register name-based cleanup as
        # soon as the successful browser create can have produced the object.
        page.goto("/rules/editor/new")
        editor = {"role": "textbox", "name": "Detection rule editor", "exact": True}
        page.wait_for(editor)
        page.editor_fill(editor, rule_yaml)
        page.click({"role": "button", "name": "Create rule", "exact": True})
        persona_cleanup.rule(manual_name)
        page.wait_url(r"/rules/editor/")
        rule = eventually(
            lambda: _rule_by_name(persona.client, manual_name),
            timeout=30,
            interval=0.2,
            desc="browser-authored staging detection",
        )
        assert rule is not None
        assert rule["mode"] == "staging", rule
        assert rule["detection_mode"] == "real-time", rule
        rule_id = str(rule["id"])
        timeline.step("nPL rule authored", rule=rule["id"], mode=rule["mode"])

        # The persona may promote but may not erase the audit trail. Prove the
        # adjacent forbidden action in the UI and with the persona JWT.
        _open_rule_actions(page)
        assert page.count({"role": "menuitem", "name": "Delete forever", "exact": True}) == 0
        page.press_key({"role": "button", "name": "Rule actions", "exact": True}, "Escape")
        forbidden = persona.client.api.delete(f"/api/rules/{rule['id']}")
        assert forbidden.status_code == 403, forbidden.text[:1000]
        timeline.step("forbidden rule delete", ui="hidden", api=forbidden.status_code)

        # Two overlapping retries carry the same source state. Exactly one may
        # apply staging -> live; the stale retry must receive 409 and must not
        # observe the first commit then advance live -> alerting.
        barrier = threading.Barrier(3)

        def concurrent_promote():
            barrier.wait(timeout=5)
            return persona.client.api.post(
                f"/api/rules/{rule_id}/promote",
                json={"expected_mode": "staging"},
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            requests = [pool.submit(concurrent_promote) for _ in range(2)]
            barrier.wait(timeout=5)
            responses = [request.result(timeout=30) for request in requests]
        assert sorted(response.status_code for response in responses) == [200, 409], [
            (response.status_code, response.text[:500]) for response in responses
        ]
        rule = eventually(
            lambda: _rule_by_name(persona.client, manual_name),
            timeout=30,
            desc="rule promoted to live",
            ok=lambda item: item is not None and item.get("mode") == "live",
        )
        assert rule is not None
        assert rule["mode"] == "live", "a stale retry skipped the live bake-in state"
        timeline.step("guarded double promotion", statuses=[response.status_code for response in responses])
        # The concurrency proof mutates through the persona API rather than the
        # editor. Reload so the next browser action reflects the returned live
        # mode instead of the pre-request staging query cache.
        page.goto(f"/rules/editor/{rule_id}")
        page.wait_text(manual_name, exact=False)

        # A matching event in live emits a durable signal but no alert.
        live_message = f"{mark} persona-live-signal"
        assert ingest.hec(stack.hec_url, src.token, {"message": live_message}).status_code == 200
        eventually(
            lambda: nano.rows(f'"{live_message}"', limit=10),
            timeout=INGEST_VISIBLE,
            desc="live-mode event searchable",
        )
        live_signals = eventually(
            lambda: _signal_rows(persona.client, manual_name),
            timeout=DETECTION,
            interval=3,
            desc="live rule signal",
        )
        # A raw ClickHouse signal becomes visible before the signal processor's
        # intentional settling lag expires. Wait for its durable live-mode
        # counter so promotion cannot race the asynchronous no-alert branch.
        eventually(
            lambda: _rule_by_name(persona.client, manual_name),
            timeout=DETECTION,
            interval=3,
            desc="live signal processed without alerting",
            ok=lambda item: item is not None and item.get("live_match_count", 0) >= 1,
        )
        live_alerts = expect(
            persona.client.api.get("/api/alerts", params={"rule_id": rule["id"], "limit": 20}), 200
        )
        assert live_alerts == [], f"live mode must not alert: {live_alerts}"
        timeline.step("live signal", signals=len(live_signals), alerts=0)

        # Live -> alerting, then a distinct matching event proves the complete
        # real-time signal processor path: signal -> alert -> enterprise case.
        _choose_rule_action(page, "Promote to alerting")
        rule = eventually(
            lambda: _rule_by_name(persona.client, manual_name),
            timeout=30,
            desc="rule promoted to alerting",
            ok=lambda item: item is not None and item.get("mode") == "alerting",
        )
        assert rule is not None
        alert_message = f"{mark} persona-alerting-signal"
        assert ingest.hec(stack.hec_url, src.token, {"message": alert_message}).status_code == 200
        eventually(
            lambda: nano.rows(f'"{alert_message}"', limit=10),
            timeout=INGEST_VISIBLE,
            desc="alerting-mode event searchable",
        )
        alerts = eventually(
            lambda: expect(
                persona.client.api.get("/api/alerts", params={"rule_id": rule["id"], "limit": 20}), 200
            ),
            timeout=DETECTION,
            interval=3,
            desc="alerting rule alert",
            ok=lambda values: any(alert_message in row_text(item.get("matched_events")) for item in values),
        )
        alert = next(item for item in alerts if alert_message in row_text(item.get("matched_events")))
        signals = eventually(
            lambda: _signal_rows(persona.client, manual_name),
            timeout=DETECTION,
            interval=3,
            desc="alerting rule signal",
            ok=lambda values: len(values) >= len(live_signals) + 1,
        )
        assert alert["kind"] == "detection", alert
        timeline.step("alerting fired", signals=len(signals), alert=alert["id"])

        if edition == "enterprise":
            alert = eventually(
                lambda: next(
                    item
                    for item in expect(
                        persona.client.api.get("/api/alerts", params={"rule_id": rule["id"], "limit": 20}),
                        200,
                    )
                    if item["id"] == alert["id"]
                ),
                timeout=DETECTION,
                interval=3,
                desc="alert grouped into a case",
                ok=lambda item: bool(item.get("case_id")),
            )
            case_id = alert["case_id"]
            persona_cleanup.case(case_id)
            page.goto(f"/cases/{case_id}")
            page.wait_text(manual_name, exact=False, timeout_ms=60_000)
            timeline.step("case opened", case=case_id)
        else:
            capability = expect(nano.api.get("/api/capabilities"), 200)
            assert capability["capabilities"]["cases"] is False, capability
            assert persona.client.api.get("/api/cases").status_code == 404
            page.goto("/cases")
            page.wait_text("Available in nano paid plans", exact=False)
            timeline.step("case boundary", edition=edition, capability=False, api=404)

        # Enterprise also proves authoring through the pivt detection wizard.
        # Open proves both capability and route absence without a dead control.
        page.goto("/rules")
        if ai_mode:
            page.click({"role": "button", "name": "Draft with pivt", "exact": True})
            prompt = {"role": "textbox", "name": "Message pivt", "exact": True}
            page.fill(uilib.field(prompt, f"@detection catch the exact marker {mark}"))
            page.press_key(prompt, "Enter")
            run = {"testid": "pivt-draft-run"}
            run_status = eventually(
                lambda: page.attr(run, "data-status"),
                timeout=300,
                interval=0.5,
                desc="pivt detection draft terminal",
                ok=lambda status: status in {"done", "failed"},
            )
            assert run_status == "done", page.texts(run)[:1]
            ai_names = [f"persona_ai_{index}_{mark.replace('-', '_')}" for index in (1, 2)]
            # Name-based cleanup is safe to pre-register and covers a partial
            # batch success just as rigorously as a full success.
            for name in ai_names:
                persona_cleanup.rule(name)
            page.click({"role": "button", "name": "Create 2", "exact": True})
            for name in ai_names:
                created = eventually(
                    lambda name=name: _rule_by_name(persona.client, name),
                    timeout=60,
                    interval=0.5,
                    desc=f"AI-created staging rule {name}",
                )
                assert created is not None
                assert created["mode"] == "staging" and created["ai_generated"] is True, created
            timeline.step("pivt detection rules authored", provider=ai_mode, count=2)
        else:
            assert page.count({"role": "button", "name": "Draft with pivt", "exact": True}) == 0
            unavailable = persona.client.api.post(
                "/api/melod/detection", json={"description": f"catch {mark}"}
            )
            assert unavailable.status_code == 404, unavailable.text[:1000]
            timeline.step("pivt detection boundary", edition=edition, ui="hidden", api=404)

        # Walk the production rule back through both guarded demotion states so
        # every lifecycle transition and its audit provenance is exercised.
        page.goto(f"/rules/editor/{rule['id']}")
        page.wait_text(manual_name, exact=False)
        _choose_rule_action(page, "Demote to live")
        eventually(
            lambda: _rule_by_name(persona.client, manual_name),
            timeout=30,
            desc="rule demoted to live",
            ok=lambda item: item is not None and item.get("mode") == "live",
        )
        _choose_rule_action(page, "Demote to staging")
        eventually(
            lambda: _rule_by_name(persona.client, manual_name),
            timeout=30,
            desc="rule demoted to staging",
            ok=lambda item: item is not None and item.get("mode") == "staging",
        )

        expected_transitions = {
            ("rule_promoted", "staging", "live"),
            ("rule_promoted", "live", "alerting"),
            ("rule_demoted", "alerting", "live"),
            ("rule_demoted", "live", "staging"),
        }
        audit_rows = eventually(
            lambda: _rule_transition_audit(nano, manual_name),
            timeout=60,
            interval=2,
            desc="state-specific rule lifecycle audit",
            ok=lambda rows: expected_transitions.issubset(
                {
                    (
                        row.get("action"),
                        (row.get("details") or {}).get("from"),
                        (row.get("details") or {}).get("to"),
                    )
                    for row in rows
                }
            ),
        )
        actual_transitions = {
            (
                row.get("action"),
                (row.get("details") or {}).get("from"),
                (row.get("details") or {}).get("to"),
            )
            for row in audit_rows
        }
        assert expected_transitions.issubset(actual_transitions), actual_transitions
        timeline.step("lifecycle audit", transitions=sorted(expected_transitions))

        # Shipped DaC clients historically sent an empty POST while still
        # setting Content-Type: application/json. Preserve that wire contract
        # for one release: apply exactly one step, mark the response deprecated,
        # and retain precise audit provenance. Guarded web callers above always
        # send expected_mode and keep the stale-retry 409 protection.
        def transition_count(rows, action: str, from_mode: str, to_mode: str) -> int:
            return sum(
                1
                for row in rows
                if row.get("action") == action
                and (row.get("details") or {}).get("from") == from_mode
                and (row.get("details") or {}).get("to") == to_mode
            )

        promoted_before = transition_count(audit_rows, "rule_promoted", "staging", "live")
        legacy_promote_response = persona.client.api.post(
            f"/api/rules/{rule_id}/promote",
            headers={"Content-Type": "application/json"},
        )
        legacy_promoted = expect(legacy_promote_response, 200)
        assert legacy_promote_response.headers.get("deprecation") == "true"
        assert legacy_promote_response.headers.get("sunset") == "Sun, 07 Feb 2027 00:00:00 GMT"
        assert "expected_mode" in legacy_promote_response.headers.get("warning", "")
        assert legacy_promoted["mode"] == "live", legacy_promoted

        legacy_promote_retry_response = persona.client.api.post(
            f"/api/rules/{rule_id}/promote",
            headers={"Content-Type": "application/json"},
        )
        legacy_promote_retry = expect(legacy_promote_retry_response, 200)
        assert legacy_promote_retry_response.headers.get("x-nano-lifecycle-replayed") == "true"
        assert legacy_promote_retry["mode"] == "live", legacy_promote_retry

        # Shipped nanodac versions send bodyless pause/resume. Keep that path
        # serialized and idempotent while guarded callers retain stale-state
        # protection, and restore the exact mode captured by pause.
        pause_response = persona.client.api.post(
            f"/api/rules/{rule_id}/pause",
            headers={"Content-Type": "application/json"},
        )
        paused = expect(pause_response, 200)
        assert pause_response.headers.get("deprecation") == "true"
        assert pause_response.headers.get("sunset") == "Sun, 07 Feb 2027 00:00:00 GMT"
        assert "expected_mode" in pause_response.headers.get("warning", "")
        assert paused["mode"] == "paused", paused
        pause_retry_response = persona.client.api.post(
            f"/api/rules/{rule_id}/pause",
            headers={"Content-Type": "application/json"},
        )
        pause_retry = expect(pause_retry_response, 200)
        assert pause_retry_response.headers.get("x-nano-lifecycle-replayed") == "true"
        assert pause_retry["mode"] == "paused", pause_retry
        assert persona.client.api.post(
            f"/api/rules/{rule_id}/pause", json={"expected_mode": "live"}
        ).status_code == 409
        resume_response = persona.client.api.post(
            f"/api/rules/{rule_id}/resume",
            headers={"Content-Type": "application/json"},
        )
        resumed = expect(resume_response, 200)
        assert resume_response.headers.get("deprecation") == "true"
        assert resume_response.headers.get("sunset") == "Sun, 07 Feb 2027 00:00:00 GMT"
        assert "expected_mode" in resume_response.headers.get("warning", "")
        assert resumed["mode"] == "live", resumed
        resume_retry_response = persona.client.api.post(
            f"/api/rules/{rule_id}/resume",
            headers={"Content-Type": "application/json"},
        )
        resume_retry = expect(resume_retry_response, 200)
        assert resume_retry_response.headers.get("x-nano-lifecycle-replayed") == "true"
        assert resume_retry["mode"] == "live", resume_retry
        assert persona.client.api.post(
            f"/api/rules/{rule_id}/resume", json={"expected_mode": "paused"}
        ).status_code == 409

        # The no-key dwell is per rule and deliberately blocks every second
        # unguarded transition, including the opposite direction. Exercise
        # bodyless demote on a separate live fixture instead of sleeping out
        # the safety window.
        legacy_demote_name = f"persona_legacy_demote_{mark[-10:].replace('-', '_')}"
        persona_cleanup.rule(legacy_demote_name)
        legacy_demote_rule = expect(
            persona.client.api.post(
                "/api/rules",
                json={
                    "name": legacy_demote_name,
                    "description": "Persona bodyless demote compatibility",
                    "query": f'source_type="{src.route_key}"',
                    "severity": "high",
                    "mode": "live",
                    "detection_mode": "scheduled",
                    "schedule_cron": "* * * * *",
                },
            ),
            200,
            201,
        )
        legacy_demote_response = persona.client.api.post(
            f"/api/rules/{legacy_demote_rule['id']}/demote",
            headers={"Content-Type": "application/json"},
        )
        legacy_demoted = expect(legacy_demote_response, 200)
        assert legacy_demote_response.headers.get("deprecation") == "true"
        assert legacy_demote_response.headers.get("sunset") == "Sun, 07 Feb 2027 00:00:00 GMT"
        assert "expected_mode" in legacy_demote_response.headers.get("warning", "")
        assert legacy_demoted["mode"] == "staging", legacy_demoted
        legacy_demote_retry_response = persona.client.api.post(
            f"/api/rules/{legacy_demote_rule['id']}/demote",
            headers={"Content-Type": "application/json"},
        )
        legacy_demote_retry = expect(legacy_demote_retry_response, 200)
        assert legacy_demote_retry_response.headers.get("x-nano-lifecycle-replayed") == "true"
        assert legacy_demote_retry["mode"] == "staging", legacy_demote_retry

        legacy_audit_rows = eventually(
            lambda: _rule_transition_audit(nano, manual_name),
            timeout=60,
            interval=2,
            desc="deprecated bodyless lifecycle audit",
            ok=lambda rows: (
                transition_count(rows, "rule_promoted", "staging", "live") == promoted_before + 1
                and transition_count(rows, "rule_paused", "live", "paused") == 1
                and transition_count(rows, "rule_resumed", "paused", "live") == 1
            ),
        )
        assert (
            transition_count(legacy_audit_rows, "rule_promoted", "staging", "live")
            == promoted_before + 1
        )
        assert transition_count(legacy_audit_rows, "rule_paused", "live", "paused") == 1
        assert transition_count(legacy_audit_rows, "rule_resumed", "paused", "live") == 1
        demote_audit_rows = eventually(
            lambda: _rule_transition_audit(nano, legacy_demote_name),
            timeout=60,
            interval=2,
            desc="deprecated bodyless demote audit",
            ok=lambda rows: transition_count(rows, "rule_demoted", "live", "staging") == 1,
        )
        assert transition_count(demote_audit_rows, "rule_demoted", "live", "staging") == 1
        timeline.step(
            "bodyless lifecycle compatibility",
            deprecation="true",
            replayed="true",
            pause_restored="live",
        )

        persona.checkpoint("rule-lifecycle-signal-alert-case")
