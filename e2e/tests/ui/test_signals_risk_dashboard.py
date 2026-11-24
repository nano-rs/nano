"""Dashboards on the detections and risk datasets (NAN-5612).

Two OCSF sources each get a live scheduled rule that fires (a real finding),
then one dashboard carries three `dataset=signals` panels (timechart, top
rules, single value) and two `dataset=risk` panels (top entities, entities by
type). Checked through the panel API and in the browser:

- the admin sees both sources' detections and risk;
- a viewer restricted from source B sees only source A, in every panel;
- a credential without detections:view gets a panel-level 403 with a clear
  message for the signals panels, while the risk panels still load;
- drilldown / "Open in Search" keeps the dataset (the query's leading
  `dataset=` token).

Screenshots: `dashboard-admin.png`, `dashboard-scoped.png` in the artifact
dir. OCSF only.
"""

from __future__ import annotations

import secrets
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from nano_e2e import ingest, schema
from nano_e2e import ui as uilib
from nano_e2e.client import Journal, Nano, expect, time_range
from nano_e2e.field_invariants import ch_query
from nano_e2e.personas import login_persona
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

PARSER = """
.class_uid = 3002
.category_uid = 3
.activity_id = 1
.type_uid = 300201
.severity_id = 1
.actor.user.name = del(.user)
.src_endpoint.ip = del(.ip)
.device.hostname = del(.host)
.metadata.log_source = "{lane}"
.metadata.product.name = "nano-e2e"
"""

VIEWER = ("dashboards:view", "search:view", "search:execute", "detections:view")


def _lane(nano: Nano, stack: Stack, tag: str, label: str) -> tuple[str, str, str, str]:
    """An OCSF auth lane: (source_type, token, source_id, credential_id)."""
    rk = f"nan5612_{label}_{tag}"
    src = nano.create_draft_source(name=rk, route_key=rk, parser_vrl=PARSER.format(lane=rk))
    cred, tok = nano.issue_token(src["id"], name=f"{rk}-tok")
    res = expect(nano.api.post(f"/api/log-sources/{src['id']}/publish", json={"acknowledge_unattested": True}), 200)
    assert res.get("success") is True, res
    n = {"i": 0}

    def probe() -> list:
        n["i"] += 1
        ingest.hec(stack.hec_url, tok, {"message": f"settle {rk} {n['i']}", "user": f"settle-{rk}", "host": f"settle-{rk}"})
        return nano.rows(f'actor.user.name="settle-{rk}"', limit=5, minutes_back=15)

    eventually(probe, timeout=180, interval=3, desc=f"lane {rk} parsing")
    return rk, tok, src["id"], cred


def _rule(nano: Nano, name: str, query: str, severity: str, score: int) -> dict[str, Any]:
    return expect(
        nano.api.post(
            "/api/rules",
            json={
                "name": name,
                "description": "nano-e2e NAN-5612 signals/risk dashboard rule",
                "query": query,
                "severity": severity,
                "schedule_cron": "* * * * *",
                "mode": "live",
                "detection_mode": "scheduled",
                "lookback_minutes": 30,
                "risk_score": score,
                "risk_entity_field": "device.hostname",
                "folder": "Automated",
            },
        ),
        200,
        201,
    )


def _panel(pid: str, title: str, query: str, viz: str) -> dict[str, Any]:
    return {
        "id": pid,
        "title": title,
        "query": query,
        "queryMode": "piped",
        "visualizationType": viz,
        "visualizationConfig": {},
        "timeRangeMode": "dashboard",
        "drilldownEnabled": True,
    }


def _panels(tag: str, host_a: str, host_b: str) -> list[dict[str, Any]]:
    """The dashboard's panels, each filtered to THIS scenario's rules or
    entities (NAN-5835). The shapes are the real ones (timechart, top 10,
    single value, bar), but unfiltered `head 10` panels are order-dependent:
    risk and signals left by earlier tests in the same stack outrank this
    scenario's (host-a scores 40; leftovers scored 75 to 225 on RC1), so
    host-a never rendered. The filter adds no visibility: source scoping is
    applied on top of it, so a source-B row can still only be hidden by RBAC."""
    sig = f'dataset=signals rule_name="e2e_nan5612_*_{tag}"'
    risk = f'dataset=risk entity IN ("{host_a}", "{host_b}")'
    return [
        _panel("sig_time", "Detections over time", f"{sig} | timechart span=1h count by severity", "line"),
        _panel("sig_rules", "Top firing rules", f"{sig} | stats count by rule_name | sort -count | head 10", "table"),
        _panel("sig_total", "Detections", f"{sig} | stats count", "single_value"),
        _panel(
            "risk_top",
            "Riskiest entities",
            f"{risk} | sort -score_24h | head 10 | table entity, entity_type, score_24h, findings_24h, last_rule_name",
            "table",
        ),
        _panel("risk_types", "Risky entities by type", f"{risk} | stats count by entity_type", "bar"),
    ]


def _panel_rows(client: Nano, query: str) -> tuple[int, Any]:
    r = client.api.post(
        "/api/dashboards/panel/query",
        json={"query": query, "query_mode": "piped", "time_range": time_range(12 * 60), "bypass_cache": True},
    )
    body = r.json() if r.content else None
    return r.status_code, body


def _realtime_signals(stack: Stack, tag: str, a_st: str, b_st: str, host_a: str, host_b: str) -> None:
    """Real-time detections spread over the last 10 hours (the signals table
    the real-time materialized views write): source A only `high`, source B
    `critical` and `medium`, so a viewer denied B sees ONE severity series."""
    now = datetime.now(timezone.utc)
    rows = []
    for h in range(1, 11):
        at = (now - timedelta(hours=h, minutes=7)).strftime("%Y-%m-%d %H:%M:%S.%f")
        for st, rule, sev, host, n in [
            (a_st, f"e2e_nan5612_rt_source_a_{tag}", "high", host_a, 1 + h % 3),
            (b_st, f"e2e_nan5612_rt_source_b_{tag}", "critical" if h % 2 else "medium", host_b, 1 + h % 2),
        ]:
            for _ in range(n):
                rows.append(
                    f"('{uuid.uuid4()}', '{at}', '{uuid.uuid5(uuid.NAMESPACE_DNS, rule)}', '{rule}', '{sev}', 20, "
                    f"'{host}', '{uuid.uuid4()}', '{st}')"
                )
    ch_query(
        stack,
        "INSERT INTO signals (id, timestamp, rule_id, rule_name, severity, risk_score, risk_entity, matched_log_id, source_type) VALUES "
        + ", ".join(rows),
    )


def _settled_bar(page: uilib.UiPage) -> dict[str, Any]:
    """The bar chart's bar height read repeatedly until two reads agree
    (recharts animates bars up from 0 after data arrives), and the plot area
    (its y: the plot starts at the chart's 5 px top margin). A single-category
    bar at the axis maximum must settle with y == 5. Waits a little more after so every
    chart on the page has finished animating before a screenshot."""
    chart = ".recharts-wrapper:has(.recharts-bar-rectangle)"
    bar = {"css": f"{chart} .recharts-bar-rectangle path"}
    reads = [page.attr(bar, "height")]
    for _ in range(40):
        time.sleep(0.1)
        reads.append(page.attr(bar, "height"))
        if len(reads) >= 4 and len(set(reads[-4:])) == 1:
            break
    time.sleep(1.5)
    return {
        "bar_height_reads": reads,
        # The chart's top margin is 5 px: a bar at the axis maximum starts there.
        "bar_y": page.attr(bar, "y"),
    }


def test_signals_and_risk_dashboard_is_scoped_and_renders(
    stack: Stack, nano: Nano, ui: uilib.Driver, page: uilib.UiPage, artifact_dir, timeline
) -> None:
    if not schema.is_ocsf():
        pytest.skip("OCSF only")
    tag = secrets.token_hex(3)
    cleanup: list[Any] = []
    try:
        a_st, a_tok, a_src, a_cred = _lane(nano, stack, tag, "a")
        b_st, b_tok, b_src, b_cred = _lane(nano, stack, tag, "b")
        cleanup += [lambda: nano.delete_source(a_src), lambda: nano.delete_source(b_src)]
        host_a, host_b = f"host-a-{tag}", f"host-b-{tag}"
        for i in range(3):
            assert ingest.hec(stack.hec_url, a_tok, {"message": f"nan5612 {tag} a {i}", "user": f"alice-{tag}", "host": host_a, "ip": "203.0.113.10"}).status_code == 200
        for i in range(2):
            assert ingest.hec(stack.hec_url, b_tok, {"message": f"nan5612 {tag} b {i}", "user": f"bob-{tag}", "host": host_b, "ip": "203.0.113.20"}).status_code == 200
        users = f'actor.user.name IN ("alice-{tag}", "bob-{tag}")'
        eventually(lambda: nano.search(users)["total_count"], timeout=INGEST_VISIBLE, desc="events", ok=lambda n: n == 5)

        _realtime_signals(stack, tag, a_st, b_st, host_a, host_b)

        rule_a = _rule(nano, f"e2e_nan5612_source_a_logons_{tag}", f'source_type="{a_st}" actor.user.name="alice-{tag}"', "high", 40)
        rule_b = _rule(nano, f"e2e_nan5612_source_b_logons_{tag}", f'source_type="{b_st}" actor.user.name="bob-{tag}"', "critical", 70)
        cleanup += [lambda: nano.api.delete(f"/api/rules/{rule_a['id']}"), lambda: nano.api.delete(f"/api/rules/{rule_b['id']}")]
        for rid in (rule_a["id"], rule_b["id"]):
            expect(nano.api.post(f"/api/rules/{rid}/trigger"), 200)

        rules_q = f'dataset=signals rule_name="e2e_nan5612_*_{tag}" | stats count by rule_name'
        admin_rules = eventually(
            lambda: _panel_rows(nano, rules_q),
            timeout=180,
            interval=5,
            desc="both scheduled detections visible as signals",
            ok=lambda r: r[0] == 200 and len(r[1]["results"]) == 4,
        )[1]
        timeline.step("admin signals by rule", rows=admin_rules["results"])
        rt_a, rt_b = f"e2e_nan5612_rt_source_a_{tag}", f"e2e_nan5612_rt_source_b_{tag}"
        risk_q = f'dataset=risk entity IN ("{host_a}", "{host_b}") | table entity, score_24h, findings_24h'
        admin_risk = eventually(
            lambda: _panel_rows(nano, risk_q),
            timeout=180,
            interval=5,
            desc="both entities in the risk dataset",
            ok=lambda r: r[0] == 200 and len(r[1]["results"]) == 2,
        )[1]
        timeline.step("admin risk", rows=admin_risk["results"])
        panels = _panels(tag, host_a, host_b)

        dashboard = expect(
            nano.api.post(
                "/api/dashboards",
                json={
                    "name": f"e2e_nan5612_detections_{tag}",
                    "description": "NAN-5612: signals and risk panels",
                    "visibility": "public",
                    "layout": {
                        "columns": 12,
                        "rowHeight": 80,
                        "autoRun": True,
                        "defaultTimeRange": {"type": "preset", "preset": "Last 12 hours"},
                        "items": [
                            {"i": "sig_total", "x": 0, "y": 0, "w": 3, "h": 2},
                            {"i": "sig_time", "x": 3, "y": 0, "w": 9, "h": 4},
                            {"i": "sig_rules", "x": 0, "y": 4, "w": 6, "h": 4},
                            {"i": "risk_top", "x": 6, "y": 4, "w": 6, "h": 4},
                            {"i": "risk_types", "x": 0, "y": 8, "w": 6, "h": 4},
                        ],
                    },
                    "panels": panels,
                },
            ),
            200,
            201,
        )
        cleanup.append(lambda: nano.api.delete(f"/api/dashboards/{dashboard['id']}"))

        # Restrict source B; the viewer persona has no grant for it.
        #
        # Source A is never restricted, and neither is any source another test
        # left in the stack, so the scoped viewer sees all of them. That is the
        # per-source RBAC model, not a leak: default allow-all, deny-by-omission,
        # "a user's visibility = all unrestricted sources + sources granted to
        # any of their groups" (docs-internal/working-notes/
        # RBAC_SOURCE_SCOPING_DESIGN.md, NAN-1789; denied = restricted -
        # grants, nanosiem-core/src/auth/source_scope_resolver.rs). Only the
        # restricted source B must disappear, which is what is asserted below.
        expect(nano.api.post("/api/source-scopes/restricted", json={"source_type": b_st, "description": "nan-5612 e2e"}), 200, 201)
        cleanup.append(lambda: nano.api.delete(f"/api/source-scopes/restricted/{b_st}"))

        # Numbers, per panel, admin vs scoped viewer.
        table: list[dict[str, Any]] = []
        with login_persona(stack, nano, ui, artifact_dir, "nan5612-scoped-viewer", VIEWER) as viewer:
            for q, label in [(rules_q, "signals by rule"), (risk_q, "risk entities")] + [(p["query"], p["title"]) for p in panels]:
                s_admin, b_admin = _panel_rows(nano, q)
                s_view, b_view = _panel_rows(viewer.client, q)
                assert s_admin == 200 and s_view == 200, (q, b_admin, b_view)
                table.append({"panel": label, "admin": b_admin["results"], "scoped": b_view["results"]})
            timeline.step("panel numbers", table=table)
            scoped_rules = {r["rule_name"] for r in table[0]["scoped"]}
            assert scoped_rules == {rule_a["name"], rt_a}, table[0]
            assert {r["rule_name"] for r in table[0]["admin"]} == {rule_a["name"], rule_b["name"], rt_a, rt_b}, table[0]
            assert {r["entity"] for r in table[1]["scoped"]} == {host_a}, table[1]
            assert {r["entity"] for r in table[1]["admin"]} == {host_a, host_b}, table[1]
            # Every dashboard panel, admin vs scoped (the panels carry only
            # this scenario's data, so each one is checked exactly).
            by = {t["panel"]: t for t in table[2:]}
            denied_sev = ("critical", "medium")  # source B's severities only
            for row in by["Detections over time"]["scoped"]:
                assert not any(row.get(k) for k in denied_sev), by["Detections over time"]
            assert any(row.get("high") for row in by["Detections over time"]["scoped"]), by["Detections over time"]
            assert any(row.get(k) for row in by["Detections over time"]["admin"] for k in denied_sev), by["Detections over time"]
            assert {r["rule_name"] for r in by["Top firing rules"]["scoped"]} == {rule_a["name"], rt_a}, by["Top firing rules"]
            assert {r["rule_name"] for r in by["Top firing rules"]["admin"]} == {rule_a["name"], rule_b["name"], rt_a, rt_b}, by["Top firing rules"]
            scoped_n = by["Detections"]["scoped"][0]["count"]
            admin_n = by["Detections"]["admin"][0]["count"]
            assert 0 < scoped_n < admin_n, by["Detections"]
            assert {r["entity"] for r in by["Riskiest entities"]["scoped"]} == {host_a}, by["Riskiest entities"]
            assert {r["entity"] for r in by["Riskiest entities"]["admin"]} == {host_a, host_b}, by["Riskiest entities"]
            assert by["Risky entities by type"]["scoped"] == [{"count": 1, "entity_type": "hostname"}], by["Risky entities by type"]
            assert by["Risky entities by type"]["admin"] == [{"count": 2, "entity_type": "hostname"}], by["Risky entities by type"]

            # A full-page capture resizes the viewport, which re-renders the
            # responsive charts and restarts their animation (the captured bar
            # was mid-grow while the settled DOM bar was full height). Fix the
            # viewport to the dashboard size and capture it, not the page.
            viewer.page.viewport(1600, 1400)
            viewer.page.goto(f"/dashboards/{dashboard['id']}")
            viewer.page.wait_text("Riskiest entities", exact=False, timeout_ms=60_000)
            viewer.page.wait_text(rule_a["name"], exact=False, timeout_ms=60_000)
            viewer.page.wait_text(host_a, exact=False, timeout_ms=60_000)
            assert not viewer.page.contains(rule_b["name"]), "denied source's rule rendered for the scoped viewer"
            assert not viewer.page.contains(rt_b), "denied source's real-time rule rendered for the scoped viewer"
            assert not viewer.page.contains(host_b), "denied source's entity rendered for the scoped viewer"
            # One severity series is still labeled.
            viewer.page.wait_for({"css": ".recharts-legend-item"}, timeout_ms=20_000)
            timeline.step("scoped legend", items=viewer.page.texts({"css": ".recharts-legend-item"}))
            timeline.step("scoped bar geometry", **_settled_bar(viewer.page))
            viewer.page.screenshot("dashboard-scoped.png", full_page=False)

        page.viewport(1600, 1400)
        page.goto(f"/dashboards/{dashboard['id']}")
        page.wait_text(rule_b["name"], exact=False, timeout_ms=60_000)
        page.wait_text(host_b, exact=False, timeout_ms=60_000)
        timeline.step("admin legend", items=page.texts({"css": ".recharts-legend-item"}))
        timeline.step("admin bar geometry", **_settled_bar(page))
        page.screenshot("dashboard-admin.png", full_page=False)

        # Drilldown keeps the dataset: the Search link for a signals panel.
        page.goto(
            "/search#"
            + urllib.parse.urlencode({"q": f'dataset=signals rule_name="{rule_b["name"]}"', "mode": "piped"})
        )
        page.wait_text(rule_b["name"], exact=False, timeout_ms=60_000)
        time.sleep(1.5)
        page.screenshot("search-from-drilldown.png", full_page=False)

        # A credential without detections:view: the signals panels refuse with
        # a clear message, the risk panels still load.
        # Key management needs an interactive (JWT) session.
        jwt = nano.login(stack.admin_email, stack.admin_password)
        session = Nano(stack.api_url, stack.search_url, {"Authorization": f"Bearer {jwt}"}, Journal(None))
        key = expect(session.api.post("/api/api-keys", json={"name": f"nan5612-{uuid.uuid4().hex[:6]}", "permissions": ["dashboards:view", "search:execute"]}), 200, 201)
        if key.get("id"):
            cleanup.append(lambda: session.api.delete(f"/api/api-keys/{key['id']}"))
        raw = key.get("key") or key.get("api_key") or key.get("raw_key")
        assert raw, sorted(key)
        no_det = Nano(stack.api_url, stack.search_url, {"X-API-Key": raw}, Journal(None))
        if True:
            s, b = _panel_rows(no_det, panels[2]["query"])
            assert s == 403 and "detections:view" in str(b), (s, b)
            s, b = _panel_rows(no_det, panels[3]["query"])
            assert s == 200, (s, b)
            timeline.step("no detections:view", signals_status=403, risk_status=200)
    finally:
        for fn in reversed(cleanup):
            try:
                fn()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
