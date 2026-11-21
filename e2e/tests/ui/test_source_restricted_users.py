"""Per-source RBAC: a source-restricted user sees nothing from the sources
they are not granted (NAN-5686, security: a leak here is P1).

Two OCSF sources, A and B, carry events with the same marker. B's events
name a user (`user_b`) and an IP (`ip_b`) that appear in no rule, title or
setting: they are pure event data, so finding either anywhere the restricted
analyst can read is a leak. The admin restricts B and grants it to one group.
Two throwaway analysts hold the same role:

- `granted` (in the granted group) is the positive control: every surface
  below must show B to them, or the check is vacuous and the test says so;
- `restricted` must see only A, and must not learn that B's objects exist:
  - search: results, `stats count by source_type`, `source_type=B`,
    field values, field stats, the streaming endpoint and a durable search job
    (the CSV / export path pages job results);
  - alerts: not in the list, not by B's rule, 404 (not 403) by id, B's rule
    name absent from the list;
  - risk (enterprise): B's user is not a risk entity;
  - prevalence: B's IP is not in the artifact explorer (checked only when
    the granted control sees it there);
  - dashboards: the panel query returns no B row;
  - cases (enterprise): B's case is not listed, 404 by id, not found by
    case search (the granted control finds it);
  - hunts leads (enterprise): no B data in the list;
  - every API response the restricted browser received while it walked
    Search, Alerts, Risk, Prevalence, the dashboard, Investigate, Case search
    and Hunts leads contains neither `user_b` nor `ip_b` (data that reached
    the browser before or under the UI, not only what it rendered).

PIVT answers are not checked: the deterministic ai-stub answers without
reading data, so it cannot show a leak either way. Notebooks run their
queries through the same search endpoints checked above.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

import pytest
from nano_e2e import ui as uilib
from nano_e2e.client import Journal, Nano, expect, row_text, time_range
from nano_e2e.rbac import role_user, typeid_uuid
from nano_e2e.stack import Stack
from nano_e2e.waits import DETECTION, INGEST_VISIBLE, eventually

ANALYST = (
    "search:view",
    "search:execute",
    "alerts:view",
    "dashboards:view",
    "cases:view",
    "detections:view",
    "risk:view",
    "prevalence:view",
    "hunts:view",
    "notebooks:view",
)


def _alerts(client: Nano, **params: Any) -> list[dict[str, Any]]:
    body = expect(client.api.get("/api/alerts", params={"limit": 200, **params}), 200)
    return body if isinstance(body, list) else body.get("alerts", [])


def _client(stack: Stack, email: str, password: str, journal: Journal) -> Nano:
    jwt = Nano(stack.api_url, stack.search_url, {}, Journal(None)).login(email, password)
    return Nano(stack.api_url, stack.search_url, {"Authorization": f"Bearer {jwt}"}, journal)


def _job_rows(client: Nano, query: str) -> str:
    job = expect(client.search_http.post("/api/search/jobs", json={
        "query": query, "limit": 1000, "skip_histogram": True, "time_range": time_range(60)}), 202)
    done = eventually(lambda: expect(client.search_http.get(f"/api/search/jobs/{job['job_id']}"), 200),
                      timeout=180, interval=2, desc="search job done",
                      ok=lambda s: s.get("status") in ("completed", "failed", "cancelled"))
    assert done["status"] == "completed", done
    page = expect(client.search_http.get(f"/api/search/jobs/{job['job_id']}/results",
                                         params={"offset": 0, "limit": 1000}), 200)
    return json.dumps(page.get("rows") or [])


def _surfaces(client: Nano, mark: str, lane_b: str, ip_b: str, enterprise: bool) -> dict[str, str]:
    """Every data surface, as text, read with one analyst's credentials."""
    tr = time_range(60)
    out: dict[str, str] = {}
    out["search"] = json.dumps(client.rows(f'"{mark}"', limit=100))
    out["stats by source_type"] = json.dumps(client.rows(f'"{mark}" | stats count by source_type, actor.user.name'))
    out["source_type=B"] = json.dumps(client.rows(f'source_type="{lane_b}"', limit=100))
    fv = client.search_http.post("/api/search/field-values", json={
        "field": "actor.user.name", "query": f'"{mark}"', "start": tr["start"], "end": tr["end"], "limit": 100})
    out["field values"] = fv.text if fv.status_code == 200 else f"<{fv.status_code}>"
    fs = client.search_http.post("/api/search/field-stats", json={
        "query": f'"{mark}"', "start": tr["start"], "end": tr["end"]})
    out["field stats"] = fs.text if fs.status_code == 200 else f"<{fs.status_code}>"
    st = client.search_http.post("/api/search/stream", json={
        "query": f'"{mark}"', "limit": 100, "time_range": tr, "skip_histogram": True})
    out["search stream"] = st.text if st.status_code == 200 else f"<{st.status_code}>"
    out["search job (export)"] = _job_rows(client, f'"{mark}"')
    pq = client.api.post("/api/dashboards/panel/query", json={
        "query": f'"{mark}" | stats count by actor.user.name, src_endpoint.ip', "query_mode": "piped",
        "time_range": tr, "bypass_cache": True})
    out["dashboard panel query"] = pq.text if pq.status_code == 200 else f"<{pq.status_code}>"
    pv = client.api.get("/api/prevalence/explorer", params={"search": ip_b, "window": "7d", "limit": 50})
    out["prevalence explorer"] = pv.text if pv.status_code == 200 else f"<{pv.status_code}>"
    if enterprise:
        rk = client.api.get("/api/risk/entities", params={"limit": 500})
        out["risk entities"] = rk.text if rk.status_code == 200 else f"<{rk.status_code}>"
        hl = client.api.get("/api/hunts/leads", params={"limit": 200})
        out["hunts leads"] = hl.text if hl.status_code == 200 else f"<{hl.status_code}>"
    return out


@pytest.mark.timeout(1800)
def test_source_restricted_user_sees_only_granted_sources(
    stack: Stack, nano: Nano, ocsf_lane_factory, mark: str, ui: uilib.Driver, artifact_dir, timeline
) -> None:
    enterprise = stack.edition == "enterprise"
    tag = secrets.token_hex(3)
    mark = f"{mark}-{tag}"  # run-unique: reruns on a kept stack never see each other's events
    # Values unique to this run: nothing left over from an earlier run on the
    # same stack (whose restriction is gone) can match them.
    octets = secrets.token_bytes(2)
    IP_A, IP_B = f"10.{octets[0]}.{octets[1]}.10", f"10.{octets[0]}.{octets[1]}.20"
    lane_a = ocsf_lane_factory(f"scope-a-{tag}")
    lane_b = ocsf_lane_factory(f"scope-b-{tag}")
    user_a, user_b = f"scope-a-{tag}", f"scope-b-{tag}"
    for i in range(2):
        lane_a.send(stack, mark, user_a, IP_A, "scope-a", note=f"a{i}")
        lane_b.send(stack, mark, user_b, IP_B, "scope-b", note=f"b{i}")
    eventually(lambda: nano.search(f'"{mark}"')["total_count"], timeout=INGEST_VISIBLE, desc="A+B events",
               ok=lambda n: n == 4)

    created: list[str] = []
    try:
        role = expect(nano.api.post("/api/roles", json={
            "name": f"e2e-scope-analyst-{tag}", "description": "nano-e2e (NAN-5686)", "permissions": list(ANALYST)}),
            200, 201)
        created.append(f"/api/roles/{role['id']}")
        # One alerting rule per lane. The queries name the source only, never
        # B's user or IP, so those strings exist only in event data. Each rule
        # scores the user (RBA) so the risk surface has data to leak.
        rules: dict[str, dict[str, Any]] = {}
        for lane in (lane_a, lane_b):
            r = expect(nano.api.post("/api/rules", json={
                "name": f"scope_{lane.lane[-12:]}_{tag}".replace("-", "_"), "description": "nano-e2e scope",
                "query": f'source_type="{lane.lane}" "{mark}"', "severity": "high", "mode": "alerting",
                "detection_mode": "scheduled", "schedule_cron": "* * * * *", "lookback_minutes": 30,
                "folder": "Automated", "risk_score": 40, "risk_entity_field": "actor.user.name"}), 200, 201)
            created.append(f"/api/rules/{r['id']}")
            rules[lane.lane] = r
            expect(nano.api.post(f"/api/rules/{r['id']}/trigger"), 200)
        rule_b = rules[lane_b.lane]
        alert_b = eventually(lambda: _alerts(nano, rule_id=rule_b["id"]), timeout=DETECTION, interval=5,
                             desc="B alert", ok=bool)[0]
        eventually(lambda: _alerts(nano, rule_id=rules[lane_a.lane]["id"]), timeout=DETECTION, interval=5,
                   desc="A alert", ok=bool)
        case_b = None
        if enterprise:
            case_b = eventually(
                lambda: next((a for a in _alerts(nano, rule_id=rule_b["id"]) if a.get("case_id")), None),
                timeout=DETECTION, interval=5, desc="B alert grouped into a case")["case_id"]
            created.append(f"/api/cases/{case_b}")
            eventually(lambda: nano.api.get("/api/risk/entities", params={"limit": 500}).text, timeout=DETECTION,
                       interval=5, desc="B's user has risk (admin view)", ok=lambda t: user_b in t)
        dash = expect(nano.api.post("/api/dashboards", json={
            "name": f"e2e scope {tag}", "description": "nano-e2e (NAN-5686)", "visibility": "public",
            "layout": {"columns": 12, "rowHeight": 80, "autoRun": True,
                       "defaultTimeRange": {"type": "preset", "preset": "Last 1 hour"},
                       "items": [{"i": "p1", "x": 0, "y": 0, "w": 12, "h": 6}]},
            "panels": [{"id": "p1", "title": "by user", "query": f'"{mark}" | stats count by actor.user.name, src_endpoint.ip',
                        "queryMode": "piped", "visualizationType": "table", "visualizationConfig": {},
                        "timeRangeMode": "dashboard", "drilldownEnabled": True}]}), 200, 201)
        created.append(f"/api/dashboards/{dash['id']}")

        # Restrict B; grant it to one group.
        expect(nano.api.post("/api/source-scopes/restricted", json={"source_type": lane_b.lane,
                                                                     "description": "nano-e2e (NAN-5686)"}), 200, 201)
        created.append(f"/api/source-scopes/restricted/{lane_b.lane}")
        with role_user(stack, f"scope-granted-{tag}", [str(role["id"])], Journal(artifact_dir / "granted.jsonl")) as granted, \
                role_user(stack, f"scope-restricted-{tag}", [str(role["id"])], Journal(artifact_dir / "restricted.jsonl")) as restricted:
            gid = typeid_uuid(granted.group_id)
            expect(nano.api.post("/api/source-scopes/grants", json={"source_type": lane_b.lane, "group_id": gid}), 200, 201)
            g = _client(stack, granted.email, granted.password, Journal(artifact_dir / "granted-api.jsonl"))
            r = _client(stack, restricted.email, restricted.password, Journal(artifact_dir / "restricted-api.jsonl"))
            leaks: list[str] = []
            vacuous: list[str] = []
            try:
                eventually(lambda: g.search(f'"{mark}"')["total_count"], timeout=30, desc="granted sees A+B",
                           ok=lambda n: n == 4)
                eventually(lambda: r.search(f'"{mark}"')["total_count"], timeout=30, desc="restricted sees A only",
                           ok=lambda n: n == 2)

                # Prevalence is built by a background job: give the control time to
                # see B's IP there, so the prevalence check is not vacuous.
                try:
                    eventually(lambda: g.api.get("/api/prevalence/explorer",
                                                 params={"search": IP_B, "window": "7d", "limit": 50}).text,
                               timeout=420, interval=15, desc="B's IP in prevalence (granted control)",
                               ok=lambda t: IP_B in t)
                except AssertionError as exc:
                    timeline.step("prevalence not computed in time", detail=str(exc)[:200])

                # Every data surface: the control must show B, the restricted view must not.
                seen_g = _surfaces(g, mark, lane_b.lane, IP_B, enterprise)
                seen_r = _surfaces(r, mark, lane_b.lane, IP_B, enterprise)
                for surface, text in seen_r.items():
                    control = seen_g[surface]
                    if user_b in text or IP_B in text:
                        leaks.append(f"{surface}: B data visible to the restricted analyst")
                    if not (user_b in control or IP_B in control):
                        vacuous.append(f"{surface}: the granted control sees no B data either ({control[:120]!r})")
                    if surface in ("search", "field values") and user_a not in text:
                        leaks.append(f"{surface}: restricted analyst lost A as well (over-restricted)")

                # Alerts: absent everywhere, and 404 (not 403) by id: existence is not confirmed.
                listed = _alerts(r)
                if any(a["id"] == alert_b["id"] for a in listed):
                    leaks.append("alert list includes B's alert")
                if rule_b["name"] in json.dumps(listed):
                    leaks.append("alert list carries B's rule name")
                if _alerts(r, rule_id=rule_b["id"]):
                    leaks.append("alerts filtered by B's rule are listed")
                detail = r.api.get(f"/api/alerts/{alert_b['id']}")
                if detail.status_code != 404:
                    leaks.append(f"alert by id answers {detail.status_code} (expected 404, as for no alert)")
                missing = r.api.get("/api/alerts/alert_00000000000000000000000000")
                timeline.step("alert existence", b=detail.status_code, nonexistent=missing.status_code)
                if not _alerts(r, rule_id=rules[lane_a.lane]["id"]):
                    leaks.append("restricted analyst cannot see A's alert (over-restricted)")
                if not any(a["id"] == alert_b["id"] for a in _alerts(g)):
                    vacuous.append("alerts: the granted control does not see B's alert")

                # Cases: not listed, 404 by id, not found by case search; the control finds it.
                if enterprise and case_b:
                    since = time_range(60)["start"]
                    listed_c = expect(r.api.get("/api/cases", params={"limit": 200}), 200)
                    if case_b in json.dumps(listed_c):
                        leaks.append("case list includes B's case")
                    one = r.api.get(f"/api/cases/{case_b}")
                    if one.status_code != 404:
                        leaks.append(f"case by id answers {one.status_code} (expected 404)")
                    seen = g.api.get("/api/cases", params={"free_text": user_b, "created_after": since, "limit": 50})
                    if not (seen.status_code == 200 and case_b in seen.text):
                        vacuous.append(f"case free_text search: the granted control does not find B's case ({seen.status_code})")
                    found = r.api.get("/api/cases", params={"free_text": user_b, "created_after": since, "limit": 50})
                    if found.status_code == 200 and case_b in found.text:
                        leaks.append("case free_text search for B's user finds B's case")

                # The browser: every API response received while walking the data pages.
                page = uilib.UiPage.open(ui, artifact_dir / "ui-restricted", name="scope:restricted")
                ui.register_secret(restricted.password)
                failed = True
                try:
                    uilib.login(page, restricted.email, restricted.password)
                    since_ms = page.now_ms()
                    uilib.run_search(page, f'"{mark}"')
                    if uilib.results_count(page) != 2:
                        leaks.append(f"search UI shows {uilib.results_count(page)} events (expected A's 2)")
                    paths = ["/alerts", f"/dashboards/{dash['id']}", "/prevalence"]
                    if enterprise:
                        paths += ["/risk", "/inbox", "/cases/search", "/hunts/leads"]
                    for path in paths:
                        page.goto(path)
                        eventually(lambda: len(page.main_text().strip()), timeout=30, interval=0.5,
                                   desc=f"{path} rendered", ok=lambda n: n > 20)
                        for needle in (user_b, IP_B):
                            if page.contains(needle):
                                leaks.append(f"{path} renders B data ({needle})")
                    page.goto(f"/dashboards/{dash['id']}")
                    page.wait_text(user_a, exact=False, timeout_ms=60_000)
                    for needle in (user_b, IP_B):
                        hits = page.responses_containing(needle, since_ms=since_ms)
                        if hits:
                            leaks.append(f"API responses to the restricted browser carry B data ({needle}): {hits[:5]}")
                    page.screenshot("scope-restricted-dashboard.png", full_page=False)
                    failed = False
                finally:
                    page.finish(failed or bool(leaks))
            finally:
                g.close()
                r.close()
                expect(nano.api.delete(f"/api/source-scopes/grants/{lane_b.lane}/{gid}"), 200, 204, 404)
            timeline.step("scope", leaks=leaks, vacuous=vacuous, surfaces=sorted(seen_r))
            assert not leaks, "P1 per-source RBAC leaks:\n" + "\n".join(f"- {x}" for x in leaks)
            # Prevalence and hunts leads are computed by background jobs; a fresh
            # stack may not have them yet. Every other surface must have B data
            # for the control, or the check proved nothing.
            hard = [v for v in vacuous if not v.startswith(("prevalence explorer", "hunts leads"))]
            assert not hard, "vacuous controls (the granted analyst saw no B data):\n" + "\n".join(hard)
    finally:
        for path in reversed(created):
            expect(nano.api.delete(path), 200, 204, 404)
