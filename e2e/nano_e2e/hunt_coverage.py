"""Seeds for the unified MITRE Coverage scenarios (NAN-5850).

The hunt layer of `/rules/coverage` reads hunts, sweeps, findings and rule
ideas from PostgreSQL (`GET /api/hunts/technique-coverage`). No AI is needed
to put them there: like test_deep_hunts.py, the rows are written directly in
the NAN-5679 shape. Techniques are picked from the stack's own ATT&CK catalog
(no rule in any mode and no hunt data yet), so other scenarios' rules and
hunts never decide what a cell shows.
"""

# ruff: noqa: S608 - SQL seeds this owned stack; every value is a quoted literal (sql_text)
from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from nano_e2e.client import Nano, expect
from nano_e2e.soar_ui import psql, sql_text
from nano_e2e.soc_team import IDLE_CRON

ALL_MODES = "alerting,live,paused,staging"
FOLDER = "Automated"


def wait_catalog(client: Nano, timeout: float = 300) -> None:
    """A fresh stack installs the signed ATT&CK catalog shortly after boot;
    until then the coverage page shows "ATT&CK catalog unavailable"."""
    from nano_e2e.waits import eventually

    def state() -> tuple[str | None, int]:
        body = expect(client.api.get("/api/mitre"), 200)
        return (body.get("sync_state") or {}).get("status"), len(body.get("techniques") or [])

    eventually(state, timeout=timeout, interval=5, desc="the ATT&CK catalog is installed",
               ok=lambda st: st[0] == "succeeded" and st[1] > 0)


def coverage(client: Nano) -> dict[str, Any]:
    return expect(client.api.get("/api/mitre/coverage", params={"mode": ALL_MODES}), 200)


def hunt_layer(client: Nano, days: int = 90) -> dict[str, Any] | None:
    """The hunt layer, or None on a build without the endpoint."""
    r = client.api.get("/api/hunts/technique-coverage", params={"days": days})
    if r.status_code == 404:
        return None
    return expect(r, 200)


def source_types(t: dict[str, Any]) -> set[str]:
    out = {(r.get("source") or "").lower() for r in t.get("rules") or []}
    for d in t.get("data_sources") or []:
        out |= {s.lower() for s in d.get("source_types") or []}
    return out - {""}


def pick_free(client: Nano, n: int, need_sources: int = 0) -> list[dict[str, Any]]:
    """`n` parent techniques with no rule in any mode and no hunt data; the
    first `need_sources` of them also map to at least one nano source type."""
    wait_catalog(client)
    cov = coverage(client)
    layer = hunt_layer(client) or {}
    hunted = {t["technique_id"] for t in layer.get("techniques") or []}
    free = [
        t for t in cov.get("techniques", [])
        if not t.get("rules") and t["technique_id"] not in hunted and t.get("tactic_ids")
        and not t.get("is_subtechnique") and "." not in t["technique_id"]
    ]
    with_sources = [t for t in free if source_types(t)]
    if len(with_sources) < need_sources or len(free) < n:
        pytest.skip(f"the ATT&CK catalog has too few free techniques ({len(free)} free, {len(with_sources)} mapped)")
    picked = with_sources[:need_sources]
    picked += [t for t in free if t not in picked][: n - need_sources]
    return picked


def other_without(client: Nano, source: str, exclude: set[str]) -> str | None:
    """A parent technique whose rules and telemetry never touch `source`, nor
    any of its sub-techniques' (a matching sub keeps its parent row shown)."""
    techs = coverage(client).get("techniques", [])
    touched = {t["technique_id"].split(".")[0] for t in techs if source in source_types(t)}
    for t in techs:
        tid = t["technique_id"]
        if "." not in tid and tid not in exclude and tid not in touched and t.get("tactic_ids"):
            return tid
    return None


@dataclass
class SeededHunt:
    hunt: str
    title: str
    technique: str
    leads: list[str] = field(default_factory=list)
    ideas: list[str] = field(default_factory=list)


def seed_hunt(
    owner_email: str,
    title: str,
    technique: str,
    tactic: str,
    *,
    sweep_age: str = "1 hour",
    enabled: bool = False,
    leads: list[tuple[str, str]] = (),
    idea: str | None = None,
) -> SeededHunt:
    """A hunt targeting `technique` with one finished sweep `sweep_age` ago.

    `leads`: (class, source type) per finding, attributed to `technique` (what
    the agent found). `idea`: a rule idea in state `ready` with that name
    (the 3 sweeps / 2 promotions counters set, as the gate leaves them).
    """
    values = ", ".join(f"({sql_text(c)}, {sql_text(st)}, {i})" for i, (c, st) in enumerate(leads)) or "(NULL, NULL, 0)"
    idea_sql = "SELECT NULL::uuid AS id WHERE FALSE"
    if idea:
        idea_sql = f"""INSERT INTO hunt_rule_ideas (playbook_id, fingerprint, name, rationale, proposed_npl,
                                       proposed_severity, mitre_technique, basis_sweep_count,
                                       basis_promoted_count, state, source_types, source_types_complete)
       SELECT id, 'fp-' || gen_random_uuid(), {sql_text(idea)}, 'nano-e2e NAN-5850',
              'class_uid=3002 | stats count by actor.user.name', 'medium', {sql_text(technique)}, 3, 2,
              'ready', ARRAY['okta']::text[], TRUE FROM pb RETURNING id"""
    out = psql(f"""
WITH u AS (SELECT id FROM users WHERE email = {sql_text(owner_email)}),
pb AS (INSERT INTO playbooks (title, category, doc, kind, status, created_by)
       SELECT {sql_text(title)}, 'network', 'nano-e2e NAN-5850', 'hunt', 'draft', u.id FROM u
       RETURNING id, current_version),
sp AS (INSERT INTO hunt_specs (playbook_id, sweep_query, mitre_tactic, mitre_technique, enabled)
       SELECT id, 'x', {sql_text(tactic)}, {sql_text(technique)}, {"TRUE" if enabled else "FALSE"} FROM pb
       RETURNING playbook_id),
sw AS (INSERT INTO hunt_sweeps (playbook_id, playbook_version, trigger, status, outcome, started_at, finished_at)
       SELECT pb.id, pb.current_version, 'manual', 'finished', 'completed',
              NOW() - INTERVAL {sql_text(sweep_age)} - INTERVAL '5 minutes', NOW() - INTERVAL {sql_text(sweep_age)}
         FROM pb, sp RETURNING id, playbook_id, playbook_version),
v(cls, st, n) AS (VALUES {values}),
l AS (INSERT INTO hunt_leads (sweep_id, playbook_id, playbook_version, entity_type, entity_value,
                              window_start, window_end, score, fingerprint, class, class_source,
                              state, mitre_technique, source_types, source_types_complete)
      SELECT sw.id, sw.playbook_id, sw.playbook_version, 'host', 'cov-' || v.n || '-' || {sql_text(title)},
             NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', 0.5, 'fp-' || gen_random_uuid(),
             v.cls, 'investigator', 'unreviewed', {sql_text(technique)}, ARRAY[v.st]::text[], TRUE
        FROM sw, v WHERE v.cls IS NOT NULL
      RETURNING id),
i AS ({idea_sql})
SELECT json_build_object('hunt', (SELECT id FROM pb),
                         'leads', (SELECT coalesce(json_agg(id), '[]') FROM l),
                         'ideas', (SELECT coalesce(json_agg(id), '[]') FROM i));
""")
    body = json.loads(out.splitlines()[-1])
    return SeededHunt(body["hunt"], title, technique, body["leads"], body["ideas"])


def drop_hunt(seeded: SeededHunt) -> None:
    psql(f"DELETE FROM playbooks WHERE id = {sql_text(seeded.hunt)}::uuid;")


def make_rule(client: Nano, name: str, mark: str, technique: str, tactic: str, mode: str) -> dict[str, Any]:
    return expect(client.api.post("/api/rules", json={
        "name": name, "description": "nano-e2e unified coverage (NAN-5850)", "query": f'"{mark}"',
        "severity": "low", "mode": mode, "detection_mode": "scheduled", "schedule_cron": IDLE_CRON,
        "lookback_minutes": 15, "folder": FOLDER, "mitre_tactics": [tactic], "mitre_techniques": [technique],
    }), 200, 201)


EVERYONE_GROUP = "00000000-0000-0000-0000-000000000001"


@contextmanager
def persona_outside_everyone(
    stack: Any, nano: Nano, ui: Any, artifact_dir: Path, label: str, permissions: list[str]
) -> Iterator[Any]:
    """`soar_ui.persona`, but the throwaway user leaves the Everyone group
    before logging in. Everyone is bound to ReadOnly (detections:view,
    mitre:view, ...), so only a user outside it can hold hunts:view WITHOUT
    detections:view (design 6, Q2)."""
    from nano_e2e import ui as uilib
    from nano_e2e.client import Journal
    from nano_e2e.rbac import limited_user
    from nano_e2e.soar_ui import Persona, user_id

    journal = Journal(artifact_dir / f"{label}.jsonl")
    with limited_user(stack, label, permissions, journal) as user:
        psql(f"DELETE FROM user_groups WHERE group_id = {sql_text(EVERYONE_GROUP)}::uuid "
             f"AND user_id = (SELECT id FROM users WHERE email = {sql_text(user.email)});")
        login = Nano(stack.api_url, stack.search_url, {}, journal)
        jwt = login.login(user.email, user.password)
        login.close()
        client = Nano(stack.api_url, stack.search_url, {"Authorization": f"Bearer {jwt}"}, journal)
        page = uilib.UiPage.open(ui, artifact_dir / f"ui-{label}", label)
        failed = True
        try:
            uilib.login(page, user.email, user.password)
            yield Persona(user, user_id(nano, user.email), client, page)
            failed = False
        finally:
            page.finish(failed)
            client.close()
