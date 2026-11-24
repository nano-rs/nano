"""The realistic seed profile (NAN-5764) cannot quietly shrink back into a
tiny, short-named, UDM-shaped seed.

Pure checks on `nano_e2e.realistic_plan` (no stack):

- deterministic: the same seed builds the same plan, byte for byte, and no
  name depends on the run id or the clock (idempotent re-runs find them);
- the issue's list holds: 20+ pending approvals (some case-linked), long rule,
  case and hunt titles, many tags (one case at the 32-tag limit), hundreds of
  hosts and users, several log sources of every ingest method, hunt findings
  with long narratives, deleted / archived / imported-then-deleted objects;
- real-world strings: unicode, apostrophes, very long UPNs and FQDNs;
- rules are snake_case in the dedicated "Automated" folder (never a display
  title, never Uncategorized);
- OCSF only: every event carries an OCSF class and none a UDM column.
"""

from __future__ import annotations

import json
from collections import Counter

import pytest
from nano_e2e import realistic_plan as rp
from nano_e2e import realistic_seed

UDM_COLUMNS = {
    "src_ip",
    "dest_ip",
    "src_host",
    "dest_host",
    "process_name",
    "command_line",
    "dest_port",
    "file_hash",
    "auth_result",
    "src_user",
}


@pytest.fixture(scope="module")
def plan() -> rp.Plan:
    return rp.build()


def test_the_plan_is_deterministic_and_run_independent(plan: rp.Plan, monkeypatch) -> None:
    assert rp.digest(plan) == rp.digest(rp.build())
    monkeypatch.setenv("E2E_RUN_ID", "someone-else-12345678")
    monkeypatch.setenv("E2E_SESSION", "abcdef")
    assert rp.digest(rp.build()) == rp.digest(plan), "a seeded name depends on the run or the session"
    assert rp.digest(rp.build(seed=1)) != rp.digest(plan), "the seed does not drive the content"
    names = json.dumps(
        [r.name for r in plan.rules] + [c.title for c in plan.cases] + [s.name for s in plan.sources]
    )
    assert "nano-e2e-" not in names, "a seeded name carries a run marker (it would differ per run)"


def test_every_name_is_unique_and_stable(plan: rp.Plan) -> None:
    for kind, names in {
        "rule": [r.name for r in plan.rules],
        "case": [c.title for c in plan.cases],
        "hunt": [h.title for h in plan.hunts] + [d.title for d in plan.drafts],
        "source": [s.name for s in plan.sources],
        "route key": [s.route_key for s in plan.sources],
        "flow": [f.name for f in plan.flows],
        "dashboard": [d.name for d in plan.dashboards],
        "event uid": [e["metadata"]["uid"] for e in plan.events],
    }.items():
        dupes = [n for n, c in Counter(names).items() if c > 1]
        assert not dupes, f"duplicate {kind} names break idempotent lookup: {dupes[:3]}"
        assert all(rp.KEY in n for n in names), f"a {kind} lacks the stable {rp.KEY} key"


def test_the_issue_list_holds(plan: rp.Plan) -> None:
    assert plan.pending_approvals >= rp.MIN_APPROVALS
    assert plan.case_linked_approvals >= rp.MIN_CASE_LINKED_APPROVALS
    assert plan.case_linked_approvals < plan.pending_approvals, "some approvals must NOT be case-linked"
    assert plan.soar_catalog == "all"
    assert len(plan.hosts) >= rp.MIN_HOSTS and len(plan.users) >= rp.MIN_USERS
    seen_hosts = {e["device"]["hostname"] for e in plan.events}
    seen_users = {e["actor"]["user"]["name"] for e in plan.events if "actor" in e}
    assert seen_hosts == set(plan.hosts), "a planned host never appears in an event"
    assert seen_users == set(plan.users), "a planned user never appears in an event"
    assert max(len(r.name) for r in plan.rules) >= 90
    assert max(len(c.title) for c in plan.cases) >= rp.MIN_LONG
    assert max(len(h.title) for h in plan.hunts) >= rp.MIN_LONG
    assert max(len(s.name) for s in plan.sources) >= 90
    assert max(len(d.name) for d in plan.dashboards) >= 90
    assert max(len(c.tags) for c in plan.cases) == 32, "one case must sit at the 32-tag limit"
    assert all(rp.CASE_TAG.match(t) for c in plan.cases for t in c.tags), "a case tag the API refuses"
    assert any(not c.tags for c in plan.cases), "one case has no tags at all"
    assert max(len(r.tags) for r in plan.rules) >= 12
    methods = Counter(s.method for s in plan.sources if not s.deleted)
    for method in ("routed", "splunk_hec", "vector"):
        assert methods[method] >= 3, f"fewer than three {method} log sources"
    # A fetch method without a bound source configuration breaks every Vector
    # render on the install (NAN-5789): never seed one.
    assert not set(methods) & {"kafka", "aws_s3", "aws_sqs", "gcp_pubsub", "azure_event_hubs"}
    findings = [f for h in plan.hunts for f in h.findings]
    assert len(findings) >= 8 and max(len(f.narrative) for f in findings) >= 2000
    assert {"lead", "benign"} <= {f.finding_class for f in findings}
    assert plan.drafts, "no hunt drafts"


def test_dead_objects_are_part_of_the_picture(plan: rp.Plan) -> None:
    assert any(s.deleted for s in plan.sources)
    assert any(r.archived for r in plan.rules)
    assert any(r.imported_then_deleted for r in plan.rules)
    assert any(c.deleted for c in plan.cases)
    assert any(h.archived for h in plan.hunts)
    assert {"open", "in_progress", "resolved", "closed"} <= {c.status for c in plan.cases}
    assert {"staging", "live", "alerting"} <= {r.mode for r in plan.rules}
    assert any(r.fire for r in plan.rules), "no rule raises real alerts"


def test_real_world_strings(plan: rp.Plan) -> None:
    def non_ascii(values) -> bool:
        return any(any(ord(ch) > 127 for ch in v) for v in values)

    assert non_ascii(plan.users) and non_ascii(plan.hosts)
    assert non_ascii(c.title for c in plan.cases)
    assert non_ascii(s.name for s in plan.sources)
    assert any("'" in u for u in plan.users)
    assert max(len(u) for u in plan.users) >= 80 and max(len(h) for h in plan.hosts) >= 80
    assert any(len(u) <= 1 for u in plan.users), "a one-character user name (the other edge)"


def test_rules_are_snake_case_in_the_automated_folder(plan: rp.Plan) -> None:
    assert rp.FOLDER == "Automated"
    for rule in plan.rules:
        assert rp.SNAKE.match(rule.name), f"rule name is not snake_case: {rule.name!r}"
    for flow in plan.flows:
        assert rp.SNAKE.match(flow.name), f"flow name is not snake_case: {flow.name!r}"


def test_rule_bodies_use_the_folder_and_an_idle_schedule(plan: rp.Plan) -> None:
    cat = {"techniques": [{"id": "T1110", "tactic_ids": ["TA0006"]}]}
    for spec in plan.rules:
        body = realistic_seed._rule_body(spec, cat)
        assert body["folder"] == "Automated" and body["folder"] != "Uncategorized"
        assert body["schedule_cron"] == rp.IDLE_CRON, "a seeded rule must only fire when the seed triggers it"
        assert set(body["mitre_techniques"]) <= {"T1110"}, "techniques absent from the catalog are not sent"


def test_events_are_ocsf_only(plan: rp.Plan) -> None:
    for e in plan.events:
        assert e["class_uid"] in (1007, 3002, 4001) and e["category_uid"] and e["type_uid"]
        assert e["metadata"]["version"].startswith("1.") and e["metadata"]["product"]["name"] == rp.PRODUCT
        assert not (UDM_COLUMNS & set(e)), f"a UDM column in a seeded event: {UDM_COLUMNS & set(e)}"
    for rule in plan.rules:
        assert not any(f"{col}=" in rule.query for col in UDM_COLUMNS), rule.query
    assert realistic_seed.LANE_PARSER.count("\n") == 1, "the lane parser must not reshape events (OCSF in)"


def test_the_profile_is_opt_in(monkeypatch) -> None:
    monkeypatch.delenv(realistic_seed.PROFILE_ENV, raising=False)
    assert not realistic_seed.enabled()
    monkeypatch.setenv(realistic_seed.PROFILE_ENV, "realistic")
    assert realistic_seed.enabled()
    monkeypatch.setenv(realistic_seed.PROFILE_ENV, "tiny")
    assert not realistic_seed.enabled()


def test_deleted_object_names_fit_the_audit_search(plan: rp.Plan) -> None:
    """A deleted object is recognised by an audit `q=<name>` search, which the
    API truncates at 256 characters: a longer name would never match."""
    names = [s.name for s in plan.sources if s.deleted] + [c.title for c in plan.cases if c.deleted]
    names += [h.title for h in plan.hunts if h.archived]
    assert names
    assert all(len(n) <= 256 for n in names), [n for n in names if len(n) > 256]
