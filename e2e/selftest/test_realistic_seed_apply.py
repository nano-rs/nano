"""`realistic_seed.apply` against an in-memory nano API (NAN-5764, no stack).

- a fresh run seeds the whole plan; a second run creates nothing and lists
  SOAR flows exactly once (the endpoint ignores paging);
- interrupted at any of its risky steps, the next run finishes the job with
  no duplicates: the lane gets published, the deleted source / case and the
  imported rule end up deleted, hunt findings land once on their own hunt's
  sweep, approvals are topped up to exactly the plan's count, missing events
  are sent once;
- a queued sweep of ANOTHER hunt ahead in the claim queue is never reported
  on, and every seed hunt still gets its own findings;
- ingest tokens are revoked; the session's access and refresh tokens and the
  ingest token are registered with the artifact guard and never reach the
  API journal.
"""

from __future__ import annotations

import functools
import json
import time
from collections import Counter
from pathlib import Path

import httpx
import pytest
from fake_nano_api import FakeNano
from nano_e2e import client as client_mod
from nano_e2e import realistic_plan as rp
from nano_e2e import realistic_seed as seed
from nano_e2e.stack import Stack

RUN_ID = "selftest-5764abcd"


def _labels(container: str) -> dict[str, str]:
    return {"nano.e2e.project": f"nanoe2e-{RUN_ID}", "nano.e2e.owner": str(seed.ROOT)}


@pytest.fixture
def plan() -> rp.Plan:
    return rp.build()


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeNano:
    api = FakeNano()
    monkeypatch.setattr(
        client_mod.httpx, "Client", functools.partial(httpx.Client, transport=api.transport())
    )
    monkeypatch.setattr(seed, "_hec_post", api.hec)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    monkeypatch.setattr(seed, "AUDIT_SETTLE_S", 2.0)
    monkeypatch.setattr(seed, "CATALOG_WAIT_S", 0.0)
    return api


@pytest.fixture
def stack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Stack:
    home = tmp_path / "target" / "e2e"
    run_dir = home / RUN_ID
    (run_dir / "artifacts").mkdir(parents=True)
    (run_dir / "compose.env").write_text(
        f"E2E_PROJECT=nanoe2e-{RUN_ID}\nE2E_OWNER={seed.ROOT}\nNANO_SCHEMA_PROFILE=ocsf\n"
        f"E2E_STARTED={int(time.time())}\n"
    )
    monkeypatch.setattr(seed, "E2E_HOME", home)
    monkeypatch.delenv("NANO_SCHEMA_PROFILE", raising=False)
    monkeypatch.delenv("E2E_TARGET", raising=False)
    monkeypatch.setenv("E2E_RUN_DIR", str(run_dir))
    url = "http://127.0.0.1:51001"
    return Stack(
        run_id=RUN_ID,
        project=f"nanoe2e-{RUN_ID}",
        edition="enterprise",
        app_mode="native",
        api_url=url,
        search_url="http://127.0.0.1:51002",
        jobs_url="http://127.0.0.1:51003",
        edge_url="http://127.0.0.1:51004",
        ingest_url="http://127.0.0.1:51004",
        hec_url="http://127.0.0.1:51005",
        vector_http_url="http://127.0.0.1:51006",
        otlp_http_url="",
        vector_metrics_url="http://127.0.0.1:51007/metrics",
        api_key="nano_ak_selftest_key_0123456789",
        admin_email="admin@e2e.invalid",
        admin_password="E2e-selftest-password-0123!",
        run_dir=run_dir,
        artifact_dir=run_dir / "artifacts",
        runner=seed.ROOT / "scripts" / "e2e.sh",
        vector_dynamic_dir=run_dir / "vector-dynamic",
        ch_url="http://127.0.0.1:51008",
        ch_admin_user="nanosiem_admin",
        ch_admin_password="",
    )


def _apply(stack: Stack, plan: rp.Plan) -> seed.Report:
    return seed.apply(stack, plan, labels=_labels)


def _assert_seeded(fake: FakeNano, plan: rp.Plan) -> None:
    """The stack holds exactly the plan, once."""
    names = Counter(s["name"] for s in fake.sources.values())
    wanted = {s.name for s in plan.sources if not s.deleted}
    assert set(names) == wanted and max(names.values()) == 1, names
    lane = next(
        s for s in fake.sources.values() if s["name"] == next(p.name for p in plan.sources if p.active)
    )
    assert lane["lifecycle_status"] == "active", "the lane was left a draft"
    uids = Counter(
        e["metadata"]["uid"] for e in fake.events if not e["metadata"]["uid"].startswith(f"{rp.KEY}-settle")
    )
    assert set(uids) == plan.uids() and max(uids.values()) == 1, "an event is missing or was sent twice"
    rules = Counter(r["name"] for r in fake.rules.values())
    assert set(rules) == {r.name for r in plan.rules} and max(rules.values()) == 1, rules
    for spec in plan.rules:
        rule = next(r for r in fake.rules.values() if r["name"] == spec.name)
        assert rule["folder"] == "Automated"
        assert rule["archived"] == (spec.archived or spec.imported_then_deleted), spec.name
    titles = Counter(c["title"] for c in fake.cases.values())
    assert set(titles) == {c.title for c in plan.cases if not c.deleted} and max(titles.values()) == 1
    for spec in plan.cases:
        if not spec.deleted:
            case = next(c for c in fake.cases.values() if c["title"] == spec.title)
            assert sorted(case["tags"]) == sorted(spec.tags), spec.title
            assert case["status"] == spec.status
    hunts = Counter(h["name"] for h in fake.hunts.values())
    assert max(hunts.values()) == 1, hunts
    for spec in plan.hunts:
        hunt = next(h for h in fake.hunts.values() if h["name"] == spec.title)
        assert (hunt["status"] == "archived") == spec.archived
        leads = [ld for ld in fake.leads if ld["playbook_id"] == hunt["id"]]
        want = {f.entity_value for f in spec.findings} if not spec.archived else set()
        assert Counter(ld["entity_value"] for ld in leads) == Counter(want), f"{spec.title[:40]}: {leads}"
        for ld in leads:
            assert (
                fake.sweeps[ld["sweep_id"]]["playbook_id"] == hunt["id"]
            ), "a finding on another hunt's sweep"
    per_flow = Counter(fake.runs[a["run_id"]]["flow_id"] for a in fake.approvals if a["status"] == "pending")
    for spec in plan.flows:
        fid = next(f["id"] for f in fake.flows.values() if f["name"] == spec.name)
        assert per_flow[fid] == spec.runs, (spec.name, per_flow[fid])
    assert len(fake.flows) == len(plan.flows)
    assert all(p["installed"] for p in fake.packs)
    assert all(t["revoked"] for t in fake.tokens.values()), "an ingest token was left live"
    assert not fake.sessions, "the seed left its admin session open"


def test_fresh_run_then_rerun_creates_nothing(stack: Stack, plan: rp.Plan, fake: FakeNano) -> None:
    first = _apply(stack, plan)
    assert not first.gaps, first.gaps
    _assert_seeded(fake, plan)
    fake.calls.clear()
    again = _apply(stack, plan)
    assert again.created == {}, again.created
    assert not again.gaps, again.gaps
    assert fake.calls["GET /api/soar/flows"] == 1, "SOAR flows were listed more than once"
    assert fake.calls["POST /api/ingest-tokens"] == 0, "a re-run issued an ingest token"
    _assert_seeded(fake, plan)


INTERRUPTIONS = {
    "lane created, not published": ("POST", r"/api/log-sources/[^/]+/publish$", 0),
    "deleted source created, not deleted": ("DELETE", r"/api/log-sources/", 0),
    "imported rule not deleted": ("DELETE", r"/api/rules/", 0),
    "case tags half applied": ("POST", r"/api/cases/[^/]+/tags$", 40),
    "deleted case created, not deleted": ("DELETE", r"/api/cases/", 0),
    "hunt sweep claimed, report lost": ("POST", r"/api/hunts/sweeps/[^/]+/report$", 1),
    "second hunt sweep queued, not claimed": ("POST", r"/api/hunts/runners/[^/]+/claim$", 1),
    "some approval runs started": ("POST", r"/api/soar/flows/[^/]+/run$", 9),
    "soar pack install": ("POST", r"/api/soar/packs/[^/]+/install$", 1),
}


@pytest.mark.parametrize("where", sorted(INTERRUPTIONS))
def test_an_interrupted_seed_resumes_without_duplicates(
    where: str, stack: Stack, plan: rp.Plan, fake: FakeNano
) -> None:
    method, path, skip = INTERRUPTIONS[where]
    fake.fail(method, path, skip)
    try:
        partial = _apply(stack, plan)
    except AssertionError:
        partial = None  # interrupted: the step raised
    if partial is not None:
        assert partial.gaps, f"{where}: the injected failure left no trace"
    assert not fake.faults, f"{where}: the interruption point was never reached"
    resumed = _apply(stack, plan)
    assert not resumed.gaps, f"{where}: {resumed.gaps}"
    _assert_seeded(fake, plan)
    assert _apply(stack, plan).created == {}, f"{where}: a third run still created something"


def test_events_resume_from_the_batch_that_failed(
    stack: Stack, plan: rp.Plan, fake: FakeNano, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}
    real = fake.hec

    def flaky(url: str, body: bytes, token: str) -> int:
        calls["n"] += 1
        return 503 if calls["n"] == 12 else real(url, body, token)  # mid-way through the batches

    monkeypatch.setattr(seed, "_hec_post", flaky)
    with pytest.raises(AssertionError, match="HEC refused"):
        _apply(stack, plan)
    assert all(t["revoked"] for t in fake.tokens.values()), "the interrupted run left its token live"
    sent = len(fake.events)
    assert 0 < sent < len(plan.events)
    _apply(stack, plan)
    _assert_seeded(fake, plan)
    assert len(fake.tokens) == 2, "one token per run that had events to send"


def test_a_foreign_sweep_ahead_in_the_queue_is_never_reported_on(
    stack: Stack, plan: rp.Plan, fake: FakeNano
) -> None:
    other = fake.hunt_create({}, {"title": "someone else's desktop hunt"})[1]
    fake.sweep_create({}, None, other["id"])  # queued first: the claim FIFO hands it out first
    report = _apply(stack, plan)
    foreign = next(s for s in fake.sweeps.values() if s["playbook_id"] == other["id"])
    assert foreign["reported"] == [], "the seed reported findings on another hunt's sweep"
    assert any("another hunt" in g for g in report.gaps), report.gaps
    assert not any(ld["playbook_id"] == other["id"] for ld in fake.leads)
    _assert_seeded(fake, plan)


def test_secrets_are_registered_and_kept_out_of_the_journal(
    stack: Stack, plan: rp.Plan, fake: FakeNano
) -> None:
    _apply(stack, plan)
    registry = (stack.run_dir / ".secrets.jsonl").read_text()
    for secret in fake.secrets_seen:
        assert json.dumps(secret) in registry, "a minted secret was not registered with the artifact guard"
    journal = (stack.artifact_dir / "realistic-seed-api.jsonl").read_text()
    for secret in [*fake.secrets_seen, stack.api_key, stack.admin_password]:
        assert secret not in journal, "a secret reached the API journal"
    (stack.artifact_dir / "leak.txt").write_text(f"oops {fake.secrets_seen[0]}")
    assert seed.scrub_artifacts(stack) == []
    assert fake.secrets_seen[0] not in (stack.artifact_dir / "leak.txt").read_text()


@pytest.mark.parametrize("hard", [False, True], ids=["ctrl-c", "sigkill"])
def test_a_killed_run_does_not_make_the_next_one_send_events_twice(
    hard: bool, stack: Stack, plan: rp.Plan, fake: FakeNano, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Killed mid-batch (no cleanup ran): the accepted batches are still on
    their way into search when the next run starts. It waits for them."""
    calls = {"n": 0}
    real = fake.hec

    def killed(url: str, body: bytes, token: str) -> int:
        calls["n"] += 1
        if calls["n"] == 12:
            raise KeyboardInterrupt  # not an Exception: the run's own wait does not run
        return real(url, body, token)

    monkeypatch.setattr(seed, "_hec_post", killed)
    if hard:  # SIGKILL: not even the token's revoke ran
        monkeypatch.setattr(client_mod.Nano, "revoke_token", lambda self, cred: None)
    with pytest.raises(KeyboardInterrupt):
        _apply(stack, plan)
    monkeypatch.undo()
    monkeypatch.setattr(
        client_mod.httpx, "Client", functools.partial(httpx.Client, transport=fake.transport())
    )
    monkeypatch.setattr(seed, "_hec_post", real)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    monkeypatch.setattr(seed, "AUDIT_SETTLE_S", 2.0)
    monkeypatch.setattr(seed, "CATALOG_WAIT_S", 0.0)
    monkeypatch.setattr(seed, "E2E_HOME", stack.run_dir.parent)
    monkeypatch.setenv("E2E_RUN_DIR", str(stack.run_dir))
    assert any(not t["revoked"] for t in fake.tokens.values()) == hard
    fake.latency = 2  # still in flight when the next run looks
    _apply(stack, plan)
    _assert_seeded(fake, plan)
