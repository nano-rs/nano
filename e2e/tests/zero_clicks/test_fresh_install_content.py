"""Zero clicks, open core (NAN-5763): content a fresh install gets on its own.

A fresh stack, nothing clicked: the content channels check by themselves
shortly after the jobs leader starts, and the official rules, parsers,
enrichment catalog and MITRE ATT&CK catalog are installed, applied and synced
without a sync, import or check call. Every edition runs this module; the
enterprise companion (tests/enterprise/zero_clicks) adds playbooks, SOAR,
recon and hunts.

Run: `scripts/e2e.sh run zero_clicks --edition open|enterprise` (owns a fresh
stack; the scenarios skip anywhere else).
"""

from __future__ import annotations

from typing import Any

import pytest

from nano_e2e import zero_clicks as zc
from nano_e2e.client import Nano
from nano_e2e.client import expect as api_expect

# Any one wait may use the whole shared budget (pyproject's 900 s default would cut it).
pytestmark = [pytest.mark.slow, pytest.mark.timeout(zc.TEST_TIMEOUT_S)]

# Open channels every build subscribes to on the OCSF profile.
OPEN_CHANNELS = ("parsers.main", "rules.main", "enrichments.main", "mitre-attack.v19-1")


@pytest.fixture(autouse=True)
def _fresh() -> None:
    zc.require_fresh_stack()


def test_open_content_channels_install_and_apply_on_their_own(nano: Nano, timeline) -> None:
    status, ok = zc.settle(
        lambda: zc.channels(nano),
        lambda chans: all(zc.channel_problems(chans.get(c)) is None for c in OPEN_CHANNELS),
    )
    problems = {c: zc.channel_problems(status.get(c)) for c in OPEN_CHANNELS}
    assert ok, f"open content channels not applied after {zc.elapsed()}s with no click: {problems}"
    timeline.step(
        "open channels applied",
        after_s=zc.elapsed(),
        sequences={c: status[c]["sequence"] for c in OPEN_CHANNELS},
    )


@pytest.mark.parametrize(
    ("path", "suffix", "count_field", "catalog"),
    [
        ("/api/rule-repositories", "nano-rs/rules", "rule_count", "rules"),
        ("/api/parser-repositories", "nano-rs/parsers", "parser_count", "parsers"),
    ],
    ids=["rules", "parsers"],
)
def test_official_repository_synced_without_a_click(
    nano: Nano, timeline, path: str, suffix: str, count_field: str, catalog: str
) -> None:
    def synced(repo: dict[str, Any] | None) -> bool:
        return bool(repo) and repo.get("last_sync_status") == "success" and int(repo.get(count_field) or 0) > 0

    repo, ok = zc.settle(lambda: zc.official_repo(nano, path, suffix), synced)
    assert repo is not None, f"no official {suffix} repository is followed on a fresh install"
    assert ok, (
        f"official {suffix} not synced after {zc.elapsed()}s with no click: "
        f"status={repo.get('last_sync_status')} {count_field}={repo.get(count_field)} error={repo.get('last_sync_error')}"
    )
    body = api_expect(nano.api.get(f"{path}/{repo['id']}/{catalog}"), 200)
    listed = len(zc.rows(body, catalog))
    assert listed > 0, f"{suffix} reports {repo[count_field]} entries but its catalog lists none: {str(body)[:500]}"
    timeline.step(f"{suffix} synced", after_s=zc.elapsed(), count=repo[count_field], listed=listed)


def test_mitre_catalog_populated_without_a_click(nano: Nano, timeline) -> None:
    def populated(body: dict[str, Any]) -> bool:
        state = body.get("sync_state") or {}
        return bool(body.get("tactics")) and bool(body.get("techniques")) and state.get("status") == "succeeded"

    body, ok = zc.settle(lambda: api_expect(nano.api.get("/api/mitre"), 200), populated)
    assert ok, (
        f"MITRE ATT&CK catalog empty after {zc.elapsed()}s with no click: "
        f"{len(body.get('tactics') or [])} tactics, {len(body.get('techniques') or [])} techniques, "
        f"sync_state={body.get('sync_state')}"
    )
    # Delivered by the signed channel, not a bundled seed or a GitHub fetch.
    source = str(body["sync_state"].get("source_url") or "")
    assert source.startswith("nano-content://mitre-attack."), f"MITRE catalog not from its content channel: {source!r}"
    ids = {t.get("id") for t in body["techniques"]}
    assert "T1059" in ids, f"the ATT&CK catalog lacks T1059 (Command and Scripting Interpreter): {len(ids)} techniques"
    timeline.step(
        "MITRE catalog",
        tactics=len(body["tactics"]),
        techniques=len(body["techniques"]),
        sync_state=body["sync_state"],
    )


def test_nothing_was_clicked(nano: Nano) -> None:
    """The premise: no person or API key ran a content action on this stack."""
    assert zc.blocked_writes == [], f"a helper tried to click (refused): {zc.blocked_writes}"
    hits = zc.manual_content_actions(nano)
    assert hits == [], f"a content action was clicked, so this run proves nothing: {hits}"
