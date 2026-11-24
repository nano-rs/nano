"""Zero-clicks plumbing (NAN-5763): the in-process write guard refuses every
API click outside the data-flow allowlist, and the audit premise check fails
loudly on a degraded or empty audit store instead of passing vacuously."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from nano_e2e import zero_clicks as zc

API = "http://127.0.0.1:5555"


@pytest.fixture
def guarded():
    zc.blocked_writes.clear()
    undo = zc.guard_api_writes(API)
    assert undo is not None
    yield httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})), base_url=API)
    undo()
    zc.blocked_writes.clear()


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/content/channels"),
        ("POST", "/api/auth/login"),
        ("POST", "/api/log-sources"),
        ("POST", "/api/log-sources/ls_1/publish"),
        ("DELETE", "/api/log-sources/ls_1"),
        ("POST", "/api/ingest-tokens"),
        ("POST", "/api/ingest-tokens/cred_1/revoke"),
    ],
)
def test_guard_allows_reads_and_the_data_flow_source(guarded: httpx.Client, method: str, path: str) -> None:
    assert guarded.request(method, path).status_code == 200
    assert zc.blocked_writes == []


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/content/channels/check"),
        ("POST", "/api/content/channels/import"),
        ("POST", "/api/playbook-repositories/pbrep_1/sync-and-import"),
        ("POST", "/api/playbook-repositories/pbrep_1/playbooks/import-all"),
        ("POST", "/api/rule-repositories/rrep_1/sync"),
        ("POST", "/api/hunts/profile/run"),
        ("PUT", "/api/soar/settings"),
        ("POST", "/api/log-sources/ls_1/deploy"),
    ],
)
def test_guard_refuses_every_other_api_write(guarded: httpx.Client, method: str, path: str) -> None:
    with pytest.raises(AssertionError, match="is a click"):
        guarded.request(method, path)
    assert zc.blocked_writes == [f"{method} {path}"]


def test_guard_ignores_other_hosts_and_installs_once(guarded: httpx.Client) -> None:
    hec = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200)), base_url="http://127.0.0.1:6666")
    assert hec.post("/services/collector/event").status_code == 200
    assert zc.guard_api_writes(API) is None


class _FakeNano:
    def __init__(self, answer: Any):
        self.api = self
        self.answer = answer

    def get(self, path: str, params: dict[str, Any]) -> httpx.Response:
        body = self.answer(params["action"]) if callable(self.answer) else self.answer
        return httpx.Response(200, json=body, request=httpx.Request("GET", f"{API}{path}"))


def test_audit_check_fails_when_the_audit_store_is_degraded() -> None:
    nano = _FakeNano({"logs": [], "total": 0, "degraded": True, "degraded_reason": "clickhouse down"})
    with pytest.raises(AssertionError, match="degraded"):
        zc.manual_content_actions(nano)  # type: ignore[arg-type]


def test_audit_check_fails_when_this_runs_setup_rows_are_missing() -> None:
    nano = _FakeNano({"logs": [], "total": 0, "degraded": False})
    with pytest.raises(AssertionError, match="system_initialized"):
        zc.manual_content_actions(nano)  # type: ignore[arg-type]


def test_audit_check_reports_a_click_by_a_user_and_ignores_the_leader() -> None:
    def answer(action: str) -> dict[str, Any]:
        rows = {
            "system_initialized": [{"action": action, "user_id": "user_1"}],
            "log_source_published": [{"action": action, "api_key_id": "key_1"}],
            "playbook_library_delivered": [{"action": action, "user_id": None}],
            "content_channels_checked": [{"action": action, "user_id": "user_1", "user_name": "e2e admin"}],
        }.get(action, [])
        return {"logs": rows, "total": len(rows), "degraded": False}

    hits = zc.manual_content_actions(_FakeNano(answer))  # type: ignore[arg-type]
    assert [h["action"] for h in hits] == ["content_channels_checked"]
