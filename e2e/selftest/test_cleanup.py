"""Cleanup registration must be strict without becoming fail-fast."""

import httpx
import pytest

from nano_e2e.cleanup import CleanupStack


def response(status: int) -> httpx.Response:
    return httpx.Response(status, request=httpx.Request("DELETE", "http://e2e.invalid/resource"))


def test_cleanup_is_lifo_and_accepts_only_deleted_or_absent_statuses() -> None:
    calls: list[str] = []
    cleanup = CleanupStack()
    cleanup.register_http("role", lambda: calls.append("role") or response(200))
    cleanup.register_http("group", lambda: calls.append("group") or response(204))
    cleanup.register_http("user", lambda: calls.append("user") or response(404))

    cleanup.close()

    assert calls == ["user", "group", "role"]


def test_cleanup_runs_remaining_actions_before_surfacing_every_failure() -> None:
    calls: list[str] = []
    cleanup = CleanupStack()
    cleanup.register_http("role", lambda: calls.append("role") or response(500))
    cleanup.register("group", lambda: (_ for _ in ()).throw(ConnectionError("offline")))
    cleanup.register_http("user", lambda: calls.append("user") or response(204))

    with pytest.raises(ExceptionGroup) as raised:
        cleanup.close()

    assert calls == ["user", "role"]
    assert len(raised.value.exceptions) == 2
    assert "group" in str(raised.value.exceptions[0])
    assert "role" in str(raised.value.exceptions[1])
