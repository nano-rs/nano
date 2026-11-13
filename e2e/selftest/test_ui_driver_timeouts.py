"""NAN-5335: a UI op's `timeout` (ms) reaches the browser driver, and the
Python read bound follows it (it was swallowed as the read timeout, so every
browser wait ran at the driver's 20 s default)."""

from __future__ import annotations

import io
import itertools
import json
import threading
from typing import Any

import pytest

from nano_e2e import ui


class _FakeProc:
    def __init__(self) -> None:
        self.stdin = io.StringIO()
        self.stdout = io.StringIO()


def _driver(monkeypatch: pytest.MonkeyPatch) -> tuple[ui.Driver, _FakeProc, list[float]]:
    driver = object.__new__(ui.Driver)
    proc = _FakeProc()
    driver._proc = proc  # type: ignore[attr-defined]
    driver._lock = threading.Lock()  # type: ignore[attr-defined]
    driver._ids = itertools.count(1)  # type: ignore[attr-defined]
    reads: list[float] = []

    def fake_readline(_stream: Any, timeout: float) -> str:
        reads.append(timeout)
        rid = json.loads(proc.stdin.getvalue().splitlines()[-1])["id"]
        return json.dumps({"id": rid, "ok": True, "result": None}) + "\n"

    monkeypatch.setattr(ui, "_readline", fake_readline)
    return driver, proc, reads


def _sent(proc: _FakeProc) -> dict[str, Any]:
    return json.loads(proc.stdin.getvalue().splitlines()[-1])["args"]


def test_op_timeout_is_forwarded_and_bounds_the_read(monkeypatch: pytest.MonkeyPatch) -> None:
    driver, proc, reads = _driver(monkeypatch)
    driver.call("wait_text", sid=1, text="x", timeout=300_000)
    assert _sent(proc)["timeout"] == 300_000
    assert reads[-1] == pytest.approx(330.0)


def test_short_op_keeps_the_hung_driver_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    driver, proc, reads = _driver(monkeypatch)
    driver.call("wait_for", sid=1, find={"testid": "x"}, timeout=20_000)
    assert _sent(proc)["timeout"] == 20_000
    assert reads[-1] == ui.OP_TIMEOUT


def test_none_timeout_is_not_sent_as_null(monkeypatch: pytest.MonkeyPatch) -> None:
    driver, proc, reads = _driver(monkeypatch)
    driver.call("click", sid=1, find={"testid": "x"}, timeout=None)
    assert "timeout" not in _sent(proc)
    assert reads[-1] == ui.OP_TIMEOUT
