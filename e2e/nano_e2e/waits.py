"""Polling helpers. Scenarios never sleep blindly; they wait for an observable
condition and, on timeout, report the last value they saw."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")

# Default deadlines (seconds), per the plan: ingest-visible 60, Vector reload
# 30, pull 180 (real cloud), detection 150.
INGEST_VISIBLE = 90.0
VECTOR_RELOAD = 30.0
PULL_VISIBLE = 240.0
DETECTION = 150.0


class Timeout(AssertionError):
    """A wait ran out. Product assertion failure (E2E-PRODUCT), never retried."""


def eventually(
    probe: Callable[[], T],
    *,
    timeout: float,
    interval: float = 2.0,
    desc: str,
    ok: Callable[[T], bool] = bool,
) -> T:
    """Call `probe` until `ok(result)` holds; return that result.

    Exceptions raised by `probe` count as "not yet" (and are reported if the
    deadline passes), so transient 5xx or connection blips during a reload do
    not fail the wait early.
    """
    deadline = time.monotonic() + timeout
    last: object = "<never evaluated>"
    while True:
        try:
            value = probe()
            if ok(value):
                return value
            last = value
        except AssertionError:
            raise
        except Exception as exc:  # noqa: BLE001 - reported on timeout
            last = f"{type(exc).__name__}: {exc}"
        if time.monotonic() >= deadline:
            raise Timeout(f"timed out after {timeout:.0f}s waiting for {desc}; last observed: {_short(last)}")
        time.sleep(interval)


def stays(
    probe: Callable[[], T],
    *,
    duration: float,
    interval: float = 3.0,
    desc: str,
    ok: Callable[[T], bool] = bool,
) -> T:
    """Assert `ok(probe())` holds for the whole `duration` (e.g. "no rows land
    while paused"). Returns the last value."""
    deadline = time.monotonic() + duration
    while True:
        value = probe()
        if not ok(value):
            raise AssertionError(f"{desc} stopped holding: {_short(value)}")
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval)


def _short(value: object, limit: int = 1500) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "...<truncated>"


_RELOAD = re.compile(r"Reloading running topology|Vector has reloaded")


def vector_reloads_quiet(project: str, quiet: float = 15.0, timeout: float = 150.0) -> float:
    """Wait until this stack's Vector has gone `quiet` seconds without a
    topology reload; returns the seconds waited.

    Publishing a log source rewrites Vector's config and it reloads, often
    several times. An event a pull connector delivers (and gets acked) during
    a reload can sit until a LATER reload flushes it (README finding "Events
    stranded by a Vector topology reload"). Scenarios that are not about that
    finding start their senders after the reloads settle.
    """
    import subprocess

    start = time.monotonic()
    while True:
        out = subprocess.run(  # noqa: S603 - fixed argv, our own container
            ["docker", "logs", "--since", f"{int(quiet)}s", f"{project}-vector"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if not _RELOAD.search(out.stdout + out.stderr):
            return time.monotonic() - start
        if time.monotonic() - start > timeout:
            raise Timeout(f"Vector kept reloading for {timeout:.0f}s")
        time.sleep(3)
