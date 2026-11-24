"""Strict LIFO cleanup for scenario-created HTTP resources."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class _Action:
    label: str
    call: Callable[[], None]


class CleanupStack:
    """Run every registered cleanup and report all failures after the last one.

    Actions are registered immediately after resource creation and run in LIFO
    order so dependent resources (user -> group -> role, token -> source) are
    removed first.  A cleanup is successful only when the product explicitly
    confirms deletion or confirms that the resource is already absent.
    """

    ACCEPTED = frozenset({200, 204, 404})

    def __init__(self) -> None:
        self._actions: list[_Action] = []

    def register_http(self, label: str, call: Callable[[], httpx.Response]) -> None:
        def checked() -> None:
            response = call()
            if response.status_code not in self.ACCEPTED:
                raise AssertionError(
                    f"HTTP {response.status_code}; expected one of {sorted(self.ACCEPTED)}"
                )

        self._actions.append(_Action(label, checked))

    def register(self, label: str, call: Callable[[], None]) -> None:
        """Register a compound cleanup that validates each HTTP call itself."""
        self._actions.append(_Action(label, call))

    def close(self) -> None:
        failures: list[Exception] = []
        while self._actions:
            action = self._actions.pop()
            try:
                action.call()
            except Exception as exc:  # noqa: BLE001 - collect so remaining cleanup still runs
                failures.append(RuntimeError(f"cleanup {action.label!r} raised {type(exc).__name__}: {exc}"))
        if failures:
            raise ExceptionGroup("one or more scenario cleanup actions failed", failures)


def after_body(label: str, call: Callable[[], object], *, body_passed: bool) -> None:
    """Run one cleanup from a scenario's `finally:` without masking its
    result (NAN-5869). A cleanup failure fails the scenario only when the body
    passed; after a body failure it is printed and the body's error stands.

        passed = False
        try:
            ...
            passed = True
        finally:
            after_body("lane source", lambda: delete(...), body_passed=passed)
    """
    try:
        call()
    except Exception as exc:  # noqa: BLE001 - reported or re-raised below
        if body_passed:
            raise
        print(f"WARNING: cleanup {label!r} failed after the scenario failed: {type(exc).__name__}: {exc}")
