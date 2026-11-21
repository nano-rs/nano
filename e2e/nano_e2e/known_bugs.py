"""Known product bugs pinned inside an otherwise-asserting scenario (NAN-5681,
tightened in NAN-5684).

A whole-test `xfail` hides every unrelated regression in the steps before the
bug, and `strict=False` lets a fixed bug read as XPASS forever. Wrap ONLY the
step that hits the bug, and describe the bug's own symptom, not the step:

    with known_bug("NAN-5693", r"^(?:[4-9]|[1-9]\\d+) rows for `head 3`"):
        assert len(rows) == 3, f"{len(rows)} rows for `head 3`"

    with known_bug("NAN-5694", r"^OUTPUT values all None:", when=lambda e: ...):
        ...

- the step raises an exception of type `raises` (default `AssertionError`),
  its message matches `signature` (`re.search`, MULTILINE: `^`/`$` anchor
  the message's lines, since pytest appends its assertion rewrite) and the
  optional `when`
  predicate accepts it: the test is XFAIL with the bug id (still there);
- the step raises anything else (another type, another message, or `when`
  says no): the failure propagates (a new regression stays red);
- the step passes: the test FAILS, asking for the marker to be removed
  (strict), so a fixed bug never hides a later re-regression.

The signature must describe the bug, so catch-alls are refused at the call
site: a pattern that matches the empty string or any of `GENERIC_FAILURES`
(driver timeouts, bare assertion text, HTTP errors, a static "BUG <slug>"
prefix) raises `ValueError`, and so does `raises=Exception` /
`BaseException`. Put the step's healthy preconditions (no page errors, the
control exists, rows rendered at all) OUTSIDE the `with`, and make the
asserted message carry the symptom (counts, values) the signature matches.

The coverage gate (scripts/release/check-e2e-coverage.py) reads `known_bug(` /
`xfail` in a test as "known broken": such a test never counts as covering a
surface, and the manifest entry must name the bug (`"known_broken"`).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest

BUG_ID = re.compile(r"^NAN-\d+$")
MIN_SIGNATURE = 8

# Failures that say nothing about a specific bug. A signature matching any of
# them would also swallow unrelated regressions, so it is refused.
GENERIC_FAILURES = (
    "",
    "assert False",
    "AssertionError",
    "assert 0 == 1",
    "UI click: Error: timed out after 20000ms waiting for element {}",
    "UI wait_for: Error: timed out after 60000ms waiting for element {}; last: null",
    "UI download: Error: timed out after 30000ms waiting for a download",
    "TypeError: Cannot read properties of undefined (reading 'x')",
    "HTTP 500: Internal Server Error",
    "GET /api/x -> 403 (expected (200,))",
    "BUG some-slug: the step did not do what it should",
    "timed out after 60s waiting for something; last observed: None",
)

_BROAD = (BaseException, Exception)


def _check(bug_id: str, signature: str, raises: tuple[type[BaseException], ...]) -> re.Pattern[str]:
    if not BUG_ID.match(bug_id):
        raise ValueError(f"known_bug needs a Linear id (NAN-123), got {bug_id!r}")
    if not isinstance(signature, str) or len(signature.strip()) < MIN_SIGNATURE:
        raise ValueError(f"{bug_id}: signature {signature!r} is too short to describe a bug")
    try:
        # MULTILINE: pytest appends its assertion rewrite ("\nassert 50 == 73")
        # to the message, so `^…$` anchors the message's own lines.
        rx = re.compile(signature, re.MULTILINE)
    except re.error as exc:
        raise ValueError(f"{bug_id}: signature {signature!r} is not a regex: {exc}") from exc
    broad = [g for g in GENERIC_FAILURES if rx.search(g)]
    if broad:
        raise ValueError(
            f"{bug_id}: signature {signature!r} is a catch-all (it matches the generic failure {broad[0]!r}); "
            "match the bug's own symptom instead"
        )
    for t in raises:
        if not (isinstance(t, type) and issubclass(t, BaseException)):
            raise ValueError(f"{bug_id}: raises={t!r} is not an exception type")
        if t in _BROAD:
            raise ValueError(f"{bug_id}: raises={t.__name__} would catch every failure; name the specific type")
    return rx


@contextmanager
def known_bug(
    bug_id: str,
    signature: str,
    *,
    raises: type[BaseException] | tuple[type[BaseException], ...] = AssertionError,
    when: Callable[[BaseException], bool] | None = None,
) -> Iterator[None]:
    types = raises if isinstance(raises, tuple) else (raises,)
    rx = _check(bug_id, signature, types)
    try:
        yield
    except types as exc:
        if rx.search(str(exc)) and (when is None or when(exc)):
            pytest.xfail(f"{bug_id} (known bug, still present): {str(exc)[:300]}")
        raise
    pytest.fail(
        f"{bug_id} looks fixed: this step passed. Remove its known_bug(...) wrapper and the manifest's "
        f'"known_broken" entry so the step asserts again.',
        pytrace=False,
    )
