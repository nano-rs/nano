"""`realistic_seed`: the realistic seed profile (NAN-5764) for the UI suites.

Opt-in: `E2E_SEED_PROFILE=realistic` (`scripts/e2e.sh run ui --seed
realistic`). The fixture is autouse in `tests/ui/` and `tests/enterprise/ui/`
and does nothing unless the profile is selected, so the default UI run keeps
its speed. When selected, the seed is applied ONCE per pytest session, before
the first scenario, and is idempotent, so a kept stack re-run adds nothing.

Gaps (a step the stack could not do, e.g. no SOAR catalog published yet) are
printed and recorded in `<artifacts>/realistic-seed.json`;
`E2E_SEED_STRICT=1` fails the session on any gap instead.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from nano_e2e import realistic_seed, schema
from nano_e2e.client import Journal
from nano_e2e.stack import Stack

# Both UI conftests import the fixture (two fixture instances in one session):
# the seed is applied by whichever runs first, once per process.
_APPLIED: dict[str, realistic_seed.Report] = {}


@pytest.fixture(scope="session", autouse=True)
def realistic_seed_profile(request: pytest.FixtureRequest) -> Iterator[realistic_seed.Report | None]:
    if not realistic_seed.enabled():
        yield None
        return
    stack: Stack = request.getfixturevalue("stack")
    if stack.target == "existing":
        pytest.fail("the realistic seed writes to the stack: never with --target existing", pytrace=False)
    if not schema.is_ocsf():
        pytest.fail("the realistic seed is OCSF only; this stack runs the legacy udm profile", pytrace=False)
    if stack.run_id in _APPLIED:
        yield _APPLIED[stack.run_id]
        return
    try:
        report = realistic_seed.apply(stack, journal=Journal(stack.artifact_dir / "realistic-seed-api.jsonl"))
    except realistic_seed.UnsafeTarget as exc:
        pytest.fail(str(exc), pytrace=False)
    _APPLIED[stack.run_id] = report
    summary = {k: v for k, v in report.as_dict().items() if k in ("created", "existing", "seconds")}
    print(f"\nrealistic seed (NAN-5764): {summary}")
    for gap in report.gaps:
        print(f"WARNING: realistic seed gap: {gap}")
    if report.gaps and os.environ.get("E2E_SEED_STRICT") == "1":
        pytest.fail("realistic seed gaps (E2E_SEED_STRICT=1):\n" + "\n".join(report.gaps), pytrace=False)
    yield report
