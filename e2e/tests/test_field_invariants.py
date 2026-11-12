"""Every field name the API shows or suggests is an OCSF field of this stack (NAN-5291).

`scripts/e2e.sh run field_invariants --run <id>` against a kept OCSF stack
(load the corpus first, `python -m nano_e2e.corpus`, for a meaningful
universe). Set E2E_FIELD_INVARIANTS_UI=1 to include the browser surfaces.
Violations are listed per surface/name/kind; warnings do not fail.
"""

from __future__ import annotations

import os

import pytest

from nano_e2e import field_invariants
from nano_e2e.client import Nano
from nano_e2e.stack import Stack


def test_shown_field_names_are_ocsf(stack: Stack, nano: Nano, artifact_dir) -> None:
    universe = field_invariants.load_universe(stack, nano.api)
    if universe.schema != "ocsf":
        pytest.skip("field invariants apply to OCSF stacks (NANO_SCHEMA_PROFILE=ocsf)")
    seen = field_invariants.collect_api(stack, nano.api, nano.search_http)
    if os.environ.get("E2E_FIELD_INVARIANTS_UI") == "1":
        from nano_e2e import explore

        with explore.session(stack, out=artifact_dir / "ui") as page:
            seen += field_invariants.collect_ui(page)
    violations = field_invariants.check(seen, universe)
    text = field_invariants.report(violations, seen, universe)
    (artifact_dir / "field-invariants.txt").write_text(text + "\n")
    errors = [v for v in violations if v.severity == "error"]
    assert not errors, text
