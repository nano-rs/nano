"""UI scenarios for open-core features that have not merged to clickhouse/dev
yet. Each is an EXPLICIT skip naming the issue and its branch, so it shows in
every report (never silently missing); the lane that lands the feature fills
it in on top of this harness, replacing the skip with the steps in the
docstring. Enterprise-only features' placeholders live in tests/enterprise/ui
(stripped from the open-core mirror).
"""

from __future__ import annotations

import pytest


def _pending(issue: str, branch: str, what: str) -> None:
    pytest.skip(f"{what}: not on clickhouse/dev yet ({issue}, branch {branch}); fill in when it merges")


def test_search_backend_tree_lateral_cloud_queued() -> None:
    """Progressive tree preview then exact pages; lateral hop-by-hop graph;
    cloud overview cards; a "queued" state under load instead of an error."""
    _todo("search backend views (merged 29abe8480)", "NAN-4928")


def test_key_ring_short_key_and_rotation() -> None:
    """Key ring: status shows the short-key warning; rotating keeps stored
    credentials decrypting (a pull source keeps reading)."""
    _todo("key ring (merged 55345bccf)", "NAN-4933")


# Merged features whose browser scenarios are not written yet: explicit, so
# the report shows the gap (NAN-4937 follow-up), never a silent omission.
def _todo(what: str, issue: str) -> None:
    pytest.skip(f"{what}: on dev, browser scenario not written yet (NAN-4937 follow-up; feature {issue})")


@pytest.mark.parametrize(
    "scenario",
    [
        "timechart == API buckets",
        "histogram partial edge buckets",
        "fired-match pivot carries query and window",
    ],
)
def test_search_ux_followups(scenario: str) -> None:
    _todo(f"search: {scenario}", "NAN-4927")


def test_add_source_negative_paths() -> None:
    """Bad cloud credential surfaces on the source (quarantine: NAN-4936,
    branch fix/NAN-4936-vector-quarantine); an expired token is refused; a
    token used on the wrong transport is refused or routed as documented."""
    pytest.skip(
        "negative ingestion paths: bad-credential quarantine not on dev yet (NAN-4936, branch "
        "fix/NAN-4936-vector-quarantine); expired/wrong-transport expectations not written yet "
        "(NAN-4937 follow-up)"
    )
