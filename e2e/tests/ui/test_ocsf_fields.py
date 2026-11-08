"""The search fields sidebar on an OCSF stack: profile-aware (OCSF canonical
columns; keys outside OCSF grouped as `Unmapped`, never the UDM `Extended`),
and for each OCSF field the values and percentages it shows equal the search
API's `stats count by <field>` for the same query."""

from __future__ import annotations

import pytest

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually


def _percentages(groups: dict[str, int]) -> dict[str, float]:
    total = sum(groups.values())
    return {k: round(100 * v / total, 1) for k, v in groups.items()}


@pytest.mark.parametrize(
    "field_name",
    [
        "actor.user.name",
        "src_endpoint.ip",
        "device.hostname",
        pytest.param(
            "metadata.log_source",
            marks=pytest.mark.xfail(
                strict=True,
                reason="product finding (NAN-4937): on an OCSF stack the fields sidebar lists "
                "`source_type`, not `metadata.log_source` (result chips and the API use metadata.log_source)",
            ),
        ),
    ],
)
def test_ocsf_sidebar_field_matches_api(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, page: uilib.UiPage, field_name: str, timeline
) -> None:
    tag = mark[-6:]
    # 4 events: alice x3 from two IPs, bob x1.
    for user, ip in (
        (f"alice-{tag}", "203.0.113.10"),
        (f"alice-{tag}", "203.0.113.10"),
        (f"alice-{tag}", "203.0.113.11"),
        (f"bob-{tag}", "203.0.113.12"),
    ):
        ocsf_lane.send(stack, mark, user, ip, f"host-{tag}", note="sidebar")

    def api() -> dict[str, int]:
        rows = nano.rows(f'"{mark}" | stats count by {field_name}', limit=50)
        return {str(r[field_name]): int(r["count"]) for r in rows}

    groups = eventually(
        api, timeout=INGEST_VISIBLE, desc="4 events via API", ok=lambda g: sum(g.values()) == 4
    )
    timeline.step("api", field=field_name, groups=groups)

    uilib.run_search(page, f'"{mark}"')
    # Profile-aware: OCSF field names, never the UDM ones or the UDM
    # `Extended` group (keys outside OCSF would be grouped as `Unmapped`).
    page.wait_for({"text": "actor.user.name", "exact": True})
    for udm in ("user", "src_ip", "src_host", "dest_ip"):
        assert page.count({"text": udm, "exact": True}) == 0, f"UDM field {udm} in the OCSF sidebar"
    assert page.count({"role": "button", "name": uilib.rx(r"^Extended\b")}) == 0

    want = (len(groups), sum(groups.values()), _percentages(groups))
    shown = eventually(
        lambda: uilib.sidebar_field(page, field_name),
        timeout=30,
        interval=1,
        desc=f"{field_name} values to settle on the API's",
        ok=lambda v: (v.unique, v.events, v.percent) == want,
    )
    timeline.step("ui", unique=shown.unique, events=shown.events, values=shown.percent)
