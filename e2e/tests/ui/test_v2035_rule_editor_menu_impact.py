"""Rule editor overflow menu, actions divider and Impact & baseline card (v2.0.35, NAN-5842).

- Rule actions (the 3-dot menu next to Test rule) uses the shared compact menu
  rows: every item is on top at its centre and corners, no other text
  overlaps it, icons are 16px with the 8px row inset, rows are one height,
  and an item is clickable (Format query runs and closes the menu).
- A 1px divider sits between the rule actions group (Matches, Test rule,
  Rule actions) and Save.
- Impact & baseline buckets the last 7 UTC calendar days (zero-filled) and
  compares them with the 7 before: a rule with 0 matches shows the quiet
  state (above the chart, never over the dashed baseline, also when only the
  prior week had matches), 1 match today draws a line (not a lone clipped dot), and matches on
  several days give the calendar-window totals. The chart stays inside the
  card. The layout scan (`UiPage.op`) runs on every state, menu open included.

Past-day matches cannot be produced through the API (a rule run stamps
`detected_at` now), so the fixture writes `detection_matches` rows for this
scenario's own rules straight into PostgreSQL; the page reads them through
`/api/rules/stats` like any other match. Acting user: a throwaway persona.
Rules are snake_case in the "Automated" folder.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import pytest

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.personas import login_persona
from nano_e2e.soar_ui import psql
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

FOLDER = "Automated"
PERMS = (
    "search:view",
    "search:execute",
    "detections:view",
    "detections:create",
    "detections:edit",
    "detections:promote",
    "detections:delete",
)
ACTIONS = {"role": "button", "name": "Rule actions", "exact": True}
MENU = {"role": "menu"}
ITEM = {"role": "menuitem"}
CARD = {"testid": "rule-impact-card"}
CHART = {"testid": "rule-impact-chart"}

# (days ago, matches) for the "several" rule: last 7 days = 3+1+5+2+4 = 15,
# the 7 before = 2+6+1 = 9, day 20 is outside both windows.
SEVERAL = ((0, 3), (1, 1), (2, 5), (4, 2), (6, 4), (8, 2), (10, 6), (12, 1), (20, 7))


def _name(prefix: str, mark: str) -> str:
    return f"{prefix}_{mark[-10:].replace('-', '_')}".lower()


@pytest.fixture
def rules(nano: Nano) -> Iterator[list[str]]:
    ids: list[str] = []
    yield ids
    for rid in ids:
        expect(nano.api.delete(f"/api/rules/{rid}"), 200, 204, 404)


def _create(nano: Nano, rules: list[str], name: str) -> dict[str, Any]:
    rule = expect(
        nano.api.post(
            "/api/rules",
            json={
                "name": name,
                "description": "nano-e2e v2.0.35 rule editor menu + impact (NAN-5842)",
                "query": f'"{name}" | stats count by src_ip',
                "severity": "medium",
                "schedule_cron": "0 0 1 1 *",
                "mode": "staging",
                "detection_mode": "scheduled",
                "lookback_minutes": 15,
                "folder": FOLDER,
            },
        ),
        200,
        201,
    )
    rules.append(rule["id"])
    return rule


def _seed_matches(name: str, days: tuple[tuple[int, int], ...]) -> None:
    """`count` matches at noon UTC `days ago` for the rule named `name` (this run's own)."""
    # The name is interpolated into SQL: only this scenario's snake_case names.
    assert re.fullmatch(r"v2035_impact_[a-z0-9_]+", name), name
    assert all(isinstance(d, int) and isinstance(c, int) for d, c in days), days
    values = ",".join(f"({d},{c})" for d, c in days)
    psql(
        f"""
        INSERT INTO detection_matches (rule_id, rule_name, severity, detected_at, event_hash)
        SELECT r.id, r.name, 'medium',
               (date_trunc('day', now() AT TIME ZONE 'UTC') + interval '12 hours'
                 - make_interval(days => v.d) - make_interval(secs => k)) AT TIME ZONE 'UTC',
               'nan5842-' || v.d || '-' || k
        FROM detection_rules r, (VALUES {values}) AS v(d, c), generate_series(1, v.c) AS k
        WHERE r.name = '{name}';
        UPDATE detection_rules r
        SET match_count = (SELECT count(*) FROM detection_matches m WHERE m.rule_id = r.id)
        WHERE r.name = '{name}';
        """
    )


def _inside(inner: dict[str, float], outer: dict[str, float], slack: float = 0.5) -> bool:
    return (
        inner["left"] >= outer["left"] - slack
        and inner["right"] <= outer["right"] + slack
        and inner["top"] >= outer["top"] - slack
        and inner["bottom"] <= outer["bottom"] + slack
    )


def test_v2035_rule_editor_overflow_menu_and_actions_divider(
    stack: Stack, nano: Nano, mark: str, ui: uilib.Driver, artifact_dir, timeline, rules
) -> None:
    name = _name("v2035_menu", mark)
    rule = _create(nano, rules, name)

    with login_persona(stack, nano, ui, artifact_dir, "rule-menu-editor", PERMS) as persona:
        page = persona.page
        page.goto(f"/rules/editor/{rule['id']}")
        page.wait_text(name, exact=False, timeout_ms=30_000)
        actions = {"testid": "rule-editor-top-actions"}
        page.wait_for({**ACTIONS, "within": actions}, timeout_ms=30_000)

        # Divider: one 1px rule between the overflow trigger and Save.
        divider = {"testid": "rule-editor-actions-divider"}
        assert page.count(divider) == 1, "no divider between the rule actions and Save"
        d = page.rect(divider)
        trigger = page.rect({**ACTIONS, "within": actions})
        save = page.rect({"role": "button", "name": "Saved", "exact": True, "within": actions})
        assert round(d["width"]) == 1, f"the divider is not 1px wide: {d}"
        assert trigger["right"] <= d["left"] <= d["right"] <= save["left"], (
            f"the divider is not between Rule actions and Save: trigger={trigger} divider={d} save={save}"
        )
        assert d["top"] >= trigger["top"] - 2 and d["bottom"] <= trigger["bottom"] + 2, d
        timeline.step("actions divider", left=d["left"], width=d["width"])

        # The menu opens next to Test rule, below the trigger.
        page.click({**ACTIONS, "within": actions})
        page.wait_for(MENU, timeout_ms=10_000)
        # The menu zooms in from 95%: measure once the open animation settles
        # (the same box on two polls in a row).
        seen: list[dict[str, float]] = []

        def settled() -> bool:
            seen.append(page.rect(MENU))
            return len(seen) > 1 and seen[-1]["width"] == seen[-2]["width"] and seen[-1]["top"] == seen[-2]["top"]

        eventually(settled, timeout=5, interval=0.15, desc="menu open animation settled", ok=bool)
        menu = seen[-1]
        assert abs(menu["right"] - trigger["right"]) <= 2, f"menu not aligned to its trigger: {menu} {trigger}"
        assert menu["top"] >= trigger["bottom"] - 1, f"menu not below its trigger: {menu} {trigger}"
        labels = [t.strip() for t in page.texts(ITEM)]
        for want in ("Duplicate rule", "Format query", "Promote to live", "Archive rule", "Delete forever"):
            assert want in labels, f"{want} missing from Rule actions: {labels}"

        hits = page.occlusion(ITEM)
        assert len(hits) == len(labels), hits
        menu_box = hits[0]["scope"]  # the menu's own content box (the items' parent)
        for h in hits:
            # A disabled item is pointer-events: none (Discard changes on a clean
            # rule), so every hit test lands on the menu box beneath it; a rounded
            # corner can do the same. Anything else on top is painted over.
            foreign = [c for c in h["covered"] if not c.endswith(menu_box)]
            assert not foreign, f"menu item painted over: {h}"
            if h["text"] != "Discard changes":
                assert not any(c.startswith("center:") for c in h["covered"]), f"item centre not clickable: {h}"
        assert not [h for h in hits if h["overlaps"]], f"text overlaps a menu item: {hits}"
        rows = page.boxes(ITEM)
        icons = page.boxes({"css": '[role="menu"] [role="menuitem"] > svg'})
        assert len(icons) == len(rows), f"every row has one icon: {len(icons)} icons for {len(rows)} rows"
        assert {round(r["height"]) for r in rows} == {28}, f"rows are not one 28px height: {rows}"
        assert {round(i["width"]) for i in icons} == {16}, f"icons are not 16px: {icons}"
        for row, icon in zip(rows, icons, strict=True):
            assert round(icon["left"] - row["left"]) == 8, f"icon not at the 8px row inset: {row} {icon}"
        page.screenshot("v2035-rule-actions-menu.png", full_page=False)
        timeline.step("menu rows", rows=len(rows), height=28, icon=16)

        # Clickable: Format query runs and the menu closes.
        page.click({"role": "menuitem", "name": "Format query", "exact": True})
        page.wait_for(MENU, timeout_ms=10_000, gone=True)
        assert not page.page_errors(), page.page_errors()
        timeline.step("menu item clicked", item="Format query")


def test_v2035_impact_card_seven_day_trend(
    stack: Stack, nano: Nano, mark: str, ui: uilib.Driver, artifact_dir, timeline, rules
) -> None:
    cases = {
        "zero": (_name("v2035_impact_zero", mark), ()),
        "one": (_name("v2035_impact_one", mark), ((0, 1),)),
        # Quiet window, busy baseline: the quiet note must not sit on the dashed baseline.
        "zero_baseline": (_name("v2035_impact_zerobase", mark), ((8, 2), (10, 6))),
        "several": (_name("v2035_impact_several", mark), SEVERAL),
    }
    ids = {}
    for key, (name, days) in cases.items():
        ids[key] = _create(nano, rules, name)["id"]
        if days:
            _seed_matches(name, days)

    with login_persona(stack, nano, ui, artifact_dir, "rule-impact-viewer", PERMS) as persona:
        page = persona.page
        expected = {
            "zero": ("0", "baseline 0 prev 7d", "none"),
            "one": ("1", "baseline 0 prev 7d", "new"),
            "zero_baseline": ("0", "baseline 8 prev 7d", "-100%"),
            "several": ("15", "baseline 9 prev 7d", "+67%"),
        }
        for key, (name, _days) in cases.items():
            page.goto(f"/rules/editor/{ids[key]}")
            page.wait_text(name, exact=False, timeout_ms=30_000)
            page.wait_for({**CHART, "within": CARD}, timeout_ms=30_000)
            total, baseline, delta = expected[key]
            page.wait_text(baseline, exact=True, timeout_ms=20_000)
            text = " ".join(page.texts(CARD))
            assert f"7d trend{total}" in text, f"{key}: 7d total {total} not shown: {text!r}"
            assert delta in text, f"{key}: delta {delta!r} not shown: {text!r}"

            card = page.rect(CARD)
            chart = page.rect(CHART)
            svg = page.rect({"css": '[data-testid="rule-impact-chart"] svg.recharts-surface'})
            assert chart["height"] >= 48, f"{key}: the chart does not fill the card: {chart}"
            assert _inside(chart, card) and _inside(svg, chart), f"{key}: chart outside its card: {card} {chart} {svg}"
            curve = {"css": '[data-testid="rule-impact-chart"] .recharts-line-curve'}
            assert page.count(curve) == 1, f"{key}: no trend line drawn"
            line = page.rect(curve)
            assert line["width"] >= svg["width"] * 0.8, f"{key}: the line does not span the 7 days: {line} {svg}"
            assert _inside(line, svg), f"{key}: the line is clipped by the chart: {line} {svg}"
            quiet_box = {"testid": "rule-impact-quiet", "within": CARD}
            quiet = page.count(quiet_box)
            assert quiet == (1 if key.startswith("zero") else 0), f"{key}: quiet state shown={quiet}"
            if quiet:
                note = page.rect(quiet_box)
                # In flow above the chart: it never shares space with the baseline line.
                assert note["bottom"] <= chart["top"] + 0.5, f"{key}: quiet note overlaps the chart: {note} {chart}"
                assert _inside(note, card), f"{key}: quiet note outside the card: {note} {card}"
                if key == "zero_baseline":
                    assert "0 vs 8 baseline" in text, f"{key}: quiet note does not name the baseline: {text!r}"
                    guide = {"css": '[data-testid="rule-impact-chart"] .recharts-reference-line line[stroke-dasharray]'}
                    assert page.count(guide) == 1, f"{key}: no dashed baseline drawn"
            page.screenshot(f"v2035-impact-{key}.png", full_page=False)
            timeline.step("impact card", rule=key, total=total, baseline=baseline, delta=delta)
