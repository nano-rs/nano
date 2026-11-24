"""v2.0.32/.33 search behavior a person sees in the browser.

- **Search guards by cost (v2.0.33).** An unfiltered `eventstats` used to be
  refused on sight; it now runs when the estimate fits this install's budget
  (at least 100,000 rows on any install), so on this small stack it completes
  with results and no refusal. The refusal half (the message naming the
  estimate and the budget) needs more than `MIN_ROW_BUDGET` (100,000) events
  and is covered by `nanosiem-core/src/search/query_processing/oom_admission`
  unit tests.
- **Operators render as typed (v2.0.33).** A query with `!=` and `>=` shows
  those characters in the search editor, and the served stylesheet turns
  font ligatures off on the whole document (`font-variant-ligatures: none`),
  which is what stops Geist Mono drawing `!=` as one "≠" glyph. (A ligature is
  a font rendering, so the DOM text alone cannot prove it; the CSS rule can.)
- **`dataset=signals` (v2.0.32).** The Dataset selector offers Signals
  ("times a rule matched") and a person with `detections:view` searches it.
  The refusal without `detections:view` is not provable in the browser here:
  every user belongs to the built-in Everyone group, whose role already grants
  `detections:view`, so a session can never lack it without editing that
  shared group. `tests/ui/test_signals_risk_dashboard.py` proves the 403 with
  an API key that lacks it.

Not covered: Rarity on OCSF (v2.0.33). The rarity scatter is drawn as SVG
dots with no per-dot test hook, and its RARE classification is computed in
the browser; `tests/ui/test_search_urls.py` only proves `view=rarity` opens.

The acting people are throwaway search personas, never the install admin.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from nano_e2e import ui as uilib
from nano_e2e.client import Journal, Nano
from nano_e2e.rbac import limited_user
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

SEARCHER = ["search:view", "search:execute", "detections:view"]


@contextmanager
def _logged_in(
    stack: Stack, ui: uilib.Driver, artifact_dir: Path, label: str, perms: list[str]
) -> Iterator[uilib.UiPage]:
    with limited_user(stack, label, perms, Journal(artifact_dir / "api.jsonl")) as user:
        p = uilib.UiPage.open(ui, artifact_dir / f"ui-{label}", label)
        failed = True
        try:
            uilib.login(p, user.email, user.password)
            yield p
            failed = False
        finally:
            p.finish(failed)


def test_v2033_unfiltered_eventstats_runs_and_operators_render_as_typed(
    stack: Stack, nano: Nano, ocsf_lane, mark: str, ui: uilib.Driver, artifact_dir, timeline
) -> None:
    for i in range(3):
        ocsf_lane.send(stack, mark, f"op-{mark[-6:]}-{i}", "198.51.100.33", "op-host", note=f"seq={i}")
    eventually(
        lambda: nano.search(f'"{mark}"')["total_count"],
        timeout=INGEST_VISIBLE,
        desc="events",
        ok=lambda n: n == 3,
    )
    with _logged_in(stack, ui, artifact_dir, "search33", SEARCHER) as p:
        # Cost guard: unfiltered eventstats is admitted under the budget.
        uilib.run_search(p, "* | eventstats count AS total_events | head 5")
        header, rows = uilib.table_rows(p)
        timeline.step("eventstats", header=header, rows=len(rows))
        assert rows and "total_events" in [h.lower() for h in header], (header, rows[:1])
        assert not p.contains("Narrow the time range or add filters"), "the cost guard refused a small search"
        # Operators as typed.
        query = f'"{mark}" actor.user.name!="nobody" | stats count AS n | where n >= 1'
        uilib.run_search(p, query)
        editor = p.texts({"css": ".cm-content"})
        timeline.step("editor", text=editor[:1])
        assert editor and "!=" in editor[0] and ">=" in editor[0], editor
        assert not any(ch in editor[0] for ch in "≠≤≥"), editor
        p.screenshot("operators-as-typed.png")
    dist = Path(os.environ["E2E_WEB_DIST"])
    css = "".join(f.read_text(errors="replace") for f in (dist / "assets").glob("*.css"))
    assert "font-variant-ligatures:none" in css.replace(" ", ""), (
        "the served CSS no longer turns ligatures off"
    )


def test_v2032_dataset_signals_needs_detections_view(
    stack: Stack, ui: uilib.Driver, artifact_dir, timeline
) -> None:
    with _logged_in(stack, ui, artifact_dir, "signals32", SEARCHER) as p:
        p.goto("/search")
        p.click({"role": "button", "name": uilib.rx(r"^Dataset")}, timeout_ms=30_000)
        option = {"role": "button", "name": uilib.rx(r"^Signals\s*times a rule matched")}
        p.wait_for(option)
        p.click(option)
        p.wait_for({"role": "button", "name": uilib.rx(r"^Dataset\s*Signals")})
        uilib.run_search(p, "dataset=signals | stats count AS fires")
        assert not p.contains("requires the detections:view permission")
        timeline.step("with detections:view", url=p.url[-120:])
        p.screenshot("dataset-signals.png")
