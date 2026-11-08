"""Nano Pipe pipelines workspace (NAN-4919, on clickhouse/dev), every step in
the browser and checked against the log-source/pipe APIs:

- open a source's pipeline, Add step > Filter (drop `.message ==
  "heartbeat-ping"`, on the raw event), Save draft: the API's draft parser is a nano-pipe-v2 plan
  carrying that predicate;
- Paste sample (3 raw events, 2 heartbeats) > Run preview: the page shows 3
  outcomes, 2 with no output, exactly what POST /pipe-preview reports for the
  saved draft and the same events;
- Review release > Publish release: a new active version in the versions API;
  change the predicate, publish again; History > Rollback to the first: the
  API's active parser carries the first predicate again.

Draft preview needs NANO_PIPE_PREVIEW_ENABLED (the e2e app env sets it).
"""

from __future__ import annotations

from typing import Any

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.runid import route_key
from nano_e2e.ui import field, rx
from nano_e2e.waits import eventually

# Steps run on RAW events, before parsing: a pasted line is `{message: <line>}`.
LINES = ["keep me", "heartbeat-ping", "heartbeat-ping"]
EVENTS = [{"message": line} for line in LINES]
FIRST, SECOND = '.message == "heartbeat-ping"', '.message == "noise-ping"'


def _source(nano: Nano, sid: str) -> dict[str, Any]:
    return api_expect(nano.api.get(f"/api/log-sources/{sid}"), 200)


def _versions(nano: Nano, sid: str) -> list[dict[str, Any]]:
    body = api_expect(nano.api.get(f"/api/log-sources/{sid}/versions"), 200)
    return body if isinstance(body, list) else body.get("versions", [])


def _predicate(page: uilib.UiPage) -> dict[str, Any]:
    return {"role": "textbox", "name": rx("^Predicate")}


def _save(page: uilib.UiPage) -> None:
    page.click({"role": "button", "name": "Save draft"})
    page.wait_text("Draft saved", exact=False, timeout_ms=30_000)


def _publish(page: uilib.UiPage) -> None:
    page.click({"role": "button", "name": "Review release"}, timeout_ms=30_000)
    dlg = {"role": "dialog"}
    ack = {"role": "checkbox", "name": "Acknowledge preview-only steps", "within": dlg}
    if page.count(ack):
        page.click(ack)
    page.click({"role": "button", "name": "Publish release", "within": dlg})
    page.wait_for(dlg, gone=True, timeout_ms=90_000)


def test_pipeline_build_preview_publish_rollback(nano: Nano, page: uilib.UiPage, request, timeline) -> None:
    rk = route_key(request.node.nodeid, "pipe")
    src = nano.create_draft_source(name=rk, route_key=rk)
    sid = src["id"]
    try:
        caps = api_expect(nano.api.get(f"/api/log-sources/{sid}/pipe-capabilities"), 200)
        timeline.step("capabilities", preview=caps["preview_enabled"], kinds=caps["step_kinds"])
        assert caps["preview_enabled"], "draft preview is off on this stack (NANO_PIPE_PREVIEW_ENABLED)"

        page.goto(f"/ingestion/pipelines/{sid}")
        page.click({"role": "button", "name": "Add step"}, timeout_ms=30_000)
        page.click({"role": "menuitem", "name": "Filter", "exact": True})
        page.fill(field(_predicate(page), FIRST))
        _save(page)
        draft = eventually(
            lambda: _source(nano, sid)["parser_vrl"], timeout=30, desc="draft stored", ok=lambda v: bool(v.strip())
        )
        timeline.step("saved", head=draft.splitlines()[0][:120])
        assert draft.startswith("# nano-pipe-v2") and "heartbeat-ping" in draft, draft[:300]

        # Preview in the page == the preview API on the same draft + events.
        page.click({"role": "button", "name": "Paste sample"})
        page.fill(field({"role": "textbox", "name": "Raw events to paste"}, "\n".join(LINES)))
        page.click({"role": "button", "name": "Use as input"})
        page.click({"role": "button", "name": "Run preview"})
        outcomes = {"role": "option", "within": {"role": "listbox", "name": "Preview input outcomes"}}
        rows = eventually(
            lambda: page.texts(outcomes), timeout=60, interval=1, desc="preview outcomes", ok=lambda r: len(r) == 3
        )
        ui_dropped = sum(1 for r in rows if r.rstrip().endswith("0 out"))
        api = api_expect(
            nano.api.post(f"/api/log-sources/{sid}/pipe-preview", json={"parser_vrl": draft, "events": EVENTS}), 200
        )
        timeline.step("preview", ui=rows, api=api["summary"])
        assert api["summary"]["input_events"] == 3 and api["summary"]["dropped_events"] == 2, api["summary"]
        assert ui_dropped == api["summary"]["dropped_events"], (rows, api["summary"])

        # Publish v_a (FIRST), then v_b (SECOND); roll back to v_a.
        before = len(_versions(nano, sid))
        _publish(page)
        v = eventually(lambda: _versions(nano, sid), timeout=60, desc="first release", ok=lambda vs: len(vs) == before + 1)
        first_rev = max(int(x["version_number"]) for x in v)
        page.fill(field(_predicate(page), SECOND))
        _save(page)
        _publish(page)
        eventually(lambda: _versions(nano, sid), timeout=60, desc="second release", ok=lambda vs: len(vs) == before + 2)
        assert "noise-ping" in _source(nano, sid)["parser_vrl"]
        timeline.step("published twice", first=first_rev)

        page.click({"role": "button", "name": "History"})
        hist = {"role": "dialog", "name": rx("Version history")}
        row = {"role": "row", "has": f"v{first_rev}", "within": hist}
        page.click({"role": "button", "name": "Rollback", "within": row})
        page.click({"role": "button", "name": rx("^(Replace and )?[Rr]oll back$"), "within": {"role": "alertdialog"}})
        active = eventually(
            lambda: _source(nano, sid)["parser_vrl"],
            timeout=90,
            interval=2,
            desc="rolled back parser active",
            ok=lambda p: "heartbeat-ping" in p and "noise-ping" not in p,
        )
        vs = _versions(nano, sid)
        timeline.step("rolled back", versions=len(vs))
        assert len(vs) == before + 3, "a rollback records a new active version"
    finally:
        nano.delete_source(sid)
