"""Help > Report a bug / Get support as a right-side flyout (v2.0.35, NAN-5857).

The support report (NAN-5253) opens from the topbar Help menu as a flyout
pinned to the right edge, with no scrim, so the page being reported on stays
visible. The scenario:

- navigates to a page with a fake secret in the query string, then makes a
  failed API call from the browser (a 404 on a rule that does not exist);
- opens Help > Report a bug: the flyout is on the right, the page is still
  visible beside it, focus is in "What happened";
- fills every field; a click on the page beside it does not close it (the
  typed report survives); the attached context shows the version and edition the
  server reports, the route with the secret omitted, and the failed call with
  the request ID the API stamped on it;
- copies the report (clipboard) and downloads it (file content), and both
  carry the same context and never the secret;
- turns on the air-gap toggle: Email and the app.nano.rs form go away, Copy
  and Download stay, and the choice survives a reopen;
- opens Help > Get support: severity choices and the support form button;
- Escape closes the flyout (only Esc and the X close it).

Nothing is sent anywhere: no request leaves the browser for app.nano.rs.
"""

from __future__ import annotations

import re

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect

FLYOUT = {"testid": "support-flyout"}
HELP = {"role": "button", "name": "Help", "exact": True}
SECRET = "e2efaketoken0nan5857x"
MISSING_RULE = "00000000-0000-4000-8000-00000005857a"
AIRGAP = {"css": "button[role=checkbox]", "within": FLYOUT}


def _open(page: uilib.UiPage, item: str) -> None:
    page.click(HELP)
    page.click({"role": "menuitem", "name": item, "exact": True})
    page.wait_for(FLYOUT, timeout_ms=10_000)
    # Focus starts in "What happened" (the only textarea with a placeholder),
    # never on the header X, where Space or Enter would dismiss it (NAN-5857).
    page.wait_for({"css": "textarea[placeholder]:focus", "within": FLYOUT}, timeout_ms=5_000)
    assert page.count({"css": "button[aria-label=Close]:focus", "within": FLYOUT}) == 0, "focus is on Close"


def _close(page: uilib.UiPage) -> None:
    page.press_key({"role": "textbox", "name": "What happened", "exact": False, "within": FLYOUT}, "Escape")
    page.wait_for(FLYOUT, gone=True, timeout_ms=10_000)


def _set_airgap(page: uilib.UiPage, on: bool) -> None:
    if (page.attr(AIRGAP, "aria-checked") == "true") != on:
        page.click(AIRGAP)
    page.wait_attr(AIRGAP, "aria-checked", "true" if on else "false")


def test_v2035_support_flyout_report_a_bug_and_get_support(
    nano: Nano, page: uilib.UiPage, timeline
) -> None:
    caps = expect(nano.api.get("/api/capabilities"), 200)
    version, edition = str(caps["version"]), str(caps["edition"])

    # A page with a secret in its query string, and a failed API call from it.
    page.goto(f"/rules?token={SECRET}&tab=rules")
    page.wait_for(HELP, timeout_ms=30_000)
    assert SECRET in page.url, f"the app dropped the query string: {page.url}"
    failed = page.session_fetch("GET", f"/api/rules/{MISSING_RULE}")
    assert failed["status"] == 404, failed

    _open(page, "Report a bug")
    flyout = page.rect(FLYOUT)
    timeline.step("flyout open", left=flyout["left"], right=flyout["right"], width=flyout["width"])
    # Pinned to the right edge, narrower than the viewport, full height.
    assert abs(flyout["right"] - flyout["viewport_width"]) <= 1, flyout
    assert flyout["left"] > flyout["viewport_width"] * 0.3, f"not a right-side flyout: {flyout}"
    assert flyout["top"] <= 1 and abs(flyout["bottom"] - flyout["viewport_height"]) <= 1, flyout
    # The page stays visible: no scrim, and the page header is left of the flyout.
    overlay = page.attr({"css": ".fixed.inset-0[data-state=open]"}, "class") or ""
    assert "bg-transparent" in overlay and "bg-black" not in overlay, f"the page is dimmed: {overlay}"
    rail = page.rect({"css": "main"})
    assert rail["left"] < flyout["left"], (rail, flyout)
    assert page.texts({"text": "Report a bug", "exact": True, "within": FLYOUT}), "no title"
    page.screenshot("support-flyout-report-a-bug.png", full_page=False)

    page.fill(
        uilib.field({"placeholder": "Steps, and the exact error or status code you saw", "within": FLYOUT}, "Rule page 404s on a deleted rule"),
        uilib.field({"role": "textbox", "name": "What did you expect", "exact": False, "within": FLYOUT},
                    "A not found message"),
        uilib.field({"role": "textbox", "name": "When (with timezone", "exact": False, "within": FLYOUT},
                    "2026-11-22 10:00 UTC, still happening"),
        uilib.field({"placeholder": "rule: …, log source: …, dashboard: …", "within": FLYOUT}, "rule: nan5857_missing_rule"),
    )

    # The page looks clickable: a click on it never throws the typed report away.
    page.click({"css": ".fixed.inset-0[data-state=open]"})
    assert page.count(FLYOUT) == 1, "a click on the page closed the flyout"
    assert page.value({"role": "textbox", "name": "What happened", "exact": False, "within": FLYOUT}) == (
        "Rule page 404s on a deleted rule"
    )

    # Attached context: version, edition, sanitized route, the failed call.
    page.click({"css": "summary", "within": FLYOUT})
    text = " ".join(page.texts(FLYOUT))
    assert f"v{version}" in text, f"version {version} not in the context"
    assert edition in text, f"edition {edition} not in the context"
    assert "/rules?token=[omitted]&tab=rules" in text, "route not captured (or not sanitized)"
    assert SECRET not in text, "the query-string secret is in the flyout"
    row = page.row_cells(MISSING_RULE, within=FLYOUT)
    assert row.get("status") == "404", row
    assert row.get("endpoint") == f"GET /api/rules/{MISSING_RULE}", row
    request_id = row.get("request id", "")
    assert re.fullmatch(r"[A-Za-z0-9._:-]{8,64}", request_id), f"no request id on the failed call: {row}"
    timeline.step("context", version=version, edition=edition, request_id=request_id)
    page.screenshot("support-flyout-context.png", full_page=False)

    def check_report(report: str, how: str) -> None:
        assert "Rule page 404s on a deleted rule" in report, how
        assert "A not found message" in report, how
        assert "rule: nan5857_missing_rule" in report, how
        assert f"nano version: {version}" in report, how
        assert "/rules?token=[omitted]&tab=rules" in report, how
        assert f"404 GET /api/rules/{MISSING_RULE} request_id={request_id}" in report, how
        assert SECRET not in report, f"{how}: the query-string secret leaked"

    page.click({"role": "button", "name": "Copy report", "within": FLYOUT})
    check_report(page.clipboard(), "copied report")
    name, body = page.download({"role": "button", "name": "Download", "within": FLYOUT})
    assert name.startswith("nano-bug-report-") and name.endswith(".md"), name
    check_report(body, "downloaded report")
    assert page.count({"role": "button", "name": "Email", "exact": True, "within": FLYOUT}) == 1
    assert page.count({"role": "button", "name": "Report on app.nano.rs", "within": FLYOUT}) == 1

    # Air-gap: copy and download only; the choice survives a reopen.
    _set_airgap(page, True)
    page.wait_for({"role": "button", "name": "Email", "exact": True, "within": FLYOUT}, gone=True)
    assert page.count({"role": "button", "name": "Report on app.nano.rs", "within": FLYOUT}) == 0
    assert page.count({"role": "button", "name": "Copy report", "within": FLYOUT}) == 1
    assert page.count({"role": "button", "name": "Download", "within": FLYOUT}) == 1
    page.screenshot("support-flyout-airgap.png", full_page=False)
    _close(page)

    # Get support: severity and the support form; air-gap remembered.
    _open(page, "Get support")
    assert page.texts({"text": "Get support", "exact": True, "within": FLYOUT}), "no Get support title"
    assert page.count({"role": "radio", "within": FLYOUT}) == 4, "no SEV1-SEV4 choices"
    assert page.attr(AIRGAP, "aria-checked") == "true", "the air-gap choice was not remembered"
    assert page.count({"role": "button", "name": "Email", "exact": True, "within": FLYOUT}) == 0
    _set_airgap(page, False)
    page.wait_for({"role": "button", "name": "Open support request", "within": FLYOUT})
    assert page.count({"role": "button", "name": "Email", "exact": True, "within": FLYOUT}) == 1
    page.screenshot("support-flyout-get-support.png", full_page=False)
    _close(page)

    # Nothing went to app.nano.rs on its own.
    assert not page.requests_containing("app.nano.rs"), "the report was sent without the user"
