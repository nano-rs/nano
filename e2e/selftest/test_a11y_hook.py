# SPDX-License-Identifier: AGPL-3.0-or-later
"""Selftests for the inline axe-core accessibility hook (NANO_E2E_A11Y) and
allowlist schema/matching (`e2e/coverage/a11y-allowlist.json`, `e2e/nano_e2e/ui.py`,
and `nanosiem-web/tests/e2e/ui/driver.mjs`)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from nano_e2e import ui
from nano_e2e.web import WebServer


class _FakeDriver:
    """In-memory Driver double recording op calls and returning scripted responses."""

    def __init__(self, responses: dict[str, list[Any]] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._responses: dict[str, list[Any]] = {
            k: list(v) for k, v in (responses or {}).items()
        }

    def call(self, op: str, **args: Any) -> Any:
        self.calls.append((op, args))
        queue = self._responses.get(op)
        if queue:
            return queue.pop(0)
        if op == "goto":
            return f"http://127.0.0.1:0{args.get('path', '/')}"
        return True


def _sample_blocking(rule: str = "color-contrast", impact: str = "serious") -> dict[str, Any]:
    return {
        "rule": rule,
        "impact": impact,
        "severity": "blocking",
        "route": "/alerts",
        "theme": "dark",
        "selector": "#alert-title",
        "help": "Elements must meet minimum color contrast ratio thresholds",
        "allowed": None,
    }


def _sample_warning(rule: str = "landmark-one-main", impact: str = "moderate") -> dict[str, Any]:
    return {
        "rule": rule,
        "impact": impact,
        "severity": "warning",
        "route": "/alerts",
        "theme": "light",
        "selector": "html",
        "help": "Document should have one main landmark",
        "allowed": None,
    }


def test_a11y_mode_defaults_to_off_and_validates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NANO_E2E_A11Y", raising=False)
    assert ui.a11y_mode() == "off"

    for mode in ("off", "report", "enforce", "ENFORCE", " Report "):
        monkeypatch.setenv("NANO_E2E_A11Y", mode)
        assert ui.a11y_mode() == mode.strip().lower()

    monkeypatch.setenv("NANO_E2E_A11Y", "invalid-mode")
    with pytest.raises(RuntimeError, match="NANO_E2E_A11Y"):
        ui.a11y_mode()


def test_driver_env_wires_a11y_allowlist_without_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_API_TOKEN", "should-be-stripped-123456")
    monkeypatch.setenv("NANO_E2E_A11Y", "report")
    env = ui.driver_env("http://127.0.0.1:41234")
    assert env["E2E_A11Y_ALLOWLIST"] == str(ui.A11Y_ALLOWLIST)
    assert env["NANO_E2E_A11Y"] == "report"
    assert "TEST_API_TOKEN" not in env


def test_checked_in_a11y_allowlist_is_valid_against_ui_surfaces() -> None:
    assert ui.A11Y_ALLOWLIST.is_file()
    doc = json.loads(ui.A11Y_ALLOWLIST.read_text(encoding="utf-8"))
    assert isinstance(doc.get("_doc"), list) and doc["_doc"]
    assert isinstance(doc.get("entries"), list)
    surfaces_doc = json.loads((ui.ROOT / "e2e" / "coverage" / "ui-surfaces.json").read_text(encoding="utf-8"))
    valid_surfaces = set(surfaces_doc["surfaces"].keys())
    assert ui.validate_a11y_allowlist(doc, valid_surfaces=valid_surfaces) == []


def test_a11y_allowlist_validation_rejects_wildcards_missing_reason_and_bad_entries() -> None:
    valid_surfaces = {"/alerts", "/dashboards", "/rules/:id"}
    good = {
        "entries": [
            {
                "id": "chart-contrast",
                "rule": "color-contrast",
                "within": "[data-testid=recharts-wrapper]",
                "surfaces": ["/dashboards"],
                "reason": "Third-party chart tooltip uses inherited SVG stroke colors.",
                "temporary": True,
                "issue": "NAN-5900",
            },
            {
                "id": "rule-editor-label",
                "rule": "label",
                "selector": ".cm-content",
                "surfaces": ["/rules/:id"],
                "reason": "CodeMirror contenteditable uses aria-labelledby on its container.",
            },
        ]
    }
    assert ui.validate_a11y_allowlist(good, valid_surfaces=valid_surfaces) == []

    bad = {
        "entries": [
            {"id": "wildcard-rule", "rule": "*", "selector": ".x", "reason": "wildcard rule must fail"},
            {"id": "any-rule", "rule": "any", "selector": ".x", "reason": "catch-all any rule must fail"},
            {"id": "prefix-wildcard", "rule": "color-*", "selector": ".x", "reason": "glob rule must fail"},
            {"id": "no-matcher", "rule": "label", "reason": "missing selector and within"},
            {"id": "star-selector", "rule": "label", "selector": "*", "reason": "bare star"},
            {"id": "no-reason", "rule": "image-alt", "selector": "img.logo", "reason": "   "},
            {
                "id": "bad-surface",
                "rule": "image-alt",
                "selector": "img.logo",
                "surfaces": ["/nope"],
                "reason": "bad surface",
            },
            {
                "id": "temp-no-issue",
                "rule": "label",
                "selector": "input",
                "temporary": True,
                "reason": "missing ticket",
            },
            {
                "id": "bad-issue",
                "rule": "label",
                "selector": "input",
                "issue": "JIRA-1",
                "reason": "wrong ticket prefix",
            },
            {
                "id": "glob-root-surface",
                "rule": "label",
                "selector": "input",
                "surfaces": ["/*"],
                "reason": "wildcard root surface glob must fail",
            },
            {
                "id": "glob-prefix-surface",
                "rule": "label",
                "selector": "input",
                "surfaces": ["/alerts/*"],
                "reason": "wildcard prefix surface glob must fail",
            },
            {
                "id": "non-slash-surface",
                "rule": "label",
                "selector": "input",
                "surfaces": ["alerts"],
                "reason": "surface without leading slash must fail",
            },
            {
                "id": "non-bool-temp",
                "rule": "label",
                "selector": "input",
                "temporary": "yes",
                "issue": "NAN-5942",
                "reason": "string temporary must fail",
            },
            {"id": "wildcard-rule", "rule": "label", "selector": "input", "reason": "duplicate id"},
        ]
    }
    errors = ui.validate_a11y_allowlist(bad, valid_surfaces=valid_surfaces)
    joined = "\n".join(errors)
    assert "wildcard-rule" in joined and "exact axe rule ID" in joined
    assert "any-rule" in joined
    assert "prefix-wildcard" in joined
    assert "no-matcher" in joined and 'at least one of "selector" or "within"' in joined
    assert "star-selector" in joined and 'universal "*"' in joined
    assert "no-reason" in joined and 'non-empty "reason"' in joined
    assert "bad-surface" in joined and "/nope" in joined
    assert "temp-no-issue" in joined and "temporary entry" in joined
    assert "bad-issue" in joined and "NAN-<id>" in joined
    assert "glob-root-surface" in joined and "without wildcards" in joined
    assert "glob-prefix-surface" in joined
    assert "non-slash-surface" in joined
    assert "non-bool-temp" in joined and "boolean" in joined
    assert "duplicate id 'wildcard-rule'" in joined

    # Also verify without valid_surfaces (mirrors driver.mjs standalone validation)
    glob_only = {
        "entries": [
            {
                "id": "glob-only",
                "rule": "label",
                "selector": "input",
                "surfaces": ["/*"],
                "reason": "glob without valid_surfaces",
            }
        ]
    }
    assert ui.validate_a11y_allowlist(glob_only, valid_surfaces=None)


def test_a11y_allowlist_matching_is_exact_on_rule_surface_and_selector() -> None:
    entries = [
        {
            "id": "alerts-contrast",
            "rule": "color-contrast",
            "selector": "#alert-title",
            "surfaces": ["/alerts"],
            "reason": "Temporary exception while alert badge palette updates.",
        },
        {
            "id": "drawer-within",
            "rule": "label",
            "within": "[data-testid=filter-drawer]",
            "surfaces": ["/rules/:id"],
            "reason": "Drawer input uses custom combobox wrapper.",
        },
        {
            "id": "nav-within",
            "rule": "color-contrast",
            "within": ".nav",
            "reason": "Scoped strictly to .nav elements.",
        },
        {
            "id": "box-within",
            "rule": "color-contrast",
            "within": "#box",
            "reason": "Scoped strictly to #box elements.",
        },
        {
            "id": "main-only",
            "rule": "region",
            "selector": "main",
            "reason": "Scoped strictly to main leaf element.",
        },
    ]
    # Exact match succeeds
    assert ui.match_a11y_allowlist(
        {"rule": "color-contrast", "route": "/alerts", "selector": "#alert-title"}, entries
    ) == "alerts-contrast"
    # Wrong rule does not match
    assert ui.match_a11y_allowlist(
        {"rule": "image-alt", "route": "/alerts", "selector": "#alert-title"}, entries
    ) is None
    # Wrong route does not match
    assert ui.match_a11y_allowlist(
        {"rule": "color-contrast", "route": "/dashboards", "selector": "#alert-title"}, entries
    ) is None
    # Wrong selector does not match
    assert ui.match_a11y_allowlist(
        {"rule": "color-contrast", "route": "/alerts", "selector": "#other-el"}, entries
    ) is None
    # Parameterized surface + within ancestor matches
    assert ui.match_a11y_allowlist(
        {
            "rule": "label",
            "route": "/rules/abc-123",
            "selector": "input.filter",
            "ancestors": ['div[data-testid="filter-drawer"]'],
        },
        entries,
    ) == "drawer-within"
    # Missing ancestor fails within match
    assert ui.match_a11y_allowlist(
        {"rule": "label", "route": "/rules/abc-123", "selector": "input.filter", "ancestors": ["main"]},
        entries,
    ) is None
    # Regression: CSS token boundary checks prevent raw substring over-matching
    assert ui.match_a11y_allowlist(
        {"rule": "color-contrast", "route": "/alerts", "selector": ".navigation-bar > button"}, entries
    ) is None
    assert ui.match_a11y_allowlist(
        {
            "rule": "color-contrast",
            "route": "/alerts",
            "selector": "#box-2",
            "ancestors": ["#box-2-wrapper"],
        },
        entries,
    ) is None
    assert ui.match_a11y_allowlist(
        {"rule": "region", "route": "/alerts", "selector": "main > #unrelated"}, entries
    ) is None
    # Positive boundary matches still succeed
    assert ui.match_a11y_allowlist(
        {"rule": "color-contrast", "route": "/alerts", "selector": "div.nav.open > button"}, entries
    ) == "nav-within"
    assert ui.match_a11y_allowlist(
        {"rule": "color-contrast", "route": "/alerts", "selector": "#box > span"}, entries
    ) == "box-within"
    assert ui.match_a11y_allowlist(
        {"rule": "region", "route": "/alerts", "selector": "body > main"}, entries
    ) == "main-only"


def test_uipage_a11y_off_mode_never_invokes_scan(tmp_path: Path) -> None:
    drv = _FakeDriver()
    page = ui.UiPage(drv, 1, tmp_path / "ui", layout="off", a11y="off")  # type: ignore[arg-type]
    page.goto("/alerts")
    page.finish(failed=False)
    ops = [op for op, _ in drv.calls]
    assert "a11y_scan" not in ops
    assert "close" in ops


def test_uipage_a11y_report_mode_records_without_failing(tmp_path: Path) -> None:
    drv = _FakeDriver(
        {
            "a11y_scan": [
                {
                    "available": True,
                    "route": "/alerts",
                    "theme": "dark",
                    "blocking": [_sample_blocking()],
                    "warnings": [_sample_warning()],
                    "allowed": [],
                },
                {"available": True, "skipped": True, "blocking": [], "warnings": [], "allowed": []},
            ]
        }
    )
    page = ui.UiPage(drv, 2, tmp_path / "ui", layout="off", a11y="report")  # type: ignore[arg-type]
    page.goto("/alerts")
    assert len(page.a11y_violations) == 1
    assert len(page.a11y_warnings) == 1
    # Report mode must NOT raise on op or teardown
    page.finish(failed=False)


def test_uipage_a11y_enforce_mode_fails_on_blocking_and_warns_on_moderate(tmp_path: Path) -> None:
    # Warnings only: passes in enforce mode
    drv_warn = _FakeDriver(
        {
            "a11y_scan": [
                {"available": True, "blocking": [], "warnings": [_sample_warning()], "allowed": []},
                {"available": True, "blocking": [], "warnings": [], "allowed": []},
            ]
        }
    )
    page_warn = ui.UiPage(drv_warn, 3, tmp_path / "ui-warn", layout="off", a11y="enforce")  # type: ignore[arg-type]
    page_warn.goto("/alerts")
    assert page_warn.a11y_violations == []
    assert len(page_warn.a11y_warnings) == 1
    page_warn.finish(failed=False)

    # Critical/serious blocking violation: raises A11yError (NOT UiError) and fails at teardown if swallowed
    drv_bad = _FakeDriver(
        {
            "a11y_scan": [
                {
                    "available": True,
                    "blocking": [_sample_blocking("label", "critical")],
                    "warnings": [],
                    "allowed": [],
                },
                {"available": True, "blocking": [], "warnings": [], "allowed": []},
            ]
        }
    )
    page_bad = ui.UiPage(
        drv_bad, 4, tmp_path / "ui-bad", layout="off", a11y="enforce"  # type: ignore[arg-type]
    )
    assert not issubclass(ui.A11yError, ui.UiError)
    with pytest.raises(ui.A11yError) as exc:
        page_bad.goto("/alerts")
    assert "label" in str(exc.value)
    assert "a11y-allowlist.json" in str(exc.value)
    with pytest.raises(ui.A11yError, match="reported at teardown"):
        page_bad.finish(failed=False)


def test_uipage_a11y_unavailable_axe_does_not_crash_in_report_mode(tmp_path: Path) -> None:
    unavail = {
        "available": False,
        "reason": "axe-core not found",
        "blocking": [],
        "warnings": [],
        "allowed": [],
    }
    drv = _FakeDriver({"a11y_scan": [dict(unavail), dict(unavail)]})
    page = ui.UiPage(drv, 5, tmp_path / "ui-unavail", layout="off", a11y="report")  # type: ignore[arg-type]
    page.goto("/alerts")
    assert page.a11y_unavailable_reason == "axe-core not found"
    page.finish(failed=False)

    drv_enf = _FakeDriver({"a11y_scan": [dict(unavail), dict(unavail)]})
    page_enf = ui.UiPage(
        drv_enf, 6, tmp_path / "ui-unavail-enf", layout="off", a11y="enforce"  # type: ignore[arg-type]
    )
    with pytest.raises(RuntimeError, match="axe-core not found"):
        page_enf.goto("/alerts")
    # If swallowed and finish(failed=False) runs, close must receive failed=True for diagnostics
    with pytest.raises(RuntimeError, match="axe-core not found"):
        page_enf.finish(failed=False)
    close_calls = [args for op, args in drv_enf.calls if op == "close"]
    assert close_calls and close_calls[-1]["failed"] is True


def test_driver_mjs_syntax_and_a11y_contract() -> None:
    src = ui.DRIVER.read_text(encoding="utf-8")
    assert "async a11y_scan(" in src
    assert "parseA11yMode(process.env.NANO_E2E_A11Y)" in src
    assert "'wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'" in src
    assert "NANO_E2E_AXE_PATH" in src
    assert "redactTokens" in src
    if shutil.which("node"):
        proc = subprocess.run(
            ["node", "--check", str(ui.DRIVER)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr


class _NoopApi(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_a: object) -> None:
        return None


def _has_browser_runtime() -> bool:
    cands = [
        os.environ.get("CHROME_PATH", ""),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ]
    return (
        bool(shutil.which("node"))
        and (ui.WEB / "node_modules" / "puppeteer-core").is_dir()
        and any(c and os.path.exists(c) for c in cands)
    )


def test_driver_real_a11y_scan_allowlist_and_missing_axe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not _has_browser_runtime():
        pytest.skip("needs node, nanosiem-web/node_modules/puppeteer-core, and Chrome")

    # Minimal deterministic mock axe-core script exercising injection, runOnly tags,
    # DOM allowlist matching, token redaction, and severity classification.
    mock_axe = tmp_path / "mock-axe.js"
    mock_axe.write_text(
        """
window.axe = {
  async run(doc, opts) {
    const violations = [];
    const img = doc.querySelector('img:not([alt])');
    if (img) {
      violations.push({
        id: 'image-alt',
        impact: 'critical',
        help: 'Images must have alternate text',
        description: 'Ensures img elements have alternate text',
        helpUrl: 'https://dequeuniversity.com/rules/axe/4.10/image-alt',
        tags: (opts && opts.runOnly && opts.runOnly.values) || ['wcag2a'],
        nodes: [{
          target: ['#' + img.id],
          html: img.outerHTML,
          failureSummary: 'Missing alt on token nsk_secret_token_0123456789abcdef',
        }],
      });
    }
    const input = doc.querySelector('input.needs-label');
    if (input) {
      violations.push({
        id: 'label',
        impact: 'serious',
        help: 'Form elements must have labels',
        description: 'Ensures every form element has a label',
        helpUrl: 'https://dequeuniversity.com/rules/axe/4.10/label',
        tags: ['wcag2a'],
        nodes: [{
          target: ['#' + input.id],
          html: input.outerHTML,
          failureSummary: 'Form element does not have an implicit or explicit label',
        }],
      });
    }
    return { violations, incomplete: [], passes: [{ id: 'html-has-lang' }] };
  },
};
""",
        encoding="utf-8",
    )

    allowlist = tmp_path / "a11y-allowlist.json"
    allowlist.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "id": "allow-input-within-panel",
                        "rule": "label",
                        "within": "[data-testid=allowed-panel]",
                        "surfaces": ["/broken"],
                        "reason": "Test fixture exception scoped strictly to allowed-panel.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text(
        """<!doctype html><html lang="en"><body><main>
        <img id="bad-img" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=">
        <div data-testid="allowed-panel"><input id="ok-input" class="needs-label" type="text"></div>
        </main></body></html>""",
        encoding="utf-8",
    )

    api = ThreadingHTTPServer(("127.0.0.1", 0), _NoopApi)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    upstream = f"http://127.0.0.1:{api.server_address[1]}"
    web = WebServer(dist, upstream, upstream)
    web.start()
    try:
        monkeypatch.setenv("NANO_E2E_LAYOUT", "off")
        monkeypatch.setenv("NANO_E2E_A11Y", "report")
        monkeypatch.setenv("E2E_A11Y_ALLOWLIST", str(allowlist))
        monkeypatch.setenv("NANO_E2E_AXE_PATH", str(mock_axe))
        drv = ui.Driver(web.url, tmp_path / "driver.log")
        try:
            page = ui.UiPage.open(drv, tmp_path / "ui", "a11y-real")
            page.goto("/broken")
            res = page.check_a11y("explicit", force=True)
            assert res["available"] is True
            assert [v["rule"] for v in page.a11y_violations] == ["image-alt"]
            jsonl = (tmp_path / "ui" / "a11y.jsonl").read_text(encoding="utf-8")
            assert "nsk_secret_token_0123456789abcdef" not in jsonl
            assert "allow-input-within-panel" in jsonl
            # Missing axe-core returns unavailable without crashing the browser process.
            missing = drv.call(
                "a11y_scan",
                sid=page.sid,
                force=True,
                axe_path=str(tmp_path / "does-not-exist-axe.js"),
            )
            assert missing["available"] is False
            assert "does not exist" in missing["reason"]
            # Browser is still healthy after unavailable scan.
            assert "/broken" in page.url
            page.finish(failed=False)
        finally:
            drv.close()
    finally:
        web.stop()
        api.shutdown()


# ---------------------------------------------------------------- r1 review fixes

_PARITY = Path(__file__).parent / "fixtures" / "a11y-allowlist-parity.json"


def _node(script: str, *, env: dict[str, str] | None = None) -> Any:
    """Run an ES module snippet from nanosiem-web (driver.mjs importable) and
    return its JSON stdout."""
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=str(ui.WEB),
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **(env or {})},
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _has_node_driver() -> bool:
    return bool(shutil.which("node")) and (ui.WEB / "node_modules" / "puppeteer-core").is_dir()


_MODE_INPUTS = [None, "", "  ", "off", "OFF", " report ", "Enforce", "invalid", "0", "1", "true", "reporting"]


def test_a11y_mode_parser_is_strict_and_the_same_in_python_and_js() -> None:
    py: list[str] = []
    for raw in _MODE_INPUTS:
        try:
            py.append(ui.parse_a11y_mode(raw))
        except RuntimeError as exc:
            assert "NANO_E2E_A11Y" in str(exc) and "expected enforce, report or off" in str(exc)
            py.append("ERROR")
    assert py == ["off", "off", "off", "off", "off", "report", "enforce", "ERROR", "ERROR", "ERROR", "ERROR", "ERROR"]
    if not _has_node_driver():
        pytest.skip("needs node and nanosiem-web/node_modules")
    js = _node(
        "const m = await import('./tests/e2e/ui/driver.mjs');"
        f"const inputs = {json.dumps(_MODE_INPUTS)};"
        "console.log(JSON.stringify(inputs.map((v) => { try { return m.parseA11yMode(v); }"
        " catch (e) { return /expected enforce, report or off/.test(e.message) ? 'ERROR' : e.message; } })));"
    )
    assert js == py


def test_driver_refuses_to_start_on_an_invalid_a11y_mode() -> None:
    if not shutil.which("node"):
        pytest.skip("needs node")
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", "await import('./tests/e2e/ui/driver.mjs');"],
        cwd=str(ui.WEB),
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "NANO_E2E_A11Y": "on"},
    )
    assert proc.returncode != 0
    assert "NANO_E2E_A11Y" in proc.stderr and "expected enforce, report or off" in proc.stderr


# Over-broad selectors and withins: each would suppress a rule on (almost) every element.
_BROAD = ["*", "html", "body", ":root", "div", "div, *", "body *", "* > *", "*:not(.x)", ":not(.__never__)",
          ".x *", ".a, .b", ":is(.a)", "main > div",
          # empty id, class or attribute
          ".", "#", "[]", "div.", "[ ]",
          # the document root, whatever its qualifiers
          "html[lang]", "html.dark", "HTML.dark", "body.class", "body[class]", ":root[lang]",
          ":root:not(.x)", "html > body", "html#app", ".shell body", "[lang]:root", ".dark:root",
          "#app:ROOT", "html.x", ".a > :root[lang]"]
_SPECIFIC = ["main .card", ".card:not(:root)", "#logo", ".cm-content", "[data-testid=recharts-wrapper]", "button.hover\\:bg-muted",
             "#a > .b", "main .x:hover", '[data-x="a,b*"]', "div.row + span.cell"]


def _entry(field: str, value: str) -> dict[str, Any]:
    return {"id": "e1", "rule": "label", field: value, "reason": "schema test"}


@pytest.mark.parametrize("field", ["selector", "within"])
@pytest.mark.parametrize("value", _BROAD)
def test_allowlist_refuses_an_over_broad_selector(field: str, value: str) -> None:
    errors = ui.validate_a11y_allowlist({"entries": [_entry(field, value)]})
    assert any(f'"{field}"' in e and ("universal" in e or "too broad" in e or "selector list" in e or "whole page" in e) for e in errors), errors


@pytest.mark.parametrize("field", ["selector", "within"])
@pytest.mark.parametrize("value", _SPECIFIC)
def test_allowlist_accepts_a_specific_selector(field: str, value: str) -> None:
    assert ui.validate_a11y_allowlist({"entries": [_entry(field, value)]}) == []


def test_allowlist_needs_a_rule_and_a_selector_or_within() -> None:
    assert ui.validate_a11y_allowlist({"entries": [{"id": "e1", "rule": "label", "reason": "r"}]})
    assert ui.validate_a11y_allowlist({"entries": [{"id": "e1", "selector": "#x", "reason": "r"}]})
    padded = {"id": "e1", "rule": "label", "selector": "#x", "surfaces": [" /alerts "], "reason": "r"}
    assert ui.validate_a11y_allowlist({"entries": [padded]})


def test_js_allowlist_loader_gives_the_same_verdicts(tmp_path: Path) -> None:
    if not _has_node_driver():
        pytest.skip("needs node and nanosiem-web/node_modules")
    docs = []
    for field in ("selector", "within"):
        for value in [*_BROAD, *_SPECIFIC]:
            docs.append({"entries": [_entry(field, value)]})
    docs.append({"entries": [{"id": "e1", "rule": "label", "selector": "#x", "surfaces": [" /alerts "], "reason": "r"}]})
    files = []
    for i, doc in enumerate(docs):
        f = tmp_path / f"allow-{i}.json"
        f.write_text(json.dumps(doc), encoding="utf-8")
        files.append(str(f))
    js = _node(
        "const m = await import('./tests/e2e/ui/driver.mjs');"
        f"const files = {json.dumps(files)};"
        "console.log(JSON.stringify(files.map((f) => { try { m.loadA11yAllowlist(f); return true; }"
        " catch { return false; } })));"
    )
    py = [not ui.validate_a11y_allowlist(doc) for doc in docs]
    assert js == py
    assert py.count(True) == 2 * len(_SPECIFIC)


def _parity_cases() -> list[dict[str, Any]]:
    return json.loads(_PARITY.read_text(encoding="utf-8"))["cases"]


def test_python_allowlist_matching_on_the_shared_parity_fixtures() -> None:
    for case in _parity_cases():
        entry = case["entry"]
        assert ui.validate_a11y_allowlist({"entries": [entry]}) == [], case["name"]
        got = ui.match_a11y_allowlist(
            {
                "rule": case["rule"],
                "route": case["route"],
                "search": case["search"],
                "selector": case["target"],
                "ancestors": case["ancestors"],
            },
            [entry],
        )
        assert (got == entry["id"]) is case["expect"], case["name"]


_PARITY_JS = r"""
import fs from 'node:fs';
import puppeteer from 'puppeteer-core';
const m = await import('./tests/e2e/ui/driver.mjs');
const [fixtures, tmp, chrome] = process.argv.slice(1);
const cases = JSON.parse(fs.readFileSync(fixtures, 'utf8')).cases;
const browser = await puppeteer.launch({ executablePath: chrome, headless: true, args: ['--no-sandbox'] });
const out = [];
try {
  const page = await browser.newPage();
  await page.setRequestInterception(true);
  let html = '';
  page.on('request', (r) => r.respond({ status: 200, contentType: 'text/html', body: html }));
  for (const [i, c] of cases.entries()) {
    const file = `${tmp}/parity-${i}.json`;
    fs.writeFileSync(file, JSON.stringify({ entries: [c.entry] }));
    const allow = m.loadA11yAllowlist(file);
    html = `<!doctype html><html lang="en"><body>${c.html}</body></html>`;
    await page.goto(`http://a11y.test${c.route}${c.search}`);
    const res = await page.evaluate(m.a11yMatchAll, { allow, items: [{ rule: c.rule, target: c.target }] });
    out.push({ name: c.name, matched: res.ids[0] === c.entry.id, errors: res.errors });
  }
} finally {
  await browser.close();
}
console.log(JSON.stringify(out));
"""


def _chrome() -> str | None:
    for c in (
        os.environ.get("CHROME_PATH", ""),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ):
        if c and os.path.exists(c):
            return c
    return None


def test_js_dom_allowlist_matching_on_the_shared_parity_fixtures(tmp_path: Path) -> None:
    chrome = _chrome()
    if not (_has_node_driver() and chrome):
        pytest.skip("needs node, nanosiem-web/node_modules/puppeteer-core, and Chrome")
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", _PARITY_JS, str(_PARITY), str(tmp_path), chrome],
        cwd=str(ui.WEB),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    got = {r["name"]: r for r in json.loads(proc.stdout)}
    for case in _parity_cases():
        assert got[case["name"]]["errors"] == [], case["name"]
        assert got[case["name"]]["matched"] is case["expect"], case["name"]


@pytest.mark.parametrize(
    "scripted",
    [
        "raise",
        "not a dict",
        ["a", "list"],
        {"available": True, "blocking": "not-a-list", "warnings": 7},
        {"available": False, "reason": "axe-core not found"},
    ],
)
def test_report_mode_never_fails_a_scenario(tmp_path: Path, scripted: Any) -> None:
    class Boom(_FakeDriver):
        def call(self, op: str, **args: Any) -> Any:
            if op == "a11y_scan" and scripted == "raise":
                self.calls.append((op, args))
                raise ui.UiError("UI a11y_scan: Error: axe internal error")
            return super().call(op, **args)

    drv = Boom({"a11y_scan": [scripted, scripted]})
    page = ui.UiPage(drv, 11, tmp_path / "ui", layout="off", a11y="report")  # type: ignore[arg-type]
    page.goto("/alerts")
    page.check_a11y("explicit", force=True)
    page.finish(failed=False)
    assert page.a11y_unavailable_reason or page.a11y_violations or page.a11y_warnings is not None
    close = [args for op, args in drv.calls if op == "close"]
    assert close and close[-1]["failed"] is False

    drv_enf = Boom({"a11y_scan": [scripted, scripted]})
    page_enf = ui.UiPage(drv_enf, 12, tmp_path / "ui-enf", layout="off", a11y="enforce")  # type: ignore[arg-type]
    with pytest.raises((ui.UiError, RuntimeError, AttributeError, TypeError)):
        page_enf.goto("/alerts")


def test_page_mode_is_passed_to_the_driver(tmp_path: Path) -> None:
    drv = _FakeDriver({"a11y_scan": [{"available": True, "blocking": [], "warnings": [], "allowed": []}] * 2})
    page = ui.UiPage(drv, 13, tmp_path / "ui", layout="off", a11y="report")  # type: ignore[arg-type]
    page.goto("/alerts")
    scans = [args for op, args in drv.calls if op == "a11y_scan"]
    assert scans and scans[0]["mode"] == "report"


_TOKEN = "nsk_planted_token_0123456789abcdef"
_COOKIE = "nanosiem_session=abcdef0123456789abcdef0123456789"
_SECRET_QS = "planted-secret-value-42"


_NIT = "nit_0123456789abcdef0123456789abcdef"


def _assert_clean(*texts: str) -> None:
    for text in texts:
        assert _TOKEN not in text
        assert _NIT not in text
        assert "abcdef0123456789abcdef0123456789" not in text
        assert _SECRET_QS not in text


def test_python_side_redacts_records_findings_and_errors(tmp_path: Path) -> None:
    leaky = {
        "rule": "link-name",
        "impact": "serious",
        "severity": "blocking",
        "route": "/invite",
        "theme": "light",
        "selector": "a.invite",
        "help": "Links must have discernible text",
        "html": f'<a class="invite" href="/x?secret={_SECRET_QS}">x</a>',
        "failure_summary": f"Cookie: {_COOKIE}",
        "allowed": None,
    }
    record = {**leaky, "url": f"http://127.0.0.1/invite?secret={_SECRET_QS}", "test": "t", "after": "goto"}
    drv = _FakeDriver(
        {"a11y_scan": [{"available": True, "blocking": [leaky], "warnings": [], "allowed": [], "records": [record]}]}
    )
    page = ui.UiPage(drv, 14, tmp_path / "ui", layout="off", a11y="enforce")  # type: ignore[arg-type]
    with pytest.raises(ui.A11yError) as exc:
        page.goto("/invite")
    jsonl = (tmp_path / "ui" / "a11y.jsonl").read_text(encoding="utf-8")
    _assert_clean(jsonl, json.dumps(page.a11y_violations), str(exc.value))


def _serve(tmp_path: Path, html: str) -> tuple[Any, Any]:
    dist = tmp_path / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "index.html").write_text(html, encoding="utf-8")
    api = ThreadingHTTPServer(("127.0.0.1", 0), _NoopApi)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    upstream = f"http://127.0.0.1:{api.server_address[1]}"
    web = WebServer(dist, upstream, upstream)
    web.start()
    return web, api


_LEAKY_AXE = """
window.axe = {
  async run() {
    const a = document.querySelector('a.invite');
    return { violations: a ? [{
      id: 'link-name', impact: 'serious', help: 'Links must have discernible text',
      description: 'd', helpUrl: 'https://dequeuniversity.com/rules/axe/4.10/link-name', tags: ['wcag2a'],
      nodes: [{ target: ['a[href="/x?t=%TOKEN%"]'], html: a.outerHTML + ' %NIT%',
        failureSummary: 'Cookie: %COOKIE% / {"Cookie": "%COOKIE%"} / %NIT%' }],
    }] : [], incomplete: [], passes: [] };
  },
};
"""


def test_real_driver_never_leaks_a_token_cookie_or_query_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not (_has_browser_runtime() and _chrome()):
        pytest.skip("needs node, nanosiem-web/node_modules/puppeteer-core, and Chrome")
    axe = tmp_path / "leaky-axe.js"
    axe.write_text(
        _LEAKY_AXE.replace("%TOKEN%", _TOKEN).replace("%COOKIE%", _COOKIE).replace("%NIT%", _NIT), encoding="utf-8"
    )
    web, api = _serve(
        tmp_path,
        f'<!doctype html><html lang="en"><body><main><a class="invite" href="/x?t={_TOKEN}"></a></main></body></html>',
    )
    try:
        monkeypatch.setenv("NANO_E2E_LAYOUT", "off")
        monkeypatch.setenv("NANO_E2E_A11Y", "enforce")
        monkeypatch.delenv("E2E_A11Y_ALLOWLIST", raising=False)
        monkeypatch.setenv("NANO_E2E_AXE_PATH", str(axe))
        drv = ui.Driver(web.url, tmp_path / "driver.log")
        try:
            page = ui.UiPage.open(drv, tmp_path / "ui", "a11y-leak")
            with pytest.raises(ui.A11yError) as exc:
                page.goto(f"/invite/{_TOKEN}/{_NIT}?secret={_SECRET_QS}")
            jsonl = (tmp_path / "ui" / "a11y.jsonl").read_text(encoding="utf-8")
            assert "link-name" in jsonl
            _assert_clean(jsonl, json.dumps(page.a11y_violations), str(exc.value))
            page.a11y_violations.clear()
            page.finish(failed=True)
        finally:
            drv.close()
    finally:
        web.stop()
        api.shutdown()


def test_real_driver_honors_a_page_opt_in_when_started_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not (_has_browser_runtime() and _chrome()):
        pytest.skip("needs node, nanosiem-web/node_modules/puppeteer-core, and Chrome")
    axe = tmp_path / "leaky-axe.js"
    axe.write_text(_LEAKY_AXE.replace("%TOKEN%", "x").replace("%COOKIE%", "x").replace("%NIT%", "x"), encoding="utf-8")
    web, api = _serve(tmp_path, '<!doctype html><html lang="en"><body><main><a class="invite" href="/x"></a></main></body></html>')
    try:
        monkeypatch.setenv("NANO_E2E_LAYOUT", "off")
        monkeypatch.delenv("NANO_E2E_A11Y", raising=False)
        monkeypatch.delenv("E2E_A11Y_ALLOWLIST", raising=False)
        monkeypatch.setenv("NANO_E2E_AXE_PATH", str(axe))
        drv = ui.Driver(web.url, tmp_path / "driver.log")  # started with the scan off
        try:
            page = ui.UiPage.open(drv, tmp_path / "ui", "a11y-optin")
            assert page.a11y == "off"
            page.a11y = "enforce"
            with pytest.raises(ui.A11yError, match="link-name"):
                page.goto("/broken")
            page.a11y_violations.clear()
            page.finish(failed=True)
        finally:
            drv.close()
    finally:
        web.stop()
        api.shutdown()
