"""NAN-5762: the layout invariants every UI op runs (nano_e2e.ui.UiPage.op +
nanosiem-web/tests/e2e/ui/layout.mjs), against static pages through the real
driver: each invariant fires on the bug shape it exists for (a flyout that
scrolls sideways, chips spilling out of a card, a card clipping its chips, a
link painted over), the allowlist exempts what it names, a clean page passes,
`report` mode records without failing, and a violation a scenario swallowed
still fails it at teardown."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading

import pytest

from nano_e2e import ui
from nano_e2e.web import WebServer

PAGE = """<!doctype html><html><head><style>
  body { margin: 0; font: 12px sans-serif; }
  main { width: 900px; overflow-x: clip; }
  .card { border: 1px solid #888; border-radius: 6px; width: 220px; padding: 6px; margin: 8px; }
  .chips { display: flex; gap: 4px; white-space: nowrap; }
  .chip { border: 1px solid #aaa; border-radius: 3px; padding: 0 4px; }
  .flyout { position: fixed; right: 0; top: 0; width: 320px; height: 300px; background: #fff; border-left: 1px solid #888; }
  .flyout-body { overflow: auto; height: 260px; }
</style></head><body><main id="root"></main><script>
  const chips = (n) => '<div class="chips">' + Array.from({length: n}, (_, i) => '<span class="chip">capability-' + i + '</span>').join('') + '</div>';
  // An open in-place dropdown (z-index >= 20) may leave its card and cover controls: not a bug.
  const clean = '<div class="card" data-testid="ok-card"><h3>Clean</h3>' + chips(2) + '<a href="#x">open case</a>'
    + '<div style="position:relative"><button data-testid="under">under</button>'
    + '<div style="position:absolute;z-index:50;top:0;left:0;width:400px;height:60px;background:#fff">dropdown</div></div></div>';
  const broken = [
    '<div class="card" data-testid="spill-card"><h3>Spill</h3>' + chips(8) + '</div>',
    '<div class="card" data-testid="clip-card" style="overflow:hidden"><h3>Clip</h3>' + chips(8) + '</div>',
    '<div class="card" data-testid="overdraw-card" style="position:relative"><a href="#case" data-testid="open-case">Open case</a>'
      + '<div style="position:absolute;left:0;top:0;width:200px;height:30px;background:#eee">next row</div></div>',
    '<div style="overflow-x:auto;width:200px" data-testid="table-scroller"><table><tr>'
      + Array.from({length: 12}, (_, i) => '<td>column-' + i + '</td>').join('') + '</tr></table></div>',
    '<div class="flyout" role="dialog" aria-label="Approvals" data-testid="flyout"><div class="flyout-body">'
      + '<div style="white-space:nowrap">' + 'approval-0123456789abcdef '.repeat(6) + '</div>'
      + '<div style="position:relative"><a href="#c" data-testid="flyout-open-case">Open case</a>'
      + '<div style="position:absolute;left:0;top:0;width:150px;height:20px;background:#ddd">next item</div></div></div></div>',
  ].join('');
  const TOKEN = 'Xk9fQ2mR7vL4pZ8sT1wB6nY3cH5jD0aE';  // token-shaped, never registered
  const pages = {
    // A spilling card while a password field and a token-shaped value are on the page.
    '/secret': '<form><input type="password" value="hunter2-not-registered"></form>'
      + '<div class="card" data-testid="secret-card"><h3>Secret</h3><div class="chips"><span class="chip">' + TOKEN + '</span>'
      + '<span class="chip">' + TOKEN + '</span><span class="chip">' + TOKEN + '</span></div></div>',
    // The terminal login masks a type=text field (autocomplete=current-password).
    '/masked': '<form><input type="text" autocomplete="current-password" value=""></form>'
      + '<div class="card" data-testid="masked-card"><h3>Masked</h3>' + chips(8) + '</div>',
    // An open tooltip elsewhere must not switch the overdraw sample off.
    '/tooltip': '<div data-radix-popper-content-wrapper style="position:fixed;right:0;bottom:0"><div role="tooltip">tip</div></div>'
      + '<div class="card" data-testid="tip-card" style="position:relative"><a href="#case" data-testid="tip-open-case">Open case</a>'
      + '<div style="position:absolute;left:0;top:0;width:200px;height:30px;background:#eee">next row</div></div>',
    // In-page state: expanding a row (same route, same DOM size) reveals a spill.
    '/state': '<button data-testid="expand" aria-expanded="false">expand</button>'
      + '<div id="more" style="display:none"><div class="card" data-testid="state-card"><h3>State</h3>' + chips(8) + '</div></div>',
  };
  const key = Object.keys(pages).find((k) => location.pathname.startsWith(k));
  document.getElementById('root').innerHTML = key ? pages[key] : location.pathname.startsWith('/broken') ? broken : clean;
  const exp = document.querySelector('[data-testid=expand]');
  if (exp) exp.addEventListener('click', () => {
    exp.setAttribute('aria-expanded', 'true');
    document.getElementById('more').style.display = 'block';
  });
</script></body></html>"""


class _Api(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_a: object) -> None:
        return None


def _chrome() -> bool:
    cands = [
        os.environ.get("CHROME_PATH", ""),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ]
    return bool(shutil.which("node")) and any(c and os.path.exists(c) for c in cands)


@pytest.fixture
def driver(tmp_path: Path) -> Iterator[ui.Driver]:
    if not _chrome() or not (ui.WEB / "node_modules" / "puppeteer-core").is_dir():
        pytest.skip("needs node, nanosiem-web/node_modules/puppeteer-core and a local Chrome")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text(PAGE)
    api = ThreadingHTTPServer(("127.0.0.1", 0), _Api)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    upstream = f"http://127.0.0.1:{api.server_address[1]}"
    web = WebServer(dist, upstream, upstream)
    web.start()
    d = ui.Driver(web.url, tmp_path / "driver.log")
    try:
        yield d
    finally:
        d.close()
        web.stop()
        api.shutdown()


def _kinds(violations: list[dict]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for v in violations:
        out.setdefault(v["kind"], []).append(v["element"] + " " + (v.get("container") or ""))
    return out


def test_clean_page_passes_and_each_invariant_fires(driver: ui.Driver, tmp_path: Path) -> None:
    page = ui.UiPage.open(driver, tmp_path / "ui", "layout")
    page.layout = "enforce"
    page.goto("/clean")
    page.wait_for({"testid": "ok-card"})
    assert page.layout_violations == []

    with pytest.raises(ui.LayoutError) as exc:
        page.goto("/broken")
        page.wait_for({"testid": "flyout"})
    kinds = _kinds(page.layout_violations)
    assert any("spill-card" in c for c in kinds.get("escape", [])), kinds
    assert any("clip-card" in c for c in kinds.get("clipped", [])), kinds
    assert any("open-case" in c for c in kinds.get("overdrawn", [])), kinds
    assert any("flyout" in c for c in kinds.get("overflow", [])), kinds
    # Inside a fixed flyout (NAN-5758's "Open case" painted over) still counts.
    assert any("flyout-open-case" in c for c in kinds.get("overdrawn", [])), kinds
    # The wide table's scroller is allowlisted, not reported.
    assert not any("table-scroller" in c for c in kinds.get("overflow", [])), kinds
    msg = str(exc.value)
    assert "LAYOUT (NAN-5762)" in msg and "layout-allowlist.json" in msg
    out = tmp_path / "ui"
    assert list(out.glob("layout-*.png")), "no screenshot of the offenders"
    lines = [json.loads(x) for x in (out / "layout.jsonl").read_text().splitlines()]
    assert any(x.get("allowed") == "wide-tables" for x in lines), lines
    # Reported once per session: the same state does not raise again.
    page.check_layout("again", force=True)
    # Swallowed above, so teardown fails the scenario.
    with pytest.raises(ui.LayoutError, match="reported at teardown"):
        page.finish(failed=False)


def test_report_mode_records_without_failing(driver: ui.Driver, tmp_path: Path) -> None:
    page = ui.UiPage.open(driver, tmp_path / "ui", "layout-report")
    page.layout = "report"
    page.goto("/broken")
    page.wait_for({"testid": "flyout"})
    assert {v["kind"] for v in page.layout_violations} >= {"escape", "clipped", "overdrawn", "overflow"}
    page.finish(failed=False)  # no raise
    assert (tmp_path / "ui" / "layout.jsonl").is_file()


def test_secrets_fail_closed_no_screenshot_and_redacted_text(driver: ui.Driver, tmp_path: Path) -> None:
    """P1 (review): a password field on the page means no screenshot, and no
    element text reaches layout.jsonl; token-shaped text is redacted anyway."""
    page = ui.UiPage.open(driver, tmp_path / "ui", "layout-secret")
    page.layout = "report"
    page.goto("/secret")
    page.wait_for({"testid": "secret-card"})
    assert any(v["kind"] == "escape" for v in page.layout_violations), page.layout_violations
    out = tmp_path / "ui"
    assert not list(out.glob("layout-*.png")), "photographed a page with a password field"
    assert list(out.glob("layout-*.png.skipped.txt"))
    blob = (out / "layout.jsonl").read_text()
    assert "Xk9fQ2mR7vL4pZ8sT1wB6nY3cH5jD0aE" not in blob and "hunter2" not in blob
    page.finish(failed=False)


def test_redact_tokens_shapes() -> None:
    """Token-shaped strings are redacted; lowercase ids and words are kept."""
    import subprocess

    js = (
        "import('./tests/e2e/ui/layout.mjs').then((m) => console.log(JSON.stringify([m.redactTokens("
        "'jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123 key nano_AbC123dEf456GhI789 "
        "b64 Xk9fQ2mR7vL4pZ8sT1wB6nY3cH5jD0aE id case_5mk8165hbs9rwajyr4h5c0gs0w "
        "host deep-title-454eaf3e-Host2 ReconnaissanceTA00430/46ResourceDevelopmentTA0042')])))"
    )
    out = subprocess.run(["node", "--input-type=module", "-e", js], cwd=ui.WEB, capture_output=True, text=True, check=True)
    text = json.loads(out.stdout)[0]
    assert "eyJ" not in text and "nano_AbC" not in text and "Xk9fQ" not in text, text
    assert "case_5mk8165hbs9rwajyr4h5c0gs0w" in text, text
    assert "deep-title-454eaf3e-Host2" in text and "ReconnaissanceTA00430/46" in text, text


def test_open_tooltip_does_not_disable_overdraw(driver: ui.Driver, tmp_path: Path) -> None:
    page = ui.UiPage.open(driver, tmp_path / "ui", "layout-tooltip")
    page.layout = "report"
    page.goto("/tooltip")
    page.wait_for({"testid": "tip-card"})
    assert any(v["kind"] == "overdrawn" and "tip-open-case" in v["element"] for v in page.layout_violations), page.layout_violations
    page.finish(failed=False)


def test_in_page_state_change_is_measured(driver: ui.Driver, tmp_path: Path) -> None:
    """P1 (review): expanding a row on the same route is a new state and is scanned."""
    page = ui.UiPage.open(driver, tmp_path / "ui", "layout-state")
    page.layout = "report"
    page.goto("/state")
    page.wait_for({"testid": "expand"})
    assert page.layout_violations == []
    page.click({"testid": "expand"})
    assert any(v["kind"] == "escape" and "state-card" in (v.get("container") or "") for v in page.layout_violations), page.layout_violations
    page.finish(failed=False)


def test_masked_text_password_field_also_skips_the_screenshot(driver: ui.Driver, tmp_path: Path) -> None:
    """The terminal-style login's password field is type=text (sanity pass)."""
    page = ui.UiPage.open(driver, tmp_path / "ui", "layout-masked")
    page.layout = "report"
    page.goto("/masked")
    page.wait_for({"testid": "masked-card"})
    assert page.layout_violations
    out = tmp_path / "ui"
    assert not list(out.glob("layout-*.png")) and list(out.glob("layout-*.png.skipped.txt"))
    page.finish(failed=False)
