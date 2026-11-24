"""NAN-5830: a click whose target sits under a transient layer reaches the target.

The driver's `el.click()` clicks the target's centre with no hit test, so a
toast stacked over it (the parser Test lab's "Test" button under "VRL invalid"
/ "VRL validated") took the click. The pointer then hovered the toaster, Sonner
paused its timers, and the toast never left: the parser editor scenario waited
90 s for a test that never ran. The same scenario then clicked "Publish" while
the "Save changes" dialog's overlay was still animating closed, and the click
landed on the overlay. These pages reproduce both through the real driver: a
toast that closes after a moment unless hovered, and a fixed
`data-state="closed"` overlay that leaves after its exit animation.
"""

from __future__ import annotations

import os
import shutil
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from nano_e2e import ui
from nano_e2e.web import WebServer

PAGE = """<!doctype html><html><head><style>
  body { margin: 0; font: 12px sans-serif; }
  #target { position: fixed; right: 40px; bottom: 40px; width: 80px; height: 32px; }
  [data-sonner-toaster] { position: fixed; right: 16px; bottom: 16px; width: 360px; margin: 0; padding: 0;
                          list-style: none; z-index: 1000; }
  [data-sonner-toast] { height: 120px; background: #400; color: #fff; padding: 8px; }
</style></head><body>
<p data-testid="clicks">clicks: 0</p>
<p data-testid="hovered">hovered: no</p>
<p data-testid="undone">undone: 0</p>
<button id="target" data-testid="under-toast">Test</button>
<section aria-label="Notifications"><ol data-sonner-toaster>
  <li data-sonner-toast>VRL invalid <button data-testid="toast-action">Undo</button></li>
</ol></section>
<div id="overlay" data-state="closed" role="presentation"
     style="position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.5)"></div>
<script>
  // /closing: no toast, a dialog overlay animating closed (Radix keeps it
  // mounted until animationend). /toast: the toast, no overlay.
  const closing = location.pathname.startsWith('/closing');
  document.querySelector(closing ? '[data-sonner-toaster]' : '#overlay').remove();
  if (closing) setTimeout(() => document.getElementById('overlay').remove(), 400);
  let clicks = 0;
  document.getElementById('target').addEventListener('click', () => {
    clicks += 1;
    document.querySelector('[data-testid=clicks]').textContent = 'clicks: ' + clicks;
  });
  // Like Sonner: the toast closes after a moment, but not while hovered.
  const toaster = document.querySelector('[data-sonner-toaster]') || document.createElement('ol');
  let left = 1500, hovered = false, last = Date.now();
  // /action: the toast stays until dismissed (a toast's own action button).
  if (location.pathname.startsWith('/action')) left = Infinity;
  let undone = 0;
  const undo = document.querySelector('[data-testid=toast-action]');
  if (undo) undo.addEventListener('click', () => {
    undone += 1;
    document.querySelector('[data-testid=undone]').textContent = 'undone: ' + undone;
  });
  toaster.addEventListener('mouseenter', () => {
    hovered = true;
    document.querySelector('[data-testid=hovered]').textContent = 'hovered: yes';
  });
  toaster.addEventListener('mouseleave', () => { hovered = false; });
  const tick = setInterval(() => {
    const now = Date.now();
    if (!hovered) left -= now - last;
    last = now;
    if (left <= 0) { toaster.innerHTML = ''; clearInterval(tick); }
  }, 50);
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


def test_click_under_a_hovered_toast_moves_off_and_reaches_the_target(driver: ui.Driver, tmp_path: Path) -> None:
    """The pointer rests on the toaster (as after a click that hit the toast),
    so the toast is paused: only moving off it lets it close."""
    page = ui.UiPage.open(driver, tmp_path / "ui", "toast")
    page.layout = "off"
    page.goto("/toast")
    page.wait_for({"testid": "under-toast"})
    page.hover({"css": "[data-sonner-toast]"})
    page.wait_text("hovered: yes", timeout_ms=5_000)
    page.click({"testid": "under-toast"})
    page.wait_text("clicks: 1", timeout_ms=5_000)
    page.finish(failed=False)


def test_click_under_a_closing_overlay_waits_and_reaches_the_target(driver: ui.Driver, tmp_path: Path) -> None:
    page = ui.UiPage.open(driver, tmp_path / "ui", "closing")
    page.layout = "off"
    page.goto("/closing")
    page.wait_for({"testid": "under-toast"})
    page.click({"testid": "under-toast"})
    page.wait_text("clicks: 1", timeout_ms=5_000)
    page.finish(failed=False)


def test_a_toast_action_is_clicked_without_waiting(driver: ui.Driver, tmp_path: Path) -> None:
    """A button inside a toast is never 'covered' by that toast (the toast
    here never closes, so a wrong wait would take the full 15 s)."""
    page = ui.UiPage.open(driver, tmp_path / "ui", "action")
    page.layout = "off"
    page.goto("/action")
    page.wait_for({"testid": "toast-action"})
    started = time.monotonic()
    page.click({"testid": "toast-action"})
    page.wait_text("undone: 1", timeout_ms=5_000)
    assert time.monotonic() - started < 5, "clicking a toast's own action waited for the toast"
    page.finish(failed=False)
