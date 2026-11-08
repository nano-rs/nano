"""Failure screenshots never show a reveal-once API key the page displays.

The page creates a key and renders it in text, an input value and an attribute.
The driver learns the secret directly from the POST response, before persona
code can fail. Before the failure screenshot it masks every rendered
occurrence; if one cannot be masked the screenshot is skipped.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from nano_e2e.web import WebServer

TOKEN = "nit_" + secrets.token_hex(16)


class _TokenApi(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        body = json.dumps({"id": "apikey_01h00000000000000000000000", "key": TOKEN}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a: object) -> None:
        pass


PAGE = """<html><body><main><h1>issued</h1><div role=dialog>
<code data-testid=issued-ingest-token></code><input aria-label='Ingest token' readonly>
<button aria-label='Copy'>copy</button></div><script>
fetch('/api/api-keys', {method: 'POST'}).then(r => r.json()).then(({key: token}) => {
  document.querySelector('code').textContent = 'Token: ' + token;
  document.querySelector('input').value = token;
  document.querySelector('button').setAttribute('data-copy', token);
});
</script></main></body></html>"""


def _chrome() -> bool:
    import shutil

    cands = [
        os.environ.get("CHROME_PATH", ""),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ]
    return bool(shutil.which("node")) and any(c and os.path.exists(c) for c in cands)


def test_api_key_response_is_registered_before_failure_artifacts(tmp_path: Path) -> None:
    from nano_e2e import ui

    if not _chrome() or not (ui.WEB / "node_modules" / "puppeteer-core").is_dir():
        pytest.skip("needs node, nanosiem-web/node_modules/puppeteer-core and a local Chrome")
    api = ThreadingHTTPServer(("127.0.0.1", 0), _TokenApi)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text(PAGE)
    up = f"http://127.0.0.1:{api.server_address[1]}"
    web = WebServer(dist, up, up)
    web.start()
    driver = ui.Driver(web.url, tmp_path / "driver.log")
    try:
        page = ui.UiPage.open(driver, tmp_path / "ui", "screenshot-guard")
        page.goto("/")
        page.wait_for({"testid": "issued-ingest-token"})
        shown = page.texts({"testid": "issued-ingest-token"})[0]
        assert TOKEN in shown and page.value({"css": "input"}) == TOKEN
        assert page.op("mask_secrets") == 0
        assert not page.contains(TOKEN), "a displayed secret survived masking"
        assert page.value({"css": "input"}) != TOKEN
        assert TOKEN not in (page.attr({"css": "button"}, "data-copy") or "")
        page.finish(failed=True)
        out = tmp_path / "ui"
        assert (out / "failure.png").is_file(), "masked page should still be photographed"
        for f in out.iterdir():
            assert TOKEN.encode() not in f.read_bytes(), f"{f.name} carries the displayed token"
    finally:
        driver.close()
        web.stop()
        api.shutdown()
