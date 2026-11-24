"""NAN-5833: the UI driver's API body capture.

One captured body that never settled stayed in the session's pending set for
good, so every later layout check waited the full 10 s settle bound: two per
page, 20 s a page, and the top-level page smoke walk ran out of its 900 s
budget at page 74 of 99 with every page clean. Each capture now gives up on its
own, and only the app's own /api responses are captured (the browser Sentry
envelope POSTs are https://…sentry.io/api/<id>/envelope/)."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from nano_e2e import ui

JS = r"""
const m = await import('./tests/e2e/ui/driver.mjs');
const base = 'http://127.0.0.1:44637';
const caps = {
  app_json: m.capturesBody(base + '/api/rules', 'application/json', base),
  app_json_charset: m.capturesBody(base + '/api/rules?x=1', 'application/json; charset=utf-8', base),
  sentry: m.capturesBody('https://o1.ingest.us.sentry.io/api/45/envelope/?sentry_key=k', 'application/json', base),
  other_port: m.capturesBody('http://127.0.0.1:9/api/rules', 'application/json', base),
  ndjson: m.capturesBody(base + '/api/search/stream', 'application/x-ndjson', base),
  sse: m.capturesBody(base + '/api/events', 'text/event-stream', base),
  asset: m.capturesBody(base + '/assets/x.json', 'application/json', base),
  html: m.capturesBody(base + '/api/x', 'text/html', base),
};
// api_responses_since and the in-flight auth tracker use the same test.
const api = {
  app: m.isAppApi(base + '/api/rules', '/api/', base),
  sentry: m.isAppApi('https://o1.ingest.us.sentry.io/api/45/envelope/', '/api/', base),
  auth: m.isAppApi(base + '/api/auth/refresh', '/api/auth/', base),
  sentry_auth: m.isAppApi('https://x.example/api/auth/refresh', '/api/auth/', base),
  not_api: m.isAppApi(base + '/rules', '/api/', base),
};
const t0 = Date.now();
const never = await m.bounded(new Promise(() => {}), 50);
const waited = Date.now() - t0;
const done = await m.bounded(Promise.resolve('body'), 5000);
console.log(JSON.stringify({ caps, api, never: never === undefined, waited, done }));
process.exit(0);
"""


def test_capture_is_app_origin_only_and_self_bounded() -> None:
    if not shutil.which("node") or not (ui.WEB / "node_modules" / "puppeteer-core").is_dir():
        pytest.skip("needs node and nanosiem-web/node_modules/puppeteer-core")
    out = subprocess.run(
        ["node", "--input-type=module", "-e", JS], cwd=ui.WEB, capture_output=True, text=True, timeout=60, check=True
    )
    r = json.loads(out.stdout.strip().splitlines()[-1])
    assert r["caps"] == {
        "app_json": True, "app_json_charset": True, "sentry": False, "other_port": False,
        "ndjson": False, "sse": False, "asset": False, "html": False,
    }, r["caps"]
    assert r["api"] == {"app": True, "sentry": False, "auth": True, "sentry_auth": False, "not_api": False}, r["api"]
    # A body that never arrives resolves (as undefined) after its bound...
    assert r["never"] and r["waited"] < 2000, r
    # ...and one that arrives is passed through.
    assert r["done"] == "body", r


def test_every_api_url_match_is_app_origin() -> None:
    """Review P2: api_responses_since (and the in-flight auth tracker) matched
    any URL with /api/ in it, Sentry envelopes included. Every URL test in the
    driver goes through isAppApi; only path-shaped checks may test '/api/'."""
    src = (ui.WEB / "tests" / "e2e" / "ui" / "driver.mjs").read_text()
    start = src.index("async api_responses_since(")
    assert "isAppApi(n.url)" in src[start : start + 400]
    assert "/\\/api\\//.test(" not in src
    assert "isAppApi(r.url(), '/api/auth/')" in src
