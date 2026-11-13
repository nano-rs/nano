"""Add source (NAN-4922) end to end in the browser, for each push transport:
HEC, HTTP JSON and OTLP (through a real OpenTelemetry Collector and the
stack's nginx edge, the shipped config).

Per transport:
  catalog → Custom source → details (feed id) → transport → Connect:
  issue the token (shown once), copy the sender snippet FROM THE CLIPBOARD and
  execute it as copied, see the first-event panel go green; Finish lands on
  Log Sources with the row highlighted and its count == the API; the source
  detail shows delivery "receiving", the health chart's total == the
  health-series API, the credentials card revokes the token (the next send
  is a 401); the health drill-down opens Search on `metadata.log_source`.
  The token never shows again (DOM after resume/reload, API responses).
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import httpx
import pytest

from nano_e2e import ingest
from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.runid import route_key
from nano_e2e.stack import Stack
from nano_e2e.ui import field, rx
from nano_e2e.waits import INGEST_VISIBLE, eventually

OTELCOL_IMAGE = (
    "otel/opentelemetry-collector-contrib"
    "@sha256:a2a52e43c1a80aa94120ad78c2db68780eb90e6d11c8db5b3ce2f6a0cc6b5029"
)
SNIPPET_BUTTON = {
    "hec": "Copy curl config",
    "nano_https": "Copy curl config",
    "otlp_http": "Copy OpenTelemetry Collector config",
}
SENDS = 3


def _source_by_route(nano: Nano, rk: str) -> dict[str, Any] | None:
    for s in api_expect(nano.api.get("/api/log-sources"), 200):
        if rk in (s.get("match_values") or []) or s.get("name") == rk:
            return s
    return None


@pytest.fixture
def created_sources(nano: Nano) -> Iterator[list[str]]:
    """Ids of sources a scenario created in the UI, deleted at teardown (with
    their tokens revoked first)."""
    ids: list[str] = []
    yield ids
    tokens = api_expect(nano.api.get("/api/ingest-tokens"), 200)
    items = tokens if isinstance(tokens, list) else tokens.get("tokens", tokens.get("credentials", []))
    names = {s.get("id"): s.get("name") for s in api_expect(nano.api.get("/api/log-sources"), 200)}
    for t in items:
        if t.get("source_name") in {names.get(i) for i in ids} and t.get("state") != "revoked":
            nano.api.post(f"/api/ingest-tokens/{t['credential_id']}/revoke")
    for sid in ids:
        nano.api.delete(f"/api/log-sources/{sid}")


def _wizard_to_connect(page: uilib.UiPage, name: str, rk: str, transport: str) -> None:
    page.goto("/ingestion/log-sources/new")
    page.wait_for({"testid": "add-feed-linear"})
    page.click({"text": "Custom source", "exact": True, "within": {"testid": "source-catalog"}})
    page.fill(field({"css": "#add-source-name"}, name))
    page.click({"testid": "source-continue"})
    page.fill(field({"testid": "feed-identifier"}, rk))
    page.click({"testid": "details-continue"})
    page.click({"testid": f"transport-{transport}"})
    page.click({"testid": "transport-continue"})
    page.wait_for({"testid": "issue-credential-panel"})


def _issue_token(page: uilib.UiPage, token_name: str) -> str:
    page.fill(field({"css": "#ingest-credential-label"}, token_name))
    page.click({"role": "button", "name": rx("^Issue")})
    page.wait_for({"testid": "one-time-token"})
    token = page.value({"css": 'input[aria-label="Ingest token"]'})
    page.driver.register_secret(token)
    assert token.startswith("nit_"), "the issued token is not an ingest token"
    return token


def _run_snippet(stack: Stack, transport: str, snippet: str, mark: str, tmp: Path) -> int:
    """Execute the copied snippet: the curl ones as copied; the OTel Collector
    one in a real collector (copied config verbatim + a receiver, and the
    endpoint re-pointed at the edge's in-network name: 127.0.0.1 inside the
    container is the container)."""
    if transport in ("hec", "nano_https"):

        def run() -> str:
            # Never `bash -c <snippet>`: the token would sit in bash's argv.
            out = ingest.run_secret_script(stack.run_dir, snippet)
            assert out.returncode == 0, f"the copied curl snippet failed: {out.stderr[-500:]}"
            return out.stdout

        # A new token is accepted once Vector re-read its token file (~2 s).
        # With Vector scaled out (Helm chart, HPA) every pod reloads on its own
        # cycle and each send may land on another pod, so wait for several
        # CONSECUTIVE acceptances (NAN-4973); every later send must succeed.
        streak = {"n": 0, "accepted": 0}

        def accepted() -> int:
            try:
                o = run()
                if "401" not in o and "rror" not in o:
                    streak["n"] += 1
                    streak["accepted"] += 1
                else:
                    streak["n"] = 0
            except AssertionError:
                streak["n"] = 0
            return streak["n"]

        eventually(
            accepted,
            timeout=60,
            interval=1,
            desc="the copied snippet to be accepted (every Vector replica)",
            ok=lambda n: n >= 6,
        )
        for _ in range(SENDS - 1):
            o = run()
            assert "401" not in o and "rror" not in o, o[-300:]
            streak["accepted"] += 1
        return streak["accepted"]
    project = stack.project
    name = f"{project}-otelcol-{mark[-8:]}"
    old = os.umask(0o077)
    try:
        (tmp / "snippet.yaml").write_text(snippet)
        (tmp / "local.yaml").write_text(
            "receivers:\n  otlp:\n    protocols:\n      http:\n        endpoint: 0.0.0.0:4318\n"
            "exporters:\n  otlphttp/nano:\n    logs_endpoint: http://edge/otlp/v1/logs\n"
        )
    finally:
        os.umask(old)
    os.chmod(tmp, 0o755)  # noqa: S103 - the collector (non-root) reads this test's own dir
    for f in ("snippet.yaml", "local.yaml"):
        os.chmod(tmp / f, 0o644)  # read by the collector's non-root user; tmp is this test's own dir
    port_out = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "--network",
            f"{project}_default",
            "--label",
            f"nano.e2e.project={project}",
            "--label",
            f"nano.e2e.started={int(time.time())}",
            "-p",
            "127.0.0.1::4318",
            "-v",
            f"{tmp}:/etc/otel:ro",
            OTELCOL_IMAGE,
            "--config=/etc/otel/snippet.yaml",
            "--config=/etc/otel/local.yaml",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert port_out.returncode == 0, f"otel collector did not start: {port_out.stderr[-500:]}"
    try:
        port = (
            subprocess.run(
                ["docker", "port", name, "4318/tcp"], capture_output=True, text=True, timeout=30, check=True
            )
            .stdout.strip()
            .rsplit(":", 1)[-1]
        )
        body = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [{"key": "service.name", "value": {"stringValue": "nano-e2e"}}]
                    },
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": str(time.time_ns()),
                                    "body": {"stringValue": f"{mark} otlp seq={i}"},
                                }
                                for i in range(SENDS)
                            ]
                        }
                    ],
                }
            ]
        }

        def send() -> int:
            return httpx.post(f"http://127.0.0.1:{port}/v1/logs", json=body, timeout=10).status_code

        eventually(send, timeout=60, interval=2, desc="the collector to accept logs", ok=lambda s: s == 200)
        (tmp / "collector.log").write_text(
            subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=30).stderr[
                -20000:
            ]
        )
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60, check=False)
        (tmp / "snippet.yaml").unlink(missing_ok=True)
    return SENDS


def _send_with(stack: Stack, transport: str, token: str, endpoint: dict[str, Any]) -> int:
    if transport == "hec":
        r = httpx.post(
            f"{stack.hec_url}/services/collector/event",
            json={"event": {"message": "after revoke"}},
            headers={"Authorization": f"Splunk {token}"},
            timeout=10,
        )
    elif transport == "nano_https":
        r = httpx.post(
            endpoint["nano_https_url"],
            json={"message": "after revoke"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
    else:
        # The edge accepts OTLP/HTTP protobuf only (anything else is a 415
        # before auth); an empty body is a valid empty ExportLogsServiceRequest.
        r = httpx.post(
            endpoint["otlp_logs_url"],
            content=b"",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/x-protobuf"},
            timeout=10,
        )
    return r.status_code


@pytest.mark.parametrize("transport", ["hec", "nano_https", "otlp_http"])
def test_add_source_wizard(
    stack: Stack,
    nano: Nano,
    page: uilib.UiPage,
    mark: str,
    transport: str,
    created_sources,
    artifact_dir: Path,
    request,
    timeline,
) -> None:
    if transport == "otlp_http" and not os.environ.get("NANOSIEM_EDGE_URL"):
        pytest.fail("the OTLP scenario goes through the nginx edge; this stack has none (re-run `up`)")
    rk = route_key(request.node.nodeid, "src")
    name = f"e2e {transport} {rk[-6:]}"
    _wizard_to_connect(page, name, rk, transport)
    src = eventually(
        lambda: _source_by_route(nano, rk), timeout=30, desc="the draft source the wizard created"
    )
    assert src is not None
    created_sources.append(src["id"])
    assert src.get("lifecycle_status") == "draft", src
    timeline.step("ui: draft created", id=src["id"], transport=transport)

    issued_at = page.now_ms()
    token = _issue_token(page, f"{rk}-{transport}")
    tokens = api_expect(nano.api.get("/api/ingest-tokens"), 200)
    items = tokens if isinstance(tokens, list) else tokens.get("tokens", tokens.get("credentials", []))
    # Token rows carry the source as a UUID; the log-source API uses typeids:
    # match on the route key (the feed id) instead.
    mine = [t for t in items if t.get("route_key") == rk and t.get("state") != "revoked"]
    assert len(mine) == 1 and token.startswith(mine[0]["token_prefix"]), (mine, token[:12])
    timeline.step("ui: token issued (shown once)", prefix=mine[0]["token_prefix"])

    page.click({"role": "button", "name": SNIPPET_BUTTON[transport]})
    snippet = page.clipboard()
    assert token in snippet, "the copied snippet does not carry the issued token"
    endpoint = api_expect(nano.api.get("/api/log-sources/ingest-endpoint"), 200)
    if transport == "nano_https":
        assert endpoint["nano_https_url"] in snippet, "the copied snippet bypasses the ingest frontend"
    work = artifact_dir / "snippet-run"
    work.mkdir(exist_ok=True)
    expected_events = _run_snippet(stack, transport, snippet, mark, work)
    timeline.step("snippet executed as copied", sends=expected_events)

    page.wait_attr({"testid": "connect-step-events"}, "data-state", "done", timeout_ms=180_000)
    page.wait_attr({"testid": "first-event-step-searchable"}, "data-state", "done", timeout_ms=60_000)
    q = f'metadata.log_source="{rk}"'
    api_n = eventually(
        lambda: nano.search(q)["total_count"],
        timeout=INGEST_VISIBLE,
        desc="events via API",
        ok=lambda n: n >= expected_events,
    )
    assert api_n == expected_events, (api_n, expected_events)
    timeline.step("first event green", api_events=api_n)

    page.click({"role": "button", "name": "Copy token"})  # marks it saved: Finish enables
    page.click({"testid": "connect-finish"})
    page.wait_url(rf"/ingestion/log-sources\?highlight={re.escape(src['id'])}")
    row = {"css": 'tr[data-highlighted="true"]'}
    page.wait_for(row)
    row_text = " ".join(page.texts(row))
    assert name in row_text or rk in row_text, row_text
    status = api_expect(nano.api.get(f"/api/log-sources/{src['id']}/connect-status"), 200)
    summary = " ".join(page.texts({"testid": "ingest-summary", "within": row}))
    shown = int(re.search(r"([\d,]+)\s*ev", summary).group(1).replace(",", ""))  # type: ignore[union-attr]
    timeline.step("list row", summary=summary, api=status)
    assert shown == int(status.get("events_24h") or 0) == expected_events, (summary, status)

    # Source detail: delivery, health, credentials card.
    page.goto(f"/ingestion/log-sources/{src['id']}")
    page.wait_for({"testid": "delivery-row-push"}, timeout_ms=60_000)
    eventually(
        lambda: " ".join(page.texts({"testid": "delivery-row-push"})).lower(),
        timeout=60,
        desc="delivery row says receiving",
        ok=lambda t: "receiving" in t,
    )
    series = api_expect(
        nano.api.get(f"/api/log-sources/{src['id']}/health-series", params={"hours": 24}), 200
    )
    api_total = sum(
        int(pt.get("events") or 0)
        for sr in (series if isinstance(series, list) else [series])
        for pt in sr.get("points", [])
    )
    page.wait_for({"testid": "log-source-health-panel"})
    panel = eventually(
        lambda: " ".join(page.texts({"testid": "log-source-health-panel"})),
        timeout=60,
        desc="health panel total",
        ok=lambda t: re.search(r"[\d,]+\s+events", t) is not None,
    )
    m = re.search(r"([\d,]+)\s+events", panel)
    assert m, panel[:300]
    timeline.step("health", ui=m.group(1), api=api_total)
    assert int(m.group(1).replace(",", "")) == api_total == expected_events, (panel[:200], api_total)

    # The token is not shown again anywhere: the detail page, a resumed Connect
    # step, or any API response other than the one that issued it.
    assert not page.contains(token)
    page.goto(f"/ingestion/log-sources/new?source_id={src['id']}&stage=connect")
    page.wait_for({"testid": "issue-credential-panel"})
    assert page.count({"testid": "one-time-token"}) == 0 and not page.contains(token)
    leaks = page.responses_containing(token, since_ms=issued_at, except_path=r"^POST /api/ingest-tokens$")
    assert not leaks, f"the token came back from: {leaks}"

    # Health drill-down opens Search on the OCSF log-source field.
    # The latest hour's bucket (ArrowLeft from nothing selected): its tooltip
    # count == the API's last point; Enter drills down.
    page.goto(f"/ingestion/log-sources/{src['id']}")
    page.press_key({"testid": "health-band-chart"}, "ArrowLeft")
    page.wait_for({"testid": "health-chart-tooltip"})
    tip = " ".join(page.texts({"testid": "health-chart-tooltip"}))
    last_pt = [
        pt for sr in (series if isinstance(series, list) else [series]) for pt in sr.get("points", [])
    ][-1]
    tip_events = re.search(r"Events\s*([\d,]+)", tip)
    assert tip_events and int(tip_events.group(1).replace(",", "")) == int(last_pt.get("events") or 0), (
        tip,
        last_pt,
    )
    page.press_key({"testid": "health-band-chart"}, "Enter")
    url = page.wait_url(r"/search")
    qs = parse_qs(urlsplit(url).query) or parse_qs(urlsplit(url).fragment)
    query = unquote((qs.get("q") or [""])[0])
    timeline.step("drill-down", query=query)
    assert query == f'metadata.log_source="{rk}"', query
    page.wait_text("Query complete", exact=False, timeout_ms=60_000)
    if qs.get("start") and qs.get("end"):
        window = {"start": qs["start"][0], "end": qs["end"][0]}
        assert uilib.results_count(page) == nano.search(query, time_range=window)["total_count"]

    # Credentials card: revoke; the next send is refused.
    page.goto(f"/ingestion/log-sources/{src['id']}")
    page.wait_for({"testid": "source-writers-table"}, timeout_ms=60_000)
    page.click(
        {"role": "button", "name": "Revoke", "within": {"testid": "source-writers-table"}}, timeout_ms=40_000
    )
    page.click({"role": "button", "name": "Revoke token", "within": {"role": "alertdialog"}})
    page.wait_text("Token revoked", exact=False)
    eventually(
        lambda: _send_with(stack, transport, token, endpoint),
        timeout=30,
        desc="revoked token refused",
        ok=lambda code: code == 401,
    )
    timeline.step("revoked: next send 401")


def test_resume_with_source_param_lands_on_connect(
    nano: Nano, page: uilib.UiPage, created_sources, request, timeline
) -> None:
    """A draft started in the wizard (through Transport) and left: opening
    `?source=<feed id>` brings the operator back to its Connect step."""
    rk = route_key(request.node.nodeid, "resume")
    _wizard_to_connect(page, f"e2e resume {rk[-6:]}", rk, "hec")
    src = eventually(lambda: _source_by_route(nano, rk), timeout=30, desc="the draft source")
    assert src is not None
    created_sources.append(src["id"])
    page.goto("/ingestion/log-sources")
    page.goto(f"/ingestion/log-sources/new?source={rk}")
    url = page.wait_url(
        rf"source_id={re.escape(src['id'])}.*stage=connect|stage=connect.*source_id={re.escape(src['id'])}"
    )
    page.wait_for({"testid": "issue-credential-panel"})
    # A fresh Connect: no token is shown again, a new one can be issued.
    assert page.count({"testid": "one-time-token"}) == 0
    timeline.step("resumed", url=url)


def _receiving_draft(stack: Stack, nano: Nano, token_source, mark: str):
    src = token_source("draft", settle=True)
    for i in range(3):
        r = ingest.hec(stack.hec_url, src.token, {"message": f"{mark} draft seq={i}"})
        assert r.status_code == 200, r.text
    eventually(
        lambda: nano.search(f'"{mark}"')["total_count"],
        timeout=INGEST_VISIBLE,
        desc="unparsed events",
        ok=lambda n: n >= 3,
    )
    status = api_expect(nano.api.get(f"/api/log-sources/{src.source_id}/connect-status"), 200)
    assert status.get("state") == "receiving_unparsed", status
    return src, status


def test_draft_receives_before_parser_and_offers_build_parser(
    stack: Stack, nano: Nano, page: uilib.UiPage, token_source, mark: str, timeline
) -> None:
    """A draft with no parser receives data; the list offers to continue its
    setup, and the wizard's Sample & parse step shows what was received."""
    src, status = _receiving_draft(stack, nano, token_source, mark)
    page.goto("/ingestion/log-sources")
    row = {"role": "row", "name": rx(re.escape(src.route_key))}
    page.wait_for(row)
    page.click({"testid": "continue-setup", "within": row})
    page.wait_for({"testid": "add-feed-linear"})
    cont = {"role": "button", "name": rx("Continue · sample")}
    eventually(
        lambda: page.count({"testid": "parse-received"}) + page.count(cont),
        timeout=30,
        interval=1,
        desc="the wizard to land on Sample & parse or Connect",
        ok=lambda n: n > 0,
    )
    if page.count({"testid": "parse-received"}) == 0:
        # Lands on Connect today (see the xfail below); the step's own button
        # goes on to Sample & parse.
        page.click({"role": "button", "name": rx("Continue · sample")})
    page.wait_for({"testid": "parse-received"})
    m = re.search(r"([\d,]+)\s+events?", " ".join(page.texts({"testid": "parse-received"})))
    assert m, "no event count on the parse step"
    shown = int(m.group(1).replace(",", ""))
    timeline.step("parse step", shown=shown, api=status.get("events_24h"))
    assert shown >= 3


@pytest.mark.xfail(
    strict=False,
    reason="product finding (NAN-4937), intermittent: Log Sources 'Continue setup' links to "
    "?stage=parse, but "
    "the wizard often rewrites the URL to stage=connect and opens Connect (a resume/URL-sync race)",
)
def test_continue_setup_lands_on_sample_and_parse(
    stack: Stack, nano: Nano, page: uilib.UiPage, token_source, mark: str
) -> None:
    src, _ = _receiving_draft(stack, nano, token_source, mark)
    page.goto("/ingestion/log-sources")
    row = {"role": "row", "name": rx(re.escape(src.route_key))}
    page.wait_for(row)
    page.click({"testid": "continue-setup", "within": row})
    page.wait_for({"testid": "parse-received"}, timeout_ms=30_000)


def test_repository_parser_import_from_wizard(
    nano: Nano, page: uilib.UiPage, created_sources, request, timeline
) -> None:
    """Add source > From repositories (NAN-4940 follows nano-rs/parsers on every
    install): pick a catalog parser, finish the wizard on HEC; the source is
    imported LINKED to its repository and deployed at once (== the API)."""
    repos = api_expect(nano.api.get("/api/parser-repositories"), 200)
    items = repos if isinstance(repos, list) else repos.get("repositories", repos.get("items", []))
    parsers = next((r for r in items if r.get("enabled") and r.get("last_sync_status") == "success"), None)
    assert parsers, f"no synced parser repository on this stack: {items}"
    rk = route_key(request.node.nodeid, "repo")
    name = f"{rk}-generic"

    page.goto("/ingestion/log-sources/new")
    catalog = {"testid": "source-catalog"}
    page.wait_text("From repositories", exact=False, timeout_ms=30_000)
    page.fill(field({"css": 'input[aria-label="Search supported sources"]', "within": catalog}, "Generic JSON"))
    page.click({"role": "option", "name": rx("^Generic JSON"), "within": catalog})
    page.fill(field({"css": "#add-source-name"}, name))
    page.click({"testid": "source-continue"})
    page.fill(field({"testid": "feed-identifier"}, rk))
    page.click({"testid": "details-continue"})
    page.click({"testid": "transport-hec"})
    page.click({"testid": "transport-continue"})
    page.wait_for({"testid": "issue-credential-panel"}, timeout_ms=90_000)

    src = eventually(
        lambda: next(
            (x for x in api_expect(nano.api.get("/api/log-sources"), 200) if rk in (x.get("match_values") or [])),
            None,
        ),
        timeout=60,
        desc="imported source in the API",
        ok=lambda x: x is not None,
    )
    created_sources.append(src["id"])
    full = api_expect(nano.api.get(f"/api/log-sources/{src['id']}"), 200)
    timeline.step(
        "imported",
        id=src["id"],
        repo=full.get("source_parser_repository_id"),
        deployed=full.get("deployed"),
        match=full.get("match_values"),
    )
    assert full.get("source_parser_repository_id") == parsers["id"], "not linked to its repository"
    assert full.get("parser_vrl", "").strip(), "imported with no parser"
    assert rk in (full.get("match_values") or []), full.get("match_values")
    eventually(
        lambda: api_expect(nano.api.get(f"/api/log-sources/{src['id']}"), 200).get("deployed"),
        timeout=90,
        desc="deployed at once",
        ok=bool,
    )
    if full.get("name") != name:
        pytest.xfail(
            f"product finding (NAN-4937): the wizard shows the source as {name!r} (Step 1 name), but the "
            f"repository import stores the catalog name {full.get('name')!r}"
        )
