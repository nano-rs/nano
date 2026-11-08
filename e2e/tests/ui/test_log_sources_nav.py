"""NAN-4941: Log Sources is the single ingestion home. Every tab and action,
in the browser, compared to the API:

- the tab strip (Log sources / Credentials / Cloud pull / Pull feeds) and
  each tab's route;
- Credentials: ingest tokens issue / rotate / revoke (old token 401 after
  rotate, new one 401 after revoke; plaintext only in its one dialog), and the
  push listeners it lists == the API's listener source configs;
- Repositories (the rail entry under Ingestion): the first-party catalogs
  are followed with no clicks, and the page lists what the API has;
- permissions: a role without credentials:* sees no secret and can't mutate
  one; a role without log_sources:view lands on the first tab it can open.

Explicit skip (naming NAN-4941) on a build without the tabs.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest

from nano_e2e import ingest, ui_pull
from nano_e2e import ui as uilib
from nano_e2e.client import Journal, Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.rbac import limited_user
from nano_e2e.runid import route_key
from nano_e2e.stack import Stack
from nano_e2e.ui import field, rx
from nano_e2e.waits import eventually

TABS = {
    "Log sources": "/ingestion/log-sources",
    "Credentials": "/ingestion/log-sources/credentials",
    "Cloud pull": "/ingestion/log-sources/cloud-pull",
    "Pull feeds": "/ingestion/log-sources/pull-feeds",
}
# Repositories left the tab strip for the rail (Ingestion > Repositories).
REPOSITORIES = "/ingestion/log-sources/repositories"
TAB_NAV = {"css": 'nav[aria-label="Log sources"]'}


@pytest.fixture(autouse=True)
def _needs_tabs(page: uilib.UiPage) -> None:
    if ui_pull.ingestion_layout(page) != ui_pull.LOG_SOURCES_TABS:
        pytest.skip(
            "Log Sources tabs are not in this build yet (NAN-4941, branch feat/ingestion-simplified-nav)"
        )


def _tokens(nano: Nano) -> list[dict]:
    body = api_expect(nano.api.get("/api/ingest-tokens"), 200)
    return body["tokens"] if isinstance(body, dict) else body


@pytest.fixture
def draft(nano: Nano, request: pytest.FixtureRequest) -> Iterator[dict]:
    rk = route_key(request.node.nodeid, "nav")
    src = nano.create_draft_source(name=rk, route_key=rk)
    yield {**src, "route_key": rk}
    for t in _tokens(nano):
        if t.get("route_key") == rk and t.get("state") != "revoked":
            nano.api.post(f"/api/ingest-tokens/{t['credential_id']}/revoke")
    nano.delete_source(src["id"])


def _confirm(page: uilib.UiPage, trigger: dict, confirm_label: str) -> None:
    """Click a row action and confirm its dialog; the row re-renders on every
    poll (30 s), so a click that lands mid-render is retried once."""
    dlg = {"role": "alertdialog"}
    for attempt in range(2):
        page.click(trigger)
        try:
            page.wait_for(dlg, timeout_ms=10_000)
            break
        except uilib.UiError:
            if attempt:
                raise
    page.click({"role": "button", "name": confirm_label, "exact": True, "within": dlg})


def test_tab_strip_routes(page: uilib.UiPage, timeline) -> None:
    for label, path in TABS.items():
        page.goto(path)
        page.wait_for({"role": "link", "name": label, "exact": True, "within": TAB_NAV})
        current = page.attr({"role": "link", "name": label, "exact": True, "within": TAB_NAV}, "aria-current")
        timeline.step("tab", label=label, current=current)
        assert current == "page", f"{path}: tab {label} is not the current one"
    links = page.texts({"role": "link", "within": TAB_NAV})
    assert [t.strip() for t in links] == list(TABS), links


def test_credentials_tab_ingest_token_lifecycle(
    stack: Stack, nano: Nano, page: uilib.UiPage, draft: dict, timeline
) -> None:
    rk = draft["route_key"]
    name = f"{rk}-tok"
    page.goto("/ingestion/log-sources/credentials")
    page.wait_for({"testid": "ingest-tokens-panel"})

    # Issue, bound to the draft source.
    page.click({"role": "button", "name": "New token", "within": {"testid": "ingest-tokens-panel"}})
    dlg = {"testid": "issue-ingest-token-dialog"}
    page.fill(field({"css": "#ingest-token-name", "within": dlg}, name))
    page.choose({"role": "combobox", "name": "Source", "within": dlg}, rx(re.escape(rk)))
    since = page.now_ms()
    page.click({"role": "button", "name": "Issue token", "within": dlg})
    page.wait_for({"testid": "issued-ingest-token"})
    token = page.texts({"testid": "issued-ingest-token"})[0].strip()
    page.driver.register_secret(token)
    mine = [t for t in _tokens(nano) if t.get("name") == name]
    assert len(mine) == 1 and mine[0].get("route_key") == rk and token.startswith(mine[0]["token_prefix"]), (
        mine
    )
    eventually(
        lambda: ingest.hec(stack.hec_url, token, {"message": "issued"}).status_code,
        timeout=60,
        desc="issued token accepted",
        ok=lambda s: s == 200,
    )
    page.click({"role": "button", "name": "Done"})
    assert not page.contains(token), "the issued token is still in the DOM after its dialog closed"
    timeline.step("issued", prefix=mine[0]["token_prefix"])

    # The row == the API (prefix, source, state).
    row = page.row_cells(name, within={"testid": "ingest-tokens-panel"})
    assert row.get("prefix", "").startswith(mine[0]["token_prefix"][:8]) and rk in row.get("source", ""), row

    # Rotate: a new token; the old one stops working.
    _confirm(
        page,
        {"role": "button", "name": "Rotate", "within": {"role": "row", "name": rx(re.escape(name))}},
        "Rotate",
    )
    page.wait_for({"testid": "rotated-ingest-token"})
    new = page.texts({"testid": "rotated-ingest-token"})[0].strip()
    page.driver.register_secret(new)
    assert new != token
    eventually(
        lambda: ingest.hec(stack.hec_url, token, {"message": "old"}).status_code,
        timeout=60,
        desc="old token refused after rotate",
        ok=lambda s: s == 401,
    )
    eventually(
        lambda: ingest.hec(stack.hec_url, new, {"message": "new"}).status_code,
        timeout=60,
        desc="rotated token accepted",
        ok=lambda s: s == 200,
    )
    page.click(
        {"role": "button", "name": rx("^(Done|Close)$"), "within": {"testid": "rotated-ingest-token-dialog"}}
    )
    timeline.step("rotated")

    # Revoke the rotated one: refused, and the row says revoked like the API.
    rotated_name = next(t["name"] for t in _tokens(nano) if new.startswith(t["token_prefix"]))
    _confirm(
        page,
        {"role": "button", "name": "Revoke", "within": {"role": "row", "name": rx(re.escape(rotated_name))}},
        "Revoke",
    )
    page.wait_text("Ingest token revoked", exact=False)
    eventually(
        lambda: ingest.hec(stack.hec_url, new, {"message": "revoked"}).status_code,
        timeout=60,
        desc="revoked token refused",
        ok=lambda s: s == 401,
    )
    leaks = page.responses_containing(token, since_ms=since, except_path=r"^POST /api/ingest-tokens$")
    leaks += page.responses_containing(
        new, since_ms=since, except_path=r"^POST /api/ingest-tokens/[^/]+/rotate$"
    )
    assert not leaks, f"a token came back from: {leaks}"
    timeline.step("revoked")


def test_push_listeners_match_api(nano: Nano, page: uilib.UiPage, timeline) -> None:
    configs = api_expect(nano.api.get("/api/source-configurations"), 200)
    items = configs if isinstance(configs, list) else configs.get("items", [])
    listeners = sorted(
        c["name"] for c in items if c.get("config_type") in ("http", "vector", "otlp", "splunk_hec")
    )
    page.goto("/ingestion/log-sources/credentials")
    page.wait_for({"testid": "push-listeners"})
    # The list loads after the panel renders: wait until it shows every listener.
    shown = eventually(
        lambda: page.texts({"testid": "push-listeners"})[0],
        timeout=30,
        interval=1,
        desc="push listeners listed",
        ok=lambda t: all(n in t for n in listeners),
    )
    timeline.step("listeners", api=listeners)
    for name in listeners:
        assert name in shown, f"listener {name!r} from the API is not listed"


def test_repositories_tab_matches_api(nano: Nano, page: uilib.UiPage, timeline) -> None:
    """NAN-4940: a fresh install follows nano-rs/parsers and nano-rs/rules with
    no clicks (OCSF stack -> channel `main`, auto-sync on) and syncs them; the
    tab lists exactly the parser repositories the API has."""

    def repos(path: str) -> list[dict]:
        body = api_expect(nano.api.get(path), 200)
        return body if isinstance(body, list) else body.get("repositories", body.get("items", []))

    def first_party(items: list[dict], repo: str) -> dict | None:
        return next((r for r in items if r.get("url", "").rstrip("/").removesuffix(".git").endswith(repo)), None)

    parsers = eventually(
        lambda: first_party(repos("/api/parser-repositories"), "nano-rs/parsers"),
        timeout=180,
        interval=5,
        desc="nano-rs/parsers registered and synced",
        ok=lambda r: r is not None and r.get("last_sync_status") == "success",
    )
    rules = eventually(
        lambda: first_party(repos("/api/rule-repositories"), "nano-rs/rules"),
        timeout=180,
        interval=5,
        desc="nano-rs/rules registered",
        ok=lambda r: r is not None,
    )
    timeline.step("first-party", parsers=parsers, rules={k: rules.get(k) for k in ("url", "branch", "auto_sync_enabled")})
    for r in (parsers, rules):
        assert r.get("branch") == "main" and r.get("auto_sync_enabled") is True, r

    items = repos("/api/parser-repositories")
    page.goto("/ingestion/log-sources")
    page.click({"role": "link", "name": "Repositories", "exact": True}, timeout_ms=30_000)
    page.wait_url(re.escape(REPOSITORIES))
    timeline.step("repositories", api=[r.get("name") for r in items])
    # The page names each library by its git identity (owner/repo): one per
    # repository the API has.
    for r in items:
        ident = "/".join(r["url"].rstrip("/").removesuffix(".git").split("/")[-2:])
        page.wait_text(ident, exact=False, timeout_ms=30_000)
    page.wait_text(rx(r"synced .* ago"), exact=False)


def test_without_credentials_permissions_no_secret_and_no_mutation(
    stack: Stack, ui: uilib.Driver, artifact_dir, timeline
) -> None:
    perms = ["log_sources:view", "source_configs:view", "parsers:view", "search:view"]
    with limited_user(stack, "nocreds", perms, Journal(artifact_dir / "api.jsonl")) as user:
        p = uilib.UiPage.open(ui, artifact_dir / "ui-limited", "no credentials:*")
        failed = True
        try:
            uilib.login(p, user.email, user.password)
            p.goto("/ingestion/log-sources/cloud-pull")
            p.wait_for({"testid": "cloud-pull-page"})
            assert p.count({"testid": "credentials-manager"}) == 0, (
                "credential store visible without credentials:view"
            )
            assert p.count({"role": "button", "name": rx("Enter new|Add credential|Rotate|Rollback")}) == 0
            assert p.count({"testid": "credential-secret-masked"}) == 0
            failed = False
        finally:
            p.finish(failed)
    timeline.step("no credentials:*: nothing to see or mutate")


def test_without_log_sources_view_lands_on_first_tab(
    stack: Stack, ui: uilib.Driver, artifact_dir, timeline
) -> None:
    perms = ["source_configs:view", "credentials:view", "search:view"]
    with limited_user(stack, "nologsrc", perms, Journal(artifact_dir / "api.jsonl")) as user:
        p = uilib.UiPage.open(ui, artifact_dir / "ui-limited", "no log_sources:view")
        failed = True
        try:
            uilib.login(p, user.email, user.password)
            p.goto("/")
            p.click({"role": "button", "name": "Ingestion"}, timeout_ms=20_000)
            p.click({"role": "link", "name": "Log Sources"})
            url = p.wait_url(r"/ingestion/log-sources/cloud-pull")
            assert p.count({"role": "link", "name": "Log sources", "exact": True, "within": TAB_NAV}) == 0
            timeline.step("landed", url=url)
            failed = False
        finally:
            p.finish(failed)
