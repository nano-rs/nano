"""Cloud pull and pull feeds set up through the web UI: the same product
objects the API scenarios create, but every step clicked and typed in the
browser (puppeteer driver, nano_e2e.ui).

Two layouts are supported, detected from what the build renders:

- **NAN-4941 Log Sources tabs** (`LOG_SOURCES_TABS`): Cloud pull →
  Add cloud pull; the connection and the credential are part of the add sheet
  and secrets are entered inline (`credential-picker` → Enter new →
  `add-credential-sheet`); a source config lives at
  `/ingestion/log-sources/inputs/:id`; pull feeds at
  `/ingestion/log-sources/pull-feeds`.
- **legacy** (before NAN-4941): Credentials page → Source configs page →
  detail page → Connection sheet.

Then, in both: routing → a deployed parser → save the rule → Deploy.
Secret fields are typed with `secret=True`: the driver scrubs them from
artifacts and blanks them before any screenshot.
"""

from __future__ import annotations

from typing import Any

from nano_e2e.ui import UiPage, field, rx

TRANSPORT_LABEL = {
    "aws_s3": "AWS S3",
    "aws_sqs": "AWS SQS",
    "gcp_pubsub": "GCP Pub/Sub",
    "azure_event_hubs": "Azure Event Hubs",
}
# Credential provider (the Add credential dialog's provider) per transport.
CREDENTIAL_PROVIDER = {
    "aws_s3": "aws_s3",
    "aws_sqs": "aws_s3",
    "gcp_pubsub": "gcp_pubsub",
    "azure_event_hubs": "azure_event_hubs",
}

LEGACY = "legacy"
LOG_SOURCES_TABS = "nan4941"
CLOUD_PULL_PATH = "/ingestion/log-sources/cloud-pull"
PULL_FEEDS_PATH = "/ingestion/log-sources/pull-feeds"

Fields = list[dict[str, Any]]  # nano_e2e.ui.field(...) entries, unscoped
SOURCE_PATH_RE = r"/ingestion/(source-configurations|log-sources/inputs)/[^/?#]+$"


def ingestion_layout(page: UiPage) -> str:
    """Which ingestion UI this build has: NAN-4941 tabs, or the legacy pages.
    Read from the web build under test (deterministic), else probed in the page."""
    import os
    from pathlib import Path

    dist = os.environ.get("E2E_WEB_DIST", "")
    if dist and (Path(dist) / "assets").is_dir():
        if _LAYOUT_CACHE.get(dist) is None:
            hit = any(
                "cloud-pull-sources" in f.read_text(errors="ignore")
                for f in (Path(dist) / "assets").glob("*.js")
            )
            _LAYOUT_CACHE[dist] = LOG_SOURCES_TABS if hit else LEGACY
        return _LAYOUT_CACHE[dist]
    return page.op("ingestion_layout")


_LAYOUT_CACHE: dict[str, str] = {}


def source_config_path(layout: str, config_id: str) -> str:
    if layout == LOG_SOURCES_TABS:
        return f"/ingestion/log-sources/inputs/{config_id}"
    return f"/ingestion/source-configurations/{config_id}"


def pull_feeds_path(layout: str) -> str:
    return PULL_FEEDS_PATH if layout == LOG_SOURCES_TABS else "/ingestion/pull-feeds"


def _scoped(scope: dict[str, Any], fields: Fields) -> Fields:
    return [{**f, "find": {**f["find"], "within": scope}} for f in fields]


def _create_credential_in(page: UiPage, sheet: dict[str, Any], cred_name: str, fields: Fields) -> None:
    page.fill(field({"role": "textbox", "name": rx("^Name"), "within": sheet}, cred_name))
    env = {"role": "combobox", "name": "Environment", "within": sheet}
    if page.count(env):
        page.select_native(env, "dev")
    page.fill(*_scoped(sheet, fields))
    page.click({"role": "button", "name": "Create credential", "within": sheet})
    page.wait_for(sheet, gone=True, timeout_ms=30_000)


def setup_pull_source(
    page: UiPage,
    config_type: str,
    cfg_name: str,
    cred_name: str,
    credential_fields: Fields,
    connection_fields: Fields,
    region: str | None = None,
) -> tuple[str, str]:
    """Credential + source config + connection, the way this build's UI does
    it. Returns (layout, source config id); the page is on the config's detail."""
    layout = ingestion_layout(page)
    label = TRANSPORT_LABEL[config_type]
    if layout == LEGACY:
        page.goto(f"/ingestion/credentials?add={CREDENTIAL_PROVIDER[config_type]}")
        _create_credential_in(
            page, {"role": "dialog", "name": "Add credential"}, cred_name, credential_fields
        )
        page.wait_text(cred_name)
        page.goto("/ingestion/source-configurations")
        page.click({"role": "button", "name": rx("Add source")})
        sheet = {"role": "dialog", "name": "Add source config"}
        page.click({"text": label, "exact": True, "within": sheet})
        page.click({"role": "button", "name": "Continue", "within": sheet})
        page.fill(field({"placeholder": f"{label} ingest", "within": sheet}, cfg_name))
        page.click({"role": "button", "name": rx("^Create"), "within": sheet})
        page.wait_url(SOURCE_PATH_RE)
        page.wait_for({"role": "heading", "name": cfg_name, "exact": True})
        cfg_id = page.url.rstrip("/").rsplit("/", 1)[-1]
        # Connection sheet: transport fields + the credential.
        page.click({"role": "button", "name": "Connection", "exact": True})
        conn = {"role": "dialog", "name": "Connection"}
        page.fill(*_scoped(conn, connection_fields))
        if region:
            _choose_region(page, conn, region)
        page.wait_text("Loading credentials…", gone=True, timeout_ms=30_000)
        page.choose({"role": "combobox", "within": conn, "last": True}, cred_name)
        page.click({"role": "button", "name": "Save", "exact": True, "within": conn})
        page.wait_for(conn, gone=True, timeout_ms=30_000)
        return layout, cfg_id

    # NAN-4941: Cloud pull → Add cloud pull; connection + credential at create.
    page.goto(CLOUD_PULL_PATH)
    page.click({"role": "button", "name": rx("Add cloud pull"), "within": {"testid": "cloud-pull-sources"}})
    sheet = {"role": "dialog", "name": rx("^Add ")}
    page.click({"text": label, "exact": True, "within": sheet})
    page.click({"role": "button", "name": "Continue", "within": sheet})
    page.fill(field({"placeholder": f"{label} ingest", "within": sheet}, cfg_name))
    conn = {"testid": "add-source-connection"}
    page.fill(*_scoped(conn, connection_fields))
    if region:
        _choose_region(page, conn, region)
    page.click({"role": "button", "name": rx("Enter new"), "within": {"testid": "credential-picker"}})
    _create_credential_in(page, {"testid": "add-credential-sheet"}, cred_name, credential_fields)
    page.wait_for({"testid": "credential-picker-selected"})
    # The secret is never shown back, only masked.
    page.wait_for({"css": '[aria-label="Secret hidden"]', "within": {"testid": "credential-picker-selected"}})
    page.click({"role": "button", "name": rx("^Create"), "within": sheet, "last": True})
    page.wait_url(r"/ingestion/log-sources/inputs/[^/?#]+$")
    page.wait_for({"role": "heading", "name": cfg_name, "exact": True})
    return layout, page.url.rstrip("/").rsplit("/", 1)[-1]


def _choose_region(page: UiPage, scope: dict[str, Any], region: str) -> None:
    trigger = {"css": "button[role=combobox]", "within": scope, "nth": 0}
    if (page.texts(trigger) or [""])[0].strip() != region:
        page.choose(trigger, region, exact=True)


def route_single(page: UiPage, parser_name: str) -> None:
    """Routing → single source type → the deployed parser → save the rule
    ("Create rule" on a config without one, "Save" once one exists)."""
    page.click({"role": "tab", "name": "Single source type"})
    page.click({"role": "combobox", "name": rx("Select a parser|e2e|_")})
    page.click({"role": "option", "name": rx(parser_name)})
    page.click({"role": "button", "name": rx("^(Create rule|Save)$")})


def deploy(page: UiPage) -> None:
    """Deploy / Deploy changes, confirmed in its dialog; returns once the page
    shows Deployed and no pending changes."""
    page.click({"role": "button", "name": rx("^Deploy")})
    confirm = {"role": "alertdialog"}
    page.click({"role": "button", "name": rx("Deploy$"), "within": confirm})
    page.wait_for(confirm, gone=True, timeout_ms=60_000)
    page.wait_text("Deployed", timeout_ms=60_000)
    page.wait_text("Pending", gone=True, timeout_ms=60_000)
