"""IPinfo Lite is served only from nano's signed platform feed bundle (NAN-4959).

Against the platform feed status API, in the browser:

- the catalog entry declares no credential field (`requires_credential = none`)
  and the configure API refuses a bring-your-own `download_url` (422); the
  retired native configure / sync / auto-sync endpoints are gone;
- the IPinfo Lite inventory drawer (`/marketplace?item=ipinfo_lite`) shows the
  bundle status: provided by the signed bundle, the revision the status API
  reports (or `—` when no bundle carries it), last update and next refresh;
  it has no credential inputs and no Configure / Uninstall actions;
- the connection drawer's Config tab (`&author=connect&tab=config`, an old deep
  link) shows the same bundle status and no inputs either.
"""

from __future__ import annotations

from nano_e2e import ui as uilib
from nano_e2e.client import Nano
from nano_e2e.client import expect as api_expect

SLUG = "ipinfo_lite"
BYO_URL = "https://ipinfo.io/data/ipinfo_lite.csv.gz?token=e2e-nan4959"


def _ipinfo_feed(status: dict) -> dict | None:
    if not status.get("installed"):
        return None
    return next((f for f in status.get("feeds", []) if f.get("feed_id") == SLUG), None)


def _text(page: uilib.UiPage, testid: str) -> str:
    texts = page.texts({"testid": testid})
    assert texts, f"{testid} not rendered"
    return texts[0].strip()


def _assert_bundle_status(page: uilib.UiPage, feed: dict | None, status: dict) -> None:
    page.wait_for({"testid": "bundle-feed-status"}, timeout_ms=30_000)
    assert "signed bundle" in _text(page, "inventory-bundle")
    revision = _text(page, "bundle-feed-revision")
    assert revision == (str(feed["revision"]) if feed else "—"), (revision, feed)
    state = _text(page, "bundle-feed-state")
    assert state.startswith(feed["state"] if feed else "not installed"), (state, feed)
    last_update = _text(page, "bundle-feed-last-update")
    assert (last_update != "—") == bool(feed and feed.get("produced_at")), (last_update, feed)
    next_refresh = _text(page, "bundle-feed-next-refresh")
    if status.get("auto_update") is False:
        assert "import a bundle file" in next_refresh, next_refresh
    elif status.get("next_check_at"):
        assert "·" in next_refresh, next_refresh
    else:
        assert "first scheduled check" in next_refresh, next_refresh
    assert "no download URL" in _text(page, "inventory-bundle-note")


def test_ipinfo_lite_is_bundle_only(nano: Nano, page: uilib.UiPage, timeline) -> None:
    entry = api_expect(nano.api.get(f"/api/marketplace/catalog/{SLUG}"), 200)
    fields = [f.get("name") for f in entry.get("credential_fields") or []]
    assert "download_url" not in fields, fields
    assert entry.get("requires_credential") == "none", entry.get("requires_credential")

    refused = nano.api.put(
        f"/api/marketplace/catalog/{SLUG}/configure", json={"credentials": {"download_url": BYO_URL}}
    )
    assert refused.status_code == 422, (refused.status_code, refused.text[:300])
    assert "platform feed bundle" in refused.text
    for method, path in [
        ("POST", "/api/enrichment/ipinfo/configure"),
        ("POST", "/api/enrichment/ipinfo/sync"),
        ("GET", "/api/enrichment/sources/ipinfo_lite/auto-sync"),
    ]:
        r = nano.api.request(method, path, json={"download_url": BYO_URL} if method == "POST" else None)
        assert r.status_code in (404, 405), (method, path, r.status_code)
    sources = api_expect(nano.api.get("/api/enrichment/sources"), 200)["sources"]
    assert all("download_url" not in s for s in sources), "sources API no longer returns download_url"
    timeline.step("api: no BYO surface", fields=fields)

    status = api_expect(nano.api.get("/api/enrichment/platform-feeds"), 200)
    feed = _ipinfo_feed(status)
    timeline.step("platform feed status", installed=status.get("installed"), ipinfo=feed,
                  next_check_at=status.get("next_check_at"), auto_update=status.get("auto_update"))

    # Inventory drawer (the card's default drawer).
    page.goto(f"/marketplace?item={SLUG}")
    page.wait_for({"testid": "inventory-details"}, timeout_ms=30_000)
    _assert_bundle_status(page, feed, status)
    assert page.count({"css": '[role="dialog"] input, [role="dialog"] textarea, [role="dialog"] select'}) == 0
    buttons = page.texts({"css": '[role="dialog"] button'})
    assert not any(b.strip() in ("Configure", "Uninstall", "Disable", "Enable", "Sync now") for b in buttons), buttons
    assert not page.contains(BYO_URL)
    timeline.step("inventory drawer", buttons=buttons)

    # Connection drawer, Config tab (old deep link).
    page.goto(f"/marketplace?item={SLUG}&author=connect&tab=config")
    page.wait_for({"testid": "bundle-only-config"}, timeout_ms=30_000)
    _assert_bundle_status(page, feed, status)
    assert page.count({"css": '[data-testid="bundle-only-config"] input'}) == 0
    assert page.count({"css": '[role="dialog"] input[type="password"], [role="dialog"] input[type="text"]'}) == 0
    assert not page.contains("Download URL")
    timeline.step("connection drawer config tab: bundle status, no inputs")


def test_threatfox_and_tor_are_bundle_only(nano: Nano, page: uilib.UiPage, timeline) -> None:
    """IOC parity (NAN-4959): ThreatFox and Tor exit nodes come only from the
    bundle too. Their catalog entries (when the first-party catalog has synced
    them) refuse install / sync / enable with 409, the legacy air-gap
    enrichment import is gone, and their drawers show the bundle status with no
    inputs."""
    entries = api_expect(nano.api.get("/api/marketplace/catalog"), 200)
    entries = entries.get("entries", entries) if isinstance(entries, dict) else entries
    slugs = {e.get("slug") for e in entries}
    checked: list[str] = []
    for slug in ("threatfox", "tor-exit-nodes"):
        if slug not in slugs:
            continue
        checked.append(slug)
        r = nano.api.post(f"/api/marketplace/catalog/{slug}/install", json={})
        assert r.status_code == 409 and "platform feed bundle" in r.text, (slug, r.status_code, r.text[:200])
        r = nano.api.post(f"/api/marketplace/catalog/{slug}/sync")
        assert r.status_code == 409, (slug, r.status_code)
        r = nano.api.put(f"/api/marketplace/catalog/{slug}/configure", json={"enabled": True})
        assert r.status_code == 409, (slug, r.status_code)
    # Legacy unfenced air-gap IP/IOC bundle import: removed (enterprise route).
    r = nano.api.post("/api/airgap/enrichment/import", files={"file": ("x.tar.gz", b"x", "application/gzip")})
    assert r.status_code in (404, 405), r.status_code
    timeline.step("api: ThreatFox/Tor refuse direct fetch", checked=checked)

    status = api_expect(nano.api.get("/api/enrichment/platform-feeds"), 200)
    for slug, feed_id in (("threatfox", "threatfox"), ("tor-exit-nodes", "tor_exit_nodes")):
        if slug not in slugs:
            continue
        feed = next((f for f in status.get("feeds", []) if f.get("feed_id") == feed_id), None) if status.get("installed") else None
        page.goto(f"/marketplace?item={slug}")
        page.wait_for({"testid": "inventory-details"}, timeout_ms=30_000)
        page.wait_for({"testid": "bundle-feed-status"}, timeout_ms=30_000)
        revision = _text(page, "bundle-feed-revision")
        assert revision == (str(feed["revision"]) if feed else "—"), (slug, revision, feed)
        assert page.count({"css": '[role="dialog"] input, [role="dialog"] textarea, [role="dialog"] select'}) == 0
        buttons = page.texts({"css": '[role="dialog"] button'})
        assert not any(b.strip() in ("Configure", "Install", "Enable", "Sync now") for b in buttons), (slug, buttons)
        timeline.step("drawer", slug=slug, revision=revision, buttons=buttons)
