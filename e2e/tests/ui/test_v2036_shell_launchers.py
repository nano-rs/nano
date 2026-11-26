"""Menus, dialogs, shortcuts and banners of the app shell (v2.0.36, NAN-5864).

The route manifest proves every page loads; these scenarios prove the things
you open FROM a page do what they say. Every one of them is a "launcher" the
coverage gate (scripts/release/check-e2e-coverage.py) finds in the shell
components and maps to an `action:` entry of e2e/coverage/ui-surfaces.json.
As the install admin (every permission), in either edition:

- user menu: User Settings opens Settings > User, Docs and API point at the
  docs site and /swagger-ui/ in a new tab, the version line names this
  build, and there is no Theme submenu (the theme lives in the rail);
- Help menu, in the main shell and in the Settings shell: Report a bug, Get
  support and Docs;
- Settings top bar: the "Settings" breadcrumb goes to the Settings home, and
  the Recent changes drawer opens, closes (X, the dimmed page, "View full
  audit log") and opens an entry's page (the feed is stubbed with one user
  change: the stack's live log holds rows the drawer cannot open);
- notification bell: unread count, Mark all read, and a click on a
  notification opens its link and marks it read;
- keyboard: Cmd/Ctrl+B collapses and expands the rail (and the choice
  survives a reload), Cmd/Ctrl+K opens the command palette in the main shell
  and focuses "Search settings" in the Settings shell;
- the rail's own Collapse / Expand button and the top bar's Toggle sidebar;
- every collapsed-rail flyout lists its section's pages and opens them;
- the mobile menu drawer (390 px): it opens, a link navigates and closes it,
  and its user menu opens Settings > User;
- breadcrumbs: Home and the parent crumb navigate;
- the status bar's ingest summary opens Platform Health;
- the open-core banners: Backup (links, dismiss for the session), Disk space
  (links, snooze for an hour) and Capacity;
- the command palette: every command it shows opens its page, and it shows
  no command for a page this edition does not ship (open core: no Cases,
  Notebooks or Risk).

The banner and bell states a throwaway stack cannot reach (a stale backup, a
nearly full disk, unread notifications) come from `UiPage.stub_api`, which
answers those calls in this browser session only.
"""

from __future__ import annotations

import json
import re
from typing import Any

from nano_e2e import ui as uilib
from nano_e2e.client import Nano, expect
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually

RAIL = {"testid": "app-rail"}
USER_MENU = {"testid": "user-menu", "within": RAIL}
SETTINGS_RAIL = {"testid": "settings-rail"}
HELP = {"role": "button", "name": "Help", "exact": True}
DRAWER = {"css": 'aside[aria-label="Recent configuration changes"]'}
BELL = {"testid": "notification-bell"}
PALETTE = {"role": "dialog", "name": "Command palette", "exact": True}
MOBILE = {"role": "dialog", "name": "Navigation", "exact": True}
TOGGLE_SIDEBAR = {"role": "button", "name": "Toggle sidebar", "exact": True}


def _menuitem(name: str, **extra: Any) -> dict[str, Any]:
    return {"role": "menuitem", "name": name, "exact": True, **extra}


def _rail_settled(page: uilib.UiPage, collapsed: bool) -> None:
    eventually(lambda: page.rect(RAIL)["width"], timeout=10, interval=0.2,
               desc=f"rail {'collapsed' if collapsed else 'expanded'}",
               ok=lambda w: (w < 60) if collapsed else (w > 150))


def _home(page: uilib.UiPage, path: str = "/") -> None:
    page.viewport(1440, 900)
    page.goto(path)
    page.wait_for(RAIL, timeout_ms=30_000)


def _expand_rail(page: uilib.UiPage) -> None:
    if page.rect(RAIL)["width"] < 60:
        page.click(TOGGLE_SIDEBAR)
        _rail_settled(page, collapsed=False)


def _external(page: uilib.UiPage, find: dict[str, Any], href: str) -> None:
    """An external menu link opens `href` in a new tab (never clicked: the
    stack has no internet, and a new tab would leave the scenario's page)."""
    assert page.attr(find, "href") == href, (find, page.attr(find, "href"))
    assert page.attr(find, "target") == "_blank", f"{href} does not open in a new tab"
    assert "noopener" in (page.attr(find, "rel") or ""), f"{href} lacks rel=noopener"


# ── user menu ──────────────────────────────────────────────────────────────
def test_v2036_user_menu_items(nano: Nano, page: uilib.UiPage, timeline) -> None:
    version = str(expect(nano.api.get("/api/capabilities"), 200)["version"])
    _home(page)
    _expand_rail(page)
    page.click(USER_MENU)
    page.wait_for(_menuitem("User Settings"), timeout_ms=10_000)
    _external(page, {"css": 'a[role="menuitem"][href="https://nano.rs/docs/"]'}, "https://nano.rs/docs/")
    _external(page, {"css": 'a[role="menuitem"][href="/swagger-ui/"]'}, "/swagger-ui/")
    assert page.count(_menuitem("Sign out")) == 1
    assert page.count(_menuitem("Theme")) == 0, "the user menu still has a Theme submenu (NAN-5858)"
    # The version line (from /health/detailed) names this build.
    page.wait_text(uilib.rx(r"^nano v\d+\.\d+\.\d+"), timeout_ms=10_000)
    shown = page.texts({"text": uilib.rx(r"^nano v\d")})
    assert any(version in t for t in shown), f"version line {shown} does not name {version}"
    timeline.step("user menu", version=version, shown=shown)
    page.screenshot("v2036-user-menu.png", full_page=False)
    page.click(_menuitem("User Settings"))
    page.wait_url(r"/settings/user$")
    page.wait_for(SETTINGS_RAIL, timeout_ms=30_000)


# ── Help menu (both shells) ────────────────────────────────────────────────
def test_v2036_help_menu_in_the_main_and_settings_shells(page: uilib.UiPage, timeline) -> None:
    for path, shell in (("/rules", RAIL), ("/settings/user", SETTINGS_RAIL)):
        page.viewport(1440, 900)
        page.goto(path)
        page.wait_for(shell, timeout_ms=30_000)
        page.click(HELP)
        page.wait_for(_menuitem("Report a bug"), timeout_ms=10_000)
        assert page.count(_menuitem("Get support")) == 1, path
        _external(page, {"css": 'a[role="menuitem"][href="https://nano.rs/docs/"]'}, "https://nano.rs/docs/")
        page.click(_menuitem("Get support"))
        page.wait_for({"testid": "support-flyout"}, timeout_ms=10_000)
        page.wait_text("Get support", timeout_ms=10_000)
        page.press_key({"css": ":focus"}, "Escape")
        page.wait_for({"testid": "support-flyout"}, gone=True, timeout_ms=10_000)
        timeline.step("help menu", path=path)


# ── Settings top bar ───────────────────────────────────────────────────────
def test_v2036_settings_topbar_breadcrumb_and_recent_changes(page: uilib.UiPage, timeline) -> None:
    # The feed is the stack's live audit log, which earlier scenarios fill with
    # rows the drawer cannot open; one known row keeps this deterministic.
    entry_row = {
        "id": "e2e-nan5864-audit", "timestamp": "2026-11-23T10:00:00Z", "user_name": "e2e admin",
        "action": "update", "resource_type": "user", "resource_name": "e2e-nan5864-analyst",
        "success": True, "message": "Changed the role of e2e-nan5864-analyst",
    }
    page.stub_api("GET", "/api/audit?limit=200", {"logs": [entry_row], "total": 1})
    page.viewport(1440, 900)
    page.goto("/settings/user")
    page.wait_for(SETTINGS_RAIL, timeout_ms=30_000)
    page.click({"css": 'nav[aria-label="Breadcrumb"] a[href="/settings"]'})
    page.wait_url(r"/settings$")

    recent = {"role": "button", "name": uilib.rx(r"^Recent changes")}
    page.goto("/settings/user")
    page.wait_for(recent, timeout_ms=30_000)
    # The X closes it.
    page.click(recent)
    page.wait_for(DRAWER, timeout_ms=10_000)
    page.wait_text("Changed the role of e2e-nan5864-analyst", timeout_ms=10_000)
    page.screenshot("v2036-recent-changes.png", full_page=False)
    page.click({"role": "button", "name": "Close", "exact": True, "within": DRAWER})
    page.wait_for(DRAWER, gone=True, timeout_ms=10_000)
    # A click on the dimmed page closes it.
    page.click(recent)
    page.wait_for(DRAWER, timeout_ms=10_000)
    page.click({"css": ".absolute.inset-0.bg-black\\/30"})
    page.wait_for(DRAWER, gone=True, timeout_ms=10_000)
    # A user change opens Access control > Users and closes the drawer.
    page.click(recent)
    page.wait_for(DRAWER, timeout_ms=10_000)
    page.click({"css": "button", "has": "Changed the role of e2e-nan5864-analyst", "within": DRAWER})
    page.wait_url(r"/settings/access-control\?tab=users$")
    page.wait_for(DRAWER, gone=True, timeout_ms=10_000)
    # "View full audit log" goes to Settings > Audit.
    page.click(recent)
    page.wait_for(DRAWER, timeout_ms=10_000)
    page.click({"role": "button", "name": uilib.rx(r"^View full audit log"), "within": DRAWER})
    page.wait_url(r"/settings/audit$")
    page.wait_for(DRAWER, gone=True, timeout_ms=10_000)
    timeline.step("recent changes", entry="user")


# ── notification bell ─────────────────────────────────────────────────────
def _note(nid: str, title: str, link: str | None, read: bool) -> dict[str, Any]:
    note: dict[str, Any] = {
        "id": nid,
        "user_id": "e2e",
        "notification_type": "case_assigned",
        "title": title,
        "message": "Seeded by the NAN-5864 scenario.",
        "is_read": read,
        "metadata": {},
        "created_at": "2026-11-23T10:00:00Z",
    }
    if link:
        note["link"] = link
    if read:
        note["read_at"] = "2026-11-23T10:05:00Z"
    return note


def test_v2036_notification_bell_mark_all_read_and_click_through(page: uilib.UiPage, timeline) -> None:
    ids = ("00000000-0000-4000-8000-000000005864", "00000000-0000-4000-8000-000000005865")
    unread = [_note(ids[0], "e2e NAN-5864 rule fired", "/rules", False),
              _note(ids[1], "e2e NAN-5864 second note", None, False)]
    page.stub_api("GET", "/api/notifications/unread-count", {"count": 2})
    page.stub_api("GET", "/api/notifications?limit=20", {"notifications": unread})
    page.stub_api("POST", "/api/notifications/read-all", {"marked_count": 2})
    page.stub_api("POST", f"/api/notifications/{ids[0]}/read", {"notification": _note(ids[0], "e2e NAN-5864 rule fired", "/rules", True)})
    _home(page, "/search")
    eventually(lambda: page.attr(BELL, "aria-label"), timeout=20, interval=0.5,
               desc="the bell shows the unread count", ok=lambda a: a == "2 unread notifications")
    page.click(BELL)
    page.wait_text("e2e NAN-5864 rule fired", timeout_ms=10_000)
    page.screenshot("v2036-notification-bell.png", full_page=False)

    # Mark all read: the call goes out, and the bell follows the server.
    since = page.now_ms()
    page.stub_api("GET", "/api/notifications/unread-count", {"count": 0})
    page.stub_api("GET", "/api/notifications?limit=20", {
        "notifications": [{**n, "read_at": "2026-11-23T10:06:00Z"} for n in unread], "total": 2})
    page.click({"role": "button", "name": "Mark all read", "exact": True})
    eventually(lambda: page.requests_containing("/api/notifications/read-all", since_ms=since), timeout=10,
               interval=0.3, desc="POST read-all sent", ok=bool)
    page.wait_for({"role": "button", "name": "Mark all read", "exact": True}, gone=True, timeout_ms=10_000)
    eventually(lambda: page.attr(BELL, "aria-label"), timeout=10, interval=0.3,
               desc="the bell has no count", ok=lambda a: a == "Notifications")

    # A click on a notification with a link opens it and closes the popover.
    page.stub_api("GET", "/api/notifications/unread-count", {"count": 1})
    page.stub_api("GET", "/api/notifications?limit=20", {"notifications": unread[:1]})
    page.reload()
    page.wait_for(BELL, timeout_ms=30_000)
    page.click(BELL)
    since = page.now_ms()
    page.click({"text": "e2e NAN-5864 rule fired", "exact": True})
    page.wait_url(r"/rules$")
    eventually(lambda: page.requests_containing(f"/api/notifications/{ids[0]}/read", since_ms=since),
               timeout=10, interval=0.3, desc="the clicked notification was marked read", ok=bool)
    page.wait_text("e2e NAN-5864 rule fired", gone=True, timeout_ms=10_000)
    timeline.step("bell", mark_all=True, click_through="/rules")


# ── keyboard shortcuts and the rail's collapse controls ────────────────────
def test_v2036_sidebar_shortcut_and_collapse_buttons(page: uilib.UiPage, timeline) -> None:
    _home(page, "/rules")
    _expand_rail(page)
    # Cmd+B and Ctrl+B both toggle (the handler takes either).
    for mod in ("Meta", "Control"):
        page.press_key({"css": "body"}, "Escape")
        page.chord(mod, "b")
        _rail_settled(page, collapsed=True)
        page.chord(mod, "b")
        _rail_settled(page, collapsed=False)
    # The collapsed choice survives a reload.
    page.chord("Control", "b")
    _rail_settled(page, collapsed=True)
    page.reload()
    page.wait_for(RAIL, timeout_ms=30_000)
    _rail_settled(page, collapsed=True)
    # The rail's own button says what it will do.
    page.click({"role": "button", "name": "Expand sidebar", "exact": True, "within": RAIL})
    _rail_settled(page, collapsed=False)
    page.click({"role": "button", "name": "Collapse sidebar", "exact": True, "within": RAIL})
    _rail_settled(page, collapsed=True)
    page.click(TOGGLE_SIDEBAR)
    _rail_settled(page, collapsed=False)
    timeline.step("sidebar shortcut", ok=True)


def test_v2036_cmd_k_opens_the_palette_or_the_settings_search(page: uilib.UiPage) -> None:
    _home(page, "/rules")
    page.press_key({"css": "body"}, "Escape")
    page.chord("Control", "k")
    page.wait_for(PALETTE, timeout_ms=10_000)
    page.chord("Control", "k")
    page.wait_for(PALETTE, gone=True, timeout_ms=10_000)
    page.chord("Meta", "k")
    page.wait_for(PALETTE, timeout_ms=10_000)
    page.press_key({"css": ":focus"}, "Escape")
    page.wait_for(PALETTE, gone=True, timeout_ms=10_000)
    # In Settings the same keys focus the settings search (there is no palette there).
    page.goto("/settings/user")
    page.wait_for(SETTINGS_RAIL, timeout_ms=30_000)
    page.chord("Control", "k")
    eventually(lambda: page.attr({"css": ":focus"}, "placeholder"), timeout=10, interval=0.3,
               desc="Search settings focused", ok=lambda p: p == "Search settings…")
    assert page.count(PALETTE) == 0, "the command palette opened in the Settings shell"


# ── collapsed-rail flyouts ─────────────────────────────────────────────────
def test_v2036_collapsed_rail_flyouts_open_their_pages(page: uilib.UiPage, timeline) -> None:
    _home(page, "/search")
    _expand_rail(page)
    page.click(TOGGLE_SIDEBAR)
    _rail_settled(page, collapsed=True)
    triggers = {"css": '[data-testid="app-rail"] nav button[aria-haspopup="menu"]'}
    n = page.count(triggers)
    assert n >= 2, f"only {n} collapsed-rail flyouts (Rules and Ingestion are in every edition)"
    opened: dict[str, str] = {}
    for i in range(n):
        trigger = {**triggers, "nth": i}
        name = page.attr(trigger, "aria-label") or f"#{i}"
        page.hover(trigger)
        menu = {"role": "menu", "name": name, "exact": True}
        page.wait_for(menu, timeout_ms=10_000)
        items = page.attrs({"css": 'a[role="menuitem"]', "within": menu}, "href")
        assert items, f"flyout {name} lists no pages"
        target = items[-1]
        section = "/" + target.lstrip("/").split("/")[0].split("?")[0]
        page.click({"css": f'a[role="menuitem"][href="{target}"]', "within": menu})
        page.wait_url(re.escape(section))
        page.wait_for(menu, gone=True, timeout_ms=10_000)
        opened[name] = target
        _rail_settled(page, collapsed=True)
    timeline.step("flyouts", opened=opened)
    page.click(TOGGLE_SIDEBAR)
    _rail_settled(page, collapsed=False)


# ── mobile drawer ──────────────────────────────────────────────────────────
def test_v2036_mobile_menu_drawer(page: uilib.UiPage, timeline) -> None:
    page.viewport(390, 844)
    page.goto("/rules")
    open_menu = {"role": "button", "name": "Open menu", "exact": True}
    page.wait_for(open_menu, timeout_ms=30_000)
    page.click(open_menu)
    page.wait_for(MOBILE, timeout_ms=10_000)
    page.screenshot("v2036-mobile-drawer.png", full_page=False)
    page.click({"css": 'a[href="/search"]', "within": MOBILE})
    page.wait_url(r"/search")
    page.wait_for(MOBILE, gone=True, timeout_ms=10_000)
    page.click(open_menu)
    page.wait_for(MOBILE, timeout_ms=10_000)
    page.click({"testid": "mobile-user-menu", "within": MOBILE})
    page.wait_for(_menuitem("User Settings"), timeout_ms=10_000)
    # The Settings shell has no phone layout yet (NAN-5876: its rail takes the
    # screen and the page overflows), so open it from the drawer's menu at
    # desktop width: the drawer and its menu stay open across the resize.
    page.viewport(1440, 900)
    page.click(_menuitem("User Settings"))
    page.wait_url(r"/settings/user$")
    page.wait_for(MOBILE, gone=True, timeout_ms=10_000)
    timeline.step("mobile drawer", ok=True)


# ── breadcrumbs ────────────────────────────────────────────────────────────
def test_v2036_breadcrumb_links_navigate(page: uilib.UiPage) -> None:
    crumbs = {"css": 'nav[aria-label="breadcrumb"]'}
    _home(page, "/rules/coverage")
    page.click({"css": 'a[href="/rules"]', "within": crumbs})
    page.wait_url(r"/rules$")
    page.goto("/rules/editor/new")
    page.wait_for(crumbs, timeout_ms=30_000)
    page.click({"css": 'a[href="/"]', "within": crumbs})
    page.wait_url(r"//[^/]+/$")


# ── status bar ─────────────────────────────────────────────────────────────
def test_v2036_status_bar_opens_platform_health(nano: Nano, page: uilib.UiPage, timeline) -> None:
    expect(nano.api.post("/api/siem-health/reports/trigger", timeout=300), 200)
    report = expect(nano.api.get("/api/siem-health/reports/latest"), 200)
    # A build without AI fills the ingest narrative with a placeholder the bar
    # hides; give it a plain sentence so the link renders in every edition.
    detail = "Ingest is steady: 3 sources sent events in the last hour."
    report = {**report, "dimension_details": {**(report.get("dimension_details") or {}), "ingestion": detail}}
    page.stub_api("GET", "/api/siem-health/reports/latest?allow_empty=true", report)
    _home(page, "/rules")
    link = {"css": 'footer a[href="/platform/health"]'}
    page.wait_for(link, timeout_ms=30_000)
    assert page.texts(link) == [detail], page.texts(link)
    page.click(link)
    page.wait_url(r"/platform/health$")
    page.wait_for({"css": "main"}, timeout_ms=30_000)
    timeline.step("status bar link", report=report.get("id"))


# ── open-core banners ──────────────────────────────────────────────────────
def test_v2036_backup_disk_and_capacity_banners(page: uilib.UiPage, timeline) -> None:
    backup = {
        "configured": True, "enabled": True, "enabled_since": "2026-11-01T00:00:00Z",
        "last_attempt_at": "2026-11-21T02:00:00Z", "last_outcome": "failure",
        "last_success_at": "2026-11-19T02:00:00Z", "last_success_backup_id": "e2e-5864",
        "last_success_size_bytes": 1024, "last_failure_at": "2026-11-21T02:00:00Z",
        "last_failure_error": "e2e: destination unreachable", "consecutive_failures": 2,
        "destination_kind": "path", "destination": "/backups", "clickhouse_data": "excluded",
        "schedule": "0 2 * * *", "keep": 7, "next_run_at": "2026-11-24T02:00:00Z",
        "updated_at": "2026-11-21T02:00:00Z", "stale": True, "stale_after_hours": 36,
    }
    disk = {
        "level": "critical",
        "disks": [{"component": "clickhouse", "name": "data", "level": "critical", "usage_fraction": 0.91,
                   "detail": "e2e", "forecast": {"hours_to_full": 30, "full_fraction": 0.95}}],
        "ingestion_paused": False, "warn_fraction": 0.8, "critical_fraction": 0.9, "imminent_fraction": 0.95,
        "runbook": "https://nano.rs/docs/administration/disk-full-recovery", "checked_at": "2026-11-23T10:00:00Z",
    }
    page.goto("/")
    page.wait_for(RAIL, timeout_ms=30_000)
    tier = page.session_fetch("GET", "/api/settings/tier")
    assert tier["status"] == 200, tier
    capacity_msg = "Today's ingest is above the daily amount in your plan. Nothing is blocked or slowed."
    tier_body = {**tier["json"], "warnings": [{"resource": "daily_volume", "current": 120, "limit": 100,
                                               "percent_used": 120, "message": capacity_msg}]}
    page.stub_api("GET", "/api/system/backup-status", backup)
    page.stub_api("GET", "/api/system/disk-alert", disk)
    page.stub_api("GET", "/api/settings/tier", tier_body)
    page.reload()
    banner = {"css": '[role="status"]', "has": "No successful backup in 36 hours"}
    page.wait_for(banner, timeout_ms=30_000)
    page.wait_for({"testid": "disk-banner"}, timeout_ms=30_000)
    page.wait_for({"css": '[role="status"]', "has": capacity_msg}, timeout_ms=30_000)
    page.screenshot("v2036-banners.png", full_page=False)

    # Backup: the docs link opens in a new tab, "Backup status" goes to Settings,
    # and a dismiss lasts for this browser session (it survives a reload).
    _external(page, {"css": 'a[href="https://nano.rs/docs/administration/backup#automatic-backups"]', "within": banner},
              "https://nano.rs/docs/administration/backup#automatic-backups")
    page.click({"role": "link", "name": "Backup status", "exact": True, "within": banner})
    page.wait_url(r"/settings$")
    page.goto("/")
    page.wait_for(banner, timeout_ms=30_000)
    page.click({"role": "button", "name": "Dismiss backup warning for this session", "exact": True})
    page.wait_for(banner, gone=True, timeout_ms=10_000)
    page.reload()
    page.wait_for({"testid": "disk-banner"}, timeout_ms=30_000)
    assert page.count(banner) == 0, "the backup banner came back after a dismiss in the same session"

    # Disk: the runbook opens in a new tab, Storage goes to Settings > Storage,
    # and a snooze hides it for an hour (it survives a reload).
    disk_banner = {"testid": "disk-banner"}
    _external(page, {"css": 'a[href="https://nano.rs/docs/administration/disk-full-recovery"]', "within": disk_banner},
              "https://nano.rs/docs/administration/disk-full-recovery")
    page.click({"role": "link", "name": "Storage", "exact": True, "within": disk_banner})
    page.wait_url(r"/settings/storage(\?|$)")
    page.goto("/")
    page.wait_for(disk_banner, timeout_ms=30_000)
    page.click({"role": "button", "name": "Snooze disk warning for an hour", "exact": True})
    page.wait_for(disk_banner, gone=True, timeout_ms=10_000)
    page.reload()
    page.wait_for({"css": '[role="status"]', "has": capacity_msg}, timeout_ms=30_000)
    assert page.count(disk_banner) == 0, "the disk banner came back while snoozed"
    timeline.step("banners", backup=True, disk=True, capacity=True)


# ── command palette ────────────────────────────────────────────────────────
# label -> (URL it lands on, the build capability it needs or None)
PALETTE_COMMANDS: dict[str, tuple[str, str | None]] = {
    "Go to Dashboard": (r"//[^/]+/$", None),
    "Go to Cases": (r"/inbox", "cases"),
    "Go to Search": (r"/search", None),
    "Go to Rules": (r"/rules$", None),
    "Go to Alerts": (r"/alerts", None),
    "Go to Risk Scoring": (r"/risk", "risk"),
    "Go to Prevalence": (r"/prevalence", None),
    "Go to Notebooks": (r"/notebooks", "notebooks"),
    "Go to Log Sources": (r"/ingestion/log-sources", None),
    "Create New Case": (r"/inbox", "cases"),
    "Create New Rule": (r"/rules/editor/new$", None),
    "Create New Notebook": (r"/notebooks$", "notebooks"),
    "Case Settings": (r"/settings/cases(\?|$)", "cases"),  # lands on ?tab=general
    "Access Control": (r"/settings/access-control", None),
    "Storage Settings": (r"/settings/storage(\?|$)", None),  # lands on ?tab=clickhouse
}


def test_v2036_command_palette_commands_match_the_edition(stack: Stack, nano: Nano, page: uilib.UiPage, timeline) -> None:
    caps = expect(nano.api.get("/api/capabilities"), 200)
    flags = caps.get("capabilities") or {}
    _home(page, "/rules")
    page.press_key({"css": "body"}, "Escape")
    page.chord("Control", "k")
    page.wait_for(PALETTE, timeout_ms=10_000)
    shown = set(page.texts({"role": "option", "within": PALETTE}))
    page.press_key({"css": ":focus"}, "Escape")
    page.wait_for(PALETTE, gone=True, timeout_ms=10_000)
    expected = {label for label, (_, cap) in PALETTE_COMMANDS.items() if cap is None or flags.get(cap)}
    assert shown == expected, (
        f"{stack.edition}: palette shows {sorted(shown)}; want {sorted(expected)} "
        f"(missing {sorted(expected - shown)}, extra {sorted(shown - expected)})"
    )
    if stack.edition == "open":
        assert not shown & {"Go to Cases", "Go to Notebooks", "Go to Risk Scoring"}, shown
    visited: dict[str, str] = {}
    for label in sorted(expected):
        url_rx, _ = PALETTE_COMMANDS[label]
        page.goto("/rules/coverage")  # no command lands here: every wait_url proves a move
        page.wait_for(RAIL, timeout_ms=30_000)
        page.press_key({"css": "body"}, "Escape")
        page.chord("Control", "k")
        page.wait_for(PALETTE, timeout_ms=10_000)
        page.click({"role": "option", "name": label, "exact": True, "within": PALETTE})
        page.wait_for(PALETTE, gone=True, timeout_ms=10_000)
        visited[label] = page.wait_url(url_rx)
        if label == "Create New Case":
            page.wait_for({"role": "dialog", "name": "New investigation", "exact": False}, timeout_ms=15_000)
        if label == "Create New Notebook":
            page.wait_for({"css": "#nb-title"}, timeout_ms=15_000)
    timeline.step("palette", edition=stack.edition, visited=json.dumps(visited)[:2000])
