"""The theme switcher lives in the left rail (v2.0.35, NAN-5858).

The top bar's light/dark toggle (Settings shell) and the user menu's Theme
submenu are gone. Every rail footer
(app rail, Settings rail, mobile drawer) carries the one light/dark toggle
plus the lake-era sideways theme strip, built on the same swatches as
Settings > User. As the install admin (theme is not permission-gated):

1. there is exactly one light/dark toggle on a page, and it is in the rail;
   none in either top bar, and the user menu has no Theme submenu;
2. expanded rail: the strip scrolls right and back with its arrows, a swatch
   changes the theme, the choice persists across a reload, and Settings >
   User shows the same selection; the Settings rail's toggle changes it back
   and Settings > User follows;
3. collapsed rail: one theme button (a dialog popup button) opens the strip
   on hover; a swatch there changes the theme; from the keyboard Enter opens
   it on the selected swatch, ArrowRight moves, Enter picks, Escape closes
   and returns focus to the button;
4. mobile (390px): the drawer carries the strip and the toggle.

With `E2E_RAIL_THEME_SHOTS=1` it also writes review screenshots
(`rail-theme-*.png`) to the scenario's ui artifact dir.
"""

from __future__ import annotations

import os
import time
from typing import Any

from nano_e2e import ui as uilib
from nano_e2e.waits import eventually

RAIL = {"testid": "app-rail"}
STRIP = {"testid": "rail-theme"}
FLYOUT = {"testid": "rail-theme-trigger-flyout"}
TRIGGER = {"role": "button", "name": "Theme", "exact": True, "within": RAIL}
TOGGLES = {"role": "button", "name": uilib.rx("^Switch to (light|dark) theme$")}
FOCUSED = {"css": ":focus"}
SWATCH_ROW = {"css": '[data-testid="rail-theme"] [role="group"][aria-label="Theme"]'}
USER_SELECT = {"testid": "user-theme-select"}
SHOTS = os.environ.get("E2E_RAIL_THEME_SHOTS") == "1"


def _swatch(name: str, within: dict[str, Any]) -> dict[str, Any]:
    return {"role": "button", "name": name, "exact": True, "within": within}


def _user_swatch(name: str) -> dict[str, Any]:
    """A swatch in Settings > User's own strip (by aria-label: the theme Select
    trigger beside it carries the same text)."""
    return {"css": f'main [role="group"][aria-label="Theme"] button[aria-label="{name}"]'}


def _expect_pressed(page: uilib.UiPage, find: dict[str, Any], where: str) -> None:
    """aria-pressed lands after the strip's mount effect: wait for it."""
    eventually(lambda: page.attr(find, "aria-pressed"), timeout=10, interval=0.2,
               desc=f"{where}: swatch pressed", ok=lambda v: v == "true")


def _html_class(page: uilib.UiPage) -> list[str]:
    return (page.attr({"css": "html"}, "class") or "").split()


def _expect_theme(page: uilib.UiPage, theme: str, where: str) -> None:
    eventually(lambda: _html_class(page), timeout=10, interval=0.2,
               desc=f"{where}: html carries {theme}", ok=lambda c: theme in c)


def _rail_settled(page: uilib.UiPage, collapsed: bool) -> None:
    eventually(lambda: page.rect(RAIL)["width"], timeout=10, interval=0.2,
               desc=f"rail {'collapsed' if collapsed else 'expanded'}",
               ok=lambda w: (w < 60) if collapsed else (w > 150))


def _shot(page: uilib.UiPage, name: str) -> None:
    if SHOTS:
        time.sleep(0.5)  # enter animations
        page.screenshot(f"rail-theme-{name}.png", full_page=False)


def test_v2035_rail_theme_strip_flyout_and_single_toggle(page: uilib.UiPage, timeline) -> None:
    problems: list[str] = []
    page.viewport(1440, 900)
    page.goto("/")
    page.wait_for(STRIP, timeout_ms=30_000)
    page.click(_swatch("Light", STRIP))
    _expect_theme(page, "light", "start")

    # 1 ── one light/dark toggle per page, in the rail -------------------------
    for path, rail in (("/", "app-rail"), ("/settings/user", "settings-rail")):
        page.goto(path)
        page.wait_for({"testid": rail}, timeout_ms=30_000)
        total = page.count(TOGGLES)
        in_rail = page.count({**TOGGLES, "within": {"testid": rail}})
        if (total, in_rail) != (1, 1):
            problems.append(f"{path}: {total} light/dark toggles, {in_rail} in the rail (want 1, 1)")
    _shot(page, "settings-light")
    # ... and the user menu has no Theme submenu: the rail footer is the one place.
    page.goto("/")
    page.wait_for(STRIP, timeout_ms=30_000)
    page.click({"css": '[data-testid="app-rail"] > div.mt-auto button[aria-haspopup="menu"]'})
    page.wait_for({"role": "menuitem", "name": "User Settings", "exact": True}, timeout_ms=10_000)
    if page.count({"role": "menuitem", "name": "Theme", "exact": True}):
        problems.append("user menu: still has a Theme submenu")
    page.press_key({"css": ":focus"}, "Escape")
    page.wait_for({"role": "menuitem", "name": "User Settings", "exact": True}, gone=True, timeout_ms=10_000)

    # 2 ── expanded rail: scroll, pick, persist, sync with Settings > User -----
    page.goto("/")
    page.wait_for(STRIP, timeout_ms=30_000)
    _shot(page, "expanded-light")
    right = {"role": "button", "name": "Scroll themes right", "exact": True, "within": STRIP}
    left = {"role": "button", "name": "Scroll themes left", "exact": True, "within": STRIP}
    last = _swatch("Dark · Amber", STRIP)
    if page.attr(right, "aria-disabled") != "false" or page.attr(left, "aria-disabled") != "true":
        problems.append("strip: at rest the right arrow should be live and the left one at its end")
    before = page.rect(last)["left"]
    # Smooth scroll: press until the right arrow reports the end, then wait for
    # the last swatch to sit fully inside the strip before clicking it.
    for _ in range(6):
        if page.attr(right, "aria-disabled") == "true":
            break
        page.click(right)
        time.sleep(0.4)
    eventually(lambda: page.attr(right, "aria-disabled"), timeout=5, interval=0.2,
               desc="strip scrolled to its end", ok=lambda v: v == "true")
    eventually(lambda: (page.rect(last), page.rect(SWATCH_ROW)), timeout=5, interval=0.2,
               desc="last swatch fully visible",
               ok=lambda r: r[0]["left"] >= r[1]["left"] - 1 and r[0]["right"] <= r[1]["right"] + 1)
    moved = page.rect(last)["left"]
    timeline.step("strip-scroll", before=before, after=moved)
    if not moved < before - 20:
        problems.append(f"strip: the right arrow did not scroll ({before} -> {moved})")
    if page.attr(left, "aria-disabled") != "false":
        problems.append("strip: after scrolling right the left arrow is still disabled")
    page.click(last)
    _expect_theme(page, "dark-amber", "strip pick")
    _expect_pressed(page, last, "strip pick")
    page.click(left)
    eventually(lambda: page.rect(last)["left"], timeout=5, interval=0.2,
               desc="strip scrolled back left", ok=lambda x: x > moved + 20)

    page.reload()
    page.wait_for(STRIP, timeout_ms=30_000)
    _expect_theme(page, "dark-amber", "after reload")
    _expect_pressed(page, last, "after reload")

    page.goto("/settings/user")
    page.wait_for({"testid": "settings-rail-theme"}, timeout_ms=30_000)
    _expect_pressed(page, _user_swatch("Dark · Amber"), "Settings > User shows the rail's pick")
    page.click({**TOGGLES, "within": {"testid": "settings-rail-theme"}})
    _expect_theme(page, "light", "settings rail toggle")
    _expect_pressed(page, _user_swatch("Light"), "Settings > User follows the rail toggle")

    # 2b ── reverse sync: Settings > User's picker -> both rails ---------------
    page.choose(USER_SELECT, "Matte Mono", exact=True)
    _expect_theme(page, "mono", "Settings > User Select")
    _expect_pressed(page, _swatch("Matte Mono", {"testid": "settings-rail-theme"}), "Settings rail follows Settings > User")
    page.goto("/")
    page.wait_for(STRIP, timeout_ms=30_000)
    _expect_pressed(page, _swatch("Matte Mono", STRIP), "app rail follows Settings > User")

    # 2c ── system: no swatch pressed, the toggle follows the resolved theme --
    page.goto("/settings/user")
    page.wait_for({"testid": "settings-rail-theme"}, timeout_ms=30_000)
    page.choose(USER_SELECT, "System", exact=True)
    pressed = {"css": '[data-testid="settings-rail-theme"] [aria-pressed="true"]', "visible": False}
    eventually(lambda: page.count(pressed), timeout=5, interval=0.2,
               desc="system: no rail swatch pressed", ok=lambda n: n == 0)
    resolved_dark = "dark" in _html_class(page)
    want_label = "Switch to light theme" if resolved_dark else "Switch to dark theme"
    got_label = page.attr({**TOGGLES, "within": {"testid": "settings-rail-theme"}}, "aria-label")
    if got_label != want_label:
        problems.append(f"system: toggle says {got_label!r} on a {'dark' if resolved_dark else 'light'} system theme")
    page.reload()
    page.wait_for({"testid": "settings-rail-theme"}, timeout_ms=30_000)
    eventually(lambda: page.texts(USER_SELECT), timeout=10, interval=0.3,
               desc="system persists across reload", ok=lambda t: bool(t) and "System" in t[0])
    time.sleep(0.5)  # give the strip its post-mount render before asserting nothing is pressed
    if page.count(pressed):
        problems.append("system after reload: a rail swatch is pressed")

    # 3 ── collapsed rail: theme button + popover strip -------------------------
    page.goto("/")
    page.wait_for(STRIP, timeout_ms=30_000)
    page.click({"role": "button", "name": "Toggle sidebar", "exact": True})
    page.wait_for(TRIGGER, timeout_ms=15_000)
    _rail_settled(page, collapsed=True)
    if page.count(STRIP):
        problems.append("collapsed: the inline strip is still rendered")
    if page.attr(TRIGGER, "aria-haspopup") != "dialog" or page.attr(TRIGGER, "aria-expanded") != "false":
        problems.append("collapsed: the theme button is not a closed dialog popup button")

    # keyboard open on `system` lands on the first swatch
    page.press_key(TRIGGER, "Enter")
    page.wait_for(FLYOUT, timeout_ms=10_000)
    eventually(lambda: page.attr(FOCUSED, "aria-label"), timeout=5, interval=0.2,
               desc="system: keyboard open focuses the first swatch", ok=lambda v: v == "Light")
    page.click(_swatch("Light", FLYOUT))
    _expect_theme(page, "light", "flyout pick out of system")
    page.chord("Escape")
    page.wait_for(FLYOUT, gone=True, timeout_ms=10_000)
    _shot(page, "collapsed-light")

    # hover peeks; a mouse pick works; leaving closes it
    page.hover({"css": "main"})
    page.hover({"testid": "rail-theme-trigger"})
    page.wait_for(FLYOUT, timeout_ms=10_000)
    if page.attr(FLYOUT, "data-mode") != "hover":
        problems.append(f"hover: panel mode {page.attr(FLYOUT, 'data-mode')!r}, expected 'hover'")
    _shot(page, "collapsed-flyout-light")
    page.click(_swatch("Matte Black", FLYOUT))
    _expect_theme(page, "matte", "flyout pick")
    page.hover({"css": "main"})
    page.wait_for(FLYOUT, gone=True, timeout_ms=10_000)

    # hover + Escape (focus elsewhere) dismisses it
    page.hover({"testid": "rail-theme-trigger"})
    page.wait_for(FLYOUT, timeout_ms=10_000)
    page.chord("Escape")
    page.wait_for(FLYOUT, gone=True, timeout_ms=10_000)
    page.hover({"css": "main"})

    # a pointer click pins it open, moves focus inside, survives the pointer leaving
    page.click(TRIGGER)
    page.wait_for(FLYOUT, timeout_ms=10_000)
    if page.attr(FLYOUT, "data-mode") != "pinned":
        problems.append(f"click: panel mode {page.attr(FLYOUT, 'data-mode')!r}, expected 'pinned'")
    eventually(lambda: page.attr(FOCUSED, "aria-label"), timeout=5, interval=0.2,
               desc="click open focuses the selected swatch", ok=lambda v: v == "Matte Black")
    page.hover({"css": "main"})
    time.sleep(0.5)
    if not page.count(FLYOUT):
        problems.append("click: the pinned panel closed when the pointer left")
    page.click({"css": "main"})
    page.wait_for(FLYOUT, gone=True, timeout_ms=10_000)

    # keyboard: Enter opens on the selected swatch, arrows move, Escape returns
    page.press_key(TRIGGER, "Enter")
    page.wait_for(FLYOUT, timeout_ms=10_000)
    if page.attr(TRIGGER, "aria-expanded") != "true":
        problems.append("keyboard: aria-expanded is not true while open")
    eventually(lambda: page.attr(FOCUSED, "aria-label"), timeout=5, interval=0.2,
               desc="keyboard open focuses the selected swatch", ok=lambda v: v == "Matte Black")
    page.press_key(FOCUSED, "ArrowRight")
    if page.attr(FOCUSED, "aria-label") != "Matte Mono":
        problems.append(f"keyboard: ArrowRight focused {page.attr(FOCUSED, 'aria-label')}, expected Matte Mono")
    page.press_key(FOCUSED, "Enter")
    _expect_theme(page, "mono", "keyboard pick")
    page.press_key(FOCUSED, "Escape")
    page.wait_for(FLYOUT, gone=True, timeout_ms=10_000)
    if page.attr(FOCUSED, "aria-label") != "Theme":
        problems.append("keyboard: Escape did not return focus to the theme button")

    # Tab past the last control closes it and moves on to the user menu button
    page.press_key(TRIGGER, "Enter")
    page.wait_for(FLYOUT, timeout_ms=10_000)
    for _ in range(5):
        if not page.count(FLYOUT):
            break
        page.chord("Tab")
    if page.count(FLYOUT):
        problems.append("Tab: the panel stayed open after tabbing past its last control")
    elif page.attr(FOCUSED, "aria-haspopup") != "menu":
        problems.append(f"Tab: focus went to {page.attr(FOCUSED, 'aria-label')!r}, expected the user menu button")
    # Shift+Tab past the first control returns to the theme button
    page.press_key(TRIGGER, "Enter")
    page.wait_for(FLYOUT, timeout_ms=10_000)
    for _ in range(5):
        if not page.count(FLYOUT):
            break
        page.chord("Shift", "Tab")
    if page.count(FLYOUT):
        problems.append("Shift+Tab: the panel stayed open after tabbing back past its first control")
    elif page.attr(FOCUSED, "aria-label") != "Theme":
        problems.append(f"Shift+Tab: focus went to {page.attr(FOCUSED, 'aria-label')!r}, expected the theme button")

    page.press_key(TRIGGER, "Enter")
    page.wait_for(FLYOUT, timeout_ms=10_000)
    page.click({**TOGGLES, "within": FLYOUT})
    _expect_theme(page, "light", "flyout light/dark toggle")
    page.press_key(FOCUSED, "Escape")
    page.wait_for(FLYOUT, gone=True, timeout_ms=10_000)
    page.click({"role": "button", "name": "Toggle sidebar", "exact": True})
    _rail_settled(page, collapsed=False)

    # 4 ── mobile drawer ----------------------------------------------------------
    page.viewport(390, 844)
    page.goto("/")
    page.click({"role": "button", "name": "Open menu", "exact": True})
    page.wait_for({"testid": "mobile-rail-theme"}, timeout_ms=15_000)
    if page.count({**TOGGLES, "within": {"testid": "mobile-rail-theme"}}) != 1:
        problems.append("mobile: the drawer has no light/dark toggle")
    page.click(_swatch("Dark", {"testid": "mobile-rail-theme"}))
    _expect_theme(page, "dark", "mobile pick")
    _shot(page, "mobile-dark")
    page.viewport(1440, 900)

    timeline.step("rail-theme", problems=problems)
    assert not problems, "rail theme switcher:\n" + "\n".join(problems)
