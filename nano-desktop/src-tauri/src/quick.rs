//! Quick Search — a global-hotkey (⌥Space) spotlight window.
//!
//! The window itself is declared in `tauri.conf.json` (label "quick": hidden,
//! frameless, always-on-top), so it's preloaded and shows instantly — toggling
//! is just show/hide. This module registers the hotkey and the two commands the
//! spotlight uses: hide itself, and hand a query to the main window.

use tauri::{AppHandle, Emitter, Manager};

/// Register the global shortcut. Non-fatal: if the hotkey is already taken by
/// another app, Quick Search is simply unavailable — that must not stop the app
/// from launching.
pub fn setup(app: &AppHandle) {
    if let Err(e) = register(app) {
        log::warn!("Quick Search hotkey unavailable: {e}");
    }
}

fn register(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    use tauri_plugin_global_shortcut::{Code, Modifiers, Shortcut, ShortcutState};

    // ⌥Space, not ⌘Space — the latter is macOS Spotlight.
    let toggle = Shortcut::new(Some(Modifiers::ALT), Code::Space);
    app.plugin(
        tauri_plugin_global_shortcut::Builder::new()
            .with_shortcut(toggle)?
            .with_handler(|app, _shortcut, event| {
                // Key-DOWN only; the matching release would immediately re-toggle
                // and cancel the show.
                if event.state() == ShortcutState::Pressed {
                    toggle_quick(app);
                }
            })
            .build(),
    )?;
    Ok(())
}

/// Payload for the `quick-show` event.
#[derive(Clone, Default, serde::Serialize)]
struct QuickShow {
    /// Live selection captured via synthetic ⌘C — high confidence (the analyst
    /// explicitly selected it), so the spotlight always pre-fills it. Needs the
    /// Accessibility permission; `None` without it or when nothing was selected.
    selection: Option<String>,
    /// The current clipboard, when it's short and single-line — the permission-free
    /// "⌘C then hotkey" path. The frontend pre-fills this only when it looks like
    /// an indicator, so a stale clipboard doesn't hijack a fresh query.
    clipboard: Option<String>,
}

fn toggle_quick(app: &AppHandle) {
    let Some(window) = app.get_webview_window("quick") else {
        return;
    };
    if window.is_visible().unwrap_or(false) {
        let _ = window.hide();
        return;
    }
    // Capture BEFORE we steal focus — once the spotlight is key, a synthetic ⌘C
    // would copy from IT instead of the analyst's app.
    let payload = capture();
    // Re-center each time — the active display may have changed since last.
    let _ = window.center();
    let _ = window.show();
    let _ = window.set_focus();
    let _ = window.emit("quick-show", payload);
}

/// Gather what the analyst might want to look up: the live selection (⌘C, if
/// Accessibility is granted) and the current clipboard (always available).
#[cfg(target_os = "macos")]
fn capture() -> QuickShow {
    let Ok(mut clip) = arboard::Clipboard::new() else {
        return QuickShow::default();
    };
    let original = clip.get_text().ok();

    let selection = capture_live(&mut clip, original.as_deref());

    // Fallback: a short, single-line clipboard (an IOC or short query), not a
    // paragraph. The frontend gates it further to indicator-shaped values.
    let clipboard = original
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty() && !text.contains('\n') && text.len() <= 256)
        .map(str::to_string);

    QuickShow { selection, clipboard }
}

/// The live selection via synthetic ⌘C. Returns `None` — leaving the clipboard as
/// it found it — unless Accessibility is granted AND something was selected.
#[cfg(target_os = "macos")]
fn capture_live(clip: &mut arboard::Clipboard, original: Option<&str>) -> Option<String> {
    use macos_accessibility_client::accessibility;
    use std::sync::atomic::{AtomicBool, Ordering};

    if !accessibility::application_is_trusted() {
        // Ask once per run; the OS remembers. Note: for a bare `tauri dev` binary
        // this prompt is unreliable (TCC attributes it to the terminal), which is
        // exactly why the clipboard fallback above exists. Solid in a bundled app.
        static PROMPTED: AtomicBool = AtomicBool::new(false);
        if !PROMPTED.swap(true, Ordering::Relaxed) {
            accessibility::application_is_trusted_with_prompt();
        }
        return None;
    }

    // A sentinel separates "the app copied a real selection" from "nothing was
    // selected" — ⌘C leaves the sentinel untouched in the latter case.
    const SENTINEL: &str = "\u{2063}nano-quick-capture\u{2063}";
    clip.set_text(SENTINEL).ok()?;
    simulate_copy();
    std::thread::sleep(std::time::Duration::from_millis(80));
    let captured = clip.get_text().ok();
    // Put the clipboard back, whatever happened.
    match original {
        Some(text) => {
            let _ = clip.set_text(text.to_string());
        }
        None => {
            let _ = clip.clear();
        }
    }

    let captured = captured?;
    if captured == SENTINEL {
        return None;
    }
    let line = captured.trim().lines().next()?.trim();
    (!line.is_empty() && line.len() <= 512).then(|| line.to_string())
}

/// Post a synthetic ⌘C to the frontmost app.
#[cfg(target_os = "macos")]
fn simulate_copy() {
    use core_graphics::event::{CGEvent, CGEventFlags, CGEventTapLocation, CGKeyCode};
    use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};

    let Ok(source) = CGEventSource::new(CGEventSourceStateID::CombinedSessionState) else {
        return;
    };
    const KEY_C: CGKeyCode = 8; // kVK_ANSI_C
    for keydown in [true, false] {
        if let Ok(event) = CGEvent::new_keyboard_event(source.clone(), KEY_C, keydown) {
            event.set_flags(CGEventFlags::CGEventFlagCommand);
            event.post(CGEventTapLocation::HID);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn capture() -> QuickShow {
    QuickShow::default()
}

/// Open the spotlight on a value someone else handed us — the macOS Services
/// entry ("Search in nano" on a selection in any app).
///
/// This deliberately goes through the SAME window as ⌥Space rather than a second
/// popover: the classification, the live peek, and the ↩ / ⌘↩ handoffs already
/// live there, and a parallel surface would be a second thing to keep correct.
/// The text arrives from the system pasteboard, so there is nothing to capture —
/// it is passed straight in as the selection.
pub fn show_with_selection(app: &AppHandle, selection: &str) {
    let Some(window) = app.get_webview_window("quick") else {
        return;
    };
    let _ = window.center();
    let _ = window.show();
    let _ = window.set_focus();
    let _ = window.emit(
        "quick-show",
        QuickShow {
            selection: Some(selection.to_string()),
            clipboard: None,
        },
    );
}

/// Hide the spotlight (Esc, or on blur — the frontend decides when).
#[tauri::command]
pub fn hide_quick(app: AppHandle) {
    if let Some(window) = app.get_webview_window("quick") {
        let _ = window.hide();
    }
}

/// Hand a query to the main window and bring it forward. The main window listens
/// for `quick-search-open` and opens the query in a search tab. `range` is an
/// optional time-range preset name (e.g. "Last 30 days") so an indicator search
/// opens over the same window the peek used, instead of the tab default.
#[derive(Clone, serde::Serialize)]
struct OpenPayload {
    query: String,
    range: Option<String>,
}

#[tauri::command]
pub fn open_in_main(app: AppHandle, query: String, range: Option<String>) {
    if let Some(quick) = app.get_webview_window("quick") {
        let _ = quick.hide();
    }
    if let Some(main) = app.get_webview_window("main") {
        let _ = main.show();
        let _ = main.unminimize();
        let _ = main.set_focus();
        let _ = main.emit("quick-search-open", OpenPayload { query, range });
    }
}

/// Hand a question to pivt in the main window: bring the window forward and open
/// the agent panel on this prompt. The main window listens for `quick-ask-pivt`.
#[tauri::command]
pub fn ask_pivt(app: AppHandle, prompt: String) {
    if let Some(quick) = app.get_webview_window("quick") {
        let _ = quick.hide();
    }
    if let Some(main) = app.get_webview_window("main") {
        let _ = main.show();
        let _ = main.unminimize();
        let _ = main.set_focus();
        let _ = main.emit("quick-ask-pivt", prompt);
    }
}
