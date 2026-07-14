//! Menu-bar presence: a tray showing a live tally of new alerts, and a native
//! notification when one arrives.
//!
//! The feed is `GET /api/alerts/stream` — a cursor keyset "new since" feed
//! (there is no SSE/websocket for alerts). A background task polls it on a fixed
//! cadence, reusing `Siem`'s authed-request + refresh machinery so all HTTP
//! still originates in Rust. Two things the feed forces on us:
//!   * seed the cursor to "now" on first watch, or a missing cursor replays
//!     every alert ever written; and
//!   * tally severities ourselves — `/api/alerts/counts` returns an empty
//!     `by_severity` map (a server-side TODO), so there is nothing cheaper to
//!     poll for the breakdown.
//!
//! The tally is a SESSION count of alerts that arrived while watching — honest
//! about what the stream can tell us, and the same data that drives the banners.

use std::sync::Mutex;
use std::time::Duration;

use chrono::Utc;
use tauri::menu::{MenuBuilder, MenuItem, PredefinedMenuItem};
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_notification::NotificationExt;

use crate::error::Error;
use crate::siem::{AlertSummary, Siem};

/// The server holds a ~5s safety lag on the feed, so polling faster buys nothing
/// but load. 10s means a new alert surfaces within ~15s worst case.
const POLL_INTERVAL: Duration = Duration::from_secs(10);
const PAGE_LIMIT: i64 = 200;
/// Drain a backlog within a tick, but bounded — a flood shouldn't let one tick
/// run away. Anything past this comes on the next tick.
const MAX_PAGES_PER_TICK: usize = 5;
/// Past this many new alerts in one tick, fire ONE summary banner instead of a
/// storm of individual ones.
const MAX_INDIVIDUAL_BANNERS: usize = 3;

/// UDM severities, most severe first — the fixed order of the menu readout and
/// the count array.
const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "informational"];

/// Per-severity tally, indexed parallel to `SEVERITIES`.
#[derive(Default, Clone)]
struct Counts {
    by_sev: [u32; 5],
}

impl Counts {
    fn total(&self) -> u32 {
        self.by_sev.iter().sum()
    }

    fn add(&mut self, severity: &str) {
        // An unrecognized severity still moves the total — bucket it as the
        // lowest rather than dropping it silently.
        let idx = SEVERITIES
            .iter()
            .position(|s| s.eq_ignore_ascii_case(severity))
            .unwrap_or(SEVERITIES.len() - 1);
        self.by_sev[idx] = self.by_sev[idx].saturating_add(1);
    }
}

struct WatcherState {
    counts: Counts,
    /// The keyset cursor. `None` until seeded; kept across empty pages (an empty
    /// page returns no cursor, and resetting would replay from the beginning).
    cursor: Option<String>,
    /// False until we've seeded the cursor to "now" for the current session.
    /// Reset whenever the session goes away so a re-auth starts fresh.
    seeded: bool,
}

/// Managed app state: the watcher's bookkeeping plus the menu-item handles whose
/// text we rewrite on each tick.
pub struct Tray {
    state: Mutex<WatcherState>,
    sev_items: [MenuItem<Wry>; 5],
}

impl Tray {
    /// Poison-tolerant lock. The critical sections here can't panic (bounded
    /// indices, `saturating_add`), but if one ever did we'd rather carry on with
    /// possibly-stale state than wedge every future tick on a poisoned mutex.
    fn guard(&self) -> std::sync::MutexGuard<'_, WatcherState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Build the tray + menu, register state, and spawn the poll loop. Called once
/// at startup.
pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let header = MenuItem::with_id(app, "header", "New alerts — this session", false, None::<&str>)?;
    let sev_items: [MenuItem<Wry>; 5] = [
        sev_item(app, SEVERITIES[0])?,
        sev_item(app, SEVERITIES[1])?,
        sev_item(app, SEVERITIES[2])?,
        sev_item(app, SEVERITIES[3])?,
        sev_item(app, SEVERITIES[4])?,
    ];
    let clear = MenuItem::with_id(app, "clear", "Clear", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Show nano", true, None::<&str>)?;
    let quit = PredefinedMenuItem::quit(app, Some("Quit nano"))?;

    let menu = MenuBuilder::new(app)
        .item(&header)
        .items(&[
            &sev_items[0],
            &sev_items[1],
            &sev_items[2],
            &sev_items[3],
            &sev_items[4],
        ])
        .separator()
        .items(&[&clear, &show])
        .separator()
        .item(&quit)
        .build()?;

    tauri::tray::TrayIconBuilder::with_id("main")
        // A dedicated menu-bar mark, NOT the colored app icon: rendered as a macOS
        // template image (black silhouette + alpha) so the OS tints it for the
        // light or dark menu bar and it's always legible. The pink dot becomes
        // part of the monochrome silhouette — standard for a menu-bar glyph.
        .icon(tauri::include_image!("icons/tray.png"))
        .icon_as_template(true)
        .tooltip("nano")
        .menu(&menu)
        .on_menu_event(on_menu_event)
        .build(app)?;

    app.manage(Tray {
        state: Mutex::new(WatcherState {
            counts: Counts::default(),
            cursor: None,
            seeded: false,
        }),
        sev_items,
    });

    request_notification_permission(app);

    let handle = app.clone();
    tauri::async_runtime::spawn(async move { watch_loop(handle).await });
    Ok(())
}

/// Ask for notification authorization up front. Without it macOS silently drops
/// the first banner — the headline of this feature would no-op on first run. The
/// OS only prompts once; later launches see the stored decision, so this is
/// cheap to call every startup.
fn request_notification_permission(app: &AppHandle) {
    use tauri_plugin_notification::PermissionState;
    match app.notification().permission_state() {
        Ok(PermissionState::Granted) => {}
        _ => {
            if let Err(e) = app.notification().request_permission() {
                log::warn!("notification permission request failed: {e}");
            }
        }
    }
}

fn sev_item(app: &AppHandle, severity: &str) -> tauri::Result<MenuItem<Wry>> {
    // Disabled: these are readouts, not actions.
    MenuItem::with_id(app, format!("sev_{severity}"), sev_label(severity, 0), false, None::<&str>)
}

fn on_menu_event(app: &AppHandle, event: tauri::menu::MenuEvent) {
    match event.id().as_ref() {
        "show" => show_main(app),
        "clear" => {
            if let Some(tray) = app.try_state::<Tray>() {
                tray.guard().counts = Counts::default();
            }
            render(app);
        }
        // "quit" is handled by the predefined item; severity lines are disabled.
        _ => {}
    }
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// The poll loop. Sleeps between ticks; only touches the network while there is
/// a live session, so Lock / Sign out genuinely pause it.
async fn watch_loop(app: AppHandle) {
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    // A slow drain (up to AUTH_TIMEOUT) shouldn't make missed ticks fire
    // back-to-back on return — skip them and resume the normal cadence.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;

        let authenticated = match app.try_state::<Siem>() {
            Some(siem) => siem.is_authenticated().await,
            None => continue,
        };

        if !authenticated {
            // Paused. Reset so a returning session re-seeds to "now" and counts
            // from zero rather than replaying whatever accrued before.
            if reset_for_pause(&app) {
                render(&app);
            }
            continue;
        }

        // First authenticated tick: seed the cursor to now and skip polling this
        // round, so the seed timestamp is safely in the past next time.
        if seed_if_needed(&app) {
            render(&app);
            continue;
        }

        let (new_alerts, advanced_cursor) = drain(&app).await;

        // If the session ended DURING the drain (Lock mid-poll), throw the batch
        // away: no banners, no counting, no cursor advance on a machine the user
        // just locked. The session-active gate in `Siem` prevents a background
        // 401 from refreshing and re-arming the session, so this recheck is a
        // true signal — the next authenticated tick reseeds from scratch.
        let still_live = match app.try_state::<Siem>() {
            Some(siem) => siem.is_authenticated().await,
            None => false,
        };
        if !still_live {
            continue;
        }

        // Persist the cursor advance and fold in the new counts under one lock.
        {
            let Some(tray) = app.try_state::<Tray>() else {
                continue;
            };
            let mut st = tray.guard();
            st.cursor = advanced_cursor;
            for alert in &new_alerts {
                st.counts.add(&alert.severity);
            }
        }

        if !new_alerts.is_empty() {
            notify(&app, &new_alerts);
            render(&app);
        }
    }
}

/// Clear session state on losing auth. Returns whether anything actually changed
/// (so we only repaint the tray when it did).
fn reset_for_pause(app: &AppHandle) -> bool {
    let Some(tray) = app.try_state::<Tray>() else {
        return false;
    };
    let mut st = tray.guard();
    let had_state = st.seeded || st.cursor.is_some() || st.counts.total() > 0;
    st.seeded = false;
    st.cursor = None;
    st.counts = Counts::default();
    had_state
}

/// Seed the cursor to "now" if this is the first tick of a session. Returns true
/// when it seeded (caller should skip polling this tick).
fn seed_if_needed(app: &AppHandle) -> bool {
    let Some(tray) = app.try_state::<Tray>() else {
        return false;
    };
    let mut st = tray.guard();
    if st.seeded {
        return false;
    }
    st.cursor = Some(now_cursor());
    st.seeded = true;
    st.counts = Counts::default();
    true
}

/// Pull up to `MAX_PAGES_PER_TICK` pages, following the cursor. Returns the new
/// alerts and the cursor to persist. Errors stop the drain and keep the cursor
/// where it was, to retry next tick.
async fn drain(app: &AppHandle) -> (Vec<AlertSummary>, Option<String>) {
    let mut cursor = {
        match app.try_state::<Tray>() {
            Some(tray) => tray.guard().cursor.clone(),
            None => return (Vec::new(), None),
        }
    };
    let Some(siem) = app.try_state::<Siem>() else {
        return (Vec::new(), cursor);
    };

    let mut collected = Vec::new();
    for _ in 0..MAX_PAGES_PER_TICK {
        match siem.poll_alerts(cursor.as_deref(), PAGE_LIMIT).await {
            Ok(page) => {
                let had_rows = !page.alerts.is_empty();
                collected.extend(page.alerts);
                // Advance only on a real cursor; an empty page returns None and
                // must not clear our place.
                if page.next_cursor.is_some() {
                    cursor = page.next_cursor;
                }
                if !page.has_more || !had_rows {
                    break;
                }
            }
            // Session ended mid-drain — next tick's auth check handles the reset.
            Err(Error::SessionExpired) | Err(Error::NotConnected) => break,
            Err(e) => {
                log::warn!("alert poll failed, will retry: {e}");
                break;
            }
        }
    }
    (collected, cursor)
}

fn notify(app: &AppHandle, alerts: &[AlertSummary]) {
    if alerts.len() <= MAX_INDIVIDUAL_BANNERS {
        for alert in alerts {
            show_banner(app, banner_title(alert), banner_body(alert));
        }
    } else {
        show_banner(
            app,
            format!("{} new alerts", alerts.len()),
            summary_body(alerts),
        );
    }
}

fn show_banner(app: &AppHandle, title: String, body: String) {
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        // Don't swallow it — a dropped banner usually means authorization was
        // never granted, which is worth a breadcrumb rather than silence.
        log::warn!("failed to show alert notification: {e}");
    }
}

fn banner_title(alert: &AlertSummary) -> String {
    let name = alert
        .rule_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("Alert");
    let sev = capitalize(&alert.severity);
    if sev.is_empty() {
        name.to_string()
    } else {
        format!("{sev} · {name}")
    }
}

fn banner_body(alert: &AlertSummary) -> String {
    match (alert.kind.as_deref(), alert.source_id.as_deref()) {
        // Risk notables carry the entity in source_id as "<type>:<entity>".
        (Some("risk_notable"), Some(src)) => {
            format!("Risk notable · {}", src.replacen(':', ": ", 1))
        }
        _ => "New alert in nano".to_string(),
    }
}

fn summary_body(alerts: &[AlertSummary]) -> String {
    let mut counts = Counts::default();
    for alert in alerts {
        counts.add(&alert.severity);
    }
    let parts: Vec<String> = SEVERITIES
        .iter()
        .enumerate()
        .filter(|(i, _)| counts.by_sev[*i] > 0)
        .map(|(i, sev)| format!("{} {}", counts.by_sev[i], sev))
        .collect();
    parts.join(", ")
}

/// Repaint the menu readout and the tray title from the current counts.
fn render(app: &AppHandle) {
    let Some(tray) = app.try_state::<Tray>() else {
        return;
    };
    let counts = tray.guard().counts.clone();

    for (i, severity) in SEVERITIES.iter().enumerate() {
        let _ = tray.sev_items[i].set_text(sev_label(severity, counts.by_sev[i]));
    }

    if let Some(icon) = app.tray_by_id("main") {
        let total = counts.total();
        let title = if total == 0 { None } else { Some(total.to_string()) };
        let _ = icon.set_title(title);
    }
}

fn sev_label(severity: &str, count: u32) -> String {
    format!("{}: {}", capitalize(severity), count)
}

/// Base64 of `"<rfc3339 now>|<nil uuid>"` — the cursor format the server parses
/// (`split('|')` → `parse_from_rfc3339` + `Uuid::parse_str`). Starting at "now"
/// means the tray watches forward from launch instead of replaying history.
fn now_cursor() -> String {
    use base64::Engine as _;
    let raw = format!("{}|00000000-0000-0000-0000-000000000000", Utc::now().to_rfc3339());
    base64::engine::general_purpose::STANDARD.encode(raw)
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests;
