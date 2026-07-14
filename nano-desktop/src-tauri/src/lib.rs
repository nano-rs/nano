mod agent;
mod biometric;
mod error;
mod mcp;
mod pty;
mod quick;
#[cfg(target_os = "macos")]
mod services;
mod siem;
mod store;
mod tray;

use serde_json::Value;
use tauri::ipc::Channel;
use tauri::Manager;

use std::collections::HashMap;
use std::sync::Mutex;

use agent::AgentStatus;
use error::Result;
use mcp::McpInventory;
use pty::Terminal;
use siem::{LoginOutcome, RestoreOutcome, Siem};
use store::ServerConfig;

/// Probe a server address and remember it. Runs before any credentials are
/// collected, so a typo'd address fails on the connect screen rather than
/// looking like a bad password.
#[tauri::command]
async fn connect(
    app: tauri::AppHandle,
    siem: tauri::State<'_, Siem>,
    url: String,
    search_url: Option<String>,
    allow_insecure: bool,
) -> Result<ServerConfig> {
    siem.connect(&app, &url, search_url.as_deref(), allow_insecure)
        .await
}

#[tauri::command]
async fn login(
    app: tauri::AppHandle,
    siem: tauri::State<'_, Siem>,
    email: String,
    password: String,
) -> Result<LoginOutcome> {
    siem.login(&app, &email, &password).await
}

#[tauri::command]
async fn verify_mfa(
    app: tauri::AppHandle,
    siem: tauri::State<'_, Siem>,
    challenge_token: String,
    code: String,
) -> Result<LoginOutcome> {
    siem.verify_mfa(&app, &challenge_token, &code).await
}

/// Trusted-device fast path: Touch ID, then swap the stored refresh token for a
/// live session. Launching the app no longer signs anyone in on its own.
#[tauri::command]
async fn unlock_session(siem: tauri::State<'_, Siem>) -> Result<Value> {
    siem.unlock().await
}

/// Called once on launch: remembered server + (if the keychain still holds a
/// valid refresh token) a live session, so a returning user lands on Search.
#[tauri::command]
async fn restore_session(
    app: tauri::AppHandle,
    siem: tauri::State<'_, Siem>,
) -> Result<RestoreOutcome> {
    siem.restore(&app).await
}

/// Ends the session but keeps the device trusted, so Touch ID can get back in.
#[tauri::command]
async fn lock_session(siem: tauri::State<'_, Siem>) -> Result<()> {
    siem.lock().await
}

/// Ends the session AND destroys device trust — next time, a password.
#[tauri::command]
async fn logout(siem: tauri::State<'_, Siem>) -> Result<()> {
    siem.logout().await
}

/// Sign out *and* forget the server address.
#[tauri::command]
async fn disconnect(app: tauri::AppHandle, siem: tauri::State<'_, Siem>) -> Result<()> {
    siem.disconnect(&app).await
}

/// Whether there's a live session — Quick Search uses it to show a "sign in
/// from the main window" state instead of erroring when nothing is signed in.
#[tauri::command]
async fn is_authenticated(siem: tauri::State<'_, Siem>) -> Result<bool> {
    Ok(siem.is_authenticated().await)
}

#[tauri::command]
async fn schema_fields(siem: tauri::State<'_, Siem>) -> Result<Value> {
    siem.schema_fields().await
}

#[tauri::command]
async fn source_types(
    siem: tauri::State<'_, Siem>,
    start: Option<String>,
    end: Option<String>,
) -> Result<Value> {
    siem.source_types(start.as_deref(), end.as_deref()).await
}

#[tauri::command]
async fn udm_fields(siem: tauri::State<'_, Siem>) -> Result<Value> {
    siem.udm_fields().await
}

/// Quick Search's indicator peek: how much / which assets / since when, from a
/// `ioc = "<value>"` search. Context, not a threat verdict. See `Siem::ioc_peek`.
#[tauri::command]
async fn ioc_peek(siem: tauri::State<'_, Siem>, value: String) -> Result<siem::IocPeek> {
    siem.ioc_peek(&value).await
}

/// "Which of these indicators have we seen?" — the bulk lookup behind a pasted
/// threat report. One search per indicator over the same `ioc = "…"` path as the
/// single peek; see `Siem::bulk_ioc_peek` for why not `/api/prevalence/bulk`.
#[tauri::command]
async fn bulk_ioc_peek(
    siem: tauri::State<'_, Siem>,
    values: Vec<String>,
    window_days: i64,
) -> Result<Vec<siem::BulkIocHit>> {
    siem.bulk_ioc_peek(&values, window_days).await
}

/// Streams SSE frames from `/api/search/stream` into the webview over a Channel,
/// so rows paint as they arrive instead of after the whole query settles.
#[tauri::command]
async fn search_stream(
    siem: tauri::State<'_, Siem>,
    search_id: String,
    request: Value,
    bypass: bool,
    on_event: Channel<Value>,
) -> Result<()> {
    siem.search_stream(&search_id, &request, bypass, on_event)
        .await
}

/// Cancels one tab's search. Other tabs keep streaming.
#[tauri::command]
async fn cancel_search(siem: tauri::State<'_, Siem>, search_id: String) -> Result<()> {
    siem.cancel_search(&search_id).await;
    Ok(())
}

/// Everything the SOC Overview shows, in one round trip. Individually degradable:
/// a panel the analyst lacks permission for costs them that panel, not the page.
#[tauri::command]
async fn dashboard(siem: tauri::State<'_, Siem>) -> Result<siem::Dashboard> {
    siem.dashboard().await
}

/// What a pinned widget window is showing. Kept in Rust, keyed by window label,
/// because a window label must be a value WE chose — a dashboard id and panel id
/// cannot be pasted into it safely, and the widget needs to ask what it is anyway.
#[derive(Clone, Debug, serde::Serialize)]
pub struct WidgetSpec {
    /// "detections" | "ingest" | "agent" | "panel"
    kind: String,
    dashboard_id: Option<String>,
    panel_id: Option<String>,
}

#[derive(Default)]
pub struct Widgets(Mutex<HashMap<String, WidgetSpec>>);

/// What is this widget window supposed to show? Called by the widget on load.
#[tauri::command]
fn widget_spec(window: tauri::WebviewWindow, widgets: tauri::State<'_, Widgets>) -> Result<WidgetSpec> {
    widgets
        .0
        .lock()
        .map_err(|_| error::Error::Internal("widget registry poisoned".into()))?
        .get(window.label())
        .cloned()
        .ok_or_else(|| error::Error::Internal("this window has no widget spec".into()))
}

/// "Pin panel to desktop" — a frameless, always-on-top window that keeps showing
/// this panel while the analyst works in other apps. The thing only a native app
/// can do.
///
/// Re-pinning something already pinned focuses it rather than stacking a second
/// copy on the desktop.
async fn open_widget(app: &tauri::AppHandle, label: String, spec: WidgetSpec, height: f64) -> Result<()> {
    {
        let widgets = app.state::<Widgets>();
        let mut registry = widgets
            .0
            .lock()
            .map_err(|_| error::Error::Internal("widget registry poisoned".into()))?;
        registry.insert(label.clone(), spec);
    }

    if let Some(existing) = app.get_webview_window(&label) {
        let _ = existing.show();
        let _ = existing.set_focus();
        return Ok(());
    }

    tauri::WebviewWindowBuilder::new(app, &label, tauri::WebviewUrl::App("index.html".into()))
        .title("nano")
        .inner_size(330.0, height)
        .decorations(false)
        .always_on_top(true)
        .resizable(false)
        .skip_taskbar(true)
        .build()
        .map_err(|e| error::Error::Internal(format!("pin widget: {e}")))?;

    Ok(())
}

#[tauri::command]
async fn pin_widget(app: tauri::AppHandle, kind: String) -> Result<()> {
    // The label is the window's identity AND what the frontend routes on, so it
    // must be a value we chose — never raw input.
    match kind.as_str() {
        "detections" | "ingest" | "agent" => {}
        other => return Err(error::Error::Internal(format!("unknown widget: {other}"))),
    }
    let label = format!("widget-{kind}");
    let spec = WidgetSpec {
        kind,
        dashboard_id: None,
        panel_id: None,
    };
    open_widget(&app, label, spec, 250.0).await
}

/// Pin ANY panel of ANY dashboard. The label is a counter, not the ids — a window
/// label is not a place to put untrusted identifiers, and the widget asks
/// `widget_spec` what it is once it loads.
#[tauri::command]
async fn pin_panel(
    app: tauri::AppHandle,
    widgets: tauri::State<'_, Widgets>,
    dashboard_id: String,
    panel_id: String,
) -> Result<()> {
    // Already pinned? Focus it rather than opening a second copy of the same panel.
    let existing = {
        let registry = widgets
            .0
            .lock()
            .map_err(|_| error::Error::Internal("widget registry poisoned".into()))?;
        registry
            .iter()
            .find(|(_, spec)| {
                spec.dashboard_id.as_deref() == Some(dashboard_id.as_str())
                    && spec.panel_id.as_deref() == Some(panel_id.as_str())
            })
            .map(|(label, _)| label.clone())
    };

    let label = match existing {
        Some(label) => label,
        None => {
            let count = widgets
                .0
                .lock()
                .map_err(|_| error::Error::Internal("widget registry poisoned".into()))?
                .len();
            format!("widget-panel-{count}")
        }
    };

    let spec = WidgetSpec {
        kind: "panel".into(),
        dashboard_id: Some(dashboard_id),
        panel_id: Some(panel_id),
    };
    open_widget(&app, label, spec, 260.0).await
}

/// Unpin: close the widget window it was called from.
#[tauri::command]
async fn close_widget(window: tauri::WebviewWindow) -> Result<()> {
    let _ = window.close();
    Ok(())
}

/// The dashboards this analyst can see (summaries).
#[tauri::command]
async fn list_dashboards(siem: tauri::State<'_, Siem>) -> Result<Value> {
    siem.list_dashboards().await
}

/// One dashboard in full — its panels and layout.
#[tauri::command]
async fn get_dashboard(siem: tauri::State<'_, Siem>, id: String) -> Result<Value> {
    siem.get_dashboard(&id).await
}

/// Run one panel. Goes through the DASHBOARD endpoint, not search — it enforces
/// per-source RBAC and substitutes $variables with the platform's own semantics,
/// so the desktop and the web app cannot render the same panel differently.
#[tauri::command]
async fn dashboard_panel_query(
    siem: tauri::State<'_, Siem>,
    query: String,
    query_mode: String,
    time_range: Value,
    variables: Option<Value>,
    bypass_cache: Option<bool>,
) -> Result<Value> {
    siem.dashboard_panel_query(
        &query,
        &query_mode,
        &time_range,
        variables.as_ref(),
        bypass_cache.unwrap_or(false),
    )
    .await
}

/// Past pivt investigations — each one is a notebook it recorded itself into.
#[tauri::command]
async fn pivt_sessions(siem: tauri::State<'_, Siem>) -> Result<Vec<Value>> {
    siem.pivt_sessions().await
}

/// One session's transcript: every question, tool call and answer, in order.
#[tauri::command]
async fn notebook_entries(siem: tauri::State<'_, Siem>, notebook_id: String) -> Result<Value> {
    siem.notebook_entries(&notebook_id).await
}

/// The tools nano exposes to agents — asked of the MCP server itself, so the
/// screen can't drift from what the agent actually gets.
#[tauri::command]
async fn mcp_tools(
    app: tauri::AppHandle,
    inventory: tauri::State<'_, McpInventory>,
) -> Result<Vec<mcp::McpTool>> {
    inventory.tools(&app).await
}

/// Which agent CLIs are installed, and whether nano's tools are wired to them.
#[tauri::command]
fn agent_status(app: tauri::AppHandle) -> Result<AgentStatus> {
    agent::status(&app)
}

/// Mint a read-only API key and write the Claude Code + Codex MCP configs.
#[tauri::command]
async fn provision_agent(
    app: tauri::AppHandle,
    siem: tauri::State<'_, Siem>,
    inventory: tauri::State<'_, McpInventory>,
) -> Result<AgentStatus> {
    let status = agent::provision(&app, &siem).await?;
    // The config the inventory was read through has just been rewritten; a cached
    // tool list from the previous server would now be describing someone else's.
    inventory.invalidate().await;
    Ok(status)
}

/// Drop the local key and configs. The key still exists server-side — the UI
/// tells the user to revoke it in the web app.
/// Revokes the key server-side as well as locally.
#[tauri::command]
async fn revoke_agent(
    app: tauri::AppHandle,
    siem: tauri::State<'_, Siem>,
    inventory: tauri::State<'_, McpInventory>,
) -> Result<AgentStatus> {
    let status = agent::revoke(&app, &siem).await?;
    // The config is gone; a cached tool list would outlive the key that reached it.
    inventory.invalidate().await;
    Ok(status)
}

/// Ask pivt. `screen` is what the analyst currently has in front of them, so the
/// assistant answers from the visible query/rows/event instead of re-fetching
/// them; it reaches for nano's MCP tools only for what isn't on screen.
#[tauri::command]
async fn agent_ask(
    app: tauri::AppHandle,
    siem: tauri::State<'_, Siem>,
    prompt: String,
    screen: Option<Value>,
    resume: Option<String>,
    notebook: Option<String>,
    on_event: Channel<Value>,
) -> Result<()> {
    agent::ask(
        &app,
        &siem,
        &prompt,
        screen.as_ref(),
        resume.as_deref(),
        notebook.as_deref(),
        on_event,
    )
    .await
}

#[tauri::command]
fn pty_open(
    app: tauri::AppHandle,
    terminal: tauri::State<'_, Terminal>,
    rows: u16,
    cols: u16,
    on_output: Channel<String>,
) -> Result<()> {
    // Start in the agent workspace so a `claude` launched here is already
    // wired to nano; fall back to $HOME if that directory can't be created.
    let agent_env = match (agent::workspace_dir(&app), agent::codex_home(&app)) {
        (Ok(workspace), Ok(codex_home)) => Some(pty::AgentEnv {
            workspace,
            codex_home,
        }),
        _ => None,
    };
    terminal.open(rows, cols, agent_env, on_output)
}

#[tauri::command]
fn pty_write(terminal: tauri::State<'_, Terminal>, data: String) -> Result<()> {
    terminal.write(&data)
}

#[tauri::command]
fn pty_resize(terminal: tauri::State<'_, Terminal>, rows: u16, cols: u16) -> Result<()> {
    terminal.resize(rows, cols)
}

#[tauri::command]
fn pty_close(terminal: tauri::State<'_, Terminal>) -> Result<()> {
    terminal.close()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            app.manage(Siem::default());
            app.manage(Terminal::default());
            // The MCP tool inventory, fetched from the server once and cached.
            app.manage(McpInventory::default());
            // What each pinned widget window is showing.
            app.manage(Widgets::default());
            // Menu-bar tray + new-alert notifications. Owns its own poll loop.
            tray::setup(app.handle())?;
            // Global-hotkey Quick Search spotlight. Non-fatal if the hotkey is taken.
            quick::setup(app.handle());
            // "Search in nano" in every app's Services menu. Only live in a real
            // .app bundle — the Services registry is keyed off its Info.plist.
            #[cfg(target_os = "macos")]
            services::setup(app.handle());
            Ok(())
        })
        .on_window_event(|window, event| match event {
            // Closing the window keeps the app alive in the menu bar rather than
            // quitting — the tray is the whole point of a background presence.
            // "Quit nano" (tray) and Cmd-Q still exit for real.
            tauri::WindowEvent::CloseRequested { api, .. } if window.label() == "main" => {
                api.prevent_close();
                let _ = window.hide();
            }
            // A real quit destroys the MAIN window — reap the shell then, or a pty
            // child outlives its parent and the user accumulates orphaned logins.
            // Scoped to "main" on purpose: the Terminal is app-global state, so an
            // unscoped handler would kill the analyst's live shell every time they
            // unpinned a desktop widget.
            tauri::WindowEvent::Destroyed if window.label() == "main" => {
                if let Some(terminal) = window.try_state::<Terminal>() {
                    let _ = terminal.close();
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            connect,
            login,
            verify_mfa,
            restore_session,
            unlock_session,
            lock_session,
            logout,
            disconnect,
            is_authenticated,
            quick::hide_quick,
            quick::open_in_main,
            quick::ask_pivt,
            schema_fields,
            source_types,
            udm_fields,
            ioc_peek,
            bulk_ioc_peek,
            search_stream,
            cancel_search,
            agent_status,
            dashboard,
            list_dashboards,
            get_dashboard,
            dashboard_panel_query,
            pin_widget,
            pin_panel,
            widget_spec,
            close_widget,
            pivt_sessions,
            notebook_entries,
            mcp_tools,
            provision_agent,
            revoke_agent,
            agent_ask,
            pty_open,
            pty_write,
            pty_resize,
            pty_close,
        ])
        .run(tauri::generate_context!())
        .expect("error while running nano desktop");
}
