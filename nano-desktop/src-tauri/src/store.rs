//! Persistence: the server the user connected to (plain file) and the refresh
//! token (macOS Keychain).
//!
//! The access token is deliberately NOT persisted — it is short-lived and lives
//! only in memory. Only the refresh token reaches the keychain, and nothing
//! secret is ever handed to the webview.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::Manager;

use crate::error::{Error, Result};

const KEYCHAIN_SERVICE: &str = "rs.nano.desktop";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    /// Normalized base URL: scheme + host + optional path prefix, no trailing slash.
    pub base_url: String,
    /// Search runs on a separate service (`nanosiem-search`). A deployed instance
    /// fans `/api/search*` to it from the same origin, so this is normally None —
    /// but local dev splits them (API :3000, search :3002), and so can a
    /// split-ingress deployment.
    #[serde(default)]
    pub search_url: Option<String>,
    /// User explicitly accepted an unverifiable certificate for this server.
    #[serde(default)]
    pub allow_insecure: bool,
    /// Who last signed in here — shown on the trusted-device card so the user
    /// knows which identity Touch ID is about to unlock. Not a credential.
    #[serde(default)]
    pub last_email: Option<String>,
}

impl ServerConfig {
    /// Where search requests go: the override if set, otherwise the main base.
    pub fn search_base(&self) -> &str {
        self.search_url.as_deref().unwrap_or(&self.base_url)
    }
}

fn config_path(app: &tauri::AppHandle) -> Result<PathBuf> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| Error::Internal(format!("no config dir: {e}")))?;
    std::fs::create_dir_all(&dir).map_err(|e| Error::Internal(format!("config dir: {e}")))?;
    Ok(dir.join("server.json"))
}

pub fn load_server(app: &tauri::AppHandle) -> Option<ServerConfig> {
    let path = config_path(app).ok()?;
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_server(app: &tauri::AppHandle, server: &ServerConfig) -> Result<()> {
    let path = config_path(app)?;
    let raw = serde_json::to_string_pretty(server)
        .map_err(|e| Error::Internal(format!("serialize server: {e}")))?;
    std::fs::write(path, raw).map_err(|e| Error::Internal(format!("write server: {e}")))
}

pub fn clear_server(app: &tauri::AppHandle) -> Result<()> {
    let path = config_path(app)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Internal(format!("clear server: {e}"))),
    }
}

/// Refresh tokens are scoped per server, so switching instances cannot
/// accidentally present one server's token to another.
fn entry(base_url: &str) -> Result<keyring::Entry> {
    Ok(keyring::Entry::new(KEYCHAIN_SERVICE, base_url)?)
}

pub fn save_refresh_token(base_url: &str, token: &str) -> Result<()> {
    save_secret(base_url, token)
}

pub fn load_refresh_token(base_url: &str) -> Option<String> {
    load_secret(base_url)
}

pub fn clear_refresh_token(base_url: &str) -> Result<()> {
    clear_secret(base_url)
}

/// Keychain access under an arbitrary account key. The agent's API key uses a
/// distinct account (`<base_url>#mcp`) so revoking it cannot disturb the user's
/// own session token.
pub fn save_secret(account: &str, secret: &str) -> Result<()> {
    entry(account)?.set_password(secret)?;
    Ok(())
}

pub fn load_secret(account: &str) -> Option<String> {
    entry(account).ok()?.get_password().ok()
}

pub fn clear_secret(account: &str) -> Result<()> {
    match entry(account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
