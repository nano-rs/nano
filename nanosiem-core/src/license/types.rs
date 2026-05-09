// SPDX-License-Identifier: AGPL-3.0-or-later

//! License types shared between checker and API

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// License state machine: active → grace_period → locked → active (on resubscribe)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseState {
    /// Subscription active, everything works
    Active,
    /// Subscription canceled but within 7-day grace period
    GracePeriod,
    /// Grace period expired — full lockout
    Locked,
}

impl LicenseState {
    pub fn as_str(&self) -> &'static str {
        match self {
            LicenseState::Active => "active",
            LicenseState::GracePeriod => "grace_period",
            LicenseState::Locked => "locked",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "grace_period" => LicenseState::GracePeriod,
            "locked" => LicenseState::Locked,
            _ => LicenseState::Active,
        }
    }

    pub fn is_locked(&self) -> bool {
        matches!(self, LicenseState::Locked)
    }

    pub fn is_grace_period(&self) -> bool {
        matches!(self, LicenseState::GracePeriod)
    }
}

impl std::fmt::Display for LicenseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cached license status (stored in Postgres and shared via AppState)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseStatus {
    pub state: LicenseState,
    pub valid: bool,
    pub tier: Option<String>,
    pub locked_reason: Option<String>,
    pub grace_ends_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
}

impl Default for LicenseStatus {
    fn default() -> Self {
        Self {
            state: LicenseState::Active,
            valid: true,
            tier: None,
            locked_reason: None,
            grace_ends_at: None,
            expires_at: None,
            last_checked_at: None,
            last_heartbeat_at: None,
        }
    }
}

/// Response from nano-main's GET /api/license/status
#[derive(Debug, Deserialize)]
pub struct LicenseResponse {
    pub valid: bool,
    pub tier: Option<String>,
    pub locked: Option<bool>,
    #[serde(rename = "lockedReason")]
    pub locked_reason: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "graceEndsAt")]
    pub grace_ends_at: Option<String>,
}
