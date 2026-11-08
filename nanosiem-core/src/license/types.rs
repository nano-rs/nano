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
    /// Set by an operator-imported air-gap license bundle (NAN-1206 / WS4).
    /// Online deployments (and any row written before migration 200) default to
    /// `false`, leaving existing behaviour byte-identical.
    #[serde(default)]
    pub offline: bool,
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
            offline: false,
        }
    }
}

impl LicenseStatus {
    /// Returns `true` if a hard `expires_at` is set and has already elapsed.
    ///
    /// This is evaluated purely against the in-memory/stored fields, so it works
    /// with no network — it is what lets an operator-imported (offline) eval
    /// license self-expire locally.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        matches!(self.expires_at, Some(exp) if now > exp)
    }

    /// Compute the **effective** status as seen by request-time enforcement
    /// (the `license_guard` middleware and `GET /api/license`).
    ///
    /// Read-time expiry: if `expires_at` is set and in the past, the license is
    /// forced to the same degraded state the online checker would produce on
    /// expiry — `Locked` / `valid = false` — regardless of `offline`. This is a
    /// pure computation: it does not mutate the stored row.
    ///
    /// When not expired, the stored state is returned unchanged, so online
    /// installs (which never set `expires_at` in the past while Active) are
    /// unaffected.
    pub fn effective(&self, now: DateTime<Utc>) -> LicenseStatus {
        if self.is_expired(now) {
            LicenseStatus {
                state: LicenseState::Locked,
                valid: false,
                locked_reason: Some(format!(
                    "License expired at {}.",
                    self.expires_at
                        .map(|e| e.to_rfc3339())
                        .unwrap_or_default()
                )),
                ..self.clone()
            }
        } else {
            self.clone()
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    /// An offline, Active, valid license whose `expires_at` is in the past must
    /// degrade to Locked/invalid at read time — this is the air-gap self-expiry
    /// (NAN-1206 / WS4) that works with no network.
    #[test]
    fn offline_active_license_self_expires_when_past_expiry() {
        let now = Utc::now();
        let status = LicenseStatus {
            state: LicenseState::Active,
            valid: true,
            expires_at: Some(now - Duration::hours(1)),
            offline: true,
            ..Default::default()
        };

        assert!(status.is_expired(now));
        let eff = status.effective(now);
        assert_eq!(eff.state, LicenseState::Locked);
        assert!(!eff.valid);
        assert!(eff.locked_reason.is_some());
    }

    /// An offline license whose `expires_at` is in the future stays Active/valid.
    #[test]
    fn offline_active_license_stays_valid_before_expiry() {
        let now = Utc::now();
        let status = LicenseStatus {
            state: LicenseState::Active,
            valid: true,
            expires_at: Some(now + Duration::days(30)),
            offline: true,
            ..Default::default()
        };

        assert!(!status.is_expired(now));
        let eff = status.effective(now);
        assert_eq!(eff.state, LicenseState::Active);
        assert!(eff.valid);
    }

    /// Online installs that never set `expires_at` are unaffected — `effective`
    /// returns the stored state byte-identically.
    #[test]
    fn no_expiry_is_a_noop() {
        let now = Utc::now();
        let status = LicenseStatus {
            state: LicenseState::Active,
            valid: true,
            expires_at: None,
            offline: false,
            ..Default::default()
        };

        assert!(!status.is_expired(now));
        let eff = status.effective(now);
        assert_eq!(eff.state, LicenseState::Active);
        assert!(eff.valid);
    }

    /// `offline` defaults to false when absent from serialized JSON (rows written
    /// before migration 200 / online check-in responses), keeping online behaviour
    /// unchanged.
    #[test]
    fn offline_defaults_false_on_deserialize() {
        let json = r#"{
            "state": "active",
            "valid": true,
            "tier": null,
            "locked_reason": null,
            "grace_ends_at": null,
            "expires_at": null,
            "last_checked_at": null,
            "last_heartbeat_at": null
        }"#;
        let status: LicenseStatus = serde_json::from_str(json).unwrap();
        assert!(!status.offline);
    }
}
