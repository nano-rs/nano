// SPDX-License-Identifier: AGPL-3.0-or-later

//! The region RLS context key a signed-RLS consumer receives from its
//! immutable Secret (`NANOSIEM_SHARED_RLS_KEY_ID`,
//! `NANOSIEM_SHARED_RLS_CONTEXT_KEY_HEX`, `NANOSIEM_SHARED_RLS_KEY_NOT_AFTER`).
//!
//! NAN-3361: on 2026-10-08 the region key expired and every consumer refused
//! to boot with only "setting NANOSIEM_SHARED_RLS_KEY_NOT_AFTER is invalid";
//! running pods gave no warning at all before PostgreSQL started refusing
//! their contexts. This loader is shared by every consumer:
//!
//! * a boot failure for an expired key says "expired at <ts>" and names the
//!   key id (never the key);
//! * [`RlsContextKeyMaterial::spawn_expiry_monitor`] logs `warn!` with less
//!   than 7 days left and `error!` with less than 72 hours left, every 10
//!   minutes, in each long-running process that holds the key.
//!
//! Rotation itself is the platform's (`rls-context-keys:region-rotate`): the
//! Secret is immutable and env-injected, so a new key rolls the consumers.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::tenant_db::{TenantDbContextSigner, TenantDbError};

pub const RLS_KEY_ID_ENV: &str = "NANOSIEM_SHARED_RLS_KEY_ID";
pub const RLS_CONTEXT_KEY_HEX_ENV: &str = "NANOSIEM_SHARED_RLS_CONTEXT_KEY_HEX";
pub const RLS_KEY_NOT_AFTER_ENV: &str = "NANOSIEM_SHARED_RLS_KEY_NOT_AFTER";

/// A consumer refuses to start with less than this left on its key.
pub const MIN_REMAINING_AT_BOOT_SECONDS: i64 = 60;
/// Expiry monitor cadence.
pub const EXPIRY_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
/// `warn!` below this much remaining lifetime.
pub const EXPIRY_WARN_BELOW_HOURS: i64 = 7 * 24;
/// `error!` below this much remaining lifetime.
pub const EXPIRY_ERROR_BELOW_HOURS: i64 = 72;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RlsContextKeyEnvError {
    #[error("required enterprise-shared RLS setting {0} is missing")]
    Missing(&'static str),
    #[error("enterprise-shared RLS setting {0} is invalid")]
    Invalid(&'static str),
    #[error(
        "enterprise-shared RLS context key {key_id} expired at {} ({RLS_KEY_NOT_AFTER_ENV}); \
         rotate the region RLS key (rls-context-keys:region-rotate) and roll this workload",
        not_after.to_rfc3339()
    )]
    Expired { key_id: Uuid, not_after: DateTime<Utc> },
    #[error(
        "enterprise-shared RLS context key {key_id} expires at {} ({RLS_KEY_NOT_AFTER_ENV}), less than \
         {MIN_REMAINING_AT_BOOT_SECONDS} s from now; rotate the region RLS key and roll this workload",
        not_after.to_rfc3339()
    )]
    ExpiresTooSoon { key_id: Uuid, not_after: DateTime<Utc> },
}

impl RlsContextKeyEnvError {
    /// The env setting at fault (for callers whose error type names one).
    pub fn setting(&self) -> &'static str {
        match self {
            Self::Missing(name) | Self::Invalid(name) => name,
            Self::Expired { .. } | Self::ExpiresTooSoon { .. } => RLS_KEY_NOT_AFTER_ENV,
        }
    }
}

/// The key id, key bytes and NOT_AFTER of the mounted region key. Not
/// `Clone`, and `Debug` never prints the key.
pub struct RlsContextKeyMaterial {
    key_id: Uuid,
    key: Vec<u8>,
    not_after: DateTime<Utc>,
}

impl std::fmt::Debug for RlsContextKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RlsContextKeyMaterial")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .field("not_after", &self.not_after)
            .finish()
    }
}

impl RlsContextKeyMaterial {
    /// Read the key from the process environment (empty values are missing).
    pub fn from_env() -> Result<Self, RlsContextKeyEnvError> {
        Self::from_lookup(|name| std::env::var(name).ok(), Utc::now())
    }

    pub fn from_lookup(
        lookup: impl Fn(&'static str) -> Option<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, RlsContextKeyEnvError> {
        let required = |name: &'static str| {
            lookup(name)
                .filter(|value| !value.trim().is_empty())
                .ok_or(RlsContextKeyEnvError::Missing(name))
        };
        let key_id = required(RLS_KEY_ID_ENV)?
            .trim()
            .parse::<Uuid>()
            .map_err(|_| RlsContextKeyEnvError::Invalid(RLS_KEY_ID_ENV))?;
        let key = hex::decode(required(RLS_CONTEXT_KEY_HEX_ENV)?.trim())
            .map_err(|_| RlsContextKeyEnvError::Invalid(RLS_CONTEXT_KEY_HEX_ENV))?;
        let not_after = DateTime::parse_from_rfc3339(required(RLS_KEY_NOT_AFTER_ENV)?.trim())
            .map_err(|_| RlsContextKeyEnvError::Invalid(RLS_KEY_NOT_AFTER_ENV))?
            .with_timezone(&Utc);
        if not_after <= now {
            return Err(RlsContextKeyEnvError::Expired { key_id, not_after });
        }
        if not_after <= now + Duration::seconds(MIN_REMAINING_AT_BOOT_SECONDS) {
            return Err(RlsContextKeyEnvError::ExpiresTooSoon { key_id, not_after });
        }
        Ok(Self { key_id, key, not_after })
    }

    pub fn key_id(&self) -> Uuid {
        self.key_id
    }

    pub fn not_after(&self) -> DateTime<Utc> {
        self.not_after
    }

    /// Consume the material into a context signer (the key bytes move; no copy stays here).
    pub fn into_signer(
        self,
        database: impl Into<String>,
        runtime_role: impl Into<String>,
        ttl_seconds: i64,
    ) -> Result<TenantDbContextSigner, TenantDbError> {
        TenantDbContextSigner::new(database, runtime_role, self.key_id, self.key, ttl_seconds)
    }

    /// Log the key's remaining lifetime now and every 10 minutes (see the
    /// module docs) for as long as the process runs. One monitor per key id
    /// per process, however many runtimes load the key. Needs a Tokio runtime;
    /// a no-op without one.
    pub fn spawn_expiry_monitor(&self, component: &'static str) {
        spawn_expiry_monitor(component, self.key_id, self.not_after);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlsKeyExpiryLevel {
    Healthy,
    /// Less than 7 days left.
    Warn,
    /// Less than 72 hours left.
    Error,
    Expired,
}

pub fn rls_key_expiry_level(not_after: DateTime<Utc>, now: DateTime<Utc>) -> RlsKeyExpiryLevel {
    let remaining = not_after - now;
    if remaining <= Duration::zero() {
        RlsKeyExpiryLevel::Expired
    } else if remaining < Duration::hours(EXPIRY_ERROR_BELOW_HOURS) {
        RlsKeyExpiryLevel::Error
    } else if remaining < Duration::hours(EXPIRY_WARN_BELOW_HOURS) {
        RlsKeyExpiryLevel::Warn
    } else {
        RlsKeyExpiryLevel::Healthy
    }
}

/// One expiry check: log at the level [`rls_key_expiry_level`] picks.
pub fn log_rls_key_expiry(component: &str, key_id: Uuid, not_after: DateTime<Utc>, now: DateTime<Utc>) -> RlsKeyExpiryLevel {
    let level = rls_key_expiry_level(not_after, now);
    let remaining_hours = (not_after - now).num_minutes() as f64 / 60.0;
    let not_after_text = not_after.to_rfc3339();
    match level {
        RlsKeyExpiryLevel::Healthy => tracing::debug!(
            component, %key_id, not_after = %not_after_text, remaining_hours,
            "enterprise-shared RLS context key lifetime ok"
        ),
        RlsKeyExpiryLevel::Warn => tracing::warn!(
            component, %key_id, not_after = %not_after_text, remaining_hours,
            "enterprise-shared RLS context key expires in less than 7 days; rotate the region RLS key"
        ),
        RlsKeyExpiryLevel::Error => tracing::error!(
            component, %key_id, not_after = %not_after_text, remaining_hours,
            "enterprise-shared RLS context key expires in less than 72 hours; rotate the region RLS key now"
        ),
        RlsKeyExpiryLevel::Expired => tracing::error!(
            component, %key_id, not_after = %not_after_text, remaining_hours,
            "enterprise-shared RLS context key has EXPIRED; PostgreSQL refuses this workload's tenant contexts until it rolls onto a rotated key"
        ),
    }
    level
}

fn monitored_keys() -> &'static Mutex<HashSet<Uuid>> {
    static KEYS: OnceLock<Mutex<HashSet<Uuid>>> = OnceLock::new();
    KEYS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// See [`RlsContextKeyMaterial::spawn_expiry_monitor`].
pub fn spawn_expiry_monitor(component: &'static str, key_id: Uuid, not_after: DateTime<Utc>) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    match monitored_keys().lock() {
        Ok(mut keys) => {
            if !keys.insert(key_id) {
                return;
            }
        }
        Err(_) => return,
    }
    handle.spawn(async move {
        let mut interval = tokio::time::interval(EXPIRY_CHECK_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            log_rls_key_expiry(component, key_id, not_after, Utc::now());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_HEX: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

    fn env(not_after: &str) -> impl Fn(&'static str) -> Option<String> + '_ {
        move |name| match name {
            RLS_KEY_ID_ENV => Some("bce9f65e-0000-4000-8000-000000000001".to_string()),
            RLS_CONTEXT_KEY_HEX_ENV => Some(KEY_HEX.to_string()),
            RLS_KEY_NOT_AFTER_ENV => Some(not_after.to_string()),
            _ => None,
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-08T16:00:00Z").unwrap().with_timezone(&Utc)
    }

    #[test]
    fn expired_key_names_the_key_and_the_expiry_but_never_the_bytes() {
        let error = RlsContextKeyMaterial::from_lookup(env("2026-10-08T15:15:51Z"), now()).unwrap_err();
        assert!(matches!(error, RlsContextKeyEnvError::Expired { .. }));
        let text = error.to_string();
        assert!(text.contains("expired at 2026-10-08T15:15:51+00:00"), "{text}");
        assert!(text.contains("bce9f65e-0000-4000-8000-000000000001"), "{text}");
        assert!(!text.contains(KEY_HEX) && !text.contains("is invalid"), "{text}");
        assert_eq!(error.setting(), RLS_KEY_NOT_AFTER_ENV);

        let soon = RlsContextKeyMaterial::from_lookup(env("2026-10-08T16:00:30Z"), now()).unwrap_err();
        assert!(matches!(soon, RlsContextKeyEnvError::ExpiresTooSoon { .. }));
        assert!(soon.to_string().contains("expires at 2026-10-08T16:00:30+00:00"));
    }

    #[test]
    fn missing_and_malformed_settings_name_the_setting() {
        let missing = RlsContextKeyMaterial::from_lookup(|_| None, now()).unwrap_err();
        assert_eq!(missing, RlsContextKeyEnvError::Missing(RLS_KEY_ID_ENV));
        let blank = RlsContextKeyMaterial::from_lookup(
            |name| if name == RLS_KEY_ID_ENV { Some("  ".into()) } else { None }, now()).unwrap_err();
        assert_eq!(blank, RlsContextKeyEnvError::Missing(RLS_KEY_ID_ENV));
        let bad = RlsContextKeyMaterial::from_lookup(env("tomorrow"), now()).unwrap_err();
        assert_eq!(bad, RlsContextKeyEnvError::Invalid(RLS_KEY_NOT_AFTER_ENV));
        let bad_hex = RlsContextKeyMaterial::from_lookup(
            |name| if name == RLS_CONTEXT_KEY_HEX_ENV { Some("zz".into()) } else { env("2027-01-06T00:00:00Z")(name) },
            now()).unwrap_err();
        assert_eq!(bad_hex, RlsContextKeyEnvError::Invalid(RLS_CONTEXT_KEY_HEX_ENV));
        assert!(!bad_hex.to_string().contains("zz"));
    }

    #[test]
    fn valid_key_loads_and_debug_is_redacted() {
        let material = RlsContextKeyMaterial::from_lookup(env("2027-01-06T00:00:00Z"), now()).unwrap();
        assert_eq!(material.key_id().to_string(), "bce9f65e-0000-4000-8000-000000000001");
        let printed = format!("{material:?}");
        assert!(!printed.contains(KEY_HEX) && !printed.contains("94, 94") && printed.contains("<redacted>"));
        material.into_signer("nano", "nano_shared_app_runtime", 30).unwrap();
    }

    #[test]
    fn expiry_levels() {
        let at = |hours: i64| now() + Duration::hours(hours);
        assert_eq!(rls_key_expiry_level(at(24 * 30), now()), RlsKeyExpiryLevel::Healthy);
        assert_eq!(rls_key_expiry_level(at(24 * 7), now()), RlsKeyExpiryLevel::Healthy);
        assert_eq!(rls_key_expiry_level(at(24 * 7 - 1), now()), RlsKeyExpiryLevel::Warn);
        assert_eq!(rls_key_expiry_level(at(72), now()), RlsKeyExpiryLevel::Warn);
        assert_eq!(rls_key_expiry_level(at(71), now()), RlsKeyExpiryLevel::Error);
        assert_eq!(rls_key_expiry_level(at(0), now()), RlsKeyExpiryLevel::Expired);
        assert_eq!(log_rls_key_expiry("test", Uuid::nil(), at(-1), now()), RlsKeyExpiryLevel::Expired);
    }

    #[tokio::test]
    async fn one_monitor_per_key_id() {
        let key = Uuid::new_v4();
        spawn_expiry_monitor("test", key, now() + Duration::days(30));
        spawn_expiry_monitor("test", key, now() + Duration::days(30));
        assert!(monitored_keys().lock().unwrap().contains(&key));
    }
}
