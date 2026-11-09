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
    /// Grace period expired — licensed-only functionality is unavailable
    Locked,
}

/// Canonical entitlement metadata returned by nano-main for a manual licence.
/// Legacy paid/subscription responses omit it and retain their existing state
/// machine. Field aliases accept both the online camelCase response and the
/// signed offline claim spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseEntitlement {
    #[serde(rename = "licenseId", alias = "license_id")]
    pub license_id: String,
    pub edition: String,
    pub operator: String,
    pub offering: String,
    pub kind: String,
    #[serde(rename = "capacityGbPerDay", alias = "capacity_gb_per_day", default)]
    pub capacity_gb_per_day: Option<u64>,
    #[serde(rename = "startsAt", alias = "starts_at", alias = "valid_from")]
    pub starts_at: DateTime<Utc>,
    #[serde(rename = "expiresAt", alias = "expires_at")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "graceEndsAt", alias = "grace_ends_at", alias = "grace_until")]
    pub grace_ends_at: DateTime<Utc>,
    pub state: String,
    #[serde(rename = "daysRemaining", alias = "days_remaining", default)]
    pub days_remaining: u64,
    pub revision: u64,
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
    /// Present for canonical v2 manual licences. A trial carries this through
    /// the cache so expiry can degrade only licensed features, never core
    /// search, ingest, or stored-data access.
    #[serde(default)]
    pub entitlement: Option<LicenseEntitlement>,
}

impl Default for LicenseStatus {
    fn default() -> Self {
        Self {
            state: LicenseState::Locked,
            valid: false,
            tier: None,
            locked_reason: Some("Licence admission has not been initialized.".into()),
            grace_ends_at: None,
            expires_at: None,
            last_checked_at: None,
            last_heartbeat_at: None,
            offline: false,
            entitlement: None,
        }
    }
}

impl LicenseStatus {
    /// Fail-closed status used before an enterprise admission authority has
    /// produced a successful observation.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            state: LicenseState::Locked,
            valid: false,
            locked_reason: Some(reason.into()),
            ..Self::default()
        }
    }

    /// Only a successful online response may seed the bounded online outage
    /// cache. The migration/default row is intentionally active for legacy
    /// readers, so `last_checked_at = NULL` must never become admission.
    pub fn for_online_admission(&self) -> LicenseStatus {
        if !self.offline && self.last_checked_at.is_some() {
            self.clone()
        } else {
            LicenseStatus::unavailable(
                "Online licence has not completed its first successful check.",
            )
        }
    }

    /// Returns `true` if a hard `expires_at` is set and has already elapsed.
    ///
    /// This is evaluated purely against the in-memory/stored fields, so it works
    /// with no network — it is what lets an operator-imported (offline) eval
    /// license self-expire locally.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }

    pub fn trial_entitlement(&self) -> Option<&LicenseEntitlement> {
        self.entitlement
            .as_ref()
            .filter(|entitlement| entitlement.kind == "trial")
    }

    pub fn trial_days_remaining(&self, now: DateTime<Utc>) -> Option<i64> {
        self.trial_entitlement().map(|entitlement| {
            let seconds = (entitlement.expires_at - now).num_seconds();
            if seconds <= 0 {
                0
            } else {
                (seconds + 86_399) / 86_400
            }
        })
    }

    /// Warning boundary currently in effect. This deliberately collapses the
    /// continuous countdown into the promised 14/7/1-day notification steps.
    pub fn trial_warning_days(&self, now: DateTime<Utc>) -> Option<i64> {
        match self.trial_days_remaining(now)? {
            0 => Some(0),
            1 => Some(1),
            2..=7 => Some(7),
            8..=14 => Some(14),
            _ => None,
        }
    }

    /// Compute the **effective** status as seen by request-time enforcement
    /// (the `license_guard` middleware and `GET /api/license`).
    ///
    /// Read-time expiry preserves `[expires_at, grace_ends_at)` as grace and
    /// locks only at the exclusive grace boundary. This is a pure computation:
    /// it does not mutate the stored row and therefore still enforces an
    /// offline hard stop without a network check.
    pub fn effective(&self, now: DateTime<Utc>) -> LicenseStatus {
        // An online observation older than the outage bound admits nothing,
        // whatever state it cached. The checker's periodic staleness lock only
        // rewrites stored-Active rows; this read-time bound also covers a
        // cached *scheduled* trial (stored Locked, unlocked locally at its
        // start) and cached grace, so blocking the licence server can never
        // keep licensed features alive past STALE_LICENSE_DAYS.
        if let Some(stale) = self.stale_online_lock(now) {
            return stale;
        }
        if let Some(trial) = self.trial_entitlement() {
            return self.trial_effective(trial, now);
        }
        self.window_effective(now)
    }

    /// A canonical manual trial from nano-main carries its own signed-off
    /// window. The cached response envelope (`expiresAt`/`graceEndsAt`) is
    /// rewritten per trial state by the platform, so the trial window is the
    /// authority and is applied through the same grace/hard-stop model as
    /// every other licence. A server-side lock is only lifted locally for a
    /// scheduled trial whose start time has arrived.
    fn trial_effective(&self, trial: &LicenseEntitlement, now: DateTime<Utc>) -> LicenseStatus {
        if trial.state == "revoked" {
            return LicenseStatus {
                state: LicenseState::Locked,
                valid: false,
                locked_reason: self
                    .locked_reason
                    .clone()
                    .or_else(|| Some("Trial revoked.".into())),
                ..self.clone()
            };
        }
        if self.state == LicenseState::Locked && trial.state != "scheduled" {
            return self.clone();
        }
        if now < trial.starts_at {
            return LicenseStatus {
                state: LicenseState::Locked,
                valid: false,
                locked_reason: Some(format!(
                    "Trial starts at {}.",
                    trial.starts_at.to_rfc3339()
                )),
                ..self.clone()
            };
        }
        let in_grace = self.state == LicenseState::GracePeriod;
        let windowed = LicenseStatus {
            state: if in_grace {
                LicenseState::GracePeriod
            } else {
                LicenseState::Active
            },
            valid: !in_grace,
            locked_reason: None,
            expires_at: Some(trial.expires_at),
            grace_ends_at: Some(trial.grace_ends_at),
            ..self.clone()
        };
        let mut effective = windowed.window_effective(now);
        if effective.state == LicenseState::Locked {
            effective.locked_reason = Some(format!(
                "Trial grace period ended at {}. Licensed-only features are disabled; search, ingest, and stored data remain available.",
                trial.grace_ends_at.to_rfc3339()
            ));
        }
        effective
    }

    fn window_effective(&self, now: DateTime<Utc>) -> LicenseStatus {
        match self.state {
            LicenseState::Locked => self.clone(),
            LicenseState::GracePeriod => {
                if self.grace_ends_at.is_some_and(|end| now < end) {
                    self.clone()
                } else {
                    self.locked_at_hard_stop()
                }
            }
            LicenseState::Active if self.is_expired(now) => {
                if self.grace_ends_at.is_some_and(|end| now < end) {
                    LicenseStatus {
                        state: LicenseState::GracePeriod,
                        valid: false,
                        ..self.clone()
                    }
                } else {
                    self.locked_at_hard_stop()
                }
            }
            LicenseState::Active => self.clone(),
        }
    }

    fn stale_online_lock(&self, now: DateTime<Utc>) -> Option<LicenseStatus> {
        if self.offline {
            return None;
        }
        let last = self.last_checked_at?;
        let bound = chrono::Duration::days(super::checker::STALE_LICENSE_DAYS);
        (now - last > bound).then(|| LicenseStatus {
            state: LicenseState::Locked,
            valid: false,
            locked_reason: Some(format!(
                "License server unreachable for {} days. Check network connectivity to the license server.",
                super::checker::STALE_LICENSE_DAYS
            )),
            ..self.clone()
        })
    }

    fn locked_at_hard_stop(&self) -> LicenseStatus {
        let boundary = self.grace_ends_at.or(self.expires_at);
        LicenseStatus {
            state: LicenseState::Locked,
            valid: false,
            locked_reason: self.locked_reason.clone().or_else(|| {
                Some(format!(
                    "Licence reached its hard-stop boundary at {}.",
                    boundary.map(|value| value.to_rfc3339()).unwrap_or_default()
                ))
            }),
            ..self.clone()
        }
    }
}

/// NAN-5055: an audited per-deployment entitlement grant carried by an
/// admitted paid/exempt online check-in (contract: "Online entitlement
/// object", `kind=paid`, `grant=grandfathered`). It never admits a
/// deployment; it only states what an admitted deployment is entitled to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementGrant {
    #[serde(rename = "licenseId")]
    pub license_id: String,
    pub edition: String,
    pub kind: String,
    pub grant: String,
    #[serde(rename = "aiCreditsPerMonth")]
    pub ai_credits_per_month: u32,
    pub state: String,
    pub revision: u64,
}

/// `increment_ai_credits` stores the counter in PostgreSQL INTEGER.
pub const MAX_GRANTED_AI_CREDITS_PER_MONTH: u32 = i32::MAX as u32;

impl EntitlementGrant {
    /// Only an active, licensed, grandfathered paid grant with an in-range
    /// allowance is honoured. Anything else is ignored (never escalates).
    pub fn is_honoured(&self) -> bool {
        self.kind == "paid"
            && self.grant == "grandfathered"
            && self.state == "active"
            && matches!(
                self.edition.parse::<crate::EntitlementEdition>(),
                Ok(crate::EntitlementEdition::Licensed)
            )
            && (1..=MAX_GRANTED_AI_CREDITS_PER_MONTH).contains(&self.ai_credits_per_month)
    }
}

/// Response from nano-main's GET /api/license/status
#[derive(Debug, Deserialize)]
#[serde(from = "LicenseResponseWire")]
pub struct LicenseResponse {
    pub valid: bool,
    pub tier: Option<String>,
    pub locked: Option<bool>,
    pub locked_reason: Option<String>,
    pub expires_at: Option<String>,
    pub grace_ends_at: Option<String>,
    /// Additive trial metadata. A malformed or newer-shaped object is ignored
    /// rather than failing the whole check-in: admission is decided by
    /// `valid`/`locked`, so dropping it degrades only to the tier-only path.
    pub entitlement: Option<LicenseEntitlement>,
    /// Honoured deployment grant (already validated by
    /// [`EntitlementGrant::is_honoured`]); `None` for every other response.
    pub grant: Option<EntitlementGrant>,
    /// NAN-5114: the newest nano release (Self-run only). Never affects
    /// admission; `None` when absent, malformed or not on the nano domain.
    pub release: Option<super::release_notice::ReleaseNotice>,
}

impl LicenseResponse {
    /// The AI allowance an admitted check-in grants, if any.
    pub fn granted_ai_credits_per_month(&self) -> Option<u32> {
        self.grant.as_ref().map(|grant| grant.ai_credits_per_month)
    }
}

#[derive(Deserialize)]
struct LicenseResponseWire {
    valid: bool,
    tier: Option<String>,
    locked: Option<bool>,
    #[serde(rename = "lockedReason")]
    locked_reason: Option<String>,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    #[serde(rename = "graceEndsAt")]
    grace_ends_at: Option<String>,
    #[serde(default)]
    entitlement: Option<serde_json::Value>,
    // NAN-5114 / FRO-940: additive release facts. Each is read loosely (any
    // JSON value) so a newer or malformed shape drops the notice instead of
    // failing the whole check-in.
    #[serde(default, rename = "latestVersion")]
    latest_version: Option<serde_json::Value>,
    #[serde(default, rename = "releaseNotesUrl")]
    release_notes_url: Option<serde_json::Value>,
    #[serde(default, rename = "upgradeUrl")]
    upgrade_url: Option<serde_json::Value>,
    #[serde(default, rename = "securityRelease")]
    security_release: Option<serde_json::Value>,
}

fn wire_string(value: Option<serde_json::Value>) -> Option<String> {
    match value {
        Some(serde_json::Value::String(value)) => Some(value),
        _ => None,
    }
}

impl From<LicenseResponseWire> for LicenseResponse {
    fn from(wire: LicenseResponseWire) -> Self {
        let (entitlement, grant) = classify_entitlement(wire.entitlement);
        let release = super::release_notice::ReleaseNotice::from_wire(
            wire_string(wire.latest_version),
            wire_string(wire.release_notes_url),
            wire_string(wire.upgrade_url),
            wire.security_release.and_then(|value| value.as_bool()),
        );
        Self {
            valid: wire.valid,
            tier: wire.tier,
            locked: wire.locked,
            locked_reason: wire.locked_reason,
            expires_at: wire.expires_at,
            grace_ends_at: wire.grace_ends_at,
            entitlement,
            grant,
            release,
        }
    }
}

/// Split the one `entitlement` wire object into the trial window or a
/// deployment grant. A grant is recognised by its `grant` member; anything
/// malformed, unknown or not honoured is dropped with a warning.
fn classify_entitlement(
    value: Option<serde_json::Value>,
) -> (Option<LicenseEntitlement>, Option<EntitlementGrant>) {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return (None, None);
    };
    if value.get("grant").is_some() {
        return match serde_json::from_value::<EntitlementGrant>(value) {
            Ok(grant) if grant.is_honoured() => (None, Some(grant)),
            Ok(grant) => {
                tracing::warn!(
                    kind = %grant.kind,
                    grant = %grant.grant,
                    state = %grant.state,
                    "Ignoring online entitlement grant that is not honoured"
                );
                (None, None)
            }
            Err(error) => {
                tracing::warn!(%error, "Ignoring malformed online entitlement grant");
                (None, None)
            }
        };
    }
    match serde_json::from_value(value) {
        Ok(entitlement) => (Some(entitlement), None),
        Err(error) => {
            tracing::warn!(%error, "Ignoring malformed online licence entitlement");
            (None, None)
        }
    }
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
            entitlement: None,
            ..Default::default()
        };

        assert!(status.is_expired(now));
        let eff = status.effective(now);
        assert_eq!(eff.state, LicenseState::Locked);
        assert!(!eff.valid);
        assert!(eff.locked_reason.is_some());
    }

    #[test]
    fn online_grace_survives_contract_expiry_until_hard_stop() {
        let now = Utc::now();
        let grace_end = now + Duration::days(7);
        let status = LicenseStatus {
            state: LicenseState::GracePeriod,
            valid: false,
            expires_at: Some(now - Duration::seconds(1)),
            grace_ends_at: Some(grace_end),
            ..Default::default()
        };

        assert_eq!(status.effective(now).state, LicenseState::GracePeriod);
        assert_eq!(
            status.effective(grace_end).state,
            LicenseState::Locked,
            "grace_until is exclusive"
        );
    }

    #[test]
    fn cached_active_status_enters_grace_at_contract_expiry() {
        let now = Utc::now();
        let status = LicenseStatus {
            state: LicenseState::Active,
            valid: true,
            expires_at: Some(now),
            grace_ends_at: Some(now + Duration::hours(72)),
            ..Default::default()
        };

        let effective = status.effective(now);
        assert_eq!(effective.state, LicenseState::GracePeriod);
        assert!(!effective.valid);
    }

    #[test]
    fn seeded_active_row_is_not_online_admission() {
        let admitted = LicenseStatus::default().for_online_admission();
        assert_eq!(admitted.state, LicenseState::Locked);
        assert!(!admitted.valid);
    }

    #[test]
    fn successful_online_observation_is_admitted_from_cache() {
        let status = LicenseStatus {
            state: LicenseState::Active,
            valid: true,
            locked_reason: None,
            last_checked_at: Some(Utc::now()),
            ..Default::default()
        };
        assert_eq!(status.for_online_admission().state, LicenseState::Active);
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
            entitlement: None,
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
            entitlement: None,
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

    fn trial(now: DateTime<Utc>) -> LicenseStatus {
        LicenseStatus {
            state: LicenseState::Active,
            valid: true,
            expires_at: Some(now + Duration::days(1)),
            grace_ends_at: Some(now + Duration::days(8)),
            entitlement: Some(LicenseEntitlement {
                license_id: "lic_test".into(),
                edition: "licensed".into(),
                operator: "self-run".into(),
                offering: "self-run".into(),
                kind: "trial".into(),
                capacity_gb_per_day: None,
                starts_at: now - Duration::days(89),
                expires_at: now + Duration::days(1),
                grace_ends_at: now + Duration::days(8),
                state: "active".into(),
                days_remaining: 1,
                revision: 1,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn trial_moves_to_grace_then_locks_at_the_seven_day_boundary() {
        let now = Utc::now();
        let status = trial(now);
        let grace = status.effective(now + Duration::days(2));
        assert_eq!(grace.state, LicenseState::GracePeriod);
        assert!(!grace.valid);

        let expired = status.effective(now + Duration::days(8));
        assert_eq!(expired.state, LicenseState::Locked);
        assert!(
            expired
                .locked_reason
                .as_deref()
                .unwrap()
                .contains("search, ingest")
        );
    }

    #[test]
    fn trial_warning_steps_are_fourteen_seven_and_one_days() {
        let now = Utc::now();
        let mut status = trial(now);
        let entitlement = status.entitlement.as_mut().unwrap();
        entitlement.expires_at = now + Duration::days(14);
        assert_eq!(status.trial_warning_days(now), Some(14));
        status.entitlement.as_mut().unwrap().expires_at = now + Duration::days(7);
        assert_eq!(status.trial_warning_days(now), Some(7));
        status.entitlement.as_mut().unwrap().expires_at = now + Duration::days(1);
        assert_eq!(status.trial_warning_days(now), Some(1));
    }

    #[test]
    fn scheduled_trial_activates_locally_when_its_start_time_arrives() {
        let now = Utc::now();
        let mut status = trial(now);
        status.state = LicenseState::Locked;
        status.valid = false;
        let entitlement = status.entitlement.as_mut().unwrap();
        entitlement.state = "scheduled".into();
        entitlement.starts_at = now + Duration::hours(1);
        entitlement.expires_at = now + Duration::days(91);
        entitlement.grace_ends_at = now + Duration::days(98);

        let scheduled = status.effective(now);
        assert_eq!(scheduled.state, LicenseState::Locked);
        assert!(!scheduled.valid);

        let active = status.effective(now + Duration::hours(2));
        assert_eq!(active.state, LicenseState::Active);
        assert!(active.valid);
    }

    #[test]
    fn revoked_trial_never_re_enters_grace_as_time_advances() {
        let now = Utc::now();
        let mut status = trial(now);
        status.state = LicenseState::Locked;
        status.valid = false;
        status.entitlement.as_mut().unwrap().state = "revoked".into();

        let after_contract_expiry = status.effective(now + Duration::days(2));
        assert_eq!(after_contract_expiry.state, LicenseState::Locked);
        assert!(!after_contract_expiry.valid);
    }

    #[test]
    fn server_locked_trial_is_not_reopened_by_the_local_window() {
        let now = Utc::now();
        let mut status = trial(now);
        status.state = LicenseState::Locked;
        status.valid = false;
        status.entitlement.as_mut().unwrap().state = "expired".into();
        // Even if the local clock still sits inside the signed window, only a
        // fresh platform observation may lift an explicit server-side lock.
        assert_eq!(status.effective(now).state, LicenseState::Locked);
    }

    /// Review fix: a box that cached one "scheduled" trial response and then
    /// blocked the licence server must not keep licensed features past the
    /// 14-day outage bound (it previously kept them until grace_until, even
    /// after a revocation it never saw).
    #[test]
    fn cached_scheduled_trial_hits_the_outage_bound() {
        let now = Utc::now();
        let mut status = trial(now);
        status.state = LicenseState::Locked;
        status.valid = false;
        status.last_checked_at = Some(now);
        {
            let entitlement = status.entitlement.as_mut().unwrap();
            entitlement.state = "scheduled".into();
            entitlement.starts_at = now + Duration::hours(1);
            entitlement.expires_at = now + Duration::days(120);
            entitlement.grace_ends_at = now + Duration::days(127);
        }
        // Fresh observation: the scheduled trial activates locally at start.
        assert_eq!(status.effective(now + Duration::hours(2)).state, LicenseState::Active);
        // Unreachable past the bound: locked, even though the window is open.
        let stale = status.effective(now + Duration::days(15));
        assert_eq!(stale.state, LicenseState::Locked);
        assert!(stale.locked_reason.unwrap().contains("unreachable"));
    }

    #[test]
    fn stale_online_observation_locks_every_cached_state_but_not_offline() {
        let now = Utc::now();
        for state in [LicenseState::Active, LicenseState::GracePeriod] {
            let status = LicenseStatus {
                state,
                valid: state == LicenseState::Active,
                last_checked_at: Some(now - Duration::days(15)),
                grace_ends_at: Some(now + Duration::days(5)),
                locked_reason: None,
                ..Default::default()
            };
            assert_eq!(status.effective(now).state, LicenseState::Locked, "{state:?}");
        }
        let offline = LicenseStatus {
            state: LicenseState::Active,
            valid: true,
            offline: true,
            last_checked_at: Some(now - Duration::days(400)),
            locked_reason: None,
            ..Default::default()
        };
        assert_eq!(offline.effective(now).state, LicenseState::Active);
    }
}
