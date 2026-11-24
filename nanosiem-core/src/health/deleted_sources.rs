// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5785: what happens to a log source's health state when the source is
//! deleted, disabled, or has stale alerting turned off.
//!
//! The feed monitor only visits sources that exist and are monitored, so a
//! removed source's "Log source stopped sending" alert used to stay active
//! with nothing explaining why. The rule here: **a source mutation never
//! closes a real alert.** `log_sources:edit` / `log_sources:delete` would
//! otherwise be a way to silence a blinded feed (and resolve its PagerDuty
//! incident) without `system_health:manage`. Instead:
//!
//! * the active alert stays active, retitled with who removed the source
//!   (`"Log source stopped sending: fw (source deleted by Alice)"`) and with
//!   `diagnostic_context.source_removed` set;
//! * its destinations get a reminder with that title, so the on-call sees the
//!   removal and the incident stays open;
//! * the caller records a durable [`SYSTEM_HEALTH_SOURCE_REMOVED`] audit event
//!   per flagged alert, naming the actor;
//! * an owner closes it with the ordinary, audited manual resolve.
//!
//! Only the in-app notification de-duplication row (`health_issue_tracker`) of
//! a DELETED source is closed quietly: it is bookkeeping, not an alert.
//!
//! [`sweep_orphaned_log_source_health`] runs on every feed-staleness pass and
//! flags what no delete path flagged (a raw SQL delete, a delete path without
//! an actor, a stale pass that raced the delete).

use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use super::repository::HealthRepository;
use crate::audit::{AuditEvent, AuditEventBuilder, AuditSource, SYSTEM_HEALTH_SOURCE_REMOVED};
use crate::system_health::{SystemHealthEvent, SystemHealthRepository};

/// The `by` of a removal no API call recorded an actor for.
pub const UNRECORDED_ACTOR: &str = "an unrecorded path";

/// How a source stopped being monitored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRemoval {
    Deleted,
    Disabled,
    StaleAlertingOff,
}

impl SourceRemoval {
    /// `diagnostic_context.source_removed.action` and the audit `details.action`.
    pub fn action(self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::Disabled => "disabled",
            Self::StaleAlertingOff => "stale_alerting_off",
        }
    }

    /// The title suffix, e.g. `source deleted by Alice`.
    pub fn label(self, by: &str) -> String {
        match self {
            Self::Deleted => format!("source deleted by {by}"),
            Self::Disabled => format!("source disabled by {by}"),
            Self::StaleAlertingOff => format!("stale alerting turned off by {by}"),
        }
    }
}

/// Who made the change, as the flag names them: the user's name (or email),
/// plus the API key when one was used. Falls back to the user id.
pub async fn actor_label(pool: &PgPool, user_id: Option<Uuid>, api_key_name: Option<&str>) -> String {
    let user = match user_id {
        Some(id) => sqlx::query_scalar::<_, String>(
            "SELECT COALESCE(NULLIF(name, ''), email) FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| id.to_string()),
        None => UNRECORDED_ACTOR.to_string(),
    };
    match api_key_name {
        Some(key) => format!("{user} (API key {key})"),
        None => user,
    }
}

/// Flag (never resolve) the active health alerts of sources that were just
/// removed, and for a delete close their notification de-dup rows. Returns
/// the flagged alerts so the caller can audit each with its actor. Never
/// fails: errors are logged (for a delete, the scheduler sweep retries).
pub async fn flag_removed_source_health(
    pool: &PgPool,
    source_ids: &[Uuid],
    removal: SourceRemoval,
    by: &str,
) -> Vec<SystemHealthEvent> {
    if source_ids.is_empty() {
        return Vec::new();
    }
    let flagged = match SystemHealthRepository::new(pool.clone())
        .flag_log_source_events_removed(source_ids, removal.action(), &removal.label(by), by)
        .await
    {
        Ok(events) => events,
        Err(error) => {
            warn!(%error, count = source_ids.len(), action = removal.action(),
                "could not flag the health alerts of removed log sources");
            Vec::new()
        }
    };
    if removal == SourceRemoval::Deleted {
        if let Err(error) = HealthRepository::new(pool.clone())
            .resolve_data_feed_issues(source_ids)
            .await
        {
            warn!(%error, count = source_ids.len(),
                "could not close the notification issues of deleted log sources");
        }
    }
    flagged
}

/// The scheduler's sweep. Flags (never resolves) active alerts that no API
/// path flagged: those of deleted sources, and stale alerts a racing pass
/// raised for a source already disabled or with stale alerting off. Closes
/// deleted sources' notification de-dup rows. Returns each flagged alert with
/// its removal kind (to audit durably). Errors are logged; the next pass
/// retries.
pub async fn sweep_orphaned_log_source_health(
    system_health: &SystemHealthRepository,
    health: &HealthRepository,
) -> Vec<(SystemHealthEvent, SourceRemoval)> {
    let mut flagged = Vec::new();
    let deleted = SourceRemoval::Deleted;
    match system_health
        .flag_orphaned_log_source_events(&deleted.label(UNRECORDED_ACTOR), UNRECORDED_ACTOR)
        .await
    {
        Ok(events) => flagged.extend(events.into_iter().map(|e| (e, deleted))),
        Err(error) => warn!(%error, "could not flag the health alerts of deleted log sources"),
    }
    for removal in [SourceRemoval::Disabled, SourceRemoval::StaleAlertingOff] {
        match system_health
            .flag_unmonitored_stale_events(removal.action(), &removal.label(UNRECORDED_ACTOR), UNRECORDED_ACTOR)
            .await
        {
            Ok(events) => flagged.extend(events.into_iter().map(|e| (e, removal))),
            Err(error) => warn!(%error, action = removal.action(),
                "could not flag the stale alerts of unmonitored log sources"),
        }
    }
    if let Err(error) = health.resolve_orphaned_data_feed_issues().await {
        warn!(%error, "could not close the notification issues of deleted log sources");
    }
    flagged
}

/// NAN-5785: the single removal an update or toggle of one source performs,
/// judged on the TRANSITION from its previous state (`before`) to the new one
/// (`after`, as `(enabled, stale_alert_enabled)`): only a `true -> false` change
/// counts, and disabling wins over stale alerting off in the same request.
pub fn removal_for_transition(before: (bool, bool), after: (bool, bool)) -> Option<SourceRemoval> {
    let (was_enabled, was_alerting) = before;
    let (enabled, alerting) = after;
    if was_enabled && !enabled {
        Some(SourceRemoval::Disabled)
    } else if was_enabled && was_alerting && !alerting {
        Some(SourceRemoval::StaleAlertingOff)
    } else {
        None
    }
}

/// The durable audit event for one flagged alert. The caller sets the actor
/// (`.actor(...)`, `.api_key(...)`, `.client_context(...)`) and builds it.
pub fn source_removed_audit(event: &SystemHealthEvent, removal: SourceRemoval, by: &str) -> AuditEventBuilder {
    let source_id = event.resource_id.as_deref().and_then(|id| Uuid::parse_str(id).ok());
    AuditEvent::builder(AuditSource::LogSource, SYSTEM_HEALTH_SOURCE_REMOVED)
        .resource("log_source", source_id, event.resource_name.clone())
        .details(serde_json::json!({
            "action": removal.action(),
            "by": by,
            "health_event_id": event.id,
            "health_event_title": event.title,
            "health_event_severity": event.severity,
            "health_event_first_seen_at": event.first_seen_at,
            "alert_left_open": true,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_true_to_false_transition_removes_and_disable_wins() {
        use SourceRemoval::*;
        assert_eq!(removal_for_transition((true, true), (false, false)), Some(Disabled));
        assert_eq!(removal_for_transition((true, true), (false, true)), Some(Disabled));
        assert_eq!(removal_for_transition((true, true), (true, false)), Some(StaleAlertingOff));
        // No-op repeats and changes on an already-unmonitored source.
        assert_eq!(removal_for_transition((false, false), (false, false)), None);
        assert_eq!(removal_for_transition((false, true), (false, false)), None);
        assert_eq!(removal_for_transition((true, false), (true, false)), None);
        assert_eq!(removal_for_transition((true, true), (true, true)), None);
        // Turning things back on is never a removal.
        assert_eq!(removal_for_transition((false, false), (true, true)), None);
    }

    #[test]
    fn removal_labels_name_the_actor() {
        assert_eq!(SourceRemoval::Deleted.label("Alice"), "source deleted by Alice");
        assert_eq!(SourceRemoval::Disabled.label("Alice"), "source disabled by Alice");
        assert_eq!(
            SourceRemoval::StaleAlertingOff.label("Alice"),
            "stale alerting turned off by Alice"
        );
        assert_eq!(SourceRemoval::StaleAlertingOff.action(), "stale_alerting_off");
    }
}
