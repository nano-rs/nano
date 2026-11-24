// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5789: the fetch log sources a render leaves out, and making that
//! visible.
//!
//! A fetch source (kafka, S3/SQS, FDR, Pub/Sub, Event Hubs) reads from its
//! source configuration's `<config>_route`. When it has no configuration, its
//! configuration was deleted, or that configuration is not deployed, the
//! renderer leaves it out of the Vector tree
//! (`VectorConfigManager::without_unroutable_parsers`) so one bad source can
//! never fail the render for every other one.
//!
//! Leaving a LIVE source out stops its ingest, which is a detection gap, so it
//! is never silent:
//! * every left-out source carries the reason on its own `validation_error`
//!   (prefix [`SOURCE_CONFIG_NOTE_PREFIX`]; a real validation error is never
//!   overwritten), cleared once it renders again;
//! * an ENABLED one also raises a High `system_health_events` condition
//!   (dedup [`health_dedup_key`]), which fans out to the notification
//!   destinations, and is resolved once it renders again.

use std::collections::HashSet;

use uuid::Uuid;

use super::repository::is_fetch_source_type;
use super::types::Parser;
use super::vector_config::VectorConfigManager;
use crate::system_health::{HealthCategory, HealthSeverity, PublishHealthEvent, SystemHealthRepository};

/// Prefix of the `validation_error` note written on a left-out source. Only
/// notes with this prefix are ever replaced or cleared here.
pub const SOURCE_CONFIG_NOTE_PREFIX: &str = "Source configuration required:";

const HEALTH_PREFIX: &str = "log_source:";
const HEALTH_SUFFIX: &str = ":not_rendered";
const HEALTH_SOURCE: &str = "vector_config_render";

/// The `system_health_events` dedup key for a live source left out.
pub fn health_dedup_key(id: Uuid) -> String {
    format!("{HEALTH_PREFIX}{id}{HEALTH_SUFFIX}")
}

/// Why a fetch source is left out of the render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnroutedReason {
    /// No `dispatch_source_config_id`.
    Unbound,
    /// `dispatch_source_config_id` names a source configuration that no longer exists.
    ConfigMissing(Uuid),
    /// The source configuration exists but its route is not deployed.
    RouteNotDeployed(String),
}

/// A fetch source the render leaves out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnroutableParser {
    pub id: Uuid,
    pub name: String,
    pub source_type: String,
    pub enabled: bool,
    pub reason: UnroutedReason,
    /// Operator-facing reason, starting with [`SOURCE_CONFIG_NOTE_PREFIX`].
    pub note: String,
}

/// What a caller's render can vouch for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportMode {
    /// The tree already holds every deployed source configuration, so a
    /// route missing on disk really is undeployed. False for the boot render
    /// (parser tree first, source configurations after) and for log-source
    /// paths on a tree that may not be the published one: those report only
    /// binding problems (unbound, configuration deleted), which do not depend
    /// on disk, and never clear a note or resolve a condition.
    pub check_routes_on_disk: bool,
    /// Raise (and, with `check_routes_on_disk`, resolve) the High health
    /// condition for an enabled source left out. Off for a log-source deploy,
    /// which renders a source it just enabled and disables it again if it does
    /// not go live; the publication reconciler that follows alerts if it stays.
    pub health: bool,
}

impl ReportMode {
    /// The source-configuration re-render (publication reconciler, every
    /// source-configuration change): complete tree, alerts.
    pub const FULL: Self = Self { check_routes_on_disk: true, health: true };
    /// Boot and parser-service renders: binding problems, alerts.
    pub const BINDINGS: Self = Self { check_routes_on_disk: false, health: true };
    /// Log-source paths: binding problems, notes only.
    pub const BINDINGS_NOTES: Self = Self { check_routes_on_disk: false, health: false };
}

/// The fetch sources in `parsers` (after dispatch routes are stamped) that
/// the renderer leaves out, given the source-configuration routes declared on
/// disk (`None`: not known, report binding problems only). Disabled ones are
/// included: a draft that cannot go live says so.
pub fn classify(parsers: &[Parser], declared_routes: Option<&HashSet<String>>) -> Vec<UnroutableParser> {
    parsers
        .iter()
        .filter(|p| p.kind != "enrichment" && is_fetch_source_type(&p.source_type))
        .filter_map(|p| {
            let reason = match (p.dispatch_source_config_id, p.dispatch_route_name.as_deref()) {
                (None, _) => UnroutedReason::Unbound,
                (Some(id), None) => UnroutedReason::ConfigMissing(id),
                (Some(_), Some(route)) if declared_routes.is_some_and(|d| !d.contains(route)) => {
                    UnroutedReason::RouteNotDeployed(route.to_string())
                }
                _ => return None,
            };
            Some(UnroutableParser {
                id: p.id,
                name: p.name.clone(),
                source_type: p.source_type.clone(),
                enabled: p.enabled,
                note: note_for(&p.source_type, &reason),
                reason,
            })
        })
        .collect()
}

/// The note for a fetch source with no source configuration (written up
/// front by writers that create such a row, e.g. repository import).
pub fn unbound_note(source_type: &str) -> String {
    note_for(source_type, &UnroutedReason::Unbound)
}

fn note_for(source_type: &str, reason: &UnroutedReason) -> String {
    let what = match reason {
        UnroutedReason::Unbound => format!("a {source_type} source reads through a source configuration and has none"),
        UnroutedReason::ConfigMissing(id) => {
            format!("the source configuration this {source_type} source reads from ({id}) no longer exists")
        }
        UnroutedReason::RouteNotDeployed(route) => format!(
            "the source configuration this {source_type} source reads from (route {route}) is not deployed"
        ),
    };
    let fix = match reason {
        UnroutedReason::RouteNotDeployed(_) => "Deploy that source configuration",
        _ => "Bind it to an existing source configuration of the same type",
    };
    format!(
        "{SOURCE_CONFIG_NOTE_PREFIX} {what}, so it is left out of the Vector config and ingests nothing. {fix}."
    )
}

/// Classify `parsers` against `manager`'s tree and make every left-out source
/// visible (see the module docs). Best-effort: the rendered config is correct
/// without it, so database errors are logged, not returned.
pub async fn report(
    pool: &sqlx::PgPool,
    manager: &VectorConfigManager,
    parsers: &[Parser],
    mode: ReportMode,
) -> Vec<UnroutableParser> {
    if mode.check_routes_on_disk {
        let declared = manager.declared_source_config_routes().await;
        return report_with_routes(pool, &declared, parsers, mode).await;
    }
    report_classified(pool, parsers, classify(parsers, None), mode).await
}

/// [`report`] against an explicit set of declared routes (a caller that
/// knows routes the tree will hold, such as a boot batch's deployed but
/// disabled configurations, which the publication reconciler renders next).
pub async fn report_with_routes(
    pool: &sqlx::PgPool,
    declared: &HashSet<String>,
    parsers: &[Parser],
    mode: ReportMode,
) -> Vec<UnroutableParser> {
    report_classified(pool, parsers, classify(parsers, Some(declared)), mode).await
}

async fn report_classified(
    pool: &sqlx::PgPool,
    parsers: &[Parser],
    unrouted: Vec<UnroutableParser>,
    mode: ReportMode,
) -> Vec<UnroutableParser> {
    for u in unrouted.iter().filter(|u| u.enabled) {
        tracing::error!(
            target: "security",
            log_source_id = %u.id,
            log_source = %u.name,
            "live log source left out of the Vector config: {}",
            u.note
        );
    }
    record_notes(pool, parsers, &unrouted, mode.check_routes_on_disk).await;
    if mode.health {
        record_health(pool, parsers, &unrouted, mode.check_routes_on_disk).await;
    }
    unrouted
}

async fn record_notes(pool: &sqlx::PgPool, parsers: &[Parser], unrouted: &[UnroutableParser], heal: bool) {
    let like = format!("{SOURCE_CONFIG_NOTE_PREFIX}%");
    for bad in unrouted {
        let current = parsers.iter().find(|p| p.id == bad.id).and_then(|p| p.validation_error.as_deref());
        if current == Some(bad.note.as_str()) {
            continue;
        }
        if let Err(e) = sqlx::query(
            "UPDATE log_sources SET validation_error = $2 \
             WHERE id = $1 AND (validation_error IS NULL OR validation_error LIKE $3)",
        )
        .bind(bad.id)
        .bind(&bad.note)
        .bind(&like)
        .execute(pool)
        .await
        {
            tracing::warn!(log_source_id = %bad.id, "could not record the source-configuration note: {e}");
        }
    }
    if !heal {
        return;
    }
    let healed: Vec<Uuid> = parsers
        .iter()
        .filter(|p| p.validation_error.as_deref().is_some_and(|e| e.starts_with(SOURCE_CONFIG_NOTE_PREFIX)))
        .filter(|p| !unrouted.iter().any(|u| u.id == p.id))
        .map(|p| p.id)
        .collect();
    if healed.is_empty() {
        return;
    }
    if let Err(e) = sqlx::query(
        "UPDATE log_sources SET validation_error = NULL WHERE id = ANY($1) AND validation_error LIKE $2",
    )
    .bind(&healed)
    .bind(&like)
    .execute(pool)
    .await
    {
        tracing::warn!("could not clear source-configuration notes: {e}");
    }
}

/// The health event for a live source left out.
pub fn health_event(u: &UnroutableParser) -> PublishHealthEvent {
    let mut event = PublishHealthEvent::new(
        health_dedup_key(u.id),
        HealthCategory::LogSource,
        HealthSeverity::High,
        format!(
            "Log source '{}' is not ingesting: left out of the Vector config",
            u.name.chars().take(200).collect::<String>()
        ),
        u.note.clone(),
        "log_source",
        HEALTH_SOURCE,
    );
    event.resource_id = Some(u.id.to_string());
    event.resource_name = Some(u.name.clone());
    let (reason, detail) = match &u.reason {
        UnroutedReason::Unbound => ("unbound", serde_json::Value::Null),
        UnroutedReason::ConfigMissing(id) => ("source_configuration_missing", serde_json::json!(id)),
        UnroutedReason::RouteNotDeployed(route) => ("source_configuration_not_deployed", serde_json::json!(route)),
    };
    // The render has no actor: the change that caused this (a source
    // configuration delete or undeploy, a rebind) is in the audit log.
    event.diagnostic_context = serde_json::json!({
        "source_type": u.source_type,
        "reason": reason,
        "detail": detail,
        "actor": null,
    });
    event.remediation = Some(
        "Bind the log source to a deployed source configuration of the same type (or deploy the \
         one it names), or disable the log source if it is retired. The condition resolves on the \
         next render once the source is live again."
            .to_string(),
    );
    event
}

async fn record_health(pool: &sqlx::PgPool, parsers: &[Parser], unrouted: &[UnroutableParser], resolve: bool) {
    let repo = SystemHealthRepository::new(pool.clone());
    let live: HashSet<Uuid> = unrouted.iter().filter(|u| u.enabled).map(|u| u.id).collect();
    for u in unrouted.iter().filter(|u| u.enabled) {
        if let Err(e) = repo.publish(&health_event(u)).await {
            tracing::warn!(log_source_id = %u.id, "could not raise the left-out log source health event: {e}");
        }
    }
    if !resolve {
        return;
    }
    // Resolve this producer's conditions that no longer hold: for a source in
    // `parsers` that now renders (or was disabled), and for a source that no
    // longer exists. A condition on any other source is left alone, so a
    // caller passing a subset never resolves what it did not look at.
    let active: Vec<String> = match sqlx::query_scalar(
        "SELECT dedup_key FROM system_health_events \
         WHERE status = 'active' AND source = $1 AND dedup_key LIKE $2",
    )
    .bind(HEALTH_SOURCE)
    .bind(format!("{HEALTH_PREFIX}%{HEALTH_SUFFIX}"))
    .fetch_all(pool)
    .await
    {
        Ok(keys) => keys,
        Err(e) => {
            tracing::warn!("could not list left-out log source health events: {e}");
            return;
        }
    };
    let keyed: Vec<(String, Uuid)> = active
        .into_iter()
        .filter_map(|k| {
            let id = k.strip_prefix(HEALTH_PREFIX)?.strip_suffix(HEALTH_SUFFIX)?.parse::<Uuid>().ok()?;
            Some((k, id))
        })
        .collect();
    let ids: Vec<Uuid> = keyed.iter().map(|(_, id)| *id).collect();
    let existing: HashSet<Uuid> = match sqlx::query_scalar::<_, Uuid>("SELECT id FROM log_sources WHERE id = ANY($1)")
        .bind(&ids)
        .fetch_all(pool)
        .await
    {
        Ok(rows) => rows.into_iter().collect(),
        Err(e) => {
            tracing::warn!("could not check log sources for left-out health events: {e}");
            return;
        }
    };
    let in_slice: HashSet<Uuid> = parsers.iter().map(|p| p.id).collect();
    for (key, id) in keyed {
        let healed = in_slice.contains(&id) && !live.contains(&id);
        if healed || !existing.contains(&id) {
            if let Err(e) = repo.resolve_by_dedup_key(&key).await {
                tracing::warn!(dedup_key = %key, "could not resolve a left-out log source health event: {e}");
            }
        }
    }
}

#[cfg(test)]
#[path = "unrouted_tests.rs"]
mod tests;
