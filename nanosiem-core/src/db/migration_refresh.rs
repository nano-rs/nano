// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable post-migration refreshable-view activation (NAN-4977).
//!
//! A numbered ClickHouse migration declares invalidations in line comments:
//!
//! ```text
//! -- nano:refresh-view nanosiem.ip_enrichment_dict_refresh reload=ip_geo_pair
//! -- nano:refresh-view nanosiem.ioc_enrichment_dict_refresh reload=nanosiem.ioc_enrichment_dict
//! ```
//!
//! The migrator records those declarations in [`MIGRATION_REFRESH_TABLE`] only
//! after the migration SQL succeeds. The jobs leader consumes the durable rows,
//! waits for every replica's refresh, then reloads the dictionary (or the IP geo
//! pair) and records success/failure. Failures persist bounded backoff state
//! across leader failover and process restart; exhausted work requires the
//! migrator's explicit manual retry.

use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::dual_pool::on_cluster_clause;

pub const MIGRATION_REFRESH_TABLE: &str = "_migration_refreshes";
pub const IP_GEO_PAIR_RELOAD: &str = "ip_geo_pair";

const DIRECTIVE: &str = "-- nano:refresh-view ";
const RELOAD_ATTEMPTS: u32 = 3;
const MAX_ACTIVATION_ATTEMPTS: u8 = 10;
const MIN_RETRY_SECONDS: u64 = 60;
const MAX_RETRY_SECONDS: u64 = 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationPhase {
    Refresh,
    Reload,
}

impl ActivationPhase {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "refresh" => Ok(Self::Refresh),
            "reload" => Ok(Self::Reload),
            other => bail!("invalid migration refresh phase {other:?}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Refresh => "refresh",
            Self::Reload => "reload",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRefreshDirective {
    pub view: String,
    pub reload_target: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationRefreshSummary {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub exhausted: usize,
}

/// Parse and validate refresh declarations before any migration SQL runs.
pub fn parse_directives(sql: &str) -> Result<Vec<MigrationRefreshDirective>, String> {
    let mut directives = Vec::new();
    for (index, line) in sql.lines().enumerate() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix(DIRECTIVE) else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let view = fields.next().unwrap_or_default();
        let reload = fields
            .next()
            .and_then(|field| field.strip_prefix("reload="))
            .unwrap_or_default();
        if view.is_empty() || reload.is_empty() || fields.next().is_some() {
            return Err(format!(
                "line {}: expected `{DIRECTIVE}<db.view> reload=<db.dictionary|{IP_GEO_PAIR_RELOAD}>`",
                index + 1
            ));
        }
        if !qualified_identifier(view) {
            return Err(format!(
                "line {}: invalid qualified view name {view:?}",
                index + 1
            ));
        }
        if reload != IP_GEO_PAIR_RELOAD && !qualified_identifier(reload) {
            return Err(format!(
                "line {}: invalid reload target {reload:?}",
                index + 1
            ));
        }
        directives.push(MigrationRefreshDirective {
            view: view.to_string(),
            reload_target: reload.to_string(),
        });
    }
    directives.sort_by(|a, b| (&a.view, &a.reload_target).cmp(&(&b.view, &b.reload_target)));
    directives.dedup();
    Ok(directives)
}

fn qualified_identifier(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(database) = parts.next() else {
        return false;
    };
    let Some(object) = parts.next() else {
        return false;
    };
    parts.next().is_none() && identifier(database) && identifier(object)
}

fn identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Process every due pending/failed invalidation once. The caller is the
/// elected jobs leader; failures back off durably and stop automatically after
/// [`MAX_ACTIVATION_ATTEMPTS`].
pub async fn process_pending(
    ch_admin: &clickhouse::Client,
    ch_runtime: &clickhouse::Client,
    database: &str,
) -> Result<MigrationRefreshSummary> {
    let table = format!("{database}.{MIGRATION_REFRESH_TABLE}");
    let sql = pending_sql(&table);
    let pending: Vec<(String, String, String, String, u64, String, u8)> = ch_admin
        .query(&sql)
        .fetch_all()
        .await
        .with_context(|| format!("reading {table}"))?;
    let on_cluster = on_cluster_clause();
    let mut summary = MigrationRefreshSummary::default();

    for (version, view, reload_target, _state, revision, phase, attempts) in pending {
        summary.attempted += 1;
        let phase = ActivationPhase::parse(&phase)
            .with_context(|| format!("reading activation phase for {version}/{view}"))?;
        let result: std::result::Result<(), (ActivationPhase, anyhow::Error)> = match phase {
            ActivationPhase::Reload => activate_reload(ch_runtime, &reload_target, &on_cluster)
                .await
                .map_err(|error| (ActivationPhase::Reload, error)),
            ActivationPhase::Refresh => {
                match activate_refresh(ch_admin, &view, &reload_target, &on_cluster).await {
                    Err(error) => Err((ActivationPhase::Refresh, error)),
                    Ok(()) => activate_reload(ch_runtime, &reload_target, &on_cluster)
                        .await
                        .map_err(|error| (ActivationPhase::Reload, error)),
                }
            }
        };
        match result {
            Ok(()) => {
                record_state(
                    ch_admin,
                    &table,
                    &version,
                    &view,
                    &reload_target,
                    "succeeded",
                    ActivationPhase::Reload,
                    attempts,
                    0,
                    "",
                    revision + 1,
                )
                .await?;
                summary.succeeded += 1;
                tracing::info!(migration = %version, %view, %reload_target, "Post-migration refresh activated");
            }
            Err((failed_phase, error)) => {
                let detail = format!("{error:#}");
                let next_attempt = attempts.saturating_add(1);
                let exhausted = next_attempt >= MAX_ACTIVATION_ATTEMPTS;
                let state = if exhausted { "exhausted" } else { "failed" };
                record_state(
                    ch_admin,
                    &table,
                    &version,
                    &view,
                    &reload_target,
                    state,
                    failed_phase,
                    next_attempt,
                    retry_delay_seconds(next_attempt),
                    &detail,
                    revision + 1,
                )
                .await?;
                summary.failed += 1;
                if exhausted {
                    summary.exhausted += 1;
                    tracing::error!(migration = %version, %view, %reload_target, attempts = next_attempt, error = %detail, "Post-migration refresh activation exhausted automatic retries; manual retry required");
                } else {
                    tracing::error!(migration = %version, %view, %reload_target, phase = failed_phase.as_str(), attempts = next_attempt, error = %detail, "Post-migration refresh activation failed; retry scheduled");
                }
            }
        }
    }
    Ok(summary)
}

fn pending_sql(table: &str) -> String {
    format!(
        "SELECT version, view, reload_target, state, revision, phase, attempts \
         FROM {table} FINAL \
         WHERE state IN ('pending', 'failed') \
           AND attempts < {MAX_ACTIVATION_ATTEMPTS} \
           AND next_attempt_at <= now64(6) \
         ORDER BY version, view"
    )
}

fn retry_delay_seconds(attempts: u8) -> u64 {
    let shift = u32::from(attempts.saturating_sub(1)).min(63);
    MIN_RETRY_SECONDS
        .saturating_mul(1_u64 << shift)
        .min(MAX_RETRY_SECONDS)
}

async fn activate_refresh(
    ch_admin: &clickhouse::Client,
    view: &str,
    reload_target: &str,
    on_cluster: &str,
) -> Result<()> {
    crate::enrichment::ip_geo::refresh_view_and_wait(ch_admin, view, on_cluster).await?;
    if reload_target == IP_GEO_PAIR_RELOAD {
        crate::enrichment::ip_geo::refresh_view_and_wait(
            ch_admin,
            crate::enrichment::ip_geo::IP_GEO_HISTORY_REFRESH,
            on_cluster,
        )
        .await?;
    }
    Ok(())
}

async fn activate_reload(
    ch_runtime: &clickhouse::Client,
    reload_target: &str,
    on_cluster: &str,
) -> Result<()> {
    if reload_target == IP_GEO_PAIR_RELOAD {
        crate::enrichment::ip_geo::reload_pair_dictionaries(ch_runtime, on_cluster).await
    } else {
        reload_dictionary(ch_runtime, reload_target, on_cluster).await
    }
}

async fn reload_dictionary(
    ch: &clickhouse::Client,
    dictionary: &str,
    on_cluster: &str,
) -> Result<()> {
    if !qualified_identifier(dictionary) {
        bail!("invalid dictionary identifier {dictionary:?}");
    }
    let sql = format!("SYSTEM RELOAD DICTIONARY{on_cluster} {dictionary}");
    let mut last_error = None;
    for attempt in 1..=RELOAD_ATTEMPTS {
        match ch.query(&sql).execute().await {
            Ok(()) => return Ok(()),
            Err(error) => {
                tracing::warn!(attempt, %dictionary, %error, "Post-migration dictionary reload failed");
                last_error = Some(error);
                if attempt < RELOAD_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(u64::from(attempt) * 2)).await;
                }
            }
        }
    }
    Err(last_error.expect("at least one reload attempt")).with_context(|| sql)
}

async fn record_state(
    ch: &clickhouse::Client,
    table: &str,
    version: &str,
    view: &str,
    reload_target: &str,
    state: &str,
    phase: ActivationPhase,
    attempts: u8,
    retry_seconds: u64,
    error: &str,
    revision: u64,
) -> Result<()> {
    let escape = crate::sql_hygiene::escape_sql_string;
    // Keep the durable diagnostic bounded; SIEM Health exposes the first 300.
    let error: String = error.chars().take(2_000).collect();
    let sql = format!(
        "INSERT INTO {table} \
            (version, view, reload_target, state, revision, phase, attempts, next_attempt_at, last_error) \
         VALUES ('{}', '{}', '{}', '{}', {}, '{}', {}, now64(6) + INTERVAL {} SECOND, '{}')",
        escape(version),
        escape(view),
        escape(reload_target),
        escape(state),
        revision,
        phase.as_str(),
        attempts,
        retry_seconds,
        escape(&error),
    );
    ch.query(&sql)
        .execute()
        .await
        .with_context(|| format!("recording {state} for {view}"))?;
    Ok(())
}

/// Re-arm every activation that exhausted automatic retries. This is only
/// called by the explicit migrator subcommand; SIEM Health continues to report
/// exhausted rows until an operator invokes it.
pub async fn retry_exhausted(ch: &clickhouse::Client, database: &str) -> Result<u64> {
    let table = format!("{database}.{MIGRATION_REFRESH_TABLE}");
    let count: u64 = ch
        .query(&format!(
            "SELECT count() FROM {table} FINAL WHERE state = 'exhausted'"
        ))
        .fetch_one()
        .await
        .with_context(|| format!("counting exhausted work in {table}"))?;
    if count == 0 {
        return Ok(0);
    }
    ch.query(&format!(
        "INSERT INTO {table} \
            (version, view, reload_target, state, revision, phase, attempts, next_attempt_at, last_error) \
         SELECT version, view, reload_target, 'pending', revision + 1, phase, 0, now64(6), '' \
         FROM {table} FINAL WHERE state = 'exhausted'"
    ))
    .execute()
    .await
    .with_context(|| format!("re-arming exhausted work in {table}"))?;
    Ok(count)
}

#[cfg(test)]
#[path = "migration_refresh_tests.rs"]
mod tests;
