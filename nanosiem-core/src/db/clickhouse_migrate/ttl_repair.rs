// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5448: one-time repair of the delete TTL the old cold-storage code cut.
//!
//! Before 2.0.27, `COLD_STORAGE_ENABLED=true` (Helm
//! `clickhouse.coldStorage.enabled`) made the jobs service run
//! `ALTER TABLE <t> MODIFY TTL timestamp + toIntervalDay(WARM_RETENTION_DAYS)`
//! on `logs`, `signals` and `ingestion_errors` at every start (default 30
//! days). This step restores those TTLs once, on the first migrator run of a
//! release that has the fix, and records that it ran (`_migrations` marker
//! row), so a TTL an operator sets afterwards is never touched again.
//!
//! Repairs only on the bug's FINGERPRINT. The old code wrote the same
//! `timestamp + toIntervalDay(N)` to all three tables, and nothing else ever
//! sets the `signals` TTL. So:
//! * `signals` and `ingestion_errors` both carry exactly that rewrite with
//!   the same N, and that pair is not simply both tables at their schema
//!   defaults (`signals` 365, `ingestion_errors` 90);
//! * then each of the three tables whose TTL is STILL exactly N is restored.
//!   A table whose TTL differs from N (an operator changed it since, e.g.
//!   `logs` set to 30 days in Settings) is never touched.
//!
//! N is whatever the old `WARM_RETENTION_DAYS` was (30 and 180 were the
//! defaults; Helm `warmDays` could be 60, 90, 120, ...): the fingerprint does
//! not depend on it.
//!
//! Target: `ingestion_errors` gets its schema default (90 days). `logs` and
//! `signals` get the event retention, in this order: the value saved in
//! Settings (NAN-5449; see [`TtlRepairInput::saved_retention`]),
//! `NANO_RETENTION_DAYS`, the active event table's TTL when that table was not
//! cut itself (`ocsf_logs` on OCSF installs, which the old code skipped), else
//! 365.
//!
//! The ALTER must not rewrite whole parts on a disk that may be nearly full.
//! `materialize_ttl_after_modify = 0` is not an option: the parts keep their
//! old TTL info and still expire at N days (verified on 26.10), so the repair
//! would save nothing. Instead the table gets the MergeTree setting
//! `materialize_ttl_recalculate_only = 1` first: the MATERIALIZE TTL that
//! `MODIFY TTL` runs then only recalculates each part's TTL info (`ttl.txt`
//! and checksums; the column files are hard-linked, not rewritten). Lengthening
//! a TTL deletes nothing, so nothing else happens. The setting stays on the
//! table: it makes later Settings retention changes cheap the same way (rows
//! a shorter TTL expires are then removed by the regular TTL merges instead
//! of an immediate rewrite). Data the old TTL already deleted cannot be
//! recovered.

use super::ClickHouseMigrator;
use crate::settings::clickhouse_ttl::{delete_ttl_days, is_safe_identifier};

/// `_migrations` marker row: the repair ran (or found nothing to repair).
/// Not a numbered migration; schema readers skip non-numbered versions.
pub const TTL_REPAIR_MARKER: &str = "__nan5448_ttl_repair";

/// The tables the old warm-TTL code rewrote.
pub const LEGACY_WARM_TTL_TABLES: &[&str] = &["logs", "signals", "ingestion_errors"];

/// `ingestion_errors`' schema TTL (init.sql).
pub const INGESTION_ERRORS_DEFAULT_DAYS: u32 = 90;

/// `signals`' schema TTL (init.sql).
pub const SIGNALS_DEFAULT_DAYS: u32 = 365;

/// Event retention when nothing else is configured (init.sql).
pub const DEFAULT_EVENT_RETENTION_DAYS: u32 = 365;

/// Health finding raised once when a TTL was restored.
pub const TTL_RESTORED_HEALTH_KEY: &str = "storage:clickhouse:retention_restored";

/// Audit action recorded once per repair.
pub const TTL_RESTORED_AUDIT_ACTION: &str = crate::audit::CH_RETENTION_RESTORED;

/// One TTL the repair restores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlRepair {
    /// Physical table (`<name>_local` on a sharded cluster).
    pub table: String,
    pub from_days: u32,
    pub to_days: u32,
}

/// What the planner needs, gathered by the migrator.
#[derive(Debug, Clone)]
pub struct TtlRepairInput<'a> {
    /// `(physical table, create_table_query)`.
    pub tables: &'a [(String, String)],
    /// The event retention an operator saved in Settings, when one is
    /// recorded (NAN-5449: PostgreSQL `system_settings.clickhouse_retention_*`,
    /// migration 388; see [`saved_settings_retention`]).
    pub saved_retention: Option<u32>,
    /// `NANO_RETENTION_DAYS`, when set and valid.
    pub retention_env: Option<u32>,
    /// The active event table (`ocsf_logs` or `logs`).
    pub active_table: &'a str,
}

/// Table name without the sharded `_local` suffix.
fn base_name(table: &str) -> &str {
    table.strip_suffix("_local").unwrap_or(table)
}

/// The table TTL clause of a `create_table_query`, trimmed (between the last
/// top-level ` TTL ` and ` SETTINGS `). Column TTLs come earlier.
fn table_ttl_clause(create_table_query: &str) -> Option<&str> {
    let at = create_table_query.rfind(" TTL ")? + " TTL ".len();
    let rest = &create_table_query[at..];
    let end = rest.find(" SETTINGS ").unwrap_or(rest.len());
    Some(rest[..end].trim())
}

/// Days of the TTL when it is EXACTLY the old warm rewrite,
/// `timestamp + toIntervalDay(N)`, with nothing else in the clause.
pub fn warm_rewrite_days(create_table_query: &str) -> Option<u32> {
    let clause = table_ttl_clause(create_table_query)?;
    let n = clause
        .strip_prefix("timestamp + toIntervalDay(")?
        .strip_suffix(')')?;
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

/// `NANO_RETENTION_DAYS` (NAN-5449) when set to a whole number in 1..=3650.
/// An invalid value is ignored here (the NAN-5449 step reports it).
pub fn retention_env_days(raw: Option<&str>) -> Option<u32> {
    raw.map(str::trim)
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|d| (1..=3650).contains(d))
}

/// The TTLs to restore. Pure: every decision is unit-tested.
pub fn plan_ttl_repairs(input: &TtlRepairInput<'_>) -> Vec<TtlRepair> {
    let rewrite_of = |base: &str| {
        input
            .tables
            .iter()
            .find(|(name, _)| base_name(name) == base)
            .and_then(|(_, q)| warm_rewrite_days(q))
    };
    // The fingerprint: signals and ingestion_errors cut to the same N.
    let (Some(signals), Some(errors)) = (rewrite_of("signals"), rewrite_of("ingestion_errors")) else {
        return Vec::new();
    };
    if signals != errors || (signals == SIGNALS_DEFAULT_DAYS && errors == INGESTION_ERRORS_DEFAULT_DAYS) {
        return Vec::new();
    }
    let n = signals;

    // Tables still exactly at N.
    let hits: Vec<&str> = input
        .tables
        .iter()
        .filter(|(name, _)| LEGACY_WARM_TTL_TABLES.contains(&base_name(name)))
        .filter(|(_, q)| warm_rewrite_days(q) == Some(n))
        .map(|(name, _)| name.as_str())
        .collect();
    let active_hit = hits.iter().any(|name| base_name(name) == input.active_table);

    // The event retention to restore.
    let target = input.saved_retention.or(input.retention_env).unwrap_or_else(|| {
        if active_hit {
            return DEFAULT_EVENT_RETENTION_DAYS;
        }
        input
            .tables
            .iter()
            .find(|(name, _)| base_name(name) == input.active_table)
            .and_then(|(_, q)| delete_ttl_days(q))
            .unwrap_or(DEFAULT_EVENT_RETENTION_DAYS)
    });

    hits.into_iter()
        .filter_map(|name| {
            let to = if base_name(name) == "ingestion_errors" {
                INGESTION_ERRORS_DEFAULT_DAYS
            } else {
                target
            };
            (to != n).then(|| TtlRepair { table: name.to_string(), from_days: n, to_days: to })
        })
        .collect()
}

/// `ALTER TABLE <db>.<t><on_cluster> MODIFY SETTING
/// materialize_ttl_recalculate_only = 1`, run before [`restore_ttl_sql`] so
/// the TTL materialization only recalculates TTL info (module docs).
pub fn recalculate_only_sql(db: &str, table: &str, on_cluster: &str) -> Option<String> {
    if !is_safe_identifier(db) || !is_safe_identifier(table) {
        return None;
    }
    Some(format!(
        "ALTER TABLE {db}.{table}{on_cluster} MODIFY SETTING materialize_ttl_recalculate_only = 1"
    ))
}

/// `ALTER TABLE <db>.<t><on_cluster> MODIFY TTL timestamp + toIntervalDay(N)`.
pub fn restore_ttl_sql(db: &str, table: &str, on_cluster: &str, days: u32) -> Option<String> {
    if !is_safe_identifier(db) || !is_safe_identifier(table) {
        return None;
    }
    Some(format!(
        "ALTER TABLE {db}.{table}{on_cluster} MODIFY TTL timestamp + toIntervalDay({days})"
    ))
}

/// What one pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TtlRepairOutcome {
    /// The marker was already present: the repair ran on an earlier upgrade.
    pub already_done: bool,
    pub restored: Vec<TtlRepair>,
    pub failed: Vec<(String, String)>,
    /// Set when the pass could not evaluate (it retries on the next run).
    pub skipped: Option<String>,
}

/// NAN-5449: the retention saved in Settings -> Storage, when the recorded
/// value came from Settings (`source = 'ui'`). A deployment-applied value is
/// `NANO_RETENTION_DAYS`, which the repair reads itself (and which the
/// migrator applies after the repair anyway).
pub fn saved_settings_retention(record: &crate::settings::ClickHouseRetentionRecord) -> Option<u32> {
    match record.source.as_deref() {
        Some("ui") => record.days.filter(|d| (1..=3650).contains(d)),
        _ => None,
    }
}

impl ClickHouseMigrator {
    /// ` ON CLUSTER '<c>'` for an explicit (self-managed) cluster, empty on a
    /// single node or ClickHouse Cloud. `Err` with the reason when the cluster
    /// cannot be detected or a replica is down (NAN-5215: ON CLUSTER DDL waits
    /// for every replica, so the caller skips and the next run retries).
    pub(super) async fn explicit_on_cluster(&mut self) -> Result<String, String> {
        Ok(self
            .reachable_explicit_cluster()
            .await?
            .map(|cl| format!(" ON CLUSTER '{cl}'"))
            .unwrap_or_default())
    }

    /// The explicit (self-managed) cluster name, `None` on a single node or
    /// ClickHouse Cloud; `Err` as [`Self::explicit_on_cluster`].
    pub(super) async fn reachable_explicit_cluster(&mut self) -> Result<Option<String>, String> {
        let cluster = self
            .detect_cluster()
            .await
            .map_err(|e| format!("cannot detect the cluster: {e}"))?;
        let explicit = match &cluster {
            Some(c) if c != &self.database && !self.is_cloud.unwrap_or(false) => Some(c.clone()),
            _ => None,
        };
        let Some(cl) = explicit else { return Ok(None) };
        let client = self.client.clone().with_database("default");
        match Self::probe_reachability(&client, &cl).await {
            Ok(r) if r.all_reachable() => Ok(Some(cl)),
            Ok(r) => Err(format!("cluster '{cl}': {}", r.describe())),
            Err(e) => Err(format!("cluster '{cl}' reachability probe failed: {e}")),
        }
    }

    /// NAN-5448: restore the delete TTLs the old cold-storage code cut. Runs
    /// its evaluation once per install (marker row); never fatal.
    ///
    /// `saved_retention`: the event retention an operator saved in Settings
    /// (NAN-5449, [`saved_settings_retention`]), the preferred restore target.
    pub async fn repair_legacy_warm_ttl(&mut self, saved_retention: Option<u32>) -> TtlRepairOutcome {
        let mut out = TtlRepairOutcome::default();
        if !is_safe_identifier(&self.database) {
            out.skipped = Some("unsafe database name".to_string());
            return out;
        }
        let db = self.database.clone();
        match self
            .client
            .query(&format!("SELECT count() FROM {db}._migrations WHERE version = ?"))
            .bind(TTL_REPAIR_MARKER)
            .fetch_one::<u64>()
            .await
        {
            Ok(0) => {}
            Ok(_) => {
                out.already_done = true;
                return out;
            }
            Err(e) => {
                out.skipped = Some(format!("cannot read _migrations: {e}"));
                return out;
            }
        }

        let active = crate::schema::active_logs_table();
        let mut names: Vec<String> = Vec::new();
        for t in LEGACY_WARM_TTL_TABLES.iter().copied().chain(std::iter::once(active)) {
            names.push(format!("'{t}'"));
            names.push(format!("'{t}_local'"));
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            name: String,
            create_table_query: String,
        }
        let rows = match self
            .client
            .query(&format!(
                "SELECT name, create_table_query FROM system.tables WHERE database = '{db}' \
                 AND name IN ({}) AND engine LIKE '%MergeTree%'",
                names.join(", ")
            ))
            .fetch_all::<Row>()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                out.skipped = Some(format!("cannot read system.tables: {e}"));
                return out;
            }
        };
        let tables: Vec<(String, String)> =
            rows.into_iter().map(|r| (r.name, r.create_table_query)).collect();
        let retention_env = retention_env_days(std::env::var("NANO_RETENTION_DAYS").ok().as_deref());
        let plan = plan_ttl_repairs(&TtlRepairInput {
            tables: &tables,
            saved_retention,
            retention_env,
            active_table: active,
        });

        if !plan.is_empty() {
            let on_cluster = match self.explicit_on_cluster().await {
                Ok(c) => c,
                Err(reason) => {
                    out.skipped = Some(reason);
                    return out;
                }
            };
            for repair in plan {
                let (Some(setting), Some(sql)) = (
                    recalculate_only_sql(&db, &repair.table, &on_cluster),
                    restore_ttl_sql(&db, &repair.table, &on_cluster, repair.to_days),
                ) else {
                    out.failed.push((repair.table, "unsafe identifier".to_string()));
                    continue;
                };
                if let Err(e) = self.client.query(&setting).execute().await {
                    // Without it the MATERIALIZE TTL would rewrite whole parts:
                    // do not risk that on a full disk; retry next run.
                    tracing::warn!(table = %repair.table, error = %e, "NAN-5448: setting materialize_ttl_recalculate_only failed; TTL not restored this run");
                    out.failed.push((repair.table, e.to_string()));
                    continue;
                }
                match self.client.query(&sql).execute().await {
                    Ok(()) => {
                        tracing::warn!(
                            table = %repair.table,
                            from_days = repair.from_days,
                            to_days = repair.to_days,
                            "NAN-5448: restored the delete TTL the old cold-storage code had cut; \
                             data already deleted cannot be recovered"
                        );
                        out.restored.push(repair);
                    }
                    Err(e) => {
                        tracing::warn!(table = %repair.table, error = %e, "NAN-5448: restoring the delete TTL failed; the next migrator run retries");
                        out.failed.push((repair.table, e.to_string()));
                    }
                }
            }
        }

        // Record the evaluation only when nothing failed, so a failed ALTER is
        // retried and a later operator change is never second-guessed.
        if out.failed.is_empty() {
            let summary: Vec<String> = out
                .restored
                .iter()
                .map(|r| format!("{} {}d->{}d", r.table, r.from_days, r.to_days))
                .collect();
            let name = if summary.is_empty() {
                "nan5448 ttl repair: nothing to restore".to_string()
            } else {
                format!("nan5448 ttl repair: {}", summary.join(", "))
            };
            if let Err(e) = self
                .client
                .query(&format!("INSERT INTO {db}._migrations (version, name) VALUES (?, ?)"))
                .bind(TTL_REPAIR_MARKER)
                .bind(name.as_str())
                .execute()
                .await
            {
                tracing::warn!(error = %e, "NAN-5448: recording the TTL repair marker failed; the next run re-evaluates (idempotent)");
            }
        }
        out
    }
}

/// Audit event and one-time SIEM Health notice for restored TTLs. Uses the
/// PostgreSQL audit outbox (the running services' drainer delivers it to
/// ClickHouse), so the migrator needs no ClickHouse audit writer.
pub async fn report_ttl_repairs(pg: &sqlx::PgPool, restored: &[TtlRepair]) {
    use crate::audit::{AuditEvent, AuditSource, SecurityAuditOutbox};
    use crate::system_health::{
        HealthCategory, HealthSeverity, PublishHealthEvent, SystemHealthRepository,
    };
    if restored.is_empty() {
        return;
    }
    let tables: Vec<serde_json::Value> = restored
        .iter()
        .map(|r| serde_json::json!({"table": r.table, "from_days": r.from_days, "to_days": r.to_days}))
        .collect();
    let event = AuditEvent::builder(AuditSource::Storage, TTL_RESTORED_AUDIT_ACTION)
        .resource("clickhouse_retention", None, Some("event tables".to_string()))
        .success(true)
        .details(serde_json::json!({
            "reason": "NAN-5448: restored the delete TTL the pre-2.0.27 cold-storage code rewrote",
            "tables": tables,
        }))
        .build();
    if let Err(e) = SecurityAuditOutbox::new(pg.clone()).enqueue(&event, true).await {
        tracing::warn!(error = %e, "NAN-5448: recording the TTL repair audit event failed");
    }

    let list = restored
        .iter()
        .map(|r| format!("{} ({} -> {} days)", r.table, r.from_days, r.to_days))
        .collect::<Vec<_>>()
        .join(", ");
    let days = restored.iter().map(|r| r.to_days).max().unwrap_or(DEFAULT_EVENT_RETENTION_DAYS);
    let mut health = PublishHealthEvent::new(
        TTL_RESTORED_HEALTH_KEY,
        HealthCategory::Storage,
        HealthSeverity::Medium,
        &format!("Retention restored to {days} days"),
        format!(
            "An earlier release cut the delete TTL of these tables when cold storage was enabled: {list}. \
             The upgrade restored it. Data already removed cannot be recovered."
        ),
        "clickhouse_retention",
        "nan5448_ttl_repair",
    );
    health.resource_id = Some("clickhouse_event_retention".to_string());
    health.resource_name = Some("ClickHouse event retention".to_string());
    health.diagnostic_context = serde_json::json!({ "tables": tables });
    health.remediation = Some(
        "Nothing to do for retention. Check whether the lost window matters (searches and detections \
         over data older than the cut TTL find nothing), then resolve this notice."
            .to_string(),
    );
    if let Err(e) = SystemHealthRepository::new(pg.clone()).publish(&health).await {
        tracing::warn!(error = %e, "NAN-5448: publishing the TTL repair health notice failed");
    }
}

#[cfg(test)]
#[path = "ttl_repair_tests.rs"]
mod tests;
