// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5907 (CH gap G1): the event tables carry the MergeTree setting
//! `materialize_ttl_recalculate_only = 1`.
//!
//! A Settings retention change runs `ALTER TABLE ... MODIFY TTL`, which the
//! server follows with a MATERIALIZE TTL mutation; "Run retention now" runs
//! `MATERIALIZE TTL` directly. With the MergeTree default (0) that mutation
//! rewrites EVERY part of the table, even when the new TTL expires nothing.
//! Measured on clickhouse-server 26.10.4.207 with nano's `ocsf_logs` DDL, 4M
//! rows in 32 parts (1.67 GiB): 0 -> 32/32 parts rewritten, 1.67 GiB written,
//! 3.51 GiB read, ~152 s of merge-pool time; 1 -> TTL info only, 4.5 MiB
//! written, ~1.7 s. Fully expired parts are then dropped whole by the TTL
//! merge (`ttl_only_drop_parts = 1`); a partly expired part goes when all of
//! it has expired.
//!
//! Fresh installs get the setting from the init DDL (`clickhouse/init.sql`,
//! `clickhouse/ocsf/init.sql`). Existing installs get it here, a migrator
//! step that runs on every migrator run and is a no-op once set. It is not a
//! numbered SQL migration because the physical table is not always the bare
//! name: clusters built by `deploy/scripts/init-clickhouse-cluster.sh` keep
//! the MergeTree as `<t>_local` with a `Distributed` table under the bare
//! name, and `MODIFY SETTING` on a Distributed table fails. So the step
//! resolves the MergeTree-family table (`<t>` or `<t>_local`) from
//! `system.tables`, like the NAN-5448 TTL repair, and never touches a
//! Distributed wrapper (`<t>_distributed` or a bare-name one).
//!
//! On an explicit cluster the check reads `clusterAllReplicas(<cluster>,
//! system.tables)`, so a table that an earlier partly failed `ON CLUSTER`
//! ALTER left unset on some shard or replica is still found and retried,
//! whichever node the migrator connects to.
//!
//! A settings-only ALTER: no mutation, no data touched. Never fatal: a failed
//! ALTER is logged, retried on the next run, and surfaced as a SIEM Health
//! notice ([`report_ttl_recalc`]); the retention code refuses to change the
//! TTL of a table it cannot set this on (`settings/retention.rs`), so a
//! failure here never turns into a full rewrite.

use super::ttl_repair::recalculate_only_sql;
use super::ClickHouseMigrator;
use crate::settings::clickhouse_ttl::is_safe_identifier;

/// The tables a retention change or the TTL repair re-TTLs, plus the OTel
/// tables (same time-based delete TTL shape).
pub const TTL_RECALC_TABLES: &[&str] =
    &["ocsf_logs", "logs", "signals", "ingestion_errors", "otel_spans", "otel_metrics"];

/// The setting as ClickHouse prints it in `create_table_query`.
const SETTING: &str = "materialize_ttl_recalculate_only = 1";

/// SIEM Health dedup key of the "tables still rewrite on retention change" notice.
pub const TTL_RECALC_HEALTH_KEY: &str = "storage:clickhouse:ttl_recalculate_only_unset";

/// What one pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TtlRecalcOutcome {
    /// Physical tables the setting was applied to this run.
    pub applied: Vec<String>,
    /// Physical tables that already had it on every node.
    pub already_set: usize,
    pub failed: Vec<(String, String)>,
    /// Set when the pass could not evaluate (it retries on the next run).
    pub skipped: Option<String>,
}

/// The `system.tables` names to look at: each table and its `_local` twin.
pub fn ttl_recalc_candidate_names() -> Vec<String> {
    TTL_RECALC_TABLES
        .iter()
        .flat_map(|t| [t.to_string(), format!("{t}_local")])
        .collect()
}

/// From `(name, engine, nodes_missing_the_setting)` rows (one per table name,
/// aggregated over every node that was read), the physical tables that still
/// need the setting. Only MergeTree-family engines qualify (a Distributed
/// table under the bare name is skipped), and only the known tables or their
/// `_local` twins.
pub fn plan_ttl_recalculate_only(rows: &[(String, String, u64)]) -> Vec<String> {
    let mut out: Vec<String> = rows
        .iter()
        .filter(|(name, engine, _)| is_target(name, engine))
        .filter(|(_, _, missing)| *missing > 0)
        .map(|(name, _, _)| name.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

fn is_target(name: &str, engine: &str) -> bool {
    let base = name.strip_suffix("_local").unwrap_or(name);
    engine.contains("MergeTree") && TTL_RECALC_TABLES.contains(&base)
}

/// The inspection query: local `system.tables`, or every replica of an
/// explicit cluster. `None` for an unsafe database or cluster name.
pub fn ttl_recalc_inspect_sql(db: &str, cluster: Option<&str>) -> Option<String> {
    if !is_safe_identifier(db) {
        return None;
    }
    let source = match cluster {
        None => "system.tables".to_string(),
        Some(cl) if !cl.is_empty() && cl.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c)) => {
            format!("clusterAllReplicas('{cl}', system.tables)")
        }
        Some(_) => return None,
    };
    let names = ttl_recalc_candidate_names()
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "SELECT name, any(engine) AS engine, \
         countIf(position(create_table_query, '{SETTING}') = 0) AS missing \
         FROM {source} WHERE database = '{db}' AND name IN ({names}) GROUP BY name"
    ))
}

impl ClickHouseMigrator {
    /// NAN-5907: set `materialize_ttl_recalculate_only = 1` on the physical
    /// event tables that lack it on any node. Idempotent; never fatal.
    pub async fn ensure_ttl_recalculate_only(&mut self) -> TtlRecalcOutcome {
        let mut out = TtlRecalcOutcome::default();
        let db = self.database.clone();
        let cluster = match self.reachable_explicit_cluster().await {
            Ok(c) => c,
            Err(reason) => {
                out.skipped = Some(reason);
                return out;
            }
        };
        let Some(sql) = ttl_recalc_inspect_sql(&db, cluster.as_deref()) else {
            out.skipped = Some("unsafe database or cluster name".to_string());
            return out;
        };
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            name: String,
            engine: String,
            missing: u64,
        }
        let rows = match self.client.query(&sql).fetch_all::<Row>().await {
            Ok(r) => r,
            Err(e) => {
                out.skipped = Some(format!("cannot read system.tables: {e}"));
                return out;
            }
        };
        let rows: Vec<(String, String, u64)> =
            rows.into_iter().map(|r| (r.name, r.engine, r.missing)).collect();
        let todo = plan_ttl_recalculate_only(&rows);
        out.already_set = rows
            .iter()
            .filter(|(n, e, missing)| is_target(n, e) && *missing == 0)
            .count();
        let on_cluster = cluster.map(|cl| format!(" ON CLUSTER '{cl}'")).unwrap_or_default();
        for table in todo {
            let Some(sql) = recalculate_only_sql(&db, &table, &on_cluster) else {
                out.failed.push((table, "unsafe identifier".to_string()));
                continue;
            };
            match self.client.query(&sql).execute().await {
                Ok(()) => out.applied.push(table),
                Err(e) => {
                    tracing::warn!(table = %table, error = %e, "NAN-5907: setting materialize_ttl_recalculate_only failed; retried next run");
                    out.failed.push((table, e.to_string()));
                }
            }
        }
        out
    }
}

/// SIEM Health: publish a notice while the step skipped or failed, resolve it
/// once a run completes cleanly. Best effort (logged on failure).
pub async fn report_ttl_recalc(pg: &sqlx::PgPool, outcome: &TtlRecalcOutcome) {
    use crate::system_health::{
        HealthCategory, HealthSeverity, PublishHealthEvent, SystemHealthRepository,
    };
    let repo = SystemHealthRepository::new(pg.clone());
    if outcome.skipped.is_none() && outcome.failed.is_empty() {
        if let Err(e) = repo.resolve_by_dedup_key(TTL_RECALC_HEALTH_KEY).await {
            tracing::warn!(error = %e, "NAN-5907: resolving the TTL setting health notice failed");
        }
        return;
    }
    let what = match &outcome.skipped {
        Some(reason) => format!("The upgrade could not check the event tables ({reason})."),
        None => format!(
            "The upgrade could not update these tables: {}.",
            outcome.failed.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>().join(", ")
        ),
    };
    let mut health = PublishHealthEvent::new(
        TTL_RECALC_HEALTH_KEY,
        HealthCategory::Storage,
        HealthSeverity::Medium,
        "Retention changes are blocked until a table setting is updated",
        format!(
            "{what} Until it is updated, changing the retention would make ClickHouse rewrite every \
             stored event, so nano refuses retention changes on these tables. Stored events are not \
             affected and expire as before."
        ),
        "clickhouse_retention",
        "nan5907_ttl_recalc",
    );
    health.resource_id = Some("clickhouse_event_retention".to_string());
    health.resource_name = Some("ClickHouse event retention".to_string());
    health.diagnostic_context = serde_json::json!({
        "skipped": outcome.skipped,
        "failed": outcome.failed.iter().map(|(t, e)| serde_json::json!({"table": t, "error": e})).collect::<Vec<_>>(),
        "setting": "materialize_ttl_recalculate_only = 1",
    });
    health.remediation = Some(
        "Check that every ClickHouse node is up, then run the migrator again (redeploy). It retries \
         on every run and resolves this notice when it succeeds."
            .to_string(),
    );
    if let Err(e) = repo.publish(&health).await {
        tracing::warn!(error = %e, "NAN-5907: publishing the TTL setting health notice failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, engine: &str, missing: u64) -> (String, String, u64) {
        (name.to_string(), engine.to_string(), missing)
    }

    #[test]
    fn single_node_and_migrator_cluster_layout_targets_the_bare_tables() {
        // Rust-migrator model: MergeTree under the bare name, `<t>_distributed`
        // wrapper (not even a candidate name).
        let rows = vec![
            row("ocsf_logs", "MergeTree", 1),
            row("logs", "ReplicatedMergeTree", 1),
            row("signals", "MergeTree", 0),
            row("otel_spans", "SharedMergeTree", 1),
        ];
        assert_eq!(plan_ttl_recalculate_only(&rows), vec!["logs", "ocsf_logs", "otel_spans"]);
    }

    #[test]
    fn local_split_cluster_targets_the_local_tables_never_the_distributed_name() {
        // init-clickhouse-cluster.sh model: `<t>_local` MergeTree, Distributed
        // under the bare name.
        let rows = vec![
            row("logs", "Distributed", 2),
            row("logs_local", "ReplicatedMergeTree", 2),
            row("otel_metrics", "Distributed", 2),
            row("otel_metrics_local", "ReplicatedMergeTree", 2),
            row("ingestion_errors_local", "ReplicatedMergeTree", 0),
        ];
        assert_eq!(plan_ttl_recalculate_only(&rows), vec!["logs_local", "otel_metrics_local"]);
    }

    #[test]
    fn a_table_unset_on_one_shard_only_is_still_planned() {
        // Partly failed ON CLUSTER ALTER: set on the node the migrator reads,
        // missing on another; the cluster-wide count still flags it.
        let rows = vec![row("logs", "ReplicatedMergeTree", 1), row("signals", "ReplicatedMergeTree", 0)];
        assert_eq!(plan_ttl_recalculate_only(&rows), vec!["logs"]);
    }

    #[test]
    fn unknown_tables_and_wrappers_are_ignored() {
        let rows = vec![
            row("logs_distributed", "Distributed", 1),
            row("logs_per_source_5m", "AggregatingMergeTree", 1),
            row("ocsf_logs_legacy_v179", "MergeTree", 1),
        ];
        assert!(plan_ttl_recalculate_only(&rows).is_empty());
    }

    #[test]
    fn inspect_sql_reads_every_replica_on_a_cluster() {
        let local = ttl_recalc_inspect_sql("nanosiem", None).unwrap();
        assert!(local.contains("FROM system.tables WHERE database = 'nanosiem'"), "{local}");
        let all = ttl_recalc_inspect_sql("nanosiem", Some("nano-cluster")).unwrap();
        assert!(all.contains("FROM clusterAllReplicas('nano-cluster', system.tables)"), "{all}");
        assert!(ttl_recalc_inspect_sql("nanosiem", Some("x', system.one) --")).is_none());
        assert!(ttl_recalc_inspect_sql("nano siem", None).is_none());
    }

    #[test]
    fn candidate_names_cover_both_layouts() {
        let names = ttl_recalc_candidate_names();
        for t in TTL_RECALC_TABLES {
            assert!(names.contains(&t.to_string()));
            assert!(names.contains(&format!("{t}_local")));
        }
    }
}
