// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stuck (unkillable) ClickHouse query monitoring
//!
//! ClickHouse >= 26.4 can wedge inside query-plan optimization: bloom_filter
//! skip-index analysis over a large scalar-subquery Map runs for hours with no
//! cancellation point, so `max_execution_time` marks the query cancelled but
//! it never dies, and `KILL QUERY` is equally ignored. Each occurrence pins an
//! HTTPHandler thread at 100% CPU until the server is restarted (NAN-2274,
//! upstream ClickHouse#113003 — assume no upstream fix). Generated queries
//! carry `use_skip_indexes=0` to dodge the known trigger; this monitor is the
//! detection fallback for everything else (raw SQL, future trigger shapes):
//! a query still present in `system.processes` with `is_cancelled = 1` long
//! past the threshold is by definition wedged — normal cancellation completes
//! within seconds.

use clickhouse::Client as ClickHouseClient;
use serde::Deserialize;
use tracing::{debug, warn};

use super::types::StuckQueryStatus;
use crate::db::dual_pool::system_processes_source_for_cluster;

/// Cluster name from the `CLICKHOUSE_CLUSTER` env — same deploy-level signal
/// `FeedMonitor` / retention use. `system.processes` is per-node, so on a
/// cluster the probe must fan out via `clusterAllReplicas` or a wedge on any
/// replica other than the one this client happens to reach stays invisible.
fn clickhouse_cluster_name() -> Option<String> {
    std::env::var("CLICKHOUSE_CLUSTER")
        .ok()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
}

#[derive(Deserialize)]
struct StuckRow {
    query_id: String,
    user: String,
    elapsed: f64,
    query_snippet: String,
}

/// Result of one wedge probe. `authoritative` is false when the probe
/// failed outright or degraded to a single node of a cluster — an incomplete
/// view must never RESOLVE tracked issues, or a flapping probe re-arms
/// `notify_issue_once` and the same wedge notifies again on every flap.
pub struct StuckQueryProbe {
    pub statuses: Vec<StuckQueryStatus>,
    pub authoritative: bool,
}

/// Monitor for cancelled-but-still-running ClickHouse queries
pub struct StuckQueryMonitor {
    ch_client: ClickHouseClient,
    threshold_secs: u64,
}

impl StuckQueryMonitor {
    pub fn new(ch_client: ClickHouseClient, threshold_secs: u64) -> Self {
        Self {
            ch_client,
            threshold_secs,
        }
    }

    /// Probe SQL. `normalizeQuery` strips literals so the snippet is safe to
    /// put in a notification (no log content / search terms leak into it).
    fn probe_sql(cluster: Option<&str>, threshold_secs: u64) -> String {
        let source = system_processes_source_for_cluster(cluster);
        let snippet = if source == "cluster_processes" {
            "query_snippet"
        } else {
            "substring(normalizeQuery(query), 1, 200) AS query_snippet"
        };
        format!(
            "SELECT query_id, user, elapsed, {snippet} \
             FROM {source} WHERE is_cancelled = 1 AND elapsed > {threshold_secs}"
        )
    }

    /// Find queries that were cancelled more than the threshold ago and are
    /// still running. On a cluster, degrade to the local node if the
    /// `clusterAllReplicas` fan-out fails (e.g. restricted inter-node access)
    /// rather than losing the check entirely.
    pub async fn check_stuck_queries(&self) -> StuckQueryProbe {
        let cluster = clickhouse_cluster_name();
        match self
            .fetch(&Self::probe_sql(cluster.as_deref(), self.threshold_secs))
            .await
        {
            Ok(statuses) => StuckQueryProbe {
                statuses,
                authoritative: true,
            },
            Err(e) if cluster.is_some() => {
                warn!(
                    error = %e,
                    "clusterAllReplicas stuck-query probe failed; falling back to local node"
                );
                let statuses = self
                    .fetch(&Self::probe_sql(None, self.threshold_secs))
                    .await
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "Stuck-query probe failed");
                        Vec::new()
                    });
                StuckQueryProbe {
                    statuses,
                    authoritative: false,
                }
            }
            Err(e) => {
                warn!(error = %e, "Stuck-query probe failed");
                StuckQueryProbe {
                    statuses: Vec::new(),
                    authoritative: false,
                }
            }
        }
    }

    async fn fetch(
        &self,
        sql: &str,
    ) -> Result<Vec<StuckQueryStatus>, Box<dyn std::error::Error + Send + Sync>> {
        let mut cursor = self.ch_client.query(sql).fetch_bytes("JSONEachRow")?;
        let mut response_bytes = Vec::new();
        while let Some(chunk) = cursor.next().await? {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes)?;
        let mut statuses = Vec::new();
        for line in response_str.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<StuckRow>(line) {
                Ok(row) => statuses.push(StuckQueryStatus {
                    query_id: row.query_id,
                    user: row.user,
                    elapsed_secs: row.elapsed,
                    query_snippet: row.query_snippet,
                }),
                Err(e) => debug!(error = %e, "Skipping unparseable stuck-query row"),
            }
        }
        Ok(statuses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_targets_local_processes_when_unclustered() {
        let sql = StuckQueryMonitor::probe_sql(None, 600);
        assert!(sql.contains("FROM system.processes"), "got: {sql}");
        assert!(sql.contains("is_cancelled = 1"), "got: {sql}");
        assert!(sql.contains("elapsed > 600"), "got: {sql}");
    }

    #[test]
    fn clustered_probe_uses_the_definer_view() {
        let sql = StuckQueryMonitor::probe_sql(Some("nano"), 900);
        assert!(
            sql.contains("FROM cluster_processes"),
            "got: {sql}"
        );
        assert!(!sql.contains("clusterAllReplicas"), "got: {sql}");
        assert!(sql.contains("elapsed > 900"), "got: {sql}");
    }

    #[test]
    fn probe_snippet_is_literal_stripped() {
        // normalizeQuery is the guarantee that notification snippets never
        // carry query literals (search terms, log content).
        let sql = StuckQueryMonitor::probe_sql(None, 600);
        assert!(sql.contains("normalizeQuery(query)"), "got: {sql}");

        // The clustered view performs that normalization as its definer, so the
        // runtime user never receives the raw query text through the view.
        let clustered = StuckQueryMonitor::probe_sql(Some("nano"), 600);
        assert!(clustered.contains("query_snippet"), "got: {clustered}");
        assert!(!clustered.contains("normalizeQuery(query)"), "got: {clustered}");
    }
}
