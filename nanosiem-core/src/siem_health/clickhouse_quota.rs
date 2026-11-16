// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5470: SIEM Health reports nano's ClickHouse users meeting their hourly
//! quota.
//!
//! The NAN-5457 outage was a quota nobody saw: the shared service user ran out
//! of its 100,000 queries an hour, inserts failed with `QUOTA_EXCEEDED` (201),
//! and nothing in nano said so. Since NAN-5470 each workload has its own user
//! and the capped ones (the interactive search identity, the raw-SQL users,
//! the backup and Agent Lane audit readers) can still meet theirs. This probe
//! turns the evidence ClickHouse keeps into one finding:
//!
//! * `system.query_log`: queries refused with `QUOTA_EXCEEDED` since the
//!   previous SIEM Health run ([`refusal_window_minutes`]: the run interval,
//!   at least an hour), per nano user (high);
//! * `system.quotas_usage`: a nano user past [`NEAR_PERCENT`] % of any capped
//!   limit (queries, errors, rows, bytes, execution time) in its current
//!   hourly interval (medium, a warning before it fails).
//!
//! Agent Lane token users (`agentlane_*`) are left out: their quota is the
//! per-token budget an operator chose, and the Agent Lane audit reports them.
//!
//! Read through the admin `system_probe_client` (it holds ALL; with the
//! runtime-user fallback the probe returns nothing). On a cluster both tables
//! are node-local, so the probe fans out with `clusterAllReplicas`. Where the
//! cluster hops still log in as the runtime user (role-split before the
//! cluster secret, NAN-5472) that user cannot read them, and the probe falls
//! back to the node it is connected to.

use serde::Deserialize;

use super::types::{AnalysisResult, Recommendation};

/// Title of the finding (stable: suppressions key on it).
pub const CLICKHOUSE_QUOTA_TITLE: &str = "A nano ClickHouse user is meeting its hourly quota";

/// Shortest look-back for refused queries: one nano quota interval.
pub const MIN_WINDOW_MINUTES: u64 = 60;

/// Look-back for refused queries: the SIEM Health run interval
/// (`SIEM_HEALTH_CHECK_INTERVAL_SECS`, 12 h by default), at least an hour,
/// so a refusal between two runs is never missed.
pub fn refusal_window_minutes(interval_secs: Option<u64>) -> u64 {
    let interval = interval_secs.unwrap_or(super::scheduler::DEFAULT_INTERVAL_SECS);
    interval.div_ceil(60).max(MIN_WINDOW_MINUTES)
}

fn configured_refusal_window_minutes() -> u64 {
    refusal_window_minutes(
        std::env::var("SIEM_HEALTH_CHECK_INTERVAL_SECS").ok().and_then(|v| v.parse().ok()),
    )
}

/// `QUOTA_EXCEEDED`.
pub const QUOTA_EXCEEDED_CODE: i32 = 201;

/// Share of a capped limit used in the current interval that is reported
/// before anything fails.
pub const NEAR_PERCENT: f64 = 80.0;

/// nano's own users: `nanosiem*` and the backup reader. Never Agent Lane
/// tokens (see the module docs).
const NANO_USER_PREDICATE: &str = "(startsWith({col}, 'nanosiem') OR {col} = 'nano_backup')";

#[derive(Debug, Clone, PartialEq, clickhouse::Row, Deserialize)]
pub struct QuotaRefusal {
    pub user: String,
    pub refused: u64,
}

/// Every quota limit ClickHouse tracks per interval, with the column of its
/// usage and of its cap in `system.quotas_usage`.
pub const QUOTA_LIMITS: &[(&str, &str)] = &[
    ("queries", "queries"),
    ("errors", "errors"),
    ("result_rows", "result rows"),
    ("result_bytes", "result bytes"),
    ("read_rows", "read rows"),
    ("read_bytes", "read bytes"),
    ("written_bytes", "written bytes"),
    ("execution_time", "execution time"),
];

#[derive(Debug, Clone, PartialEq, clickhouse::Row, Deserialize)]
pub struct QuotaUsage {
    pub user: String,
    pub quota: String,
    /// `(used, max)` per [`QUOTA_LIMITS`] entry, in that order; max 0 = not capped.
    pub limits: Vec<(f64, f64)>,
}

impl QuotaUsage {
    /// The highest share of a capped limit this interval has used, with the
    /// limit's name. `None` when nothing is capped (`nano_service`).
    fn highest_share(&self) -> Option<(f64, &'static str)> {
        let mut out: Option<(f64, &'static str)> = None;
        for ((used, max), (_, name)) in self.limits.iter().zip(QUOTA_LIMITS) {
            if *max > 0.0 {
                let share = used * 100.0 / max;
                if out.is_none_or(|(s, _)| share > s) {
                    out = Some((share, name));
                }
            }
        }
        out
    }
}

/// What the probe found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QuotaFindings {
    pub refusals: Vec<QuotaRefusal>,
    pub usage: Vec<QuotaUsage>,
    /// Look-back of `refusals`, in minutes.
    pub window_minutes: u64,
    /// The cluster-wide read was refused and only the connected ClickHouse
    /// node was checked.
    pub connected_node_only: bool,
}

fn source(cluster: Option<&str>, table: &str) -> String {
    match cluster {
        Some(c) => format!("clusterAllReplicas('{}', system.{table})", crate::sql_hygiene::escape_sql_string(c)),
        None => format!("system.{table}"),
    }
}

fn refusals_sql(cluster: Option<&str>, window_minutes: u64) -> String {
    format!(
        "SELECT user, count() AS refused FROM {src} \
         WHERE event_date >= toDate(now() - INTERVAL {window_minutes} MINUTE) \
         AND event_time > now() - INTERVAL {window_minutes} MINUTE \
         AND type IN ('ExceptionBeforeStart', 'ExceptionWhileProcessing') \
         AND exception_code = {QUOTA_EXCEEDED_CODE} AND {users} \
         GROUP BY user ORDER BY user",
        src = source(cluster, "query_log"),
        users = NANO_USER_PREDICATE.replace("{col}", "user"),
    )
}

fn usage_sql(cluster: Option<&str>) -> String {
    let limits = QUOTA_LIMITS
        .iter()
        .map(|(col, _)| format!("(toFloat64(ifNull({col}, 0)), toFloat64(ifNull(max_{col}, 0)))"))
        .collect::<Vec<_>>()
        .join(", ");
    let capped = QUOTA_LIMITS
        .iter()
        .map(|(col, _)| format!("ifNull(max_{col}, 0) > 0"))
        .collect::<Vec<_>>()
        .join(" OR ");
    format!(
        "SELECT quota_key AS user, quota_name AS quota, [{limits}] AS limits \
         FROM {src} WHERE {users} AND ({capped}) ORDER BY user",
        src = source(cluster, "quotas_usage"),
        users = NANO_USER_PREDICATE.replace("{col}", "quota_key"),
    )
}

async fn read(
    client: &clickhouse::Client,
    cluster: Option<&str>,
    window_minutes: u64,
) -> Result<QuotaFindings, clickhouse::error::Error> {
    let refusals = client.query(&refusals_sql(cluster, window_minutes)).fetch_all::<QuotaRefusal>().await?;
    let usage = client.query(&usage_sql(cluster)).fetch_all::<QuotaUsage>().await?;
    Ok(QuotaFindings { refusals, usage, window_minutes, connected_node_only: false })
}

/// Reads refused queries and current quota usage of nano's users. Returns
/// nothing with the runtime-user fallback (it cannot read either table).
pub async fn clickhouse_quota(
    system_probe_client: &clickhouse::Client,
    cluster: Option<&str>,
) -> Result<QuotaFindings, clickhouse::error::Error> {
    let current: String = system_probe_client.query("SELECT currentUser()").fetch_one().await?;
    let runtime = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "nanosiem".into());
    if current == runtime {
        return Ok(QuotaFindings::default());
    }
    let client = system_probe_client
        .clone()
        .with_setting(super::collector::PROBE_SKIP_UNAVAILABLE_REPLICAS.0, super::collector::PROBE_SKIP_UNAVAILABLE_REPLICAS.1);
    let window = configured_refusal_window_minutes();
    match cluster {
        Some(c) => match read(&client, Some(c), window).await {
            Ok(found) => Ok(found),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "ClickHouse quota probe: the cluster-wide read was refused (cluster hops log in as \
                     the runtime user until the cluster secret is on); only the connected ClickHouse \
                     node was checked"
                );
                let mut found = read(system_probe_client, None, window).await?;
                found.connected_node_only = true;
                Ok(found)
            }
        },
        None => read(system_probe_client, None, window).await,
    }
}

/// One line per user: refusals first, then users near a capped limit.
pub fn quota_lines(found: &QuotaFindings) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut refused_users = std::collections::BTreeMap::<&str, u64>::new();
    for r in &found.refusals {
        *refused_users.entry(r.user.as_str()).or_default() += r.refused;
    }
    for (user, refused) in &refused_users {
        lines.push(format!(
            "{user}: {refused} queries refused with QUOTA_EXCEEDED in the last {}",
            window_text(found.window_minutes)
        ));
    }
    let mut near = std::collections::BTreeMap::<&str, (f64, &str, &str)>::new();
    for u in &found.usage {
        if refused_users.contains_key(u.user.as_str()) {
            continue;
        }
        if let Some((share, limit)) = u.highest_share() {
            if share >= NEAR_PERCENT && near.get(u.user.as_str()).is_none_or(|(s, _, _)| share > *s) {
                near.insert(u.user.as_str(), (share, limit, u.quota.as_str()));
            }
        }
    }
    for (user, (share, limit, quota)) in &near {
        lines.push(format!("{user}: {share:.0} % of its hourly {limit} cap used this hour (quota {quota})"));
    }
    (lines, !refused_users.is_empty())
}

fn window_text(minutes: u64) -> String {
    if minutes % 60 == 0 {
        let hours = minutes / 60;
        if hours == 1 { "hour".to_string() } else { format!("{hours} hours") }
    } else {
        format!("{minutes} minutes")
    }
}

/// Adds the finding: high (score capped at 79) when a user was refused,
/// medium when one is near a capped limit.
pub fn ensure_clickhouse_quota_findings(analysis: &mut AnalysisResult, found: &QuotaFindings) {
    let (lines, refused) = quota_lines(found);
    if lines.is_empty() {
        return;
    }
    if refused {
        analysis.overall_score = analysis.overall_score.min(79);
    }
    if analysis.recommendations.iter().any(|r| r.title == CLICKHOUSE_QUOTA_TITLE) {
        return;
    }
    analysis.recommendations.insert(
        0,
        Recommendation {
            title: CLICKHOUSE_QUOTA_TITLE.to_string(),
            description: format!(
                "{}{}. Each nano workload has its own ClickHouse user and hourly quota (per user, per \
                 ClickHouse server; docs/administration/upgrades.md). A user over its quota has its \
                 queries refused until the hour rolls over: for nanosiem_search that is searches, \
                 dashboards and pivt; for the raw-SQL users, SQL search and SQL panels. Find what \
                 drives the load in system.query_log (user, normalized_query_hash). A quota that \
                 normal use outgrows is a sizing bug: report it.",
                lines.join("; "),
                if found.connected_node_only {
                    " (only the connected ClickHouse node was checked: the cluster-wide read needs the \
                     cluster secret, NANO_CLICKHOUSE_CLUSTER_AUTH=secret)"
                } else {
                    ""
                }
            ),
            priority: if refused { "high" } else { "medium" }.to_string(),
        },
    );
}

#[cfg(test)]
#[path = "clickhouse_quota_tests.rs"]
mod tests;
