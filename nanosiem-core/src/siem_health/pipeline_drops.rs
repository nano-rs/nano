// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5431: SIEM Health flags events Vector discarded unintentionally.
//!
//! Vector logs `Events dropped` at ERROR only for UNINTENTIONAL drops
//! (`intentional=false`: an event it could not encode into a disk buffer, a
//! sink that gave up, ...); intentional drops (filters, sampling) log at DEBUG.
//! `92-metrics.toml` ships every WARN/ERROR internal log to
//! `collector_errors`, so a row with that message is evidence that ingest
//! accepted events which never reached ClickHouse. The finding names the
//! components and counts the reports (Vector rate-limits its own logs, so this
//! is a count of reports, not of events: the `component_discarded_events_total`
//! / `buffer_discarded_events_total` metrics on each Vector carry the totals).

use serde::Deserialize;

use super::types::{AnalysisResult, Recommendation};
use crate::db::TableNames;

/// Title of the finding (stable: suppressions key on it).
pub const PIPELINE_DROPS_TITLE: &str = "Vector discarded events after accepting them";

/// Look-back window.
pub const WINDOW_HOURS: u32 = 24;

#[derive(Debug, Clone, clickhouse::Row, Deserialize)]
pub struct DropRow {
    pub component_id: String,
    pub reports: u64,
}

/// The query, kept separate so it can be asserted without ClickHouse.
/// `component_id` leads the table's ORDER BY; the time bound prunes
/// partitions. Single WHERE, no explicit PREWHERE (NAN-1412).
pub fn drop_query(is_clustered: bool) -> String {
    let table = TableNames::new(is_clustered).read_bare("collector_errors");
    format!(
        "SELECT component_id, count() AS reports FROM nanosiem.{table} \
         WHERE timestamp > now() - INTERVAL {WINDOW_HOURS} HOUR \
         AND level = 'ERROR' AND startsWith(message, 'Events dropped') \
         GROUP BY component_id ORDER BY reports DESC, component_id LIMIT 20"
    )
}

pub async fn pipeline_drops(
    ch_client: &clickhouse::Client,
    is_clustered: bool,
) -> Result<Vec<DropRow>, clickhouse::error::Error> {
    ch_client.query(&drop_query(is_clustered)).fetch_all::<DropRow>().await
}

/// Adds a high-priority finding (score capped at 69) when `rows` is not empty.
pub fn ensure_pipeline_drop_findings(analysis: &mut AnalysisResult, rows: &[DropRow]) {
    let rows: Vec<&DropRow> = rows.iter().filter(|r| r.reports > 0).collect();
    if rows.is_empty() {
        return;
    }
    analysis.overall_score = analysis.overall_score.min(69);
    if analysis.recommendations.iter().any(|r| r.title == PIPELINE_DROPS_TITLE) {
        return;
    }
    let components = rows
        .iter()
        .map(|r| {
            let id = if r.component_id.is_empty() { "unknown component" } else { r.component_id.as_str() };
            format!("{id} ({} reports)", r.reports)
        })
        .collect::<Vec<_>>()
        .join(", ");
    analysis.recommendations.push(Recommendation {
        title: PIPELINE_DROPS_TITLE.to_string(),
        description: format!(
            "In the last {WINDOW_HOURS} hours Vector reported unintentionally dropped events at: \
             {components}. These events were accepted at ingest but are not stored, so searches \
             and detections cannot see them. Check the Vector logs for the reason (search \
             `collector_errors` for \"Events dropped\") and the \
             `nanosiem_vector_component_discarded_events_total` and \
             `nanosiem_vector_buffer_discarded_events_total` metrics for the totals."
        ),
        priority: "high".to_string(),
    });
}

#[cfg(test)]
#[path = "pipeline_drops_tests.rs"]
mod tests;
