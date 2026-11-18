// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5567: SIEM Health flags batches ClickHouse permanently rejected.
//!
//! From Vector `0.61.0-nano.13`, a ClickHouse sink writes a batch ClickHouse
//! refuses for good (an HTTP 4xx, or a non-retryable code such as 117
//! "incorrect data" or 53 "type mismatch") to a bounded dead-letter store on
//! the Vector data volume, `/var/lib/vector/dead_letter/<sink>/`, instead of
//! dropping it. The store is read from each Vector's exporter page together
//! with the disk buffers ([`crate::health::disk_monitor`]), so the finding
//! lists the sinks with the events stored, the bytes held and any events the
//! full store had to discard.

use super::types::{AnalysisResult, CollectedMetrics, Recommendation};
use crate::health::disk_monitor::{human_bytes, VectorDeadLetter};

/// Title of the finding (stable: suppressions key on it).
pub const VECTOR_DEAD_LETTER_TITLE: &str = "ClickHouse rejected events; Vector kept them in its dead-letter store";

fn describe(d: &VectorDeadLetter) -> String {
    let mut s = d.component_id.clone();
    if let Some(host) = &d.host {
        s.push_str(" on ");
        s.push_str(host);
    }
    let mut parts = vec![format!("{} held", human_bytes(d.held_bytes))];
    if d.dead_lettered_events > 0 {
        parts.push(format!("{} events stored since Vector started", d.dead_lettered_events));
    }
    if d.discarded_events > 0 {
        parts.push(format!("{} events discarded because the store was full or a write failed", d.discarded_events));
    }
    format!("{s} ({})", parts.join(", "))
}

/// The finding for `dead_letters`, if any store has something to report:
/// `high`, score capped at 69, as for other events missing from ClickHouse.
pub fn dead_letter_recommendation(dead_letters: &[VectorDeadLetter]) -> Option<Recommendation> {
    let active: Vec<&VectorDeadLetter> = dead_letters.iter().filter(|d| d.is_active()).collect();
    if active.is_empty() {
        return None;
    }
    let lines = active.iter().map(|d| describe(d)).collect::<Vec<_>>().join("; ");
    Some(Recommendation {
        title: VECTOR_DEAD_LETTER_TITLE.to_string(),
        description: format!(
            "ClickHouse refused some batches for good (for example a type mismatch or malformed data), so \
             these events are not searchable: {lines}. Vector kept each batch, as it would have been sent, \
             under /var/lib/vector/dead_letter/<sink>/ on the Vector data volume: a body file \
             (.ndjson.gz) and a .meta.json file with the table, the rejection reason and the INSERT query \
             that replays it. Find the cause in the reason, fix the table or the parser, then replay the \
             body with that query (send it with Content-Encoding: gzip) and delete both files. The store is \
             capped per sink and drops its oldest batches when full. This warning clears the next time Vector \
             restarts (`docker compose restart vector`) after you replay and delete the files."
        ),
        priority: "high".to_string(),
    })
}

/// Adds the finding to `analysis` on every report path (AI, fallback).
pub fn ensure_vector_dead_letter_findings(analysis: &mut AnalysisResult, metrics: &CollectedMetrics) {
    let Some(report) = metrics.disk.as_ref() else {
        return;
    };
    let Some(rec) = dead_letter_recommendation(&report.vector_dead_letters) else {
        return;
    };
    analysis.overall_score = analysis.overall_score.min(69);
    if !analysis.recommendations.iter().any(|r| r.title == rec.title) {
        analysis.recommendations.push(rec);
    }
}

#[cfg(test)]
#[path = "vector_dead_letters_tests.rs"]
mod tests;
