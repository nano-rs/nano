// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5450: SIEM Health findings for data volumes at 80 % / 90 %.
//!
//! The report is [`crate::health::disk_monitor::DiskHealthReport`], collected
//! with the other metrics (`CollectedMetrics::disk`). One finding per level,
//! listing every volume at that level, so a suppression keys on a stable
//! title rather than on a host name.

use super::types::{AnalysisResult, CollectedMetrics, Recommendation};
use crate::health::disk_monitor::{DiskHealthReport, DiskLevel};

/// Title at 90 % or more (stable: suppressions key on it).
pub const DISK_CRITICAL_TITLE: &str = "A data disk is almost full";
/// Title at 80 % or more.
pub const DISK_WARNING_TITLE: &str = "A data disk is filling up";

/// Findings for one report: `critical` (score capped at 49) when any volume
/// is at 90 % or more, at 95 % or more (imminent), or forecast to fill within
/// 24 hours; `high` (capped at 79) at 80 % or more. Each line carries the
/// volume's detail, which includes the "full in about N hours" forecast.
pub fn disk_recommendations(report: &DiskHealthReport) -> Vec<(Recommendation, i32)> {
    let mut out = Vec::new();
    for (level, title, priority, cap) in [
        (DiskLevel::Critical, DISK_CRITICAL_TITLE, "critical", 49i32),
        (DiskLevel::Warning, DISK_WARNING_TITLE, "high", 79i32),
    ] {
        let lines: Vec<String> = report
            .volumes
            .iter()
            // Imminent (95 %) counts as critical; a volume that shares another
            // volume's filesystem is listed once, under that volume.
            .filter(|v| v.shared_with.is_none())
            .filter(|v| if level == DiskLevel::Critical { v.level >= DiskLevel::Critical } else { v.level == level })
            .map(|v| format!("{} ({})", v.display_name(), v.detail))
            .collect();
        if lines.is_empty() {
            continue;
        }
        let threshold = if level == DiskLevel::Critical {
            report.critical_fraction
        } else {
            report.warn_fraction
        };
        out.push((
            Recommendation {
                title: title.to_string(),
                description: format!(
                    "At or above {:.0}%: {}. When the ClickHouse disk fills, inserts fail and the oldest \
                     partitions are dropped; when the PostgreSQL disk fills, PostgreSQL stops and every nano \
                     service with it; a full Vector buffer pushes back on senders. Free space or grow the \
                     volume now. The recovery steps for a disk that is already full are in \
                     docs/administration/disk-full-recovery.md.",
                    threshold * 100.0,
                    lines.join("; ")
                ),
                priority: priority.to_string(),
            },
            cap,
        ));
    }
    out
}

/// Adds the findings to `analysis` on every report path (AI, fallback).
pub fn ensure_disk_findings(analysis: &mut AnalysisResult, metrics: &CollectedMetrics) {
    let Some(report) = metrics.disk.as_ref() else {
        return;
    };
    // Inserted at the front in reverse, so the critical finding ends up first.
    for (rec, cap) in disk_recommendations(report).into_iter().rev() {
        analysis.overall_score = analysis.overall_score.min(cap);
        if !analysis.recommendations.iter().any(|r| r.title == rec.title) {
            analysis.recommendations.insert(0, rec);
        }
    }
}

#[cfg(test)]
#[path = "disk_findings_tests.rs"]
mod tests;
