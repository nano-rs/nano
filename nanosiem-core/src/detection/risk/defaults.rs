// SPDX-License-Identifier: AGPL-3.0-or-later

//! Default risk-score values for severity levels.
//!
//! When a detection rule does not set an explicit `risk_score`, both the
//! real-time materialized-view path and the scheduled execution path fall
//! back to a severity-based default. The two paths must agree on these
//! values — this module is the single source of truth.
//!
//! Keep `migrations/postgres/<N>_*.sql` `COMMENT ON COLUMN
//! detection_rules.risk_score` aligned with this table.

use crate::models::Severity;

/// Default risk score (0-100) applied to a finding when the rule has no
/// explicit `risk_score` set.
pub const fn default_score_for_severity(severity: Severity) -> i32 {
    match severity {
        Severity::Critical => 90,
        Severity::High => 75,
        Severity::Medium => 50,
        Severity::Low => 25,
        Severity::Informational => 10,
    }
}
