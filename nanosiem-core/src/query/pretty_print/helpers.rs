// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper functions for pretty-printing.

/// Canonical `dataset=` selector string for a cross-dataset subsearch (NAN-1562).
/// Round-trips through [`Dataset::from_selector`].
pub(crate) fn dataset_selector_str(
    ds: crate::query::clickhouse_sql_gen::otel::Dataset,
) -> &'static str {
    use crate::query::clickhouse_sql_gen::otel::Dataset;
    match ds {
        Dataset::Logs => "logs",
        Dataset::Spans => "spans",
        Dataset::Metrics => "metrics",
    }
}

/// Format duration as a human-readable string (1h, 5m, 30s, etc.)
pub(crate) fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs % 86400 == 0 {
        format!("{}d", secs / 86400)
    } else if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}
