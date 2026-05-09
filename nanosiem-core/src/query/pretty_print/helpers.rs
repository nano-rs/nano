// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper functions for pretty-printing.

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
