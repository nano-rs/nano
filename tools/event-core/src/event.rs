// SPDX-License-Identifier: AGPL-3.0-or-later

//! Event structure sent to Vector HTTP endpoint

use serde::{Deserialize, Serialize};
use std::sync::{OnceLock, atomic::{AtomicU64, Ordering}};
use std::time::{SystemTime, UNIX_EPOCH};

/// Produce a process-unique, restart-resistant synthetic Windows Event
/// RecordID. Real Windows collectors supply a monotonically increasing u64 per
/// channel; sampling a small random range creates birthday collisions quickly
/// enough to corrupt metadata.uid in sustained log-blaster runs.
pub fn next_windows_record_id() -> u64 {
    static NEXT: OnceLock<AtomicU64> = OnceLock::new();
    let next = NEXT.get_or_init(|| {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros()
            .min(u64::MAX as u128) as u64;
        AtomicU64::new(seed)
    });
    next.fetch_add(1, Ordering::Relaxed)
}

/// An event to be sent to Vector via HTTP.
///
/// Vector expects: `message` (raw log), `source_type`, and `timestamp`.
/// The `message` field contains the raw Windows Event JSON or proxy log line —
/// Vector's parsers handle UDM mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// The raw log line/JSON — this is what the SIEM parser will parse
    pub message: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Source type for Vector routing (e.g., "windows_sysmon", "windows_event", "conduit_proxy")
    pub source_type: String,
    /// Display-only label for terminal output (not serialized to the wire)
    #[serde(skip)]
    pub display_label: String,
}

#[cfg(test)]
mod tests {
    use super::next_windows_record_id;

    #[test]
    fn synthetic_windows_record_ids_are_monotonic() {
        let first = next_windows_record_id();
        let second = next_windows_record_id();
        assert_eq!(second, first + 1);
    }
}
