//! Event structure sent to Vector HTTP endpoint

use serde::{Deserialize, Serialize};

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
