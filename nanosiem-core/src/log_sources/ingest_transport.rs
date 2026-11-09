// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ingestion methods a log source can declare as its `source_type`
//! (NAN-5033).
//!
//! The value is used to pick the Vector input lane
//! (`vector_config::router::transport_of`) and is embedded in generated VRL,
//! so a writer that accepts it from a request must accept only these names.
//! The set is the union of every name an existing writer or the renderer
//! already understands, so no value that works today is refused.

/// Canonical names, in the order shown in error messages.
pub const SUPPORTED: &[&str] = &[
    "routed",
    "vector",
    "otlp",
    "splunk_hec",
    "kafka",
    "aws_s3",
    "aws_sqs",
    "gcp_pubsub",
    "azure_event_hubs",
    "file",
    "syslog",
    "stdin",
];

/// The canonical name for an ingestion method, or `None` when it is not one.
/// Case-insensitive; surrounding whitespace is ignored. Aliases map to the
/// name the renderer classifies identically (`http` → `routed`, `otel` /
/// `opentelemetry` → `otlp`, `splunk` / `hec` → `splunk_hec`, `s3` →
/// `aws_s3`, `pubsub` → `gcp_pubsub`).
pub fn canonical(method: &str) -> Option<&'static str> {
    Some(match method.trim().to_ascii_lowercase().as_str() {
        "routed" | "http" => "routed",
        "vector" => "vector",
        "otlp" | "otel" | "opentelemetry" => "otlp",
        "splunk_hec" | "splunk" | "hec" => "splunk_hec",
        "kafka" => "kafka",
        "aws_s3" | "s3" => "aws_s3",
        "aws_sqs" => "aws_sqs",
        "gcp_pubsub" | "pubsub" => "gcp_pubsub",
        "azure_event_hubs" => "azure_event_hubs",
        // Legacy labels from the parser-service vocabulary
        // (`parsers::types::SourceType::all_types`); the renderer sends them
        // down the routed lane.
        "file" => "file",
        "syslog" => "syslog",
        "stdin" => "stdin",
        _ => return None,
    })
}

/// The 400 message for an unsupported method. The value is Debug-quoted so
/// control characters in it are shown escaped, never raw.
pub fn unsupported_message(field: &str, method: &str) -> String {
    format!(
        "{field} {method:?} is not a supported ingestion method; expected one of {}",
        SUPPORTED.join(", ")
    )
}

#[cfg(test)]
#[path = "ingest_transport_tests.rs"]
mod tests;
