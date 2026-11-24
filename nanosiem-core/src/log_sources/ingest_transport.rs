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
    "crowdstrike_fdr",
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
    // NAN-5789: THE alias table. `is_fetch`, `dispatch_compatible`,
    // `parsers::is_fetch_source_type` and `vector_config::router::transport_of`
    // all classify through it, so an alias accepted anywhere is classified the
    // same everywhere. It is the union of every spelling `SourceConfigType`,
    // `parsers::types::SourceType` and `log_sources::SourceType` accept.
    Some(match method.trim().to_ascii_lowercase().as_str() {
        "routed" | "http" => "routed",
        "vector" => "vector",
        "otlp" | "otel" | "opentelemetry" => "otlp",
        "splunk_hec" | "splunk" | "hec" => "splunk_hec",
        "kafka" => "kafka",
        "aws_s3" | "s3" => "aws_s3",
        "aws_sqs" | "sqs" => "aws_sqs",
        "crowdstrike_fdr" | "fdr" => "crowdstrike_fdr",
        "gcp_pubsub" | "pubsub" => "gcp_pubsub",
        "azure_event_hubs" | "event_hubs" | "eventhubs" => "azure_event_hubs",
        // Legacy labels from the parser-service vocabulary
        // (`parsers::types::SourceType::all_types`); the renderer sends them
        // down the routed lane.
        "file" => "file",
        "syslog" => "syslog",
        "stdin" => "stdin",
        _ => return None,
    })
}

/// The canonical methods that read through a source configuration (pull).
pub const FETCH: &[&str] = &["kafka", "aws_s3", "aws_sqs", "crowdstrike_fdr", "gcp_pubsub", "azure_event_hubs"];

/// Whether `method` (any accepted spelling) reads through a source
/// configuration rather than a push lane.
pub fn is_fetch(method: &str) -> bool {
    canonical(method).is_some_and(|m| FETCH.contains(&m))
}

/// The canonical `source_configurations.config_type` for any accepted
/// spelling (the same table: a configuration type is named like the method
/// it feeds, except `http`, which feeds `routed`).
pub fn canonical_config_type(config_type: &str) -> Option<&'static str> {
    canonical(config_type).map(|m| if m == "routed" { "http" } else { m })
}

/// NAN-5789 / NAN-943: whether a source configuration of `config_type` can
/// feed a log source of ingestion method `method`. Both sides are
/// canonicalized first (case, aliases), so the one table covers every
/// spelling a writer accepts. A fetch method needs a configuration of the
/// SAME type (a kafka source bound to an S3 configuration filters on the
/// wrong route and ingests nothing); a routed source pairs with `http`.
pub fn dispatch_compatible(config_type: &str, method: &str) -> bool {
    let (Some(config_type), Some(method)) = (canonical_config_type(config_type), canonical(method)) else {
        return false;
    };
    match method {
        "routed" => config_type == "http",
        "kafka" | "aws_s3" | "aws_sqs" | "crowdstrike_fdr" | "gcp_pubsub" | "azure_event_hubs" | "splunk_hec" | "otlp"
        | "vector" => config_type == method,
        _ => false,
    }
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
