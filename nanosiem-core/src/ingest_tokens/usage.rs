// SPDX-License-Identifier: AGPL-3.0-or-later

//! "Last used" for ingest tokens, from Vector's metrics endpoint.
//!
//! The fork's hashed-token check increments `hashed_token_requests_total`
//! (label `credential_id`) for every request a listed token authenticates.
//! `internal_metrics` (namespace `nanosiem_vector`) exports it on :9598 next to
//! the other pipeline metrics nano-api already scrapes. A credential whose
//! summed counter moved since the previous sample was used in between.

use std::collections::HashMap;

use uuid::Uuid;

/// The exported counter name (internal metric + `nanosiem_vector` namespace).
pub const CREDENTIAL_REQUESTS_METRIC: &str = "nanosiem_vector_hashed_token_requests_total";

/// Sums the counter per credential id across every series (one per source
/// component and host). Lines that are not the counter, or carry no valid
/// `credential_id`, are ignored.
pub fn parse_credential_request_counts(text: &str) -> HashMap<Uuid, f64> {
    let mut counts = HashMap::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(CREDENTIAL_REQUESTS_METRIC) else {
            continue;
        };
        let Some(labels_and_value) = rest.strip_prefix('{') else {
            continue;
        };
        let Some((labels, value)) = labels_and_value.rsplit_once('}') else {
            continue;
        };
        let Some(id) = label_value(labels, "credential_id").and_then(|v| Uuid::parse_str(v).ok())
        else {
            continue;
        };
        let Some(value) = value
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
        else {
            continue;
        };
        *counts.entry(id).or_insert(0.0) += value;
    }
    counts
}

fn label_value<'a>(labels: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let start = labels.find(&needle)? + needle.len();
    // Label boundary: the match must start the list or follow a comma.
    let before = &labels[..start - needle.len()];
    if !(before.is_empty() || before.ends_with(',')) {
        return None;
    }
    let end = labels[start..].find('"')?;
    Some(&labels[start..start + end])
}

#[cfg(test)]
#[path = "usage_tests.rs"]
mod tests;
