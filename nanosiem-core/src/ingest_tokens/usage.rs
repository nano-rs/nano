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
mod tests {
    use super::*;

    #[test]
    fn sums_series_per_credential() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let text = format!(
            "# HELP nanosiem_vector_hashed_token_requests_total hashed_token_requests_total\n\
             # TYPE nanosiem_vector_hashed_token_requests_total counter\n\
             nanosiem_vector_hashed_token_requests_total{{component_id=\"splunk_hec_ingest\",component_kind=\"source\",credential_id=\"{a}\",host=\"v\"}} 12 1760000000000\n\
             nanosiem_vector_hashed_token_requests_total{{component_id=\"http_ingest\",credential_id=\"{a}\"}} 3\n\
             nanosiem_vector_hashed_token_requests_total{{credential_id=\"{b}\",host=\"v\"}} 1\n\
             nanosiem_vector_hashed_token_requests_total{{xcredential_id=\"{b}\"}} 99\n\
             nanosiem_vector_hashed_token_requests_total{{credential_id=\"install\"}} 5\n\
             nanosiem_vector_component_received_events_total{{credential_id=\"{b}\"}} 7\n"
        );
        let counts = parse_credential_request_counts(&text);
        assert_eq!(counts.len(), 2);
        assert_eq!(counts[&a], 15.0);
        assert_eq!(counts[&b], 1.0);
    }

    #[test]
    fn garbage_is_ignored() {
        assert!(parse_credential_request_counts("not prometheus\n{}\n").is_empty());
        assert!(parse_credential_request_counts(&format!(
            "{CREDENTIAL_REQUESTS_METRIC}{{credential_id=\"{}\"}} NaNx",
            Uuid::nil()
        ))
        .is_empty());
    }
}
