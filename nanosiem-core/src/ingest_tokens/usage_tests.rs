// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for parsing Vector's per-credential request counter.

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
