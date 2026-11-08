// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4946 (main NAN-3762): an artifact type with no events in the window is
//! "not measured yet", never 0 %; payloads cached before the field existed
//! still deserialize as measured.

use super::{ArtifactCoverage, MarketplaceCoverage};

#[test]
fn cached_payload_without_measured_fields_reads_as_measured() {
    let json = r#"{"artifacts":[{"id":"ip","label":"IP addresses","pct":40,"state":"partial","have":[],"missing":[]}],"computed_at":"2026-11-03T00:00:00Z"}"#;
    let coverage: MarketplaceCoverage = serde_json::from_str(json).expect("legacy cache entry");
    assert!(coverage.telemetry_available);
    assert!(coverage.artifacts[0].measured);
}

#[test]
fn unmeasured_rows_serialize_their_flag() {
    let row = ArtifactCoverage {
        id: "hash".into(),
        label: "File hashes".into(),
        pct: 0,
        state: super::CoverageState::Gap,
        have: vec![],
        missing: vec![],
        measured: false,
    };
    let value = serde_json::to_value(&row).unwrap();
    assert_eq!(value["measured"], false);
}

/// NAN-1412: one WHERE carrying the time bound and every filter; an explicit
/// PREWHERE suppresses ClickHouse's auto move-to-prewhere.
#[test]
fn coverage_sql_uses_a_single_where_without_prewhere() {
    use std::collections::BTreeSet;
    let denied: BTreeSet<String> = ["audit"].into_iter().map(str::to_string).collect();
    for clustered in [false, true] {
        for sql in [
            super::coverage_sql(&crate::schema::UdmProfile::new(), clustered, &BTreeSet::new()),
            super::coverage_sql(&crate::schema::UdmProfile::new(), clustered, &denied),
            super::coverage_sql(&crate::schema::OcsfProfile::new(), clustered, &denied),
        ] {
            assert!(!sql.to_uppercase().contains("PREWHERE"), "explicit PREWHERE:\n{sql}");
            assert_eq!(sql.matches("WHERE timestamp >= now() - INTERVAL 24 HOUR").count(), 1, "sql:\n{sql}");
        }
    }
}
