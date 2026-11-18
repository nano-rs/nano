// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5577 — `hunt_finding` alerts never count as detections.
//!
//! A hunt-finding alert carries a promoted hunt finding's evidence events on
//! its case. It is not a rule that fired, so every alert KPI (counts by
//! status and severity, velocity, MTTA, the system and briefing tallies) and
//! the default alert stream leave it out. These source-reading tests pin that:
//! a new aggregate over `alerts` in one of these files fails here until it
//! says what it does with the kind.

use super::*;

const REPOSITORY: &str = include_str!("alerts.rs");
const HEALTH_COLLECTOR: &str = include_str!("../../siem_health/collector.rs");

/// Every `FROM alerts` statement in `source` must mention `hunt_finding`
/// before its statement ends (the closing raw-string / string quote).
fn assert_every_aggregate_excludes(label: &str, source: &str) {
    let mut checked = 0;
    for (at, _) in source.match_indices("FROM alerts") {
        let tail = &source[at..];
        let end = tail.find("\"#").or_else(|| tail.find("\",")).unwrap_or(tail.len().min(600));
        let stmt = &tail[..end];
        assert!(
            stmt.contains("hunt_finding"),
            "{label}: an alert aggregate does not exclude hunt_finding alerts:\n{stmt}"
        );
        checked += 1;
    }
    assert!(checked > 0, "{label}: no alert aggregate found; the pin is stale");
}

#[test]
fn health_collector_alert_kpis_exclude_hunt_findings() {
    // Only the alerting/detection metric functions read `alerts`.
    assert_every_aggregate_excludes("siem_health/collector.rs", HEALTH_COLLECTOR);
}

#[test]
fn api_and_briefing_alert_tallies_exclude_hunt_findings() {
    // Other crates: read at runtime so a stripped mirror tree (no enterprise)
    // still builds; a missing file there is skipped, anywhere else it fails.
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    for (rel, required) in [
        ("nanosiem-api/src/handlers/system.rs", true),
        ("nanosiem-enterprise/src/melod/data_access/briefing.rs", false),
    ] {
        let path = format!("{root}/{rel}");
        match std::fs::read_to_string(&path) {
            Ok(src) => assert_every_aggregate_excludes(rel, &src),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {}
            Err(e) => panic!("read {path}: {e}"),
        }
    }
    let velocity = std::fs::read_to_string(format!("{root}/nanosiem-api/src/handlers/alerts.rs")).expect("alerts handler");
    assert!(velocity.contains("kinds_filter_sql(\"kind\", 3)"), "the velocity histogram lost the kinds filter");
    assert!(velocity.contains("include_hunt_findings"), "the alert stream lost its hunt-finding opt-in");
}

#[test]
fn repository_counts_lists_and_stream_default_to_excluding_hunt_findings() {
    assert_eq!(REPOSITORY.matches("kinds_filter_sql(\"kind\", 1)").count(), 2, "count_by_status*");
    assert!(REPOSITORY.contains("kinds_filter_sql(\"a.kind\", 6)"), "list_filtered");
    assert!(REPOSITORY.contains("AND a.kind <> 'hunt_finding'"), "list_after");
}

#[test]
fn the_kinds_filter_drops_hunt_findings_only_when_no_kind_is_named() {
    let sql = kinds_filter_sql("a.kind", 6);
    assert_eq!(sql, "(($6::text[] IS NULL AND a.kind <> 'hunt_finding') OR a.kind = ANY($6))");
    assert_eq!(NOT_HUNT_FINDING_SQL, "kind <> 'hunt_finding'");
}
