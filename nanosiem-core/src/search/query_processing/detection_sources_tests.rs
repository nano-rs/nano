// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2961: detection source pinning for correlation rules.

use super::*;
use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};

const F: &str = "metadata.log_source";

fn pin(query: &str, bound: &str) -> PinnedDetectionQuery {
    pin_detection_query(query, bound, F).unwrap_or_else(|error| panic!("{query}: {error}"))
}

fn refused(query: &str, bound: &str) -> String {
    match pin_detection_query(query, bound, F) {
        Ok(pinned) => panic!("{query} must be refused, got {}", pinned.query),
        Err(error) => error.to_string(),
    }
}

/// Every scan's pin, in walk order, from the re-parsed pinned query.
fn scan_pins(query: &str) -> Vec<BTreeSet<String>> {
    fn walk_query(query: &Query, out: &mut Vec<BTreeSet<String>>) {
        match query {
            Query::Search(SearchExpr::And(left, right)) => {
                out.push(pin_values(right, F).expect("every scan carries a pin"));
                walk_expr(left, out);
            }
            Query::Search(other) => panic!("unpinned scan: {other:?}"),
            Query::Piped { source, command } => {
                walk_query(source, out);
                match command {
                    Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => walk_query(subsearch, out),
                    Command::Where { condition } => walk_expr(condition, out),
                    Command::Sequence { conditions, .. } => conditions.iter().for_each(|c| walk_expr(c, out)),
                    _ => {}
                }
            }
        }
    }
    fn walk_expr(expr: &SearchExpr, out: &mut Vec<BTreeSet<String>>) {
        match expr {
            SearchExpr::InSubsearch { subsearch, .. } => walk_query(subsearch, out),
            SearchExpr::And(l, r) | SearchExpr::Or(l, r) => {
                walk_expr(l, out);
                walk_expr(r, out);
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => walk_expr(inner, out),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk_query(&parse_query(query).unwrap(), &mut out);
    out
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn plain_rule_is_pinned_like_the_legacy_exact_source_gate() {
    let pinned = pin("status=failure | stats count by user", "Windows_Security");
    assert!(pinned.companions.is_empty());
    assert_eq!(pinned.nested_scans, 0);
    assert_eq!(scan_pins(&pinned.query), vec![set(&["windows_security"])]);
    // Byte-identical to the pre-NAN-2961 gate for a single-source rule.
    let legacy = crate::search::query_processing::enforce_exact_source_scope_with_field(
        "status=failure | stats count by user",
        "Windows_Security",
        F,
    )
    .unwrap();
    assert_eq!(pinned.query, legacy);
}

#[test]
fn same_source_correlation_pins_every_subsearch_to_the_bound_source() {
    for query in [
        "user.name=bob | join user.name [search status_id=2 | head 5]",
        "status_id=2 | append [search status_id=1]",
        "device.hostname IN [search process.name=\"mimikatz.exe\" | return device.hostname]",
        "* | where device.hostname IN [search status_id=2 | return device.hostname]",
        "* | sequence by device.hostname maxspan=5m [process.name=\"a.exe\"] [process.name=\"b.exe\"]",
    ] {
        let pinned = pin(query, "sysmon");
        assert!(pinned.companions.is_empty(), "{query}");
        let pins = scan_pins(&pinned.query);
        assert_eq!(pins.len(), pinned.nested_scans + 1, "{query}");
        assert!(pins.iter().all(|pin| *pin == set(&["sysmon"])), "{query}: {pins:?}");
    }
}

#[test]
fn multi_source_correlation_names_companions_per_scan() {
    let pinned = pin(
        "action=allowed | join user.name [search metadata.log_source=okta status_id=2]",
        "proxy",
    );
    assert_eq!(pinned.companions, set(&["okta"]));
    assert_eq!(scan_pins(&pinned.query), vec![set(&["proxy"]), set(&["okta"])]);

    // Top-level multi-source sequence: the bound source must be included.
    let pinned = pin(
        "metadata.log_source IN (\"okta\", \"sysmon\") | sequence by user.name maxspan=10m [status_id=2] [process.name=\"x\"]",
        "sysmon",
    );
    assert_eq!(pinned.companions, set(&["okta"]));
    assert_eq!(scan_pins(&pinned.query), vec![set(&["okta", "sysmon"])]);

    // A parenthesised OR of equalities is the same naming condition.
    let pinned = pin(
        "(metadata.log_source=okta OR metadata.log_source=Sysmon) user.name=bob",
        "sysmon",
    );
    assert_eq!(pinned.companions, set(&["okta"]));
}

#[test]
fn unsupported_shapes_are_refused_with_a_reason() {
    // The top-level scan must read the rule's own source.
    let reason = refused("metadata.log_source=okta | stats count", "sysmon");
    assert!(reason.contains("not the rule's own source \"sysmon\""), "{reason}");
    // A nested scan whose source condition is not a top-level naming condition.
    for query in [
        "* | join user.name [search (metadata.log_source=okta user.name=a) OR (metadata.log_source=azure user.name=b)]",
        "* | join user.name [search NOT metadata.log_source=okta]",
        "* | join user.name [search metadata.log_source=okta metadata.log_source=azure]",
        "* | join user.name [search metadata.log_source!=okta]",
    ] {
        let reason = refused(query, "sysmon");
        assert!(reason.contains("top-level condition"), "{query}: {reason}");
    }
    // Cross-dataset subsearches.
    let reason = refused("* | join trace_id [dataset=spans search status=500]", "sysmon");
    assert!(reason.contains("cross-dataset"), "{reason}");
    // Invalid identities never become a pin.
    let reason = refused("* | join user.name [search metadata.log_source=\"a/b\"]", "sysmon");
    assert!(reason.contains("not a valid source identity"), "{reason}");
    assert!(pin_detection_query("*", "unsafe/source", F).is_err());
    assert!(pin_detection_query("*", "sysmon", "unmapped.source_type").is_err());
    // Bounded fan-out.
    let many = (0..=MAX_DETECTION_NESTED_SCANS)
        .map(|index| format!("| append [search status_id={index}]"))
        .collect::<Vec<_>>()
        .join(" ");
    let reason = refused(&format!("status_id=0 {many}"), "sysmon");
    assert!(reason.contains("at most"), "{reason}");
}

#[test]
fn legacy_top_level_stray_mentions_stay_pinned_to_the_bound_source() {
    // Before NAN-2961 this ran as `(<q>) AND source=bound`; it still does.
    let pinned = pin("NOT metadata.log_source=okta user.name=bob", "sysmon");
    assert!(pinned.companions.is_empty());
    assert_eq!(scan_pins(&pinned.query), vec![set(&["sysmon"])]);
    // Authoring analysis is strict about it.
    assert!(analyze_detection_sources("NOT metadata.log_source=okta user.name=bob", F).is_err());
}

#[test]
fn authoring_analysis_reports_named_sources() {
    let plan = analyze_detection_sources(
        "metadata.log_source=sysmon | join user.name [search metadata.log_source=okta] | append [search status_id=1]",
        F,
    )
    .unwrap();
    assert_eq!(plan.top_level, Some(set(&["sysmon"])));
    assert_eq!(plan.named, set(&["okta", "sysmon"]));
    assert_eq!(plan.nested_scans, 2);
    let plan = analyze_detection_sources("status_id=1", F).unwrap();
    assert_eq!(plan, DetectionSourcePlan::default());
}

#[test]
fn a_breakout_value_cannot_dislodge_a_pin() {
    // A crafted keyword/value must never leave a scan unpinned after the
    // serialize → re-parse round trip; either it is pinned or it is refused.
    for query in [
        r#"user.name="x) OR (metadata.log_source=secret" | join user.name [search status_id=1]"#,
        r#"* | append [search "a\") OR (x=\"y"]"#,
    ] {
        if let Ok(pinned) = pin_detection_query(query, "sysmon", F) {
            let pins = scan_pins(&pinned.query);
            assert_eq!(pins.len(), pinned.nested_scans + 1, "{query}");
            assert!(pins.iter().all(|pin| pin.is_subset(&set(&["sysmon"]))), "{query}: {pins:?}");
        }
    }
}

#[test]
fn time_modifiers_survive_pinning() {
    let pinned = pin("status_id=2 | join user.name [search status_id=1] earliest=-1h", "sysmon");
    assert!(pinned.query.ends_with(" earliest=-1h"), "{}", pinned.query);
}

/// Parity with ClickHouse semantics: the pinned lean rule compiles to exactly
/// the SQL the ClickHouse product generates for the same correlation written
/// with explicit source conditions on every scan. The lean path adds no
/// semantics beyond the source pin; join/append/IN/sequence keep their
/// ClickHouse meaning.
#[test]
fn pinned_correlation_compiles_like_the_explicitly_sourced_clickhouse_query() {
    use crate::schema::OcsfProfile;
    use std::sync::Arc;
    let generator = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
    let range = TimeRange {
        start: "2024-01-01T00:00:00Z".parse().unwrap(),
        end: "2024-01-02T00:00:00Z".parse().unwrap(),
    };
    let cases = [
        (
            "status_id=2 | join user.name [search metadata.log_source=okta status_id=1 | head 5]",
            r#"(status_id=2) metadata.log_source="proxy" | join user.name [search (metadata.log_source=okta status_id=1) metadata.log_source="okta" | head 5]"#,
        ),
        (
            "status_id=2 | append [search status_id=1]",
            r#"(status_id=2) metadata.log_source="proxy" | append [search (status_id=1) metadata.log_source="proxy"]"#,
        ),
        (
            "device.hostname IN [search metadata.log_source=okta status_id=1 | return device.hostname]",
            r#"(device.hostname IN [search (metadata.log_source=okta status_id=1) metadata.log_source="okta" | return device.hostname]) metadata.log_source="proxy""#,
        ),
        (
            "metadata.log_source IN (\"okta\", \"proxy\") | sequence by user.name maxspan=10m [status_id=2] [status_id=1]",
            r#"(metadata.log_source IN ("okta", "proxy")) metadata.log_source IN ("okta", "proxy") | sequence by user.name maxspan=10m [status_id=2] [status_id=1]"#,
        ),
    ];
    for (rule, explicit) in cases {
        let pinned = pin(rule, "proxy");
        let lean = generator.generate(&parse_query(&pinned.query).unwrap(), &range).unwrap();
        let clickhouse = generator.generate(&parse_query(explicit).unwrap(), &range).unwrap();
        assert_eq!(lean, clickhouse, "{rule}\npinned: {}", pinned.query);
    }
}

/// NAN-3080: the live `newly_seen_rare_process_execution` query (prevalence
/// enrich + chained risk commands + an escaped backslash) pins quickly.
#[test]
fn nan3080_newly_seen_rare_process_query_pins_quickly() {
    let query = "metadata.log_source=\"windows_sysmon\"\n| where class_uid=1007 AND activity_id=1\n| where process.file.hashes.value != \"\"\n| prevalence enrich=true window=30d\n| where host_count < 5 AND prevalence_first_seen > now() - INTERVAL 24 HOUR\n| risk score=80 entity=device.hostname factor=\"Newly seen rare process\"\n| where host_count < 3\n| risk score=90 factor=\"Very rare hash\"\n| where process.file.path CONTAINS \"Temp\" OR process.file.path CONTAINS \"AppData\\\\Local\"\n| risk score=95 factor=\"Suspicious execution path\"\n| table time, device.hostname, actor.user.name, process.name, process.file.path, process.file.hashes.value, actor.process.name, process.cmd_line, risk_score, unmapped.risk_factors";
    let started = std::time::Instant::now();
    let pinned = pin_detection_query(query, "windows_sysmon", crate::search::query_processing::LAKE_SOURCE_FIELD);
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    let pinned = pinned.expect("pins").query;
    // Pinning re-serializes the query: the interval must survive the trip.
    assert!(pinned.contains("now() - INTERVAL 24 HOURS"), "{pinned}");
    let twice = pin_detection_query(&pinned, "windows_sysmon", crate::search::query_processing::LAKE_SOURCE_FIELD)
        .expect("re-pins").query;
    assert!(twice.contains("now() - INTERVAL 24 HOURS"), "{twice}");
}

/// NAN-3080: every INTERVAL unit round-trips through pretty-print/re-parse.
#[test]
fn nan3080_interval_values_round_trip_through_pretty_print() {
    use crate::query::PrettyPrint;
    for (written, printed) in [
        ("INTERVAL 24 HOUR", "INTERVAL 24 HOURS"),
        ("INTERVAL 7 DAYS", "INTERVAL 7 DAYS"),
        ("INTERVAL 90 SECOND", "INTERVAL 90 SECONDS"),
        ("INTERVAL 15 MINUTE", "INTERVAL 15 MINUTES"),
        ("INTERVAL 2 WEEK", "INTERVAL 2 WEEKS"),
    ] {
        let query = format!("* | where time > now() - {written}");
        let once = parse_query(&query).unwrap().pretty_print();
        assert!(once.contains(printed), "{written}: {once}");
        let twice = parse_query(&once).unwrap().pretty_print();
        assert_eq!(once, twice, "{written} is stable");
    }
}
