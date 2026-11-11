// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{resolves_into_column, DynamicFieldBucket};
use crate::schema::{OcsfProfile, SchemaProfile, UdmProfile};

/// NAN-5265: the inventory contract is BARE keys for every profile — the
/// service must not add the `unmapped.` namespace the field panels add, or the
/// sidebar lists (and filters on) `unmapped.unmapped.*`.
#[test]
fn spill_inventory_returns_bare_keys_for_every_profile() {
    let source = include_str!("field_queries.rs");
    assert!(
        !source.contains(&["canonical_dynamic", "_field_name("].concat()),
        "the spill inventory must not re-prefix keys with the column name"
    );
    assert!(source.contains("return Ok(names);"), "spill names pass through bare");
}

#[test]
fn bucket_defaults_to_spill_and_uses_lowercase_wire_names() {
    assert_eq!(DynamicFieldBucket::default(), DynamicFieldBucket::Spill);
    assert_eq!(
        serde_json::from_str::<DynamicFieldBucket>("\"extended\"").unwrap(),
        DynamicFieldBucket::Extended
    );
    assert_eq!(serde_json::to_string(&DynamicFieldBucket::Spill).unwrap(), "\"spill\"");
}

/// The Extended bucket keeps only names a bare query reads back from `event`.
#[test]
fn extended_bucket_keeps_valid_non_promoted_ocsf_attributes_only() {
    let p = OcsfProfile::new();
    let event = p.extended_json_column().expect("OCSF has an extended column");
    for name in ["module.file.company_name", "module.file.hashes", "actor.process.file.name"] {
        assert!(resolves_into_column(&p, name, event), "{name} is a valid non-promoted attribute");
    }
    // Promoted (explicit column) and unknown (would fall into the spill).
    for name in ["src_endpoint.ip", "process.cmd_line", "metadata.log_source", "event_data.utc_time"] {
        assert!(!resolves_into_column(&p, name, event), "{name} must not be listed as Extended");
    }
}

#[test]
fn udm_has_no_extended_column() {
    assert_eq!(UdmProfile::new().extended_json_column(), None);
}

/// The Extended scan reads only the last 15 minutes of the search range — the
/// predicate the service generates carries the clamped bound, not the
/// requested start (a 7-day Sysmon range timed out without it).
#[test]
fn extended_scan_is_clamped_to_the_end_of_the_range() {
    use super::{clamp_extended_scan_range, SearchService};
    use crate::search::TimeRangeInput;
    use chrono::{Duration, TimeZone, Utc};

    assert_eq!(SearchService::EXTENDED_FIELD_NAMES_WINDOW_MINUTES, 15);
    let end = Utc.with_ymd_and_hms(2026, 11, 10, 14, 0, 0).unwrap();
    let week = TimeRangeInput::new(end - Duration::days(7), end);
    let clamped = clamp_extended_scan_range(&week);
    assert_eq!(clamped.start, end - Duration::minutes(15));
    assert_eq!(clamped.end, end);
    let predicate = format!(
        "timestamp BETWEEN '{}' AND '{}'",
        crate::sql_hygiene::format_ch_bound_micros(&clamped.start),
        crate::sql_hygiene::format_ch_bound_micros(&clamped.end),
    );
    assert!(predicate.contains("2026-11-10 13:45:00"), "{predicate}");

    let short = TimeRangeInput::new(end - Duration::minutes(5), end);
    assert_eq!(clamp_extended_scan_range(&short).start, short.start);

    // The service wires the clamp into the Extended predicate.
    let source = include_str!("field_queries.rs");
    assert!(source.contains("Some(tr) if extended =>"));
    assert!(source.contains("clamped = clamp_extended_scan_range(tr);"));
}

/// Filter-then-cap: a valid attribute late in the alphabet survives even when
/// hundreds of non-resolving names sort ahead of it.
#[test]
fn extended_filter_runs_before_the_output_cap() {
    use super::filter_extended_names;
    let p = OcsfProfile::new();
    let mut names: Vec<String> = (0..600).map(|i| format!("aaa_unknown_{i:03}.x")).collect();
    names.push("module.file.company_name".to_string());
    let kept = filter_extended_names(&p, "event", names);
    assert_eq!(kept, vec!["module.file.company_name".to_string()]);

    let many: Vec<String> = (0..600).map(|_| "module.file.company_name".to_string()).collect();
    assert_eq!(filter_extended_names(&p, "event", many).len(), 512);
}
