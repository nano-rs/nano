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

    // NAN-5485: only the context-free fallback (no query) clamps the Extended
    // window, and reports the clamp as a partial list. A search's Extended
    // inventory reads its matched rows instead (bounded by a LIMIT).
    let source = include_str!("field_queries.rs");
    assert!(source.contains("Some(tr) if extended && query.is_none() =>"));
    assert!(source.contains("clamped = clamp_extended_scan_range(tr);"));
    assert!(source.contains("DynamicFieldInventory::partial(names, InventoryGap::SampledFallback)"));
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

// ---- NAN-5485: why an inventory or a stats response is partial -------------

mod partial_reasons {
    use super::super::{
        adds_subsearch_rows, creates_fields, mark_pipeline_gaps, DynamicFieldInventory,
        FieldStatsOutcome, InventoryGap,
    };
    use crate::query::parse_query;

    fn complete() -> DynamicFieldInventory {
        DynamicFieldInventory::complete(vec!["k".to_string()])
    }

    #[test]
    fn subsearch_and_join_rows_are_detected_anywhere_in_the_pipeline() {
        let q = |s: &str| parse_query(s).expect("parses");
        assert!(adds_subsearch_rows(&q("source_type=a | append [search source_type=b]")));
        assert!(adds_subsearch_rows(&q("source_type=a | join user [search source_type=b] | head 5")));
        assert!(!adds_subsearch_rows(&q("source_type=a | where x=1 | head 5")));
        assert!(!adds_subsearch_rows(&q("source_type=a")));
    }

    #[test]
    fn field_creating_commands_are_detected_anywhere_in_the_pipeline() {
        let q = |s: &str| parse_query(s).expect("parses");
        for created in [
            "source_type=a | eval tag=\"x\"",
            "source_type=a | rex field=message \"(?<word>\\\\w+)\"",
            "source_type=a | rename user AS who | head 5",
            "source_type=a | head 5 | eval n=1",
        ] {
            assert!(creates_fields(&q(created)), "{created}");
        }
        for plain in ["source_type=a", "source_type=a | where x=1 | sort -timestamp | head 5"] {
            assert!(!creates_fields(&q(plain)), "{plain}");
        }
    }

    #[test]
    fn pipeline_gaps_mark_a_complete_list_with_the_first_applicable_reason() {
        let none = mark_pipeline_gaps(complete(), false, false);
        assert!(!none.partial && none.reason.is_none());

        let sub = mark_pipeline_gaps(complete(), true, true);
        assert!(sub.partial);
        assert_eq!(sub.reason, Some(InventoryGap::SubsearchRowsNotScanned));

        let derived = mark_pipeline_gaps(complete(), false, true);
        assert_eq!(derived.reason, Some(InventoryGap::DerivedFieldsNotListed));

        // A list already partial keeps its own, more specific reason.
        let mut capped = complete();
        capped.partial = true;
        capped.reason = Some(InventoryGap::RowLimit);
        assert_eq!(mark_pipeline_gaps(capped, true, true).reason, Some(InventoryGap::RowLimit));
    }

    #[test]
    fn stats_partial_reason_is_the_cap_then_dropped_columns() {
        let at_cap = FieldStatsOutcome { rows_examined: Some(100_000), row_cap: Some(100_000), ..Default::default() };
        assert!(at_cap.sampled());
        assert_eq!(at_cap.partial_reason(), Some("row_cap"));

        let dropped = FieldStatsOutcome {
            rows_examined: Some(10),
            row_cap: Some(100_000),
            columns_dropped: true,
            ..Default::default()
        };
        assert!(!dropped.sampled());
        assert_eq!(dropped.partial_reason(), Some("columns_dropped"));

        let full = FieldStatsOutcome { rows_examined: Some(10), row_cap: Some(100_000), ..Default::default() };
        assert_eq!(full.partial_reason(), None);
        assert_eq!(FieldStatsOutcome::default().partial_reason(), None);
    }

    #[test]
    fn gaps_serialize_as_snake_case_wire_names() {
        for (gap, wire) in [
            (InventoryGap::RowLimit, "row_limit"),
            (InventoryGap::OutputCap, "output_cap"),
            (InventoryGap::ScanFailed, "scan_failed"),
            (InventoryGap::QueryNotScanned, "query_not_scanned"),
            (InventoryGap::SubsearchRowsNotScanned, "subsearch_rows_not_scanned"),
            (InventoryGap::SampledFallback, "sampled_fallback"),
            (InventoryGap::DerivedFieldsNotListed, "derived_fields_not_listed"),
            (InventoryGap::DatasetNotSupported, "dataset_not_supported"),
        ] {
            assert_eq!(serde_json::to_string(&gap).unwrap(), format!("\"{wire}\""));
        }
    }

    /// Spans, metrics and risk searches have no on-demand JSON inventory: the
    /// answer is partial `dataset_not_supported`, never the log keys as if
    /// complete. No ClickHouse is touched (the service cannot connect).
    #[tokio::test]
    async fn non_log_datasets_are_partial_not_supported() {
        let svc = super::super::super::npl_golden_corpus_tests::sql_only_service("ocsf");
        let range = crate::TimeRangeInput::new(chrono::Utc::now() - chrono::Duration::hours(1), chrono::Utc::now());
        for dataset in ["spans", "metrics", "risk"] {
            let inv = svc
                .get_dynamic_field_inventory_with_admission(
                    super::super::DynamicFieldBucket::Spill,
                    Some("x=1"),
                    Some(&range),
                    None,
                    uuid::Uuid::nil(),
                    crate::search::QueryPriority::Interactive,
                    Some(dataset),
                    &crate::auth::ScopeSet::unrestricted(),
                )
                .await
                .expect("answers without a scan");
            assert!(inv.partial && inv.names.is_empty(), "{dataset}: {inv:?}");
            assert_eq!(inv.reason, Some(InventoryGap::DatasetNotSupported), "{dataset}");
        }
    }

    /// An `earliest=` that empties the window is never scanned as the
    /// picker's window: the list is partial `query_not_scanned`.
    #[tokio::test]
    async fn an_unusable_in_query_window_is_not_scanned_as_the_picker_window() {
        let svc = super::super::super::npl_golden_corpus_tests::sql_only_service("ocsf");
        let end = chrono::Utc::now() - chrono::Duration::days(30);
        let range = crate::TimeRangeInput::new(end - chrono::Duration::hours(1), end);
        let inv = svc
            .get_dynamic_field_inventory_with_admission(
                super::super::DynamicFieldBucket::Spill,
                Some("x=1 earliest=-15m"),
                Some(&range),
                None,
                uuid::Uuid::nil(),
                crate::search::QueryPriority::Interactive,
                None,
                &crate::auth::ScopeSet::unrestricted(),
            )
            .await
            .expect("answers without a scan");
        assert_eq!(inv.reason, Some(InventoryGap::QueryNotScanned), "{inv:?}");
    }
}
