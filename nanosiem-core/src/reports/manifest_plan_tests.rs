// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5039: a report's source manifest is derived from the query PLAN (one
//! companion per scan), never from row values the query itself can write.

use super::report_companion_queries;

#[test]
fn a_forged_row_source_type_does_not_change_the_companion() {
    // Exploit shape: every row carries source_type="syslog" whatever it came
    // from. The companion scans the leading search itself.
    let q = r#"index=* | eval source_type="syslog" | table user, source_type"#;
    let companions = report_companion_queries(q).expect("companionable");
    assert_eq!(companions.len(), 1);
    assert!(companions[0].ends_with("| stats count by source_type"), "{companions:?}");
    assert!(!companions[0].contains("eval"), "the companion must scan BEFORE projection");
}

#[test]
fn every_join_and_append_scan_gets_its_own_companion() {
    let q = r#"src_ip=* | join src_ip [ search source_type=hr_payroll ] | append [ search error ]"#;
    let companions = report_companion_queries(q).expect("companionable");
    assert_eq!(companions.len(), 3, "{companions:?}");
    assert!(companions.iter().any(|c| c.contains("hr_payroll")));
}

#[test]
fn scans_no_companion_can_express_make_the_manifest_incomplete() {
    for q in [
        "user=bob | lateral",
        "src_ip=* | asset",
        "src_ip IN [ search source_type=hr_payroll | fields src_ip ]",
        "* | where src_ip IN [ search error | fields src_ip ]",
        "not nPL ((( at all",
    ] {
        assert!(report_companion_queries(q).is_none(), "{q} must be incomplete");
    }
}

#[test]
fn ordinary_aggregate_reports_stay_companionable() {
    for q in [
        "error | stats count by src_ip",
        "action=login status=failure | timechart span=1h count",
        "* | stats count by user | sort -count | head 10",
    ] {
        let companions = report_companion_queries(q).unwrap_or_else(|| panic!("{q}"));
        assert_eq!(companions.len(), 1, "{q}");
    }
}
