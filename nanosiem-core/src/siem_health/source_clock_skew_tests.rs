// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::siem_health::analyzer::fallback_report;
use crate::siem_health::analyzer::tests::base_zero_metrics_fixture;

fn analysis() -> AnalysisResult {
    fallback_report(&base_zero_metrics_fixture())
}

fn row(source_type: &str, tz: &str, events: u64, gap: i64) -> SkewRow {
    SkewRow {
        source_type: source_type.into(),
        assumed_tz: tz.into(),
        events,
        median_gap_secs: gap,
    }
}

fn skew_findings(a: &AnalysisResult) -> Vec<&Recommendation> {
    a.recommendations
        .iter()
        .filter(|r| r.title.starts_with(CLOCK_SKEW_TITLE_PREFIX))
        .collect()
}

#[test]
fn the_query_is_bounded_and_follows_the_clickhouse_rules() {
    let sql = skew_query(false, &ScopeSet::unrestricted());
    assert!(sql.contains("FROM nanosiem.ocsf_logs WHERE") || sql.contains("FROM nanosiem.logs WHERE"), "{sql}");
    assert!(!sql.to_uppercase().contains("PREWHERE"), "{sql}");
    assert_eq!(sql.matches(" WHERE ").count(), 1, "a single WHERE: {sql}");
    // Time-bounded on the partition column, both sides.
    assert!(sql.contains("WHERE timestamp >= now() - INTERVAL 17 HOUR AND timestamp <= now() + INTERVAL 15 HOUR"), "{sql}");
    assert!(sql.contains("_inserted_at >= now() - INTERVAL 2 HOUR"), "{sql}");
    assert!(sql.contains("isNotNull(unmapped.nano_time_assumed_tz)"), "{sql}");
    assert!(sql.contains("LIMIT 200"), "{sql}");
    assert!(sql.contains("max_execution_time"), "{sql}");
    assert!(sql.contains("source_type != ''"), "{sql}");
    assert!(!sql.contains("JSONExtract"), "{sql}");
}

#[test]
fn whole_half_and_three_quarter_hour_gaps_are_offsets() {
    assert_eq!(offset_for_gap(-5 * 3600), Some(-5 * 3600));
    // Normal ingest latency makes the gap slightly more negative.
    assert_eq!(offset_for_gap(-5 * 3600 - 90), Some(-5 * 3600));
    assert_eq!(offset_for_gap(-5 * 3600 + 240), Some(-5 * 3600));
    assert_eq!(offset_for_gap(19_800), Some(19_800)); // +05:30
    assert_eq!(offset_for_gap(20_700 + 60), Some(20_700)); // +05:45
    assert_eq!(offset_for_gap(-1800), Some(-1800));
    assert_eq!(offset_for_gap(14 * 3600), Some(14 * 3600));
}

#[test]
fn small_odd_or_impossible_gaps_are_not() {
    for gap in [
        0,
        -60,
        -1200,            // 20 min: under 30
        -5 * 3600 - 600,  // 10 min off a whole hour
        3600 + 15 * 60,   // a :15 offset does not exist
        15 * 3600,        // beyond +14:00
        -3 * 3600 - 420,  // 7 min off
    ] {
        assert_eq!(offset_for_gap(gap), None, "{gap}");
    }
}

#[test]
fn offsets_format_like_the_timezone_setting() {
    assert_eq!(format_offset(-18_000), "-05:00");
    assert_eq!(format_offset(19_800), "+05:30");
    assert_eq!(format_offset(20_700), "+05:45");
    assert_eq!(format_hours(-18_000), "5");
    assert_eq!(format_hours(19_800), "5.5");
    assert_eq!(format_hours(20_700), "5.75");
}

/// The acceptance criterion: no setting, devices 5 hours off, a finding.
#[test]
fn a_utc_source_five_hours_off_raises_a_finding() {
    let mut a = analysis();
    let names = HashMap::from([("pan_fw".to_string(), "Palo Alto edge".to_string())]);
    let rows = [row("pan_fw", "UTC", 500, -5 * 3600 - 45)];
    ensure_clock_skew_findings(&mut a, &rows, &names);
    ensure_clock_skew_findings(&mut a, &rows, &names);
    let found = skew_findings(&a);
    assert_eq!(found.len(), 1, "idempotent");
    assert_eq!(found[0].title, "Events from Palo Alto edge look 5 h off; set its timezone");
    assert_eq!(found[0].priority, "medium");
    let d = &found[0].description;
    assert!(d.contains("source type `pan_fw`"), "{d}");
    assert!(d.contains("5 h behind"), "{d}");
    assert!(d.contains("set Timezone to `-05:00`"), "{d}");
    assert!(d.contains("America/New_York"), "{d}");
    assert!(d.contains("500 events"), "{d}");
}

#[test]
fn a_device_ahead_of_utc_suggests_a_positive_offset() {
    let mut a = analysis();
    ensure_clock_skew_findings(&mut a, &[row("fortigate", "UTC", 40, 19_800 + 30)], &HashMap::new());
    let found = skew_findings(&a);
    assert_eq!(found[0].title, "Events from fortigate look 5.5 h off; set its timezone");
    assert!(found[0].description.contains("ahead of"), "{}", found[0].description);
    // A fractional offset only one zone uses: the IANA zone (DST-correct).
    assert!(found[0].description.contains("set Timezone to `Asia/Kolkata`"), "{}", found[0].description);
    // No "(source type ...)" when the name is the route key itself.
    assert!(!found[0].description.contains("source type"), "{}", found[0].description);
}

#[test]
fn a_wrong_setting_is_flagged_with_the_corrected_offset() {
    // Set to a fixed -05:00 zone while the device is really at -06:00: 09:00
    // local is read as 14:00 UTC instead of 15:00, an hour behind.
    let mut a = analysis();
    ensure_clock_skew_findings(&mut a, &[row("asa", "Etc/GMT+5", 100, -3600)], &HashMap::new());
    let found = skew_findings(&a);
    assert_eq!(found[0].title, "Events from asa look 1 h off; check its timezone");
    assert!(found[0].description.contains("`-06:00`"), "{}", found[0].description);
    assert!(found[0].description.contains("Etc/GMT+5, the log source's timezone setting"));
}

#[test]
fn correct_quiet_or_noisy_sources_raise_nothing() {
    let mut a = analysis();
    let rows = [
        row("ok_utc", "UTC", 1000, -20),               // correct clock, normal latency
        row("ok_ny", "America/New_York", 1000, -40),   // setting already right
        row("few", "UTC", MIN_EVENTS - 1, -5 * 3600),  // too few events
        row("jitter", "UTC", 1000, -2 * 3600 - 1200),  // 20 min off a whole hour
        row("", "UTC", 1000, -5 * 3600),               // no source identity
    ];
    ensure_clock_skew_findings(&mut a, &rows, &HashMap::new());
    assert!(skew_findings(&a).is_empty(), "{:?}", skew_findings(&a));
}

#[test]
fn one_finding_per_source_busiest_zone_wins_worst_first() {
    let rows = [
        row("syslog", "UTC", 50, -3 * 3600),
        row("syslog", "Europe/Berlin", 500, -3600 * 2),
        row("pan_fw", "UTC", 100, -8 * 3600),
    ];
    let found = skewed_sources(&rows, &HashMap::new());
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].source_type, "pan_fw", "largest skew first");
    assert_eq!(found[1].assumed_tz, "Europe/Berlin", "busiest zone for the source");
}

#[test]
fn the_title_signature_is_stable_across_the_hours() {
    use crate::siem_health::finding_signature::signature_for_title;
    let a = finding_title(&skewed_sources(&[row("x", "UTC", 99, -5 * 3600)], &HashMap::new())[0]);
    let b = finding_title(&skewed_sources(&[row("x", "UTC", 99, -6 * 3600)], &HashMap::new())[0]);
    assert_ne!(a, b);
    assert_eq!(signature_for_title(&a), signature_for_title(&b), "a suppression survives a changed offset");
}

fn only(rows: &[SkewRow]) -> ClockSkew {
    let found = skewed_sources(rows, &HashMap::new());
    assert_eq!(found.len(), 1, "{found:?}");
    found[0].clone()
}

fn description(rows: &[SkewRow]) -> String {
    let mut a = analysis();
    ensure_clock_skew_findings(&mut a, rows, &HashMap::new());
    skew_findings(&a)[0].description.clone()
}

/// Review P1: parsers#87 records a fixed-offset setting verbatim (`-05:00`),
/// reading the clock as UTC and shifting it. A device really at -06:00 on a
/// source set to -05:00 is an hour behind: recommend -06:00, not -01:00.
#[test]
fn fixed_offset_sources_use_the_offset_as_the_base() {
    let skew = only(&[row("asa", "-05:00", 100, -3600)]);
    assert_eq!(skew.device_offset_secs, -6 * 3600);
    let d = description(&[row("asa", "-05:00", 100, -3600)]);
    assert!(d.contains("set Timezone to `-06:00`"), "{d}");
    assert!(d.contains("America/Chicago"), "an IANA example for a DST device: {d}");

    // DST moved the device to -04:00 while the setting stays -05:00.
    assert_eq!(only(&[row("asa", "-05:00", 100, 3600)]).device_offset_secs, -4 * 3600);
    // +05:30 set, device at +06:30.
    let d = description(&[row("fw", "+05:30", 100, 3600)]);
    assert!(d.contains("set Timezone to `Asia/Yangon`"), "{d}");
}

#[test]
fn iana_sources_use_the_zone_offset_now_as_the_base() {
    let base = zone_offset_now("America/New_York").expect("known zone");
    assert!(base == -5 * 3600 || base == -4 * 3600);
    let skew = only(&[row("pan", "America/New_York", 100, -3600)]);
    assert_eq!(skew.device_offset_secs, base - 3600);
    let d = description(&[row("pan", "America/New_York", 100, -3600)]);
    assert!(d.contains(&format!("set Timezone to `{}`", format_offset(base - 3600))), "{d}");
}

/// Review P2: only values the API accepts (and the picker lists).
#[test]
fn every_recommendation_passes_the_api_validator() {
    for offset in (-14 * 4..=15 * 4).map(|q| q * 900) {
        if let Some(setting) = recommended_setting(offset) {
            assert_eq!(
                crate::timezone::normalize_source_timezone(&setting).as_deref(),
                Ok(setting.as_str()),
                "{offset}: {setting}"
            );
        }
    }
    assert_eq!(recommended_setting(0).as_deref(), Some("UTC"));
    assert_eq!(recommended_setting(12_600).as_deref(), Some("Asia/Tehran"));
    assert_eq!(recommended_setting(-12_600).as_deref(), Some("America/St_Johns"));
    assert_eq!(recommended_setting(-5 * 3600).as_deref(), Some("-05:00"));
    assert_eq!(recommended_setting(5400), None, "+01:30 is no zone");
    assert_eq!(recommended_setting(-14 * 3600), None, "below -12:00");
    assert_eq!(recommended_setting(15 * 3600), None, "above +14:00");
}

#[test]
fn a_utc_device_set_to_a_zone_is_told_utc_and_impossible_offsets_are_not_recommended() {
    // A UTC device configured as Etc/GMT+5 (-05:00) reads 5 h ahead.
    let d = description(&[row("x", "Etc/GMT+5", 100, 5 * 3600)]);
    assert!(d.contains("set Timezone to `UTC`"), "{d}");
    // Set to -08:00 and 6 h behind: -14:00 is not a real offset.
    let d = description(&[row("y", "-08:00", 100, -6 * 3600)]);
    assert!(!d.contains("set Timezone to"), "{d}");
    assert!(d.contains("not a real UTC offset"), "{d}");
}
