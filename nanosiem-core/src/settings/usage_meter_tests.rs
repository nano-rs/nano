// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::log_telemetry::repository::{
    build_daily_ingest_sql, build_ingest_meter_start_sql, parse_daily_totals,
    parse_ingest_meter_start,
};
use crate::settings::{MeteredDay, FINAL_HOLD_HOURS};
use chrono::{NaiveDate, TimeZone, Utc};

fn d(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
}

fn total(day: &str, bytes: u64) -> DailyIngestTotal {
    DailyIngestTotal { day: d(day), events: 1, bytes }
}

#[test]
fn window_covers_today_and_five_complete_days() {
    assert_eq!(meter_window(d("2026-11-09")), (d("2026-11-04"), d("2026-11-09")));
}

#[test]
fn the_partly_metered_first_day_is_never_recorded() {
    // The view started at 10:00 on the 6th: the 6th is partial, the 7th on are whole.
    let start = Some(Utc.with_ymd_and_hms(2026, 11, 6, 10, 0, 0).unwrap());
    let totals = vec![total("2026-11-06", 500), total("2026-11-07", 900)];
    let days = days_to_record(&totals, d("2026-11-04"), d("2026-11-09"), start, None);
    assert_eq!(days.iter().map(|t| t.day).collect::<Vec<_>>(), vec![d("2026-11-07"), d("2026-11-08"), d("2026-11-09")]);
    assert_eq!(days[0].bytes, 900);
    assert_eq!(days[1].bytes, 0, "a fully metered day with no ingest is an explicit zero");
}

#[test]
fn nothing_is_recorded_before_the_meter_has_seen_anything() {
    assert!(days_to_record(&[], d("2026-11-04"), d("2026-11-09"), None, None).is_empty());
}

#[test]
fn a_recorded_day_proves_later_days_whole_after_the_rollup_ttl_moves_its_start() {
    // TTL dropped the first hours: the rollup now "starts" on the 8th, but the
    // 5th was already recorded, so the 6th..9th are whole.
    let start = Some(Utc.with_ymd_and_hms(2026, 11, 8, 0, 0, 0).unwrap());
    let days = days_to_record(&[], d("2026-11-04"), d("2026-11-09"), start, Some(d("2026-11-05")));
    assert_eq!(days.first().unwrap().day, d("2026-11-06"));
    assert_eq!(days.len(), 4);
}

#[test]
fn daily_ingest_sql_is_arrival_time_utc_bounded_and_excludes_platform_rows() {
    let sql = build_daily_ingest_sql("nanosiem.ingest_volume_1h", "udm", d("2026-11-04"), d("2026-11-09"));
    assert!(sql.contains("FROM nanosiem.ingest_volume_1h"));
    assert!(sql.contains("toDate(received_hour, 'UTC')"));
    assert!(sql.contains("received_hour >= toDateTime('2026-11-04 00:00:00', 'UTC')"));
    assert!(sql.contains("received_hour < toDateTime('2026-11-10 00:00:00', 'UTC')"));
    assert!(sql.contains("schema_profile = 'udm'"));
    assert!(sql.contains("platform = 0"));
    assert!(!sql.to_uppercase().contains("PREWHERE"));
    assert!(sql.contains("GROUP BY day"));
    let start = build_ingest_meter_start_sql("nanosiem.ingest_volume_1h_distributed", "ocsf");
    assert!(start.contains("min(received_hour)") && start.contains("schema_profile = 'ocsf'"));
}

#[test]
fn parses_totals_and_meter_start() {
    let body = "{\"day\":\"2026-11-08\",\"events\":\"12\",\"bytes\":\"12500000000\"}\nnot json\n{\"day\":\"bad\",\"bytes\":1}\n";
    assert_eq!(parse_daily_totals(body), vec![DailyIngestTotal { day: d("2026-11-08"), events: 12, bytes: 12_500_000_000 }]);
    assert_eq!(
        parse_ingest_meter_start("{\"rows\":\"3\",\"first_hour\":\"2026-11-06 10:00:00\"}\n"),
        Some(Utc.with_ymd_and_hms(2026, 11, 6, 10, 0, 0).unwrap())
    );
    assert_eq!(parse_ingest_meter_start("{\"rows\":\"0\",\"first_hour\":\"1970-01-01 00:00:00\"}\n"), None);
}

#[test]
fn a_day_is_final_only_once_metered_three_hours_past_its_end() {
    let at = |h, m| MeteredDay {
        date: d("2026-11-08"),
        bytes_ingested: 1,
        metered_at: Utc.with_ymd_and_hms(2026, 11, 9, h, m, 0).unwrap(),
    };
    assert_eq!(FINAL_HOLD_HOURS, 3);
    assert!(!at(0, 10).is_final());
    assert!(!at(2, 59).is_final());
    assert!(at(3, 0).is_final());
}
