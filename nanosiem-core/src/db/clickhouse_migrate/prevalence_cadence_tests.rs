// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5345: prevalence refresh cadence rewrite (pure parts).

use super::prevalence_cadence::{
    current_cadence_minutes, plan_view, prevalence_refresh_minutes_from_env, retime_recency_window,
    CadencePlan, WindowRewrite, DEFAULT_CADENCE_MINUTES, PREVALENCE_FINAL_REFRESH_MVS,
    WINDOW_MARGIN_MINUTES,
};

// `as_select` exactly as ClickHouse 26.10 prints the shipped ip view (the
// INTERVAL literal comes back as toIntervalMinute).
const IP_BODY: &str = "SELECT ip, if(uniqMerge(source_host_count) >= 1000, toUInt16(9999), \
toUInt16(least(9998, uniqMerge(source_host_count)))) AS host_count, min(first_seen) AS first_seen, \
max(last_seen) AS last_seen, toUInt64(sum(total_count)) AS total_occurrences, now64(6) AS version \
FROM nanosiem.ip_prevalence_summary_distributed WHERE (is_private = 0) AND (ip GLOBAL IN (SELECT ip \
FROM nanosiem.ip_prevalence_summary_distributed WHERE (is_private = 0) AND (last_seen >= (now64(6) - \
toIntervalMinute(40))))) GROUP BY ip SETTINGS max_memory_usage = 536870912, max_threads = 2, \
max_result_rows = 0, max_result_bytes = 0";

#[test]
fn env_unset_or_empty_is_the_shipped_default() {
    for unset in [None, Some(""), Some("  ")] {
        assert_eq!(prevalence_refresh_minutes_from_env(unset).unwrap(), DEFAULT_CADENCE_MINUTES);
    }
}

#[test]
fn env_accepts_tier_values_and_refuses_the_rest() {
    for m in [10, 30, 60, 1440] {
        assert_eq!(prevalence_refresh_minutes_from_env(Some(&m.to_string())).unwrap(), m);
    }
    for bad in ["0", "5", "9", "1441", "-1", "30m", "1.5"] {
        assert!(prevalence_refresh_minutes_from_env(Some(bad)).is_err(), "{bad}");
    }
}

#[test]
fn window_tracks_cadence_and_keeps_the_rest_of_the_body() {
    let window = 30 + WINDOW_MARGIN_MINUTES;
    let WindowRewrite::Rewrite(new) = retime_recency_window(IP_BODY, window) else {
        panic!("window changes");
    };
    assert_eq!(new, IP_BODY.replace("toIntervalMinute(40)", "toIntervalMinute(60)"));
    // Distributed FROM and the NAN-5262 result-cap settings survive verbatim.
    assert!(new.contains("ip_prevalence_summary_distributed"));
    assert!(new.ends_with("max_result_rows = 0, max_result_bytes = 0"));
    // Idempotent: a body already at the window is left alone.
    assert_eq!(retime_recency_window(&new, window), WindowRewrite::AlreadySet);
    // The shipped pair: cadence 10 restores the 40-minute window.
    assert_eq!(
        retime_recency_window(&new, 10 + WINDOW_MARGIN_MINUTES),
        WindowRewrite::Rewrite(IP_BODY.to_string())
    );
}

#[test]
fn window_is_never_guessed_on_a_foreign_body() {
    assert_eq!(retime_recency_window("SELECT 1", 60), WindowRewrite::Unrecognized);
    assert_eq!(retime_recency_window("", 60), WindowRewrite::Unrecognized);
}

#[test]
fn cadence_parses_from_create_table_query() {
    let create = "CREATE MATERIALIZED VIEW nanosiem.hash_prevalence_final_refresh REFRESH EVERY 10 MINUTE \
                  APPEND TO nanosiem.hash_prevalence_final (`file_hash` String) AS SELECT 1";
    assert_eq!(current_cadence_minutes(create), Some(10));
    assert_eq!(current_cadence_minutes(&create.replace("EVERY 10", "EVERY 30")), Some(30));
    // ClickHouse prints `EVERY 60 MINUTE` back as `EVERY 1 HOUR`.
    assert_eq!(current_cadence_minutes(&create.replace("EVERY 10 MINUTE", "EVERY 1 HOUR")), Some(60));
    assert_eq!(current_cadence_minutes(&create.replace("EVERY 10 MINUTE", "EVERY 1 DAY")), Some(1440));
    assert_eq!(current_cadence_minutes("CREATE VIEW v AS SELECT 1"), None);
}

#[test]
fn covers_the_three_shipped_views() {
    let shipped = include_str!("../../../../clickhouse/160_prevalence_finalized_host_count.sql");
    for mv in PREVALENCE_FINAL_REFRESH_MVS {
        assert!(
            shipped.contains(&format!("nanosiem.{mv}\nREFRESH EVERY 10 MINUTE APPEND")),
            "{mv} is not a shipped 10-minute APPEND view"
        );
    }
}

fn create(every: &str) -> String {
    format!(
        "CREATE MATERIALIZED VIEW nanosiem.ip_prevalence_final_refresh REFRESH EVERY {every} APPEND \
         TO nanosiem.ip_prevalence_final (`ip` String) AS {IP_BODY}"
    )
}

#[test]
fn an_untouched_install_at_the_default_needs_nothing() {
    assert_eq!(plan_view(IP_BODY, &create("10 MINUTE"), DEFAULT_CADENCE_MINUTES), CadencePlan::InPlace);
}

#[test]
fn widening_moves_the_window_before_the_cadence() {
    match plan_view(IP_BODY, &create("10 MINUTE"), 30) {
        CadencePlan::Alter { query: Some(q), refresh: true, refresh_first: false } => {
            assert!(q.contains("toIntervalMinute(60)"), "{q}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn dropping_back_from_a_large_tier_resets_to_the_default() {
    // xlarge left 1 HOUR / 90; the volume is cleared (unset = 10 minutes).
    let body = IP_BODY.replace("toIntervalMinute(40)", "toIntervalMinute(90)");
    match plan_view(&body, &create("1 HOUR"), DEFAULT_CADENCE_MINUTES) {
        CadencePlan::Alter { query: Some(q), refresh: true, refresh_first: true } => {
            assert_eq!(q, IP_BODY, "window restored to 40");
        }
        other => panic!("{other:?}"),
    }
    // large (30 / 60) -> default.
    let body = IP_BODY.replace("toIntervalMinute(40)", "toIntervalMinute(60)");
    assert!(matches!(
        plan_view(&body, &create("30 MINUTE"), DEFAULT_CADENCE_MINUTES),
        CadencePlan::Alter { query: Some(_), refresh: true, refresh_first: true }
    ));
}

#[test]
fn an_unrecognised_window_never_moves_the_cadence() {
    let foreign = "SELECT ip FROM nanosiem.ip_prevalence_summary GROUP BY ip";
    assert_eq!(plan_view(foreign, &create("10 MINUTE"), 60), CadencePlan::Skip);
    assert_eq!(plan_view(foreign, &create("1 HOUR"), DEFAULT_CADENCE_MINUTES), CadencePlan::Skip);
}

#[test]
fn a_window_already_right_only_moves_the_cadence() {
    let body = IP_BODY.replace("toIntervalMinute(40)", "toIntervalMinute(60)");
    assert_eq!(
        plan_view(&body, &create("10 MINUTE"), 30),
        CadencePlan::Alter { query: None, refresh: true, refresh_first: false }
    );
}
