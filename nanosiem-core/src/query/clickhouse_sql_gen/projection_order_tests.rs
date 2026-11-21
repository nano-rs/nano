// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5703: a trailing `table` / `fields` / `rename` over raw events keeps
//! the newest-first order. Without a final `ORDER BY <time> DESC`, page 1 was
//! any N rows and `OFFSET` pages overlapped or skipped events (and the daily
//! chunks of the stream disagreed with one query).

use std::sync::Arc;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, QueryOptions, TimeRange};
use crate::schema::OcsfProfile;

fn range() -> TimeRange {
    TimeRange { start: "2026-10-08T00:00:00Z".parse().unwrap(), end: "2026-10-09T00:00:00Z".parse().unwrap() }
}

fn sql(npl: &str, unordered: bool) -> String {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
    let options = QueryOptions { use_cache: false, table_view: true, limit: Some(50), unordered, omit_settings: true };
    ClickHouseSqlGenerator::new()
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate_with_options(&q, &range(), &options)
        .unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

/// The final statement (after the last CTE).
fn tail(sql: &str) -> &str {
    sql.rsplit("\n)").next().unwrap_or(sql)
}

#[test]
fn a_trailing_reshape_keeps_the_newest_first_order() {
    for npl in [
        "* | table timestamp, actor.user.name",
        "* | table actor.user.name, traffic.bytes_in",
        "* | table actor.user.name as who",
        "* | fields actor.user.name",
        "* | fields - message",
        "* | rename actor.user.name as who",
        "* | where traffic.bytes_in > 5 | rename actor.user.name as who | table who",
    ] {
        let s = sql(npl, false);
        assert!(tail(&s).contains("ORDER BY timestamp DESC LIMIT 50"), "{npl}: {s}");
        assert!(!s.contains("PREWHERE"), "{npl}: no explicit PREWHERE");
    }
}

/// The time key itself was renamed away, re-aliased or dropped: there is no
/// column left to order by, so no ORDER BY is invented (it would not resolve).
#[test]
fn a_reshape_of_the_time_key_adds_no_order() {
    for npl in [
        "* | rename timestamp as t",
        "* | fields - timestamp",
        "* | table bytes_in as timestamp",
    ] {
        let s = sql(npl, false);
        assert!(!tail(&s).contains("ORDER BY timestamp"), "{npl}: {s}");
    }
}

/// Aggregates keep their own order, and the count companion stays unordered.
#[test]
fn aggregates_and_unordered_companions_are_unchanged() {
    let s = sql("* | stats count by actor.user.name | rename actor.user.name as who", false);
    assert!(!tail(&s).contains("ORDER BY timestamp"), "{s}");
    let s = sql("* | table actor.user.name", true);
    assert!(!s.contains("ORDER BY timestamp"), "{s}");
}
