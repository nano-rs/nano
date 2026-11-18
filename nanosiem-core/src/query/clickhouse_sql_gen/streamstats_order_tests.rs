// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5621: `streamstats` runs in ascending event time, deterministically.
//!
//! Hunt pivots (the DNS tunneling candidates' "newest 25 per source", the
//! beacon gap measurements) depend on it: every window function the command
//! emits carries an explicit `ORDER BY <time column>` (ascending), whatever
//! the stage order before it. A `| sort -timestamp` ahead of `streamstats`
//! does not reverse it.

use std::sync::Arc;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, TimeRange};
use crate::schema::OcsfProfile;

fn sql(npl: &str) -> String {
    let range = TimeRange { start: "2026-11-17T00:00:00Z".parse().unwrap(), end: "2026-11-17T06:00:00Z".parse().unwrap() };
    let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl}: {e}"));
    ClickHouseSqlGenerator::with_table("ocsf_logs".to_string())
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&query, &range)
        .unwrap_or_else(|e| panic!("{npl}: {e}"))
}

#[test]
fn streamstats_windows_order_by_the_time_column_ascending() {
    let s = sql(r#"class_uid=4003 | streamstats count AS seq by src_endpoint.ip"#);
    assert!(
        s.contains(r#"count() OVER (PARTITION BY "src_endpoint.ip" ORDER BY timestamp ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS seq"#),
        "{s}"
    );
    assert!(!s.contains("ORDER BY timestamp DESC ROWS"), "ascending, never descending: {s}");
}

#[test]
fn streamstats_previous_value_is_the_previous_event_in_time() {
    let s = sql(r#"class_uid=4003 | streamstats current=false last(timestamp) AS prev_ts by src_endpoint.ip"#);
    assert!(s.contains(r#"OVER (PARTITION BY "src_endpoint.ip" ORDER BY timestamp)"#) && s.contains("lagInFrame("), "{s}");
}

#[test]
fn a_descending_sort_before_streamstats_does_not_reverse_its_order() {
    let s = sql(r#"class_uid=4003 | sort -timestamp | streamstats count AS seq by src_endpoint.ip"#);
    assert!(s.contains(r#"OVER (PARTITION BY "src_endpoint.ip" ORDER BY timestamp ROWS BETWEEN"#), "{s}");
}
