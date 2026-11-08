// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-4903 bench support: renders the hunt queries in
//! `nanosiem-core/tests/fixtures/ocsf-bench/queries.tsv` through the
//! OCSF-profiled SQL generator, so
//! the bench measures exactly the SQL search would send (single WHERE with the
//! time bounds, `lower()` index forms, `has()` on arrays, JSON subcolumns).
//! `{T}` stands for the table; `scripts/ocsf-bench/bench.py` substitutes it.
//!
//! ```text
//! BENCH_END=2026-11-03T04:35:00Z BENCH_SQL_OUT=/tmp/bench_sql.txt \
//!   cargo test -p nanosiem-core --test ocsf_bench_sql -- --ignored
//! ```
//!
//! `BENCH_HINTS=1` renders as for a table whose `event` carries every
//! `json_hints.json` path (the typed-subcolumn form), for the hinted layouts.
//! `BENCH_REDERIVE=1` renders the pre-NAN-4934 form, where later stages
//! re-derive `event` fields instead of reading the stage_0 alias.

// The query list lives under tests/fixtures (not scripts/) because the
// open-core mirror strips scripts/, and include_str! of a stripped path
// breaks the mirror build.

use std::sync::Arc;

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::OcsfProfile;

const QUERIES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ocsf-bench/queries.tsv"
));

#[test]
#[ignore = "bench support: writes BENCH_SQL_OUT (see module docs)"]
fn render_ocsf_bench_sql() {
    let end: chrono::DateTime<chrono::Utc> = std::env::var("BENCH_END")
        .expect("BENCH_END (RFC3339)")
        .parse()
        .expect("BENCH_END must be RFC3339");
    let mut out = String::new();
    for line in QUERIES.lines().filter(|l| !l.trim().is_empty()) {
        let mut cols = line.splitn(3, '\t');
        let (name, days, npl) = (
            cols.next().unwrap(),
            cols.next().unwrap().parse::<i64>().expect("window days"),
            cols.next().unwrap(),
        );
        // RAW rows are hand-written in bench.py (nPL has no ARRAY JOIN).
        if npl == "RAW" {
            continue;
        }
        let range = TimeRange {
            start: end - chrono::Duration::days(days),
            end,
        };
        let mut gen = ClickHouseSqlGenerator::with_table("{T}".to_string())
            .with_profile(Arc::new(OcsfProfile::new()));
        if std::env::var("BENCH_REDERIVE").is_ok() {
            gen = gen.with_tail_field_rederivation();
        }
        let query = parse_query(npl).unwrap_or_else(|e| panic!("{name}: {e}"));
        let render = || gen.generate(&query, &range).unwrap_or_else(|e| panic!("{name}: {e}"));
        let sql = if std::env::var("BENCH_HINTS").is_ok() {
            nanosiem_core::schema::with_event_json_hints(
                &nanosiem_core::schema::manifest_event_json_hints(),
                render,
            )
        } else {
            render()
        };
        out.push_str(&format!("-- {name}\n{sql}\n;;\n"));
    }
    std::fs::write(std::env::var("BENCH_SQL_OUT").expect("BENCH_SQL_OUT"), out).unwrap();
}
