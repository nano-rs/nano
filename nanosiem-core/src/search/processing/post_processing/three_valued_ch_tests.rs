// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4902 (lane I review, P1): the post-stage evaluator (`where` / `eval`
//! after `| prevalence`, `| risk`, …) follows SQL three-valued logic exactly as
//! ClickHouse does. Differential: each predicate / expression runs through the
//! Rust post-processing path on JSON rows and as SQL on ClickHouse over the
//! same rows (every true/false/NULL combination of two Nullable booleans plus a
//! Nullable string), and the answers must agree row for row.
//!
//! SELECT-only (a `values()` table function); no schema or data is written.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --lib three_valued_ch_tests -- --ignored
//! ```

use super::apply_post_prevalence_commands;
use crate::query::{parse_query, Command, Query};
use serde_json::{json, Value};

fn ch() -> clickhouse::Client {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    // Shared transport: pins LZ4 (raw clients fail against CH 26.9+).
    let mut client = crate::db::clickhouse_transport::client().with_url(url);
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        client = client.with_password(password);
    }
    client
}

const TRI: [Option<bool>; 3] = [Some(true), Some(false), None];

/// (row_id, a, b, s): all nine (a, b) combinations, `s` NULL on every third row.
fn fixture() -> Vec<(u32, Option<bool>, Option<bool>, Option<&'static str>)> {
    let mut rows = Vec::new();
    for (i, a) in TRI.iter().enumerate() {
        for (j, b) in TRI.iter().enumerate() {
            let id = (i * 3 + j) as u32;
            let s = [Some("abcdef"), Some("x"), None][j];
            rows.push((id, *a, *b, s));
        }
    }
    rows
}

fn json_rows() -> Vec<Value> {
    fixture()
        .into_iter()
        .map(|(id, a, b, s)| json!({"row_id": id, "a": a, "b": b, "s": s}))
        .collect()
}

/// The same rows as a ClickHouse `values()` table.
fn ch_source() -> String {
    let lit = |v: Option<bool>| v.map_or("NULL".to_string(), |b| (b as u8).to_string());
    let tuples: Vec<String> = fixture()
        .into_iter()
        .map(|(id, a, b, s)| {
            format!("({id}, {}, {}, {})", lit(a), lit(b), s.map_or("NULL".to_string(), |s| format!("'{s}'")))
        })
        .collect();
    format!(
        "values('row_id UInt32, a Nullable(UInt8), b Nullable(UInt8), s Nullable(String)', {})",
        tuples.join(", ")
    )
}

fn pipeline(npl: &str) -> Vec<Command> {
    fn collect(q: &Query, out: &mut Vec<Command>) {
        if let Query::Piped { source, command } = q {
            collect(source, out);
            out.push(command.clone());
        }
    }
    let mut out = Vec::new();
    collect(&parse_query(npl).unwrap_or_else(|e| panic!("{npl}: {e}")), &mut out);
    out
}

fn rust_ids(npl: &str) -> Vec<u32> {
    let rows = apply_post_prevalence_commands(json_rows(), &pipeline(npl)).unwrap().results;
    let mut ids: Vec<u32> = rows.iter().map(|r| r["row_id"].as_u64().unwrap() as u32).collect();
    ids.sort();
    ids
}

async fn ch_ids(ch: &clickhouse::Client, where_sql: &str) -> Vec<u32> {
    ch.query(&format!("SELECT row_id FROM {} WHERE {where_sql} ORDER BY row_id", ch_source()))
        .fetch_all::<u32>()
        .await
        .unwrap_or_else(|e| panic!("{where_sql}: {e}"))
}

#[derive(Debug, clickhouse::Row, serde::Deserialize)]
struct Cell {
    row_id: u32,
    k: Option<f64>,
}

/// `eval k=<expr>` per row: `Some(1.0)` / `Some(0.0)` for booleans, the number
/// otherwise, `None` for NULL. An explicit JSON null must be written.
fn rust_eval(expr: &str) -> Vec<(u32, Option<f64>)> {
    let rows = apply_post_prevalence_commands(json_rows(), &pipeline(&format!("* | eval k={expr}")))
        .unwrap()
        .results;
    rows.iter()
        .map(|r| {
            let k = r.get("k").unwrap_or_else(|| panic!("eval k={expr} wrote no value: {r}"));
            let k = match k {
                Value::Bool(b) => Some(u8::from(*b) as f64),
                Value::Null => None,
                other => Some(other.as_f64().unwrap()),
            };
            (r["row_id"].as_u64().unwrap() as u32, k)
        })
        .collect()
}

async fn ch_eval(ch: &clickhouse::Client, sql: &str) -> Vec<(u32, Option<f64>)> {
    ch.query(&format!(
        "SELECT row_id, CAST(({sql}) AS Nullable(Float64)) AS k FROM {} ORDER BY row_id",
        ch_source()
    ))
    .fetch_all::<Cell>()
    .await
    .unwrap_or_else(|e| panic!("{sql}: {e}"))
    .into_iter()
    .map(|c| (c.row_id, c.k))
    .collect()
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn where_predicates_after_a_post_stage_match_clickhouse() {
    let ch = ch();
    // (nPL `where` predicate, the ClickHouse SQL it means)
    let cases = [
        ("a=true", "a = 1"),
        ("NOT a=true", "NOT (a = 1)"),
        ("a!=true", "a != 1"),
        ("a=true AND b=true", "a = 1 AND b = 1"),
        ("a=true OR b=true", "a = 1 OR b = 1"),
        ("NOT (a=true AND b=true)", "NOT (a = 1 AND b = 1)"),
        ("NOT (a=true OR b=true)", "NOT (a = 1 OR b = 1)"),
        ("a=true OR NOT b=true", "a = 1 OR NOT (b = 1)"),
        ("NOT a=true AND NOT b=true", "NOT (a = 1) AND NOT (b = 1)"),
        (r#"s IN ("x")"#, "s IN ('x')"),
        (r#"NOT s IN ("x")"#, "NOT (s IN ('x'))"),
        (r#"s="x" OR NOT a=true"#, "s = 'x' OR NOT (a = 1)"),
        ("len(s) > 2", "length(s) > 2"),
        ("NOT len(s) > 2", "NOT (length(s) > 2)"),
        ("NOT len(s) > 2 OR a=true", "NOT (length(s) > 2) OR a = 1"),
        ("isnull(s)", "isNull(s)"),
        ("NOT isnull(s)", "NOT isNull(s)"),
    ];
    let mut failures = Vec::new();
    for (npl, sql) in cases {
        let rust = rust_ids(&format!("* | where {npl}"));
        let oracle = ch_ids(&ch, sql).await;
        if rust != oracle {
            failures.push(format!("where {npl}: rust {rust:?} vs clickhouse {oracle:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn eval_assignments_after_a_post_stage_match_clickhouse() {
    let ch = ch();
    // (nPL eval expression, the ClickHouse SQL it means)
    let cases = [
        ("NOT a", "NOT a"),
        ("NOT NOT a", "NOT (NOT a)"),
        ("a AND b", "a AND b"),
        ("a OR b", "a OR b"),
        ("a OR NOT b", "a OR NOT b"),
        ("NOT a AND b", "(NOT a) AND b"),
        ("NOT (a AND b)", "NOT (a AND b)"),
        ("NOT (a OR b)", "NOT (a OR b)"),
        ("a = b", "a = b"),
        ("if(a, 1, 0)", "if(a, 1, 0)"),
        ("if(NOT a, 1, 0)", "if(NOT a, 1, 0)"),
        ("len(s) > 2 OR a", "(length(s) > 2) OR a"),
    ];
    let mut failures = Vec::new();
    for (npl, sql) in cases {
        let rust = rust_eval(npl);
        let oracle = ch_eval(&ch, sql).await;
        if rust != oracle {
            failures.push(format!("eval k={npl}:\n  rust       {rust:?}\n  clickhouse {oracle:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // A NULL eval result is a value a later `where` reads, not a skipped write:
    // `true OR NOT <null>` keeps the row, as in SQL.
    let rust = rust_ids("* | eval keep=(a OR NOT b) | where keep=true");
    let oracle = ch_ids(&ch, "a OR NOT b").await;
    assert_eq!(rust, oracle, "eval keep=(a OR NOT b) | where keep=true");
}
