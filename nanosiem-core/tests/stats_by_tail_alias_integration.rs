// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-4934: later pipeline stages read the `event` tail alias stage_0 already
//! computed instead of re-deriving the value from the whole `event` JSON.
//!
//! Before, `* | stats count by actor.process.file.name` projected the value in
//! stage_0 and then grouped stage_1 by the full `multiIf(… event …)` again, so
//! `event` was passed through and read in full (bench: 1,989 → 71 MiB read).
//!
//! This runs every query twice on real ClickHouse, as generated now and in the
//! pre-NAN-4934 form (`with_tail_field_rederivation`), on an unhinted table and
//! on a table whose `event` carries the `json_hints.json` type hints (generated
//! with those hints live, as boot detection would find them). Results must be
//! identical in all four cells. The data holds mixed-case strings, explicit
//! JSON nulls, absent paths, object-valued producer violations and a numeric
//! `unmapped` field, across stats / timechart / top / rare / dedup / where /
//! eval / sort and an IN-subsearch in a later stage.
//!
//! Requires a ClickHouse with DDL rights (CLICKHOUSE_TEST_URL, default
//! http://localhost:8123; CLICKHOUSE_ADMIN_USER / CLICKHOUSE_ADMIN_PASSWORD).
//! Skips cleanly when unreachable or when `SKIP_DB_TESTS` is set.
//!   cargo test -p nanosiem-core --test stats_by_tail_alias_integration -- --nocapture

use std::sync::Arc;

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::{FieldResolution, OcsfProfile, SchemaProfile};

const JSON_HINTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/ocsf/events/json_hints.json"
));

/// Hinted `event` paths (in `json_hints.json`).
const HINTED: [&str; 2] = ["actor.process.file.name", "dst_endpoint.svc_name"];
/// Unhinted, unpromoted `event` paths.
const UNHINTED: [&str; 2] = ["actor.session.uid", "device.os.name"];

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}
fn ch_user() -> String {
    std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or_else(|_| "nanosiem_admin".into())
}
fn ch_pass() -> String {
    std::env::var("CLICKHOUSE_ADMIN_PASSWORD").unwrap_or_else(|_| "nanosiem_admin_secret".into())
}

async fn exec(client: &reqwest::Client, sql: &str) -> Result<String, String> {
    let resp = client
        .post(format!("{}/?enable_full_text_index=1", ch_url()))
        .basic_auth(ch_user(), Some(ch_pass()))
        .body(sql.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("HTTP {status}: {body}"))
    }
}

/// JSONEachRow insert: statement in the URL, rows in the body.
async fn insert(client: &reqwest::Client, table: &str, rows: &str) {
    let stmt = format!("INSERT INTO {table} FORMAT JSONEachRow").replace(' ', "%20");
    let url = format!(
        "{}/?query={stmt}&async_insert=0&wait_end_of_query=1&date_time_input_format=best_effort",
        ch_url()
    );
    let resp = client
        .post(url)
        .basic_auth(ch_user(), Some(ch_pass()))
        .body(rows.to_string())
        .send()
        .await
        .expect("insert request");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "insert into {table} failed: {body}");
}

fn window() -> TimeRange {
    let end = chrono::Utc::now() + chrono::Duration::hours(1);
    TimeRange {
        start: end - chrono::Duration::days(1),
        end,
    }
}

/// Set `path` (dotted) in a JSON object, creating parents.
fn put(obj: &mut serde_json::Value, path: &str, v: serde_json::Value) {
    let segs: Vec<&str> = path.split('.').collect();
    let mut cur = obj;
    for s in &segs[..segs.len() - 1] {
        cur = cur
            .as_object_mut()
            .unwrap()
            .entry(s.to_string())
            .or_insert_with(|| serde_json::json!({}));
    }
    cur.as_object_mut().unwrap().insert(segs[segs.len() - 1].to_string(), v);
}

/// Rows compared as a sorted multiset: an ORDER BY over tied keys may emit ties
/// in any order, which is not a result difference.
fn normalized(body: &str) -> Vec<String> {
    let mut lines: Vec<String> = body.lines().map(str::to_string).collect();
    lines.sort();
    lines
}

#[tokio::test]
async fn later_stages_read_the_stage0_tail_alias_with_identical_results() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return;
    }
    let client = reqwest::Client::new();
    if exec(&client, "SELECT 1").await.map(|b| b.trim() == "1") != Ok(true) {
        eprintln!("Skipping: ClickHouse not reachable at {}", ch_url());
        return;
    }

    // The paths really are what the test claims: unpromoted `event` tails, two
    // of them hinted, plus a numeric tail field in `unmapped`.
    let profile = OcsfProfile::new();
    for p in HINTED.iter().chain(UNHINTED.iter()) {
        assert!(
            matches!(profile.resolve(p), FieldResolution::JsonPath { ref col, .. } if col == "event"),
            "{p} must resolve to an event JSON path, got {:?}",
            profile.resolve(p)
        );
    }
    assert!(matches!(profile.resolve("risk_score"), FieldResolution::JsonPath { .. }));
    let hints: Vec<serde_json::Value> = serde_json::from_str(JSON_HINTS).unwrap();
    let manifest: Vec<&str> = hints.iter().map(|h| h["ocsf_path"].as_str().unwrap()).collect();
    for p in HINTED {
        assert!(manifest.contains(&p), "{p} must be a json_hints.json path");
    }
    for p in UNHINTED {
        assert!(!manifest.contains(&p), "{p} must not be hinted");
    }

    let db = format!(
        "n4934_tail_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    exec(&client, &format!("CREATE DATABASE {db}")).await.expect("create db");
    let typed: String = hints
        .iter()
        .map(|h| format!("`{}` {}, ", h["ocsf_path"].as_str().unwrap(), h["ch_type"].as_str().unwrap()))
        .collect();
    // The wide base (`SELECT *, <materialized columns>`, used by dedup) names
    // the profile's MATERIALIZED columns; plain String stand-ins suffice here.
    let materialized: String = profile
        .materialized_columns()
        .iter()
        .map(|c| format!(", `{c}` String DEFAULT ''"))
        .collect();
    for (name, json_type) in [
        ("plain", "JSON(max_dynamic_paths = 1024, SKIP unmapped)".to_string()),
        ("hinted", format!("JSON(max_dynamic_paths = 1024, {typed}SKIP unmapped)")),
    ] {
        exec(
            &client,
            &format!(
                "CREATE TABLE {db}.{name} (timestamp DateTime64(3, 'UTC'), id UUID, message String,
                    source_type LowCardinality(String), event {json_type}, unmapped JSON{materialized})
                 ENGINE = MergeTree ORDER BY (timestamp, id)
                 SETTINGS min_bytes_for_wide_part = 0"
            ),
        )
        .await
        .expect("create table");
    }

    // 3,000 rows over ~8 hours. Per path and row: a mixed-case string, a second
    // spelling, an explicit JSON null, an absent path, or (on 1 row in 23) an
    // object where OCSF says string. Skewed counts keep top/rare ranks distinct.
    let now = chrono::Utc::now();
    let mut rows = String::new();
    for i in 0..3_000u32 {
        let mut event = serde_json::json!({"class_uid": 4001, "time": 0});
        for (k, p) in HINTED.iter().chain(UNHINTED.iter()).enumerate() {
            let v = match (i as usize * (k + 1)) % 11 {
                _ if i % 23 == 5 => serde_json::json!({"nested": format!("Obj{}", i % 2)}),
                0..=3 => serde_json::Value::String(format!("Val{}_{k}", i % 3)),
                4..=5 => serde_json::Value::String(format!("val{}_{k}", i % 5)),
                6 => serde_json::Value::Null,
                7..=8 => serde_json::Value::String(format!("Rare{}_{k}", i % 7)),
                _ => continue,
            };
            put(&mut event, p, v);
        }
        let mut unmapped = serde_json::json!({});
        if i % 4 != 0 {
            put(&mut unmapped, "risk_score", serde_json::json!((i % 9) * 10));
        }
        let row = serde_json::json!({
            "timestamp": (now - chrono::Duration::seconds(i64::from(i) * 10)).to_rfc3339(),
            "id": format!("00000000-0000-0000-0000-{:012}", i),
            "message": "m", "source_type": "t", "event": event, "unmapped": unmapped,
        });
        rows.push_str(&row.to_string());
        rows.push('\n');
    }
    for name in ["plain", "hinted"] {
        insert(&client, &format!("{db}.{name}"), &rows).await;
    }

    // Index of a path in the data generator (its values end in `_<k>`).
    let k_of = |p: &str| HINTED.iter().chain(UNHINTED.iter()).position(|x| *x == p).unwrap();
    let queries = |p: &str, q: &str| {
        let k = k_of(p);
        vec![
            format!("* | stats count by {p} | sort -count, {p}"),
            format!("* | stats count by {p}, {q}"),
            format!("* | stats count, dc({q}) by {p}"),
            format!("* | stats values({q}) by {p}"),
            format!("* | stats count by risk_score | sort risk_score"),
            format!("* | stats avg(risk_score) by {p}"),
            format!("* | timechart span=1h count by {p}"),
            format!("* | top limit=100 {p}"),
            format!("* | rare limit=100 {p}"),
            format!("* | dedup {p} | table {p}, id"),
            format!("* | where {p}=\"val1_{k}\" OR {p}=\"Val2_{k}\" | stats count by {p}"),
            format!("* | where {p}!=\"\" | stats count"),
            format!("* | eval z=lower({p}) | stats count by z"),
            format!("* | stats count by {p} | where count > 50 | sort {p}"),
            format!("* | sort {p}, id | head 25 | table id, {p}"),
            format!("* | eventstats count as c by {p} | stats max(c) by {p}"),
            format!("* | where {p} IN [search {q}=\"Val0_*\" | return {p}] | stats count by {p}"),
            format!("* | rename {p} as rn | stats count by rn"),
            format!("* | rename {p} as rn | stats count by rn, {p}"),
            format!("* | eval {p}=upper({p}) | stats count by {p}"),
        ]
    };
    let gen = |table: &str| {
        ClickHouseSqlGenerator::with_table(table.to_string())
            .with_profile(Arc::new(OcsfProfile::new()))
    };
    let generate = |table: &str, hinted: bool, legacy: bool, npl: &str| {
        let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl}: {e}"));
        let g = if legacy { gen(table).with_tail_field_rederivation() } else { gen(table) };
        let run = || g.generate(&query, &window()).unwrap_or_else(|e| panic!("{npl}: {e}"));
        if hinted {
            nanosiem_core::schema::with_event_json_hints(&manifest, run)
        } else {
            run()
        }
    };

    let mut bad = Vec::new();
    let mut checked = 0usize;
    let mut alias_forms = 0usize;
    let pairs = [
        (HINTED[0], HINTED[1]),
        (UNHINTED[0], UNHINTED[1]),
        (HINTED[1], UNHINTED[0]),
        (UNHINTED[1], HINTED[0]),
    ];
    for (p, q) in pairs {
        for npl in queries(p, q) {
            let mut cells = Vec::new();
            for (name, hinted) in [("plain", false), ("hinted", true)] {
                let table = format!("{db}.{name}");
                for legacy in [true, false] {
                    let sql = generate(&table, hinted, legacy, &npl);
                    // The new form reads the alias past stage_0. `stats by <p>`
                    // must not touch `event` after stage_0 at all.
                    let later = sql.split_once("stage_1 AS").map(|(_, rest)| rest).unwrap_or("");
                    if !legacy && npl.starts_with("* | stats count by") && npl.contains(p) {
                        if later.contains("event.") {
                            bad.push(format!("{npl} [{name}]: a later stage still reads event:\n{sql}"));
                        } else {
                            alias_forms += 1;
                        }
                    }
                    // A hinted path in a slim stage_0 reads its typed subcolumn.
                    let slim_hinted = HINTED.contains(&p) && npl == format!("* | stats count by {p} | sort -count, {p}");
                    if hinted && !legacy && slim_hinted && !sql.contains("ifNull(toString(event.") {
                        bad.push(format!("{npl} [{name}]: typed hint form not emitted:\n{sql}"));
                    }
                    let out = exec(&client, &format!("{sql} FORMAT TSV"))
                        .await
                        .unwrap_or_else(|e| panic!("{npl} [{name}, legacy={legacy}]: {e}\n{sql}"));
                    cells.push((format!("{name}/{}", if legacy { "legacy" } else { "alias" }), normalized(&out)));
                }
            }
            if cells[0].1.is_empty() {
                bad.push(format!("{npl}: returned no rows (the probe proves nothing)"));
            }
            for (label, out) in &cells[1..] {
                if *out != cells[0].1 {
                    bad.push(format!(
                        "{npl}: {label} differs from {}\n  {}: {:?}\n  {label}: {:?}",
                        cells[0].0,
                        cells[0].0,
                        cells[0].1.iter().take(8).collect::<Vec<_>>(),
                        out.iter().take(8).collect::<Vec<_>>()
                    ));
                }
            }
            checked += 1;
        }
    }
    // `fields p, q | stats count by p` FAILED before NAN-4934 (Code 47: the
    // stats stage re-derived `p` from `event`, which `fields` had dropped). The
    // pre-change SQL has no result to compare with, so the oracle is the same
    // aggregation without the `fields` stage, in the pre-change form.
    let mut fixed = 0usize;
    for (p, q) in pairs {
        let npl = format!("* | fields {p}, {q} | stats count by {p}");
        let reference = format!("* | stats count by {p}");
        for (name, hinted) in [("plain", false), ("hinted", true)] {
            let table = format!("{db}.{name}");
            let legacy_sql = generate(&table, hinted, true, &npl);
            if exec(&client, &format!("{legacy_sql} FORMAT TSV")).await.is_ok() {
                bad.push(format!("{npl} [{name}]: expected the pre-change form to fail (Code 47)"));
            }
            let sql = generate(&table, hinted, false, &npl);
            let out = exec(&client, &format!("{sql} FORMAT TSV"))
                .await
                .unwrap_or_else(|e| panic!("{npl} [{name}]: {e}\n{sql}"));
            let ref_sql = generate(&table, hinted, true, &reference);
            let want = exec(&client, &format!("{ref_sql} FORMAT TSV")).await.unwrap();
            if normalized(&out) != normalized(&want) || want.is_empty() {
                bad.push(format!("{npl} [{name}]: {:?} != reference {:?}", normalized(&out), normalized(&want)));
            }
            fixed += 1;
        }
    }
    eprintln!("checked {checked} queries x 4 cells; {alias_forms} stats-by cells used the alias form; {fixed} previously failing cells now match the reference");
    assert!(alias_forms > 0, "no stats-by query exercised the alias form");

    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    assert!(bad.is_empty(), "{}", bad.join("\n\n"));
}
