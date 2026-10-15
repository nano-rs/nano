//! Cell SQL parity for a bounded internal inputlookup snapshot. The search
//! service test checks the rewrite against InputLookupService; this executes
//! its reserved-alias projection on the same chDB engine query[T] uses.
use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, QueryOptions, TimeRange};
use nanosiem_core::schema::{FieldType, OcsfProfile};
use nanosiem_lake_worker::native::NativeChdb;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

#[test]
#[ignore = "requires digest-verified native chDB library"]
fn nested_inputlookup_projection_preserves_nonmatching_prefixed_field() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let connection = runtime.connect(&[]).unwrap();
    let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::from([
        ("host".into(), FieldType::String),
        ("inputlookup_owner".into(), FieldType::String),
    ]))
    .unwrap();
    let query = parse_query(
        r#"host=never | table host, inputlookup_owner | append [* | eval __nano_il_match_fixture = case(host == "web01", true, false), __nano_il_value_fixture_0 = case(host == "web01", "alice", null()) | eval inputlookup_owner = case(__nano_il_match_fixture, __nano_il_value_fixture_0, inputlookup_owner) | fields - __nano_il_match_fixture, __nano_il_value_fixture_0 | eval score = 1 | where score > 0 | table host, inputlookup_owner] | stats count as Count by inputlookup_owner"#,
    ).unwrap();
    let start = chrono::DateTime::parse_from_rfc3339("2026-09-26T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let end = chrono::DateTime::parse_from_rfc3339("2026-09-27T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let sql = ClickHouseSqlGenerator::with_table("__tenant_parts")
        .with_profile(Arc::new(profile))
        .generate_with_options(
            &query,
            &TimeRange::new(start, end),
            &QueryOptions {
                use_cache: false,
                table_view: false,
                limit: Some(100),
                unordered: false,
            },
        )
        .unwrap();
    let parts = "SELECT toDateTime64('2026-09-26 12:00:00', 3, 'UTC') AS time, 'web01' AS host, 'old' AS inputlookup_owner UNION ALL SELECT toDateTime64('2026-09-26 12:00:01', 3, 'UTC') AS time, 'web99' AS host, 'prior' AS inputlookup_owner";
    let sql = sql.replace("__tenant_parts", &format!("({parts})"));
    let output = connection
        .query_with_params(&sql, "JSONEachRow", &[])
        .unwrap();
    let mut rows = String::from_utf8(output.data)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| row["inputlookup_owner"].as_str().unwrap().to_string());
    assert_eq!(
        rows,
        vec![
            json!({"inputlookup_owner": "alice", "Count": 1}),
            json!({"inputlookup_owner": "prior", "Count": 1}),
        ]
    );
}
