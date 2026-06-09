// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! OCSF-native detection findings (NAN-1254) — write↔read round-trip test.
//!
//! Proves the OCSF Detection Finding (class_uid 2004) path end-to-end:
//!   1. `FindingLogger::build_ocsf_finding_event` produces an `event` that, when
//!      written to `ocsf_logs`, materializes the right promoted columns
//!      (`class_uid=2004`, `category_uid=2`, `type_uid=200401`, `severity_id`,
//!      `source_type='findings'`).
//!   2. The risk-repository read path's exact extraction expressions
//!      (`JSONExtractString(event,'unmapped','risk_entity')`, `JSONExtractInt(
//!      event,'risk_score')`, `JSONExtractString(event,'finding_info','title')`,
//!      `lower(JSONExtractString(event,'severity'))`, plus the f32-safe
//!      `toFloat32(JSONExtractInt(...))`) read back the values the writer put in.
//!
//! This is the gate against a write/read contract drift: if the builder moves a
//! field or the read path's JSON path changes, the round-trip breaks here rather
//! than silently returning empty risk panels under OCSF.
//!
//! Requires a local ClickHouse with DDL rights. Skips cleanly if unreachable or
//! if `SKIP_DB_TESTS` is set.
//!   Run: cargo test -p nanosiem-core --test ocsf_detection_findings_integration -- --nocapture

use chrono::Utc;
use nanosiem_core::detection::findings::FindingLogger;
use serde_json::json;

const DDL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));

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
        .post(ch_url())
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

async fn reachable(client: &reqwest::Client) -> bool {
    exec(client, "SELECT 1")
        .await
        .map(|b| b.trim() == "1")
        .unwrap_or(false)
}

/// Insert the finding `event` (+ source_type) via JSONEachRow — statement in the
/// `query` URL param, JSON in the body (the form reqwest doesn't drop). timestamp
/// is left to default; the test table strips TTL so it never prunes.
async fn insert_finding(client: &reqwest::Client, db: &str, event: &serde_json::Value) -> Result<(), String> {
    let stmt = format!("INSERT INTO {db}.ocsf_logs (event, source_type) FORMAT JSONEachRow")
        .replace(' ', "%20");
    let url = format!("{}/?query={stmt}&async_insert=0&wait_end_of_query=1", ch_url());
    let row = json!({ "event": event, "source_type": "findings" }).to_string();
    let resp = client
        .post(url)
        .basic_auth(ch_user(), Some(ch_pass()))
        .body(row)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {status}: {body}"))
    }
}

async fn select1(client: &reqwest::Client, db: &str, expr: &str) -> String {
    let sql = format!(
        "SELECT {expr} FROM {db}.ocsf_logs WHERE source_type='findings' FORMAT TSV"
    );
    exec(client, &sql).await.expect("select failed").trim().to_string()
}

/// Extract ONLY the `ocsf_logs` CREATE TABLE statement from the canonical DDL
/// (the file is multi-statement — table + prevalence MVs/dictionaries, the
/// latter using creds placeholders we don't want here). Strip `--` comments
/// (so a comment semicolon can't truncate it early) and the TTL clause (so the
/// default epoch-0 timestamp isn't pruned), and point it at the test DB.
fn test_table_ddl(db: &str) -> String {
    let start = DDL
        .find("CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs")
        .expect("ocsf_logs CREATE TABLE in DDL");
    let from = &DDL[start..];
    // Drop line comments first so their semicolons don't terminate us early.
    let no_comments: String = from
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let end = no_comments.find(';').expect("CREATE TABLE terminator");
    no_comments[..end]
        .lines()
        .filter(|l| !l.trim_start().starts_with("TTL "))
        .collect::<Vec<_>>()
        .join("\n")
        .replace("nanosiem.ocsf_logs", &format!("{db}.ocsf_logs"))
}

fn sample_metadata() -> serde_json::Value {
    json!({
        "signal_type": "detection_match",
        "rule_id": "rule-abc-123",
        "rule_name": "Suspicious Login",
        "severity": "high",
        "rule_mode": "live",
        "matched_event_count": 3,
        "matched_events_sample": [],
        "realtime": false,
        "raw_risk_score": 50,
        "risk_score": 75,
        "risk_entity": "10.0.0.5",
        "risk_entity_field": "src_ip",
        "risk_factors": ["off-hours"]
    })
}

#[tokio::test]
async fn ocsf_finding_round_trips_write_to_read() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return;
    }
    let client = reqwest::Client::new();
    if !reachable(&client).await {
        eprintln!("Skipping: ClickHouse not reachable at {} as admin", ch_url());
        return;
    }

    let db = format!(
        "ocsf_findings_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    exec(&client, &format!("CREATE DATABASE {db}"))
        .await
        .expect("create test db");

    let result = run_round_trip(&client, &db).await;
    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    result.expect("finding round-trip assertions");
}

async fn run_round_trip(client: &reqwest::Client, db: &str) -> Result<(), String> {
    exec(client, &test_table_ddl(db)).await?;

    // Build the event with the REAL writer, then write it.
    let event = FindingLogger::build_ocsf_finding_event(
        &sample_metadata(),
        "Suspicious Login - src_ip=10.0.0.5",
        Utc::now(),
    );
    insert_finding(client, db, &event).await?;

    // 1) Materialized promoted columns (the DDL's JSONExtract expressions).
    assert_eq!(select1(client, db, "class_uid").await, "2004", "class_uid");
    assert_eq!(select1(client, db, "category_uid").await, "2", "category_uid");
    assert_eq!(select1(client, db, "type_uid").await, "200401", "type_uid");
    assert_eq!(select1(client, db, "severity_id").await, "4", "severity_id");
    assert_eq!(select1(client, db, "source_type").await, "findings", "source_type");

    // 2) The risk-repository read path's exact extraction expressions.
    assert_eq!(
        select1(client, db, "JSONExtractString(event, 'unmapped', 'risk_entity')").await,
        "10.0.0.5",
        "read-path risk_entity"
    );
    assert_eq!(
        select1(client, db, "JSONExtractInt(event, 'risk_score')").await,
        "75",
        "read-path risk_score (Int)"
    );
    assert_eq!(
        select1(client, db, "toFloat32(JSONExtractInt(event, 'risk_score'))").await,
        "75",
        "read-path risk_score (f32-safe, get_signals_for_entities)"
    );
    assert_eq!(
        select1(client, db, "JSONExtractString(event, 'finding_info', 'title')").await,
        "Suspicious Login",
        "read-path rule_name"
    );
    assert_eq!(
        select1(client, db, "JSONExtractString(event, 'unmapped', 'rule_id')").await,
        "rule-abc-123",
        "read-path rule_id"
    );
    assert_eq!(
        select1(client, db, "JSONExtractString(event, 'unmapped', 'signal_type')").await,
        "detection_match",
        "read-path signal_type"
    );
    assert_eq!(
        select1(client, db, "lower(JSONExtractString(event, 'severity'))").await,
        "high",
        "read-path severity (lowercased to match UDM)"
    );

    Ok(())
}
