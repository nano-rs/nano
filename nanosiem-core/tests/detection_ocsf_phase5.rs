// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! OCSF Phase 5 (NAN-1241) — scheduled detection is schema-aware.
//!
//! Proves the two Phase-5 seams in the **scheduled** detection path:
//!
//!   (a) `entity_extraction_order()`-driven entity extraction: under an
//!       `OcsfProfile` the `ScoreCalculator` (scheduled risk scoring) extracts
//!       the OCSF physical field for a role (`src_endpoint.ip`, `user.name`, …)
//!       from a real OCSF event, while the UDM path stays byte-identical
//!       (`src_ip`, `user`, …).
//!
//!   (b) the scheduled rule query SQL: a detection rule's nPL, generated through
//!       the **same profile-threaded `ClickHouseSqlGenerator` the SearchService
//!       uses for scheduled detection**, executes against the canonical OCSF
//!       table loaded with the spec-compliant fixtures and matches the expected
//!       events. (CH-gated; skips on `SKIP_DB_TESTS` / unreachable.)
//!
//! The injection-safe `validate_ddl_field_name` allowlist (profile-derived but
//! never loosening the strict-identifier guard) is covered by the unit tests in
//! `detection/materialized_view.rs`.
//!
//! Pure assertions (a) always run; the CH proof (b) reuses the throwaway-DB +
//! `event`-only insert pattern from `ocsf_query_integration.rs`.
//!   Run: cargo test -p nanosiem-core --test detection_ocsf_phase5 -- --nocapture

use std::sync::Arc;

use nanosiem_core::detection::risk::ScoreCalculator;
use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::OcsfProfile;
use serde_json::Value;

const OCSF_AUTH_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/fixtures/authentication_3002_logon.json"
));

const OCSF_NETWORK_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/fixtures/network_activity_4001_traffic.json"
));

const DDL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));

// ---------------------------------------------------------------------------
// (a) entity extraction is profile-driven — pure, always runs
// ---------------------------------------------------------------------------

/// On an OCSF deployment the auto-detect entity-extraction order yields the OCSF
/// physical field for the highest-priority role present in the event. The auth
/// fixture carries `src_endpoint.ip` (initiator), so the SrcIp role wins.
#[test]
fn ocsf_score_calculator_extracts_ocsf_physical_field() {
    let event: Value = serde_json::from_str(OCSF_AUTH_FIXTURE).expect("fixture parses");
    let events = vec![event];

    let calc = ScoreCalculator::new().with_profile(Arc::new(OcsfProfile::new()));
    // No explicit entity_field -> auto-detect over OcsfProfile::entity_extraction_order().
    let (entity, field) = calc.extract_entity(None, &events);

    assert_eq!(
        field.as_deref(),
        Some("src_endpoint.ip"),
        "OCSF auto-detect should resolve the SrcIp role to the OCSF physical field"
    );
    assert_eq!(entity, "10.20.30.40", "value pulled from src_endpoint.ip");
}

/// When only a user is present (no endpoint IP), OCSF resolves to `user.name`
/// — the OCSF physical field for the User role — proving the dotted-path
/// navigation works through the nested OCSF event shape.
#[test]
fn ocsf_score_calculator_resolves_user_role_to_dotted_path() {
    // Strip the endpoints so the IP/host roles miss and the User role wins.
    let mut event: Value = serde_json::from_str(OCSF_AUTH_FIXTURE).unwrap();
    let obj = event.as_object_mut().unwrap();
    obj.remove("src_endpoint");
    obj.remove("dst_endpoint");
    let events = vec![event];

    let calc = ScoreCalculator::new().with_profile(Arc::new(OcsfProfile::new()));
    let (entity, field) = calc.extract_entity(None, &events);

    assert_eq!(field.as_deref(), Some("user.name"));
    assert_eq!(entity, "jsmith");
}

/// The UDM path is byte-identical: a UDM-shaped event auto-detects `src_ip`,
/// and the OCSF physical field (`src_endpoint.ip`) is NOT a UDM field, so a
/// UDM calculator never picks it up even if present.
#[test]
fn udm_score_calculator_unchanged() {
    let calc = ScoreCalculator::new(); // default = UdmProfile
    let events = vec![serde_json::json!({
        "src_ip": "192.168.1.1",
        "user": "admin",
        // an OCSF-style nested field is invisible to the UDM order
        "src_endpoint": { "ip": "10.0.0.9" }
    })];
    let (entity, field) = calc.extract_entity(None, &events);
    assert_eq!(field.as_deref(), Some("src_ip"));
    assert_eq!(entity, "192.168.1.1");

    // Priority order preserved: host beats user beats hash.
    let calc2 = ScoreCalculator::new();
    let (e2, f2) = calc2.extract_entity(
        None,
        &[serde_json::json!({ "src_host": "h1", "user": "u1", "file_hash": "abc" })],
    );
    assert_eq!(f2.as_deref(), Some("src_host"));
    assert_eq!(e2, "h1");
}

/// The two profiles disagree on the same event — the seam is real, not a no-op:
/// the network fixture has both endpoints, and each profile picks its own
/// source-IP physical field.
#[test]
fn ocsf_and_udm_orders_differ_on_same_event() {
    let ocsf_event: Value = serde_json::from_str(OCSF_NETWORK_FIXTURE).unwrap();

    let ocsf_calc = ScoreCalculator::new().with_profile(Arc::new(OcsfProfile::new()));
    let (_v, ocsf_field) = ocsf_calc.extract_entity(None, &[ocsf_event.clone()]);
    assert_eq!(ocsf_field.as_deref(), Some("src_endpoint.ip"));

    // The same OCSF event run through a UDM calculator finds no flat UDM field
    // and falls back to "unknown" (no `src_ip` column in OCSF JSON).
    let udm_calc = ScoreCalculator::new();
    let (uv, uf) = udm_calc.extract_entity(None, &[ocsf_event]);
    assert_eq!(uf, None);
    assert_eq!(uv, "unknown");
}

// ---------------------------------------------------------------------------
// (b) scheduled rule query SQL executes against OCSF fixtures — CH-gated
// ---------------------------------------------------------------------------

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}
fn ch_user() -> String {
    std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or_else(|_| "nanosiem_admin".into())
}
fn ch_pass() -> String {
    std::env::var("CLICKHOUSE_ADMIN_PASSWORD").unwrap_or_else(|_| "nanosiem_admin_secret".into())
}

fn fixture_time_range() -> TimeRange {
    TimeRange {
        start: "2025-06-01T00:00:00Z".parse().unwrap(),
        end: "2025-06-10T00:00:00Z".parse().unwrap(),
    }
}

/// Generate the scheduled-detection rule query SQL exactly as the SearchService
/// does for an OCSF deployment: an `OcsfProfile`-threaded generator over the
/// `ocsf_logs` table.
fn scheduled_rule_sql(rule_npl: &str, db: &str) -> String {
    let query = parse_query(rule_npl).unwrap_or_else(|e| panic!("parse failed: {e}"));
    ClickHouseSqlGenerator::with_table(format!("{db}.ocsf_logs"))
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&query, &fixture_time_range())
        .unwrap_or_else(|e| panic!("SQL gen failed: {e}"))
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

async fn insert_event(client: &reqwest::Client, db: &str, event_json: &str) -> Result<(), String> {
    let stmt = format!("INSERT INTO {db}.ocsf_logs (event) FORMAT JSONEachRow").replace(' ', "%20");
    let url = format!("{}/?query={stmt}&async_insert=0&wait_end_of_query=1", ch_url());
    let row = serde_json::json!({ "event": serde_json::from_str::<Value>(event_json).unwrap() })
        .to_string();
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

fn test_table_ddl(db: &str) -> String {
    // NAN-1241: extract ONLY the ocsf_logs CREATE TABLE — the canonical DDL is
    // multi-statement (prevalence MVs/dicts) and the CH HTTP endpoint rejects
    // multi-statement bodies. Strip `--` comments + the TTL clause.
    let start = DDL
        .find("CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs")
        .expect("ocsf_logs CREATE TABLE in DDL");
    let no_comments: String = DDL[start..]
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

/// Run a `| stats count` rule query and return the scalar count.
async fn rule_match_count(client: &reqwest::Client, db: &str, rule_npl: &str) -> u64 {
    let sql = format!("{} FORMAT TSV", scheduled_rule_sql(rule_npl, db));
    let body = exec(client, &sql)
        .await
        .unwrap_or_else(|e| panic!("CH error for rule `{rule_npl}`:\n{sql}\n\n{e}"));
    body.trim()
        .lines()
        .next()
        .and_then(|l| l.split('\t').last())
        .and_then(|c| c.trim().parse().ok())
        .unwrap_or_else(|| panic!("could not parse count from `{body}`"))
}

#[tokio::test]
async fn ocsf_scheduled_detection_rule_query_matches_fixtures() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return;
    }
    let client = reqwest::Client::new();
    if !reachable(&client).await {
        eprintln!("Skipping: ClickHouse not reachable at {}", ch_url());
        return;
    }

    let db = format!(
        "ocsf_det_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    exec(&client, &format!("CREATE DATABASE {db}"))
        .await
        .expect("create test db");

    let result = run_ch_assertions(&client, &db).await;
    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    result.expect("ocsf scheduled-detection assertions");
}

async fn run_ch_assertions(client: &reqwest::Client, db: &str) -> Result<(), String> {
    exec(client, &test_table_ddl(db)).await?;
    insert_event(client, db, OCSF_AUTH_FIXTURE).await?;
    insert_event(client, db, OCSF_NETWORK_FIXTURE).await?;

    // A scheduled detection rule written in OCSF field names. The rule filters
    // on the promoted dotted column `src_endpoint.ip` and counts — exactly the
    // shape SearchService produces for a `| stats count` rule on a cron tick.
    let by_src_ip = rule_match_count(
        client,
        db,
        "src_endpoint.ip=\"10.20.30.40\" | stats count",
    )
    .await;
    assert_eq!(
        by_src_ip, 2,
        "both fixtures share src_endpoint.ip 10.20.30.40"
    );

    // A rule on the OCSF taxonomy int (class_uid) — Authentication only.
    let auth_only = rule_match_count(client, db, "class_uid=3002 | stats count").await;
    assert_eq!(auth_only, 1, "only the auth fixture is class_uid=3002");

    // A rule on a nested OCSF user path resolving to the JSON spill — proves the
    // scheduled query can hunt on OCSF fields beyond the promoted columns.
    let by_user = rule_match_count(client, db, "user.name=\"jsmith\" | stats count").await;
    assert_eq!(by_user, 1, "only the auth fixture carries user.name jsmith");

    Ok(())
}
