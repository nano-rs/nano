// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! UDM contract test for the drive-by injector and nano-rs/rules demo rule.
//!
//! This test compiles the production nPL sequence to ClickHouse SQL, executes it
//! against five normalized UDM fixtures, and verifies the complete correlation.
//! It skips cleanly when ClickHouse is unavailable.
//!
//! To validate the exact checked-out rules repository instead of the embedded
//! fallback query:
//! `NANO_RULES_REPO=/path/to/rules cargo test -p nanosiem-core
//!   --test drive_by_rule_contract -- --nocapture`

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::rule_repository::parse_npl;
use serde_json::Value;

const SAMPLE_SHA256: &str = "3e120cc23a568678151b2bc258291511e3fa0b5983f7cf301aac95e4c0d2a44c";

const EMBEDDED_QUERY: &str = r#"
source_type="conduit_proxy" OR source_type="windows_sysmon"
| sequence by user maxspan=5m
    fields(src_host, src_ip, dest_host, dest_ip, dest_port, url, file_path, file_hash, prevalence_file_hash, process_name, parent_process_name, command_line)
    [source_type="conduit_proxy" url CONTAINS "/downloads/" url=/\.zip(\?|$)/i]
    [source_type="windows_sysmon" file_action="create" file_path=/\.js$/i file_hash!="" prevalence_file_hash < 5]
    [source_type="windows_sysmon" event_type="process_create" process_name="wscript.exe" command_line CONTAINS ".js"]
    [source_type="windows_sysmon" event_type="network_connection" process_name="wscript.exe" dest_port=443 dest_ip!=/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/]
    [source_type="windows_sysmon" event_type="process_create" process_name="powershell.exe" parent_process_name="wscript.exe"]
| risk score=95 entity=user factor="Drive-by JavaScript execution chain"
| table timestamp, user, step1_url, step1_dest_host, step2_src_host, step2_file_path, step2_file_hash, step2_prevalence_file_hash, step3_process_name, step3_command_line, step4_dest_host, step4_dest_ip, step4_dest_port, step5_process_name, step5_parent_process_name, step5_command_line, sequence_duration_seconds, risk_score, risk_factors
"#;

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
        start: "2026-07-24T12:59:00Z".parse().unwrap(),
        end: "2026-07-24T13:10:00Z".parse().unwrap(),
    }
}

fn rule_query() -> String {
    let Ok(rules_repo) = std::env::var("NANO_RULES_REPO") else {
        return EMBEDDED_QUERY.trim().to_string();
    };
    let path = std::path::Path::new(&rules_repo).join("demo/drive_by_js_execution_chain.yml");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read rule {}: {error}", path.display()));
    parse_npl(&content)
        .unwrap_or_else(|error| panic!("parse rule {}: {error}", path.display()))
        .query
}

async fn exec(client: &reqwest::Client, sql: &str) -> Result<String, String> {
    let response = client
        .post(ch_url())
        .basic_auth(ch_user(), Some(ch_pass()))
        .body(sql.to_string())
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("HTTP {status}: {body}"))
    }
}

async fn reachable(client: &reqwest::Client) -> bool {
    exec(client, "SELECT 1")
        .await
        .map(|body| body.trim() == "1")
        .unwrap_or(false)
}

async fn run_contract(client: &reqwest::Client, database: &str) -> Result<(), String> {
    exec(
        client,
        &format!("CREATE TABLE {database}.logs AS nanosiem.logs ENGINE = Memory"),
    )
    .await?;
    // Keep this fixture deterministic even if the sample hash later becomes
    // common in the developer's global prevalence dictionary.
    exec(
        client,
        &format!("ALTER TABLE {database}.logs MODIFY COLUMN prevalence_file_hash UInt16 DEFAULT 1"),
    )
    .await?;

    let fixture_sql = format!(
        r#"
INSERT INTO {database}.logs
(timestamp, source_type, user, src_host, src_ip, dest_host, dest_ip, dest_port, url, file_path, file_hash, action, file_action, process_name, parent_process_name, command_line)
SELECT toDateTime64('2026-07-24 13:00:00', 6, 'UTC'), 'conduit_proxy', 'alice', '', '10.1.1.21', 'search-check-results.test', '198.51.100.42', 443, 'https://search-check-results.test/downloads/search_term.zip', '', '', 'http_request', '', '', '', ''
UNION ALL
SELECT toDateTime64('2026-07-24 13:00:20', 6, 'UTC'), 'windows_sysmon', 'alice', 'ws-eng-003', '', '', '', 0, '', 'C:\\Users\\alice\\Downloads\\search_term\\EhDSjenZsx.js', '{SAMPLE_SHA256}', 'file_create', 'create', 'explorer.exe', '', ''
UNION ALL
SELECT toDateTime64('2026-07-24 13:00:40', 6, 'UTC'), 'windows_sysmon', 'alice', 'ws-eng-003', '', '', '', 0, '', '', '', 'process_create', '', 'wscript.exe', 'explorer.exe', 'wscript.exe "C:\\Users\\alice\\Downloads\\search_term\\EhDSjenZsx.js"'
UNION ALL
SELECT toDateTime64('2026-07-24 13:01:00', 6, 'UTC'), 'windows_sysmon', 'alice', 'ws-eng-003', '', 'cdn-session-check.test', '203.0.113.77', 443, '', '', '', 'network_connection', '', 'wscript.exe', '', ''
UNION ALL
SELECT toDateTime64('2026-07-24 13:01:20', 6, 'UTC'), 'windows_sysmon', 'alice', 'ws-eng-003', '', '', '', 0, '', '', '', 'process_create', '', 'powershell.exe', 'wscript.exe', 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\\Users\\alice\\AppData\\Local\\Temp\\stage.ps1"'
"#
    );
    exec(client, &fixture_sql).await?;

    let parsed = parse_query(&rule_query()).map_err(|error| error.to_string())?;
    let sql = ClickHouseSqlGenerator::with_table(format!("{database}.logs"))
        .generate(&parsed, &fixture_time_range())
        .map_err(|error| error.to_string())?;
    let body = exec(client, &format!("{sql} FORMAT JSONEachRow")).await?;
    let rows = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;

    if rows.len() != 1 {
        return Err(format!(
            "expected one drive-by sequence, got {}:\n{body}\nSQL:\n{sql}",
            rows.len()
        ));
    }
    let row = &rows[0];
    let expected = [
        ("user", "alice"),
        (
            "step1_url",
            "https://search-check-results.test/downloads/search_term.zip",
        ),
        ("step2_src_host", "ws-eng-003"),
        ("step2_file_hash", SAMPLE_SHA256),
        ("step3_process_name", "wscript.exe"),
        ("step4_dest_host", "cdn-session-check.test"),
        ("step4_dest_ip", "203.0.113.77"),
        ("step5_process_name", "powershell.exe"),
        ("step5_parent_process_name", "wscript.exe"),
    ];
    for (field, value) in expected {
        if row[field] != value {
            return Err(format!("expected {field}={value:?}, got {}", row[field]));
        }
    }
    if row["step2_prevalence_file_hash"] != 1
        || row["step4_dest_port"] != 443
        || row["sequence_duration_seconds"] != 80
        || row["risk_score"] != 95
    {
        return Err(format!("unexpected numeric captures: {row}"));
    }

    Ok(())
}

#[tokio::test]
async fn udm_drive_by_rule_matches_normalized_campaign() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping drive-by rule contract (SKIP_DB_TESTS set)");
        return;
    }
    let client = reqwest::Client::new();
    if !reachable(&client).await {
        eprintln!(
            "Skipping: ClickHouse is not reachable at {} with the configured admin credentials",
            ch_url()
        );
        return;
    }

    let database = format!(
        "drive_by_rule_contract_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    exec(&client, &format!("CREATE DATABASE {database}"))
        .await
        .expect("create isolated test database");
    let result = run_contract(&client, &database).await;
    let cleanup = exec(&client, &format!("DROP DATABASE {database}")).await;
    result.expect("drive-by UDM rule contract");
    cleanup.expect("drop isolated test database");
}
