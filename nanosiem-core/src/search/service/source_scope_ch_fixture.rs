// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5793: a disposable ClickHouse seeded for the bound source-scope tests.
//!
//! The schema is the product's own DDL (`clickhouse/ocsf/init.sql` for
//! `ocsf_logs`, `clickhouse/init.sql` for the side tables), read at runtime.
//! `ocsf_logs` columns MATERIALIZED from dictionaries become plain columns: a
//! throwaway server has none of the dictionaries, and no read under test
//! depends on their values.
//!
//! Every allowed row carries `allowed` in its marker values and every denied
//! row carries [`DENIED_TAG`] (a word no output field name contains), so a read's output can be checked for leaks as text.
//! The denied source names carry the characters that broke the inline form:
//! a `?`, a `'`, `?fields`, and mixed case.
//!
//! Point `NANOSIEM_TEST_CLICKHOUSE_URL` at a DISPOSABLE server (this drops
//! and recreates `nanosiem.*` tables) and set
//! `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1`.

use crate::auth::ScopeSet;
use std::collections::BTreeSet;

/// The one allowed source.
pub(crate) const ALLOWED: &str = "allowed_src";
/// Denied sources: a `?` (an unbound client-side bind in the inline form), a
/// quote plus `?fields` (the driver's field-list placeholder), and mixed case
/// (the predicate lowercases both sides).
pub(crate) const DENIED: [&str; 3] = ["we?ird src", "o'brien?fields", "Mixed?Case"];
/// The marker every denied row's values carry.
pub(crate) const DENIED_TAG: &str = "xdenyx";
/// The service whose span carries [`SHARED_IP`] (the otel security-signals read).
pub(crate) const SPAN_SERVICE: &str = "checkout";

/// The user every row shares, so per-principal reads see both kinds of row.
pub(crate) const SHARED_USER: &str = "shared-user";
/// The host every row shares.
pub(crate) const SHARED_HOST: &str = "host-a";
/// The source IP every row shares.
pub(crate) const SHARED_IP: &str = "10.1.1.1";
/// The destination IP only the denied rows carry (a retro / pivot target).
pub(crate) const DENIED_DST_IP: &str = "10.3.3.3";
/// The destination IP only the allowed row carries.
pub(crate) const ALLOWED_DST_IP: &str = "10.2.2.2";

static SETUP: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// The throwaway server's client (default database `nanosiem`).
pub(crate) fn client() -> clickhouse::Client {
    server_client().with_database("nanosiem")
}

/// The throwaway server's client with no default database (to create it).
fn server_client() -> clickhouse::Client {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    let mut client = clickhouse::Client::default().with_url(url);
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        client = client.with_password(password);
    }
    client
}

/// A viewer denied every [`DENIED`] source.
pub(crate) fn restricted() -> ScopeSet {
    ScopeSet::from_denied(DENIED.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>())
}

/// Text that must never appear in a restricted read's output.
pub(crate) fn leaks(output: &str) -> Vec<String> {
    let lower = output.to_lowercase();
    let mut found: Vec<String> = DENIED
        .iter()
        .filter(|d| lower.contains(&d.to_lowercase()))
        .map(|d| d.to_string())
        .collect();
    if lower.contains(DENIED_TAG) {
        found.push(DENIED_TAG.to_string());
    }
    found
}

/// Create the schema and seed it, once per test process.
pub(crate) async fn setup() {
    SETUP
        .get_or_init(|| async {
            assert_eq!(
                std::env::var("NANOSIEM_ALLOW_DESTRUCTIVE_TESTS").as_deref(),
                Ok("1"),
                "this suite drops nanosiem.* tables: set NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 \
                 against a disposable ClickHouse"
            );
            create_schema().await;
            seed().await;
        })
        .await;
}

fn repo_file(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The `CREATE TABLE` statement for `nanosiem.<table>` in `sql`, comment lines
/// dropped, dictionary-MATERIALIZED columns made plain.
fn create_statement(sql: &str, table: &str) -> String {
    let re = regex::Regex::new(&format!(
        r"CREATE TABLE IF NOT EXISTS nanosiem\.{}\s*\(",
        regex::escape(table)
    ))
    .unwrap();
    let start = re.find(sql).unwrap_or_else(|| panic!("no DDL for {table}")).start();
    let body: Vec<String> = sql[start..]
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .map(|l| match (l.contains("dictGet"), l.find(" MATERIALIZED ")) {
            (true, Some(at)) => {
                let tail = l.rfind(" CODEC(").map(|c| &l[c..]).unwrap_or(",");
                format!("{}{tail}", &l[..at])
            }
            _ => l.to_string(),
        })
        .collect();
    let body = body.join("\n");
    body[..body.find(';').expect("statement terminator")].to_string()
}

async fn exec(sql: &str) {
    client()
        .query(sql)
        .execute()
        .await
        .unwrap_or_else(|e| panic!("{e}\n--- SQL ---\n{sql}"));
}

async fn create_schema() {
    server_client()
        .query("CREATE DATABASE IF NOT EXISTS nanosiem")
        .execute()
        .await
        .expect("create the nanosiem database");
    let ocsf = repo_file("clickhouse/ocsf/init.sql");
    let core = repo_file("clickhouse/init.sql");
    let spans = repo_file("clickhouse/138_otel_spans.sql");
    for (table, ddl) in [
        ("ocsf_logs", &ocsf),
        ("identity_observations", &core),
        ("logs_per_source_5m_v2", &core),
        ("signals", &core),
        ("cloud_user_activity_agg", &core),
        ("entity_time_range_agg", &core),
        ("otel_spans", &spans),
    ] {
        exec(&format!("DROP TABLE IF EXISTS nanosiem.{table} SYNC")).await;
        exec(&create_statement(ddl, table)).await;
    }
}

/// One allowed row and one row per denied source: same user / host / source
/// IP, different destination, file hash and message markers.
async fn seed() {
    let now = chrono::Utc::now();
    let ts = (now - chrono::Duration::minutes(30))
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string();
    let bucket = (now - chrono::Duration::minutes(30))
        .format("%Y-%m-%d %H:%M:00")
        .to_string();
    let mut sources: Vec<(&str, &str)> = vec![(ALLOWED, "allowed")];
    sources.extend(DENIED.iter().map(|d| (*d, DENIED_TAG)));
    let ch = client();
    for (i, (source, tag)) in sources.iter().enumerate() {
        let dst_ip = if *tag == "allowed" { ALLOWED_DST_IP } else { DENIED_DST_IP };
        let hash = format!("{tag}{i}").repeat(8);
        // Values bind (`?`), so the hostile names reach storage verbatim.
        ch.query(
            "INSERT INTO nanosiem.ocsf_logs (timestamp, source_type, class_uid, category_uid, \
               activity_id, status_id, message, raw_data, `metadata.product.name`, \
               `actor.user.name`, `user.name`, `device.hostname`, \
               `src_endpoint.ip`, `src_endpoint.hostname`, `dst_endpoint.ip`, \
               `dst_endpoint.hostname`, `dst_endpoint.port`, `process.name`, \
               `file.hashes.sha256`, `query.hostname`, `cloud.provider`, `cloud.region`, \
               `cloud.account.uid`, `api.operation`, `api.service.name`, `http_request.user_agent`) \
             VALUES (?, ?, 3002, 3, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 445, ?, ?, ?, 'aws', ?, ?, ?, ?, ?)",
        )
        .bind(&ts)
        .bind(*source)
        .bind(format!("{tag} event {i}"))
        .bind(format!("{{\"marker\":\"{tag}_{i}\"}}"))
        .bind(format!("{tag}_product"))
        .bind(SHARED_USER)
        .bind(SHARED_USER)
        .bind(SHARED_HOST)
        .bind(SHARED_IP)
        .bind(SHARED_HOST)
        .bind(dst_ip)
        .bind(format!("{tag}_dst_{i}.example"))
        .bind(format!("{tag}_proc.exe"))
        .bind(&hash)
        .bind(format!("{tag}_{i}.example"))
        .bind(format!("{tag}_region_{i}"))
        .bind(format!("{tag}_account_{i}"))
        .bind(format!("{tag}_op_{i}"))
        .bind(format!("{tag}_svc_{i}"))
        .bind(format!("{tag}_agent_{i}"))
        .execute()
        .await
        .expect("seed ocsf_logs");

        // Denied observations rank higher, so an unscoped resolution picks them.
        let priority: u8 = if *tag == "allowed" { 1 } else { 9 };
        ch.query(
            "INSERT INTO nanosiem.identity_observations \
               (observed_at, ip, hostname, fqdn, user, source, source_priority) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&ts)
        .bind(SHARED_IP)
        .bind(format!("{tag}_host_{i}"))
        .bind(format!("{tag}_host_{i}.corp"))
        .bind(format!("{tag}_user_{i}"))
        .bind(*source)
        .bind(priority)
        .execute()
        .await
        .expect("seed identity_observations");

        ch.query(
            "INSERT INTO nanosiem.logs_per_source_5m_v2 (schema_profile, source_type, \
               scope_source_type, scope_source_type_complete, bucket_start, events, bytes, \
               last_event_at, first_event_at) VALUES (?, ?, ?, 1, ?, 7, 70, ?, ?)",
        )
        .bind(crate::schema::log_telemetry_profile_for(crate::schema::SchemaId::Ocsf))
        .bind(source.to_lowercase())
        .bind(source.to_lowercase())
        .bind(&bucket)
        .bind(&ts)
        .bind(&ts)
        .execute()
        .await
        .expect("seed logs_per_source_5m_v2");

        ch.query(
            "INSERT INTO nanosiem.signals (timestamp, rule_id, rule_name, severity, risk_score, \
               risk_entity, matched_log_id, source_type) \
             VALUES (?, generateUUIDv4(), ?, 'high', 50, ?, generateUUIDv4(), ?)",
        )
        .bind(&ts)
        .bind(format!("{tag}_rule_{i}"))
        .bind(SHARED_IP)
        .bind(*source)
        .execute()
        .await
        .expect("seed signals");
    }
    // One span for the otel read to resolve its entities from.
    ch.query(
        "INSERT INTO nanosiem.otel_spans (start_time, service_name, src_ip, host) VALUES (?, ?, ?, ?)",
    )
    .bind(&ts)
    .bind(SPAN_SERVICE)
    .bind(SHARED_IP)
    .bind(SHARED_HOST)
    .execute()
    .await
    .expect("seed otel_spans");
}
