// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! OCSF Fields-panel (field-stats) execution proof (NAN-1241).
//!
//! The Fields panel (`POST /api/search/field-stats` →
//! `SearchService::get_field_stats_for_query`) enumerates the active schema's
//! columns from `system.columns` and feeds them into a `topK`/`uniq`
//! field-stats query. Before the fix this hardcoded `table='logs'` (UDM
//! columns) and emitted unquoted `toString(<col>)`, so against `ocsf_logs` it
//! failed with `Code: 47 Unknown identifier 'action'` (wrong columns) and, even
//! with the right columns, with a parse/identifier error on dotted OCSF names
//! like `src_endpoint.ip` (parsed as `table.column`).
//!
//! This test reproduces the production path against a live `ocsf_logs`:
//!   1. enumerate field-stats columns from `system.columns` with the SAME filter
//!      `get_table_columns` uses (incl. the new `%.search` exclusion);
//!   2. build the SAME `topK`/`uniq` field-stats SQL `build_field_stats_sql`
//!      emits — dotted columns double-quoted inside `toString`/`uniq`, dot-free
//!      aliases;
//!   3. execute it and assert it succeeds (NO Code 47) and returns stats for
//!      the promoted dotted column `src_endpoint.ip` and the taxonomy int
//!      `class_uid`.
//!
//! Requires a local ClickHouse with DDL rights (admin
//! nanosiem_admin/nanosiem_admin_secret @ :8123). Skips cleanly if unreachable
//! or `SKIP_DB_TESTS` is set. Reuses the throwaway-DB + synchronous-insert
//! pattern from `ocsf_search_integration`.
//!   Run: cargo test -p nanosiem-core --test ocsf_field_stats_integration -- --nocapture

use serde_json::Value;

const DDL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));

const FIXTURES: &[(&str, &str)] = &[
    (
        "auth",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/authentication_3002_logon.json"
        )),
    ),
    (
        "network",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/network_activity_4001_traffic.json"
        )),
    ),
    (
        "process",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/process_activity_1007_launch.json"
        )),
    ),
    (
        "file",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/file_activity_1001_delete.json"
        )),
    ),
    (
        "dns",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/dns_activity_4003_query.json"
        )),
    ),
    (
        "http",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/ocsf/fixtures/http_activity_4002_get.json"
        )),
    ),
];

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

/// Strip CREATE DATABASE + TTL and repoint at the throwaway DB.
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

/// Mirror of `ClickHouseExecutor::get_table_columns`'s `system.columns` filter,
/// including the new `%.search` exclusion that drops OCSF's dotted `_search`
/// companion columns. Returns the queryable column names for `<db>.ocsf_logs`.
async fn field_stats_columns(client: &reqwest::Client, db: &str) -> Result<Vec<String>, String> {
    let sql = format!(
        "SELECT name FROM system.columns \
         WHERE database = '{db}' AND table = 'ocsf_logs' \
           AND type NOT LIKE '%Array%' \
           AND type NOT LIKE '%Map%' \
           AND type NOT LIKE 'JSON%' \
           AND name NOT LIKE '\\_%' \
           AND name NOT LIKE '%_search' \
           AND name NOT LIKE '%.search' \
           AND name NOT LIKE 'prevalence_%' \
           AND default_kind != 'ALIAS' \
           AND name NOT IN ('ext', 'metadata', 'event_id', 'ingest_time', 'namespace') \
         ORDER BY name FORMAT JSONEachRow"
    );
    let body = exec(client, &sql).await?;
    Ok(body
        .lines()
        .filter_map(|l| {
            serde_json::from_str::<Value>(l)
                .ok()
                .and_then(|v| v.get("name")?.as_str().map(String::from))
        })
        .collect())
}

/// Replicate the exact `topK`/`uniq` field-stats SELECT shape that
/// `build_field_stats_sql` emits: dotted columns double-quoted inside
/// `toString`/`uniq`, alias dots collapsed to underscores.
fn build_field_stats_sql(db: &str, cols: &[String]) -> String {
    let mut parts = Vec::new();
    for f in cols {
        let col = if f.contains('.') {
            format!("\"{}\"", f.replace('"', "\"\""))
        } else {
            f.clone()
        };
        let alias = f.replace('.', "_");
        parts.push(format!("topK(100)(toString({col})) as {alias}_top"));
        parts.push(format!("uniq({col}) as {alias}_cardinality"));
    }
    format!(
        "SELECT {} FROM {db}.ocsf_logs FORMAT JSONEachRow",
        parts.join(", ")
    )
}

#[tokio::test]
async fn ocsf_field_stats_executes_against_ocsf_logs() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return;
    }
    let client = reqwest::Client::new();
    if !reachable(&client).await {
        eprintln!(
            "Skipping: ClickHouse not reachable at {} as admin (start: docker-compose up -d clickhouse)",
            ch_url()
        );
        return;
    }

    let db = format!(
        "ocsf_fieldstats_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    exec(&client, &format!("CREATE DATABASE {db}"))
        .await
        .expect("create test db");

    let result = run_assertions(&client, &db).await;
    let _ = exec(&client, &format!("DROP DATABASE IF EXISTS {db}")).await;
    result.expect("ocsf field-stats assertions");
}

async fn run_assertions(client: &reqwest::Client, db: &str) -> Result<(), String> {
    exec(client, &test_table_ddl(db)).await?;
    for (name, raw) in FIXTURES {
        insert_event(client, db, raw)
            .await
            .map_err(|e| format!("insert {name}: {e}"))?;
    }

    // Enumerate the OCSF columns the field panel would query.
    let cols = field_stats_columns(client, db).await?;
    if cols.is_empty() {
        return Err("field-stats column enumeration returned no columns".into());
    }

    // `.search` companion columns must NOT appear (the new exclusion). The OCSF
    // table has dotted `.search` companions like `src_endpoint.hostname.search`.
    if cols.iter().any(|c| c.ends_with(".search")) {
        return Err(format!(
            "`.search` companion columns leaked into field-stats columns: {:?}",
            cols.iter().filter(|c| c.ends_with(".search")).collect::<Vec<_>>()
        ));
    }

    // The promoted dotted column and the taxonomy int must be present.
    if !cols.iter().any(|c| c == "src_endpoint.ip") {
        return Err(format!(
            "expected dotted column `src_endpoint.ip` in field-stats columns; got: {cols:?}"
        ));
    }
    if !cols.iter().any(|c| c == "class_uid") {
        return Err(format!(
            "expected `class_uid` in field-stats columns; got: {cols:?}"
        ));
    }

    // Build + execute the field-stats SQL. The headline assertion: NO Code 47.
    let sql = build_field_stats_sql(db, &cols);
    let body = exec(client, &sql).await.map_err(|e| {
        format!("field-stats query failed (the NAN-1241 bug — Code 47 on dotted/UDM columns):\n{sql}\n\n{e}")
    })?;

    let first = body.lines().next().unwrap_or("");
    let row: Value =
        serde_json::from_str(first).map_err(|e| format!("field-stats result JSON: {e}\n{first}"))?;

    // The dotted column resolved: its `uniq` cardinality is present and > 0
    // (src_endpoint.ip is populated on auth/network/dns/http fixtures), and its
    // topK top-values array is non-empty — proving the quoted reference worked.
    let ip_card = row
        .get("src_endpoint_ip_cardinality")
        .and_then(value_to_u64)
        .ok_or("missing src_endpoint_ip_cardinality in field-stats result")?;
    if ip_card == 0 {
        return Err(format!(
            "src_endpoint.ip cardinality is 0, expected > 0; row:\n{row}"
        ));
    }
    let ip_top = row
        .get("src_endpoint_ip_top")
        .and_then(|v| v.as_array())
        .ok_or("missing/!array src_endpoint_ip_top in field-stats result")?;
    if ip_top.is_empty() {
        return Err("src_endpoint.ip topK returned no values".into());
    }

    // class_uid (bare column) also resolved.
    let class_card = row
        .get("class_uid_cardinality")
        .and_then(value_to_u64)
        .ok_or("missing class_uid_cardinality in field-stats result")?;
    if class_card == 0 {
        return Err("class_uid cardinality is 0, expected > 0".into());
    }

    Ok(())
}

fn value_to_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
}
