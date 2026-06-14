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
    let stmt = format!("INSERT INTO {db}.ocsf_logs_raw (event) FORMAT JSONEachRow").replace(' ', "%20");
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
fn test_table_ddl(db: &str) -> Vec<String> {
    // NAN-1443: the OCSF table is now three objects — `ocsf_logs_raw` (ENGINE=Null
    // landing table), `ocsf_logs_raw_mv` (derives the row), and `ocsf_logs`
    // (MergeTree storage; the `*_unified` columns are inline in its CREATE). They
    // are contiguous, ahead of the `CREATE OR REPLACE DICTIONARY` statements.
    // Extract that block, strip `--` comments + the TTL clause, split into the
    // individual statements (the CH HTTP endpoint rejects multi-statement bodies),
    // and repoint at the throwaway DB. Inserts go to `ocsf_logs_raw`; reads hit
    // `ocsf_logs`. `dictGet('nanosiem.…')` refs stay cross-DB to the real dicts.
    let start = DDL
        .find("CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs_raw")
        .expect("ocsf_logs_raw CREATE TABLE in DDL");
    let end = DDL[start..]
        .find("CREATE OR REPLACE DICTIONARY")
        .map(|i| start + i)
        .expect("dictionaries follow the ocsf_logs table block");
    DDL[start..end]
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => &l[..i],
            None => l,
        })
        .filter(|l| !l.trim_start().starts_with("TTL "))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(|s| s.trim().replace("nanosiem.ocsf_logs", &format!("{db}.ocsf_logs")))
        .filter(|s| !s.trim().is_empty())
        .collect()
}

/// Mirror of `ClickHouseExecutor::get_table_columns`'s `system.columns` filter,
/// including the new `%.search` exclusion that drops OCSF's dotted `_search`
/// companion columns. Returns `(name, default_kind)` rows for `<db>.ocsf_logs`;
/// the NAN-1397 companion-safety filter (MATERIALIZED ∧ not re-added →
/// excluded) is applied by the caller so the raw enumeration can also be
/// asserted against.
async fn field_stats_column_rows(
    client: &reqwest::Client,
    db: &str,
) -> Result<Vec<(String, String)>, String> {
    let sql = format!(
        "SELECT name, default_kind FROM system.columns \
         WHERE database = '{db}' AND table = 'ocsf_logs' \
           AND type NOT LIKE '%Array%' \
           AND type NOT LIKE '%Map%' \
           AND type NOT LIKE 'JSON%' \
           AND name NOT LIKE '\\_%' \
           AND name NOT LIKE '%_search' \
           AND name NOT LIKE '%.search' \
           AND name NOT LIKE 'prevalence_%' \
           AND default_kind != 'ALIAS' \
           AND name NOT IN ('ext', 'metadata', 'event_id', 'ingest_time', 'namespace', 'event_bytes') \
         ORDER BY name FORMAT JSONEachRow"
    );
    let body = exec(client, &sql).await?;
    Ok(body
        .lines()
        .filter_map(|l| {
            let v = serde_json::from_str::<Value>(l).ok()?;
            let name = v.get("name")?.as_str()?.to_string();
            let kind = v
                .get("default_kind")
                .and_then(|k| k.as_str())
                .unwrap_or("")
                .to_string();
            Some((name, kind))
        })
        .collect())
}

/// Mirror of `ClickHouseExecutor::is_companion_safe_column` (NAN-1397): a
/// MATERIALIZED column survives the inventory only if the active profile's
/// CTE re-add list projects it — otherwise it is invisible inside the
/// companion's subquery wrap (`SELECT *` excludes MATERIALIZED) and the
/// `topK(toString(col))` is a guaranteed Code 47.
fn apply_companion_safety_filter(
    rows: &[(String, String)],
    cte_visible_materialized: &[&str],
) -> Vec<String> {
    rows.iter()
        .filter(|(name, kind)| {
            kind != "MATERIALIZED" || cte_visible_materialized.contains(&name.as_str())
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// Replicate the exact `topK`/`uniq` field-stats SELECT shape that
/// `build_field_stats_sql` emits: dotted columns double-quoted inside
/// `toString`/`uniq`, alias dots collapsed to underscores.
fn build_field_stats_sql(db: &str, cols: &[String]) -> String {
    format!(
        "SELECT {} FROM {db}.ocsf_logs FORMAT JSONEachRow",
        field_stats_select_parts(cols).join(", ")
    )
}

fn field_stats_select_parts(cols: &[String]) -> Vec<String> {
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
    parts
}

/// Replicate the companion shape the production path emits for multi-CTE
/// pipelines (the NAN-1315 subquery wrap): the inner scope mirrors stage_0's
/// `SELECT *, <profile re-add list>` projection, so any inventory column that
/// is MATERIALIZED and NOT re-added (e.g. `event_bytes`) does not resolve —
/// the exact NAN-1397 Code 47.
fn build_wrapped_field_stats_sql(db: &str, cols: &[String], readd: &[&str]) -> String {
    let readd_cols = readd
        .iter()
        .map(|c| {
            if c.contains('.') {
                format!("\"{}\"", c.replace('"', "\"\""))
            } else {
                (*c).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "SELECT {} FROM (SELECT *, {readd_cols} FROM {db}.ocsf_logs) FORMAT JSONEachRow",
        field_stats_select_parts(cols).join(", ")
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
    for stmt in test_table_ddl(db) {
        exec(client, &stmt).await?;
    }
    for (name, raw) in FIXTURES {
        insert_event(client, db, raw)
            .await
            .map_err(|e| format!("insert {name}: {e}"))?;
    }

    // Enumerate the OCSF columns the field panel would query.
    let rows = field_stats_column_rows(client, db).await?;
    if rows.is_empty() {
        return Err("field-stats column enumeration returned no columns".into());
    }

    // NAN-1443: `event_bytes` was MATERIALIZED (so the companion-safety filter
    // below dropped it). Under the Null+MV chop it is a PLAIN column the
    // `ocsf_logs_raw_mv` populates, so the `SELECT *`-excludes-MATERIALIZED logic
    // no longer catches it — it is excluded at the SQL stage by name instead, and
    // must not reach the enumeration at all.
    if rows.iter().any(|(n, _)| n == "event_bytes") {
        return Err(format!(
            "`event_bytes` leaked into the field-stats enumeration — a plain metering \
             column must be excluded by name (NAN-1443); got: {rows:?}"
        ));
    }

    use nanosiem_core::schema::{OcsfProfile, SchemaProfile, OCSF_BOOKKEEPING_COLUMNS};
    let profile = OcsfProfile::new();
    let readd = profile.materialized_columns();
    let cols = apply_companion_safety_filter(&rows, readd);

    // Defensive: `event_bytes` must NOT reach the analyst-facing field-stats
    // inventory under any path (NAN-1397/1443).
    if cols.iter().any(|c| c == "event_bytes") {
        return Err("`event_bytes` leaked into the field-stats inventory (NAN-1397/1443)".into());
    }

    // Chokepoint for the next metering column: every surviving inventory
    // column registered in the BOOKKEEPING set must be CTE-visible — either
    // `SELECT *`-visible (non-MATERIALIZED) or in the profile's re-add list.
    for (name, kind) in &rows {
        if OCSF_BOOKKEEPING_COLUMNS.contains(&name.as_str())
            && cols.contains(name)
            && kind == "MATERIALIZED"
            && !readd.contains(&name.as_str())
        {
            return Err(format!(
                "bookkeeping column `{name}` is MATERIALIZED, not re-added, and still in the field-stats inventory (NAN-1397 regression)"
            ));
        }
    }

    // `.search` companion columns must NOT appear (the new exclusion). The OCSF
    // table has dotted `.search` companions like `src_endpoint.hostname.search`.
    // Asserted against the RAW enumeration so the SQL-level `%.search` filter is
    // pinned independently of the NAN-1397 companion-safety filter (which would
    // otherwise mask a regression — `.search` columns are also MATERIALIZED).
    if rows.iter().any(|(c, _)| c.ends_with(".search")) {
        return Err(format!(
            "`.search` companion columns leaked into field-stats columns: {:?}",
            rows.iter()
                .filter(|(c, _)| c.ends_with(".search"))
                .collect::<Vec<_>>()
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

    // NAN-1397 end-to-end: the companion in its multi-CTE WRAPPED shape
    // (`FROM (SELECT *, <re-add list> FROM ocsf_logs)`) must also execute
    // cleanly over the filtered inventory. Before the fix, `event_bytes` was
    // in the inventory but invisible in this scope → Code 47 on every wrapped
    // OCSF search (eval/rex/risk/join pipelines).
    let wrapped_sql = build_wrapped_field_stats_sql(db, &cols, readd);
    exec(client, &wrapped_sql).await.map_err(|e| {
        format!(
            "WRAPPED field-stats query failed (the NAN-1397 bug — a MATERIALIZED \
             non-re-added column leaked into the inventory):\n{e}"
        )
    })?;

    Ok(())
}

fn value_to_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
}
