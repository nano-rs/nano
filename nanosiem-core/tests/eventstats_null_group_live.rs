// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-4296 review fix — grouped `eventstats` must keep an all-NULL group's
//! aggregate NULL.
//!
//! The per-group scalar is a `(keys, values)` pair of arrays looked up with
//! `transform`. `groupArray` skips NULL inputs, so an unwrapped Nullable
//! aggregate either drops its group or misaligns the arrays, and the lookup's
//! missing-key default then turns the group's NULL into 0. With window
//! semantics `avg(x) OVER (PARTITION BY k)` is NULL for a group whose every `x`
//! is NULL, so `| where avg_bytes = 0` must match nothing for that group — a
//! zero there is a false positive for any `<` / `=` threshold detection.
//!
//! The probe runs the generated SQL against a real ClickHouse on a private
//! scratch table (never `nanosiem.logs`) and always drops it.

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use uuid::Uuid;

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}
fn ch_user() -> String {
    std::env::var("CLICKHOUSE_TEST_USER").unwrap_or_else(|_| "nanosiem".into())
}
fn ch_pass() -> String {
    std::env::var("CLICKHOUSE_TEST_PASSWORD").unwrap_or_else(|_| "nanosiem".into())
}
fn ch_db() -> String {
    std::env::var("CLICKHOUSE_TEST_DB").unwrap_or_else(|_| "nanosiem".into())
}

async fn exec(client: &reqwest::Client, sql: &str) -> Result<String, String> {
    let resp = client
        .post(format!("{}?database={}", ch_url(), ch_db()))
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

fn time_range() -> TimeRange {
    TimeRange {
        start: "2026-07-01T00:00:00Z".parse().unwrap(),
        end: "2026-07-02T00:00:00Z".parse().unwrap(),
    }
}

fn sql_for(table: &str, npl: &str) -> String {
    ClickHouseSqlGenerator::with_table(table)
        .generate(&parse_query(npl).unwrap(), &time_range())
        .unwrap_or_else(|e| panic!("SQL gen failed for {npl}: {e}"))
}

/// Run `sql` and return its TSV lines (sorted, so assertions are order-free).
/// The generated SQL carries its own SETTINGS clause, so it runs as-is with
/// only a FORMAT appended.
async fn lines(client: &reqwest::Client, sql: &str) -> Result<Vec<String>, String> {
    let out = exec(client, &format!("{sql} FORMAT TSV")).await?;
    let mut v: Vec<String> = out.lines().filter(|l| !l.is_empty()).map(str::to_string).collect();
    v.sort();
    Ok(v)
}

struct Probe {
    zero_matches: Result<Vec<String>, String>,
    per_host: Result<Vec<String>, String>,
}

async fn run(client: &reqwest::Client, table: &str) -> Result<Probe, String> {
    // A private copy of the real `logs` structure (the generated SQL projects
    // its UDM columns); nothing reaches `nanosiem.logs` or its views.
    exec(client, &format!("CREATE TABLE {db}.{table} AS {db}.logs", db = ch_db())).await?;
    // host-null carries the sentinel -1, which `nullif(.., -1)` turns into
    // NULL on every row of that group → window avg is NULL.
    // host-zero: 0, 0 → avg 0 (positive control: must match `= 0`).
    // host-ten:  5, 15 → avg 10.
    exec(
        client,
        &format!(
            "INSERT INTO {db}.{table} (id, timestamp, source_type, message, src_host, ext) VALUES \
             (generateUUIDv4(), '2026-07-01 01:00:00', 'nan4296', 'a', 'host-null', '{{\"bytes\":-1}}'), \
             (generateUUIDv4(), '2026-07-01 01:01:00', 'nan4296', 'b', 'host-null', '{{\"bytes\":-1}}'), \
             (generateUUIDv4(), '2026-07-01 01:02:00', 'nan4296', 'c', 'host-zero', '{{\"bytes\":0}}'), \
             (generateUUIDv4(), '2026-07-01 01:03:00', 'nan4296', 'd', 'host-zero', '{{\"bytes\":0}}'), \
             (generateUUIDv4(), '2026-07-01 01:04:00', 'nan4296', 'e', 'host-ten', '{{\"bytes\":5}}'), \
             (generateUUIDv4(), '2026-07-01 01:05:00', 'nan4296', 'f', 'host-ten', '{{\"bytes\":15}}')",
            db = ch_db()
        ),
    )
    .await?;

    let zero = sql_for(
        table,
        "* | eval b=nullif(tonumber(ext.bytes), -1) | eventstats avg(b) as avg_bytes by src_host | where avg_bytes = 0 | stats count by src_host",
    );
    let per_host = sql_for(
        table,
        "* | eval b=nullif(tonumber(ext.bytes), -1) | eventstats avg(b) as avg_bytes by src_host | stats count, max(avg_bytes) as a by src_host",
    );
    Ok(Probe {
        zero_matches: lines(client, &zero).await,
        per_host: lines(client, &per_host).await,
    })
}

#[tokio::test]
async fn all_null_group_aggregate_stays_null_through_where() {
    if std::env::var("SKIP_DB_TESTS").map(|v| v == "1" || v == "true").unwrap_or(false) {
        println!("Skipping (SKIP_DB_TESTS is set)");
        return;
    }
    let client = reqwest::Client::new();
    if exec(&client, "SELECT 1").await.is_err() {
        println!("Skipping: no ClickHouse at {}", ch_url());
        return;
    }

    // The emitted shape keeps every group and wraps the value (no NULL filter).
    let sql = sql_for("t", "* | eval b=nullif(tonumber(ext.bytes), -1) | eventstats avg(b) as avg_bytes by src_host");
    assert!(
        sql.contains("groupArray(tuple(__nano_v))") && !sql.contains("isNotNull(__nano_v)"),
        "group values must be tuple-wrapped, not NULL-filtered:\n{sql}"
    );

    let table = format!("nan4296_null_group_{}", Uuid::new_v4().simple());
    let probe = run(&client, &table).await;
    let _ = exec(&client, &format!("DROP TABLE IF EXISTS {}.{table}", ch_db())).await;
    let probe = probe.expect("live probe ran");

    let zero = probe.zero_matches.expect("where-stage query ran");
    assert_eq!(
        zero,
        vec!["host-zero\t2".to_string()],
        "only the genuine 0-average group may match `avg_bytes = 0`; an all-NULL group must not"
    );
    let per_host = probe.per_host.expect("per-host query ran");
    assert!(
        per_host.contains(&"host-null\t2\t\\N".to_string()),
        "all-NULL group keeps a NULL aggregate on every row: {per_host:?}"
    );
    assert!(per_host.contains(&"host-ten\t2\t10".to_string()), "{per_host:?}");
    assert!(per_host.contains(&"host-zero\t2\t0".to_string()), "{per_host:?}");
}
