// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1407 — staging-table indirection smoke harness (the issue's Option 4).
//!
//! Pins the entire insert-path-resilience guarantee on a miniature replica of
//! the production shape (migration 133): a source table → a plain MergeTree
//! staging table → a full-replace refreshable MV → a dictionary sourced from
//! `SELECT ... FROM <staging>` → a landing table with a MATERIALIZED
//! `dictGetOrDefault` column. Then it breaks the REFRESH (the only place a
//! complex query can now fail — all four historical FAILED-dict ingestion
//! halts were source-query failures: NAN-1114/1117/1120/1404) and asserts:
//!
//!   (a) the failure is VISIBLE — `system.view_refreshes.exception` carries
//!       it (26.4 note: there is NO last_refresh_result column; exception /
//!       retry / last_success_time are the signal columns the siem-health
//!       staleness probe reads);
//!   (b) the staging table KEEPS the last good data (full-replace only swaps
//!       on success);
//!   (c) INSERTs into the landing table still land, enriched from the stale
//!       snapshot — the exact opposite of the old design, where a FAILED
//!       dict made every insert THROW;
//!   (d) after DETACH/ATTACH of the dictionary (restart simulation — the
//!       fatal Saturn window was first-load-after-restart with a broken
//!       source) inserts STILL land: the lazy first load reads the intact
//!       staging table.
//!
//! Requires a local ClickHouse with DDL rights. Skips cleanly if unreachable
//! or if `SKIP_DB_TESTS` is set.
//!   Run: cargo test -p nanosiem-core --test dict_staging_resilience -- --nocapture
//!   (local dev CH: docker-compose up -d clickhouse)

use std::time::{Duration, Instant};

const DB: &str = "nan1407_staging_harness";

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}
fn ch_user() -> String {
    std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or_else(|_| "nanosiem_admin".into())
}
fn ch_pass() -> String {
    std::env::var("CLICKHOUSE_ADMIN_PASSWORD").unwrap_or_else(|_| "nanosiem_admin_secret".into())
}

/// Execute one statement; returns the response body, or Err with CH's message.
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

async fn exec_ok(client: &reqwest::Client, sql: &str) -> String {
    exec(client, sql)
        .await
        .unwrap_or_else(|e| panic!("statement failed: {sql}\n{e}"))
}

async fn reachable(client: &reqwest::Client) -> bool {
    exec(client, "SELECT 1")
        .await
        .map(|b| b.trim() == "1")
        .unwrap_or(false)
}

/// Poll `sql` until its trimmed result equals `expected`, or panic after the
/// deadline with the last observed value.
async fn poll_until(client: &reqwest::Client, sql: &str, expected: &str, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    while Instant::now() < deadline {
        last = exec_ok(client, sql).await.trim().to_string();
        if last == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("timed out waiting for {what}: wanted {expected:?}, last saw {last:?} ({sql})");
}

/// The refresh-MV body used while "healthy" — an aggregating stand-in for the
/// production dict source queries (argMax dedup, like user_registry/ip dicts).
fn good_refresh_query() -> String {
    format!("SELECT k, argMax(v, version) AS v FROM {DB}.src GROUP BY k")
}

#[tokio::test]
async fn broken_refresh_degrades_enrichment_but_never_inserts() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("SKIP_DB_TESTS set — skipping");
        return;
    }
    let client = reqwest::Client::new();
    if !reachable(&client).await {
        eprintln!("ClickHouse not reachable at {} — skipping", ch_url());
        return;
    }

    // Fresh throwaway database (fixed name so a previous panicked run is
    // cleaned up by the next one).
    exec_ok(&client, &format!("DROP DATABASE IF EXISTS {DB}")).await;
    exec_ok(&client, &format!("CREATE DATABASE {DB}")).await;

    // --- Build the miniature production shape -----------------------------
    exec_ok(
        &client,
        &format!(
            "CREATE TABLE {DB}.src (k String, v String, version UInt64) \
             ENGINE = ReplacingMergeTree(version) ORDER BY k"
        ),
    )
    .await;
    exec_ok(
        &client,
        &format!(
            "INSERT INTO {DB}.src VALUES ('alice','engineering',1),\
             ('alice','security',2),('bob','finance',1)"
        ),
    )
    .await;

    // Plain (non-replicated) staging — the per-replica copy of the dict's
    // payload. Migration 133 tags this with nano:keep-local-engine; on the
    // single-node harness the plain engine needs no marker handling.
    exec_ok(
        &client,
        &format!("CREATE TABLE {DB}.mini_dict_staging (k String, v String) ENGINE = MergeTree ORDER BY k"),
    )
    .await;

    // Full-replace refreshable MV. The CREATE schedules an initial refresh;
    // wait for it to succeed before building the dict on top.
    exec_ok(
        &client,
        &format!(
            "CREATE MATERIALIZED VIEW {DB}.mini_dict_refresh \
             REFRESH EVERY 5 MINUTE TO {DB}.mini_dict_staging AS {}",
            good_refresh_query()
        ),
    )
    .await;
    poll_until(
        &client,
        &format!("SELECT count() FROM {DB}.mini_dict_staging"),
        "2",
        "initial refresh to populate staging",
    )
    .await;

    // Dictionary sourced from the staging table (the NAN-1407 repoint shape;
    // creds flow exactly like the {clickhouse_self_*} substitution does in
    // production — the dict loads by connecting back into the server).
    exec_ok(
        &client,
        &format!(
            "CREATE DICTIONARY {DB}.mini_dict (k String, v String DEFAULT '') PRIMARY KEY k \
             SOURCE(CLICKHOUSE(HOST 'localhost' PORT 9000 USER '{}' PASSWORD '{}' \
             DB '{DB}' QUERY 'SELECT k, v FROM {DB}.mini_dict_staging')) \
             LIFETIME(MIN 60 MAX 120) LAYOUT(COMPLEX_KEY_HASHED())",
            ch_user(),
            ch_pass()
        ),
    )
    .await;

    // Landing table with a MATERIALIZED dictGetOrDefault column — the
    // nanosiem.logs enrichment-column shape that turned FAILED dicts into
    // total ingestion halts.
    exec_ok(
        &client,
        &format!(
            "CREATE TABLE {DB}.landing (k String, \
             e String MATERIALIZED dictGetOrDefault('{DB}.mini_dict','v',k,'')) \
             ENGINE = MergeTree ORDER BY k"
        ),
    )
    .await;
    exec_ok(&client, &format!("INSERT INTO {DB}.landing (k) VALUES ('alice')")).await;
    let enriched = exec_ok(
        &client,
        &format!("SELECT e FROM {DB}.landing WHERE k = 'alice'"),
    )
    .await;
    assert_eq!(
        enriched.trim(),
        "security",
        "healthy path: MATERIALIZED column enriches from the staging-backed dict"
    );

    // --- Break the REFRESH (the only failure point left) ------------------
    exec_ok(&client, &format!("DROP TABLE {DB}.mini_dict_refresh")).await;
    exec_ok(
        &client,
        &format!(
            "CREATE MATERIALIZED VIEW {DB}.mini_dict_refresh \
             REFRESH EVERY 5 MINUTE TO {DB}.mini_dict_staging AS \
             SELECT k, argMax(v, version) AS v FROM {DB}.src \
             WHERE throwIf(1, 'NAN-1407 harness: refresh deliberately broken') = 0 \
             GROUP BY k"
        ),
    )
    .await;
    // The create-time initial refresh fails; force one more for determinism
    // and wait until the failure is recorded.
    let _ = exec(&client, &format!("SYSTEM REFRESH VIEW {DB}.mini_dict_refresh")).await;
    poll_until(
        &client,
        &format!(
            "SELECT countIf(exception != '') FROM system.view_refreshes \
             WHERE database = '{DB}' AND view = 'mini_dict_refresh'"
        ),
        "1",
        "broken refresh to surface its exception",
    )
    .await;

    // (a) The failure is visible through exactly the columns the siem-health
    // staleness probe queries (exception / retry / last_success_time).
    let exception = exec_ok(
        &client,
        &format!(
            "SELECT substring(exception, 1, 100) FROM system.view_refreshes \
             WHERE database = '{DB}' AND view = 'mini_dict_refresh'"
        ),
    )
    .await;
    assert!(
        exception.contains("deliberately broken"),
        "system.view_refreshes must carry the refresh exception, got: {exception}"
    );

    // (b) Staging keeps the last good snapshot — full-replace only swaps on
    // success.
    let staging_rows = exec_ok(&client, &format!("SELECT count() FROM {DB}.mini_dict_staging")).await;
    assert_eq!(
        staging_rows.trim(),
        "2",
        "staging must retain the last good rows while the refresh fails"
    );

    // (c) Inserts STILL land, enriched from the stale snapshot. Under the old
    // design (dict sourced from the complex query) this exact scenario made
    // every insert THROW once the dict next reloaded.
    exec_ok(&client, &format!("INSERT INTO {DB}.landing (k) VALUES ('bob')")).await;
    let bob = exec_ok(&client, &format!("SELECT e FROM {DB}.landing WHERE k = 'bob'")).await;
    assert_eq!(
        bob.trim(),
        "finance",
        "insert during a hard-failing refresh must land with stale-snapshot enrichment"
    );

    // (d) Restart simulation: DETACH/ATTACH drops the dict to NOT_LOADED (the
    // Saturn 36h window — first load after restart). The lazy first load now
    // reads the intact staging table instead of the broken query.
    exec_ok(&client, &format!("DETACH DICTIONARY {DB}.mini_dict")).await;
    exec_ok(&client, &format!("ATTACH DICTIONARY {DB}.mini_dict")).await;
    exec_ok(&client, &format!("INSERT INTO {DB}.landing (k) VALUES ('alice')")).await;
    let counts = exec_ok(
        &client,
        &format!("SELECT count(), countIf(e != '') FROM {DB}.landing"),
    )
    .await;
    assert_eq!(
        counts.trim(),
        "3\t3",
        "after restart-sim with the refresh still broken, inserts land AND enrich"
    );

    exec_ok(&client, &format!("DROP DATABASE {DB}")).await;
}
