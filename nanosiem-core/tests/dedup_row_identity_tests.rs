// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-2264 — `dedup <keys>` must emit exactly ONE row per key.
//!
//! NAN-1636 rewrote `dedup` from `ORDER BY <keys>, <time> LIMIT 1 BY <keys>`
//! (which full-sorted every wide ~200-column row and hit Code 241,
//! MergeSortingTransform OOM, at >=~15min windows under the production
//! 3GiB/query profile) to survivor-id selection:
//!
//! ```sql
//! SELECT * FROM <src> WHERE id IN (SELECT argMin(id, timestamp) FROM <src> GROUP BY <keys>)
//! ```
//!
//! That is one-row-per-key ONLY if `id` is unique per PHYSICAL row, and it is
//! not: `ClickHouseLogRow` derives `id` as a CONTENT hash so retried batches
//! insert idempotently. Content-identical rows therefore share an id, MergeTree
//! does not enforce uniqueness, and electing one row as survivor let EVERY row
//! carrying that id through the filter.
//!
//! The fix keeps the sort-free property (no `ORDER BY` over the wide rows) by
//! restricting each group to its oldest timestamp — an aggregate, not a sort —
//! and collapsing the ties with `LIMIT 1 BY <keys>`, which guarantees one row
//! per key by construction, independent of any id.
//!
//! `live_ch::` holds the end-to-end proof against a real ClickHouse. It builds
//! its own scratch table, never touches `nanosiem.logs`, and always drops the
//! table again (see `run_live_probe`).

use chrono::{TimeZone, Utc};
use nanosiem_core::ingestion::ClickHouseLogRow;
use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, Command, TimeRange};
use nanosiem_core::ParsedLog;

fn test_time_range() -> TimeRange {
    TimeRange {
        start: "2026-06-01T00:00:00Z".parse().unwrap(),
        end: "2026-08-01T00:00:00Z".parse().unwrap(),
    }
}

/// Parse nPL → generate SQL through the full pipeline path (the one the search
/// service uses), which is where the dedup rewrite is reachable.
fn npl(query_str: &str) -> String {
    let query = parse_query(query_str)
        .unwrap_or_else(|e| panic!("parse failed for {query_str}: {e}"));
    ClickHouseSqlGenerator::new()
        .generate(&query, &test_time_range())
        .unwrap_or_else(|e| panic!("SQL gen failed for {query_str}: {e}"))
}

/// A `ParsedLog` whose id-bearing content is `(source_type, timestamp, message)`
/// and whose every other field is caller-varied — so a test can prove the id
/// ignores everything outside that triple.
fn parsed_log(message: &str, src_ip: &str, user: &str) -> ParsedLog {
    ParsedLog {
        // Fixed instant: `compute_content_uuid` hashes timestamp micros, so the
        // two rows a test compares must share it exactly.
        timestamp: Utc.with_ymd_and_hms(2026, 7, 1, 0, 0, 0).unwrap(),
        message: message.to_string(),
        metadata: serde_json::json!({}),
        source_type: "nan2264_fixture".to_string(),
        source: Some("test".to_string()),
        src_ip: Some(src_ip.to_string()),
        user: Some(user.to_string()),
        dest_ip: None,
        src_host: None,
        dest_host: None,
        src_port: None,
        dest_port: None,
        protocol: None,
        action: None,
        status: None,
        severity: None,
        auth_type: None,
        auth_result: None,
        session_id: None,
        process_name: None,
        process_id: None,
        command_line: None,
        parent_process_name: None,
        parent_command_line: None,
        file_path: None,
        file_name: None,
        file_hash: None,
        file_action: None,
        bytes_in: None,
        bytes_out: None,
        user_agent: None,
        ext: None,
    }
}

// ============================================================================
// Root cause: `id` is a content hash, not a physical row identity
// ============================================================================

/// The premise NAN-1636's `WHERE id IN (argMin(id, …))` filter relied on, and
/// which does not hold. `ClickHouseLogRow::compute_content_uuid` hashes
/// `source_type + timestamp_micros + message` ONLY — by design, so a retried
/// ingest batch is idempotent (`ingestion/row.rs`). Two physically distinct rows
/// that agree on that triple therefore carry the SAME `id`, and ClickHouse
/// MergeTree stores both.
///
/// If this ever turns red because `id` became a per-row UUID, the survivor-id
/// filter would become sound again — but do not restore it on that basis alone:
/// an explicitly supplied, repeated OCSF id reproduces the same duplicate output.
#[test]
fn content_identical_logs_share_one_id() {
    let ingest = Utc::now();
    // Same (source_type, timestamp, message); DIFFERENT src_ip and user.
    let a = ClickHouseLogRow::from_parsed_log(&parsed_log("same content", "10.0.0.1", "alice"), ingest);
    let b = ClickHouseLogRow::from_parsed_log(&parsed_log("same content", "10.0.0.2", "bob"), ingest);
    assert_eq!(
        a.id, b.id,
        "id is a content hash over (source_type, timestamp, message) — two rows \
         agreeing on it share an id even when the rest of the row differs. \
         This is why `WHERE id IN (…)` cannot select one row per key."
    );

    // …and the hash does depend on the content, so the fixture below really is
    // exercising a collision rather than a constant.
    let c = ClickHouseLogRow::from_parsed_log(&parsed_log("other content", "10.0.0.1", "alice"), ingest);
    assert_ne!(a.id, c.id, "different message must hash to a different id");
}

// ============================================================================
// Generated shape: one row per key, without a full-row sort
// ============================================================================

/// The `LIMIT 1 BY <keys>` is the entire one-row-per-key guarantee — it is what
/// makes the output correct no matter how many physical rows share an id. Its
/// absence is the NAN-2264 bug.
#[test]
fn dedup_collapses_each_key_with_limit_1_by() {
    let sql = npl("* | dedup src_ip");
    assert!(
        sql.contains("LIMIT 1 BY src_ip"),
        "dedup must collapse each key with LIMIT 1 BY — that is the only \
         construct that guarantees one row per key (NAN-2264), got:\n{sql}"
    );
}

/// The candidate set must be each group's OLDEST row (keep-oldest semantics,
/// unchanged since the legacy shape), computed as an aggregate rather than a
/// sort.
#[test]
fn dedup_restricts_candidates_to_the_group_minimum_time() {
    let sql = npl("* | dedup src_ip");
    assert!(
        sql.contains("min(timestamp) FROM stage_0") && sql.contains("GROUP BY src_ip"),
        "dedup must restrict candidates to each key's oldest timestamp, got:\n{sql}"
    );
}

/// The regression NAN-1636 fixed and NAN-2264 must not undo: no `ORDER BY` over
/// the wide rows ahead of the LIMIT BY. That sort is the Code 241
/// (MergeSortingTransform OOM) source at >=~15min windows under the production
/// 3GiB/query profile.
#[test]
fn dedup_does_not_full_sort_the_rows() {
    let sql = npl("* | dedup src_ip");
    assert!(
        !sql.contains("ORDER BY src_ip, timestamp"),
        "dedup must not sort every row before the LIMIT BY (NAN-1636 OOM), got:\n{sql}"
    );
}

/// The survivor-id filter itself. Asserted by absence so a revert to
/// `WHERE id IN (SELECT argMin(id, …))` turns this red rather than passing on a
/// query that merely also has a LIMIT BY.
#[test]
fn dedup_does_not_filter_rows_by_id() {
    let sql = npl("* | dedup src_ip");
    assert!(
        !sql.contains("argMin(id"),
        "dedup must not elect survivors by id — `id` is a content hash shared by \
         content-identical rows, so every row carrying the elected id passes \
         (NAN-2264), got:\n{sql}"
    );
}

/// ClickHouse's `IN` keeps SQL NULL semantics by default (`transform_null_in =
/// 0`), so a tuple carrying NULL matches nothing. A bare `(<keys>, <time>) IN
/// (…)` would silently DROP every row whose dedup key is NULL — reachable today
/// (`enrich_time` is Nullable, as is any eval-computed key) — where the legacy
/// shape kept one row for the NULL group.
#[test]
fn dedup_key_matching_is_null_safe() {
    let sql = npl("* | dedup src_ip");
    assert!(
        sql.contains("isNull(src_ip), assumeNotNull(src_ip)"),
        "dedup key matching must be NULL-total, or a NULL-keyed group is dropped \
         entirely instead of collapsing to one row, got:\n{sql}"
    );
}

/// Every key must reach all three of: the candidate match, the grouping, and the
/// LIMIT BY. A key present in only some of them silently changes the grain.
#[test]
fn dedup_threads_every_key_through_match_group_and_limit_by() {
    let sql = npl("* | dedup src_ip, dest_ip, dest_port");
    for key in ["src_ip", "dest_ip", "dest_port"] {
        assert!(
            sql.contains(&format!("isNull({key}), assumeNotNull({key})")),
            "key {key} missing from the candidate match, got:\n{sql}"
        );
    }
    assert!(
        sql.contains("GROUP BY src_ip, dest_ip, dest_port"),
        "every key must reach the GROUP BY, got:\n{sql}"
    );
    assert!(
        sql.contains("LIMIT 1 BY src_ip, dest_ip, dest_port"),
        "every key must reach the LIMIT BY, got:\n{sql}"
    );
}

/// `uniq` is an alias for `dedup` — compared against dedup's own SQL so the two
/// can never drift apart silently.
#[test]
fn uniq_alias_matches_dedup() {
    let uniq_sql = npl("* | uniq src_ip");
    assert_eq!(uniq_sql, npl("* | dedup src_ip"), "uniq must lower to dedup");
    assert!(
        uniq_sql.contains("LIMIT 1 BY src_ip") && !uniq_sql.contains("argMin(id"),
        "uniq must inherit the corrected dedup shape, got:\n{uniq_sql}"
    );
}

// ============================================================================
// The guarded split — the rewrite only applies to the deterministic base scan
// ============================================================================

/// The rewrite scans its source CTE twice (outer + IN-subquery), so it is only
/// sound when that source is the deterministic base scan. An upstream `head`
/// with no ORDER BY could sample different rows per scan, so dedup must fall
/// back to the single-scan legacy shape there.
#[test]
fn dedup_after_a_nondeterministic_stage_keeps_the_legacy_shape() {
    let sql = npl("* | head 100 | dedup src_ip");
    assert!(
        sql.contains("ORDER BY src_ip, timestamp") && sql.contains("LIMIT 1 BY src_ip"),
        "dedup over a LIMITed upstream must keep the single-scan legacy shape, got:\n{sql}"
    );
    assert!(
        !sql.contains("isNull(src_ip), assumeNotNull(src_ip)"),
        "the double-scan rewrite must not apply to a nondeterministic source, got:\n{sql}"
    );
}

/// `generate_command_sql` — the public no-context API used by subsearch nesting
/// and prevalence re-embedding — never receives the deterministic base scan, so
/// it deliberately keeps the legacy shape. This path had no live coverage before
/// NAN-2264 (its assertions lived in an orphaned, never-compiled test dir).
#[test]
fn nested_command_path_keeps_the_legacy_shape() {
    let sql = ClickHouseSqlGenerator::new()
        .generate_command_sql(
            "inner_0",
            &Command::Dedup {
                fields: vec!["src_ip".to_string()],
                keep_first: true,
            },
        )
        .expect("dedup command SQL should generate");
    assert!(
        sql.contains("ORDER BY src_ip, timestamp") && sql.contains("LIMIT 1 BY src_ip"),
        "the no-context command path must keep the legacy shape, got:\n{sql}"
    );
    assert!(
        !sql.contains("argMin(id") && !sql.contains("min(timestamp)"),
        "the no-context command path must not emit a double-scan rewrite, got:\n{sql}"
    );
}

// ============================================================================
// End-to-end against a real ClickHouse
// ============================================================================

/// Result correctness, not SQL text: the shape assertions above all pass on a
/// query that still returns two rows for one key, which is exactly how NAN-2264
/// survived NAN-1636's test suite.
mod live_ch {
    use super::*;
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
        // The generated SQL names the scratch table unqualified (`FROM <table>`),
        // so the session database has to carry the qualification.
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

    /// Everything the probe learned, gathered so the caller can DROP the scratch
    /// table BEFORE asserting — a panic mid-probe would otherwise leave a table
    /// behind on the developer's long-lived ClickHouse.
    struct Probe {
        rows_inserted: u32,
        distinct_ids: u32,
        survivors: Vec<String>,
    }

    async fn run_live_probe(client: &reqwest::Client, table: &str, sql: &str) -> Result<Probe, String> {
        // A private copy of the real `logs` structure — same engine, ORDER BY,
        // partitioning and column types, but its own storage. Nothing here
        // reaches `nanosiem.logs`, its materialized views, or Postgres.
        exec(
            client,
            &format!("CREATE TABLE {db}.{table} AS {db}.logs", db = ch_db()),
        )
        .await?;

        // Two rows whose ids are the REAL content hash, computed by the
        // production ingestion path, plus a second key with two distinct rows so
        // the probe also proves keep-oldest still holds.
        let ingest = Utc::now();
        let dup_a = ClickHouseLogRow::from_parsed_log(&parsed_log("dup content", "10.0.0.1", "alice"), ingest);
        let dup_b = ClickHouseLogRow::from_parsed_log(&parsed_log("dup content", "10.0.0.1", "bob"), ingest);
        assert_eq!(dup_a.id, dup_b.id, "fixture precondition: shared content id");

        exec(
            client,
            &format!(
                "INSERT INTO {db}.{table} (id, timestamp, source_type, message, src_ip) VALUES \
                 ('{dup}', '2026-07-01 00:00:00.000000', 'nan2264_fixture', 'dup content', '10.0.0.1'), \
                 ('{dup}', '2026-07-01 00:00:00.000000', 'nan2264_fixture', 'dup content', '10.0.0.1'), \
                 ('{u2}', '2026-07-01 00:00:00.000000', 'nan2264_fixture', 'b-oldest', '10.0.0.2'), \
                 ('{u3}', '2026-07-01 00:05:00.000000', 'nan2264_fixture', 'b-newer', '10.0.0.2')",
                db = ch_db(),
                dup = dup_a.id,
                u2 = Uuid::new_v4(),
                u3 = Uuid::new_v4(),
            ),
        )
        .await?;

        let counts = exec(
            client,
            &format!(
                "SELECT count(), uniqExact(id) FROM {db}.{table} FORMAT TSV",
                db = ch_db()
            ),
        )
        .await?;
        let mut parts = counts.trim().split('\t');
        let rows_inserted = parts.next().unwrap_or("0").parse().unwrap_or(0);
        let distinct_ids = parts.next().unwrap_or("0").parse().unwrap_or(0);

        // The generated SQL already carries its own SETTINGS clause, so it must
        // run as-is rather than be wrapped in a counting subquery.
        let out = exec(client, sql).await?;
        let survivors = out
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect();

        Ok(Probe {
            rows_inserted,
            distinct_ids,
            survivors,
        })
    }

    /// Two physical rows sharing a content-hash id and a dedup key must yield
    /// ONE survivor. Before NAN-2264 this returned both (the elected survivor id
    /// matched every row carrying it).
    ///
    /// Skipped when `SKIP_DB_TESTS` is set or ClickHouse is unreachable, matching
    /// the other DB-backed tests in this crate.
    #[tokio::test]
    async fn dedup_emits_one_row_per_key_when_rows_share_an_id() {
        if std::env::var("SKIP_DB_TESTS").is_ok() {
            println!("Skipping (SKIP_DB_TESTS is set)");
            return;
        }
        let client = reqwest::Client::new();
        if exec(&client, "SELECT 1").await.is_err() {
            println!("Skipping: no ClickHouse at {} (docker-compose up -d clickhouse)", ch_url());
            return;
        }

        let table = format!("nan2264_dedup_{}", Uuid::new_v4().simple());
        let query = parse_query("* | dedup src_ip").expect("dedup query parses");
        let sql = ClickHouseSqlGenerator::with_table(&table)
            .generate(&query, &test_time_range())
            .expect("dedup SQL generates");

        let probe = run_live_probe(&client, &table, &sql).await;

        // Cleanup FIRST, unconditionally, so an assertion failure below cannot
        // strand the table; then prove there is no residue.
        let dropped = exec(
            &client,
            &format!("DROP TABLE IF EXISTS {db}.{table}", db = ch_db()),
        )
        .await;
        let residue = exec(
            &client,
            &format!(
                "SELECT count() FROM system.tables WHERE database = '{db}' \
                 AND name LIKE 'nan2264_dedup_%' FORMAT TSV",
                db = ch_db()
            ),
        )
        .await;

        let probe = probe.expect("live dedup probe should run");
        assert_eq!(probe.rows_inserted, 4, "fixture should hold 4 physical rows");
        assert_eq!(
            probe.distinct_ids, 3,
            "fixture precondition: two of the four rows must share one id"
        );
        assert_eq!(
            probe.survivors.len(),
            2,
            "dedup src_ip over 2 distinct keys must emit exactly 2 rows, got:\n{:#?}",
            probe.survivors
        );
        assert_eq!(
            probe
                .survivors
                .iter()
                .filter(|r| r.contains("dup content"))
                .count(),
            1,
            "the two rows sharing a content-hash id must collapse to one (NAN-2264), got:\n{:#?}",
            probe.survivors
        );
        assert!(
            probe.survivors.iter().any(|r| r.contains("b-oldest"))
                && !probe.survivors.iter().any(|r| r.contains("b-newer")),
            "dedup must keep each key's OLDEST row, got:\n{:#?}",
            probe.survivors
        );

        dropped.expect("scratch table should drop");
        assert_eq!(
            residue.expect("residue check should run").trim(),
            "0",
            "the test must leave no scratch tables behind"
        );
    }
}
