//! Pipeline command SQL generation tests.
//!
//! These are integration tests that verify nPL queries parse and generate
//! valid ClickHouse SQL — especially for newer commands (resolve_identity,
//! prevalence, anomaly) and tricky command combinations (table → resolve_identity).
//!
//! Run with: cargo test -p nanosiem-core --test pipeline_command_tests

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};

fn test_time_range() -> TimeRange {
    TimeRange {
        start: "2024-01-01T00:00:00Z".parse().unwrap(),
        end: "2024-01-02T00:00:00Z".parse().unwrap(),
    }
}

/// Parse nPL query → generate ClickHouse SQL. Panics with context on failure.
fn npl(query_str: &str) -> String {
    let query = parse_query(query_str)
        .unwrap_or_else(|e| panic!("Parse failed for: {}\nError: {}", query_str, e));
    let gen = ClickHouseSqlGenerator::new();
    gen.generate(&query, &test_time_range())
        .unwrap_or_else(|e| panic!("SQL gen failed for: {}\nError: {}", query_str, e))
}

// ============================================================================
// resolve_identity
// ============================================================================

#[test]
fn resolve_identity_basic() {
    let sql = npl("* | resolve_identity field=src_ip");
    assert!(
        sql.contains("ASOF LEFT JOIN"),
        "Missing ASOF JOIN"
    );
    // NAN-1638: the build side is a subquery bounded to the query window, not
    // the bare table — ASOF JOINing all of identity_observations read the whole
    // table on every resolve. Assert the bound, not just the join: an unbounded
    // `ASOF LEFT JOIN identity_observations` would still satisfy the line above.
    assert!(
        sql.contains("FROM identity_observations")
            && sql.contains("WHERE observed_at BETWEEN"),
        "ASOF build side must stay window-bounded (NAN-1638), got:\n{sql}"
    );
    assert!(
        sql.contains("main.src_ip = i.ip"),
        "Missing join condition on src_ip"
    );
    assert!(
        sql.contains("identity_confidence"),
        "Missing identity_confidence column"
    );
    assert!(
        sql.contains("identity_source"),
        "Missing identity_source column"
    );
}

#[test]
fn resolve_identity_dest_ip() {
    let sql = npl("* | resolve_identity field=dest_ip");
    assert!(
        sql.contains("main.dest_ip = i.ip"),
        "Should join on dest_ip"
    );
}

#[test]
fn resolve_identity_fills_empty_src_host() {
    // Without prior table command, src_host exists → fill-if-empty logic
    let sql = npl("* | resolve_identity field=src_ip");
    assert!(
        sql.contains("EXCEPT"),
        "Should EXCEPT src_host/src_mac/user from main.*"
    );
    assert!(
        sql.contains("main.src_host"),
        "Should reference main.src_host for fill-if-empty"
    );
}

#[test]
fn resolve_identity_after_table_no_src_host() {
    // | table prunes columns → resolve_identity must NOT reference main.src_host
    let sql = npl("* | table timestamp, dest_ip, process_name | resolve_identity field=dest_ip");
    assert!(
        sql.contains("ASOF LEFT JOIN"),
        "Missing ASOF JOIN"
    );
    // NAN-1638: the build side is a subquery bounded to the query window, not
    // the bare table — ASOF JOINing all of identity_observations read the whole
    // table on every resolve. Assert the bound, not just the join: an unbounded
    // `ASOF LEFT JOIN identity_observations` would still satisfy the line above.
    assert!(
        sql.contains("FROM identity_observations")
            && sql.contains("WHERE observed_at BETWEEN"),
        "ASOF build side must stay window-bounded (NAN-1638), got:\n{sql}"
    );
    assert!(
        !sql.contains("main.src_host"),
        "Should NOT reference pruned main.src_host"
    );
    assert!(
        !sql.contains("main.src_mac"),
        "Should NOT reference pruned main.src_mac"
    );
    assert!(
        !sql.contains("main.user ="),
        "Should NOT reference pruned main.user in fill logic"
    );
    // Should still add resolved identity columns
    assert!(
        sql.contains("AS src_host"),
        "Should add src_host from identity"
    );
    assert!(
        sql.contains("AS src_mac"),
        "Should add src_mac from identity"
    );
}

#[test]
fn resolve_identity_after_table_with_src_host() {
    // | table includes src_host → resolve_identity SHOULD use fill-if-empty
    let sql = npl("* | table timestamp, src_ip, src_host | resolve_identity field=src_ip");
    assert!(
        sql.contains("main.src_host"),
        "Should use fill-if-empty for src_host"
    );
}

#[test]
fn resolve_identity_after_fields_keep() {
    // | fields keep prunes columns like | table
    let sql = npl("* | fields dest_ip, dest_port, protocol | resolve_identity field=dest_ip");
    assert!(
        !sql.contains("main.src_host"),
        "Should NOT reference pruned main.src_host"
    );
    assert!(
        sql.contains("AS src_host"),
        "Should still add src_host from identity"
    );
}

#[test]
fn resolve_identity_max_age() {
    let sql = npl("* | resolve_identity field=src_ip max_age=4h");
    assert!(
        sql.contains("INTERVAL 14400 SECOND"),
        "max_age=4h should be 14400 seconds"
    );
}

// --- Reverse lookups (user/hostname → IP) ---

#[test]
fn resolve_identity_field_user() {
    let sql = npl("* | resolve_identity field=user");
    assert!(
        sql.contains("lower(main.\"user\") = lower(i.user)"),
        "Should join on i.user for user field"
    );
    assert!(
        sql.contains("ASOF LEFT JOIN"),
        "Missing ASOF JOIN"
    );
    // NAN-1638: the build side is a subquery bounded to the query window, not
    // the bare table — ASOF JOINing all of identity_observations read the whole
    // table on every resolve. Assert the bound, not just the join: an unbounded
    // `ASOF LEFT JOIN identity_observations` would still satisfy the line above.
    assert!(
        sql.contains("FROM identity_observations")
            && sql.contains("WHERE observed_at BETWEEN"),
        "ASOF build side must stay window-bounded (NAN-1638), got:\n{sql}"
    );
    assert!(
        sql.contains("identity_confidence"),
        "Missing identity_confidence column"
    );
    // NAN-1160: without join_use_nulls=1 the ASOF LEFT JOIN silently degrades to INNER
    // (CH default fills the non-nullable i.observed_at with epoch, not NULL), dropping
    // every unmatched event. The fragment must set it so the IS NULL guard works.
    assert!(
        sql.contains("join_use_nulls = 1"),
        "resolve_identity must set join_use_nulls=1 so unmatched events survive the LEFT join"
    );
}

#[test]
fn resolve_identity_field_dest_user() {
    let sql = npl("* | resolve_identity field=dest_user");
    assert!(
        sql.contains("lower(main.dest_user) = lower(i.user)"),
        "Should join on i.user for dest_user field"
    );
}

#[test]
fn resolve_identity_field_src_host() {
    let sql = npl("* | resolve_identity field=src_host");
    assert!(
        sql.contains("lower(main.src_host) = lower(i.hostname)"),
        "Should join on i.hostname for src_host field"
    );
    assert!(
        sql.contains("ASOF LEFT JOIN"),
        "Missing ASOF JOIN"
    );
    // NAN-1638: the build side is a subquery bounded to the query window, not
    // the bare table — ASOF JOINing all of identity_observations read the whole
    // table on every resolve. Assert the bound, not just the join: an unbounded
    // `ASOF LEFT JOIN identity_observations` would still satisfy the line above.
    assert!(
        sql.contains("FROM identity_observations")
            && sql.contains("WHERE observed_at BETWEEN"),
        "ASOF build side must stay window-bounded (NAN-1638), got:\n{sql}"
    );
}

#[test]
fn resolve_identity_field_dest_host() {
    let sql = npl("* | resolve_identity field=dest_host");
    assert!(
        sql.contains("lower(main.dest_host) = lower(i.hostname)"),
        "Should join on i.hostname for dest_host field"
    );
}

#[test]
fn resolve_identity_user_adds_identity_ip() {
    let sql = npl("* | resolve_identity field=user");
    assert!(
        sql.contains("identity_ip"),
        "Reverse lookup should add identity_ip output column"
    );
    assert!(
        sql.contains("i.ip AS identity_ip"),
        "Should select i.ip AS identity_ip"
    );
}

#[test]
fn resolve_identity_user_after_table() {
    // After table prunes columns, reverse lookup should still work
    let sql = npl("* | table timestamp, user, process_name | resolve_identity field=user");
    assert!(
        sql.contains("lower(main.\"user\") = lower(i.user)"),
        "Should join on i.user"
    );
    assert!(
        sql.contains("identity_ip"),
        "Should add identity_ip for reverse lookup"
    );
    // user is the lookup key, not a fill target — should NOT be in EXCEPT
    assert!(
        !sql.contains("EXCEPT"),
        "user/dest_user reverse lookup should not EXCEPT user"
    );
}

// ============================================================================
// prevalence — uses condition syntax, not field= syntax
// prevalence is a post-processing command; SQL gen produces a passthrough
// ============================================================================

#[test]
fn prevalence_enrich() {
    let sql = npl("* | prevalence enrich=true");
    // Prevalence enrich mode passes through data; enrichment happens post-SQL
    assert!(sql.contains("FROM logs"), "Should generate base query");
}

#[test]
fn prevalence_filter() {
    let sql = npl("* | prevalence hash_prevalence < 5");
    assert!(sql.contains("FROM logs"), "Should generate base query");
}

// ============================================================================
// anomaly
// ============================================================================

#[test]
fn anomaly_categorical() {
    let sql = npl("* | anomaly field=process_name method=mad threshold=2");
    assert!(
        sql.contains("anomaly_score"),
        "Should produce anomaly_score column"
    );
    assert!(
        sql.contains("is_anomaly"),
        "Should produce is_anomaly column"
    );
}

#[test]
fn anomaly_after_table() {
    let sql = npl(
        "* | table process_name, src_host, timestamp | anomaly field=process_name method=mad threshold=1"
    );
    assert!(
        sql.contains("anomaly_score"),
        "Should produce anomaly_score"
    );
}

#[test]
fn anomaly_then_table() {
    // | anomaly | table — select anomaly output columns
    let sql = npl(
        "* | anomaly field=process_name method=mad threshold=2 | table process_name, anomaly_score, is_anomaly"
    );
    assert!(
        sql.contains("anomaly_score"),
        "Should include anomaly_score in table output"
    );
    assert!(
        sql.contains("is_anomaly"),
        "Should include is_anomaly in table output"
    );
}

// ============================================================================
// search (mid-pipeline filter)
// ============================================================================

#[test]
fn search_command_basic() {
    let sql = npl(r#"* | search src_host="workstation-01""#);
    assert!(sql.contains("src_host"), "Should filter on src_host");
}

#[test]
fn search_command_after_stats() {
    let sql = npl("* | stats count by src_ip | search count > 10");
    assert!(sql.contains("count"), "Should reference count from stats");
}

// ============================================================================
// table + downstream commands
// ============================================================================

#[test]
fn table_then_sort() {
    let sql = npl("* | stats count by src_ip | table src_ip, count | sort -count");
    assert!(sql.contains("ORDER BY"), "Should have ORDER BY from sort");
}

#[test]
fn table_then_where() {
    let sql = npl("* | table src_ip, dest_port | where dest_port > 1024");
    assert!(
        sql.contains("dest_port > 1024"),
        "Should filter on dest_port"
    );
}

#[test]
fn table_then_head() {
    let sql = npl("* | table src_ip, dest_ip | head 10");
    assert!(sql.contains("LIMIT 10"), "Should limit to 10");
}

// ============================================================================
// stats variations — ClickHouse uses count() not count(*)
// ============================================================================

#[test]
fn stats_count_by() {
    let sql = npl("* | stats count by src_ip");
    assert!(
        sql.contains("count()") || sql.contains("count(*)"),
        "Should have count aggregation"
    );
    assert!(sql.contains("GROUP BY"), "Should GROUP BY");
}

#[test]
fn stats_multiple_aggs() {
    let sql = npl("* | stats count, dc(user) by src_ip");
    assert!(sql.contains("count"), "Should have count aggregation");
    assert!(sql.contains("uniq"), "dc should map to uniq/uniqExact");
}

#[test]
fn stats_then_sort_then_head() {
    let sql = npl("* | stats count by src_ip | sort -count | head 20");
    assert!(sql.contains("GROUP BY"), "Should have GROUP BY");
    assert!(sql.contains("ORDER BY"), "Should have ORDER BY");
    assert!(sql.contains("LIMIT 20"), "Should limit to 20");
}

// ============================================================================
// eval
// ============================================================================

#[test]
fn eval_basic_arithmetic() {
    let sql = npl("* | eval total = bytes_in + bytes_out");
    assert!(
        sql.contains("bytes_in") && sql.contains("bytes_out"),
        "Should reference both fields"
    );
}

#[test]
fn eval_conditional() {
    let sql = npl(r#"* | eval risk = if(dest_port=443, "low", "high")"#);
    assert!(sql.contains("443"), "Should reference port 443");
}

#[test]
fn eval_len_function() {
    // len() maps to length() in ClickHouse
    let sql = npl("* | eval cmd_len = len(command_line)");
    assert!(sql.contains("length("), "len() should map to length()");
}

// ============================================================================
// dedup — one row per key, without a full row sort
//
// Two properties, and both matter:
//   - NAN-1636: no `ORDER BY <keys>, <time>` over the wide (~200-column) rows,
//     which hit Code 241 (MergeSortingTransform OOM) at >=~15min windows;
//   - NAN-2264: exactly one row per key. NAN-1636's `WHERE id IN (SELECT
//     argMin(id, <time>) …)` was NOT that — `id` is a CONTENT hash, so
//     content-identical rows share one and every row carrying the elected id
//     passed. `LIMIT 1 BY <keys>` over each group's oldest timestamp gives the
//     guarantee without the sort.
//
// The end-to-end proof (real rows, real ClickHouse) is in
// `dedup_row_identity_tests.rs`; these stay text-level shape checks.
// ============================================================================

#[test]
fn dedup_single_field() {
    let sql = npl("* | dedup src_ip");
    assert!(
        sql.contains("min(timestamp) FROM stage_0") && sql.contains("GROUP BY src_ip"),
        "dedup should restrict candidates to each key's oldest row, got:\n{sql}"
    );
    assert!(
        sql.contains("LIMIT 1 BY src_ip"),
        "dedup must collapse each key with LIMIT 1 BY (NAN-2264), got:\n{sql}"
    );
    assert!(
        !sql.contains("ORDER BY src_ip, timestamp"),
        "dedup must not full-sort rows (NAN-1636), got:\n{sql}"
    );
    assert!(
        !sql.contains("argMin(id"),
        "dedup must not elect survivors by content-hash id (NAN-2264), got:\n{sql}"
    );
}

#[test]
fn dedup_multiple_fields() {
    let sql = npl("* | dedup src_ip, dest_ip");
    assert!(
        sql.contains("min(timestamp) FROM stage_0")
            && sql.contains("GROUP BY src_ip, dest_ip"),
        "dedup should restrict candidates to each key's oldest row, got:\n{sql}"
    );
    assert!(
        sql.contains("LIMIT 1 BY src_ip, dest_ip"),
        "every dedup key must reach the LIMIT BY (NAN-2264), got:\n{sql}"
    );
    assert!(
        !sql.contains("ORDER BY src_ip, timestamp"),
        "dedup must not full-sort rows (NAN-1636), got:\n{sql}"
    );
    assert!(
        !sql.contains("argMin(id"),
        "dedup must not elect survivors by content-hash id (NAN-2264), got:\n{sql}"
    );
}

// ============================================================================
// rex (regex extraction)
// ============================================================================

#[test]
fn rex_basic() {
    let sql = npl(r#"* | rex field=message "(?P<status_code>\d{3})""#);
    assert!(
        sql.contains("status_code") || sql.contains("extract"),
        "Should extract status_code"
    );
}

// ============================================================================
// fillnull — generates ifNull/coalesce replacements for UDM columns
// ============================================================================

#[test]
fn fillnull_parses() {
    // fillnull may generate complex SQL; just verify it parses and generates
    let sql = npl(r#"* | fillnull value="N/A""#);
    assert!(sql.contains("FROM logs"), "Should generate a valid query");
}

// ============================================================================
// Multi-command pipelines (realistic AI-generated queries)
// ============================================================================

#[test]
fn realistic_network_hunt_table_then_resolve() {
    // The exact query that was failing: table prunes → resolve_identity references pruned columns
    let sql = npl(
        r#"source_type="defender_edr" action="network_connection" dest_port != 80 dest_port != 443 | table timestamp, process_name, dest_ip, dest_port, protocol | resolve_identity field=dest_ip"#,
    );
    assert!(sql.contains("ASOF LEFT JOIN"), "Should have identity join");
    assert!(
        !sql.contains("main.src_host ="),
        "Should not reference pruned src_host in fill logic"
    );
}

#[test]
fn realistic_stats_then_where_then_sort() {
    let sql = npl(
        "* | stats count by src_ip, dest_ip, dest_port | where count > 100 | sort -count | head 20",
    );
    assert!(sql.contains("GROUP BY"), "Should aggregate");
    assert!(sql.contains("LIMIT 20"), "Should limit");
}

#[test]
fn realistic_eval_then_table() {
    let sql =
        npl("* | eval cmd_len = len(command_line) | where cmd_len > 100 | sort -cmd_len | head 50");
    assert!(sql.contains("length("), "Should use length() for len()");
    assert!(sql.contains("ORDER BY"), "Should sort");
}

#[test]
fn realistic_anomaly_hunt() {
    let sql = npl(
        r#"source_type="defender_edr" | anomaly field=process_name method=mad threshold=1 | where is_anomaly=1 | table timestamp, src_host, process_name, anomaly_score"#,
    );
    assert!(sql.contains("anomaly_score"), "Should have anomaly_score");
}

#[test]
fn realistic_dedup_then_stats() {
    let sql = npl("* | dedup src_ip, dest_ip | stats count by dest_port | sort -count | head 10");
    assert!(sql.contains("GROUP BY"), "Should aggregate after dedup");
}

#[test]
fn realistic_timechart() {
    let sql = npl(r#"source_type="squid_proxy" | timechart span=1h count"#);
    assert!(
        sql.contains("toStartOfInterval") || sql.contains("toStartOfHour"),
        "Should bucket by hour"
    );
}

#[test]
fn realistic_resolve_then_stats() {
    // Resolve identity, then aggregate by resolved hostname
    let sql =
        npl("* | resolve_identity field=src_ip | stats count by src_host, dest_ip | sort -count");
    assert!(sql.contains("ASOF LEFT JOIN"), "Should have identity join");
    assert!(sql.contains("GROUP BY"), "Should aggregate");
}

// ============================================================================
// risk command — computed fields vs. metadata extraction (NAN-1236)
//
// `risk_factors` / `raw_risk_score` are in `is_known_metadata_field` (correct
// for searching STORED signal events, where they live in the `metadata` JSON).
// But after a live `| risk` command they are real computed columns. A `table`
// projection must reference them directly, not `JSONExtract*(metadata, …)` —
// otherwise the query errors (`Unknown identifier metadata`) once a `stats`
// upstream has dropped the `metadata` column. This was breaking shipped
// detection rules (ransomware, kerberoasting, port-scanning, …).
// ============================================================================

/// The exact failing shape: stats → risk → table risk_factors. The output must
/// reference `risk_factors` as a real column and must NOT touch `metadata`.
#[test]
fn risk_factors_after_stats_and_risk_is_direct_column_not_metadata_extract() {
    let sql = npl(
        r#"source_type="windows_security" | where event_type="ticket_request" | stats count() as count, dc(dest_host) as unique_targets by user | risk score=75 entity=user factor="Multiple TGS requests" | where unique_targets>15 | risk score=90 factor="Likely Kerberoasting" | table user, count, unique_targets, risk_score, risk_factors"#,
    );
    // The risk command produces a real risk_factors array column...
    assert!(
        sql.contains("AS risk_factors"),
        "risk command should project a real risk_factors column:\n{sql}"
    );
    // ...and the `table` projection must NOT JSON-extract it from `metadata`.
    assert!(
        !sql.contains("metadata, 'risk_factors'"),
        "risk_factors must not be JSON-extracted from metadata after `| risk`:\n{sql}"
    );
    // `metadata` was dropped at the stats aggregation; nothing should reference
    // it at all in this query.
    assert!(
        !sql.contains("metadata"),
        "query must not reference the dropped `metadata` column:\n{sql}"
    );
}

/// `raw_risk_score` (also in is_known_metadata_field) must likewise be direct
/// after a `| risk` command.
#[test]
fn raw_risk_score_after_risk_is_direct_column() {
    let sql = npl(
        r#"* | stats count() as count by src_ip | risk score=50 entity=src_ip factor="x" | table src_ip, raw_risk_score"#,
    );
    assert!(
        !sql.contains("metadata, 'raw_risk_score'"),
        "raw_risk_score must not be JSON-extracted from metadata after `| risk`:\n{sql}"
    );
}

/// Regression guard for the OTHER use case: searching stored signal events with
/// NO `| risk` command. There, `risk_factors` legitimately lives in the
/// `metadata` JSON and must still be extracted from it.
#[test]
fn risk_factors_without_risk_command_still_extracts_from_metadata() {
    let sql = npl(r#"* | table risk_factors"#);
    assert!(
        sql.contains("metadata, 'risk_factors'"),
        "stored-signal search (no `| risk`) must still extract risk_factors from metadata:\n{sql}"
    );
}

// ============================================================================
// join subsearch codegen (NAN-1346 #4)
// ============================================================================

/// An aggregated subsearch has no `timestamp` column; the old
/// `ROW_NUMBER() OVER (… ORDER BY timestamp)` window made the ClickHouse
/// analyzer resolve `timestamp` from the OUTER query and reject the join as a
/// correlated subquery (Code 48). The per-key cap is now a `LIMIT n BY` on the
/// sub side with no window at all.
#[test]
fn join_max_on_aggregated_subsearch_has_no_window_over_timestamp() {
    let sql = npl("* | join type=left max=3 user [search * | stats count() as sub_count by user]");
    assert!(
        !sql.contains("ROW_NUMBER"),
        "per-key cap must not use a window function (NAN-1346 #4):\n{sql}"
    );
    assert!(
        sql.contains(r#"LIMIT 3 BY "user""#),
        "max=3 must cap via LIMIT BY on the sub side:\n{sql}"
    );
}

/// `join` matches at most one subsearch row per key by default. The old SQL
/// left the default join unbounded many-to-many — repeated sub keys exploded
/// the join product (OOM on real data). Empty/NULL keys are evicted from the
/// sub side too: events without the join field never match.
#[test]
fn join_default_caps_one_sub_row_per_key_and_evicts_empty_keys() {
    let sql = npl("* | join type=left user [search action=logon]");
    assert!(
        sql.contains(r#"LIMIT 1 BY "user""#),
        "default join must cap at one sub row per key (NAN-1346 #4):\n{sql}"
    );
    assert!(
        sql.contains(r#"toString("user") != ''"#),
        "empty join keys must be evicted from the sub side:\n{sql}"
    );
}

/// With a known sub shape the join projects `main.*` plus the sub's non-key
/// columns under bare names. A bare `SELECT *` emitted the sub's columns as
/// literal `sub.<col>` duplicates — a later CHAINED join's `ON main.k = sub.k`
/// bound `sub.k` to the prior stage's column instead of the new sub table
/// (Code 403), and a downstream `| where` couldn't see the bare name.
#[test]
fn chained_joins_project_sub_columns_under_bare_names() {
    let sql = npl(
        "* | stats count() as events by src_ip | sort -events | head 10 \
         | join src_ip [search * | stats dc(dest_port) as ports by src_ip] \
         | join type=left src_ip [search * | stats dc(dest_ip) as targets by src_ip] \
         | table src_ip, events, ports, targets",
    );
    assert!(
        sql.contains("main.*, sub.ports AS ports") && sql.contains("main.*, sub.targets AS targets"),
        "join must re-project sub columns under bare names (NAN-1346 #4):\n{sql}"
    );
}

/// A subsearch output column referenced downstream (`| where port_count > 20`)
/// must resolve as a real column — before the fix it wasn't registered as
/// computed, fell back to a string ext-extraction, and the numeric comparison
/// died with Code 386 (no supertype String/UInt8).
#[test]
fn join_sub_columns_resolve_downstream_not_ext_extracted() {
    let sql = npl(
        "* | join type=left src_ip [search * | stats dc(dest_port) as port_count by src_ip] \
         | where port_count > 20 | table src_ip, port_count, message",
    );
    assert!(
        !sql.contains("ext, 'port_count'") && !sql.contains("ext.port_count"),
        "joined sub column must not be JSON-extracted downstream (NAN-1346 #4):\n{sql}"
    );
    assert!(
        sql.contains("WHERE port_count > 20"),
        "where must reference the joined column directly:\n{sql}"
    );
}

// ============================================================================
// transaction startswith= / endswith= (NAN-1346 #6)
// ============================================================================

/// The markers were parsed-then-discarded: `transaction user startswith="login"
/// endswith="logout"` silently produced the same SQL as the bare form — ONE
/// transaction per user over ALL its events instead of login→logout sessions.
#[test]
fn transaction_startswith_endswith_sessionizes() {
    let sql = npl(r#"* | transaction user startswith="login" endswith="logout" maxspan=8h"#);
    assert!(
        sql.contains("_txn_session"),
        "startswith/endswith must sessionize, not collapse per group key (NAN-1346 #6):\n{sql}"
    );
    // NAN-1515 routed bare keywords to hasAllTokens; the markers reuse that
    // lowering (this assertion previously pinned the old iLike '%…%' form).
    assert!(
        sql.contains("hasAllTokens(lower(message), 'login')")
            && sql.contains("hasAllTokens(lower(message), 'logout')"),
        "both markers must be evaluated as row flags:\n{sql}"
    );
    // Sessions begin at a start marker; rows after the first end marker and
    // sessions with no end marker are evicted (keepevicted=false default).
    assert!(
        sql.contains("_txn_session > 0")
            && sql.contains("_txn_ends_before = 0")
            && sql.contains("_txn_has_end = 1"),
        "start/end eviction filters must be applied:\n{sql}"
    );
    // Transactions group per session, not per bare group key.
    assert!(
        sql.contains(r#"GROUP BY "user", _txn_session"#),
        "must GROUP BY the session, not just the transaction fields:\n{sql}"
    );
}

/// startswith without endswith: sessions split at each start marker; no
/// end-based eviction.
#[test]
fn transaction_startswith_only_splits_at_start_markers() {
    let sql = npl(r#"* | transaction user startswith="login" maxspan=8h"#);
    assert!(
        sql.contains("_txn_is_start") && sql.contains("_txn_session > 0"),
        "startswith-only must split sessions at start markers:\n{sql}"
    );
    assert!(
        !sql.contains("_txn_has_end"),
        "no end marker → no end-based eviction:\n{sql}"
    );
}

/// endswith without startswith: a transaction accumulates until its end marker;
/// sessions that never see the marker are evicted.
#[test]
fn transaction_endswith_only_splits_after_end_markers() {
    let sql = npl(r#"* | transaction user endswith="logout" maxspan=8h"#);
    assert!(
        sql.contains("1 + sum(_txn_is_end) OVER"),
        "endswith-only sessions must split AFTER each end marker:\n{sql}"
    );
    assert!(
        sql.contains("_txn_has_end = 1"),
        "sessions with no end marker must be evicted:\n{sql}"
    );
}

/// The bare form (no markers) must keep its original one-group-per-key SQL —
/// no sessionization machinery.
#[test]
fn transaction_without_markers_is_unchanged() {
    let sql = npl("* | transaction user maxspan=1h");
    assert!(
        !sql.contains("_txn_session") && !sql.contains("_txn_is_start"),
        "bare transaction must not pay the sessionization windows:\n{sql}"
    );
    assert!(
        sql.contains(r#"GROUP BY "user""#),
        "bare transaction still groups per key:\n{sql}"
    );
}

// ============================================================================
// tree positional form (NAN-1346 #5)
// ============================================================================

/// Parse nPL → SQL gen, returning the error. Panics if generation succeeds.
fn npl_err(query_str: &str) -> String {
    let query = parse_query(query_str)
        .unwrap_or_else(|e| panic!("Parse failed for: {}\nError: {}", query_str, e));
    let gen = ClickHouseSqlGenerator::new();
    match gen.generate(&query, &test_time_range()) {
        Ok(sql) => panic!("expected gen error for `{}`, got SQL:\n{}", query_str, sql),
        Err(e) => e.to_string(),
    }
}

/// The positional `tree <field>` form parses with an EMPTY parent_field when
/// no `parent=` is given; the codegen emitted it as an empty identifier —
/// `SELECT *, , process_name` → CH Code 62 syntax error. It must refuse with
/// usage guidance instead.
#[test]
fn tree_positional_without_parent_errors_actionably() {
    for q in [
        "* | tree process_name",
        "* | tree process_name by src_host depth=3",
    ] {
        let err = npl_err(q);
        assert!(
            err.contains("tree requires a parent field"),
            "parent-less tree must explain its usage (NAN-1346); got: {err}"
        );
    }
}

/// The well-formed positional and preset forms keep generating valid SQL —
/// no empty identifier (`, ,`) anywhere in the projection.
#[test]
fn tree_with_parent_and_presets_generate_clean_sql() {
    for q in [
        "* | tree process_name parent=parent_process_name",
        "* | tree process",
        "source_type=edr | tree parent=ppid child=pid label=process_name",
    ] {
        let sql = npl(q);
        assert!(
            !sql.contains(", ,") && !sql.contains(",  ,"),
            "tree SQL must not contain an empty identifier for `{q}`:\n{sql}"
        );
    }
}

// ============================================================================
// resolve_identity bare aliases (NAN-1346 #5)
// ============================================================================

/// With exactly one resolve_identity in the pipeline, the bare `identity_*`
/// names are unambiguous: the stage emits them as extra aliases of the
/// prefixed canonical columns, and a downstream `| where identity_department`
/// resolves them as real columns instead of JSON-extracting from ext.
#[test]
fn single_resolve_identity_emits_bare_aliases() {
    let sql = npl(
        r#"* | resolve_identity field=user | where identity_department != "" | table user, identity_department"#,
    );
    assert!(
        sql.contains("AS identity_department"),
        "single resolve_identity must emit the bare alias (NAN-1346 #5):\n{sql}"
    );
    assert!(
        sql.contains("AS user_identity_department"),
        "the prefixed canonical column must still be emitted:\n{sql}"
    );
    assert!(
        !sql.contains("ext, 'identity_department'") && !sql.contains("ext.identity_department"),
        "downstream bare reference must not be JSON-extracted:\n{sql}"
    );
}

/// With two resolved entities the bare names are ambiguous — only the
/// prefixed columns are emitted.
#[test]
fn two_resolve_identities_keep_prefixed_columns_only() {
    let sql = npl("* | resolve_identity field=user | resolve_identity field=dest_user");
    assert!(
        sql.contains("AS user_identity_department") && sql.contains("AS dest_user_identity_department"),
        "both entities keep their prefixed columns:\n{sql}"
    );
    assert!(
        !sql.contains(") AS identity_department") && !sql.contains("_department AS identity_department"),
        "ambiguous bare aliases must not be emitted with two entities:\n{sql}"
    );
}

// ============================================================================
// asset is terminal (NAN-1346 #5)
// ============================================================================

/// `asset` renders a terminal dossier view — its rendered attributes
/// (asset_criticality, …) are not pipeline fields. A command piped after it
/// previously fell through to ext JSON extraction and failed at execution or
/// silently matched nothing; it must refuse with guidance instead.
#[test]
fn commands_after_asset_error_actionably() {
    for q in [
        r#"* | asset field=src_ip | where asset_criticality = "critical""#,
        "* | asset field=src_ip | table src_ip, asset_criticality",
    ] {
        let err = npl_err(q);
        assert!(
            err.contains("asset") && err.contains("last command"),
            "piping after asset must explain the terminal-dossier shape; got: {err}"
        );
    }
}

/// Terminal asset (the documented form) keeps generating.
#[test]
fn terminal_asset_still_generates() {
    for q in [
        "src_host=\"server-01\" | asset",
        "* | where src_host=\"workstation-42\" | asset field=src_host",
    ] {
        let sql = npl(q);
        assert!(!sql.is_empty(), "terminal asset must generate for `{q}`");
    }
}

// ============================================================================
// {func}_{field} references to un-aliased aggregations (NAN-1339)
// ============================================================================

/// An un-aliased `avg(bytes_in)` outputs a column literally named `avg`, but
/// the `values_`/`list_` naming convention makes `avg_bytes_in` the intuitive
/// downstream reference — it previously emitted a bare unknown identifier
/// (CH Code 47). Sort and field resolution now map it to the real column.
#[test]
fn func_field_reference_resolves_to_unaliased_agg_column() {
    let sql = npl("* | chart avg(bytes_in) over dest_port | sort -avg_bytes_in | head 20");
    assert!(
        sql.contains("ORDER BY avg DESC"),
        "sort -avg_bytes_in must order by the real `avg` column (NAN-1339):\n{sql}"
    );
    let sql = npl("* | stats avg(bytes_in) by dest_port | where avg_bytes_in > 100");
    assert!(
        sql.contains("WHERE avg > 100"),
        "where avg_bytes_in must filter the real `avg` column (NAN-1339):\n{sql}"
    );
}

/// Explicit aliases own their names — the reference alias never shadows one,
/// and bare func-name references are untouched.
#[test]
fn explicit_aliases_and_bare_func_references_are_unchanged() {
    let sql = npl("* | chart avg(bytes_in) as avg_bytes_in over dest_port | sort -avg_bytes_in");
    assert!(
        sql.contains("ORDER BY avg_bytes_in DESC"),
        "an explicit alias owns its name:\n{sql}"
    );
    let sql = npl("* | stats avg(bytes_in) by dest_port | sort -avg");
    assert!(
        sql.contains("ORDER BY avg DESC"),
        "bare func-name references keep working:\n{sql}"
    );
}

// ============================================================================
// table/fields wildcard expansion (NAN-1339)
// ============================================================================

/// A wildcard pattern in `table`/`fields` must not leak into the slim base
/// projection as a literal identifier — `toString(ext.src_) AS src_*` is a
/// guaranteed CH Code 62 syntax error. Wildcards force the wide base
/// projection instead.
#[test]
fn table_wildcard_does_not_leak_pattern_into_base_projection() {
    let sql = npl("* | table src_*");
    assert!(
        !sql.contains("src_*"),
        "the literal wildcard pattern must not appear in generated SQL (NAN-1339):\n{sql}"
    );
    assert!(
        sql.contains("src_ip"),
        "the wildcard must expand to matching schema columns:\n{sql}"
    );
}

/// Wildcards also expand against pipeline-computed fields (rex captures,
/// spath outputs, eval/stats aliases).
#[test]
fn table_wildcard_expands_against_computed_fields() {
    let sql = npl(r#"* | rex "(?P<ext_method>GET|POST)" | table ext_*, timestamp"#);
    assert!(
        sql.contains("ext_method"),
        "wildcard must match the rex capture (NAN-1339):\n{sql}"
    );
    assert!(
        !sql.contains("ext_*"),
        "the literal pattern must not survive into SQL:\n{sql}"
    );
}

/// A wildcard list matching NOTHING refuses with guidance instead of emitting
/// an empty SELECT (CH Code 62).
#[test]
fn table_wildcard_matching_nothing_errors_actionably() {
    let err = npl_err("* | spath input=ext | table ext_*");
    assert!(
        err.contains("no fields match") && err.contains("ext_*"),
        "zero-match wildcard must explain itself (NAN-1339); got: {err}"
    );
}

// ============================================================================
// eval alias escaping (NAN-1352)
// ============================================================================

#[test]
fn eval_ordinary_alias_is_emitted_bare() {
    // Byte-identical to the pre-fix output for normal identifier aliases:
    // escape_identifier leaves dot/space/reserved-word-free names unquoted.
    let sql = npl("* | eval total=bytes_in+bytes_out");
    assert!(
        sql.contains(" AS total"),
        "ordinary eval alias must stay bare; got: {sql}"
    );
    assert!(
        !sql.contains(r#"AS "total""#),
        "ordinary eval alias must not be needlessly quoted; got: {sql}"
    );
}

#[test]
fn eval_adversarial_quoted_alias_is_escaped() {
    // The parser accepts a quoted eval alias carrying arbitrary characters.
    // Pre-fix this interpolated raw into the projection (`1 AS a, b`), injecting a
    // second column. It must now be emitted as a single double-quoted identifier
    // with the embedded quote doubled — never as raw SQL.
    let sql = npl(r#"* | eval "a, b"=1"#);
    assert!(
        sql.contains(r#"AS "a, b""#),
        "adversarial eval alias must be quoted as one identifier; got: {sql}"
    );
    assert!(
        !sql.contains("AS a, b "),
        "adversarial eval alias must not reach SQL unquoted; got: {sql}"
    );

    // Single-quoted alias can embed a double-quote; escape_identifier doubles it.
    let sql2 = npl(r#"* | eval 'inj" x'=1"#);
    assert!(
        sql2.contains(r#"AS "inj"" x""#),
        "embedded double-quote must be doubled inside the quoted alias; got: {sql2}"
    );
}

#[test]
fn eval_reserved_word_alias_is_quoted() {
    // `user` is a ClickHouse reserved word; escaping it as an alias is also a
    // latent correctness win (a bare `AS user` is ambiguous).
    let sql = npl("* | eval user=1");
    assert!(
        sql.contains(r#"AS "user""#),
        "reserved-word eval alias must be quoted; got: {sql}"
    );
}

// ============================================================================
// NAN-1430: single-scan top-N timechart (audit D1) + estdc() (audit D2)
// ============================================================================

/// `timechart … by X limit=N` with a count rank must use the single-scan
/// windowed form — the old rank subquery re-read the raw-scan CTE (read_rows 2x).
#[test]
fn timechart_limit_count_is_single_scan() {
    let sql = npl("* | timechart span=1h count by source_type limit=3");
    assert!(
        sql.contains("dense_rank() OVER (ORDER BY __rank_total DESC, __rank_key ASC)"),
        "expected windowed single-scan rank; got: {sql}"
    );
    assert!(
        sql.contains("sum(__rank_val) OVER (PARTITION BY __rank_key)"),
        "expected decomposed rank total; got: {sql}"
    );
    assert!(
        !sql.contains("IN (SELECT"),
        "single-scan form must not re-read the source via a rank subquery; got: {sql}"
    );
}

#[test]
fn timechart_limit_sum_is_single_scan() {
    let sql = npl("* | timechart span=1h sum(bytes_in) by source_type limit=3");
    assert!(
        sql.contains("sum(bytes_in) AS __rank_val"),
        "sum rank should carry the per-bucket sum; got: {sql}"
    );
    assert!(!sql.contains("IN (SELECT"), "got: {sql}");
}

/// avg is not directly decomposable: the aggregated stage carries sum+count and
/// the rank total divides at the end. The avg output column shadows its input
/// field name (timechart default alias), so it is emitted under a temp name and
/// renamed back in the outer projection.
#[test]
fn timechart_limit_avg_carries_sum_and_count() {
    let sql = npl("* | timechart span=1h avg(bytes_in) by source_type limit=3");
    assert!(
        sql.contains("sum(bytes_in) AS __rank_sum") && sql.contains("count(bytes_in) AS __rank_cnt"),
        "avg rank must carry sum+count; got: {sql}"
    );
    assert!(
        sql.contains("sum(__rank_sum) OVER (PARTITION BY __rank_key) / sum(__rank_cnt) OVER (PARTITION BY __rank_key)"),
        "avg rank total must divide carried sums; got: {sql}"
    );
    assert!(
        sql.contains("avg(bytes_in) AS _agg_topn_0") && sql.contains("_agg_topn_0 AS bytes_in"),
        "shadowing avg output must be temp-named and renamed back; got: {sql}"
    );
    assert!(!sql.contains("IN (SELECT"), "got: {sql}");
}

/// dc() ranks are not decomposable as scalar sums, but the per-bucket
/// uniqExact STATES merge exactly — the single-scan windowed form carries
/// `uniqExactState` through the aggregated stage and `uniqExactMerge`s it per
/// split value (NAN-1632 3.2). Must stay uniqExact end-to-end: ranking by an
/// approximate merged state is not result-identical to the exact two-pass
/// form this replaces.
#[test]
fn timechart_limit_dc_single_scan_merges_uniq_exact_states() {
    let sql = npl("* | timechart span=1h dc(src_ip) by source_type limit=3");
    assert!(
        sql.contains("uniqExactState(src_ip) AS __rank_state"),
        "dc rank must carry the per-bucket uniqExact state; got: {sql}"
    );
    assert!(
        sql.contains("uniqExactMerge(__rank_state) OVER (PARTITION BY __rank_key)"),
        "dc rank total must merge the carried states; got: {sql}"
    );
    assert!(
        sql.contains("dense_rank() OVER (ORDER BY __rank_total DESC, __rank_key ASC)"),
        "expected the windowed single-scan rank; got: {sql}"
    );
    assert!(
        !sql.contains("IN (SELECT"),
        "single-scan form must not re-read the source via a rank subquery; got: {sql}"
    );
}

/// estdc() likewise merges per-bucket states, with the approximate
/// uniqCombined64 sketch it already aggregates with (state-merge is exactly
/// how the sketch composes, so this matches the old two-pass ranking).
#[test]
fn timechart_limit_estdc_single_scan_merges_uniq_combined_states() {
    let sql = npl("* | timechart span=1h estdc(src_ip) by source_type limit=3");
    assert!(
        sql.contains("uniqCombined64State(src_ip) AS __rank_state"),
        "estdc rank must carry the per-bucket uniqCombined64 state; got: {sql}"
    );
    assert!(
        sql.contains("uniqCombined64Merge(__rank_state) OVER (PARTITION BY __rank_key)"),
        "estdc rank total must merge the carried states; got: {sql}"
    );
    assert!(!sql.contains("IN (SELECT"), "got: {sql}");
}

/// A field-less aggregation with no derivable output name (empty-parens
/// non-count/non-sparkline) keeps ClickHouse's expression-derived column name,
/// which the single-scan outer projection can't reference — fall back to the
/// two-pass form rather than renaming user-visible columns.
#[test]
fn timechart_limit_unnamed_agg_falls_back_to_two_pass() {
    let sql = npl("* | timechart span=1h sum(bytes_in), median() by source_type limit=3");
    assert!(
        sql.contains("IN (SELECT source_type FROM stage_0"),
        "unnamed agg columns must keep the two-pass form; got: {sql}"
    );
    assert!(!sql.contains("dense_rank"), "got: {sql}");
}

/// Field-less sparkline default-names its output column `sparkline`
/// (NAN-1632 3.7) — it no longer counts as unnamed, so a count-ranked
/// timechart carrying it keeps the single-scan windowed form.
#[test]
fn timechart_limit_fieldless_sparkline_stays_single_scan() {
    let sql = npl("* | timechart span=1h count, sparkline by source_type limit=3");
    assert!(
        sql.contains("AS sparkline"),
        "field-less sparkline must be default-named; got: {sql}"
    );
    assert!(
        sql.contains("dense_rank() OVER (ORDER BY __rank_total DESC, __rank_key ASC)"),
        "expected the windowed single-scan rank; got: {sql}"
    );
    assert!(
        !sql.contains("IN (SELECT"),
        "sparkline must not force the two-pass rank subquery; got: {sql}"
    );
}

/// timechart without limit= keeps the plain GROUP BY shape — no window stages.
#[test]
fn timechart_split_without_limit_unchanged() {
    let sql = npl("* | timechart span=1h count by source_type");
    assert!(!sql.contains("__rank"), "no rank machinery without limit=; got: {sql}");
    assert!(sql.contains("GROUP BY time_bucket, source_type"), "got: {sql}");
}

// ---------------------------------------------------------------------------
// estdc(): approximate distinct count → uniqCombined64 (D2). dc() stays
// uniqExact — detection thresholds and Splunk parity depend on exact counts.
// ---------------------------------------------------------------------------

#[test]
fn stats_estdc_uses_uniq_combined64() {
    let sql = npl("* | stats estdc(src_ip) by source_type");
    assert!(
        sql.contains("uniqCombined64(src_ip) AS estdc"),
        "estdc should map to uniqCombined64; got: {sql}"
    );
}

#[test]
fn timechart_estdc_uses_uniq_combined64() {
    let sql = npl("* | timechart span=1h estdc(src_ip)");
    assert!(sql.contains("uniqCombined64(src_ip)"), "got: {sql}");
}

#[test]
fn eventstats_estdc_uses_uniq_combined64() {
    let sql = npl("* | eventstats estdc(src_ip) by source_type");
    // NAN-1642: the grouped form is no longer a whole-partition window. Those
    // materialised every row of the partition per row and were the OOM class
    // this replaced; the group->value map is built once and looked up per row.
    // Assert both halves — the aggregate still being uniqCombined64 AND the
    // absence of the window — since checking only the former would pass on a
    // reverted implementation.
    assert!(
        sql.contains("uniqCombined64(src_ip)") && sql.contains("mapFromArrays"),
        "eventstats estdc should be a uniqCombined64 map attach (NAN-1642); got: {sql}"
    );
    assert!(
        !sql.contains("OVER (PARTITION BY"),
        "eventstats must not use whole-partition windows (NAN-1642); got: {sql}"
    );
    // Whole-set form stays a scalar subquery, mirroring dc(). The aggregate is
    // wrapped in toFloat64 so the attached column has one numeric type across
    // both the grouped (map value) and whole-set shapes, so match on the
    // subquery and the aggregate rather than an exact `(SELECT <agg> FROM`.
    let sql2 = npl("* | eventstats estdc(src_ip)");
    assert!(
        sql2.contains("(SELECT toFloat64(uniqCombined64(src_ip)) FROM"),
        "whole-set eventstats estdc should use a scalar subquery; got: {sql2}"
    );
    assert!(
        !sql2.contains("OVER ("),
        "whole-set eventstats must not use a window (NAN-1642); got: {sql2}"
    );
}

#[test]
fn streamstats_estdc_uses_uniq_combined64() {
    let sql = npl("* | streamstats estdc(src_ip) by source_type");
    assert!(
        sql.contains("uniqCombined64(src_ip) OVER ("),
        "streamstats estdc should be a uniqCombined64 window; got: {sql}"
    );
}

#[test]
fn estdc_distinct_count_alias_unaffected() {
    // distinct_count remains an alias for exact dc(), not estdc().
    let sql = npl("* | stats distinct_count(src_ip) by source_type");
    assert!(sql.contains("uniqExact(src_ip)"), "got: {sql}");
}

/// dc() emission pins: byte-identical uniqExact forms in every surface.
#[test]
fn dc_emission_stays_uniq_exact_everywhere() {
    let stats = npl("* | stats dc(src_ip) by source_type");
    assert!(stats.contains("uniqExact(src_ip) AS dc"), "got: {stats}");

    let timechart = npl("* | timechart span=1h dc(src_ip)");
    assert!(timechart.contains("uniqExact(src_ip)"), "got: {timechart}");
    assert!(!timechart.contains("uniqCombined64"), "got: {timechart}");

    // NAN-1642: grouped eventstats is a map attach, not a window (see
    // eventstats_estdc_uses_uniq_combined64). dc() staying uniqExact is what
    // this test is about, so assert the aggregate and let the shape be pinned
    // there rather than duplicating a brittle window expectation here.
    let eventstats = npl("* | eventstats dc(src_ip) by source_type");
    assert!(eventstats.contains("uniqExact(src_ip)"), "got: {eventstats}");
    assert!(!eventstats.contains("uniqCombined64"), "dc must stay exact; got: {eventstats}");
    // The dc arm is emitted separately from estdc, so the estdc test cannot
    // protect it: a dc-only regression to `uniqExact(src_ip) OVER (PARTITION
    // BY ...)` would satisfy both lines above while restoring exactly the
    // whole-partition window NAN-1642 removed. Pin the shape here too.
    assert!(
        eventstats.contains("mapFromArrays"),
        "grouped eventstats dc must use the map attach (NAN-1642); got: {eventstats}"
    );
    assert!(
        !eventstats.contains("OVER (PARTITION BY"),
        "grouped eventstats dc must not use a whole-partition window (NAN-1642); got: {eventstats}"
    );

    let streamstats = npl("* | streamstats dc(src_ip) by source_type");
    assert!(streamstats.contains("uniqExact(src_ip) OVER ("), "got: {streamstats}");
}

// ============================================================================
// NAN-2265: eventstats / anomaly must aggregate the rows they annotate
//
// The map-scalar attach (NAN-1642) references its source CTE twice — once to
// build the constants, once to emit the rows. Generator CTEs are ordinary,
// non-materialized CTEs, so ClickHouse re-executes each reference; downstream
// of an arbitrary bounded subset (`head N`, `sort N`, `sample`, …) the two
// references see DIFFERENT rows and the attached aggregate belongs to a
// different sample than the rows it is printed on. Measured on 18.3M local
// rows: `head 20000 | eventstats avg(bytes_out) by dest_ip` mis-attached
// ~13,000 of ~15,500 groups on every run. Behind an unstable source the
// generator therefore falls back to the single-scan window shape — reachable
// only behind a stage that already bounded the rows, so it never buffers the
// unbounded partition NAN-1642 removed. Everywhere else the bounded map attach
// stays, byte-identical to what it emitted before this guard existed.
// ============================================================================

/// Number of `FROM <source_cte>` references at or after the CTE that owns the
/// attach. All the queries below put the attach in the LAST stage, so counting
/// from its marker to the end of the SQL counts exactly its own references.
fn source_refs_in_last_stage(sql: &str, owner_cte: &str, source_cte: &str) -> usize {
    let body = sql
        .split_once(&format!("{} AS (", owner_cte))
        .unwrap_or_else(|| panic!("{owner_cte} not found in:\n{sql}"))
        .1;
    body.matches(&format!("FROM {}", source_cte)).count()
}

/// The closure's pinned-ids scalar for `unstable_cte` — the ONLY place the
/// unstable CTE may be referenced. Identical scalar text is evaluated once
/// per query (scalar-subquery cache), so however many times the closure
/// recurs, the sample is pinned exactly once.
fn pinned_ids_scalar(unstable_cte: &str) -> String {
    format!("(SELECT groupArray(id) FROM {})", unstable_cte)
}

#[test]
fn eventstats_after_head_scans_its_source_once() {
    let sql = npl("* | head 100 | eventstats avg(bytes_out) by dest_ip");
    // Behind a pure selector over identity-carrying rows the attach swaps the
    // unstable source for its deterministic id-closure: the selector's ids
    // pinned once, the rows re-read from the stable ancestor. Every textual
    // reference to the unstable CTE must be the identical pinned-ids scalar —
    // anything else re-executes the LIMIT and samples different rows.
    let ids = pinned_ids_scalar("stage_1");
    let closure =
        format!("(SELECT * FROM stage_0 WHERE id IN (SELECT arrayJoin({ids})))");
    assert_eq!(
        sql.matches("FROM stage_1").count(),
        sql.matches(ids.as_str()).count(),
        "every reference to the unstable CTE must be the identical pinned-ids \
         scalar (one evaluation via the scalar cache); got:\n{sql}"
    );
    assert!(
        sql.matches(closure.as_str()).count() == 2 && sql.contains("mapFromArrays"),
        "constants AND rows must both read the id-closure (`{closure}`); got:\n{sql}"
    );
    assert!(
        !sql.contains("OVER (PARTITION BY"),
        "the id-closure must not fall back to the whole-partition window; got:\n{sql}"
    );
    // Whole-set form has the same hazard (scalar subquery + row scan).
    let global = npl("* | head 100 | eventstats avg(bytes_out)");
    assert!(
        global.contains(
            "(SELECT toFloat64(avg(bytes_out)) FROM (SELECT * FROM stage_0 WHERE id IN"
        ) && global.matches(closure.as_str()).count() == 2,
        "whole-set form must take the id-closure shape too; got:\n{global}"
    );
}

#[test]
fn eventstats_snapshot_rewinds_selector_chains_to_the_last_stable_cte() {
    // Chained selectors compose to a subset — pin the FINAL selector's ids,
    // close over the last STABLE CTE (stage_0 here).
    let chained = npl("* | head 1000 | sort 100 -bytes_out | eventstats avg(bytes_out) by dest_ip");
    assert!(
        chained.contains(&format!(
            "(SELECT * FROM stage_0 WHERE id IN (SELECT arrayJoin({})))",
            pinned_ids_scalar("stage_2")
        )),
        "chained selectors must pin the final sample and close over stage_0; got:\n{chained}"
    );
    // A stable stage BEFORE the selector run moves the closure ancestor up.
    let filtered =
        npl("* | where bytes_out > 0 | head 100 | eventstats avg(bytes_out) by dest_ip");
    assert!(
        filtered.contains(&format!(
            "(SELECT * FROM stage_1 WHERE id IN (SELECT arrayJoin({})))",
            pinned_ids_scalar("stage_2")
        )),
        "the closure must re-read the last row-stable CTE (the `where` stage); got:\n{filtered}"
    );
    // A stable stage AFTER a selector is not a pure selector suffix — the
    // closed-over rows would lack its computed columns — so the window
    // fallback stays.
    let sandwiched =
        npl("* | head 100 | eval x = bytes_out * 2 | eventstats avg(x) by dest_ip");
    assert!(
        sandwiched.contains("OVER (PARTITION BY") && !sandwiched.contains("groupArray(id)"),
        "a non-selector stage behind the selector must keep the window fallback; got:\n{sandwiched}"
    );
}

#[test]
fn eventstats_snapshot_carries_every_aggregate_slot() {
    // Multi-aggregation: the closure is a stable source, so the map build
    // carries the SAME aggregate table as the stable shape — over the closure.
    let sql = npl(
        "* | head 100 | eventstats count as c, dc(src_ip) as d, avg(bytes_out) as a, \
         earliest(user) as el by dest_ip",
    );
    for fragment in [
        "toFloat64(count())",
        "toFloat64(uniqExact(src_ip))",
        "toFloat64(avg(bytes_out))",
        "argMin(\"user\", timestamp)",
    ] {
        assert!(
            sql.contains(fragment),
            "the closure map build must keep every aggregate (`{fragment}`); got:\n{sql}"
        );
    }
    assert!(
        sql.contains("WHERE id IN (SELECT arrayJoin((SELECT groupArray(id) FROM stage_1)))"),
        "multi-agg eventstats must aggregate over the id-closure; got:\n{sql}"
    );
}

#[test]
fn eventstats_after_stable_stages_keeps_bounded_map_attach() {
    // The OOM property NAN-1642 bought: everything that does not select an
    // arbitrary bounded subset keeps the map attach.
    for query in [
        "* | eventstats avg(bytes_out) by dest_ip",
        "* | where bytes_out > 0 | eventstats avg(bytes_out) by dest_ip",
        "* | eval x = bytes_out * 2 | eventstats avg(x) by dest_ip",
        "* | sort -timestamp | eventstats avg(bytes_out) by dest_ip",
        "* | dedup dest_ip | eventstats avg(bytes_out) by dest_ip",
        "* | stats count by dest_ip | eventstats avg(count) by dest_ip",
    ] {
        let sql = npl(query);
        assert!(
            sql.contains("mapFromArrays") && !sql.contains("OVER (PARTITION BY"),
            "`{query}` must keep the bounded map attach (NAN-1642); got:\n{sql}"
        );
    }
}

#[test]
fn eventstats_after_every_subset_selector_takes_the_snapshot_shape() {
    // Each of these picks an arbitrary bounded subset of identity-carrying
    // rows — the snapshot-refetch pins the subset once instead of
    // double-scanning (map) or re-buffering wide rows (window).
    for query in [
        "* | head 100 | eventstats avg(bytes_out) by dest_ip",
        "* | tail 100 | eventstats avg(bytes_out) by dest_ip",
        "* | sort 100 -bytes_out | eventstats avg(bytes_out) by dest_ip",
        "* | sample 100 | eventstats avg(bytes_out) by dest_ip",
    ] {
        let sql = npl(query);
        assert!(
            sql.contains("WHERE id IN (SELECT arrayJoin((SELECT groupArray(id) FROM ")
                && sql.contains("mapFromArrays"),
            "`{query}` must take the id-closure shape; got:\n{sql}"
        );
        assert!(
            !sql.contains("OVER (PARTITION BY"),
            "`{query}` must not fall back to the whole-partition window; got:\n{sql}"
        );
    }
}

#[test]
fn eventstats_after_non_selector_unstable_stages_falls_back_to_window() {
    // Unstable sources that are NOT pure row-subset selectors: aggregated
    // subsets (top / rare emit grouped rows with no row id) and subsearch
    // unions (append: the arm carries its own LIMIT and the union has no
    // single stable ancestor). The id-filtered refetch cannot reproduce those
    // rows, so the single-scan window fallback stays — over aggregated /
    // union rows, not the raw-wide-row OOM class.
    for query in [
        "* | top 10 dest_ip | eventstats avg(count) by dest_ip",
        "* | rare 10 dest_ip | eventstats avg(count) by dest_ip",
        "* | append [search error] | eventstats avg(bytes_out) by dest_ip",
    ] {
        let sql = npl(query);
        assert!(
            !sql.contains("mapFromArrays") && !sql.contains("groupArray(id)"),
            "`{query}` has no identity-preserving selector suffix — neither \
             the map attach nor the id-closure may be used; got:\n{sql}"
        );
        assert!(
            sql.contains("OVER (PARTITION BY"),
            "`{query}` must fall back to the single-scan window; got:\n{sql}"
        );
    }
}

#[test]
fn eventstats_snapshot_requires_the_physical_row_identity() {
    // An include-mode projection that pruned `id` (fields/table) or an
    // upstream `eval id=…` reassignment invalidates the closure — the window
    // fallback must take over.
    for query in [
        "* | fields dest_ip, bytes_out, timestamp | head 100 | eventstats avg(bytes_out) by dest_ip",
        "* | eval id = dest_ip | head 100 | eventstats avg(bytes_out) by dest_ip",
    ] {
        let sql = npl(query);
        assert!(
            !sql.contains("groupArray(id)") && sql.contains("OVER (PARTITION BY"),
            "`{query}` must not close over ids without the physical row id; got:\n{sql}"
        );
    }
}

#[test]
fn eventstats_window_fallback_keeps_every_aggregate_and_alias() {
    // The fallback shares ONE emission table with the map shape, so every
    // aggregate keeps its function and its alias — a `_`-arm regression that
    // silently emitted count() under the user's alias (NAN-1145) would show up
    // here as well as in the map shape. `fields` prunes `id`, so this stays on
    // the window path (the snapshot shape needs the physical row identity).
    let sql = npl(
        "* | fields dest_ip, src_ip, bytes_out, timestamp | head 100 | \
         eventstats count as c, dc(src_ip) as d, estdc(src_ip) as e, \
         sum(bytes_out) as s, stdev(bytes_out) as sd, range(bytes_out) as r, \
         values(src_ip) as v, mode(src_ip) as m, earliest(src_ip) as el by dest_ip",
    );
    for fragment in [
        "toFloat64(count() OVER (PARTITION BY dest_ip)) AS c",
        "toFloat64(uniqExact(src_ip) OVER (PARTITION BY dest_ip)) AS d",
        "toFloat64(uniqCombined64(src_ip) OVER (PARTITION BY dest_ip)) AS e",
        "toFloat64(sum(bytes_out) OVER (PARTITION BY dest_ip)) AS s",
        "toFloat64(stddevPop(bytes_out) OVER (PARTITION BY dest_ip)) AS sd",
        "toFloat64(max(bytes_out) OVER (PARTITION BY dest_ip) - \
         min(bytes_out) OVER (PARTITION BY dest_ip)) AS r",
        "groupUniqArray(100)(toString(src_ip)) OVER (PARTITION BY dest_ip)",
        "(topK(1)(src_ip) OVER (PARTITION BY dest_ip))[1] AS m",
        "argMin(src_ip, timestamp) OVER (PARTITION BY dest_ip) AS el",
    ] {
        assert!(
            sql.contains(fragment),
            "window fallback must emit `{fragment}`; got:\n{sql}"
        );
    }
}

#[test]
fn anomaly_after_head_scans_its_source_once() {
    // Numeric z-score / MAD annotate RAW rows, so behind a selector run they
    // swap the unstable source for its id-closure and keep the bounded
    // map/scalar constants shape over it.
    for (query, expected) in [
        ("* | head 100 | anomaly bytes_out by dest_ip", "__nano_stats"),
        ("* | head 100 | anomaly bytes_out", "__nano_stats"),
        ("* | head 100 | anomaly bytes_out by dest_ip method=mad", "__nano_med[__nano_k]"),
    ] {
        let sql = npl(query);
        assert!(
            sql.contains(expected)
                && sql
                    .contains("WHERE id IN (SELECT arrayJoin((SELECT groupArray(id) FROM stage_1)))"),
            "`{query}` must attach constants from the id-closure (`{expected}`); got:\n{sql}"
        );
        assert!(
            !sql.contains("avg(bytes_out) OVER") && !sql.contains("quantile(0.5)(bytes_out) OVER"),
            "`{query}` must not buffer wide rows in a stats window; got:\n{sql}"
        );
    }
    // Categorical and aggregation-first attach over AGGREGATED rows (pair /
    // group counts) — no row id to refetch by, and their window fallback
    // buffers narrow aggregates, not the raw-row OOM class. They keep the
    // single-scan window shape behind an unstable source.
    for (query, expected) in [
        ("* | head 100 | anomaly process_name by user", "avg(_anomaly_count) OVER (PARTITION BY"),
        ("* | head 100 | anomaly count() by user", "avg(_agg_value) OVER ()"),
    ] {
        let sql = npl(query);
        assert!(
            !sql.contains("mapFromArrays") && !sql.contains("__nano_stats") && !sql.contains("__nano_med"),
            "`{query}` must not compute anomaly constants from a second scan; got:\n{sql}"
        );
        assert!(
            sql.contains(expected),
            "`{query}` must attach constants with `{expected}`; got:\n{sql}"
        );
    }
    // The categorical path's pair-count dedup windows are unchanged — they are
    // fine-grained partitions, not the OOM class (NAN-1642).
    let categorical = npl("* | head 100 | anomaly process_name by user");
    assert!(
        categorical.contains("count() OVER (PARTITION BY \"user\", process_name) as _anomaly_count"),
        "pair-count window must be preserved; got:\n{categorical}"
    );
    assert_eq!(
        source_refs_in_last_stage(&categorical, "stage_2", "stage_1"),
        1,
        "categorical anomaly must scan an unstable source once; got:\n{categorical}"
    );
}

#[test]
fn subsearch_eventstats_follows_the_same_stability_rule() {
    // A subsearch stage source is an inline subquery that a twice-scanning
    // rewrite duplicates textually — same hazard, same rule. A stable
    // subsearch body must keep the bounded map attach (it is not bounded by
    // the subsearch LIMIT, which is applied to the finished body).
    let stable = npl("* | join user [search error | eventstats avg(bytes_out) by user]");
    assert!(
        stable.contains("mapFromArrays") && !stable.contains("OVER (PARTITION BY"),
        "eventstats over a stable subsearch body must keep the map attach; got:\n{stable}"
    );
    let unstable = npl("* | join user [search error | head 100 | eventstats avg(bytes_out) by user]");
    assert!(
        !unstable.contains("mapFromArrays") && unstable.contains("OVER (PARTITION BY"),
        "eventstats after a head INSIDE a subsearch must not double-scan it; got:\n{unstable}"
    );
}

#[test]
fn anomaly_after_stable_stages_keeps_bounded_map_attach() {
    for (query, expected) in [
        ("* | anomaly bytes_out by dest_ip", "mapFromArrays"),
        ("* | where bytes_out > 0 | anomaly bytes_out by dest_ip method=mad", "__nano_med"),
        ("* | where bytes_out > 0 | anomaly process_name by user", "__nano_cnt"),
        ("* | where bytes_out > 0 | anomaly count() by user", "__nano_stats"),
    ] {
        let sql = npl(query);
        assert!(
            sql.contains(expected),
            "`{query}` must keep the bounded attach (NAN-1642) via `{expected}`; got:\n{sql}"
        );
        assert!(
            !sql.contains("avg(bytes_out) OVER") && !sql.contains("quantile(0.5)(bytes_out) OVER"),
            "`{query}` must not reintroduce whole-partition stats windows; got:\n{sql}"
        );
    }
}


#[test]
fn eventstats_snapshot_requires_an_identity_preserving_prefix() {
    // Row-STABLE is not row-IDENTITY-preserving: `stats` output is stable but
    // carries no `id` (a snapshot would emit `tuple(id, …)` over id-less
    // aggregate rows — UNKNOWN_IDENTIFIER), and `mvexpand` duplicates ids
    // (an id-filtered re-read returns every copy, not the sampled subset).
    // Both must keep the single-scan window fallback — over aggregated /
    // already-narrow rows, not the raw-row OOM class.
    for query in [
        "* | stats count by dest_ip | head 5 | eventstats avg(count)",
        "* | stats count by dest_ip | head 5 | eventstats avg(count) by dest_ip",
    ] {
        let sql = npl(query);
        assert!(
            !sql.contains("groupArray(id)") && sql.contains("OVER ("),
            "`{query}` has an id-less prefix — the id-closure must not \
             be used; got:\n{sql}"
        );
    }
}
