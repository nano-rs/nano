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
        sql.contains("ASOF LEFT JOIN identity_observations"),
        "Missing ASOF JOIN"
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
        sql.contains("ASOF LEFT JOIN identity_observations"),
        "Missing ASOF JOIN"
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
        sql.contains("ASOF LEFT JOIN identity_observations"),
        "Missing ASOF JOIN"
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
        sql.contains("ASOF LEFT JOIN identity_observations"),
        "Missing ASOF JOIN"
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
// dedup — ClickHouse uses LIMIT 1 BY, not ROW_NUMBER
// ============================================================================

#[test]
fn dedup_single_field() {
    let sql = npl("* | dedup src_ip");
    assert!(
        sql.contains("LIMIT 1 BY"),
        "Dedup should use LIMIT 1 BY (ClickHouse native dedup)"
    );
}

#[test]
fn dedup_multiple_fields() {
    let sql = npl("* | dedup src_ip, dest_ip");
    assert!(
        sql.contains("src_ip") && sql.contains("dest_ip"),
        "Should dedup by both fields"
    );
    assert!(sql.contains("LIMIT 1 BY"), "Should use LIMIT 1 BY");
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
