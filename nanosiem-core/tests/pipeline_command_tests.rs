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
    assert!(
        sql.contains("'%login%'") && sql.contains("'%logout%'"),
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
