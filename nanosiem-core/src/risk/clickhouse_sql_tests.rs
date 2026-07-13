// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the shared risk ClickHouse SQL builder (NAN-1803).
//!
//! The correctness bar for the extraction was that the builder emits the SAME
//! statements the enterprise `RiskRepository` inlined before it existed. The
//! `ORIG_*` constants below are the pre-refactor templates copied VERBATIM
//! from `nanosiem-enterprise/src/risk/repository.rs` (as of origin/main at
//! extraction time), with ONE deliberate lockstep evolution: NAN-1806 (P4)
//! added the stamped `risk_entity_type = 'cloud_account'` first branch to the
//! entity-type inference (write-side stamp honored for the one type value
//! inference can never produce), so the goldens carry the same branch — every
//! other token remains the pre-refactor statement, and rows without the stamp
//! are bit-identical in behavior (`''` never equals `'cloud_account'`).
//!
//! - entity list (`get_time_windowed_risk_scores_clickhouse`) and per-rule
//!   contributions (`get_rule_contributions_for_entities`) must be
//!   **byte-identical**;
//! - decayed overview (`get_decayed_overview_clickhouse`) shared the CTE with
//!   different comment text — asserted **token-identical** (equal after
//!   stripping `--` comments and collapsing whitespace), which ClickHouse
//!   treats as the same statement.
//!
//! (The pre-refactor threshold view golden was removed with
//! `EntityScoreSelection::ExceedsThresholds` in NAN-1806 — risk alerting is a
//! `dataset=risk` detection rule since NAN-1805.)
//!
//! Bind order is locked per variant: the `?` placeholder sequence and the
//! bind sequence live in one place now, and these tests pin both. The P4
//! reader variants (leaderboard / dossier / facet / lateral batch) are pinned
//! against the SAME CTE prefix so they can never drift from the canonical
//! entity-list computation.

use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};

use super::{
    decayed_overview_query, entity_scores_query, entity_types_query, lateral_scores_query,
    risk_dataset_base_query, risk_for_entities_query, risky_entities_query,
    rule_contributions_query, ClearedBoundaries, EntityScoreSelection, RiskChQuery,
    RiskFindingsSource, RiskSqlBind,
};
use crate::risk::types::{RiskDecayConfig, RiskTimeWindow};

// ---------------------------------------------------------------------------
// Pre-refactor templates (verbatim copies — do NOT reformat)
// ---------------------------------------------------------------------------

/// `get_time_windowed_risk_scores_clickhouse` raw template, pre-refactor,
/// plus the NAN-1806 stamped-type first branch (see module docs).
const ORIG_TIME_WINDOWED: &str = r#"
            WITH signal_scores AS (
                SELECT
                    __RISK_ENTITY__ as entity,
                    -- Infer entity type from the value; honor the write-side
                    -- stamp for cloud_account only (NAN-1806)
                    multiIf(
                        __RISK_ENTITY_TYPE__ = 'cloud_account', 'cloud_account',
                        match(__RISK_ENTITY__, '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'), 'ip',
                        position(__RISK_ENTITY__, '@') > 0, 'email',
                        position(__RISK_ENTITY__, '.') > 0, 'hostname',
                        'user'
                    ) as entity_type,
                    toInt32(__RISK_SCORE__) as risk_score,
                    toUnixTimestamp64Micro(timestamp) as ts_micros,
                    __RULE_NAME__ as rule_name,
                    __SEVERITY__ as severity,
                    -- Calculate decay factor based on signal age
                    multiIf(
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 0-24h: decay_0_24h
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 1-3d:  decay_1_3d
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 3-5d:  decay_3_5d
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 5-7d:  decay_5_7d
                        0.0                                           -- >7d:   excluded
                    ) as decay_factor
                FROM __LOGS_TBL__
                WHERE source_type = 'findings'
                  AND __RISK_ENTITY__ != ''
                  AND __RISK_ENTITY__ != 'unknown'
                  AND toUnixTimestamp64Micro(timestamp) >= ?
                  -- Cleared-entity boundary: for a cleared entity keep only
                  -- post-clear findings (ts > its boundary); everything else
                  -- falls through indexOf=0 -> arrayElement(_,0)=0 -> ts>0. (R4)
                  AND toUnixTimestamp64Micro(timestamp) > arrayElement(?, indexOf(?, __RISK_ENTITY__))
            ),
            aggregated AS (
                SELECT
                    entity,
                    entity_type,
                    -- Raw scores (no decay, for backwards compatibility)
                    sumIf(risk_score, ts_micros >= ?) as risk_score_24h,
                    sum(risk_score) as risk_score_7d,
                    -- Decayed scores (primary metric). round() (not truncating
                    -- toInt64) so the headline matches the per-rule contribution
                    -- breakdown, which also rounds (NAN-1658 / R3).
                    toInt64(round(sumIf(risk_score * decay_factor, ts_micros >= ?))) as decayed_score_24h,
                    toInt64(round(sum(risk_score * decay_factor))) as decayed_score_7d,
                    countIf(ts_micros >= ?) as signal_count_24h,
                    count() as signal_count_7d,
                    max(ts_micros) as last_signal_at,
                    argMax(rule_name, ts_micros) as last_rule_name,
                    argMax(severity, ts_micros) as last_severity
                FROM signal_scores
                GROUP BY entity, entity_type
            )
            SELECT
                entity,
                entity_type,
                risk_score_24h,
                risk_score_7d,
                decayed_score_24h,
                decayed_score_7d,
                signal_count_24h,
                signal_count_7d,
                last_signal_at,
                last_rule_name,
                last_severity
            FROM aggregated
            WHERE decayed_score_24h >= ? OR decayed_score_7d >= ?
            ORDER BY decayed_score_24h DESC, decayed_score_7d DESC
            LIMIT ?
        "#;

/// `get_decayed_overview_clickhouse` raw template, pre-refactor (the
/// `{dscore}`/`{scount}` format! holes renamed to sentinels).
const ORIG_OVERVIEW: &str = r#"
            WITH signal_scores AS (
                SELECT
                    __RISK_ENTITY__ as entity,
                    toInt32(__RISK_SCORE__) as risk_score,
                    toUnixTimestamp64Micro(timestamp) as ts_micros,
                    multiIf(
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,
                        0.0
                    ) as decay_factor
                FROM __LOGS_TBL__
                WHERE source_type = 'findings'
                  AND __RISK_ENTITY__ != ''
                  AND __RISK_ENTITY__ != 'unknown'
                  AND toUnixTimestamp64Micro(timestamp) >= ?
                  AND toUnixTimestamp64Micro(timestamp) > arrayElement(?, indexOf(?, __RISK_ENTITY__))
            ),
            aggregated AS (
                SELECT
                    entity,
                    toInt64(round(sumIf(risk_score * decay_factor, ts_micros >= ?))) as decayed_score_24h,
                    toInt64(round(sum(risk_score * decay_factor))) as decayed_score_7d,
                    countIf(ts_micros >= ?) as signal_count_24h,
                    count() as signal_count_7d
                FROM signal_scores
                GROUP BY entity
            )
            SELECT
                count() AS total_entities,
                countIf(__DSCORE__ > 70) AS critical_entities,
                countIf(__DSCORE__ > 50 AND __DSCORE__ <= 70) AS high_entities,
                countIf(__DSCORE__ > 30 AND __DSCORE__ <= 50) AS medium_entities,
                countIf(__DSCORE__ > 0 AND __DSCORE__ <= 30) AS low_entities,
                toInt64(sum(__SCOUNT__)) AS total_signals,
                if(count() > 0, avg(__DSCORE__), 0.0) AS avg_risk_score
            FROM aggregated
            WHERE __DSCORE__ > 0
        "#;

/// `get_rule_contributions_for_entities` raw template, pre-refactor.
const ORIG_CONTRIBUTIONS: &str = r#"
            WITH signal_scores AS (
                SELECT
                    toInt32(__RISK_SCORE__) as risk_score,
                    toUnixTimestamp64Micro(timestamp) as ts_micros,
                    __RULE_ID__ as rule_id,
                    __RULE_NAME__ as rule_name,
                    __SEVERITY__ as severity,
                    multiIf(
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 0-24h: decay_0_24h
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 1-3d:  decay_1_3d
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 3-5d:  decay_3_5d
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 5-7d:  decay_5_7d
                        0.0                                           -- >7d:   excluded
                    ) as decay_factor
                FROM __LOGS_TBL__
                WHERE source_type = 'findings'
                  AND __RISK_ENTITY__ IN ?
                  AND toUnixTimestamp64Micro(timestamp) >= ?
            )
            SELECT
                rule_id,
                argMax(rule_name, ts_micros) as rule_name,
                argMax(severity, ts_micros) as severity,
                countIf(ts_micros >= ?) as fires_24h,
                count() as fires_7d,
                toInt64(round(sumIf(risk_score * decay_factor, ts_micros >= ?))) as decayed_contribution_24h,
                toInt64(round(sum(risk_score * decay_factor))) as decayed_contribution_7d,
                max(ts_micros) as last_fire_at,
                argMax(risk_score, ts_micros) as last_fire_score
            FROM signal_scores
            GROUP BY rule_id
            ORDER BY decayed_contribution_7d DESC
            LIMIT 50
        "#;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The exact sentinel substitution the pre-refactor repository applied, plus
/// the NAN-1806 stamped-type column (`__RISK_ENTITY_TYPE__` substitutes first
/// — it shares a prefix with `__RISK_ENTITY__`).
fn substitute_original(template: &str, ocsf: bool, logs_table: &str) -> String {
    let (entity_col, score_col, rule_name_col, rule_id_col, severity_col, stamped_type_col) =
        if ocsf {
            (
                "JSONExtractString(toString(unmapped),'risk_entity')",
                "JSONExtractInt(toString(unmapped), 'risk_score')",
                "JSONExtractString(toString(unmapped), 'rule_name')",
                "JSONExtractString(toString(unmapped),'rule_id')",
                "lower(severity)",
                "JSONExtractString(toString(unmapped),'risk_entity_type')",
            )
        } else {
            (
                "risk_entity",
                "risk_score",
                "rule_name",
                "rule_id",
                "severity",
                "JSONExtractString(metadata, 'risk_entity_type')",
            )
        };
    template
        .replace("__RISK_ENTITY_TYPE__", stamped_type_col)
        .replace("__RISK_ENTITY__", entity_col)
        .replace("__RISK_SCORE__", score_col)
        .replace("__RULE_NAME__", rule_name_col)
        .replace("__RULE_ID__", rule_id_col)
        .replace("__SEVERITY__", severity_col)
        .replace("__LOGS_TBL__", logs_table)
}

/// Strip `--` line comments and collapse all whitespace runs to one space.
/// Two statements that normalize equal are the same statement to ClickHouse
/// (none of these queries contain `--` or significant whitespace inside
/// string literals).
fn normalize_sql(sql: &str) -> String {
    sql.lines()
        .map(|line| match line.find("--") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn fixed_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 10, 12, 0, 0).unwrap()
}

fn decay_config() -> RiskDecayConfig {
    RiskDecayConfig {
        decay_0_24h: 1.0,
        decay_1_3d: 0.7,
        decay_3_5d: 0.4,
        decay_5_7d: 0.2,
    }
}

fn one_cleared_entity() -> (ClearedBoundaries, i64) {
    let cleared_at = Utc.with_ymd_and_hms(2026, 7, 8, 9, 30, 0).unwrap();
    let mut map = HashMap::new();
    map.insert("john.doe".to_string(), cleared_at);
    (
        ClearedBoundaries::from_map(&map),
        cleared_at.timestamp_micros(),
    )
}

/// Every `?` placeholder must have exactly one bind, in order — the builder's
/// core structural guarantee.
fn assert_placeholder_bind_parity(query: &RiskChQuery) {
    let placeholders = query.sql.matches('?').count();
    assert_eq!(
        placeholders,
        query.binds.len(),
        "placeholder count must equal bind count\nsql: {}",
        query.sql
    );
}

/// Microsecond cutoffs at `fixed_now()` in (24h, 3d, 5d, 7d) order.
fn fixed_cutoffs() -> (i64, i64, i64, i64) {
    let now = fixed_now();
    (
        (now - chrono::Duration::hours(24)).timestamp_micros(),
        (now - chrono::Duration::hours(72)).timestamp_micros(),
        (now - chrono::Duration::hours(120)).timestamp_micros(),
        (now - chrono::Duration::hours(168)).timestamp_micros(),
    )
}

fn expected_decay_binds() -> Vec<RiskSqlBind> {
    let (c24, c3d, c5d, c7d) = fixed_cutoffs();
    vec![
        RiskSqlBind::I64(c24),
        RiskSqlBind::F64(1.0),
        RiskSqlBind::I64(c3d),
        RiskSqlBind::F64(0.7),
        RiskSqlBind::I64(c5d),
        RiskSqlBind::F64(0.4),
        RiskSqlBind::I64(c7d),
        RiskSqlBind::F64(0.2),
    ]
}

// ---------------------------------------------------------------------------
// SQL-text equivalence vs the pre-refactor inline queries
// ---------------------------------------------------------------------------

#[test]
fn entity_list_sql_is_byte_identical_to_pre_refactor_query() {
    for (ocsf, table) in [
        (false, "logs"),
        (false, "logs_distributed"),
        (true, "ocsf_logs"),
        (true, "ocsf_logs_distributed"),
    ] {
        let source = RiskFindingsSource::new(ocsf, table);
        let (cleared, _) = one_cleared_entity();
        let query = entity_scores_query(
            &source,
            fixed_now(),
            &decay_config(),
            &cleared,
            EntityScoreSelection::MinScores {
                min_score_24h: 0,
                min_score_7d: 0,
                limit: 1000,
            },
        );
        let expected = substitute_original(ORIG_TIME_WINDOWED, ocsf, table);
        assert_eq!(
            query.sql, expected,
            "entity-list SQL must be byte-identical (ocsf={ocsf}, table={table})"
        );
        assert_placeholder_bind_parity(&query);
    }
}

#[test]
fn contributions_sql_is_byte_identical_to_pre_refactor_query() {
    for (ocsf, table) in [(false, "logs"), (true, "ocsf_logs_distributed")] {
        let source = RiskFindingsSource::new(ocsf, table);
        let query = rule_contributions_query(
            &source,
            fixed_now(),
            &decay_config(),
            &["a".to_string(), "b".to_string()],
        );
        let expected = substitute_original(ORIG_CONTRIBUTIONS, ocsf, table);
        assert_eq!(
            query.sql, expected,
            "contributions SQL must be byte-identical (ocsf={ocsf}, table={table})"
        );
        assert_placeholder_bind_parity(&query);
    }
}

#[test]
fn overview_sql_is_token_identical_to_pre_refactor_query() {
    for (window, dscore, scount) in [
        (
            RiskTimeWindow::Last24Hours,
            "decayed_score_24h",
            "signal_count_24h",
        ),
        (
            RiskTimeWindow::Last7Days,
            "decayed_score_7d",
            "signal_count_7d",
        ),
        (RiskTimeWindow::All, "decayed_score_7d", "signal_count_7d"),
    ] {
        let source = RiskFindingsSource::new(false, "logs");
        let (cleared, _) = one_cleared_entity();
        let query =
            decayed_overview_query(&source, fixed_now(), &decay_config(), &cleared, window);
        let expected = substitute_original(ORIG_OVERVIEW, false, "logs")
            .replace("__DSCORE__", dscore)
            .replace("__SCOUNT__", scount);
        assert_eq!(
            normalize_sql(&query.sql),
            normalize_sql(&expected),
            "overview SQL must be token-identical (window={window:?})"
        );
        assert_placeholder_bind_parity(&query);
        // Banding must target the window's decayed column.
        assert!(query.sql.contains(&format!("countIf({dscore} > 70)")));
        assert!(!query.sql.contains("__DSCORE__") && !query.sql.contains("__SCOUNT__"));
    }
}

/// The entity list and the P4 leaderboard are the SAME statement up to the
/// final WHERE/ORDER tail — the drift the builder exists to prevent. The
/// leaderboard can therefore never diverge from the Risk page's numbers.
#[test]
fn min_scores_and_leaderboard_share_the_cte_prefix() {
    let source = RiskFindingsSource::new(false, "logs");
    let (cleared, _) = one_cleared_entity();
    let min = entity_scores_query(
        &source,
        fixed_now(),
        &decay_config(),
        &cleared,
        EntityScoreSelection::MinScores {
            min_score_24h: 0,
            min_score_7d: 0,
            limit: 1,
        },
    );
    let leaderboard = risky_entities_query(
        &source,
        fixed_now(),
        &decay_config(),
        &cleared,
        RiskTimeWindow::Last7Days,
        None,
        0,
        50,
        0,
    );
    let min_prefix = min.sql.split("            WHERE decayed_score").next().unwrap();
    let lb_prefix = leaderboard
        .sql
        .split("            WHERE decayed_score")
        .next()
        .unwrap();
    assert_eq!(min_prefix, lb_prefix);
}

// ---------------------------------------------------------------------------
// P4 reader variants (NAN-1806): leaderboard / dossier / facet / lateral batch
// ---------------------------------------------------------------------------

#[test]
fn leaderboard_windows_selection_and_binds() {
    let (c24, _c3d, _c5d, c7d) = fixed_cutoffs();
    let (cleared, cleared_micros) = one_cleared_entity();
    let source = RiskFindingsSource::new(false, "logs");

    // 24h window, no type filter.
    let q24 = risky_entities_query(
        &source,
        fixed_now(),
        &decay_config(),
        &cleared,
        RiskTimeWindow::Last24Hours,
        None,
        5,
        50,
        10,
    );
    assert!(q24.sql.contains("WHERE decayed_score_24h >= ?"), "{}", q24.sql);
    assert!(
        q24.sql
            .contains("ORDER BY decayed_score_24h DESC, signal_count_24h DESC"),
        "{}",
        q24.sql
    );
    assert!(q24.sql.contains("LIMIT ? OFFSET ?"), "{}", q24.sql);
    assert!(!q24.sql.contains("entity_type = ?"), "{}", q24.sql);
    let mut expected = expected_decay_binds();
    expected.extend([
        RiskSqlBind::I64(c7d),
        RiskSqlBind::I64List(vec![cleared_micros, 0]),
        RiskSqlBind::StrList(vec!["john.doe".into(), String::new()]),
        RiskSqlBind::I64(c24),
        RiskSqlBind::I64(c24),
        RiskSqlBind::I64(c24),
        RiskSqlBind::I64(5),  // floor
        RiskSqlBind::I64(50), // LIMIT
        RiskSqlBind::I64(10), // OFFSET
    ]);
    assert_eq!(q24.binds, expected);
    assert_placeholder_bind_parity(&q24);

    // 7d and All windows band on the 7d columns (the findings horizon).
    for window in [RiskTimeWindow::Last7Days, RiskTimeWindow::All] {
        let q = risky_entities_query(
            &source,
            fixed_now(),
            &decay_config(),
            &cleared,
            window,
            None,
            0,
            50,
            0,
        );
        assert!(
            q.sql
                .contains("WHERE decayed_score_7d >= ? AND signal_count_7d > 0"),
            "{}",
            q.sql
        );
        assert!(
            q.sql
                .contains("ORDER BY decayed_score_7d DESC, signal_count_7d DESC"),
            "{}",
            q.sql
        );
        assert_placeholder_bind_parity(&q);
    }
}

#[test]
fn leaderboard_entity_type_filter_binds_after_floor() {
    let (c24, _c3d, _c5d, c7d) = fixed_cutoffs();
    let (cleared, cleared_micros) = one_cleared_entity();
    let q = risky_entities_query(
        &RiskFindingsSource::new(false, "logs"),
        fixed_now(),
        &decay_config(),
        &cleared,
        RiskTimeWindow::Last7Days,
        Some("cloud_account"),
        0,
        200,
        0,
    );
    assert!(
        q.sql
            .contains("WHERE decayed_score_7d >= ? AND signal_count_7d > 0 AND entity_type = ?"),
        "{}",
        q.sql
    );
    let mut expected = expected_decay_binds();
    expected.extend([
        RiskSqlBind::I64(c7d),
        RiskSqlBind::I64List(vec![cleared_micros, 0]),
        RiskSqlBind::StrList(vec!["john.doe".into(), String::new()]),
        RiskSqlBind::I64(c24),
        RiskSqlBind::I64(c24),
        RiskSqlBind::I64(c24),
        RiskSqlBind::I64(0),
        RiskSqlBind::Str("cloud_account".into()),
        RiskSqlBind::I64(200),
        RiskSqlBind::I64(0),
    ]);
    assert_eq!(q.binds, expected);
    assert_placeholder_bind_parity(&q);
}

/// The stamped write-side type is honored for cloud_account ONLY — every
/// other branch of the inference is the pre-P4 value inference, so scores and
/// groupings for unstamped/non-cloud entities are unchanged.
#[test]
fn entity_type_inference_honors_cloud_account_stamp_only() {
    let (cleared, _) = one_cleared_entity();
    for (ocsf, stamped_col) in [
        (false, "JSONExtractString(metadata, 'risk_entity_type')"),
        (true, "JSONExtractString(toString(unmapped),'risk_entity_type')"),
    ] {
        let source = RiskFindingsSource::new(ocsf, "logs");
        let q = entity_scores_query(
            &source,
            fixed_now(),
            &decay_config(),
            &cleared,
            EntityScoreSelection::MinScores {
                min_score_24h: 0,
                min_score_7d: 0,
                limit: 1,
            },
        );
        let stamped_branch = format!("{stamped_col} = 'cloud_account', 'cloud_account',");
        assert!(q.sql.contains(&stamped_branch), "{}", q.sql);
        // Exactly one stamped-type comparison — the other types stay value-inferred.
        assert_eq!(q.sql.matches("risk_entity_type").count(), 1, "{}", q.sql);
        assert!(!q.sql.contains("__RISK_ENTITY_TYPE__"), "{}", q.sql);
    }
}

#[test]
fn dossier_query_restricts_to_entity_set_and_ranks_by_decayed_7d() {
    let (c24, _c3d, _c5d, c7d) = fixed_cutoffs();
    let (cleared, cleared_micros) = one_cleared_entity();
    let entities = vec!["web-01".to_string(), "10.0.0.5".to_string()];
    let q = risk_for_entities_query(
        &RiskFindingsSource::new(false, "logs"),
        fixed_now(),
        &decay_config(),
        &cleared,
        &entities,
    );
    assert!(q.sql.contains("AND risk_entity IN ?"), "{}", q.sql);
    assert!(
        q.sql.contains("ORDER BY decayed_score_7d DESC\n            LIMIT 1"),
        "{}",
        q.sql
    );
    let mut expected = expected_decay_binds();
    expected.extend([
        RiskSqlBind::StrList(entities.clone()), // entity IN ?
        RiskSqlBind::I64(c7d),
        RiskSqlBind::I64List(vec![cleared_micros, 0]),
        RiskSqlBind::StrList(vec!["john.doe".into(), String::new()]),
        RiskSqlBind::I64(c24),
        RiskSqlBind::I64(c24),
        RiskSqlBind::I64(c24),
    ]);
    assert_eq!(q.binds, expected);
    assert_placeholder_bind_parity(&q);

    // Same projection as the canonical entity list (same row type).
    assert!(q.sql.contains("decayed_score_24h,"), "{}", q.sql);
    assert!(q.sql.contains("last_severity"), "{}", q.sql);
}

#[test]
fn facet_query_counts_distinct_entities_per_type() {
    let (_c24, _c3d, _c5d, c7d) = fixed_cutoffs();
    let (cleared, cleared_micros) = one_cleared_entity();
    let q = entity_types_query(
        &RiskFindingsSource::new(false, "logs"),
        fixed_now(),
        &decay_config(),
        &cleared,
    );
    assert!(q.sql.contains("GROUP BY entity, entity_type"), "{}", q.sql);
    assert!(
        q.sql.contains("SELECT entity_type, count() as entity_count"),
        "{}",
        q.sql
    );
    assert!(
        q.sql.contains("ORDER BY entity_count DESC, entity_type ASC"),
        "{}",
        q.sql
    );
    let mut expected = expected_decay_binds();
    expected.extend([
        RiskSqlBind::I64(c7d),
        RiskSqlBind::I64List(vec![cleared_micros, 0]),
        RiskSqlBind::StrList(vec!["john.doe".into(), String::new()]),
    ]);
    assert_eq!(q.binds, expected);
    assert_placeholder_bind_parity(&q);
}

#[test]
fn lateral_query_matches_lowered_and_fqdn_stripped_ids() {
    let (_c24, _c3d, _c5d, c7d) = fixed_cutoffs();
    let (cleared, cleared_micros) = one_cleared_entity();
    let ids = vec!["web-01".to_string(), "dc01".to_string()];
    let q = lateral_scores_query(
        &RiskFindingsSource::new(false, "logs"),
        fixed_now(),
        &decay_config(),
        &cleared,
        &ids,
    );
    // The FQDN double-match the retired PG reader performed, now in CH SQL.
    assert!(q.sql.contains("lower(risk_entity) IN ?"), "{}", q.sql);
    assert!(
        q.sql
            .contains("lower(arrayElement(splitByChar('.', risk_entity), 1)) IN ?"),
        "{}",
        q.sql
    );
    // 7d decayed sum per entity value, same rounding as the entity list.
    assert!(
        q.sql
            .contains("toInt64(round(sum(risk_score * decay_factor))) as decayed_score_7d"),
        "{}",
        q.sql
    );
    assert!(q.sql.contains("GROUP BY entity"), "{}", q.sql);
    let mut expected = expected_decay_binds();
    expected.extend([
        RiskSqlBind::I64(c7d),
        RiskSqlBind::I64List(vec![cleared_micros, 0]),
        RiskSqlBind::StrList(vec!["john.doe".into(), String::new()]),
        RiskSqlBind::StrList(ids.clone()),
        RiskSqlBind::StrList(ids.clone()),
    ]);
    assert_eq!(q.binds, expected);
    assert_placeholder_bind_parity(&q);
}

/// OCSF sentinel substitution covers every P4 variant (no leaked sentinels).
#[test]
fn p4_variants_substitute_ocsf_sentinels() {
    let (cleared, _) = one_cleared_entity();
    let source = RiskFindingsSource::new(true, "ocsf_logs_distributed");
    let queries = [
        risky_entities_query(
            &source,
            fixed_now(),
            &decay_config(),
            &cleared,
            RiskTimeWindow::Last7Days,
            Some("cloud_account"),
            0,
            50,
            0,
        ),
        risk_for_entities_query(
            &source,
            fixed_now(),
            &decay_config(),
            &cleared,
            &["a".to_string()],
        ),
        entity_types_query(&source, fixed_now(), &decay_config(), &cleared),
        lateral_scores_query(
            &source,
            fixed_now(),
            &decay_config(),
            &cleared,
            &["a".to_string()],
        ),
    ];
    for q in &queries {
        assert!(
            q.sql
                .contains("JSONExtractString(toString(unmapped),'risk_entity')"),
            "{}",
            q.sql
        );
        assert!(q.sql.contains("FROM ocsf_logs_distributed"), "{}", q.sql);
        assert!(!q.sql.contains("__"), "leaked sentinel:\n{}", q.sql);
        assert_placeholder_bind_parity(q);
    }
}

// ---------------------------------------------------------------------------
// Bind order (pins the pre-refactor `.bind()` chains)
// ---------------------------------------------------------------------------

#[test]
fn entity_list_bind_order_matches_pre_refactor_chain() {
    let (c24, _c3d, _c5d, c7d) = fixed_cutoffs();
    let (cleared, cleared_micros) = one_cleared_entity();
    let query = entity_scores_query(
        &RiskFindingsSource::new(false, "logs"),
        fixed_now(),
        &decay_config(),
        &cleared,
        EntityScoreSelection::MinScores {
            min_score_24h: 5,
            min_score_7d: 10,
            limit: 100,
        },
    );

    let mut expected = expected_decay_binds();
    expected.extend([
        RiskSqlBind::I64(c7d), // main WHERE timestamp >= ?
        RiskSqlBind::I64List(vec![cleared_micros, 0]), // arrayElement(?, …)
        RiskSqlBind::StrList(vec!["john.doe".into(), String::new()]), // indexOf(?, …)
        RiskSqlBind::I64(c24), // sumIf 24h raw
        RiskSqlBind::I64(c24), // sumIf 24h decayed
        RiskSqlBind::I64(c24), // countIf 24h
        RiskSqlBind::I64(5),   // WHERE decayed_score_24h >= ?
        RiskSqlBind::I64(10),  // WHERE decayed_score_7d >= ?
        RiskSqlBind::I64(100), // LIMIT ?
    ]);
    assert_eq!(query.binds, expected);
}

#[test]
fn overview_bind_order_matches_pre_refactor_chain() {
    let (c24, _c3d, _c5d, c7d) = fixed_cutoffs();
    let (cleared, cleared_micros) = one_cleared_entity();
    let query = decayed_overview_query(
        &RiskFindingsSource::new(false, "logs"),
        fixed_now(),
        &decay_config(),
        &cleared,
        RiskTimeWindow::Last24Hours,
    );

    let mut expected = expected_decay_binds();
    expected.extend([
        RiskSqlBind::I64(c7d),
        RiskSqlBind::I64List(vec![cleared_micros, 0]),
        RiskSqlBind::StrList(vec!["john.doe".into(), String::new()]),
        RiskSqlBind::I64(c24), // sumIf 24h decayed
        RiskSqlBind::I64(c24), // countIf 24h
    ]);
    assert_eq!(query.binds, expected);
}

#[test]
fn contributions_bind_order_matches_pre_refactor_chain() {
    let (c24, _c3d, _c5d, c7d) = fixed_cutoffs();
    let query = rule_contributions_query(
        &RiskFindingsSource::new(false, "logs"),
        fixed_now(),
        &decay_config(),
        &["a".to_string(), "b".to_string()],
    );

    let mut expected = expected_decay_binds();
    expected.extend([
        RiskSqlBind::StrList(vec!["a".into(), "b".into()]), // WHERE entity IN ?
        RiskSqlBind::I64(c7d),                              // main WHERE timestamp >= ?
        RiskSqlBind::I64(c24),                              // countIf fires_24h
        RiskSqlBind::I64(c24),                              // sumIf 24h decayed
    ]);
    assert_eq!(query.binds, expected);
}

// ---------------------------------------------------------------------------
// nPL dataset base source (NAN-1798 P2)
// ---------------------------------------------------------------------------

/// The dataset base and the canonical entity list must share the SAME
/// `signal_scores` scan — same entity/type inference, decay `multiIf`,
/// findings WHERE, and cleared boundary — so `score_24h/7d` can never be a
/// divergent computation. The dataset adds only the `rule_id`/`tactics`
/// inputs to the CTE's select list.
#[test]
fn dataset_base_shares_the_entity_scores_scan() {
    let source = RiskFindingsSource::new(false, "logs");
    let (cleared, _) = one_cleared_entity();
    let entity_list = entity_scores_query(
        &source,
        fixed_now(),
        &decay_config(),
        &cleared,
        EntityScoreSelection::MinScores {
            min_score_24h: 0,
            min_score_7d: 0,
            limit: 1,
        },
    );
    let dataset = risk_dataset_base_query(&source, fixed_now(), &decay_config(), &cleared);

    // Identical scan: strip the dataset-only select columns from the CTE and
    // the two signal_scores CTEs must be byte-identical up to `aggregated`.
    let scan_of = |sql: &str| sql.split("aggregated AS").next().unwrap().to_string();
    let dataset_scan = scan_of(&dataset.sql).replace(
        "                    rule_id as rule_id,\n                    JSONExtract(metadata, 'mitre_tactics', 'Array(String)') as tactics,\n",
        "",
    );
    assert_eq!(
        scan_of(&entity_list.sql),
        dataset_scan,
        "dataset base must reuse the exact entity-scores signal_scores scan"
    );

    // Identical decayed-sum expressions under the dataset's public names.
    for expr in [
        "toInt64(round(sumIf(risk_score * decay_factor, ts_micros >= ?))) as score_24h",
        "toInt64(round(sum(risk_score * decay_factor))) as score_7d",
        "sumIf(risk_score, ts_micros >= ?) as raw_score_24h",
        "sum(risk_score) as raw_score_7d",
        "uniqIf(rule_id, ts_micros >= ?) as distinct_rules_24h",
        "uniqArrayIf(tactics, ts_micros >= ?) as distinct_tactics_24h",
        "GROUP BY entity, entity_type",
    ] {
        assert!(dataset.sql.contains(expr), "missing {expr}\n{}", dataset.sql);
    }

    // Same bind prefix (decay + findings WHERE) as the entity list; the tail
    // is five 24h cutoffs (decayed/raw/count/rules/tactics), no selection binds.
    let (c24, _c3d, _c5d, c7d) = fixed_cutoffs();
    let (cleared, cleared_micros) = one_cleared_entity();
    let mut expected = expected_decay_binds();
    expected.extend([
        RiskSqlBind::I64(c7d),
        RiskSqlBind::I64List(vec![cleared_micros, 0]),
        RiskSqlBind::StrList(vec!["john.doe".into(), String::new()]),
    ]);
    expected.extend(std::iter::repeat(RiskSqlBind::I64(c24)).take(5));
    let dataset = risk_dataset_base_query(
        &RiskFindingsSource::new(false, "logs"),
        fixed_now(),
        &decay_config(),
        &cleared,
    );
    assert_eq!(dataset.binds, expected);
    assert_placeholder_bind_parity(&dataset);
    // No selection tail — the nPL pipeline owns filtering/ordering/limiting.
    assert!(!dataset.sql.contains("ORDER BY"));
    assert!(!dataset.sql.contains("LIMIT"));
}

/// OCSF sentinel substitution covers the dataset-only tactics column too.
#[test]
fn dataset_base_ocsf_reads_unmapped_sentinels() {
    let (cleared, _) = one_cleared_entity();
    let q = risk_dataset_base_query(
        &RiskFindingsSource::new(true, "ocsf_logs_distributed"),
        fixed_now(),
        &decay_config(),
        &cleared,
    );
    assert!(q.sql.contains("JSONExtractString(toString(unmapped),'risk_entity')"));
    assert!(q.sql.contains("JSONExtract(toString(unmapped), 'mitre_tactics', 'Array(String)')"));
    assert!(q.sql.contains("FROM ocsf_logs_distributed"));
    assert!(!q.sql.contains("__MITRE_TACTICS__"));
    assert_placeholder_bind_parity(&q);
}

/// Inline rendering substitutes every placeholder with the literal the
/// client-side binder would send: integers bare, floats with a decimal
/// point, arrays bracketed with escaped string items.
#[test]
fn inline_rendering_matches_bind_semantics() {
    let mut cleared_map = HashMap::new();
    cleared_map.insert(
        "o'brien\\host".to_string(),
        Utc.with_ymd_and_hms(2026, 7, 8, 9, 30, 0).unwrap(),
    );
    let cleared = ClearedBoundaries::from_map(&cleared_map);
    let q = risk_dataset_base_query(
        &RiskFindingsSource::new(false, "logs"),
        fixed_now(),
        &decay_config(),
        &cleared,
    );
    let inline = q.to_inline_sql();

    // Every placeholder rendered.
    assert!(!inline.contains('?'), "unrendered placeholder:\n{inline}");
    // Floats keep a decimal point (Float64 typing in the multiIf branches).
    assert!(inline.contains(", 1.0,"), "{inline}");
    assert!(inline.contains(", 0.7,"), "{inline}");
    // Cleared arrays inline as bracketed literals with escaping; the entity
    // and boundary arrays stay index-aligned with the trailing sentinel.
    let boundary = Utc
        .with_ymd_and_hms(2026, 7, 8, 9, 30, 0)
        .unwrap()
        .timestamp_micros();
    assert!(
        inline.contains(&format!("arrayElement([{boundary}, 0], indexOf(['o''brien\\\\host', ''],")),
        "{inline}"
    );
    // Cutoffs inline as bare integers.
    let (_c24, _c3d, _c5d, c7d) = fixed_cutoffs();
    assert!(inline.contains(&c7d.to_string()), "{inline}");
}

// ---------------------------------------------------------------------------
// ClearedBoundaries invariants (moved from the enterprise repository tests
// when `cleared_boundary_arrays` was lifted into the builder)
// ---------------------------------------------------------------------------

/// The cleared-boundary arrays must ALWAYS be non-empty (so ClickHouse can type
/// `indexOf` / `arrayElement`) even when nothing is cleared, and the trailing
/// sentinel must be the empty entity with a zero boundary — a value that never
/// matches a real `risk_entity` (those are excluded by `!= ''`).
#[test]
fn cleared_boundaries_empty_map_yields_only_sentinel() {
    let cleared: HashMap<String, DateTime<Utc>> = HashMap::new();
    let bounds = ClearedBoundaries::from_map(&cleared);

    assert_eq!(
        bounds.entities().len(),
        1,
        "sentinel must keep the array non-empty"
    );
    assert_eq!(bounds.boundaries_micros().len(), 1);
    assert_eq!(bounds.entities()[0], "", "sentinel entity is the empty string");
    assert_eq!(bounds.boundaries_micros()[0], 0, "sentinel boundary is 0");
}

/// A cleared entity contributes its value + `cleared_at` in microseconds, and
/// the parallel arrays stay index-aligned so `arrayElement(bounds, indexOf(...))`
/// resolves the correct boundary.
#[test]
fn cleared_boundaries_preserves_value_and_micros() {
    let cleared_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let mut cleared = HashMap::new();
    cleared.insert("john.doe".to_string(), cleared_at);

    let bounds = ClearedBoundaries::from_map(&cleared);

    // One real entry + the sentinel.
    assert_eq!(bounds.entities().len(), 2);
    assert_eq!(bounds.boundaries_micros().len(), 2);

    let idx = bounds
        .entities()
        .iter()
        .position(|e| e == "john.doe")
        .expect("cleared entity must be present");
    assert_eq!(
        bounds.boundaries_micros()[idx],
        cleared_at.timestamp_micros(),
        "boundary must be the clear time in microseconds, index-aligned to the entity"
    );

    // Sentinel still present and inert.
    assert!(bounds.entities().iter().any(|e| e.is_empty()));
}
