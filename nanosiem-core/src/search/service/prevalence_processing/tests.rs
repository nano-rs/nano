// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests for the dict-path prevalence filter decision.
//!
//! The audit (P2) found that a dict-lookup MISS was treated as host_count 0,
//! which inverted the filter: a common artifact absent from the dict passed a
//! `host_count < N` rarity test. A miss must instead fail every comparison,
//! mirroring the JOIN path's NULL-drop semantics.

use super::prevalence_passes_filter;
use crate::query::PrevalenceOperator;

#[test]
fn dict_miss_fails_every_comparison() {
    // A miss (`None`) must be excluded regardless of operator — it is "common /
    // not tracked", never host_count 0.
    for op in [
        PrevalenceOperator::Lt,
        PrevalenceOperator::Lte,
        PrevalenceOperator::Gt,
        PrevalenceOperator::Gte,
        PrevalenceOperator::Eq,
        PrevalenceOperator::Ne,
    ] {
        assert!(
            !prevalence_passes_filter(None, &op, 3),
            "a dict miss must fail {op:?} (row dropped), not be treated as host_count 0"
        );
    }
}

#[test]
fn common_artifact_absent_from_dict_does_not_pass_rare_filter() {
    // The exact failure scenario: `| prevalence host_count < 3` on a common
    // artifact the dict omits. With the old `unwrap_or(0)` this returned true
    // (0 < 3). It must now be false.
    assert!(!prevalence_passes_filter(None, &PrevalenceOperator::Lt, 3));
}

#[test]
fn present_rare_artifact_passes_lt() {
    // A genuinely rare artifact (host_count 1) still passes `< 3`.
    assert!(prevalence_passes_filter(
        Some(1),
        &PrevalenceOperator::Lt,
        3
    ));
}

#[test]
fn present_common_artifact_fails_lt_passes_gte() {
    // host_count 50 is common: fails `< 3`, passes `>= 3`.
    assert!(!prevalence_passes_filter(
        Some(50),
        &PrevalenceOperator::Lt,
        3
    ));
    assert!(prevalence_passes_filter(
        Some(50),
        &PrevalenceOperator::Gte,
        3
    ));
}

#[test]
fn boundary_values_respect_operator_strictness() {
    // Boundary at the threshold: `<` excludes equality, `<=` includes it.
    assert!(!prevalence_passes_filter(
        Some(3),
        &PrevalenceOperator::Lt,
        3
    ));
    assert!(prevalence_passes_filter(
        Some(3),
        &PrevalenceOperator::Lte,
        3
    ));
    assert!(prevalence_passes_filter(
        Some(3),
        &PrevalenceOperator::Eq,
        3
    ));
    assert!(!prevalence_passes_filter(
        Some(3),
        &PrevalenceOperator::Ne,
        3
    ));
}

// ---------------------------------------------------------------------------
// NAN-1691 (P1-A): filter-form pushdown mapper. The `| prevalence <field> <op>
// N` count condition must translate to a dictGet-masked host-count WHERE
// predicate that yields the SAME row set as the in-memory `prevalence_passes_filter`
// (a dict miss / out-of-window entry — the 9999 sentinel — fails every operator).
// ---------------------------------------------------------------------------
mod filter_pushdown {
    use super::super::prevalence_filter_condition_to_sql;
    use crate::query::{
        PrevalenceCondition, PrevalenceField, PrevalenceOperator, PrevalenceThreshold,
    };

    fn cond(
        field: PrevalenceField,
        operator: PrevalenceOperator,
        threshold: PrevalenceThreshold,
    ) -> PrevalenceCondition {
        PrevalenceCondition {
            field,
            operator,
            threshold,
        }
    }

    #[test]
    fn hash_prevalence_maps_to_hp_host_count_alias_each_operator() {
        for (op, glyph) in [
            (PrevalenceOperator::Lt, "<"),
            (PrevalenceOperator::Lte, "<="),
            (PrevalenceOperator::Gt, ">"),
            (PrevalenceOperator::Gte, ">="),
            (PrevalenceOperator::Eq, "="),
            (PrevalenceOperator::Ne, "!="),
        ] {
            let sql = prevalence_filter_condition_to_sql(&cond(
                PrevalenceField::HashPrevalence,
                op,
                PrevalenceThreshold::Count(5),
            ))
            .expect("count field must push down");
            assert_eq!(sql, format!("(_hp_host_count < 9999 AND _hp_host_count {glyph} 5)"));
        }
    }

    #[test]
    fn domain_prevalence_maps_to_dp_host_count_alias() {
        let sql = prevalence_filter_condition_to_sql(&cond(
            PrevalenceField::DomainPrevalence,
            PrevalenceOperator::Lte,
            PrevalenceThreshold::Count(3),
        ))
        .expect("count field must push down");
        assert_eq!(sql, "(_dp_host_count < 9999 AND _dp_host_count <= 3)");
    }

    #[test]
    fn every_operator_carries_the_9999_presence_guard() {
        // The `< 9999` guard is what makes a miss / out-of-window entry fail even
        // `>`, `>=`, `!=` — without it a sentinel 9999 row would spuriously pass and
        // diverge from the in-memory filter.
        //
        // NAN-1705 (D4b): the predicate is UNCHANGED from NAN-1691 — the rescue is
        // applied to the `_hp/_dp_host_count` PROJECTION (see the `rescue` mod's
        // `rescue_transform_*` tests), not here — so a rescued row arrives with a
        // real (< 9999) count and passes this guard without any predicate rewrite.
        for op in [
            PrevalenceOperator::Lt,
            PrevalenceOperator::Lte,
            PrevalenceOperator::Gt,
            PrevalenceOperator::Gte,
            PrevalenceOperator::Eq,
            PrevalenceOperator::Ne,
        ] {
            let sql = prevalence_filter_condition_to_sql(&cond(
                PrevalenceField::HashPrevalence,
                op,
                PrevalenceThreshold::Count(500),
            ))
            .unwrap();
            assert!(
                sql.contains("< 9999 AND"),
                "predicate must guard against the 9999 sentinel, got: {sql}"
            );
        }
    }

    #[test]
    fn timestamp_fields_do_not_push_down() {
        assert!(prevalence_filter_condition_to_sql(&cond(
            PrevalenceField::HashFirstSeen,
            PrevalenceOperator::Lt,
            PrevalenceThreshold::Count(5),
        ))
        .is_none());
        assert!(prevalence_filter_condition_to_sql(&cond(
            PrevalenceField::DomainFirstSeen,
            PrevalenceOperator::Lt,
            PrevalenceThreshold::Count(5),
        ))
        .is_none());
    }

    #[test]
    fn duration_threshold_does_not_push_down() {
        assert!(prevalence_filter_condition_to_sql(&cond(
            PrevalenceField::HashPrevalence,
            PrevalenceOperator::Lt,
            PrevalenceThreshold::Duration(std::time::Duration::from_secs(3600)),
        ))
        .is_none());
    }
}

// ---------------------------------------------------------------------------
// NAN-1705 (D4b): rescue plumbing — probe row filtering, probe SQL shape, and
// the `transform(...)` projection rewrite that makes a rescued dict-blind
// artifact's host_count / first_seen / … TRUE in-SQL (so the pushed predicate,
// the decoration CASEs, and any downstream `| where host_count < N` all agree).
// ---------------------------------------------------------------------------
mod rescue {
    use super::super::{
        build_prevalence_rescue_probe_sql, filter_rescued_artifacts, rescue_transform_sql,
        RescueAttr, RescuedArtifact, PREVALENCE_RESCUE_MAX_ARTIFACTS,
        PREVALENCE_RESCUE_MISS_KEY_CAP,
    };
    use crate::query::{
        PrevalenceCondition, PrevalenceField, PrevalenceOperator, PrevalenceThreshold,
    };
    use serde_json::json;

    // NAN-1723: the probe SQL SELECTs the timestamps as `fs_raw`/`ls_raw`, and
    // that is what a row looks like AFTER `execute_dynamic_query`'s
    // `convert_timestamps_to_iso8601` runs (those names are outside its list, so
    // the space format is preserved). Mock rows must use the same keys.
    fn probe_row(artifact: &str, host_count: u64) -> serde_json::Value {
        json!({
            "artifact": artifact,
            "host_count": host_count,
            "fs_raw": "2026-07-06 10:00:00.000000",
            "ls_raw": "2026-07-06 10:05:00.000000",
            "total_occurrences": 4,
        })
    }

    fn lte(n: u64) -> PrevalenceCondition {
        PrevalenceCondition {
            field: PrevalenceField::HashPrevalence,
            operator: PrevalenceOperator::Lte,
            threshold: PrevalenceThreshold::Count(n),
        }
    }

    fn rescued(artifact: &str, host_count: u64) -> RescuedArtifact {
        RescuedArtifact {
            artifact: artifact.to_string(),
            host_count,
            first_seen: "2026-07-06 10:00:00.000000".to_string(),
            last_seen: "2026-07-06 10:05:00.000000".to_string(),
            total_occurrences: 4,
        }
    }

    #[test]
    fn filter_rescued_keeps_only_condition_passing_artifacts() {
        // Brand-new rare (1 host) passes `<= 5`; a fresh-but-not-rare artifact
        // (400 hosts, still under the dict's 1000 cutoff) must NOT be rescued.
        let rows = vec![probe_row("new_rare", 1), probe_row("fresh_uncommon", 400)];
        let conds = [lte(5)];
        let cond_refs: Vec<&PrevalenceCondition> = conds.iter().collect();
        let rescued = filter_rescued_artifacts(rows, &cond_refs);
        assert_eq!(rescued.len(), 1);
        assert_eq!(rescued[0].artifact, "new_rare");
        assert_eq!(rescued[0].host_count, 1);
    }

    #[test]
    fn filter_rescued_requires_every_condition() {
        // `<= 5 AND >= 2`: host_count 1 fails the second condition.
        let rows = vec![probe_row("h1", 1), probe_row("h3", 3)];
        let conds = [
            lte(5),
            PrevalenceCondition {
                field: PrevalenceField::HashPrevalence,
                operator: PrevalenceOperator::Gte,
                threshold: PrevalenceThreshold::Count(2),
            },
        ];
        let cond_refs: Vec<&PrevalenceCondition> = conds.iter().collect();
        let rescued = filter_rescued_artifacts(rows, &cond_refs);
        assert_eq!(rescued.len(), 1);
        assert_eq!(rescued[0].artifact, "h3");
    }

    #[test]
    fn filter_rescued_tolerates_quoted_64bit_integers() {
        // CH JSON formats may quote 64-bit integers
        // (output_format_json_quote_64bit_integers) — the parser must accept both.
        let rows = vec![json!({
            "artifact": "q",
            "host_count": "2",
            "fs_raw": "2026-07-06 10:00:00.000000",
            "ls_raw": "2026-07-06 10:05:00.000000",
            "total_occurrences": "17",
        })];
        let conds = [lte(5)];
        let cond_refs: Vec<&PrevalenceCondition> = conds.iter().collect();
        let rescued = filter_rescued_artifacts(rows, &cond_refs);
        assert_eq!(rescued.len(), 1);
        assert_eq!(rescued[0].host_count, 2);
        assert_eq!(rescued[0].total_occurrences, 17);
    }

    #[test]
    fn probe_sql_shape_carries_the_bounds_and_dict_contract() {
        let sql = build_prevalence_rescue_probe_sql(
            "SELECT * FROM logs WHERE timestamp BETWEEN a AND b",
            "lower(COALESCE(nullIf(file_hash, ''), nullIf(process_hash, '')))",
            "nanosiem.hash_prevalence_dict",
            "nanosiem.hash_prevalence_summary",
            "file_hash",
            "host_count",
            "now() - INTERVAL 1 DAY",
            "",
        );
        // Bounded DISTINCT miss-key set (never the summary universe).
        assert!(sql.contains(&format!("LIMIT {PREVALENCE_RESCUE_MISS_KEY_CAP}")));
        // Only dict-blind keys (the masked 9999 sentinel) are probed.
        assert!(sql.contains("toUInt16(9999)) = 9999"));
        // The dict source's rarity contract: common artifacts can never be rescued.
        assert!(sql.contains("_hc < 1000"));
        // The NAN-364 window mask on the FRESH last_seen.
        assert!(sql.contains("_ls >= now() - INTERVAL 1 DAY"));
        // The GROUP BY is over the summary, bounded by the IN-set.
        assert!(sql.contains("FROM nanosiem.hash_prevalence_summary"));
        assert!(sql.contains("GROUP BY file_hash"));
        // Rarest-first, capped at MAX_ARTIFACTS + 1 (so overflow is visible/WARNed).
        assert!(sql.contains("ORDER BY _hc ASC"));
        assert!(sql.contains(&format!("LIMIT {}", PREVALENCE_RESCUE_MAX_ARTIFACTS + 1)));
        // No extra summary filter for hash (empty arg).
        assert!(sql.contains("WHERE file_hash IN ("));
        // NAN-1723: the outer timestamp aliases MUST be fs_raw/ls_raw (NOT
        // first_seen/last_seen) so `execute_dynamic_query`'s normaliser leaves
        // the space format intact for `toDateTime64`.
        assert!(sql.contains("toString(_fs) AS fs_raw"), "probe must alias first_seen away from the normaliser: {sql}");
        assert!(sql.contains("toString(_ls) AS ls_raw"));
        assert!(!sql.contains("AS first_seen"), "outer alias must not be `first_seen`: {sql}");
        assert!(!sql.contains("AS last_seen"), "outer alias must not be `last_seen`: {sql}");
    }

    /// NAN-1723 regression: the rescue timestamps must survive
    /// `execute_dynamic_query`'s `convert_timestamps_to_iso8601` post-processor
    /// and yield a `toDateTime64` literal ClickHouse can actually parse. The
    /// previous `first_seen`/`last_seen` aliases were rewritten to rfc3339
    /// (`…T…Z`), which `toDateTime64('…', 6)` rejects → the whole rescued
    /// detection query 500'd. This test drives the REAL normaliser (not a
    /// hand-built RescuedArtifact) so the regression can't hide behind a mock.
    #[test]
    fn rescue_timestamps_survive_executor_normaliser() {
        use crate::search::evaluator::helpers::convert_timestamps_to_iso8601;

        // Row exactly as the probe SQL emits it, before the executor post-processes it.
        let mut row = json!({
            "artifact": "abc123",
            "host_count": 1,
            "fs_raw": "2026-07-06 10:00:00.000000",
            "ls_raw": "2026-07-06 10:05:00.000000",
            "total_occurrences": 4,
        });
        convert_timestamps_to_iso8601(row.as_object_mut().unwrap());

        // fs_raw/ls_raw are outside the normaliser's field list → untouched space format.
        assert_eq!(row["fs_raw"], "2026-07-06 10:00:00.000000");
        assert_eq!(row["ls_raw"], "2026-07-06 10:05:00.000000");

        // Guard: the OLD alias names WOULD be corrupted to the unparseable rfc3339
        // form — this is exactly the NAN-1723 failure the rename avoids.
        let mut legacy = json!({ "first_seen": "2026-07-06 10:00:00.000000" });
        convert_timestamps_to_iso8601(legacy.as_object_mut().unwrap());
        assert_eq!(legacy["first_seen"], "2026-07-06T10:00:00.000000Z");

        // End-to-end: filter → transform literal must be a parseable toDateTime64
        // (space format, NO `T`/`Z`).
        let conds = [lte(5)];
        let cond_refs: Vec<&PrevalenceCondition> = conds.iter().collect();
        let rescued = filter_rescued_artifacts(vec![row], &cond_refs);
        assert_eq!(rescued.len(), 1);
        assert_eq!(rescued[0].first_seen, "2026-07-06 10:00:00.000000");
        assert_eq!(rescued[0].last_seen, "2026-07-06 10:05:00.000000");

        for attr in [RescueAttr::FirstSeen, RescueAttr::LastSeen] {
            let sql = rescue_transform_sql("<BASE>", "ifNull(_hash_lookup, '')", &rescued, attr);
            // Space-format literal present; no rfc3339 `T`-separator or `Z`-suffix
            // inside the quoted timestamp (the exact CANNOT_PARSE_TEXT signature).
            assert!(sql.contains("toDateTime64('2026-07-06 10:0"), "space-format literal expected: {sql}");
            assert!(!sql.contains("2026-07-06T"), "no rfc3339 T-separator in the literal: {sql}");
            assert!(!sql.contains(".000000Z"), "no rfc3339 Z-suffix in the literal: {sql}");
        }
    }

    #[test]
    fn ip_probe_carries_is_private_filter_and_raw_key() {
        let sql = build_prevalence_rescue_probe_sql(
            "SELECT * FROM logs WHERE timestamp BETWEEN a AND b",
            "COALESCE(nullIf(dest_ip, ''), nullIf(src_ip, ''))",
            "nanosiem.ip_prevalence_dict",
            "nanosiem.ip_prevalence_summary",
            "ip",
            "source_host_count",
            "now() - INTERVAL 1 DAY",
            "is_private = 0 AND ",
        );
        // The ip dict source's `WHERE is_private = 0` is mirrored, ANDed before the IN.
        assert!(
            sql.contains("WHERE is_private = 0 AND ip IN ("),
            "IP probe must exclude private IPs: {sql}"
        );
        assert!(sql.contains("uniqMerge(source_host_count)"));
        assert!(sql.contains("GROUP BY ip"));
    }

    // -----------------------------------------------------------------------
    // transform() projection rewrite — the core of the downstream-decoration
    // fix. A rescued key must resolve to its fresh value IN-SQL so every
    // reference (predicate, decoration CASE, `| where host_count`) sees it.
    // -----------------------------------------------------------------------

    #[test]
    fn empty_rescue_returns_base_expr_byte_identical() {
        // The whole-query byte-identity invariant: with no rescued artifacts the
        // projection is the plain dict expression, unchanged.
        let base = "if(dictGetOrDefault('d', 'last_seen', k, toDateTime64(0, 6)) >= now(), \
                    dictGetOrDefault('d', 'host_count', k, toUInt16(9999)), toUInt16(9999))";
        assert_eq!(
            rescue_transform_sql(base, "ifNull(_hash_lookup, '')", &[], RescueAttr::HostCount),
            base
        );
        assert_eq!(
            rescue_transform_sql(
                "dictGetOrDefault('d', 'first_seen', k, toDateTime64(0, 6))",
                "ifNull(_domain_lookup, '')",
                &[],
                RescueAttr::FirstSeen
            ),
            "dictGetOrDefault('d', 'first_seen', k, toDateTime64(0, 6))"
        );
    }

    #[test]
    fn host_count_transform_maps_rescued_key_to_uint16() {
        let sql = rescue_transform_sql(
            "<BASE>",
            "ifNull(_hash_lookup, '')",
            &[rescued("abc123", 1), rescued("def456", 3)],
            RescueAttr::HostCount,
        );
        assert_eq!(
            sql,
            "transform(ifNull(_hash_lookup, ''), ['abc123', 'def456'], [toUInt16(1), toUInt16(3)], <BASE>)"
        );
    }

    #[test]
    fn first_and_last_seen_transform_emit_datetime64_literals() {
        let fs = rescue_transform_sql(
            "<BASE_FS>",
            "ifNull(_domain_lookup, '')",
            &[rescued("evil.example.com", 2)],
            RescueAttr::FirstSeen,
        );
        assert_eq!(
            fs,
            "transform(ifNull(_domain_lookup, ''), ['evil.example.com'], [toDateTime64('2026-07-06 10:00:00.000000', 6)], <BASE_FS>)"
        );
        let occ = rescue_transform_sql(
            "<BASE_OCC>",
            "ifNull(_hash_lookup, '')",
            &[rescued("abc123", 1)],
            RescueAttr::TotalOccurrences,
        );
        assert_eq!(
            occ,
            "transform(ifNull(_hash_lookup, ''), ['abc123'], [toUInt64(4)], <BASE_OCC>)"
        );
    }

    #[test]
    fn transform_default_preserves_the_base_dict_expr() {
        // A NON-rescued key must fall through to the original dict-with-window-mask
        // lookup (the transform default), so behavior for everything the dict
        // already knew is unchanged.
        let base = "if(dictGetOrDefault('d','last_seen',k,toDateTime64(0,6)) >= now(), dictGetOrDefault('d','host_count',k,toUInt16(9999)), toUInt16(9999))";
        let sql = rescue_transform_sql(
            base,
            "ifNull(_hash_lookup, '')",
            &[rescued("abc123", 1)],
            RescueAttr::HostCount,
        );
        assert!(sql.ends_with(&format!("{base})")), "base expr must be the transform default: {sql}");
    }

    #[test]
    fn transform_keys_are_sql_escaped() {
        let sql = rescue_transform_sql(
            "<BASE>",
            "ifNull(_hash_lookup, '')",
            &[rescued("it's'); DROP--", 1)],
            RescueAttr::HostCount,
        );
        assert!(
            sql.contains("['it''s''); DROP--']"),
            "single quotes must be doubled, got: {sql}"
        );
    }

    #[test]
    fn transform_stays_out_of_aggregation_sniffing() {
        // The executor routes raw-vs-aggregation on token sniffing
        // (`is_aggregation_query` in execution/clickhouse_executor/sql_helpers.rs:
        // GROUP BY / COUNT( / MAX( / …). The transform-wrapped projection must
        // never introduce such a token into the MAIN query or every filter-form
        // prevalence search would flip into the full-materialization count(*)
        // OVER () branch. (The probe SQL, which does aggregate, runs outside the
        // paginated executor.) Token list mirrored from is_aggregation_query.
        const SNIFFED_TOKENS: [&str; 11] = [
            "GROUP BY", "COUNT(", "SUM(", "AVG(", "MIN(", "MAX(", "UNIQ(", "QUANTILE(", "TOPK(",
            "ARGMAX(", "ARGMIN(",
        ];
        // A benign base expr (no agg tokens) + a rescued list → the wrapper must
        // add only `transform(...)`, `toUInt16(...)`, literals.
        let base = "if(dictGetOrDefault('d','last_seen',k,toDateTime64(0,6)) >= now(), dictGetOrDefault('d','host_count',k,toUInt16(9999)), toUInt16(9999))";
        for attr in [
            RescueAttr::HostCount,
            RescueAttr::FirstSeen,
            RescueAttr::LastSeen,
            RescueAttr::TotalOccurrences,
        ] {
            let sql = rescue_transform_sql(
                base,
                "ifNull(_hash_lookup, '')",
                &[rescued("abc123", 1), rescued("def456", 3)],
                attr,
            )
            .to_uppercase();
            for token in SNIFFED_TOKENS {
                assert!(
                    !sql.contains(token),
                    "transform projection must not trip aggregation sniffing on {token}: {sql}"
                );
            }
        }
    }

    #[test]
    fn filter_rescued_caps_and_warns_on_overflow() {
        // The probe returns up to MAX_ARTIFACTS + 1 (rarest-first); the cap must
        // truncate back to MAX_ARTIFACTS (the WARN is emitted as a side effect).
        let rows: Vec<serde_json::Value> = (0..(PREVALENCE_RESCUE_MAX_ARTIFACTS + 1))
            .map(|i| probe_row(&format!("h{i}"), 1))
            .collect();
        let conds = [lte(5)];
        let cond_refs: Vec<&PrevalenceCondition> = conds.iter().collect();
        let rescued = filter_rescued_artifacts(rows, &cond_refs);
        assert_eq!(rescued.len(), PREVALENCE_RESCUE_MAX_ARTIFACTS);
    }
}

// ---------------------------------------------------------------------------
// NAN-1705 (D4b, residual #2): the `enrich=true | where <decorated>` trigger
// detector. Only rare-direction drop-bug filters on host_count / is_rare fire
// the rescue; pure-decorate enrich and common-direction filters do NOT.
// ---------------------------------------------------------------------------
mod decorated_filter {
    use super::super::decorated_filter_rescue_threshold;
    use crate::query::{Command, Comparator, SearchExpr, Value};

    fn where_cmd(field: &str, op: Comparator, value: Value) -> Command {
        Command::Where {
            condition: SearchExpr::FieldFilter {
                field: field.to_string(),
                op,
                value,
            },
        }
    }

    #[test]
    fn host_count_lt_triggers_with_ceil_threshold() {
        let cmds = [where_cmd("host_count", Comparator::Lt, Value::Number(5.0))];
        assert_eq!(decorated_filter_rescue_threshold(&cmds, 3), Some(5));
    }

    #[test]
    fn host_count_lte_and_eq_trigger() {
        assert_eq!(
            decorated_filter_rescue_threshold(
                &[where_cmd("host_count", Comparator::Lte, Value::Number(10.0))],
                3
            ),
            Some(10)
        );
        assert_eq!(
            decorated_filter_rescue_threshold(
                &[where_cmd("host_count", Comparator::Eq, Value::Number(1.0))],
                3
            ),
            Some(1)
        );
    }

    #[test]
    fn is_rare_truthy_triggers_at_rarity_threshold() {
        // is_rare = host_count < rarity_threshold, so rescue up to rarity_threshold - 1.
        for v in [
            Value::Bool(true),
            Value::Number(1.0),
            Value::String("true".into()),
        ] {
            assert_eq!(
                decorated_filter_rescue_threshold(
                    &[where_cmd("is_rare", Comparator::Eq, v)],
                    5
                ),
                Some(4)
            );
        }
    }

    #[test]
    fn common_direction_and_score_do_not_trigger() {
        // host_count > N (common hunt) — masked rows pass, different bug.
        assert_eq!(
            decorated_filter_rescue_threshold(
                &[where_cmd("host_count", Comparator::Gt, Value::Number(100.0))],
                3
            ),
            None
        );
        // is_rare = false — common direction.
        assert_eq!(
            decorated_filter_rescue_threshold(
                &[where_cmd("is_rare", Comparator::Eq, Value::Bool(false))],
                3
            ),
            None
        );
        // prevalence_score < X — masked row scores 0, `0 < X` keeps it (no drop-bug).
        assert_eq!(
            decorated_filter_rescue_threshold(
                &[where_cmd("prevalence_score", Comparator::Lt, Value::Number(20.0))],
                3
            ),
            None
        );
        // A non-decorated column filter never triggers.
        assert_eq!(
            decorated_filter_rescue_threshold(
                &[where_cmd("src_ip", Comparator::Eq, Value::String("1.2.3.4".into()))],
                3
            ),
            None
        );
    }

    #[test]
    fn pure_decorate_enrich_has_no_downstream_filter() {
        // No `| where` at all → None → no probe → byte-identical.
        assert_eq!(decorated_filter_rescue_threshold(&[], 3), None);
    }

    #[test]
    fn nested_and_collects_the_loosest_threshold() {
        // `host_count < 5 AND host_count < 10` → rescue the superset (10); the
        // in-SQL WHERE narrows to < 5.
        let cmd = Command::Where {
            condition: SearchExpr::And(
                Box::new(SearchExpr::FieldFilter {
                    field: "host_count".into(),
                    op: Comparator::Lt,
                    value: Value::Number(5.0),
                }),
                Box::new(SearchExpr::FieldFilter {
                    field: "host_count".into(),
                    op: Comparator::Lt,
                    value: Value::Number(10.0),
                }),
            ),
        };
        assert_eq!(decorated_filter_rescue_threshold(&[cmd], 3), Some(10));
    }

    #[test]
    fn not_is_opaque_no_spurious_fire_and_no_direction_inversion() {
        // Audit D4b (codex): `Not` inverts direction, so it must be opaque.
        // `NOT(host_count < 5)` ⇒ `host_count >= 5` (common direction) must NOT
        // fire a rescue — stays byte-identical, no spurious probe.
        let not_lt = Command::Where {
            condition: SearchExpr::Not(Box::new(SearchExpr::FieldFilter {
                field: "host_count".into(),
                op: Comparator::Lt,
                value: Value::Number(5.0),
            })),
        };
        assert_eq!(decorated_filter_rescue_threshold(&[not_lt], 3), None);

        // The contrived rare-via-`Not` form (`NOT(is_rare = false)` ⇒ rare) is
        // deliberately NOT rescued — authors write the un-negated `is_rare`.
        let not_is_rare_false = Command::Where {
            condition: SearchExpr::Not(Box::new(SearchExpr::FieldFilter {
                field: "is_rare".into(),
                op: Comparator::Eq,
                value: Value::Bool(false),
            })),
        };
        assert_eq!(
            decorated_filter_rescue_threshold(&[not_is_rare_false], 3),
            None
        );

        // A rare-direction filter nested inside AND still fires *through* the
        // AND (transparent), even when a sibling is `Not`-wrapped.
        let and_with_not = Command::Where {
            condition: SearchExpr::And(
                Box::new(SearchExpr::FieldFilter {
                    field: "host_count".into(),
                    op: Comparator::Lt,
                    value: Value::Number(5.0),
                }),
                Box::new(SearchExpr::Not(Box::new(SearchExpr::FieldFilter {
                    field: "host_count".into(),
                    op: Comparator::Lt,
                    value: Value::Number(9.0),
                }))),
            ),
        };
        assert_eq!(decorated_filter_rescue_threshold(&[and_with_not], 3), Some(5));
    }
}

// ---------------------------------------------------------------------------
// NAN-1691 (Fix 1): the residual in-memory filter's artifact selection must stay
// in lock-step with the pushdown. HashPrevalence keys on COALESCE(file_hash,
// process_hash), so a sysmon row carrying ONLY a process_hash matches a
// `hash_prevalence` filter on both paths.
// ---------------------------------------------------------------------------
mod coalesce_extraction {
    use super::super::{extract_prevalence_artifact, prevalence_filter_udm_concepts};
    use crate::query::PrevalenceField;
    use serde_json::json;

    #[test]
    fn hash_filter_coalesces_file_hash_then_process_hash() {
        // The COALESCE concept order the pushdown mirrors.
        assert_eq!(
            prevalence_filter_udm_concepts(&PrevalenceField::HashPrevalence),
            &["file_hash", "process_hash"]
        );
        assert_eq!(
            prevalence_filter_udm_concepts(&PrevalenceField::HashFirstSeen),
            &["file_hash", "process_hash"]
        );
    }

    #[test]
    fn domain_filter_keys_on_dest_host() {
        assert_eq!(
            prevalence_filter_udm_concepts(&PrevalenceField::DomainPrevalence),
            &["dest_host"]
        );
    }

    #[test]
    fn process_hash_only_row_matches_hash_filter() {
        // Sysmon-shaped row: no file_hash, only a process_hash. Before the fix the
        // in-memory path keyed on file_hash ONLY and skipped this row, diverging from
        // the pushdown. Now it must fall back to process_hash.
        let fields: Vec<String> = prevalence_filter_udm_concepts(&PrevalenceField::HashPrevalence)
            .iter()
            .map(|s| s.to_string())
            .collect();
        let row = json!({ "process_hash": "abc123", "process_name": "evil.exe" });
        assert_eq!(
            extract_prevalence_artifact(&row, &fields),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn file_hash_wins_when_both_present() {
        // COALESCE priority: file_hash before process_hash.
        let fields: Vec<String> = prevalence_filter_udm_concepts(&PrevalenceField::HashPrevalence)
            .iter()
            .map(|s| s.to_string())
            .collect();
        let row = json!({ "file_hash": "file_h", "process_hash": "proc_h" });
        assert_eq!(
            extract_prevalence_artifact(&row, &fields),
            Some("file_h".to_string())
        );
    }

    #[test]
    fn empty_file_hash_falls_back_to_process_hash() {
        // An empty-string file_hash is treated as absent (COALESCE skips it).
        let fields: Vec<String> = prevalence_filter_udm_concepts(&PrevalenceField::HashPrevalence)
            .iter()
            .map(|s| s.to_string())
            .collect();
        let row = json!({ "file_hash": "", "process_hash": "proc_h" });
        assert_eq!(
            extract_prevalence_artifact(&row, &fields),
            Some("proc_h".to_string())
        );
    }

    #[test]
    fn row_with_no_hash_yields_none() {
        let fields: Vec<String> = prevalence_filter_udm_concepts(&PrevalenceField::HashPrevalence)
            .iter()
            .map(|s| s.to_string())
            .collect();
        let row = json!({ "process_name": "evil.exe" });
        assert_eq!(extract_prevalence_artifact(&row, &fields), None);
    }
}
