// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests for the dict-path prevalence filter decision.
//!
//! The audit (P2) found that a dict-lookup MISS was treated as host_count 0,
//! which inverted the filter: a common artifact absent from the dict passed a
//! `host_count < N` rarity test. A miss must instead fail every comparison,
//! mirroring the JOIN path's NULL-drop semantics.

use super::{
    collect_lake_domains, collect_lake_hashes, collect_lake_ips, extract_prevalence_artifact,
    lake_prevalence_artifact_paths, lake_prevalence_filter_prefix, prevalence_passes_filter,
    enrich_rows_with_prevalence, lake_positional_artifact_keys, result_field_strings,
    LAKE_DOMAIN_ARTIFACT_PATHS,
    LAKE_HASH_ARTIFACT_PATHS, LAKE_IP_ARTIFACT_PATHS,
};
use crate::query::{parse_query, PrettyPrint, PrevalenceOperator};

#[test]
fn explicit_prevalence_field_accepts_sequence_array_output() {
    let row = serde_json::json!({
        "step2_file_hashes_value": [
            "eb7533166139d123fa4e5ca321ae69af0bc743aa0bd698e49f66fb730054a6bc"
        ]
    });
    assert_eq!(
        result_field_strings(&row, "step2_file_hashes_value"),
        vec!["eb7533166139d123fa4e5ca321ae69af0bc743aa0bd698e49f66fb730054a6bc"]
    );
}

/// NAN-3492: `prevalence file_hash` on the lean gate decorated nothing, so
/// the row's ingest-time `prevalence_file_hash` (1, a first sighting) read as
/// the answer for a hash on 4 hosts. A UDM alias must reach the native OCSF
/// path the lake row carries; the given name stays first for derived fields.
#[test]
fn lake_positional_prevalence_fields_reach_the_native_ocsf_path() {
    let profile = crate::schema::OcsfProfile::lake_1_9();
    let keys = |fields: &[&str]| {
        lake_positional_artifact_keys(
            &profile,
            &fields.iter().map(|field| field.to_string()).collect::<Vec<_>>(),
        )
    };
    assert_eq!(keys(&["file_hash"]), vec!["file_hash", "file.hashes.value"]);
    assert_eq!(keys(&["file.hashes.value"]), vec!["file.hashes.value"]);
    assert_eq!(keys(&["step2_file_hashes_value"]), vec!["step2_file_hashes_value"]);

    let hash = "ccf2eae33fa64f050f860cf367caa80ff8f27e7b5439c457f1aaf32032147b16";
    let row = serde_json::json!({"file": {"hashes": [{"algorithm_id": 3, "value": hash}]}});
    let found = keys(&["file_hash"])
        .iter()
        .map(|key| result_field_strings(&row, key))
        .find(|values| !values.is_empty());
    assert_eq!(found, Some(vec![hash]));
}

#[test]
fn lake_scatter_keeps_only_leading_raw_row_filters() {
    let query = parse_query(
        "metadata.log_source=\"windows_sysmon\" | where severity_id >= 2 | eval score=severity_id * 2 | where score > 4 | head 5",
    )
    .unwrap();

    assert_eq!(
        lake_prevalence_filter_prefix(&query).pretty_print(),
        "metadata.log_source=\"windows_sysmon\" | where severity_id>=2"
    );
}

#[test]
fn lake_scatter_candidate_parser_handles_current_and_future_aggregate_shapes() {
    use std::collections::BTreeSet;

    let sha256 = "EB7533166139D123FA4E5CA321AE69AF0BC743AA0BD698E49F66FB730054A6BC";
    let sha1 = "0123456789ABCDEF0123456789ABCDEF01234567";
    let hashes = serde_json::json!(format!("['{sha256}'], [], ['{sha1}']"));
    let ips = serde_json::json!(["10.1.2.3", "2001:db8::1, invalid"]);
    let domains = serde_json::json!("EXAMPLE.COM, srv-web02.corp.local, 10.1.2.3, invalid");

    let mut parsed_hashes = BTreeSet::new();
    let mut parsed_ips = BTreeSet::new();
    let mut parsed_domains = BTreeSet::new();
    collect_lake_hashes(Some(&hashes), &mut parsed_hashes);
    collect_lake_ips(Some(&ips), &mut parsed_ips);
    collect_lake_domains(Some(&domains), &mut parsed_domains);

    assert_eq!(
        parsed_hashes,
        BTreeSet::from([sha1.to_ascii_lowercase(), sha256.to_ascii_lowercase()])
    );
    assert_eq!(
        parsed_ips,
        BTreeSet::from(["10.1.2.3".to_string(), "2001:db8::1".to_string()])
    );
    assert_eq!(
        parsed_domains,
        BTreeSet::from([
            "example.com".to_string(),
            "srv-web02.corp.local".to_string()
        ])
    );
}

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
            assert_eq!(
                sql,
                format!("(_hp_host_count < 9999 AND _hp_host_count {glyph} 5)")
            );
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

    /// NAN-4372: first_seen conditions push down onto the `_*_first_seen`
    /// aliases (they used to return None and the JOIN path dropped them, so
    /// the filter matched every row). Their presence guard is 30d presence
    /// (a dict hit), not the window-masked host count: first_seen is judged
    /// against the 30d dict whatever `window=` is, like the lake path's 30d
    /// snapshot.
    #[test]
    fn first_seen_fields_push_down_with_the_presence_guard() {
        for (field, prefix) in [
            (PrevalenceField::DomainFirstSeen, "_dp"),
            (PrevalenceField::HashFirstSeen, "_hp"),
        ] {
            for (op, glyph) in [
                (PrevalenceOperator::Lt, "<"),
                (PrevalenceOperator::Lte, "<="),
                (PrevalenceOperator::Gt, ">"),
                (PrevalenceOperator::Gte, ">="),
                (PrevalenceOperator::Eq, "="),
                (PrevalenceOperator::Ne, "!="),
            ] {
                let sql = prevalence_filter_condition_to_sql(&cond(
                    field,
                    op,
                    PrevalenceThreshold::Duration(std::time::Duration::from_secs(86_400)),
                ))
                .expect("first_seen must push down");
                assert_eq!(
                    sql,
                    format!(
                        "({prefix}_first_seen > toDateTime64(0, 6) AND {prefix}_first_seen {glyph} subtractSeconds(now64(6), 86400))"
                    )
                );
            }
        }
    }

    /// A field/threshold pairing the parser never produces is an error, never
    /// a dropped (match-everything) predicate.
    #[test]
    fn mismatched_threshold_is_an_error_not_a_dropped_predicate() {
        assert!(prevalence_filter_condition_to_sql(&cond(
            PrevalenceField::DomainFirstSeen,
            PrevalenceOperator::Lt,
            PrevalenceThreshold::Count(5),
        ))
        .is_err());
        assert!(prevalence_filter_condition_to_sql(&cond(
            PrevalenceField::HashPrevalence,
            PrevalenceOperator::Lt,
            PrevalenceThreshold::Duration(std::time::Duration::from_secs(3600)),
        ))
        .is_err());
    }
}

// NAN-4372: the in-memory comparison the lake (and ClickHouse fallback) path
// applies per row.
mod first_seen_comparison {
    use super::super::{PrevalenceComparison, PrevalenceFacts};
    use crate::query::{PrevalenceField, PrevalenceOperator, PrevalenceThreshold};
    use chrono::{TimeZone, Utc};

    fn facts(first_seen: chrono::DateTime<Utc>) -> Option<PrevalenceFacts> {
        Some(PrevalenceFacts { host_count: 2, first_seen })
    }

    #[test]
    fn newer_than_cutoff_passes_gt_and_older_fails() {
        let now = Utc.with_ymd_and_hms(2026, 10, 22, 12, 0, 0).unwrap();
        let comparison = PrevalenceComparison::new(
            &PrevalenceField::DomainFirstSeen,
            &PrevalenceThreshold::Duration(std::time::Duration::from_secs(86_400)),
            now,
        )
        .unwrap();
        let fresh = facts(now - chrono::Duration::hours(2));
        let old = facts(now - chrono::Duration::days(3));
        assert!(comparison.passes(fresh, &PrevalenceOperator::Gt));
        assert!(!comparison.passes(old, &PrevalenceOperator::Gt));
        assert!(comparison.passes(old, &PrevalenceOperator::Lt));
        assert!(!comparison.passes(fresh, &PrevalenceOperator::Lt));
    }

    #[test]
    fn a_miss_fails_every_operator() {
        let now = Utc::now();
        let comparison = PrevalenceComparison::new(
            &PrevalenceField::HashFirstSeen,
            &PrevalenceThreshold::Duration(std::time::Duration::from_secs(3600)),
            now,
        )
        .unwrap();
        for op in [
            PrevalenceOperator::Lt,
            PrevalenceOperator::Lte,
            PrevalenceOperator::Gt,
            PrevalenceOperator::Gte,
            PrevalenceOperator::Eq,
            PrevalenceOperator::Ne,
        ] {
            assert!(!comparison.passes(None, &op), "{op:?}");
        }
    }

    #[test]
    fn mismatched_pairings_are_errors() {
        let now = Utc::now();
        assert!(PrevalenceComparison::new(
            &PrevalenceField::DomainFirstSeen,
            &PrevalenceThreshold::Count(3),
            now
        )
        .is_err());
        assert!(PrevalenceComparison::new(
            &PrevalenceField::DomainPrevalence,
            &PrevalenceThreshold::Duration(std::time::Duration::from_secs(1)),
            now
        )
        .is_err());
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
        assert!(
            sql.contains("toString(_fs) AS fs_raw"),
            "probe must alias first_seen away from the normaliser: {sql}"
        );
        assert!(sql.contains("toString(_ls) AS ls_raw"));
        assert!(
            !sql.contains("AS first_seen"),
            "outer alias must not be `first_seen`: {sql}"
        );
        assert!(
            !sql.contains("AS last_seen"),
            "outer alias must not be `last_seen`: {sql}"
        );
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
            assert!(
                sql.contains("toDateTime64('2026-07-06 10:0"),
                "space-format literal expected: {sql}"
            );
            assert!(
                !sql.contains("2026-07-06T"),
                "no rfc3339 T-separator in the literal: {sql}"
            );
            assert!(
                !sql.contains(".000000Z"),
                "no rfc3339 Z-suffix in the literal: {sql}"
            );
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
        assert!(
            sql.ends_with(&format!("{base})")),
            "base expr must be the transform default: {sql}"
        );
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
            "GROUP BY",
            "COUNT(",
            "SUM(",
            "AVG(",
            "MIN(",
            "MAX(",
            "UNIQ(",
            "QUANTILE(",
            "TOPK(",
            "ARGMAX(",
            "ARGMIN(",
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
    use super::super::{decorated_filter_rescue_threshold, PREVALENCE_DICT_HOST_COUNT_CUTOFF};
    use crate::query::{
        parse_query, BinaryOperator, Command, Comparator, EvalAssignment, EvalExpression,
        SearchExpr, Value,
    };
    use crate::search::query_processing::extract_post_prevalence_commands;

    fn where_cmd(field: &str, op: Comparator, value: Value) -> Command {
        Command::Where {
            condition: SearchExpr::FieldFilter {
                field: field.to_string(),
                op,
                value,
                rhs: crate::query::RhsSyntax::Literal,
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
                &[where_cmd(
                    "host_count",
                    Comparator::Lte,
                    Value::Number(10.0)
                )],
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
                decorated_filter_rescue_threshold(&[where_cmd("is_rare", Comparator::Eq, v)], 5),
                Some(4)
            );
        }
    }

    #[test]
    fn common_direction_and_score_do_not_trigger() {
        // host_count > N (common hunt) — masked rows pass, different bug.
        assert_eq!(
            decorated_filter_rescue_threshold(
                &[where_cmd(
                    "host_count",
                    Comparator::Gt,
                    Value::Number(100.0)
                )],
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
                &[where_cmd(
                    "prevalence_score",
                    Comparator::Lt,
                    Value::Number(20.0)
                )],
                3
            ),
            None
        );
        // A non-decorated column filter never triggers.
        assert_eq!(
            decorated_filter_rescue_threshold(
                &[where_cmd(
                    "src_ip",
                    Comparator::Eq,
                    Value::String("1.2.3.4".into())
                )],
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
                    rhs: crate::query::RhsSyntax::Literal,
                }),
                Box::new(SearchExpr::FieldFilter {
                    field: "host_count".into(),
                    op: Comparator::Lt,
                    value: Value::Number(10.0),
                    rhs: crate::query::RhsSyntax::Literal,
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
                rhs: crate::query::RhsSyntax::Literal,
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
                rhs: crate::query::RhsSyntax::Literal,
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
                    rhs: crate::query::RhsSyntax::Literal,
                }),
                Box::new(SearchExpr::Not(Box::new(SearchExpr::FieldFilter {
                    field: "host_count".into(),
                    op: Comparator::Lt,
                    value: Value::Number(9.0),
                    rhs: crate::query::RhsSyntax::Literal,
                }))),
            ),
        };
        assert_eq!(
            decorated_filter_rescue_threshold(&[and_with_not], 3),
            Some(5)
        );
    }

    #[test]
    fn prevalence_arithmetic_predicate_gets_conservative_rescue() {
        let query =
            parse_query("* | prevalence enrich=true | where (last_seen - first_seen) >= 300")
                .unwrap();
        let post = extract_post_prevalence_commands(&query);
        assert_eq!(
            decorated_filter_rescue_threshold(&post.commands, 3),
            Some(PREVALENCE_DICT_HOST_COUNT_CUTOFF - 1)
        );
    }

    #[test]
    fn ordinary_arithmetic_predicate_does_not_trigger_prevalence_rescue() {
        let query =
            parse_query("* | prevalence enrich=true | where (source_port - destination_port) >= 0")
                .unwrap();
        let post = extract_post_prevalence_commands(&query);
        assert_eq!(decorated_filter_rescue_threshold(&post.commands, 3), None);
    }

    #[test]
    fn eval_alias_carries_prevalence_dependency_into_where() {
        let commands = [
            Command::Eval {
                assignments: vec![EvalAssignment {
                    field: "age".into(),
                    expression: EvalExpression::BinaryOp {
                        left: Box::new(EvalExpression::Field("last_seen".into())),
                        op: BinaryOperator::Sub,
                        right: Box::new(EvalExpression::Field("first_seen".into())),
                    },
                }],
            },
            where_cmd("age", Comparator::Gte, Value::Number(300.0)),
        ];
        assert_eq!(
            decorated_filter_rescue_threshold(&commands, 3),
            Some(PREVALENCE_DICT_HOST_COUNT_CUTOFF - 1)
        );
    }

    #[test]
    fn eval_alias_reassignment_clears_stale_prevalence_dependency() {
        let commands = [
            Command::Eval {
                assignments: vec![EvalAssignment {
                    field: "age".into(),
                    expression: EvalExpression::Field("last_seen".into()),
                }],
            },
            Command::Eval {
                assignments: vec![EvalAssignment {
                    field: "age".into(),
                    expression: EvalExpression::Field("bytes_in".into()),
                }],
            },
            where_cmd("age", Comparator::Gte, Value::Number(300.0)),
        ];
        assert_eq!(decorated_filter_rescue_threshold(&commands, 3), None);
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

/// NAN-2373 — the primary-lake defect.
///
/// A lake row is native nested OCSF JSON, not a flat map of SELECT aliases, and
/// its hashes live in the repeated `file.hashes[]` object. The flat-key-only
/// reader found nothing on such a row, so `| prevalence` extracted no artifact,
/// decorated no row, emitted no `host_count`, and the downstream
/// `| where host_count < 10` dropped every row without a word.
mod lake_row_shape {
    use super::*;

    fn lake_row() -> serde_json::Value {
        serde_json::json!({
            "class_uid": 1007,
            "activity_id": 1,
            "actor": {
                "process": {
                    "name": "keylogger.exe",
                    "file": {
                        "hashes": [
                            {"algorithm_id": 1, "value": "d41d8cd98f00b204e9800998ecf8427e"},
                            {"algorithm_id": 3, "value": "AB12CD34"}
                        ]
                    }
                }
            },
            "device": {"hostname": "WS-014"},
            "src_endpoint": {"ip": "10.1.2.3"},
            "dst_endpoint": {"hostname": "evil.example.test"}
        })
    }

    #[test]
    fn nested_ocsf_scalar_paths_resolve() {
        let row = lake_row();
        assert_eq!(
            result_field_strings(&row, "src_endpoint.ip"),
            vec!["10.1.2.3"]
        );
        assert_eq!(
            result_field_strings(&row, "dst_endpoint.hostname"),
            vec!["evil.example.test"]
        );
        assert_eq!(
            result_field_strings(&row, "device.hostname"),
            vec!["WS-014"]
        );
    }

    #[test]
    fn repeated_hash_objects_resolve_element_wise() {
        let row = lake_row();
        assert_eq!(
            result_field_strings(&row, "actor.process.file.hashes.value"),
            vec!["d41d8cd98f00b204e9800998ecf8427e", "AB12CD34"]
        );
    }

    #[test]
    fn every_lake_artifact_path_is_reachable_on_a_lake_row() {
        // Whatever the concept, the configured path must be *readable* on the
        // native row shape — the property whose absence made the command a
        // silent pass-through.
        let row = lake_row();
        let reachable = lake_prevalence_artifact_paths()
            .filter(|path| !result_field_strings(&row, path).is_empty())
            .count();
        // NAN-3070: the fixture's `device.hostname` (the reporting host) is
        // deliberately no longer an artifact path.
        assert!(
            reachable >= 3,
            "lake artifact paths must resolve on native OCSF rows, only {reachable} did"
        );
    }

    #[test]
    fn flat_clickhouse_rows_still_win_first() {
        // The ClickHouse lanes key rows by SELECT alias, so the dotted name is
        // one literal key. That lookup must stay byte-identical.
        let row = serde_json::json!({"file.hashes.sha256": "AB12CD34", "dest_ip": "10.9.9.9"});
        assert_eq!(
            result_field_strings(&row, "file.hashes.sha256"),
            vec!["AB12CD34"]
        );
        assert_eq!(result_field_strings(&row, "dest_ip"), vec!["10.9.9.9"]);
    }

    #[test]
    fn missing_paths_stay_empty() {
        let row = lake_row();
        assert!(result_field_strings(&row, "file.hashes.value").is_empty());
        assert!(result_field_strings(&row, "nope.not.here").is_empty());
    }

    #[test]
    fn coalesce_artifact_extraction_reads_nested_paths() {
        let row = lake_row();
        let fields = LAKE_HASH_ARTIFACT_PATHS
            .iter()
            .map(|path| (*path).to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            extract_prevalence_artifact(&row, &fields).as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
    }

    #[test]
    fn artifact_path_lists_are_canonical_ocsf_1_9_fields() {
        // A typo here is invisible at runtime — it just extracts nothing, which
        // is exactly the failure mode being fixed. Pin the paths against the
        // lake profile's own field universe.
        let profile = crate::schema::OcsfProfile::lake_1_9();
        for path in LAKE_HASH_ARTIFACT_PATHS
            .iter()
            .chain(LAKE_DOMAIN_ARTIFACT_PATHS)
            .chain(LAKE_IP_ARTIFACT_PATHS)
        {
            assert!(
                crate::schema::SchemaProfile::is_known_field(&profile, path),
                "{path} is not a field of the OCSF 1.9 lake schema"
            );
        }
    }
}


/// NAN-3070: the default lake enrichment must key `host_count` on what the
/// event touched (hash / destination), never on the event's own host.
mod nan3070_self_hostname {
    use super::*;
    use crate::prevalence::{ArtifactType, PrevalenceData};
    use std::collections::HashMap;

    fn data(artifact: &str, artifact_type: ArtifactType, host_count: u64) -> PrevalenceData {
        let at = chrono::DateTime::parse_from_rfc3339("2026-09-28T18:28:11Z").unwrap().with_timezone(&chrono::Utc);
        PrevalenceData {
            artifact: artifact.to_string(),
            artifact_type,
            host_count,
            host_count_saturated: host_count >= 1000,
            total_occurrences: host_count * 3,
            first_seen: at,
            last_seen: at,
            is_rare: host_count < 5,
            prevalence_score: 50,
        }
    }

    fn lists() -> (Vec<String>, Vec<String>, Vec<String>) {
        let own = |paths: &[&str]| paths.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        (own(LAKE_HASH_ARTIFACT_PATHS), own(LAKE_DOMAIN_ARTIFACT_PATHS), own(LAKE_IP_ARTIFACT_PATHS))
    }

    const HASH: &str = "f447ae2e838d4de71ca4baba321fea67dabb38aa4321efac81f3ff03cf55fe0a";
    const HOST: &str = "ws-exec-052.corp.local";

    /// The live the pooled host case: a process hash seen on 1000 hosts came back
    /// `host_count 1` (the reporting host's own hostname) through
    /// `prevalence enrich=true`, so `newly_seen_rare_process` matched 6,574
    /// rows an hour.
    #[test]
    fn process_hash_host_count_is_not_the_reporting_hosts_own_hostname() {
        let (h, d, i) = lists();
        let hashes = HashMap::from([(HASH.to_string(), data(HASH, ArtifactType::HashSha256, 1000))]);
        let domains = HashMap::from([(HOST.to_string(), data(HOST, ArtifactType::Subdomain, 1))]);
        for mut row in [
            // The table-projected shape the rule's result rows carry.
            serde_json::json!({"device.hostname": HOST, "process.file.hashes.value": HASH, "process.name": "svchost.exe"}),
            // The native nested OCSF shape.
            serde_json::json!({"device": {"hostname": HOST}, "process": {"file": {"hashes": [{"algorithm_id": 3, "value": HASH}]}}}),
        ] {
            let mut rows = vec![row.take()];
            enrich_rows_with_prevalence(&mut rows, &h, &d, &i, &hashes, &domains, &HashMap::new());
            assert_eq!(rows[0]["host_count"], serde_json::json!(1000), "{}", rows[0]);
            assert_eq!(rows[0]["is_rare"], serde_json::json!(false));
            assert_eq!(rows[0]["prevalence_type"], serde_json::json!("hash"));
        }
    }

    #[test]
    fn outbound_flow_is_keyed_on_the_destination_not_the_source_host() {
        let (h, d, i) = lists();
        let domains = HashMap::from([("ws1.corp.local".to_string(), data("ws1.corp.local", ArtifactType::Subdomain, 1))]);
        let ips = HashMap::from([("203.0.113.9".to_string(), data("203.0.113.9", ArtifactType::IpAddress, 40))]);
        let mut rows = vec![serde_json::json!({"src_endpoint.hostname": "ws1.corp.local", "dst_endpoint.ip": "203.0.113.9"})];
        enrich_rows_with_prevalence(&mut rows, &h, &d, &i, &HashMap::new(), &domains, &ips);
        assert_eq!(rows[0]["host_count"], serde_json::json!(40), "{}", rows[0]);
        assert_eq!(rows[0]["prevalence_type"], serde_json::json!("ip"));
    }

    #[test]
    fn a_destination_domain_still_outranks_the_hash() {
        let (h, d, i) = lists();
        let hashes = HashMap::from([(HASH.to_string(), data(HASH, ArtifactType::HashSha256, 1000))]);
        let domains = HashMap::from([("evil.example.test".to_string(), data("evil.example.test", ArtifactType::Subdomain, 2))]);
        let mut rows = vec![serde_json::json!({"device.hostname": HOST, "dst_endpoint.hostname": "evil.example.test", "process.file.hashes.value": HASH})];
        enrich_rows_with_prevalence(&mut rows, &h, &d, &i, &hashes, &domains, &HashMap::new());
        assert_eq!(rows[0]["host_count"], serde_json::json!(2));
    }

    #[test]
    fn an_explicit_own_host_field_is_still_honoured() {
        // `| prevalence src_endpoint.hostname`: the positional contract uses
        // exactly the named field for every artifact class.
        let named = vec!["src_endpoint.hostname".to_string()];
        let domains = HashMap::from([("ws1.corp.local".to_string(), data("ws1.corp.local", ArtifactType::Subdomain, 1))]);
        let mut rows = vec![serde_json::json!({"src_endpoint.hostname": "ws1.corp.local"})];
        enrich_rows_with_prevalence(&mut rows, &named, &named, &named, &HashMap::new(), &domains, &HashMap::new());
        assert_eq!(rows[0]["host_count"], serde_json::json!(1));
    }

    #[test]
    fn default_domain_list_excludes_the_events_own_hosts() {
        assert!(!LAKE_DOMAIN_ARTIFACT_PATHS.contains(&"device.hostname"));
        assert!(!LAKE_DOMAIN_ARTIFACT_PATHS.contains(&"src_endpoint.hostname"));
        assert_eq!(LAKE_DOMAIN_ARTIFACT_PATHS[0], "dst_endpoint.hostname");
    }
}


/// NAN-4372: lake prevalence snapshots are per-window, so a `window=24h`
/// snapshot's first_seen is only the earliest sighting inside those 24 hours.
/// first_seen conditions must read the 30d snapshot whatever `window=` is,
/// while host counts keep `window=`.
mod first_seen_window {
    use super::super::{lookup_window_for, PrevalenceComparison};
    use crate::prevalence::{ArtifactType, PrevalenceData, TimeWindow};
    use crate::query::{PrevalenceCondition, PrevalenceField, PrevalenceThreshold};
    use crate::search::query_processing::PrevalenceCommandInfo;
    use crate::search::SearchService;
    use chrono::{Duration, Utc};
    use std::sync::{Arc, Mutex};

    /// Serves per-window snapshots the way the lake does: inside the 24h
    /// snapshot every artifact's first_seen is clamped to the window.
    struct PerWindowLake {
        requested: Arc<Mutex<Vec<TimeWindow>>>,
    }

    fn data(artifact: &str, first_seen: chrono::DateTime<Utc>) -> PrevalenceData {
        PrevalenceData {
            artifact: artifact.to_string(),
            artifact_type: ArtifactType::Subdomain,
            host_count: 2,
            host_count_saturated: false,
            total_occurrences: 6,
            first_seen,
            last_seen: Utc::now(),
            is_rare: true,
            prevalence_score: 50,
        }
    }

    #[async_trait::async_trait]
    impl crate::prevalence::PrevalenceLookup for PerWindowLake {
        async fn rarity_threshold(&self) -> u64 {
            5
        }

        async fn lookup(
            &self,
            artifacts: &[String],
            time_window: TimeWindow,
            _scope: &crate::auth::ArtifactScope,
        ) -> Result<Vec<PrevalenceData>, crate::prevalence::PrevalenceError> {
            self.requested.lock().unwrap().push(time_window);
            let now = Utc::now();
            Ok(artifacts
                .iter()
                .map(|artifact| {
                    let true_first_seen = if artifact == "old.example" {
                        now - Duration::days(10)
                    } else {
                        now - Duration::hours(2)
                    };
                    let first_seen = match time_window {
                        TimeWindow::ThirtyDays => true_first_seen,
                        // Earliest sighting inside the window.
                        _ => true_first_seen.max(now - Duration::hours(20)),
                    };
                    data(artifact, first_seen)
                })
                .collect())
        }
    }

    #[test]
    fn first_seen_reads_the_30d_window_and_counts_keep_the_requested_one() {
        let first_seen = PrevalenceComparison::FirstSeen(Utc::now());
        let count = PrevalenceComparison::HostCount(10);
        for window in [TimeWindow::TwentyFourHours, TimeWindow::SevenDays, TimeWindow::ThirtyDays] {
            assert_eq!(lookup_window_for(&first_seen, window), TimeWindow::ThirtyDays);
            assert_eq!(lookup_window_for(&count, window), window);
        }
    }

    /// `prevalence domain_prevalence < 10 domain_first_seen > now() - 24h
    /// window=24h` on the lake: a domain first seen ten days ago is excluded.
    #[tokio::test]
    async fn lake_window_24h_excludes_an_artifact_first_seen_ten_days_ago() {
        let pool = crate::db::DualPool::new_lake_control_plane(
            &crate::db::DualPoolConfig::with_auth(
                "postgres://unused:unused@127.0.0.1:1/nanosiem",
                "http://127.0.0.1:1",
                "nanosiem",
                "unused",
                "nanosiem",
            ),
        )
        .await
        .unwrap();
        let mut service = SearchService::with_dual_pool(&pool);
        service.set_active_profile(Arc::new(crate::schema::OcsfProfile::lake_1_9()));
        let requested = Arc::new(Mutex::new(Vec::new()));
        service.set_prevalence_lookup(Arc::new(PerWindowLake {
            requested: requested.clone(),
        }));
        let rows = vec![
            serde_json::json!({"dst_endpoint.hostname": "old.example"}),
            serde_json::json!({"dst_endpoint.hostname": "new.example"}),
        ];
        let info = PrevalenceCommandInfo {
            artifact_fields: Vec::new(),
            conditions: vec![
                PrevalenceCondition {
                    field: PrevalenceField::DomainPrevalence,
                    operator: crate::query::PrevalenceOperator::Lt,
                    threshold: PrevalenceThreshold::Count(10),
                },
                PrevalenceCondition {
                    field: PrevalenceField::DomainFirstSeen,
                    operator: crate::query::PrevalenceOperator::Gt,
                    threshold: PrevalenceThreshold::Duration(std::time::Duration::from_secs(
                        86_400,
                    )),
                },
            ],
            time_window: Some(crate::query::PrevalenceTimeWindow::TwentyFourHours),
            enrich: false,
        };
        let out = service
            .apply_prevalence_processing(rows, &[info], &crate::auth::ArtifactScope::system())
            .await
            .unwrap();
        assert_eq!(
            out,
            vec![serde_json::json!({"dst_endpoint.hostname": "new.example"})],
            "a domain known for ten days is not new in the last 24h"
        );
        assert_eq!(
            *requested.lock().unwrap(),
            vec![TimeWindow::TwentyFourHours, TimeWindow::ThirtyDays],
            "the count reads window=24h, first_seen the 30d snapshot"
        );
    }
}
