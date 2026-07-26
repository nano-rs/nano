// SPDX-License-Identifier: AGPL-3.0-or-later

//! nPL `dataset=risk` SQL generation tests (NAN-1798 P2).
//!
//! Pins:
//! - the derived `FROM (<risk aggregation>)` base source composes the shared
//!   risk builder's fragments (never a re-derived decay formula) — asserted by
//!   building the expected subquery with `risk_dataset_base_query` itself;
//! - the outer time bound is neutralized for risk (fixed trailing windows the
//!   picker does not reshape) but byte-identical for every other dataset;
//! - risk columns resolve bare + numeric (no `lower()`, no `ext.*` spill);
//! - `where`/`stats`/`sort`/`table`/`head` compose over the derived grain;
//! - `[dataset=risk …]` IN-subsearch brackets scope the derived source and the
//!   neutral bound to the SUBSEARCH only;
//! - `dataset=logs/spans/metrics` output is byte-identical with and without an
//!   attached risk config (the new plumbing is output-neutral for non-risk).

use std::collections::{BTreeSet, HashMap};

use chrono::{TimeZone, Utc};

use super::otel::Dataset;
use super::ClickHouseSqlGenerator;
use crate::query::parser::parse_query;
use crate::query::TimeRange;
use crate::risk::clickhouse_sql::{
    risk_dataset_base_query, ClearedBoundaries, RiskFindingsSource, RiskQueryConfig,
};
use crate::risk::types::RiskDecayConfig;

fn fixed_now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 10, 12, 0, 0).unwrap()
}

fn time_range() -> TimeRange {
    TimeRange {
        start: "2026-07-10T00:00:00Z".parse().unwrap(),
        end: "2026-07-10T12:00:00Z".parse().unwrap(),
    }
}

fn risk_config() -> RiskQueryConfig {
    let mut cleared = HashMap::new();
    cleared.insert(
        "john.doe".to_string(),
        Utc.with_ymd_and_hms(2026, 7, 8, 9, 30, 0).unwrap(),
    );
    RiskQueryConfig {
        decay: RiskDecayConfig::default(),
        cleared: ClearedBoundaries::from_map(&cleared),
        now: fixed_now(),
    }
}

fn risk_generator() -> ClickHouseSqlGenerator {
    ClickHouseSqlGenerator::new()
        .with_risk_config(risk_config())
        .with_dataset(Dataset::Risk)
}

/// The exact derived base source the generator must embed: the shared
/// builder's entity-grain aggregation, inlined and parenthesized.
fn expected_base_source() -> String {
    let cfg = risk_config();
    let source = RiskFindingsSource::new(false, "logs");
    format!(
        "({})",
        risk_dataset_base_query(&source, cfg.now, &cfg.decay, &cfg.cleared).to_inline_sql()
    )
}

fn generate(gen: &ClickHouseSqlGenerator, q: &str) -> String {
    let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
    gen.generate(&query, &time_range())
        .unwrap_or_else(|e| panic!("generate {q}: {e}"))
}

// ---------------------------------------------------------------------------
// Derived base source
// ---------------------------------------------------------------------------

#[test]
fn risk_single_stage_scans_the_shared_builder_subquery() {
    let sql = generate(&risk_generator(), "score_24h > 100");

    // The FROM is the EXACT inline rendering of the shared builder's dataset
    // base query — proving the dataset composes P1's fragments rather than
    // re-deriving the decay SQL.
    let base = expected_base_source();
    assert!(
        sql.contains(&base),
        "generated SQL must embed the shared-builder base source\nsql: {sql}\nexpected base: {base}"
    );

    // Fixed trailing windows: the picker's bound is neutralized for risk.
    assert!(
        sql.contains("WHERE 1 = 1 AND (score_24h > 100)"),
        "risk time bound must be constant-true; got: {sql}"
    );
    assert!(
        !sql.contains("last_finding_at BETWEEN"),
        "picker window must not reshape the risk grain: {sql}"
    );

    // Default ordering is the grain's time column.
    assert!(sql.contains("ORDER BY last_finding_at DESC"), "{sql}");
}

#[test]
fn risk_base_source_inlines_decay_and_cleared_boundaries() {
    let sql = generate(&risk_generator(), "score_24h > 100");
    let cfg = risk_config();

    // Decay factors inlined as float literals in bucket order.
    for factor in ["1.0", "0.7", "0.4", "0.2"] {
        assert!(sql.contains(factor), "decay factor {factor} missing: {sql}");
    }
    // Cleared-entity parallel arrays (entity + boundary micros + sentinels).
    let boundary = Utc
        .with_ymd_and_hms(2026, 7, 8, 9, 30, 0)
        .unwrap()
        .timestamp_micros()
        .to_string();
    assert!(sql.contains("'john.doe'"), "{sql}");
    assert!(sql.contains(&boundary), "{sql}");
    // The 7d horizon cutoff anchored at the pinned `now`.
    let cutoff_7d = (cfg.now - chrono::Duration::hours(168))
        .timestamp_micros()
        .to_string();
    assert!(sql.contains(&cutoff_7d), "{sql}");
    // No unresolved placeholders.
    assert!(!sql.contains('?'), "unrendered bind placeholder: {sql}");
}

#[test]
fn risk_dataset_uses_generator_source_scope_for_finding_origins() {
    let deny: BTreeSet<String> = ["insider_threat".to_string()].into_iter().collect();
    let gen = ClickHouseSqlGenerator::new()
        .with_risk_config(risk_config())
        .with_source_scope_deny(deny.clone())
        .with_dataset(Dataset::Risk);
    let sql = generate(&gen, "score_24h > 0");

    assert!(
        sql.contains(
            "notEmpty(JSONExtract(metadata, 'origin_source_types', 'Array(String)'))"
        ),
        "restricted dataset=risk must fail closed on legacy-empty origins: {sql}"
    );
    assert!(
        sql.contains("['__nano:unresolved_source__', 'insider_threat']"),
        "restricted dataset=risk must inline the normalized effective deny payload: {sql}"
    );

    let subsearch = ClickHouseSqlGenerator::new()
        .with_risk_config(risk_config())
        .with_source_scope_deny(deny);
    let subsearch_sql = generate(
        &subsearch,
        "user IN [dataset=risk score_24h > 0 | return entity]",
    );
    assert!(
        subsearch_sql.contains(
            "notEmpty(JSONExtract(metadata, 'origin_source_types', 'Array(String)'))"
        ),
        "a risk subsearch must inherit the outer request's scope: {subsearch_sql}"
    );
}

#[test]
fn risk_base_source_is_ocsf_and_cluster_aware() {
    // OCSF profile + clustered routing: the derived scan must read the
    // captured tenant table (`ocsf_logs_distributed`) through the OCSF
    // `unmapped` sentinels — inherited from the shared builder.
    let gen = ClickHouseSqlGenerator::with_table("ocsf_logs_distributed")
        .with_profile(std::sync::Arc::new(crate::schema::OcsfProfile::new()))
        .with_cluster_routing(true)
        .with_risk_config(risk_config())
        .with_dataset(Dataset::Risk);
    let sql = generate(&gen, "score_24h > 100");

    assert!(sql.contains("FROM ocsf_logs_distributed"), "{sql}");
    assert!(
        sql.contains("JSONExtractString(toString(unmapped),'risk_entity')"),
        "OCSF risk-entity sentinel missing: {sql}"
    );
    assert!(
        sql.contains("JSONExtract(toString(unmapped), 'mitre_tactics', 'Array(String)')"),
        "OCSF tactics sentinel missing: {sql}"
    );

    let cfg = risk_config();
    let source = RiskFindingsSource::new(true, "ocsf_logs_distributed");
    let base = format!(
        "({})",
        risk_dataset_base_query(&source, cfg.now, &cfg.decay, &cfg.cleared).to_inline_sql()
    );
    assert!(sql.contains(&base), "must embed the OCSF/clustered base source");
}

// ---------------------------------------------------------------------------
// Pipeline composition over the derived grain
// ---------------------------------------------------------------------------

#[test]
fn risk_columns_resolve_bare_and_numeric() {
    let gen = risk_generator();

    // Bare numeric comparison: direct column, no lower() wrap.
    let sql = generate(&gen, "score_24h > 100");
    assert!(sql.contains("score_24h > 100"), "{sql}");
    assert!(!sql.contains("lower(score_24h)"), "{sql}");

    // Quoted numeric equality (UI drill-down form) coerces to a number —
    // the same `field_is_numeric` seam spans/metrics numeric columns ride.
    let sql = generate(&gen, "score_24h=\"100\"");
    assert!(sql.contains("score_24h = 100"), "{sql}");
    assert!(!sql.contains("lower(score_24h)"), "{sql}");

    // String equality on entity: never an ext spill on the derived grain.
    let sql = generate(&gen, "entity=\"10.0.0.5\"");
    assert!(!sql.contains("ext."), "no ext spill on risk grain: {sql}");
    assert!(sql.contains("entity"), "{sql}");
}

#[test]
fn risk_pipeline_where_stats_sort_table_head_compose() {
    let gen = risk_generator();

    let sql = generate(
        &gen,
        "score_24h > 100 | where distinct_tactics_24h >= 3 and distinct_rules_24h >= 2 | sort -score_24h | head 10",
    );
    assert!(sql.contains("WITH stage_0 AS"), "{sql}");
    assert!(sql.contains(&expected_base_source()), "{sql}");
    assert!(sql.contains("distinct_tactics_24h >= 3"), "{sql}");
    assert!(sql.contains("distinct_rules_24h >= 2"), "{sql}");
    assert!(sql.contains("ORDER BY score_24h DESC"), "{sql}");
    assert!(sql.contains("LIMIT 10"), "{sql}");

    let sql = generate(&gen, "* | stats count by entity_type");
    assert!(sql.contains("GROUP BY"), "{sql}");
    assert!(sql.contains("entity_type"), "{sql}");
    assert!(!sql.contains("ext."), "{sql}");

    let sql = generate(&gen, "* | table entity, entity_type, score_24h, score_7d");
    assert!(sql.contains("SELECT entity, entity_type, score_24h, score_7d"), "{sql}");
}

// ---------------------------------------------------------------------------
// Cross-dataset subsearch bracket
// ---------------------------------------------------------------------------

#[test]
fn logs_query_with_risk_in_subsearch_scopes_derived_source_to_the_bracket() {
    // A logs query correlating against hot risk entities: the OUTER scan keeps
    // its real time bound on `logs`; the IN subquery reads the derived risk
    // source with the neutral bound.
    let gen = ClickHouseSqlGenerator::new().with_risk_config(risk_config());
    let sql = generate(
        &gen,
        "user IN [dataset=risk score_24h > 100 | return entity]",
    );

    assert!(sql.contains("FROM logs"), "{sql}");
    assert!(sql.contains("timestamp BETWEEN"), "outer logs bound must remain: {sql}");
    assert!(sql.contains(&expected_base_source()), "subsearch must read the derived source: {sql}");
    assert!(
        sql.contains("WHERE 1 = 1 AND (score_24h > 100)"),
        "subsearch bound must be neutral: {sql}"
    );
}

#[test]
fn logs_query_with_risk_join_scopes_derived_source_to_the_subsearch() {
    // Cross-dataset JOIN enrichment: annotate matching log rows with the
    // entity's accumulated scores. The subsearch side reads the derived risk
    // source with the neutral bound; the outer logs scan keeps its real bound.
    let gen = ClickHouseSqlGenerator::new().with_risk_config(risk_config());
    let sql = generate(
        &gen,
        "error | join user [dataset=risk score_7d > 50 | rename entity as user]",
    );

    assert!(sql.contains("timestamp BETWEEN"), "outer logs bound must remain: {sql}");
    // The multi-stage subsearch generator re-indents nested SQL, so compare the
    // embedded derived source whitespace-normalized (token-identical).
    let normalize = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        normalize(&sql).contains(&normalize(&expected_base_source())),
        "join subsearch must read the derived source: {sql}"
    );
    assert!(
        sql.contains("1 = 1"),
        "join subsearch bound must be neutral: {sql}"
    );
}

#[test]
fn risk_selector_is_strict_and_lenient_consistently() {
    assert_eq!(Dataset::from_selector("risk"), Dataset::Risk);
    assert_eq!(Dataset::from_selector_strict("risk"), Some(Dataset::Risk));
    assert_eq!(Dataset::from_selector_strict("RISK"), Some(Dataset::Risk));
    // Typos stay hard errors in the strict form (subsearch brackets).
    assert_eq!(Dataset::from_selector_strict("risks"), None);
}

// ---------------------------------------------------------------------------
// Non-risk datasets: byte-identical
// ---------------------------------------------------------------------------

#[test]
fn non_risk_datasets_are_byte_identical_with_and_without_risk_config() {
    let queries = [
        "error | head 100",
        "status=500 | stats count by src_ip | sort -count",
        "* | timechart span=1h count",
        "user IN [dataset=spans duration_ns > 1000 | return user]",
    ];
    for (dataset, base) in [
        (None, "logs"),
        (Some(Dataset::Spans), "spans"),
        (Some(Dataset::Metrics), "metrics"),
    ] {
        for q in queries {
            let plain = {
                let mut g = ClickHouseSqlGenerator::new();
                if let Some(ds) = dataset {
                    g = g.with_dataset(ds);
                }
                g
            };
            let with_cfg = {
                let mut g = ClickHouseSqlGenerator::new().with_risk_config(risk_config());
                if let Some(ds) = dataset {
                    g = g.with_dataset(ds);
                }
                g
            };
            let a = generate(&plain, q);
            let b = generate(&with_cfg, q);
            assert_eq!(
                a, b,
                "dataset={base}: attaching a risk config must not perturb SQL for {q}"
            );
        }
    }
}

#[test]
fn logs_time_bound_predicate_is_byte_identical_form() {
    // The refactored helper must emit the exact historical bound text.
    let gen = ClickHouseSqlGenerator::new();
    let tr = time_range();
    assert_eq!(
        gen.time_bound_predicate("timestamp", &tr),
        "timestamp BETWEEN '2026-07-10 00:00:00.000000' AND '2026-07-10 12:00:00.000000'"
    );
    let sql = generate(&gen, "error | head 100");
    assert!(
        sql.contains(
            "WHERE timestamp BETWEEN '2026-07-10 00:00:00.000000' AND '2026-07-10 12:00:00.000000' AND ("
        ),
        "{sql}"
    );
}
