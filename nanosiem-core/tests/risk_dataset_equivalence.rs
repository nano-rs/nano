// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live equivalence probe for the nPL `dataset=risk` derived base source
//! (NAN-1798 P2): the per-entity `score_24h`/`score_7d` an nPL query returns
//! MUST equal what the shared builder's canonical `entity_scores_query` (the
//! Risk page entity list / leaderboard computation, proven byte-identical to
//! the pre-P1 inline repository SQL by `risk_ch_sql_equivalence`) produces for
//! the same data, decay factors, cleared boundaries, and `now` — proving the
//! dataset is a composition of the same computation, never a re-derivation.
//!
//! Also pins the dataset-only widths (`distinct_rules_*`, `distinct_tactics_*`
//! from the finding `metadata.mitre_tactics` JSON) against hand-computed
//! ground truth, and that the search time picker does NOT reshape the fixed
//! trailing 24h/7d windows (identical rows under a 15-minute and a 30-day
//! picker window).
//!
//! Seeds fixture findings spanning the decay buckets, a cleared entity, and
//! per-rule MITRE tactic sets. Existing findings rows in the target database
//! participate in the old-vs-new comparison too — more data, stronger probe.
//!
//! Requires a local ClickHouse with the nano schema:
//!   cargo test -p nanosiem-core --test risk_dataset_equivalence -- --ignored --nocapture
//! Env: CLICKHOUSE_TEST_URL (default http://localhost:8123), user/password
//! nanosiem/nanosiem, database nanosiem (UDM profile).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use clickhouse::Client;
use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, Dataset, TimeRange};
use nanosiem_core::risk::clickhouse_sql::{
    entity_scores_query, ClearedBoundaries, EntityScoreSelection, RiskFindingsSource,
    RiskQueryConfig,
};
use nanosiem_core::risk::RiskDecayConfig;

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}

fn ch_client() -> Client {
    Client::default()
        .with_url(ch_url())
        .with_user("nanosiem")
        .with_password("nanosiem")
        .with_database("nanosiem")
}

/// Insert client: async_insert off + wait_end_of_query so seeded rows are
/// queryable on return (repo convention for CH inserts from Rust tests).
fn ch_insert_client() -> Client {
    ch_client()
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1")
}

// ---------------------------------------------------------------------------
// Row shapes
// ---------------------------------------------------------------------------

/// The canonical entity-list row (P1 `entity_scores_query` projection).
#[derive(Debug, Clone, PartialEq, clickhouse::Row, serde::Deserialize)]
struct EntityScoreRow {
    entity: String,
    entity_type: String,
    risk_score_24h: i64,
    risk_score_7d: i64,
    decayed_score_24h: i64,
    decayed_score_7d: i64,
    signal_count_24h: u64,
    signal_count_7d: u64,
    last_signal_at: i64,
    last_rule_name: String,
    last_severity: String,
}

/// The `dataset=risk` row as projected by the nPL `| table …` below (every
/// dataset column except the DateTime64 `last_finding_at`, which the
/// RowBinary deserializer has no plain-integer mapping for).
#[derive(Debug, Clone, PartialEq, clickhouse::Row, serde::Deserialize)]
struct RiskDatasetRow {
    entity: String,
    entity_type: String,
    score_24h: i64,
    score_7d: i64,
    raw_score_24h: i64,
    raw_score_7d: i64,
    findings_24h: u64,
    findings_7d: u64,
    distinct_rules_24h: u64,
    distinct_rules_7d: u64,
    distinct_tactics_24h: u64,
    distinct_tactics_7d: u64,
    last_rule_name: String,
    last_severity: String,
}

const DATASET_TABLE_PIPE: &str = "* | table entity, entity_type, score_24h, score_7d, \
     raw_score_24h, raw_score_7d, findings_24h, findings_7d, distinct_rules_24h, \
     distinct_rules_7d, distinct_tactics_24h, distinct_tactics_7d, last_rule_name, \
     last_severity";

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    source: String,
    user_entity: String,
    host_entity: String,
    cleared_entity: String,
}

/// Seed findings across decay buckets with per-rule tactic sets:
/// - user entity:
///     2h  old, score 10, rule-a, tactics [TA0001, TA0002]
///     36h old, score 20, rule-a, tactics [TA0001, TA0002]
///     96h old, score 30, rule-b, tactics [TA0002, TA0003]
///     192h old (aged out), score 50, rule-b
///   → decayed 7d = 10*1.0 + 20*0.7 + 30*0.4 = 36; 24h = 10
///   → rules 24h/7d = 1/2; tactics 24h/7d = 2 (TA0001-2) / 3 (TA0001-3)
/// - host entity: 2h old, score 15, rule-a → hostname-typed, 15/15
/// - cleared entity: 96h old score 60 (pre-clear, dropped) + 2h old score 70
async fn seed_fixture(client: &Client, now: DateTime<Utc>) -> Fixture {
    let run = now.timestamp_nanos_opt().unwrap_or(0);
    let fx = Fixture {
        source: format!("p2eq-{run}"),
        user_entity: format!("p2eq_user_{run}"), // no '.'/'@' → 'user'
        host_entity: format!("p2eq-{run}.example.com"), // '.' → 'hostname'
        cleared_entity: format!("p2eq_cleared_{run}"), // cleared at now-1d
    };

    let rows: Vec<(&str, f64, Duration, &str, &str, &str, &str)> = vec![
        (
            &fx.user_entity,
            10.0,
            Duration::hours(2),
            "p2eq-rule-a",
            "P2EQ Rule A",
            "high",
            r#"{"mitre_tactics":["TA0001","TA0002"]}"#,
        ),
        (
            &fx.user_entity,
            20.0,
            Duration::hours(36),
            "p2eq-rule-a",
            "P2EQ Rule A",
            "high",
            r#"{"mitre_tactics":["TA0001","TA0002"]}"#,
        ),
        (
            &fx.user_entity,
            30.0,
            Duration::hours(96),
            "p2eq-rule-b",
            "P2EQ Rule B",
            "medium",
            r#"{"mitre_tactics":["TA0002","TA0003"]}"#,
        ),
        (
            &fx.user_entity,
            50.0,
            Duration::hours(192),
            "p2eq-rule-b",
            "P2EQ Rule B",
            "medium",
            r#"{"mitre_tactics":["TA0009"]}"#,
        ),
        (
            &fx.host_entity,
            15.0,
            Duration::hours(2),
            "p2eq-rule-a",
            "P2EQ Rule A",
            "high",
            r#"{"mitre_tactics":["TA0001"]}"#,
        ),
        (
            &fx.cleared_entity,
            60.0,
            Duration::hours(96),
            "p2eq-rule-c",
            "P2EQ Rule C",
            "low",
            "{}",
        ),
        (
            &fx.cleared_entity,
            70.0,
            Duration::hours(2),
            "p2eq-rule-c",
            "P2EQ Rule C",
            "low",
            "{}",
        ),
    ];

    for (entity, score, age, rule_id, rule_name, severity, metadata) in rows {
        client
            .query(
                "INSERT INTO logs \
                 (timestamp, message, metadata, source_type, source, risk_entity, risk_score, \
                  rule_id, rule_name, severity, action) \
                 VALUES (fromUnixTimestamp64Micro(?), ?, ?, 'findings', ?, ?, ?, ?, ?, ?, 'detection_match')",
            )
            .bind((now - age).timestamp_micros())
            .bind(format!("p2eq dataset equivalence fixture {run}"))
            .bind(metadata)
            .bind(fx.source.as_str())
            .bind(entity)
            .bind(score)
            .bind(rule_id)
            .bind(rule_name)
            .bind(severity)
            .execute()
            .await
            .expect("seed findings row");
    }

    fx
}

async fn cleanup_fixture(client: &Client, fx: &Fixture) {
    let _ = client
        .query("DELETE FROM logs WHERE source = ? AND source_type = 'findings'")
        .bind(fx.source.as_str())
        .execute()
        .await;
}

fn sort_entity_rows(mut rows: Vec<EntityScoreRow>) -> Vec<EntityScoreRow> {
    rows.sort_by(|a, b| (&a.entity, &a.entity_type).cmp(&(&b.entity, &b.entity_type)));
    rows
}

fn sort_dataset_rows(mut rows: Vec<RiskDatasetRow>) -> Vec<RiskDatasetRow> {
    rows.sort_by(|a, b| (&a.entity, &a.entity_type).cmp(&(&b.entity, &b.entity_type)));
    rows
}

/// Generate the executable SQL for an nPL query over `dataset=risk` with the
/// given per-request config — the exact `core_search` path (config attached
/// before the dataset swap; single-node `logs` table; UDM profile).
fn dataset_sql(npl: &str, config: &RiskQueryConfig, time_range: &TimeRange) -> String {
    let generator = ClickHouseSqlGenerator::new()
        .with_risk_config(config.clone())
        .with_dataset(Dataset::Risk);
    let query = parse_query(npl).unwrap_or_else(|e| panic!("parse {npl}: {e}"));
    generator
        .generate(&query, time_range)
        .unwrap_or_else(|e| panic!("generate {npl}: {e}"))
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a local ClickHouse (:8123) with the nano schema — run with --ignored"]
async fn dataset_scores_equal_the_canonical_entity_scores_query() {
    let insert_client = ch_insert_client();
    let client = ch_client();

    let now = Utc::now();
    let fx = seed_fixture(&insert_client, now).await;

    let decay = RiskDecayConfig::default(); // 1.0 / 0.7 / 0.4 / 0.2
    let mut cleared_map: HashMap<String, DateTime<Utc>> = HashMap::new();
    cleared_map.insert(fx.cleared_entity.clone(), now - Duration::hours(24));
    let cleared = ClearedBoundaries::from_map(&cleared_map);
    let source = RiskFindingsSource::new(false, "logs");
    let config = RiskQueryConfig {
        decay: decay.clone(),
        cleared: cleared.clone(),
        now,
    };

    // --- 1. Canonical scores: P1's entity_scores_query (the Risk page /
    // leaderboard computation) over the whole findings population. ----------
    let canonical: Vec<EntityScoreRow> = entity_scores_query(
        &source,
        now,
        &decay,
        &cleared,
        EntityScoreSelection::MinScores {
            min_score_24h: 0,
            min_score_7d: 0,
            limit: 1_000_000,
        },
    )
    .to_clickhouse_query(&client)
    .fetch_all()
    .await
    .expect("canonical entity scores");
    assert!(
        canonical.len() >= 3,
        "expected at least the fixture entities, got {}",
        canonical.len()
    );

    // --- 2. The same population through nPL `dataset=risk`. ----------------
    let picker_window = TimeRange {
        start: now - Duration::minutes(15),
        end: now,
    };
    let sql = dataset_sql(DATASET_TABLE_PIPE, &config, &picker_window);
    let dataset_rows: Vec<RiskDatasetRow> = client
        .query(&sql)
        .fetch_all()
        .await
        .unwrap_or_else(|e| panic!("dataset=risk SQL failed: {e}\n{sql}"));

    let canonical = sort_entity_rows(canonical);
    let dataset_rows = sort_dataset_rows(dataset_rows);

    // Same entity universe (both scan the identical findings WHERE; the
    // canonical MinScores{0,0} tail keeps every non-negative-score entity).
    assert_eq!(
        canonical
            .iter()
            .map(|r| (&r.entity, &r.entity_type))
            .collect::<Vec<_>>(),
        dataset_rows
            .iter()
            .map(|r| (&r.entity, &r.entity_type))
            .collect::<Vec<_>>(),
        "dataset=risk must see the exact entity universe of the canonical query"
    );

    // Per-entity equality of every shared measure — the headline guarantee:
    // dataset=risk IS the leaderboard computation.
    for (old, new) in canonical.iter().zip(dataset_rows.iter()) {
        assert_eq!(new.score_24h, old.decayed_score_24h, "score_24h {}", old.entity);
        assert_eq!(new.score_7d, old.decayed_score_7d, "score_7d {}", old.entity);
        assert_eq!(new.raw_score_24h, old.risk_score_24h, "raw_24h {}", old.entity);
        assert_eq!(new.raw_score_7d, old.risk_score_7d, "raw_7d {}", old.entity);
        assert_eq!(new.findings_24h, old.signal_count_24h, "findings_24h {}", old.entity);
        assert_eq!(new.findings_7d, old.signal_count_7d, "findings_7d {}", old.entity);
        assert_eq!(new.last_rule_name, old.last_rule_name, "last_rule_name {}", old.entity);
        assert_eq!(new.last_severity, old.last_severity, "last_severity {}", old.entity);
    }

    // --- 3. Fixture ground truth incl. the dataset-only widths. ------------
    let by_entity = |e: &str| {
        dataset_rows
            .iter()
            .find(|r| r.entity == e)
            .unwrap_or_else(|| panic!("fixture entity {e} present"))
    };

    let user = by_entity(&fx.user_entity);
    assert_eq!(user.entity_type, "user");
    assert_eq!(user.score_24h, 10);
    assert_eq!(user.score_7d, 36); // 10*1.0 + 20*0.7 + 30*0.4; >7d row excluded
    assert_eq!(user.raw_score_7d, 60);
    assert_eq!(user.findings_7d, 3);
    assert_eq!(user.distinct_rules_24h, 1);
    assert_eq!(user.distinct_rules_7d, 2);
    assert_eq!(user.distinct_tactics_24h, 2); // TA0001, TA0002
    assert_eq!(user.distinct_tactics_7d, 3); // + TA0003; aged-out TA0009 excluded
    assert_eq!(user.last_rule_name, "P2EQ Rule A");

    let host = by_entity(&fx.host_entity);
    assert_eq!(host.entity_type, "hostname");
    assert_eq!(host.score_7d, 15);
    assert_eq!(host.distinct_tactics_7d, 1);

    // Cleared boundary honored: only the post-clear 70-point finding counts.
    let cleared_row = by_entity(&fx.cleared_entity);
    assert_eq!(cleared_row.score_7d, 70);
    assert_eq!(cleared_row.findings_7d, 1);
    assert_eq!(cleared_row.distinct_tactics_7d, 0); // '{}' metadata

    // --- 4. The picker window must NOT reshape the fixed trailing windows:
    // a 15-minute and a 30-day picker window return identical rows. ---------
    let wide_window = TimeRange {
        start: now - Duration::days(30),
        end: now,
    };
    let sql_wide = dataset_sql(DATASET_TABLE_PIPE, &config, &wide_window);
    let wide_rows: Vec<RiskDatasetRow> = client
        .query(&sql_wide)
        .fetch_all()
        .await
        .unwrap_or_else(|e| panic!("dataset=risk SQL (wide window) failed: {e}\n{sql_wide}"));
    assert_eq!(
        dataset_rows,
        sort_dataset_rows(wide_rows),
        "picker window must not reshape the risk grain"
    );

    // --- 5. Pipeline filtering composes on the derived grain: the risk-notable
    // shape (`where` over scores + widths, sorted). --------------------------
    let filtered_sql = dataset_sql(
        &format!(
            "* | where score_7d >= 30 and distinct_rules_7d >= 2 | sort -score_7d | {}",
            &DATASET_TABLE_PIPE[4..] // reuse the table projection
        ),
        &config,
        &picker_window,
    );
    let filtered: Vec<RiskDatasetRow> = client
        .query(&filtered_sql)
        .fetch_all()
        .await
        .unwrap_or_else(|e| panic!("filtered dataset=risk SQL failed: {e}\n{filtered_sql}"));
    // Every returned row satisfies the predicate…
    assert!(filtered.iter().all(|r| r.score_7d >= 30 && r.distinct_rules_7d >= 2));
    // …the fixture's multi-rule hot entity is in, the single-rule ones are out…
    assert!(filtered.iter().any(|r| r.entity == fx.user_entity));
    assert!(filtered.iter().all(|r| r.entity != fx.host_entity));
    assert!(filtered.iter().all(|r| r.entity != fx.cleared_entity));
    // …and the result set is exactly the canonical rows passing the predicate.
    let expected: Vec<&RiskDatasetRow> = dataset_rows
        .iter()
        .filter(|r| r.score_7d >= 30 && r.distinct_rules_7d >= 2)
        .collect();
    assert_eq!(
        sort_dataset_rows(filtered.clone()).iter().collect::<Vec<_>>(),
        expected,
        "filtered dataset rows must be exactly the canonical rows passing the predicate"
    );

    // --- 6. Cross-dataset correlation executes end-to-end: a logs query with
    // a `[dataset=risk …]` IN bracket (the NAN-1562 seam the risk selector
    // lights up). Wrapped in count() so no wide-row typing is needed; the
    // point is that ClickHouse accepts and executes the embedded derived
    // source with its neutral bound inside a real logs scan. ----------------
    let in_sql = dataset_sql_logs_outer(
        "* | where user IN [dataset=risk score_7d >= 30 | return entity] | stats count",
        &config,
        &TimeRange {
            start: now - Duration::days(7),
            end: now,
        },
    );
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CountRow {
        count: u64,
    }
    let _count: Vec<CountRow> = client
        .query(&in_sql)
        .fetch_all()
        .await
        .unwrap_or_else(|e| panic!("cross-dataset risk IN subsearch failed: {e}\n{in_sql}"));

    cleanup_fixture(&insert_client, &fx).await;
}

/// Generate SQL for a LOGS-outer query that may carry `[dataset=risk …]`
/// subsearches — the `core_search` shape: risk config attached, no dataset
/// swap on the outer generator.
fn dataset_sql_logs_outer(npl: &str, config: &RiskQueryConfig, time_range: &TimeRange) -> String {
    let generator = ClickHouseSqlGenerator::new().with_risk_config(config.clone());
    let query = parse_query(npl).unwrap_or_else(|e| panic!("parse {npl}: {e}"));
    generator
        .generate(&query, time_range)
        .unwrap_or_else(|e| panic!("generate {npl}: {e}"))
}
