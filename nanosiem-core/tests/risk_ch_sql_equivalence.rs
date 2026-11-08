// SPDX-License-Identifier: AGPL-3.0-or-later

//! Old-vs-new equivalence probe for the shared risk ClickHouse SQL builder
//! (NAN-1803): executes the PRE-refactor inline statements (verbatim golden
//! copies, bound with the pre-refactor `.bind()` chains) and the builder's
//! statements against a real ClickHouse, over the same findings data and the
//! same `now`, and asserts identical results.
//!
//! Lockstep evolution (NAN-1806 / P4): the entity-type inference gained a
//! stamped `risk_entity_type = 'cloud_account'` first branch, so the entity
//! golden carries the same branch — behavior for unstamped rows is unchanged
//! (`''` never equals `'cloud_account'`), and the stamp behavior itself is
//! pinned by `risk_p4_readers_live.rs`. The threshold-view golden was removed
//! with `EntityScoreSelection::ExceedsThresholds` (risk alerting is a
//! `dataset=risk` rule since NAN-1805).
//!
//! Seeds fixture findings spanning every decay bucket (0-24h / 1-3d / 3-5d /
//! 5-7d / >7d-excluded), the `unknown` entity filter, and a cleared-entity
//! boundary, then also asserts the decayed sums against hand-computed ground
//! truth. Existing findings rows in the target database participate in the
//! old-vs-new comparison too — more data, stronger probe.
//!
//! Requires a local ClickHouse with the nano schema:
//!   cargo test -p nanosiem-core --test risk_ch_sql_equivalence -- --ignored --nocapture
//! Env: CLICKHOUSE_TEST_URL (default http://localhost:8123), user/password
//! nanosiem/nanosiem, database nanosiem (UDM profile).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use clickhouse::Client;
use nanosiem_core::risk::clickhouse_sql::{
    decayed_overview_query, entity_scores_query, rule_contributions_query, ClearedBoundaries,
    EntityScoreSelection, RiskFindingsSource,
};
use nanosiem_core::risk::{RiskDecayConfig, RiskTimeWindow};

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
// Golden copies of the PRE-refactor inline statements + bind chains
// (from nanosiem-enterprise/src/risk/repository.rs before NAN-1803; UDM
// sentinels substituted: risk_entity/risk_score/rule_name/rule_id/severity,
// single-node table `logs`)
// ---------------------------------------------------------------------------

const OLD_TIME_WINDOWED: &str = r#"
            WITH signal_scores AS (
                SELECT
                    risk_entity as entity,
                    -- Infer entity type from the value; honor the write-side
                    -- stamp for cloud_account only (NAN-1806)
                    multiIf(
                        JSONExtractString(metadata, 'risk_entity_type') = 'cloud_account', 'cloud_account',
                        match(risk_entity, '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'), 'ip',
                        position(risk_entity, '@') > 0, 'email',
                        position(risk_entity, '.') > 0, 'hostname',
                        'user'
                    ) as entity_type,
                    toInt32(risk_score) as risk_score,
                    toUnixTimestamp64Micro(timestamp) as ts_micros,
                    rule_name as rule_name,
                    severity as severity,
                    -- Calculate decay factor based on signal age
                    multiIf(
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 0-24h: decay_0_24h
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 1-3d:  decay_1_3d
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 3-5d:  decay_3_5d
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 5-7d:  decay_5_7d
                        0.0                                           -- >7d:   excluded
                    ) as decay_factor
                FROM logs
                WHERE source_type = 'findings'
                  AND risk_entity != ''
                  AND risk_entity != 'unknown'
                  AND toUnixTimestamp64Micro(timestamp) >= ?
                  -- Cleared-entity boundary: for a cleared entity keep only
                  -- post-clear findings (ts > its boundary); everything else
                  -- falls through indexOf=0 -> arrayElement(_,0)=0 -> ts>0. (R4)
                  AND toUnixTimestamp64Micro(timestamp) > arrayElement(?, indexOf(?, risk_entity))
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

/// Overview golden copy with the `{dscore}`/`{scount}` format! holes expanded
/// per window by [`old_overview_sql`].
const OLD_OVERVIEW: &str = r#"
            WITH signal_scores AS (
                SELECT
                    risk_entity as entity,
                    toInt32(risk_score) as risk_score,
                    toUnixTimestamp64Micro(timestamp) as ts_micros,
                    multiIf(
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,
                        0.0
                    ) as decay_factor
                FROM logs
                WHERE source_type = 'findings'
                  AND risk_entity != ''
                  AND risk_entity != 'unknown'
                  AND toUnixTimestamp64Micro(timestamp) >= ?
                  AND toUnixTimestamp64Micro(timestamp) > arrayElement(?, indexOf(?, risk_entity))
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

const OLD_CONTRIBUTIONS: &str = r#"
            WITH signal_scores AS (
                SELECT
                    toInt32(risk_score) as risk_score,
                    toUnixTimestamp64Micro(timestamp) as ts_micros,
                    rule_id as rule_id,
                    rule_name as rule_name,
                    severity as severity,
                    multiIf(
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 0-24h: decay_0_24h
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 1-3d:  decay_1_3d
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 3-5d:  decay_3_5d
                        toUnixTimestamp64Micro(timestamp) >= ? , ?,   -- 5-7d:  decay_5_7d
                        0.0                                           -- >7d:   excluded
                    ) as decay_factor
                FROM logs
                WHERE source_type = 'findings'
                  AND risk_entity IN ?
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

fn old_overview_sql(window: RiskTimeWindow) -> String {
    let (dscore, scount) = if matches!(window, RiskTimeWindow::Last24Hours) {
        ("decayed_score_24h", "signal_count_24h")
    } else {
        ("decayed_score_7d", "signal_count_7d")
    };
    OLD_OVERVIEW
        .replace("__DSCORE__", dscore)
        .replace("__SCOUNT__", scount)
}

struct Cutoffs {
    c24: i64,
    c3d: i64,
    c5d: i64,
    c7d: i64,
}

fn cutoffs_at(now: DateTime<Utc>) -> Cutoffs {
    Cutoffs {
        c24: (now - Duration::hours(24)).timestamp_micros(),
        c3d: (now - Duration::hours(72)).timestamp_micros(),
        c5d: (now - Duration::hours(120)).timestamp_micros(),
        c7d: (now - Duration::hours(168)).timestamp_micros(),
    }
}

/// The pre-refactor decay + findings-WHERE bind prefix shared by the old
/// entity-grain statements (order copied from the original `.bind()` chains).
fn old_entity_bind_prefix(
    query: clickhouse::query::Query,
    c: &Cutoffs,
    decay: &RiskDecayConfig,
    cleared: &ClearedBoundaries,
) -> clickhouse::query::Query {
    query
        .bind(c.c24)
        .bind(decay.decay_0_24h)
        .bind(c.c3d)
        .bind(decay.decay_1_3d)
        .bind(c.c5d)
        .bind(decay.decay_3_5d)
        .bind(c.c7d)
        .bind(decay.decay_5_7d)
        .bind(c.c7d)
        .bind(cleared.boundaries_micros())
        .bind(cleared.entities())
}

// ---------------------------------------------------------------------------
// Row types (match the repository's deserialization shapes)
// ---------------------------------------------------------------------------

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

#[derive(Debug, Clone, PartialEq, clickhouse::Row, serde::Deserialize)]
struct OverviewRow {
    total_entities: u64,
    critical_entities: u64,
    high_entities: u64,
    medium_entities: u64,
    low_entities: u64,
    total_signals: i64,
    avg_risk_score: f64,
}

#[derive(Debug, Clone, PartialEq, clickhouse::Row, serde::Deserialize)]
struct ContributionRow {
    rule_id: String,
    rule_name: String,
    severity: String,
    fires_24h: u64,
    fires_7d: u64,
    decayed_contribution_24h: i64,
    decayed_contribution_7d: i64,
    last_fire_at: i64,
    last_fire_score: i32,
}

fn sort_entities(mut rows: Vec<EntityScoreRow>) -> Vec<EntityScoreRow> {
    rows.sort_by(|a, b| (&a.entity, &a.entity_type).cmp(&(&b.entity, &b.entity_type)));
    rows
}

fn sort_contribs(mut rows: Vec<ContributionRow>) -> Vec<ContributionRow> {
    rows.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    rows
}

// ---------------------------------------------------------------------------
// Fixture seeding
// ---------------------------------------------------------------------------

struct Fixture {
    source: String,
    user_entity: String,
    host_entity: String,
    cleared_entity: String,
}

/// Seed findings across every decay bucket + the filter edge cases.
async fn seed_fixture(client: &Client, now: DateTime<Utc>) -> Fixture {
    let run = now.timestamp_nanos_opt().unwrap_or(0);
    let fx = Fixture {
        source: format!("p1eq-{run}"),
        user_entity: format!("p1eq_user_{run}"),          // no '.'/'@' → 'user'
        host_entity: format!("p1eq-{run}.example.com"),   // '.' → 'hostname'
        cleared_entity: format!("p1eq_cleared_{run}"),    // cleared at now-1d
    };

    // (entity, score, age, rule_id, rule_name, severity)
    let rows: Vec<(&str, f64, Duration, &str, &str, &str)> = vec![
        // user entity: one finding per decay bucket + one aged-out (>7d)
        (&fx.user_entity, 10.0, Duration::hours(2), "p1eq-rule-a", "P1EQ Rule A", "high"),
        (&fx.user_entity, 20.0, Duration::hours(36), "p1eq-rule-a", "P1EQ Rule A", "high"),
        (&fx.user_entity, 30.0, Duration::hours(96), "p1eq-rule-b", "P1EQ Rule B", "medium"),
        (&fx.user_entity, 40.0, Duration::hours(144), "p1eq-rule-b", "P1EQ Rule B", "medium"),
        (&fx.user_entity, 50.0, Duration::hours(192), "p1eq-rule-b", "P1EQ Rule B", "medium"),
        // hostname-typed entity, fresh
        (&fx.host_entity, 15.0, Duration::hours(2), "p1eq-rule-a", "P1EQ Rule A", "high"),
        // cleared entity: pre-clear finding must be excluded by the boundary,
        // post-clear finding counts
        (&fx.cleared_entity, 60.0, Duration::hours(96), "p1eq-rule-c", "P1EQ Rule C", "low"),
        (&fx.cleared_entity, 70.0, Duration::hours(2), "p1eq-rule-c", "P1EQ Rule C", "low"),
        // the literal 'unknown' entity is excluded by the entity filter
        ("unknown", 99.0, Duration::hours(2), "p1eq-rule-a", "P1EQ Rule A", "high"),
    ];

    for (entity, score, age, rule_id, rule_name, severity) in rows {
        client
            .query(
                "INSERT INTO logs \
                 (timestamp, message, metadata, source_type, source, risk_entity, risk_score, \
                  rule_id, rule_name, severity, action) \
                 VALUES (fromUnixTimestamp64Micro(?), ?, '{}', 'findings', ?, ?, ?, ?, ?, ?, 'detection_match')",
            )
            .bind((now - age).timestamp_micros())
            .bind(format!("p1eq equivalence fixture {run}"))
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

/// Best-effort cleanup (lightweight delete; leftovers are inert — unique
/// entity values and `source`).
async fn cleanup_fixture(client: &Client, fx: &Fixture) {
    let _ = client
        .query("DELETE FROM logs WHERE source = ? AND source_type = 'findings'")
        .bind(fx.source.as_str())
        .execute()
        .await;
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a local ClickHouse (:8123) with the nano schema — run with --ignored"]
async fn builder_results_match_pre_refactor_inline_queries() {
    let insert_client = ch_insert_client();
    let client = ch_client();

    let now = Utc::now();
    let fx = seed_fixture(&insert_client, now).await;

    let decay = RiskDecayConfig::default(); // 1.0 / 0.7 / 0.4 / 0.2
    let mut cleared_map: HashMap<String, DateTime<Utc>> = HashMap::new();
    cleared_map.insert(fx.cleared_entity.clone(), now - Duration::hours(24));
    let cleared = ClearedBoundaries::from_map(&cleared_map);
    let source = RiskFindingsSource::new(false, "logs");
    let c = cutoffs_at(now);

    // --- 1. entity list (get_time_windowed_risk_scores) -------------------
    // High limit so the whole findings population participates; sorted by
    // entity for set comparison (the ORDER BY clause itself is token-identical
    // in both statements, so ordering semantics are unchanged; sorting only
    // removes tie nondeterminism between executions).
    let old_rows: Vec<EntityScoreRow> =
        old_entity_bind_prefix(client.query(OLD_TIME_WINDOWED), &c, &decay, &cleared)
            .bind(c.c24)
            .bind(c.c24)
            .bind(c.c24)
            .bind(0i64)
            .bind(0i64)
            .bind(1_000_000i64)
            .fetch_all()
            .await
            .expect("old entity list");
    let new_rows: Vec<EntityScoreRow> = entity_scores_query(
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
    .expect("new entity list");

    assert!(
        new_rows.len() >= 3,
        "expected at least the fixture entities, got {}",
        new_rows.len()
    );
    let old_sorted = sort_entities(old_rows);
    let new_sorted = sort_entities(new_rows);
    assert_eq!(
        old_sorted, new_sorted,
        "entity list: old inline query and builder query must return identical rows"
    );

    // Ground truth for the seeded rows (decay 1.0/0.7/0.4/0.2):
    // user: 10*1.0 + 20*0.7 + 30*0.4 + 40*0.2 = 44 (7d), 10 (24h); >7d row excluded.
    let user = new_sorted
        .iter()
        .find(|r| r.entity == fx.user_entity)
        .expect("user fixture entity present");
    assert_eq!(user.entity_type, "user");
    assert_eq!(user.decayed_score_24h, 10);
    assert_eq!(user.decayed_score_7d, 44);
    assert_eq!(user.risk_score_24h, 10);
    assert_eq!(user.risk_score_7d, 100);
    assert_eq!(user.signal_count_24h, 1);
    assert_eq!(user.signal_count_7d, 4);
    assert_eq!(user.last_rule_name, "P1EQ Rule A");

    let host = new_sorted
        .iter()
        .find(|r| r.entity == fx.host_entity)
        .expect("host fixture entity present");
    assert_eq!(host.entity_type, "hostname");
    assert_eq!(host.decayed_score_7d, 15);

    // cleared: the pre-clear 4d/60-point finding is excluded; only the fresh
    // post-clear 70-point row counts.
    let cleared_row = new_sorted
        .iter()
        .find(|r| r.entity == fx.cleared_entity)
        .expect("cleared fixture entity present");
    assert_eq!(cleared_row.decayed_score_7d, 70);
    assert_eq!(cleared_row.signal_count_7d, 1);

    // 'unknown' never appears.
    assert!(new_sorted.iter().all(|r| r.entity != "unknown"));

    // Nonzero floors exercise the WHERE tail.
    let old_floored: Vec<EntityScoreRow> =
        old_entity_bind_prefix(client.query(OLD_TIME_WINDOWED), &c, &decay, &cleared)
            .bind(c.c24)
            .bind(c.c24)
            .bind(c.c24)
            .bind(12i64)
            .bind(40i64)
            .bind(1_000_000i64)
            .fetch_all()
            .await
            .expect("old entity list (floors)");
    let new_floored: Vec<EntityScoreRow> = entity_scores_query(
        &source,
        now,
        &decay,
        &cleared,
        EntityScoreSelection::MinScores {
            min_score_24h: 12,
            min_score_7d: 40,
            limit: 1_000_000,
        },
    )
    .to_clickhouse_query(&client)
    .fetch_all()
    .await
    .expect("new entity list (floors)");
    assert_eq!(sort_entities(old_floored), sort_entities(new_floored));

    // --- 2. decayed overview ----------------------------------------------
    for window in [RiskTimeWindow::Last24Hours, RiskTimeWindow::Last7Days] {
        let old_ov: OverviewRow = old_entity_bind_prefix(
            client.query(&old_overview_sql(window)),
            &c,
            &decay,
            &cleared,
        )
        .bind(c.c24)
        .bind(c.c24)
        .fetch_one()
        .await
        .expect("old overview");
        let new_ov: OverviewRow = decayed_overview_query(&source, now, &decay, &cleared, window)
            .to_clickhouse_query(&client)
            .fetch_one()
            .await
            .expect("new overview");

        assert_eq!(old_ov.total_entities, new_ov.total_entities, "{window:?}");
        assert_eq!(old_ov.critical_entities, new_ov.critical_entities, "{window:?}");
        assert_eq!(old_ov.high_entities, new_ov.high_entities, "{window:?}");
        assert_eq!(old_ov.medium_entities, new_ov.medium_entities, "{window:?}");
        assert_eq!(old_ov.low_entities, new_ov.low_entities, "{window:?}");
        assert_eq!(old_ov.total_signals, new_ov.total_signals, "{window:?}");
        // avg over identical row sets; tolerance only for float-summation
        // order across separate executions.
        assert!(
            (old_ov.avg_risk_score - new_ov.avg_risk_score).abs() < 1e-6,
            "{window:?}: avg_risk_score old={} new={}",
            old_ov.avg_risk_score,
            new_ov.avg_risk_score
        );
    }

    // --- 3. per-rule contributions -----------------------------------------
    let contrib_entities = vec![fx.user_entity.clone(), fx.cleared_entity.clone()];
    let old_contrib: Vec<ContributionRow> = client
        .query(OLD_CONTRIBUTIONS)
        .bind(c.c24)
        .bind(decay.decay_0_24h)
        .bind(c.c3d)
        .bind(decay.decay_1_3d)
        .bind(c.c5d)
        .bind(decay.decay_3_5d)
        .bind(c.c7d)
        .bind(decay.decay_5_7d)
        .bind(contrib_entities.as_slice())
        .bind(c.c7d)
        .bind(c.c24)
        .bind(c.c24)
        .fetch_all()
        .await
        .expect("old contributions");
    let new_contrib: Vec<ContributionRow> =
        rule_contributions_query(&source, now, &decay, &contrib_entities)
            .to_clickhouse_query(&client)
            .fetch_all()
            .await
            .expect("new contributions");
    let old_contrib = sort_contribs(old_contrib);
    let new_contrib = sort_contribs(new_contrib);
    assert_eq!(
        old_contrib, new_contrib,
        "contributions: old and new must return identical rows"
    );

    // Contribution ground truth (no cleared boundary on this view by design):
    // rule-a: 10*1.0 + 20*0.7 = 24 · rule-b: 30*0.4 + 40*0.2 = 20 (the >7d
    // row adds 0) · rule-c: 70*1.0 + 60*0.4 = 94.
    let by_rule = |id: &str| {
        new_contrib
            .iter()
            .find(|r| r.rule_id == id)
            .unwrap_or_else(|| panic!("rule {id} present"))
    };
    assert_eq!(by_rule("p1eq-rule-a").decayed_contribution_7d, 24);
    assert_eq!(by_rule("p1eq-rule-b").decayed_contribution_7d, 20);
    assert_eq!(by_rule("p1eq-rule-c").decayed_contribution_7d, 94);
    // rule-a + rule-b reproduce the user entity's decayed 7d headline (44).
    assert_eq!(
        by_rule("p1eq-rule-a").decayed_contribution_7d
            + by_rule("p1eq-rule-b").decayed_contribution_7d,
        user.decayed_score_7d
    );

    cleanup_fixture(&insert_client, &fx).await;
}
