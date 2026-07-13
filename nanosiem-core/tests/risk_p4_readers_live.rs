// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live probe for the P4 reader queries (NAN-1806 / NAN-1798 P4): the
//! leaderboard, dossier-badge, entity-type facet, and lateral-graph batch
//! variants of the shared risk builder, executed against a real ClickHouse.
//!
//! The numbers-must-not-change bar: every variant composes the SAME
//! `signal_scores` scan as the canonical `entity_scores_query` (proven
//! result-identical to the pre-P1 inline repository SQL — the source the
//! 15-min PG sweep persisted — by `risk_ch_sql_equivalence`). This probe
//! closes the chain by asserting each P4 variant returns exactly the
//! canonical rows for the same data/decay/cleared/`now`:
//!
//!   old PG readers = sweep(CH canonical) = CH canonical = P4 variants
//!
//! modulo the documented intentional deltas: leaderboard `risk_score`
//! cumulative→decayed, dossier/facet freshness (live vs 15-min snapshot),
//! and the cloud_account fix — a previously-EMPTY fan-out that now resolves,
//! asserted explicitly (stamped finding types `cloud_account`; an identical
//! unstamped value still types `user`, so pre-P4 rows are unaffected).
//!
//! Requires a local ClickHouse with the nano schema:
//!   cargo test -p nanosiem-core --test risk_p4_readers_live -- --ignored --nocapture
//! Env: CLICKHOUSE_TEST_URL (default http://localhost:8123), user/password
//! nanosiem/nanosiem, database nanosiem (UDM profile).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use clickhouse::Client;
use nanosiem_core::risk::clickhouse_sql::{
    entity_scores_query, entity_types_query, lateral_scores_query, risk_for_entities_query,
    risky_entities_query, ClearedBoundaries, EntityScoreSelection, RiskFindingsSource,
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

/// The canonical entity-grain projection (shared by the entity list, the
/// leaderboard, and the dossier query).
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
struct FacetRow {
    entity_type: String,
    entity_count: u64,
}

#[derive(Debug, Clone, PartialEq, clickhouse::Row, serde::Deserialize)]
struct LateralRow {
    entity: String,
    decayed_score_7d: i64,
}

fn sort_entities(mut rows: Vec<EntityScoreRow>) -> Vec<EntityScoreRow> {
    rows.sort_by(|a, b| (&a.entity, &a.entity_type).cmp(&(&b.entity, &b.entity_type)));
    rows
}

struct Fixture {
    source: String,
    user_entity: String,
    /// Stored VERBATIM with uppercase + FQDN — exercises the lateral batch's
    /// lower()/first-label matching.
    host_entity: String,
    /// Its `normalize_id` form (lowercased first label) — the graph node id.
    host_node_id: String,
    /// Findings stamped `risk_entity_type = cloud_account` (the P4 fix).
    cloud_entity: String,
    /// Two verbatim spellings of the SAME logical host that both normalize to
    /// `collide_node_id` — exercises the lateral batch's per-node MAX fold.
    collide_upper: String,
    collide_fqdn: String,
    collide_node_id: String,
    /// Same shape of opaque value, UNSTAMPED — must keep typing as `user`
    /// (pre-P4 rows are unaffected by the new branch).
    unstamped_entity: String,
    cleared_entity: String,
}

async fn seed_fixture(client: &Client, now: DateTime<Utc>) -> Fixture {
    let run = now.timestamp_nanos_opt().unwrap_or(0);
    let fx = Fixture {
        source: format!("p4eq-{run}"),
        user_entity: format!("p4eq_user_{run}"),
        host_entity: format!("P4EQ-{run}.CORP.EXAMPLE"),
        host_node_id: format!("p4eq-{run}"),
        cloud_entity: format!("99988877{run}"),
        unstamped_entity: format!("11122233{run}"),
        collide_upper: format!("COLLIDE-{run}"),
        collide_fqdn: format!("collide-{run}.corp.example"),
        collide_node_id: format!("collide-{run}"),
        cleared_entity: format!("p4eq_cleared_{run}"),
    };

    // (entity, score, age, rule, severity, metadata)
    let rows: Vec<(&str, f64, Duration, &str, &str, &str)> = vec![
        // user entity across every decay bucket + one aged-out (>7d):
        // decayed 7d = 10*1.0 + 20*0.7 + 30*0.4 + 40*0.2 = 44; 24h = 10.
        (&fx.user_entity, 10.0, Duration::hours(2), "P4 Rule A", "high", "{}"),
        (&fx.user_entity, 20.0, Duration::hours(36), "P4 Rule A", "high", "{}"),
        (&fx.user_entity, 30.0, Duration::hours(96), "P4 Rule B", "medium", "{}"),
        (&fx.user_entity, 40.0, Duration::hours(144), "P4 Rule B", "medium", "{}"),
        (&fx.user_entity, 50.0, Duration::hours(192), "P4 Rule B", "medium", "{}"),
        // host entity (verbatim uppercase FQDN): 7d = 15*1.0 + 25*0.4 = 25.
        (&fx.host_entity, 15.0, Duration::hours(2), "P4 Rule A", "high", "{}"),
        (&fx.host_entity, 25.0, Duration::hours(96), "P4 Rule B", "medium", "{}"),
        // cloud account, stamped write-side (NAN-1806): 7d = 30*0.7 = 21.
        (
            &fx.cloud_entity,
            30.0,
            Duration::hours(36),
            "P4 Cloud Rule",
            "high",
            r#"{"risk_entity_type":"cloud_account"}"#,
        ),
        // identical value shape, UNSTAMPED → still types as 'user'.
        (&fx.unstamped_entity, 12.0, Duration::hours(2), "P4 Rule A", "low", "{}"),
        // cleared at now-24h: the 4d/60-point finding is pre-clear (excluded),
        // the fresh 70-point one counts.
        (&fx.cleared_entity, 60.0, Duration::hours(96), "P4 Rule C", "low", "{}"),
        (&fx.cleared_entity, 70.0, Duration::hours(2), "P4 Rule C", "low", "{}"),
        // Two spellings of one host that collide on normalize_id: the lateral
        // batch must fold to the MAX (35), not an arbitrary colliding row.
        (&fx.collide_upper, 20.0, Duration::hours(2), "P4 Rule A", "high", "{}"),
        (&fx.collide_fqdn, 35.0, Duration::hours(2), "P4 Rule A", "high", "{}"),
    ];

    for (entity, score, age, rule_name, severity, metadata) in rows {
        client
            .query(
                "INSERT INTO logs \
                 (timestamp, message, metadata, source_type, source, risk_entity, risk_score, \
                  rule_id, rule_name, severity, action) \
                 VALUES (fromUnixTimestamp64Micro(?), ?, ?, 'findings', ?, ?, ?, ?, ?, ?, 'detection_match')",
            )
            .bind((now - age).timestamp_micros())
            .bind(format!("p4 readers fixture {run}"))
            .bind(metadata)
            .bind(fx.source.as_str())
            .bind(entity)
            .bind(score)
            .bind(format!("p4eq-rule-{run}"))
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

#[tokio::test]
#[ignore = "requires a local ClickHouse (:8123) with the nano schema — run with --ignored"]
async fn p4_reader_queries_match_the_canonical_computation() {
    let insert_client = ch_insert_client();
    let client = ch_client();

    let now = Utc::now();
    let fx = seed_fixture(&insert_client, now).await;

    let decay = RiskDecayConfig::default();
    let mut cleared_map: HashMap<String, DateTime<Utc>> = HashMap::new();
    cleared_map.insert(fx.cleared_entity.clone(), now - Duration::hours(24));
    let cleared = ClearedBoundaries::from_map(&cleared_map);
    let source = RiskFindingsSource::new(false, "logs");

    // --- Canonical baseline: the entity list every prior phase proved -------
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
    .expect("canonical entity list");
    assert!(canonical.len() >= 5, "fixture entities present");

    // --- 1. Leaderboard: same rows/numbers as the canonical list ------------
    let leaderboard: Vec<EntityScoreRow> = risky_entities_query(
        &source,
        now,
        &decay,
        &cleared,
        RiskTimeWindow::Last7Days,
        None,
        0,
        1_000_000,
        0,
    )
    .to_clickhouse_query(&client)
    .fetch_all()
    .await
    .expect("leaderboard");
    assert_eq!(
        sort_entities(canonical.clone()),
        sort_entities(leaderboard.clone()),
        "leaderboard must return the exact canonical entity rows"
    );
    // Ordering: hottest-first on the 7d decayed score, ties by finding count.
    for pair in leaderboard.windows(2) {
        assert!(
            (pair[0].decayed_score_7d, pair[0].signal_count_7d)
                >= (pair[1].decayed_score_7d, pair[1].signal_count_7d),
            "leaderboard ordering violated: {pair:?}"
        );
    }

    // Ground truth for the fixture user entity.
    let user = leaderboard
        .iter()
        .find(|r| r.entity == fx.user_entity)
        .expect("user entity on the leaderboard");
    assert_eq!(user.entity_type, "user");
    assert_eq!(user.decayed_score_7d, 44);
    assert_eq!(user.decayed_score_24h, 10);
    assert_eq!(user.signal_count_7d, 4); // the >7d finding is out of window

    // Cleared boundary honored (only the post-clear finding counts).
    let cleared_row = leaderboard
        .iter()
        .find(|r| r.entity == fx.cleared_entity)
        .expect("cleared entity present");
    assert_eq!(cleared_row.decayed_score_7d, 70);

    // 24h window: only entities ACTIVE inside 24h appear (the old PG reader's
    // `updated_at >= cutoff` semantics). The cloud entity's single finding is
    // 36h old → present on the 7d board, absent from the 24h board.
    let lb24: Vec<EntityScoreRow> = risky_entities_query(
        &source,
        now,
        &decay,
        &cleared,
        RiskTimeWindow::Last24Hours,
        None,
        0,
        1_000_000,
        0,
    )
    .to_clickhouse_query(&client)
    .fetch_all()
    .await
    .expect("24h leaderboard");
    assert!(
        lb24.iter().all(|r| r.entity != fx.cloud_entity),
        "no 24h findings → not on the 24h leaderboard"
    );
    assert!(lb24.iter().any(|r| r.entity == fx.user_entity));
    assert!(lb24.iter().all(|r| r.signal_count_24h > 0));

    // Pagination: LIMIT/OFFSET slices the same ordering.
    let page1: Vec<EntityScoreRow> = risky_entities_query(
        &source, now, &decay, &cleared, RiskTimeWindow::Last7Days, None, 0, 1, 0,
    )
    .to_clickhouse_query(&client)
    .fetch_all()
    .await
    .expect("page 1");
    let page2: Vec<EntityScoreRow> = risky_entities_query(
        &source, now, &decay, &cleared, RiskTimeWindow::Last7Days, None, 0, 1, 1,
    )
    .to_clickhouse_query(&client)
    .fetch_all()
    .await
    .expect("page 2");
    assert_eq!(page1.len(), 1);
    assert_eq!(page2.len(), 1);
    assert_eq!(page1[0], leaderboard[0]);
    assert_eq!(page2[0], leaderboard[1]);

    // --- 2. cloud_account fix: previously-empty fan-out now resolves --------
    let cloud_rows: Vec<EntityScoreRow> = risky_entities_query(
        &source,
        now,
        &decay,
        &cleared,
        RiskTimeWindow::Last7Days,
        Some("cloud_account"),
        0,
        200,
        0,
    )
    .to_clickhouse_query(&client)
    .fetch_all()
    .await
    .expect("cloud_account fan-out");
    let cloud = cloud_rows
        .iter()
        .find(|r| r.entity == fx.cloud_entity)
        .expect("stamped cloud-account entity must resolve under the type filter (the pre-P4 gap)");
    assert_eq!(cloud.entity_type, "cloud_account");
    assert_eq!(cloud.decayed_score_7d, 21); // 30 * 0.7
    // The unstamped opaque value keeps its pre-P4 value inference ('user') —
    // proving old rows are untouched and only the stamp lights the branch up.
    assert!(
        cloud_rows.iter().all(|r| r.entity != fx.unstamped_entity),
        "unstamped opaque entity must NOT type as cloud_account"
    );
    let unstamped = canonical
        .iter()
        .find(|r| r.entity == fx.unstamped_entity)
        .expect("unstamped entity present");
    assert_eq!(unstamped.entity_type, "user");

    // --- 3. Dossier badge: max across the identity set, = canonical 7d ------
    let badge: Option<EntityScoreRow> = risk_for_entities_query(
        &source,
        now,
        &decay,
        &cleared,
        &[fx.user_entity.clone(), fx.host_entity.clone()],
    )
    .to_clickhouse_query(&client)
    .fetch_optional()
    .await
    .expect("dossier badge");
    let badge = badge.expect("badge resolves");
    assert_eq!(badge.entity, fx.user_entity, "44 > 25 → the user identity wins");
    assert_eq!(
        badge.decayed_score_7d,
        canonical
            .iter()
            .find(|r| r.entity == fx.user_entity)
            .unwrap()
            .decayed_score_7d,
        "badge value must equal the canonical entity list's decayed 7d score"
    );

    // Unknown identities → no row (the old reader returned None likewise).
    let none: Option<EntityScoreRow> = risk_for_entities_query(
        &source,
        now,
        &decay,
        &cleared,
        &[format!("absent-{}", fx.source)],
    )
    .to_clickhouse_query(&client)
    .fetch_optional()
    .await
    .expect("absent badge query");
    assert!(none.is_none());

    // --- 4. Entity-type facet: exactly the canonical list, grouped ----------
    let facet: Vec<FacetRow> = entity_types_query(&source, now, &decay, &cleared)
        .to_clickhouse_query(&client)
        .fetch_all()
        .await
        .expect("facet");
    let mut expected: HashMap<String, u64> = HashMap::new();
    for row in &canonical {
        *expected.entry(row.entity_type.clone()).or_default() += 1;
    }
    let got: HashMap<String, u64> = facet
        .iter()
        .map(|r| (r.entity_type.clone(), r.entity_count))
        .collect();
    assert_eq!(
        got, expected,
        "facet must count exactly the entity set the canonical list returns"
    );
    assert!(got.get("cloud_account").copied().unwrap_or(0) >= 1);

    // --- 5. Lateral batch: FQDN/lowered matching + canonical scores ---------
    let lateral: Vec<LateralRow> = lateral_scores_query(
        &source,
        now,
        &decay,
        &cleared,
        // normalize_id forms: lowered first label for the host, lowered user,
        // and the colliding-host node id (two raw spellings share it).
        &[
            fx.host_node_id.clone(),
            fx.user_entity.clone(),
            fx.collide_node_id.clone(),
        ],
    )
    .to_clickhouse_query(&client)
    .fetch_all()
    .await
    .expect("lateral batch");
    let by_entity: HashMap<&str, i64> = lateral
        .iter()
        .map(|r| (r.entity.as_str(), r.decayed_score_7d))
        .collect();
    // The verbatim uppercase FQDN row is matched via lower(first label).
    assert_eq!(
        by_entity.get(fx.host_entity.as_str()).copied(),
        Some(25),
        "uppercase FQDN entity must match its normalized node id: {lateral:?}"
    );
    assert_eq!(by_entity.get(fx.user_entity.as_str()).copied(), Some(44));
    // Scores equal the canonical decayed 7d values.
    for row in &lateral {
        if let Some(c) = canonical.iter().find(|r| r.entity == row.entity) {
            assert_eq!(row.decayed_score_7d, c.decayed_score_7d, "{}", row.entity);
        }
    }

    // Per-node MAX fold (the `fetch_risk_for_nodes` helper's job, replicated
    // here since it is private): the query returns one row per RAW entity, so
    // both colliding spellings come back; the caller folds them to the node's
    // MAX (35), never an arbitrary colliding row (codex P1-3 fix).
    assert_eq!(by_entity.get(fx.collide_upper.as_str()).copied(), Some(20));
    assert_eq!(by_entity.get(fx.collide_fqdn.as_str()).copied(), Some(35));
    let mut folded: HashMap<String, i64> = HashMap::new();
    for row in &lateral {
        // normalize_id is private; both fixture spellings collide on the same
        // lowered first label, which is exactly `collide_node_id`.
        let node = if row.entity == fx.collide_upper || row.entity == fx.collide_fqdn {
            fx.collide_node_id.clone()
        } else {
            row.entity.clone()
        };
        folded
            .entry(node)
            .and_modify(|s| *s = (*s).max(row.decayed_score_7d))
            .or_insert(row.decayed_score_7d);
    }
    assert_eq!(
        folded.get(&fx.collide_node_id).copied(),
        Some(35),
        "colliding node must fold to the MAX of its raw entities"
    );

    cleanup_fixture(&insert_client, &fx).await;
}
