// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5659 (v2.0.33 release review P2-9): one entity VALUE is one risk
//! entity, whatever types the rules stamped on its findings.
//!
//! Since NAN-5615 each finding is typed by its write-side stamp. Grouping the
//! entity grain on `(value, type)` split one value across rows when two rules
//! stamped it differently (rule A on `device.hostname` stamps `hostname`; rule
//! B on a field with no recognised token falls back to value inference and
//! stamps `user`), so each half could sit under the notable threshold. The
//! readers now group on the value and resolve one type per value by
//! precedence (`ENTITY_TYPE_RESOLVE_SQL`).
//!
//! Self-contained: creates its own scratch database with minimal UDM `logs`
//! and OCSF `ocsf_logs` tables (only the columns the risk readers touch), so
//! it runs against any throwaway ClickHouse, never a real nano stack:
//!
//!   docker run -d --name risk-ch -p 127.0.0.1:18923:8123 \
//!     -e CLICKHOUSE_USER=nanosiem -e CLICKHOUSE_PASSWORD=nanosiem \
//!     clickhouse/clickhouse-server:26.10.4.207   # any 25.x+ (stable JSON type)
//!   RISK_ONE_KEY_CH_URL=http://127.0.0.1:18923 \
//!     cargo test -p nanosiem-core --test risk_entity_one_key_live -- --ignored --nocapture
//!
//! Env: RISK_ONE_KEY_CH_URL (required: no default, so it can never hit a
//! developer stack by accident), user/password nanosiem/nanosiem.

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Duration, Utc};
use clickhouse::Client;
use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, Dataset, TimeRange};
use nanosiem_core::risk::clickhouse_sql::{
    entity_scores_query, entity_types_query, risky_entities_query, ClearedBoundaries,
    EntityScoreSelection, RiskFindingsSource, RiskQueryConfig,
};
use nanosiem_core::risk::{RiskDecayConfig, RiskNotableConfig, RiskTimeWindow};

tokio::task_local! {
    /// Each test seeds its own scratch database so they can run in parallel.
    static DB: &'static str;
}

fn db() -> &'static str {
    DB.with(|d| *d)
}

fn ch_url() -> String {
    std::env::var("RISK_ONE_KEY_CH_URL")
        .expect("set RISK_ONE_KEY_CH_URL to a THROWAWAY ClickHouse (see module docs)")
}

fn root_client() -> Client {
    Client::default()
        .with_url(ch_url())
        .with_user("nanosiem")
        .with_password("nanosiem")
        .with_setting("async_insert", "0")
        .with_setting("wait_end_of_query", "1")
}

fn db_client() -> Client {
    root_client().with_database(db())
}

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
    base_decayed_score_24h: i64,
    base_decayed_score_7d: i64,
    watch_weight: f64,
}

#[derive(Debug, Clone, PartialEq, clickhouse::Row, serde::Deserialize)]
struct FacetRow {
    entity_type: String,
    entity_count: u64,
}

#[derive(Debug, Clone, PartialEq, clickhouse::Row, serde::Deserialize)]
struct NotableRow {
    entity: String,
    entity_type: String,
    score_24h: i64,
}

/// One seeded finding: (entity, stamp or None for a pre-NAN-1806 row, score,
/// hours ago, rule).
type Finding = (&'static str, Option<&'static str>, i32, i64, &'static str);

/// The two-rule example plus the typing edge cases #9968 fixed.
const FINDINGS: &[Finding] = &[
    // host-a-17: rule A (device.hostname) stamps hostname; rule B
    // (device.name, no recognised token) stamps user by value inference; one
    // unstamped legacy row. 30 + 30 + 20 = 80, typed hostname.
    ("host-a-17", Some("hostname"), 30, 2, "rule_a_device_hostname"),
    ("host-a-17", Some("user"), 30, 3, "rule_b_device_name"),
    ("host-a-17", None, 20, 1, "legacy_unstamped"),
    // A cloud account id stamped by an account rule and inferred `user`
    // elsewhere: cloud_account (the cloud-overview fan-out filters on it).
    ("123456789012", Some("cloud_account"), 10, 2, "rule_cloud"),
    ("123456789012", Some("user"), 10, 4, "rule_b_device_name"),
    // An email is email whatever the stamp.
    ("alice@corp.example", Some("user"), 15, 2, "rule_user"),
    // `domain` is never honored: a dotted value types hostname.
    ("web01.corp.local", Some("domain"), 12, 2, "rule_dns"),
    // An IPv4 stamped hostname by one rule and unstamped in another: ip.
    ("10.1.2.3", Some("hostname"), 5, 2, "rule_a_device_hostname"),
    ("10.1.2.3", None, 5, 3, "legacy_unstamped"),
    // A plain user stays user.
    ("jsmith", Some("user"), 8, 2, "rule_user"),
];

async fn exec(client: &Client, sql: &str) {
    client
        .query(sql)
        .execute()
        .await
        .unwrap_or_else(|e| panic!("{e}\n{sql}"));
}

async fn seed(now: DateTime<Utc>) {
    let root = root_client();
    exec(&root, &format!("DROP DATABASE IF EXISTS {}", db())).await;
    exec(&root, &format!("CREATE DATABASE {}", db())).await;
    let db = db_client();
    exec(
        &db,
        "CREATE TABLE logs (
            timestamp DateTime64(6, 'UTC'),
            source_type LowCardinality(String),
            risk_entity String DEFAULT '',
            risk_score Float32 DEFAULT 0,
            rule_id String DEFAULT '',
            rule_name String DEFAULT '',
            severity LowCardinality(String) DEFAULT 'medium',
            metadata String DEFAULT '{}'
        ) ENGINE = MergeTree ORDER BY timestamp",
    )
    .await;
    exec(
        &db,
        "CREATE TABLE ocsf_logs (
            timestamp DateTime64(6, 'UTC'),
            source_type LowCardinality(String),
            severity LowCardinality(String) DEFAULT 'Medium',
            unmapped JSON
        ) ENGINE = MergeTree ORDER BY timestamp",
    )
    .await;

    for (entity, stamp, score, hours_ago, rule) in FINDINGS {
        let ts = (now - Duration::hours(*hours_ago)).format("%Y-%m-%d %H:%M:%S%.6f");
        let metadata = match stamp {
            Some(t) => format!(r#"{{"risk_entity_type":"{t}"}}"#),
            None => "{}".to_string(),
        };
        exec(
            &db,
            &format!(
                "INSERT INTO logs (timestamp, source_type, risk_entity, risk_score, rule_id, rule_name, metadata) \
                 VALUES ('{ts}', 'findings', '{entity}', {score}, '{rule}', '{rule}', '{metadata}')"
            ),
        )
        .await;
        let stamp_json = match stamp {
            Some(t) => format!(r#","risk_entity_type":"{t}""#),
            None => String::new(),
        };
        exec(
            &db,
            &format!(
                "INSERT INTO ocsf_logs (timestamp, source_type, unmapped) VALUES ('{ts}', 'findings', \
                 '{{\"risk_entity\":\"{entity}\",\"risk_score\":{score},\"rule_id\":\"{rule}\",\"rule_name\":\"{rule}\"{stamp_json}}}')"
            ),
        )
        .await;
    }
}

fn no_clears() -> ClearedBoundaries {
    ClearedBoundaries::from_map(&HashMap::new())
}

fn all_rows() -> EntityScoreSelection {
    EntityScoreSelection::MinScores {
        min_score_24h: 0,
        min_score_7d: 0,
        limit: 1_000,
    }
}

/// The current builder's entity list, as SQL text (the variants below are
/// derived from it so they share every other token).
fn current_entity_sql(source: &RiskFindingsSource, now: DateTime<Utc>) -> (String, nanosiem_core::risk::clickhouse_sql::RiskChQuery) {
    let q = entity_scores_query(source, now, &RiskDecayConfig::default(), &no_clears(), all_rows());
    (q.to_inline_sql(), q)
}

/// The resolve line the builder emits inside the `aggregated` CTEs.
fn resolve_line() -> String {
    format!(
        "                    -- One type per entity value, by precedence (NAN-5659)\n                    {} as entity_type,\n",
        nanosiem_core::risk::clickhouse_sql::ENTITY_TYPE_RESOLVE_SQL
    )
}

/// The v2.0.32 (pre-NAN-5615) readers: value-inferred type, honoring only the
/// `cloud_account` stamp, grouped on `(value, type)`; the type was a function
/// of the value, so in practice one row per value.
fn v2032_entity_sql(sql: &str, stamped_col: &str, entity_col: &str) -> String {
    let current_row_type = format!(
        "multiIf(position({entity_col}, '@') > 0, 'email', {stamped_col} IN ('ip', 'hostname', 'user', 'hash', 'cloud_account'), {stamped_col}, match({entity_col}, '^[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}$'), 'ip', position({entity_col}, '.') > 0, 'hostname', 'user') as row_entity_type"
    );
    assert!(sql.contains(&current_row_type), "row type expression moved:\n{sql}");
    let old_row_type = format!(
        "multiIf({stamped_col} = 'cloud_account', 'cloud_account', match({entity_col}, '^[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}$'), 'ip', position({entity_col}, '@') > 0, 'email', position({entity_col}, '.') > 0, 'hostname', 'user') as entity_type"
    );
    pre_5659_grouping(&sql.replace(&current_row_type, &old_row_type))
}

/// The #9968 (NAN-5615, unfixed) readers: stamp-typed per finding AND grouped
/// on `(value, type)`: the split this fix removes.
fn split_entity_sql(sql: &str) -> String {
    pre_5659_grouping(&sql.replace("as row_entity_type", "as entity_type"))
}

fn pre_5659_grouping(sql: &str) -> String {
    let resolve = resolve_line();
    assert!(sql.contains(&resolve), "resolve line moved:\n{sql}");
    let sql = sql.replace(&resolve, "                    entity_type,\n");
    let group = "                FROM signal_scores\n                GROUP BY entity\n            )";
    assert!(sql.contains(group));
    sql.replace(group, "                FROM signal_scores\n                GROUP BY entity, entity_type\n            )")
}

async fn fetch_entities(sql: &str) -> Vec<EntityScoreRow> {
    let mut rows: Vec<EntityScoreRow> = db_client()
        .query(sql)
        .fetch_all()
        .await
        .unwrap_or_else(|e| panic!("{e}\n{sql}"));
    rows.sort_by(|a, b| (&a.entity, &a.entity_type).cmp(&(&b.entity, &b.entity_type)));
    rows
}

fn by_entity(rows: &[EntityScoreRow]) -> BTreeMap<String, Vec<&EntityScoreRow>> {
    let mut map: BTreeMap<String, Vec<&EntityScoreRow>> = BTreeMap::new();
    for r in rows {
        map.entry(r.entity.clone()).or_default().push(r);
    }
    map
}

fn expected_types() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("host-a-17", "hostname"),
        ("123456789012", "cloud_account"),
        ("alice@corp.example", "email"),
        ("web01.corp.local", "hostname"),
        ("10.1.2.3", "ip"),
        ("jsmith", "user"),
    ])
}

/// Two rules stamp `host-a-17` as `hostname` and `user`: ONE entity, the
/// combined score, typed `hostname`; the #9968 fixes hold (email, no domain,
/// dotless hosts not `user`). Every builder reader agrees, on both profiles.
#[tokio::test]
#[ignore = "requires a throwaway ClickHouse (RISK_ONE_KEY_CH_URL) — run with --ignored"]
async fn one_value_stamped_two_ways_is_one_entity_with_the_combined_score() {
    DB.scope("risk_one_key_split_nan5659", split_case()).await
}

async fn split_case() {
    let now = Utc::now();
    seed(now).await;

    for (ocsf, table) in [(false, "logs"), (true, "ocsf_logs")] {
        let source = RiskFindingsSource::new(ocsf, table);
        let (sql, q) = current_entity_sql(&source, now);
        // The bound form (production path) and the inline form agree.
        let bound: Vec<EntityScoreRow> = q
            .to_clickhouse_query(&db_client())
            .fetch_all()
            .await
            .expect("bound entity scores");
        let rows = fetch_entities(&sql).await;
        let mut bound_sorted = bound.clone();
        bound_sorted.sort_by(|a, b| (&a.entity, &a.entity_type).cmp(&(&b.entity, &b.entity_type)));
        assert_eq!(bound_sorted, rows, "ocsf={ocsf}");

        let grouped = by_entity(&rows);
        assert_eq!(grouped.len(), expected_types().len(), "ocsf={ocsf}: {rows:#?}");
        for (entity, ty) in expected_types() {
            let rs = &grouped[entity];
            assert_eq!(rs.len(), 1, "ocsf={ocsf}: {entity} split: {rs:#?}");
            assert_eq!(rs[0].entity_type, ty, "ocsf={ocsf}: {entity}");
        }
        let host = grouped["host-a-17"][0];
        assert_eq!(host.decayed_score_24h, 80, "ocsf={ocsf}: combined score");
        assert_eq!(host.signal_count_24h, 3, "ocsf={ocsf}");
        assert_eq!(host.last_rule_name, "legacy_unstamped", "ocsf={ocsf}");

        // Leaderboard type filter sees the resolved type: host-a-17 under
        // hostname (combined), nothing for it under user.
        for (filter, expect_host) in [("hostname", Some(80)), ("user", None)] {
            let lb: Vec<EntityScoreRow> = risky_entities_query(
                &source,
                now,
                &RiskDecayConfig::default(),
                &no_clears(),
                RiskTimeWindow::Last24Hours,
                Some(filter),
                0,
                None,
                100,
                0,
            )
            .to_clickhouse_query(&db_client())
            .fetch_all()
            .await
            .expect("leaderboard");
            let host = lb.iter().find(|r| r.entity == "host-a-17").map(|r| r.decayed_score_24h);
            assert_eq!(host, expect_host, "ocsf={ocsf} filter={filter}: {lb:#?}");
        }

        // Facet: one count per value.
        let facets: Vec<FacetRow> = entity_types_query(&source, now, &RiskDecayConfig::default(), &no_clears())
            .to_clickhouse_query(&db_client())
            .fetch_all()
            .await
            .expect("facet");
        let total: u64 = facets.iter().map(|f| f.entity_count).sum();
        assert_eq!(total, expected_types().len() as u64, "ocsf={ocsf}: {facets:#?}");
        let hostnames = facets.iter().find(|f| f.entity_type == "hostname").unwrap();
        assert_eq!(hostnames.entity_count, 2, "host-a-17 + web01.corp.local");
        assert_eq!(facets.iter().find(|f| f.entity_type == "user").unwrap().entity_count, 1);

        // The bug this fixes, demonstrated on the same data: the (value, type)
        // grain splits host-a-17 into hostname 30 + user 50.
        let split = by_entity(&fetch_entities(&split_entity_sql(&sql)).await)["host-a-17"]
            .iter()
            .map(|r| (r.entity_type.clone(), r.decayed_score_24h))
            .collect::<Vec<_>>();
        assert_eq!(split, vec![("hostname".to_string(), 30), ("user".to_string(), 50)], "ocsf={ocsf}");
    }
    exec(&root_client(), &format!("DROP DATABASE IF EXISTS {}", db())).await;
}

/// Upgrade from v2.0.32: the same findings history read by the v2.0.32
/// (value-typed) readers and by this code yields the SAME entity keys with the
/// SAME scores and counts. Only the type label may change (a dotless host was
/// `user`, now `hostname`), and no reader keys identity on the label: the
/// notable rule's dedup and cooldown key on `risk_entity_field = entity` (the
/// value), clears and score weights on the value.
#[tokio::test]
#[ignore = "requires a throwaway ClickHouse (RISK_ONE_KEY_CH_URL) — run with --ignored"]
async fn upgrade_keeps_entity_keys_and_scores_from_v2032() {
    DB.scope("risk_one_key_upgrade_nan5659", upgrade_case()).await
}

async fn upgrade_case() {
    let now = Utc::now();
    seed(now).await;

    for (ocsf, table, stamped_col, entity_col) in [
        (false, "logs", "JSONExtractString(metadata, 'risk_entity_type')", "risk_entity"),
        (
            true,
            "ocsf_logs",
            "JSONExtractString(ifNull(toJSONString(unmapped.risk_entity_type), 'null'))",
            "JSONExtractString(ifNull(toJSONString(unmapped.risk_entity), 'null'))",
        ),
    ] {
        let source = RiskFindingsSource::new(ocsf, table);
        let (sql, _) = current_entity_sql(&source, now);
        let old = fetch_entities(&v2032_entity_sql(&sql, stamped_col, entity_col)).await;
        let new = fetch_entities(&sql).await;

        let strip = |rows: &[EntityScoreRow]| {
            rows.iter()
                .map(|r| {
                    (
                        r.entity.clone(),
                        r.decayed_score_24h,
                        r.decayed_score_7d,
                        r.risk_score_7d,
                        r.signal_count_7d,
                        r.last_signal_at,
                        r.last_rule_name.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        // v2.0.32 typed by the value (plus the cloud_account stamp), so it
        // had one row per value for every value except an account id stamped
        // `cloud_account` by one rule only: that one it split itself, and the
        // fix merges it (combined score, never a new key). Every other key
        // and score is identical.
        let acct = "123456789012";
        let old_acct: Vec<_> = old.iter().filter(|r| r.entity == acct).collect();
        assert_eq!(old_acct.len(), 2, "v2.0.32 split the account: {old_acct:#?}");
        let new_acct = new.iter().find(|r| r.entity == acct).unwrap();
        assert_eq!(new_acct.entity_type, "cloud_account");
        assert_eq!(
            new_acct.decayed_score_7d,
            old_acct.iter().map(|r| r.decayed_score_7d).sum::<i64>()
        );
        let old_rest: Vec<_> = old.iter().filter(|r| r.entity != acct).cloned().collect();
        let new_rest: Vec<_> = new.iter().filter(|r| r.entity != acct).cloned().collect();
        assert_eq!(old_rest.len(), new_rest.len(), "ocsf={ocsf}\nold {old:#?}\nnew {new:#?}");
        assert_eq!(strip(&old_rest), strip(&new_rest), "ocsf={ocsf}");
        let old_types: BTreeMap<_, _> = old.iter().map(|r| (r.entity.as_str(), r.entity_type.as_str())).collect();
        assert_eq!(old_types["host-a-17"], "user", "v2.0.32 mislabeled the dotless host");
        assert_eq!(new.iter().find(|r| r.entity == "host-a-17").unwrap().entity_type, "hostname");
    }

    // The seeded notable rule over dataset=risk now: exactly one row (one
    // notable candidate) for host-a-17 with the combined score. (v2.0.32 also
    // gave one row for it, typed `user`, with the same 80, proven above; the
    // notable identity is the value, so it is the same notable.)
    let notable = RiskNotableConfig {
        threshold_24h: 60,
        threshold_7d: 100_000,
        ..RiskNotableConfig::default()
    };
    let config = RiskQueryConfig {
        decay: RiskDecayConfig::default(),
        cleared: no_clears(),
        now,
    };
    let generator = ClickHouseSqlGenerator::new()
        .with_risk_config(config)
        .with_dataset(Dataset::Risk);
    let query = parse_query(&notable.default_rule_query()).expect("parse notable rule");
    let sql = generator
        .generate(
            &query,
            &TimeRange {
                start: now - Duration::days(7),
                end: now,
            },
        )
        .expect("generate notable rule");
    let rows: Vec<NotableRow> = db_client()
        .query(&format!(
            "SELECT entity, entity_type, score_24h FROM ({sql}) ORDER BY entity"
        ))
        .fetch_all()
        .await
        .unwrap_or_else(|e| panic!("{e}\n{sql}"));
    assert_eq!(
        rows,
        vec![NotableRow {
            entity: "host-a-17".into(),
            entity_type: "hostname".into(),
            score_24h: 80,
        }],
        "one notable candidate, combined score crossing 60 (the split halves 30/50 would not)"
    );

    exec(&root_client(), &format!("DROP DATABASE IF EXISTS {}", db())).await;
}
