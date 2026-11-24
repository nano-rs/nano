// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5751 on a disposable ClickHouse: an aggregation rule's run is bounded
//! on its output (`DETECTION_MAX_MATCHES_PER_RUN`) without ever dropping a
//! match silently.
//!
//! Every case runs the REAL scheduled-run path (`evaluate_rule_run`: the
//! detection window, the injected `_first_seen`/`_last_seen` and the search
//! service).
//!
//! Opt-in: `NANOSIEM_TEST_CLICKHOUSE_URL` (+ `_USER` / `_PASSWORD`) must name a
//! DISPOSABLE ClickHouse. Each test creates its own database there (the
//! production `ocsf_logs` DDL with stub prevalence dictionaries) and drops it;
//! the prevalence tests also create empty `nanosiem.*_prevalence_dict` stubs.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18751 \
//!   cargo test -p nanosiem-core --lib reduction_bound_live_tests -- --nocapture
//! ```

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

use super::*;
use crate::lookup::repository::{LookupRepositoryError, RuleReferenceRow};
use crate::lookup::types::NewLookupTable;
use crate::lookup::{LookupColumn, LookupService, LookupStore, LookupTable};
use crate::prevalence::PrevalenceService;

// ---------------------------------------------------------------------------
// In-memory lookup tables (both paths read the same store).
// ---------------------------------------------------------------------------

struct Store {
    tables: HashMap<String, LookupTable>,
    rows: HashMap<String, Vec<HashMap<String, Value>>>,
}

fn key_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[async_trait]
impl LookupStore for Store {
    async fn list_tables(&self) -> Result<Vec<LookupTable>, LookupRepositoryError> {
        Ok(self.tables.values().cloned().collect())
    }
    async fn get_table(&self, name: &str) -> Result<LookupTable, LookupRepositoryError> {
        self.tables.get(name).cloned().ok_or_else(|| LookupRepositoryError::TableNotFound(name.to_string()))
    }
    async fn table_exists(&self, name: &str) -> Result<bool, LookupRepositoryError> {
        Ok(self.tables.contains_key(name))
    }
    /// The PostgreSQL store's contract: rows whose key column equals one of
    /// the values (`LOWER` on both sides when case-insensitive), keyed by the
    /// STORED key, with the requested output columns.
    async fn lookup_batch(
        &self,
        table_name: &str,
        _columns: &[LookupColumn],
        key_field: &str,
        key_values: &[Value],
        output_fields: Option<&[String]>,
        case_insensitive: bool,
    ) -> Result<HashMap<String, HashMap<String, Value>>, LookupRepositoryError> {
        let fold = |s: String| if case_insensitive { s.to_lowercase() } else { s };
        let wanted: std::collections::HashSet<String> = key_values.iter().filter_map(key_string).map(fold).collect();
        let mut out = HashMap::new();
        for row in self.rows.get(table_name).into_iter().flatten() {
            let Some(stored) = row.get(key_field).and_then(key_string) else { continue };
            if !wanted.contains(&fold(stored.clone())) {
                continue;
            }
            let fields = row
                .iter()
                .filter(|(k, _)| output_fields.is_none_or(|o| o.iter().any(|f| f == *k)))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            out.insert(stored, fields);
        }
        Ok(out)
    }
    async fn list_rows(
        &self,
        _: &str,
        _: &[LookupColumn],
        _: i64,
        _: i64,
    ) -> Result<(Vec<HashMap<String, Value>>, i64), LookupRepositoryError> {
        unimplemented!()
    }
    async fn register_table(&self, _: &NewLookupTable, _: &str, _: Option<Uuid>) -> Result<LookupTable, LookupRepositoryError> {
        unimplemented!()
    }
    async fn update_table_stats(&self, _: &str, _: i64, _: i64) -> Result<(), LookupRepositoryError> {
        unimplemented!()
    }
    async fn unregister_table(&self, _: &str) -> Result<LookupTable, LookupRepositoryError> {
        unimplemented!()
    }
    async fn update_table_columns(&self, _: &str, _: &[LookupColumn], _: Option<&str>) -> Result<(), LookupRepositoryError> {
        unimplemented!()
    }
    async fn find_rules_referencing(&self, _: &str) -> Result<Vec<RuleReferenceRow>, LookupRepositoryError> {
        unimplemented!()
    }
    async fn create_dynamic_table(&self, _: &str, _: &[LookupColumn], _: Option<&str>) -> Result<(), LookupRepositoryError> {
        unimplemented!()
    }
    async fn drop_dynamic_table(&self, _: &str) -> Result<(), LookupRepositoryError> {
        unimplemented!()
    }
    async fn truncate_dynamic_table(&self, _: &str) -> Result<(), LookupRepositoryError> {
        unimplemented!()
    }
    async fn swap_staged_table(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &[LookupColumn],
        _: Option<&str>,
        _: i64,
    ) -> Result<(), LookupRepositoryError> {
        unimplemented!()
    }
    async fn insert_records(&self, _: &str, _: &[LookupColumn], _: &[HashMap<String, Value>]) -> Result<usize, LookupRepositoryError> {
        unimplemented!()
    }
    async fn get_table_row_count(&self, _: &str) -> Result<i64, LookupRepositoryError> {
        unimplemented!()
    }
    async fn get_table_size(&self, _: &str) -> Result<i64, LookupRepositoryError> {
        unimplemented!()
    }
    async fn lookup(
        &self,
        _: &str,
        _: &[LookupColumn],
        _: &str,
        _: &Value,
        _: Option<&[String]>,
        _: bool,
    ) -> Result<Option<HashMap<String, Value>>, LookupRepositoryError> {
        unimplemented!()
    }
    async fn sample_rows(&self, _: &str, _: i64) -> Result<Vec<HashMap<String, Value>>, LookupRepositoryError> {
        unimplemented!()
    }
    async fn insert_row(&self, _: &str, _: &[LookupColumn], _: &HashMap<String, Value>) -> Result<i64, LookupRepositoryError> {
        unimplemented!()
    }
    async fn update_row(&self, _: &str, _: i64, _: &[LookupColumn], _: &HashMap<String, Value>) -> Result<(), LookupRepositoryError> {
        unimplemented!()
    }
    async fn delete_row(&self, _: &str, _: i64) -> Result<(), LookupRepositoryError> {
        unimplemented!()
    }
    async fn delete_rows(&self, _: &str, _: &[i64]) -> Result<u64, LookupRepositoryError> {
        unimplemented!()
    }
}

fn table(name: &str, key: &str, columns: &[&str]) -> LookupTable {
    LookupTable {
        id: Uuid::now_v7(),
        name: name.to_string(),
        description: None,
        table_name: format!("lookup_{name}"),
        columns: columns.iter().map(|c| LookupColumn::text(*c, true)).collect(),
        primary_key: Some(key.to_string()),
        row_count: 0,
        size_bytes: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        created_by: None,
    }
}

fn record(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

/// `assets` (by IP; one NULL site, one key no event carries), `users` (by
/// name, mixed case), `ports` (numeric keys stored as text and number).
fn store(owner_count: usize) -> Store {
    let mut tables = HashMap::new();
    let mut rows = HashMap::new();
    let mut add = |t: LookupTable, r: Vec<HashMap<String, Value>>| {
        rows.insert(t.table_name.clone(), r);
        tables.insert(t.name.clone(), t);
    };
    let mut assets = vec![
        record(&[("ip", json!("10.0.0.1")), ("owner", json!("eng")), ("site", json!("nyc")), ("tier", json!("4"))]),
        record(&[("ip", json!("10.0.0.2")), ("owner", json!("eng")), ("site", Value::Null), ("tier", json!("1"))]),
        record(&[("ip", json!("10.0.0.3")), ("owner", json!("ops")), ("site", json!("sfo")), ("tier", json!("4"))]),
        // Only the race test's late event carries this key.
        record(&[("ip", json!("10.0.0.5")), ("owner", json!("late")), ("site", json!("lax"))]),
        record(&[("ip", json!("10.9.9.9")), ("owner", json!("ghost")), ("site", json!("nowhere"))]),
    ];
    for i in 0..owner_count {
        let tier = if i % 10 == 0 { "critical" } else { "low" };
        assets.push(record(&[
            ("ip", json!(format!("172.16.{}.{}", i / 250, i % 250))),
            ("owner", json!(format!("team-{i}"))),
            ("tier", json!(tier)),
        ]));
    }
    add(table("assets", "ip", &["ip", "owner", "site", "tier"]), assets);
    // A table storing `''` (a CSV upload's empty cell).
    add(
        table("assets_blank", "ip", &["ip", "owner"]),
        vec![record(&[("ip", json!("10.0.0.1")), ("owner", json!(""))]), record(&[("ip", json!("10.0.0.3")), ("owner", json!("ops"))])],
    );
    add(
        table("users", "name", &["name", "dept"]),
        vec![
            record(&[("name", json!("alice")), ("dept", json!("research"))]),
            record(&[("name", json!("Bob")), ("dept", json!("sales"))]),
        ],
    );
    add(
        table("ports", "port", &["port", "service"]),
        vec![record(&[("port", json!("443")), ("service", json!("https"))]), record(&[("port", json!(22)), ("service", json!("ssh"))])],
    );
    Store { tables, rows }
}

// ---------------------------------------------------------------------------
// Disposable ClickHouse
// ---------------------------------------------------------------------------

struct Live {
    admin: clickhouse::Client,
    db: String,
    svc: DetectionService,
    source_type: String,
}

fn ocsf_logs_ddl(db: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../clickhouse/ocsf/init.sql");
    let sql = std::fs::read_to_string(path).expect("ocsf init.sql");
    let head = "CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs\n";
    let start = sql.find(head).expect("ocsf_logs DDL");
    let end = start + sql[start..].find("\n;").expect("statement end");
    sql[start..end].replace("nanosiem.", &format!("{db}."))
}

impl Live {
    async fn connect(tag: &str, owner_count: usize) -> Option<Self> {
        let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL").ok()?;
        let mut admin = crate::db::clickhouse_transport::client().with_url(url);
        if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
            admin = admin.with_user(user);
        }
        if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
            admin = admin.with_password(password);
        }
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let db = format!("nan5751_{tag}_{nanos}");
        let exec = |sql: String| {
            let admin = admin.clone();
            async move { admin.query(&sql).execute().await.unwrap_or_else(|e| panic!("{e}\n{sql}")) }
        };
        exec(format!("CREATE DATABASE {db}")).await;
        exec(format!("CREATE TABLE {db}.prevalence_stub (key String, host_count UInt16) ENGINE = Memory")).await;
        for (dict, key) in [("hash_prevalence_dict", "file_hash"), ("domain_prevalence_dict", "domain"), ("ip_prevalence_dict", "ip")] {
            exec(format!(
                "CREATE DICTIONARY {db}.{dict} ({key} String, host_count UInt16 DEFAULT 9999) PRIMARY KEY {key} \
                 SOURCE(CLICKHOUSE(QUERY 'SELECT key AS {key}, host_count FROM {db}.prevalence_stub')) \
                 LAYOUT(COMPLEX_KEY_HASHED()) LIFETIME(0)"
            ))
            .await;
        }
        exec(ocsf_logs_ddl(&db)).await;

        let pool = crate::db::DualPool::for_live_clickhouse_tests(admin.clone().with_database(&db));
        let svc = DetectionService::with_dual_pool_prevalence_and_profile(
            &pool,
            LookupService::new(store(owner_count)),
            PrevalenceService::new(pool.clickhouse().clone(), pool.table_names()),
            crate::schema::profile_for_id(crate::schema::SchemaId::Ocsf),
        );
        Some(Self { admin, db, svc, source_type: format!("nan5751_{tag}") })
    }

    async fn insert(&self, rows: &[Value]) {
        for chunk in rows.chunks(10_000) {
            let body: Vec<String> = chunk.iter().map(Value::to_string).collect();
            let sql = format!(
                "INSERT INTO {}.ocsf_logs SETTINGS async_insert=0 FORMAT JSONEachRow\n{}",
                self.db,
                body.join("\n")
            );
            self.admin.query(&sql.replace('?', "??")).execute().await.expect("insert");
        }
    }

    fn event(&self, minutes_ago: i64, ip: &str, user: &str, port: i32) -> Value {
        let ts = Utc::now() - Duration::minutes(minutes_ago);
        json!({
            "timestamp": ts.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            "class_uid": 4001,
            "source_type": self.source_type,
            "metadata.uid": Uuid::now_v7().to_string(),
            "message": format!("nan5751 {ip} {user}"),
            "src_endpoint.ip": ip,
            "actor.user.name": user,
            "dst_endpoint.port": port,
        })
    }

    fn rule(&self, body: &str) -> DetectionRule {
        let mut rule = crate::detection::findings::tests::sample_rule();
        rule.query = format!("source_type=\"{}\" {body}", self.source_type);
        rule
    }

    fn window() -> crate::search::TimeRangeInput {
        let end = Utc::now();
        crate::search::TimeRangeInput::new(end - Duration::hours(2), end)
    }

    /// One scheduled run of `rule`.
    async fn run(&self, rule: &DetectionRule) -> (Vec<Value>, Vec<String>) {
        let svc = self.svc.clone();
        crate::search::partial_run::collect(async {
            Box::pin(svc.evaluate_rule_run(rule, &Self::window())).await.unwrap_or_else(|e| panic!("{}: {e}", rule.query))
        })
        .await
    }

    /// `result_rows` of every finished query of this test's database.
    async fn result_rows(&self) -> Vec<(String, u64)> {
        self.admin.query("SYSTEM FLUSH LOGS").execute().await.expect("flush logs");
        let sql = format!(
            "SELECT query, result_rows FROM system.query_log WHERE type = 'QueryFinish' \
             AND has(databases, '{}') AND query_kind = 'Select' ORDER BY event_time_microseconds",
            self.db
        );
        self.admin.query(&sql).fetch_all::<(String, u64)>().await.expect("query_log")
    }

    /// The prevalence pushdown reads `nanosiem.*_prevalence_dict` by name:
    /// empty stubs of the production shape on this DISPOSABLE ClickHouse.
    async fn create_production_prevalence_dicts(&self) {
        let exec = |sql: String| {
            let admin = self.admin.clone();
            async move { admin.query(&sql).execute().await.unwrap_or_else(|e| panic!("{e}\n{sql}")) }
        };
        exec("CREATE DATABASE IF NOT EXISTS nanosiem".into()).await;
        for (dict, key) in [("hash_prevalence_dict", "file_hash"), ("domain_prevalence_dict", "domain"), ("ip_prevalence_dict", "ip")] {
            exec(format!(
                "CREATE TABLE IF NOT EXISTS nanosiem.nan5751_{dict}_src ({key} String, host_count UInt16, \
                 first_seen DateTime64(6), last_seen DateTime64(6), total_occurrences UInt64) ENGINE = Memory"
            ))
            .await;
            exec(format!(
                "CREATE DICTIONARY IF NOT EXISTS nanosiem.{dict} ({key} String, host_count UInt16 DEFAULT 9999, \
                 first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00', last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00', \
                 total_occurrences UInt64 DEFAULT 0) PRIMARY KEY {key} \
                 SOURCE(CLICKHOUSE(QUERY 'SELECT * FROM nanosiem.nan5751_{dict}_src')) LAYOUT(COMPLEX_KEY_HASHED()) LIFETIME(0)"
            ))
            .await;
        }
    }

    async fn drop(self) {
        let _ = self.admin.query(&format!("DROP DATABASE IF EXISTS {}", self.db)).execute().await;
    }
}

/// Rows as an order-free multiset (the Rust aggregation is unordered).
fn canonical(rows: &[Value]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for row in rows {
        *out.entry(row.to_string()).or_insert(0) += 1;
    }
    out
}

/// Events covering the lookup key cases (matched, unmatched, empty).
fn parity_events(live: &Live) -> Vec<Value> {
    let mut events = Vec::new();
    let spec: &[(&str, &str, i32, usize)] = &[
        ("10.0.0.1", "alice", 443, 5),
        ("10.0.0.1", "Alice", 22, 2),
        ("10.0.0.2", "ALICE", 443, 3),
        ("10.0.0.3", "bob", 8080, 4),
        ("192.168.1.1", "carol", 443, 6),
        ("", "dave", 53, 2),
    ];
    for (i, (ip, user, port, n)) in spec.iter().enumerate() {
        for j in 0..*n {
            events.push(live.event(10 + (i * 7 + j) as i64, ip, user, *port));
        }
    }
    events
}

fn ip(i: usize, net: u8) -> String {
    format!("172.{net}.{}.{}", i / 250, i % 250)
}

/// The flood: 20,000 events over 300 IPs with a cap of 50. The aggregation
/// runs in ClickHouse and returns exactly 51 groups (no query returns more):
/// the run keeps 50 and says loudly that coverage is incomplete.
#[tokio::test]
async fn a_too_large_aggregation_is_bounded_not_computed_in_memory() {
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    const IPS: usize = 300;
    const EVENTS: usize = 20_000;
    const CAP: usize = 50;
    let Some(mut live) = Live::connect("flood", 0).await else { return };
    live.svc = live.svc.clone().with_max_matches_per_run(CAP);
    let events: Vec<Value> = (0..EVENTS).map(|i| live.event(5 + (i % 60) as i64, &ip(i % IPS, 16), "u", 443)).collect();
    live.insert(&events).await;
    let rule = live.rule("| stats count by src_endpoint.ip | where count > 0");

    let (rows, notes) = live.run(&rule).await;
    assert_eq!(rows.len(), CAP + 1, "the cap's groups plus the coverage-incomplete row");
    assert_eq!(rows[0][COVERAGE_INCOMPLETE_MARKER], true, "{:?}", rows[0]);
    assert!(rows[1..].iter().all(|r| r.get("src_endpoint.ip").is_some() && r.get("count").is_some()), "{rows:?}");
    assert!(notes.iter().any(|n| n.starts_with("DETECTION COVERAGE INCOMPLETE")), "{notes:?}");
    let queries = live.result_rows().await;
    let largest = queries.iter().map(|(_, n)| *n).max().unwrap_or(0);
    assert_eq!(largest, (CAP + 1) as u64, "ClickHouse returned only cap + 1 groups: {queries:?}");
    live.drop().await;
}

/// An aggregation after a `| lookup` still aggregates in Rust (every event is
/// fetched), but its result rows are bounded the same way.
#[tokio::test]
async fn a_lookup_aggregation_is_bounded_on_its_output() {
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    const OWNERS: usize = 300;
    const CAP: usize = 50;
    let Some(mut live) = Live::connect("lookupflood", OWNERS).await else { return };
    live.svc = live.svc.clone().with_max_matches_per_run(CAP);
    let events: Vec<Value> = (0..3_000).map(|i| live.event(5, &ip(i % OWNERS, 16), "u", 443)).collect();
    live.insert(&events).await;
    let rule = live.rule("| lookup assets src_endpoint.ip AS ip OUTPUT owner | stats count by owner");
    let (rows, notes) = live.run(&rule).await;
    assert_eq!(rows.len(), CAP + 1);
    assert_eq!(rows[0][COVERAGE_INCOMPLETE_MARKER], true);
    assert!(notes.iter().any(|n| n.starts_with("DETECTION COVERAGE INCOMPLETE")), "{notes:?}");
    live.drop().await;
}

/// Review round 1 finding 1: `stats … | lookup … | where …` pages the SQL
/// aggregation only after the Rust lookup filtered it, so a bounded run never
/// drops matches.
#[tokio::test]
async fn an_aggregation_filtered_by_a_later_lookup_keeps_every_match() {
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    const IPS: usize = 300;
    let Some(mut live) = Live::connect("statslookup", IPS).await else { return };
    live.svc = live.svc.clone().with_max_matches_per_run(50);
    let events: Vec<Value> = (0..IPS).flat_map(|i| [0, 1].map(|j| (i, j))).map(|(i, j)| live.event(5 + j, &ip(i, 16), "u", 443)).collect();
    live.insert(&events).await;
    let rule = live.rule("| stats count by src_endpoint.ip | lookup assets src_endpoint.ip AS ip OUTPUT tier | where tier=\"critical\"");
    let (rows, notes) = live.run(&rule).await;
    assert_eq!(rows.len(), IPS / 10, "every critical IP: {rows:?}");
    assert!(notes.is_empty(), "{notes:?}");
    live.drop().await;
}

/// Round 1 finding 4: `| prevalence … | stats …` reads at most `cap + 1`
/// groups from the prevalence pushdown, not up to 1M.
#[tokio::test]
async fn a_prevalence_aggregation_reads_only_the_capped_groups() {
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    const IPS: usize = 300;
    const CAP: usize = 50;
    let Some(mut live) = Live::connect("prevalence", 0).await else { return };
    live.create_production_prevalence_dicts().await;
    live.svc = live.svc.clone().with_max_matches_per_run(CAP);
    let events: Vec<Value> = (0..IPS).map(|i| live.event(5, &ip(i, 20), "u", 443)).collect();
    live.insert(&events).await;
    let rule = live.rule("| prevalence enrich=true | stats count by src_endpoint.ip");
    let (rows, notes) = live.run(&rule).await;
    assert_eq!(rows.len(), CAP + 1, "{rows:?}");
    assert!(notes.iter().any(|n| n.starts_with("DETECTION COVERAGE INCOMPLETE")), "{notes:?}");
    let queries = live.result_rows().await;
    let largest = queries.iter().filter(|(q, _)| q.contains("prevalence_dict")).map(|(_, n)| *n).max();
    assert_eq!(largest, Some((CAP + 1) as u64), "{queries:?}");
    live.drop().await;
}

/// Round 2 finding 2: a command before the aggregation that the prevalence
/// pushdown replays in Rust (here `dedup`) must see every SQL row; cutting
/// them to `cap + 1` first silently lost matches. The bounded run equals the
/// unbounded run cut to the cap.
#[tokio::test]
async fn a_prevalence_aggregation_with_a_rust_stage_is_not_cut_early() {
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    const IPS: usize = 300;
    const CAP: usize = 50;
    let Some(mut live) = Live::connect("prevrust", 0).await else { return };
    live.create_production_prevalence_dicts().await;
    live.svc = live.svc.clone().with_max_matches_per_run(CAP);
    // IP i has (i % 60) + 1 events: 60 distinct counts across 300 groups.
    let events: Vec<Value> = (0..IPS).flat_map(|i| (0..=(i % 60)).map(move |_| i)).map(|i| live.event(5, &ip(i, 21), "u", 443)).collect();
    live.insert(&events).await;
    let rule = live.rule("| prevalence enrich=true | dedup count | stats count by src_endpoint.ip");
    let unbounded = Box::pin(live.svc.evaluate_window(&rule.query, Live::window(), None, &crate::auth::ScopeSet::unrestricted()))
        .await
        .expect("unbounded run");
    assert!(unbounded.len() > CAP, "the fixture overflows the cap: {}", unbounded.len());
    let (rows, notes) = live.run(&rule).await;
    assert_eq!(rows.len(), CAP + 1, "{rows:?}");
    assert!(notes.iter().any(|n| n.starts_with("DETECTION COVERAGE INCOMPLETE")), "loud, never silent: {notes:?}");
    live.drop().await;
}

/// Under the cap a reduction rule's rows are exactly the unbounded run's.
#[tokio::test]
async fn under_the_cap_a_reduction_run_is_unchanged() {
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    let Some(live) = Live::connect("undercap", 0).await else { return };
    live.insert(&parity_events(&live)).await;
    for body in [
        "| stats count by src_endpoint.ip",
        "| dedup actor.user.name",
        "| timechart span=1h count by src_endpoint.ip",
        "| top actor.user.name",
        "| lookup assets src_endpoint.ip AS ip OUTPUT owner | stats count by owner",
        "| lookup users actor.user.name AS name OUTPUT dept CASE_INSENSITIVE | stats count by dept",
    ] {
        let rule = live.rule(body);
        let (bounded, notes) = live.run(&rule).await;
        let unbounded = Box::pin(live.svc.evaluate_window(
            &rule.query,
            Live::window(),
            None,
            &crate::auth::ScopeSet::unrestricted(),
        ))
        .await
        .expect("unbounded run");
        assert!(!bounded.is_empty(), "{body}");
        assert_eq!(canonical(&bounded), canonical(&unbounded), "{body}");
        assert!(notes.is_empty(), "{body}: {notes:?}");
    }
    live.drop().await;
}

// ---------------------------------------------------------------------------
// Alerting (needs a disposable PostgreSQL too)
// ---------------------------------------------------------------------------

/// A fresh PostgreSQL database with the nano schema, on the DISPOSABLE server
/// `NANOSIEM_TEST_PG_URL` (`postgres://user:pass@host:port`).
async fn fresh_pg(tag: &str) -> Option<sqlx::PgPool> {
    let base = std::env::var("NANOSIEM_TEST_PG_URL").ok()?;
    let admin = sqlx::PgPool::connect(&format!("{base}/postgres")).await.expect("connect PG");
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let db = format!("nan5751_{tag}_{nanos}");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db}"))).execute(&admin).await.expect("create db");
    let pg = sqlx::PgPool::connect(&format!("{base}/{db}")).await.expect("connect test db");
    crate::db::run_postgres_migrations(&pg).await.expect("migrations");
    Some(pg)
}

/// Review round 3: the coverage-incomplete alert of an overflowing grouped
/// aggregation rule is its own finding per window. A rule grouped by a
/// non-entity field puts every ordinary row in the `unknown` bucket; once that
/// bucket alerted (a finding exists, and a cooldown anchor), the next
/// overflowing window must still raise its coverage-incomplete alert, and a
/// rerun of the same window must not raise it twice.
#[tokio::test]
async fn the_coverage_incomplete_alert_fires_once_per_overflowing_window() {
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    for mode in ["grouped", "per_event"] {
        coverage_incomplete_alert_case(mode).await;
    }
}

async fn coverage_incomplete_alert_case(mode: &str) {
    let Some(pg) = fresh_pg(mode).await else { return };
    let Some(mut live) = Live::connect(mode, 0).await else { return };
    let pool = crate::db::DualPool::for_live_tests(pg.clone(), live.admin.clone().with_database(&live.db));
    let mut svc = DetectionService::with_dual_pool_prevalence_and_profile(
        &pool,
        LookupService::new(store(0)),
        PrevalenceService::new(pool.clickhouse().clone(), pool.table_names()),
        crate::schema::profile_for_id(crate::schema::SchemaId::Ocsf),
    )
    .with_max_matches_per_run(3);
    // Findings go to ClickHouse tables this test does not create; the alert
    // path (PostgreSQL) is what is under test.
    svc.finding_logger = None;
    live.svc = svc.clone();

    // Five ports, one event each: five groups over a cap of three, none of
    // them carrying an entity (the `unknown` bucket).
    let events: Vec<Value> = [22, 53, 80, 443, 8080].iter().map(|p| live.event(30, "", "", *p)).collect();
    live.insert(&events).await;
    let body: serde_json::Value = json!({
        "name": "nan5751_coverage_incomplete_probe",
        "description": "NAN-5751 coverage-incomplete alert probe",
        "query": format!("source_type=\"{}\" | stats count by dst_endpoint.port", live.source_type),
        "severity": "high",
        "mode": "alerting",
        "schedule_cron": "0 5 31 12 *",
        "alert_mode": mode,
        "lookback_minutes": 120,
        "alert_cooldown_minutes": 60,
        "folder": "Automated",
    });
    let rule = svc.create_rule(serde_json::from_value(body).expect("rule")).await.expect("create rule");
    let carries_marker =
        |events: &serde_json::Value| events.as_array().is_some_and(|a| a.iter().any(|e| e[COVERAGE_INCOMPLETE_MARKER] == true));
    // The alerts that carry the coverage-incomplete row, oldest first.
    let alerts = || async {
        sqlx::query_as::<_, (serde_json::Value,)>("SELECT matched_events FROM alerts WHERE rule_id = $1 ORDER BY created_at")
            .bind(rule.id)
            .fetch_all(&pg)
            .await
            .expect("alerts")
            .into_iter()
            .filter(|(events,)| carries_marker(events))
            .collect::<Vec<_>>()
    };

    let end1 = Utc::now();
    let window = |end: chrono::DateTime<Utc>| crate::search::TimeRangeInput::new(end - Duration::hours(2), end);
    svc.execute_rule(&rule, Some(window(end1))).await.expect("run 1");
    let after1 = alerts().await;
    assert_eq!(after1.len(), 1, "{mode}: the first overflow alerts");

    // The same data, the next window: the `unknown` rows were already alerted
    // (same `_last_seen`) and are in cooldown; the overflow still alerts.
    let end2 = end1 + Duration::minutes(1);
    svc.execute_rule(&rule, Some(window(end2))).await.expect("run 2");
    let after2 = alerts().await;
    assert_eq!(after2.len(), 2, "{mode}: the second overflowing window alerts too: {after2:?}");

    // A rerun of the second window is the same incomplete window: no new alert.
    svc.execute_rule(&rule, Some(window(end2))).await.expect("rerun 2");
    assert_eq!(alerts().await.len(), 2, "{mode}: one coverage-incomplete alert per window");

    // Only real entities are anchored for cooldown, never the overflow.
    let anchored: Vec<String> = sqlx::query_scalar("SELECT entity FROM detection_alert_entity_cooldowns WHERE rule_id = $1")
        .bind(rule.id)
        .fetch_all(&pg)
        .await
        .unwrap_or_default();
    assert!(!anchored.iter().any(|e| e.starts_with("nano-coverage-incomplete")), "{mode}: {anchored:?}");
    live.drop().await;
}
