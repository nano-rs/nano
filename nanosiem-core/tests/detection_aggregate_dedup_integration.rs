// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1711 (audit D15 + D16): cross-cycle dedup for top/rare/timechart rules.
//!
//! Drives the REAL `DetectionService::execute_rule` (the same call the
//! `POST /api/rules/{id}/trigger` endpoint makes) repeatedly against live
//! PostgreSQL + ClickHouse, with controlled probe data, and asserts:
//!
//! - **D15 (grouped)**: a `| top src_ip` / `| rare` / `| timechart` alerting
//!   rule over static data stays FLAT across triggers — finding emissions and
//!   alerts do not climb when only the drifting `count`/`percent`/`_first_seen`
//!   change (an event inserted OLDER than the entity's newest activity).
//!   Pre-fix, these rows carried no `_first_seen`/`_last_seen`, fell to the
//!   content-hash dedup branch, and re-emitted every cycle (measured live on
//!   the pre-fix binary: emissions 2→4→6 / alerts 1→2→3 over three triggers).
//! - **D16 (per-event)**: a per-event-alert-mode rule over the same aggregate
//!   stays flat across drift-only triggers (pre-fix: alerts 2→4→6).
//! - **Controls**: genuinely new activity (a later `_last_seen`) and a new
//!   entity DO still emit — dedup must not over-suppress.
//!
//! Requires local PG (:5432) + CH (:8123) with the nanosiem schema. Skips
//! cleanly when unreachable or when `SKIP_DB_TESTS` is set.
//!   Run: cargo test -p nanosiem-core --test detection_aggregate_dedup_integration -- --nocapture

use chrono::{Duration, Utc};
use nanosiem_core::detection::DetectionService;
use nanosiem_core::lookup::{LookupService, PostgresLookupRepository};
use nanosiem_core::models::{DetectionRule, NewDetectionRule};
use nanosiem_core::prevalence::PrevalenceService;
use nanosiem_core::search::TimeRangeInput;
use nanosiem_core::{DualPool, DualPoolConfig};
use serde_json::json;

fn pg_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/nanosiem".into())
}
fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}

/// Insert one probe event into `nanosiem.logs` via the CH HTTP interface
/// (async_insert off + wait_end_of_query so the row is queryable on return).
/// The message carries a UUID so retried/parallel inserts never block-dedup.
async fn insert_event(
    client: &reqwest::Client,
    source_type: &str,
    src_ip: &str,
    ts: chrono::DateTime<Utc>,
) {
    let stmt = "INSERT INTO nanosiem.logs (timestamp, message, source_type, src_ip) FORMAT JSONEachRow";
    let url = format!(
        "{}/?query={}&async_insert=0&wait_end_of_query=1",
        ch_url(),
        urlencoding::encode(stmt)
    );
    let row = json!({
        "timestamp": ts.format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
        "message": format!("nan1711 dedup probe {}", uuid::Uuid::new_v4()),
        "source_type": source_type,
        "src_ip": src_ip,
    })
    .to_string();
    let resp = client
        .post(url)
        .basic_auth("nanosiem", Some("nanosiem"))
        .body(row)
        .send()
        .await
        .expect("CH insert send");
    assert!(
        resp.status().is_success(),
        "CH probe insert failed: {}",
        resp.text().await.unwrap_or_default()
    );
}

/// Best-effort cleanup of the probe rows (lightweight delete; ignore errors —
/// the runtime user may lack DELETE rights, and unique source_types make
/// leftovers inert).
async fn cleanup_probe_rows(client: &reqwest::Client, source_types: &[String]) {
    let list = source_types
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",");
    let _ = client
        .post(ch_url())
        .basic_auth("nanosiem", Some("nanosiem"))
        .body(format!(
            "DELETE FROM nanosiem.logs WHERE source_type IN ({list})"
        ))
        .send()
        .await;
}

/// Execute the rule over a now-anchored lookback window — byte-for-byte the
/// window construction of the `POST /api/rules/{id}/trigger` handler.
async fn trigger(svc: &DetectionService, rule: &DetectionRule) {
    let end = Utc::now();
    let lookback = rule.lookback_minutes.map(|m| m as i64).unwrap_or(15);
    let range = TimeRangeInput::new(end - Duration::minutes(lookback), end);
    svc.execute_rule(rule, Some(range))
        .await
        .expect("execute_rule");
}

async fn emissions(pool: &sqlx::PgPool, rule_id: uuid::Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM detection_finding_emissions WHERE rule_id = $1")
        .bind(rule_id)
        .fetch_one(pool)
        .await
        .expect("emissions count")
}

async fn alerts(pool: &sqlx::PgPool, rule_id: uuid::Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM alerts WHERE rule_id = $1")
        .bind(rule_id)
        .fetch_one(pool)
        .await
        .expect("alerts count")
}

/// Build a probe rule. `alert_mode` is "grouped" or "per_event".
fn probe_rule(name: &str, query: &str, alert_mode: &str) -> NewDetectionRule {
    serde_json::from_value(json!({
        "name": name,
        "description": "NAN-1711 aggregate-dedup integration probe (auto-deleted)",
        "query": query,
        "severity": "low",
        "mode": "alerting",
        // A far-off cron so a co-resident scheduler never races the test's
        // explicit triggers.
        "schedule_cron": "0 5 31 12 *",
        "lookback_minutes": 60,
        "alert_mode": alert_mode,
    }))
    .expect("NewDetectionRule from JSON")
}

struct Harness {
    svc: DetectionService,
    pg: sqlx::PgPool,
    http: reqwest::Client,
    run_tag: String,
    source_types: Vec<String>,
    rule_ids: Vec<uuid::Uuid>,
}

impl Harness {
    async fn connect() -> Option<Harness> {
        if std::env::var("SKIP_DB_TESTS").is_ok() {
            println!("Skipping (SKIP_DB_TESTS set)");
            return None;
        }
        let config = DualPoolConfig::with_auth(pg_url(), ch_url(), "nanosiem", "nanosiem", "nanosiem");
        let dual_pool = match DualPool::new(&config).await {
            Ok(p) => p,
            Err(e) => {
                println!("Skipping: could not connect to local PG+CH: {e}");
                return None;
            }
        };
        let pg = dual_pool.postgres().clone();
        let lookup = LookupService::new(PostgresLookupRepository::new(pg.clone()));
        let prevalence =
            PrevalenceService::new(dual_pool.clickhouse().clone(), dual_pool.table_names());
        let svc = DetectionService::with_dual_pool_and_prevalence(&dual_pool, lookup, prevalence);
        // Unique per run so parallel/retried runs never see each other's rows.
        let run_tag = format!("{:x}", Utc::now().timestamp_micros());
        Some(Harness {
            svc,
            pg,
            http: reqwest::Client::new(),
            run_tag,
            source_types: vec![],
            rule_ids: vec![],
        })
    }

    /// Register + seed a scenario: a unique source_type with entity A
    /// (10.99.1.1, 3 events) and entity B (10.99.1.2, 2 events), all 20–30
    /// minutes in the past (well inside the 60-minute lookback, newest at
    /// A: now-20m / B: now-21m).
    async fn seed_scenario(&mut self, tag: &str) -> String {
        let st = format!("nan1711{}{}", tag, self.run_tag);
        let now = Utc::now();
        for (ip, mins) in [
            ("10.99.1.1", 30),
            ("10.99.1.1", 28),
            ("10.99.1.1", 20),
            ("10.99.1.2", 29),
            ("10.99.1.2", 21),
        ] {
            insert_event(&self.http, &st, ip, now - Duration::minutes(mins)).await;
        }
        self.source_types.push(st.clone());
        st
    }

    async fn create_rule(&mut self, name: &str, query: &str, alert_mode: &str) -> DetectionRule {
        let rule = self
            .svc
            .create_rule(probe_rule(name, query, alert_mode))
            .await
            .expect("create_rule");
        self.rule_ids.push(rule.id);
        rule
    }

    /// Drift-only mutation: an event for entity A OLDER than A's newest
    /// activity (now-20m), so `count`/`percent`/`_first_seen` move while
    /// `_last_seen` stays put. `offset_secs` de-duplicates repeated inserts.
    async fn insert_drift(&self, st: &str, offset_secs: i64) {
        insert_event(
            &self.http,
            st,
            "10.99.1.1",
            Utc::now() - Duration::minutes(25) - Duration::seconds(offset_secs),
        )
        .await;
    }

    async fn teardown(self) {
        for rule_id in &self.rule_ids {
            if let Err(e) = self.svc.delete_rule(*rule_id).await {
                println!("cleanup: delete_rule {rule_id}: {e}");
            }
        }
        cleanup_probe_rows(&self.http, &self.source_types).await;
    }
}

#[tokio::test]
async fn aggregate_rules_dedup_across_cycles_without_over_suppressing() {
    let Some(mut h) = Harness::connect().await else {
        return;
    };

    // ---- D15: grouped `| top src_ip` stays flat under drift ----
    let st = h.seed_scenario("top").await;
    let rule = h
        .create_rule(
            &format!("capstone-nan1711-top-{}", h.run_tag),
            &format!("source_type={st} | top src_ip"),
            "grouped",
        )
        .await;

    trigger(&h.svc, &rule).await;
    assert_eq!(emissions(&h.pg, rule.id).await, 2, "cycle 1: one finding per entity (A, B)");
    assert_eq!(alerts(&h.pg, rule.id).await, 1, "cycle 1: one grouped alert");

    for cycle in 2..=3 {
        h.insert_drift(&st, cycle).await;
        trigger(&h.svc, &rule).await;
        assert_eq!(
            emissions(&h.pg, rule.id).await,
            2,
            "cycle {cycle}: emissions must stay FLAT under count/percent/_first_seen drift"
        );
        assert_eq!(
            alerts(&h.pg, rule.id).await,
            1,
            "cycle {cycle}: alerts must stay FLAT under drift"
        );
    }

    // Control 1: genuinely NEW activity for A (advances _last_seen) → re-emit.
    insert_event(&h.http, &st, "10.99.1.1", Utc::now() - Duration::minutes(1)).await;
    trigger(&h.svc, &rule).await;
    assert_eq!(emissions(&h.pg, rule.id).await, 3, "new activity must re-emit A");
    assert_eq!(alerts(&h.pg, rule.id).await, 2, "new activity must alert");

    // Control 2: a NEW entity C → emits.
    insert_event(&h.http, &st, "10.99.1.3", Utc::now() - Duration::minutes(2)).await;
    trigger(&h.svc, &rule).await;
    assert_eq!(emissions(&h.pg, rule.id).await, 4, "new entity must emit");
    assert_eq!(alerts(&h.pg, rule.id).await, 3, "new entity must alert");

    // ---- D16: per-event mode over the aggregate stays flat under drift ----
    let st_pe = h.seed_scenario("pe").await;
    let rule_pe = h
        .create_rule(
            &format!("capstone-nan1711-perevent-{}", h.run_tag),
            &format!("source_type={st_pe} | top src_ip"),
            "per_event",
        )
        .await;

    trigger(&h.svc, &rule_pe).await;
    assert_eq!(alerts(&h.pg, rule_pe.id).await, 2, "cycle 1: one alert per aggregate row (A, B)");
    for cycle in 2..=3 {
        h.insert_drift(&st_pe, cycle).await;
        trigger(&h.svc, &rule_pe).await;
        assert_eq!(
            alerts(&h.pg, rule_pe.id).await,
            2,
            "cycle {cycle}: per-event alerts must stay FLAT under drift (pre-fix: +2/cycle)"
        );
    }
    // Control: advancing _last_seen mints a new per-event alert for A.
    insert_event(&h.http, &st_pe, "10.99.1.1", Utc::now() - Duration::minutes(1)).await;
    trigger(&h.svc, &rule_pe).await;
    assert_eq!(alerts(&h.pg, rule_pe.id).await, 3, "new activity must alert per-event");

    // ---- D15: timechart (grouped; dedup entity = the row's own time bucket) ----
    //
    // Timestamps are aligned to the 5-minute bucket grid so "older than the
    // bucket's newest" is deterministic (bucket membership doesn't depend on
    // when the test runs). Two buckets:
    //   bucket1 = [g, g+5m):  events at g+10s and g+240s (bucket max = g+240s)
    //   bucket2 = [g+5m, …):  event at g+5m+30s
    let st_tc = format!("nan1711tc{}", h.run_tag);
    let g = {
        let t = (Utc::now() - Duration::minutes(26)).timestamp();
        chrono::DateTime::<Utc>::from_timestamp(t - t.rem_euclid(300), 0).unwrap()
    };
    for secs in [10, 240, 330] {
        insert_event(&h.http, &st_tc, "10.99.1.1", g + Duration::seconds(secs)).await;
    }
    h.source_types.push(st_tc.clone());
    let rule_tc = h
        .create_rule(
            &format!("capstone-nan1711-timechart-{}", h.run_tag),
            &format!("source_type={st_tc} | timechart span=5m count"),
            "grouped",
        )
        .await;

    trigger(&h.svc, &rule_tc).await;
    assert_eq!(
        emissions(&h.pg, rule_tc.id).await,
        2,
        "cycle 1: one finding per time bucket (the auto-detect bucket fallback)"
    );
    assert_eq!(alerts(&h.pg, rule_tc.id).await, 1);
    for cycle in 2..=3i64 {
        // Late-arriving event inside bucket1, OLDER than bucket1's newest
        // (g+240s): the bucket's count drifts but its _last_seen holds.
        insert_event(&h.http, &st_tc, "10.99.1.1", g + Duration::seconds(100 + cycle)).await;
        trigger(&h.svc, &rule_tc).await;
        assert_eq!(
            emissions(&h.pg, rule_tc.id).await,
            2,
            "cycle {cycle}: bucket-count drift must not re-emit timechart findings"
        );
        assert_eq!(alerts(&h.pg, rule_tc.id).await, 1, "cycle {cycle}: alerts flat");
    }
    // Control: an event in a NEW bucket → new bucket entity → re-emits.
    insert_event(&h.http, &st_tc, "10.99.1.1", Utc::now() - Duration::seconds(30)).await;
    trigger(&h.svc, &rule_tc).await;
    assert_eq!(emissions(&h.pg, rule_tc.id).await, 3, "later activity must re-emit");
    assert_eq!(alerts(&h.pg, rule_tc.id).await, 2);

    // ---- D15: rare (same SQL path as top; two-cycle drift check) ----
    let st_rare = h.seed_scenario("rare").await;
    let rule_rare = h
        .create_rule(
            &format!("capstone-nan1711-rare-{}", h.run_tag),
            &format!("source_type={st_rare} | rare src_ip"),
            "grouped",
        )
        .await;
    trigger(&h.svc, &rule_rare).await;
    assert_eq!(emissions(&h.pg, rule_rare.id).await, 2, "rare cycle 1: A + B findings");
    h.insert_drift(&st_rare, 11).await;
    trigger(&h.svc, &rule_rare).await;
    assert_eq!(
        emissions(&h.pg, rule_rare.id).await,
        2,
        "rare cycle 2: emissions flat under drift"
    );
    assert_eq!(alerts(&h.pg, rule_rare.id).await, 1, "rare: single alert across cycles");

    h.teardown().await;
}
