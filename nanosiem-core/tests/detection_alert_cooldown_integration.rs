// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1805: per-(rule, entity) alert cooldown + dataset=risk Live e2e.
//!
//! Drives the REAL `DetectionService::execute_rule` against live
//! PostgreSQL + ClickHouse (same harness family as the NAN-1711 aggregate
//! dedup suite) and asserts the storm-guard semantics the risk→CH P3 design
//! requires:
//!
//! - **Stays-above**: an entity above threshold with genuinely NEW activity
//!   every cycle (which window-dedup alone would re-alert) fires ONCE, is
//!   suppressed for the cooldown window, and re-fires after it expires.
//! - **Flap**: crossing below the threshold (an empty evaluation) and back
//!   above INSIDE the window does not re-fire — the anchor is time-based,
//!   not edge-triggered.
//! - **Durability / restart**: a brand-new `DetectionService` instance (a
//!   simulated jobs restart / leader failover) still honors the window —
//!   the anchor lives in `detection_alert_entity_cooldowns`, not in memory.
//! - **Per-entity isolation**: a different entity crossing for the first
//!   time while the hot one is cooling still alerts.
//! - **dataset=risk Live e2e**: a `dataset='risk'` scheduled rule in Live
//!   mode evaluates end-to-end (engine → search → risk grain) and records
//!   matches WITHOUT creating alerts.
//!
//! Requires local PG (:5432) + CH (:8123) with the nanosiem schema (and, for
//! the cooldown tests, migrations 248/249 applied). Skips cleanly when
//! unreachable or when `SKIP_DB_TESTS` is set.
//!   Run: cargo test -p nanosiem-core --test detection_alert_cooldown_integration -- --nocapture

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

/// Insert one probe log event (async_insert off + wait_end_of_query so the
/// row is queryable on return).
async fn insert_event(
    client: &reqwest::Client,
    source_type: &str,
    src_ip: &str,
    ts: chrono::DateTime<Utc>,
) {
    let stmt =
        "INSERT INTO nanosiem.logs (timestamp, message, source_type, src_ip) FORMAT JSONEachRow";
    let url = format!(
        "{}/?query={}&async_insert=0&wait_end_of_query=1",
        ch_url(),
        urlencoding::encode(stmt)
    );
    let row = json!({
        "timestamp": ts.format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
        "message": format!("nan1805 cooldown probe {}", uuid::Uuid::new_v4()),
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

/// Insert one FINDINGS row (the risk dataset's source stream).
async fn insert_finding(
    client: &reqwest::Client,
    source: &str,
    entity: &str,
    score: f64,
    ts: chrono::DateTime<Utc>,
) {
    let stmt = "INSERT INTO nanosiem.logs (timestamp, message, source_type, source, risk_entity, risk_score, rule_id, rule_name, severity, action) FORMAT JSONEachRow";
    let url = format!(
        "{}/?query={}&async_insert=0&wait_end_of_query=1",
        ch_url(),
        urlencoding::encode(stmt)
    );
    let row = json!({
        "timestamp": ts.format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
        "message": format!("nan1805 risk fixture {}", uuid::Uuid::new_v4()),
        "source_type": "findings",
        "source": source,
        "risk_entity": entity,
        "risk_score": score,
        "rule_id": "nan1805-fixture-rule",
        "rule_name": "NAN-1805 fixture rule",
        "severity": "high",
        "action": "detection_match",
    })
    .to_string();
    let resp = client
        .post(url)
        .basic_auth("nanosiem", Some("nanosiem"))
        .body(row)
        .send()
        .await
        .expect("CH findings insert send");
    assert!(
        resp.status().is_success(),
        "CH findings insert failed: {}",
        resp.text().await.unwrap_or_default()
    );
}

async fn cleanup_probe_rows(client: &reqwest::Client, source_types: &[String]) {
    if source_types.is_empty() {
        return;
    }
    let list = source_types
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",");
    let _ = client
        .post(ch_url())
        .basic_auth("nanosiem", Some("nanosiem"))
        .body(format!(
            "DELETE FROM nanosiem.logs WHERE source_type IN ({list}) OR source IN ({list})"
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

/// A "dip below threshold" cycle: evaluate an (empty) window so the rule
/// matches nothing — the flap's downward edge.
async fn trigger_empty_window(svc: &DetectionService, rule: &DetectionRule) {
    let end = Utc::now() - Duration::days(300);
    let range = TimeRangeInput::new(end - Duration::minutes(1), end);
    svc.execute_rule(rule, Some(range))
        .await
        .expect("execute_rule (empty window)");
}

async fn alerts(pool: &sqlx::PgPool, rule_id: uuid::Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM alerts WHERE rule_id = $1")
        .bind(rule_id)
        .fetch_one(pool)
        .await
        .expect("alerts count")
}

async fn connect() -> Option<(DetectionService, sqlx::PgPool, DualPool)> {
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
    let svc = build_service(&dual_pool);
    Some((svc, pg, dual_pool))
}

/// Fresh service instance from the same pools — a simulated restart (all
/// in-process state gone; only durable PG/CH state survives).
fn build_service(dual_pool: &DualPool) -> DetectionService {
    let lookup = LookupService::new(PostgresLookupRepository::new(dual_pool.postgres().clone()));
    let prevalence =
        PrevalenceService::new(dual_pool.clickhouse().clone(), dual_pool.table_names());
    DetectionService::with_dual_pool_and_prevalence(dual_pool, lookup, prevalence)
}

fn probe_rule(name: &str, query: &str, extra: serde_json::Value) -> NewDetectionRule {
    let mut base = json!({
        "name": name,
        "description": "NAN-1805 cooldown integration probe (auto-deleted)",
        "query": query,
        "severity": "low",
        "mode": "alerting",
        // A far-off cron so a co-resident scheduler never races the test.
        "schedule_cron": "0 5 31 12 *",
        "lookback_minutes": 60,
        "alert_mode": "grouped",
        "risk_entity_field": "src_ip",
    });
    if let (Some(base_map), Some(extra_map)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in extra_map {
            base_map.insert(k.clone(), v.clone());
        }
    }
    serde_json::from_value(base).expect("NewDetectionRule from JSON")
}

/// Rewind this rule's cooldown anchors by `minutes` — the test's stand-in for
/// waiting out real wall-clock time.
async fn rewind_anchors(pool: &sqlx::PgPool, rule_id: uuid::Uuid, minutes: i64) {
    sqlx::query(
        "UPDATE detection_alert_entity_cooldowns \
         SET last_alert_at = last_alert_at - make_interval(mins => $2::int) \
         WHERE rule_id = $1",
    )
    .bind(rule_id)
    .bind(minutes as i32)
    .execute(pool)
    .await
    .expect("rewind anchors");
}

#[tokio::test]
async fn cooldown_fires_once_suppresses_then_refires_after_window() {
    let Some((svc, pg, dual_pool)) = connect().await else {
        return;
    };
    let http = reqwest::Client::new();
    let run_tag = format!("{:x}", Utc::now().timestamp_micros());
    let st = format!("nan1805cd{run_tag}");
    let now = Utc::now();

    // Entity A above threshold: 2 events, newest at now-20m.
    for mins in [30, 20] {
        insert_event(&http, &st, "10.98.1.1", now - Duration::minutes(mins)).await;
    }

    // Aggregate rule with a 240m cooldown. `| stats … | where count >= 1`
    // keys window-dedup on _last_seen, so NEW activity re-surfaces every
    // cycle — exactly the storm shape the cooldown exists to stop.
    let rule = svc
        .create_rule(probe_rule(
            &format!("capstone-nan1805-cd-{run_tag}"),
            &format!("source_type={st} | stats count by src_ip | where count >= 1"),
            json!({ "alert_cooldown_minutes": 240 }),
        ))
        .await
        .expect("create_rule");
    let rule_id = rule.id;

    let result = async {
        // --- 1. First crossing fires exactly once.
        trigger(&svc, &rule).await;
        assert_eq!(alerts(&pg, rule_id).await, 1, "first crossing must alert");

        // --- 2. Stays above WITH new activity (later _last_seen → passes
        // window-dedup; pre-cooldown this re-alerted) → suppressed.
        insert_event(&http, &st, "10.98.1.1", Utc::now() - Duration::minutes(10)).await;
        trigger(&svc, &rule).await;
        assert_eq!(
            alerts(&pg, rule_id).await,
            1,
            "new activity inside the cooldown window must be suppressed"
        );

        // --- 3. Flap: below threshold (empty evaluation) then back above
        // with even newer activity, still inside the window → no re-fire.
        trigger_empty_window(&svc, &rule).await;
        insert_event(&http, &st, "10.98.1.1", Utc::now() - Duration::minutes(5)).await;
        trigger(&svc, &rule).await;
        assert_eq!(
            alerts(&pg, rule_id).await,
            1,
            "flap across the threshold inside the window must not re-fire"
        );

        // --- 4. Restart durability: a brand-new service instance (fresh
        // process state) must still honor the window.
        let svc_after_restart = build_service(&dual_pool);
        insert_event(&http, &st, "10.98.1.1", Utc::now() - Duration::minutes(4)).await;
        trigger(&svc_after_restart, &rule).await;
        assert_eq!(
            alerts(&pg, rule_id).await,
            1,
            "the cooldown must survive a restart (durable anchor, not in-memory)"
        );

        // --- 5. Per-entity isolation: entity B's FIRST crossing alerts even
        // while A is cooling.
        insert_event(&http, &st, "10.98.1.2", Utc::now() - Duration::minutes(3)).await;
        trigger(&svc, &rule).await;
        assert_eq!(
            alerts(&pg, rule_id).await,
            2,
            "a different entity's first crossing must not be suppressed by A's cooldown"
        );

        // --- 6. Window expiry: rewind both anchors past 240m; new activity
        // for A re-fires.
        rewind_anchors(&pg, rule_id, 241).await;
        insert_event(&http, &st, "10.98.1.1", Utc::now() - Duration::minutes(2)).await;
        trigger(&svc, &rule).await;
        assert_eq!(
            alerts(&pg, rule_id).await,
            3,
            "after the cooldown expires the entity must re-fire"
        );
    };
    result.await;

    // Cleanup.
    if let Err(e) = svc.delete_rule(rule_id).await {
        println!("cleanup: delete_rule {rule_id}: {e}");
    }
    cleanup_probe_rows(&http, &[st]).await;
}

#[tokio::test]
async fn risk_dataset_rule_in_live_mode_records_matches_without_alerting() {
    let Some((svc, pg, _dual_pool)) = connect().await else {
        return;
    };
    let http = reqwest::Client::new();
    let run_tag = format!("{:x}", Utc::now().timestamp_micros());
    let source = format!("nan1805risk{run_tag}");
    let entity = format!("nan1805_user_{run_tag}");
    let now = Utc::now();

    // Findings for one entity, 2h old, score 40 → score_24h = score_7d = 40.
    insert_finding(&http, &source, &entity, 40.0, now - Duration::hours(2)).await;

    // A dataset=risk rule in LIVE mode with the feedback-guard-compliant
    // shape (risk_score 0, entity attribution, no `| risk`).
    let rule = svc
        .create_rule(probe_rule(
            &format!("capstone-nan1805-risk-live-{run_tag}"),
            &format!(
                "* | where score_7d >= 1 and entity = \"{entity}\" \
                 | table entity, entity_type, score_24h, score_7d"
            ),
            json!({
                "mode": "live",
                "dataset": "risk",
                "risk_score": 0,
                "risk_entity_field": "entity",
                "alert_cooldown_minutes": 240,
            }),
        ))
        .await
        .expect("create_rule (dataset=risk, live)");
    let rule_id = rule.id;

    let result = async {
        trigger(&svc, &rule).await;

        // Live mode: matches recorded, NO alerts.
        let (live_match_count,): (i64,) =
            sqlx::query_as("SELECT live_match_count FROM detection_rules WHERE id = $1")
                .bind(rule_id)
                .fetch_one(&pg)
                .await
                .expect("read live_match_count");
        assert!(
            live_match_count >= 1,
            "risk-dataset Live rule must record matches (got {live_match_count})"
        );
        assert_eq!(
            alerts(&pg, rule_id).await,
            0,
            "Live mode must never create alerts"
        );

        // The emission store recorded the per-entity live finding.
        let (emissions,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM detection_finding_emissions WHERE rule_id = $1 AND entity = $2",
        )
        .bind(rule_id)
        .bind(&entity)
        .fetch_one(&pg)
        .await
        .expect("emissions count");
        assert!(
            emissions >= 1,
            "live finding for the risk entity must be recorded"
        );
    };
    result.await;

    if let Err(e) = svc.delete_rule(rule_id).await {
        println!("cleanup: delete_rule {rule_id}: {e}");
    }
    cleanup_probe_rows(&http, &[source]).await;
}

#[tokio::test]
async fn risk_dataset_rule_save_guard_rejects_feedback_shapes() {
    let Some((svc, _pg, _dual_pool)) = connect().await else {
        return;
    };
    let run_tag = format!("{:x}", Utc::now().timestamp_micros());

    // Nonzero risk_score on dataset=risk → rejected at save.
    let err = svc
        .create_rule(probe_rule(
            &format!("capstone-nan1805-guard-score-{run_tag}"),
            "* | where score_7d >= 1",
            json!({ "mode": "staging", "dataset": "risk", "risk_score": 50 }),
        ))
        .await
        .expect_err("nonzero risk_score on dataset=risk must be rejected");
    assert!(
        err.to_string().contains("risk_score = 0"),
        "unexpected error: {err}"
    );

    // `| risk` in the body → rejected at save.
    let err = svc
        .create_rule(probe_rule(
            &format!("capstone-nan1805-guard-cmd-{run_tag}"),
            "* | risk score=10 entity=entity | where score_7d >= 1",
            json!({ "mode": "staging", "dataset": "risk", "risk_score": 0 }),
        ))
        .await
        .expect_err("`| risk` on dataset=risk must be rejected");
    assert!(
        err.to_string().contains("| risk"),
        "unexpected error: {err}"
    );
}
