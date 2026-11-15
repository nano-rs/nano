// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5424 integration: event values PostgreSQL cannot store as-is are
//! sanitized and alerted, write failures are isolated per event, a
//! persistent failure is retried a bounded number of times and then recorded
//! as a coverage gap, and failures are visible in rule health.
//!
//! Drives the REAL claim → `execute_and_release` cycle against live
//! PostgreSQL + ClickHouse (OCSF schema), with probe events inserted into
//! `ocsf_logs`. A persistent PostgreSQL data error that sanitizing cannot fix
//! is injected with a test-scoped trigger raising SQLSTATE 22P05, the error a
//! U+0000 in jsonb produces.
//!
//! Needs a throwaway stack; skips when PG/CH are unreachable or
//! `SKIP_DB_TESTS` is set. Configure with the usual `DATABASE_URL`,
//! `CLICKHOUSE_URL`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` (see
//! `DualPoolConfig::from_env`), e.g.
//!   cargo test -p nanosiem-core --lib nul_persistence_integration -- --nocapture --test-threads=1

use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use super::*;
use crate::db::{DualPool, DualPoolConfig};
use crate::lookup::{LookupService, PostgresLookupRepository};
use crate::models::NewDetectionRule;
use crate::prevalence::PrevalenceService;

const NODE: &str = "nan5424-integration-node";

struct Harness {
    svc: DetectionService,
    repo: DetectionRuleRepository,
    pg: sqlx::PgPool,
    http: reqwest::Client,
    ch_url: String,
    ch_user: String,
    ch_pass: String,
    tag: String,
    rule_ids: Vec<Uuid>,
    triggers: Vec<(String, &'static str)>,
}

impl Harness {
    async fn connect() -> Option<Self> {
        if std::env::var("SKIP_DB_TESTS").is_ok() {
            println!("Skipping (SKIP_DB_TESTS set)");
            return None;
        }
        let config = match DualPoolConfig::from_env() {
            Ok(c) => c,
            Err(e) => {
                println!("Skipping: no PG/CH configuration in the environment: {e}");
                return None;
            }
        };
        let dual_pool = match DualPool::new(&config).await {
            Ok(p) => p,
            Err(e) => {
                println!("Skipping: could not connect to PG+CH: {e}");
                return None;
            }
        };
        let pg = dual_pool.postgres().clone();
        let lookup = LookupService::new(PostgresLookupRepository::new(pg.clone()));
        let prevalence =
            PrevalenceService::new(dual_pool.clickhouse().clone(), dual_pool.table_names());
        // The probe rows are OCSF (`ocsf_logs`), the default schema.
        let svc = DetectionService::with_dual_pool_prevalence_and_profile(
            &dual_pool,
            lookup,
            prevalence,
            crate::schema::profile_for_id(crate::schema::SchemaId::Ocsf),
        );
        if let Err(e) = sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION nan5424_test_reject() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'nan5424 test-injected data error' USING ERRCODE = '22P05';
            END $$ LANGUAGE plpgsql
            "#,
        )
        .execute(&pg)
        .await
        {
            println!("Skipping: cannot create the test trigger function: {e}");
            return None;
        }
        let Ok(ch_url) = std::env::var("CLICKHOUSE_URL") else {
            println!("Skipping: CLICKHOUSE_URL not set");
            return None;
        };
        Some(Self {
            svc,
            repo: DetectionRuleRepository::new(pg.clone()),
            pg,
            http: reqwest::Client::new(),
            ch_url,
            ch_user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "nanosiem".into()),
            ch_pass: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default(),
            tag: format!("{:x}", Utc::now().timestamp_micros()),
            rule_ids: vec![],
            triggers: vec![],
        })
    }

    fn source_type(&self, name: &str) -> String {
        format!("nan5424_{name}_{}", self.tag)
    }

    /// Insert one probe event into `ocsf_logs` (synchronous insert, so it is
    /// queryable on return). `user` lands in `unmapped`, as HEC events do.
    async fn insert_event(&self, source_type: &str, message: &str, user: &str, ts: DateTime<Utc>) {
        let stmt = "INSERT INTO nanosiem.ocsf_logs (timestamp, id, source_type, message, `actor.user.name`, unmapped) FORMAT JSONEachRow";
        let url = format!(
            "{}/?query={}&async_insert=0&wait_end_of_query=1",
            self.ch_url,
            urlencoding::encode(stmt)
        );
        // serde_json writes U+0000 as the `\u0000` escape, exactly what an
        // upstream `json.dumps` produces.
        let row = json!({
            "timestamp": ts.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            "id": Uuid::now_v7().to_string(),
            "source_type": source_type,
            "message": message,
            "actor.user.name": user,
            "unmapped": {"user": user, "source_type": source_type},
        })
        .to_string();
        let resp = self
            .http
            .post(url)
            .basic_auth(&self.ch_user, Some(&self.ch_pass))
            .body(row)
            .send()
            .await
            .expect("CH insert");
        assert!(resp.status().is_success(), "CH insert: {}", resp.text().await.unwrap_or_default());
    }

    /// An alerting, marker-driven rule (no lookback) whose high-water mark
    /// sits `mark_ago` in the past.
    async fn create_rule(&mut self, name: &str, source_type: &str, alert_mode: &str, mark_ago: Duration) -> Uuid {
        self.create_rule_with(name, source_type, alert_mode, mark_ago, json!({})).await
    }

    async fn create_rule_with(
        &mut self,
        name: &str,
        source_type: &str,
        alert_mode: &str,
        mark_ago: Duration,
        extra: serde_json::Value,
    ) -> Uuid {
        let mut body = json!({
            "name": format!("nan5424 {name} {}", self.tag),
            "description": "NAN-5424 integration probe (auto-deleted)",
            "query": format!("source_type=\"{source_type}\""),
            "severity": "high",
            "mode": "alerting",
            // Far-off cron: a co-resident scheduler never claims it.
            "schedule_cron": "0 5 31 12 *",
            "alert_mode": alert_mode,
        });
        body.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
        let new: NewDetectionRule = serde_json::from_value(body).expect("NewDetectionRule");
        let rule = self.svc.create_rule(new).await.expect("create_rule");
        sqlx::query("UPDATE detection_rules SET last_run_at = $2 WHERE id = $1")
            .bind(rule.id)
            .bind(Utc::now() - mark_ago)
            .execute(&self.pg)
            .await
            .expect("seed last_run_at");
        self.rule_ids.push(rule.id);
        rule.id
    }

    /// Reject inserts into `table` matching `when` with SQLSTATE 22P05.
    async fn reject_inserts(&mut self, table: &'static str, when: &str) {
        let name = format!("nan5424_reject_{}_{}_{}", table, self.tag, self.triggers.len());
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE TRIGGER {name} BEFORE INSERT ON {table} FOR EACH ROW WHEN ({when}) \
             EXECUTE FUNCTION nan5424_test_reject()"
        )))
        .execute(&self.pg)
        .await
        .expect("create trigger");
        self.triggers.push((name, table));
    }

    async fn drop_triggers(&mut self) {
        for (name, table) in self.triggers.drain(..) {
            let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DROP TRIGGER IF EXISTS {name} ON {table}")))
                .execute(&self.pg)
                .await;
        }
    }

    /// One scheduler cycle: claim the rule as this node, then run the real
    /// `execute_and_release`.
    async fn cycle(&self, rule_id: Uuid) -> DetectionRule {
        let rule: DetectionRule = sqlx::query_as(
            // Mirrors `claim_due_rules` (incl. the in-flight count).
            "UPDATE detection_rules SET claimed_by = $2, claimed_at = NOW(), \
             inflight_claims = inflight_claims + 1 WHERE id = $1 RETURNING *",
        )
        .bind(rule_id)
        .bind(NODE)
        .fetch_one(&self.pg)
        .await
        .expect("claim");
        execute_and_release(
            &self.svc,
            &self.repo,
            &rule,
            NODE,
            &DistributedSchedulerConfig::default(),
        )
        .await;
        self.rule(rule_id).await
    }

    async fn rule(&self, rule_id: Uuid) -> DetectionRule {
        sqlx::query_as("SELECT * FROM detection_rules WHERE id = $1")
            .bind(rule_id)
            .fetch_one(&self.pg)
            .await
            .expect("rule")
    }

    async fn alert_events(&self, rule_id: Uuid) -> Vec<serde_json::Value> {
        let rows: Vec<(serde_json::Value,)> =
            sqlx::query_as("SELECT matched_events FROM alerts WHERE rule_id = $1 ORDER BY created_at")
                .bind(rule_id)
                .fetch_all(&self.pg)
                .await
                .expect("alerts");
        rows.into_iter()
            .flat_map(|(events,)| events.as_array().cloned().unwrap_or_default())
            .collect()
    }

    async fn gaps(&self, rule_id: Uuid) -> Vec<(DateTime<Utc>, DateTime<Utc>, i32, String)> {
        sqlx::query_as(
            "SELECT window_start, window_end, attempts, error_message FROM detection_coverage_gaps \
             WHERE rule_id = $1 ORDER BY recorded_at",
        )
        .bind(rule_id)
        .fetch_all(&self.pg)
        .await
        .expect("gaps")
    }

    async fn teardown(mut self) {
        self.drop_triggers().await;
        for id in &self.rule_ids {
            let _ = sqlx::query("DELETE FROM detection_rules WHERE id = $1")
                .bind(id)
                .execute(&self.pg)
                .await;
        }
    }
}

/// Every string anywhere in the alert's events, for content assertions.
fn event_text(events: &[serde_json::Value]) -> String {
    serde_json::to_string(events).unwrap()
}

#[tokio::test]
async fn nul_in_an_output_field_alerts_with_the_value_sanitized() {
    // The probe rows are OCSF; `#[tokio::test]` is current-thread, so the
    // pin covers every await below.
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    let Some(mut h) = Harness::connect().await else { return };
    let st = h.source_type("nul");
    let rule_id = h.create_rule("grouped nul", &st, "grouped", Duration::minutes(10)).await;
    h.insert_event(&st, "poison message \u{0000} body", "evil\u{0000}x", Utc::now() - Duration::minutes(5))
        .await;

    let before = h.rule(rule_id).await.last_run_at;
    let after = h.cycle(rule_id).await;

    let events = h.alert_events(rule_id).await;
    let text = event_text(&events);
    assert_eq!(events.len(), 1, "the event must alert: {text}");
    assert!(text.contains("evil\u{FFFD}x"), "value must be kept with U+FFFD: {text}");
    assert!(!text.contains("\\u0000"), "no NUL may reach PostgreSQL: {text}");
    assert!(after.last_run_at > before, "the marker must advance");
    assert_eq!(after.consecutive_failures, 0);
    let matches: i64 = sqlx::query_scalar("SELECT count(*) FROM detection_matches WHERE rule_id = $1")
        .bind(rule_id)
        .fetch_one(&h.pg)
        .await
        .unwrap();
    assert_eq!(matches, 1, "the detection match must be stored too");
    h.teardown().await;
}

#[tokio::test]
async fn a_poisoned_event_does_not_block_the_clean_events_in_its_batch() {
    // The probe rows are OCSF; `#[tokio::test]` is current-thread, so the
    // pin covers every await below.
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    let Some(mut h) = Harness::connect().await else { return };
    let st = h.source_type("batch");
    let rule_id = h.create_rule("per-event batch", &st, "per_event", Duration::minutes(10)).await;
    // An event PostgreSQL refuses even after sanitizing (injected 22P05),
    // plus a NUL event and two clean events in the same window.
    let marker = format!("unstorable-{}", h.tag);
    h.reject_inserts("alerts", &format!("NEW.matched_events::text LIKE '%{marker}%'"))
        .await;
    let base = Utc::now() - Duration::minutes(6);
    h.insert_event(&st, "clean one", "alice", base).await;
    h.insert_event(&st, &marker, "mallory", base + Duration::seconds(1)).await;
    h.insert_event(&st, "nul event", "evil\u{0000}x", base + Duration::seconds(2)).await;
    h.insert_event(&st, "clean two", "bob", base + Duration::seconds(3)).await;

    let before = h.rule(rule_id).await.last_run_at;
    let after = h.cycle(rule_id).await;

    let text = event_text(&h.alert_events(rule_id).await);
    for expected in ["alice", "bob", "evil\u{FFFD}x"] {
        assert!(text.contains(expected), "{expected} must alert: {text}");
    }
    assert!(!text.contains(&marker), "the refused event is skipped");
    assert!(after.last_run_at > before, "a skipped event must not pin the rule");
    let error = after.last_error.clone().unwrap_or_default();
    assert!(error.contains("1 of 4 matched event(s)"), "skip must be recorded: {error:?}");
    assert!(error.contains("SQLSTATE 22P05") && !error.contains("test-injected"), "{error:?}");
    assert!(after.last_error_at.is_some());
    // Durable evidence: identifiers + SQLSTATE, and a reference alert.
    let skipped: Vec<(String, Option<String>, Option<Uuid>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT event_id, sqlstate, reference_alert_id, window_start FROM detection_skipped_events WHERE rule_id = $1",
    )
    .bind(rule_id)
    .fetch_all(&h.pg)
    .await
    .unwrap();
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    assert_eq!(skipped[0].1.as_deref(), Some("22P05"));
    assert!(skipped[0].2.is_some(), "a reference alert was raised");
    assert!(skipped[0].3.is_some(), "the window is recorded");
    assert!(text.contains("_nano_unstored_event"), "the reference alert is visible: {text}");
    h.teardown().await;
}

#[tokio::test]
async fn a_persistent_data_error_narrows_retries_then_gaps_only_the_minimum_slice() {
    // The probe rows are OCSF; `#[tokio::test]` is current-thread, so the
    // pin covers every await below.
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    let Some(mut h) = Harness::connect().await else { return };
    let st = h.source_type("persist");
    let rule_id = h.create_rule("grouped persistent", &st, "grouped", Duration::minutes(10)).await;
    h.reject_inserts("detection_matches", &format!("NEW.rule_id = '{rule_id}'::uuid"))
        .await;
    // Inside the first minimum slice after the mark.
    h.insert_event(&st, "any event", "alice", Utc::now() - Duration::minutes(8)).await;
    let mark = h.rule(rule_id).await.last_run_at.unwrap();

    let mut cycles = 0;
    let gaps = loop {
        cycles += 1;
        assert!(cycles <= 12, "the window must be gapped after a bounded number of attempts");
        let rule = h.cycle(rule_id).await;
        let gaps = h.gaps(rule_id).await;
        if !gaps.is_empty() {
            break gaps;
        }
        assert_eq!(rule.last_run_at, Some(mark), "cycle {cycles}: the window is retried");
        assert!(rule.failing_since.is_some());
        assert_eq!(
            rule.last_error.as_deref(),
            Some("[data] PostgreSQL error (SQLSTATE 22P05)"),
            "the rule shows the class and SQLSTATE, not the database's text"
        );
        let health = crate::detection::health::read_execution_health(&h.pg).await.unwrap();
        assert_eq!(health.status, "critical", "a failing rule is a critical detection finding");
        assert!(health.currently_failing_rules >= 1);
    };
    assert_eq!(gaps.len(), 1, "one coverage gap");
    let (start, end, attempts, error) = &gaps[0];
    assert_eq!(*start, mark - Duration::seconds(5));
    assert!(
        *end - *start <= Duration::minutes(MIN_CATCHUP_CHUNK_MINUTES) + Duration::seconds(5),
        "only the minimum slice is gapped, not the whole window: {start} → {end}"
    );
    assert_eq!(*attempts, i32::from(DATA_FAILURE_ATTEMPTS));
    assert_eq!(error, "[data] PostgreSQL error (SQLSTATE 22P05)");
    let rule = h.rule(rule_id).await;
    assert_eq!(rule.consecutive_failures, 0);
    let failing = crate::detection::health::list_failing_rules(&h.pg, 500).await.unwrap();
    assert!(failing.iter().any(|r| r.rule_id == rule_id), "SIEM Health lists the rule");

    // The rest of the window is evaluated normally after the gap.
    h.drop_triggers().await;
    h.insert_event(&st, "after recovery", "bob", Utc::now() - Duration::seconds(30)).await;
    let mut rule = h.cycle(rule_id).await;
    for _ in 0..5 {
        if rule.last_run_at >= Some(Utc::now() - Duration::seconds(10)) {
            break;
        }
        rule = h.cycle(rule_id).await;
    }
    assert!(rule.last_run_at > Some(*end), "the marker-driven rule advances");
    let text = event_text(&h.alert_events(rule_id).await);
    assert!(text.contains("bob"), "{text}");
    assert!(!text.contains("alice"), "the gapped slice was not evaluated");
    h.teardown().await;
}

#[tokio::test]
async fn editing_a_rule_resets_its_failure_streak() {
    let Some(mut h) = Harness::connect().await else { return };
    let st = h.source_type("edit");
    let rule_id = h.create_rule("edit reset", &st, "grouped", Duration::minutes(10)).await;
    sqlx::query(
        "UPDATE detection_rules SET consecutive_failures = 4, failing_since = NOW(), \
         failure_class = 'data', catchup_size_failures = 2 WHERE id = $1",
    )
    .bind(rule_id)
    .execute(&h.pg)
    .await
    .unwrap();
    let update: crate::models::UpdateDetectionRule =
        serde_json::from_value(json!({"description": "edited"})).unwrap();
    h.svc.update_rule(rule_id, update).await.expect("update_rule");
    let counters = h.repo.get_failure_counters(rule_id).await.unwrap();
    assert_eq!(counters, RuleFailureCounters::default(), "an edit starts a fresh streak");
    h.teardown().await;
}

#[tokio::test]
async fn claims_that_never_released_are_counted_and_cleared() {
    let Some(mut h) = Harness::connect().await else { return };
    let st = h.source_type("crash");
    let rule_id = h.create_rule("crash count", &st, "grouped", Duration::minutes(10)).await;
    // Three claims that died mid-run, then the current one.
    sqlx::query("UPDATE detection_rules SET inflight_claims = 4 WHERE id = $1")
        .bind(rule_id)
        .execute(&h.pg)
        .await
        .unwrap();
    assert_eq!(h.repo.get_failure_counters(rule_id).await.unwrap().crashed_attempts, 3);
    h.cycle(rule_id).await;
    let inflight: i16 = sqlx::query_scalar("SELECT inflight_claims FROM detection_rules WHERE id = $1")
        .bind(rule_id)
        .fetch_one(&h.pg)
        .await
        .unwrap();
    assert_eq!(inflight, 0, "a release clears the in-flight count");
    h.teardown().await;
}

#[tokio::test]
async fn a_nul_entity_alerts_and_its_cooldown_key_still_suppresses() {
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    let Some(mut h) = Harness::connect().await else { return };
    let st = h.source_type("cooldown");
    // The cooldown lookup binds the entity as text before any jsonb write.
    let rule_id = h
        .create_rule_with(
            "grouped cooldown",
            &st,
            "grouped",
            Duration::minutes(10),
            json!({"risk_entity_field": "actor.user.name", "alert_cooldown_minutes": 60}),
        )
        .await;
    h.insert_event(&st, "first", "h\u{0000}x", Utc::now() - Duration::minutes(5)).await;
    let rule = h.cycle(rule_id).await;
    assert_eq!(rule.consecutive_failures, 0, "{:?}", rule.last_error);
    assert_eq!(h.alert_events(rule_id).await.len(), 1, "the NUL entity must alert");
    let anchors: Vec<(String,)> =
        sqlx::query_as("SELECT entity FROM detection_alert_entity_cooldowns WHERE rule_id = $1")
            .bind(rule_id)
            .fetch_all(&h.pg)
            .await
            .unwrap();
    assert_eq!(anchors, vec![("h\u{FFFD}x".to_string(),)], "anchor stored sanitized");

    // Same entity again, newer activity: the cooldown (looked up with the
    // sanitized key) suppresses it and the rule keeps running.
    h.insert_event(&st, "second", "h\u{0000}x", Utc::now() - Duration::seconds(20)).await;
    let rule = h.cycle(rule_id).await;
    assert_eq!(rule.consecutive_failures, 0, "{:?}", rule.last_error);
    assert_eq!(h.alert_events(rule_id).await.len(), 1, "cooldown must still apply");
    h.teardown().await;
}

#[tokio::test]
async fn a_long_entity_is_anchored_and_its_cooldown_suppresses() {
    // NAN-5429: an entity longer than a btree index entry (~2.7 KB) that does
    // not compress must still get a cooldown anchor.
    let _ocsf = crate::schema::pin_active_schema_for_test(crate::schema::SchemaId::Ocsf);
    let Some(mut h) = Harness::connect().await else { return };
    let st = h.source_type("cooldown-long");
    let rule_id = h
        .create_rule_with(
            "grouped cooldown long entity",
            &st,
            "grouped",
            Duration::minutes(10),
            json!({"risk_entity_field": "actor.user.name", "alert_cooldown_minutes": 60}),
        )
        .await;
    let long: String = (0..132).map(|_| Uuid::new_v4().simple().to_string()).collect();
    assert!(long.len() > 4000);
    h.insert_event(&st, "first", &long, Utc::now() - Duration::minutes(5)).await;
    let rule = h.cycle(rule_id).await;
    assert_eq!(rule.consecutive_failures, 0, "{:?}", rule.last_error);
    assert_eq!(h.alert_events(rule_id).await.len(), 1);
    let anchors: Vec<(String,)> =
        sqlx::query_as("SELECT entity FROM detection_alert_entity_cooldowns WHERE rule_id = $1")
            .bind(rule_id)
            .fetch_all(&h.pg)
            .await
            .unwrap();
    assert_eq!(anchors, vec![(long.clone(),)], "full value kept next to the digest key");

    h.insert_event(&st, "second", &long, Utc::now() - Duration::seconds(20)).await;
    let rule = h.cycle(rule_id).await;
    assert_eq!(rule.consecutive_failures, 0, "{:?}", rule.last_error);
    assert_eq!(h.alert_events(rule_id).await.len(), 1, "cooldown must apply to the long entity");
    h.teardown().await;
}

#[tokio::test]
async fn the_shared_alert_and_match_writes_sanitize_for_every_producer() {
    // The real-time signal processor and the observability evaluators write
    // through these same functions.
    let Some(mut h) = Harness::connect().await else { return };
    let st = h.source_type("shared");
    let rule_id = h.create_rule("shared writes", &st, "per_event", Duration::minutes(10)).await;
    let rule = h.rule(rule_id).await;
    let events = vec![json!({"id": Uuid::now_v7().to_string(), "k\u{0000}": "v\u{0000}", "source_type": "s\u{0000}t"})];
    let alert = crate::db::repository::AlertRepository::new(h.pg.clone())
        .create(&crate::models::NewAlert {
            rule_id,
            severity: rule.severity,
            matched_events: serde_json::Value::Array(events.clone()),
            event_hash: None,
            match_count: Some(1),
        })
        .await
        .expect("alert insert must not fail on U+0000");
    let text = serde_json::to_string(&alert.matched_events).unwrap();
    assert!(text.contains("v\u{FFFD}") && text.contains("k\u{FFFD}"), "{text}");
    crate::detection::service::helpers::store_detection_match_with_pool(&h.pg, &rule, &events)
        .await
        .expect("detection match insert must not fail on U+0000");
    h.teardown().await;
}

#[tokio::test]
async fn a_gap_recorded_from_an_error_quoting_event_bytes_is_stored_sanitized() {
    let Some(mut h) = Harness::connect().await else { return };
    let st = h.source_type("gaperr");
    let rule_id = h.create_rule("gap error text", &st, "grouped", Duration::minutes(10)).await;
    sqlx::query("UPDATE detection_rules SET claimed_by = $2, claimed_at = NOW() WHERE id = $1")
        .bind(rule_id)
        .bind(NODE)
        .execute(&h.pg)
        .await
        .unwrap();
    // ClickHouse / PostgreSQL errors can quote the row verbatim.
    let raw = "Code: 6. Cannot parse input: 'a\u{0000}b\nFAKE LOG LINE\x1b[31m'";
    let end = Utc::now();
    let gap = DetectionCoverageGap {
        window_start: end - Duration::minutes(5),
        window_end: end,
        attempts: 3,
        error_message: raw.to_string(),
    };
    h.repo
        .release_claim(
            rule_id,
            NODE,
            &ClaimRelease {
                next_run_at: end + Duration::minutes(1),
                advance_last_run_to: Some(end),
                catchup_size_failures: 0,
                consecutive_failures: 0,
                failing_since: None,
                failure_class: None,
                error: Some(raw),
                coverage_gap: Some(&gap),
            },
        )
        .await
        .expect("recording the gap must not fail on the error's own bytes");
    let gaps = h.gaps(rule_id).await;
    assert_eq!(gaps.len(), 1, "the gap row exists");
    let stored = &gaps[0].3;
    assert!(stored.contains("a\u{FFFD}b FAKE LOG LINE"), "{stored:?}");
    assert!(!stored.contains('\n') && !stored.contains('\x1b'), "{stored:?}");
    let rule = h.rule(rule_id).await;
    assert_eq!(rule.last_run_at, Some(end), "the marker moved with the gap");
    assert_eq!(rule.last_error.as_deref(), Some(stored.as_str()));
    // SIEM Health reads the same sanitized text.
    let failing = crate::detection::health::list_failing_rules(&h.pg, 500).await.unwrap();
    let listed = failing.iter().find(|r| r.rule_id == rule_id).expect("listed");
    assert!(!listed.last_error.as_deref().unwrap_or("").contains('\n'));
    let health = crate::detection::health::read_execution_health(&h.pg).await.unwrap();
    assert_eq!(health.status, "critical", "a recorded gap is a critical detection finding");
    h.teardown().await;
}
