// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5785: a log source's live "stopped sending" alert when the source is
//! deleted, disabled, or has stale alerting turned off.
//!
//! The contract: a source mutation never closes a real alert (that would let
//! `log_sources:edit` / `log_sources:delete` silence a blinded feed and resolve
//! its paging incident). The alert stays active, flagged and retitled with who
//! removed the source, and its destinations get a reminder, never a
//! resolution. Only data that arrived after the alert opened resolves it.
//!
//! Against migrated PostgreSQL. Ignored in ordinary unit runs; the
//! pg-integration-tests lane runs it with `--ignored --test-threads=1` (the
//! sweep is table-wide). Every test uses fresh ids and deletes what it made.

mod common;

use chrono::{Duration, Utc};
use nanosiem_core::health::deleted_sources::{
    flag_removed_source_health, sweep_orphaned_log_source_health, SourceRemoval, UNRECORDED_ACTOR,
};
use nanosiem_core::health::HealthRepository;
use nanosiem_core::log_sources::LogSourceRepository;
use nanosiem_core::parsers::ParserRepository;
use nanosiem_core::system_health::{
    HealthCategory, HealthSeverity, PublishHealthEvent, SystemHealthEvent, SystemHealthRepository,
};
use sqlx::PgPool;
use uuid::Uuid;

/// Rows one test created. Each test reads what it asserts on, calls `clean`,
/// and only then asserts, so even a failing test leaves nothing behind.
#[derive(Default)]
struct Made {
    sources: Vec<Uuid>,
    events: Vec<Uuid>,
    webhooks: Vec<Uuid>,
}

impl Made {
    async fn clean(&self, pool: &PgPool) {
        let keys: Vec<String> = self.sources.iter().map(Uuid::to_string).collect();
        // Outbox rows cascade from their event and webhook.
        sqlx::query("DELETE FROM system_health_events WHERE id = ANY($1) OR resource_id = ANY($2)")
            .bind(&self.events)
            .bind(&keys)
            .execute(pool)
            .await
            .expect("clean events");
        sqlx::query("DELETE FROM health_issue_tracker WHERE issue_key = ANY($1)")
            .bind(&keys)
            .execute(pool)
            .await
            .expect("clean issues");
        sqlx::query("DELETE FROM log_sources WHERE id = ANY($1)")
            .bind(&self.sources)
            .execute(pool)
            .await
            .expect("clean sources");
        sqlx::query("DELETE FROM log_source_tombstones WHERE log_source_id = ANY($1)")
            .bind(&self.sources)
            .execute(pool)
            .await
            .expect("clean tombstones");
        sqlx::query("DELETE FROM webhooks WHERE id = ANY($1)")
            .bind(&self.webhooks)
            .execute(pool)
            .await
            .expect("clean webhooks");
    }
}

async fn create_source(pool: &PgPool, made: &mut Made, label: &str) -> Uuid {
    let id = Uuid::now_v7();
    let name = format!("nan5785_{label}_{}", id.simple());
    sqlx::query(
        "INSERT INTO log_sources
             (id, name, source_type, parser_vrl, match_values, deployed, deployed_at, enabled, stale_alert_enabled)
         VALUES ($1, $2, 'routed', '.', ARRAY[$2], true, now(), true, true)",
    )
    .bind(id)
    .bind(&name)
    .execute(pool)
    .await
    .expect("create log source");
    made.sources.push(id);
    id
}

/// A destination subscribed to every health event, so lifecycle fan-out is
/// observable in the outbox.
async fn create_webhook(pool: &PgPool, made: &mut Made) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO webhooks (id, name, url, channel_type, enabled, event_types)
         VALUES ($1, $2, 'https://hooks.example.invalid/nan5785', 'generic', true, '{}')",
    )
    .bind(id)
    .bind(format!("nan5785-{}", id.simple()))
    .execute(pool)
    .await
    .expect("create webhook");
    made.webhooks.push(id);
    id
}

fn stale_event(id: Uuid) -> PublishHealthEvent {
    let mut event = PublishHealthEvent::new(
        format!("log_source:{id}:stale"),
        HealthCategory::LogSource,
        HealthSeverity::High,
        format!("Log source stopped sending: {id}"),
        "No data received for 20 minutes; configured stale threshold is 15 minutes.",
        "log_source",
        "health_scheduler.feed_monitor",
    );
    event.resource_id = Some(id.to_string());
    event.resource_name = Some(id.to_string());
    event
}

/// What the feed monitor raises for a stale source: the alert and its
/// notification de-dup row.
async fn raise_stale(pool: &PgPool, made: &mut Made, id: Uuid) -> SystemHealthEvent {
    let event = SystemHealthRepository::new(pool.clone())
        .publish(&stale_event(id))
        .await
        .expect("publish stale event");
    made.events.push(event.id);
    sqlx::query(
        "INSERT INTO health_issue_tracker (issue_type, issue_key) VALUES ('data_feed', $1)
         ON CONFLICT (issue_type, issue_key) DO UPDATE SET resolved_at = NULL",
    )
    .bind(id.to_string())
    .execute(pool)
    .await
    .expect("open data-feed issue");
    event
}

/// (status, title, source_removed.action, source_removed.by)
async fn alert(pool: &PgPool, id: Uuid) -> (String, String, Option<String>, Option<String>) {
    sqlx::query_as(
        "SELECT status, title, diagnostic_context->'source_removed'->>'action',
                diagnostic_context->'source_removed'->>'by'
         FROM system_health_events WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("alert row")
}

async fn issue_open(pool: &PgPool, key: &str) -> bool {
    sqlx::query_scalar(
        "SELECT resolved_at IS NULL FROM health_issue_tracker
         WHERE issue_type = 'data_feed' AND issue_key = $1",
    )
    .bind(key)
    .fetch_one(pool)
    .await
    .expect("issue row")
}

async fn outbox_actions(pool: &PgPool, event: Uuid, webhook: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_action FROM system_health_outbox WHERE event_id = $1 AND webhook_id = $2
         ORDER BY event_action",
    )
    .bind(event)
    .bind(webhook)
    .fetch_all(pool)
    .await
    .expect("outbox rows")
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn deleting_a_source_flags_its_live_alert_and_never_resolves_it() {
    let pool = common::migrated_pool().await;
    let mut made = Made::default();
    let webhook = create_webhook(&pool, &mut made).await;
    let kept = create_source(&pool, &mut made, "kept").await;
    let single = create_source(&pool, &mut made, "single").await;
    let bulk_a = create_source(&pool, &mut made, "bulk_a").await;
    let bulk_b = create_source(&pool, &mut made, "bulk_b").await;
    let parser = create_source(&pool, &mut made, "parser").await;
    let mut alerts = std::collections::HashMap::new();
    for id in [kept, single, bulk_a, bulk_b, parser] {
        alerts.insert(id, raise_stale(&pool, &mut made, id).await);
    }

    // Every delete path; the API flags with the actor right after.
    let sources = LogSourceRepository::new(pool.clone());
    sources.delete(single).await.expect("single delete");
    sources.delete_many(&[bulk_a, bulk_b]).await.expect("bulk delete");
    ParserRepository::new(pool.clone()).delete(parser).await.expect("parser repository delete");
    // The repository delete by itself closes nothing.
    assert_eq!(alert(&pool, alerts[&single].id).await.0, "active");
    let flagged = flag_removed_source_health(&pool, &[single, bulk_a, bulk_b], SourceRemoval::Deleted, "Alice").await;
    let parser_flagged = flag_removed_source_health(&pool, &[parser], SourceRemoval::Deleted, "Bob").await;

    let results: Vec<_> = {
        let mut r = Vec::new();
        for (id, by) in [(single, "Alice"), (bulk_a, "Alice"), (bulk_b, "Alice"), (parser, "Bob")] {
            r.push((id, by, alert(&pool, alerts[&id].id).await, issue_open(&pool, &id.to_string()).await,
                    outbox_actions(&pool, alerts[&id].id, webhook).await));
        }
        r
    };
    let kept_state = (alert(&pool, alerts[&kept].id).await, issue_open(&pool, &kept.to_string()).await);
    made.clean(&pool).await;

    assert_eq!(flagged.len(), 3);
    assert_eq!(parser_flagged.len(), 1);
    for (id, by, (status, title, action, flagged_by), issue, outbox) in results {
        assert_eq!(status, "active", "a delete never resolves the alert ({id})");
        assert_eq!(title, format!("Log source stopped sending: {id} (source deleted by {by})"));
        assert_eq!(action.as_deref(), Some("deleted"));
        assert_eq!(flagged_by.as_deref(), Some(by));
        assert!(!issue, "a deleted source's notification de-dup row is closed");
        assert_eq!(outbox, ["reminder", "triggered"], "the destination is reminded, never resolved");
    }
    let ((status, title, action, _), issue) = kept_state;
    assert_eq!((status.as_str(), action), ("active", None), "a surviving source is untouched");
    assert_eq!(title, format!("Log source stopped sending: {kept}"));
    assert!(issue);
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn disabling_a_source_or_its_stale_alerting_flags_the_alert_and_keeps_it_open() {
    let pool = common::migrated_pool().await;
    let mut made = Made::default();
    let webhook = create_webhook(&pool, &mut made).await;
    let disabled = create_source(&pool, &mut made, "disabled").await;
    let alerting_off = create_source(&pool, &mut made, "alerting_off").await;
    let disabled_alert = raise_stale(&pool, &mut made, disabled).await;
    let off_alert = raise_stale(&pool, &mut made, alerting_off).await;
    sqlx::query("UPDATE log_sources SET enabled = false WHERE id = $1")
        .bind(disabled)
        .execute(&pool)
        .await
        .expect("disable");
    sqlx::query("UPDATE log_sources SET stale_alert_enabled = false WHERE id = $1")
        .bind(alerting_off)
        .execute(&pool)
        .await
        .expect("stale alerting off");

    flag_removed_source_health(&pool, &[disabled], SourceRemoval::Disabled, "Mallory").await;
    flag_removed_source_health(&pool, &[alerting_off], SourceRemoval::StaleAlertingOff, "Mallory").await;
    // A repeat of the same removal changes nothing; a different one replaces
    // the suffix instead of stacking it.
    let repeat = flag_removed_source_health(&pool, &[disabled], SourceRemoval::Disabled, "Mallory").await;
    flag_removed_source_health(&pool, &[alerting_off], SourceRemoval::Disabled, "Eve").await;
    // The sweep (deleted sources only) leaves both alone, and their
    // notification de-dup rows stay open.
    sweep_orphaned_log_source_health(&SystemHealthRepository::new(pool.clone()), &HealthRepository::new(pool.clone()))
        .await;

    let disabled_state = alert(&pool, disabled_alert.id).await;
    let off_state = alert(&pool, off_alert.id).await;
    let issues = (issue_open(&pool, &disabled.to_string()).await, issue_open(&pool, &alerting_off.to_string()).await);
    let outbox = outbox_actions(&pool, disabled_alert.id, webhook).await;
    made.clean(&pool).await;

    assert!(repeat.is_empty(), "re-flagging the same removal is a no-op");
    assert_eq!(
        disabled_state,
        (
            "active".to_string(),
            format!("Log source stopped sending: {disabled} (source disabled by Mallory)"),
            Some("disabled".to_string()),
            Some("Mallory".to_string())
        )
    );
    assert_eq!(
        off_state,
        (
            "active".to_string(),
            format!("Log source stopped sending: {alerting_off} (source disabled by Eve)"),
            Some("disabled".to_string()),
            Some("Eve".to_string())
        )
    );
    assert_eq!(issues, (true, true), "disabling never closes the notification de-dup row");
    assert_eq!(outbox, ["reminder", "triggered"]);
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn the_sweep_flags_unflagged_deleted_sources_and_touches_nothing_else() {
    let pool = common::migrated_pool().await;
    let mut made = Made::default();
    let monitored = create_source(&pool, &mut made, "monitored").await;
    let gone = create_source(&pool, &mut made, "gone").await;
    let monitored_alert = raise_stale(&pool, &mut made, monitored).await;
    let gone_alert = raise_stale(&pool, &mut made, gone).await;
    // Unrelated health state the sweep must not touch.
    let storage = SystemHealthRepository::new(pool.clone())
        .publish(&{
            let mut e = PublishHealthEvent::new(
                format!("storage:nan5785:{}", Uuid::now_v7().simple()),
                HealthCategory::Storage,
                HealthSeverity::High,
                "Disk filling",
                "nan5785 unrelated",
                "storage",
                "nan5785_test",
            );
            e.resource_id = Some(Uuid::now_v7().to_string());
            e
        })
        .await
        .expect("unrelated event");
    made.events.push(storage.id);
    let ai_key = format!("nan5785-{}", Uuid::now_v7().simple());
    sqlx::query("INSERT INTO health_issue_tracker (issue_type, issue_key) VALUES ('ai_provider', $1)")
        .bind(&ai_key)
        .execute(&pool)
        .await
        .expect("unrelated issue");
    // A delete with no flag (raw SQL, or a path without an actor).
    sqlx::query("DELETE FROM log_sources WHERE id = $1")
        .bind(gone)
        .execute(&pool)
        .await
        .expect("raw delete");

    let system_health = SystemHealthRepository::new(pool.clone());
    let health = HealthRepository::new(pool.clone());
    let flagged = sweep_orphaned_log_source_health(&system_health, &health).await;
    let again = sweep_orphaned_log_source_health(&system_health, &health).await;

    let gone_state = alert(&pool, gone_alert.id).await;
    let monitored_state = alert(&pool, monitored_alert.id).await;
    let storage_status: String = sqlx::query_scalar("SELECT status FROM system_health_events WHERE id = $1")
        .bind(storage.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let ai_open: bool = sqlx::query_scalar(
        "SELECT resolved_at IS NULL FROM health_issue_tracker WHERE issue_type = 'ai_provider' AND issue_key = $1",
    )
    .bind(&ai_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    let gone_issue = issue_open(&pool, &gone.to_string()).await;
    let monitored_issue = issue_open(&pool, &monitored.to_string()).await;
    sqlx::query("DELETE FROM health_issue_tracker WHERE issue_type = 'ai_provider' AND issue_key = $1")
        .bind(&ai_key)
        .execute(&pool)
        .await
        .unwrap();
    made.clean(&pool).await;

    assert!(flagged.iter().any(|(e, r)| e.id == gone_alert.id && *r == SourceRemoval::Deleted), "the sweep reports what it flagged (to audit)");
    assert!(!again.iter().any(|(e, _)| e.id == gone_alert.id), "a flagged alert is not re-flagged");
    assert_eq!(gone_state.0, "active", "the sweep never resolves");
    assert_eq!(gone_state.2.as_deref(), Some("deleted"));
    assert_eq!(gone_state.3.as_deref(), Some(UNRECORDED_ACTOR));
    assert!(!gone_issue);
    assert_eq!((monitored_state.0.as_str(), monitored_state.2), ("active", None));
    assert!(monitored_issue);
    assert_eq!(storage_status, "active");
    assert!(ai_open);
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn only_data_after_the_alert_opened_resolves_it_and_a_racing_publish_keeps_the_delete_flag() {
    let pool = common::migrated_pool().await;
    let mut made = Made::default();
    let quiet = create_source(&pool, &mut made, "quiet").await;
    let deleted = create_source(&pool, &mut made, "deleted").await;
    let quiet_alert = raise_stale(&pool, &mut made, quiet).await;
    let deleted_alert = raise_stale(&pool, &mut made, deleted).await;
    let repo = SystemHealthRepository::new(pool.clone());
    let key = format!("log_source:{quiet}:stale");

    // A raised threshold (or a grace window) makes the source "not stale" with
    // its last event still older than the alert: not a recovery.
    let early = repo
        .resolve_recovered(&key, quiet_alert.first_seen_at - Duration::minutes(30))
        .await
        .expect("early");
    let still = alert(&pool, quiet_alert.id).await.0;
    let late = repo.resolve_recovered(&key, Utc::now() + Duration::seconds(1)).await.expect("late");

    // A stale pass that listed the source before its delete publishes after
    // the flag: the attributed flag survives.
    LogSourceRepository::new(pool.clone()).delete(deleted).await.expect("delete");
    flag_removed_source_health(&pool, &[deleted], SourceRemoval::Deleted, "Alice").await;
    repo.publish(&stale_event(deleted)).await.expect("racing publish");
    let raced = alert(&pool, deleted_alert.id).await;
    made.clean(&pool).await;

    assert!(early.is_none());
    assert_eq!(still, "active");
    assert_eq!(late.map(|e| e.status), Some("resolved".to_string()));
    assert_eq!(raced.0, "active");
    assert_eq!(raced.1, format!("Log source stopped sending: {deleted} (source deleted by Alice)"));
    assert_eq!(raced.3.as_deref(), Some("Alice"));
}

async fn reminders(pool: &PgPool, event: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM system_health_outbox WHERE event_id = $1 AND event_action = 'reminder'")
        .bind(event)
        .fetch_one(pool)
        .await
        .expect("reminder count")
}

/// Review round 2: a flag only escalates (deleted > disabled > stale alerting
/// off), so repeated or alternating removals send no further reminders and a
/// weaker removal never hides a stronger one.
#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn flags_only_escalate_so_repeats_and_alternation_cannot_spam() {
    let pool = common::migrated_pool().await;
    let mut made = Made::default();
    let webhook = create_webhook(&pool, &mut made).await;
    let id = create_source(&pool, &mut made, "escalate").await;
    let event = raise_stale(&pool, &mut made, id).await;

    let first = flag_removed_source_health(&pool, &[id], SourceRemoval::Disabled, "Mallory").await.len();
    // Mark the reminder delivered: a re-flag would be free to enqueue another.
    sqlx::query("UPDATE system_health_outbox SET status = 'delivered' WHERE event_id = $1")
        .bind(event.id)
        .execute(&pool)
        .await
        .unwrap();
    let mut repeats = 0;
    for _ in 0..3 {
        repeats += flag_removed_source_health(&pool, &[id], SourceRemoval::StaleAlertingOff, "Mallory").await.len();
        repeats += flag_removed_source_health(&pool, &[id], SourceRemoval::Disabled, "Mallory").await.len();
    }
    let after_repeats = (alert(&pool, event.id).await, reminders(&pool, event.id).await);
    let escalated = flag_removed_source_health(&pool, &[id], SourceRemoval::Deleted, "Alice").await.len();
    let after_delete = alert(&pool, event.id).await;
    let outbox = outbox_actions(&pool, event.id, webhook).await;
    made.clean(&pool).await;

    assert_eq!(first, 1);
    assert_eq!(repeats, 0, "no re-flag on repeats or a weaker removal");
    let ((status, title, action, by), reminder_rows) = after_repeats;
    assert_eq!(status, "active");
    assert_eq!(title, format!("Log source stopped sending: {id} (source disabled by Mallory)"));
    assert_eq!((action.as_deref(), by.as_deref()), (Some("disabled"), Some("Mallory")));
    assert_eq!(reminder_rows, 1, "one reminder for the one flag");
    assert_eq!(escalated, 1, "a stronger removal still flags");
    assert_eq!(after_delete.1, format!("Log source stopped sending: {id} (source deleted by Alice)"));
    assert!(outbox.iter().all(|a| a != "resolved"));
}

/// Review round 2: a stale pass that publishes after a disable (or a stale
/// alerting off) keeps the attributed flag while the source stays
/// unmonitored, and clears it only once the source is monitored again.
#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn a_racing_publish_keeps_any_removal_flag_until_monitoring_resumes() {
    let pool = common::migrated_pool().await;
    let mut made = Made::default();
    let disabled = create_source(&pool, &mut made, "race_disabled").await;
    let alerting_off = create_source(&pool, &mut made, "race_alerting_off").await;
    let d_event = raise_stale(&pool, &mut made, disabled).await;
    let o_event = raise_stale(&pool, &mut made, alerting_off).await;
    sqlx::query("UPDATE log_sources SET enabled = false WHERE id = $1").bind(disabled).execute(&pool).await.unwrap();
    sqlx::query("UPDATE log_sources SET stale_alert_enabled = false WHERE id = $1")
        .bind(alerting_off)
        .execute(&pool)
        .await
        .unwrap();
    flag_removed_source_health(&pool, &[disabled], SourceRemoval::Disabled, "Mallory").await;
    flag_removed_source_health(&pool, &[alerting_off], SourceRemoval::StaleAlertingOff, "Mallory").await;
    let repo = SystemHealthRepository::new(pool.clone());
    repo.publish(&stale_event(disabled)).await.unwrap();
    repo.publish(&stale_event(alerting_off)).await.unwrap();
    let raced = (alert(&pool, d_event.id).await, alert(&pool, o_event.id).await);

    // Monitoring resumes and the source is still stale: the live condition
    // takes the alert back.
    sqlx::query("UPDATE log_sources SET enabled = true WHERE id = $1").bind(disabled).execute(&pool).await.unwrap();
    repo.publish(&stale_event(disabled)).await.unwrap();
    let resumed = alert(&pool, d_event.id).await;
    made.clean(&pool).await;

    let (d, o) = raced;
    assert_eq!(d.1, format!("Log source stopped sending: {disabled} (source disabled by Mallory)"));
    assert_eq!((d.2.as_deref(), d.3.as_deref()), (Some("disabled"), Some("Mallory")));
    assert_eq!(o.1, format!("Log source stopped sending: {alerting_off} (stale alerting turned off by Mallory)"));
    assert_eq!(o.2.as_deref(), Some("stale_alerting_off"));
    assert_eq!(resumed.1, format!("Log source stopped sending: {disabled}"));
    assert_eq!(resumed.2, None);
}

/// Review round 2: a stale alert a racing pass RAISED (none existed when the
/// API flagged) for a source already disabled / with stale alerting off is
/// flagged by the next sweep, never left unexplained.
#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn the_sweep_flags_a_new_alert_raised_for_an_unmonitored_source() {
    let pool = common::migrated_pool().await;
    let mut made = Made::default();
    let disabled = create_source(&pool, &mut made, "late_disabled").await;
    let alerting_off = create_source(&pool, &mut made, "late_alerting_off").await;
    sqlx::query("UPDATE log_sources SET enabled = false WHERE id = $1").bind(disabled).execute(&pool).await.unwrap();
    sqlx::query("UPDATE log_sources SET stale_alert_enabled = false WHERE id = $1")
        .bind(alerting_off)
        .execute(&pool)
        .await
        .unwrap();
    let d_event = raise_stale(&pool, &mut made, disabled).await;
    let o_event = raise_stale(&pool, &mut made, alerting_off).await;

    let system_health = SystemHealthRepository::new(pool.clone());
    let health = HealthRepository::new(pool.clone());
    let flagged = sweep_orphaned_log_source_health(&system_health, &health).await;
    let again = sweep_orphaned_log_source_health(&system_health, &health).await;
    let states = (alert(&pool, d_event.id).await, alert(&pool, o_event.id).await);
    made.clean(&pool).await;

    assert!(flagged.iter().any(|(e, r)| e.id == d_event.id && *r == SourceRemoval::Disabled));
    assert!(flagged.iter().any(|(e, r)| e.id == o_event.id && *r == SourceRemoval::StaleAlertingOff));
    assert!(!again.iter().any(|(e, _)| e.id == d_event.id || e.id == o_event.id), "flagged once");
    let (d, o) = states;
    assert_eq!((d.0.as_str(), d.2.as_deref(), d.3.as_deref()), ("active", Some("disabled"), Some(UNRECORDED_ACTOR)));
    assert_eq!((o.0.as_str(), o.2.as_deref()), ("active", Some("stale_alerting_off")));
}

/// Review round 2: the never-sent grace anchor is stamped once by every path
/// that marks a source deployed (single deploy, deploy-all's
/// `mark_enabled_deployed`) and never moves on later deploys; a legacy source
/// already deployed before the column existed is anchored to `created_at`.
#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn first_deployed_at_is_stamped_once_on_every_deploy_path() {
    let pool = common::migrated_pool().await;
    let mut made = Made::default();
    let fresh = Uuid::now_v7();
    let sibling = Uuid::now_v7();
    let legacy = Uuid::now_v7();
    for (id, label, deployed) in [(fresh, "fresh", false), (sibling, "sibling", false), (legacy, "legacy", true)] {
        sqlx::query(
            "INSERT INTO log_sources (id, name, source_type, parser_vrl, enabled, deployed, deployed_at, created_at)
             VALUES ($1, $2, 'routed', '.', true, $3, CASE WHEN $3 THEN now() - interval '2 days' END,
                     now() - interval '3 days')",
        )
        .bind(id)
        .bind(format!("nan5785_{label}_{}", id.simple()))
        .bind(deployed)
        .execute(&pool)
        .await
        .unwrap();
        made.sources.push(id);
    }
    let first_deployed = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<chrono::DateTime<Utc>>>(
                "SELECT first_deployed_at FROM log_sources WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let created = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, chrono::DateTime<Utc>>("SELECT created_at FROM log_sources WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };

    let repo = LogSourceRepository::new(pool.clone());
    repo.mark_deployed(fresh).await.unwrap();
    let fresh_first = first_deployed(fresh).await;
    repo.mark_enabled_deployed().await.unwrap();
    let sibling_first = first_deployed(sibling).await;
    repo.mark_deployed(legacy).await.unwrap();
    let legacy_first = first_deployed(legacy).await;
    // A later deploy / deploy-all rewrites deployed_at, never the anchor.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    repo.mark_deployed(fresh).await.unwrap();
    repo.mark_deployed(sibling).await.unwrap();
    let (fresh_again, sibling_again) = (first_deployed(fresh).await, first_deployed(sibling).await);
    let legacy_created = created(legacy).await;
    made.clean(&pool).await;

    assert!(fresh_first.is_some_and(|t| t > Utc::now() - Duration::minutes(5)), "stamped on first deploy");
    assert!(sibling_first.is_some_and(|t| t > Utc::now() - Duration::minutes(5)), "deploy-all sibling stamped");
    assert_eq!(fresh_again, fresh_first, "a re-deploy never moves the anchor");
    assert_eq!(sibling_again, sibling_first);
    assert_eq!(legacy_first, Some(legacy_created), "a legacy deployed source anchors to created_at");
}
