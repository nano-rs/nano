// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5672 live PG + ClickHouse test: deleting a real-time rule drops its
//! materialized view, nothing but an explicit unarchive brings it back (a
//! plain update of the deleted rule is a 404 and provisions nothing), and an
//! unarchive restores the view so the rule fires again once promoted.
//!
//! Drives the real `DetectionService` + `MaterializedViewGenerator` against a
//! throwaway stack. The ClickHouse side gets the production `signals` and
//! `ocsf_logs` DDL straight from the repository's init scripts. Skips unless
//! `NANOSIEM_TEST_REALTIME=1` and the usual `DualPoolConfig::from_env` vars
//! (`DATABASE_URL`, `CLICKHOUSE_URL`, `CLICKHOUSE_USER`, ...) target
//! disposable databases:
//!
//! ```text
//! NANOSIEM_TEST_REALTIME=1 DATABASE_URL=postgres://... CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   CLICKHOUSE_USER=nanosiem CLICKHOUSE_PASSWORD=test \
//!   cargo test -p nanosiem-core --lib realtime_delete_live_tests -- --ignored --test-threads=1
//! ```

use uuid::Uuid;

use super::materialized_view::MaterializedViewGenerator;
use super::{DetectionError, DetectionService};
use crate::db::{DualPool, DualPoolConfig};
use crate::lookup::{LookupService, PostgresLookupRepository};
use crate::models::detection_rule::{
    DetectionMode, NewDetectionRule, RuleMode, Severity, UpdateDetectionRule,
};
use crate::prevalence::PrevalenceService;

/// One `CREATE TABLE IF NOT EXISTS <name>` statement from a repo init script.
fn table_ddl(script: &str, table: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(script);
    let sql = std::fs::read_to_string(&path).expect("init script");
    let head = format!("CREATE TABLE IF NOT EXISTS {table}\n");
    let start = sql.find(&head).unwrap_or_else(|| panic!("{table} in {script}"));
    let end = start + sql[start..].find("\n;").expect("statement end");
    sql[start..end].to_string()
}

struct Stack {
    svc: DetectionService,
    generator: MaterializedViewGenerator,
    ch: clickhouse::Client,
}

async fn stack() -> Option<Stack> {
    if std::env::var("NANOSIEM_TEST_REALTIME").as_deref() != Ok("1") {
        return None;
    }
    let config = DualPoolConfig::from_env().expect("PG/CH env");
    let dual_pool = DualPool::new(&config).await.expect("connect PG + CH");
    let pg = dual_pool.postgres().clone();
    crate::db::run_postgres_migrations(&pg).await.expect("PG migrations");
    let ch = dual_pool.clickhouse_admin().clone();
    // `ocsf_logs` prevalence columns default from these dictionaries. Stubs of
    // the production shape (key + host_count) over an empty local table: the
    // test needs the table to exist, not prevalence data.
    ch.query(
        "CREATE TABLE IF NOT EXISTS nanosiem.nan5672_prevalence_stub \
         (key String, host_count UInt16) ENGINE = Memory",
    )
    .execute()
    .await
    .expect("stub source");
    for (dict, key) in [
        ("hash_prevalence_dict", "file_hash"),
        ("domain_prevalence_dict", "domain"),
        ("ip_prevalence_dict", "ip"),
    ] {
        ch.query(&format!(
            "CREATE DICTIONARY IF NOT EXISTS nanosiem.{dict} ({key} String, host_count UInt16 DEFAULT 9999) \
             PRIMARY KEY {key} \
             SOURCE(CLICKHOUSE(QUERY 'SELECT key AS {key}, host_count FROM nanosiem.nan5672_prevalence_stub')) \
             LAYOUT(COMPLEX_KEY_HASHED()) LIFETIME(0)"
        ))
        .execute()
        .await
        .expect("stub dictionary");
    }
    for ddl in [
        table_ddl("clickhouse/init.sql", "nanosiem.signals"),
        table_ddl("clickhouse/ocsf/init.sql", "nanosiem.ocsf_logs"),
    ] {
        ch.query(&ddl).execute().await.expect("CH table");
    }
    let profile = crate::schema::profile_for_id(crate::schema::SchemaId::Ocsf);
    let svc = DetectionService::with_dual_pool_prevalence_and_profile(
        &dual_pool,
        LookupService::new(PostgresLookupRepository::new(pg.clone())),
        PrevalenceService::new(dual_pool.clickhouse().clone(), dual_pool.table_names()),
        profile.clone(),
    );
    let generator = MaterializedViewGenerator::new(ch.clone()).with_profile(profile);
    Some(Stack { svc, generator, ch })
}

async fn view_exists(ch: &clickhouse::Client, rule_id: Uuid) -> bool {
    let name = MaterializedViewGenerator::view_name_for_rule_id(rule_id);
    ch.query("SELECT count() FROM system.tables WHERE database = 'nanosiem' AND name = ?")
        .bind(name)
        .fetch_one::<u64>()
        .await
        .expect("system.tables")
        > 0
}

fn realtime_rule(name: &str) -> NewDetectionRule {
    NewDetectionRule {
        name: name.into(),
        description: Some("NAN-5672 real-time delete live test".into()),
        query: "class_uid=3002 status_id=2".into(),
        severity: Severity::High,
        mitre_tactics: None,
        mitre_techniques: None,
        schedule_cron: None,
        mode: Some(RuleMode::Alerting),
        narrative: None,
        reference_url: None,
        author: None,
        tags: None,
        ai_generated: Some(false),
        realtime_enabled: Some(true),
        detection_mode: Some(DetectionMode::RealTime),
        risk_score: Some(40),
        risk_entity_field: None,
        risk_modifiers: None,
        lookback_minutes: None,
        dataset: None,
        auto_tuning_enabled: Some(false),
        auto_tuning_min_confidence: None,
        auto_tuning_critical: None,
        ai_triage_hints: None,
        folder: Some("nan_5672_delete_tests".into()),
        case_visibility: None,
        case_group_ids: None,
        case_assigned_group: None,
        alert_mode: None,
        playbook_selector_mode: None,
        playbook_id: None,
        source_path: None,
        source_repo_url: None,
        alert_cooldown_minutes: None,
    }
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL + ClickHouse (NANOSIEM_TEST_REALTIME=1)"]
async fn deleted_realtime_rule_view_is_gone_and_stays_gone_until_unarchived() {
    let Some(Stack { svc, generator, ch }) = stack().await else { return };
    let name = format!("nan_5672_realtime_{}", Uuid::new_v4().simple());
    let rule = svc
        .create_rule_with_mode(realtime_rule(&name), &generator)
        .await
        .expect("create real-time rule");
    assert!(view_exists(&ch, rule.id).await, "a real-time rule provisions its view");

    svc.delete_rule_with_mode(rule.id, &generator).await.expect("delete");
    assert!(!view_exists(&ch, rule.id).await, "delete drops the view");
    let archived = svc.get_rule(rule.id).await.unwrap();
    assert!(archived.archived);
    assert_eq!(archived.mode, RuleMode::Staging);
    assert_eq!(archived.materialized_view_name, None, "no stale view name");
    assert!(matches!(svc.get_active_rule(rule.id).await, Err(DetectionError::RuleNotFound(_))));

    // A plain PUT of the deleted rule (the reactivation the review found) is
    // a 404 and provisions nothing, whatever it asks for.
    for update in [
        UpdateDetectionRule { mode: Some(RuleMode::Alerting), ..Default::default() },
        UpdateDetectionRule { query: Some("class_uid=3002".into()), ..Default::default() },
        UpdateDetectionRule { name: Some(format!("{name}_renamed")), ..Default::default() },
    ] {
        let result = svc.update_rule_with_mode(rule.id, update, &generator, None).await;
        assert!(matches!(result, Err(DetectionError::RuleNotFound(_))), "{result:?}");
        assert!(!view_exists(&ch, rule.id).await, "the view must not come back");
    }
    // Nor can the lifecycle endpoints or a schedule stamp revive it.
    assert!(matches!(
        svc.promote_rule(rule.id, Some(RuleMode::Staging)).await,
        Err(DetectionError::RuleNotFound(_))
    ));
    assert!(matches!(svc.promote_rule(rule.id, None).await, Err(DetectionError::RuleNotFound(_))));
    assert!(matches!(svc.set_mode(rule.id, "alerting").await, Err(DetectionError::RuleNotFound(_))));
    let still = svc.get_rule(rule.id).await.unwrap();
    assert!(still.archived && still.mode == RuleMode::Staging);
    assert!(!view_exists(&ch, rule.id).await);

    // Unarchiving straight into alerting is refused; staging is the way back.
    let into_alerting = UpdateDetectionRule {
        archived: Some(false),
        mode: Some(RuleMode::Alerting),
        ..Default::default()
    };
    assert!(matches!(
        svc.update_rule_with_mode(rule.id, into_alerting, &generator, None).await,
        Err(DetectionError::InvalidStateTransition(_))
    ));

    // The unarchive recreates the view, so the restored rule fires again.
    let restored = svc
        .update_rule_with_mode(
            rule.id,
            UpdateDetectionRule { archived: Some(false), ..Default::default() },
            &generator,
            None,
        )
        .await
        .expect("unarchive");
    assert!(!restored.archived);
    assert_eq!(restored.mode, RuleMode::Staging);
    assert!(restored.materialized_view_name.is_some());
    assert!(view_exists(&ch, rule.id).await, "unarchive restores the view");

    // Clean up: delete again (drops the view).
    svc.delete_rule_with_mode(rule.id, &generator).await.expect("cleanup delete");
    assert!(!view_exists(&ch, rule.id).await);
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL + ClickHouse (NANOSIEM_TEST_REALTIME=1)"]
async fn a_plain_update_never_archives_an_active_rule() {
    let Some(Stack { svc, generator, ch }) = stack().await else { return };
    let name = format!("nan_5672_realtime_archive_{}", Uuid::new_v4().simple());
    let rule = svc.create_rule_with_mode(realtime_rule(&name), &generator).await.expect("create");
    let result = svc
        .update_rule_with_mode(
            rule.id,
            UpdateDetectionRule { archived: Some(true), ..Default::default() },
            &generator,
            None,
        )
        .await;
    assert!(matches!(result, Err(DetectionError::InvalidStateTransition(_))), "{result:?}");
    let row = svc.get_rule(rule.id).await.unwrap();
    assert!(!row.archived && row.mode == RuleMode::Alerting, "untouched");
    assert!(view_exists(&ch, rule.id).await);
    svc.delete_rule_with_mode(rule.id, &generator).await.expect("cleanup delete");
}
