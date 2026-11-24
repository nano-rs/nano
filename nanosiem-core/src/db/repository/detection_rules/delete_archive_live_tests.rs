// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5672 live PostgreSQL tests: `DELETE /api/rules/{id}` archives the rule
//! (NAN-3816), and the archived rule must behave as deleted everywhere: hidden
//! from the lists, never scheduled again, and, for a repository-imported rule,
//! no longer "imported", so a repo sync cannot bring it back as an update.
//!
//! Against a disposable, fully migrated database only:
//!
//! ```text
//! NANOSIEM_TEST_DATABASE_URL=postgres://nanosiem:test@127.0.0.1:38433/nanosiem \
//!   cargo test -p nanosiem-core --lib -- delete_archive_live_tests --ignored --test-threads=1
//! ```

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use super::{DetectionRuleRepository, DetectionRuleRepositoryError};
use crate::models::detection_rule::{DetectionMode, NewDetectionRule, RuleMode, Severity};
use crate::rule_repository::{RepositoryRulesRepository, RuleImportsRepository};

pub(crate) async fn pool() -> Option<PgPool> {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new().max_connections(4).connect(&url).await.expect("connect");
    crate::db::run_postgres_migrations(&pool).await.expect("migrations");
    Some(pool)
}

fn rule(name: &str, mode: RuleMode) -> NewDetectionRule {
    NewDetectionRule {
        name: name.into(),
        description: Some("NAN-5672 delete live test".into()),
        query: "class_uid=3002 status_id=2".into(),
        severity: Severity::Medium,
        mitre_tactics: None,
        mitre_techniques: None,
        schedule_cron: Some("*/1 * * * *".into()),
        mode: Some(mode),
        narrative: None,
        reference_url: None,
        author: None,
        tags: None,
        ai_generated: Some(false),
        realtime_enabled: Some(false),
        detection_mode: Some(DetectionMode::Scheduled),
        risk_score: None,
        risk_entity_field: None,
        risk_modifiers: None,
        lookback_minutes: Some(10),
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

/// The API delete path: quiesce (no new claims, wait out the owner), then
/// archive. Mirrors `DetectionService::delete_rule_with_mode` for a
/// scheduled rule, which has no execution tier to tear down.
async fn api_delete(rules: &DetectionRuleRepository, id: Uuid) -> bool {
    assert!(rules.quiesce_for_delete(id).await.expect("quiesce"), "rule not claimed");
    rules.archive_for_delete(id).await.expect("archive")
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn delete_hides_the_rule_and_stops_scheduling_it() {
    let Some(pool) = pool().await else { return };
    let rules = DetectionRuleRepository::new(pool.clone());
    let name = format!("nan_5672_alerting_{}", Uuid::new_v4().simple());
    let created = rules.create(&rule(&name, RuleMode::Alerting)).await.expect("create");
    // Due now, so the scheduler would claim it on its next tick.
    rules
        .update_next_run_at(created.id, Some(chrono::Utc::now() - chrono::Duration::seconds(5)))
        .await
        .expect("schedule");

    assert!(api_delete(&rules, created.id).await, "first delete archives");

    // Gone from every default list the API and the scheduler read.
    let ids = |v: Vec<crate::models::DetectionRule>| v.into_iter().map(|r| r.id).collect::<Vec<_>>();
    assert!(!ids(rules.list().await.unwrap()).contains(&created.id), "GET /api/rules");
    assert!(!ids(rules.list_alerting().await.unwrap()).contains(&created.id));
    assert!(!ids(rules.list_active().await.unwrap()).contains(&created.id));
    assert!(!ids(rules.list_missing_next_run_at().await.unwrap()).contains(&created.id), "startup backfill");
    assert!(ids(rules.list_archived().await.unwrap()).contains(&created.id), "kept as archived history");

    // Never claimed again, even with an aggressive stale timeout.
    let claimed = rules.claim_due_rules(10_000, "nan-5672-test-node", 0).await.unwrap();
    rules.release_all_claims("nan-5672-test-node").await.ok();
    assert!(!ids(claimed).contains(&created.id), "scheduler must not claim a deleted rule");

    // The row stays (match/alert history keeps its rule_id), unscheduled.
    let row = rules.find_by_id(created.id).await.expect("row kept for history");
    assert!(row.archived);
    assert_eq!(row.next_run_at, None);
    assert_eq!(row.mode, RuleMode::Staging);

    // A repeated DELETE changes nothing (the API answers 404).
    assert!(!rules.archive_for_delete(created.id).await.unwrap());
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn deleted_linked_rule_stays_deleted_across_a_repo_sync() {
    let Some(pool) = pool().await else { return };
    let rules = DetectionRuleRepository::new(pool.clone());
    let catalog = RepositoryRulesRepository::new(pool.clone());
    let imports = RuleImportsRepository::new(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();

    let repo_id: Uuid = sqlx::query_scalar(
        "INSERT INTO rule_repositories (name, slug, url, rule_format) \
         VALUES ($1, $1, 'https://github.com/example/rules', 'nanosiem') RETURNING id",
    )
    .bind(format!("nan-5672-{suffix}"))
    .fetch_one(&pool)
    .await
    .expect("repository");
    let path = "endpoint/linked_rule.npl";
    let upsert = |content: &'static str| {
        let catalog = catalog.clone();
        async move {
            catalog
                .upsert(repo_id, path, Some(content), content, Some("Linked rule"), None,
                        Some("medium"), None, None, None, None, None, Some("success"))
                .await
                .expect("catalog upsert")
        }
    };
    let repo_rule = upsert("v1").await;

    // Imported as a linked rule, as `import_rule` leaves it.
    let name = format!("nan_5672_linked_{suffix}");
    let detection = rules.create(&rule(&name, RuleMode::Live)).await.expect("create");
    sqlx::query(
        "UPDATE detection_rules SET source_repository_id = $2, source_rule_path = $3, \
         source_linked = TRUE WHERE id = $1",
    )
    .bind(detection.id)
    .bind(repo_id)
    .bind(path)
    .execute(&pool)
    .await
    .unwrap();
    imports
        .create(repo_rule.id, detection.id, "linked", None, Some("c1"), None)
        .await
        .expect("import record");
    assert_eq!(imports.find_by_repository_rule(repo_rule.id).await.unwrap().len(), 1);

    assert!(api_delete(&rules, detection.id).await);

    // The delete unlinked the import in the same statement.
    let links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_imports WHERE detection_rule_id = $1")
        .bind(detection.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(links, 0, "import link dropped");

    // A repo sync with new upstream content: the same catalog upsert plus the
    // upstream-changed mark `run_sync` performs.
    let refreshed = upsert("v2").await;
    assert_eq!(refreshed.id, repo_rule.id);
    assert_eq!(imports.mark_upstream_changed(repo_rule.id).await.unwrap(), 0, "nothing imported to flag");

    // Not "imported", not an "update available", and no rule came back.
    assert!(imports.find_by_repository_rule(repo_rule.id).await.unwrap().is_empty());
    let pending = imports.list_with_upstream_changes().await.unwrap();
    assert!(pending.iter().all(|i| i.detection_rule_id != detection.id));
    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM detection_rules WHERE source_repository_id = $1 AND archived = FALSE",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(live, 0, "a repo sync must not re-create a deleted linked rule");
    assert!(rules.find_by_id(detection.id).await.unwrap().archived);

    // The catalog entry stays, so the rule can be re-imported explicitly: the
    // per-repo name guard ignores the archived row (migration 287).
    let again = rules.create(&rule(&name, RuleMode::Staging)).await.expect("re-import");
    sqlx::query("UPDATE detection_rules SET source_repository_id = $2 WHERE id = $1")
        .bind(again.id)
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("a fresh row may carry the deleted rule's repo name");
}

/// A rule deleted on an older build kept its `rule_imports` row. That stale
/// link must not read as "already imported" (which blocked re-importing) or
/// as an available update.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn a_stale_import_link_to_an_archived_rule_is_ignored() {
    let Some(pool) = pool().await else { return };
    let rules = DetectionRuleRepository::new(pool.clone());
    let catalog = RepositoryRulesRepository::new(pool.clone());
    let imports = RuleImportsRepository::new(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();

    let repo_id: Uuid = sqlx::query_scalar(
        "INSERT INTO rule_repositories (name, slug, url, rule_format) \
         VALUES ($1, $1, 'https://github.com/example/rules', 'nanosiem') RETURNING id",
    )
    .bind(format!("nan-5672-stale-{suffix}"))
    .fetch_one(&pool)
    .await
    .unwrap();
    let repo_rule = catalog
        .upsert(repo_id, "stale.npl", None, "v1", Some("Stale"), None, None, None, None, None,
                None, None, Some("success"))
        .await
        .unwrap();
    let detection = rules.create(&rule(&format!("nan_5672_stale_{suffix}"), RuleMode::Live)).await.unwrap();
    let link = imports.create(repo_rule.id, detection.id, "linked", None, None, None).await.unwrap();
    // The pre-fix archive: flag only, link left behind.
    sqlx::query("UPDATE detection_rules SET archived = TRUE, mode = 'staging', next_run_at = NULL WHERE id = $1")
        .bind(detection.id)
        .execute(&pool)
        .await
        .unwrap();
    imports.mark_upstream_changed(repo_rule.id).await.unwrap();

    assert!(imports.find_by_repository_rule(repo_rule.id).await.unwrap().is_empty());
    assert!(imports.list_linked_with_updates().await.unwrap().iter().all(|i| i.id != link.id));
    assert!(imports.find_by_detection_rule(detection.id).await.unwrap().is_none(), "upstream diff 404s");
    assert!(imports.list_active_for_repository(repo_id).await.unwrap().is_empty(), "browser: not imported");
    assert!(imports
        .list_with_upstream_changes_for_repo(repo_id)
        .await
        .unwrap()
        .is_empty());
    // "Remove all imported" still sees it, to drop it.
    assert!(imports.list_for_repository(repo_id).await.unwrap().iter().any(|i| i.id == link.id));
}

/// Review P1-2: the archived guard lives in the WHERE of every mode and
/// schedule write, so a transition that read the rule before the delete
/// committed still cannot touch it afterwards.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn no_mode_or_schedule_write_touches_a_deleted_rule() {
    let Some(pool) = pool().await else { return };
    let rules = DetectionRuleRepository::new(pool.clone());
    let name = format!("nan_5672_race_{}", Uuid::new_v4().simple());
    let created = rules.create(&rule(&name, RuleMode::Live)).await.expect("create");
    sqlx::query("UPDATE detection_rules SET materialized_view_name = 'mv_rt_stale' WHERE id = $1")
        .bind(created.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(api_delete(&rules, created.id).await);

    let not_found = |r: Result<_, DetectionRuleRepositoryError>| {
        matches!(r, Err(DetectionRuleRepositoryError::NotFound(_)))
    };
    // archive_for_delete parks the rule in staging, the exact source mode of
    // a promotion: each of these would have matched it before.
    assert!(not_found(rules.promote_to_live(created.id).await.map(|_| ())), "promote");
    assert!(not_found(rules.promote_legacy(created.id).await.map(|_| ())), "legacy promote");
    assert!(not_found(rules.set_mode(created.id, "alerting").await.map(|_| ())), "bulk");
    assert!(not_found(rules.set_mode(created.id, "staging").await.map(|_| ())), "bulk to staging");
    assert!(not_found(rules.pause(created.id, RuleMode::Live).await.map(|_| ())), "pause");
    assert!(not_found(rules.resume(created.id, RuleMode::Paused).await.map(|_| ())), "resume");
    assert!(not_found(rules.pause_legacy(created.id).await.map(|_| ())), "legacy pause");
    assert!(not_found(rules.resume_legacy(created.id).await.map(|_| ())), "legacy resume");
    assert!(not_found(rules.demote_legacy(created.id).await.map(|_| ())), "legacy demote");

    // A handler holding a pre-delete copy re-stamping a schedule: refused.
    rules
        .update_next_run_at(created.id, Some(chrono::Utc::now()))
        .await
        .expect("statement runs");
    let row = rules.find_by_id(created.id).await.unwrap();
    assert!(row.archived);
    assert_eq!(row.mode, RuleMode::Staging);
    assert_eq!(row.next_run_at, None, "no schedule on a deleted rule");
    assert_eq!(row.materialized_view_name, None, "the dropped view's name is cleared");
}

/// Review P1-3: unarchiving a deleted repo rule whose name was re-imported
/// since is a typed conflict (409), not a database error (500).
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn unarchiving_into_a_reimported_name_is_a_conflict() {
    let Some(pool) = pool().await else { return };
    let rules = DetectionRuleRepository::new(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let repo_id: Uuid = sqlx::query_scalar(
        "INSERT INTO rule_repositories (name, slug, url, rule_format) \
         VALUES ($1, $1, 'https://github.com/example/rules', 'nanosiem') RETURNING id",
    )
    .bind(format!("nan-5672-conflict-{suffix}"))
    .fetch_one(&pool)
    .await
    .unwrap();
    let name = format!("nan_5672_conflict_{suffix}");
    let link = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query("UPDATE detection_rules SET source_repository_id = $2 WHERE id = $1")
                .bind(id)
                .bind(repo_id)
                .execute(&pool)
                .await
                .expect("link to repo");
        }
    };
    let original = rules.create(&rule(&name, RuleMode::Staging)).await.unwrap();
    link(original.id).await;
    assert!(api_delete(&rules, original.id).await);
    let reimported = rules.create(&rule(&name, RuleMode::Staging)).await.unwrap();
    link(reimported.id).await;

    let unarchive = crate::models::detection_rule::UpdateDetectionRule {
        archived: Some(false),
        ..Default::default()
    };
    let err = rules.update(original.id, &unarchive).await.expect_err("name is taken");
    assert!(matches!(err, DetectionRuleRepositoryError::NameConflict(_)), "{err:?}");
    let api: crate::detection::DetectionError = err.into();
    assert!(
        matches!(api, crate::detection::DetectionError::InvalidStateTransition(_)),
        "maps to 409 Conflict"
    );
    assert!(rules.find_by_id(original.id).await.unwrap().archived, "still archived");
}
