// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5716 live PostgreSQL tests: a linked rule edited locally since its
//! import (or last upstream update) reads `local_drift`; lifecycle changes
//! (mode, folder) do not; applying the upstream update re-baselines it.
//!
//! Against a disposable, fully migrated database only:
//!
//! ```text
//! NANOSIEM_TEST_DATABASE_URL=postgres://nanosiem:test@127.0.0.1:38433/nanosiem \
//!   cargo test -p nanosiem-core --lib -- import_drift_live_tests --ignored --test-threads=1
//! ```

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use super::{RepositoryRulesRepository, RuleImportsRepository};
use crate::db::repository::DetectionRuleRepository;
use crate::models::detection_rule::{
    DetectionMode, NewDetectionRule, RuleMode, Severity, UpdateDetectionRule,
};

async fn pool() -> Option<PgPool> {
    let url = nanosiem_test_db::pg_url().ok()?;
    let pool = PgPoolOptions::new().max_connections(4).connect(&url).await.expect("connect");
    crate::db::run_postgres_migrations(&pool).await.expect("migrations");
    Some(pool)
}

fn rule(name: &str) -> NewDetectionRule {
    NewDetectionRule {
        name: name.into(),
        description: Some("upstream description".into()),
        query: "class_uid=3002 status_id=2".into(),
        severity: Severity::Medium,
        mitre_tactics: None,
        mitre_techniques: None,
        schedule_cron: Some("*/5 * * * *".into()),
        mode: Some(RuleMode::Staging),
        narrative: None,
        reference_url: None,
        author: None,
        tags: Some(vec!["nano".into()]),
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
        folder: Some("nan_5716_drift_tests".into()),
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

struct Fixture {
    pool: PgPool,
    rules: DetectionRuleRepository,
    imports: RuleImportsRepository,
    repo_id: Uuid,
}

impl Fixture {
    async fn new(pool: PgPool) -> Self {
        let repo_id: Uuid = sqlx::query_scalar(
            "INSERT INTO rule_repositories (name, slug, url, rule_format) \
             VALUES ($1, $1, 'https://github.com/example/rules', 'nanosiem') RETURNING id",
        )
        .bind(format!("nan-5716-{}", Uuid::new_v4().simple()))
        .fetch_one(&pool)
        .await
        .expect("repository");
        Self {
            rules: DetectionRuleRepository::new(pool.clone()),
            imports: RuleImportsRepository::new(pool.clone()),
            pool,
            repo_id,
        }
    }

    /// A linked import of a fresh detection rule, as `import_rule` leaves it.
    async fn linked(&self, path: &str) -> (Uuid, Uuid) {
        let catalog = RepositoryRulesRepository::new(self.pool.clone());
        let repo_rule = catalog
            .upsert(self.repo_id, path, Some("sha1"), "v1", Some("Linked"), None, Some("medium"),
                    None, None, None, None, None, Some("success"))
            .await
            .expect("catalog upsert");
        let name = format!("nan_5716_{}", Uuid::new_v4().simple());
        let detection = self.rules.create(&rule(&name)).await.expect("create");
        let import = self
            .imports
            .create(repo_rule.id, detection.id, "linked", None, Some("c1"), None)
            .await
            .expect("import record");
        assert!(import.synced_content_hash.is_some(), "import stamps the baseline");
        (detection.id, import.id)
    }

    async fn drift(&self, detection_id: Uuid) -> bool {
        self.imports
            .list_active_for_repository(self.repo_id)
            .await
            .expect("list")
            .into_iter()
            .find(|i| i.detection_rule_id == detection_id)
            .expect("import listed")
            .local_drift
    }
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn a_local_edit_reads_drift_until_the_upstream_update_rebaselines_it() {
    let Some(pool) = pool().await else { return };
    let fx = Fixture::new(pool).await;
    let (detection_id, import_id) = fx.linked("endpoint/edited.npl").await;
    assert!(!fx.drift(detection_id).await, "fresh import is not drift");

    // `PUT /api/rules/{id}` with a new description (the e2e repro).
    let update = UpdateDetectionRule {
        description: Some("local edit of a linked rule".into()),
        ..Default::default()
    };
    fx.rules.update(detection_id, &update).await.expect("edit");
    assert!(fx.drift(detection_id).await, "a local edit reads DRIFT");

    // Applying the upstream update (import_rule's update branch) rewrites the
    // content and calls update_sync, which re-stamps the baseline.
    sqlx::query("UPDATE detection_rules SET description = 'upstream v2' WHERE id = $1")
        .bind(detection_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    fx.imports.update_sync(import_id, "c2").await.expect("sync");
    assert!(!fx.drift(detection_id).await, "an applied upstream update is the new baseline");
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn lifecycle_changes_and_null_normalization_are_not_drift() {
    let Some(pool) = pool().await else { return };
    let fx = Fixture::new(pool).await;
    let (detection_id, _) = fx.linked("endpoint/promoted.npl").await;

    // Promote, rename the folder, pause: local by design.
    let lifecycle = UpdateDetectionRule {
        mode: Some(RuleMode::Live),
        folder: Some("nan_5716_elsewhere".into()),
        ..Default::default()
    };
    fx.rules.update(detection_id, &lifecycle).await.expect("promote");
    assert!(!fx.drift(detection_id).await, "a promote is not drift");

    // NULL vs empty: a save that normalizes NULL tactics to '{}' is no edit.
    sqlx::query("UPDATE detection_rules SET mitre_tactics = '{}' WHERE id = $1 AND mitre_tactics IS NULL")
        .bind(detection_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    assert!(!fx.drift(detection_id).await, "NULL and empty arrays hash alike");

    // A query change is drift.
    let edit = UpdateDetectionRule {
        query: Some("class_uid=3002 status_id=1".into()),
        ..Default::default()
    };
    fx.rules.update(detection_id, &edit).await.expect("edit query");
    assert!(fx.drift(detection_id).await, "a query edit reads DRIFT");
}

/// Forked imports take one-click upstream Updates too (import_rule's update
/// branch ignores import_type), so a local edit to one is drift as well.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn a_forked_import_reads_drift_too() {
    let Some(pool) = pool().await else { return };
    let fx = Fixture::new(pool).await;
    let (detection_id, import_id) = fx.linked("endpoint/forked.npl").await;
    sqlx::query("UPDATE rule_imports SET import_type = 'forked' WHERE id = $1")
        .bind(import_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    assert!(!fx.drift(detection_id).await);
    sqlx::query("UPDATE detection_rules SET description = 'forked and edited' WHERE id = $1")
        .bind(detection_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    assert!(fx.drift(detection_id).await, "an Update would discard this edit");
}

/// Representation-only rewrites a save can make are not edits: CRLF vs LF,
/// surrounding whitespace, severity case, tag order / duplicates / blanks.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn representation_only_rewrites_are_not_drift() {
    let Some(pool) = pool().await else { return };
    let fx = Fixture::new(pool).await;
    let (detection_id, _) = fx.linked("endpoint/canonical.npl").await;
    sqlx::query("UPDATE detection_rules SET query = E'class_uid=3002\r\nstatus_id=2', tags = ARRAY['zeta','alpha'] WHERE id = $1")
        .bind(detection_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    // Re-baseline at the CRLF / unsorted form, as an import of such a file would.
    sqlx::query(concat!(
        "UPDATE rule_imports ri SET synced_content_hash = rule_import_content_hash(",
        "dr.query, dr.description, dr.severity, dr.mitre_tactics, dr.mitre_techniques, ",
        "dr.schedule_cron, dr.lookback_minutes, dr.tags) FROM detection_rules dr ",
        "WHERE dr.id = ri.detection_rule_id AND dr.id = $1"
    ))
    .bind(detection_id)
    .execute(&fx.pool)
    .await
    .unwrap();
    // What the editor writes back: LF, trailing newline, sorted + duplicated tags.
    sqlx::query(
        "UPDATE detection_rules SET query = E'class_uid=3002\nstatus_id=2\n',          tags = ARRAY['alpha', ' zeta ', 'alpha', ''], description = description || E'  \n' WHERE id = $1",
    )
    .bind(detection_id)
    .execute(&fx.pool)
    .await
    .unwrap();
    assert!(!fx.drift(detection_id).await, "a representation-only save is not drift");
    sqlx::query("UPDATE detection_rules SET tags = ARRAY['alpha'] WHERE id = $1")
        .bind(detection_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    assert!(fx.drift(detection_id).await, "dropping a tag is an edit");
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn an_import_without_a_baseline_never_reads_drift() {
    let Some(pool) = pool().await else { return };
    let fx = Fixture::new(pool).await;
    let (detection_id, import_id) = fx.linked("endpoint/legacy.npl").await;
    sqlx::query("UPDATE rule_imports SET synced_content_hash = NULL WHERE id = $1")
        .bind(import_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE detection_rules SET description = 'edited' WHERE id = $1")
        .bind(detection_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    assert!(!fx.drift(detection_id).await, "no baseline = unknown, not DRIFT");
}
