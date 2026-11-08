// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4995B lifecycle retry and pause-origin integration coverage.
//!
//! These tests drive the real PostgreSQL repository. They prove that row
//! locking makes overlapping legacy transitions apply once, that immediate
//! retries return the committed state, and that guarded and bodyless
//! pause/resume restore the exact pre-pause mode without moving twice.

mod common;

use std::sync::Arc;

use nanosiem_core::db::repository::detection_rules::DetectionRuleRepositoryError;
use nanosiem_core::db::repository::DetectionRuleRepository;
use nanosiem_core::RuleMode;
use sqlx::PgPool;
use tokio::sync::Barrier;
use uuid::Uuid;

async fn insert_rule(pool: &PgPool, mode: RuleMode) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_rules
            (id, name, description, query, severity, mode, detection_mode)
        VALUES ($1, $2, 'NAN-4995B lifecycle test', 'source_type=apache',
                'medium', $3, 'scheduled')
        "#,
    )
    .bind(id)
    .bind(format!("NAN-4995B-lifecycle-{id}"))
    .bind(mode.to_string())
    .execute(pool)
    .await
    .expect("insert lifecycle rule");
    id
}

async fn persisted_state(pool: &PgPool, id: Uuid) -> (String, Option<String>) {
    sqlx::query_as("SELECT mode::text, paused_from_mode FROM detection_rules WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read lifecycle state")
}

async fn expire_legacy_dwell(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "UPDATE detection_rules \
         SET legacy_lifecycle_transition_at = NOW() - INTERVAL '31 seconds' \
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("expire legacy lifecycle dwell");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn concurrent_and_retried_legacy_promote_apply_exactly_once() {
    let pool = common::migrated_pool().await;
    let repo = DetectionRuleRepository::new(pool.clone());
    let id = insert_rule(&pool, RuleMode::Staging).await;
    let barrier = Arc::new(Barrier::new(3));

    let mut requests = Vec::new();
    for _ in 0..2 {
        let repo = repo.clone();
        let barrier = barrier.clone();
        requests.push(tokio::spawn(async move {
            barrier.wait().await;
            repo.promote_legacy(id).await
        }));
    }
    barrier.wait().await;

    let mut outcomes = Vec::new();
    for request in requests {
        outcomes.push(
            request
                .await
                .expect("join promote")
                .expect("legacy promote"),
        );
    }
    assert_eq!(
        outcomes.iter().filter(|(from, _)| from.is_some()).count(),
        1,
        "only one overlapping bodyless request may mutate"
    );
    assert!(outcomes.iter().all(|(_, rule)| rule.mode == RuleMode::Live));
    assert_eq!(persisted_state(&pool, id).await.0, "live");

    let (from, retry) = repo.promote_legacy(id).await.expect("retry promote");
    assert_eq!(from, None, "retry inside dwell must be replay-suppressed");
    assert_eq!(retry.mode, RuleMode::Live, "retry returns current state");

    expire_legacy_dwell(&pool, id).await;
    let (from, after_dwell) = repo
        .promote_legacy(id)
        .await
        .expect("promote after dwell expires");
    assert_eq!(from, Some(RuleMode::Live));
    assert_eq!(after_dwell.mode, RuleMode::Alerting);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn concurrent_and_retried_legacy_demote_apply_exactly_once() {
    let pool = common::migrated_pool().await;
    let repo = DetectionRuleRepository::new(pool.clone());
    let id = insert_rule(&pool, RuleMode::Alerting).await;
    let barrier = Arc::new(Barrier::new(3));

    let mut requests = Vec::new();
    for _ in 0..2 {
        let repo = repo.clone();
        let barrier = barrier.clone();
        requests.push(tokio::spawn(async move {
            barrier.wait().await;
            repo.demote_legacy(id).await
        }));
    }
    barrier.wait().await;

    let mut outcomes = Vec::new();
    for request in requests {
        outcomes.push(request.await.expect("join demote").expect("legacy demote"));
    }
    assert_eq!(
        outcomes.iter().filter(|(from, _)| from.is_some()).count(),
        1,
        "only one overlapping bodyless request may mutate"
    );
    assert!(outcomes.iter().all(|(_, rule)| rule.mode == RuleMode::Live));
    assert_eq!(persisted_state(&pool, id).await.0, "live");

    let (from, retry) = repo.demote_legacy(id).await.expect("retry demote");
    assert_eq!(from, None, "retry inside dwell must be replay-suppressed");
    assert_eq!(retry.mode, RuleMode::Live, "retry returns current state");

    expire_legacy_dwell(&pool, id).await;
    let (from, after_dwell) = repo
        .demote_legacy(id)
        .await
        .expect("demote after dwell expires");
    assert_eq!(from, Some(RuleMode::Live));
    assert_eq!(after_dwell.mode, RuleMode::Staging);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn pause_resume_guards_bodyless_retries_and_concurrency_restore_exactly() {
    let pool = common::migrated_pool().await;
    let repo = DetectionRuleRepository::new(pool.clone());
    let id = insert_rule(&pool, RuleMode::Live).await;

    let (first_pause, second_pause) = tokio::join!(
        repo.pause(id, RuleMode::Live),
        repo.pause(id, RuleMode::Live)
    );
    assert_eq!(
        [first_pause.as_ref(), second_pause.as_ref()]
            .into_iter()
            .filter(|result| result.is_ok())
            .count(),
        1,
        "only one guarded pause may apply"
    );
    assert_eq!(
        persisted_state(&pool, id).await,
        ("paused".into(), Some("live".into()))
    );
    assert!(matches!(
        repo.pause(id, RuleMode::Live).await,
        Err(DetectionRuleRepositoryError::InvalidModeTransition(_, _))
    ));

    let (first_resume, second_resume) = tokio::join!(
        repo.resume(id, RuleMode::Paused),
        repo.resume(id, RuleMode::Paused)
    );
    assert_eq!(
        [first_resume.as_ref(), second_resume.as_ref()]
            .into_iter()
            .filter(|result| result.is_ok())
            .count(),
        1,
        "only one guarded resume may apply"
    );
    assert_eq!(persisted_state(&pool, id).await, ("live".into(), None));
    assert!(matches!(
        repo.resume(id, RuleMode::Paused).await,
        Err(DetectionRuleRepositoryError::InvalidModeTransition(_, _))
    ));

    let id = insert_rule(&pool, RuleMode::Alerting).await;
    let barrier = Arc::new(Barrier::new(3));

    let mut pauses = Vec::new();
    for _ in 0..2 {
        let repo = repo.clone();
        let barrier = barrier.clone();
        pauses.push(tokio::spawn(async move {
            barrier.wait().await;
            repo.pause_legacy(id).await
        }));
    }
    barrier.wait().await;

    let mut pause_outcomes = Vec::new();
    for pause in pauses {
        pause_outcomes.push(pause.await.expect("join pause").expect("bodyless pause"));
    }
    assert_eq!(
        pause_outcomes
            .iter()
            .filter(|(from, _)| *from == Some(RuleMode::Alerting))
            .count(),
        1,
        "only one overlapping bodyless pause may mutate"
    );
    assert_eq!(
        pause_outcomes
            .iter()
            .filter(|(from, _)| from.is_none())
            .count(),
        1,
        "the overlapping retry must be an idempotent no-op"
    );
    assert!(pause_outcomes
        .iter()
        .all(|(_, rule)| rule.mode == RuleMode::Paused));
    assert_eq!(
        persisted_state(&pool, id).await,
        ("paused".into(), Some("alerting".into()))
    );
    let (from, retry) = repo.pause_legacy(id).await.expect("retry bodyless pause");
    assert_eq!(from, None);
    assert_eq!(retry.mode, RuleMode::Paused);

    let barrier = Arc::new(Barrier::new(3));
    let mut resumes = Vec::new();
    for _ in 0..2 {
        let repo = repo.clone();
        let barrier = barrier.clone();
        resumes.push(tokio::spawn(async move {
            barrier.wait().await;
            repo.resume_legacy(id).await
        }));
    }
    barrier.wait().await;

    let mut resume_outcomes = Vec::new();
    for resume in resumes {
        resume_outcomes.push(resume.await.expect("join resume").expect("bodyless resume"));
    }
    assert_eq!(
        resume_outcomes
            .iter()
            .filter(|(from, _)| *from == Some(RuleMode::Paused))
            .count(),
        1,
        "only one overlapping bodyless resume may mutate"
    );
    assert_eq!(
        resume_outcomes
            .iter()
            .filter(|(from, _)| from.is_none())
            .count(),
        1,
        "the overlapping retry must be an idempotent no-op"
    );
    assert!(resume_outcomes
        .iter()
        .all(|(_, rule)| rule.mode == RuleMode::Alerting));
    assert_eq!(persisted_state(&pool, id).await, ("alerting".into(), None));
    let (from, retry) = repo.resume_legacy(id).await.expect("retry bodyless resume");
    assert_eq!(from, None);
    assert_eq!(retry.mode, RuleMode::Alerting);

    let id = insert_rule(&pool, RuleMode::Staging).await;

    assert!(matches!(
        repo.pause_legacy(id).await,
        Err(DetectionRuleRepositoryError::InvalidModeTransition(_, _))
    ));
    let (from, rule) = repo
        .resume_legacy(id)
        .await
        .expect("resuming a non-paused rule is idempotent");
    assert_eq!(from, None);
    assert_eq!(rule.mode, RuleMode::Staging);
    assert_eq!(persisted_state(&pool, id).await, ("staging".into(), None));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn alerting_pause_resumes_to_alerting_not_a_default_mode() {
    let pool = common::migrated_pool().await;
    let repo = DetectionRuleRepository::new(pool.clone());
    let id = insert_rule(&pool, RuleMode::Alerting).await;

    let paused = repo
        .pause(id, RuleMode::Alerting)
        .await
        .expect("pause alerting");
    assert_eq!(paused.mode, RuleMode::Paused);
    assert_eq!(
        persisted_state(&pool, id).await,
        ("paused".into(), Some("alerting".into()))
    );

    let resumed = repo
        .resume(id, RuleMode::Paused)
        .await
        .expect("resume alerting");
    assert_eq!(resumed.mode, RuleMode::Alerting);
    assert_eq!(persisted_state(&pool, id).await, ("alerting".into(), None));
}
