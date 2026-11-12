// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5132: the PostgreSQL deploy-job store — coalescing under concurrent
//! requests (the partial unique index), queued → running, restart recovery,
//! and a runner driving concurrent, failing and rolled-back jobs end to end.
//!
//! `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 cargo test -p nanosiem-core \
//!     --test log_source_deploy_jobs_integration -- --ignored --test-threads=1`

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use nanosiem_core::log_sources::deploy_jobs::{
    DeployJobKind, DeployJobRunner, DeployJobState, DeployJobStore, DeployPhase, JobFinish,
    JobOutcome, NewDeployJob, PgDeployJobStore, STALE_AFTER,
};
use nanosiem_core::log_sources::DeploymentResult;
use sqlx::PgPool;
use uuid::Uuid;

async fn pool() -> PgPool {
    let pool = common::migrated_pool().await;
    sqlx::query("DELETE FROM log_source_deploy_jobs")
        .execute(&pool)
        .await
        .unwrap();
    pool
}

fn job(kind: DeployJobKind, coalescible: bool) -> NewDeployJob {
    // No log source row is needed: deploy-all and the null target share the
    // same coalescing rules as a per-source job.
    NewDeployJob {
        kind,
        log_source_id: None,
        requested_by: Some(Uuid::now_v7()),
        coalescible,
    }
}

fn result(success: bool, message: &str) -> DeploymentResult {
    DeploymentResult {
        success,
        log_source_id: Uuid::nil(),
        action: "deploy".to_string(),
        message: message.to_string(),
        validation_result: None,
        deployment_id: None,
        delivery: None,
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL (DATABASE_URL)"]
async fn concurrent_requests_coalesce_into_one_queued_job() {
    let pool = pool().await;
    let store = Arc::new(PgDeployJobStore::new(pool.clone()));
    let mut tasks = Vec::new();
    for i in 0..16 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .create_or_join(&job(DeployJobKind::DeployAll, true), &format!("api-{i}"))
                .await
                .unwrap()
        }));
    }
    let mut ids = Vec::new();
    let mut created = 0;
    for task in tasks {
        let (job, joined) = task.await.unwrap();
        if !joined {
            created += 1;
        }
        ids.push(job.id);
    }
    assert_eq!(created, 1, "exactly one request created the job");
    ids.dedup();
    assert_eq!(ids.len(), 1, "every request got the same job");

    // Not coalescible: always its own job, even with one queued.
    let (own, joined) = store
        .create_or_join(&job(DeployJobKind::DeployAll, false), "api")
        .await
        .unwrap();
    assert!(!joined);
    assert_ne!(own.id, ids[0]);

    // Once the queued job holds the lock it stops absorbing requests.
    store.set_phase(ids[0], DeployPhase::WaitingForLock).await.unwrap();
    let still = store.get(ids[0]).await.unwrap().unwrap();
    assert_eq!(still.state, DeployJobState::Queued);
    store.set_phase(ids[0], DeployPhase::Rendering).await.unwrap();
    let running = store.get(ids[0]).await.unwrap().unwrap();
    assert_eq!(running.state, DeployJobState::Running);
    assert!(running.started_at.is_some());
    let (next, joined) = store
        .create_or_join(&job(DeployJobKind::DeployAll, true), "api")
        .await
        .unwrap();
    assert!(!joined);
    assert_ne!(next.id, ids[0]);
}

#[tokio::test]
#[ignore = "needs PostgreSQL (DATABASE_URL)"]
async fn stale_jobs_are_interrupted_and_a_real_finish_still_lands() {
    let pool = pool().await;
    let store = PgDeployJobStore::new(pool.clone());
    let (stale, _) = store.create_or_join(&job(DeployJobKind::Deploy, true), "api-dead").await.unwrap();
    let (live, _) = store.create_or_join(&job(DeployJobKind::Undeploy, true), "api-live").await.unwrap();
    store.set_phase(stale.id, DeployPhase::Promoting).await.unwrap();
    sqlx::query("UPDATE log_source_deploy_jobs SET heartbeat_at = now() - interval '5 minutes' WHERE id = $1")
        .bind(stale.id)
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(store.interrupt_stale(STALE_AFTER, None).await.unwrap(), 1);
    let read = store.get(stale.id).await.unwrap().unwrap();
    assert_eq!(read.state, DeployJobState::Interrupted);
    assert_eq!(read.phase, DeployPhase::Done);
    assert_eq!(read.error_status, Some(500));
    assert!(read.finished_at.is_some());
    assert_eq!(store.get(live.id).await.unwrap().unwrap().state, DeployJobState::Queued);

    // The interrupted job no longer blocks a new queued job for the target.
    let (fresh, joined) = store.create_or_join(&job(DeployJobKind::Deploy, true), "api").await.unwrap();
    assert!(!joined);
    assert_ne!(fresh.id, stale.id);

    // A finish from the (actually alive) owner overwrites the interrupt…
    store
        .finish(
            stale.id,
            &JobFinish {
                state: DeployJobState::Succeeded,
                message: Some("ok".into()),
                result: Some(result(true, "ok")),
                error_status: None,
            },
        )
        .await
        .unwrap();
    let done = store.get(stale.id).await.unwrap().unwrap();
    assert_eq!(done.state, DeployJobState::Succeeded);
    assert!(done.result.is_some_and(|r| r.success));

    // …but never a finished one.
    store
        .finish(
            stale.id,
            &JobFinish {
                state: DeployJobState::Failed,
                message: Some("late".into()),
                result: None,
                error_status: Some(500),
            },
        )
        .await
        .unwrap();
    assert_eq!(store.get(stale.id).await.unwrap().unwrap().state, DeployJobState::Succeeded);

    // Prune keeps recent finished jobs.
    assert_eq!(store.prune(Duration::from_secs(3600)).await.unwrap(), 0);
    sqlx::query("UPDATE log_source_deploy_jobs SET finished_at = now() - interval '8 days' WHERE id = $1")
        .bind(stale.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(store.prune(Duration::from_secs(7 * 24 * 3600)).await.unwrap(), 1);
    assert!(store.get(stale.id).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "needs PostgreSQL (DATABASE_URL)"]
async fn runner_on_postgres_serializes_and_records_failures_and_rollbacks() {
    let pool = pool().await;
    let runner = DeployJobRunner::with_pool(pool.clone());
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let inside = Arc::new(AtomicUsize::new(0));
    let max_inside = Arc::new(AtomicUsize::new(0));
    let kinds = [
        DeployJobKind::Deploy,
        DeployJobKind::Undeploy,
        DeployJobKind::Publish,
        DeployJobKind::DeployAll,
    ];
    let mut ids = Vec::new();
    for i in 0..8usize {
        let (lock, inside, max_inside) = (lock.clone(), inside.clone(), max_inside.clone());
        let submitted = runner
            .submit(job(kinds[i % 4], false), move |progress| {
                async move {
                    progress.phase(DeployPhase::WaitingForLock);
                    let _guard = lock.lock().await;
                    progress.phase(DeployPhase::Rendering);
                    let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                    max_inside.fetch_max(now, Ordering::SeqCst);
                    progress.phase(DeployPhase::Reloading);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    inside.fetch_sub(1, Ordering::SeqCst);
                    match i {
                        2 => {
                            progress.phase(DeployPhase::RollingBack);
                            JobOutcome::Result(result(false, "Reload failed, rolled back: refused"))
                        }
                        5 => JobOutcome::Result(result(false, "VRL validation failed: x")),
                        6 => JobOutcome::Error { status: 409, message: "Conflict: stale".into() },
                        _ => JobOutcome::Result(result(true, "ok")),
                    }
                }
                .boxed()
            })
            .await
            .unwrap();
        ids.push(submitted.job.id);
    }
    let mut states = Vec::new();
    for id in &ids {
        let job = tokio::time::timeout(Duration::from_secs(30), runner.wait(*id, Duration::from_millis(20)))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(job.phase, DeployPhase::Done);
        states.push((job.state, job.error_status));
    }
    assert_eq!(max_inside.load(Ordering::SeqCst), 1);
    assert_eq!(states[2], (DeployJobState::RolledBack, None));
    assert_eq!(states[5], (DeployJobState::Failed, None));
    assert_eq!(states[6], (DeployJobState::Failed, Some(409)));
    for i in [0, 1, 3, 4, 7] {
        assert_eq!(states[i].0, DeployJobState::Succeeded, "job {i}: {states:?}");
    }
}
