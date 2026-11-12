// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5132: deploy jobs — detached execution, progress, concurrency,
//! coalescing, failure, rollback, panic and restart recovery.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use uuid::Uuid;

use super::*;

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

fn new_job(kind: DeployJobKind, source: Option<Uuid>, coalescible: bool) -> NewDeployJob {
    NewDeployJob {
        kind,
        log_source_id: source,
        requested_by: None,
        coalescible,
    }
}

fn runner() -> (DeployJobRunner, Arc<MemoryDeployJobStore>) {
    let store = Arc::new(MemoryDeployJobStore::new());
    (DeployJobRunner::new(store.clone()), store)
}

async fn wait_terminal(runner: &DeployJobRunner, id: Uuid) -> DeployJob {
    tokio::time::timeout(Duration::from_secs(10), runner.wait(id, Duration::from_millis(5)))
        .await
        .expect("job did not finish in time")
        .expect("store")
        .expect("job exists")
}

async fn wait_for<F: Fn(&DeployJob) -> bool>(runner: &DeployJobRunner, id: Uuid, pred: F) -> DeployJob {
    for _ in 0..2000 {
        let job = runner.get(id).await.unwrap().unwrap();
        if pred(&job) {
            return job;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("condition not reached for job {id}");
}

#[tokio::test]
async fn successful_job_records_phases_and_result() {
    let (runner, _) = runner();
    let source = Uuid::now_v7();
    let submitted = runner
        .submit(new_job(DeployJobKind::Deploy, Some(source), true), |progress| {
            async move {
                progress.phase(DeployPhase::Validating);
                progress.phase(DeployPhase::Rendering);
                progress.phase(DeployPhase::Promoting);
                progress.phase(DeployPhase::Reloading);
                JobOutcome::Result(result(true, "Log source 'x' deployed successfully"))
            }
            .boxed()
        })
        .await
        .unwrap();
    assert!(!submitted.coalesced);
    assert_eq!(submitted.job.state, DeployJobState::Queued);
    assert!(submitted.job.status_path.starts_with("/api/log-sources/deploy-jobs/djob_"));

    let job = wait_terminal(&runner, submitted.job.id).await;
    assert_eq!(job.state, DeployJobState::Succeeded);
    assert_eq!(job.phase, DeployPhase::Done);
    assert_eq!(job.message.as_deref(), Some("Log source 'x' deployed successfully"));
    assert!(job.result.as_ref().is_some_and(|r| r.success));
    assert!(job.started_at.is_some() && job.finished_at.is_some());
    assert_eq!(job.error_status, None);
}

#[tokio::test]
async fn work_keeps_running_after_the_caller_is_gone() {
    // A client disconnect drops the handler future. The job must not care.
    let (runner, _) = runner();
    let (release, gate) = tokio::sync::oneshot::channel::<()>();
    let ran = Arc::new(AtomicUsize::new(0));
    let ran_in = ran.clone();
    let id = {
        let submit = runner.submit(new_job(DeployJobKind::Deploy, Some(Uuid::now_v7()), false), move |progress| {
            async move {
                progress.phase(DeployPhase::Promoting);
                let _ = gate.await;
                progress.phase(DeployPhase::Reloading);
                ran_in.fetch_add(1, Ordering::SeqCst);
                JobOutcome::Result(result(true, "ok"))
            }
            .boxed()
        });
        // The "request" ends here: only the job id survives.
        submit.await.unwrap().job.id
    };
    let mid = wait_for(&runner, id, |j| j.phase == DeployPhase::Promoting).await;
    assert_eq!(mid.state, DeployJobState::Running);
    release.send(()).unwrap();
    let job = wait_terminal(&runner, id).await;
    assert_eq!(job.state, DeployJobState::Succeeded);
    assert_eq!(ran.load(Ordering::SeqCst), 1, "the deploy ran to completion exactly once");
}

#[tokio::test]
async fn concurrent_jobs_serialize_on_the_deploy_lock() {
    // The work stands in for LogSourceService::deploy: it takes one shared
    // lock for its critical section, as the real deploy takes the NAN-2297
    // deploy lock. Jobs add no lock of their own and must not break that.
    let (runner, _) = runner();
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let inside = Arc::new(AtomicUsize::new(0));
    let max_inside = Arc::new(AtomicUsize::new(0));
    let mut ids = Vec::new();
    for i in 0..8 {
        let (lock, inside, max_inside) = (lock.clone(), inside.clone(), max_inside.clone());
        let submitted = runner
            .submit(new_job(DeployJobKind::Deploy, Some(Uuid::now_v7()), true), move |progress| {
                async move {
                    progress.phase(DeployPhase::WaitingForLock);
                    let _guard = lock.lock().await;
                    progress.phase(DeployPhase::Validating);
                    let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                    max_inside.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    inside.fetch_sub(1, Ordering::SeqCst);
                    if i == 3 {
                        progress.phase(DeployPhase::RollingBack);
                        JobOutcome::Result(result(false, "Reload failed, rolled back"))
                    } else {
                        JobOutcome::Result(result(true, "ok"))
                    }
                }
                .boxed()
            })
            .await
            .unwrap();
        assert!(!submitted.coalesced, "different sources never coalesce");
        ids.push(submitted.job.id);
    }
    let mut states = Vec::new();
    for id in &ids {
        states.push(wait_terminal(&runner, *id).await.state);
    }
    assert_eq!(max_inside.load(Ordering::SeqCst), 1, "two deploys held the lock at once");
    assert_eq!(states[3], DeployJobState::RolledBack, "one job's rollback stays its own");
    assert_eq!(
        states.iter().filter(|s| **s == DeployJobState::Succeeded).count(),
        7,
        "a failing job does not affect the others: {states:?}"
    );
}

#[tokio::test]
async fn a_job_waiting_for_the_lock_stays_queued() {
    let (runner, _) = runner();
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let held = lock.clone().lock_owned().await;
    let source = Uuid::now_v7();
    let lock_in = lock.clone();
    let id = runner
        .submit(new_job(DeployJobKind::Deploy, Some(source), true), move |progress| {
            async move {
                progress.phase(DeployPhase::WaitingForLock);
                let _guard = lock_in.lock().await;
                progress.phase(DeployPhase::Validating);
                JobOutcome::Result(result(true, "ok"))
            }
            .boxed()
        })
        .await
        .unwrap()
        .job
        .id;
    let waiting = wait_for(&runner, id, |j| j.phase == DeployPhase::WaitingForLock).await;
    assert_eq!(waiting.state, DeployJobState::Queued);
    assert!(waiting.started_at.is_none());
    drop(held);
    assert_eq!(wait_terminal(&runner, id).await.state, DeployJobState::Succeeded);
}

#[tokio::test]
async fn a_queued_job_absorbs_identical_async_requests() {
    let (runner, _) = runner();
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let held = lock.clone().lock_owned().await;
    let source = Uuid::now_v7();
    let runs = Arc::new(AtomicUsize::new(0));

    let submit = |runs: Arc<AtomicUsize>, lock: Arc<tokio::sync::Mutex<()>>, coalescible: bool, kind| {
        runner.submit(new_job(kind, Some(source), coalescible), move |progress| {
            async move {
                progress.phase(DeployPhase::WaitingForLock);
                let _guard = lock.lock().await;
                progress.phase(DeployPhase::Validating);
                runs.fetch_add(1, Ordering::SeqCst);
                JobOutcome::Result(result(true, "ok"))
            }
            .boxed()
        })
    };

    let first = submit(runs.clone(), lock.clone(), true, DeployJobKind::Deploy).await.unwrap();
    let second = submit(runs.clone(), lock.clone(), true, DeployJobKind::Deploy).await.unwrap();
    assert!(second.coalesced);
    assert!(second.job.coalesced);
    assert_eq!(second.job.id, first.job.id);

    // A synchronous call or a publish never joins: each waits for its own run.
    let own = submit(runs.clone(), lock.clone(), false, DeployJobKind::Deploy).await.unwrap();
    assert!(!own.coalesced);
    let publish = submit(runs.clone(), lock.clone(), false, DeployJobKind::Publish).await.unwrap();
    assert!(!publish.coalesced);
    // A different action on the same source does not join a deploy.
    let undeploy = submit(runs.clone(), lock.clone(), true, DeployJobKind::Undeploy).await.unwrap();
    assert!(!undeploy.coalesced);

    drop(held);
    for id in [first.job.id, own.job.id, publish.job.id, undeploy.job.id] {
        assert_eq!(wait_terminal(&runner, id).await.state, DeployJobState::Succeeded);
    }
    assert_eq!(runs.load(Ordering::SeqCst), 4, "the coalesced request's work never ran");

    // Once the first job holds the lock it no longer absorbs requests: a
    // deploy that already read the database must not answer a later edit.
    let lock2 = Arc::new(tokio::sync::Mutex::new(()));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let running = runner
        .submit(new_job(DeployJobKind::Deploy, Some(source), true), move |progress| {
            async move {
                let _guard = lock2.lock().await;
                progress.phase(DeployPhase::Validating);
                let _ = entered_tx.send(());
                let _ = release_rx.await;
                JobOutcome::Result(result(true, "ok"))
            }
            .boxed()
        })
        .await
        .unwrap();
    entered_rx.await.unwrap();
    wait_for(&runner, running.job.id, |j| j.state == DeployJobState::Running).await;
    let later = submit(runs.clone(), lock.clone(), true, DeployJobKind::Deploy).await.unwrap();
    assert!(!later.coalesced, "a running job must not absorb a later request");
    release_tx.send(()).unwrap();
    wait_terminal(&runner, running.job.id).await;
    wait_terminal(&runner, later.job.id).await;
}

#[tokio::test]
async fn failure_rollback_and_error_outcomes() {
    let (runner, _) = runner();
    let run = |outcome: JobOutcome, roll_back: bool| {
        runner.submit(new_job(DeployJobKind::Deploy, Some(Uuid::now_v7()), false), move |progress| {
            async move {
                progress.phase(DeployPhase::Reloading);
                if roll_back {
                    progress.phase(DeployPhase::RollingBack);
                }
                outcome
            }
            .boxed()
        })
    };

    let failed = run(JobOutcome::Result(result(false, "VRL validation failed: x")), false).await.unwrap();
    let rolled = run(JobOutcome::Result(result(false, "Reload failed, rolled back: y")), true).await.unwrap();
    let error = run(
        JobOutcome::Error { status: 409, message: "modified by another update".into() },
        false,
    )
    .await
    .unwrap();
    // A rollback that still went live (impossible today) would be a success.
    let ok_after = run(JobOutcome::Result(result(true, "ok")), true).await.unwrap();

    let failed = wait_terminal(&runner, failed.job.id).await;
    assert_eq!(failed.state, DeployJobState::Failed);
    assert!(failed.result.as_ref().is_some_and(|r| !r.success));
    assert_eq!(failed.error_status, None);

    let rolled = wait_terminal(&runner, rolled.job.id).await;
    assert_eq!(rolled.state, DeployJobState::RolledBack);
    assert_eq!(rolled.message.as_deref(), Some("Reload failed, rolled back: y"));

    let error = wait_terminal(&runner, error.job.id).await;
    assert_eq!(error.state, DeployJobState::Failed);
    assert_eq!(error.error_status, Some(409));
    assert!(error.result.is_none());

    assert_eq!(wait_terminal(&runner, ok_after.job.id).await.state, DeployJobState::Succeeded);
}

#[tokio::test]
async fn a_panicking_deploy_is_recorded_as_failed() {
    let (runner, _) = runner();
    let id = runner
        .submit(new_job(DeployJobKind::DeployAll, None, false), |progress| {
            async move {
                progress.phase(DeployPhase::Rendering);
                panic!("render blew up");
            }
            .boxed()
        })
        .await
        .unwrap()
        .job
        .id;
    let job = wait_terminal(&runner, id).await;
    assert_eq!(job.state, DeployJobState::Failed);
    assert_eq!(job.error_status, Some(500));
    assert!(job.message.unwrap().contains("panic"));
}

#[tokio::test]
async fn deploy_all_without_a_result_succeeds_with_its_message() {
    let (runner, _) = runner();
    let id = runner
        .submit(new_job(DeployJobKind::DeployAll, None, true), |_| {
            async move { JobOutcome::Done("All enabled log sources deployed".into()) }.boxed()
        })
        .await
        .unwrap()
        .job
        .id;
    let job = wait_terminal(&runner, id).await;
    assert_eq!(job.state, DeployJobState::Succeeded);
    assert!(job.result.is_none());
    assert_eq!(job.kind, DeployJobKind::DeployAll);
    assert_eq!(job.log_source_id, None);
}

#[tokio::test]
async fn a_job_whose_process_died_reads_interrupted() {
    let (runner, store) = runner();
    let source = Uuid::now_v7();
    // A job some other (now dead) process created and never finished.
    let (job, _) = store
        .create_or_join(&new_job(DeployJobKind::Deploy, Some(source), true), "api-dead")
        .await
        .unwrap();
    store.set_phase(job.id, DeployPhase::Promoting).await.unwrap();
    assert_eq!(runner.get(job.id).await.unwrap().unwrap().state, DeployJobState::Running);

    store.age_heartbeat(job.id, STALE_AFTER + Duration::from_secs(1));
    let read = runner.get(job.id).await.unwrap().unwrap();
    assert_eq!(read.state, DeployJobState::Interrupted);
    assert_eq!(read.phase, DeployPhase::Done);
    assert!(read.message.unwrap().contains("run the deploy again"));

    // The stale job no longer blocks a new request for the same target.
    let fresh = runner
        .submit(new_job(DeployJobKind::Deploy, Some(source), true), |_| {
            async move { JobOutcome::Result(result(true, "ok")) }.boxed()
        })
        .await
        .unwrap();
    assert!(!fresh.coalesced);
    wait_terminal(&runner, fresh.job.id).await;
}

#[tokio::test]
async fn boot_recovery_interrupts_stale_jobs_only() {
    let (runner, store) = runner();
    let (stale, _) = store
        .create_or_join(&new_job(DeployJobKind::Deploy, Some(Uuid::now_v7()), true), "api-dead")
        .await
        .unwrap();
    let (live, _) = store
        .create_or_join(&new_job(DeployJobKind::Deploy, Some(Uuid::now_v7()), true), "api-live")
        .await
        .unwrap();
    store.age_heartbeat(stale.id, STALE_AFTER * 2);
    let (interrupted, _) = runner.recover().await.unwrap();
    assert_eq!(interrupted, 1);
    assert_eq!(store.get(stale.id).await.unwrap().unwrap().state, DeployJobState::Interrupted);
    assert_eq!(store.get(live.id).await.unwrap().unwrap().state, DeployJobState::Queued);
}

#[tokio::test]
async fn a_real_finish_overwrites_a_premature_interrupt() {
    // PostgreSQL unreachable for a minute: heartbeats failed, a poll marked
    // the job interrupted, then the deploy finished. The truth wins.
    let store = MemoryDeployJobStore::new();
    let (job, _) = store
        .create_or_join(&new_job(DeployJobKind::Deploy, Some(Uuid::now_v7()), false), "api")
        .await
        .unwrap();
    store.age_heartbeat(job.id, STALE_AFTER * 2);
    assert_eq!(store.interrupt_stale(STALE_AFTER, None).await.unwrap(), 1);
    store
        .finish(job.id, &finish_for(JobOutcome::Result(result(true, "ok")), false))
        .await
        .unwrap();
    assert_eq!(store.get(job.id).await.unwrap().unwrap().state, DeployJobState::Succeeded);
    // ...but a finished job is never rewritten.
    store
        .finish(job.id, &finish_for(JobOutcome::Error { status: 500, message: "x".into() }, false))
        .await
        .unwrap();
    assert_eq!(store.get(job.id).await.unwrap().unwrap().state, DeployJobState::Succeeded);
}

#[test]
fn progress_never_moves_backwards_except_into_rollback() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let progress = ChannelProgress {
        tx,
        last: Mutex::new(DeployPhase::Queued),
        rolled_back: AtomicBool::new(false),
    };
    for phase in [
        DeployPhase::WaitingForLock,
        DeployPhase::Validating,
        DeployPhase::WaitingForLock, // publish → deploy re-reports it: ignored
        DeployPhase::Promoting,
        DeployPhase::Rendering, // stale: ignored
        DeployPhase::Reloading,
        DeployPhase::RollingBack,
    ] {
        progress.phase(phase);
    }
    let mut seen = Vec::new();
    while let Ok(Update::Phase(phase)) = rx.try_recv() {
        seen.push(phase);
    }
    assert_eq!(
        seen,
        vec![
            DeployPhase::WaitingForLock,
            DeployPhase::Validating,
            DeployPhase::Promoting,
            DeployPhase::Reloading,
            DeployPhase::RollingBack,
        ]
    );
    assert!(progress.rolled_back.load(Ordering::SeqCst));
}

#[test]
fn wire_names_round_trip() {
    for kind in [DeployJobKind::Deploy, DeployJobKind::Undeploy, DeployJobKind::Publish, DeployJobKind::DeployAll] {
        assert_eq!(DeployJobKind::parse(kind.as_str()), Some(kind));
        assert_eq!(serde_json::to_value(kind).unwrap(), kind.as_str());
    }
    for state in [
        DeployJobState::Queued,
        DeployJobState::Running,
        DeployJobState::Succeeded,
        DeployJobState::Failed,
        DeployJobState::RolledBack,
        DeployJobState::Interrupted,
    ] {
        assert_eq!(DeployJobState::parse(state.as_str()), Some(state));
        assert_eq!(serde_json::to_value(state).unwrap(), state.as_str());
    }
    for phase in [
        DeployPhase::Queued,
        DeployPhase::WaitingForLock,
        DeployPhase::Validating,
        DeployPhase::Rendering,
        DeployPhase::ValidatingConfig,
        DeployPhase::Promoting,
        DeployPhase::Reloading,
        DeployPhase::RollingBack,
        DeployPhase::Done,
    ] {
        assert_eq!(DeployPhase::parse(phase.as_str()), Some(phase));
        assert_eq!(serde_json::to_value(phase).unwrap(), phase.as_str());
    }
}
