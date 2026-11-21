// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5611: the boot render's fast retry is bounded, its stall is a finding
//! (read from the shared volume, as nano-jobs does) until the pipeline
//! identity is recorded, and the quiet slow retry still recovers.

use super::*;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

const POLICY: RetryPolicy = RetryPolicy {
    max_attempts: 4,
    first_delay: Duration::from_secs(5),
    max_delay: Duration::from_secs(60),
    slow_delay: Duration::from_secs(300),
};

fn denied() -> std::io::Error {
    std::io::Error::from_raw_os_error(13)
}

#[derive(Debug, thiserror::Error)]
enum Wrapped {
    #[error("Vector config error: {0}")]
    Io(#[from] std::io::Error),
}

fn analysis() -> AnalysisResult {
    let metrics = crate::siem_health::analyzer::tests::base_zero_metrics_fixture();
    let mut analysis = crate::siem_health::analyzer::fallback_report(&metrics);
    analysis.overall_score = 95;
    analysis.recommendations.retain(|r| r.title != VECTOR_PIPELINE_GATE_TITLE);
    analysis
}

#[tokio::test(start_paused = true)]
async fn the_fast_retry_stops_after_the_limit_and_raises_the_finding() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join(".nano-pipeline-identity");
    std::fs::write(&marker, "2.0.32/fsync/off\n").unwrap();
    let renders = Arc::new(AtomicU32::new(0));
    let counted = renders.clone();
    let outcome = retry_until_recorded(
        POLICY,
        marker.clone(),
        "2.0.33/fsync/off".to_string(),
        || async { true },
        move || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), Wrapped>(Wrapped::Io(denied())) }
        },
    )
    .await;
    assert_eq!(renders.load(Ordering::SeqCst), POLICY.max_attempts, "exactly N fast retries");
    let RetryOutcome::GaveUp(stall) = outcome else {
        panic!("expected GaveUp, got {outcome:?}");
    };
    assert_eq!(stall.errno, Some(13));
    assert_eq!(stall.attempts, POLICY.max_attempts);
    assert_eq!(stall.marker_path, marker);
    assert!(stall.error.contains("os error 13"), "{}", stall.error);

    // Another process (nano-jobs) reads it from the shared dir.
    let current = current_stall(dir.path()).await.expect("the stall is recorded on the volume");
    assert_eq!(current, stall);
    let mut report = analysis();
    ensure_vector_pipeline_gate_findings(&mut report, Some(&current));
    assert_eq!(report.overall_score, 69);
    let rec = report.recommendations.iter().find(|r| r.title == VECTOR_PIPELINE_GATE_TITLE).expect("finding");
    assert!(rec.description.contains(&marker.display().to_string()), "{}", rec.description);
    assert!(rec.description.contains("errno 13"), "{}", rec.description);
    assert_eq!(rec.priority, "high");
    ensure_vector_pipeline_gate_findings(&mut report, Some(&current));
    assert_eq!(report.recommendations.iter().filter(|r| r.title == VECTOR_PIPELINE_GATE_TITLE).count(), 1);

    // Recorded later (a deploy, a restart): the finding clears and the record goes.
    std::fs::write(&marker, "2.0.33/fsync/off\n").unwrap();
    assert_eq!(current_stall(dir.path()).await, None);
    assert!(!dir.path().join(STALL_FILE).exists());
    let mut report = analysis();
    ensure_vector_pipeline_gate_findings(&mut report, current_stall(dir.path()).await.as_ref());
    assert!(!report.recommendations.iter().any(|r| r.title == VECTOR_PIPELINE_GATE_TITLE));
    assert_eq!(report.overall_score, 95);
}

#[tokio::test(start_paused = true)]
async fn the_slow_retry_recovers_and_clears_the_stall() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join(".nano-pipeline-identity");
    report_stall(&PipelineGateStall {
        marker_path: marker.clone(),
        identity: "2.0.33/fsync/off".to_string(),
        attempts: 15,
        error: "database unavailable".to_string(),
        errno: None,
    })
    .await;
    assert!(current_stall(dir.path()).await.is_some());
    // The database comes back on the third slow retry.
    let left = Arc::new(AtomicU32::new(3));
    let check = left.clone();
    let started = tokio::time::Instant::now();
    let retries = retry_slowly_until_recorded(
        POLICY,
        &marker,
        move || {
            let n = check.load(Ordering::SeqCst);
            async move { n > 0 }
        },
        move || {
            let now = left.fetch_sub(1, Ordering::SeqCst) - 1;
            async move {
                if now == 0 {
                    Ok(())
                } else {
                    Err(Wrapped::Io(std::io::Error::other("database unavailable")))
                }
            }
        },
    )
    .await;
    assert_eq!(retries, 3);
    assert_eq!(started.elapsed(), POLICY.slow_delay * 3);
    assert!(!dir.path().join(STALL_FILE).exists(), "cleared on success");
}

#[tokio::test(start_paused = true)]
async fn a_render_that_records_ends_the_retry_without_a_finding() {
    let dir = tempfile::tempdir().unwrap();
    let pending = Arc::new(AtomicU32::new(2));
    let check = pending.clone();
    let outcome = retry_until_recorded(
        POLICY,
        dir.path().join(".nano-pipeline-identity"),
        "2.0.33/fsync/off".to_string(),
        move || {
            let left = check.load(Ordering::SeqCst);
            async move { left > 0 }
        },
        move || {
            pending.fetch_sub(1, Ordering::SeqCst);
            async { Ok::<(), Wrapped>(()) }
        },
    )
    .await;
    assert_eq!(outcome, RetryOutcome::Recorded { retries: 2 });
    assert_eq!(current_stall(dir.path()).await, None);
    assert!(!dir.path().join(STALL_FILE).exists());
}

#[tokio::test(start_paused = true)]
async fn the_shipped_fast_retries_wait_735_seconds() {
    let dir = tempfile::tempdir().unwrap();
    let started = tokio::time::Instant::now();
    let outcome = retry_until_recorded(
        BOOT_RENDER_RETRY,
        dir.path().join(".nano-pipeline-identity"),
        "x".to_string(),
        || async { true },
        || async { Err::<(), Wrapped>(Wrapped::Io(denied())) },
    )
    .await;
    assert!(matches!(outcome, RetryOutcome::GaveUp(_)));
    // 5 + 10 + 20 + 40 + 11 x 60 s of waiting (each real render adds its own time).
    assert_eq!(started.elapsed(), Duration::from_secs(735));
}

#[tokio::test]
async fn no_record_or_an_unreadable_one_is_no_finding() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(current_stall(dir.path()).await, None);
    std::fs::write(dir.path().join(STALL_FILE), "not json").unwrap();
    assert_eq!(current_stall(dir.path()).await, None);
}

#[test]
fn errno_is_found_through_wrapping_errors() {
    let wrapped = Wrapped::Io(denied());
    assert_eq!(io_errno(&wrapped), Some(13));
    assert_eq!(io_errno(&std::fmt::Error), None);
}

/// NAN-5657: when the identity file's directory cannot take the stall record
/// (the root-owned case the finding describes), the record lands in the data
/// directory, the finding still reads it, and recording the identity clears it.
#[tokio::test]
async fn a_stall_that_cannot_be_written_beside_the_marker_falls_back_to_the_data_dir() {
    let config = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    // A marker whose "directory" is a regular file: every write beside it fails.
    let blocked = config.path().join("not-a-dir");
    std::fs::write(&blocked, "x").unwrap();
    let marker = blocked.join(".nano-pipeline-identity");
    let stall = PipelineGateStall {
        marker_path: marker.clone(),
        identity: "2.0.34/fsync/off".to_string(),
        attempts: 15,
        error: "Permission denied (os error 13)".to_string(),
        errno: Some(13),
    };
    report_stall_to(&stall, Some(data.path())).await;
    assert!(data.path().join(STALL_FILE).exists(), "recorded in the data directory");
    assert_eq!(current_stall_in(config.path(), Some(data.path())).await, Some(stall.clone()));
    assert_eq!(current_stall_in(config.path(), None).await, None, "no fallback, nothing to read");

    // Recorded later: the fallback record clears too.
    std::fs::write(config.path().join(".nano-pipeline-identity"), "2.0.34/fsync/off\n").unwrap();
    assert_eq!(current_stall_in(config.path(), Some(data.path())).await, None);
    assert!(!data.path().join(STALL_FILE).exists());

    report_stall_to(&stall, Some(data.path())).await;
    clear_stall_in(&marker, Some(data.path())).await;
    assert!(!data.path().join(STALL_FILE).exists(), "clear removes the fallback record");
}

fn stall_for(marker: &Path, identity: &str) -> PipelineGateStall {
    PipelineGateStall {
        marker_path: marker.to_path_buf(),
        identity: identity.to_string(),
        attempts: 15,
        error: "Permission denied (os error 13)".to_string(),
        errno: Some(13),
    }
}

/// NAN-5657 review: a resolved primary record (its identity is the recorded
/// one) never hides a live fallback record behind it.
#[tokio::test]
async fn a_resolved_primary_record_does_not_hide_a_live_fallback_one() {
    let config = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let marker = config.path().join(".nano-pipeline-identity");
    std::fs::write(&marker, "2.0.33/fsync/off\n").unwrap();
    let old = stall_for(&marker, "2.0.33/fsync/off");
    let live = stall_for(&marker, "2.0.34/fsync/off");
    std::fs::write(config.path().join(STALL_FILE), serde_json::to_vec(&old).unwrap()).unwrap();
    std::fs::write(data.path().join(STALL_FILE), serde_json::to_vec(&live).unwrap()).unwrap();
    assert_eq!(current_stall_in(config.path(), Some(data.path())).await, Some(live));
    assert!(!config.path().join(STALL_FILE).exists(), "the resolved record is removed");
}

/// NAN-5657 review: a new primary record replaces an older fallback one, so
/// recovery never leaves the fallback behind to raise the finding again.
#[tokio::test]
async fn a_primary_record_supersedes_an_older_fallback_one() {
    let config = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let marker = config.path().join(".nano-pipeline-identity");
    std::fs::write(data.path().join(STALL_FILE), serde_json::to_vec(&stall_for(&marker, "2.0.34/fsync/off")).unwrap())
        .unwrap();
    report_stall_to(&stall_for(&marker, "2.0.35/fsync/off"), Some(data.path())).await;
    assert!(config.path().join(STALL_FILE).exists());
    assert!(!data.path().join(STALL_FILE).exists(), "the older fallback record is gone");
    std::fs::write(&marker, "2.0.35/fsync/off\n").unwrap();
    assert_eq!(current_stall_in(config.path(), Some(data.path())).await, None);
    assert_eq!(current_stall_in(config.path(), Some(data.path())).await, None, "nothing resurfaces");
}
