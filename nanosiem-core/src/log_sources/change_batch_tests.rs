// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5678: N changes submitted together cost one batch (one render, one
//! reload); results stay per key; a caller that stops waiting does not cancel
//! the batch; a panicking batch fails only its own callers.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use futures::FutureExt;

/// A runner that records each batch it ran and answers `Ok(key)` for every
/// key, except `fail` keys, which get `Err`.
fn recording_runner(
    batches: Arc<Mutex<Vec<Vec<u32>>>>,
    hold: Duration,
) -> BatchRunner<u32, Result<u32, String>> {
    Arc::new(move |keys: Vec<u32>| {
        let batches = Arc::clone(&batches);
        async move {
            batches.lock().unwrap().push(keys.clone());
            tokio::time::sleep(hold).await;
            keys.into_iter()
                .map(|k| (k, if k >= 1000 { Err(format!("{k} refused")) } else { Ok(k) }))
                .collect()
        }
        .boxed()
    })
}

#[tokio::test]
async fn n_changes_submitted_together_cost_one_batch() {
    let batcher = Arc::new(ChangeBatcher::new(Duration::from_millis(50)));
    let batches = Arc::new(Mutex::new(Vec::new()));
    let runner = recording_runner(Arc::clone(&batches), Duration::from_millis(10));

    let calls = (0..36u32).map(|k| {
        let batcher = Arc::clone(&batcher);
        let runner = Arc::clone(&runner);
        tokio::spawn(async move { batcher.submit(vec![k], runner).await })
    });
    let results = futures::future::join_all(calls).await;

    for (k, result) in results.into_iter().enumerate() {
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[&(k as u32)], Ok(Ok(k as u32)), "each caller gets its own key's result");
    }
    let batches = batches.lock().unwrap();
    assert_eq!(batches.len(), 1, "36 changes, one render/reload: {batches:?}");
    assert_eq!(batches[0].len(), 36);
    assert_eq!(batcher.batches_run(), 1);
}

/// A batch holds the deploy lock for its whole reload. Changes that arrive
/// meanwhile wait for it and then go out TOGETHER in the next batch, so a
/// stream of changes costs at most two reloads, not one per change.
#[tokio::test]
async fn changes_arriving_during_a_batch_share_the_next_one() {
    let batcher = Arc::new(ChangeBatcher::new(Duration::ZERO));
    let batches = Arc::new(Mutex::new(Vec::new()));
    let runner = recording_runner(Arc::clone(&batches), Duration::from_millis(200));

    let first = {
        let batcher = Arc::clone(&batcher);
        let runner = Arc::clone(&runner);
        tokio::spawn(async move { batcher.submit(vec![1], runner).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let later: Vec<_> = (2..=10u32)
        .map(|k| {
            let batcher = Arc::clone(&batcher);
            let runner = Arc::clone(&runner);
            tokio::spawn(async move { batcher.submit(vec![k], runner).await })
        })
        .collect();
    assert_eq!(first.await.unwrap()[&1], Ok(Ok(1)));
    for (i, call) in later.into_iter().enumerate() {
        let k = i as u32 + 2;
        assert_eq!(call.await.unwrap()[&k], Ok(Ok(k)));
    }
    let batches = batches.lock().unwrap();
    assert_eq!(batches.len(), 2, "{batches:?}");
    assert_eq!(batches[0], vec![1]);
    assert_eq!(batches[1], (2..=10).collect::<Vec<_>>());
}

/// A multi-key (bulk) submission is one batch; duplicates are judged once;
/// a key the batch refused fails alone while the rest succeed.
#[tokio::test]
async fn bulk_submission_keeps_results_per_key() {
    let batcher = ChangeBatcher::new(Duration::ZERO);
    let batches = Arc::new(Mutex::new(Vec::new()));
    let runner = recording_runner(Arc::clone(&batches), Duration::ZERO);

    let results = batcher.submit(vec![1, 2, 1000, 2, 3], runner).await;

    assert_eq!(results[&1], Ok(Ok(1)));
    assert_eq!(results[&3], Ok(Ok(3)));
    assert_eq!(results[&1000], Ok(Err("1000 refused".to_string())));
    assert_eq!(batches.lock().unwrap().as_slice(), &[vec![1, 2, 1000, 3]], "deduplicated, in order");
}

#[tokio::test]
async fn a_key_the_batch_did_not_judge_is_reported_not_invented() {
    let batcher = ChangeBatcher::new(Duration::ZERO);
    let runner: BatchRunner<u32, Result<u32, String>> =
        Arc::new(|_keys: Vec<u32>| async { HashMap::from([(1, Ok(1))]) }.boxed());
    let results = batcher.submit(vec![1, 2], runner).await;
    assert_eq!(results[&1], Ok(Ok(1)));
    assert_eq!(results[&2], Err(BatchError::NoResult));
}

/// NAN-5678 (d): the HTTP client timing out drops the caller's future. The
/// batch keeps going to completion: the render, the reload and the row
/// writes after it are never cut off between steps.
#[tokio::test]
async fn a_caller_that_stops_waiting_does_not_cancel_the_batch() {
    let batcher = Arc::new(ChangeBatcher::new(Duration::ZERO));
    let finished = Arc::new(AtomicUsize::new(0));
    let runner: BatchRunner<u32, Result<u32, String>> = {
        let finished = Arc::clone(&finished);
        Arc::new(move |keys: Vec<u32>| {
            let finished = Arc::clone(&finished);
            async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                finished.fetch_add(keys.len(), Ordering::SeqCst);
                keys.into_iter().map(|k| (k, Ok(k))).collect()
            }
            .boxed()
        })
    };

    let timed_out = tokio::time::timeout(Duration::from_millis(20), batcher.submit(vec![7], Arc::clone(&runner))).await;
    assert!(timed_out.is_err(), "the caller gave up first");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(finished.load(Ordering::SeqCst), 1, "the batch still ran to the end");

    // The batcher is idle again and serves the next caller.
    assert_eq!(batcher.submit(vec![8], runner).await[&8], Ok(Ok(8)));
}

#[tokio::test]
async fn a_panicking_batch_fails_its_callers_and_the_next_batch_still_runs() {
    let batcher = ChangeBatcher::new(Duration::ZERO);
    let panicking: BatchRunner<u32, Result<u32, String>> =
        Arc::new(|_keys: Vec<u32>| async { panic!("render blew up") }.boxed());
    let results = batcher.submit(vec![1], panicking).await;
    assert!(matches!(results[&1], Err(BatchError::Aborted(_))), "{results:?}");

    let batches = Arc::new(Mutex::new(Vec::new()));
    let results = batcher.submit(vec![2], recording_runner(batches, Duration::ZERO)).await;
    assert_eq!(results[&2], Ok(Ok(2)));
}

#[tokio::test]
async fn an_empty_submission_runs_nothing() {
    let batcher: ChangeBatcher<u32, Result<u32, String>> = ChangeBatcher::new(Duration::ZERO);
    let batches = Arc::new(Mutex::new(Vec::new()));
    assert!(batcher.submit(vec![], recording_runner(Arc::clone(&batches), Duration::ZERO)).await.is_empty());
    assert_eq!(batcher.batches_run(), 0);
}
