// SPDX-License-Identifier: AGPL-3.0-or-later
//! Live sizing regressions through the production ingestor's merge planner.
use super::*;
use super::nan4749_ingest_tests::Lab;
use crate::part_ingest::merge_attempts::{merge_id, MergeAttempts, MAX_SHIFT};
use crate::part_ingest::merge_quota::MEMORY_PROBE_FOR_TEST;
use crate::parts::levels::PlannedMerge;

const ROLE: u64 = 3_413_114_880;
fn low_base() -> Option<(u64, u64)> { Some((270_000_000, ROLE)) }
fn high_base() -> Option<(u64, u64)> { Some((870_000_000, ROLE)) }
fn admission_full() -> Option<(u64, u64)> { Some((3_000_000_000, ROLE)) }
fn roomy() -> Option<(u64, u64)> { Some((0, 64 * 1024 * 1024 * 1024)) }

fn live_point(hour: i32, rows: u64, count: usize) -> PlannedMerge {
    let start = i64::from(hour) * 3_600_000_000;
    PlannedMerge { output_level: Level::Hour, event_hour: hour, inputs: (0..count).map(|i| PartRef {
        part_id: crate::parts::format::PartId::new(i as i64).unwrap(), level: Level::L0,
        event_hour: hour, event_day: None, rows: rows / count as u64 + u64::from((i as u64) < rows % count as u64),
        min_time_us: start, max_time_us: start + 3_599_999_999, schema_fingerprint: "0".repeat(64),
        provenance_sha256: "0".repeat(64), merkle_root: "0".repeat(64), sorted: true,
        // The brief gives rows and fan-in, not compressed bytes. Zero
        // exercises the row fallback, without inventing a live byte count.
        data_bytes: 0, row_groups: 1, data_files: 1,
    }).collect() }
}

async fn assert_live_point(hour: i32, rows: u64, inputs: usize, committed_fan_in: Option<usize>,
    expected: [(u8, Option<u32>); 2]) {
    for (probe, expected) in [low_base as fn() -> _, high_base as fn() -> _].into_iter().zip(expected) {
        let lab = Lab::new(ROLE * 2 / 5);
        let mut ingestor = lab.open().await; // the production constructor
        MEMORY_PROBE_FOR_TEST.set(Some(probe));
        let merge = live_point(hour, rows, inputs);
        let selected = ingestor.converge_memory_bound_merges(vec![merge.clone()]);
        let id = merge_id("h", hour);
        let entry = ingestor.merge_attempts.entry(&id).unwrap();
        assert_eq!((entry.failures, entry.parks, entry.in_flight), (0, 0, false));
        assert_eq!((entry.shift, entry.max_inputs), expected, "avoid shrinking the live fixture more than necessary");
        assert!(selected.iter().all(|chunk| !ingestor.fragmented_merge_may_run_beside_admission(chunk)),
            "a cap alone cannot claim the catch-up lane without a fragmented live hour");
        match committed_fan_in {
            Some(safe) => {
                assert_eq!(entry.shift, MAX_SHIFT);
                assert!(entry.max_inputs.is_some_and(|cap| cap as usize <= safe), "live {hour}: {entry:?}");
                assert!(selected.iter().all(|chunk| (2..=safe).contains(&chunk.inputs.len())));
            }
            None => {
                assert_eq!((selected.len(), selected[0].inputs.len(), entry.max_inputs), (1, inputs, None));
                assert!(entry.shift >= 2, "116k/5 stopped at shift 1 and committed at 2: {entry:?}");
            }
        }
        eprintln!("NAN-4818 live {hour}: rows {rows}, inputs {inputs}, baseline {}, first shift {}, cap {:?}, chunks {:?}",
            probe().unwrap().0, entry.shift, entry.max_inputs, selected.iter().map(|c| c.inputs.len()).collect::<Vec<_>>());
        let cap = entry.max_inputs;
        let reopened = MergeAttempts::open(&lab.config.work_dir, 0);
        assert_eq!(reopened.entry(&id), Some(entry), "choice is durable before any attempt starts");
        assert!(!reopened.died_during_merge());
        let actual = selected.iter().flat_map(|chunk| &chunk.inputs).map(|p| p.part_id.clone()).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual.len(), selected.iter().map(|chunk| chunk.inputs.len()).sum::<usize>(), "chunks never overlap");
        assert!(merge.inputs.len() - actual.len() <= 1, "only an odd single input may stay unmerged");
        MEMORY_PROBE_FOR_TEST.set(Some(roomy));
        ingestor.converge_memory_bound_merges(vec![merge]);
        assert_eq!(ingestor.merge_attempts.entry(&id).unwrap().max_inputs, cap, "more room cannot undo committed split policy");
        MEMORY_PROBE_FOR_TEST.set(None);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn live_498120_five_inputs_choose_the_observed_committing_shape() {
    assert_live_point(498120, 116_000, 5, None, [(2, None), (3, None)]).await;
}

#[tokio::test(flavor = "current_thread")]
async fn live_498126_thirty_nine_inputs_split_before_the_first_attempt() {
    assert_live_point(498126, 124_000, 39, Some(19), [(3, Some(19)), (3, Some(9))]).await;
}

#[tokio::test(flavor = "current_thread")]
async fn live_498128_fifty_three_inputs_skip_the_failed_twenty_six_input_chunk() {
    assert_live_point(498128, 131_000, 53, Some(13), [(3, Some(13)), (3, Some(13))]).await;
}

#[tokio::test(flavor = "current_thread")]
async fn memory_held_elsewhere_does_not_create_a_permanent_split() {
    let lab = Lab::new(ROLE * 2 / 5);
    let mut ingestor = lab.open().await;
    MEMORY_PROBE_FOR_TEST.set(Some(admission_full));
    let merge = live_point(498128, 131_000, 53);
    let selected = ingestor.converge_memory_bound_merges(vec![merge]);
    assert_eq!(selected.len(), 1);
    assert!(ingestor.merge_attempts.entry(&merge_id("h", 498128)).is_none());
    MEMORY_PROBE_FOR_TEST.set(None);
}

#[tokio::test(flavor = "current_thread")]
async fn committed_chunks_do_not_inflate_the_remaining_plan_or_repeat_after_restart() {
    let lab = Lab::new(ROLE * 2 / 5);
    let mut ingestor = lab.open().await;
    let id = merge_id("h", 498128);
    MEMORY_PROBE_FOR_TEST.set(Some(low_base));
    let original = live_point(498128, 131_000, 53);
    let chunks = ingestor.converge_memory_bound_merges(vec![original]);
    let cap = ingestor.merge_attempts.max_inputs(&id).unwrap();
    ingestor.merge_attempts.begin(&id, chunks[0].inputs.len()).unwrap();
    ingestor.merge_attempts.committed(&id).unwrap();
    let mut remaining = chunks[1].clone();
    let mut finished = chunks[0].inputs[0].clone();
    finished.level = Level::Hour;
    finished.rows = u64::MAX;
    let finished_id = finished.part_id.clone();
    remaining.inputs.push(finished);
    ingestor.merge_attempts = MergeAttempts::open(&lab.config.work_dir, 0);
    let selected = ingestor.converge_memory_bound_merges(vec![remaining]);
    assert_eq!(ingestor.merge_attempts.max_inputs(&id), Some(cap));
    assert!(selected.iter().flat_map(|chunk| &chunk.inputs).all(|p| p.part_id != finished_id));
    assert_eq!(ingestor.merge_attempts.entry(&id).unwrap().failures, 0);
    MEMORY_PROBE_FOR_TEST.set(None);
}

#[tokio::test(flavor = "current_thread")]
async fn skewed_inputs_are_sized_by_the_largest_chunk_and_running_policy_is_unchanged() {
    let lab = Lab::new(ROLE * 2 / 5);
    let mut ingestor = lab.open().await;
    MEMORY_PROBE_FOR_TEST.set(Some(low_base));
    let id = merge_id("h", 498128);
    let uniform = live_point(498128, 131_000, 53);
    let selected = ingestor.converge_memory_bound_merges(vec![uniform.clone()]);
    let uniform_cap = ingestor.merge_attempts.max_inputs(&id).unwrap();
    ingestor.merge_attempts.begin(&id, selected[0].inputs.len()).unwrap();
    let running = ingestor.merge_attempts.entry(&id).cloned();
    MEMORY_PROBE_FOR_TEST.set(Some(high_base));
    ingestor.converge_memory_bound_merges(vec![uniform.clone()]);
    assert_eq!(ingestor.merge_attempts.entry(&id), running.as_ref());
    ingestor.merge_attempts.committed(&id).unwrap();
    let mut skewed = uniform;
    for input in &mut skewed.inputs { input.rows = 0; }
    skewed.inputs[0].rows = 131_000;
    MEMORY_PROBE_FOR_TEST.set(Some(high_base));
    ingestor.converge_memory_bound_merges(vec![skewed]);
    assert!(ingestor.merge_attempts.max_inputs(&id).unwrap() < uniform_cap,
        "a large chunk must not be admitted on the average rows per input");
    MEMORY_PROBE_FOR_TEST.set(None);
}

#[tokio::test(flavor = "current_thread")]
async fn shrinking_a_durable_cap_rechecks_the_new_global_chunk_boundaries() {
    let lab = Lab::new(ROLE * 2 / 5);
    let mut ingestor = lab.open().await;
    MEMORY_PROBE_FOR_TEST.set(Some(high_base));
    let id = merge_id("h", 498126);
    ingestor.merge_attempts.plan_at_least(&id, MAX_SHIFT, Some(13)).unwrap();
    let mut merge = live_point(498126, 0, 39);
    // Each old 13-input chunk has at most one large input. A global cap
    // of six puts both in the same chunk, crossing the old boundary.
    merge.inputs[25].rows = 150_000;
    merge.inputs[26].rows = 150_000;
    let selected = ingestor.converge_memory_bound_merges(vec![merge]);
    assert!(!selected.is_empty());
    for chunk in &selected {
        let choice = super::super::merge::initial_shape(chunk,
            super::super::merge_quota::merge_headroom(), ingestor.cfg.merge_headroom_bytes, MAX_SHIFT);
        assert_eq!(choice.max_inputs, None, "the final chunk must fit without another split");
    }
    MEMORY_PROBE_FOR_TEST.set(None);
}

#[tokio::test(flavor = "current_thread")]
async fn an_unwritable_initial_plan_defers_work_and_an_unreadable_ledger_is_preserved() {
    for unreadable in [false, true] {
        let lab = Lab::new(ROLE * 2 / 5);
        let mut ingestor = lab.open().await;
        let path = lab.config.work_dir.join("merge-attempts.json");
        if unreadable {
            std::fs::write(&path, b"{broken").unwrap();
            ingestor.merge_attempts = MergeAttempts::open(&lab.config.work_dir, 0);
        } else {
            // A directory cannot be replaced by the atomic ledger rename.
            std::fs::create_dir(&path).unwrap();
        }
        MEMORY_PROBE_FOR_TEST.set(Some(low_base));
        for retry in 1..=2 {
            let selected = ingestor.converge_memory_bound_merges(vec![live_point(498128, 131_000, 53)]);
            assert!(selected.is_empty(), "no compute without a recorded plan, even on a later tick");
            assert_eq!(ingestor.health().merge_failures_total, retry);
        }
        if unreadable { assert_eq!(std::fs::read(&path).unwrap(), b"{broken"); }
        MEMORY_PROBE_FOR_TEST.set(None);
    }
}
