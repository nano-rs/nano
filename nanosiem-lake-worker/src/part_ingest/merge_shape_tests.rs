// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::parts::levels::PlannedMerge;

fn plan(rows: u64, bytes: u64, count: usize) -> PlannedMerge {
    PlannedMerge { output_level: Level::Hour, event_hour: 7, inputs: (0..count).map(|i| PartRef {
        part_id: crate::parts::format::PartId::new(i as i64).unwrap(), level: Level::L0,
        event_hour: 7, event_day: None, rows: rows / count as u64 + u64::from((i as u64) < rows % count as u64),
        min_time_us: 0, max_time_us: 1, schema_fingerprint: "0".repeat(64), provenance_sha256: "0".repeat(64),
        merkle_root: "0".repeat(64), sorted: true, data_bytes: bytes / count as u64,
        row_groups: 1, data_files: 1,
    }).collect() }
}

#[test]
fn an_unfit_full_hour_requests_a_bounded_upfront_split() {
    let merge = plan(115_000, 8_000_000, 164);
    let small = (2_090_000_000_f64 * super::super::merge_quota::MEMORY_GUARD_SHARE) as u64 - 1_200_000_000;
    let fp = (3_413_114_880_f64 * super::super::merge_quota::MEMORY_GUARD_SHARE) as u64 - 1_180_000_000;
    for room in [small, fp] {
        let choice = initial_shape(&merge, Some(room), 0, 0);
        assert_eq!(choice.shift, super::super::merge_attempts::MAX_SHIFT);
        let cap = choice.max_inputs.unwrap();
        assert!(cap >= 2 && cap < merge.inputs.len());
        assert!(crate::parts::levels::split_merge(merge.clone(), cap).iter()
            .all(|chunk| shape_estimate(&chunk.inputs, choice.shift) <= room));
    }
}

#[test]
fn bytes_rows_and_fan_in_all_contribute_and_overflow_is_bounded() {
    let base = plan(100, 100, 2);
    for heavier in [plan(100_000, 100, 2), plan(100, 10_000_000, 2), plan(100, 100, 8)] {
        assert!(shape_estimate(&heavier.inputs, 0) > shape_estimate(&base.inputs, 0));
    }
    let huge = plan(u64::MAX, u64::MAX, 164);
    assert_eq!(starting_shape(&huge, Some(0), u64::MAX), super::super::merge_attempts::MAX_SHIFT);
    for shift in 1..=super::super::merge_attempts::MAX_SHIFT {
        assert!(shape_estimate(&huge.inputs, shift) <= shape_estimate(&huge.inputs, shift - 1));
    }
}

#[test]
fn unknown_limits_and_other_lanes_keep_their_shape() {
    let mut merge = plan(115_000, 8_000_000, 164);
    assert_eq!(starting_shape(&merge, None, u64::MAX), 0);
    for level in [Level::Minute, Level::Day] {
        merge.output_level = level;
        assert_eq!(starting_shape(&merge, Some(0), u64::MAX), 0);
    }
}

#[test]
fn admission_reservations_leave_less_room_for_the_hour() {
    let merge = plan(115_000, 8_000_000, 164);
    assert!(initial_shape(&merge, Some(1_800_000_000), 600_000_000, 0).max_inputs
        < initial_shape(&merge, Some(1_800_000_000), 0, 0).max_inputs);
}
