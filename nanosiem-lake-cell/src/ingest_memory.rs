// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared ingest admission, flush and placement reservations.

use crate::budget::{GIB, MIB};

pub const DEFAULT_WORKING_BUDGET_BYTES: u64 = 768 * MIB;
/// Below half the signed 32-bit Arrow variable-column offset range.
pub const MAX_BUFFER_BYTES: u64 = GIB;
pub const MIN_WORKING_BYTES: u64 = 64 * MIB;
const BUILD_COPIES: u64 = 2;
/// Full production builds measured up to 4.17x retained Arrow (50k rows;
/// earlier 50k/70k/120k runs: 3.66x/2.63x/1.23x). Five adds 20% margin.
/// Keep this separate from the unchanged merge copy calibration above.
const FLUSH_BUILD_PEAK_PER_ARROW_BYTE: u64 = 5;
/// Retained input + measured build + next buffer, with admission room.
/// Keep a full flight and a full next buffer inside the working envelope.
const BUFFER_DIVISOR: u64 = FLUSH_BUILD_PEAK_PER_ARROW_BYTE + 3;
/// The running guard's boundary; pinned against the worker guard in tests.
pub const ROLE_GUARD_PERCENT: u64 = 85;
/// Process/code/allocator headroom, including a margin over the measured base.
pub const PROCESS_BASE_RESERVE_BYTES: u64 = 160 * MIB;
pub const UID_BYTES_PER_ENTRY: u64 = 58;
pub const MIN_WINDOW_UIDS: usize = 500_000;
pub const MAX_WINDOW_UIDS: usize = 12_000_000;
pub const BUFFER_SHARE_OF_WORKING: f64 = 1.0 / BUFFER_DIVISOR as f64;
/// Existing merge concat/sort calibration. Ingest's measured whole-build
/// envelope is separate, so this change does not alter merge sizing.
pub const BUILD_BYTES_PER_BUFFER_BYTE: f64 = BUILD_COPIES as f64;
/// Measured writer scratch ~21 MiB, with margin for index/Parquet variation.
pub const L0_WRITER_BYTES: u64 = 48 * MIB;
/// Bound native writer threads/stacks on an unlimited host.
pub const MAX_PARALLEL_L0_WRITES: usize = 64;
pub const REFERENCE_L0_WRITERS: usize = 4;
/// Preserve the original ordinary-part batch on modest roles; larger role
/// caps continue to scale. This is a progress floor, not a global ceiling.
pub const FLUSH_PROGRESS_ROWS: u64 = REFERENCE_L0_WRITERS as u64 * crate::budget::L0_PART_MIN_ROWS;
pub const FLIGHT_ADMISSION_BYTES: u64 = 3 * L0_WRITER_BYTES;
/// Row-oriented index/digest scratch independent of narrow Arrow width.
pub const FLUSH_ROW_MEMORY_BYTES: u64 = 1024;

const fn min(a: u64, b: u64) -> u64 {
    if a < b {
        a
    } else {
        b
    }
}
const fn max(a: u64, b: u64) -> u64 {
    if a > b {
        a
    } else {
        b
    }
}

pub const fn uid_window_cap(memory_bytes: u64) -> usize {
    let rows = memory_bytes.saturating_mul(3) / 10 / UID_BYTES_PER_ENTRY;
    min(max(rows, MIN_WINDOW_UIDS as u64), MAX_WINDOW_UIDS as u64) as usize
}

/// Process headroom scales down on modest roles so their existing working
/// floor is preserved; the measured base reservation bounds larger roles.
pub const fn process_base_reserve(memory_cap_bytes: u64) -> u64 {
    // 85% guard - 30% UID - the existing 30% working floor leaves 25%.
    min(PROCESS_BASE_RESERVE_BYTES, memory_cap_bytes / 4)
}

/// Spend the guard-safe role envelope after the bounded UID window and
/// process base. Admission, buffer, flight and existing merges share it.
pub const fn working_budget(memory_cap_bytes: u64) -> u64 {
    if memory_cap_bytes == 0 {
        return DEFAULT_WORKING_BUDGET_BYTES;
    }
    let guard = (memory_cap_bytes as u128 * ROLE_GUARD_PERCENT as u128 / 100) as u64;
    let uid = uid_window_cap(memory_cap_bytes) as u64 * UID_BYTES_PER_ENTRY;
    let bytes = guard
        .saturating_sub(uid)
        .saturating_sub(process_base_reserve(memory_cap_bytes));
    min(
        max(bytes, MIN_WORKING_BYTES),
        MAX_BUFFER_BYTES * BUFFER_DIVISOR,
    )
}

pub const fn writer_limit(cpu_millicores: u32) -> usize {
    let cores = (cpu_millicores / 1000) as usize;
    if cores == 0 {
        1
    } else if cores > MAX_PARALLEL_L0_WRITES {
        MAX_PARALLEL_L0_WRITES
    } else {
        cores
    }
}

pub const fn buffer_cap(working_budget: u64) -> u64 {
    min(working_budget / BUFFER_DIVISOR, MAX_BUFFER_BYTES)
}

/// Small roles retain the original ordinary-part batch floor to avoid
/// extra low-rate seals/signing calls. Heap admission and whole-object
/// progress bounds still apply; larger capacities come from role memory.
pub const fn flush_max_rows(working_budget: u64) -> u64 {
    let rows = buffer_cap(working_budget) / FLUSH_ROW_MEMORY_BYTES;
    if working_budget >= MIN_WORKING_BYTES {
        max(rows, FLUSH_PROGRESS_ROWS)
    } else {
        max(rows, 1)
    }
}

pub const fn writer_room(working: u64, merges: u64, flights: u64) -> u64 {
    let admission = min(working / 3, FLIGHT_ADMISSION_BYTES);
    working.saturating_sub(
        merges
            .saturating_add(buffer_cap(working))
            .saturating_add(admission)
            .saturating_add(flights),
    )
}

/// Retained input + the larger measured build envelope or writer phase.
/// Writer scratch does not add to the whole-build high-water mark.
pub const fn flight_bytes(buffer_bytes: u64, writers: usize) -> u64 {
    let sort = buffer_bytes.saturating_mul(FLUSH_BUILD_PEAK_PER_ARROW_BYTE);
    let write = buffer_bytes.saturating_add((writers as u64).saturating_mul(L0_WRITER_BYTES));
    buffer_bytes.saturating_add(max(sort, write))
}

pub const fn writers_for(buffer_bytes: u64, room: u64, max_writers: usize) -> usize {
    let mut writers = min(max(max_writers as u64, 1), MAX_PARALLEL_L0_WRITES as u64) as usize;
    while writers > 1 {
        if flight_bytes(buffer_bytes, writers) <= room {
            return writers;
        }
        writers -= 1;
    }
    1 // Existing progress fallback for roles smaller than fixed writer scratch.
}

pub const fn flush_rows_for_working(
    working: u64,
    merges: u64,
    arrow_row_bytes: u64,
    max_writers: usize,
) -> u64 {
    // Below the ordinary four-part progress floor there is no larger
    // batch to buy. Preserve the legacy row/packing policy; byte caps and
    // heap admission still bound whole-object progress exactly as before.
    let nominal_rows = flush_max_rows(working);
    if nominal_rows == FLUSH_PROGRESS_ROWS {
        return nominal_rows;
    }
    let width = if arrow_row_bytes == 0 {
        FLUSH_ROW_MEMORY_BYTES
    } else {
        arrow_row_bytes
    };
    let byte_rows = min(max(buffer_cap(working) / width, 1), nominal_rows);
    if byte_rows < 2 * crate::budget::L0_PART_MIN_ROWS {
        return byte_rows;
    }
    let room = writer_room(working, merges, 0);
    let mut writers = min(max_writers as u64, MAX_PARALLEL_L0_WRITES as u64) as usize;
    while writers >= 2 {
        // Both phases must fit, rather than adding their separate peaks.
        let build_bytes = room / (1 + FLUSH_BUILD_PEAK_PER_ARROW_BYTE);
        let write_bytes = room.saturating_sub(writers as u64 * L0_WRITER_BYTES) / 2;
        let rows = min(min(build_bytes, write_bytes) / width, byte_rows);
        if rows >= writers as u64 * crate::budget::L0_PART_MIN_ROWS {
            return rows;
        }
        writers -= 1;
    }
    byte_rows
}

/// Whole-GiB placement for useful CPU lanes, bounded by Arrow's input
/// ceiling. The row threshold buys an ordinary L0 part per writer; it is
/// not the old fixed flush cap. Runtime may fill further within this model.
pub(crate) const fn parallel_flush_role_minimum(
    merge_reserve: u64,
    requested_writers: usize,
) -> u64 {
    let mut writers = min(
        max(requested_writers as u64, 1),
        MAX_PARALLEL_L0_WRITES as u64,
    ) as usize;
    let mut need;
    loop {
        let bytes = writers as u64
            * crate::budget::L0_PART_MIN_ROWS
            * crate::budget::INGEST_REFERENCE_ARROW_ROW_BYTES;
        let fixed = flight_bytes(bytes, writers)
            .saturating_add(merge_reserve)
            .saturating_add(FLIGHT_ADMISSION_BYTES);
        need = max(
            bytes.saturating_mul(BUFFER_DIVISOR),
            fixed
                .saturating_mul(BUFFER_DIVISOR)
                .div_ceil(BUFFER_DIVISOR - 1),
        );
        if (bytes <= MAX_BUFFER_BYTES && need <= MAX_BUFFER_BYTES * BUFFER_DIVISOR) || writers == 1
        {
            break;
        }
        writers -= 1;
    }
    let mut role = GIB;
    while working_budget(role) < need && role < 64 * GIB {
        role += GIB;
    }
    role
}

/// Placement reference uses the same width/writer/flight constraints.
pub const fn flush_rows_for_width(role_memory: u64, arrow_row_bytes: u64) -> u64 {
    flush_rows_for_working(
        working_budget(role_memory),
        crate::budget::INGEST_FLUSH_MERGE_RESERVE_BYTES,
        arrow_row_bytes,
        REFERENCE_L0_WRITERS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_envelope_reserves_uid_and_base_before_working_memory() {
        assert_eq!(working_budget(0), DEFAULT_WORKING_BUDGET_BYTES);
        assert_eq!(working_budget(1), MIN_WORKING_BYTES);
        assert_eq!(working_budget(u64::MAX), MAX_BUFFER_BYTES * BUFFER_DIVISOR);
        assert_eq!(flush_max_rows(0), 1);
        for role in [
            256 * MIB,
            512 * MIB,
            GIB,
            2_089_996_288,
            3_413_114_880,
            32 * GIB,
        ] {
            let uid = uid_window_cap(role) as u64 * UID_BYTES_PER_ENTRY;
            assert!(
                working_budget(role) + uid + process_base_reserve(role)
                    <= role * ROLE_GUARD_PERCENT / 100
            );
            assert!(buffer_cap(working_budget(role)) <= MAX_BUFFER_BYTES);
        }
        assert!(working_budget(3_413_114_880) > working_budget(2_089_996_288));
        assert_eq!(writer_limit(500), 1);
        assert_eq!(writer_limit(4_000), 4);
        assert_eq!(writer_limit(16_000), 16);
        assert_eq!(writer_limit(u32::MAX), MAX_PARALLEL_L0_WRITES);
    }

    #[test]
    fn useful_wide_flushes_scale_inside_both_build_phases() {
        for (role, minimum) in [(2_089_996_288, 50_000), (3_413_114_880, 120_000)] {
            let working = working_budget(role);
            let merges = role / 20;
            let rows = flush_rows_for_working(working, merges, 1_648, 4);
            let bytes = rows * 1_648;
            let room = writer_room(working, merges, 0);
            let writers = writers_for(bytes, room, 4);
            assert!(rows >= minimum, "role={role} rows={rows}");
            assert!(writers >= 2);
            assert!(flight_bytes(bytes, writers) <= room);
            assert!(bytes <= buffer_cap(working));
            assert!(rows <= flush_max_rows(working));
        }
        // Whole build phases, not the sum of each phase's high-water mark.
        assert_eq!(flight_bytes(200 * MIB, 4), 1_200 * MIB);
        assert_eq!(flight_bytes(32 * MIB, 4), 256 * MIB);
        assert_eq!(flush_max_rows(MIN_WORKING_BYTES), 65_536);
    }

    #[test]
    fn placement_floor_buys_useful_cpu_lanes_with_the_runtime_model() {
        let merge = crate::budget::INGEST_FLUSH_MERGE_RESERVE_BYTES;
        assert_eq!(parallel_flush_role_minimum(merge, 4), 4 * GIB);
        for (cpu, useful) in [(4_000, 4), (8_000, 8), (16_000, 16)] {
            let lanes = writer_limit(cpu);
            let role = parallel_flush_role_minimum(merge, lanes);
            let working = working_budget(role);
            let width = crate::budget::INGEST_REFERENCE_ARROW_ROW_BYTES;
            let rows = flush_rows_for_working(working, merge, width, lanes);
            let room = writer_room(working, merge, 0);
            assert_eq!(
                (rows / crate::budget::L0_PART_MIN_ROWS).min(lanes as u64),
                useful as u64
            );
            assert_eq!(writers_for(rows * width, room, useful), useful);
            let smaller = working_budget(role - GIB);
            let smaller_rows = flush_rows_for_working(smaller, merge, width, lanes);
            assert!(
                smaller_rows < useful as u64 * crate::budget::L0_PART_MIN_ROWS
                    || writers_for(smaller_rows * width, writer_room(smaller, merge, 0), lanes)
                        < lanes
            );
        }
        let high = working_budget(32 * GIB);
        let rows = flush_rows_for_working(high, merge, 2_400, 16);
        assert!(rows > 120_000);
        assert_eq!(
            writers_for(rows * 2_400, writer_room(high, merge, 0), 16),
            16
        );
    }
}
