// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ingest[T] memory model (NAN-3183 OOM).
//!
//! Catch-up holds, at once: one admission group (JSON values + its Arrow
//! decode), the filling Arrow buffer, the pipelined flush in flight (its
//! sealed buffer, the concat + sort copies of its hours and up to
//! [`MAX_PARALLEL_L0_WRITES`] Parquet part writers) and the background merge
//! lanes. Every one of them is charged against ONE working budget
//! ([`super::ingest::buffer_budget_for`]): admission takes only the room the
//! others leave, the flush in flight is charged its build cost (not only its
//! buffered rows), and its writer count shrinks when the room is tight.
//!
//! Measured on the load-test tenant edge segments (`catchup_bench::catchup_memory_profile`,
//! 66,822-row flush, 3.15 KB/row of Arrow):
//! - admission peak 1.24x the modelled JSON heap (`value_heap_bytes`);
//! - flush build 1.94x the sealed buffer above it (concat + sorted copy),
//!   +~21 MiB per extra parallel 16.7k-row part writer;
//! - a minute merge of 8 such L0 parts: 136 MiB.
//!
//! The live heap stayed ~1.3 GiB at peak, but glibc's per-thread arenas kept
//! what rayon, the blocking pool and the per-flush writer threads freed: RSS
//! climbed to ~5 GiB in 20 cycles locally on 32 threads (live heap between
//! cycles 243 MiB). [`tune_allocator`] serves large buffers from mmap;
//! [`release_freed`] hands freed arena pages back after every flush and
//! merge commit.

/// Flush build working memory per byte of the sealed buffer (concat of its
/// admission batches + the sorted copy, both alive while the sort runs).
/// Measured 1.94.
pub const BUILD_BYTES_PER_BUFFER_BYTE: f64 = 2.0;
/// Resident bytes of one parallel L0 part writer beyond its rows (Parquet
/// column buffers, token groups, partials). Measured ~21 MiB; doubled.
pub const L0_WRITER_BYTES: u64 = 48 * 1024 * 1024;
/// Admission peak per modelled JSON-value heap byte (measured 1.24).
pub const ADMISSION_PEAK_PER_MODELLED_HEAP: f64 = 1.5;
/// Threads writing one flush's L0 parts at most.
pub const MAX_PARALLEL_L0_WRITES: usize = 4;
/// Share of the working budget the filling buffer may reach before it
/// flushes: a sealed flight (1 + BUILD) plus the next buffer (1) plus
/// admission and writers must fit the rest.
pub const BUFFER_SHARE_OF_WORKING: f64 = 1.0 / (2.0 + BUILD_BYTES_PER_BUFFER_BYTE + 1.0);

/// Bytes a sealed flush holds until it commits: its rows, its build copies
/// and its part writers.
pub fn flight_bytes(buffer_bytes: u64, writers: usize) -> u64 {
    let build = (buffer_bytes as f64 * BUILD_BYTES_PER_BUFFER_BYTE) as u64;
    buffer_bytes.saturating_add(build).saturating_add(writers as u64 * L0_WRITER_BYTES)
}

/// Parallel L0 writers a flush of `buffer_bytes` may use with `room` bytes
/// of the working budget free (everything else already charged): the most
/// that fit, at least one (a flush must always make progress).
pub fn writers_for(buffer_bytes: u64, room: u64) -> usize {
    (1..=MAX_PARALLEL_L0_WRITES).rev().find(|w| flight_bytes(buffer_bytes, *w) <= room).unwrap_or(1)
}

/// Bytes the filling buffer may reach before it is due.
pub fn buffer_cap(working_budget: u64) -> u64 {
    (working_budget as f64 * BUFFER_SHARE_OF_WORKING) as u64
}

/// What admission may add with `committed` bytes already charged (the
/// buffer, the flight, the merges): the predicted admission peak (JSON
/// values while they decode) plus the Arrow rows it leaves in the buffer.
pub fn admission_fits(working_budget: u64, committed: u64, predicted_heap: f64, predicted_arrow: f64) -> bool {
    let room = working_budget.saturating_sub(committed) as f64;
    predicted_heap * ADMISSION_PEAK_PER_MODELLED_HEAP + predicted_arrow <= room
}

/// Cap glibc's malloc retention: a fixed mmap threshold so large Arrow and
/// Parquet buffers return to the kernel on free (glibc's dynamic threshold
/// otherwise grows to 32 MiB after the first large free and serves them from
/// the per-thread arenas, which keep them), and a bounded trim threshold.
/// The arena count is left alone: capping it at 4 cost 22% of admission
/// throughput (rayon threads contend on the arena locks). Call once at
/// ingest start. No-op off glibc.
pub fn tune_allocator() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        // SAFETY: mallopt only changes allocator parameters.
        libc::mallopt(libc::M_MMAP_THRESHOLD, MMAP_THRESHOLD_BYTES);
        libc::mallopt(libc::M_TRIM_THRESHOLD, TRIM_THRESHOLD_BYTES);
    }
}

/// Allocations at least this large are mmapped (returned on free).
pub const MMAP_THRESHOLD_BYTES: i32 = 1024 * 1024;
/// Free top-of-heap kept before glibc trims it.
pub const TRIM_THRESHOLD_BYTES: i32 = 64 * 1024 * 1024;

/// Return freed pages of every arena to the kernel (after a flush or merge
/// commit: the flight's buffers were just dropped). No-op off glibc.
pub fn release_freed() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        // SAFETY: malloc_trim only releases free memory.
        libc::malloc_trim(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn the_flight_is_charged_its_build_and_writers_not_only_its_rows() {
        let rows = 206 * MIB;
        assert_eq!(flight_bytes(rows, 4), rows + 2 * rows + 4 * L0_WRITER_BYTES);
        assert!(flight_bytes(rows, 1) < flight_bytes(rows, 4));
    }

    #[test]
    fn writers_scale_down_with_the_room() {
        let rows = 206 * MIB;
        assert_eq!(writers_for(rows, 2048 * MIB), 4);
        assert_eq!(writers_for(rows, flight_bytes(rows, 4)), 4);
        assert_eq!(writers_for(rows, flight_bytes(rows, 4) - 1), 3);
        assert_eq!(writers_for(rows, flight_bytes(rows, 2)), 2);
        // Never below one: a flush always makes progress.
        assert_eq!(writers_for(rows, 0), 1);
    }

    #[test]
    fn admission_takes_only_the_room_left() {
        let budget = 2048 * MIB;
        // 500 MiB modelled heap peaks at 750 MiB, plus 50 MiB of rows.
        assert!(admission_fits(budget, 0, 500.0 * MIB as f64, 50.0 * MIB as f64));
        // The same admission no longer fits beside a full flight (1,392 MiB).
        let flight = flight_bytes(400 * MIB, 4);
        assert!(!admission_fits(budget, flight, 500.0 * MIB as f64, 50.0 * MIB as f64));
        assert!(admission_fits(budget, flight, 200.0 * MIB as f64, 50.0 * MIB as f64));
    }

    #[test]
    fn a_flight_and_the_next_buffer_fit_the_budget() {
        for budget in [512 * MIB, 2048 * MIB, 4096 * MIB] {
            let cap = buffer_cap(budget);
            assert!(flight_bytes(cap, 1) + cap <= budget, "{budget}");
        }
    }
}
