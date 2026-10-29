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
/// Admission room kept when choosing flush writers, capped so a 6 GiB role
/// still runs four L0 writers beside two maximum-window minute merges.
/// Admission itself always checks the actual remaining working budget.
pub const FLIGHT_ADMISSION_BYTES: u64 = 3 * L0_WRITER_BYTES;
/// Share of the working budget the filling buffer may reach before it
/// flushes: a sealed flight (1 + BUILD) plus the next buffer (1) plus
/// admission, writers and reserved merge room must fit the rest. At a
/// 628 MB working budget, a fifth plus four writers monopolized the budget;
/// an eighth leaves room for calibrated admission beside a flight.
/// Large roles still reach the flush row cap before this byte cap.
pub const BUFFER_SHARE_OF_WORKING: f64 = 1.0 / 8.0;

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

/// NAN-4749: packs one tick's objects into admission groups that decode one
/// after another. A group's JSON values live only while it decodes; what it
/// leaves is its Arrow rows. So a group must fit beside everything already
/// charged plus the Arrow rows of the groups before it, and the tick is no
/// longer capped by one group's transient JSON peak (the 1.0.11 bakeoff:
/// a few thousand rows per tick, tick overhead dominating at 10k eps).
///
/// Every group's transient peak obeys the admission bound. Joins and new
/// groups also obey the buffer's byte and row caps: the flush keeps the size
/// its build was sized for. An oversized first object retains the existing
/// progress path, which admission cuts into bounded slices.
#[derive(Debug, Clone)]
pub struct AdmissionGroups {
    working_budget: u64,
    committed: u64,
    buffer_bytes: u64,
    buffer_rows: u64,
    /// Rows offered this tick (footer counts, before deduplication).
    rows: u64,
    /// Arrow rows of the closed groups.
    closed_arrow: f64,
    /// The open group's predicted JSON heap and Arrow rows.
    heap: f64,
    arrow: f64,
    groups: usize,
}

/// What [`AdmissionGroups::offer`] decided for one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// Joins the open group.
    Joins,
    /// Starts a new group (the open one closes).
    NewGroup,
    /// Does not fit this tick.
    Refused,
}

impl AdmissionGroups {
    /// `committed`: bytes already charged to the working budget (the
    /// buffer, flights, merges); `buffer_bytes`: the filling buffer's share
    /// of it; `buffer_rows`: rows already held in the filling buffer.
    pub fn new(working_budget: u64, committed: u64, buffer_bytes: u64, buffer_rows: u64) -> Self {
        Self { working_budget, committed, buffer_bytes, buffer_rows, rows: 0, closed_arrow: 0.0, heap: 0.0, arrow: 0.0, groups: 0 }
    }

    /// Offer the next object (its predicted modelled JSON heap and Arrow rows).
    /// Preselection does not know footer row counts yet and passes 0;
    /// admission repacks with the actual counts before decoding anything.
    pub fn offer(&mut self, heap: f64, arrow: f64, rows: u64) -> Offer {
        let buffered = self.buffer_bytes as f64 + self.closed_arrow + self.arrow + arrow;
        let buffered_rows = self.buffer_rows.saturating_add(self.rows).saturating_add(rows);
        let within_caps = buffered <= buffer_cap(self.working_budget) as f64
            && buffered_rows <= crate::parts::levels::FLUSH_MAX_ROWS as u64;
        // Joins in the first group obey the buffer caps too. Otherwise a
        // calibrated group can fill the old one-fifth buffer in one offer
        // sequence, leaving no admission room beside its flight. A lone
        // oversized first object retains the existing progress/slicing path.
        if self.groups > 0 && !within_caps {
            return Offer::Refused;
        }
        let charged = self.committed.saturating_add(self.closed_arrow as u64);
        if admission_fits(self.working_budget, charged, self.heap + heap, self.arrow + arrow) {
            self.join(heap, arrow, rows);
            return Offer::Joins;
        }
        let closed = self.closed_arrow + self.arrow;
        if self.groups > 0 && within_caps
            && self.buffer_rows.saturating_add(self.rows) < crate::parts::levels::FLUSH_MAX_ROWS as u64
            && admission_fits(self.working_budget, self.committed.saturating_add(closed as u64), heap, arrow)
        {
            self.closed_arrow = closed;
            self.heap = 0.0;
            self.arrow = 0.0;
            self.groups += 1;
            self.join(heap, arrow, rows);
            return Offer::NewGroup;
        }
        Offer::Refused
    }

    /// Add an object to the open group without the bound (the first object
    /// from idle always makes progress).
    pub fn force(&mut self, heap: f64, arrow: f64, rows: u64) {
        self.join(heap, arrow, rows);
    }

    fn join(&mut self, heap: f64, arrow: f64, rows: u64) {
        self.groups = self.groups.max(1);
        self.heap += heap;
        self.arrow += arrow;
        self.rows = self.rows.saturating_add(rows);
    }

    /// Groups opened so far.
    pub fn groups(&self) -> usize {
        self.groups
    }
}

/// NAN-4770: what admission predicts per decoded (uncompressed bronze)
/// byte, learned per object prefix from the rows it actually admitted.
///
/// The fixed model ([`super::ingest::HEAP_PER_DECODED_BYTE`] 16.0 modelled
/// JSON heap, [`super::ingest::ARROW_PER_DECODED_BYTE`] 1.0 Arrow) was
/// measured on narrow Tenzir OCSF rows. It is not a large overestimate for
/// every shape: on the ~1 KB blaster row (`nan4770_ingest_tests`) the rows
/// model at 18-23 heap bytes per decoded byte and the measured admission
/// peak was 15.6-17.9 allocated bytes per decoded byte, so that shape keeps
/// the prior. Rows dominated by long strings model at a fraction of it, and
/// those objects were sliced (or kept out of a group) for nothing.
///
/// What is learned is the SAME modelled heap ([`super::ingest::value_heap_bytes`],
/// sampled on the admitted rows) and Arrow bytes the fixed constants
/// approximate, so the measured admission peak per modelled heap byte
/// ([`ADMISSION_PEAK_PER_MODELLED_HEAP`]) still applies on top. Bounds:
/// - an unmeasured prefix uses the fixed constants (the prior);
/// - the learned ratio carries [`CALIBRATION_MARGIN`] and is clamped to
///   [`MIN_CALIBRATED_HEAP_SHARE`]..1 of the prior: never above the fixed
///   model; this is an estimate, not a bound on a different next object;
/// - a heavier group raises the ratio at once; a lighter one lowers it by
///   a quarter of the gap per observation (a burst of narrow rows after
///   wide ones is not trusted at once);
/// - a group that mixes prefixes may only raise each prefix's ratio;
/// - at most [`MAX_CALIBRATED_PREFIXES`] prefixes are kept (least recently
///   observed dropped: it falls back to the prior).
///
/// History cannot bound the next object's shape, or an unsampled row.
/// Calibrated groups therefore also enforce their modelled heap allowance
/// while reading bronze; an underestimate retries with the fixed model.
#[derive(Debug, Clone, Default)]
pub struct AdmissionCalibration {
    by_prefix: std::collections::BTreeMap<String, Learned>,
    observations: u64,
}

#[derive(Debug, Clone, Copy)]
struct Learned {
    heap: f64,
    arrow: f64,
    last: u64,
}

/// Safety margin on a learned ratio.
pub const CALIBRATION_MARGIN: f64 = 1.25;
/// Lowest share of the fixed model a learned heap ratio may predict.
pub const MIN_CALIBRATED_HEAP_SHARE: f64 = 1.0 / 4.0;
/// Lowest share of the fixed Arrow ratio a learned one may predict.
pub const MIN_CALIBRATED_ARROW_SHARE: f64 = 1.0 / 4.0;
/// Fewest rows a group must hold to calibrate (the heap is sampled every
/// 16th row).
pub const MIN_CALIBRATION_ROWS: u64 = 256;
/// Prefixes remembered.
pub const MAX_CALIBRATED_PREFIXES: usize = 64;

/// The calibration prefix of a bronze object key: its folder (the shard
/// and tenant), so one writer's objects share a ratio.
pub fn calibration_prefix(key: &str) -> &str {
    key.rsplit_once('/').map_or("", |(folder, _)| folder)
}

impl AdmissionCalibration {
    /// (modelled JSON heap, Arrow bytes) per decoded byte for `prefix`.
    pub fn per_decoded_byte(&self, prefix: &str) -> (f64, f64) {
        let (heap, arrow) = (super::ingest::HEAP_PER_DECODED_BYTE, super::ingest::ARROW_PER_DECODED_BYTE);
        match self.by_prefix.get(prefix) {
            None => (heap, arrow),
            Some(learned) => (
                (learned.heap * CALIBRATION_MARGIN).clamp(heap * MIN_CALIBRATED_HEAP_SHARE, heap),
                (learned.arrow * CALIBRATION_MARGIN).clamp(arrow * MIN_CALIBRATED_ARROW_SHARE, arrow),
            ),
        }
    }

    /// Predicted (modelled JSON heap, Arrow rows) of an object under
    /// `prefix` whose rows decode to `decoded` bytes.
    pub fn cost(&self, prefix: &str, decoded: u64) -> (f64, f64) {
        let (heap, arrow) = self.per_decoded_byte(prefix);
        (decoded as f64 * heap, decoded as f64 * arrow)
    }

    /// Reservation with the learned margin and floors. The bronze reader
    /// checks actual heap before allowing a calibrated group to accumulate.
    pub fn reservation_cost(&self, prefix: &str, decoded: u64) -> (f64, f64) {
        self.cost(prefix, decoded)
    }

    /// Whether `prefix` has a learned ratio.
    pub fn measured(&self, prefix: &str) -> bool {
        self.by_prefix.contains_key(prefix)
    }

    /// Record one admitted group: its `prefixes` (one per object), `rows`
    /// kept, `decoded` bytes, sampled modelled `heap` and Arrow `arrow` bytes.
    pub fn observe(&mut self, prefixes: &[&str], rows: u64, decoded: u64, heap: f64, arrow: f64) {
        if rows < MIN_CALIBRATION_ROWS || decoded == 0 || !(heap.is_finite() && arrow.is_finite()) || heap <= 0.0 || arrow <= 0.0 {
            return;
        }
        let (heap, arrow) = (heap / decoded as f64, arrow / decoded as f64);
        let mut unique = prefixes.to_vec();
        unique.sort_unstable();
        unique.dedup();
        let mixed = unique.len() > 1;
        self.observations += 1;
        let now = self.observations;
        for prefix in unique {
            match self.by_prefix.get_mut(prefix) {
                Some(learned) => {
                    learned.heap = Self::step(learned.heap, heap, mixed);
                    learned.arrow = Self::step(learned.arrow, arrow, mixed);
                    learned.last = now;
                }
                // A mixed group's ratio is a blend: never a first measure.
                None if mixed => {}
                None => {
                    if self.by_prefix.len() >= MAX_CALIBRATED_PREFIXES {
                        if let Some(oldest) = self.by_prefix.iter().min_by_key(|(_, l)| l.last).map(|(k, _)| k.clone()) {
                            self.by_prefix.remove(&oldest);
                        }
                    }
                    self.by_prefix.insert(prefix.to_string(), Learned { heap, arrow, last: now });
                }
            }
        }
    }

    fn step(learned: f64, observed: f64, raise_only: bool) -> f64 {
        if observed >= learned {
            observed
        } else if raise_only {
            learned
        } else {
            learned - (learned - observed) / 4.0
        }
    }
}

/// Fewest rows in one admission slice (NAN-4553): below this the per-slice
/// overhead (a Parquet file, one admission pass) outweighs the memory saved.
pub const MIN_ADMISSION_SLICE_ROWS: u64 = 256;

/// Rows per slice for an object of `rows` rows whose whole admission
/// (`predicted_heap` modelled JSON heap, `predicted_arrow` Arrow rows) does
/// not fit beside `committed` (NAN-4553). Its Arrow rows accumulate across
/// the slices; its JSON values live one slice at a time, so each slice's
/// peak takes the room the Arrow rows leave (at least a quarter of the
/// room, so a tight budget still makes progress in small slices).
pub fn admission_slice_rows(working_budget: u64, committed: u64, predicted_heap: f64, predicted_arrow: f64, rows: u64) -> u64 {
    let rows = rows.max(1);
    let room = working_budget.saturating_sub(committed) as f64;
    let json_room = (room - predicted_arrow).max(room / 4.0);
    let per_row = predicted_heap * ADMISSION_PEAK_PER_MODELLED_HEAP / rows as f64;
    let fit = if per_row > 0.0 { (json_room / per_row).floor() as u64 } else { rows };
    fit.clamp(MIN_ADMISSION_SLICE_ROWS.min(rows), rows)
}

/// Fewest rows per slice of an object admitted beside flushes in flight
/// (NAN-4770): smaller slices wait for the flights to commit instead.
pub const MIN_PIPELINED_SLICE_ROWS: u64 = MIN_ADMISSION_SLICE_ROWS;

/// NAN-4770: rows per slice of the next buffer's first object, admitted
/// beside the flushes still in flight (`committed`), or `None` when it must
/// wait for them. Unlike [`admission_slice_rows`] (idle: progress at any
/// size), the object's Arrow rows AND every slice's peak must fit the room
/// left: the flights keep their reservation.
pub fn pipelined_slice_rows(working_budget: u64, committed: u64, predicted_heap: f64, predicted_arrow: f64, rows: u64) -> Option<u64> {
    if rows == 0 || committed >= working_budget || !predicted_heap.is_finite() || !predicted_arrow.is_finite()
        || predicted_heap <= 0.0 || predicted_arrow <= 0.0 {
        return None;
    }
    let room = working_budget.saturating_sub(committed) as f64;
    let json_room = room - predicted_arrow;
    let per_row = predicted_heap * ADMISSION_PEAK_PER_MODELLED_HEAP / rows as f64;
    if json_room <= 0.0 || per_row <= 0.0 {
        return (json_room >= 0.0 && per_row <= 0.0).then_some(rows);
    }
    let fit = (json_room / per_row).floor() as u64;
    (fit >= MIN_PIPELINED_SLICE_ROWS.min(rows)).then(|| fit.min(rows))
}

/// Check the actual rewritten slices before decoding any JSON. An
/// object's average bytes per row does not bound its heaviest slice, and
/// rewriting dictionaries can increase its decoded bytes. Charge all
/// retained Arrow rows plus the heaviest slice's fixed-model JSON peak.
pub fn pipelined_slices_fit(working_budget: u64, committed: u64, object_decoded: u64, decoded: &[u64]) -> bool {
    if object_decoded == 0 || decoded.is_empty() || decoded.contains(&0) || committed >= working_budget {
        return false;
    }
    let total = decoded.iter().fold(0_u64, |total, bytes| total.saturating_add(*bytes));
    let heap = super::ingest::decoded_admission_cost(*decoded.iter().max().expect("nonempty slices")).0;
    let arrow = super::ingest::decoded_admission_cost(total.max(object_decoded)).1;
    admission_fits(working_budget, committed, heap, arrow)
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
    fn an_object_too_large_to_admit_whole_is_sliced_to_the_room() {
        let budget = 64 * MIB;
        // 10k rows, 15 MiB decoded: 240 MiB modelled heap, 15 MiB of rows.
        let (heap, arrow) = (240.0 * MIB as f64, 15.0 * MIB as f64);
        assert!(!admission_fits(budget, 0, heap, arrow));
        let rows = admission_slice_rows(budget, 0, heap, arrow, 10_000);
        let slice_peak = heap * ADMISSION_PEAK_PER_MODELLED_HEAP * rows as f64 / 10_000.0;
        assert!(slice_peak + arrow <= budget as f64, "{rows} rows per slice");
        assert!(rows >= MIN_ADMISSION_SLICE_ROWS && rows < 10_000);
        // No room left at all: still progress, in the smallest slices.
        assert_eq!(admission_slice_rows(budget, budget, heap, arrow, 10_000), MIN_ADMISSION_SLICE_ROWS);
        // A tiny object is never cut below its own size.
        assert_eq!(admission_slice_rows(budget, budget, heap, arrow, 10), 10);
    }

    /// NAN-4749: a tick packs objects into groups decoded one after
    /// another; each group fits beside the Arrow rows of the ones before it,
    /// the first group is the old single-group bound, and no group opens
    /// past the buffer's byte or row cap.
    #[test]
    fn a_tick_admits_several_groups_within_the_budget() {
        let budget = 2048 * MIB;
        // Objects of 10 MiB decoded: 160 MiB heap (240 MiB peak) + 10 MiB rows.
        let (heap, arrow) = (160.0 * MIB as f64, 10.0 * MIB as f64);
        let mut groups = AdmissionGroups::new(budget, 0, 0, 0);
        let mut offers = Vec::new();
        for _ in 0..20 {
            offers.push(groups.offer(heap, arrow, 0));
        }
        // One group alone: 8 objects (8 x 250 MiB <= 2048 MiB), as before.
        let first = offers.iter().take_while(|o| **o == Offer::Joins).count();
        assert_eq!(first, 8);
        let mut single = 0.0;
        while admission_fits(budget, 0, (single + 1.0) * heap, (single + 1.0) * arrow) {
            single += 1.0;
        }
        assert_eq!(first as f64, single, "the first group is the single-group bound");
        // Further groups: every object admitted, each group fits beside the
        // rows of the groups before it, and the buffer cap (409.6 MiB) is
        // never passed by the rows.
        assert!(groups.groups() > 1);
        let admitted = offers.iter().filter(|o| **o != Offer::Refused).count();
        assert_eq!(admitted, 20, "{offers:?}");
        assert!(20.0 * arrow <= buffer_cap(budget) as f64);
        // The buffer cap bounds the rows of a tick's further groups.
        let mut capped = AdmissionGroups::new(budget, 400 * MIB, 400 * MIB, 0);
        let offers = (0..30).map(|_| capped.offer(heap, arrow, 0)).collect::<Vec<_>>();
        assert!(!offers.contains(&Offer::NewGroup), "{offers:?}");
        // A buffer at its row cap takes one group only.
        let mut full = AdmissionGroups::new(budget, 0, 0, crate::parts::levels::FLUSH_MAX_ROWS as u64);
        let offers = (0..30).map(|_| full.offer(heap, arrow, 0)).collect::<Vec<_>>();
        assert_eq!(offers.iter().filter(|o| **o == Offer::Joins).count(), 8);
        assert!(!offers.contains(&Offer::NewGroup));
        // Nothing fits: refused, never a new group from nothing.
        let mut none = AdmissionGroups::new(64 * MIB, 64 * MIB, 0, 0);
        assert_eq!(none.offer(heap, arrow, 0), Offer::Refused);
        none.force(heap, arrow, 0);
        assert_eq!(none.groups(), 1);
    }

    #[test]
    fn later_group_joins_cannot_pass_the_buffer_byte_cap() {
        let budget = 2048 * MIB;
        let (heap, arrow) = (160.0 * MIB as f64, 10.0 * MIB as f64);
        let mut groups = AdmissionGroups::new(budget, 0, 0, 0);
        let admitted = (0..64).take_while(|_| groups.offer(heap, arrow, 0) != Offer::Refused).count();
        assert!(groups.groups() > 1);
        // The original packer admitted 42 objects: its final joins took
        // the buffer past the old 409.6 MiB cap after opening the last group.
        assert_eq!(admitted as u64, buffer_cap(budget) / (arrow as u64));
        assert!(groups.closed_arrow + groups.arrow <= buffer_cap(budget) as f64);
    }

    #[test]
    fn later_groups_charge_this_ticks_rows_beside_the_existing_buffer() {
        let budget = 2048 * MIB;
        let (heap, arrow) = (160.0 * MIB as f64, 10.0 * MIB as f64);
        for buffered_rows in [0, 10_000] {
            let mut groups = AdmissionGroups::new(budget, 0, 0, buffered_rows);
            let admitted = (0..64).take_while(|_| groups.offer(heap, arrow, 5_000) != Offer::Refused).count();
            assert!(groups.groups() > 1);
            assert_eq!(admitted as u64, (crate::parts::levels::FLUSH_MAX_ROWS as u64 - buffered_rows) / 5_000);
            assert!(buffered_rows + groups.rows <= crate::parts::levels::FLUSH_MAX_ROWS as u64);
        }
    }

    /// NAN-4770: the prior until measured; the learned ratio with its
    /// margin inside its bounds; heavier rises at once, lighter decays;
    /// mixed groups only raise; prefixes are bounded.
    #[test]
    fn calibration_is_bounded_and_rises_at_once() {
        use super::super::ingest::{ARROW_PER_DECODED_BYTE as ARROW, HEAP_PER_DECODED_BYTE as HEAP};
        let mut c = AdmissionCalibration::default();
        assert_eq!(c.per_decoded_byte("a"), (HEAP, ARROW));
        // Too few rows: not a measure.
        c.observe(&["a"], MIN_CALIBRATION_ROWS - 1, 1_000, 4_000.0, 500.0);
        assert!(!c.measured("a"));
        c.observe(&["a"], 10_000, 1_000, 4_000.0, 500.0);
        assert_eq!(c.per_decoded_byte("a"), (4.0 * CALIBRATION_MARGIN, 0.5 * CALIBRATION_MARGIN));
        assert_eq!(c.cost("a", 1_000), (5_000.0, 625.0));
        // Another prefix keeps the prior.
        assert_eq!(c.per_decoded_byte("b"), (HEAP, ARROW));
        // Heavier: at once. Lighter: a quarter of the gap.
        c.observe(&["a"], 10_000, 1_000, 8_000.0, 500.0);
        assert_eq!(c.per_decoded_byte("a").0, 8.0 * CALIBRATION_MARGIN);
        c.observe(&["a"], 10_000, 1_000, 4_000.0, 500.0);
        assert_eq!(c.per_decoded_byte("a").0, 7.0 * CALIBRATION_MARGIN);
        // Never above the prior; never below the floor.
        c.observe(&["a"], 10_000, 1_000, 100_000.0, 5_000.0);
        assert_eq!(c.per_decoded_byte("a"), (HEAP, ARROW));
        let mut tiny = AdmissionCalibration::default();
        tiny.observe(&["t"], 10_000, 1_000_000, 1.0, 1.0);
        assert_eq!(tiny.per_decoded_byte("t"), (HEAP * MIN_CALIBRATED_HEAP_SHARE, ARROW * MIN_CALIBRATED_ARROW_SHARE));
        assert_eq!(tiny.reservation_cost("t", 1_000), (HEAP * MIN_CALIBRATED_HEAP_SHARE * 1_000.0, ARROW * MIN_CALIBRATED_ARROW_SHARE * 1_000.0));
        // A mixed group: no first measure, and only raises.
        let mut m = AdmissionCalibration::default();
        m.observe(&["x"], 10_000, 1_000, 5_000.0, 500.0);
        m.observe(&["x", "y"], 10_000, 1_000, 4_000.0, 400.0);
        assert!(!m.measured("y"));
        assert_eq!(m.per_decoded_byte("x").0, 5.0 * CALIBRATION_MARGIN);
        m.observe(&["x", "y"], 10_000, 1_000, 6_000.0, 400.0);
        assert_eq!(m.per_decoded_byte("x").0, 6.0 * CALIBRATION_MARGIN);
        // Non-finite or empty observations are ignored.
        m.observe(&["z"], 10_000, 0, 1.0, 1.0);
        m.observe(&["z"], 10_000, 1_000, f64::NAN, 1.0);
        assert!(!m.measured("z"));
        // Bounded: the least recently observed prefix falls back to the prior.
        let mut many = AdmissionCalibration::default();
        for i in 0..=MAX_CALIBRATED_PREFIXES {
            many.observe(&[format!("p{i}").as_str()], 10_000, 1_000, 2_000.0, 500.0);
        }
        assert_eq!(many.by_prefix.len(), MAX_CALIBRATED_PREFIXES);
        assert!(!many.measured("p0") && many.measured(&format!("p{MAX_CALIBRATED_PREFIXES}")));
        assert_eq!(calibration_prefix("bronze-v2/shard=3/tenant_id=t/1-u.parquet"), "bronze-v2/shard=3/tenant_id=t");
        assert_eq!(calibration_prefix("flat.parquet"), "");
    }

    /// NAN-4770: beside flights, the object's Arrow rows and a slice of at
    /// least MIN_PIPELINED_SLICE_ROWS must fit the room they leave.
    #[test]
    fn pipelined_slices_take_only_the_room_the_flights_leave() {
        let budget = 600 * MIB;
        let flight = flight_bytes(60 * MIB, 2);
        // 140k rows: 110 MiB of Arrow, 2.5 GiB modelled heap (whole: never fits).
        let (heap, arrow, rows) = (2_560.0 * MIB as f64, 110.0 * MIB as f64, 140_000);
        assert!(!admission_fits(budget, flight, heap, arrow));
        let slice = pipelined_slice_rows(budget, flight, heap, arrow, rows).expect("a slice fits beside the flight");
        let room = (budget - flight) as f64;
        assert!(arrow + heap * ADMISSION_PEAK_PER_MODELLED_HEAP * slice as f64 / rows as f64 <= room);
        assert!((MIN_PIPELINED_SLICE_ROWS..rows).contains(&slice));
        // The Arrow rows alone do not fit: wait for the flight.
        assert_eq!(pipelined_slice_rows(budget, budget - 100 * MIB, heap, arrow, rows), None);
        // Room for slices smaller than the minimum: wait.
        assert_eq!(pipelined_slice_rows(budget, budget - arrow as u64 - MIB, heap, arrow, rows), None);
        // A small object fits in one slice.
        assert_eq!(pipelined_slice_rows(budget, 0, 10.0 * MIB as f64, MIB as f64, 100), Some(100));
        assert_eq!(pipelined_slice_rows(budget, 0, 0.0, 0.0, 0), None, "unknown footer is not free admission");
        assert_eq!(pipelined_slice_rows(budget, budget, 0.0, 0.0, rows), None);
        assert_eq!(pipelined_slice_rows(budget, 0, f64::NAN, arrow, rows), None);
        assert!(pipelined_slices_fit(budget, flight, 4 * MIB, &[MIB; 4]));
        assert!(!pipelined_slices_fit(budget, flight, 23 * MIB, &[20 * MIB, MIB, MIB, MIB]), "a heavy slice exceeds the room");
        assert!(!pipelined_slices_fit(budget, flight, 4 * MIB, &[MIB; 400]), "all slices' Arrow stays resident");
        assert!(!pipelined_slices_fit(budget, flight, 400 * MIB, &[MIB; 4]), "the original Arrow reserve is retained too");
        assert!(!pipelined_slices_fit(budget, flight, MIB, &[0]));
    }

    #[test]
    fn a_flight_and_the_next_buffer_fit_the_budget() {
        for budget in [512 * MIB, 2048 * MIB, 4096 * MIB] {
            let cap = buffer_cap(budget);
            assert!(flight_bytes(cap, 1) + cap <= budget, "{budget}");
        }
    }
}
