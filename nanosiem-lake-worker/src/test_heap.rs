// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test-only heap accounting scoped to opted-in threads (NAN-2611).
//!
//! The lib test binary runs many tests in parallel, so a process-wide
//! allocation counter would measure its neighbours. Instead every allocation
//! made on a thread that called [`track_current_thread`] adjusts one live
//! counter and its high-water mark. A measured scenario runs on a dedicated
//! Tokio runtime whose worker and blocking threads opt in at start, so the
//! peak covers exactly the code under test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

pub(crate) struct ScopedCountingAllocator;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
/// Count every thread's allocations (a bench run alone, whose rayon and
/// scoped writer threads cannot opt in one by one).
static TRACK_ALL: AtomicBool = AtomicBool::new(false);

thread_local! {
    static TRACKED: Cell<bool> = const { Cell::new(false) };
}

fn tracked() -> bool {
    TRACK_ALL.load(Ordering::Relaxed) || TRACKED.try_with(Cell::get).unwrap_or(false)
}

fn add(bytes: usize) {
    let live = LIVE.fetch_add(bytes as isize, Ordering::Relaxed) + bytes as isize;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

fn sub(bytes: usize) {
    LIVE.fetch_sub(bytes as isize, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for ScopedCountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && tracked() {
            add(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() && tracked() {
            add(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        if tracked() {
            sub(layout.size());
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() && tracked() {
            if new_size >= layout.size() {
                add(new_size - layout.size());
            } else {
                sub(layout.size() - new_size);
            }
        }
        moved
    }
}

#[global_allocator]
static GLOBAL: ScopedCountingAllocator = ScopedCountingAllocator;

pub(crate) fn track_current_thread(enabled: bool) {
    TRACKED.with(|flag| flag.set(enabled));
}

/// Serializes measured scenarios: the counters are process-wide.
pub(crate) static MEASUREMENT: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Start a fresh measurement window from the current live bytes.
pub(crate) fn reset_peak() -> isize {
    let live = LIVE.load(Ordering::Relaxed);
    PEAK.store(live, Ordering::Relaxed);
    live
}

/// Track allocations on every thread (single-test benches only).
#[allow(dead_code)]
pub(crate) fn track_all_threads(enabled: bool) {
    TRACK_ALL.store(enabled, Ordering::Relaxed);
}

#[allow(dead_code)]
pub(crate) fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

pub(crate) fn peak() -> isize {
    PEAK.load(Ordering::Relaxed)
}

