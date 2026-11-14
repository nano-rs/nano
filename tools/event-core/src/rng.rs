//! Seedable randomness for every generator in this crate.
//!
//! By default each thread draws from an OS-seeded `StdRng`, exactly like the
//! `rand::rng()` calls this replaced. When a seed is set with [`set_seed`]
//! before any generation, every thread instead derives its stream from that
//! seed, so a single-threaded run (log-blaster `--output`) is byte-for-byte
//! reproducible, and a multi-worker run reproduces each worker's event content
//! when the worker calls [`reseed_thread`] with its own stream id.
//!
//! The public benchmark (`benchmarks/public/`) depends on this: the dataset is
//! the generator plus a fixed seed.

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

static GLOBAL_SEED: OnceLock<u64> = OnceLock::new();
/// Stream ids handed to threads that never call [`reseed_thread`]. Starts high
/// so it never collides with the small worker ids callers pass explicitly.
static NEXT_STREAM: AtomicU64 = AtomicU64::new(1 << 32);

thread_local! {
    static LOCAL: RefCell<StdRng> = RefCell::new(fresh(None));
}

/// SplitMix64 finalizer: decorrelates `seed` and `stream` so neighboring
/// streams do not produce overlapping sequences.
fn mix(seed: u64, stream: u64) -> u64 {
    let mut z = seed ^ stream.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn fresh(stream: Option<u64>) -> StdRng {
    match GLOBAL_SEED.get() {
        Some(&seed) => {
            let stream = stream.unwrap_or_else(|| NEXT_STREAM.fetch_add(1, Ordering::Relaxed));
            StdRng::seed_from_u64(mix(seed, stream))
        }
        None => StdRng::from_os_rng(),
    }
}

/// Fix the process-wide seed. Call once, before generating anything. Returns
/// `false` if a seed was already set (the first one wins).
pub fn set_seed(seed: u64) -> bool {
    let ok = GLOBAL_SEED.set(seed).is_ok();
    if ok {
        // The calling thread may already have initialized its RNG from the OS
        // (e.g. while parsing args); restart it on stream 0.
        reseed_thread(0);
    }
    ok
}

/// The seed set with [`set_seed`], if any.
pub fn seed() -> Option<u64> {
    GLOBAL_SEED.get().copied()
}

/// Restart the calling thread's RNG on a fixed stream derived from the global
/// seed. A no-op when no seed is set.
pub fn reseed_thread(stream: u64) {
    if GLOBAL_SEED.get().is_some() {
        LOCAL.with(|r| *r.borrow_mut() = fresh(Some(stream)));
    }
}

/// An owned RNG for one worker: derived from the global seed and `stream`
/// when a seed is set, OS-seeded otherwise.
pub fn stream_rng(stream: u64) -> StdRng {
    fresh(Some(stream))
}

/// Handle to the calling thread's RNG; a drop-in for `rand::rng()`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadRng;

/// Drop-in replacement for `rand::rng()` that honors [`set_seed`].
pub fn rng() -> ThreadRng {
    ThreadRng
}

impl RngCore for ThreadRng {
    fn next_u32(&mut self) -> u32 {
        LOCAL.with(|r| r.borrow_mut().next_u32())
    }
    fn next_u64(&mut self) -> u64 {
        LOCAL.with(|r| r.borrow_mut().next_u64())
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        LOCAL.with(|r| r.borrow_mut().fill_bytes(dst))
    }
}

/// Record ids (process/logon GUIDs, request ids). Unseeded: a time-ordered
/// v7 UUID as before. Seeded: a v4 UUID drawn from the thread RNG, so ids
/// replay with the seed instead of following the wall clock.
pub fn uuid() -> uuid::Uuid {
    if GLOBAL_SEED.get().is_some() {
        let mut bytes = [0u8; 16];
        rng().fill_bytes(&mut bytes);
        uuid::Builder::from_random_bytes(bytes).into_uuid()
    } else {
        uuid::Uuid::now_v7()
    }
}
