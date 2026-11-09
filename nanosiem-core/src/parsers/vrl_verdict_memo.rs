// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded LRU memo of VRL compile verdicts for the render path.
//!
//! Every Vector config publication re-renders every deployed source, and the
//! render-time safety checks (stored-text quarantine, the deploy guard's
//! allowlist compile of each tenant remap and condition) compile the same
//! 20–60 KB parser programs again each time. A verdict is a pure function of
//! the source text and the function allowlist, so it is cached under
//! `sha256(allowlist tag ‖ kind ‖ 0 ‖ source)`: a verdict is only ever reused
//! for byte-identical source checked by the same kind of check against the
//! same allowlist. The cache is size-bounded with least-recently-used
//! eviction.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use sha2::{Digest, Sha256};

/// Verdicts kept per process; one entry per distinct (check, source) pair.
pub(crate) const VERDICT_MEMO_CAPACITY: usize = 1024;

type Key = [u8; 32];
type Verdict = Result<(), String>;

/// Fingerprint of the parser function allowlist the guarded checks compile
/// against, so a verdict can never outlive a change to that allowlist.
static ALLOWLIST_TAG: LazyLock<Key> = LazyLock::new(|| {
    let mut names: Vec<&'static str> = crate::parsers::vrl_functions::parser_vrl_functions()
        .iter()
        .map(|f| f.identifier())
        .collect();
    names.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(b"nano-vrl-verdict-v1\0");
    for name in names {
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
    }
    hasher.finalize().into()
});

static GLOBAL: LazyLock<VerdictMemo> =
    LazyLock::new(|| VerdictMemo::new(VERDICT_MEMO_CAPACITY, *ALLOWLIST_TAG));

/// Memoize `check` for `(kind, src)` in the process-wide memo.
pub(crate) fn verdict(kind: &str, src: &str, check: impl FnOnce() -> Verdict) -> Verdict {
    GLOBAL.get_or_check(kind, src, check)
}

/// A bounded LRU map from a (tag, kind, source) digest to its verdict.
pub(crate) struct VerdictMemo {
    capacity: usize,
    tag: Key,
    inner: Mutex<Entries>,
}

struct Entries {
    map: HashMap<Key, (Verdict, u64)>,
    tick: u64,
}

impl VerdictMemo {
    pub(crate) fn new(capacity: usize, tag: Key) -> Self {
        Self {
            capacity: capacity.max(1),
            tag,
            inner: Mutex::new(Entries {
                map: HashMap::new(),
                tick: 0,
            }),
        }
    }

    fn key(&self, kind: &str, src: &str) -> Key {
        let mut hasher = Sha256::new();
        hasher.update(self.tag);
        hasher.update(kind.as_bytes());
        hasher.update([0u8]);
        hasher.update(src.as_bytes());
        hasher.finalize().into()
    }

    /// The cached verdict for `(kind, src)`, or run `check` and cache it. The
    /// lock is not held while `check` runs, so concurrent misses may both
    /// compile; they store the same verdict.
    pub(crate) fn get_or_check(&self, kind: &str, src: &str, check: impl FnOnce() -> Verdict) -> Verdict {
        let key = self.key(kind, src);
        if let Ok(mut entries) = self.inner.lock() {
            entries.tick += 1;
            let tick = entries.tick;
            if let Some((verdict, used)) = entries.map.get_mut(&key) {
                *used = tick;
                return verdict.clone();
            }
        }
        let verdict = check();
        if let Ok(mut entries) = self.inner.lock() {
            if entries.map.len() >= self.capacity && !entries.map.contains_key(&key) {
                if let Some(oldest) = entries
                    .map
                    .iter()
                    .min_by_key(|(_, (_, used))| *used)
                    .map(|(k, _)| *k)
                {
                    entries.map.remove(&oldest);
                }
            }
            entries.tick += 1;
            let tick = entries.tick;
            entries.map.insert(key, (verdict.clone(), tick));
        }
        verdict
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().map(|e| e.map.len()).unwrap_or(0)
    }
}

#[cfg(test)]
#[path = "vrl_verdict_memo_tests.rs"]
mod tests;
