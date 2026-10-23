// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-side instrumentation for platform enrichment. This module has no feed
//! artifact client.
//!
//! NAN-4168: platform enrichment entitlement is enforced at ingest only. A
//! stamped event keeps its values; there is no read-time authorization,
//! masking or result fence.

/// Fixture-only instrumentation at actual artifact and reader entry points.
#[cfg(feature = "enrichment-read-audit")]
pub mod audit {
    use std::sync::atomic::{AtomicU64, Ordering};
    static ARTIFACT_READS: AtomicU64 = AtomicU64::new(0);
    static FEED_MATCHES: AtomicU64 = AtomicU64::new(0);
    pub(crate) fn artifact_read() {
        ARTIFACT_READS.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn feed_match() {
        FEED_MATCHES.fetch_add(1, Ordering::Relaxed);
    }
    pub fn counts() -> (u64, u64) {
        (
            ARTIFACT_READS.load(Ordering::Relaxed),
            FEED_MATCHES.load(Ordering::Relaxed),
        )
    }
}
