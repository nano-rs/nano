// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3809: rules for re-serving an identical settled search.
//!
//! A pasted search URL with an absolute range re-ran the whole search. Search
//! now re-serves a finished durable job of the same caller through its
//! existing result pages (`BackgroundSearchJobs::settled_reuse`).
//!
//! Reuse is never decided on time alone. The job must be the caller's own,
//! with the exact same attach identity (normalized query, absolute window,
//! dataset and view flags, result cap) and the exact same effective deny sets
//! (both halves of the source scope), so a narrowed scope or another user
//! always misses. On ClickHouse the data identity is the late-arrival rule:
//! the window must have settled before the reused job RAN (it finished at
//! least [`LATE_ARRIVAL_GRACE_SECS`] after the window's end), so the job read
//! the window's final data rather than a still-arriving one.

use chrono::{DateTime, Duration, Utc};

/// How far behind "now" an event can still land and be expected in a read.
/// A window that ends inside it is still settling and is never re-served.
pub const LATE_ARRIVAL_GRACE_SECS: i64 = 300;

/// Whether a window ending at `end` is settled at `now`: it ends at least the
/// late-arrival grace in the past. A relative range ("last 1h") always ends at
/// about now, so it is never settled.
pub fn is_settled_end(end: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    end <= now - Duration::seconds(LATE_ARRIVAL_GRACE_SECS)
}

/// The earliest a job may have finished to have read the settled window.
pub fn settled_after(end: DateTime<Utc>) -> DateTime<Utc> {
    end + Duration::seconds(LATE_ARRIVAL_GRACE_SECS)
}

/// Whether a query's answer depends only on the events in its window.
///
/// Conservative and textual on purpose: anything that may read state outside
/// the event data (lookups, IOC feeds, prevalence, risk, `| ai`, enrichment
/// views, typed product views, subsearches) or the clock is refused. A false
/// refusal only costs a re-run.
pub fn query_allows_settled_reuse(query: &str) -> bool {
    static STATEFUL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let stateful = STATEFUL.get_or_init(|| {
        regex::Regex::new(
            r"(?i)\b(inputlookup|outputlookup|lookup|ioc\w*|prevalence\w*|risk\w*|ai|enrich\w*|retro|lateral|baseline|tree|asset\w*|cloud\w*|identity|now|today|yesterday|relative_time|random|rand|uuid|earliest|latest)\b",
        )
        .expect("static regex")
    });
    !query.contains('[') && !stateful.is_match(query)
}

#[cfg(test)]
#[path = "settled_reuse_tests.rs"]
mod tests;
