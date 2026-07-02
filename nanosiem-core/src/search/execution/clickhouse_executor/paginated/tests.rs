// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-1645 (finding 3.5): pin the pagination companion gate.
//!
//! Companion queries (the count companion in `paginated.rs` and the histogram
//! spawn in `service/core_search.rs`) both route their offset decision through
//! [`is_first_page`]. These tests pin the contract: offset 0 runs companions,
//! any offset > 0 skips them and reports [`paged_total_estimate`] instead.

use super::{is_first_page, paged_total_estimate};

#[test]
fn first_page_runs_companion_queries() {
    assert!(
        is_first_page(0),
        "offset=0 must run the count + histogram companions (43155f11: in parallel, never sequential)"
    );
}

#[test]
fn page_flips_skip_companion_queries() {
    for offset in [1usize, 100, 100_000] {
        assert!(
            !is_first_page(offset),
            "offset={offset} must NOT re-run the count/histogram companions — page 1 already delivered them"
        );
    }
}

#[test]
fn full_page_estimate_stays_ahead_of_client_position() {
    // Full page → "there is probably more": estimate must exceed offset+returned
    // so the client's next-page fetch stays enabled.
    assert_eq!(paged_total_estimate(100, 100, 100), 300);
    assert_eq!(paged_total_estimate(500, 100, 100), 700);
}

#[test]
fn partial_page_estimate_is_exact() {
    // Partial page → definitively the last page: offset + returned is exact.
    assert_eq!(paged_total_estimate(100, 37, 100), 137);
    // Empty page N: nothing past the offset.
    assert_eq!(paged_total_estimate(200, 0, 100), 200);
}
