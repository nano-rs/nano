// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5736: let a caller that never reads `total_count` skip the parallel
//! `count(*)` companion of a raw-event search (a scan of up to the 1M limit
//! of matches on a broad query). Detection windows read only the rows.
//!
//! A task-local like [`crate::search::partial_run`]; `request_actor::inherit`
//! carries it into spawned search work. Outside a [`skip`] scope nothing
//! changes.

use std::future::Future;

tokio::task_local! {
    static SKIP_COUNT: ();
}

/// Run `future` with the count companion skipped.
pub async fn skip<F: Future>(future: F) -> F::Output {
    SKIP_COUNT.scope((), future).await
}

/// Whether the current search skips its count companion.
pub fn skipped() -> bool {
    SKIP_COUNT.try_with(|_| ()).is_ok()
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn the_scope_is_visible_only_inside() {
        assert!(!super::skipped());
        assert!(super::skip(async { super::skipped() }).await);
        assert!(!super::skipped());
    }
}
