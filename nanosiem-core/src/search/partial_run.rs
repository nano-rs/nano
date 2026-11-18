// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5565: a search that completed but evaluated less than its query asked
//! for reports that here, so a scheduled rule run can be marked PARTIAL
//! instead of looking like a full success.
//!
//! The detection scheduler runs a rule inside [`collect`]; search code calls
//! [`note`] when it had to leave part of the work out (today: the prevalence
//! rescue dropping its least-rare artifacts at the inlined-key byte cap).
//! Outside a [`collect`] scope, [`note`] is a no-op: interactive searches
//! carry the same fact as a response warning instead.
//!
//! Like every `tokio::task_local!`, the scope does not cross `tokio::spawn`
//! on its own; `request_actor::inherit` carries it into spawned search work.

use std::future::Future;
use std::sync::{Arc, Mutex};

/// The notes recorded in one [`collect`] scope.
#[derive(Clone, Default)]
pub struct PartialNotes(Arc<Mutex<Vec<String>>>);

impl PartialNotes {
    fn push(&self, note: String) {
        if let Ok(mut notes) = self.0.lock() {
            if !notes.contains(&note) {
                notes.push(note);
            }
        }
    }

    fn take(&self) -> Vec<String> {
        self.0.lock().map(|mut notes| std::mem::take(&mut *notes)).unwrap_or_default()
    }
}

tokio::task_local! {
    static PARTIAL_NOTES: PartialNotes;
}

/// Run `future`, returning its output and every partial-evaluation note
/// recorded while it ran.
pub async fn collect<F: Future>(future: F) -> (F::Output, Vec<String>) {
    let notes = PartialNotes::default();
    let output = PARTIAL_NOTES.scope(notes.clone(), future).await;
    (output, notes.take())
}

/// Record that the current search evaluated only part of its input.
pub fn note(message: impl Into<String>) {
    let message = message.into();
    let _ = PARTIAL_NOTES.try_with(|notes| notes.push(message));
}

/// The active scope, for `request_actor::inherit`.
pub(crate) fn current() -> Option<PartialNotes> {
    PARTIAL_NOTES.try_with(Clone::clone).ok()
}

/// Run `future` inside an existing scope (spawned search work).
pub(crate) async fn with_scope<F: Future>(notes: PartialNotes, future: F) -> F::Output {
    PARTIAL_NOTES.scope(notes, future).await
}

/// The `last_error` text a partial-but-successful rule run records.
pub fn partial_run_message(notes: &[String]) -> Option<String> {
    if notes.is_empty() {
        return None;
    }
    Some(format!("[partial] {}", notes.join("; ")))
}

#[cfg(test)]
#[path = "partial_run_tests.rs"]
mod tests;
