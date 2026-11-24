// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test-only: capture the levels of the tracing events a block emits
//! (NAN-5817 log-level tests).

use std::sync::{Arc, Mutex};
use tracing::Level;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

/// Records the level of every event emitted while installed.
#[derive(Clone, Default)]
pub(crate) struct LevelCapture(Arc<Mutex<Vec<Level>>>);

impl LevelCapture {
    pub(crate) fn levels(&self) -> Vec<Level> {
        self.0.lock().unwrap().clone()
    }

    /// Install on the current thread until the guard drops. On a
    /// current-thread tokio runtime that covers every `.await` in the test.
    pub(crate) fn install(&self) -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(tracing_subscriber::registry().with(self.clone()))
    }
}

impl<S: tracing::Subscriber> Layer<S> for LevelCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        self.0.lock().unwrap().push(*event.metadata().level());
    }
}

/// Run `f` under a capturing subscriber; return its output and the levels it logged.
pub(crate) fn levels_logged<T>(f: impl FnOnce() -> T) -> (T, Vec<Level>) {
    let capture = LevelCapture::default();
    let out = {
        let _guard = capture.install();
        f()
    };
    (out, capture.levels())
}
