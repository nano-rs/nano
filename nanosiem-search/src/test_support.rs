// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test-only helpers shared across the crate's unit tests.

use std::sync::{Arc, Mutex, Once};
use std::cell::RefCell;
use tracing::field::{Field, Visit};
use tracing_subscriber::{layer::Context, prelude::*, Layer};

/// One captured tracing event: its level and every field rendered as
/// `name=value`, joined with the message.
#[derive(Debug, Clone)]
pub(crate) struct CapturedEvent {
    pub level: tracing::Level,
    pub rendered: String,
}

#[derive(Default)]
struct Render(String);

impl Visit for Render {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={:?}", field.name(), value));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push_str(&format!(" {}={}", field.name(), value));
    }
}

thread_local! {
    static EVENTS: RefCell<Option<Arc<Mutex<Vec<CapturedEvent>>>>> = const { RefCell::new(None) };
}
struct Capture;

/// A capture must be dropped on the same test thread that installed it.
pub(crate) struct CaptureGuard {
    previous: Option<Arc<Mutex<Vec<CapturedEvent>>>>,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Drop for CaptureGuard {
    fn drop(&mut self) {
        EVENTS.with(|slot| { *slot.borrow_mut() = self.previous.take(); });
    }
}

impl<S: tracing::Subscriber> Layer<S> for Capture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let Some(events) = EVENTS.with(|slot| slot.borrow().clone()) else { return; };
        let mut render = Render::default();
        event.record(&mut render);
        events.lock().unwrap().push(CapturedEvent {
            level: *event.metadata().level(),
            rendered: render.0,
        });
    }
}

/// Use one stable subscriber with per-test-thread buffers. Replacing/dropping
/// dispatchers in parallel tests races tracing's process-global callsite
/// interest cache and can suppress an ERROR despite an active local capture.
/// A fixed subscriber avoids that race without serializing unrelated tests.
pub(crate) fn capture_logs() -> (
    Arc<Mutex<Vec<CapturedEvent>>>,
    CaptureGuard,
) {
    static SUBSCRIBER: Once = Once::new();
    SUBSCRIBER.call_once(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(Capture))
            .expect("test log capture owns the global subscriber");
    });
    let events = Arc::new(Mutex::new(Vec::new()));
    let previous = EVENTS.with(|slot| slot.replace(Some(events.clone())));
    (events, CaptureGuard { previous, _thread_bound: std::marker::PhantomData })
}

/// True when some captured event at `level` or more severe mentions `needle`.
pub(crate) fn logged_at_least(
    events: &Mutex<Vec<CapturedEvent>>,
    level: tracing::Level,
    needle: &str,
) -> bool {
    events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.level <= level && event.rendered.contains(needle))
}
