// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5798: a test-error trigger for the Sentry trial on local and e2e
//! stacks. DEBUG BUILDS ONLY: the whole module is compiled out of release
//! builds, and even in a debug build the route exists only when
//! `NANO_SENTRY_TEST_TRIGGER=1` and error tracking initialized (a
//! `NANO_SENTRY_DSN` is set).
//!
//! `GET /api/_sentry-test` logs `Sentry test error api <ts>` at ERROR and
//! answers 500; `?kind=panic` panics instead (the catch-panic layer answers
//! 500). It sits behind the normal authentication middleware.
//!
//! Deliberately NOT in the OpenAPI spec: it does not exist in any shipped
//! build, and a debug-only path would make the exported spec depend on the
//! build profile.

use axum::extract::Query;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

pub const PATH: &str = "/api/_sentry-test";

#[derive(Debug, Default, Deserialize)]
pub struct TriggerQuery {
    #[serde(default)]
    pub kind: Option<String>,
}

/// The trigger route, or `None` when it must not exist.
pub fn routes<S: Clone + Send + Sync + 'static>() -> Option<Router<S>> {
    nanosiem_core::error_tracking::test_trigger_requested().then(|| Router::new().route(PATH, get(trigger)))
}

async fn trigger(Query(query): Query<TriggerQuery>) -> (StatusCode, Json<serde_json::Value>) {
    let message = nanosiem_core::error_tracking::test_error_message("api");
    if query.kind.as_deref() == Some("panic") {
        panic!("{message}");
    }
    tracing::error!("{message}");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": message })))
}
