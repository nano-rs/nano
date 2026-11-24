// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5817: log level of search failures in the HTTP layer. Every 500 logs
//! at ERROR; a caller's query mistake never does.

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use tracing::Level;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

use nanosiem_core::SearchError as CoreError;

#[derive(Clone, Default)]
struct LevelCapture(Arc<Mutex<Vec<Level>>>);

impl<S: tracing::Subscriber> Layer<S> for LevelCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        self.0.lock().unwrap().push(*event.metadata().level());
    }
}

fn levels_logged<T>(f: impl FnOnce() -> T) -> (T, Vec<Level>) {
    let capture = LevelCapture::default();
    let out = tracing::subscriber::with_default(
        tracing_subscriber::registry().with(capture.clone()),
        f,
    );
    let levels = capture.0.lock().unwrap().clone();
    (out, levels)
}

fn every_core_error() -> Vec<CoreError> {
    vec![
        CoreError::ParseError("x".into()),
        CoreError::FieldNotFound { field: "f".into(), suggestions: vec![], message: "m".into() },
        CoreError::SqlGenError("Invalid query: Unknown eval function 'nosuchfn'".into()),
        CoreError::SqlGenError("Invalid rex pattern '(': bad".into()),
        CoreError::SqlGenError("Internal error: boom".into()),
        CoreError::DatabaseError(sqlx::Error::Protocol("boom".into())),
        CoreError::Timeout(10_000),
        CoreError::InvalidTimeRange,
        CoreError::SqlValidationError("bad".into()),
        CoreError::PrevalenceError("dict".into()),
        CoreError::ResponseTooLarge(200, 100),
        CoreError::AdmissionDenied("busy".into()),
        CoreError::Cancelled,
        CoreError::JobResultsUnavailable("later".into()),
        CoreError::ViewTooLarge { view: "asset".into(), needed_bytes: 2, budget_bytes: 1 },
        CoreError::ViewMemoryBusy { view: "asset".into(), waited_ms: 1 },
        CoreError::Unavailable("refused".into()),
        CoreError::Forbidden("no".into()),
        CoreError::ResourceLimit("memory".into()),
        CoreError::DataError { code: 6, name: "CANNOT_PARSE_TEXT".into() },
    ]
}

/// Review P1: the level follows the response status as well as the error
/// kind. ResponseTooLarge answers 500 and used to log at WARN.
#[test]
fn every_500_logs_at_error() {
    for core in every_core_error() {
        let label = format!("{core:?}");
        let (mapped, levels) = levels_logged(|| crate::SearchError::from(core));
        if mapped.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            assert!(levels.contains(&Level::ERROR), "{label} -> 500 without ERROR: {levels:?}");
        }
    }
}

#[test]
fn caller_query_mistakes_do_not_log_error() {
    for core in [
        CoreError::SqlGenError("Invalid query: Unknown eval function 'nosuchfn'".into()),
        CoreError::SqlGenError("Unsupported operation: asset must be the last command".into()),
        CoreError::SqlGenError("Invalid rex pattern '(': bad".into()),
    ] {
        let label = format!("{core:?}");
        let (mapped, levels) = levels_logged(|| crate::SearchError::from(core));
        assert_ne!(mapped.status_code(), StatusCode::INTERNAL_SERVER_ERROR, "{label}");
        assert!(!levels.contains(&Level::ERROR), "{label}: {levels:?}");
    }
}

/// Review P2: the prevalence-artifacts call runs on every search page load.
#[test]
fn prevalence_artifacts_failure_level() {
    let (_, user) = levels_logged(|| {
        super::log_prevalence_artifacts_failure(&CoreError::SqlGenError(
            "Invalid query: Unknown eval function 'nosuchfn'".into(),
        ))
    });
    assert_eq!(user, vec![Level::WARN]);
    let (_, internal) = levels_logged(|| {
        super::log_prevalence_artifacts_failure(&CoreError::Unavailable("refused".into()))
    });
    assert_eq!(internal, vec![Level::ERROR]);
}
