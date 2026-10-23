// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tracing for lean-cell tenant children (`ingest[T]`, `query[T]`).
//!
//! The cell supervisor forwards `RUST_LOG` to a child only when the cell
//! itself has one, and production cells render none. A child must therefore
//! default to INFO on its own: `EnvFilter::from_default_env()` with no
//! `RUST_LOG` keeps ERROR only, which left the first lean tenant's ingest
//! silent for its whole life (NAN-2964). Output is JSON, one object per line,
//! like every other child line the supervisor forwards.

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// The filter a cell child runs with: `rust_log` when it parses, else `info`.
pub fn child_env_filter(rust_log: Option<&str>) -> EnvFilter {
    rust_log
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| EnvFilter::try_new(value).ok())
        .unwrap_or_else(|| EnvFilter::new("info"))
}

/// Install the JSON subscriber for a cell child (call once, after the jail).
pub fn init_child_tracing() {
    let rust_log = std::env::var("RUST_LOG").ok();
    let service =
        std::env::var("NANO_OTLP_TRACE_SERVICE").unwrap_or_else(|_| "nano-lake-worker".into());
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json())
        .with(nanosiem_core::telemetry::OtlpTraceLayer::from_env(&service))
        .with(child_env_filter(rust_log.as_deref()))
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::filter::LevelFilter;

    #[test]
    fn a_child_without_rust_log_logs_info() {
        assert_eq!(child_env_filter(None).max_level_hint(), Some(LevelFilter::INFO));
        assert_eq!(child_env_filter(Some("")).max_level_hint(), Some(LevelFilter::INFO));
        // An unparseable RUST_LOG falls back to info rather than silence.
        assert_eq!(child_env_filter(Some("=[")).max_level_hint(), Some(LevelFilter::INFO));
    }

    #[test]
    fn an_explicit_rust_log_still_wins() {
        assert_eq!(child_env_filter(Some("debug")).max_level_hint(), Some(LevelFilter::DEBUG));
        assert_eq!(child_env_filter(Some("warn")).max_level_hint(), Some(LevelFilter::WARN));
    }
}
