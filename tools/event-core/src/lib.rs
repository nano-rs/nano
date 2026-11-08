//! Event Core - Shared library for log-blaster and injector tools
//!
//! Provides profile-driven event generation using real telemetry data
//! exported from the Ludus lab ClickHouse environment.

pub mod entity;
pub mod event;
pub mod generators;
pub mod http;
pub mod otlp;
pub mod profiles;
