// SPDX-License-Identifier: AGPL-3.0-or-later

//! Event Core - Shared library for log-blaster and injector tools
//!
//! Provides profile-driven event generation from real telemetry profiles
//! (originally captured in the Ludus lab).

pub mod entity;
pub mod event;
pub mod generators;
pub mod http;
pub mod otlp;
pub mod profiles;
pub mod variance;
pub mod web_session;
