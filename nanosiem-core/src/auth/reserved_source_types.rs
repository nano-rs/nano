// SPDX-License-Identifier: AGPL-3.0-or-later

//! Platform-owned `source_type` values (NAN-5032).
//!
//! Some `source_type` values are written by nano itself and are TRUSTED by
//! readers: the audit page reads `source_type = 'audit'`, tuning and risk read
//! `source_type = 'findings'`. Every multiplex ingest lane keeps the
//! sender-declared type, so before this module a forwarder holding the install
//! token could insert rows the audit page showed as genuine audit entries.
//!
//! This is the ONE list. It is enforced at:
//! - the storage boundary of the generated Vector pipeline
//!   ([`reserved_source_type_guard_vrl!`](crate::parsers::vector_config)),
//!   which every UDM row passes, whatever lane it came in on;
//! - ClickHouse itself: the `logs_ingest_mv` bridge (the only path from
//!   Vector's credential into `logs`) rewrites the same values
//!   (`clickhouse/192_reserved_source_type_guard.sql`);
//! - the control plane: a parser, log-source conversion or integration stream
//!   cannot be NAMED with an enforced value.
//!
//! Enforcement level (v2.0.1):
//! - [`ENFORCED`] values are rewritten to [`SPOOF_MARKER`] at ingest; the
//!   declared value is kept as `claimed_source_type` (moved into `ext`), so a
//!   forgery attempt stays visible to the SOC instead of disappearing.
//! - [`WARN_ONLY`] values and prefixes are logged and surfaced in SIEM Health
//!   but still accepted. They become enforced in v2.1.
//!
//! The audit emitter and the findings writer insert into `logs` directly as the
//! platform's ClickHouse user, never through Vector, so they are unaffected.

/// Rewritten at ingest in v2.0.1.
pub const ENFORCED: &[&str] = &["audit", "findings"];

/// Logged / surfaced only in v2.0.1 (exact values).
pub const WARN_ONLY: &[&str] = &["signal", "signals"];

/// Logged / surfaced only in v2.0.1 (prefixes).
pub const WARN_ONLY_PREFIXES: &[&str] = &["nano_", "__nano:"];

/// Platform lanes under a warn-only prefix that nano itself writes through
/// Vector. Never flagged.
pub const PLATFORM_LANES: &[&str] = &["nano_enrich", "nano_operational"];

/// The value an enforced reserved `source_type` is rewritten to.
pub const SPOOF_MARKER: &str = "reserved_spoof";

/// How a declared `source_type` relates to the reserved set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation {
    /// Not reserved.
    None,
    /// Reserved and enforced: rewritten at ingest, refused as a source name.
    Enforced,
    /// Reserved, warn-only in this release.
    WarnOnly,
}

/// Classify a `source_type` / route key (trimmed, case-insensitive).
pub fn classify(source_type: &str) -> Reservation {
    let s = source_type.trim().to_ascii_lowercase();
    if ENFORCED.contains(&s.as_str()) {
        return Reservation::Enforced;
    }
    if PLATFORM_LANES.iter().any(|lane| s.starts_with(lane)) {
        return Reservation::None;
    }
    if WARN_ONLY.contains(&s.as_str()) || WARN_ONLY_PREFIXES.iter().any(|p| s.starts_with(p)) {
        return Reservation::WarnOnly;
    }
    Reservation::None
}

/// The error text for a control-plane name that collides with an enforced
/// value. One wording for every surface.
pub fn enforced_name_error(name: &str) -> String {
    format!(
        "{name:?} is a source type nano writes itself (audit/findings records) and cannot \
         name a log source, parser or integration stream"
    )
}
