// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source-scope value type for per-source RBAC (NAN-1789 / NAN-1797).
//!
//! `ScopeSet` is a PURE value type — no database or service dependencies —
//! so it can be used from query manipulation and SQL generation without
//! pulling in auth infrastructure.
//!
//! Semantics:
//! - An EMPTY denied set means UNRESTRICTED: the caller sees everything.
//!   This is the SYSTEM-caller / back-compat default (`Default` == unrestricted).
//! - A non-empty denied set lists `source_type` values the caller must never
//!   see; the query injector excludes them at every base-table scan.
//! - This type carries SOURCE-scope ONLY. The `audit` source gate is unioned
//!   into the deny set by the handler (based on the `audit:view` permission),
//!   not here.

use std::collections::BTreeSet;

/// Reserved `source_type` marker meaning "this row's source provenance could
/// NOT be determined" (NAN-2155).
///
/// # Why a sentinel exists at all
///
/// `alerts.source_types` / `detection_matches.source_types` use an EMPTY array
/// to mean "not source-derived" — observability / risk-notable alerts and
/// retro-hunt indicator summaries legitimately have no `source_type` — and the
/// read side deliberately keeps those rows visible to everyone. That makes
/// `'{}'` ambiguous: it cannot distinguish "known to have no source" from "we
/// failed to work out the source", and the failure case then publishes the row
/// to principals denied the source it actually came from, permanently and
/// unrecoverably (the row is written once and never re-derived).
///
/// The producer therefore stamps this value instead of leaving the array empty
/// when it cannot resolve provenance, and every deny-set → SQL binding routes
/// through [`deny_bind_values`] so a restricted caller's deny array always
/// contains it. Net effect: an unresolved-provenance row is visible ONLY to an
/// unrestricted principal — the same posture as the full-restricted-set stamp
/// the producer uses on every other failure branch.
///
/// # Invariants
///
/// * Already normalized (lowercase, no whitespace) so it survives the
///   `trim().to_lowercase()` normalization every stamping/deny path applies.
/// * **Not expressible as an ingested `source_type`** (codex round 3). The `:`
///   is deliberate: every `source_type` allow-list in the codebase is
///   `[A-Za-z0-9_-]` (`log_telemetry::repository::is_safe_source_type`,
///   `sql_hygiene::is_safe_sql_identifier`), so a colon cannot survive them.
///   Without that, an event sender could set `X-Source-Type:
///   __nano_unresolved_source__` and have their OWN detections hidden from
///   every source-restricted analyst — detection suppression by ingest. The
///   charset is the cheap half of the defense; [`is_reserved_source_type`]
///   applied to per-event values is the authoritative half, since nothing
///   guarantees a validator sits on every ingest path.
/// * NOT a member of the `restricted_source_types` registry — adding it there
///   would make every non-bypass principal "restricted" and emit the scope
///   predicate on deployments that have no source scoping configured at all.
pub const UNRESOLVED_SOURCE_SENTINEL: &str = "__nano:unresolved_source__";

/// Is `source_type` a RESERVED internal marker that no ingested event, log
/// source, or scope-registry row may ever claim?
///
/// Apply this to any `source_type` that originates OUTSIDE the engine — the
/// per-event `source_type` column read by the four
/// "derive source types from matched_events" helpers, and the write boundaries
/// of the restricted-source registry. Only the detection engine's own
/// `_nano_source_types` annotation (which no ingest path can produce — `_nano_*`
/// is an in-memory reserved prefix, never a projected column) may carry
/// [`UNRESOLVED_SOURCE_SENTINEL`].
///
/// Dropping a reserved value from a derived stamp is safe: the row falls back
/// to whatever its other sources say, or to `'{}'` (visible to everyone) —
/// exactly the pre-existing behaviour for an unattributed row. The attacker
/// gains nothing and loses the ability to hide their events.
pub fn is_reserved_source_type(source_type: &str) -> bool {
    source_type.trim().to_lowercase() == UNRESOLVED_SOURCE_SENTINEL
}

/// Does a stored source manifest carry [`UNRESOLVED_SOURCE_SENTINEL`]?
///
/// The counterpart to [`deny_bind_values`] for the surfaces that decide
/// visibility in RUST rather than by binding a deny array — the tuning-proposal
/// manifest (`tuning::scope`), the frozen report artifact
/// (`reports::report_artifact_download_allowed`), and the write-time origin
/// redactions (`SourceScopeResolver::any_restricted`).
///
/// Those surfaces use ALLOW-list semantics ("is this manifest disjoint from the
/// deny set / provably unrestricted?"), so an unfamiliar value in the manifest
/// reads as harmless rather than dangerous — the exact opposite of the
/// deny-array surfaces. They must therefore test for the sentinel explicitly.
///
/// Inputs are normalized defensively; a manifest that has been round-tripped
/// through storage is already trimmed and lowercased, but a directly
/// constructed one may not be.
pub fn is_unresolved_provenance(source_types: &[String]) -> bool {
    // Delegates so there is exactly ONE definition of "is this the sentinel".
    // Two copies of the comparison would drift the moment a second reserved
    // marker is added, and the two functions guard opposite-shaped decisions
    // (drop-on-input vs deny-on-read) — the failure would be silent in both.
    source_types.iter().any(|s| is_reserved_source_type(s))
}

/// Origins whose evidence must never reach FINDING STORAGE, independent of the
/// configurable restricted-source registry.
///
/// `audit` is deliberately not seeded into `restricted_source_types`: doing so
/// would source-scope every non-bypass principal on otherwise unscoped
/// deployments. It is nevertheless always restricted for findings, because a
/// finding re-embeds raw audit event content under a different outer
/// `source_type` and then feeds risk scores every analyst reads.
///
/// NAN-2207: this is a FINDINGS-ONLY policy. Webhook egress deliberately does
/// NOT consult it — see [`is_always_restricted_origin`] for why the two
/// write-time boundaries diverged.
pub const ALWAYS_RESTRICTED_ORIGINS: &[&str] = &["audit"];

/// Does a source manifest contain an always-restricted origin?
///
/// The write-time predicate for FINDING STORAGE
/// (`FindingLogger::origin_restricted`). Keep it separate from per-user source
/// visibility: an unrestricted UI principal may inspect audit data, but a
/// finding that re-embeds it is a different, longer-lived artifact.
///
/// # Not for webhook egress (NAN-2207)
///
/// NAN-2155 applied this to webhook payloads too. That silently broke every
/// existing SOAR integration built on an audit-sourced detection rule: the
/// payload kept `matched_event_count` but dropped `matched_events` + `entity`,
/// with no error and no delivery-log signal, on deployments that had never
/// configured source scoping at all. On such a deployment there is no RBAC
/// boundary for the redaction to protect — every analyst can already read audit
/// events in search — so the strip removed evidence from the receiver without
/// hiding it from anyone.
///
/// Webhook egress now redacts an audit origin only when an admin has explicitly
/// registered `audit` in `restricted_source_types`, which is the deployment's
/// own statement that audit is sensitive. Unresolved provenance
/// ([`is_unresolved_provenance`]) still redacts unconditionally on BOTH
/// boundaries: "we could not tell where this came from" is not a policy choice
/// an admin can make in advance.
pub fn is_always_restricted_origin(source_types: &[String]) -> bool {
    source_types.iter().any(|source_type| {
        let normalized = source_type.trim().to_lowercase();
        ALWAYS_RESTRICTED_ORIGINS.contains(&normalized.as_str())
    })
}

/// Normalize a caller's effective deny set into the values to BIND as the
/// `text[]` parameter of a `source_types` overlap predicate.
///
/// Trims + lowercases (the stamping side does the same, so a differently-cased
/// deny value must not silently fail to overlap), drops empties, and — for a
/// RESTRICTED caller only — appends [`UNRESOLVED_SOURCE_SENTINEL`] so rows
/// whose provenance could not be determined are hidden.
///
/// An empty input returns an empty vector: callers must keep emitting no
/// predicate at all for an unrestricted caller, so the SQL stays byte-identical
/// to the pre-scoping form and admins keep seeing unresolved-provenance rows.
pub fn deny_bind_values(denied: &BTreeSet<String>) -> Vec<String> {
    let mut values: Vec<String> = denied
        .iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if !values.is_empty() {
        values.push(UNRESOLVED_SOURCE_SENTINEL.to_string());
        values.sort();
        values.dedup();
    }
    values
}

/// Set of `source_type` values denied to a caller.
///
/// Empty denied set = unrestricted = SYSTEM caller. Carries SOURCE-scope only;
/// the audit gate is unioned in by the handler, not by this type.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeSet {
    denied: BTreeSet<String>,
}

impl ScopeSet {
    /// An unrestricted scope (empty denied set) — sees everything.
    /// Use for SYSTEM callers (schedulers, internal jobs) only.
    pub fn unrestricted() -> Self {
        Self::default()
    }

    /// Build a scope from an explicit denied set of `source_type` values.
    pub fn from_denied(denied: BTreeSet<String>) -> Self {
        Self { denied }
    }

    /// The `source_type` values this caller must never see.
    pub fn deny_set(&self) -> &BTreeSet<String> {
        &self.denied
    }

    /// True when at least one source is denied. `false` means unrestricted.
    pub fn is_restricted(&self) -> bool {
        !self.denied.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_is_unrestricted() {
        let scope = ScopeSet::default();
        assert!(!scope.is_restricted());
        assert!(scope.deny_set().is_empty());
        assert_eq!(scope, ScopeSet::unrestricted());
    }

    #[test]
    fn unrestricted_equals_from_empty_denied() {
        assert_eq!(
            ScopeSet::unrestricted(),
            ScopeSet::from_denied(BTreeSet::new())
        );
    }

    #[test]
    fn from_denied_is_restricted_and_exposes_deny_set() {
        let scope = ScopeSet::from_denied(set(&["insider_threat", "audit"]));
        assert!(scope.is_restricted());
        assert_eq!(scope.deny_set(), &set(&["audit", "insider_threat"]));
    }

    #[test]
    fn equality_is_order_independent() {
        let a = ScopeSet::from_denied(set(&["b", "a"]));
        let b = ScopeSet::from_denied(set(&["a", "b"]));
        assert_eq!(a, b);
    }

    // ---- NAN-2155: unresolved-provenance sentinel -------------------------

    #[test]
    fn deny_bind_values_unrestricted_stays_empty() {
        // An unrestricted caller must emit NO predicate at all, so the sentinel
        // must not sneak in and turn an empty bind into a filter.
        assert!(deny_bind_values(&BTreeSet::new()).is_empty());
        assert!(deny_bind_values(&set(&["", "   "])).is_empty());
    }

    #[test]
    fn deny_bind_values_restricted_appends_sentinel_and_normalizes() {
        let got = deny_bind_values(&set(&["  Insider_Threat ", "AUDIT"]));
        assert_eq!(
            got,
            vec![
                UNRESOLVED_SOURCE_SENTINEL.to_string(),
                "audit".to_string(),
                "insider_threat".to_string(),
            ],
            "restricted callers deny their own sources PLUS unresolved provenance"
        );
    }

    #[test]
    fn deny_bind_values_is_idempotent_when_sentinel_already_present() {
        // Defensive: a caller that somehow already carries the sentinel must
        // not end up binding it twice.
        let got = deny_bind_values(&set(&["audit", UNRESOLVED_SOURCE_SENTINEL]));
        assert_eq!(
            got.iter()
                .filter(|v| v.as_str() == UNRESOLVED_SOURCE_SENTINEL)
                .count(),
            1
        );
    }

    #[test]
    fn sentinel_is_already_normalized() {
        // The stamping side normalizes with trim+lowercase; if the constant did
        // not survive that round-trip the stamp and the deny value would never
        // overlap and the whole mechanism would silently fail open.
        assert_eq!(
            UNRESOLVED_SOURCE_SENTINEL.trim().to_lowercase(),
            UNRESOLVED_SOURCE_SENTINEL
        );
    }

    #[test]
    fn always_restricted_origin_is_normalized_and_exact() {
        assert!(is_always_restricted_origin(&[" Audit ".to_string()]));
        assert!(!is_always_restricted_origin(&["auditbeat".to_string()]));
        assert!(!is_always_restricted_origin(&[]));
    }

    #[test]
    fn unresolved_provenance_is_independent_of_the_always_restricted_set() {
        // NAN-2207 split the two write-time policies: findings consult BOTH
        // predicates, webhook egress consults only this one. They must therefore
        // stay independently true — an `audit` origin is not "unresolved", and a
        // sentinel origin does not need `audit` to redact.
        assert!(is_unresolved_provenance(&[
            "syslog".to_string(),
            UNRESOLVED_SOURCE_SENTINEL.to_string(),
        ]));
        assert!(!is_unresolved_provenance(&["audit".to_string()]));
        assert!(!is_always_restricted_origin(&[
            UNRESOLVED_SOURCE_SENTINEL.to_string()
        ]));
    }
}
