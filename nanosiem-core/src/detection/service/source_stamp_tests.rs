// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2155: the aggregate `source_types` stamp must never fail OPEN.
//!
//! `annotate_source_types_for_scoping` used to `return` without stamping when
//! the restricted-source registry could not be loaded, leaving the row at
//! `source_types = '{}'`. The read side treats `'{}'` as "not source-derived",
//! i.e. VISIBLE TO EVERYONE, so a transient PostgreSQL blip permanently and
//! unrecoverably published a restricted-source match to every principal (the
//! row is written once; its provenance can never be re-derived).
//!
//! Two things changed and both are pinned here:
//!
//! 1. the registry is now read through `SourceScopeResolver`, which RETAINS its
//!    last-known set past a refresh failure — so the common case degrades to
//!    the same deny-all-restricted stamp every other failure branch uses;
//! 2. the residual "registry never loaded at all" case stamps
//!    [`UNRESOLVED_SOURCE_SENTINEL`], which every restricted principal's deny
//!    bind carries.
//!
//! The tests below model the Postgres `source_types && $deny` overlap in Rust.
//! That model is deliberately hand-derived rather than reused from production
//! code: the SQL text itself is asserted separately (`MatchScope::sql_predicate`
//! tests, `AlertRepository::scope_clause` tests), so asserting it again here
//! would only prove the code equals itself.

use std::collections::BTreeSet;

use super::execution::{classify_companion_rows, fail_closed_stamp, CompanionProvenance};
use crate::auth::{deny_bind_values, UNRESOLVED_SOURCE_SENTINEL};
use crate::db::repository::alerts::distinct_source_types;

fn deny(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|s| s.to_string()).collect()
}

/// Hand-written model of Postgres `stamped && $deny` — `true` means the arrays
/// intersect, which is what HIDES the row (`NOT (source_types && $deny)`).
fn arrays_overlap(stamped: &[String], deny_bind: &[String]) -> bool {
    stamped.iter().any(|s| deny_bind.contains(s))
}

/// The events an aggregate rule produces: collapsed rows with no per-event
/// `source_type`, carrying only the engine's `_nano_source_types` annotation.
fn aggregate_rows(stamp: &serde_json::Value) -> serde_json::Value {
    serde_json::json!([{ "count": 12, "_nano_source_types": stamp }])
}

/// THE bug. A restricted principal must not see a match whose provenance the
/// engine could not determine.
///
/// Derivation, by hand: the row is stamped with the sentinel; a restricted
/// principal's bind array contains the sentinel; therefore the arrays overlap;
/// therefore `NOT (source_types && $deny)` is false; therefore the row is
/// filtered out. Before the fix the stamp was `'{}'`, which overlaps nothing,
/// so the row survived every deny set.
#[test]
fn unresolved_provenance_is_hidden_from_every_restricted_principal() {
    let stamped = distinct_source_types(&aggregate_rows(&fail_closed_stamp(&BTreeSet::new())));
    assert!(
        !stamped.is_empty(),
        "an unresolved stamp must NOT collapse back to the visible-to-everyone '{{}}' form"
    );

    // A principal denied one unrelated source, and one denied only `audit`:
    // neither of their deny sets mentions the match's real source (nobody
    // knows what it was), so only the sentinel can hide it.
    for denied in [
        deny(&["insider_threat"]),
        deny(&["audit"]),
        deny(&["some_source_that_does_not_exist"]),
    ] {
        assert!(
            arrays_overlap(&stamped, &deny_bind_values(&denied)),
            "unresolved-provenance match leaked to a principal denying {denied:?}"
        );
    }
}

/// The other direction: an UNRESTRICTED principal still sees it. Hiding the row
/// from everyone would make it un-triageable, which is a different failure, not
/// a safer one.
#[test]
fn unresolved_provenance_stays_visible_to_an_unrestricted_principal() {
    // Unrestricted callers bind nothing and the predicate is not emitted at
    // all, so no filtering can occur.
    assert!(deny_bind_values(&BTreeSet::new()).is_empty());
}

/// A LEGITIMATELY sourceless producer (observability alert, risk notable,
/// retro-hunt indicator summary) must keep its `'{}'` stamp and stay visible.
/// This is the contract the failure case used to be conflated with; if this
/// regresses, the fix has quietly become "hide everything unattributed".
#[test]
fn legitimately_sourceless_rows_keep_the_visible_empty_stamp() {
    let stamped = distinct_source_types(&serde_json::json!([{ "value": 1.0 }]));
    assert!(stamped.is_empty());
    assert!(!arrays_overlap(
        &stamped,
        &deny_bind_values(&deny(&["insider_threat"]))
    ));
}

/// The sentinel has to survive the stamping-side normalization
/// (`trim().to_lowercase()` in `distinct_source_types`) byte-for-byte, or the
/// stamp and the deny value would never compare equal and the whole mechanism
/// would fail open silently.
#[test]
fn the_sentinel_round_trips_through_stamp_normalization() {
    let stamped = distinct_source_types(&aggregate_rows(&fail_closed_stamp(&BTreeSet::new())));
    assert!(stamped.iter().any(|s| s == UNRESOLVED_SOURCE_SENTINEL));
}

/// The unresolved stamp also carries `audit`, which is
/// `auth::ALWAYS_RESTRICTED_ORIGINS` / the webhook egress sentinel.
/// Without it those two WRITE-time redactions would see a "known origin" they
/// cannot prove restricted and would let the matched-event sample through to
/// ClickHouse findings and to webhook subscribers — a second disclosure path
/// that the Postgres-side deny predicate does not cover at all.
#[test]
fn the_unresolved_stamp_also_trips_the_always_restricted_origin_sentinel() {
    let stamped = distinct_source_types(&aggregate_rows(&fail_closed_stamp(&BTreeSet::new())));
    assert!(
        stamped.iter().any(|s| s == "audit"),
        "unresolved stamp must trip the registry-independent audit sentinel"
    );
}

// ---------------------------------------------------------------------------
// The ALLOW-LIST shaped consumers (codex round 1).
//
// The surfaces above decide visibility by binding a DENY array, so adding the
// sentinel to the bind is enough. These three ask the opposite question — "is
// this manifest provably safe?" — where an unrecognised value reads as harmless
// and therefore fails OPEN unless the sentinel is tested for explicitly.
// ---------------------------------------------------------------------------

/// The exact P1 codex found: a proposal derived from an unattributable finding
/// carries a NON-EMPTY manifest, so the old "empty ⇒ incomplete" rule did not
/// fire and a reader restricted from one source but holding `audit:view` (deny
/// = that source only) found the manifest disjoint from their deny set.
#[test]
fn an_unresolved_finding_cannot_produce_a_complete_tuning_manifest() {
    use crate::tuning::scope::{derive_finding_source_manifest, FindingProvenance, TuningScope};

    let origin = distinct_source_types(&aggregate_rows(&fail_closed_stamp(&BTreeSet::new())));
    let sample = aggregate_rows(&fail_closed_stamp(&BTreeSet::new()));
    let (manifest, complete) = derive_finding_source_manifest(&[FindingProvenance {
        origin_source_types: Some(&origin),
        matched_events: &sample,
    }]);

    assert!(!manifest.is_empty(), "the manifest is non-empty — which is why the empty check missed it");
    assert!(
        !complete,
        "an unresolved origin must never be recorded as a complete manifest"
    );

    // …and the reader-side gate agrees, by BOTH routes: incompleteness, and the
    // sentinel now being in the restricted reader's deny bind.
    let reader = TuningScope::from_denied(&deny(&["insider_threat"]));
    assert!(!reader.allows(&manifest, complete));
    assert!(
        !reader.allows(&manifest, true),
        "even if a producer wrongly claimed completeness, the deny bind must still hide it"
    );
    assert!(reader
        .deny_bind_values()
        .iter()
        .any(|v| v == UNRESOLVED_SOURCE_SENTINEL));
}

/// A contributor with unresolved provenance poisons a merged manifest too —
/// prior proposals are folded into a new one, so a clean derivation must not be
/// able to launder an unresolved input.
#[test]
fn merging_an_unresolved_contributor_makes_the_manifest_incomplete() {
    use crate::tuning::scope::merge_source_manifest;

    let (merged, complete) = merge_source_manifest(
        (vec!["apache".to_string()], true),
        (
            &[UNRESOLVED_SOURCE_SENTINEL.to_string()],
            // The contributor lies about being complete; the merge must still
            // refuse, or the sentinel would be laundered into a readable row.
            true,
        ),
    );
    assert!(merged.iter().any(|v| v == UNRESOLVED_SOURCE_SENTINEL));
    assert!(!complete);
}

/// Frozen report artifacts are gated the same allow-list way, and their bytes
/// cannot be row-filtered after the fact — an unresolved manifest must deny.
#[test]
fn an_unresolved_report_manifest_is_not_downloadable_by_a_restricted_requester() {
    use crate::reports::report_artifact_download_allowed;

    let manifest = distinct_source_types(&aggregate_rows(&fail_closed_stamp(&BTreeSet::new())));

    // Restricted requester whose deny set does NOT name the sentinel's peers.
    assert!(!report_artifact_download_allowed(
        &deny(&["insider_threat"]),
        &manifest,
        true
    ));
    // Unrestricted requester is unaffected.
    assert!(report_artifact_download_allowed(
        &BTreeSet::new(),
        &manifest,
        true
    ));
    // A genuinely clean, complete manifest still downloads — the guard must not
    // have degenerated into "deny everything".
    assert!(report_artifact_download_allowed(
        &deny(&["insider_threat"]),
        &["apache".to_string()],
        true
    ));
}

/// The stamp must never be mistaken for a grantable source. Nothing may add it
/// to `restricted_source_types` (that would make every principal "restricted"
/// on deployments with no scoping configured) and no grant can name it, so the
/// value has to be recognisably reserved.
#[test]
fn the_sentinel_cannot_be_confused_with_a_real_source_type() {
    assert!(UNRESOLVED_SOURCE_SENTINEL.starts_with("__"));
    assert!(UNRESOLVED_SOURCE_SENTINEL.ends_with("__"));
    // Real source types come from parsers/log sources and never look like this.
    assert!(UNRESOLVED_SOURCE_SENTINEL.contains("nano"));
}

// ---------------------------------------------------------------------------
// Ingest cannot forge the sentinel (codex round 3).
//
// The sentinel lives in the same namespace as real `source_type` values. If an
// event sender could claim it, they would hide THEIR OWN detections from every
// source-restricted analyst — detection suppression, the mirror image of the
// disclosure bug this whole change fixes.
// ---------------------------------------------------------------------------

/// Defense one: the sentinel is not expressible under any `source_type`
/// allow-list in the codebase, all of which are `[A-Za-z0-9_-]`.
#[test]
fn the_sentinel_cannot_survive_a_source_type_allow_list() {
    assert!(
        !crate::log_telemetry::repository::is_safe_source_type(UNRESOLVED_SOURCE_SENTINEL),
        "sentinel must not be expressible as an ingested source_type"
    );
    assert!(!crate::sql_hygiene::is_safe_sql_identifier(
        UNRESOLVED_SOURCE_SENTINEL
    ));
}

/// Defense two, the authoritative one: even if some ingest path skips every
/// validator and lands the literal value in `logs.source_type`, the stamp
/// derivation refuses to harvest it from a PER-EVENT field.
#[test]
fn a_spoofed_per_event_source_type_cannot_forge_unresolved_provenance() {
    let spoofed = serde_json::json!([{
        "message": "x",
        "source_type": UNRESOLVED_SOURCE_SENTINEL,
    }]);
    let stamped = distinct_source_types(&spoofed);
    assert!(
        !stamped.iter().any(|s| s == UNRESOLVED_SOURCE_SENTINEL),
        "an ingested source_type must never become an unresolved-provenance stamp"
    );

    // …so the row falls back to the ordinary visible-to-everyone form, i.e. the
    // attacker gains nothing rather than gaining concealment.
    assert!(stamped.is_empty());
    assert!(!arrays_overlap(
        &stamped,
        &deny_bind_values(&deny(&["insider_threat"]))
    ));
}

/// Mixed case: a spoofed sentinel alongside a real source must not suppress the
/// real attribution either — the row still stamps `apache` and is still visible
/// to a viewer who is not denied `apache`.
#[test]
fn a_spoofed_sentinel_does_not_suppress_real_attribution() {
    let spoofed = serde_json::json!([
        { "source_type": UNRESOLVED_SOURCE_SENTINEL },
        { "source_type": "Apache" },
    ]);
    let stamped = distinct_source_types(&spoofed);
    assert_eq!(stamped, vec!["apache".to_string()]);
}

/// The engine's OWN annotation is still honoured — this is the channel the fix
/// depends on, so a filter that was too broad would silently disable it.
#[test]
fn the_engine_annotation_channel_still_carries_the_sentinel() {
    let stamped = distinct_source_types(&aggregate_rows(&fail_closed_stamp(&BTreeSet::new())));
    assert!(stamped.iter().any(|s| s == UNRESOLVED_SOURCE_SENTINEL));
}

/// codex round 4: the aggregate COMPANION query is a second route from
/// ingest-controlled `logs.source_type` into the trusted stamp, and the
/// per-event filter above does not cover it. Modelled here as the exact list
/// comprehension `annotate_source_types_for_scoping` applies to companion rows.
#[test]
fn the_companion_query_cannot_launder_a_spoofed_sentinel() {
    // Companion rows are `{source_type, count}` pairs straight off the logs
    // table — one legitimate source, one attacker-named.
    let rows = vec![
        serde_json::json!({ "source_type": "Apache", "count": 3 }),
        serde_json::json!({ "source_type": UNRESOLVED_SOURCE_SENTINEL, "count": 9 }),
    ];
    let harvested: Vec<String> = rows
        .iter()
        .filter_map(|r| r.get("source_type").and_then(|v| v.as_str()))
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .filter(|s| !crate::auth::is_reserved_source_type(s))
        .collect();
    assert_eq!(
        harvested,
        vec!["apache".to_string()],
        "a spoofed companion row must not reach the trusted stamp"
    );
}

/// codex round 5: round 4's filter created a NEW suppression primitive. If the
/// companion's ONLY value was the forged sentinel, the filtered list went empty
/// and the "no source types" branch failed closed with the restricted set —
/// which every restricted analyst denies. So the attacker got their detection
/// hidden again, just via a different branch.
///
/// The two empties must be distinguished: "no attribution at all" (fail closed)
/// vs "attributed to a name we refuse to honour" (unrestricted, stays visible).
/// Modelled as the exact branch `annotate_source_types_for_scoping` runs.
#[test]
fn a_reserved_only_companion_window_is_not_treated_as_unresolved() {
    // Calls the REAL classifier. Earlier revisions of this test re-implemented
    // the branch, which is exactly how the round 5/6/7 defects survived their own
    // tests — a model of buggy code agrees with the buggy code.
    fn classify(rows: &[serde_json::Value]) -> &'static str {
        match classify_companion_rows(rows) {
            CompanionProvenance::Attributed(_) => "attributed",
            CompanionProvenance::Unresolved { .. } => "fail_closed",
            CompanionProvenance::ReservedOnly => "reserved_only_visible",
        }
    }

    // Forged-only window: must NOT fail closed — that is the suppression bug.
    assert_eq!(
        classify(&[serde_json::json!({ "source_type": UNRESOLVED_SOURCE_SENTINEL })]),
        "reserved_only_visible"
    );
    // Genuinely unattributed window: MUST fail closed.
    assert_eq!(classify(&[serde_json::json!({ "count": 4 })]), "fail_closed");
    assert_eq!(
        classify(&[serde_json::json!({ "source_type": "  " })]),
        "fail_closed"
    );
    // MIXED reserved + real: the real source survives the filter, so the row is
    // still stamped on its strength — a forged value can never mask a restricted
    // one.
    assert_eq!(
        classify(&[
            serde_json::json!({ "source_type": UNRESOLVED_SOURCE_SENTINEL }),
            serde_json::json!({ "source_type": "hr_feed" }),
        ]),
        "attributed"
    );
    assert_eq!(
        classify_companion_rows(&[
            serde_json::json!({ "source_type": UNRESOLVED_SOURCE_SENTINEL }),
            serde_json::json!({ "source_type": " HR_Feed " }),
        ]),
        CompanionProvenance::Attributed(vec!["hr_feed".to_string()]),
        "the surviving source must be normalized and the reserved value dropped"
    );

    // codex round 7: PARTIAL attribution loses to nothing. A real source next to
    // an unattributed group must NOT be stamped on the real source's strength —
    // that would let a viewer denied some OTHER source see an aggregate that
    // includes the unattributed slice.
    assert_eq!(
        classify(&[
            serde_json::json!({ "source_type": "apache", "count": 5 }),
            serde_json::json!({ "source_type": "", "count": 2 }),
        ]),
        "fail_closed",
        "a partially attributed window must fail closed, not stamp its known sources"
    );

    // codex round 6: a forged row NEXT TO an unattributed one must not launder
    // the window into the visible branch. Provenance is only partly known, so
    // the whole window fails closed. Every unattributed shape counts.
    for unattributed in [
        serde_json::json!({ "source_type": "", "count": 1 }),
        serde_json::json!({ "source_type": "   ", "count": 1 }),
        serde_json::json!({ "source_type": serde_json::Value::Null, "count": 1 }),
        serde_json::json!({ "source_type": 7, "count": 1 }),
        serde_json::json!({ "count": 1 }),
    ] {
        assert_eq!(
            classify(&[
                serde_json::json!({ "source_type": UNRESOLVED_SOURCE_SENTINEL }),
                unattributed.clone(),
            ]),
            "fail_closed",
            "a forged row must not certify an unattributed row: {unattributed}"
        );
    }
}

/// The reserved-only outcome must leave the row VISIBLE. An empty stamp is the
/// "not source-derived / not restricted" form, which is correct here: the forged
/// name cannot be in the restricted registry, so nobody is denied it.
#[test]
fn a_reserved_only_window_stamps_the_visible_empty_form() {
    let stamp = serde_json::Value::Array(Vec::new());
    let stamped = distinct_source_types(&aggregate_rows(&stamp));
    assert!(stamped.is_empty());
    assert!(!arrays_overlap(
        &stamped,
        &deny_bind_values(&deny(&["insider_threat"]))
    ));
}

/// codex round 5 (P2): a forged per-event value must not reach a report's stored
/// manifest, or `report_artifact_download_allowed`'s sentinel check would deny
/// EVERY source-restricted requester — including the report's own owner — so one
/// crafted event could take a scheduled report offline.
#[test]
fn a_forged_source_type_cannot_take_a_report_offline() {
    use crate::reports::report_artifact_download_allowed;

    // What the report collector now stores for a forged event: nothing.
    // (`distinct_source_types` shares the per-event filter with the report
    // collector's `distinct_source_types_over`.)
    let stored = distinct_source_types(&serde_json::json!([{
        "source_type": UNRESOLVED_SOURCE_SENTINEL,
        "message": "x",
    }]));
    assert!(stored.is_empty(), "a forged value must not enter the manifest");
    assert!(
        report_artifact_download_allowed(&deny(&["insider_threat"]), &stored, true),
        "a restricted requester must keep access to a report a forged event touched"
    );

    // …while an ENGINE-written unresolved manifest is still denied. Both halves
    // matter: filtering must not have disabled the round-1 guard.
    let engine = distinct_source_types(&aggregate_rows(&fail_closed_stamp(&BTreeSet::new())));
    assert!(!report_artifact_download_allowed(
        &deny(&["insider_threat"]),
        &engine,
        true
    ));
}

/// codex round 4: the fail-closed stamp must not depend on registry FRESHNESS.
/// The detection service builds its own resolver, which converges on registry
/// mutations only via the cross-process version poll — and the stamp is
/// irreversible, so a stale snapshot would permanently under-stamp.
///
/// Derivation by hand: source `newly_restricted` is added to the registry, but
/// this process's snapshot still holds `{old_source}`. A viewer denied only
/// `newly_restricted` (and holding `audit:view`, so no implicit audit deny)
/// therefore does NOT overlap `{old_source, audit}`. Only the sentinel closes
/// that gap.
#[test]
fn the_fail_closed_stamp_survives_a_stale_registry_snapshot() {
    // The real production stamp, built from a STALE snapshot that has not yet
    // picked up `newly_restricted`.
    let stale_registry = deny(&["old_source"]);
    let stamped = distinct_source_types(&aggregate_rows(&fail_closed_stamp(&stale_registry)));

    let victim = deny_bind_values(&deny(&["newly_restricted"]));

    // Precondition: the registry contribution alone does NOT hide the row from
    // this viewer. If this assertion ever fails the test has stopped proving
    // anything — it would be passing for the wrong reason.
    let registry_part: Vec<String> = stale_registry.iter().cloned().collect();
    assert!(
        !arrays_overlap(&registry_part, &victim),
        "precondition: the stale registry alone must not hide the row — that is the bug"
    );
    assert!(
        arrays_overlap(&stamped, &victim),
        "the sentinel must hide the row regardless of registry freshness"
    );
}

/// The registry contribution is still present and still precise — the sentinel
/// is additive, not a replacement. A viewer denied a source that IS in the
/// snapshot must be hidden by that value too, so the stamp keeps working if the
/// sentinel is ever narrowed.
#[test]
fn the_fail_closed_stamp_keeps_the_precise_registry_contribution() {
    let registry = deny(&["insider_threat", "hr_feed"]);
    let stamped = distinct_source_types(&aggregate_rows(&fail_closed_stamp(&registry)));

    for value in ["insider_threat", "hr_feed", "audit", UNRESOLVED_SOURCE_SENTINEL] {
        assert!(
            stamped.iter().any(|s| s == value),
            "fail-closed stamp must carry {value}"
        );
    }
    // Deterministic and duplicate-free — `audit` appears once even when the
    // registry already lists it.
    let with_audit = deny(&["audit"]);
    let stamped_audit = distinct_source_types(&aggregate_rows(&fail_closed_stamp(&with_audit)));
    assert_eq!(
        stamped_audit.iter().filter(|s| s.as_str() == "audit").count(),
        1
    );
}
