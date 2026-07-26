// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-source RBAC scoping for AI tuning artifacts (NAN-2085 / NAN-2088).
//!
//! A tuning proposal is a DERIVED artifact. The auto-tuner lifts exact values
//! out of matched events — IPs, hostnames, usernames, process names, command
//! lines, file paths, arbitrary string metadata — into `affected_patterns`, and
//! the model that writes `proposed_query` / `rationale` / `changes_summary` sees
//! the same matched-event samples and can repeat those values anywhere in its
//! output. The silent-rule detector separately serializes a source's exact
//! recent event volume, which schema fields it populates, and its peak grouped
//! count into the same free-form fields.
//!
//! Neither producer recorded WHERE the facts came from, and every read path
//! required only `detections:view`. A principal denied a sensitive source could
//! therefore recover its entity values and activity shape through the tuning
//! queue, and restricting a source later could not revoke that access because
//! the artifact carried no provenance to re-evaluate.
//!
//! # Fail-closed, because the payload is prose
//!
//! These semantics are DELIBERATELY inverted relative to `alerts.source_types`
//! and `detection_matches.source_types`, and match the frozen-artifact
//! `report_runs` gate instead. A match row is structured and row-attributed, so
//! an empty stamp reliably means "not source-derived" and stays visible. A
//! proposal is free-form text and model output: an empty/untrustworthy manifest
//! means "we do not know what is in here", which for a restricted reader must
//! mean deny. Every pre-feature proposal carries `'{}' + complete = false` and
//! is therefore hidden from source-scoped readers until a producer stamps it.
//!
//! Unrestricted readers (empty deny set) are never affected — the predicate is
//! not even emitted, so their SQL stays byte-identical to the pre-scoping form.
//!
//! # System callers are not viewers
//!
//! Proposal GENERATION is a background/system activity that legitimately reads
//! every source; the orchestrator's PR-recovery and state-transition reads run
//! with no human principal at all. Those callers pass [`TuningScope::system`].
//! That system execution scope is never the later viewer's authorization — the
//! artifact is re-evaluated against the reader's own deny set on every read.

use std::collections::BTreeSet;

pub use crate::auth::{normalize_source_manifest, ArtifactScope as TuningScope};

/// Derive the origin-source manifest for a proposal generated from detection
/// findings (NAN-2085).
///
/// The auto-tuner reads findings out of the synthetic `source_type='findings'`
/// stream, so the OUTER row's source type is always the literal `findings` and
/// says nothing about where the data came from. The real origin is the
/// `source_type` (and the aggregate `_nano_source_types` stamp) on each NESTED
/// matched event — the same two forms `distinct_source_types` reads when
/// stamping `alerts` / `detection_matches`, so UDM and OCSF samples are both
/// covered.
///
/// # The sample is NOT the whole match set
///
/// `matched_events_sample` is TRUNCATED (the writer keeps only the first few
/// events), so deriving provenance from it alone under-reports a mixed-source
/// finding: if the sampled events all came from source A but later matched
/// events came from denied source B, the proposal would be stamped "complete
/// for A" and stay readable after B is restricted. The finding therefore also
/// persists `origin_source_types`, computed by
/// `FindingEvent::origin_source_types_from` over the FULL match set — that is
/// the authoritative manifest, and this function requires it.
///
/// Returns `(manifest, complete)`. `complete` is `true` only when EVERY
/// contributing finding carries a non-empty persisted `origin_source_types`
/// AND that manifest accounts for every value visible in its sample. Anything
/// less — no findings at all, a missing manifest (pre-NAN-1800 finding or
/// unparseable metadata), an empty manifest, or a sample carrying a source the
/// manifest omits — yields `false`, which denies every restricted reader.
pub fn derive_finding_source_manifest(findings: &[FindingProvenance<'_>]) -> (Vec<String>, bool) {
    if findings.is_empty() {
        return (Vec::new(), false);
    }

    let mut manifest: BTreeSet<String> = BTreeSet::new();
    let mut complete = true;

    for finding in findings {
        let sampled: BTreeSet<String> = sample_source_values(finding.matched_events);

        match finding.origin_source_types {
            // Authoritative manifest over the full match set.
            Some(origin) if !origin.is_empty() => {
                let origin: BTreeSet<String> =
                    normalize_source_manifest(origin).into_iter().collect();
                // The sample must be a SUBSET of the recorded origin. A sampled
                // source the manifest omits means the two disagree, and we
                // cannot tell which is short — fail closed.
                if !sampled.is_subset(&origin) {
                    complete = false;
                }
                manifest.extend(sampled);
                manifest.extend(origin);
            }
            // Missing (legacy / malformed) or empty: origin unknown. Still
            // union whatever the sample showed — those sources ARE in the
            // proposal — but the result can never be trusted as complete.
            _ => {
                complete = false;
                manifest.extend(sampled);
            }
        }
    }

    let manifest: Vec<String> = manifest.into_iter().collect();
    // An empty manifest can never be complete. NAN-2155: neither can one that
    // carries the unresolved-provenance sentinel — the contributing finding
    // came from a window whose source the detection engine could not determine,
    // which is the definition of an incomplete manifest even though the array
    // is non-empty. Belt-and-braces with `TuningScope`'s deny bind: this makes
    // the STORED artifact self-describing, so any future reader that only looks
    // at `source_types_complete` is right without knowing about the sentinel.
    let complete =
        complete && !manifest.is_empty() && !crate::auth::is_unresolved_provenance(&manifest);
    (manifest, complete)
}

/// One finding's provenance inputs: the persisted FULL origin manifest plus the
/// truncated sample the prompt and pattern extraction actually see.
#[derive(Debug, Clone, Copy)]
pub struct FindingProvenance<'a> {
    /// `FindingEvent::origin_source_types` as persisted in the finding's
    /// metadata — computed over every matched event. `None` when the key was
    /// absent or the metadata could not be parsed.
    pub origin_source_types: Option<&'a [String]>,
    /// `metadata.matched_events_sample` — a truncated array.
    pub matched_events: &'a serde_json::Value,
}

/// Normalized source values visible in one finding's (truncated) sample, in
/// both the per-event (`source_type`) and aggregate (`_nano_source_types`)
/// forms — the same two the `alerts` / `detection_matches` stamps read.
fn sample_source_values(matched_events: &serde_json::Value) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let Some(events) = matched_events.as_array() else {
        return out;
    };
    for event in events {
        // NAN-2155 (codex round 3): the per-event `source_type` is
        // ingest-controlled; only the engine's `_nano_source_types` stamp may
        // carry the reserved unresolved-provenance sentinel.
        if let Some(st) = event
            .get("source_type")
            .and_then(|v| v.as_str())
            .filter(|st| !crate::auth::is_reserved_source_type(st))
        {
            let st = st.trim().to_lowercase();
            if !st.is_empty() {
                out.insert(st);
            }
        }
        if let Some(arr) = event.get("_nano_source_types").and_then(|v| v.as_array()) {
            for v in arr.iter().filter_map(|v| v.as_str()) {
                let v = v.trim().to_lowercase();
                if !v.is_empty() {
                    out.insert(v);
                }
            }
        }
    }
    out
}

/// Fold one additional contributing manifest into a proposal's provenance.
///
/// NAN-2085: a proposal's inputs are not only its matched-event samples. The
/// generation prompt also carries PRIOR proposals for the same rule
/// (`get_proposal_history` → `proposed_query`, `rationale`, reviewer notes), so
/// the model can echo a previous proposal's values into the new one. Every such
/// contributor must be unioned in, and a contributor whose own provenance is not
/// complete makes the result incomplete — an unaccounted input can hide anything.
pub fn merge_source_manifest(
    into: (Vec<String>, bool),
    contributor: (&[String], bool),
) -> (Vec<String>, bool) {
    let (existing, existing_complete) = into;
    let (extra, extra_complete) = contributor;
    let mut merged: BTreeSet<String> = existing.into_iter().collect();
    merged.extend(normalize_source_manifest(extra));
    let merged: Vec<String> = merged.into_iter().collect();
    // NAN-2155: same rule as `derive_finding_source_manifest` — a contributor
    // carrying the unresolved-provenance sentinel makes the merged manifest
    // incomplete, even if the contributor itself claimed `complete`.
    let complete = existing_complete
        && extra_complete
        && !merged.is_empty()
        && !crate::auth::is_unresolved_provenance(&merged);
    (merged, complete)
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod scope_tests;
