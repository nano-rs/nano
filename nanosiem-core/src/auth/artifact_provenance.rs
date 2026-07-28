// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable source provenance for persistent derived artifacts (NAN-2137).
//!
//! Frozen analytics, reports, and model-generated text cannot be safely
//! row-filtered after they are persisted. Their producers therefore store:
//!
//! - the normalized union of every contributing event origin; and
//! - whether that union is a complete account of every input.
//!
//! Legacy rows and partially attributed artifacts are deliberately incomplete.
//! An unrestricted/system reader may still use them, but every source-scoped
//! reader fails closed unless the stored manifest is complete and disjoint from
//! the reader's effective deny set.

use std::collections::BTreeSet;

use super::{deny_bind_values, is_unresolved_provenance, ScopeSet};

/// Persistable origin manifest for one derived artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceProvenance {
    source_types: Vec<String>,
    complete: bool,
}

/// A derived value paired with the provenance of every input used to make it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenanced<T> {
    pub value: T,
    pub provenance: SourceProvenance,
}

impl<T> Provenanced<T> {
    pub fn new(value: T, provenance: SourceProvenance) -> Self {
        Self { value, provenance }
    }

    pub fn into_value(self) -> T {
        self.value
    }
}

impl SourceProvenance {
    /// Build a normalized provenance value from producer-classified inputs.
    ///
    /// `complete = true` is accepted only for a non-empty manifest with no
    /// unresolved-provenance sentinel. This makes the stored completeness flag
    /// self-describing even if a future reader forgets the sentinel rule.
    pub fn from_parts<I, S>(source_types: I, complete: bool) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let source_types = normalize_source_manifest(source_types);
        let complete =
            complete && !source_types.is_empty() && !is_unresolved_provenance(&source_types);
        Self {
            source_types,
            complete,
        }
    }

    /// A producer proved every contributor and supplied a non-empty manifest.
    pub fn complete<I, S>(source_types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::from_parts(source_types, true)
    }

    /// Preserve the origins a producer did identify without claiming they are
    /// the whole input set. This is the correct stamp for legacy bridges and
    /// partially source-partitioned analytics.
    pub fn incomplete<I, S>(known_source_types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::from_parts(known_source_types, false)
    }

    /// Stable, normalized source manifest to persist in a `TEXT[]` column.
    pub fn source_types(&self) -> &[String] {
        &self.source_types
    }

    /// Whether [`Self::source_types`] accounts for every contributor.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Consume the value into database-bindable parts.
    pub fn into_parts(self) -> (Vec<String>, bool) {
        (self.source_types, self.complete)
    }

    /// Union another contributor into this artifact.
    ///
    /// Completeness is monotonic toward failure: one incomplete contributor
    /// makes the combined artifact incomplete, and an unresolved marker can
    /// never be laundered into a complete result by merging it with good data.
    pub fn merge(self, contributor: &SourceProvenance) -> Self {
        let mut source_types: BTreeSet<String> = self.source_types.into_iter().collect();
        source_types.extend(contributor.source_types.iter().cloned());
        Self::from_parts(source_types, self.complete && contributor.complete)
    }
}

/// A persistent-artifact reader's effective source scope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactScope {
    /// Normalized explicit denies plus the unresolved-provenance sentinel.
    /// Empty means unrestricted.
    deny: Vec<String>,
}

impl ArtifactScope {
    /// Unrestricted scope for system/background callers with no viewer.
    pub fn system() -> Self {
        Self::default()
    }

    /// Build from the canonical source-scope value carried by request paths.
    ///
    /// NAN-2219: this reads the scope's DERIVED-ARTIFACT half
    /// ([`ScopeSet::artifact_deny_set`]), not its row-filter half. The two
    /// differ only by denies a composer explicitly classified as live-data-only
    /// — today just the `audit:view` gate, which must not make an otherwise
    /// unscoped analyst "restricted" against artifact provenance gates whose
    /// backing columns were never backfilled. See
    /// [`compose_viewer_scope`](crate::auth::compose_viewer_scope).
    ///
    /// Use [`Self::from_denied`] with `scope.deny_set()` at any site that is
    /// really doing per-source ROW filtering and merely borrows this type's
    /// classifier (e.g. retaining per-source partitions inside a report).
    pub fn from_scope(scope: &ScopeSet) -> Self {
        Self::from_denied(scope.artifact_deny_set())
    }

    /// Build from an already-composed effective deny set.
    pub fn from_denied(denied: &BTreeSet<String>) -> Self {
        Self {
            deny: deny_bind_values(denied),
        }
    }

    /// `true` when no artifact predicate should be emitted.
    pub fn is_unrestricted(&self) -> bool {
        self.deny.is_empty()
    }

    /// Values to bind for [`Self::sql_predicate`].
    pub fn deny_bind_values(&self) -> &[String] {
        &self.deny
    }

    /// Pure visibility classifier for a stored provenance value.
    pub fn allows_provenance(&self, provenance: &SourceProvenance) -> bool {
        self.allows(provenance.source_types(), provenance.is_complete())
    }

    /// Compatibility form for row types that expose separate manifest and
    /// completeness columns.
    pub fn allows(&self, source_types: &[String], complete: bool) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        if !complete || is_unresolved_provenance(source_types) {
            return false;
        }
        // A complete empty manifest is valid for artifact classes whose
        // producer proved they contain no source-derived rows (`report_runs`
        // uses this for reserved-only companion output). SourceProvenance
        // producers remain stricter and never manufacture that state.
        let normalized = normalize_source_manifest(source_types);
        let manifest: BTreeSet<&str> = normalized.iter().map(String::as_str).collect();
        let denied: BTreeSet<&str> = self.deny.iter().map(String::as_str).collect();
        denied.is_disjoint(&manifest)
    }

    /// SQL counterpart of [`Self::allows`].
    ///
    /// Callers emit no predicate for an unrestricted scope. For a restricted
    /// reader this fragment requires an explicitly complete row and excludes
    /// every mixed-origin artifact overlapping the bound deny array.
    pub fn sql_predicate(
        manifest_column: &'static str,
        complete_column: &'static str,
        param: usize,
    ) -> String {
        format!(" AND {complete_column} AND NOT ({manifest_column} && ${param}::text[])")
    }
}

/// Normalize producer-collected source values for stable storage and overlap.
pub fn normalize_source_manifest<I, S>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let set: BTreeSet<String> = values
        .into_iter()
        .map(|source_type| source_type.as_ref().trim().to_lowercase())
        .filter(|source_type| !source_type.is_empty())
        .collect();
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::UNRESOLVED_SOURCE_SENTINEL;

    fn deny(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn producer_normalizes_and_completeness_fails_closed() {
        let complete = SourceProvenance::complete([" Windows_Event ", "windows_event", "Apache"]);
        assert_eq!(
            complete.source_types(),
            &["apache".to_string(), "windows_event".to_string()]
        );
        assert!(complete.is_complete());

        assert!(!SourceProvenance::complete(Vec::<String>::new()).is_complete());
        assert!(
            !SourceProvenance::complete([UNRESOLVED_SOURCE_SENTINEL.to_string()]).is_complete()
        );
    }

    #[test]
    fn merge_unions_sources_and_never_repairs_incomplete_inputs() {
        let allowed = SourceProvenance::complete(["apache"]);
        let denied = SourceProvenance::complete(["insider_threat"]);
        let merged = allowed.merge(&denied);
        assert_eq!(
            merged.source_types(),
            &["apache".to_string(), "insider_threat".to_string()]
        );
        assert!(merged.is_complete());

        let incomplete = SourceProvenance::incomplete(["legacy"]);
        assert!(!merged.merge(&incomplete).is_complete());
    }

    #[test]
    fn reader_matrix_is_fail_closed_and_mixed_origin_conservative() {
        let unrestricted = ArtifactScope::system();
        let restricted = ArtifactScope::from_denied(&deny(&["insider_threat"]));
        let legacy = SourceProvenance::incomplete(Vec::<String>::new());
        let allowed = SourceProvenance::complete(["apache"]);
        let denied = SourceProvenance::complete(["insider_threat"]);
        let mixed = SourceProvenance::complete(["apache", "insider_threat"]);

        assert!(unrestricted.allows_provenance(&legacy));
        assert!(unrestricted.allows_provenance(&mixed));
        assert!(!restricted.allows_provenance(&legacy));
        assert!(restricted.allows_provenance(&allowed));
        assert!(!restricted.allows_provenance(&denied));
        assert!(!restricted.allows_provenance(&mixed));
    }

    /// NAN-2219: `from_scope` reads the scope's DERIVED-ARTIFACT half, while a
    /// site doing real per-source ROW filtering opts into the row-filter half
    /// explicitly via `from_denied(scope.deny_set())`. Both directions are
    /// pinned here so a future edit cannot quietly swap them.
    #[test]
    fn from_scope_reads_the_artifact_half_and_from_denied_the_row_half() {
        let scope = crate::auth::compose_viewer_scope(
            &ScopeSet::from_denied(deny(&["insider_threat"])),
            /* has_audit_view = */ false,
        );

        let artifact = ArtifactScope::from_scope(&scope);
        assert!(artifact.allows(&["audit".to_string()], true));
        assert!(!artifact.allows(&["insider_threat".to_string()], true));

        let row = ArtifactScope::from_denied(scope.deny_set());
        assert!(!row.allows(&["audit".to_string()], true));
        assert!(!row.allows(&["insider_threat".to_string()], true));

        // A caller with no per-source boundary at all is artifact-unrestricted,
        // which is what keeps the provenance gates off the byte-identical path.
        let unscoped = crate::auth::compose_viewer_scope(&ScopeSet::unrestricted(), false);
        assert!(ArtifactScope::from_scope(&unscoped).is_unrestricted());
        assert!(!ArtifactScope::from_denied(unscoped.deny_set()).is_unrestricted());
    }

    #[test]
    fn sql_and_rust_classifiers_have_the_same_direction() {
        assert_eq!(
            ArtifactScope::sql_predicate("a.source_types", "a.source_types_complete", 4),
            " AND a.source_types_complete AND NOT (a.source_types && $4::text[])"
        );

        let restricted = ArtifactScope::from_denied(&deny(&["insider_threat"]));
        for (source_types, complete) in [
            (vec![], false),
            (vec!["apache".to_string()], false),
            (vec!["apache".to_string()], true),
            (vec!["insider_threat".to_string()], true),
            (
                vec!["apache".to_string(), "insider_threat".to_string()],
                true,
            ),
        ] {
            let overlaps = source_types
                .iter()
                .any(|source_type| restricted.deny.contains(source_type));
            assert_eq!(
                restricted.allows(&source_types, complete),
                complete && !overlaps
            );
        }
    }
}
