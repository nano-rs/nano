// SPDX-License-Identifier: AGPL-3.0-or-later

//! The visibility a tenant read runs under on the shared lake (NAN-2361
//! wave 8) — a pure value type, ungated so the search service and every
//! tenant view can carry it without the enterprise feature. The model
//! (group restrictions, exceptions, the DB reads / writes, the audit) lives
//! in `crate::shared_source_visibility`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ScopeSet;

/// The ONE restriction label for lake events with no declared source
/// ("Unattributed", NAN-2602). The UI and the model store it as `default`.
pub const UNATTRIBUTED_RESTRICTION_LABEL: &str = "default";

/// Every `metadata.log_source` spelling that means "no declared source".
/// Stored lake rows carry `unknown` (Vector `00-base.toml` / `02-hec-source.toml`,
/// the router catch-all and the deployed parser config stamp it), while the
/// per-source counters and the source-visibility model call the same bucket
/// `default`. They are ONE label for RBAC: denying either name denies both.
pub const UNATTRIBUTED_SOURCE_ALIASES: [&str; 2] = ["default", "unknown"];

/// Is `slug` (any case / padding) a spelling of the Unattributed label?
pub fn is_unattributed_source(slug: &str) -> bool {
    let slug = slug.trim();
    UNATTRIBUTED_SOURCE_ALIASES.iter().any(|alias| slug.eq_ignore_ascii_case(alias))
}

/// Canonical restriction key: trimmed, lowercase, and `unknown` folded onto
/// [`UNATTRIBUTED_RESTRICTION_LABEL`].
pub fn canonical_restriction_slug(slug: &str) -> String {
    if is_unattributed_source(slug) {
        UNATTRIBUTED_RESTRICTION_LABEL.to_string()
    } else {
        slug.trim().to_ascii_lowercase()
    }
}

/// Fail-closed expansion of a lake deny set (NAN-2602): the set normalized
/// (trimmed, lowercase, empties dropped) and, when it names EITHER spelling
/// of the Unattributed label, carrying BOTH. Idempotent. Every consumer that
/// turns a hosted-shared deny set into a row filter goes through this, so a
/// member restricted from `default` can never read `unknown` rows (or the
/// reverse).
pub fn expand_unattributed_sources<I>(denied: I) -> BTreeSet<String>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut out: BTreeSet<String> = denied
        .into_iter()
        .map(|slug| slug.as_ref().trim().to_ascii_lowercase())
        .filter(|slug| !slug.is_empty())
        .collect();
    if out.iter().any(|slug| is_unattributed_source(slug)) {
        out.extend(UNATTRIBUTED_SOURCE_ALIASES.iter().map(|alias| alias.to_string()));
    }
    out
}

/// Add both Unattributed spellings to a wire deny set that names either,
/// keeping every other entry exactly as sent (so a reader's own bound /
/// validation still sees the caller's values). Idempotent.
pub fn with_unattributed_aliases(mut denied: Vec<String>) -> Vec<String> {
    if denied.iter().any(|slug| is_unattributed_source(slug)) {
        for alias in UNATTRIBUTED_SOURCE_ALIASES {
            if !denied.iter().any(|slug| slug == alias) {
                denied.push(alias.to_string());
            }
        }
    }
    denied
}

/// Serde `deserialize_with` for a lake reader's wire deny set
/// (`deny_source_types`): the final read boundary re-applies the
/// Unattributed expansion so a caller that sent only `default` (or only
/// `unknown`) still gets both denied (NAN-2602, fail closed).
pub fn deserialize_lake_deny_set<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromIterator<String>,
{
    let raw = <Vec<String> as Deserialize>::deserialize(deserializer)?;
    Ok(with_unattributed_aliases(raw).into_iter().collect())
}

/// Why a read runs outside the member deny set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "name")]
pub enum UnrestrictedReason {
    /// The tenant detection runtime (scheduled / near-real-time evaluation,
    /// retro hunts, hunt recon estate probes, shadow investigation's
    /// autonomous hunting).
    DetectionRuntime,
    /// A named tenant runner (risk / prevalence / identity builders, report
    /// and export runners).
    Runner(String),
}

impl UnrestrictedReason {
    pub fn label(&self) -> String {
        match self {
            Self::DetectionRuntime => "detection_runtime".to_string(),
            Self::Runner(name) => format!("runner:{name}"),
        }
    }
}

/// The visibility a tenant read runs under. Threaded explicitly through the
/// tenant search view so a bypass is a decision, never an accident of a
/// missing user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceVisibility {
    /// A member (or automation key): exactly its effective deny set. An
    /// empty set is "everything visible".
    Member { denied: BTreeSet<String> },
    /// The tenant system / worker member or a runner reading the full lake.
    Unrestricted { reason: UnrestrictedReason },
    /// A case participant reading a case's attached evidence: the member's
    /// own deny set still applies to everything EXCEPT the rows the case's
    /// evidence ledger names by `metadata.uid`.
    CaseScoped {
        case_id: Uuid,
        member_denied: BTreeSet<String>,
        evidence_uids: BTreeSet<String>,
    },
}

impl SourceVisibility {
    /// A member read. The deny set is expanded over the Unattributed
    /// aliases ([`expand_unattributed_sources`]) so `default` and `unknown`
    /// are always denied together (NAN-2602).
    pub fn member(denied: BTreeSet<String>) -> Self {
        Self::Member { denied: expand_unattributed_sources(denied) }
    }
    pub fn detection_runtime() -> Self {
        Self::Unrestricted { reason: UnrestrictedReason::DetectionRuntime }
    }
    pub fn runner(name: impl Into<String>) -> Self {
        Self::Unrestricted { reason: UnrestrictedReason::Runner(name.into()) }
    }

    /// The deny set the row filter carries (empty for an unrestricted read).
    pub fn deny_set(&self) -> &BTreeSet<String> {
        static EMPTY: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
        match self {
            Self::Member { denied } => denied,
            Self::Unrestricted { .. } => EMPTY.get_or_init(BTreeSet::new),
            Self::CaseScoped { member_denied, .. } => member_denied,
        }
    }

    /// The case evidence allow-list, if this is a case-scoped read.
    pub fn evidence(&self) -> Option<&BTreeSet<String>> {
        match self {
            Self::CaseScoped { evidence_uids, .. } => Some(evidence_uids),
            _ => None,
        }
    }

    /// The legacy [`ScopeSet`] every existing search surface takes. A
    /// case-scoped read collapses to its member deny set here; the evidence
    /// re-admission only exists through [`Self::enforce_lake_query`].
    pub fn scope_set(&self) -> ScopeSet {
        ScopeSet::from_denied(self.deny_set().clone())
    }

    /// `Some(label)` when this read runs outside the member deny set:
    /// `detection_runtime`, `runner:<name>` or `case:<id>`.
    pub fn bypass_label(&self) -> Option<String> {
        match self {
            Self::Member { .. } => None,
            Self::Unrestricted { reason } => Some(reason.label()),
            Self::CaseScoped { case_id, .. } => Some(format!("case:{case_id}")),
        }
    }

    /// Inject this visibility into a lake logs nPL query as the ONE row
    /// filter on `metadata.log_source` (plus the evidence re-admission for a
    /// case-scoped read). An unrestricted read returns the text unchanged.
    pub fn enforce_lake_query(&self, query: &str) -> std::result::Result<String, crate::SearchError> {
        use crate::search::query_processing::{
            enforce_source_visibility_with_field, LAKE_EVENT_UID_FIELD,
        };
        let evidence = self.evidence().map(|ids| (LAKE_EVENT_UID_FIELD, ids));
        enforce_source_visibility_with_field(query, self.deny_set(), evidence, "metadata.log_source")
    }

    /// Is a native OTLP dataset hidden from this read?
    pub fn otlp_dataset_denied(&self, dataset: &str) -> bool {
        crate::search::query_processing::otlp_dataset_denied(dataset, self.deny_set())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unattributed_spellings_expand_to_both_and_nothing_else_changes() {
        assert_eq!(expand_unattributed_sources(set(&["default"])), set(&["default", "unknown"]));
        assert_eq!(expand_unattributed_sources(set(&["unknown"])), set(&["default", "unknown"]));
        assert_eq!(expand_unattributed_sources(set(&[" UNKNOWN ", "hec_windows"])), set(&["default", "hec_windows", "unknown"]));
        assert_eq!(expand_unattributed_sources(set(&["hec_windows", ""])), set(&["hec_windows"]));
        assert!(expand_unattributed_sources(BTreeSet::<String>::new()).is_empty());
        // Idempotent.
        let once = expand_unattributed_sources(set(&["default"]));
        assert_eq!(expand_unattributed_sources(&once), once);
        // `default_feed` / `unknown_app` are ordinary slugs, not the label.
        assert_eq!(expand_unattributed_sources(set(&["default_feed", "unknown_app"])), set(&["default_feed", "unknown_app"]));
        assert_eq!(canonical_restriction_slug(" Unknown"), "default");
        assert_eq!(canonical_restriction_slug("DEFAULT"), "default");
        assert_eq!(canonical_restriction_slug("HEC_Windows"), "hec_windows");
    }

    #[test]
    fn wire_deny_sets_gain_both_spellings_without_losing_raw_entries() {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default, deserialize_with = "deserialize_lake_deny_set")]
            set: BTreeSet<String>,
            #[serde(default, deserialize_with = "deserialize_lake_deny_set")]
            list: Vec<String>,
        }
        let wire: Wire = serde_json::from_str(r#"{"set":["default"],"list":["unknown","apache"]}"#).unwrap();
        assert_eq!(wire.set, set(&["default", "unknown"]));
        assert_eq!(wire.list, vec!["unknown", "apache", "default"]);
        // Raw entries are kept verbatim so the reader's own bound checks see them.
        let wire: Wire = serde_json::from_str(r#"{"set":[""],"list":[]}"#).unwrap();
        assert_eq!(wire.set, set(&[""]));
        let wire: Wire = serde_json::from_str("{}").unwrap();
        assert!(wire.set.is_empty() && wire.list.is_empty());
    }

    #[test]
    fn member_visibility_denies_both_spellings() {
        let member = SourceVisibility::member(set(&["default"]));
        assert_eq!(member.deny_set(), &set(&["default", "unknown"]));
        assert!(member.scope_set().deny_set().contains("unknown"));
        assert!(SourceVisibility::member(BTreeSet::new()).deny_set().is_empty());
    }
}
