// SPDX-License-Identifier: AGPL-3.0-or-later

//! Composite target-resource capability policy for content-repository
//! pipelines (NAN-2117/2118/2111/2081/2103/2120).
//!
//! Rule-, parser- and playbook-repository import / sync / fixup / remove paths
//! do not only touch the repository catalog: they materialize, rewrite, and
//! delete **first-class tenant resources** — detection rules, log sources, source
//! configurations, parser VRL, library playbooks. Historically each handler
//! authorized only its own repository capability (`rule_repositories:import`,
//! `parser_repositories:manage`, `playbook_repositories:import`, …), so one
//! narrow catalog permission silently stood in for `detections:create`,
//! `log_sources:create`, `source_configs:edit`, `detections:delete` or
//! `playbooks:manage` (NAN-2119).
//!
//! This module is the single mapping from *"this operation will
//! create/update/delete/read a resource of kind K"* to *"these capabilities are
//! required"*. Handlers preflight the effects and refuse before any write; the
//! `nanosiem-core` services take the resulting [`TargetGrants`] and re-check at
//! the exact branch that performs the mutation, so a create→update race cannot
//! launder a missing capability (check-then-act).
//!
//! `nanosiem-core` cannot see `AuthContext` (it lives in `nanosiem-api-lib`),
//! so the enum and the grant set live here and the thin
//! `AuthContext`-to-`TargetGrants` adapters live in
//! `nanosiem-api/src/handlers/repository_target_authz.rs`.

use std::collections::BTreeSet;

use super::permissions;

/// One first-class-resource effect a content-repository operation can have.
///
/// Each variant maps to exactly the capability the *canonical* route for that
/// resource enforces (e.g. `POST /api/rules` → `detections:create`), so a
/// repository alias can never be weaker than the direct API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetEffect {
    /// Reads a live detection rule's private content (query/title/description).
    DetectionView,
    /// Creates a new detection rule.
    DetectionCreate,
    /// Rewrites an existing detection rule.
    DetectionEdit,
    /// Deletes a detection rule.
    DetectionDelete,
    /// Places a detection outside Staging or provisions real-time execution.
    DetectionPromote,
    /// Reads a live log source's private content (parser/normalize VRL).
    LogSourceView,
    /// Creates a log source.
    LogSourceCreate,
    /// Rewrites an existing log source.
    LogSourceEdit,
    /// Deletes a log source.
    LogSourceDelete,
    /// Mutates an ingestion source configuration (e.g. inserts a routing rule).
    SourceConfigEdit,
    /// Rewrites live parser content / routing metadata.
    ParserEdit,
    /// Materializes a repository playbook into the tenant playbook library
    /// (NAN-2119). `POST /api/playbooks` requires `playbooks:manage`; importing
    /// creates the same first-class rows (`playbooks` + `playbook_versions`),
    /// so the repository alias must demand the same capability.
    PlaybookCreate,
}

impl TargetEffect {
    /// The capability the canonical route for this resource+action enforces.
    pub const fn permission(self) -> &'static str {
        match self {
            TargetEffect::DetectionView => permissions::DETECTIONS_VIEW,
            TargetEffect::DetectionCreate => permissions::DETECTIONS_CREATE,
            TargetEffect::DetectionEdit => permissions::DETECTIONS_EDIT,
            TargetEffect::DetectionDelete => permissions::DETECTIONS_DELETE,
            TargetEffect::DetectionPromote => permissions::DETECTIONS_PROMOTE,
            TargetEffect::LogSourceView => permissions::LOG_SOURCES_VIEW,
            TargetEffect::LogSourceCreate => permissions::LOG_SOURCES_CREATE,
            TargetEffect::LogSourceEdit => permissions::LOG_SOURCES_EDIT,
            TargetEffect::LogSourceDelete => permissions::LOG_SOURCES_DELETE,
            TargetEffect::SourceConfigEdit => permissions::SOURCE_CONFIGS_EDIT,
            TargetEffect::ParserEdit => permissions::PARSERS_EDIT,
            TargetEffect::PlaybookCreate => permissions::PLAYBOOKS_MANAGE,
        }
    }

    /// Every effect this policy knows about. Used to snapshot which target
    /// capabilities a principal actually holds before entering a service that
    /// may branch between create and update.
    pub const ALL: [TargetEffect; 12] = [
        TargetEffect::DetectionView,
        TargetEffect::DetectionCreate,
        TargetEffect::DetectionEdit,
        TargetEffect::DetectionDelete,
        TargetEffect::DetectionPromote,
        TargetEffect::LogSourceView,
        TargetEffect::LogSourceCreate,
        TargetEffect::LogSourceEdit,
        TargetEffect::LogSourceDelete,
        TargetEffect::SourceConfigEdit,
        TargetEffect::ParserEdit,
        TargetEffect::PlaybookCreate,
    ];
}

/// The set of target effects the current principal is allowed to cause.
///
/// Constructed from an authenticated caller's permissions ([`from_effects`]),
/// or [`system`] for the internal SYSTEM callers that legitimately have no
/// principal (leader-elected schedulers, background sync jobs). Default is
/// **empty** — fail-closed: a service handed `TargetGrants::default()` can
/// mutate nothing.
///
/// [`from_effects`]: TargetGrants::from_effects
/// [`system`]: TargetGrants::system
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetGrants {
    granted: BTreeSet<TargetEffect>,
}

impl TargetGrants {
    /// No target effects allowed. Same as [`Default`]; spelled out at call
    /// sites that mean "this path must not reach a target mutation".
    pub fn none() -> Self {
        Self::default()
    }

    /// All target effects — for SYSTEM/internal callers only (schedulers,
    /// background sync). Never derive this from a request principal.
    pub fn system() -> Self {
        Self {
            granted: TargetEffect::ALL.into_iter().collect(),
        }
    }

    /// Build from the effects a principal was verified to hold.
    pub fn from_effects(effects: impl IntoIterator<Item = TargetEffect>) -> Self {
        Self {
            granted: effects.into_iter().collect(),
        }
    }

    /// True when this principal may cause `effect`.
    pub fn allows(&self, effect: TargetEffect) -> bool {
        self.granted.contains(&effect)
    }

    /// Fail-closed check used at the exact mutation branch inside services.
    /// Returns the missing effect so the caller can render the canonical
    /// `Missing permission: <capability>` message.
    pub fn ensure(&self, effect: TargetEffect) -> Result<(), TargetEffect> {
        if self.allows(effect) {
            Ok(())
        } else {
            Err(effect)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_effect_maps_to_the_canonical_route_capability() {
        assert_eq!(TargetEffect::DetectionCreate.permission(), "detections:create");
        assert_eq!(TargetEffect::DetectionEdit.permission(), "detections:edit");
        assert_eq!(TargetEffect::DetectionDelete.permission(), "detections:delete");
        assert_eq!(
            TargetEffect::DetectionPromote.permission(),
            "detections:promote"
        );
        assert_eq!(TargetEffect::DetectionView.permission(), "detections:view");
        assert_eq!(TargetEffect::LogSourceCreate.permission(), "log_sources:create");
        assert_eq!(TargetEffect::LogSourceEdit.permission(), "log_sources:edit");
        assert_eq!(TargetEffect::LogSourceDelete.permission(), "log_sources:delete");
        assert_eq!(TargetEffect::LogSourceView.permission(), "log_sources:view");
        assert_eq!(
            TargetEffect::SourceConfigEdit.permission(),
            "source_configs:edit"
        );
        assert_eq!(TargetEffect::ParserEdit.permission(), "parsers:edit");
        assert_eq!(
            TargetEffect::PlaybookCreate.permission(),
            "playbooks:manage"
        );
    }

    #[test]
    fn all_covers_every_variant_exactly_once() {
        let unique: BTreeSet<TargetEffect> = TargetEffect::ALL.into_iter().collect();
        assert_eq!(unique.len(), TargetEffect::ALL.len());
    }

    #[test]
    fn default_grants_nothing() {
        let grants = TargetGrants::default();
        for effect in TargetEffect::ALL {
            assert!(!grants.allows(effect), "{effect:?} must not be granted");
            assert_eq!(grants.ensure(effect), Err(effect));
        }
        assert_eq!(grants, TargetGrants::none());
    }

    #[test]
    fn system_grants_everything() {
        let grants = TargetGrants::system();
        for effect in TargetEffect::ALL {
            assert!(grants.allows(effect), "{effect:?} must be granted to SYSTEM");
            assert_eq!(grants.ensure(effect), Ok(()));
        }
    }

    #[test]
    fn from_effects_grants_only_the_listed_effects() {
        let grants = TargetGrants::from_effects([TargetEffect::DetectionCreate]);
        assert!(grants.allows(TargetEffect::DetectionCreate));
        assert!(!grants.allows(TargetEffect::DetectionEdit));
        assert!(!grants.allows(TargetEffect::DetectionPromote));
        assert_eq!(
            grants.ensure(TargetEffect::DetectionEdit),
            Err(TargetEffect::DetectionEdit)
        );
    }
}
