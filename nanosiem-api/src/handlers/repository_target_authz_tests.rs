// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression matrix for the content-repository composite capability policy
//! (NAN-2117 / NAN-2118 / NAN-2111 / NAN-2103 / NAN-2120).
//!
//! Each finding proved that a narrow repository capability silently stood in for
//! a target-resource capability. These assert the two halves of the fix:
//!
//! 1. the *plan → required effects* mapping every import/sync/remove path shares
//!    (`RuleImportPlan::required_effects`, `ParserImportPlan::required_effects`),
//!    including the create-vs-update lifecycle branch a static `AllOf(import,
//!    create)` policy cannot express; and
//! 2. `ensure_target_effects` / `held_target_grants`, the enforcement funnel —
//!    fail-closed, identical for JWT and API-key principals.

use nanosiem_core::auth::api_key::ApiKeyInfo;
use nanosiem_core::auth::permissions;
use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
use nanosiem_core::auth::{TargetEffect, TokenClaims};
use nanosiem_core::parser_repository::ParserImportPlan;
use nanosiem_core::rule_repository::{RuleImportAction, RuleImportPlan};
use uuid::Uuid;

use super::{ensure_target_effects, held_target_grants};
use crate::error::ApiError;
use crate::middleware::AuthContext;

fn jwt_auth(values: &[&str]) -> AuthContext {
    AuthContext::from_jwt(TokenClaims {
        iss: DEFAULT_TOKEN_ISSUER.to_string(),
        aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
        sub: Uuid::now_v7(),
        roles: Vec::new(),
        permissions: values.iter().map(ToString::to_string).collect(),
        exp: chrono::Utc::now().timestamp() + 60,
        iat: chrono::Utc::now().timestamp(),
        jti: Uuid::now_v7(),
        purpose: "access".to_string(),
    })
}

fn api_key_auth(values: &[&str]) -> AuthContext {
    AuthContext::from_api_key(&ApiKeyInfo {
        id: Uuid::now_v7(),
        name: "probe".to_string(),
        permissions: values.iter().map(ToString::to_string).collect(),
        user_id: Some(Uuid::now_v7()),
    })
}

/// Both principal flavors must reach the identical decision — the findings were
/// all proven with an under-scoped API key.
fn both_principals(values: &[&str]) -> [AuthContext; 2] {
    [jwt_auth(values), api_key_auth(values)]
}

fn forbidden_message(result: Result<(), ApiError>) -> String {
    match result {
        Err(ApiError::Forbidden(message)) => message,
        Err(other) => panic!("expected Forbidden, got {other:?}"),
        Ok(()) => panic!("expected Forbidden, got Ok"),
    }
}

fn rule_plan(action: RuleImportAction, requires_promote: bool) -> RuleImportPlan {
    RuleImportPlan {
        action,
        requires_promote,
        resolved_name: "nan2029_probe".to_string(),
    }
}

// =============================================================================
// Plan → required capability mapping
// =============================================================================

mod rule_import_plan {
    use super::*;

    #[test]
    fn creating_a_detection_requires_detections_create() {
        assert_eq!(
            rule_plan(RuleImportAction::Create, false).required_effects(),
            vec![TargetEffect::DetectionCreate]
        );
    }

    #[test]
    fn rewriting_a_linked_detection_requires_detections_edit_not_create() {
        // NAN-2118: re-import of an `upstream_changed` linked rule writes
        // straight into the existing detection_rules row.
        assert_eq!(
            rule_plan(RuleImportAction::Update, false).required_effects(),
            vec![TargetEffect::DetectionEdit]
        );
    }

    #[test]
    fn non_staging_or_realtime_target_also_requires_promote() {
        assert_eq!(
            rule_plan(RuleImportAction::Create, true).required_effects(),
            vec![TargetEffect::DetectionCreate, TargetEffect::DetectionPromote]
        );
        assert_eq!(
            rule_plan(RuleImportAction::Update, true).required_effects(),
            vec![TargetEffect::DetectionEdit, TargetEffect::DetectionPromote]
        );
    }

    #[test]
    fn already_imported_and_unchanged_consumes_nothing() {
        // `import_rule` returns AlreadyImported and writes nothing, so a batch
        // containing only such items must not demand target capabilities.
        assert!(rule_plan(RuleImportAction::Skip, false)
            .required_effects()
            .is_empty());
        assert!(rule_plan(RuleImportAction::Skip, true)
            .required_effects()
            .is_empty());
    }
}

mod parser_import_plan {
    use super::*;

    fn parser_plan(creates_log_source: bool, mutates_source_config: bool) -> ParserImportPlan {
        ParserImportPlan {
            creates_log_source,
            mutates_source_config,
        }
    }

    #[test]
    fn creating_a_log_source_requires_log_sources_create() {
        assert_eq!(
            parser_plan(true, false).required_effects(),
            vec![TargetEffect::LogSourceCreate]
        );
    }

    #[test]
    fn touching_a_dispatch_source_config_also_requires_source_configs_edit() {
        // NAN-2117: holds whether the caller pinned `dispatch_source_config_id`
        // or the NAN-1270 auto-resolution picked one from `ingestion_method`.
        assert_eq!(
            parser_plan(true, true).required_effects(),
            vec![
                TargetEffect::LogSourceCreate,
                TargetEffect::SourceConfigEdit
            ]
        );
    }

    #[test]
    fn already_imported_consumes_nothing() {
        assert!(parser_plan(false, false).required_effects().is_empty());
    }
}

// =============================================================================
// Enforcement funnel
// =============================================================================

mod ensure_target_effects_matrix {
    use super::*;

    const RULE_IMPORT_CREATE: &[TargetEffect] = &[TargetEffect::DetectionCreate];
    const PARSER_IMPORT_ROUTED: &[TargetEffect] = &[
        TargetEffect::LogSourceCreate,
        TargetEffect::SourceConfigEdit,
    ];

    #[test]
    fn zero_permissions_are_denied() {
        for auth in both_principals(&[]) {
            assert_eq!(
                forbidden_message(ensure_target_effects(&auth, RULE_IMPORT_CREATE)),
                "Missing permission: detections:create"
            );
        }
    }

    #[test]
    fn an_unrelated_permission_is_denied() {
        for auth in both_principals(&[permissions::ALERTS_VIEW]) {
            assert_eq!(
                forbidden_message(ensure_target_effects(&auth, RULE_IMPORT_CREATE)),
                "Missing permission: detections:create"
            );
        }
    }

    /// The headline bug: `rule_repositories:import` alone minted detections.
    #[test]
    fn the_repository_capability_alone_is_denied() {
        for auth in both_principals(&[permissions::RULE_REPOSITORIES_IMPORT]) {
            assert_eq!(
                forbidden_message(ensure_target_effects(&auth, RULE_IMPORT_CREATE)),
                "Missing permission: detections:create"
            );
        }
        for auth in both_principals(&[permissions::PARSER_REPOSITORIES_IMPORT]) {
            assert_eq!(
                forbidden_message(ensure_target_effects(&auth, PARSER_IMPORT_ROUTED)),
                "Missing permission: log_sources:create"
            );
        }
        // NAN-2111: repository *manage* is not a delete capability either.
        for auth in both_principals(&[permissions::RULE_REPOSITORIES_MANAGE]) {
            assert_eq!(
                forbidden_message(ensure_target_effects(
                    &auth,
                    &[TargetEffect::DetectionDelete]
                )),
                "Missing permission: detections:delete"
            );
        }
        for auth in both_principals(&[permissions::PARSER_REPOSITORIES_MANAGE]) {
            assert_eq!(
                forbidden_message(ensure_target_effects(
                    &auth,
                    &[TargetEffect::LogSourceDelete]
                )),
                "Missing permission: log_sources:delete"
            );
        }
    }

    /// NAN-2117: creating the log source is allowed, wiring the source config is
    /// not — a partially-capable caller is refused before any write.
    #[test]
    fn a_partially_capable_caller_is_denied_the_missing_half() {
        for auth in both_principals(&[
            permissions::PARSER_REPOSITORIES_IMPORT,
            permissions::LOG_SOURCES_CREATE,
        ]) {
            assert!(ensure_target_effects(&auth, &[TargetEffect::LogSourceCreate]).is_ok());
            assert_eq!(
                forbidden_message(ensure_target_effects(&auth, PARSER_IMPORT_ROUTED)),
                "Missing permission: source_configs:edit"
            );
        }
    }

    /// NAN-2118: create without promote may only land in Staging.
    #[test]
    fn create_without_promote_is_denied_a_non_staging_target() {
        for auth in both_principals(&[
            permissions::RULE_REPOSITORIES_IMPORT,
            permissions::DETECTIONS_CREATE,
        ]) {
            assert!(ensure_target_effects(
                &auth,
                &rule_plan(RuleImportAction::Create, false).required_effects()
            )
            .is_ok());
            assert_eq!(
                forbidden_message(ensure_target_effects(
                    &auth,
                    &rule_plan(RuleImportAction::Create, true).required_effects()
                )),
                "Missing permission: detections:promote"
            );
        }
    }

    /// NAN-2118: create does not imply edit — a changed linked re-import is a
    /// different capability from a fresh import.
    #[test]
    fn create_without_edit_is_denied_the_update_branch() {
        for auth in both_principals(&[
            permissions::RULE_REPOSITORIES_IMPORT,
            permissions::DETECTIONS_CREATE,
        ]) {
            assert_eq!(
                forbidden_message(ensure_target_effects(
                    &auth,
                    &rule_plan(RuleImportAction::Update, false).required_effects()
                )),
                "Missing permission: detections:edit"
            );
        }
    }

    #[test]
    fn holding_every_required_capability_is_allowed() {
        for auth in both_principals(&[
            permissions::RULE_REPOSITORIES_IMPORT,
            permissions::DETECTIONS_CREATE,
            permissions::DETECTIONS_EDIT,
            permissions::DETECTIONS_PROMOTE,
        ]) {
            for plan in [
                rule_plan(RuleImportAction::Create, false),
                rule_plan(RuleImportAction::Create, true),
                rule_plan(RuleImportAction::Update, false),
                rule_plan(RuleImportAction::Update, true),
                rule_plan(RuleImportAction::Skip, true),
            ] {
                assert!(ensure_target_effects(&auth, &plan.required_effects()).is_ok());
            }
        }
        for auth in both_principals(&[
            permissions::PARSER_REPOSITORIES_IMPORT,
            permissions::LOG_SOURCES_CREATE,
            permissions::SOURCE_CONFIGS_EDIT,
        ]) {
            assert!(ensure_target_effects(&auth, PARSER_IMPORT_ROUTED).is_ok());
        }
    }

    /// An empty effect list (a fully-skipped batch) must not accidentally deny.
    #[test]
    fn no_required_effects_is_allowed() {
        for auth in both_principals(&[]) {
            assert!(ensure_target_effects(&auth, &[]).is_ok());
        }
    }

    /// NAN-2103: the diff routes leak the live object, so they need the live
    /// object's read capability on top of repository visibility.
    #[test]
    fn diff_routes_require_the_live_object_read_capability() {
        for auth in both_principals(&[permissions::RULE_REPOSITORIES_VIEW]) {
            assert_eq!(
                forbidden_message(ensure_target_effects(&auth, &[TargetEffect::DetectionView])),
                "Missing permission: detections:view"
            );
        }
        for auth in both_principals(&[permissions::PARSER_REPOSITORIES_VIEW]) {
            assert_eq!(
                forbidden_message(ensure_target_effects(&auth, &[TargetEffect::LogSourceView])),
                "Missing permission: log_sources:view"
            );
        }
        for auth in both_principals(&[
            permissions::RULE_REPOSITORIES_VIEW,
            permissions::DETECTIONS_VIEW,
        ]) {
            assert!(ensure_target_effects(&auth, &[TargetEffect::DetectionView]).is_ok());
        }
    }

    /// NAN-2120: the global match_values fixup is a live parser-routing edit.
    #[test]
    fn fixup_requires_parser_and_log_source_edit() {
        let fixup = [TargetEffect::ParserEdit, TargetEffect::LogSourceEdit];
        for auth in both_principals(&[permissions::PARSER_REPOSITORIES_MANAGE]) {
            assert_eq!(
                forbidden_message(ensure_target_effects(&auth, &fixup)),
                "Missing permission: parsers:edit"
            );
        }
        for auth in both_principals(&[
            permissions::PARSER_REPOSITORIES_MANAGE,
            permissions::PARSERS_EDIT,
        ]) {
            assert_eq!(
                forbidden_message(ensure_target_effects(&auth, &fixup)),
                "Missing permission: log_sources:edit"
            );
        }
        for auth in both_principals(&[
            permissions::PARSER_REPOSITORIES_MANAGE,
            permissions::PARSERS_EDIT,
            permissions::LOG_SOURCES_EDIT,
        ]) {
            assert!(ensure_target_effects(&auth, &fixup).is_ok());
        }
    }
}

/// NAN-2081: the import preview / coverage endpoints read live telemetry, which
/// is a separate capability from repository visibility.
///
/// NAN-2159: and it must be the SAME capability policy `GET /api/source-types`
/// applies. Preview kept the pre-NAN-2055 `search:view` gate, so it both handed
/// the all-time inventory to a principal `/api/source-types` refuses and
/// withheld it from a legitimate `search:execute` holder. The test below that
/// asserted `search:view` unlocks the view was asserting the bug — it passed
/// against the defect and fails against the fix.
mod live_inventory_gate {
    use super::*;
    use crate::handlers::rule_repositories::live_inventory_access;
    use nanosiem_api_lib::{permits_source_inventory, SOURCE_INVENTORY_CAPS};
    use nanosiem_core::auth::ScopeSet;
    use nanosiem_core::rule_repository::LiveInventoryAccess;

    #[test]
    fn repository_view_alone_does_not_unlock_live_telemetry() {
        let scope = ScopeSet::unrestricted();
        for auth in both_principals(&[permissions::RULE_REPOSITORIES_VIEW]) {
            assert!(matches!(
                live_inventory_access(&auth, &scope),
                LiveInventoryAccess::Denied
            ));
            assert!(!live_inventory_access(&auth, &scope).permits_live_data());
        }
    }

    /// The confidentiality half of NAN-2159's live repro: this exact principal
    /// receives 403 from `/api/source-types` and, before the fix, 52 source
    /// types from preview.
    #[test]
    fn search_view_is_not_a_live_inventory_capability() {
        let scope = ScopeSet::unrestricted();
        for auth in both_principals(&[
            permissions::RULE_REPOSITORIES_VIEW,
            permissions::SEARCH_VIEW,
        ]) {
            assert!(
                !live_inventory_access(&auth, &scope).permits_live_data(),
                "search:view regressed to unlocking preview inventory (NAN-2159): \
                 it is refused by /api/source-types, so preview would be an \
                 alternate route around NAN-2055"
            );
        }
    }

    /// The positive-access half: a least-privilege search executor is
    /// authorized for the canonical inventory endpoint, so preview must not
    /// refuse it.
    #[test]
    fn every_source_inventory_capability_unlocks_the_scoped_view() {
        let scope = ScopeSet::unrestricted();
        for cap in SOURCE_INVENTORY_CAPS {
            for auth in both_principals(&[permissions::RULE_REPOSITORIES_VIEW, cap]) {
                assert!(
                    matches!(
                        live_inventory_access(&auth, &scope),
                        LiveInventoryAccess::Scoped(_)
                    ),
                    "{cap} is admitted by /api/source-types but denied preview \
                     inventory — the two surfaces disagree"
                );
            }
        }
    }

    /// The invariant the two halves above are instances of. Asserted over the
    /// capability alone so a future edit to either surface's admission rule
    /// fails here rather than in production.
    #[test]
    fn preview_and_source_types_admit_exactly_the_same_principals() {
        let scope = ScopeSet::unrestricted();
        let candidates: Vec<&str> = SOURCE_INVENTORY_CAPS
            .iter()
            .copied()
            .chain([
                permissions::SEARCH_VIEW,
                permissions::RULE_REPOSITORIES_VIEW,
                permissions::RULE_REPOSITORIES_IMPORT,
                permissions::LOG_SOURCES_VIEW,
            ])
            .collect();

        for cap in candidates {
            for auth in both_principals(&[cap]) {
                assert_eq!(
                    permits_source_inventory(&auth),
                    live_inventory_access(&auth, &scope).permits_live_data(),
                    "preview and /api/source-types disagree about {cap}"
                );
            }
        }
    }

    /// Capability admission is not the confidentiality boundary — the caller's
    /// effective deny set still applies on the admitted path. `Scoped` carries
    /// the scope the handler resolved from
    /// `AuthContext::effective_source_deny_set()`; a fix that admitted the
    /// caller but dropped the scope would still leak denied sources.
    #[test]
    fn admitted_callers_still_carry_their_deny_set() {
        let scope = ScopeSet::from_denied(["windows_sysmon".to_string()].into_iter().collect());
        for auth in both_principals(&[
            permissions::RULE_REPOSITORIES_VIEW,
            permissions::SEARCH_EXECUTE,
        ]) {
            match live_inventory_access(&auth, &scope) {
                LiveInventoryAccess::Scoped(s) => assert!(
                    s.deny_set().contains("windows_sysmon"),
                    "admitted caller lost their deny set — denied sources would \
                     reappear in preview inventory"
                ),
                LiveInventoryAccess::Denied => panic!("search:execute must be admitted"),
            }
        }
    }

    #[test]
    fn zero_permissions_are_denied_live_telemetry() {
        let scope = ScopeSet::unrestricted();
        for auth in both_principals(&[]) {
            assert!(!live_inventory_access(&auth, &scope).permits_live_data());
        }
    }
}

mod held_grants {
    use super::*;

    #[test]
    fn grants_reflect_exactly_the_held_target_capabilities() {
        for auth in both_principals(&[
            permissions::RULE_REPOSITORIES_IMPORT,
            permissions::DETECTIONS_CREATE,
        ]) {
            let grants = held_target_grants(&auth);
            assert!(grants.allows(TargetEffect::DetectionCreate));
            assert!(!grants.allows(TargetEffect::DetectionEdit));
            assert!(!grants.allows(TargetEffect::DetectionPromote));
            assert!(!grants.allows(TargetEffect::LogSourceCreate));
        }
    }

    #[test]
    fn a_principal_with_no_permissions_grants_nothing() {
        for auth in both_principals(&[]) {
            let grants = held_target_grants(&auth);
            for effect in TargetEffect::ALL {
                assert!(!grants.allows(effect), "{effect:?} must not be granted");
            }
        }
    }

    /// The service re-check is what closes the create→update race: a caller who
    /// legitimately holds both still succeeds either way.
    #[test]
    fn a_fully_capable_principal_grants_both_branches() {
        for auth in both_principals(&[
            permissions::DETECTIONS_CREATE,
            permissions::DETECTIONS_EDIT,
        ]) {
            let grants = held_target_grants(&auth);
            assert!(grants.ensure(TargetEffect::DetectionCreate).is_ok());
            assert!(grants.ensure(TargetEffect::DetectionEdit).is_ok());
            assert_eq!(
                grants.ensure(TargetEffect::DetectionPromote),
                Err(TargetEffect::DetectionPromote)
            );
        }
    }
}
