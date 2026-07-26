// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2055 / NAN-2159: the ONE capability policy for enumerating live source
//! inventory.
//!
//! Several surfaces answer the question "which `source_type`s exist in this
//! tenant's live telemetry, and how much of each?" — `GET /api/source-types`,
//! rule-import preview, and repository coverage. That is a **log-data read**,
//! not a metadata read: the answer names the tenant's data sources and their
//! exact volumes.
//!
//! NAN-2055 established the policy on `/api/source-types` and NAN-2159 found
//! that rule preview had kept the pre-NAN-2055 gate (`search:view`), which made
//! it an alternate route around the fix — the same key that `/api/source-types`
//! correctly 403s received the all-time inventory through preview, while a
//! legitimate `search:execute` holder was refused it. Two surfaces answering
//! one question must not each carry their own copy of the answer, so the policy
//! lives here and both call it.
//!
//! **The gate is admission, not confidentiality.** Every caller admitted by any
//! branch below is still filtered by their effective deny set (per-source RBAC
//! ∪ implicit `audit` without `audit:view`) at the query. Callers must apply
//! `AuthContext::effective_viewer_scope()` regardless of which capability
//! admitted them; this function does not and cannot enforce that half.
//!
//! ## Why four capabilities and not just `search:execute`
//!
//! The inventory is not only a search affordance — four separate UI surfaces
//! populate a picker from it, each reachable under a DIFFERENT capability.
//! These track the ROUTE guards in `nanosiem-web/src/App.tsx` (`PermissionRoute`),
//! **not** the capability whose name reads closest to the page:
//!
//! | consumer                             | route guard          |
//! |--------------------------------------|----------------------|
//! | `lib/query-autocomplete.ts` (search) | search pages         |
//! | `pages/AddFeed.tsx`                  | `log_sources:create` |
//! | `pages/RuleRepositories.tsx`         | `detections:view`    |
//! | `pages/Settings/SourceScopes.tsx`    | `source_scopes:view` |
//!
//! Requiring `search:execute` alone would break all three non-search pages for
//! a custom role that legitimately cannot run searches. Guessing this mapping
//! from capability names is how the first version of the NAN-2055 gate got all
//! three wrong — `RuleRepositories` is guarded by `detections:view`, not
//! `rule_repositories:view`, and `AddFeed` by `log_sources:create`, not
//! `log_sources:view`.
//!
//! Note that `rule_repositories:view` is deliberately absent: repository
//! visibility is catalog visibility and has never been a live-data capability.
//! Rule preview admits on `detections:view` — the guard on the page the preview
//! is reached from — so a principal who can open that page keeps working.

use nanosiem_core::auth::permissions;

use crate::api_error::ApiError;
use crate::auth_context::AuthContext;

/// The capabilities that admit a principal to live source-type inventory.
///
/// Adding a consumer surface means adding its ROUTE guard here, not widening a
/// caller's local check.
pub const SOURCE_INVENTORY_CAPS: [&str; 4] = [
    permissions::SEARCH_EXECUTE,
    permissions::LOG_SOURCES_CREATE,
    permissions::DETECTIONS_VIEW,
    permissions::SOURCE_SCOPES_VIEW,
];

/// Whether this principal may enumerate live source inventory at all.
///
/// Use this where inventory is one OPTIONAL half of a larger response (rule
/// preview returns its catalog half either way); use
/// [`ensure_source_inventory_access`] where inventory IS the response.
pub fn permits_source_inventory(auth: &AuthContext) -> bool {
    auth.has_any_permission(&SOURCE_INVENTORY_CAPS)
}

/// Reject a principal that may not enumerate live source inventory.
pub fn ensure_source_inventory_access(auth: &AuthContext) -> Result<(), ApiError> {
    if permits_source_inventory(auth) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(format!(
            "Requires one of: {}",
            SOURCE_INVENTORY_CAPS.join(", ")
        )))
    }
}

#[cfg(test)]
#[path = "source_inventory_tests.rs"]
mod source_inventory_tests;
