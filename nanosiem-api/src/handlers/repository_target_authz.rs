// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AuthContext` adapters for the content-repository target-capability policy
//! (NAN-2117/2118/2111/2103/2120).
//!
//! Content-repository import / sync / fixup / remove endpoints are *composite*
//! operations: they authorize the repository catalog action AND materialize,
//! rewrite or delete first-class tenant resources. Every such handler funnels
//! through the two functions here so the repository permission stays **additive**
//! and can never substitute for the target resource's own capability.
//!
//! Usage shape:
//!
//! ```ignore
//! ensure_permission(&auth, permissions::RULE_REPOSITORIES_IMPORT)?;  // catalog side
//! let plan = service.plan_import(repo_id, &path, &req).await?;       // what will it touch?
//! ensure_target_effects(&auth, &plan.required_effects())?;           // target side, before any write
//! let grants = held_target_grants(&auth);                            // re-checked inside the service
//! ```
//!
//! [`held_target_grants`] snapshots *everything* the principal holds (not just
//! the preflighted subset) so a create→update race inside the service resolves
//! against the caller's real capabilities rather than the plan's guess, while
//! still denying anything they lack.

use nanosiem_core::auth::{TargetEffect, TargetGrants};

use crate::error::ApiError;
use crate::middleware::AuthContext;

/// Enforce every target-resource capability an operation will consume.
///
/// Returns `403 Missing permission: <capability>` for the first missing effect,
/// byte-identical to what the canonical route for that resource returns, so a
/// denied repository alias is indistinguishable from a denied direct call.
pub fn ensure_target_effects(
    auth: &AuthContext,
    effects: &[TargetEffect],
) -> Result<(), ApiError> {
    for effect in effects {
        if !auth.has_permission(effect.permission()) {
            return Err(ApiError::Forbidden(format!(
                "Missing permission: {}",
                effect.permission()
            )));
        }
    }
    Ok(())
}

/// Snapshot the target effects this principal actually holds.
///
/// Handed to `nanosiem-core` services so they can re-check at the exact branch
/// that mutates — the handler preflight decides *which* effects are needed, this
/// decides *which* are available, and the service enforces the intersection at
/// write time.
pub fn held_target_grants(auth: &AuthContext) -> TargetGrants {
    TargetGrants::from_effects(
        TargetEffect::ALL
            .into_iter()
            .filter(|effect| auth.has_permission(effect.permission())),
    )
}

#[cfg(test)]
#[path = "repository_target_authz_tests.rs"]
mod tests;
