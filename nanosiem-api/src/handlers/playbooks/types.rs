// SPDX-License-Identifier: AGPL-3.0-or-later

//! Handler-local DTOs for the playbooks API.

use nanosiem_core::playbooks::{
    acl::resolve_principal, Playbook, PlaybookCategory, PlaybookPrincipal, PlaybookStatus,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::middleware::AuthContext;
use crate::{error::ApiError, state::AppState};

/// Build the per-playbook ACL principal for a request (NAN-2097).
///
/// * **API key** → the single synthetic role `api_key`, which is what
///   `AuthContext::from_api_key` actually carries. A key deliberately does NOT
///   inherit its owner's roles: an API key is its own authorization principal
///   (NAN-2043), so a narrowly-scoped key cannot borrow a human's playbook
///   grants — the same reason `source_scope_principal()` resolves the key id.
/// * **Interactive session** → role IDs resolved from the DATABASE, not from
///   `claims.roles`. The claim is documented as "used for UI display, not
///   authorization decisions" and is trusted from a JWT that can be 15 minutes
///   stale, so reading it would let a revoked group membership keep its playbook
///   grants until the next token refresh. IDs rather than names, because keying
///   on a renameable label let grants be orphaned or captured. The supported
///   legacy exception is a database role already named `demo_analyst`: its
///   name-derived restrictions are preserved by mapping its members to the same
///   synthetic demo principal — see `nanosiem_core::playbooks::acl`.
/// * **Demo session** → additionally carries the synthetic `demo_analyst` role,
///   but only after `demo.sessions` is checked to confirm the session is still
///   live. Demo users hold no group role assignments, so without this an ACL'd
///   playbook could never grant them access despite `DEMO_PERMISSIONS`
///   including the playbook capabilities. `claims.roles` only decides whether
///   that probe is worth making — it never grants the role by itself.
///
/// Never returns [`PlaybookPrincipal::System`] — that variant exists only for
/// internal callers with no request principal (rule-fire auto-attach,
/// shadow-investigation compose).
pub async fn playbook_principal(
    state: &AppState,
    auth: &AuthContext,
) -> Result<PlaybookPrincipal, ApiError> {
    if auth.is_api_key {
        return Ok(PlaybookPrincipal::api_key());
    }
    resolve_principal(&state.pool, auth.user_id(), &auth.claims.roles)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to resolve caller roles: {e}")))
}

/// Response for listing playbooks (with total count for pagination).
#[derive(Debug, Serialize, ToSchema)]
pub struct ListPlaybooksResponse {
    pub playbooks: Vec<Playbook>,
    pub total: i64,
}

/// Query parameters for listing playbooks.
#[derive(Debug, Deserialize, Default, IntoParams)]
pub struct ListPlaybooksParams {
    /// Filter by category.
    pub category: Option<PlaybookCategory>,
    /// Filter by status.
    pub status: Option<PlaybookStatus>,
    /// Match playbooks whose `match_signals` contains this signal.
    pub signal: Option<String>,
    /// Free-text search across title and subtitle.
    pub search: Option<String>,
    /// Sort mode: `recent` (default) | `title` | `attached`.
    pub sort: Option<String>,
    /// Page size (default 100, max 1000).
    pub limit: Option<i64>,
    /// Offset for pagination.
    pub offset: Option<i64>,
    /// Filter to adaptive (agent-composed) playbooks.
    pub adaptive: Option<bool>,
}
