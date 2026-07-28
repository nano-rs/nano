// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2121: privilege-grant authority.
//!
//! The access-control write capabilities (`users:create`/`users:edit`,
//! `groups:create`/`groups:edit`, `roles:create`/`roles:edit`) authorize
//! mutating a user/group/role *object* — they are NOT authority to grant the
//! *effective privileges* encoded by the groups, roles, or permissions being
//! assigned. Without an additional check, a principal holding only a narrow
//! object capability can assign the built-in Admin role (or an Admin-bearing
//! group, or an arbitrary permission set) and escalate to full administrator.
//!
//! The invariant enforced here (issue requirement #1): **a caller may not grant
//! any effective permission they do not currently hold.** Validation returns an
//! authoritative database generation that the writer locks and verifies in the
//! same transaction as the mutation, so denied or concurrently-stale grants
//! produce no partial mutation. This closes the escalation: Admin's permission
//! set is a superset of any non-admin's, so only an admin can grant Admin.
//!
//! Deferred hardening (tracked on NAN-2121, not required to close the
//! escalation): an explicit privileged-admin boundary for high-impact meta
//! permissions even when held (#2), and session/permission-cache invalidation
//! on membership/role changes (#9).

use std::collections::{BTreeMap, BTreeSet};

use axum::http::StatusCode;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use nanosiem_core::auth::permissions::DEMO_PERMISSIONS;
use nanosiem_core::auth::types::builtin_groups;
use nanosiem_core::auth::GrantAuthorityStamp;

use crate::auth_context::AuthContext;

/// The magic role name `PermissionResolver::resolve_with_roles` keys on to
/// inject the hard-coded `DEMO_PERMISSIONS` set (exact match, mirroring the
/// resolver). A role carrying this name confers those permissions by NAME at
/// auth-resolution time, independent of its stored `role_permissions`.
const DEMO_ROLE_NAME: &str = "demo_analyst";

/// The effective permissions a role could confer to its bearer at auth-resolution
/// time. For a role literally named `demo_analyst` the assignee may receive
/// EITHER set depending on token timing, so the grant check requires the caller
/// to hold their UNION (fail-closed):
/// - a FRESH token whose `claims.roles` carries the name short-circuits
///   `resolve_with_roles`, which RETURNS `DEMO_PERMISSIONS`; but
/// - a STALE token whose `claims.roles` predates the name falls through to the
///   DB permission query and receives the role's STORED `role_permissions`.
/// Modelling only one of the two would let a caller escalate an existing user via
/// the other path, so we union both (`NAN-2121`). For any ordinary role the
/// effective set is exactly its stored permissions.
fn effective_role_permissions(role_name: &str, stored: Vec<String>) -> BTreeSet<String> {
    let mut perms: BTreeSet<String> = stored.into_iter().collect();
    if role_name == DEMO_ROLE_NAME {
        perms.extend(DEMO_PERMISSIONS.iter().map(|s| s.to_string()));
    }
    perms
}

/// Normalize a `source_type` for comparison — trim + lowercase, matching
/// `SourceScopeResolver::normalize_source_type`. The caller's deny set (from
/// `denied_sources`) is already normalized this way, so a group's raw grant
/// values must be normalized before intersecting.
fn normalize_source_type(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// Upper bound on the number of distinct role/group ids validated in one grant
/// request. The id arrays are caller-supplied and each id drives several DB
/// lookups, so this caps the per-request amplification; a realistic membership
/// mutation is far below this.
const MAX_GRANT_IDS: usize = 256;

/// Deduplicate the caller-supplied id list (a BTreeSet also gives a stable
/// order) and reject it if the distinct count exceeds [`MAX_GRANT_IDS`].
fn dedup_capped(ids: &[Uuid]) -> Result<BTreeSet<Uuid>, GrantErr> {
    let set: BTreeSet<Uuid> = ids.iter().copied().collect();
    if set.len() > MAX_GRANT_IDS {
        return Err(GrantErr::too_many());
    }
    Ok(set)
}

/// A privilege-grant failure, carried as `(status, code, message)` so each
/// access-control handler can map it onto its own error type
/// (`RoleApiError` / `GroupApiError` / `UserApiError`), e.g.
/// `.map_err(|g| (g.status, Json(RoleApiError::new(g.code, &g.message))))?`.
#[derive(Debug)]
pub struct GrantErr {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl GrantErr {
    fn denied(missing: &[String]) -> Self {
        GrantErr {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: format!(
                "You cannot grant permission(s) you do not hold: {}",
                missing.join(", ")
            ),
        }
    }

    /// Deny a group assignment that would grant broader per-source DATA
    /// visibility than the caller holds (NAN-2121 P1). Deliberately generic —
    /// it does NOT name the offending `source_type`, so a source-restricted
    /// caller cannot use this endpoint as an existence oracle for restricted
    /// sources they are denied.
    fn denied_source_scope() -> Self {
        GrantErr {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: "You cannot assign a group whose source-visibility scope \
                      exceeds your own."
                .to_string(),
        }
    }

    /// A repository/database failure. The underlying error is logged
    /// server-side but NOT returned to the client — serializing the raw sqlx/
    /// repo error would leak schema, constraint, or connection details.
    fn repo(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "privilege-grant validation: repository error");
        GrantErr {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "Internal error validating privileges".to_string(),
        }
    }

    /// Reject a request whose (deduplicated) id set exceeds [`MAX_GRANT_IDS`],
    /// bounding the per-request database work — the id arrays are caller-supplied,
    /// so an unbounded list would amplify one request into thousands of lookups.
    fn too_many() -> Self {
        GrantErr {
            status: StatusCode::BAD_REQUEST,
            code: "too_many_ids",
            message: format!("Too many ids in one request (max {MAX_GRANT_IDS})"),
        }
    }

    /// Reject a grant that references a role that does not exist (400) rather
    /// than treating its absent permissions as a harmless empty set. Without
    /// this, a nonexistent role id passes the subset check and then partially
    /// mutates access-control state on the downstream FK failure (NAN-2121).
    fn unknown_role(id: Uuid) -> Self {
        GrantErr {
            status: StatusCode::BAD_REQUEST,
            code: "unknown_role",
            message: format!("Unknown role id: {id}"),
        }
    }

    /// Reject a grant that references a group that does not exist (400), for the
    /// same partial-mutation reason as [`Self::unknown_role`].
    fn unknown_group(id: Uuid) -> Self {
        GrantErr {
            status: StatusCode::BAD_REQUEST,
            code: "unknown_group",
            message: format!("Unknown group id: {id}"),
        }
    }
}

struct AuthoritySnapshot<'a> {
    tx: Transaction<'a, Postgres>,
    permissions: BTreeSet<String>,
    denied_sources: BTreeSet<String>,
    stamp: GrantAuthorityStamp,
}

impl AuthoritySnapshot<'_> {
    async fn commit(self) -> Result<GrantAuthorityStamp, GrantErr> {
        let stamp = self.stamp;
        self.tx.commit().await.map_err(GrantErr::repo)?;
        Ok(stamp)
    }
}

/// Resolve a principal's current permissions and source scope from PostgreSQL
/// in one repeatable-read snapshot. Tokens and resolver caches remain the cheap
/// outer request gate; persisted privilege grants use this authoritative view.
async fn authority_snapshot<'a>(
    pool: &'a PgPool,
    auth: &AuthContext,
) -> Result<AuthoritySnapshot<'a>, GrantErr> {
    let mut tx = pool.begin().await.map_err(GrantErr::repo)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .map_err(GrantErr::repo)?;

    let version: i64 =
        sqlx::query_scalar("SELECT version FROM grant_authority_version WHERE singleton = TRUE")
            .fetch_one(&mut *tx)
            .await
            .map_err(GrantErr::repo)?;

    let permissions: Vec<String> = if let Some(api_key_id) = auth.api_key_id {
        sqlx::query_scalar(
            r#"
            SELECT unnest(ak.permissions)
              FROM api_keys ak
              JOIN users owner ON owner.id = ak.created_by
             WHERE ak.id = $1
               AND ak.enabled
               AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
               AND owner.status = 'active'
            "#,
        )
        .bind(api_key_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(GrantErr::repo)?
    } else {
        sqlx::query_scalar(
            r#"
            SELECT DISTINCT rp.permission_id
              FROM users u
              JOIN user_groups ug ON ug.user_id = u.id
              JOIN group_roles gr ON gr.group_id = ug.group_id
              JOIN role_permissions rp ON rp.role_id = gr.role_id
             WHERE u.id = $1
               AND u.status = 'active'
            "#,
        )
        .bind(auth.user_id())
        .fetch_all(&mut *tx)
        .await
        .map_err(GrantErr::repo)?
    };
    let permissions: BTreeSet<String> = permissions.into_iter().collect();

    let denied_sources =
        if permissions.contains(nanosiem_core::auth::permissions::SOURCE_SCOPES_VIEW_ALL) {
            BTreeSet::new()
        } else {
            sqlx::query_scalar::<_, String>(
                r#"
            SELECT rst.source_type
              FROM restricted_source_types rst
             WHERE NOT EXISTS (
                   SELECT 1
                     FROM source_type_grants stg
                     JOIN user_groups ug ON ug.group_id = stg.group_id
                    WHERE stg.source_type = rst.source_type
                      AND ug.user_id = $1
             )
            "#,
            )
            .bind(auth.source_scope_principal())
            .fetch_all(&mut *tx)
            .await
            .map_err(GrantErr::repo)?
            .into_iter()
            .map(|source| normalize_source_type(&source))
            .collect()
        };

    Ok(AuthoritySnapshot {
        tx,
        permissions,
        denied_sources,
        stamp: GrantAuthorityStamp::new(version),
    })
}

fn ensure_holds_current(
    held: &BTreeSet<String>,
    granted: &BTreeSet<String>,
) -> Result<(), GrantErr> {
    let missing: Vec<String> = granted
        .iter()
        .filter(|permission| !held.contains(*permission))
        .cloned()
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(GrantErr::denied(&missing))
    }
}

fn ensure_holds_source_scope_current(
    denied_sources: &BTreeSet<String>,
    granted_sources: &BTreeSet<String>,
) -> Result<(), GrantErr> {
    if granted_sources
        .iter()
        .any(|source| denied_sources.contains(source))
    {
        Err(GrantErr::denied_source_scope())
    } else {
        Ok(())
    }
}

/// Permissions in `granted` the caller does NOT hold (pure).
#[cfg(test)]
fn missing_grants(auth: &AuthContext, granted: &BTreeSet<String>) -> Vec<String> {
    granted
        .iter()
        .filter(|perm| !auth.has_permission(perm))
        .cloned()
        .collect()
}

/// Fail-closed if the caller doesn't hold every permission in `granted`.
#[cfg(test)]
fn ensure_holds(auth: &AuthContext, granted: &BTreeSet<String>) -> Result<(), GrantErr> {
    let missing = missing_grants(auth, granted);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(GrantErr::denied(&missing))
    }
}

/// NAN-2121: the caller may assign `role_ids` only if it holds every permission
/// those roles confer. Each role is loaded (validating it exists — a nonexistent
/// id is rejected 400, not passed as an empty set) and its EFFECTIVE permissions
/// — stored plus name-derived `DEMO_PERMISSIONS` — are checked.
pub async fn ensure_can_grant_roles(
    auth: &AuthContext,
    pool: &PgPool,
    required_permission: &str,
    role_ids: &[Uuid],
) -> Result<GrantAuthorityStamp, GrantErr> {
    let mut snapshot = authority_snapshot(pool, auth).await?;
    ensure_holds_current(
        &snapshot.permissions,
        &BTreeSet::from([required_permission.to_string()]),
    )?;
    let role_ids = dedup_capped(role_ids)?;
    let mut granted = BTreeSet::new();
    for role_id in &role_ids {
        let role_name: Option<String> = sqlx::query_scalar("SELECT name FROM roles WHERE id = $1")
            .bind(role_id)
            .fetch_optional(&mut *snapshot.tx)
            .await
            .map_err(GrantErr::repo)?;
        let Some(role_name) = role_name else {
            return Err(GrantErr::unknown_role(*role_id));
        };
        let stored: Vec<String> =
            sqlx::query_scalar("SELECT permission_id FROM role_permissions WHERE role_id = $1")
                .bind(role_id)
                .fetch_all(&mut *snapshot.tx)
                .await
                .map_err(GrantErr::repo)?;
        granted.extend(effective_role_permissions(&role_name, stored));
    }
    ensure_holds_current(&snapshot.permissions, &granted)?;
    snapshot.commit().await
}

/// Fail-closed if any group-conferred `source_type` (normalized) is in the
/// caller's own per-source deny set — i.e. the caller would grant DATA
/// visibility it does not itself hold. `denied_sources` carries SOURCE scope
/// only (the `audit` gate is not a group-grantable `source_type`), so it is
/// compared RAW, without the `audit:view` augmentation.
#[cfg(test)]
fn ensure_holds_source_scope(
    auth: &AuthContext,
    granted_sources: &BTreeSet<String>,
) -> Result<(), GrantErr> {
    let denied = auth.denied_sources.deny_set();
    if granted_sources.iter().any(|s| denied.contains(s)) {
        Err(GrantErr::denied_source_scope())
    } else {
        Ok(())
    }
}

/// NAN-2121: the caller may assign `group_ids` only if it holds every effective
/// entitlement those groups confer to the target account. A group confers TWO
/// kinds of entitlement, BOTH checked here:
///
/// 1. **Role permissions** (group → roles → permissions) — else the caller could
///    mint an Admin-bearing group member.
/// 2. **Per-source DATA visibility** (`source_type_grants`, NAN-1797) — a group
///    grant un-restricts an otherwise-hidden `source_type` for its members, so a
///    source-scoped caller must not place an account in a group that can see a
///    source the caller itself is denied.
///
/// This entry point validates USER-MEMBERSHIP grants, where the built-in
/// `Everyone` group is an IMPLICIT FLOOR rather than a grantable entitlement
/// (NAN-2223), and is therefore EXCLUDED from validation — see
/// [`strip_implicit_everyone`]. Every explicitly-named group is still checked in
/// full. For grants that do not confer Everyone membership at all (e.g. OIDC
/// claim→group mappings), use [`ensure_can_grant_groups_exact`].
pub async fn ensure_can_grant_groups(
    auth: &AuthContext,
    pool: &PgPool,
    required_permission: &str,
    group_ids: &[Uuid],
) -> Result<GrantAuthorityStamp, GrantErr> {
    let explicit = strip_implicit_everyone(group_ids);
    ensure_can_grant_groups_exact(auth, pool, required_permission, &explicit).await
}

/// Drop the built-in `Everyone` group from a USER-MEMBERSHIP grant before it is
/// validated (NAN-2223).
///
/// Everyone is not a privilege the caller *chooses* to confer: a post-insert DB
/// trigger (`trigger_add_user_to_everyone`) joins every new account to it,
/// `set_user_groups` refuses to remove it (`DELETE ... WHERE group_id !=
/// EVERYONE_ID`), and `remove_user_from_group` rejects it outright. Account
/// existence and Everyone membership are the same fact, so a caller authorized to
/// create/edit the account (checked separately as `required_permission`) has no
/// reachable request shape that omits the baseline. Requiring the caller to
/// additionally "hold" that baseline therefore blocks nothing an attacker could
/// otherwise do — it only denies the operation outright.
///
/// And it denied it often. Everyone is permanently bound to the seeded
/// ReadOnly role (21 permissions), and an API key's grant authority is exclusively
/// its frozen `api_keys.permissions` array — never its owner's roles — so a
/// least-privilege provisioning key such as `["users:create","users:view"]` failed
/// the subset check permanently, as did any full-privilege key minted before
/// ReadOnly last grew. The observable symptom was a 403 enumerating all 21
/// permissions on `POST /api/users`, `PUT /api/users/{id}` (with `group_ids`),
/// `PUT /api/users/{id}/groups`, and OIDC provider create/update/enable — the last
/// of which turned a routine client-secret rotation into a 21-permission demand.
///
/// **The exemption cannot be widened into an escalation.** It is keyed on one
/// hard-coded UUID, so every other group id — including any group that happens to
/// carry the ReadOnly role — is still validated in full. Nor can the baseline
/// itself be inflated first: `Everyone`'s role set is immutable through the API
/// (`set_group_roles` / `set_group_roles_authorized` both reject `EVERYONE_ID`
/// with `CannotModifySystemGroup`, and no other write path touches `group_roles`
/// for an existing group), and ReadOnly's permission set is likewise immutable
/// (`update_role_inner` and `set_role_permissions` reject `READONLY_ID` with
/// `CannotModifySystemRole`). Everyone's per-source `source_type_grants` CAN be
/// changed, but only by a caller who already holds `source_scopes:manage` AND is
/// not itself denied that source — and such a grant makes the source visible to
/// every existing account by definition, so it confers nothing on the grantee that
/// creating one more account could add.
///
/// What remains is the honest residual: a principal holding `users:create` can
/// obtain a session carrying the tenant-wide baseline, by creating an account and
/// signing in as it. That is inherent in the authority to create accounts — the
/// pre-NAN-2223 check did not prevent it either, it merely required the caller to
/// already hold the baseline — and it is bounded by the baseline being, by
/// construction, what the tenant grants everyone.
fn strip_implicit_everyone(group_ids: &[Uuid]) -> Vec<Uuid> {
    group_ids
        .iter()
        .copied()
        .filter(|id| *id != builtin_groups::EVERYONE_ID)
        .collect()
}

/// Validate the caller can grant EXACTLY the given groups. Use this where the
/// grant does not itself confer Everyone membership: OIDC claim→group mappings map
/// a claim to the listed local groups, and clearing the mapping (`group_ids = []`)
/// grants nothing and must stay possible. JIT provisioning's unavoidable Everyone
/// baseline is an implicit floor, not a grant — see [`strip_implicit_everyone`].
///
/// Callers that DO confer Everyone membership go through
/// [`ensure_can_grant_groups`], which strips the baseline first; this entry point
/// validates whatever it is handed verbatim.
pub async fn ensure_can_grant_groups_exact(
    auth: &AuthContext,
    pool: &PgPool,
    required_permission: &str,
    group_ids: &[Uuid],
) -> Result<GrantAuthorityStamp, GrantErr> {
    let mut snapshot = authority_snapshot(pool, auth).await?;
    ensure_holds_current(
        &snapshot.permissions,
        &BTreeSet::from([required_permission.to_string()]),
    )?;
    let group_ids = dedup_capped(group_ids)?;
    // First pass: resolve the group→role edges into a set of DISTINCT roles (by
    // id) and the union of source grants. Deduplicating roles globally means a
    // role shared across many groups is fetched ONCE, not per (group, role) edge
    // — otherwise 256 groups × 256 roles would fan out to ~65k permission
    // queries from one caller-controlled request (DB exhaustion).
    let mut distinct_roles: BTreeMap<Uuid, String> = BTreeMap::new();
    let mut granted_sources = BTreeSet::new();
    for group_id in &group_ids {
        // Validate the group exists — reject a nonexistent id (400) rather than
        // treating its absent entitlements as harmless and then partially
        // mutating membership state on the downstream FK failure.
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM groups WHERE id = $1)")
            .bind(group_id)
            .fetch_one(&mut *snapshot.tx)
            .await
            .map_err(GrantErr::repo)?;
        if !exists {
            return Err(GrantErr::unknown_group(*group_id));
        }

        let roles: Vec<(Uuid, String)> = sqlx::query_as(
            r#"
            SELECT r.id, r.name
              FROM roles r
              JOIN group_roles gr ON gr.role_id = r.id
             WHERE gr.group_id = $1
            "#,
        )
        .bind(group_id)
        .fetch_all(&mut *snapshot.tx)
        .await
        .map_err(GrantErr::repo)?;
        for (role_id, role_name) in roles {
            distinct_roles.entry(role_id).or_insert(role_name);
        }
        let sources: Vec<String> =
            sqlx::query_scalar("SELECT source_type FROM source_type_grants WHERE group_id = $1")
                .bind(group_id)
                .fetch_all(&mut *snapshot.tx)
                .await
                .map_err(GrantErr::repo)?;
        for source_type in sources {
            granted_sources.insert(normalize_source_type(&source_type));
        }
    }

    // Cap the EXPANDED distinct-role count too (a few groups can still carry many
    // roles), then fetch each distinct role's permissions exactly once.
    if distinct_roles.len() > MAX_GRANT_IDS {
        return Err(GrantErr::too_many());
    }
    let mut granted_perms = BTreeSet::new();
    for (role_id, role_name) in &distinct_roles {
        let stored: Vec<String> =
            sqlx::query_scalar("SELECT permission_id FROM role_permissions WHERE role_id = $1")
                .bind(role_id)
                .fetch_all(&mut *snapshot.tx)
                .await
                .map_err(GrantErr::repo)?;
        granted_perms.extend(effective_role_permissions(role_name, stored));
    }

    ensure_holds_current(&snapshot.permissions, &granted_perms)?;
    ensure_holds_source_scope_current(&snapshot.denied_sources, &granted_sources)?;
    snapshot.commit().await
}

/// NAN-2121: the caller may assign the named permissions only if it holds each
/// of them (used by role create/update, which take permission names directly).
pub async fn ensure_can_grant_permissions(
    auth: &AuthContext,
    pool: &PgPool,
    required_permission: &str,
    permission_names: &[String],
) -> Result<GrantAuthorityStamp, GrantErr> {
    let snapshot = authority_snapshot(pool, auth).await?;
    let granted: BTreeSet<String> = permission_names.iter().cloned().collect();
    ensure_holds_current(
        &snapshot.permissions,
        &BTreeSet::from([required_permission.to_string()]),
    )?;
    ensure_holds_current(&snapshot.permissions, &granted)?;
    snapshot.commit().await
}

/// Authoritatively validate a source-scope mutation against current PostgreSQL
/// state, bypassing the short-lived resolver cache used for ordinary reads.
pub async fn ensure_can_mutate_source(
    auth: &AuthContext,
    pool: &PgPool,
    source_type: &str,
) -> Result<GrantAuthorityStamp, GrantErr> {
    let snapshot = authority_snapshot(pool, auth).await?;
    ensure_holds_current(
        &snapshot.permissions,
        &BTreeSet::from([nanosiem_core::auth::permissions::SOURCE_SCOPES_MANAGE.to_string()]),
    )?;
    ensure_holds_source_scope_current(
        &snapshot.denied_sources,
        &BTreeSet::from([normalize_source_type(source_type)]),
    )?;
    snapshot.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::TokenClaims;

    fn auth_with(perms: &[&str]) -> AuthContext {
        let claims = TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: vec![],
            permissions: perms.iter().map(|s| s.to_string()).collect(),
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        };
        AuthContext::from_jwt(claims)
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn grant_of_held_subset_is_allowed() {
        let auth = auth_with(&["users:edit", "search:view", "cases:view"]);
        assert!(ensure_holds(&auth, &set(&["search:view", "cases:view"])).is_ok());
        assert!(ensure_holds(&auth, &set(&[])).is_ok());
    }

    #[test]
    fn grant_of_unheld_permission_is_denied_403() {
        // The escalation case: a narrow key cannot grant permissions (e.g. the
        // Admin-bearing set) it does not itself hold.
        let auth = auth_with(&["users:create"]);
        let err = ensure_holds(
            &auth,
            &set(&["users:create", "settings:system", "users:delete"]),
        )
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert!(err.message.contains("settings:system"));
        assert!(err.message.contains("users:delete"));
        assert!(!err.message.contains("users:create")); // held → not listed
    }

    #[test]
    fn zero_permission_caller_cannot_grant_anything() {
        let auth = auth_with(&[]);
        assert!(ensure_holds(&auth, &set(&["search:view"])).is_err());
        assert!(ensure_holds(&auth, &set(&[])).is_ok()); // empty grant is vacuous
    }

    #[test]
    fn grant_permissions_by_name_checks_each() {
        let auth = auth_with(&["roles:create", "search:view"]);
        assert!(ensure_holds(&auth, &set(&["search:view"])).is_ok());
        assert!(ensure_holds(&auth, &set(&["settings:system"])).is_err());
    }

    fn auth_with_denied_sources(denied: &[&str]) -> AuthContext {
        let mut auth = auth_with(&[]);
        auth.denied_sources = nanosiem_core::auth::ScopeSet::from_denied(set(denied));
        auth
    }

    #[test]
    fn source_type_is_normalized_for_comparison() {
        assert_eq!(normalize_source_type("  Insider_Threat "), "insider_threat");
        assert_eq!(normalize_source_type("audit"), "audit");
    }

    #[test]
    fn granting_a_source_the_caller_is_denied_is_rejected() {
        // A source-restricted caller cannot assign a group whose source_type
        // grants include a source the caller itself is denied (NAN-2121 P1 #2).
        let auth = auth_with_denied_sources(&["insider_threat"]);
        let err = ensure_holds_source_scope(&auth, &set(&["insider_threat"])).unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        // Generic message — must NOT leak the specific restricted source name.
        assert!(!err.message.contains("insider_threat"));
    }

    #[test]
    fn granting_a_source_the_caller_can_see_is_allowed() {
        // The group grants a source outside the caller's deny set → allowed.
        let auth = auth_with_denied_sources(&["insider_threat"]);
        assert!(ensure_holds_source_scope(&auth, &set(&["web_proxy"])).is_ok());
        // Empty grant set is vacuously fine.
        assert!(ensure_holds_source_scope(&auth, &set(&[])).is_ok());
    }

    #[test]
    fn unrestricted_caller_can_grant_any_source_scope() {
        // A caller with an empty deny set (unrestricted / source_scopes:view_all,
        // resolved upstream) is never blocked by the source-scope check.
        let auth = auth_with_denied_sources(&[]);
        assert!(ensure_holds_source_scope(&auth, &set(&["insider_threat", "web_proxy"])).is_ok());
    }

    #[test]
    fn demo_named_role_confers_union_of_stored_and_demo() {
        // Fail-closed: a `demo_analyst` role's assignee may receive DEMO_PERMISSIONS
        // (fresh token, resolver short-circuit) OR its stored role_permissions
        // (stale token, DB fall-through), so the grant check requires the UNION.
        // A stored permission the caller lacks must therefore still be checked.
        let eff = effective_role_permissions("demo_analyst", vec!["settings:system".to_string()]);
        assert!(
            eff.contains("settings:system"),
            "stored perms must be unioned in (reachable via the stale-token path)"
        );
        assert!(
            eff.contains(DEMO_PERMISSIONS[0]),
            "DEMO_PERMISSIONS must be unioned in too"
        );
    }

    #[test]
    fn dedup_capped_dedups_and_rejects_oversized() {
        // Duplicates collapse; distinct count stays under the cap → ok.
        let ids = vec![Uuid::nil(), Uuid::nil(), Uuid::from_u128(2)];
        assert_eq!(dedup_capped(&ids).unwrap().len(), 2);
        // Over the cap → 400 (bounds request-controlled DB amplification).
        let many: Vec<Uuid> = (0..=(MAX_GRANT_IDS as u128)).map(Uuid::from_u128).collect();
        let err = dedup_capped(&many).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    /// NAN-2223: the membership entry point must not validate the built-in
    /// Everyone baseline — it is conferred by a DB trigger on every account and
    /// cannot be declined, so it is a floor, not a grant.
    #[test]
    fn implicit_everyone_is_not_validated_as_a_grant() {
        // Empty request (create_user with no groups, OIDC JIT) stays empty
        // rather than becoming a one-element `[Everyone]` validation.
        assert!(strip_implicit_everyone(&[]).is_empty());
        // Naming Everyone explicitly is equivalent to omitting it: membership is
        // unconditional either way, so the request shapes must not diverge.
        assert!(strip_implicit_everyone(&[builtin_groups::EVERYONE_ID]).is_empty());
    }

    /// The exemption is keyed on exactly one hard-coded id. Naming Everyone must
    /// not launder any OTHER group past the hold-to-grant check (NAN-2121).
    #[test]
    fn stripping_everyone_preserves_every_other_group() {
        let other = Uuid::from_u128(0xfeed);
        let another = Uuid::from_u128(0xbeef);
        assert_eq!(
            strip_implicit_everyone(&[other, builtin_groups::EVERYONE_ID, another]),
            vec![other, another],
        );
        // Order is preserved and nothing but Everyone is removed.
        assert_eq!(strip_implicit_everyone(&[other]), vec![other]);
    }

    #[test]
    fn ordinary_role_confers_only_stored_permissions() {
        let eff =
            effective_role_permissions("Analyst", vec!["search:view".into(), "cases:view".into()]);
        assert_eq!(eff, set(&["search:view", "cases:view"]));
    }
}
