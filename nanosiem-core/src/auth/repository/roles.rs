// SPDX-License-Identifier: AGPL-3.0-or-later

//! Role repository for CRUD operations
//!
//! Requirements: 4.5, 4.6, 4.7

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::types::{builtin_roles, CreateRoleRequest, Permission, Role, UpdateRoleRequest};

#[derive(Error, Debug)]
pub enum RoleRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Role not found: {0}")]
    NotFound(Uuid),
    #[error("Role name already exists: {0}")]
    NameExists(String),
    #[error("Cannot modify system role: {0}")]
    CannotModifySystemRole(String),
    #[error("Cannot delete system role: {0}")]
    CannotDeleteSystemRole(String),
    #[error("Role is in use by groups")]
    RoleInUse,
    #[error(
        "Role is in use by one or more playbook ACLs; remove those ACL entries before deleting it"
    )]
    RoleInUseByPlaybookAcl,
    #[error(
        "Permission change would leave one or more playbook ACLs without a role that can administer them"
    )]
    WouldOrphanPlaybookAcl,
    #[error("Reserved role name: {0}")]
    ReservedRoleName(String),
    #[error("grant authority changed during validation; retry the request")]
    GrantAuthorityChanged,
}

/// Role names the platform derives privileges or behavior from by STRING VALUE,
/// not from `role_permissions`. `PermissionResolver::resolve_with_roles` injects
/// the hard-coded `DEMO_PERMISSIONS` set for any role named `demo_analyst`, and
/// `SourceScopeResolver` force-denies it. Because `get_user_roles` feeds a role's
/// NAME into those resolvers, a tenant role that acquired one of these names
/// would confer name-derived privileges WITHOUT going through the NAN-2121
/// permission-set grant check. Creating or renaming a role to a reserved name is
/// therefore rejected (a `roles:edit` holder must not be able to grant
/// `DEMO_PERMISSIONS` by renaming a role).
///
/// NAN-2097 adds `api_key`: `AuthContext::from_api_key` sets
/// `claims.roles = ["api_key"]`, and the per-playbook ACL treats that label as a
/// synthetic principal (`nanosiem_core::playbooks::acl::SYNTHETIC_ROLES`). The
/// ACL keys ordinary real roles by `role_id` and synthetics by the label with
/// `role_id IS NULL`. Reserving the name keeps the migration's backfill
/// unambiguous and stops an operator creating a role whose members would *look*
/// like API keys anywhere else this string is compared. A pre-existing
/// `demo_analyst` role is preserved as a name-derived restricted principal;
/// new roles still cannot take either reserved name.
const RESERVED_ROLE_NAMES: &[&str] = &["demo_analyst", "api_key"];

/// Case-insensitive, whitespace-trimmed reserved-name check (matches the exact
/// forms the resolvers compare against, plus casing/whitespace variants).
fn is_reserved_role_name(name: &str) -> bool {
    let normalized = name.trim().to_lowercase();
    RESERVED_ROLE_NAMES
        .iter()
        .any(|reserved| *reserved == normalized)
}

/// Repository for role operations
#[derive(Clone)]
pub struct RoleRepository {
    pool: PgPool,
}

impl RoleRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List all roles
    pub async fn list_roles(&self) -> Result<Vec<Role>, RoleRepositoryError> {
        let roles =
            sqlx::query_as::<_, Role>("SELECT * FROM roles ORDER BY is_system DESC, name ASC")
                .fetch_all(&self.pool)
                .await?;

        Ok(roles)
    }

    /// Get a role by ID
    pub async fn get_role(&self, id: Uuid) -> Result<Role, RoleRepositoryError> {
        sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(RoleRepositoryError::NotFound(id))
    }

    /// Get a role by name
    pub async fn get_role_by_name(&self, name: &str) -> Result<Role, RoleRepositoryError> {
        sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| RoleRepositoryError::NotFound(Uuid::nil()))
    }

    /// Create a new role
    /// Requirements: 4.5
    pub async fn create_role(
        &self,
        request: &CreateRoleRequest,
    ) -> Result<Role, RoleRepositoryError> {
        self.create_role_inner(request, None).await
    }

    pub async fn create_role_authorized(
        &self,
        request: &CreateRoleRequest,
        stamp: crate::auth::GrantAuthorityStamp,
    ) -> Result<Role, RoleRepositoryError> {
        self.create_role_inner(request, Some(stamp)).await
    }

    async fn create_role_inner(
        &self,
        request: &CreateRoleRequest,
        stamp: Option<crate::auth::GrantAuthorityStamp>,
    ) -> Result<Role, RoleRepositoryError> {
        // NAN-2121: reject reserved magic names (e.g. `demo_analyst`) that would
        // confer name-derived privileges bypassing the permission-set check.
        if is_reserved_role_name(&request.name) {
            return Err(RoleRepositoryError::ReservedRoleName(request.name.clone()));
        }

        let mut tx = self.pool.begin().await?;
        if let Some(stamp) = stamp {
            if !crate::auth::lock_and_verify_grant_authority(&mut tx, stamp).await? {
                return Err(RoleRepositoryError::GrantAuthorityChanged);
            }
        }

        // Check if name already exists
        let existing = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM roles WHERE name = $1")
            .bind(&request.name)
            .fetch_one(&mut *tx)
            .await?;

        if existing > 0 {
            return Err(RoleRepositoryError::NameExists(request.name.clone()));
        }

        // Create the role
        let role = sqlx::query_as::<_, Role>(
            r#"
            INSERT INTO roles (name, description, is_system)
            VALUES ($1, $2, FALSE)
            RETURNING *
            "#,
        )
        .bind(&request.name)
        .bind(&request.description)
        .fetch_one(&mut *tx)
        .await?;

        // Add permissions
        for permission_id in &request.permissions {
            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
            )
            .bind(role.id)
            .bind(permission_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(role)
    }

    /// Update a role
    /// Requirements: 4.6, 4.7
    pub async fn update_role(
        &self,
        id: Uuid,
        request: &UpdateRoleRequest,
    ) -> Result<Role, RoleRepositoryError> {
        self.update_role_inner(id, request, None).await
    }

    pub async fn update_role_authorized(
        &self,
        id: Uuid,
        request: &UpdateRoleRequest,
        stamp: crate::auth::GrantAuthorityStamp,
    ) -> Result<Role, RoleRepositoryError> {
        self.update_role_inner(id, request, Some(stamp)).await
    }

    async fn update_role_inner(
        &self,
        id: Uuid,
        request: &UpdateRoleRequest,
        stamp: Option<crate::auth::GrantAuthorityStamp>,
    ) -> Result<Role, RoleRepositoryError> {
        let mut tx = self.pool.begin().await?;
        if let Some(stamp) = stamp {
            if !crate::auth::lock_and_verify_grant_authority(&mut tx, stamp).await? {
                return Err(RoleRepositoryError::GrantAuthorityChanged);
            }
        }
        let existing = sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(RoleRepositoryError::NotFound(id))?;

        // NAN-2121: block permission mutation of the baseline-critical system
        // roles. Admin is the full-privilege set; ReadOnly is the role the
        // built-in Everyone group is permanently bound to, so stripping its
        // permissions (e.g. a `roles:edit` caller sending `permissions: []`, which
        // passes the empty grant-subset check vacuously) would revoke baseline
        // permissions for every account. (Editor and other roles stay editable.)
        if request.permissions.is_some()
            && (id == builtin_roles::ADMIN_ID || id == builtin_roles::READONLY_ID)
        {
            return Err(RoleRepositoryError::CannotModifySystemRole(
                existing.name.clone(),
            ));
        }

        // NAN-2121: role names are load-bearing (resolvers derive privileges from
        // them). Reject (a) renaming ANY role to a reserved magic name, and
        // (b) renaming a SYSTEM role at all — its name is referenced by string
        // elsewhere (e.g. the Everyone group's ReadOnly baseline), so a rename
        // could confer name-derived privileges past the permission-set check.
        if let Some(ref new_name) = request.name {
            // Reject renaming TO a reserved name — but allow an ordinary edit that
            // merely echoes an existing legacy role's unchanged reserved name
            // (the web edit dialog always sends name+description+permissions), or
            // the role would be uneditable. The rename-AWAY guard below still fires
            // when the name actually changes.
            if is_reserved_role_name(new_name) && new_name != &existing.name {
                return Err(RoleRepositoryError::ReservedRoleName(new_name.clone()));
            }
            // Also block renaming AWAY from a reserved name (a legacy `demo_analyst`
            // role): the rename silently activates the role's stored
            // `role_permissions` (the resolver stops injecting `DEMO_PERMISSIONS`)
            // for every assignee on their next token refresh — past the
            // permission-set grant check. Such a role must be deleted, not renamed.
            if is_reserved_role_name(&existing.name) && new_name != &existing.name {
                return Err(RoleRepositoryError::ReservedRoleName(existing.name.clone()));
            }
            if existing.is_system && new_name != &existing.name {
                return Err(RoleRepositoryError::CannotModifySystemRole(
                    existing.name.clone(),
                ));
            }
        }

        // Check name uniqueness if changing name
        if let Some(ref new_name) = request.name {
            if new_name != &existing.name {
                let count = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM roles WHERE name = $1 AND id != $2",
                )
                .bind(new_name)
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;

                if count > 0 {
                    return Err(RoleRepositoryError::NameExists(new_name.clone()));
                }
            }
        }

        let name = request.name.as_ref().unwrap_or(&existing.name);
        let description = request.description.clone().or(existing.description);

        let role = sqlx::query_as::<_, Role>(
            r#"
            UPDATE roles SET
                name = $2,
                description = $3,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(description)
        .fetch_one(&mut *tx)
        .await?;

        // Update permissions if provided (and not Admin role)
        if let Some(ref permissions) = request.permissions {
            // Migration 269's rolling-compatibility trigger must distinguish
            // this atomic replacement from the old binary's autocommit
            // DELETE-then-INSERT sequence. The marker is transaction-local, so
            // the trigger may allow our temporary empty set and validate the
            // final state at commit without weakening direct legacy writes.
            sqlx::query("SET LOCAL nanosiem.atomic_role_permission_replace = 'on'")
                .execute(&mut *tx)
                .await?;

            // Serialize with ACL writes by locking every referenced playbook in
            // deterministic order. Otherwise a role edit can remove
            // playbooks:manage immediately after an ACL write accepted this role
            // as its sole administrator.
            let affected = Self::lock_playbook_acls_for_role_permission_change(&mut tx, id).await?;

            // Remove existing permissions
            sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;

            // Add new permissions
            for permission_id in permissions {
                sqlx::query(
                    "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
                )
                .bind(id)
                .bind(permission_id)
                .execute(&mut *tx)
                .await?;
            }

            Self::assert_affected_playbook_acls_still_administrable(&mut tx, &affected).await?;
        }

        tx.commit().await?;
        Ok(role)
    }

    /// Delete a role
    /// Requirements: 4.6
    pub async fn delete_role(&self, id: Uuid) -> Result<(), RoleRepositoryError> {
        let role = self.get_role(id).await?;

        // Cannot delete system roles
        if role.is_system {
            return Err(RoleRepositoryError::CannotDeleteSystemRole(role.name));
        }

        // Check if role is assigned to any groups
        let in_use =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM group_roles WHERE role_id = $1")
                .bind(id)
                .fetch_one(&self.pool)
                .await?;

        if in_use > 0 {
            return Err(RoleRepositoryError::RoleInUse);
        }

        // NAN-2097: the enterprise playbook ACL FK uses ON DELETE RESTRICT
        // because removing the last ACL row would turn a restricted playbook
        // into an unrestricted one. Rely on that FK as the atomic in-use check
        // and translate it to the expected domain conflict. Do not probe the
        // enterprise-only table first: it deliberately does not exist on a
        // fresh open-edition schema.
        let deleted = sqlx::query("DELETE FROM roles WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await;
        match deleted {
            Ok(_) => {}
            Err(sqlx::Error::Database(db))
                if db.constraint() == Some("playbook_permissions_role_id_fkey") =>
            {
                return Err(RoleRepositoryError::RoleInUseByPlaybookAcl);
            }
            Err(err) => return Err(RoleRepositoryError::DatabaseError(err)),
        }

        Ok(())
    }

    /// Get permissions for a role
    pub async fn get_role_permissions(
        &self,
        role_id: Uuid,
    ) -> Result<Vec<String>, RoleRepositoryError> {
        let permissions = sqlx::query_scalar::<_, String>(
            r#"
            SELECT permission_id FROM role_permissions
            WHERE role_id = $1
            ORDER BY permission_id
            "#,
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    /// Set permissions for a role (replaces existing)
    pub async fn set_role_permissions(
        &self,
        role_id: Uuid,
        permission_ids: &[String],
    ) -> Result<(), RoleRepositoryError> {
        let mut tx = self.pool.begin().await?;
        let role = sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = $1 FOR UPDATE")
            .bind(role_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(RoleRepositoryError::NotFound(role_id))?;

        // Cannot modify Admin or ReadOnly role permissions. `update_role_inner`
        // already guards BOTH (see its comment); this path guarded only Admin,
        // which was harmless while it had no handler wired to it but left the
        // ReadOnly half of the invariant resting on "nothing calls this yet".
        // NAN-2223 makes that invariant load-bearing — the Everyone baseline is
        // exempt from the privilege-grant subset check precisely BECAUSE it is
        // immutable — so state it structurally in every write path.
        if role_id == builtin_roles::ADMIN_ID || role_id == builtin_roles::READONLY_ID {
            return Err(RoleRepositoryError::CannotModifySystemRole(role.name));
        }

        let affected =
            Self::lock_playbook_acls_for_role_permission_change(&mut tx, role_id).await?;

        // See update_role: this path is one atomic replacement even though old
        // deployed replicas performed the same logical operation as separate
        // autocommit statements.
        sqlx::query("SET LOCAL nanosiem.atomic_role_permission_replace = 'on'")
            .execute(&mut *tx)
            .await?;

        // Remove existing permissions
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
            .bind(role_id)
            .execute(&mut *tx)
            .await?;

        // Add new permissions
        for permission_id in permission_ids {
            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
            )
            .bind(role_id)
            .bind(permission_id)
            .execute(&mut *tx)
            .await?;
        }

        Self::assert_affected_playbook_acls_still_administrable(&mut tx, &affected).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Lock every playbook whose ACL references `role_id`. The role row is
    /// already locked `FOR UPDATE`; real-role ACL writes first lock that same
    /// row `FOR SHARE`, then their playbook. Keeping the common role → playbook
    /// order closes the new-ACL race without introducing a lock-order cycle.
    ///
    /// The ACL tables are enterprise-only, so open-edition schemas legitimately
    /// return an empty set. Ordering prevents two simultaneous role edits from
    /// deadlocking when their ACL footprints overlap.
    async fn lock_playbook_acls_for_role_permission_change(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        role_id: Uuid,
    ) -> Result<Vec<Uuid>, RoleRepositoryError> {
        let acl_table: Option<String> =
            sqlx::query_scalar("SELECT to_regclass('public.playbook_permissions')::text")
                .fetch_one(&mut **tx)
                .await?;
        if acl_table.is_none() {
            return Ok(Vec::new());
        }

        Ok(sqlx::query_scalar(
            r#"SELECT p.id
                 FROM playbooks p
                 JOIN playbook_permissions pp ON pp.playbook_id = p.id
                WHERE pp.role_id = $1
                ORDER BY p.id
                FOR UPDATE OF p"#,
        )
        .bind(role_id)
        .fetch_all(&mut **tx)
        .await?)
    }

    async fn assert_affected_playbook_acls_still_administrable(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        affected: &[Uuid],
    ) -> Result<(), RoleRepositoryError> {
        if affected.is_empty() {
            return Ok(());
        }

        let orphaned: Option<Uuid> = sqlx::query_scalar(
            r#"SELECT DISTINCT affected.playbook_id
                 FROM playbook_permissions affected
                WHERE affected.playbook_id = ANY($1)
                  AND NOT EXISTS (
                      SELECT 1
                        FROM playbook_permissions administrator
                        JOIN role_permissions rp
                          ON rp.role_id = administrator.role_id
                       WHERE administrator.playbook_id = affected.playbook_id
                         AND administrator.can_view
                         AND administrator.can_edit
                         AND rp.permission_id = 'playbooks:manage'
                  )
                LIMIT 1"#,
        )
        .bind(affected)
        .fetch_optional(&mut **tx)
        .await?;
        if orphaned.is_some() {
            return Err(RoleRepositoryError::WouldOrphanPlaybookAcl);
        }
        Ok(())
    }

    /// Check if a role is a system role
    pub async fn is_system_role(&self, id: Uuid) -> Result<bool, RoleRepositoryError> {
        let role = self.get_role(id).await?;
        Ok(role.is_system)
    }

    /// List all permissions
    pub async fn list_permissions(&self) -> Result<Vec<Permission>, RoleRepositoryError> {
        let permissions =
            sqlx::query_as::<_, Permission>("SELECT * FROM permissions ORDER BY category, id")
                .fetch_all(&self.pool)
                .await?;

        Ok(permissions)
    }

    /// Get permissions by category
    pub async fn get_permissions_by_category(
        &self,
        category: &str,
    ) -> Result<Vec<Permission>, RoleRepositoryError> {
        let permissions = sqlx::query_as::<_, Permission>(
            "SELECT * FROM permissions WHERE category = $1 ORDER BY id",
        )
        .bind(category)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    /// Count roles
    pub async fn count_roles(&self) -> Result<i64, RoleRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM roles")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    /// Get groups that have a specific role
    pub async fn get_groups_with_role(
        &self,
        role_id: Uuid,
    ) -> Result<Vec<Uuid>, RoleRepositoryError> {
        let group_ids =
            sqlx::query_scalar::<_, Uuid>("SELECT group_id FROM group_roles WHERE role_id = $1")
                .bind(role_id)
                .fetch_all(&self.pool)
                .await?;

        Ok(group_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::is_reserved_role_name;

    #[test]
    fn reserved_role_name_matches_magic_names_case_insensitively() {
        // NAN-2121: `demo_analyst` triggers name-derived DEMO_PERMISSIONS.
        assert!(is_reserved_role_name("demo_analyst"));
        assert!(is_reserved_role_name("Demo_Analyst"));
        assert!(is_reserved_role_name("  DEMO_ANALYST  "));
        // NAN-2097: `api_key` is the synthetic per-playbook API-key principal.
        assert!(is_reserved_role_name("api_key"));
        assert!(is_reserved_role_name(" API_KEY "));
        assert!(is_reserved_role_name("\tAPI_KEY\n"));
        assert!(is_reserved_role_name("\u{00a0}Demo_Analyst\u{00a0}"));
    }

    #[test]
    fn ordinary_role_names_are_not_reserved() {
        assert!(!is_reserved_role_name("Analyst"));
        assert!(!is_reserved_role_name("demo analyst")); // space, not the magic form
        assert!(!is_reserved_role_name("ReadOnly"));
        assert!(!is_reserved_role_name(""));
    }
}
