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
        // Check if name already exists
        let existing = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM roles WHERE name = $1")
            .bind(&request.name)
            .fetch_one(&self.pool)
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
        .fetch_one(&self.pool)
        .await?;

        // Add permissions
        for permission_id in &request.permissions {
            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
            )
            .bind(role.id)
            .bind(permission_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(role)
    }

    /// Update a role
    /// Requirements: 4.6, 4.7
    pub async fn update_role(
        &self,
        id: Uuid,
        request: &UpdateRoleRequest,
    ) -> Result<Role, RoleRepositoryError> {
        let existing = self.get_role(id).await?;

        // Check if it's the Admin role - cannot modify permissions
        if id == builtin_roles::ADMIN_ID && request.permissions.is_some() {
            return Err(RoleRepositoryError::CannotModifySystemRole(
                "Admin".to_string(),
            ));
        }

        // Check name uniqueness if changing name
        if let Some(ref new_name) = request.name {
            if new_name != &existing.name {
                let count = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM roles WHERE name = $1 AND id != $2",
                )
                .bind(new_name)
                .bind(id)
                .fetch_one(&self.pool)
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
        .fetch_one(&self.pool)
        .await?;

        // Update permissions if provided (and not Admin role)
        if let Some(ref permissions) = request.permissions {
            // Remove existing permissions
            sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;

            // Add new permissions
            for permission_id in permissions {
                sqlx::query(
                    "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
                )
                .bind(id)
                .bind(permission_id)
                .execute(&self.pool)
                .await?;
            }
        }

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

        // Delete role (permissions cascade)
        sqlx::query("DELETE FROM roles WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

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
        // Verify role exists and check if it's Admin
        let _role = self.get_role(role_id).await?;

        // Cannot modify Admin role permissions
        if role_id == builtin_roles::ADMIN_ID {
            return Err(RoleRepositoryError::CannotModifySystemRole(
                "Admin".to_string(),
            ));
        }

        // Remove existing permissions
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
            .bind(role_id)
            .execute(&self.pool)
            .await?;

        // Add new permissions
        for permission_id in permission_ids {
            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
            )
            .bind(role_id)
            .bind(permission_id)
            .execute(&self.pool)
            .await?;
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
