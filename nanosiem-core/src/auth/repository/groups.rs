// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group repository for CRUD operations
//!
//! Requirements: 6.1, 6.2, 6.3, 6.6

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::types::{
    builtin_groups, CreateGroupRequest, Group, RoleSummary, UpdateGroupRequest, User,
};

#[derive(Error, Debug)]
pub enum GroupRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Group not found: {0}")]
    NotFound(Uuid),
    #[error("Group name already exists: {0}")]
    NameExists(String),
    #[error("Cannot modify system group: {0}")]
    CannotModifySystemGroup(String),
    #[error("Cannot delete system group: {0}")]
    CannotDeleteSystemGroup(String),
}

/// Repository for group operations
#[derive(Clone)]
pub struct GroupRepository {
    pool: PgPool,
}

impl GroupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List all groups
    pub async fn list_groups(&self) -> Result<Vec<Group>, GroupRepositoryError> {
        let groups =
            sqlx::query_as::<_, Group>("SELECT * FROM groups ORDER BY is_system DESC, name ASC")
                .fetch_all(&self.pool)
                .await?;

        Ok(groups)
    }

    /// Get a group by ID
    pub async fn get_group(&self, id: Uuid) -> Result<Group, GroupRepositoryError> {
        sqlx::query_as::<_, Group>("SELECT * FROM groups WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(GroupRepositoryError::NotFound(id))
    }

    /// Create a new group
    /// Requirements: 6.1
    pub async fn create_group(
        &self,
        request: &CreateGroupRequest,
    ) -> Result<Group, GroupRepositoryError> {
        // Check if name already exists
        let existing = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM groups WHERE name = $1")
            .bind(&request.name)
            .fetch_one(&self.pool)
            .await?;

        if existing > 0 {
            return Err(GroupRepositoryError::NameExists(request.name.clone()));
        }

        // Create the group
        let group = sqlx::query_as::<_, Group>(
            r#"
            INSERT INTO groups (name, description, is_system)
            VALUES ($1, $2, FALSE)
            RETURNING *
            "#,
        )
        .bind(&request.name)
        .bind(&request.description)
        .fetch_one(&self.pool)
        .await?;

        // Add roles if provided
        for role_id in &request.role_ids {
            sqlx::query(
                "INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
            )
            .bind(group.id)
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(group)
    }

    /// Update a group
    pub async fn update_group(
        &self,
        id: Uuid,
        request: &UpdateGroupRequest,
    ) -> Result<Group, GroupRepositoryError> {
        let existing = self.get_group(id).await?;

        // Check name uniqueness if changing name
        if let Some(ref new_name) = request.name {
            if new_name != &existing.name {
                // Cannot rename system groups
                if existing.is_system {
                    return Err(GroupRepositoryError::CannotModifySystemGroup(
                        existing.name.clone(),
                    ));
                }

                let count = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM groups WHERE name = $1 AND id != $2",
                )
                .bind(new_name)
                .bind(id)
                .fetch_one(&self.pool)
                .await?;

                if count > 0 {
                    return Err(GroupRepositoryError::NameExists(new_name.clone()));
                }
            }
        }

        let name = request.name.as_ref().unwrap_or(&existing.name);
        let description = request.description.clone().or(existing.description);

        let group = sqlx::query_as::<_, Group>(
            r#"
            UPDATE groups SET
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

        Ok(group)
    }

    /// Delete a group
    /// Requirements: 6.6
    pub async fn delete_group(&self, id: Uuid) -> Result<(), GroupRepositoryError> {
        let group = self.get_group(id).await?;

        // Cannot delete system groups
        if group.is_system {
            return Err(GroupRepositoryError::CannotDeleteSystemGroup(group.name));
        }

        // Delete group (user_groups and group_roles cascade)
        sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Get roles assigned to a group
    /// Requirements: 6.2
    pub async fn get_group_roles(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<RoleSummary>, GroupRepositoryError> {
        let roles = sqlx::query_as::<_, RoleSummary>(
            r#"
            SELECT r.id, r.name
            FROM roles r
            INNER JOIN group_roles gr ON r.id = gr.role_id
            WHERE gr.group_id = $1
            ORDER BY r.name
            "#,
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(roles)
    }

    /// Set roles for a group (replaces existing)
    /// Requirements: 6.2
    pub async fn set_group_roles(
        &self,
        group_id: Uuid,
        role_ids: &[Uuid],
    ) -> Result<(), GroupRepositoryError> {
        // Verify group exists
        self.get_group(group_id).await?;

        // Remove existing role assignments
        sqlx::query("DELETE FROM group_roles WHERE group_id = $1")
            .bind(group_id)
            .execute(&self.pool)
            .await?;

        // Add new role assignments
        for role_id in role_ids {
            sqlx::query(
                "INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
            )
            .bind(group_id)
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    /// Get members of a group
    /// Requirements: 6.3
    pub async fn get_group_members(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<User>, GroupRepositoryError> {
        // Verify group exists
        self.get_group(group_id).await?;

        let users = sqlx::query_as::<_, User>(
            r#"
            SELECT u.*
            FROM users u
            INNER JOIN user_groups ug ON u.id = ug.user_id
            WHERE ug.group_id = $1
            ORDER BY u.name
            "#,
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    /// Add a user to a group
    /// Requirements: 6.3
    pub async fn add_user_to_group(
        &self,
        user_id: Uuid,
        group_id: Uuid,
    ) -> Result<(), GroupRepositoryError> {
        // Verify group exists
        self.get_group(group_id).await?;

        sqlx::query(
            "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(group_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Remove a user from a group
    /// Requirements: 6.3
    pub async fn remove_user_from_group(
        &self,
        user_id: Uuid,
        group_id: Uuid,
    ) -> Result<(), GroupRepositoryError> {
        // Cannot remove from Everyone group
        if group_id == builtin_groups::EVERYONE_ID {
            return Err(GroupRepositoryError::CannotModifySystemGroup(
                "Everyone".to_string(),
            ));
        }

        sqlx::query("DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2")
            .bind(user_id)
            .bind(group_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Get member count for a group
    pub async fn get_member_count(&self, group_id: Uuid) -> Result<i64, GroupRepositoryError> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_groups WHERE group_id = $1")
                .bind(group_id)
                .fetch_one(&self.pool)
                .await?;

        Ok(count)
    }

    /// Count groups
    pub async fn count_groups(&self) -> Result<i64, GroupRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM groups")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    /// Check if a user is in a group
    pub async fn is_user_in_group(
        &self,
        user_id: Uuid,
        group_id: Uuid,
    ) -> Result<bool, GroupRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_groups WHERE user_id = $1 AND group_id = $2",
        )
        .bind(user_id)
        .bind(group_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Get all permissions for a user through their group memberships
    pub async fn get_user_permissions(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<String>, GroupRepositoryError> {
        let permissions = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT rp.permission_id
            FROM user_groups ug
            INNER JOIN group_roles gr ON ug.group_id = gr.group_id
            INNER JOIN role_permissions rp ON gr.role_id = rp.role_id
            WHERE ug.user_id = $1
            ORDER BY rp.permission_id
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    /// Get all role names for a user through their group memberships
    pub async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<String>, GroupRepositoryError> {
        let roles = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT r.name
            FROM user_groups ug
            INNER JOIN group_roles gr ON ug.group_id = gr.group_id
            INNER JOIN roles r ON gr.role_id = r.id
            WHERE ug.user_id = $1
            ORDER BY r.name
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(roles)
    }
}
