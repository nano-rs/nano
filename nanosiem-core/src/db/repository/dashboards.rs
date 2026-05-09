// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dashboard repository for CRUD operations

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::models::{
    Dashboard, DashboardAffectedUser, DashboardShareResult, DashboardSharedGroup,
    DashboardWithContext, DashboardWithOwner, NewDashboard, ShareDashboardRequest, UpdateDashboard,
};

#[derive(Error, Debug)]
pub enum DashboardRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Dashboard not found: {0}")]
    NotFound(Uuid),
    #[error("Access denied to dashboard: {0}")]
    AccessDenied(Uuid),
    #[error("Only the owner can share this dashboard")]
    NotOwner,
}

/// Repository for dashboard operations
#[derive(Clone)]
pub struct DashboardRepository {
    pool: PgPool,
}

impl DashboardRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new dashboard
    pub async fn create(
        &self,
        dashboard: &NewDashboard,
    ) -> Result<Dashboard, DashboardRepositoryError> {
        let result = sqlx::query_as::<_, Dashboard>(
            r#"
            INSERT INTO dashboards (name, description, layout, panels, refresh_interval, owner_id, visibility)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(&dashboard.name)
        .bind(&dashboard.description)
        .bind(&dashboard.layout)
        .bind(&dashboard.panels)
        .bind(dashboard.refresh_interval)
        .bind(dashboard.owner_id)
        .bind(&dashboard.visibility)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Find a dashboard by ID
    pub async fn find_by_id(&self, id: Uuid) -> Result<Dashboard, DashboardRepositoryError> {
        let result = sqlx::query_as::<_, Dashboard>(r#"SELECT * FROM dashboards WHERE id = $1"#)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DashboardRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Find a dashboard by ID with owner name
    pub async fn find_by_id_with_owner(
        &self,
        id: Uuid,
    ) -> Result<DashboardWithOwner, DashboardRepositoryError> {
        let result = sqlx::query_as::<_, DashboardWithOwner>(
            r#"
            SELECT d.*, u.name as owner_name
            FROM dashboards d
            LEFT JOIN users u ON d.owner_id = u.id
            WHERE d.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DashboardRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Check if a user has access to a dashboard
    pub async fn check_user_access(
        &self,
        dashboard: &Dashboard,
        user_id: Uuid,
    ) -> Result<bool, DashboardRepositoryError> {
        // Owner always has access
        if dashboard.owner_id == Some(user_id) {
            return Ok(true);
        }

        // Legacy dashboards (no owner) are accessible to all
        if dashboard.owner_id.is_none() {
            return Ok(true);
        }

        // Public dashboards are accessible to all
        if dashboard.visibility == "public" {
            return Ok(true);
        }

        // Private dashboards only accessible to owner (already checked above)
        if dashboard.visibility == "private" {
            return Ok(false);
        }

        // Group visibility: check if user is in any shared group
        if dashboard.visibility == "group" {
            let count: i64 = sqlx::query_scalar(
                r#"
                SELECT COUNT(*)
                FROM dashboard_groups dg
                JOIN user_groups ug ON ug.group_id = dg.group_id
                WHERE dg.dashboard_id = $1 AND ug.user_id = $2
                "#,
            )
            .bind(dashboard.id)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;

            return Ok(count > 0);
        }

        Ok(false)
    }

    /// Get groups a dashboard is shared with
    pub async fn get_shared_groups(
        &self,
        dashboard_id: Uuid,
    ) -> Result<Vec<DashboardSharedGroup>, DashboardRepositoryError> {
        let groups = sqlx::query_as::<_, DashboardSharedGroup>(
            r#"
            SELECT g.id, g.name
            FROM dashboard_groups dg
            JOIN groups g ON g.id = dg.group_id
            WHERE dg.dashboard_id = $1
            ORDER BY g.name
            "#,
        )
        .bind(dashboard_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(groups)
    }

    /// Get users in specified groups (for affected users calculation)
    async fn get_users_in_groups(
        &self,
        group_ids: &[Uuid],
        exclude_user_id: Uuid,
    ) -> Result<Vec<DashboardAffectedUser>, DashboardRepositoryError> {
        if group_ids.is_empty() {
            return Ok(vec![]);
        }

        let users = sqlx::query_as::<_, DashboardAffectedUser>(
            r#"
            SELECT DISTINCT u.id as user_id, u.name as user_name, u.email as user_email
            FROM users u
            JOIN user_groups ug ON ug.user_id = u.id
            WHERE ug.group_id = ANY($1)
              AND u.id != $2
            ORDER BY u.name
            "#,
        )
        .bind(group_ids)
        .bind(exclude_user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    /// Find a dashboard by ID with full context, checking access for a specific user
    pub async fn find_by_id_for_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<DashboardWithContext, DashboardRepositoryError> {
        // First fetch the dashboard with owner
        let dashboard = self.find_by_id_with_owner(id).await?;

        // Convert to Dashboard for access check
        let dashboard_for_check = Dashboard {
            id: dashboard.id,
            name: dashboard.name.clone(),
            description: dashboard.description.clone(),
            layout: dashboard.layout.clone(),
            panels: dashboard.panels.clone(),
            refresh_interval: dashboard.refresh_interval,
            owner_id: dashboard.owner_id,
            visibility: dashboard.visibility.clone(),
            created_at: dashboard.created_at,
            updated_at: dashboard.updated_at,
        };

        // Check access
        let has_access = self
            .check_user_access(&dashboard_for_check, user_id)
            .await?;
        if !has_access {
            return Err(DashboardRepositoryError::AccessDenied(id));
        }

        // Get shared groups
        let shared_groups = self.get_shared_groups(id).await?;

        // Build context
        let is_owner = dashboard.owner_id == Some(user_id);

        Ok(DashboardWithContext {
            id: dashboard.id,
            name: dashboard.name,
            description: dashboard.description,
            layout: dashboard.layout,
            panels: dashboard.panels,
            refresh_interval: dashboard.refresh_interval,
            owner_id: dashboard.owner_id,
            visibility: dashboard.visibility,
            created_at: dashboard.created_at,
            updated_at: dashboard.updated_at,
            owner_name: dashboard.owner_name,
            shared_groups,
            is_owner,
        })
    }

    /// List all dashboards (legacy - returns all)
    pub async fn list(&self) -> Result<Vec<Dashboard>, DashboardRepositoryError> {
        let results =
            sqlx::query_as::<_, Dashboard>(r#"SELECT * FROM dashboards ORDER BY created_at DESC"#)
                .fetch_all(&self.pool)
                .await?;

        Ok(results)
    }

    /// List dashboards accessible to a user (public + user's private + group shared)
    pub async fn list_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<DashboardWithOwner>, DashboardRepositoryError> {
        let results = sqlx::query_as::<_, DashboardWithOwner>(
            r#"
            SELECT d.*, u.name as owner_name
            FROM dashboards d
            LEFT JOIN users u ON d.owner_id = u.id
            WHERE d.visibility = 'public'
               OR d.owner_id = $1
               OR d.owner_id IS NULL
               OR (d.visibility = 'group' AND EXISTS (
                   SELECT 1 FROM dashboard_groups dg
                   JOIN user_groups ug ON ug.group_id = dg.group_id
                   WHERE dg.dashboard_id = d.id AND ug.user_id = $1
               ))
            ORDER BY d.created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List only the user's own dashboards ("My Dashboards")
    pub async fn list_owned_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<DashboardWithOwner>, DashboardRepositoryError> {
        let results = sqlx::query_as::<_, DashboardWithOwner>(
            r#"
            SELECT d.*, u.name as owner_name
            FROM dashboards d
            LEFT JOIN users u ON d.owner_id = u.id
            WHERE d.owner_id = $1
            ORDER BY d.created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Update a dashboard
    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdateDashboard,
    ) -> Result<Dashboard, DashboardRepositoryError> {
        // First check if dashboard exists
        self.find_by_id(id).await?;

        let result = sqlx::query_as::<_, Dashboard>(
            r#"
            UPDATE dashboards SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                layout = COALESCE($4, layout),
                panels = COALESCE($5, panels),
                refresh_interval = COALESCE($6, refresh_interval),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(&update.description)
        .bind(&update.layout)
        .bind(&update.panels)
        .bind(update.refresh_interval)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Update a dashboard, verifying user has access
    pub async fn update_owned(
        &self,
        id: Uuid,
        user_id: Uuid,
        update: &UpdateDashboard,
    ) -> Result<Dashboard, DashboardRepositoryError> {
        // First check access
        let dashboard = self.find_by_id(id).await?;
        let has_access = self.check_user_access(&dashboard, user_id).await?;
        if !has_access {
            return Err(DashboardRepositoryError::AccessDenied(id));
        }

        // Only owner or public dashboards can be edited
        let is_owner = dashboard.owner_id == Some(user_id);
        let is_public = dashboard.visibility == "public";
        let is_legacy = dashboard.owner_id.is_none();

        if !is_owner && !is_public && !is_legacy {
            return Err(DashboardRepositoryError::AccessDenied(id));
        }

        let result = sqlx::query_as::<_, Dashboard>(
            r#"
            UPDATE dashboards SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                layout = COALESCE($4, layout),
                panels = COALESCE($5, panels),
                refresh_interval = COALESCE($6, refresh_interval),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(&update.description)
        .bind(&update.layout)
        .bind(&update.panels)
        .bind(update.refresh_interval)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Share a dashboard (owner only)
    pub async fn share(
        &self,
        id: Uuid,
        request: &ShareDashboardRequest,
        user_id: Uuid,
    ) -> Result<DashboardShareResult, DashboardRepositoryError> {
        // Get the dashboard and verify ownership
        let dashboard = self.find_by_id(id).await?;

        if dashboard.owner_id != Some(user_id) {
            return Err(DashboardRepositoryError::NotOwner);
        }

        // Get old groups before change (to detect removed groups)
        let old_groups = self.get_shared_groups(id).await?;
        let old_group_ids: Vec<Uuid> = old_groups.iter().map(|g| g.id).collect();

        // Determine new groups
        let new_group_ids: Vec<Uuid> = if request.visibility == "group" {
            request.group_ids.clone().unwrap_or_default()
        } else {
            vec![]
        };

        // Find removed groups (in old but not in new)
        let removed_group_ids: Vec<Uuid> = old_group_ids
            .iter()
            .filter(|id| !new_group_ids.contains(id))
            .copied()
            .collect();

        // Get affected users (those who will lose access)
        let users_who_lost_access = self
            .get_users_in_groups(&removed_group_ids, user_id)
            .await?;

        // Update visibility
        sqlx::query(
            r#"
            UPDATE dashboards SET visibility = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&request.visibility)
        .execute(&self.pool)
        .await?;

        // Clear all dashboard_groups entries
        sqlx::query(r#"DELETE FROM dashboard_groups WHERE dashboard_id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        // Insert new dashboard_groups entries if visibility is 'group'
        if request.visibility == "group" {
            for group_id in &new_group_ids {
                sqlx::query(
                    r#"
                    INSERT INTO dashboard_groups (dashboard_id, group_id)
                    VALUES ($1, $2)
                    ON CONFLICT DO NOTHING
                    "#,
                )
                .bind(id)
                .bind(group_id)
                .execute(&self.pool)
                .await?;
            }
        }

        // Fetch the updated dashboard with context
        let dashboard_with_context = self.find_by_id_for_user(id, user_id).await?;

        Ok(DashboardShareResult {
            dashboard: dashboard_with_context,
            users_who_lost_access,
        })
    }

    /// Share a dashboard as admin (bypasses ownership check)
    pub async fn share_as_admin(
        &self,
        id: Uuid,
        request: &ShareDashboardRequest,
        admin_user_id: Uuid,
    ) -> Result<DashboardShareResult, DashboardRepositoryError> {
        // Get the dashboard
        let dashboard = self.find_by_id(id).await?;

        // Get old groups before change
        let old_groups = self.get_shared_groups(id).await?;
        let old_group_ids: Vec<Uuid> = old_groups.iter().map(|g| g.id).collect();

        // Determine new groups
        let new_group_ids: Vec<Uuid> = if request.visibility == "group" {
            request.group_ids.clone().unwrap_or_default()
        } else {
            vec![]
        };

        // Find removed groups
        let removed_group_ids: Vec<Uuid> = old_group_ids
            .iter()
            .filter(|id| !new_group_ids.contains(id))
            .copied()
            .collect();

        // Get affected users (exclude owner if any)
        let exclude_user = dashboard.owner_id.unwrap_or(admin_user_id);
        let users_who_lost_access = self
            .get_users_in_groups(&removed_group_ids, exclude_user)
            .await?;

        // Update visibility
        sqlx::query(
            r#"
            UPDATE dashboards SET visibility = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&request.visibility)
        .execute(&self.pool)
        .await?;

        // Clear all dashboard_groups entries
        sqlx::query(r#"DELETE FROM dashboard_groups WHERE dashboard_id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        // Insert new dashboard_groups entries if visibility is 'group'
        if request.visibility == "group" {
            for group_id in &new_group_ids {
                sqlx::query(
                    r#"
                    INSERT INTO dashboard_groups (dashboard_id, group_id)
                    VALUES ($1, $2)
                    ON CONFLICT DO NOTHING
                    "#,
                )
                .bind(id)
                .bind(group_id)
                .execute(&self.pool)
                .await?;
            }
        }

        // Fetch the updated dashboard with context
        let dashboard_with_context = self.find_by_id_for_user(id, admin_user_id).await?;

        Ok(DashboardShareResult {
            dashboard: dashboard_with_context,
            users_who_lost_access,
        })
    }

    /// Delete a dashboard
    pub async fn delete(&self, id: Uuid) -> Result<(), DashboardRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM dashboards WHERE id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(DashboardRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Delete a dashboard, verifying ownership
    pub async fn delete_owned(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<(), DashboardRepositoryError> {
        let result = sqlx::query(
            r#"DELETE FROM dashboards WHERE id = $1 AND (owner_id = $2 OR owner_id IS NULL)"#,
        )
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DashboardRepositoryError::AccessDenied(id));
        }

        Ok(())
    }
}
