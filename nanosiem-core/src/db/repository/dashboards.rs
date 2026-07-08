// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dashboard repository for CRUD operations

use chrono::{DateTime, Utc};
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
    /// Optimistic-concurrency precondition failed: the dashboard was modified
    /// by another writer since the caller last read it (DSH9). Mapped to HTTP
    /// 409 Conflict by the handler.
    #[error("Dashboard was modified by another update: {0}")]
    Conflict(Uuid),
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

    /// Get shared groups for many dashboards in a single query, keyed by
    /// dashboard id (DSH42). Dashboards with no group rows are absent from the
    /// map, so callers should default to an empty vec. Lets list endpoints
    /// populate `shared_groups` without an N+1 per-dashboard fetch.
    pub async fn get_shared_groups_for_dashboards(
        &self,
        dashboard_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, Vec<DashboardSharedGroup>>, DashboardRepositoryError>
    {
        use std::collections::HashMap;

        if dashboard_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = sqlx::query_as::<_, (Uuid, Uuid, String)>(
            r#"
            SELECT dg.dashboard_id, g.id, g.name
            FROM dashboard_groups dg
            JOIN groups g ON g.id = dg.group_id
            WHERE dg.dashboard_id = ANY($1)
            ORDER BY g.name
            "#,
        )
        .bind(dashboard_ids)
        .fetch_all(&self.pool)
        .await?;

        let mut map: HashMap<Uuid, Vec<DashboardSharedGroup>> = HashMap::new();
        for (dashboard_id, group_id, group_name) in rows {
            map.entry(dashboard_id)
                .or_default()
                .push(DashboardSharedGroup {
                    id: group_id,
                    name: group_name,
                });
        }

        Ok(map)
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

        self.context_from_with_owner(dashboard, user_id).await
    }

    /// Build a `DashboardWithContext` from an already-fetched `DashboardWithOwner`
    /// WITHOUT an access check. Callers requiring authorization must check first
    /// (e.g. `find_by_id_for_user`); the admin share path uses this directly
    /// because the admin is already authorized and may not have view access to
    /// the dashboard it just mutated (DSH11).
    async fn context_from_with_owner(
        &self,
        dashboard: DashboardWithOwner,
        viewer_user_id: Uuid,
    ) -> Result<DashboardWithContext, DashboardRepositoryError> {
        let shared_groups = self.get_shared_groups(dashboard.id).await?;
        let is_owner = dashboard.owner_id == Some(viewer_user_id);

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

    /// Update a dashboard (no ownership check — internal/legacy callers only).
    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdateDashboard,
    ) -> Result<Dashboard, DashboardRepositoryError> {
        self.apply_update(id, update, None).await
    }

    /// Apply the field update atomically, honoring the optimistic-concurrency
    /// precondition and the tri-state clearable fields.
    ///
    /// - `description`/`refresh_interval` are `Option<Option<_>>`: `None` leaves
    ///   the column untouched, `Some(None)` clears it to NULL, `Some(Some(v))`
    ///   sets it (DSH13).
    /// - When `expected_updated_at` is `Some`, the write is gated on the row's
    ///   `updated_at` still matching; a mismatch (or a concurrent delete)
    ///   yields `Conflict` (DSH9). When `None`, it behaves as an unconditional
    ///   update.
    async fn apply_update(
        &self,
        id: Uuid,
        update: &UpdateDashboard,
        expected_updated_at: Option<DateTime<Utc>>,
    ) -> Result<Dashboard, DashboardRepositoryError> {
        // Decompose the tri-state clearable fields into (should_set, value).
        let (set_description, description) = match &update.description {
            None => (false, None),
            Some(value) => (true, value.clone()),
        };
        let (set_refresh, refresh_interval) = match update.refresh_interval {
            None => (false, None),
            Some(value) => (true, value),
        };

        let result = sqlx::query_as::<_, Dashboard>(
            r#"
            UPDATE dashboards SET
                name = COALESCE($2, name),
                description = CASE WHEN $3 THEN $4::text ELSE description END,
                layout = COALESCE($5, layout),
                panels = COALESCE($6, panels),
                refresh_interval = CASE WHEN $7 THEN $8::integer ELSE refresh_interval END,
                updated_at = NOW()
            WHERE id = $1 AND ($9::timestamptz IS NULL OR updated_at = $9)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(set_description)
        .bind(description)
        .bind(&update.layout)
        .bind(&update.panels)
        .bind(set_refresh)
        .bind(refresh_interval)
        .bind(expected_updated_at)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(dashboard) => Ok(dashboard),
            None => {
                // No row updated: either the id no longer exists, or the
                // optimistic-concurrency precondition failed. Disambiguate with
                // a light existence probe so the caller gets NotFound vs Conflict.
                let exists: Option<Uuid> =
                    sqlx::query_scalar(r#"SELECT id FROM dashboards WHERE id = $1"#)
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                if exists.is_some() {
                    Err(DashboardRepositoryError::Conflict(id))
                } else {
                    Err(DashboardRepositoryError::NotFound(id))
                }
            }
        }
    }

    /// Update a dashboard, verifying the caller is the owner (DSH2).
    ///
    /// Public/legacy (owner-less) dashboards are no longer world-editable —
    /// non-owners are rejected. Admins edit foreign/legacy dashboards through
    /// `update_as_admin`. `expected_updated_at` enables optimistic concurrency
    /// (DSH9).
    pub async fn update_owned(
        &self,
        id: Uuid,
        user_id: Uuid,
        update: &UpdateDashboard,
        expected_updated_at: Option<DateTime<Utc>>,
    ) -> Result<Dashboard, DashboardRepositoryError> {
        let dashboard = self.find_by_id(id).await?;

        if dashboard.owner_id != Some(user_id) {
            return Err(DashboardRepositoryError::AccessDenied(id));
        }

        self.apply_update(id, update, expected_updated_at).await
    }

    /// Update a dashboard as an admin, bypassing the ownership check (DSH2).
    ///
    /// The caller must already be authorized (SETTINGS_SYSTEM checked at the
    /// handler). `expected_updated_at` enables optimistic concurrency (DSH9).
    pub async fn update_as_admin(
        &self,
        id: Uuid,
        update: &UpdateDashboard,
        expected_updated_at: Option<DateTime<Utc>>,
    ) -> Result<Dashboard, DashboardRepositoryError> {
        // Ensure the dashboard exists so a missing id surfaces as NotFound even
        // when no version precondition is supplied.
        self.find_by_id(id).await?;
        self.apply_update(id, update, expected_updated_at).await
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

        // Apply the visibility change and group rewrite atomically (DSH12) so a
        // mid-sequence failure can't leave visibility='group' with missing rows.
        self.apply_share_mutation(id, &request.visibility, &new_group_ids)
            .await?;

        // Fetch the updated dashboard with context (owner always retains access).
        let dashboard_with_context = self.find_by_id_for_user(id, user_id).await?;

        Ok(DashboardShareResult {
            dashboard: dashboard_with_context,
            users_who_lost_access,
        })
    }

    /// Apply a share change (visibility + group membership rewrite) inside a
    /// single transaction so it is all-or-nothing (DSH12).
    async fn apply_share_mutation(
        &self,
        id: Uuid,
        visibility: &str,
        new_group_ids: &[Uuid],
    ) -> Result<(), DashboardRepositoryError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            r#"
            UPDATE dashboards SET visibility = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(visibility)
        .execute(&mut *tx)
        .await?;

        sqlx::query(r#"DELETE FROM dashboard_groups WHERE dashboard_id = $1"#)
            .bind(id)
            .execute(&mut *tx)
            .await?;

        if visibility == "group" {
            for group_id in new_group_ids {
                sqlx::query(
                    r#"
                    INSERT INTO dashboard_groups (dashboard_id, group_id)
                    VALUES ($1, $2)
                    ON CONFLICT DO NOTHING
                    "#,
                )
                .bind(id)
                .bind(group_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;
        Ok(())
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

        // Apply the visibility change and group rewrite atomically (DSH12).
        self.apply_share_mutation(id, &request.visibility, &new_group_ids)
            .await?;

        // Rebuild the context WITHOUT an access check (DSH11): the admin is
        // already authorized and may have just made the dashboard private or a
        // group they don't belong to. Running `find_by_id_for_user` here would
        // 403 AFTER the mutation committed, reporting a real success as failure
        // and skipping the audit emit.
        let updated = self.find_by_id_with_owner(id).await?;
        let dashboard_with_context = self.context_from_with_owner(updated, admin_user_id).await?;

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

    /// Delete a dashboard, verifying the caller is the owner (DSH2).
    ///
    /// Legacy (owner-less) dashboards are no longer deletable by arbitrary
    /// users — they must be removed through `delete_as_admin`.
    pub async fn delete_owned(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<(), DashboardRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM dashboards WHERE id = $1 AND owner_id = $2"#)
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(DashboardRepositoryError::AccessDenied(id));
        }

        Ok(())
    }

    /// Delete a dashboard as an admin, bypassing the ownership check (DSH2).
    ///
    /// The caller must already be authorized (SETTINGS_SYSTEM checked at the
    /// handler). Mirrors `share_as_admin`/`update_as_admin`.
    pub async fn delete_as_admin(&self, id: Uuid) -> Result<(), DashboardRepositoryError> {
        self.delete(id).await
    }
}
