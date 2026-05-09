// SPDX-License-Identifier: AGPL-3.0-or-later

//! Saved search repository for CRUD operations

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use uuid::Uuid;

use crate::models::{
    AffectedUser, NewSavedSearch, SavedSearch, SavedSearchWithContext, ShareResult,
    ShareSavedSearchRequest, SharedGroup, UpdateSavedSearch,
};

/// Internal struct for query results with owner name
#[derive(Debug, FromRow)]
struct SavedSearchWithOwner {
    pub id: Uuid,
    pub name: String,
    pub query: String,
    pub time_range: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub user_id: Option<Uuid>,
    pub visibility: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
    pub owner_name: Option<String>,
}

#[derive(Error, Debug)]
pub enum SavedSearchRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Saved search not found: {0}")]
    NotFound(Uuid),
    #[error("Access denied")]
    AccessDenied,
}

/// Repository for saved search operations
#[derive(Clone)]
pub struct SavedSearchRepository {
    pool: PgPool,
}

impl SavedSearchRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new saved search with ownership
    pub async fn create(
        &self,
        search: &NewSavedSearch,
        user_id: Uuid,
    ) -> Result<SavedSearch, SavedSearchRepositoryError> {
        let visibility = search.visibility.as_deref().unwrap_or("private");

        let result = sqlx::query_as::<_, SavedSearch>(
            r#"
            INSERT INTO saved_searches (name, query, time_range, user_id, visibility, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            RETURNING *
            "#,
        )
        .bind(&search.name)
        .bind(&search.query)
        .bind(&search.time_range)
        .bind(user_id)
        .bind(visibility)
        .fetch_one(&self.pool)
        .await?;

        // Add group associations if visibility is 'group'
        if visibility == "group" {
            if let Some(ref group_ids) = search.group_ids {
                for group_id in group_ids {
                    sqlx::query(
                        r#"
                        INSERT INTO saved_search_groups (saved_search_id, group_id)
                        VALUES ($1, $2)
                        ON CONFLICT DO NOTHING
                        "#,
                    )
                    .bind(result.id)
                    .bind(group_id)
                    .execute(&self.pool)
                    .await?;
                }
            }
        }

        Ok(result)
    }

    /// Find a saved search by ID with access check
    pub async fn find_by_id_for_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<SavedSearchWithContext, SavedSearchRepositoryError> {
        // Get the search with owner info
        let row = sqlx::query_as::<_, SavedSearchWithOwner>(
            r#"
            SELECT
                ss.id, ss.name, ss.query, ss.time_range, ss.created_at,
                ss.user_id, ss.visibility, ss.updated_at,
                u.name as owner_name
            FROM saved_searches ss
            LEFT JOIN users u ON u.id = ss.user_id
            WHERE ss.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SavedSearchRepositoryError::NotFound(id))?;

        // Convert to SavedSearch for access check
        let search = SavedSearch {
            id: row.id,
            name: row.name.clone(),
            query: row.query.clone(),
            time_range: row.time_range.clone(),
            created_at: row.created_at,
            user_id: row.user_id,
            visibility: row.visibility.clone(),
            updated_at: row.updated_at,
        };

        // Check access
        let has_access = self.check_user_access(&search, user_id).await?;
        if !has_access {
            return Err(SavedSearchRepositoryError::AccessDenied);
        }

        // Get shared groups
        let shared_groups = self.get_shared_groups(id).await?;

        Ok(SavedSearchWithContext {
            id: row.id,
            name: row.name,
            query: row.query,
            time_range: row.time_range,
            created_at: row.created_at,
            user_id: row.user_id,
            visibility: row.visibility.unwrap_or_else(|| "public".to_string()),
            updated_at: row.updated_at,
            is_owner: row.user_id == Some(user_id),
            owner_name: row.owner_name,
            shared_groups,
        })
    }

    /// List all saved searches visible to user (own + public + group-shared)
    pub async fn list_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SavedSearchWithContext>, SavedSearchRepositoryError> {
        // Get all searches the user can see
        let searches = sqlx::query_as::<_, SavedSearchWithOwner>(
            r#"
            SELECT DISTINCT
                ss.id, ss.name, ss.query, ss.time_range, ss.created_at,
                ss.user_id, ss.visibility, ss.updated_at,
                u.name as owner_name
            FROM saved_searches ss
            LEFT JOIN users u ON u.id = ss.user_id
            LEFT JOIN saved_search_groups ssg ON ssg.saved_search_id = ss.id
            LEFT JOIN user_groups ug ON ug.group_id = ssg.group_id AND ug.user_id = $1
            WHERE
                ss.user_id = $1  -- User owns it
                OR ss.visibility = 'public'  -- It's public
                OR (ss.visibility = 'group' AND ug.user_id IS NOT NULL)  -- User is in a shared group
            ORDER BY ss.created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::new();
        for row in searches {
            let shared_groups = self.get_shared_groups(row.id).await?;
            result.push(SavedSearchWithContext {
                id: row.id,
                name: row.name,
                query: row.query,
                time_range: row.time_range,
                created_at: row.created_at,
                user_id: row.user_id,
                visibility: row.visibility.unwrap_or_else(|| "public".to_string()),
                updated_at: row.updated_at,
                is_owner: row.user_id == Some(user_id),
                owner_name: row.owner_name,
                shared_groups,
            });
        }

        Ok(result)
    }

    /// List only searches shared with user (not owned by user)
    pub async fn list_shared_with_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SavedSearchWithContext>, SavedSearchRepositoryError> {
        let searches = sqlx::query_as::<_, SavedSearchWithOwner>(
            r#"
            SELECT DISTINCT
                ss.id, ss.name, ss.query, ss.time_range, ss.created_at,
                ss.user_id, ss.visibility, ss.updated_at,
                u.name as owner_name
            FROM saved_searches ss
            LEFT JOIN users u ON u.id = ss.user_id
            LEFT JOIN saved_search_groups ssg ON ssg.saved_search_id = ss.id
            LEFT JOIN user_groups ug ON ug.group_id = ssg.group_id AND ug.user_id = $1
            WHERE
                (ss.user_id IS NULL OR ss.user_id != $1)  -- Not owned by user
                AND (
                    ss.visibility = 'public'  -- It's public
                    OR (ss.visibility = 'group' AND ug.user_id IS NOT NULL)  -- User is in a shared group
                )
            ORDER BY ss.created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::new();
        for row in searches {
            let shared_groups = self.get_shared_groups(row.id).await?;
            result.push(SavedSearchWithContext {
                id: row.id,
                name: row.name,
                query: row.query,
                time_range: row.time_range,
                created_at: row.created_at,
                user_id: row.user_id,
                visibility: row.visibility.unwrap_or_else(|| "public".to_string()),
                updated_at: row.updated_at,
                is_owner: false,
                owner_name: row.owner_name,
                shared_groups,
            });
        }

        Ok(result)
    }

    /// List only user's own saved searches
    pub async fn list_owned_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SavedSearchWithContext>, SavedSearchRepositoryError> {
        let searches = sqlx::query_as::<_, SavedSearchWithOwner>(
            r#"
            SELECT
                ss.id, ss.name, ss.query, ss.time_range, ss.created_at,
                ss.user_id, ss.visibility, ss.updated_at,
                u.name as owner_name
            FROM saved_searches ss
            LEFT JOIN users u ON u.id = ss.user_id
            WHERE ss.user_id = $1
            ORDER BY ss.created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::new();
        for row in searches {
            let shared_groups = self.get_shared_groups(row.id).await?;
            result.push(SavedSearchWithContext {
                id: row.id,
                name: row.name,
                query: row.query,
                time_range: row.time_range,
                created_at: row.created_at,
                user_id: row.user_id,
                visibility: row.visibility.unwrap_or_else(|| "private".to_string()),
                updated_at: row.updated_at,
                is_owner: true,
                owner_name: row.owner_name,
                shared_groups,
            });
        }

        Ok(result)
    }

    /// List all saved searches (legacy, no user context)
    pub async fn list(&self) -> Result<Vec<SavedSearch>, SavedSearchRepositoryError> {
        let results = sqlx::query_as::<_, SavedSearch>(
            r#"SELECT * FROM saved_searches ORDER BY created_at DESC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Find a saved search by ID (legacy, no user context)
    pub async fn find_by_id(&self, id: Uuid) -> Result<SavedSearch, SavedSearchRepositoryError> {
        let result =
            sqlx::query_as::<_, SavedSearch>(r#"SELECT * FROM saved_searches WHERE id = $1"#)
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(SavedSearchRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Search saved searches by name
    pub async fn search_by_name(
        &self,
        name_pattern: &str,
    ) -> Result<Vec<SavedSearch>, SavedSearchRepositoryError> {
        let results = sqlx::query_as::<_, SavedSearch>(
            r#"SELECT * FROM saved_searches WHERE name ILIKE $1 ORDER BY created_at DESC"#,
        )
        .bind(format!("%{}%", name_pattern))
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Update a saved search (owner only)
    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdateSavedSearch,
        user_id: Uuid,
    ) -> Result<SavedSearch, SavedSearchRepositoryError> {
        // Check ownership
        let existing = self.find_by_id(id).await?;
        if existing.user_id != Some(user_id) {
            return Err(SavedSearchRepositoryError::AccessDenied);
        }

        let result = sqlx::query_as::<_, SavedSearch>(
            r#"
            UPDATE saved_searches SET
                name = COALESCE($2, name),
                query = COALESCE($3, query),
                time_range = COALESCE($4, time_range),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(&update.query)
        .bind(&update.time_range)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Delete a saved search (owner only)
    pub async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<(), SavedSearchRepositoryError> {
        // Check ownership
        let existing = self.find_by_id(id).await?;
        if existing.user_id != Some(user_id) {
            return Err(SavedSearchRepositoryError::AccessDenied);
        }

        let result = sqlx::query(r#"DELETE FROM saved_searches WHERE id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(SavedSearchRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Share a saved search (change visibility and groups)
    /// Returns the updated search and a list of users who lost access
    pub async fn share(
        &self,
        id: Uuid,
        request: &ShareSavedSearchRequest,
        user_id: Uuid,
    ) -> Result<ShareResult, SavedSearchRepositoryError> {
        // Check ownership
        let existing = self.find_by_id(id).await?;
        if existing.user_id != Some(user_id) {
            return Err(SavedSearchRepositoryError::AccessDenied);
        }

        // Get current groups BEFORE the change (to track who loses access)
        let old_groups = self.get_shared_groups(id).await?;
        let old_group_ids: std::collections::HashSet<Uuid> =
            old_groups.iter().map(|g| g.id).collect();

        // Determine new group IDs
        let new_group_ids: std::collections::HashSet<Uuid> = if request.visibility == "group" {
            request
                .group_ids
                .as_ref()
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        };

        // Find groups that are being REMOVED (were shared, now aren't)
        let removed_group_ids: Vec<Uuid> =
            old_group_ids.difference(&new_group_ids).copied().collect();

        // Get users in removed groups who will lose access (excluding the owner)
        let users_who_lost_access = if !removed_group_ids.is_empty() {
            self.get_users_in_groups(&removed_group_ids, user_id)
                .await?
        } else {
            Vec::new()
        };

        // Update visibility
        sqlx::query(
            r#"
            UPDATE saved_searches
            SET visibility = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&request.visibility)
        .execute(&self.pool)
        .await?;

        // Clear existing group associations
        sqlx::query(r#"DELETE FROM saved_search_groups WHERE saved_search_id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        // Add new group associations if visibility is 'group'
        if request.visibility == "group" {
            if let Some(ref group_ids) = request.group_ids {
                for group_id in group_ids {
                    sqlx::query(
                        r#"
                        INSERT INTO saved_search_groups (saved_search_id, group_id)
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
        }

        // Return updated search with context and affected users
        let search = self.find_by_id_for_user(id, user_id).await?;
        Ok(ShareResult {
            search,
            users_who_lost_access,
        })
    }

    /// Get users in the specified groups (excluding a specific user, e.g., the owner)
    async fn get_users_in_groups(
        &self,
        group_ids: &[Uuid],
        exclude_user_id: Uuid,
    ) -> Result<Vec<AffectedUser>, SavedSearchRepositoryError> {
        if group_ids.is_empty() {
            return Ok(Vec::new());
        }

        let users = sqlx::query_as::<_, (Uuid, String, String)>(
            r#"
            SELECT DISTINCT u.id, u.name, u.email
            FROM users u
            JOIN user_groups ug ON ug.user_id = u.id
            WHERE ug.group_id = ANY($1) AND u.id != $2
            "#,
        )
        .bind(group_ids)
        .bind(exclude_user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(users
            .into_iter()
            .map(|(user_id, user_name, user_email)| AffectedUser {
                user_id,
                user_name,
                user_email,
            })
            .collect())
    }

    /// Check if a user has access to a saved search
    async fn check_user_access(
        &self,
        search: &SavedSearch,
        user_id: Uuid,
    ) -> Result<bool, SavedSearchRepositoryError> {
        // Owner always has access
        if search.user_id == Some(user_id) {
            return Ok(true);
        }

        // Public searches are visible to all
        if search.visibility.as_deref() == Some("public") {
            return Ok(true);
        }

        // For group visibility, check if user is in any shared group
        if search.visibility.as_deref() == Some("group") {
            let count: (i64,) = sqlx::query_as(
                r#"
                SELECT COUNT(*)
                FROM saved_search_groups ssg
                JOIN user_groups ug ON ug.group_id = ssg.group_id
                WHERE ssg.saved_search_id = $1 AND ug.user_id = $2
                "#,
            )
            .bind(search.id)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;

            return Ok(count.0 > 0);
        }

        // Private searches - only owner has access
        Ok(false)
    }

    /// Get shared groups for a saved search
    async fn get_shared_groups(
        &self,
        search_id: Uuid,
    ) -> Result<Vec<SharedGroup>, SavedSearchRepositoryError> {
        let groups = sqlx::query_as::<_, (Uuid, String)>(
            r#"
            SELECT g.id, g.name
            FROM groups g
            JOIN saved_search_groups ssg ON ssg.group_id = g.id
            WHERE ssg.saved_search_id = $1
            "#,
        )
        .bind(search_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(groups
            .into_iter()
            .map(|(id, name)| SharedGroup { id, name })
            .collect())
    }
}
