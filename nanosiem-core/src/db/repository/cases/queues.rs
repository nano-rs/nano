// SPDX-License-Identifier: AGPL-3.0-or-later

//! Queue + queue-routing-rule repository methods (NAN-426 / NAN-427).
//!
//! Hung off `CaseRepository` so the case service can route cases on create
//! without juggling yet another repository handle. All queries are
//! hand-written (no compile-time `query!` macros) to stay consistent with
//! the rest of the cases module.

use std::collections::HashMap;

use uuid::Uuid;

use super::{CaseRepository, CaseRepositoryError};
use crate::models::queue::{
    NewQueue, NewQueueRoutingRule, Queue, QueueRoutingRule, QueueRoutingRuleUpdate, QueueUpdate,
    QueueWithMembership, QueueWithMembershipRow,
};

/// Shared SELECT for the queue-with-membership projection. Used by list,
/// get, list_for_user. Keeps the counts + name in a single round-trip.
const QUEUE_LIST_SELECT: &str = r#"
    SELECT
        q.id,
        q.group_id,
        q.kind,
        q.default_sla_tier,
        q.slack_channel,
        q.routing_priority,
        q.icon,
        q.color,
        q.is_default_landing,
        q.description,
        q.created_at,
        q.updated_at,
        g.name AS name,
        g.is_system AS is_system,
        COALESCE((
            SELECT COUNT(*) FROM user_groups ug WHERE ug.group_id = q.group_id
        ), 0)::bigint AS member_count,
        COALESCE((
            SELECT COUNT(*) FROM cases c
             WHERE c.assigned_group = q.group_id
               AND c.assigned_to IS NULL
               AND c.status IN ('open', 'in_progress')
        ), 0)::bigint AS unclaimed_count
    FROM queues q
    JOIN groups g ON g.id = q.group_id
"#;

impl CaseRepository {
    // ==================== QUEUE CRUD ====================

    /// List all queues with counts. `_user_id_for_unclaimed` is currently
    /// unused — unclaimed counts today are "queue-wide," not "queue-wide but
    /// filtered to what this user can see." The argument is wired through so
    /// a follow-up can plug in visibility filtering without another API
    /// migration.
    pub async fn list_queues(
        &self,
        _user_id_for_unclaimed: Option<Uuid>,
    ) -> Result<Vec<QueueWithMembership>, CaseRepositoryError> {
        let sql = format!(
            "{QUEUE_LIST_SELECT} ORDER BY q.routing_priority DESC, g.name ASC"
        );
        let rows = sqlx::query_as::<_, QueueWithMembershipRow>(&sql)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Fetch a single queue with counts, returning `None` when the ID is
    /// unknown (the caller decides whether that's a 404).
    pub async fn get_queue(
        &self,
        id: Uuid,
    ) -> Result<Option<QueueWithMembership>, CaseRepositoryError> {
        let sql = format!("{QUEUE_LIST_SELECT} WHERE q.id = $1");
        let row = sqlx::query_as::<_, QueueWithMembershipRow>(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(Into::into))
    }

    /// List the queues a user is on (i.e. where they're a member of the
    /// backing group). Ordered by `routing_priority` DESC so highest-tier
    /// surfaces land first in the sidebar.
    pub async fn list_queues_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<QueueWithMembership>, CaseRepositoryError> {
        let sql = format!(
            "{QUEUE_LIST_SELECT} \
             WHERE q.group_id IN (SELECT group_id FROM user_groups WHERE user_id = $1) \
             ORDER BY q.routing_priority DESC, g.name ASC"
        );
        let rows = sqlx::query_as::<_, QueueWithMembershipRow>(&sql)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Insert a new queue row. The backing group must already exist; admins
    /// pick a group in the create form.
    pub async fn create_queue(&self, input: &NewQueue) -> Result<Queue, CaseRepositoryError> {
        let kind_str = input.kind.to_string();
        let result = sqlx::query_as::<_, Queue>(
            r#"
            INSERT INTO queues (
                group_id, kind, default_sla_tier, slack_channel,
                routing_priority, icon, color, is_default_landing, description
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(input.group_id)
        .bind(&kind_str)
        .bind(&input.default_sla_tier)
        .bind(&input.slack_channel)
        .bind(input.routing_priority)
        .bind(&input.icon)
        .bind(&input.color)
        .bind(input.is_default_landing)
        .bind(&input.description)
        .fetch_one(&self.pool)
        .await?;
        Ok(result)
    }

    /// Apply a partial update. All fields use COALESCE-style patching so
    /// callers can nil out only what they care about.
    pub async fn update_queue(
        &self,
        id: Uuid,
        input: &QueueUpdate,
    ) -> Result<Queue, CaseRepositoryError> {
        let result = sqlx::query_as::<_, Queue>(
            r#"
            UPDATE queues SET
                default_sla_tier   = COALESCE($2, default_sla_tier),
                slack_channel      = COALESCE($3, slack_channel),
                routing_priority   = COALESCE($4, routing_priority),
                icon               = COALESCE($5, icon),
                color              = COALESCE($6, color),
                is_default_landing = COALESCE($7, is_default_landing),
                description        = COALESCE($8, description)
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&input.default_sla_tier)
        .bind(&input.slack_channel)
        .bind(input.routing_priority)
        .bind(&input.icon)
        .bind(&input.color)
        .bind(input.is_default_landing)
        .bind(&input.description)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::NotFound(id))?;
        Ok(result)
    }

    /// Delete a queue row. The caller is responsible for gating `is_system`
    /// — the repository layer only surfaces whether the row existed.
    pub async fn delete_queue(&self, id: Uuid) -> Result<(), CaseRepositoryError> {
        let affected = sqlx::query(r#"DELETE FROM queues WHERE id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(CaseRepositoryError::NotFound(id));
        }
        Ok(())
    }

    /// Is the backing group for a queue marked `is_system`? Service layer
    /// consults this before accepting a delete request.
    pub async fn queue_backing_group_is_system(
        &self,
        queue_id: Uuid,
    ) -> Result<Option<bool>, CaseRepositoryError> {
        let row: Option<(bool,)> = sqlx::query_as(
            r#"
            SELECT g.is_system
              FROM queues q
              JOIN groups g ON g.id = q.group_id
             WHERE q.id = $1
            "#,
        )
        .bind(queue_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(is_system,)| is_system))
    }

    /// Batch fetch of unclaimed counts. Returns a map from queue_id →
    /// count, only populating entries for queue IDs passed in.
    pub async fn unclaimed_counts(
        &self,
        queue_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, i64>, CaseRepositoryError> {
        if queue_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, i64)> = sqlx::query_as(
            r#"
            SELECT q.id, COUNT(c.id)::bigint
              FROM queues q
              LEFT JOIN cases c
                     ON c.assigned_group = q.group_id
                    AND c.assigned_to IS NULL
                    AND c.status IN ('open', 'in_progress')
             WHERE q.id = ANY($1)
             GROUP BY q.id
            "#,
        )
        .bind(queue_ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Fetch the single queue flagged `is_default_landing=true`. Partial
    /// unique index guarantees at most one row.
    pub async fn default_landing_queue(&self) -> Result<Option<Queue>, CaseRepositoryError> {
        let row = sqlx::query_as::<_, Queue>(
            r#"SELECT * FROM queues WHERE is_default_landing = true LIMIT 1"#,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    // ==================== QUEUE ROUTING RULES ====================

    /// List all routing rules ordered by priority ascending.
    pub async fn list_queue_routing_rules(
        &self,
    ) -> Result<Vec<QueueRoutingRule>, CaseRepositoryError> {
        let rows = sqlx::query_as::<_, QueueRoutingRule>(
            r#"
            SELECT * FROM queue_routing_rules
            ORDER BY priority ASC, created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// List only enabled routing rules (hot path for the case-create
    /// evaluator).
    pub async fn list_enabled_queue_routing_rules(
        &self,
    ) -> Result<Vec<QueueRoutingRule>, CaseRepositoryError> {
        let rows = sqlx::query_as::<_, QueueRoutingRule>(
            r#"
            SELECT * FROM queue_routing_rules
            WHERE enabled = true
            ORDER BY priority ASC, created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn get_queue_routing_rule(
        &self,
        id: Uuid,
    ) -> Result<Option<QueueRoutingRule>, CaseRepositoryError> {
        let row = sqlx::query_as::<_, QueueRoutingRule>(
            r#"SELECT * FROM queue_routing_rules WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn create_queue_routing_rule(
        &self,
        input: &NewQueueRoutingRule,
    ) -> Result<QueueRoutingRule, CaseRepositoryError> {
        let row = sqlx::query_as::<_, QueueRoutingRule>(
            r#"
            INSERT INTO queue_routing_rules (name, enabled, priority, queue_id, conditions)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(&input.name)
        .bind(input.enabled)
        .bind(input.priority)
        .bind(input.queue_id)
        .bind(&input.conditions)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn update_queue_routing_rule(
        &self,
        id: Uuid,
        input: &QueueRoutingRuleUpdate,
    ) -> Result<QueueRoutingRule, CaseRepositoryError> {
        let row = sqlx::query_as::<_, QueueRoutingRule>(
            r#"
            UPDATE queue_routing_rules SET
                name       = COALESCE($2, name),
                enabled    = COALESCE($3, enabled),
                priority   = COALESCE($4, priority),
                queue_id   = COALESCE($5, queue_id),
                conditions = COALESCE($6, conditions)
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&input.name)
        .bind(input.enabled)
        .bind(input.priority)
        .bind(input.queue_id)
        .bind(&input.conditions)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::NotFound(id))?;
        Ok(row)
    }

    pub async fn delete_queue_routing_rule(&self, id: Uuid) -> Result<(), CaseRepositoryError> {
        let affected = sqlx::query(r#"DELETE FROM queue_routing_rules WHERE id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(CaseRepositoryError::NotFound(id));
        }
        Ok(())
    }
}
