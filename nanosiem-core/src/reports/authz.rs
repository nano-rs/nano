// SPDX-License-Identifier: AGPL-3.0-or-later

//! Run-time authorization for scheduled reports (NAN-2065).
//!
//! Report definitions are durable, but their authorization is not: every
//! execution must re-resolve the owner's current account state, capabilities,
//! and (for dashboard reports) object ACL. This resolver deliberately bypasses
//! the request permission cache so a scheduler cannot keep executing after a
//! role or dashboard share is revoked.

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::permissions;
use crate::db::repository::DashboardRepositoryError;
use crate::{Dashboard, DashboardRepository};

use super::{ReportDefinition, ReportSourceType};

/// Maximum number of dashboard panels classified and executed for one report.
///
/// The authorization classifier and runner share this cap so an ignored panel
/// cannot demand (or avoid) a capability the production path never uses.
pub(super) const MAX_DASHBOARD_PANELS: usize = 50;

/// Authorization failure classification shared by the scheduler and API.
#[derive(Debug, Error)]
pub enum ReportAuthorizationError {
    /// The current authorization facts were resolved and do not allow access.
    #[error("{0}")]
    Denied(String),
    /// Authorization facts could not be resolved. Callers must fail closed.
    #[error("{0}")]
    Resolution(String),
}

/// Required capabilities for a report operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportAuthorizationIntent {
    Execute,
    Read,
}

/// Whether this exact stored panel would reach the report runner's raw-SQL arm.
///
/// Keep this predicate shared with `ReportService::run_panel`: capability
/// classification and execution must not drift into different interpretations
/// of malformed, empty, or unsupported metric widgets.
pub fn dashboard_panel_executes_search_sql(panel: &serde_json::Value) -> bool {
    let visualization_type = panel
        .get("visualizationType")
        .and_then(|value| value.as_str())
        .unwrap_or("table");
    let is_metric = visualization_type == "obs_metric"
        || panel
            .get("metricConfig")
            .is_some_and(|value| !value.is_null());
    if is_metric {
        return false;
    }
    let has_query = panel
        .get("query")
        .and_then(|value| value.as_str())
        .is_some_and(|query| !query.trim().is_empty());
    has_query && panel.get("queryMode").and_then(|value| value.as_str()) == Some("sql")
}

/// Whether any panel in a dashboard can execute through the raw-SQL path.
pub fn dashboard_executes_search_sql(dashboard: &Dashboard) -> bool {
    dashboard
        .panels
        .as_array()
        .is_some_and(|panels| {
            panels
                .iter()
                .take(MAX_DASHBOARD_PANELS)
                .any(dashboard_panel_executes_search_sql)
        })
}

/// Current dashboard object authorization facts used by request handlers and
/// execution authorization.
#[derive(Debug, Clone)]
pub struct ReportDashboardAuthorization {
    dashboard: Dashboard,
    requires_search_sql: bool,
}

impl ReportDashboardAuthorization {
    pub fn dashboard(&self) -> &Dashboard {
        &self.dashboard
    }

    pub fn requires_search_sql(&self) -> bool {
        self.requires_search_sql
    }
}

/// Authorized source snapshot for one report execution.
///
/// Dashboard execution consumes this exact snapshot instead of reloading the
/// object after authorization, closing the ACL/query-mode check-to-use window.
#[derive(Debug, Clone)]
pub struct ReportExecutionAuthorization {
    dashboard: Option<ReportDashboardAuthorization>,
}

impl ReportExecutionAuthorization {
    fn search() -> Self {
        Self { dashboard: None }
    }

    fn dashboard(authorization: ReportDashboardAuthorization) -> Self {
        Self {
            dashboard: Some(authorization),
        }
    }

    pub fn dashboard_authorization(&self) -> Option<&ReportDashboardAuthorization> {
        self.dashboard.as_ref()
    }

    pub fn requires_search_sql(&self) -> bool {
        self.dashboard
            .as_ref()
            .is_some_and(ReportDashboardAuthorization::requires_search_sql)
    }
}

/// Return all capabilities required for the source and operation.
///
/// This is shared with request handlers so JWT and API-key callers receive the
/// same source-aware gates as the scheduler's owner identity.
pub fn required_report_permissions(
    source_type: ReportSourceType,
    intent: ReportAuthorizationIntent,
) -> &'static [&'static str] {
    match (source_type, intent) {
        (ReportSourceType::Search, ReportAuthorizationIntent::Execute) => {
            &[permissions::SEARCH_EXECUTE]
        }
        (ReportSourceType::Dashboard, ReportAuthorizationIntent::Execute) => {
            &[permissions::SEARCH_EXECUTE, permissions::DASHBOARDS_VIEW]
        }
        (ReportSourceType::Search, ReportAuthorizationIntent::Read) => &[permissions::SEARCH_VIEW],
        (ReportSourceType::Dashboard, ReportAuthorizationIntent::Read) => {
            &[permissions::SEARCH_VIEW, permissions::DASHBOARDS_VIEW]
        }
    }
}

/// Authoritative, no-cache authorization resolver for durable report owners.
#[derive(Clone)]
pub struct ReportAuthorizer {
    pool: PgPool,
}

impl ReportAuthorizer {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Re-authorize a report immediately before execution.
    pub async fn authorize_execution(
        &self,
        definition: &ReportDefinition,
    ) -> Result<ReportExecutionAuthorization, ReportAuthorizationError> {
        self.ensure_owner_active(definition.owner_id).await?;
        let current_permissions = self.resolve_permissions(definition.owner_id).await?;
        for required in
            required_report_permissions(definition.source_type, ReportAuthorizationIntent::Execute)
        {
            if !current_permissions
                .iter()
                .any(|permission| permission == required)
            {
                return Err(ReportAuthorizationError::Denied(format!(
                    "report owner no longer has required permission {required}; run skipped"
                )));
            }
        }

        if definition.source_type == ReportSourceType::Search {
            return Ok(ReportExecutionAuthorization::search());
        }

        let dashboard_id = definition.source_dashboard_id.ok_or_else(|| {
            ReportAuthorizationError::Denied(
                "dashboard report no longer identifies a dashboard; run skipped".to_string(),
            )
        })?;
        let dashboard_authorization = self
            .authorize_dashboard_access(definition.owner_id, dashboard_id)
            .await?;
        if dashboard_authorization.requires_search_sql()
            && !current_permissions
                .iter()
                .any(|permission| permission == permissions::SEARCH_SQL)
        {
            return Err(ReportAuthorizationError::Denied(format!(
                "report owner no longer has required permission {}; run skipped",
                permissions::SEARCH_SQL
            )));
        }

        Ok(ReportExecutionAuthorization::dashboard(
            dashboard_authorization,
        ))
    }

    /// Check current access to a dashboard object. There is intentionally no
    /// administrator bypass: report execution must obey the same object ACL as
    /// a direct dashboard read.
    pub async fn authorize_dashboard_access(
        &self,
        user_id: Uuid,
        dashboard_id: Uuid,
    ) -> Result<ReportDashboardAuthorization, ReportAuthorizationError> {
        let repository = DashboardRepository::new(self.pool.clone());
        let dashboard = match repository.find_by_id(dashboard_id).await {
            Ok(dashboard) => dashboard,
            Err(DashboardRepositoryError::NotFound(_)) => {
                return Err(ReportAuthorizationError::Denied(
                    "the report dashboard no longer exists or is unavailable".to_string(),
                ))
            }
            Err(error) => {
                return Err(ReportAuthorizationError::Resolution(format!(
                    "could not resolve report dashboard access ({error}); failing closed"
                )))
            }
        };
        let allowed = repository
            .check_user_access(&dashboard, user_id)
            .await
            .map_err(|error| {
                ReportAuthorizationError::Resolution(format!(
                    "could not resolve report dashboard access ({error}); failing closed"
                ))
            })?;
        if !allowed {
            return Err(ReportAuthorizationError::Denied(
                "report owner no longer has access to the dashboard; run skipped".to_string(),
            ));
        }
        let requires_search_sql = dashboard_executes_search_sql(&dashboard);
        Ok(ReportDashboardAuthorization {
            dashboard,
            requires_search_sql,
        })
    }

    async fn ensure_owner_active(&self, owner_id: Uuid) -> Result<(), ReportAuthorizationError> {
        let status = sqlx::query_scalar::<_, String>("SELECT status FROM users WHERE id = $1")
            .bind(owner_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| {
                ReportAuthorizationError::Resolution(format!(
                    "could not resolve the report owner's status ({error}); failing closed"
                ))
            })?;
        match status.as_deref() {
            Some("active") => Ok(()),
            _ => Err(ReportAuthorizationError::Denied(
                "report owner disabled; run skipped".to_string(),
            )),
        }
    }

    async fn resolve_permissions(
        &self,
        owner_id: Uuid,
    ) -> Result<Vec<String>, ReportAuthorizationError> {
        sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT rp.permission_id
            FROM user_groups ug
            INNER JOIN group_roles gr ON ug.group_id = gr.group_id
            INNER JOIN role_permissions rp ON gr.role_id = rp.role_id
            WHERE ug.user_id = $1
            ORDER BY rp.permission_id
            "#,
        )
        .bind(owner_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| {
            ReportAuthorizationError::Resolution(format!(
                "could not resolve the report owner's permissions ({error}); failing closed"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn permission_matrix_is_source_and_intent_specific() {
        assert_eq!(
            required_report_permissions(
                ReportSourceType::Search,
                ReportAuthorizationIntent::Execute
            ),
            &[permissions::SEARCH_EXECUTE]
        );
        assert_eq!(
            required_report_permissions(
                ReportSourceType::Dashboard,
                ReportAuthorizationIntent::Execute
            ),
            &[permissions::SEARCH_EXECUTE, permissions::DASHBOARDS_VIEW]
        );
        assert_eq!(
            required_report_permissions(ReportSourceType::Search, ReportAuthorizationIntent::Read),
            &[permissions::SEARCH_VIEW]
        );
        assert_eq!(
            required_report_permissions(
                ReportSourceType::Dashboard,
                ReportAuthorizationIntent::Read
            ),
            &[permissions::SEARCH_VIEW, permissions::DASHBOARDS_VIEW]
        );
    }

    #[test]
    fn raw_sql_classification_matches_the_executable_panel_path() {
        for panel in [
            json!({"queryMode": "piped", "query": "error"}),
            json!({"queryMode": "sql", "query": ""}),
            json!({"queryMode": "sql", "query": "   "}),
            json!({
                "queryMode": "sql",
                "query": "SELECT 1",
                "visualizationType": "obs_metric"
            }),
            json!({
                "queryMode": "sql",
                "query": "SELECT 1",
                "metricConfig": {}
            }),
            json!({"query_mode": "sql", "query": "SELECT 1"}),
        ] {
            assert!(
                !dashboard_panel_executes_search_sql(&panel),
                "panel cannot reach raw SQL: {panel}"
            );
        }
        assert!(dashboard_panel_executes_search_sql(&json!({
            "queryMode": "sql",
            "query": "SELECT 424242 AS authorization_probe",
            "visualizationType": "table"
        })));
    }

    #[test]
    fn raw_sql_classification_obeys_the_execution_panel_cap() {
        let mut panels = vec![
            json!({
                "queryMode": "piped",
                "query": "error",
                "visualizationType": "table"
            });
            MAX_DASHBOARD_PANELS
        ];
        panels.push(json!({
            "queryMode": "sql",
            "query": "SELECT 1",
            "visualizationType": "table"
        }));
        let mut dashboard = Dashboard {
            id: Uuid::now_v7(),
            name: "panel-cap-test".to_string(),
            description: None,
            layout: json!({}),
            panels: serde_json::Value::Array(panels),
            refresh_interval: None,
            owner_id: None,
            visibility: "private".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert!(
            !dashboard_executes_search_sql(&dashboard),
            "an ignored panel beyond the execution cap must not require search:sql"
        );

        dashboard.panels[MAX_DASHBOARD_PANELS - 1] = json!({
            "queryMode": "sql",
            "query": "SELECT 1",
            "visualizationType": "table"
        });
        assert!(
            dashboard_executes_search_sql(&dashboard),
            "an executable panel inside the cap must require search:sql"
        );
    }
}
