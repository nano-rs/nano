// SPDX-License-Identifier: AGPL-3.0-or-later

//! Settings endpoint handlers
//!
//! Split into focused submodules by domain:
//! - `retention` — PostgreSQL retention + ClickHouse storage
//! - `risk` — risk weight + decay + notable thresholds
//! - `tiering` — S3 warm/cold storage tiering
//! - `ai_providers` — multi-provider AI config, models, agents, catalog
//! - `operational` — org context, health monitoring, developer settings, search admission
//! - `webhooks` — webhook CRUD + test + deliveries
//! - `tier` — organization tier + usage

// AI provider credentials, agent-model bindings, and the model catalog all
// live in the enterprise meloD stack — they touch `state.melod_service` and
// `state.agent_config_registry`, both of which are cfg-gated. Open-core builds
// drop the entire `ai_providers` surface; the OpenAPI spec lists the same
// endpoints only on the enterprise build.
#[cfg(feature = "enterprise")]
mod ai_providers;
// NAN-3226: dedicated "Internal domains" (enterprise migration 9011200).
#[cfg(feature = "enterprise")]
mod internal_domains;
mod operational;
mod retention;
mod risk;
mod tier;
mod tiering;
mod webhooks;

#[cfg(feature = "enterprise")]
pub use ai_providers::*;
#[cfg(feature = "enterprise")]
pub use internal_domains::*;
pub use operational::*;
pub use retention::*;
pub use risk::*;
pub use tier::*;
pub use tiering::*;
pub use webhooks::*;

use crate::error::ApiError;
use crate::state::AppState;

/// Guard: reject mutations when settings are platform-owned.
///
/// Only the `ai_providers` submodule consumes this in open-core builds —
/// keeping the cfg-gate avoids a dead-code warning when ai_providers is gated
/// out.
#[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
fn check_not_managed(state: &AppState) -> Result<(), ApiError> {
    #[cfg(feature = "enterprise")]
    let shared_profile = state.config.deployment_mode.is_enterprise_shared();
    #[cfg(not(feature = "enterprise"))]
    let shared_profile = false;
    if state.config.deployment_mode.is_managed() || shared_profile {
        return Err(ApiError::Forbidden(
            "This setting is managed by the platform and cannot be modified. Contact support for changes.".to_string()
        ));
    }
    Ok(())
}

/// Dedicated ClickHouse/SystemSettings retention and tiering are process-wide.
/// They are never tenant authority in hosted shared: exposing even the
/// read endpoints would disclose another tenant's/global storage state, while
/// mutation or manual-run endpoints could destroy unrelated data. The shared
/// read-only plan view must come from the exact tenant retention revision.
#[cfg(feature = "enterprise")]
pub(super) fn reject_enterprise_shared_storage_settings(state: &AppState) -> Result<(), ApiError> {
    if state.config.deployment_mode.is_enterprise_shared() {
        return Err(ApiError::Forbidden(
            "Enterprise-shared retention is plan-authoritative and cannot use global retention or tiering settings"
                .to_string(),
        ));
    }
    Ok(())
}

// ============================================================================
// OpenAPI Documentation
// ============================================================================

/// Settings API documentation
pub struct SettingsApiDoc;

#[cfg(feature = "enterprise")]
impl utoipa::OpenApi for SettingsApiDoc {
    fn openapi() -> utoipa::openapi::OpenApi {
        use nanosiem_core::settings::UpdateTieringRequest;
        use utoipa::OpenApi;

        #[derive(OpenApi)]
        #[openapi(
            paths(
                retention::get_retention_config,
                retention::update_retention_config,
                retention::get_storage_stats,
                retention::run_retention_now,
                risk::get_risk_config,
                risk::update_risk_config,
                risk::get_risk_decay_config,
                risk::update_risk_decay_config,
                risk::get_risk_notable_config,
                internal_domains::get_internal_domains,
                internal_domains::update_internal_domains,
                risk::update_risk_notable_config,
                retention::get_storage_overview,
                retention::get_clickhouse_storage_stats,
                retention::update_clickhouse_retention,
                retention::run_clickhouse_retention_now,
                tiering::get_tiering_config,
                tiering::update_tiering_config,
                tiering::set_tiering_credentials,
                tiering::test_tiering_connection,
                tiering::apply_tiering_config,
                tiering::get_tier_stats,
                operational::get_organizational_context,
                operational::update_organizational_context,
                // ai_providers + risk_decay endpoints below are enterprise-only.
                ai_providers::get_ai_availability,
                ai_providers::list_ai_providers,
                ai_providers::get_ai_provider,
                ai_providers::update_ai_provider,
                ai_providers::validate_ai_provider,
                ai_providers::list_agent_model_configs,
                ai_providers::get_agent_model_config,
                ai_providers::update_agent_model_config,
                ai_providers::list_available_models,
                ai_providers::list_all_available_models,
                ai_providers::create_available_model,
                ai_providers::update_available_model,
                ai_providers::delete_available_model,
                ai_providers::sync_model_catalog,
                ai_providers::get_model_catalog_status,
                operational::get_health_monitoring_settings,
                operational::update_health_monitoring_settings,
                operational::get_developer_settings,
                operational::update_developer_settings,
                webhooks::list_webhooks,
                webhooks::create_webhook,
                webhooks::get_webhook,
                webhooks::update_webhook,
                webhooks::delete_webhook,
                webhooks::test_webhook,
                webhooks::list_webhook_deliveries,
                webhooks::get_notification_config,
                webhooks::update_notification_config,
                operational::get_search_admission_settings,
                operational::update_search_admission_settings,
                operational::get_search_query_limits,
                operational::update_search_query_limits,
                tier::get_tier_status,
                tier::set_tier,
                tier::update_tier_limits,
                tier::get_usage_history,
                tier::get_ai_usage_detail,
            ),
            components(
                schemas(
                    retention::RetentionConfigResponse,
                    retention::UpdateRetentionRequest,
                    retention::StorageStatsResponse,
                    risk::RiskConfigResponse,
                    risk::UpdateRiskConfigRequest,
                    risk::RiskDecayConfigResponse,
                    risk::UpdateRiskDecayConfigRequest,
                    nanosiem_core::risk::RiskNotableConfig,
                    nanosiem_core::risk::RiskNotableTypeThresholds,
                    nanosiem_core::internal_domains::InternalDomainsSettings,
                    nanosiem_core::internal_domains::InternalDomainsDistribution,
                    nanosiem_core::internal_domains::UpdateInternalDomainsRequest,
                    nanosiem_core::internal_domains::RefusedSuffix,
                    nanosiem_core::internal_domains::SuffixRefusal,
                    retention::StorageOverviewResponse,
                    retention::ClickHouseStorageStatsResponse,
                    retention::UpdateClickHouseRetentionRequest,
                    tiering::TieringConfigResponse,
                    UpdateTieringRequest,
                    tiering::SetTieringCredentialsRequest,
                    tiering::TieringConnectionTestResponse,
                    tiering::TierStatsResponse,
                    tiering::TierInfoResponse,
                    operational::OrganizationalContextResponse,
                    operational::UpdateOrganizationalContextApiRequest,
                    ai_providers::AiAvailabilityResponse,
                    ai_providers::ProviderCredentialsResponse,
                    ai_providers::UpdateProviderCredentialsRequest,
                    ai_providers::AgentModelConfigResponse,
                    ai_providers::UpdateAgentModelConfigRequest,
                    ai_providers::AvailableModelResponse,
                    ai_providers::CreateAvailableModelRequest,
                    ai_providers::UpdateAvailableModelRequest,
                    ai_providers::ModelCatalogSyncResponse,
                    ai_providers::ModelCatalogStatusResponse,
                    operational::HealthMonitoringSettingsResponse,
                    operational::UpdateHealthMonitoringSettingsRequest,
                    operational::DeveloperSettingsResponse,
                    operational::UpdateDeveloperSettingsRequest,
                    nanosiem_core::webhooks::WebhookResponse,
                    nanosiem_core::webhooks::CreateWebhookRequest,
                    nanosiem_core::webhooks::UpdateWebhookRequest,
                    nanosiem_core::webhooks::WebhookDeliveryLog,
                    nanosiem_core::webhooks::WebhookPayload,
                    nanosiem_core::webhooks::WebhookTestResult,
                    webhooks::NotificationConfigResponse,
                    webhooks::UpdateNotificationConfigRequest,
                    nanosiem_core::settings::SearchAdmissionConfig,
                    nanosiem_core::settings::SearchQueryLimitsConfig,
                    retention::DiskPressureStatusResponse,
                    tier::TierStatusResponse,
                    tier::TierUsageResponse,
                    tier::SetTierRequest,
                    nanosiem_core::TierLimits,
                    nanosiem_core::OrganizationTier,
                    nanosiem_core::ApiAccessLevel,
                    nanosiem_core::AiModelTier,
                    nanosiem_core::AiUsage,
                    nanosiem_core::DailyUsage,
                    tier::AiUsageDetailResponse,
                    nanosiem_core::AgentUsage,
                    nanosiem_core::DailyAiUsage,
                    nanosiem_core::AiUsageEvent,
                    nanosiem_core::UpdateTierLimits,
                    nanosiem_core::TierLimitExceeded,
                    nanosiem_core::TierWarning,
                )
            ),
            tags(
                (name = "settings", description = "System settings and configuration management")
            )
        )]
        struct ApiDoc;

        ApiDoc::openapi()
    }
}

#[cfg(all(test, feature = "enterprise"))]
mod enterprise_shared_retention_route_tests {
    fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
        let marker = format!("pub async fn {name}(");
        let start = source.find(&marker).expect("handler exists");
        let tail = &source[start..];
        let end = tail[marker.len()..]
            .find("pub async fn ")
            .map(|offset| marker.len() + offset)
            .unwrap_or(tail.len());
        &tail[..end]
    }

    #[test]
    fn global_retention_and_tiering_handlers_reject_enterprise_shared_before_state_access() {
        let retention = include_str!("retention.rs");
        for name in [
            "get_retention_config",
            "update_retention_config",
            "get_storage_stats",
            "run_retention_now",
            "get_storage_overview",
            "get_clickhouse_storage_stats",
            "update_clickhouse_retention",
            "run_clickhouse_retention_now",
        ] {
            assert!(
                function_body(retention, name)
                    .contains("reject_enterprise_shared_storage_settings(&state)?"),
                "{name} must reject shared tenants before global storage access"
            );
        }

        let tiering = include_str!("tiering.rs");
        for name in [
            "get_tiering_config",
            "update_tiering_config",
            "set_tiering_credentials",
            "test_tiering_connection",
            "apply_tiering_config",
            "get_tier_stats",
        ] {
            assert!(
                function_body(tiering, name)
                    .contains("reject_enterprise_shared_storage_settings(&state)?"),
                "{name} must reject shared tenants before global tiering access"
            );
        }
    }
}

/// Open-core variant of `SettingsApiDoc`. Drops:
/// - the entire `ai_providers` surface (paths + schemas) since AI provider
///   configuration lives in the enterprise meloD stack
/// - the `risk-decay` TTL settings endpoints + schemas, which read/write
///   config consumed by `RiskAnalyticsService` (lifted to enterprise in
///   Phase 3.4 of NAN-744)
///
/// All other settings endpoints are identical to the enterprise variant.
#[cfg(not(feature = "enterprise"))]
impl utoipa::OpenApi for SettingsApiDoc {
    fn openapi() -> utoipa::openapi::OpenApi {
        use nanosiem_core::settings::UpdateTieringRequest;
        use utoipa::OpenApi;

        #[derive(OpenApi)]
        #[openapi(
            paths(
                retention::get_retention_config,
                retention::update_retention_config,
                retention::get_storage_stats,
                retention::run_retention_now,
                risk::get_risk_config,
                risk::update_risk_config,
                retention::get_storage_overview,
                retention::get_clickhouse_storage_stats,
                retention::update_clickhouse_retention,
                retention::run_clickhouse_retention_now,
                tiering::get_tiering_config,
                tiering::update_tiering_config,
                tiering::set_tiering_credentials,
                tiering::test_tiering_connection,
                tiering::apply_tiering_config,
                tiering::get_tier_stats,
                operational::get_organizational_context,
                operational::update_organizational_context,
                operational::get_health_monitoring_settings,
                operational::update_health_monitoring_settings,
                operational::get_developer_settings,
                operational::update_developer_settings,
                webhooks::list_webhooks,
                webhooks::create_webhook,
                webhooks::get_webhook,
                webhooks::update_webhook,
                webhooks::delete_webhook,
                webhooks::test_webhook,
                webhooks::list_webhook_deliveries,
                webhooks::get_notification_config,
                webhooks::update_notification_config,
                operational::get_search_admission_settings,
                operational::update_search_admission_settings,
                operational::get_search_query_limits,
                operational::update_search_query_limits,
                tier::get_tier_status,
                tier::set_tier,
                tier::update_tier_limits,
                tier::get_usage_history,
                tier::get_ai_usage_detail,
            ),
            components(
                schemas(
                    retention::RetentionConfigResponse,
                    retention::UpdateRetentionRequest,
                    retention::StorageStatsResponse,
                    risk::RiskConfigResponse,
                    risk::UpdateRiskConfigRequest,
                    retention::StorageOverviewResponse,
                    retention::ClickHouseStorageStatsResponse,
                    retention::UpdateClickHouseRetentionRequest,
                    tiering::TieringConfigResponse,
                    UpdateTieringRequest,
                    tiering::SetTieringCredentialsRequest,
                    tiering::TieringConnectionTestResponse,
                    tiering::TierStatsResponse,
                    tiering::TierInfoResponse,
                    operational::OrganizationalContextResponse,
                    operational::UpdateOrganizationalContextApiRequest,
                    operational::HealthMonitoringSettingsResponse,
                    operational::UpdateHealthMonitoringSettingsRequest,
                    operational::DeveloperSettingsResponse,
                    operational::UpdateDeveloperSettingsRequest,
                    nanosiem_core::webhooks::WebhookResponse,
                    nanosiem_core::webhooks::CreateWebhookRequest,
                    nanosiem_core::webhooks::UpdateWebhookRequest,
                    nanosiem_core::webhooks::WebhookDeliveryLog,
                    nanosiem_core::webhooks::WebhookPayload,
                    nanosiem_core::webhooks::WebhookTestResult,
                    webhooks::NotificationConfigResponse,
                    webhooks::UpdateNotificationConfigRequest,
                    nanosiem_core::settings::SearchAdmissionConfig,
                    nanosiem_core::settings::SearchQueryLimitsConfig,
                    retention::DiskPressureStatusResponse,
                    tier::TierStatusResponse,
                    tier::TierUsageResponse,
                    tier::SetTierRequest,
                    nanosiem_core::TierLimits,
                    nanosiem_core::OrganizationTier,
                    nanosiem_core::ApiAccessLevel,
                    nanosiem_core::AiModelTier,
                    nanosiem_core::AiUsage,
                    nanosiem_core::DailyUsage,
                    tier::AiUsageDetailResponse,
                    nanosiem_core::AgentUsage,
                    nanosiem_core::DailyAiUsage,
                    nanosiem_core::AiUsageEvent,
                    nanosiem_core::UpdateTierLimits,
                    nanosiem_core::TierLimitExceeded,
                    nanosiem_core::TierWarning,
                )
            ),
            tags(
                (name = "settings", description = "System settings and configuration management")
            )
        )]
        struct ApiDoc;

        ApiDoc::openapi()
    }
}
