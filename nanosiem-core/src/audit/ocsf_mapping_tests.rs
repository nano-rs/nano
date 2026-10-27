// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3460: the platform audit → OCSF mapping table, pinned for every audit
//! action string the codebase emits, plus the SQL lockstep and the OCSF 1.9
//! contract of each class.

use super::*;
use crate::audit::{AuditEvent, AuditSource};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

/// Every audit action emitted anywhere (Rust builders and helpers, the
/// `actions.rs` constants, `CaseAuditAction`, and SQL-built rows), with its
/// OCSF class and activity. The trailing comment is the emitting source(s).
/// A new action must be added here with a deliberate classification —
/// `every_emitted_action_is_classified` fails until it is.
pub(crate) const EVERY_AUDIT_ACTION: &[(&str, i64, i64)] = &[
    ("agent_cell_feature_admission", 6003, 99), // search (agent lane admission decision)
    ("agent_cell_feature_completed", 6003, 99), // search (agent lane feature execution)
    ("agent_enrichment_created", 6003, 1), // agent_enrichment
    ("agent_enrichment_credentials_updated", 6003, 3), // agent_enrichment
    ("agent_enrichment_deleted", 6003, 4), // agent_enrichment
    ("agent_enrichment_updated", 6003, 3), // agent_enrichment
    ("agent_query_reported", 6003, 99), // search (agent gateway query execution receipt)
    ("threat_intel_lookup_fetched", 6003, 2), // agent_enrichment (NAN-3763)
    ("threat_intel_provider_installed", 6003, 1), // agent_enrichment (NAN-3763)
    ("threat_intel_provider_uninstalled", 6003, 4), // agent_enrichment (NAN-3763)
    ("threat_intel_provider_updated", 6003, 3), // agent_enrichment (NAN-3763)
    ("agent_model_config_updated", 6003, 3), // settings
    ("ai_analysis", 6003, 99), // case
    ("ai_provider_updated", 6003, 3), // settings
    ("ai_provider_validated", 6003, 99), // settings
    ("alert_acknowledged", 6003, 3), // alert
    ("alert_added", 6003, 1), // case
    ("alert_assigned", 6003, 3), // alert
    ("alert_bulk_acknowledged", 6003, 3), // alert
    ("alert_bulk_closed", 6003, 3), // alert
    ("alert_closed", 6003, 3), // alert
    ("alert_removed", 6003, 4), // case
    ("apikey_authenticated", 3002, 1), // apikey
    ("apikey_created", 6003, 1), // apikey
    ("apikey_deleted", 6003, 4), // apikey
    ("apikey_disabled", 6003, 3), // apikey
    ("apikey_enabled", 6003, 3), // apikey
    ("apikey_rate_limited", 6003, 99), // apikey
    ("apikey_reset", 6003, 3), // apikey
    ("apikey_revoked", 6003, 4), // apikey
    ("apikey_rotated", 6003, 3), // apikey
    ("apikey_updated", 6003, 3), // apikey
    ("artifact_created", 6003, 1), // artifact
    ("artifact_deleted", 6003, 4), // artifact
    ("artifact_updated", 6003, 3), // artifact
    ("assigned", 6003, 3), // case
    ("audit_logs_exported", 6003, 2), // audit
    ("auth_denied", 6003, 99), // auth
    ("auth_session_created", 3002, 1), // auth
    ("auth_session_refreshed", 3002, 5), // auth
    ("auth_session_removed", 3002, 2), // auth
    ("auth_tenant_session_fence_changed", 6003, 3), // auth
    ("auth_tenant_sessions_revoked", 6003, 4), // auth
    ("auto_sync_configured", 6003, 3), // enrichment
    ("available_model_created", 6003, 1), // settings
    ("available_model_deleted", 6003, 4), // settings
    ("available_model_updated", 6003, 3), // settings
    ("case_alert_added", 6003, 1), // case
    ("case_alert_removed", 6003, 4), // case
    ("case_assigned", 6003, 3), // case
    ("case_bulk_status_changed", 6003, 3), // case
    ("case_created", 6003, 1), // case
    ("case_deleted", 6003, 4), // case
    ("case_escalated", 6003, 3), // case
    ("case_grouping_rule_created", 6003, 1), // case
    ("case_grouping_rule_deleted", 6003, 4), // case
    ("case_grouping_rule_updated", 6003, 3), // case
    ("case_handoff_accepted", 6003, 3), // case
    ("case_handoff_bounced", 6003, 99), // case
    ("case_handoff_canceled", 6003, 3), // case
    ("case_handoff_sent", 6003, 99), // case
    ("case_merged", 6003, 3), // case
    ("case_notebook_linked", 6003, 3), // case
    ("case_notebook_merged", 6003, 3), // case
    ("case_notebook_unlinked", 6003, 3), // case
    ("case_saved_search_created", 6003, 1), // case
    ("case_saved_search_deleted", 6003, 4), // case
    ("case_saved_search_updated", 6003, 3), // case
    ("case_settings_updated", 6003, 3), // case
    ("case_shared", 6003, 3), // case
    ("case_status_changed", 6003, 3), // case
    ("case_updated", 6003, 3), // case
    ("ch_retention_run_triggered", 6003, 99), // settings
    ("ch_retention_updated", 6003, 3), // settings
    ("closed", 6003, 3), // case
    ("comment_added", 6003, 1), // case
    ("created", 6003, 1), // case
    ("credential_created", 6003, 1), // credentials
    ("credential_deleted", 6003, 4), // credentials
    ("credential_rolled_back", 6003, 3), // credentials
    ("credential_rotated", 6003, 3), // credentials
    ("credential_updated", 6003, 3), // credentials
    ("custom_enrichment_created", 6003, 1), // custom_enrichment
    ("custom_enrichment_deleted", 6003, 4), // custom_enrichment
    ("custom_enrichment_deployed", 6003, 3), // custom_enrichment
    ("custom_enrichment_disabled", 6003, 3), // custom_enrichment
    ("custom_enrichment_execution_refused", 6003, 99), // custom_enrichment
    ("custom_enrichment_run_triggered", 6003, 99), // custom_enrichment
    ("custom_enrichment_updated", 6003, 3), // custom_enrichment
    ("custom_integration_code_generated", 6003, 1), // log_source
    ("custom_integration_created", 6003, 1), // log_source
    ("custom_integration_deleted", 6003, 4), // log_source
    ("custom_integration_previewed", 6003, 2), // log_source
    ("custom_integration_updated", 6003, 3), // log_source
    ("dashboard_created", 6003, 1), // dashboard
    ("dashboard_deleted", 6003, 4), // dashboard
    ("dashboard_exported", 6003, 2), // dashboard
    ("dashboard_imported", 6003, 1), // dashboard
    ("dashboard_shared", 6003, 3), // dashboard
    ("dashboard_updated", 6003, 3), // dashboard
    ("detection_code_pr_opened", 6003, 1), // tuning
    ("detection_code_target_connection_tested", 6003, 99), // rule_repo
    ("detection_code_target_created", 6003, 1), // detection,rule_repo
    ("detection_code_target_deleted", 6003, 4), // detection,rule_repo
    ("detection_code_target_token_set", 6003, 3), // detection,rule_repo
    ("detection_code_target_updated", 6003, 3), // detection,rule_repo
    ("developer_settings_updated", 6003, 3), // settings
    ("disk_pressure_critical", 6003, 99), // storage
    ("enrichment_configured", 6003, 3), // enrichment
    ("enrichment_coordinator_assigned", 6003, 3), // operator
    ("enrichment_coordinator_superseded", 6003, 3), // operator
    ("enrichment_disabled", 6003, 3), // enrichment
    ("enrichment_enabled", 6003, 3), // enrichment
    ("enrichment_synced", 6003, 3), // enrichment
    ("enterprise_shared_local_activation", 3001, 2), // auth
    ("enterprise_shared_membership_accepted", 6003, 3), // auth
    ("enterprise_shared_oidc_provider_created", 6003, 1), // auth
    ("enterprise_shared_oidc_provider_disabled", 6003, 3), // auth
    ("enterprise_shared_oidc_provider_enabled", 6003, 3), // auth
    ("enterprise_shared_oidc_provider_mutated", 6003, 3), // auth
    ("enterprise_shared_oidc_provider_retired", 6003, 3), // auth
    ("enterprise_shared_oidc_provider_secret_rotated", 6003, 3), // auth
    ("enterprise_shared_oidc_provider_updated", 6003, 3), // auth
    ("entity_added", 6003, 1), // case
    ("escalated", 6003, 3), // case
    ("feed_recovered", 6003, 99), // ingest
    ("feed_segment_dropped", 6003, 4), // ingest
    ("feed_segment_recovered", 6003, 99), // ingest
    ("feed_stale", 6003, 99), // ingest
    ("folder_icon_cleared", 6003, 4), // detection
    ("folder_icon_set", 6003, 3), // detection
    ("gdpr_anonymization_completed", 6003, 99), // gdpr
    ("gdpr_anonymization_deferred", 6003, 99), // gdpr
    ("gdpr_anonymization_failed", 6003, 99), // gdpr
    ("gdpr_anonymization_running", 6003, 99), // gdpr
    ("gdpr_anonymization_started", 6003, 99), // gdpr
    ("gdpr_anonymization_submitted", 6003, 1), // gdpr
    ("group_created", 6003, 1), // group
    ("group_deleted", 6003, 4), // group
    ("group_member_added", 6003, 1), // group
    ("group_member_removed", 6003, 4), // group
    ("group_roles_updated", 6003, 3), // group
    ("group_updated", 6003, 3), // group
    ("health_monitoring_updated", 6003, 3), // settings
    ("hec_sources_enrolled", 6003, 1), // operator
    ("hunt_drafts_created", 6003, 1), // hunt
    ("hunt_knowledge_revoked", 6003, 4), // hunt
    ("hunt_lead_dismissed", 6003, 3), // hunt
    ("hunt_lead_promoted", 6003, 3), // hunt
    ("hunt_profile_saved", 6003, 3), // hunt
    ("hunt_recon_ran", 6003, 99), // hunt
    ("hunt_report_branding_updated", 6003, 3), // hunt
    ("hunt_report_exported", 6003, 2), // hunt
    ("hunt_rule_idea_rejected", 6003, 3), // hunt
    ("hunt_rule_idea_sent", 6003, 99), // hunt
    ("hunt_runner_agy_waiver_granted", 6003, 3), // hunt
    ("hunt_runner_agy_waiver_revoked", 6003, 4), // hunt
    ("hunt_schedule_disabled", 6003, 3), // hunt
    ("hunt_schedule_enabled", 6003, 3), // hunt
    ("hunt_schedule_set", 6003, 3), // hunt
    ("hunt_source_capability_bound", 6003, 3), // hunt
    ("hunt_source_capability_reset", 6003, 3), // hunt
    ("hunt_suppression_recorded", 6003, 1), // hunt
    ("hunt_suppression_revoked", 6003, 4), // hunt
    ("iceberg_export_updated", 6003, 3), // settings
    ("identity_provider_created", 6003, 1), // identity
    ("identity_provider_credentials_updated", 6003, 3), // identity
    ("identity_provider_deleted", 6003, 4), // identity
    ("identity_provider_updated", 6003, 3), // identity
    ("identity_sync_completed", 6003, 3), // identity
    ("identity_sync_triggered", 6003, 99), // identity
    ("identity_users_pushed", 6003, 3), // identity
    ("incident_case_added", 6003, 1), // case
    ("incident_case_removed", 6003, 4), // case
    ("incident_created", 6003, 1), // case
    ("ingest_cell_activated", 6003, 3), // operator
    ("ingest_cell_enrolled", 6003, 1), // operator
    ("ingest_cell_generation_rolled", 6003, 3), // operator
    ("ingest_credential_created", 6003, 1), // the platform,operator
    ("ingest_credential_requested", 6003, 1), // ingest
    ("ingest_credential_request_fulfilled", 6003, 3), // the platform
    ("ingest_credential_request_rejected", 6003, 3), // the platform
    ("ingest_credential_requests_expired", 6003, 3), // the platform
    ("ingest_credential_revealed", 6003, 2), // ingest
    ("ingest_credential_revoked", 6003, 4), // ingest,operator,tenant
    ("ingest_install_token_updated", 6003, 3), // settings
    ("ingest_route_created", 6003, 1), // operator
    ("ingest_route_retired", 6003, 3), // operator
    ("ingest_token_bound", 6003, 3), // settings
    ("ingest_token_created", 6003, 1), // settings
    ("ingest_token_revoked", 6003, 4), // settings
    ("inputlookup_allowlist_updated", 6003, 3), // search
    ("inputlookup_egress_denied", 6003, 99), // search
    ("inputlookup_fetch", 6003, 2), // search
    ("integration_instance_created", 6003, 1), // log_source
    ("integration_instance_deleted", 6003, 4), // log_source
    ("integration_instance_updated", 6003, 3), // log_source
    ("integration_run_triggered", 6003, 99), // log_source
    ("internal_domains_updated", 6003, 3), // settings
    ("ioc_list_created", 6003, 1), // enrichment
    ("ioc_list_deleted", 6003, 4), // enrichment
    ("ioc_list_published", 6003, 3), // enrichment
    ("ioc_list_updated", 6003, 3), // enrichment
    ("ip_allowlist_created", 6003, 1), // settings
    ("ip_allowlist_deleted", 6003, 4), // settings
    ("ip_allowlist_updated", 6003, 3), // settings
    ("ip_context_batch", 6003, 99), // enrichment
    ("ip_context_source_delete", 6003, 4), // enrichment
    ("login_failed", 3002, 1), // auth
    ("login_success", 3002, 1), // auth
    ("logout", 3002, 2), // auth
    ("log_source_created", 6003, 1), // log_source,parser_repo
    ("log_source_deleted", 6003, 4), // log_source
    ("log_source_deploy_all", 6003, 3), // log_source
    ("log_source_deployed", 6003, 3), // log_source
    ("log_source_published", 6003, 3), // log_source
    ("log_source_reverted", 6003, 3), // log_source
    ("log_source_toggled", 6003, 3), // log_source
    ("log_source_undeployed", 6003, 3), // log_source
    ("log_source_updated", 6003, 3), // log_source,parser_repo
    ("lookup_rows_added", 6003, 1), // lookup
    ("lookup_rows_deleted", 6003, 4), // lookup
    ("lookup_row_updated", 6003, 3), // lookup
    ("lookup_table_created", 6003, 1), // lookup
    ("lookup_table_deleted", 6003, 4), // lookup
    ("marketplace_configured", 6003, 3), // marketplace
    ("marketplace_installed", 6003, 1), // marketplace
    ("marketplace_preview_executed", 6003, 99), // marketplace
    ("marketplace_repo_created", 6003, 1), // marketplace
    ("marketplace_repo_deleted", 6003, 4), // marketplace
    ("marketplace_repo_synced", 6003, 3), // marketplace
    ("marketplace_repo_updated", 6003, 3), // marketplace
    ("marketplace_sync_triggered", 6003, 99), // marketplace
    ("marketplace_uninstalled", 6003, 4), // marketplace
    ("marketplace_updated", 6003, 3), // marketplace
    ("melod_artifact_revision_drafted", 6003, 1), // settings (NAN-4653)
    ("melod_background_ai_ran", 6003, 99), // settings
    ("melod_config_updated", 6003, 3), // settings
    ("melod_connection_validated", 6003, 99), // settings
    ("melod_credentials_updated", 6003, 3), // settings
    ("melod_flow_drafted", 6003, 1), // settings (NAN-4535)
    ("melod_playbook_drafted", 6003, 1), // settings
    ("merged", 6003, 3), // case
    ("mfa_admin_reset", 3001, 11), // auth
    ("mfa_backup_codes_regenerated", 6003, 3), // auth
    ("mfa_backup_code_used", 3002, 6), // auth
    ("mfa_challenge_failed", 3002, 1), // auth
    ("mfa_challenge_issued", 3002, 6), // auth
    ("mfa_challenge_success", 3002, 6), // auth
    ("mfa_disabled", 3001, 11), // auth
    ("mfa_enforced_globally", 6003, 3), // auth
    ("mfa_setup_complete", 3001, 10), // auth
    ("mfa_setup_initiated", 6003, 1), // auth
    ("mitre_catalog_synced", 6003, 3), // mitre
    ("model_catalog_synced", 6003, 3), // settings
    ("notebook_created", 6003, 1), // notebook
    ("notebook_deleted", 6003, 4), // notebook
    ("notebook_entry_added", 6003, 1), // notebook
    ("notebook_entry_deleted", 6003, 4), // notebook
    ("notebook_escalated", 6003, 3), // notebook
    ("notebook_merged", 6003, 3), // notebook
    ("notebook_shared", 6003, 3), // notebook
    ("notebook_updated", 6003, 3), // notebook
    ("oidc_group_mappings_updated", 6003, 3), // oidc
    ("oidc_login", 3002, 1), // auth
    ("oidc_provider_created", 6003, 1), // oidc
    ("oidc_provider_deleted", 6003, 4), // oidc
    ("oidc_provider_disabled", 6003, 3), // oidc
    ("oidc_provider_enabled", 6003, 3), // oidc
    ("oidc_provider_updated", 6003, 3), // oidc
    ("oidc_user_provisioned", 3001, 1), // oidc
    ("org_context_updated", 6003, 3), // settings
    ("otlp_sources_enrolled", 6003, 1), // operator
    ("parser_all_removed", 6003, 4), // parser_repo
    ("parser_base_merge_requested", 6003, 1), // log_source
    ("parser_base_sources_carried_forward", 6003, 99), // log_source
    ("parser_batch_imported", 6003, 1), // parser_repo
    ("parser_bundle_activated", 6003, 3), // operator
    ("parser_bundle_promoted", 6003, 3), // operator
    ("parser_bundle_roll_abandoned", 6003, 99), // operator
    ("parser_bundle_roll_pending", 6003, 99), // operator
    ("parser_bundle_validated", 6003, 99), // operator
    ("parser_imported", 6003, 1), // parser_repo
    ("parser_platform_base_offered", 6003, 99), // operator
    ("parser_repo_created", 6003, 1), // parser_repo
    ("parser_repo_deleted", 6003, 4), // parser_repo
    ("parser_repo_synced", 6003, 3), // parser_repo
    ("parser_repo_updated", 6003, 3), // parser_repo
    ("parser_rollout_building", 6003, 99), // operator
    ("parser_rollout_failed", 6003, 99), // operator
    ("parser_rollout_requested", 6003, 1), // log_source
    ("parser_rollout_validated", 6003, 99), // operator
    ("parser_samples_updated", 6003, 3), // log_source
    ("parser_signing_key.register", 6003, 1), // operator
    ("parser_signing_key.retire", 6003, 3), // operator
    ("parser_signing_key.revoke", 6003, 4), // operator
    ("parser_upstream_applied", 6003, 3), // parser_repo
    ("partition_dropped", 6003, 4), // storage
    ("password_changed", 3001, 3), // auth
    ("password_reset_complete", 3001, 4), // auth
    ("password_reset_request", 6003, 1), // auth
    ("pipe_capture_cancel_requested", 6003, 1), // ingest
    ("pipe_capture_snapshot_read", 6003, 2), // ingest
    ("pipe_capture_started", 6003, 99), // ingest
    ("pipe_recent_events_read", 6003, 2), // ingest
    ("platform_ai_provider.set", 6003, 3), // operator
    ("playbook_run_executed", 6003, 99), // case
    ("proposal_approved", 6003, 3), // tuning
    ("proposal_rejected", 6003, 3), // tuning
    ("query_created", 6003, 1), // query_library
    ("query_deleted", 6003, 4), // query_library
    ("query_explanation_stored", 6003, 1), // search
    ("queue_created", 6003, 1), // case
    ("queue_deleted", 6003, 4), // case
    ("queue_routing_rule_created", 6003, 1), // case
    ("queue_routing_rule_deleted", 6003, 4), // case
    ("queue_routing_rule_updated", 6003, 3), // case
    ("queue_updated", 6003, 3), // case
    ("reopened", 6003, 3), // case
    ("report_created", 6003, 1), // report
    ("report_deleted", 6003, 4), // report
    ("report_run_triggered", 6003, 99), // report
    ("report_updated", 6003, 3), // report
    ("resolved", 6003, 3), // case
    ("retention_config_updated", 6003, 3), // settings
    ("retention_run_triggered", 6003, 99), // settings
    ("risk_all_cleared", 6003, 4), // risk
    ("risk_config_updated", 6003, 3), // risk,settings
    ("risk_decay_config_updated", 6003, 3), // risk,settings
    ("risk_entity_cleared", 6003, 4), // risk
    ("risk_notable_config_updated", 6003, 3), // risk,settings
    ("risk_publisher_assigned", 6003, 3), // operator
    ("risk_publisher_superseded", 6003, 3), // operator
    ("risk_watchlist_created", 6003, 1), // risk
    ("risk_watchlist_deleted", 6003, 4), // risk
    ("risk_watchlist_members_added", 6003, 1), // risk
    ("risk_watchlist_members_removed", 6003, 4), // risk
    ("risk_watchlist_updated", 6003, 3), // risk
    ("rls_context_key.region.promote", 6003, 3), // operator
    ("rls_context_key.region.register", 6003, 1), // operator
    ("rls_context_key.region.retire", 6003, 3), // operator
    ("role_created", 6003, 1), // role
    ("role_deleted", 6003, 4), // role
    ("role_updated", 6003, 3), // role
    ("routing_rule_created", 6003, 1), // case,parser_repo,source_config
    ("routing_rule_deleted", 6003, 4), // case,source_config
    ("routing_rule_reordered", 6003, 3), // source_config
    ("routing_rule_updated", 6003, 3), // case,source_config
    ("rule_all_removed", 6003, 4), // rule_repo
    ("rule_batch_imported", 6003, 1), // rule_repo
    ("rule_created", 6003, 1), // detection,rule_repo
    ("rule_deleted", 6003, 4), // detection,rule_repo
    ("rule_demoted", 6003, 3), // detection
    ("rule_duplicated", 6003, 1), // detection
    ("rule_imported", 6003, 1), // rule_repo
    ("rule_paused", 6003, 3), // detection
    ("rule_promoted", 6003, 3), // detection
    ("rule_repo_created", 6003, 1), // rule_repo
    ("rule_repo_deleted", 6003, 4), // rule_repo
    ("rule_repo_synced", 6003, 3), // rule_repo
    ("rule_repo_updated", 6003, 3), // rule_repo
    ("rule_resumed", 6003, 3), // detection
    ("rules_bulk_updated", 6003, 3), // detection
    ("rules_exported", 6003, 2), // detection
    ("rules_imported", 6003, 1), // detection
    ("rule_triggered", 6003, 99), // detection
    ("rule_updated", 6003, 3), // detection,rule_repo
    ("runtime_assignments_assigned", 6003, 3), // operator
    ("runtime_assignments_renewed", 6003, 3), // operator
    ("runtime_assignments_superseded", 6003, 3), // operator
    ("saved_search_shared", 6003, 3), // search
    ("search_history_cleared", 6003, 4), // search
    ("search_history_deleted", 6003, 4), // search
    ("search_history_disabled", 6003, 3), // search
    ("search_history_enabled", 6003, 3), // search
    ("search_job_admin_cancelled", 6003, 3), // search
    ("search_settings_updated", 6003, 3), // settings
    ("search.source_scope_denied", 6003, 99), // search
    ("session_terminated", 3002, 2), // session
    ("settings_updated", 6003, 3), // tuning
    ("severity_changed", 6003, 3), // case
    ("shared", 6003, 3), // case
    ("shared_search_created", 6003, 1), // search
    ("siem_health_suppression_recorded", 6003, 1), // settings
    ("siem_health_suppression_revoked", 6003, 4), // settings
    ("sigma_converted", 6003, 99), // rule_repo
    ("soar.run.canceled", 6003, 3), // soar
    ("source_authority_login_bound", 6003, 3), // operator
    ("source_authority_login_verified", 6003, 99), // operator
    ("source_config_created", 6003, 1), // source_config
    ("source_config_deleted", 6003, 4), // source_config
    ("source_config_deploy_all", 6003, 3), // source_config
    ("source_config_deployed", 6003, 3), // source_config
    ("source_config_toggled", 6003, 3), // source_config
    ("source_config_undeployed", 6003, 3), // source_config
    ("source_config_updated", 6003, 3), // source_config
    ("source_scope_granted", 6003, 3), // source_scope
    ("source_scope_restricted", 6003, 3), // source_scope
    ("source_scope_revoked", 6003, 4), // source_scope
    ("source_scope_unrestricted", 6003, 3), // source_scope
    ("source_visibility_bypass", 6003, 99), // source_scope
    ("source_visibility_group_set", 6003, 3), // source_scope
    ("source_visibility_member_set", 6003, 3), // source_scope
    ("sovereign_capacity_recommended", 6003, 99), // storage (capacity advisor)
    ("sso_group_grants_synchronized", 6003, 3), // oidc
    ("sso_sign_in_denied", 3002, 1), // auth
    ("status_changed", 6003, 3), // case
    ("system_health_acknowledged", 6003, 3), // settings
    ("system_health_resolved", 6003, 3), // settings
    ("system_initialized", 6003, 1), // auth
    ("system_settings_updated", 6003, 3), // oidc
    ("tiering_config_applied", 6003, 3), // settings
    ("tiering_config_updated", 6003, 3), // settings
    ("tiering_connection_tested", 6003, 99), // settings
    ("tiering_credentials_set", 6003, 3), // settings
    ("tier_limits_updated", 6003, 3), // settings
    ("tier_updated", 6003, 3), // settings
    ("token_refresh", 3002, 5), // auth
    ("tuning_reverted", 6003, 3), // tuning
    ("unassigned", 6003, 3), // case
    ("user_created", 3001, 1), // user
    ("user_deleted", 3001, 6), // user
    ("user_disabled", 3001, 5), // user
    ("user_enabled", 3001, 2), // user
    ("user_groups_updated", 6003, 3), // user
    ("user_locked", 3001, 9), // auth
    ("user_sessions_terminated", 3002, 2), // session
    ("user_unlocked", 3001, 12), // user
    ("user_updated", 6003, 3), // user
    ("version_activated", 6003, 3), // tuning
    ("version_reverted", 6003, 3), // tuning
    ("webhook_created", 6003, 1), // webhook
    ("webhook_deleted", 6003, 4), // webhook
    ("webhook_tested", 6003, 99), // settings
    ("webhook_updated", 6003, 3), // settings,webhook
];

fn golden(action: &str) -> Option<(i64, i64)> {
    EVERY_AUDIT_ACTION
        .iter()
        .find(|(name, _, _)| *name == action)
        .map(|(_, class, activity)| (*class, *activity))
}

/// An event of `action` whose account is known both ways (an actor and a
/// `user` resource), so every IAM row resolves its subject.
fn known_event(action: &str) -> AuditEvent {
    let mut event = AuditEvent::builder(AuditSource::Settings, action)
        .actor(Some(Uuid::now_v7()), Some("dan@nano.rs".into()))
        .resource("user", Some(Uuid::now_v7()), Some("analyst@nano.rs".into()))
        .client(Some("203.0.113.7".into()), Some("Mozilla/5.0".into()))
        .build();
    event.request_uid = Some("0199c1d2-req".into());
    event
}

#[test]
fn every_golden_action_maps_to_its_class_and_activity() {
    let mut seen = std::collections::BTreeSet::new();
    for (action, class, activity) in EVERY_AUDIT_ACTION {
        assert!(seen.insert(*action), "{action} listed twice");
        let ocsf = known_event(action).to_ocsf_event_with(Utc::now(), true);
        assert_eq!((ocsf["class_uid"].as_i64(), ocsf["activity_id"].as_i64()),
            (Some(*class), Some(*activity)), "{action}");
        assert_eq!(ocsf["type_uid"], class * 100 + activity, "{action}");
        let class_enum = match class {
            3001 => OcsfAuditClass::AccountChange,
            3002 => OcsfAuditClass::Authentication,
            _ => OcsfAuditClass::ApiActivity,
        };
        assert_eq!(ocsf["activity_name"], class_enum.activity_name(*activity), "{action}");
        assert_eq!(ocsf["class_name"], class_enum.class_name(), "{action}");
        // 99 Other in API Activity only for verbs that are not CRUD.
        if *class == 6003 && *activity == 99 {
            assert!(iam_action(action).is_none(), "{action}");
        }
    }
    // Every IAM row is an emitted action (no dead table rows).
    for (action, row) in IAM_ACTIONS {
        assert_eq!(golden(action), Some((row.class.class_uid(), row.activity_id)), "{action}");
    }
}

/// Every action string a Rust emitter or `actions.rs` names is in the golden
/// table. Scans the source trees present in this checkout (the open-core
/// mirror has no the enterprise crate).
#[test]
fn every_emitted_action_is_classified() {
    let constant = regex::Regex::new(r#"pub const [A-Z0-9_]+: &str = "([a-z0-9_.]+)";"#).unwrap();
    let actions_rs = include_str!("actions.rs");
    let constants: Vec<&str> = constant.captures_iter(actions_rs).map(|c| c.get(1).unwrap().as_str()).collect();
    assert!(constants.len() > 300, "actions.rs constants: {}", constants.len());
    let mut missing: Vec<String> = constants.iter().filter(|a| golden(a).is_none()).map(|a| a.to_string()).collect();

    let builder = regex::Regex::new(r#"AuditEvent::builder\(\s*AuditSource::\w+\s*,\s*"([a-z0-9_.]+)""#).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = 0;
    #[allow(unused_mut)]
    let mut crate_dirs = vec!["nanosiem-core/src", "nanosiem-api/src", "nanosiem-api-lib/src", "nanosiem-search/src"];
    #[cfg(feature = "enterprise")]
    crate_dirs.push("nanosiem-enterprise/src");
    for crate_dir in crate_dirs {
        let mut stack = vec![root.join(crate_dir)];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs")
                    && !path.to_string_lossy().ends_with("_tests.rs")
                    && !path.to_string_lossy().contains("/tests/")
                {
                    let text = std::fs::read_to_string(&path).unwrap();
                    // Production code only: stop at the file's test module.
                    let production = text.split("#[cfg(test)]").next().unwrap_or("");
                    files += 1;
                    for capture in builder.captures_iter(production) {
                        let action = capture.get(1).unwrap().as_str();
                        if golden(action).is_none() {
                            missing.push(format!("{action} ({})", path.display()));
                        }
                    }
                }
            }
        }
    }
    assert!(files > 100, "scanned {files} files");
    missing.sort();
    missing.dedup();
    assert!(missing.is_empty(), "audit actions without an OCSF classification: {missing:?}");
}

#[cfg(feature = "enterprise")]
/// The SQL copy (`nano_shared.platform_audit_ocsf_iam_class`, 9015390) lists
/// exactly `IAM_ACTIONS`, in order, so a SQL-built row and a Rust-built row
/// of the same action get the same class.
#[test]
fn sql_iam_table_matches_rust() {
    // Runtime read (the open-core mirror strips postgres-enterprise).
    let path = concat!(env!("CARGO_MANIFEST_DIR"),
        "/../migrations/postgres-enterprise/9015390_audit_ocsf_mapping_gaps.sql");
    let sql = match std::fs::read_to_string(path) {
        Ok(sql) => sql,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping: {path} is absent (open-core tree)");
            return;
        }
        Err(err) => panic!("read {path}: {err}"),
    };
    let section = sql.split("-- BEGIN OCSF IAM ACTIONS").nth(1)
        .and_then(|rest| rest.split("-- END OCSF IAM ACTIONS").next())
        .expect("IAM section markers");
    let rows: Vec<String> = section.lines().skip(1).map(str::trim).filter(|l| l.starts_with('('))
        .map(|l| l.trim_end_matches(',').to_string()).collect();
    let expected: Vec<String> = IAM_ACTIONS.iter().map(|(action, row)| {
        let subject = match row.subject {
            AuditSubject::Actor => "actor",
            AuditSubject::Account => "account",
            AuditSubject::AccountOnly => "account_only",
        };
        let protocol = row.protocol.map_or("NULL".to_string(), |p| format!("'{}'", p.sql_name()));
        let mfa = row.mfa.map_or("NULL", |m| if m { "TRUE" } else { "FALSE" });
        format!("('{action}', {}, {}, '{subject}', {protocol}, {mfa})", row.class.class_uid(), row.activity_id)
    }).collect();
    assert_eq!(rows, expected, "9015390 IAM table drifted from IAM_ACTIONS");
}

/// Every audit action, from every writer shape, is a valid OCSF 1.9 event
/// of its class as the lake admits it (the lean lane + `ingest[T]` contract).
#[test]
fn every_action_is_valid_ocsf_1_9_in_every_shape() {
    let shapes: [(&str, fn(&str) -> AuditEvent); 4] = [
        ("known actor + user resource + client", known_event),
        ("actor id only (shared callers), no client", |action| {
            AuditEvent::builder(AuditSource::Auth, action).actor(Some(Uuid::now_v7()), None).build()
        }),
        ("failed attempt by name, non-user resource", |action| {
            AuditEvent::builder(AuditSource::Auth, action)
                .actor(None, Some("probe@example.com".into()))
                .resource("endpoint", None, Some("POST /api/rules".into()))
                .api_key(Some(Uuid::now_v7()), Some("ci-bot".into()))
                .client(Some("2001:db8::7".into()), None)
                .success(false)
                .details(json!({"reason": "invalid_password"}))
                .build()
        }),
        ("system, type-only resource", |action| {
            AuditEvent::builder(AuditSource::Storage, action).resource("system", None, None).build()
        }),
    ];
    for (action, _, _) in EVERY_AUDIT_ACTION {
        for (shape, build) in &shapes {
            let event = build(action);
            let ocsf = event.to_ocsf_event_for_lake_with(Utc::now(), Uuid::now_v7(), "tenant-a", true);
            let verdict = crate::parsers::validate_ocsf_event(&ocsf);
            assert!(verdict.valid, "{action} / {shape}: {:?}\n{ocsf:#}", verdict.errors);
            // The envelope every class keeps (the signed append guard pins it):
            // the action / source as class-independent metadata, and as `api`
            // on API Activity only (OCSF `api` is cloud-profile-only on IAM).
            assert_eq!(ocsf["metadata"]["event_code"], *action, "{action} / {shape}");
            assert_eq!(ocsf["metadata"]["product"]["feature"]["name"], event.source.to_string());
            if ocsf["class_uid"] == 6003 {
                assert_eq!(ocsf["api"]["operation"], *action, "{action} / {shape}");
                assert_eq!(ocsf["api"]["service"]["name"], event.source.to_string());
            } else {
                assert!(ocsf.get("api").is_none(), "{action} / {shape}: api on an IAM class");
                if event.request_uid.is_some() {
                    assert_eq!(ocsf["metadata"]["correlation_uid"], json!(event.request_uid));
                }
            }
            assert_eq!(ocsf["metadata"]["version"], "1.9.0");
            assert_eq!(ocsf["metadata"]["log_name"], "audit");
            assert_eq!(ocsf["actor"]["user"]["uid"], json!(event.actor_id.map(|id| id.to_string())));
            // No mapped field is ever repeated in `unmapped`.
            if let Some(unmapped) = ocsf.get("unmapped") {
                let keys: Vec<&String> = unmapped.as_object().unwrap().keys().collect();
                for key in &keys {
                    assert!(["api_key_name", "details", "resource_type", "resource"].contains(&key.as_str()),
                        "{action} / {shape}: unmapped.{key} duplicates a mapped field");
                }
                assert!(!keys.is_empty());
            }
        }
    }
}

/// The login Dan saw on open core (NAN-3460): Authentication / Logon from the
/// real client, `user` = the principal, nothing duplicated in `unmapped`.
#[test]
fn a_login_is_an_authentication_logon() {
    let user = Uuid::now_v7();
    let login = AuditEvent::builder(AuditSource::Auth, "login_success")
        .actor(Some(user), Some("admin@nano.rs".into()))
        .resource("user", Some(user), Some("admin@nano.rs".into()))
        .client(Some("198.51.100.23".into()), Some("Mozilla/5.0".into()))
        .build();
    let ocsf = login.to_ocsf_event_with(Utc::now(), true);
    assert_eq!(ocsf["class_uid"], 3002);
    assert_eq!(ocsf["class_name"], "Authentication");
    assert_eq!(ocsf["category_uid"], 3);
    assert_eq!(ocsf["activity_id"], 1);
    assert_eq!(ocsf["activity_name"], "Logon");
    assert_eq!(ocsf["type_uid"], 300201);
    assert_eq!(ocsf["status_id"], 1);
    assert_eq!(ocsf["user"], json!({"name": "admin@nano.rs", "uid": user.to_string(), "email_addr": "admin@nano.rs"}));
    assert_eq!(ocsf["src_endpoint"]["ip"], "198.51.100.23");
    assert_eq!(ocsf["http_request"]["user_agent"], "Mozilla/5.0");
    assert_eq!(ocsf["service"]["name"], "nano");
    assert_eq!(ocsf["auth_protocol"], "Password");
    assert_eq!(ocsf["auth_protocol_id"], 99);
    assert_eq!(ocsf["is_mfa"], false);
    assert_eq!(ocsf["metadata"]["event_code"], "login_success");
    assert_eq!(ocsf["metadata"]["product"]["feature"]["name"], "auth");
    assert!(ocsf.get("api").is_none());
    assert!(ocsf.get("unmapped").is_none(), "nothing is unmapped: {ocsf:#}");
    assert!(ocsf.get("resources").is_none());

    // After the MFA challenge the same logon says so.
    let mfa = AuditEvent::builder(AuditSource::Auth, "login_success")
        .actor(Some(user), Some("admin@nano.rs".into()))
        .details(json!({"mfa_verified": true}))
        .build()
        .to_ocsf_event_with(Utc::now(), true);
    assert_eq!(mfa["is_mfa"], true);

    // A failed logon by an unknown principal: the attempted name is the user.
    let failed = AuditEvent::builder(AuditSource::Auth, "login_failed")
        .actor(None, Some("ghost@example.com".into()))
        .resource("user", None, Some("ghost@example.com".into()))
        .client(Some("192.0.2.9".into()), None)
        .success(false)
        .details(json!({"error": "invalid credentials"}))
        .build()
        .to_ocsf_event_with(Utc::now(), true);
    assert_eq!((failed["class_uid"].as_i64(), failed["activity_id"].as_i64()), (Some(3002), Some(1)));
    assert_eq!(failed["status_id"], 2);
    assert_eq!(failed["severity_id"], 2);
    assert_eq!(failed["user"]["name"], "ghost@example.com");
    assert!(failed.get("is_mfa").is_none(), "unknown for a failed password logon");
    assert!(failed.get("http_request").is_none(), "an unknown user agent is absent");
    assert_eq!(failed["unmapped"], json!({"details": {"error": "invalid credentials"}}));

    // A refused SSO logon (NAN-3904) after the ID token validated names the
    // IdP-asserted account (NAN-4547): Authentication Logon, Failure, OpenID —
    // the failed twin of oidc_login.
    let denied = AuditEvent::builder(AuditSource::Auth, "sso_sign_in_denied")
        .actor(None, Some("ghost@example.com".into()))
        .success(false)
        .details(json!({"provider": "okta", "reason": "admission_denied",
            "identity": "validated", "idp_subject": "idp-sub-1"}))
        .build()
        .to_ocsf_event_with(Utc::now(), true);
    assert_eq!((denied["class_uid"].as_i64(), denied["activity_id"].as_i64()), (Some(3002), Some(1)));
    assert_eq!(denied["status_id"], 2);
    assert_eq!(denied["auth_protocol_id"], 4);
    assert_eq!(denied["status_detail"], "admission_denied");
    // Refused before the token validated: no trusted identity, so it records
    // `unvalidated`, OCSF has no `user` to name, and it stays API Activity.
    let anonymous = AuditEvent::builder(AuditSource::Auth, "sso_sign_in_denied")
        .success(false)
        .details(json!({"reason": "idp_validation_failed", "identity": "unvalidated"}))
        .build()
        .to_ocsf_event_with(Utc::now(), true);
    assert_eq!(anonymous["class_uid"], 6003);
    assert_eq!(anonymous["status_id"], 2);

    // Logoff: the session's holder.
    let logout = AuditEvent::builder(AuditSource::Auth, "logout")
        .actor(Some(user), None)
        .resource("session", None, None)
        .build()
        .to_ocsf_event_with(Utc::now(), true);
    assert_eq!((logout["class_uid"].as_i64(), logout["activity_id"].as_i64()), (Some(3002), Some(2)));
    assert_eq!(logout["user"], json!({"uid": user.to_string()}));
    assert!(logout.get("src_endpoint").is_none() && logout.get("unmapped").is_some());
    assert_eq!(logout["unmapped"]["resource"], json!({"type": "session"}));
}

#[test]
fn account_changes_name_the_account_not_the_administrator() {
    let admin = Uuid::now_v7();
    let target = Uuid::now_v7();
    for (action, activity, name) in [
        ("user_created", 1, "Create"),
        ("user_enabled", 2, "Enable"),
        ("password_changed", 3, "Password Change"),
        ("password_reset_complete", 4, "Password Reset"),
        ("user_disabled", 5, "Disable"),
        ("user_deleted", 6, "Delete"),
        ("user_locked", 9, "Lock"),
        ("mfa_setup_complete", 10, "MFA Factor Enable"),
        ("mfa_admin_reset", 11, "MFA Factor Disable"),
        ("user_unlocked", 12, "Unlock"),
    ] {
        let ocsf = AuditEvent::builder(AuditSource::User, action)
            .actor(Some(admin), Some("Admin".into()))
            .resource("user", Some(target), Some("analyst@nano.rs".into()))
            .build()
            .to_ocsf_event_with(Utc::now(), true);
        assert_eq!(ocsf["class_uid"], 3001, "{action}");
        assert_eq!(ocsf["activity_id"], activity, "{action}");
        assert_eq!(ocsf["activity_name"], name, "{action}");
        assert_eq!(ocsf["user"]["uid"], target.to_string(), "{action}");
        assert_eq!(ocsf["actor"]["user"]["uid"], admin.to_string(), "{action}");
        assert!(ocsf.get("service").is_none() && ocsf.get("is_mfa").is_none(), "{action}");
    }
}

/// An IAM action whose account nano cannot name stays API Activity (OCSF
/// requires `user`); an administrator ending sessions names only the account.
#[test]
fn unknown_account_falls_back_to_api_activity() {
    let anonymous = AuditEvent::builder(AuditSource::Auth, "logout").build().to_ocsf_event_with(Utc::now(), true);
    assert_eq!(anonymous["class_uid"], 6003);
    assert_eq!(anonymous["activity_id"], 99, "logout is not CRUD");
    let terminated = AuditEvent::builder(AuditSource::Session, "session_terminated")
        .actor(Some(Uuid::now_v7()), Some("Admin".into()))
        .resource("session", Some(Uuid::now_v7()), None)
        .build()
        .to_ocsf_event_with(Utc::now(), true);
    assert_eq!(terminated["class_uid"], 6003, "the administrator is not the session holder");
    assert_eq!(terminated["activity_id"], 4);
}
