// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit Action Constants
//!
//! Standardized action names for all audit events (underscore convention).

// =============================================================================
// Authentication Actions
// =============================================================================

/// User successfully logged in
pub const LOGIN_SUCCESS: &str = "login_success";
/// User login attempt failed
pub const LOGIN_FAILED: &str = "login_failed";
/// User logged out
pub const LOGOUT: &str = "logout";
/// Token was refreshed
pub const TOKEN_REFRESH: &str = "token_refresh";
/// Password reset was requested
pub const PASSWORD_RESET_REQUEST: &str = "password_reset_request";
/// Password reset was completed
pub const PASSWORD_RESET_COMPLETE: &str = "password_reset_complete";
/// Password was changed
pub const PASSWORD_CHANGED: &str = "password_changed";
/// OIDC login completed
pub const OIDC_LOGIN: &str = "oidc_login";

// =============================================================================
// Authorization Actions
// =============================================================================

/// Authenticated caller was denied access to a protected endpoint
/// (insufficient permissions, scope, session-only enforcement, or resource ACL).
pub const AUTH_DENIED: &str = "auth_denied";

// =============================================================================
// Detection Rule Actions
// =============================================================================

/// Detection rule was created
pub const RULE_CREATED: &str = "rule_created";
/// Detection rule was updated
pub const RULE_UPDATED: &str = "rule_updated";
/// Detection rule was deleted
pub const RULE_DELETED: &str = "rule_deleted";
/// Detection rule was paused
pub const RULE_PAUSED: &str = "rule_paused";
/// Detection rule was resumed from paused state
pub const RULE_RESUMED: &str = "rule_resumed";
/// Detection rule was promoted (experimental -> production)
pub const RULE_PROMOTED: &str = "rule_promoted";
/// Detection rule was demoted (production -> experimental)
pub const RULE_DEMOTED: &str = "rule_demoted";
/// Detection rule was duplicated
pub const RULE_DUPLICATED: &str = "rule_duplicated";
/// Detection rules were bulk updated (mode change)
pub const RULES_BULK_UPDATED: &str = "rules_bulk_updated";

// =============================================================================
// User Management Actions
// =============================================================================

/// User was created
pub const USER_CREATED: &str = "user_created";
/// User was updated
pub const USER_UPDATED: &str = "user_updated";
/// User was deleted
pub const USER_DELETED: &str = "user_deleted";
/// User was locked
pub const USER_LOCKED: &str = "user_locked";
/// User was unlocked
pub const USER_UNLOCKED: &str = "user_unlocked";
/// User was disabled
pub const USER_DISABLED: &str = "user_disabled";
/// User was enabled
pub const USER_ENABLED: &str = "user_enabled";
/// User's groups were updated
pub const USER_GROUPS_UPDATED: &str = "user_groups_updated";

// =============================================================================
// Tuning Actions
// =============================================================================

/// Tuning proposal was approved
pub const PROPOSAL_APPROVED: &str = "proposal_approved";
/// Tuning proposal was rejected
pub const PROPOSAL_REJECTED: &str = "proposal_rejected";
/// Tuning settings were updated
pub const SETTINGS_UPDATED: &str = "settings_updated";
/// Rule was reverted to a previous version
pub const VERSION_REVERTED: &str = "version_reverted";

// =============================================================================
// Case Actions
// =============================================================================

/// Case was created
pub const CASE_CREATED: &str = "case_created";
/// Case was updated
pub const CASE_UPDATED: &str = "case_updated";
/// Case was deleted
pub const CASE_DELETED: &str = "case_deleted";
/// Case sharing was updated
pub const CASE_SHARED: &str = "case_shared";

// =============================================================================
// API Key Actions
// =============================================================================

/// API key was created
pub const APIKEY_CREATED: &str = "apikey_created";
/// API key was deleted
pub const APIKEY_DELETED: &str = "apikey_deleted";
/// API key was enabled
pub const APIKEY_ENABLED: &str = "apikey_enabled";
/// API key was disabled
pub const APIKEY_DISABLED: &str = "apikey_disabled";
/// API key was updated
pub const APIKEY_UPDATED: &str = "apikey_updated";
/// API key was reset (new key generated)
pub const APIKEY_RESET: &str = "apikey_reset";

// =============================================================================
// Role Actions
// =============================================================================

/// Role was created
pub const ROLE_CREATED: &str = "role_created";
/// Role was updated
pub const ROLE_UPDATED: &str = "role_updated";
/// Role was deleted
pub const ROLE_DELETED: &str = "role_deleted";

// =============================================================================
// Group Actions
// =============================================================================

/// Group was created
pub const GROUP_CREATED: &str = "group_created";
/// Group was updated
pub const GROUP_UPDATED: &str = "group_updated";
/// Group was deleted
pub const GROUP_DELETED: &str = "group_deleted";
/// Group's roles were updated
pub const GROUP_ROLES_UPDATED: &str = "group_roles_updated";
/// Member was added to group
pub const GROUP_MEMBER_ADDED: &str = "group_member_added";
/// Member was removed from group
pub const GROUP_MEMBER_REMOVED: &str = "group_member_removed";

// =============================================================================
// Credential Actions
// =============================================================================

/// Cloud credential was created
pub const CREDENTIAL_CREATED: &str = "credential_created";
/// Cloud credential metadata was updated (name/description/region/environment/expires_at)
pub const CREDENTIAL_UPDATED: &str = "credential_updated";
/// Cloud credential was deleted
pub const CREDENTIAL_DELETED: &str = "credential_deleted";
/// Cloud credential's secret material was rotated — produced a new active version
pub const CREDENTIAL_ROTATED: &str = "credential_rotated";
/// Cloud credential was rolled back to a previous version's secret material
pub const CREDENTIAL_ROLLED_BACK: &str = "credential_rolled_back";

// =============================================================================
// Search Actions
// =============================================================================

/// Saved search sharing was updated
pub const SAVED_SEARCH_SHARED: &str = "saved_search_shared";

/// A single search-history entry was deleted (anti-forensics relevant)
pub const SEARCH_HISTORY_DELETED: &str = "search_history_deleted";
/// All of a user's search history was cleared (anti-forensics relevant)
pub const SEARCH_HISTORY_CLEARED: &str = "search_history_cleared";
/// Search-history tracking was turned on
pub const SEARCH_HISTORY_ENABLED: &str = "search_history_enabled";
/// Search-history tracking was turned off (evasion lever — single-filter hunt)
pub const SEARCH_HISTORY_DISABLED: &str = "search_history_disabled";

// =============================================================================
// System Actions
// =============================================================================

// =============================================================================
// Webhook Actions
// =============================================================================

/// Webhook was created
pub const WEBHOOK_CREATED: &str = "webhook_created";
/// Webhook was updated
pub const WEBHOOK_UPDATED: &str = "webhook_updated";
/// Webhook was deleted
pub const WEBHOOK_DELETED: &str = "webhook_deleted";

// =============================================================================
// System Actions
// =============================================================================

/// System was initialized (first-run setup)
pub const SYSTEM_INITIALIZED: &str = "system_initialized";
/// Settings were updated
pub const SYSTEM_SETTINGS_UPDATED: &str = "system_settings_updated";

// =============================================================================
// Marketplace Actions
// =============================================================================

/// Marketplace enrichment was installed
pub const MARKETPLACE_INSTALLED: &str = "marketplace_installed";
/// Marketplace enrichment was uninstalled
pub const MARKETPLACE_UNINSTALLED: &str = "marketplace_uninstalled";
/// Marketplace enrichment was updated
pub const MARKETPLACE_UPDATED: &str = "marketplace_updated";
/// Marketplace enrichment was configured (enabled/disabled/credentials)
pub const MARKETPLACE_CONFIGURED: &str = "marketplace_configured";
/// Marketplace enrichment data sync triggered
pub const MARKETPLACE_SYNC_TRIGGERED: &str = "marketplace_sync_triggered";
/// Marketplace repository was synced
pub const MARKETPLACE_REPO_SYNCED: &str = "marketplace_repo_synced";

// =============================================================================
// Dashboard Actions
// =============================================================================

/// Dashboard was created
pub const DASHBOARD_CREATED: &str = "dashboard_created";
/// Dashboard was updated
pub const DASHBOARD_UPDATED: &str = "dashboard_updated";
/// Dashboard was deleted
pub const DASHBOARD_DELETED: &str = "dashboard_deleted";
/// Dashboard sharing was changed
pub const DASHBOARD_SHARED: &str = "dashboard_shared";
/// Dashboard was exported
pub const DASHBOARD_EXPORTED: &str = "dashboard_exported";
/// Dashboard was imported
pub const DASHBOARD_IMPORTED: &str = "dashboard_imported";

// =============================================================================
// Notebook Actions
// =============================================================================

/// Notebook was created
pub const NOTEBOOK_CREATED: &str = "notebook_created";
/// Notebook was updated
pub const NOTEBOOK_UPDATED: &str = "notebook_updated";
/// Notebook was deleted
pub const NOTEBOOK_DELETED: &str = "notebook_deleted";
/// Notebook sharing was changed
pub const NOTEBOOK_SHARED: &str = "notebook_shared";
/// Entry was added to a notebook
pub const NOTEBOOK_ENTRY_ADDED: &str = "notebook_entry_added";
/// Entry was deleted from a notebook
pub const NOTEBOOK_ENTRY_DELETED: &str = "notebook_entry_deleted";
/// Notebook was escalated to a case
pub const NOTEBOOK_ESCALATED: &str = "notebook_escalated";
/// Notebooks were merged
pub const NOTEBOOK_MERGED: &str = "notebook_merged";

// =============================================================================
// Alert Actions
// =============================================================================

/// Alert was acknowledged
pub const ALERT_ACKNOWLEDGED: &str = "alert_acknowledged";
/// Alert was closed
pub const ALERT_CLOSED: &str = "alert_closed";
/// Alert was assigned to a user
pub const ALERT_ASSIGNED: &str = "alert_assigned";
/// Alerts were bulk acknowledged
pub const ALERT_BULK_ACKNOWLEDGED: &str = "alert_bulk_acknowledged";
/// Alerts were bulk closed
pub const ALERT_BULK_CLOSED: &str = "alert_bulk_closed";

// =============================================================================
// Query Library Actions
// =============================================================================

/// Saved query was created
pub const QUERY_CREATED: &str = "query_created";
/// Saved query was deleted
pub const QUERY_DELETED: &str = "query_deleted";

// =============================================================================
// Log Source Actions
// =============================================================================

/// Log source was created
pub const LOG_SOURCE_CREATED: &str = "log_source_created";
/// Log source was updated
pub const LOG_SOURCE_UPDATED: &str = "log_source_updated";
/// Log source was deleted
pub const LOG_SOURCE_DELETED: &str = "log_source_deleted";
/// Log source was toggled (enabled/disabled)
pub const LOG_SOURCE_TOGGLED: &str = "log_source_toggled";
/// Log source was deployed
pub const LOG_SOURCE_DEPLOYED: &str = "log_source_deployed";
/// Log source was undeployed
pub const LOG_SOURCE_UNDEPLOYED: &str = "log_source_undeployed";
/// Log source was published
pub const LOG_SOURCE_PUBLISHED: &str = "log_source_published";
/// Log source was reverted to a previous version
pub const LOG_SOURCE_REVERTED: &str = "log_source_reverted";
/// All log sources were deployed
pub const LOG_SOURCE_DEPLOY_ALL: &str = "log_source_deploy_all";

// =============================================================================
// Source Config Actions
// =============================================================================

/// Source config was created
pub const SOURCE_CONFIG_CREATED: &str = "source_config_created";
/// Source config was updated
pub const SOURCE_CONFIG_UPDATED: &str = "source_config_updated";
/// Source config was deleted
pub const SOURCE_CONFIG_DELETED: &str = "source_config_deleted";
/// Source config was toggled (enabled/disabled)
pub const SOURCE_CONFIG_TOGGLED: &str = "source_config_toggled";
/// Source config was deployed
pub const SOURCE_CONFIG_DEPLOYED: &str = "source_config_deployed";
/// Source config was undeployed
pub const SOURCE_CONFIG_UNDEPLOYED: &str = "source_config_undeployed";
/// All source configs were deployed
pub const SOURCE_CONFIG_DEPLOY_ALL: &str = "source_config_deploy_all";
/// Routing rule was created
pub const ROUTING_RULE_CREATED: &str = "routing_rule_created";
/// Routing rule was updated
pub const ROUTING_RULE_UPDATED: &str = "routing_rule_updated";
/// Routing rule was deleted
pub const ROUTING_RULE_DELETED: &str = "routing_rule_deleted";
/// Routing rules were reordered
pub const ROUTING_RULE_REORDERED: &str = "routing_rule_reordered";

// =============================================================================
// Enrichment Actions
// =============================================================================

/// Enrichment source was configured
pub const ENRICHMENT_CONFIGURED: &str = "enrichment_configured";
/// Enrichment source data was synced
pub const ENRICHMENT_SYNCED: &str = "enrichment_synced";
/// Enrichment source was enabled
pub const ENRICHMENT_ENABLED: &str = "enrichment_enabled";
/// Enrichment source was disabled
pub const ENRICHMENT_DISABLED: &str = "enrichment_disabled";
/// Enrichment auto-sync was configured
pub const AUTO_SYNC_CONFIGURED: &str = "auto_sync_configured";

// =============================================================================
// Custom Enrichment Actions
// =============================================================================

/// Custom enrichment was created
pub const CUSTOM_ENRICHMENT_CREATED: &str = "custom_enrichment_created";
/// Custom enrichment was updated
pub const CUSTOM_ENRICHMENT_UPDATED: &str = "custom_enrichment_updated";
/// Custom enrichment was deleted
pub const CUSTOM_ENRICHMENT_DELETED: &str = "custom_enrichment_deleted";
/// Custom enrichment was deployed
pub const CUSTOM_ENRICHMENT_DEPLOYED: &str = "custom_enrichment_deployed";
/// Custom enrichment was disabled
pub const CUSTOM_ENRICHMENT_DISABLED: &str = "custom_enrichment_disabled";
/// Custom enrichment run was triggered
pub const CUSTOM_ENRICHMENT_RUN_TRIGGERED: &str = "custom_enrichment_run_triggered";

// =============================================================================
// Agent Enrichment Actions
// =============================================================================

/// Agent enrichment provider was created
pub const AGENT_ENRICHMENT_CREATED: &str = "agent_enrichment_created";
/// Agent enrichment provider was updated
pub const AGENT_ENRICHMENT_UPDATED: &str = "agent_enrichment_updated";
/// Agent enrichment provider was deleted
pub const AGENT_ENRICHMENT_DELETED: &str = "agent_enrichment_deleted";
/// Agent enrichment provider credentials were updated
pub const AGENT_ENRICHMENT_CREDENTIALS_UPDATED: &str = "agent_enrichment_credentials_updated";

// =============================================================================
// Session Actions
// =============================================================================

/// Session was terminated
pub const SESSION_TERMINATED: &str = "session_terminated";
/// All sessions for a user were terminated
pub const USER_SESSIONS_TERMINATED: &str = "user_sessions_terminated";

// =============================================================================
// OIDC Actions
// =============================================================================

/// OIDC provider was created
pub const OIDC_PROVIDER_CREATED: &str = "oidc_provider_created";
/// OIDC provider was updated
pub const OIDC_PROVIDER_UPDATED: &str = "oidc_provider_updated";
/// OIDC provider was deleted
pub const OIDC_PROVIDER_DELETED: &str = "oidc_provider_deleted";
/// OIDC provider was enabled
pub const OIDC_PROVIDER_ENABLED: &str = "oidc_provider_enabled";
/// OIDC provider was disabled
pub const OIDC_PROVIDER_DISABLED: &str = "oidc_provider_disabled";
/// OIDC group mappings were updated
pub const OIDC_GROUP_MAPPINGS_UPDATED: &str = "oidc_group_mappings_updated";
/// A new user was just-in-time provisioned on first OIDC login
pub const OIDC_USER_PROVISIONED: &str = "oidc_user_provisioned";

// =============================================================================
// Parser Repository Actions
// =============================================================================

/// Parser repository was created
pub const PARSER_REPO_CREATED: &str = "parser_repo_created";
/// Parser repository was updated
pub const PARSER_REPO_UPDATED: &str = "parser_repo_updated";
/// Parser repository was deleted
pub const PARSER_REPO_DELETED: &str = "parser_repo_deleted";
/// Parser repository was synced
pub const PARSER_REPO_SYNCED: &str = "parser_repo_synced";
/// Parser was imported from repository
pub const PARSER_IMPORTED: &str = "parser_imported";
/// Parsers were batch imported from repository
pub const PARSER_BATCH_IMPORTED: &str = "parser_batch_imported";
/// All imported parsers were removed
pub const PARSER_ALL_REMOVED: &str = "parser_all_removed";
/// Parser VRL was updated from upstream repository
pub const PARSER_UPSTREAM_APPLIED: &str = "parser_upstream_applied";

// =============================================================================
// Rule Repository Actions
// =============================================================================

/// Rule repository was created
pub const RULE_REPO_CREATED: &str = "rule_repo_created";
/// Rule repository was updated
pub const RULE_REPO_UPDATED: &str = "rule_repo_updated";
/// Rule repository was deleted
pub const RULE_REPO_DELETED: &str = "rule_repo_deleted";
/// Rule repository was synced
pub const RULE_REPO_SYNCED: &str = "rule_repo_synced";

// Detection-as-Code push target actions (NAN-1745)
/// Push target was created
pub const DETECTION_CODE_TARGET_CREATED: &str = "detection_code_target_created";
/// Push target metadata was updated
pub const DETECTION_CODE_TARGET_UPDATED: &str = "detection_code_target_updated";
/// Push target was deleted
pub const DETECTION_CODE_TARGET_DELETED: &str = "detection_code_target_deleted";
/// GitHub token was set/replaced on a push target
pub const DETECTION_CODE_TARGET_TOKEN_SET: &str = "detection_code_target_token_set";
/// A tuning Pull Request was opened in a push target repo
pub const DETECTION_CODE_PR_OPENED: &str = "detection_code_pr_opened";
/// Rule was imported from repository
pub const RULE_IMPORTED: &str = "rule_imported";
/// Rules were batch imported from repository
pub const RULE_BATCH_IMPORTED: &str = "rule_batch_imported";
/// All imported rules were removed
pub const RULE_ALL_REMOVED: &str = "rule_all_removed";

// =============================================================================
// Case Settings Actions
// =============================================================================

/// Case settings were updated
pub const CASE_SETTINGS_UPDATED: &str = "case_settings_updated";
/// Case grouping rule was created
pub const CASE_GROUPING_RULE_CREATED: &str = "case_grouping_rule_created";
/// Case grouping rule was updated
pub const CASE_GROUPING_RULE_UPDATED: &str = "case_grouping_rule_updated";
/// Case grouping rule was deleted
pub const CASE_GROUPING_RULE_DELETED: &str = "case_grouping_rule_deleted";
/// Case was assigned to a user
pub const CASE_ASSIGNED: &str = "case_assigned";
/// Case was escalated while still active
pub const CASE_ESCALATED: &str = "case_escalated";
/// Case handoff was sent
pub const CASE_HANDOFF_SENT: &str = "case_handoff_sent";
/// Case handoff was accepted
pub const CASE_HANDOFF_ACCEPTED: &str = "case_handoff_accepted";
/// Case handoff was bounced (rejected back to sender)
pub const CASE_HANDOFF_BOUNCED: &str = "case_handoff_bounced";
/// Case handoff was canceled by source
pub const CASE_HANDOFF_CANCELED: &str = "case_handoff_canceled";
/// Case status was changed
pub const CASE_STATUS_CHANGED: &str = "case_status_changed";
/// Cases were bulk status changed
pub const CASE_BULK_STATUS_CHANGED: &str = "case_bulk_status_changed";
/// Cases were merged
pub const CASE_MERGED: &str = "case_merged";
/// Alert was added to a case
pub const CASE_ALERT_ADDED: &str = "case_alert_added";
/// Alert was removed from a case
pub const CASE_ALERT_REMOVED: &str = "case_alert_removed";
/// Notebook was linked to a case
pub const CASE_NOTEBOOK_LINKED: &str = "case_notebook_linked";
/// Notebook was unlinked from a case
pub const CASE_NOTEBOOK_UNLINKED: &str = "case_notebook_unlinked";
/// Notebook was merged into a case
pub const CASE_NOTEBOOK_MERGED: &str = "case_notebook_merged";

// =============================================================================
// Incident Actions (NAN-417)
// =============================================================================

/// Incident was created (promoted from one or more cases)
pub const INCIDENT_CREATED: &str = "incident_created";
/// Case was added to an incident
pub const INCIDENT_CASE_ADDED: &str = "incident_case_added";
/// Case was removed from an incident
pub const INCIDENT_CASE_REMOVED: &str = "incident_case_removed";

// =============================================================================
// Settings Actions
// =============================================================================

/// MeloD configuration was updated
pub const MELOD_CONFIG_UPDATED: &str = "melod_config_updated";
/// MeloD credentials were updated
pub const MELOD_CREDENTIALS_UPDATED: &str = "melod_credentials_updated";
/// MeloD connection was validated
pub const MELOD_CONNECTION_VALIDATED: &str = "melod_connection_validated";
/// Retention configuration was updated
pub const RETENTION_CONFIG_UPDATED: &str = "retention_config_updated";
/// Retention was manually triggered
pub const RETENTION_RUN_TRIGGERED: &str = "retention_run_triggered";
/// ClickHouse retention was updated
pub const CH_RETENTION_UPDATED: &str = "ch_retention_updated";
/// ClickHouse retention was manually triggered
pub const CH_RETENTION_RUN_TRIGGERED: &str = "ch_retention_run_triggered";
/// Risk configuration was updated
pub const RISK_CONFIG_UPDATED: &str = "risk_config_updated";
/// Risk decay configuration was updated
pub const RISK_DECAY_CONFIG_UPDATED: &str = "risk_decay_config_updated";
/// Tiering configuration was updated
pub const TIERING_CONFIG_UPDATED: &str = "tiering_config_updated";
/// Tiering credentials were set
pub const TIERING_CREDENTIALS_SET: &str = "tiering_credentials_set";
/// Tiering connection was tested
pub const TIERING_CONNECTION_TESTED: &str = "tiering_connection_tested";
/// Tiering configuration was applied
pub const TIERING_CONFIG_APPLIED: &str = "tiering_config_applied";
/// Organizational context was updated
pub const ORG_CONTEXT_UPDATED: &str = "org_context_updated";
/// Health monitoring settings were updated
pub const HEALTH_MONITORING_UPDATED: &str = "health_monitoring_updated";
/// Developer settings were updated
pub const DEVELOPER_SETTINGS_UPDATED: &str = "developer_settings_updated";
/// Search admission settings were updated
pub const SEARCH_SETTINGS_UPDATED: &str = "search_settings_updated";
/// AI provider was updated
pub const AI_PROVIDER_UPDATED: &str = "ai_provider_updated";
/// AI provider connection was validated
pub const AI_PROVIDER_VALIDATED: &str = "ai_provider_validated";
/// Agent model configuration was updated
pub const AGENT_MODEL_CONFIG_UPDATED: &str = "agent_model_config_updated";
/// Available model was created
pub const AVAILABLE_MODEL_CREATED: &str = "available_model_created";
/// Available model was updated
pub const AVAILABLE_MODEL_UPDATED: &str = "available_model_updated";
/// Available model was deleted
pub const AVAILABLE_MODEL_DELETED: &str = "available_model_deleted";
/// Model catalog was synced from upstream repository
pub const MODEL_CATALOG_SYNCED: &str = "model_catalog_synced";
/// Webhook was tested
pub const WEBHOOK_TESTED: &str = "webhook_tested";
/// Organization tier was changed
pub const TIER_UPDATED: &str = "tier_updated";
/// Tier limits were customized
pub const TIER_LIMITS_UPDATED: &str = "tier_limits_updated";

// =============================================================================
// Tuning Actions (additional)
// =============================================================================

/// Rule version was activated
pub const VERSION_ACTIVATED: &str = "version_activated";
/// Tuning change was reverted
pub const TUNING_REVERTED: &str = "tuning_reverted";

// =============================================================================
// Risk Actions
// =============================================================================

/// Entity risk score was cleared
pub const RISK_ENTITY_CLEARED: &str = "risk_entity_cleared";
/// All risk scores were cleared
pub const RISK_ALL_CLEARED: &str = "risk_all_cleared";

// =============================================================================
// Detection Actions (additional)
// =============================================================================

/// Detection rules were imported
pub const RULES_IMPORTED: &str = "rules_imported";
/// Detection rules were exported (bulk download of the rule corpus)
pub const RULES_EXPORTED: &str = "rules_exported";
/// Detection rule was manually triggered
pub const RULE_TRIGGERED: &str = "rule_triggered";

// =============================================================================
// Audit Subsystem Actions
// =============================================================================

/// Audit trail was exported (bulk download of audit logs)
pub const AUDIT_LOGS_EXPORTED: &str = "audit_logs_exported";

// =============================================================================
// Lookup Table Actions
// =============================================================================

/// Lookup table was created
pub const LOOKUP_TABLE_CREATED: &str = "lookup_table_created";
/// Lookup table was deleted
pub const LOOKUP_TABLE_DELETED: &str = "lookup_table_deleted";
/// Lookup rows were added
pub const LOOKUP_ROWS_ADDED: &str = "lookup_rows_added";
/// Lookup row was updated
pub const LOOKUP_ROW_UPDATED: &str = "lookup_row_updated";
/// Lookup rows were deleted
pub const LOOKUP_ROWS_DELETED: &str = "lookup_rows_deleted";

// =============================================================================
// MFA Actions
// =============================================================================

/// MFA challenge was issued during login (user prompted for a TOTP/backup code)
pub const MFA_CHALLENGE_ISSUED: &str = "mfa_challenge_issued";
/// MFA challenge was satisfied (valid TOTP or backup code) — login proceeds
pub const MFA_CHALLENGE_SUCCESS: &str = "mfa_challenge_success";
/// MFA challenge failed (invalid/expired code or challenge token)
pub const MFA_CHALLENGE_FAILED: &str = "mfa_challenge_failed";
/// A single-use MFA backup code was consumed to satisfy a challenge
pub const MFA_BACKUP_CODE_USED: &str = "mfa_backup_code_used";
/// MFA setup was initiated (TOTP secret issued, not yet verified)
pub const MFA_SETUP_INITIATED: &str = "mfa_setup_initiated";
/// MFA setup was completed (first valid code verified, MFA now active)
pub const MFA_SETUP_COMPLETE: &str = "mfa_setup_complete";
/// MFA was disabled for an account
pub const MFA_DISABLED: &str = "mfa_disabled";
/// MFA backup codes were regenerated
pub const MFA_BACKUP_CODES_REGENERATED: &str = "mfa_backup_codes_regenerated";
/// An admin reset another user's MFA enrollment
pub const MFA_ADMIN_RESET: &str = "mfa_admin_reset";
/// MFA enforcement was toggled globally
pub const MFA_ENFORCED_GLOBALLY: &str = "mfa_enforced_globally";

// =============================================================================
// Identity Actions (additional)
// =============================================================================

/// Identity provider was created
pub const IDENTITY_PROVIDER_CREATED: &str = "identity_provider_created";
/// Identity provider was updated
pub const IDENTITY_PROVIDER_UPDATED: &str = "identity_provider_updated";
/// Identity provider was deleted
pub const IDENTITY_PROVIDER_DELETED: &str = "identity_provider_deleted";
/// Identity provider credentials were updated
pub const IDENTITY_PROVIDER_CREDENTIALS_UPDATED: &str = "identity_provider_credentials_updated";
/// Identity directory sync was triggered
pub const IDENTITY_SYNC_TRIGGERED: &str = "identity_sync_triggered";
/// Identity directory sync completed
pub const IDENTITY_SYNC_COMPLETED: &str = "identity_sync_completed";

/// Identity users were pushed/synced
pub const IDENTITY_USERS_PUSHED: &str = "identity_users_pushed";

// MITRE ATT&CK catalog
pub const MITRE_CATALOG_SYNCED: &str = "mitre_catalog_synced";

// =============================================================================
// Marketplace Actions (additional)
// =============================================================================

/// Marketplace repository was created
pub const MARKETPLACE_REPO_CREATED: &str = "marketplace_repo_created";
/// Marketplace repository was updated
pub const MARKETPLACE_REPO_UPDATED: &str = "marketplace_repo_updated";

// =============================================================================
// GDPR Anonymization Actions
// =============================================================================

/// GDPR anonymization request was submitted
pub const GDPR_ANONYMIZATION_SUBMITTED: &str = "gdpr_anonymization_submitted";
/// GDPR anonymization execution started
pub const GDPR_ANONYMIZATION_STARTED: &str = "gdpr_anonymization_started";
/// GDPR anonymization completed successfully
pub const GDPR_ANONYMIZATION_COMPLETED: &str = "gdpr_anonymization_completed";
/// GDPR anonymization execution failed
pub const GDPR_ANONYMIZATION_FAILED: &str = "gdpr_anonymization_failed";

// =============================================================================
// IP Allowlist Actions
// =============================================================================

/// IP allowlist rule was created
pub const IP_ALLOWLIST_CREATED: &str = "ip_allowlist_created";
/// IP allowlist rule was updated
pub const IP_ALLOWLIST_UPDATED: &str = "ip_allowlist_updated";
/// IP allowlist rule was deleted
pub const IP_ALLOWLIST_DELETED: &str = "ip_allowlist_deleted";

// =============================================================================
// Folder Settings Actions (NAN-730)
// =============================================================================

/// Custom folder icon was set or changed
pub const FOLDER_ICON_SET: &str = "folder_icon_set";
/// Custom folder icon was cleared (folder reverts to default icon)
pub const FOLDER_ICON_CLEARED: &str = "folder_icon_cleared";

// =============================================================================
// Durable-audit classifier (NAN-1625)
// =============================================================================

/// Audit actions that must be emitted **durably** — i.e. via a synchronous
/// ClickHouse insert (`AuditEmitter::emit_durable`, which forces
/// `async_insert=0` + `wait_end_of_query=1`) rather than the default
/// fire-and-forget async-insert path. After NAN-1622 made ClickHouse the sole
/// audit store, silent loss of these events is a real reliability/compliance
/// gap, so the emit path awaits the write and surfaces failures loudly.
///
/// ## What is (and is NOT) in this set — and WHY
///
/// This is intentionally an **explicit, greppable list, not a prefix match**,
/// so the durability contract is auditable. The list is a *deliberate subset*
/// of all security-relevant actions, chosen to be **non-floodable**:
///
/// - **INCLUDED**: low-volume, successful/completed security **state changes**
///   that require a *valid, authenticated* action to trigger — a login that
///   actually succeeded, an MFA challenge that was satisfied, an API-key
///   lifecycle change, an account lockout transition, JIT user provisioning,
///   session termination, a completed password reset / change. An
///   unauthenticated attacker cannot flood these.
///
/// - **DELIBERATELY EXCLUDED** (kept fire-and-forget) even though they are
///   security-relevant, because they are **high-volume or attacker-floodable**
///   and awaiting a synchronous insert on them would amplify a flood into a
///   self-inflicted DoS on the ClickHouse connection pool:
///     * `auth_denied` — fires on every 403 (very high volume)
///     * `login_failed` — brute-force floodable by an unauthenticated attacker
///     * `mfa_challenge_issued` / `mfa_challenge_failed` — floodable by anyone
///       repeatedly submitting wrong/again
///     * `password_reset_request` — unauthenticated, floodable
///     * `mfa_setup_initiated` — a *non-committed* step (TOTP secret issued,
///       not yet verified) that an authenticated user can re-trigger; only the
///       committed `mfa_setup_complete` transition is durable
///   These are still audited (fire-and-forget, exactly as before) — just not
///   blocking. The dispatch path additionally caps durable-insert concurrency
///   and falls back to fire-and-forget under load, but keeping floodable
///   events out of the durable set is the primary guard.
///
/// The rule of thumb: durable == an **authenticated, committed, low-volume
/// security state change**. All authenticated MFA and API-key state changes
/// qualify; only the floodable challenge/request events and the non-committed
/// `mfa_setup_initiated` step are excluded.
///
/// The unit test below pins this set in lockstep (C2 pattern): adding or
/// removing a member forces a matching test edit in the same commit, keeping
/// the contract reviewable.
pub const SECURITY_CRITICAL_ACTIONS: &[&str] = &[
    // Authentication — a login that actually *succeeded* (not floodable).
    LOGIN_SUCCESS,
    // Password changes that require an authenticated/validated action.
    PASSWORD_RESET_COMPLETE,
    PASSWORD_CHANGED,
    // MFA — all authenticated / committed account-security state changes.
    // (The floodable `mfa_challenge_issued`/`mfa_challenge_failed` and the
    // non-committed `mfa_setup_initiated` are deliberately excluded above.)
    MFA_CHALLENGE_SUCCESS,
    MFA_BACKUP_CODE_USED,
    MFA_SETUP_COMPLETE,
    MFA_DISABLED,
    MFA_ADMIN_RESET,
    MFA_BACKUP_CODES_REGENERATED,
    MFA_ENFORCED_GLOBALLY,
    // Account lockout — once per lock transition, inherently low-volume.
    USER_LOCKED,
    // API-key lifecycle — all authenticated, low-volume state changes
    // (create/delete/reset/enable/disable + permission/expiry/rate-limit
    // updates).
    APIKEY_CREATED,
    APIKEY_DELETED,
    APIKEY_RESET,
    APIKEY_ENABLED,
    APIKEY_DISABLED,
    APIKEY_UPDATED,
    // Federated identity — JIT provisioning of a new user on first OIDC login.
    OIDC_USER_PROVISIONED,
    // Session termination — administrative, low-volume.
    SESSION_TERMINATED,
    USER_SESSIONS_TERMINATED,
];

/// Returns `true` when `action` must be emitted durably (synchronous insert,
/// awaited) rather than fire-and-forget. See [`SECURITY_CRITICAL_ACTIONS`] for
/// the exact set and the DoS-amplification rationale behind the exclusions.
#[inline]
pub fn is_security_critical(action: &str) -> bool {
    SECURITY_CRITICAL_ACTIONS.contains(&action)
}

#[cfg(test)]
mod durable_classifier_tests {
    use super::*;

    /// Pins the exact durable set (C2 lockstep). If you change
    /// `SECURITY_CRITICAL_ACTIONS`, update this list in the SAME commit — the
    /// diff makes the durability/DoS contract reviewable.
    #[test]
    fn durable_action_set_is_pinned() {
        let mut expected = vec![
            "login_success",
            "password_reset_complete",
            "password_changed",
            "mfa_challenge_success",
            "mfa_backup_code_used",
            "mfa_setup_complete",
            "mfa_disabled",
            "mfa_admin_reset",
            "mfa_backup_codes_regenerated",
            "mfa_enforced_globally",
            "user_locked",
            "apikey_created",
            "apikey_deleted",
            "apikey_reset",
            "apikey_enabled",
            "apikey_disabled",
            "apikey_updated",
            "oidc_user_provisioned",
            "session_terminated",
            "user_sessions_terminated",
        ];
        let mut actual: Vec<&str> = SECURITY_CRITICAL_ACTIONS.to_vec();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(
            actual, expected,
            "durable audit action set changed — review DoS-floodability before editing"
        );
    }

    #[test]
    fn classifier_matches_the_durable_set() {
        // Included: low-volume, authenticated, non-floodable security events.
        assert!(is_security_critical(LOGIN_SUCCESS));
        assert!(is_security_critical(MFA_CHALLENGE_SUCCESS));
        assert!(is_security_critical(MFA_BACKUP_CODE_USED));
        assert!(is_security_critical(MFA_SETUP_COMPLETE));
        assert!(is_security_critical(MFA_DISABLED));
        assert!(is_security_critical(MFA_ADMIN_RESET));
        assert!(is_security_critical(APIKEY_CREATED));
        assert!(is_security_critical(APIKEY_RESET));
        assert!(is_security_critical(APIKEY_UPDATED));
        assert!(is_security_critical(USER_LOCKED));
        assert!(is_security_critical(OIDC_USER_PROVISIONED));
        assert!(is_security_critical(USER_SESSIONS_TERMINATED));
        assert!(is_security_critical(PASSWORD_RESET_COMPLETE));

        // Deliberately EXCLUDED: floodable / high-volume security events stay
        // fire-and-forget so awaiting them can't amplify a flood into a DoS,
        // plus the non-committed `mfa_setup_initiated` step.
        assert!(!is_security_critical(AUTH_DENIED));
        assert!(!is_security_critical(LOGIN_FAILED));
        assert!(!is_security_critical(MFA_CHALLENGE_ISSUED));
        assert!(!is_security_critical(MFA_CHALLENGE_FAILED));
        assert!(!is_security_critical(MFA_SETUP_INITIATED));
        assert!(!is_security_critical(PASSWORD_RESET_REQUEST));

        // Routine, high-volume mutations are never durable.
        assert!(!is_security_critical(RULE_CREATED));
        assert!(!is_security_critical(SEARCH_HISTORY_CLEARED));
        assert!(!is_security_critical(TOKEN_REFRESH));
        assert!(!is_security_critical("nonexistent_action"));
    }
}
