// SPDX-License-Identifier: AGPL-3.0-or-later

//! Permission constants organized by feature
//!
//! Requirements: 5.1

// Search permissions
pub const SEARCH_VIEW: &str = "search:view";
pub const SEARCH_EXECUTE: &str = "search:execute";
pub const SEARCH_SAVE: &str = "search:save";
pub const SEARCH_SHARE: &str = "search:share";
pub const SEARCH_SQL: &str = "search:sql";

// Dashboard permissions
pub const DASHBOARDS_VIEW: &str = "dashboards:view";
pub const DASHBOARDS_CREATE: &str = "dashboards:create";
pub const DASHBOARDS_EDIT: &str = "dashboards:edit";
pub const DASHBOARDS_DELETE: &str = "dashboards:delete";

// Notebook permissions
pub const NOTEBOOKS_VIEW: &str = "notebooks:view";
pub const NOTEBOOKS_CREATE: &str = "notebooks:create";
pub const NOTEBOOKS_EDIT: &str = "notebooks:edit";
pub const NOTEBOOKS_DELETE: &str = "notebooks:delete";
pub const NOTEBOOKS_SHARE: &str = "notebooks:share";

// Detection permissions
pub const DETECTIONS_VIEW: &str = "detections:view";
pub const DETECTIONS_CREATE: &str = "detections:create";
pub const DETECTIONS_EDIT: &str = "detections:edit";
pub const DETECTIONS_DELETE: &str = "detections:delete";
pub const DETECTIONS_PROMOTE: &str = "detections:promote";
pub const DETECTIONS_EXPORT: &str = "detections:export";

// Alert permissions
pub const ALERTS_VIEW: &str = "alerts:view";
pub const ALERTS_ACKNOWLEDGE: &str = "alerts:acknowledge";
pub const ALERTS_CLOSE: &str = "alerts:close";
pub const ALERTS_ASSIGN: &str = "alerts:assign";
pub const ALERTS_TRIAGE: &str = "alerts:triage";

// Case permissions
pub const CASES_VIEW: &str = "cases:view";
pub const CASES_CREATE: &str = "cases:create";
pub const CASES_EDIT: &str = "cases:edit";
pub const CASES_DELETE: &str = "cases:delete";
pub const CASES_ASSIGN: &str = "cases:assign";
pub const CASES_CLOSE: &str = "cases:close";
pub const CASES_COMMENT: &str = "cases:comment";
pub const CASES_SHARE: &str = "cases:share";

// Parser permissions
pub const PARSERS_VIEW: &str = "parsers:view";
pub const PARSERS_CREATE: &str = "parsers:create";
pub const PARSERS_EDIT: &str = "parsers:edit";
pub const PARSERS_DELETE: &str = "parsers:delete";
pub const PARSERS_DEPLOY: &str = "parsers:deploy";

// Log Source permissions
pub const LOG_SOURCES_VIEW: &str = "log_sources:view";
pub const LOG_SOURCES_CREATE: &str = "log_sources:create";
pub const LOG_SOURCES_EDIT: &str = "log_sources:edit";
pub const LOG_SOURCES_DELETE: &str = "log_sources:delete";
pub const LOG_SOURCES_DEPLOY: &str = "log_sources:deploy";

// Source Configuration permissions
pub const SOURCE_CONFIGS_VIEW: &str = "source_configs:view";
pub const SOURCE_CONFIGS_CREATE: &str = "source_configs:create";
pub const SOURCE_CONFIGS_EDIT: &str = "source_configs:edit";
pub const SOURCE_CONFIGS_DELETE: &str = "source_configs:delete";
pub const SOURCE_CONFIGS_DEPLOY: &str = "source_configs:deploy";

// Credential permissions
pub const CREDENTIALS_VIEW: &str = "credentials:view";
pub const CREDENTIALS_CREATE: &str = "credentials:create";
pub const CREDENTIALS_EDIT: &str = "credentials:edit";
pub const CREDENTIALS_DELETE: &str = "credentials:delete";

// Enrichment permissions
pub const ENRICHMENTS_VIEW: &str = "enrichments:view";
pub const ENRICHMENTS_CONFIGURE: &str = "enrichments:configure";
pub const ENRICHMENTS_CODE: &str = "enrichments:code"; // Manual code editor access
pub const ENRICHMENTS_CUSTOM_CREATE: &str = "enrichments:custom:create";
pub const ENRICHMENTS_CUSTOM_DELETE: &str = "enrichments:custom:delete";

// Lookup table permissions
pub const LOOKUP_VIEW: &str = "lookup:view";
pub const LOOKUP_CREATE: &str = "lookup:create";
pub const LOOKUP_EDIT: &str = "lookup:edit";
pub const LOOKUP_DELETE: &str = "lookup:delete";

// Upload permissions
pub const UPLOAD_LOGS: &str = "upload:logs";
pub const UPLOAD_HISTORY: &str = "upload:history";

// Risk analytics permissions
pub const RISK_VIEW: &str = "risk:view";
pub const RISK_CONFIGURE: &str = "risk:configure";
pub const RISK_CLEAR: &str = "risk:clear";

// Prevalence tracking permissions
pub const PREVALENCE_VIEW: &str = "prevalence:view";
pub const PREVALENCE_CONFIGURE: &str = "prevalence:configure";
pub const PREVALENCE_EXPORT: &str = "prevalence:export";

// Notification permissions
pub const NOTIFICATIONS_VIEW: &str = "notifications:view";
pub const NOTIFICATIONS_MANAGE: &str = "notifications:manage";

// Settings permissions
pub const SETTINGS_VIEW: &str = "settings:view";
pub const SETTINGS_SYSTEM: &str = "settings:system";
pub const SETTINGS_RETENTION: &str = "settings:retention";
pub const SETTINGS_AI: &str = "settings:ai";
pub const SETTINGS_RISK: &str = "settings:risk";
pub const SETTINGS_WEBHOOKS: &str = "settings:webhooks";
pub const SETTINGS_AI_PROVIDERS: &str = "settings:ai_providers";
pub const SETTINGS_AGENT_MODELS: &str = "settings:agent_models";

// User management permissions
pub const USERS_VIEW: &str = "users:view";
pub const USERS_CREATE: &str = "users:create";
pub const USERS_EDIT: &str = "users:edit";
pub const USERS_DELETE: &str = "users:delete";

// Session management permissions (H9)
pub const SESSIONS_ADMIN: &str = "sessions:admin";

// Group management permissions
pub const GROUPS_VIEW: &str = "groups:view";
pub const GROUPS_CREATE: &str = "groups:create";
pub const GROUPS_EDIT: &str = "groups:edit";
pub const GROUPS_DELETE: &str = "groups:delete";

// Role management permissions
pub const ROLES_VIEW: &str = "roles:view";
pub const ROLES_CREATE: &str = "roles:create";
pub const ROLES_EDIT: &str = "roles:edit";
pub const ROLES_DELETE: &str = "roles:delete";

// API key permissions
pub const APIKEYS_VIEW: &str = "apikeys:view";
pub const APIKEYS_CREATE: &str = "apikeys:create";
pub const APIKEYS_EDIT: &str = "apikeys:edit";
pub const APIKEYS_DELETE: &str = "apikeys:delete";

// Audit permissions
pub const AUDIT_VIEW: &str = "audit:view";

// meloD AI assistant permissions
pub const MELOD_CHAT: &str = "melod:chat";
pub const MELOD_QUERY: &str = "melod:query";
pub const MELOD_PARSER: &str = "melod:parser";
pub const MELOD_DETECTION: &str = "melod:detection";
pub const MELOD_SUMMARIZE: &str = "melod:summarize";
pub const MELOD_DASHBOARD: &str = "melod:dashboard";
pub const MELOD_NOTEBOOK: &str = "melod:notebook";

// MITRE ATT&CK framework permissions
pub const MITRE_VIEW: &str = "mitre:view";
pub const MITRE_SYNC: &str = "mitre:sync";

// Rule Repository permissions
pub const RULE_REPOSITORIES_VIEW: &str = "rule_repositories:view";
pub const RULE_REPOSITORIES_MANAGE: &str = "rule_repositories:manage";
pub const RULE_REPOSITORIES_SYNC: &str = "rule_repositories:sync";
pub const RULE_REPOSITORIES_IMPORT: &str = "rule_repositories:import";

// Parser Repository permissions
pub const PARSER_REPOSITORIES_VIEW: &str = "parser_repositories:view";
pub const PARSER_REPOSITORIES_MANAGE: &str = "parser_repositories:manage";
pub const PARSER_REPOSITORIES_SYNC: &str = "parser_repositories:sync";
pub const PARSER_REPOSITORIES_IMPORT: &str = "parser_repositories:import";

// Playbook permissions
pub const PLAYBOOKS_VIEW: &str = "playbooks:view";
pub const PLAYBOOKS_MANAGE: &str = "playbooks:manage";
pub const PLAYBOOKS_RUN: &str = "playbooks:run";
pub const PLAYBOOKS_PUBLISH: &str = "playbooks:publish";

// Playbook Repository permissions
pub const PLAYBOOK_REPOSITORIES_VIEW: &str = "playbook_repositories:view";
pub const PLAYBOOK_REPOSITORIES_MANAGE: &str = "playbook_repositories:manage";
pub const PLAYBOOK_REPOSITORIES_SYNC: &str = "playbook_repositories:sync";
pub const PLAYBOOK_REPOSITORIES_IMPORT: &str = "playbook_repositories:import";

// GDPR permissions
pub const GDPR_ANONYMIZE: &str = "gdpr:anonymize";

/// All permission IDs in the system
pub const ALL_PERMISSIONS: &[&str] = &[
    // Search
    SEARCH_VIEW,
    SEARCH_EXECUTE,
    SEARCH_SAVE,
    SEARCH_SHARE,
    SEARCH_SQL,
    // Dashboards
    DASHBOARDS_VIEW,
    DASHBOARDS_CREATE,
    DASHBOARDS_EDIT,
    DASHBOARDS_DELETE,
    // Notebooks
    NOTEBOOKS_VIEW,
    NOTEBOOKS_CREATE,
    NOTEBOOKS_EDIT,
    NOTEBOOKS_DELETE,
    NOTEBOOKS_SHARE,
    // Detections
    DETECTIONS_VIEW,
    DETECTIONS_CREATE,
    DETECTIONS_EDIT,
    DETECTIONS_DELETE,
    DETECTIONS_PROMOTE,
    DETECTIONS_EXPORT,
    // Alerts
    ALERTS_VIEW,
    ALERTS_ACKNOWLEDGE,
    ALERTS_CLOSE,
    ALERTS_ASSIGN,
    ALERTS_TRIAGE,
    // Cases
    CASES_VIEW,
    CASES_CREATE,
    CASES_EDIT,
    CASES_DELETE,
    CASES_ASSIGN,
    CASES_CLOSE,
    CASES_COMMENT,
    CASES_SHARE,
    // Parsers
    PARSERS_VIEW,
    PARSERS_CREATE,
    PARSERS_EDIT,
    PARSERS_DELETE,
    PARSERS_DEPLOY,
    // Log Sources
    LOG_SOURCES_VIEW,
    LOG_SOURCES_CREATE,
    LOG_SOURCES_EDIT,
    LOG_SOURCES_DELETE,
    LOG_SOURCES_DEPLOY,
    // Source Configurations
    SOURCE_CONFIGS_VIEW,
    SOURCE_CONFIGS_CREATE,
    SOURCE_CONFIGS_EDIT,
    SOURCE_CONFIGS_DELETE,
    SOURCE_CONFIGS_DEPLOY,
    // Credentials
    CREDENTIALS_VIEW,
    CREDENTIALS_CREATE,
    CREDENTIALS_EDIT,
    CREDENTIALS_DELETE,
    // Enrichments
    ENRICHMENTS_VIEW,
    ENRICHMENTS_CONFIGURE,
    ENRICHMENTS_CODE,
    ENRICHMENTS_CUSTOM_CREATE,
    ENRICHMENTS_CUSTOM_DELETE,
    // Lookup
    LOOKUP_VIEW,
    LOOKUP_CREATE,
    LOOKUP_EDIT,
    LOOKUP_DELETE,
    // Upload
    UPLOAD_LOGS,
    UPLOAD_HISTORY,
    // Risk
    RISK_VIEW,
    RISK_CONFIGURE,
    RISK_CLEAR,
    // Prevalence
    PREVALENCE_VIEW,
    PREVALENCE_CONFIGURE,
    PREVALENCE_EXPORT,
    // Notifications
    NOTIFICATIONS_VIEW,
    NOTIFICATIONS_MANAGE,
    // Settings
    SETTINGS_VIEW,
    SETTINGS_SYSTEM,
    SETTINGS_RETENTION,
    SETTINGS_AI,
    SETTINGS_RISK,
    SETTINGS_WEBHOOKS,
    SETTINGS_AI_PROVIDERS,
    SETTINGS_AGENT_MODELS,
    // Users & Sessions
    USERS_VIEW,
    USERS_CREATE,
    USERS_EDIT,
    USERS_DELETE,
    SESSIONS_ADMIN,
    // Groups
    GROUPS_VIEW,
    GROUPS_CREATE,
    GROUPS_EDIT,
    GROUPS_DELETE,
    // Roles
    ROLES_VIEW,
    ROLES_CREATE,
    ROLES_EDIT,
    ROLES_DELETE,
    // API Keys
    APIKEYS_VIEW,
    APIKEYS_CREATE,
    APIKEYS_EDIT,
    APIKEYS_DELETE,
    // Audit
    AUDIT_VIEW,
    // meloD AI
    MELOD_CHAT,
    MELOD_QUERY,
    MELOD_PARSER,
    MELOD_DETECTION,
    MELOD_SUMMARIZE,
    MELOD_DASHBOARD,
    MELOD_NOTEBOOK,
    // MITRE ATT&CK
    MITRE_VIEW,
    MITRE_SYNC,
    // Rule Repositories
    RULE_REPOSITORIES_VIEW,
    RULE_REPOSITORIES_MANAGE,
    RULE_REPOSITORIES_SYNC,
    RULE_REPOSITORIES_IMPORT,
    // Parser Repositories
    PARSER_REPOSITORIES_VIEW,
    PARSER_REPOSITORIES_MANAGE,
    PARSER_REPOSITORIES_SYNC,
    PARSER_REPOSITORIES_IMPORT,
    // Playbooks
    PLAYBOOKS_VIEW,
    PLAYBOOKS_MANAGE,
    PLAYBOOKS_RUN,
    PLAYBOOKS_PUBLISH,
    // Playbook Repositories
    PLAYBOOK_REPOSITORIES_VIEW,
    PLAYBOOK_REPOSITORIES_MANAGE,
    PLAYBOOK_REPOSITORIES_SYNC,
    PLAYBOOK_REPOSITORIES_IMPORT,
    // GDPR
    GDPR_ANONYMIZE,
];

/// Permissions granted to demo users — analyst experience without admin access
pub const DEMO_PERMISSIONS: &[&str] = &[
    // Search — full power
    SEARCH_VIEW,
    SEARCH_EXECUTE,
    SEARCH_SAVE,
    // Dashboards — full CRUD (scoped to session, cleaned up on expiry)
    DASHBOARDS_VIEW,
    DASHBOARDS_CREATE,
    DASHBOARDS_EDIT,
    DASHBOARDS_DELETE,
    // Notebooks — full CRUD (scoped to session)
    NOTEBOOKS_VIEW,
    NOTEBOOKS_CREATE,
    NOTEBOOKS_EDIT,
    NOTEBOOKS_DELETE,
    // Detections — full CRUD (scoped to session)
    DETECTIONS_VIEW,
    DETECTIONS_CREATE,
    DETECTIONS_EDIT,
    DETECTIONS_DELETE,
    DETECTIONS_PROMOTE,
    DETECTIONS_EXPORT,
    // Alerts — view and triage
    ALERTS_VIEW,
    ALERTS_ACKNOWLEDGE,
    ALERTS_CLOSE,
    ALERTS_TRIAGE,
    // Cases — full CRUD (scoped to session)
    CASES_VIEW,
    CASES_CREATE,
    CASES_EDIT,
    CASES_DELETE,
    CASES_COMMENT,
    // Risk — view only
    RISK_VIEW,
    // Prevalence — view and export
    PREVALENCE_VIEW,
    PREVALENCE_EXPORT,
    // meloD AI — full access
    MELOD_CHAT,
    MELOD_QUERY,
    MELOD_PARSER,
    MELOD_DETECTION,
    MELOD_SUMMARIZE,
    MELOD_DASHBOARD,
    MELOD_NOTEBOOK,
    // MITRE — view only
    MITRE_VIEW,
    // Lookup — view only
    LOOKUP_VIEW,
    // Enrichments — view only
    ENRICHMENTS_VIEW,
    // Parsers — view only
    PARSERS_VIEW,
    // Rule repos — view only
    RULE_REPOSITORIES_VIEW,
    // Parser repos — view only
    PARSER_REPOSITORIES_VIEW,
    // Playbooks — full CRUD (scoped to session), matching Notebooks/Detections/Cases.
    // NAN-841: prospects should be able to evaluate authoring + running playbooks.
    PLAYBOOKS_VIEW,
    PLAYBOOKS_MANAGE,
    PLAYBOOKS_RUN,
    PLAYBOOKS_PUBLISH,
    PLAYBOOK_REPOSITORIES_VIEW,
    // Settings — AI provider read access (needed to detect meloD availability
    // for natural language search; write endpoints are blocked by managed mode)
    SETTINGS_AI,
    // Settings — umbrella view for the /settings index. NAN-841: makes the
    // Settings nav entry visible to demo users so they can see the surface
    // exists; sub-page handlers stay blocked by demo_guard's BLOCKED_PREFIXES
    // until NAN-842 ships the secret-masking audit + per-area read access.
    SETTINGS_VIEW,
];

/// Permission categories
pub const CATEGORIES: &[&str] = &[
    "search",
    "dashboards",
    "notebooks",
    "detections",
    "alerts",
    "cases",
    "parsers",
    "log_sources",
    "source_configs",
    "credentials",
    "enrichments",
    "lookup",
    "upload",
    "notifications",
    "risk",
    "prevalence",
    "settings",
    "users",
    "groups",
    "roles",
    "apikeys",
    "audit",
    "melod",
    "mitre",
    "rule_repositories",
    "parser_repositories",
    "gdpr",
];

/// Check if a permission ID is valid
pub fn is_valid_permission(permission: &str) -> bool {
    ALL_PERMISSIONS.contains(&permission)
}

/// Get all permissions for a category
pub fn permissions_for_category(category: &str) -> Vec<&'static str> {
    ALL_PERMISSIONS
        .iter()
        .filter(|p| p.starts_with(&format!("{}:", category)))
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_permissions_are_valid_format() {
        for perm in ALL_PERMISSIONS {
            assert!(perm.contains(':'), "Permission {} should contain ':'", perm);
            let parts: Vec<&str> = perm.split(':').collect();
            assert!(
                parts.len() >= 2,
                "Permission {} should have at least one ':' separator",
                perm
            );
            assert!(
                !parts[0].is_empty(),
                "Permission {} category should not be empty",
                perm
            );
            assert!(
                !parts[1].is_empty(),
                "Permission {} action should not be empty",
                perm
            );
        }
    }

    #[test]
    fn test_is_valid_permission() {
        assert!(is_valid_permission(SEARCH_VIEW));
        assert!(is_valid_permission(USERS_CREATE));
        assert!(!is_valid_permission("invalid:permission"));
        assert!(!is_valid_permission(""));
    }

    #[test]
    fn test_permissions_for_category() {
        let search_perms = permissions_for_category("search");
        assert_eq!(search_perms.len(), 5);
        assert!(search_perms.contains(&SEARCH_VIEW));
        assert!(search_perms.contains(&SEARCH_EXECUTE));
    }
}
