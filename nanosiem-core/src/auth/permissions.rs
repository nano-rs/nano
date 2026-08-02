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

// Artifact permissions (NAN-1977) — shared artifact-analysis store
pub const ARTIFACTS_VIEW: &str = "artifacts:view";
pub const ARTIFACTS_CREATE: &str = "artifacts:create";
pub const ARTIFACTS_EDIT: &str = "artifacts:edit";
pub const ARTIFACTS_DELETE: &str = "artifacts:delete";

// Notebook permissions
pub const NOTEBOOKS_VIEW: &str = "notebooks:view";
pub const NOTEBOOKS_CREATE: &str = "notebooks:create";
pub const NOTEBOOKS_EDIT: &str = "notebooks:edit";
pub const NOTEBOOKS_DELETE: &str = "notebooks:delete";
pub const NOTEBOOKS_SHARE: &str = "notebooks:share";
/// Record a CLIENT-HOSTED agent's transcript into a notebook (NAN-1840).
///
/// Distinct from `notebooks:edit` on purpose. It gates the one endpoint that
/// accepts the AI-reserved entry types, which `POST /entries` refuses (NAN-686) —
/// the server stamps the provenance itself, so an entry recorded by an analyst's
/// local agent can never masquerade as one a trusted server flow produced.
pub const NOTEBOOKS_AGENT_RECORD: &str = "notebooks:agent_record";

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
/// Attach or use stored credential material in a runtime integration.
///
/// Deliberately separate from `credentials:view`: viewing credential metadata
/// must not authorize a caller to cause secret material to be decrypted.
pub const CREDENTIALS_USE: &str = "credentials:use";
/// Rotate or roll back the secret material on a stored credential.
///
/// Separate from `credentials:edit`: rotation replaces the secret itself rather
/// than metadata, and downstream source configs pick up the new value on their
/// next deploy. Seeded by migration 165 and, for installs that skipped it,
/// 278 (NAN-2218).
pub const CREDENTIALS_ROTATE: &str = "credentials:rotate";

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

// System health event bus permissions
pub const SYSTEM_HEALTH_VIEW: &str = "system_health:view";
pub const SYSTEM_HEALTH_MANAGE: &str = "system_health:manage";

// Settings permissions
pub const SETTINGS_VIEW: &str = "settings:view";
pub const SETTINGS_SYSTEM: &str = "settings:system";
pub const SETTINGS_RETENTION: &str = "settings:retention";
pub const SETTINGS_AI: &str = "settings:ai";
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

// Detection-as-Code push target permissions (NAN-1745)
pub const DETECTION_CODE_TARGETS_VIEW: &str = "detection_code_targets:view";
pub const DETECTION_CODE_TARGETS_MANAGE: &str = "detection_code_targets:manage";

// Per-source RBAC scoping permissions (NAN-1797)
pub const SOURCE_SCOPES_VIEW: &str = "source_scopes:view";
pub const SOURCE_SCOPES_MANAGE: &str = "source_scopes:manage";
/// ADMIN / full-visibility bypass for per-source RBAC (NAN-1841 / F-34).
///
/// A caller holding this permission sees EVERY `source_type` regardless of the
/// restricted-source registry — `SourceScopeResolver::resolve` short-circuits to
/// an empty (unrestricted) deny set for them. Without such a bypass, any source
/// marked restricted without a matching grant is invisible to EVERYONE, admins
/// included (a restricted source with no grant is `denied` for all), which made
/// `GET /api/cases/{id}` 404 for admins on cases whose alerts were all from
/// denied sources.
///
/// DELIBERATELY DISTINCT from [`SOURCE_SCOPES_MANAGE`]: administering the
/// restriction registry/grants (config control) must not silently also confer
/// the right to READ every restricted compartment. This is a POSITIVE
/// data-visibility grant, held by the Admin role only (see migration 255).
pub const SOURCE_SCOPES_VIEW_ALL: &str = "source_scopes:view_all";

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

// Hunt permissions (NAN-2238 Active Hunter).
//
// Separate from `playbooks:*` even though a hunt definition lives in the
// `playbooks` table: the two have different audiences and different blast
// radii. `playbooks:manage` grants authority over case-response procedure;
// `hunts:manage` grants authority over what runs unattended against the whole
// log estate on a schedule.
pub const HUNTS_VIEW: &str = "hunts:view";
pub const HUNTS_MANAGE: &str = "hunts:manage";
/// Enable/disable a hunt's schedule and trigger a manual sweep. Deliberately
/// distinct from `HUNTS_MANAGE`: authoring a hunt and putting it on a cron
/// against production telemetry are different decisions.
pub const HUNTS_RUN: &str = "hunts:run";
/// Promote a lead to a case, and dismiss a lead into a tenant-wide
/// suppression. Both are analyst-only by design — the hunter agent has no
/// path to either, because a suppression it could write would let it blind
/// its own successors.
pub const HUNTS_TRIAGE: &str = "hunts:triage";
/// The ONLY scope minted into a hunt runner's key: append a sweep result and
/// its leads. Not `hunts:manage`, not `cases:edit`, not the parser writes pivt's
/// interactive key carries. The agent submits evidence and narrative; the server
/// computes the score, the fingerprint and the notebook target.
///
/// **Held by Admin** (9000059). An earlier revision withheld it from every role
/// on the theory that a scope meant for a minted key should not be assignable to
/// a human — which was self-defeating: every minted key in this product is
/// `requested set ∩ the minting user's own permissions`, so a scope no principal
/// holds intersects to nothing and the key can never be created. The narrowness
/// of a minted key comes from the short REQUEST list, not from hiding scopes;
/// pivt's key carries `cases:edit`, which analysts hold too.
///
/// Withholding it also bought nothing. `POST /api/hunts/sweeps/{id}/report`
/// reasserts sweep + runner + fence + unexpired lease + active status under
/// `FOR UPDATE`, so a principal holding this scope with no claimed lease can
/// post nothing. The fence is the control; this is a coarse gate in front of it.
pub const HUNTS_REPORT: &str = "hunts:report";
/// Write a deployment profile and create DISABLED draft hunts — the whole
/// write surface of agent-driven recon, and nothing else.
///
/// Exists because `HUNTS_MANAGE` was the narrowest scope that could save a
/// profile, and it also EDITS and ARCHIVES hunts. A key minted to write one
/// profile could therefore delete the hunt library. Every minted key is
/// `requested set ∩ the minting user's own permissions`, so the narrowness has
/// to come from a scope that exists — asking for a subset of `hunts:manage`
/// gets you `hunts:manage`.
///
/// **Held by Admin** (9000060), for the reason 9000059 had to be written at
/// all: a scope no principal holds intersects to nothing and can never be
/// minted, which makes the feature unusable rather than safe.
///
/// `HUNTS_MANAGE` remains sufficient everywhere this is accepted — this only
/// ever widens who may call recon, never narrows it, so nothing that worked
/// before stops working.
pub const HUNTS_PROFILE_WRITE: &str = "hunts:profile_write";

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
    // Artifacts
    ARTIFACTS_VIEW,
    ARTIFACTS_CREATE,
    ARTIFACTS_EDIT,
    ARTIFACTS_DELETE,
    // Notebooks
    NOTEBOOKS_VIEW,
    NOTEBOOKS_AGENT_RECORD,
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
    CREDENTIALS_USE,
    CREDENTIALS_ROTATE,
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
    // System health
    SYSTEM_HEALTH_VIEW,
    SYSTEM_HEALTH_MANAGE,
    // Settings
    SETTINGS_VIEW,
    SETTINGS_SYSTEM,
    SETTINGS_RETENTION,
    SETTINGS_AI,
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
    // Detection-as-Code push targets
    DETECTION_CODE_TARGETS_VIEW,
    DETECTION_CODE_TARGETS_MANAGE,
    // Per-source RBAC scoping
    SOURCE_SCOPES_VIEW,
    SOURCE_SCOPES_MANAGE,
    SOURCE_SCOPES_VIEW_ALL,
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
    // Hunts
    HUNTS_VIEW,
    HUNTS_MANAGE,
    HUNTS_RUN,
    HUNTS_TRIAGE,
    HUNTS_REPORT,
    HUNTS_PROFILE_WRITE,
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
    // Artifacts — full analyst workflow (drop, analyze, curate; scoped to session)
    ARTIFACTS_VIEW,
    ARTIFACTS_CREATE,
    ARTIFACTS_EDIT,
    ARTIFACTS_DELETE,
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
    "artifacts",
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
    "system_health",
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
    "hunts",
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
