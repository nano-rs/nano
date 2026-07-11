// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unified Audit Event System
//!
//! Emits platform audit events as searchable log entries with source_type='audit'.
//! All platform operations (auth, detection, user management, etc.) emit events here.
//!
//! ## UDM Field Mapping
//!
//! Audit events are mapped to UDM fields as follows:
//! - `status`: Set to "success" or "failure" for ALL audit events
//! - `auth_result`: Only set for authentication events (source=auth), otherwise None
//! - `action`: The specific action performed (e.g., "login_success", "feed_stale")
//! - `source`: The subsystem that generated the event (auth, ingest, detection, etc.)
//!
//! This ensures that non-authentication events (like feed monitoring) don't incorrectly
//! populate the `auth_result` field, which is semantically specific to authentication.
//!
//! Example queries:
//! - `source_type=audit source=auth action=login_success` - Successful logins
//! - `source_type=audit source=detection action=rule_created` - Detection rule changes
//! - `source_type=audit source=ingest status=failure` - Ingestion failures (uses status, not auth_result)
//! - `source_type=audit | stats count by source, action` - Activity breakdown

pub mod actions;
mod context;
mod emitter;
pub mod query;

pub use actions::*;
pub use context::ClientContext;
pub use emitter::{AuditEmitError, AuditEmitter};
pub use query::{AuditQueryError, AuditQueryService, ClickHouseAuditEntry, ClickHouseAuditQuery};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::ingestion::ParsedLog;

/// Subsystem that generated the audit event
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditSource {
    /// Authentication events (login, logout, token refresh, password reset)
    Auth,
    /// Detection rule events (create, update, delete, enable, disable)
    Detection,
    /// User management events (create, update, delete, lock, unlock)
    User,
    /// Auto-tuning events (proposal approve, reject, settings update)
    Tuning,
    /// MITRE ATT&CK catalog synchronization events
    Mitre,
    /// Case management events (create, update, delete)
    Case,
    /// API key events (create, delete, enable, disable)
    ApiKey,
    /// Role management events (create, update, delete)
    Role,
    /// Group management events (create, update, delete, member changes)
    Group,
    /// Cloud credential events (create, update, delete)
    Credentials,
    /// Search events (saved search sharing)
    Search,
    /// Ingestion/health events (feed staleness, ingestion errors)
    Ingest,
    /// Webhook events (create, update, delete)
    Webhook,
    /// Storage events (disk pressure, partition drops)
    Storage,
    /// Identity provider events (create, update, delete, sync)
    Identity,
    /// Marketplace events (install, uninstall, update, configure, repo sync)
    Marketplace,
    /// Dashboard events (create, update, delete, share, export, import)
    Dashboard,
    /// Notebook events (create, update, delete, share, entries, escalation)
    Notebook,
    /// Alert events (acknowledge, close, assign, bulk operations)
    Alert,
    /// Query library events (saved query CRUD)
    QueryLibrary,
    /// Log source events (CRUD, deploy/undeploy)
    LogSource,
    /// Source configuration events (CRUD, routing rules)
    SourceConfig,
    /// Enrichment events (configure, sync, enable/disable)
    Enrichment,
    /// Custom enrichment events (CRUD, deploy)
    CustomEnrichment,
    /// Agent enrichment provider events (CRUD)
    AgentEnrichment,
    /// Session events (termination)
    Session,
    /// OIDC provider events (CRUD, group mappings)
    Oidc,
    /// Parser repository events (CRUD, sync, import)
    ParserRepo,
    /// Rule repository events (CRUD, sync, import)
    RuleRepo,
    /// System settings events (melod, retention, risk, tiering, AI providers)
    Settings,
    /// Risk score events (clear entity, clear all)
    Risk,
    /// Lookup table events (CRUD)
    Lookup,
    /// GDPR data subject anonymization events
    Gdpr,
    /// Audit subsystem events (export/read of the audit trail itself)
    Audit,
}

impl std::fmt::Display for AuditSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth => write!(f, "auth"),
            Self::Detection => write!(f, "detection"),
            Self::User => write!(f, "user"),
            Self::Tuning => write!(f, "tuning"),
            Self::Mitre => write!(f, "mitre"),
            Self::Case => write!(f, "case"),
            Self::ApiKey => write!(f, "apikey"),
            Self::Role => write!(f, "role"),
            Self::Group => write!(f, "group"),
            Self::Credentials => write!(f, "credentials"),
            Self::Search => write!(f, "search"),
            Self::Ingest => write!(f, "ingest"),
            Self::Webhook => write!(f, "webhook"),
            Self::Storage => write!(f, "storage"),
            Self::Identity => write!(f, "identity"),
            Self::Marketplace => write!(f, "marketplace"),
            Self::Dashboard => write!(f, "dashboard"),
            Self::Notebook => write!(f, "notebook"),
            Self::Alert => write!(f, "alert"),
            Self::QueryLibrary => write!(f, "query_library"),
            Self::LogSource => write!(f, "log_source"),
            Self::SourceConfig => write!(f, "source_config"),
            Self::Enrichment => write!(f, "enrichment"),
            Self::CustomEnrichment => write!(f, "custom_enrichment"),
            Self::AgentEnrichment => write!(f, "agent_enrichment"),
            Self::Session => write!(f, "session"),
            Self::Oidc => write!(f, "oidc"),
            Self::ParserRepo => write!(f, "parser_repo"),
            Self::RuleRepo => write!(f, "rule_repo"),
            Self::Settings => write!(f, "settings"),
            Self::Risk => write!(f, "risk"),
            Self::Lookup => write!(f, "lookup"),
            Self::Gdpr => write!(f, "gdpr"),
            Self::Audit => write!(f, "audit"),
        }
    }
}

/// Unified audit event for all subsystems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Subsystem that generated this event
    pub source: AuditSource,
    /// Action performed (underscore convention: login_success, rule_created)
    pub action: String,
    /// User ID who performed the action (None for system actions)
    pub actor_id: Option<Uuid>,
    /// Actor's display name
    pub actor_name: Option<String>,
    /// API key ID if authenticated via API key
    pub api_key_id: Option<Uuid>,
    /// API key display name if authenticated via API key
    pub api_key_name: Option<String>,
    /// Resource type affected (user, detection_rule, api_key, etc.)
    pub resource_type: Option<String>,
    /// Resource ID affected
    pub resource_id: Option<Uuid>,
    /// Resource name/identifier for display
    pub resource_name: Option<String>,
    /// Client IP address
    pub ip_address: Option<String>,
    /// Client user agent
    pub user_agent: Option<String>,
    /// Whether the action succeeded
    pub success: bool,
    /// Additional context as JSON (varies by action)
    pub details: Option<serde_json::Value>,
}

impl AuditEvent {
    /// Create a new audit event builder
    pub fn builder(source: AuditSource, action: &str) -> AuditEventBuilder {
        AuditEventBuilder {
            source,
            action: action.to_string(),
            actor_id: None,
            actor_name: None,
            api_key_id: None,
            api_key_name: None,
            resource_type: None,
            resource_id: None,
            resource_name: None,
            ip_address: None,
            user_agent: None,
            success: true,
            details: None,
        }
    }

    /// Build the human-readable message line for full-text search. Shared by
    /// the UDM (`to_parsed_log`) and OCSF (`to_ocsf_event`) storage shapes so
    /// both rows carry the identical hunt-able summary.
    fn build_message(&self) -> String {
        let resource_desc = match (&self.resource_type, &self.resource_name) {
            (Some(rt), Some(rn)) => format!("{} '{}'", rt, rn),
            (Some(rt), None) => rt.clone(),
            _ => "unknown".to_string(),
        };

        // When the actor was a delegated API-key credential, surface it in the
        // human-readable message so reviewers can tell at a glance that the
        // owning user's name is acting via a service credential, not in person.
        let actor_desc = match (self.actor_name.as_deref(), self.api_key_name.as_deref(), self.api_key_id) {
            (Some(name), Some(key_name), _) => format!("{} via API key '{}'", name, key_name),
            (Some(name), None, Some(key_id)) => format!("{} via API key {}", name, key_id),
            (Some(name), None, None) => name.to_string(),
            (None, Some(key_name), _) => format!("API key '{}'", key_name),
            (None, None, Some(key_id)) => format!("API key {}", key_id),
            (None, None, None) => "system".to_string(),
        };

        format!(
            "[{}] {} on {} by {}",
            self.source, self.action, resource_desc, actor_desc
        )
    }

    /// Convert this audit event into a ParsedLog for storage
    pub fn to_parsed_log(&self) -> ParsedLog {
        let now = Utc::now();

        // Build the message for full-text search
        let message = self.build_message();

        // Build metadata JSON for audit-specific fields not in UDM schema
        // (source, action, src_ip, user_agent, status are already top-level columns)
        let metadata = json!({
            "actor_id": self.actor_id.map(|id| id.to_string()),
            "actor_name": self.actor_name,
            "api_key_id": self.api_key_id.map(|id| id.to_string()),
            "api_key_name": self.api_key_name,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id.map(|id| id.to_string()),
            "resource_name": self.resource_name,
            "success": self.success,
            "details": self.details,
        });

        ParsedLog {
            timestamp: now,
            message,
            metadata,
            source_type: "audit".to_string(),
            source: Some(self.source.to_string()),
            // Use standard UDM fields where appropriate.
            //
            // LOWERCASE_NORMALIZED_FIELDS contract (NAN-1432): `user`, `action`
            // and `src_ip` are raw-equality compared by the SQL generator (no
            // `lower()` wrapper, so the raw-column indexes prune), which is only
            // correct if every writer stores them lowercase. The display-case
            // actor name is preserved in `metadata.actor_name` (above) and in
            // `message`; the audit page renders from metadata
            // (`audit/query.rs::row_to_entry`).
            user: self.actor_name.as_ref().map(|n| n.to_lowercase()),
            action: Some(self.action.to_lowercase()),
            status: Some(if self.success { "success" } else { "failure" }.to_string()),
            severity: None, // Audit events don't have severity
            src_ip: self.ip_address.as_ref().map(|ip| ip.to_lowercase()),
            user_agent: self.user_agent.clone(),
            ext: None, // Audit events don't have extended fields beyond UDM
            // Session ID stores the resource ID for correlation
            session_id: self.resource_id.map(|id| id.to_string()),
            // Leave other fields empty
            dest_ip: None,
            src_host: None,
            dest_host: None,
            src_port: None,
            dest_port: None,
            protocol: None,
            auth_type: None,
            // Only set auth_result for authentication events
            auth_result: if matches!(self.source, AuditSource::Auth) {
                Some(if self.success { "success" } else { "failure" }.to_string())
            } else {
                None
            },
            process_name: None,
            process_id: None,
            command_line: None,
            parent_process_name: None,
            parent_command_line: None,
            file_path: None,
            file_name: None,
            file_hash: None,
            file_action: None,
            bytes_in: None,
            bytes_out: None,
        }
    }

    /// Map the nano audit `action` verb onto the OCSF API Activity
    /// `activity_id` enum: 1=Create, 2=Read, 3=Update, 4=Delete, 99=Other.
    /// Heuristic on the underscore-convention action string ("rule_created",
    /// "user_deleted", "audit_exported"); anything unrecognized is Other — the
    /// exact nano verb is always preserved verbatim in `api.operation`.
    fn ocsf_activity(&self) -> (i64, &'static str) {
        let action = self.action.to_lowercase();
        if action.contains("creat") || action.contains("import") || action.contains("install") {
            (1, "Create")
        } else if action.contains("read") || action.contains("export") || action.contains("view") || action.contains("download") {
            (2, "Read")
        } else if action.contains("updat")
            || action.contains("enabl")
            || action.contains("disabl")
            || action.contains("chang")
            || action.contains("edit")
        {
            (3, "Update")
        } else if action.contains("delet") || action.contains("remov") || action.contains("uninstall") {
            (4, "Delete")
        } else {
            (99, "Other")
        }
    }

    /// Convert this audit event into an OCSF API Activity (`class_uid` 6003)
    /// `event` JSON for `ocsf_logs` storage (NAN-1390).
    ///
    /// Platform audit records are actor-performs-operation-on-resource shaped,
    /// which is exactly the OCSF API Activity model (the same class CloudTrail
    /// maps to): `actor.user` carries who, `api.operation`/`api.service.name`
    /// carry the nano action + subsystem, `resources[]` carries what was acted
    /// on, and `src_endpoint.ip`/`http_request.user_agent` carry the client.
    /// The full nano-native payload mirrors `to_parsed_log`'s metadata under
    /// `unmapped` — the sanctioned vendor-extension object (same pattern as the
    /// NAN-1254 Detection Finding 2004 writer in `detection/findings.rs`) — so
    /// no information is lost relative to the UDM row.
    ///
    /// `time` is epoch milliseconds per the OCSF `timestamp_t` spec; the caller
    /// passes the same instant it binds into the explicit `timestamp` column so
    /// the two never drift.
    pub fn to_ocsf_event(&self, time: chrono::DateTime<Utc>) -> serde_json::Value {
        let (activity_id, activity_name) = self.ocsf_activity();
        const CLASS_UID: i64 = 6003; // API Activity

        let (status_id, status) = if self.success {
            (1, "Success")
        } else {
            (2, "Failure")
        };

        json!({
            "class_uid": CLASS_UID,
            "class_name": "API Activity",
            "category_uid": 6,
            "category_name": "Application Activity",
            "activity_id": activity_id,
            "activity_name": activity_name,
            "type_uid": CLASS_UID * 100 + activity_id,
            // OCSF `time` is epoch milliseconds.
            "time": time.timestamp_millis(),
            "message": self.build_message(),
            "severity_id": 1,
            "severity": "Informational",
            "status_id": status_id,
            "status": status,
            "metadata": {
                "product": { "name": "nano", "vendor_name": "nano" },
                "log_name": "audit",
            },
            "actor": {
                "user": {
                    "name": self.actor_name,
                    "uid": self.actor_id.map(|id| id.to_string()),
                },
            },
            "api": {
                "operation": self.action,
                "service": { "name": self.source.to_string() },
            },
            "src_endpoint": { "ip": self.ip_address },
            "http_request": { "user_agent": self.user_agent },
            "resources": [{
                "type": self.resource_type,
                "uid": self.resource_id.map(|id| id.to_string()),
                "name": self.resource_name,
            }],
            // nano vendor extension — byte-parity with the UDM row's metadata
            // JSON (plus source/action, which UDM stores as top-level columns).
            "unmapped": {
                "source": self.source.to_string(),
                "action": self.action,
                "actor_id": self.actor_id.map(|id| id.to_string()),
                "actor_name": self.actor_name,
                "api_key_id": self.api_key_id.map(|id| id.to_string()),
                "api_key_name": self.api_key_name,
                "resource_type": self.resource_type,
                "resource_id": self.resource_id.map(|id| id.to_string()),
                "resource_name": self.resource_name,
                "success": self.success,
                "details": self.details,
            },
        })
    }
}

/// Builder for AuditEvent
pub struct AuditEventBuilder {
    source: AuditSource,
    action: String,
    actor_id: Option<Uuid>,
    actor_name: Option<String>,
    api_key_id: Option<Uuid>,
    api_key_name: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<Uuid>,
    resource_name: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    success: bool,
    details: Option<serde_json::Value>,
}

impl AuditEventBuilder {
    /// Set the actor (user performing the action)
    pub fn actor(mut self, id: Option<Uuid>, name: Option<String>) -> Self {
        self.actor_id = id;
        self.actor_name = name;
        self
    }

    /// Set the API key actor (id and display name) when the request was
    /// authenticated via an API key. Both are stored and surfaced in the audit
    /// API response and the human-readable message so investigators can
    /// distinguish delegated-credential actions from interactive-session ones.
    pub fn api_key(mut self, id: Option<Uuid>, name: Option<String>) -> Self {
        self.api_key_id = id;
        self.api_key_name = name;
        self
    }

    /// Set the resource being acted upon
    pub fn resource(mut self, resource_type: &str, id: Option<Uuid>, name: Option<String>) -> Self {
        self.resource_type = Some(resource_type.to_string());
        self.resource_id = id;
        self.resource_name = name;
        self
    }

    /// Set client connection info (IP and user agent)
    pub fn client(mut self, ip: Option<String>, user_agent: Option<String>) -> Self {
        self.ip_address = ip;
        self.user_agent = user_agent;
        self
    }

    /// Set client connection info from ClientContext
    pub fn client_context(mut self, ctx: &ClientContext) -> Self {
        self.ip_address = ctx.ip_address.clone();
        self.user_agent = ctx.user_agent.clone();
        self
    }

    /// Set whether the action succeeded (default: true)
    pub fn success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    /// Set additional details as JSON
    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Build the AuditEvent
    pub fn build(self) -> AuditEvent {
        AuditEvent {
            source: self.source,
            action: self.action,
            actor_id: self.actor_id,
            actor_name: self.actor_name,
            api_key_id: self.api_key_id,
            api_key_name: self.api_key_name,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            resource_name: self.resource_name,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            success: self.success,
            details: self.details,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_to_parsed_log() {
        let event = AuditEvent::builder(AuditSource::Detection, "rule_created")
            .actor(Some(Uuid::now_v7()), Some("admin@example.com".to_string()))
            .resource(
                "detection_rule",
                Some(Uuid::now_v7()),
                Some("Suspicious Login".to_string()),
            )
            .success(true)
            .build();

        let log = event.to_parsed_log();

        assert_eq!(log.source_type, "audit");
        assert_eq!(log.action, Some("rule_created".to_string()));
        assert_eq!(log.status, Some("success".to_string()));
        assert!(log.message.contains("[detection]"));
        assert!(log.message.contains("rule_created"));
    }

    #[test]
    fn test_audit_source_display() {
        assert_eq!(AuditSource::Auth.to_string(), "auth");
        assert_eq!(AuditSource::Detection.to_string(), "detection");
        assert_eq!(AuditSource::User.to_string(), "user");
        assert_eq!(AuditSource::Mitre.to_string(), "mitre");
        // Defenders filter exports by `source=audit`; lock the wire form (NAN-1365).
        assert_eq!(AuditSource::Audit.to_string(), "audit");
    }

    #[test]
    fn test_export_action_constants_are_stable() {
        // Saved searches / dashboards key on these exact strings.
        assert_eq!(crate::audit::AUDIT_LOGS_EXPORTED, "audit_logs_exported");
        assert_eq!(crate::audit::RULES_EXPORTED, "rules_exported");
    }

    #[test]
    fn test_search_history_action_constants_are_stable() {
        // Anti-forensics hunts filter on these exact strings (NAN-1366).
        assert_eq!(crate::audit::SEARCH_HISTORY_DELETED, "search_history_deleted");
        assert_eq!(crate::audit::SEARCH_HISTORY_CLEARED, "search_history_cleared");
        assert_eq!(crate::audit::SEARCH_HISTORY_ENABLED, "search_history_enabled");
        assert_eq!(
            crate::audit::SEARCH_HISTORY_DISABLED,
            "search_history_disabled"
        );
    }

    #[test]
    fn test_api_key_actor_in_message_and_metadata() {
        let owner_id = Uuid::now_v7();
        let key_id = Uuid::now_v7();
        let event = AuditEvent::builder(AuditSource::ApiKey, "apikey_disabled")
            .actor(Some(owner_id), Some("Dan Lussier".to_string()))
            .api_key(Some(key_id), Some("ci-bot".to_string()))
            .resource(
                "api_key",
                Some(Uuid::now_v7()),
                Some("target-key".to_string()),
            )
            .build();

        let log = event.to_parsed_log();

        assert!(
            log.message.contains("Dan Lussier via API key 'ci-bot'"),
            "message should attribute action to delegated credential, got: {}",
            log.message
        );
        assert_eq!(
            log.metadata.get("api_key_id").and_then(|v| v.as_str()),
            Some(key_id.to_string().as_str())
        );
        assert_eq!(
            log.metadata.get("api_key_name").and_then(|v| v.as_str()),
            Some("ci-bot")
        );
    }

    #[test]
    fn test_human_actor_message_omits_api_key_clause() {
        let event = AuditEvent::builder(AuditSource::ApiKey, "apikey_created")
            .actor(Some(Uuid::now_v7()), Some("Dan Lussier".to_string()))
            .resource(
                "api_key",
                Some(Uuid::now_v7()),
                Some("new-key".to_string()),
            )
            .build();

        let log = event.to_parsed_log();

        assert!(log.message.ends_with("by Dan Lussier"), "got: {}", log.message);
        assert!(log.metadata.get("api_key_id").is_some_and(|v| v.is_null()));
        assert!(log.metadata.get("api_key_name").is_some_and(|v| v.is_null()));
    }

    /// NAN-1432: every field in `LOWERCASE_NORMALIZED_FIELDS` is compared with
    /// raw equality by the SQL generator (no `lower()` wrapper, so the
    /// raw-column indexes prune) — sound only if every writer stores those
    /// columns lowercase. The audit emitter is the one in-process writer to
    /// `logs` (Vector's VRL handles everything else), so it must uphold the
    /// contract: pre-fix it stored display-case actor names and
    /// `user="dan lussier"` found 0 audit rows.
    ///
    /// The list is consumed dynamically: a field added to
    /// `LOWERCASE_NORMALIZED_FIELDS` without a mapping here fails the test
    /// with instructions instead of silently going unchecked.
    #[test]
    fn test_audit_writer_upholds_lowercase_normalized_fields_contract() {
        use crate::ingestion::ClickHouseLogRow;
        use crate::query::LOWERCASE_NORMALIZED_FIELDS;

        // Mixed-case inputs in every contract field the builder can populate.
        let event = AuditEvent::builder(AuditSource::Auth, "Login_Failed")
            .actor(Some(Uuid::now_v7()), Some("Dan Lussier".to_string()))
            .client(
                Some("FE80::1ABC:2DEF".to_string()), // IPv6 with uppercase hex
                Some("Mozilla/5.0".to_string()),
            )
            .build();

        let row = ClickHouseLogRow::from_parsed_log(&event.to_parsed_log(), Utc::now());

        for field in LOWERCASE_NORMALIZED_FIELDS {
            // Map the queryable field name onto the column the audit writer
            // produces. `sourcetype` is a query-layer alias of `source_type`;
            // `event_type` is a ClickHouse ALIAS of `action`.
            let value: &str = match *field {
                "source_type" | "sourcetype" => &row.source_type,
                "event_type" | "action" => &row.action,
                "src_ip" => &row.src_ip,
                "dest_ip" => &row.dest_ip,
                "src_host" => &row.src_host,
                "dest_host" => &row.dest_host,
                "protocol" => &row.protocol,
                // Not columns of ClickHouseLogRow: the audit writer cannot
                // write them, so the contract holds vacuously for audit rows
                // (ClickHouse defaults them to '').
                "user_domain" | "src_mac" | "dest_mac" | "src_user" | "trace_id"
                | "span_id" | "dvc_ip" => continue,
                other => panic!(
                    "`{other}` joined LOWERCASE_NORMALIZED_FIELDS — teach this \
                     contract test where the audit writer surfaces it (or record \
                     here that the writer never populates it)"
                ),
            };
            assert_eq!(
                value,
                value.to_lowercase(),
                "audit writer must store `{field}` lowercase (raw-equality \
                 fast-path precondition), got: {value:?}"
            );
        }

        // The lowercase contract must not cost the display name: it is
        // preserved for the audit page in metadata.actor_name and the message.
        let log = event.to_parsed_log();
        assert_eq!(log.user.as_deref(), Some("dan lussier"));
        assert_eq!(
            log.metadata.get("actor_name").and_then(|v| v.as_str()),
            Some("Dan Lussier")
        );
        assert!(log.message.contains("Dan Lussier"), "got: {}", log.message);
    }

    #[test]
    fn test_failed_action() {
        let event = AuditEvent::builder(AuditSource::Auth, "login_failed")
            .actor(None, Some("unknown@example.com".to_string()))
            .success(false)
            .details(json!({"reason": "invalid_password"}))
            .build();

        let log = event.to_parsed_log();

        assert_eq!(log.status, Some("failure".to_string()));
        assert_eq!(log.auth_result, Some("failure".to_string()));
    }

    /// NAN-1390: the OCSF API Activity (6003) mirror-write contract. The event
    /// must be spec-shaped (class/category/type_uid/time-in-ms) and carry the
    /// full nano-native payload under `unmapped` with the same keys as the UDM
    /// row's metadata JSON, so no information is lost relative to `logs`.
    #[test]
    fn test_audit_event_to_ocsf_event() {
        let actor_id = Uuid::now_v7();
        let resource_id = Uuid::now_v7();
        let event = AuditEvent::builder(AuditSource::Detection, "rule_created")
            .actor(Some(actor_id), Some("admin@example.com".to_string()))
            .resource(
                "detection_rule",
                Some(resource_id),
                Some("Suspicious Login".to_string()),
            )
            .client(Some("10.1.2.3".to_string()), Some("curl/8".to_string()))
            .success(true)
            .build();

        let time = Utc::now();
        let ocsf = event.to_ocsf_event(time);

        assert_eq!(ocsf["class_uid"], 6003);
        assert_eq!(ocsf["category_uid"], 6);
        assert_eq!(ocsf["activity_id"], 1); // "rule_created" -> Create
        assert_eq!(ocsf["type_uid"], 600301);
        assert_eq!(ocsf["time"], time.timestamp_millis());
        assert_eq!(ocsf["status_id"], 1);
        assert_eq!(ocsf["status"], "Success");
        // Identical hunt-able message in both storage shapes.
        assert_eq!(ocsf["message"], event.to_parsed_log().message);
        assert_eq!(ocsf["actor"]["user"]["name"], "admin@example.com");
        assert_eq!(ocsf["actor"]["user"]["uid"], actor_id.to_string());
        assert_eq!(ocsf["api"]["operation"], "rule_created");
        assert_eq!(ocsf["api"]["service"]["name"], "detection");
        assert_eq!(ocsf["src_endpoint"]["ip"], "10.1.2.3");
        assert_eq!(ocsf["http_request"]["user_agent"], "curl/8");
        assert_eq!(ocsf["resources"][0]["type"], "detection_rule");
        assert_eq!(ocsf["resources"][0]["uid"], resource_id.to_string());
        assert_eq!(ocsf["resources"][0]["name"], "Suspicious Login");
        assert_eq!(ocsf["metadata"]["product"]["name"], "nano");

        // `unmapped` carries every key the UDM row's metadata JSON carries,
        // plus source/action (top-level columns on the UDM side).
        let udm_metadata = event.to_parsed_log().metadata;
        let unmapped = &ocsf["unmapped"];
        for key in udm_metadata.as_object().unwrap().keys() {
            assert!(
                unmapped.get(key).is_some(),
                "unmapped missing UDM metadata key '{key}'"
            );
            assert_eq!(&unmapped[key], &udm_metadata[key], "unmapped['{key}'] drifted");
        }
        assert_eq!(unmapped["source"], "detection");
        assert_eq!(unmapped["action"], "rule_created");
    }

    #[test]
    fn test_to_ocsf_event_failure_status() {
        let event = AuditEvent::builder(AuditSource::Auth, "login_failed")
            .success(false)
            .build();
        let ocsf = event.to_ocsf_event(Utc::now());
        assert_eq!(ocsf["status_id"], 2);
        assert_eq!(ocsf["status"], "Failure");
        // No actor: nulls, not fabricated values.
        assert!(ocsf["actor"]["user"]["name"].is_null());
    }

    #[test]
    fn test_ocsf_activity_mapping() {
        let activity = |action: &str| {
            AuditEvent::builder(AuditSource::Settings, action)
                .build()
                .ocsf_activity()
                .0
        };
        assert_eq!(activity("rule_created"), 1);
        assert_eq!(activity("audit_exported"), 2);
        assert_eq!(activity("settings_updated"), 3);
        assert_eq!(activity("rule_enabled"), 3);
        assert_eq!(activity("user_deleted"), 4);
        assert_eq!(activity("member_removed"), 4);
        assert_eq!(activity("login_success"), 99);
    }
}
