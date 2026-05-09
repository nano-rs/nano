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

mod actions;
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
}

impl std::fmt::Display for AuditSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth => write!(f, "auth"),
            Self::Detection => write!(f, "detection"),
            Self::User => write!(f, "user"),
            Self::Tuning => write!(f, "tuning"),
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

    /// Convert this audit event into a ParsedLog for storage
    pub fn to_parsed_log(&self) -> ParsedLog {
        let now = Utc::now();

        // Build the message for full-text search
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

        let message = format!(
            "[{}] {} on {} by {}",
            self.source, self.action, resource_desc, actor_desc
        );

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
            // Use standard UDM fields where appropriate
            user: self.actor_name.clone(),
            action: Some(self.action.clone()),
            status: Some(if self.success { "success" } else { "failure" }.to_string()),
            severity: None, // Audit events don't have severity
            src_ip: self.ip_address.clone(),
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
}
