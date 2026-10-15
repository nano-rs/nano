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
pub mod trusted_local_delivery;
mod context;
pub mod ocsf_mapping;
mod emitter;
pub mod query;
#[cfg(feature = "enterprise")]
mod tenant;
#[cfg(feature = "enterprise")]
pub use tenant::TenantAuthorizationAudit;
#[cfg(feature = "enterprise")]
mod tenant_mfa;
#[cfg(feature = "enterprise")]
pub use tenant_mfa::{TenantMfaChallengeAudit, TenantPreSessionAudit};
#[cfg(feature = "enterprise")]
mod tenant_auth;
#[cfg(feature = "enterprise")]
pub use tenant_auth::{TenantAuthAudit, ENTERPRISE_SHARED_MEMBERSHIP_ACCEPTED, SHARED_ACTOR_AUTH_ACTIONS, SHARED_PREAUTH_AUTH_ACTIONS};
#[cfg(feature = "enterprise")]
mod tenant_query;
#[cfg(feature = "enterprise")]
pub use tenant_query::{TenantAuditFacet, TenantAuditPage, TenantAuditQueryError, TenantAuditQueryService};

pub use actions::*;
pub use context::ClientContext;
pub use ocsf_mapping::{AuditAuthProtocol, AuditSubject, IamAction, OcsfAuditClass};
pub use emitter::{append_dedicated_audit_in_transaction, append_tenant_audit_in_transaction, AuditEmitError, AuditEmitter};
#[cfg(feature = "enterprise")]
pub(crate) use emitter::mirror_automation_key_audit_in_transaction;
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
    /// Scheduled report events (definition CRUD, manual run trigger)
    Report,
    /// Per-source RBAC scope events (restrict/un-restrict a source_type,
    /// grant/revoke a group's visibility of it) — NAN-1799.
    SourceScope,
    /// Artifact-analysis store events (create, update, delete) — NAN-1977.
    Artifact,
    /// Active Hunter events (NAN-2238): enabling what runs unattended,
    /// promoting a lead into a case, and writing or revoking the tenant-wide
    /// dismissal memory. All four decide what the SOC does and does not see.
    Hunt,
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
            Self::Report => write!(f, "report"),
            Self::SourceScope => write!(f, "source_scope"),
            Self::Artifact => write!(f, "artifact"),
            Self::Hunt => write!(f, "hunt"),
        }
    }
}

/// Verb lists for [`AuditEvent::ocsf_activity`]. The SQL copy in the latest
/// `nano_shared.ocsf_api_activity_id` definition
/// (enterprise migration `9012100_platform_audit_ocsf_iam_classes.sql`,
/// used for SQL-built audit rows) must list exactly the same verbs —
/// `sql_activity_verbs_match_rust` enforces it (NAN-3227, NAN-3460).
const OCSF_CREATE_VERBS: &[&str] = &[
    "create", "created", "add", "added", "import", "imported", "install",
    "installed", "issued", "generated", "provisioned", "enrolled", "registered",
    "duplicated", "cloned", "uploaded", "request", "requested", "submitted",
    "drafted", "opened", "recorded", "stored", "register", "initialized",
    "initiated",
];
const OCSF_READ_VERBS: &[&str] = &[
    "read", "view", "viewed", "export", "exported", "download", "downloaded",
    "reveal", "revealed", "list", "listed", "previewed", "accessed", "fetched",
    "retrieved", "fetch",
];
const OCSF_UPDATE_VERBS: &[&str] = &[
    "update", "updated", "change", "changed", "edit", "edited", "modified",
    "enable", "enabled", "disable", "disabled", "set", "rotate", "rotated",
    "renamed", "assign", "assigned", "unassigned", "acknowledged", "close",
    "closed", "reopened", "resolved", "sync", "synced", "revert", "reverted",
    "restored", "refresh", "refreshed", "publish", "published", "deploy",
    "deployed", "undeploy", "undeployed", "promoted", "demoted", "activated",
    "deactivated", "locked", "unlocked", "reset", "moved", "share", "shared",
    "unshared", "granted", "approved", "rejected", "archived", "unarchived",
    "configured", "toggled", "merged", "linked", "unlinked", "bound", "applied",
    "regenerated", "escalated", "dismissed", "accepted", "canceled", "cancelled",
    "paused", "resumed", "reordered", "restricted", "unrestricted", "enforced",
    "fulfilled", "saved", "rolled", "anonymized", "pushed", "promote", "retire",
    "retired", "renewed", "superseded", "expired",
];
const OCSF_DELETE_VERBS: &[&str] = &[
    "delete", "deleted", "remove", "removed", "uninstall", "uninstalled",
    "revoke", "revoked", "purge", "purged", "dropped", "terminated", "clear",
    "cleared", "destroyed", "tombstoned", "erased",
];
// Execution / authentication verbs: the operation ran or was decided,
// nothing was created, read, changed or deleted. Stop scanning so a
// resource noun earlier in the action cannot claim a CRUD verb
// ("identity_sync_triggered" is a run, not an Update).
const OCSF_NON_CRUD_VERBS: &[&str] = &[
    "triggered", "ran", "run", "executed", "tested", "validated", "started",
    "sent", "bounced", "used", "denied", "refused", "authenticated", "login",
    "logout", "bypass",
];

/// Unified audit event for all subsystems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Stable identity retained across retries and recovery serialization.
    #[serde(default = "Uuid::now_v7")]
    event_id: Uuid,
    /// Original event time, independent of later storage attempts.
    #[serde(default = "Utc::now")]
    occurred_at: chrono::DateTime<Utc>,
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
    /// Per-request id of the HTTP request that caused this event
    /// (`X-Request-ID`, OCSF `api.request.uid`). Not the id of a domain
    /// object that happens to be called a "request" — that stays in
    /// `details` (NAN-3227).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_uid: Option<String>,
    /// Response/status code the handler actually returned for this
    /// operation (OCSF `status_code`), only where the emitter knows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,
}

impl AuditEvent {
    pub fn event_id(&self) -> Uuid {
        self.event_id
    }

    pub fn occurred_at(&self) -> chrono::DateTime<Utc> {
        self.occurred_at
    }

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
            request_uid: None,
            status_code: None,
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
        let actor_desc = match (
            self.actor_name.as_deref(),
            self.api_key_name.as_deref(),
            self.api_key_id,
        ) {
            (Some(name), Some(key_name), _) => format!("{} via API key '{}'", name, key_name),
            (Some(name), None, Some(key_id)) => format!("{} via API key {}", name, key_id),
            (Some(name), None, None) => name.to_string(),
            (None, Some(key_name), _) => format!("API key '{}'", key_name),
            (None, None, Some(key_id)) => format!("API key {}", key_id),
            // A known actor whose name was not resolved is a user, not the
            // system (NAN-3227: shared-tenant callers pass no name).
            (None, None, None) => self
                .actor_id
                .map_or_else(|| "system".to_string(), |id| format!("user {id}")),
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
    ///
    /// The underscore-convention action is `<resource…>_<verb>[_<outcome>]`
    /// ("rule_created", "ingest_credential_revoked", "rule_update_failed"), so
    /// the action is split into whole tokens and the LAST token that is a
    /// known verb decides (NAN-3223). Whole-token matching replaces the old
    /// substring heuristic, which matched resource nouns ("review" ⊃ "view",
    /// "thread" ⊃ "read") and missed most past-tense verbs (`*_revoked`,
    /// `*_closed`, `*_added`, `*_synced`, `*_rotated`, … all fell to Other).
    /// Executions, authentications and denials (`*_triggered`, `*_ran`,
    /// `apikey_authenticated`, `auth_denied`, `login_success`) are not CRUD
    /// and stay Other — the exact nano verb is always preserved verbatim in
    /// `api.operation`.
    pub(crate) fn ocsf_activity(&self) -> (i64, &'static str) {
        let action = self.action.to_lowercase();
        for token in action.rsplit(|c: char| !c.is_ascii_alphanumeric()) {
            if OCSF_NON_CRUD_VERBS.contains(&token) {
                break;
            }
            if OCSF_CREATE_VERBS.contains(&token) {
                return (1, "Create");
            }
            if OCSF_READ_VERBS.contains(&token) {
                return (2, "Read");
            }
            if OCSF_UPDATE_VERBS.contains(&token) {
                return (3, "Update");
            }
            if OCSF_DELETE_VERBS.contains(&token) {
                return (4, "Delete");
            }
        }
        (99, "Other")
    }

    /// `actor.user.email_addr` (OCSF `email_t`) when the actor display name is
    /// itself a plain email address — the common case for interactive users.
    /// Never fabricated: anything that is not a single `local@domain.tld`
    /// token is left out.
    fn actor_email(&self) -> Option<&str> {
        plain_email(self.actor_name.as_deref()?)
    }

    /// Failure detail from the nano-native `details` payload for
    /// `status_detail` (`details.reason`, else `details.error`), only for
    /// failed actions — a success event's `reason` (e.g. why a credential was
    /// revoked) is not a status detail.
    fn failure_detail(&self) -> Option<&str> {
        if self.success {
            return None;
        }
        let details = self.details.as_ref()?;
        ["reason", "error"]
            .iter()
            .find_map(|key| details.get(*key).and_then(serde_json::Value::as_str))
            .filter(|detail| !detail.is_empty())
    }

    /// The OCSF class + activity of this event (NAN-3460): an IAM class from
    /// [`ocsf_mapping::IAM_ACTIONS`] when the action is one AND the account
    /// it is about is known (OCSF requires `user` there), else API Activity
    /// with the verb's CRUD activity.
    ///
    /// Gated by [`ocsf_mapping::IAM_CLASSES_ENV`] (default off: always 6003).
    pub fn ocsf_classification(&self) -> (OcsfAuditClass, i64) {
        self.ocsf_classification_with(ocsf_mapping::iam_classes_enabled())
    }

    /// [`Self::ocsf_classification`] with the IAM-class gate given explicitly.
    pub fn ocsf_classification_with(&self, iam_classes: bool) -> (OcsfAuditClass, i64) {
        match ocsf_mapping::iam_action(&self.action).filter(|_| iam_classes) {
            Some(row) if self.ocsf_subject(row.subject).is_some() => (row.class, row.activity_id),
            _ => (OcsfAuditClass::ApiActivity, self.ocsf_activity().0),
        }
    }

    /// The OCSF `user` of an IAM-class event: whose account it is about.
    /// `None` when nano does not know (no id and no name), so the event
    /// stays API Activity instead of fabricating a user.
    fn ocsf_subject(&self, subject: AuditSubject) -> Option<serde_json::Value> {
        let user_resource = (self.resource_type.as_deref() == Some("user")
            && (self.resource_id.is_some() || self.resource_name.is_some()))
            .then(|| (self.resource_id, self.resource_name.as_deref()));
        let actor = (self.actor_id.is_some() || self.actor_name.is_some())
            .then(|| (self.actor_id, self.actor_name.as_deref()));
        let (uid, name) = match subject {
            AuditSubject::Actor => actor.or(user_resource)?,
            AuditSubject::Account => user_resource.or(actor)?,
            AuditSubject::AccountOnly => user_resource?,
        };
        let mut user = serde_json::Map::new();
        if let Some(name) = name {
            user.insert("name".into(), json!(name));
            if let Some(email) = plain_email(name) {
                user.insert("email_addr".into(), json!(email));
            }
        }
        if let Some(uid) = uid {
            user.insert("uid".into(), json!(uid.to_string()));
        }
        Some(serde_json::Value::Object(user))
    }

    /// Convert this audit event into its OCSF 1.9 `event` JSON (NAN-1390,
    /// NAN-3460): Authentication (3002) for logons/logoffs/MFA steps,
    /// Account Change (3001) for account lifecycle, and API Activity (6003)
    /// for every other actor-operates-on-object record.
    ///
    /// Every class carries the same nano envelope, so one search spans them:
    /// `actor.user` (who), `api.operation` (the nano action, verbatim) and
    /// `api.service.name` (the subsystem), `src_endpoint.ip` /
    /// `http_request.user_agent` (the client), `metadata` (product, version
    /// 1.9.0, `log_name` audit). API Activity names what was acted on in
    /// `resources[]`; the IAM classes name the account in `user` (and the
    /// session in `session`) and add `service`, `auth_protocol` and `is_mfa`
    /// where known.
    ///
    /// `unmapped` holds only what has no OCSF home — the API key's display
    /// name, the nano-native `details` payload, and a resource OCSF cannot
    /// carry — and is absent when there is none. Fields already mapped above
    /// are never repeated there.
    ///
    /// `time` is epoch milliseconds per the OCSF `timestamp_t` spec; the caller
    /// passes the same instant it binds into the explicit `timestamp` column so
    /// the two never drift.
    ///
    /// The IAM classes follow [`ocsf_mapping::IAM_CLASSES_ENV`] (default off).
    pub fn to_ocsf_event(&self, time: chrono::DateTime<Utc>) -> serde_json::Value {
        self.to_ocsf_event_with(time, ocsf_mapping::iam_classes_enabled())
    }

    /// [`Self::to_ocsf_event`] with the IAM-class gate given explicitly. Off,
    /// the event is API Activity 6003 in the shape every pre-NAN-3460 lane
    /// admits (with `unmapped` de-duplicated and the metadata search keys).
    pub fn to_ocsf_event_with(&self, time: chrono::DateTime<Utc>, iam_classes: bool) -> serde_json::Value {
        let iam = ocsf_mapping::iam_action(&self.action);
        let (class, activity_id) = self.ocsf_classification_with(iam_classes);

        let (status_id, status) = if self.success {
            (1, "Success")
        } else {
            (2, "Failure")
        };
        // A failed or denied platform operation (auth_denied, login_failed,
        // a refused mutation) is Low, not Informational: it is the population
        // a SOC triages for brute force / privilege probing, while one event
        // alone is not an incident — so never above Low here (NAN-3223).
        let (severity_id, severity) = if self.success {
            (1, "Informational")
        } else {
            (2, "Low")
        };

        let mut event = json!({
            "class_uid": class.class_uid(),
            "class_name": class.class_name(),
            "category_uid": class.category_uid(),
            "category_name": class.category_name(),
            "activity_id": activity_id,
            "activity_name": class.activity_name(activity_id),
            "type_uid": class.class_uid() * 100 + activity_id,
            // OCSF `time` is epoch milliseconds.
            "time": time.timestamp_millis(),
            "message": self.build_message(),
            "severity_id": severity_id,
            "severity": severity,
            "status_id": status_id,
            "status": status,
            // `metadata.event_code` (the verbatim nano action) and
            // `metadata.product.feature.name` (the emitting subsystem) are the
            // class-independent search keys: OCSF `api` exists only on API
            // Activity (on 3001/3002 it needs the cloud profile), so
            // `api.operation` / `api.service.name` are 6003-only (NAN-3460).
            "metadata": {
                "product": {
                    "name": "nano",
                    "vendor_name": "nano",
                    "feature": { "name": self.source.to_string() },
                },
                "event_code": self.action,
                "log_name": "audit",
                "version": "1.9.0",
            },
            // `actor.user.name`/`uid` stay exactly the stored columns: the
            // shared `append_tenant_audit` guard compares them byte-for-byte.
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
        });

        // Optional OCSF attributes are added only when nano knows them, so
        // a missing value is absent rather than a fabricated/empty object.
        let user = &mut event["actor"]["user"];
        if let Some(email) = self.actor_email() {
            user["email_addr"] = json!(email);
        }
        // OCSF `user.credential_uid`: "the unique identifier of the user's
        // credential, e.g. AWS Access Key ID" — the API key the owning user
        // acted through. The key's display name has no OCSF home and stays
        // in `unmapped.api_key_name`.
        if let Some(key_id) = self.api_key_id {
            user["credential_uid"] = json!(key_id.to_string());
        }
        let mut unmapped = serde_json::Map::new();
        if let Some(key_name) = &self.api_key_name {
            unmapped.insert("api_key_name".into(), json!(key_name));
        }
        if let Some(details) = &self.details {
            unmapped.insert("details".into(), details.clone());
        }

        match (class, iam) {
            (OcsfAuditClass::ApiActivity, _) | (_, None) => {
                // `resources[]` (OCSF `resource_details`: type/uid/name) only
                // when a resource is identified. OCSF requires `name` or `uid`,
                // so a type-only resource (`.resource("system", None, None)`:
                // setup, logout, bulk actions) is not emitted: strict lake
                // admission rejected and then quarantined every such audit row
                // (NAN-3390). Its type is the one resource fact left, kept in
                // `unmapped.resource_type`.
                if self.resource_id.is_some() || self.resource_name.is_some() {
                    event["resources"] = json!([self.resource_details()]);
                } else if let Some(resource_type) = &self.resource_type {
                    unmapped.insert("resource_type".into(), json!(resource_type));
                }
            }
            (_, Some(row)) => {
                let subject = self
                    .ocsf_subject(row.subject)
                    .expect("ocsf_classification picks an IAM class only with a known subject");
                event["user"] = subject;
                // The IAM classes carry no `resources[]`: the account is
                // `user`, a session is `session`; any other resource is kept
                // whole in `unmapped.resource`.
                let is_user = self.resource_type.as_deref() == Some("user");
                let is_session = self.resource_type.as_deref() == Some("session");
                if is_session && self.resource_id.is_some() {
                    event["session"] = json!({ "uid": self.resource_id.map(|id| id.to_string()) });
                } else if !is_user && self.resource_type.is_some() {
                    unmapped.insert("resource".into(), serde_json::Value::Object(self.resource_details()));
                }
                // Client: only a known one (both are optional here). No
                // `api`: it is cloud-profile-only outside API Activity.
                let object = event.as_object_mut().expect("event is an object");
                object.remove("api");
                if self.ip_address.is_none() {
                    object.remove("src_endpoint");
                }
                if self.user_agent.is_none() {
                    object.remove("http_request");
                }
                if class == OcsfAuditClass::Authentication {
                    // The service the principal authenticated to.
                    event["service"] = json!({ "name": "nano" });
                    if let Some(protocol) = row.protocol {
                        let (id, name) = protocol.id_and_name();
                        event["auth_protocol_id"] = json!(id);
                        event["auth_protocol"] = json!(name);
                    }
                    if let Some(is_mfa) = self.ocsf_is_mfa(row) {
                        event["is_mfa"] = json!(is_mfa);
                    }
                }
            }
        }
        if let Some(detail) = self.failure_detail() {
            event["status_detail"] = json!(detail);
        }
        // OCSF `api.request.uid`: the HTTP request id (X-Request-ID), never a
        // domain object's id (NAN-3227). The IAM classes have no `api`; the
        // request id correlates there as `metadata.correlation_uid`.
        if let Some(request_uid) = &self.request_uid {
            if class == OcsfAuditClass::ApiActivity {
                event["api"]["request"] = json!({ "uid": request_uid });
            } else {
                event["metadata"]["correlation_uid"] = json!(request_uid);
            }
        }
        if let Some(code) = &self.status_code {
            event["status_code"] = json!(code);
        }
        if !unmapped.is_empty() {
            event["unmapped"] = serde_json::Value::Object(unmapped);
        }
        event
    }

    /// OCSF `resource_details` (type/uid/name) of the event's resource.
    fn resource_details(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut resource = serde_json::Map::new();
        if let Some(resource_type) = &self.resource_type {
            resource.insert("type".to_string(), json!(resource_type));
        }
        if let Some(resource_id) = self.resource_id {
            resource.insert("uid".to_string(), json!(resource_id.to_string()));
        }
        if let Some(resource_name) = &self.resource_name {
            resource.insert("name".to_string(), json!(resource_name));
        }
        resource
    }

    /// `is_mfa` of an Authentication event: an MFA step says so itself; a
    /// password logon completed through the MFA challenge carries
    /// `details.mfa_verified`; a password logon without it was single-factor.
    /// Otherwise (OIDC, session rows) nano does not know, and says nothing.
    fn ocsf_is_mfa(&self, row: IamAction) -> Option<bool> {
        if row.mfa.is_some() {
            return row.mfa;
        }
        let verified = self
            .details
            .as_ref()
            .and_then(|details| details.get("mfa_verified"))
            .and_then(serde_json::Value::as_bool);
        match (verified, row.protocol) {
            (Some(verified), _) => Some(verified),
            (None, Some(AuditAuthProtocol::Password)) if self.success => Some(false),
            _ => None,
        }
    }
    /// Build the immutable OCSF 1.9 mirror persisted beside a primary-lake
    /// PostgreSQL audit row. The ledger UUID is the event identity, so a retry
    /// cannot create a second searchable audit event.
    pub fn to_ocsf_event_for_lake(
        &self,
        time: chrono::DateTime<Utc>,
        event_id: Uuid,
        tenant_id: &str,
    ) -> serde_json::Value {
        self.to_ocsf_event_for_lake_with(time, event_id, tenant_id, ocsf_mapping::iam_classes_enabled())
    }

    /// [`Self::to_ocsf_event_for_lake`] with the IAM-class gate given explicitly.
    pub fn to_ocsf_event_for_lake_with(
        &self,
        time: chrono::DateTime<Utc>,
        event_id: Uuid,
        tenant_id: &str,
        iam_classes: bool,
    ) -> serde_json::Value {
        let mut event = self.to_ocsf_event_with(time, iam_classes);
        let metadata = event
            .get_mut("metadata")
            .and_then(serde_json::Value::as_object_mut)
            .expect("to_ocsf_event always emits metadata");
        metadata.insert("uid".to_string(), json!(event_id.to_string()));
        metadata.insert("tenant_uid".to_string(), json!(tenant_id));
        metadata.insert("version".to_string(), json!("1.9.0"));
        metadata.insert("log_source".to_string(), json!("audit"));
        metadata.insert("log_name".to_string(), json!("audit"));
        event
    }
}

/// `name` when it is itself a plain `local@domain.tld` email address (OCSF
/// `email_t`). Never fabricated: anything else is `None`.
fn plain_email(name: &str) -> Option<&str> {
    let (local, domain) = name.split_once('@')?;
    let plain = !local.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !name.chars().any(|c| c.is_whitespace() || c.is_control());
    plain.then_some(name)
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
    request_uid: Option<String>,
    status_code: Option<String>,
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

    /// Set client connection info (IP, user agent and the per-request id)
    /// from ClientContext
    pub fn client_context(mut self, ctx: &ClientContext) -> Self {
        self.ip_address = ctx.ip_address.clone();
        self.user_agent = ctx.user_agent.clone();
        self.request_uid = ctx.request_id.clone();
        self
    }

    /// Record the status code the handler actually returned (e.g. the HTTP
    /// status of a refused request). Never set a guessed value.
    pub fn status_code(mut self, code: impl ToString) -> Self {
        self.status_code = Some(code.to_string());
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
            event_id: Uuid::now_v7(),
            occurred_at: Utc::now(),
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
            request_uid: self.request_uid,
            status_code: self.status_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_identity_survives_clone_and_recovery_serialization() {
        let original = AuditEvent::builder(AuditSource::Auth, "logout").build();
        let recovered: AuditEvent = serde_json::from_value(
            serde_json::to_value(&original).unwrap(),
        ).unwrap();
        for retry in [original.clone(), recovered] {
            assert_eq!(retry.event_id(), original.event_id());
            assert_eq!(retry.occurred_at(), original.occurred_at());
            assert_eq!(
                retry.to_ocsf_event_for_lake(retry.occurred_at(), retry.event_id(), "tenant-a"),
                original.to_ocsf_event_for_lake(original.occurred_at(), original.event_id(), "tenant-a"),
            );
        }
        let independent = AuditEvent::builder(AuditSource::Auth, "logout").build();
        assert_ne!(independent.event_id(), original.event_id());
    }

    #[test]
    fn legacy_serialized_audit_gains_identity_once_when_loaded() {
        let original = AuditEvent::builder(AuditSource::Auth, "logout").build();
        let mut legacy = serde_json::to_value(&original).unwrap();
        legacy.as_object_mut().unwrap().remove("event_id");
        legacy.as_object_mut().unwrap().remove("occurred_at");
        let recovered: AuditEvent = serde_json::from_value(legacy).unwrap();
        assert!(!recovered.event_id().is_nil());
        assert_eq!(recovered.clone().event_id(), recovered.event_id());
    }

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
        assert_eq!(
            crate::audit::SEARCH_HISTORY_DELETED,
            "search_history_deleted"
        );
        assert_eq!(
            crate::audit::SEARCH_HISTORY_CLEARED,
            "search_history_cleared"
        );
        assert_eq!(
            crate::audit::SEARCH_HISTORY_ENABLED,
            "search_history_enabled"
        );
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
            .actor(Some(owner_id), Some("Jane Analyst".to_string()))
            .api_key(Some(key_id), Some("ci-bot".to_string()))
            .resource(
                "api_key",
                Some(Uuid::now_v7()),
                Some("target-key".to_string()),
            )
            .build();

        let log = event.to_parsed_log();

        assert!(
            log.message.contains("Jane Analyst via API key 'ci-bot'"),
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
            .actor(Some(Uuid::now_v7()), Some("Jane Analyst".to_string()))
            .resource("api_key", Some(Uuid::now_v7()), Some("new-key".to_string()))
            .build();

        let log = event.to_parsed_log();

        assert!(
            log.message.ends_with("by Jane Analyst"),
            "got: {}",
            log.message
        );
        assert!(log.metadata.get("api_key_id").is_some_and(|v| v.is_null()));
        assert!(log
            .metadata
            .get("api_key_name")
            .is_some_and(|v| v.is_null()));
    }

    /// NAN-1432: every field in `LOWERCASE_NORMALIZED_FIELDS` is compared with
    /// raw equality by the SQL generator (no `lower()` wrapper, so the
    /// raw-column indexes prune) — sound only if every writer stores those
    /// columns lowercase. The audit emitter is the one in-process writer to
    /// `logs` (Vector's VRL handles everything else), so it must uphold the
    /// contract: pre-fix it stored display-case actor names and
    /// `user="jane analyst"` found 0 audit rows.
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
            .actor(Some(Uuid::now_v7()), Some("Jane Analyst".to_string()))
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
                "user_domain" | "src_mac" | "dest_mac" | "src_user" | "trace_id" | "span_id"
                | "dvc_ip" => continue,
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
        assert_eq!(log.user.as_deref(), Some("jane analyst"));
        assert_eq!(
            log.metadata.get("actor_name").and_then(|v| v.as_str()),
            Some("Jane Analyst")
        );
        assert!(log.message.contains("Jane Analyst"), "got: {}", log.message);
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
    /// must be spec-shaped (class/category/type_uid/time-in-ms), with every
    /// UDM metadata fact in its OCSF home (NAN-3460: not repeated in
    /// `unmapped`).
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

        assert_eq!(ocsf["metadata"]["version"], "1.9.0");

        // NAN-3460: nothing mapped above is repeated in `unmapped`; with no
        // API key name and no details there is nothing unmapped at all.
        assert!(ocsf.get("unmapped").is_none(), "{ocsf:#}");
        let with_details = AuditEvent::builder(AuditSource::Detection, "rule_created")
            .api_key(Some(Uuid::now_v7()), Some("ci-bot".into()))
            .details(json!({"rule_version": 3}))
            .build()
            .to_ocsf_event(time);
        assert_eq!(
            with_details["unmapped"],
            json!({"api_key_name": "ci-bot", "details": {"rule_version": 3}})
        );
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
    fn test_lake_audit_event_has_stable_ocsf_identity() {
        let event_id = Uuid::now_v7();
        let event = AuditEvent::builder(AuditSource::Settings, "settings_updated").build();
        let ocsf = event.to_ocsf_event_for_lake(Utc::now(), event_id, "tenant-a");
        assert_eq!(ocsf["metadata"]["uid"], event_id.to_string());
        assert_eq!(ocsf["metadata"]["tenant_uid"], "tenant-a");
        assert_eq!(ocsf["metadata"]["version"], "1.9.0");
        assert_eq!(ocsf["metadata"]["log_source"], "audit");
        assert_eq!(ocsf["class_uid"], 6003);
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

    /// NAN-3223: the verb, not a substring or the subsystem, decides the OCSF
    /// activity. Rows are live lean-tenant actions that mapped wrong before
    /// (`ingest_credential_revoked` was Other/Create, `alert_closed` Other, …)
    /// plus the non-CRUD ones that must stay Other.
    #[test]
    fn ocsf_activity_follows_the_action_verb() {
        let cases: &[(AuditSource, &str, i64)] = &[
            (AuditSource::Ingest, "ingest_credential_revoked", 4),
            (AuditSource::Ingest, "ingest_credential_created", 1),
            (AuditSource::Ingest, "ingest_credential_requested", 1),
            (AuditSource::Ingest, "ingest_credential_revealed", 2),
            (AuditSource::Ingest, "ingest_credential_request_fulfilled", 3),
            (AuditSource::Detection, "rule_created", 1),
            (AuditSource::Detection, "rule_updated", 3),
            (AuditSource::Detection, "rule_deleted", 4),
            (AuditSource::Detection, "rule_update_failed", 3),
            (AuditSource::Case, "case_alert_added", 1),
            (AuditSource::Case, "case_status_changed", 3),
            (AuditSource::Notebook, "notebook_entry_added", 1),
            (AuditSource::Alert, "alert_closed", 3),
            (AuditSource::ApiKey, "apikey_rotated", 3),
            (AuditSource::ApiKey, "apikey_created", 1),
            (AuditSource::ParserRepo, "parser_repo_synced", 3),
            (AuditSource::ParserRepo, "parser_imported", 1),
            (AuditSource::LogSource, "log_source_published", 3),
            (AuditSource::LogSource, "log_source_deployed", 3),
            (AuditSource::SourceScope, "source_visibility_group_set", 3),
            (AuditSource::Risk, "risk_entity_cleared", 4),
            (AuditSource::Search, "search_history_cleared", 4),
            (AuditSource::Tuning, "version_reverted", 3),
            (AuditSource::Credentials, "credential_rolled_back", 3),
            (AuditSource::Session, "session_terminated", 4),
            (AuditSource::Auth, "auth_tenant_sessions_revoked", 4),
            (AuditSource::Audit, "audit_logs_exported", 2),
            (AuditSource::Identity, "identity_sync_completed", 3),
            (AuditSource::Auth, "mfa_challenge_issued", 1),
            (AuditSource::Auth, "password_reset_complete", 3),
            // Resource nouns that merely contain a verb are not verbs.
            (AuditSource::Detection, "review_note_added", 1),
            (AuditSource::Case, "thread_pinned", 99),
            // Executions / authentications / decisions are not CRUD.
            (AuditSource::ApiKey, "apikey_authenticated", 99),
            (AuditSource::Auth, "auth_denied", 99),
            (AuditSource::Auth, "login_success", 99),
            (AuditSource::Auth, "login_failed", 99),
            (AuditSource::Auth, "mfa_challenge_failed", 99),
            (AuditSource::Identity, "identity_sync_triggered", 99),
            (AuditSource::Report, "report_run_triggered", 99),
            (AuditSource::Settings, "melod_background_ai_ran", 99),
            (AuditSource::SourceScope, "source_visibility_bypass", 99),
        ];
        for (source, action, expected) in cases {
            let ocsf = AuditEvent::builder(*source, action)
                .build()
                .to_ocsf_event(Utc::now());
            assert_eq!(ocsf["activity_id"], *expected, "{action}");
            assert_eq!(ocsf["type_uid"], 600300 + expected, "{action}");
            let name = match expected {
                1 => "Create",
                2 => "Read",
                3 => "Update",
                4 => "Delete",
                _ => "Other",
            };
            assert_eq!(ocsf["activity_name"], name, "{action}");
        }
    }

    /// NAN-3223: actor/resource/status attributes land in their OCSF homes,
    /// the lean audit lane + `append_tenant_audit` guard invariants hold, and
    /// the event validates against the pinned OCSF 1.9.0 contract.
    #[test]
    fn lake_audit_event_maps_actor_resource_and_failure_to_ocsf() {
        let actor_id = Uuid::now_v7();
        let key_id = Uuid::now_v7();
        let event_id = Uuid::now_v7();
        let denied = AuditEvent::builder(AuditSource::Auth, AUTH_DENIED)
            .actor(Some(actor_id), Some("dan@nano.rs".to_string()))
            .api_key(Some(key_id), Some("ci-bot".to_string()))
            .resource("endpoint", None, Some("POST /api/rules".to_string()))
            .client(Some("10.1.2.3".to_string()), Some("curl/8".to_string()))
            .success(false)
            .details(json!({"reason": "missing permission detections:manage"}))
            .build();
        let time = Utc::now();
        let ocsf = denied.to_ocsf_event_for_lake(time, event_id, "tenant-a");

        assert_eq!(ocsf["activity_id"], 99);
        assert_eq!(ocsf["type_uid"], 600399);
        assert_eq!(ocsf["status_id"], 2);
        assert_eq!(ocsf["status"], "Failure");
        assert_eq!(ocsf["status_detail"], "missing permission detections:manage");
        assert_eq!(ocsf["severity_id"], 2);
        assert_eq!(ocsf["severity"], "Low");
        // `append_tenant_audit` compares these byte-for-byte with the columns.
        assert_eq!(ocsf["actor"]["user"]["name"], "dan@nano.rs");
        assert_eq!(ocsf["actor"]["user"]["uid"], actor_id.to_string());
        assert_eq!(ocsf["actor"]["user"]["email_addr"], "dan@nano.rs");
        assert_eq!(ocsf["actor"]["user"]["credential_uid"], key_id.to_string());
        assert_eq!(ocsf["src_endpoint"]["ip"], "10.1.2.3");
        assert_eq!(ocsf["http_request"]["user_agent"], "curl/8");
        assert_eq!(ocsf["api"]["operation"], AUTH_DENIED);
        assert_eq!(ocsf["api"]["service"]["name"], "auth");
        assert_eq!(
            ocsf["resources"],
            json!([{"type": "endpoint", "name": "POST /api/rules"}])
        );
        // Lean delivery / platform audit lane contract.
        assert_eq!(ocsf["class_uid"], 6003);
        assert_eq!(ocsf["time"], time.timestamp_millis());
        assert_eq!(ocsf["metadata"]["uid"], event_id.to_string());
        assert_eq!(ocsf["metadata"]["tenant_uid"], "tenant-a");
        assert_eq!(ocsf["metadata"]["log_name"], "audit");
        assert_eq!(ocsf["metadata"]["log_source"], "audit");
        assert_eq!(ocsf["metadata"]["product"]["name"], "nano");
        assert_eq!(ocsf["metadata"]["version"], "1.9.0");
        // The nano-native payload stays whole under `unmapped`.
        assert_eq!(ocsf["unmapped"]["api_key_name"], "ci-bot");
        assert_eq!(ocsf["unmapped"]["details"]["reason"], "missing permission detections:manage");

        let validation = crate::parsers::validate_ocsf_event(&ocsf);
        assert!(validation.valid, "{:?}", validation.errors);
    }

    #[test]
    fn type_only_resource_is_not_emitted_and_validates() {
        // NAN-3390: OCSF `resource_details` needs `name` or `uid`; a
        // type-only entry failed strict lake admission and was quarantined.
        for (source, action, kind) in [
            (AuditSource::Auth, "system_initialized", "system"),
            (AuditSource::Mitre, "mitre_catalog_synced", "mitre_catalog"),
        ] {
            let event = AuditEvent::builder(source, action)
                .actor(Some(Uuid::now_v7()), Some("Lab Admin".to_string()))
                .resource(kind, None, None)
                .build();
            // The lake row (what strict admission validates).
            let ocsf = event.to_ocsf_event_for_lake(Utc::now(), Uuid::now_v7(), "tenant-a");
            assert!(
                ocsf.get("resources").is_none(),
                "{action}: type-only resource emitted"
            );
            assert_eq!(
                ocsf["unmapped"]["resource_type"], kind,
                "{action}: type kept in unmapped"
            );
            let validation = crate::parsers::validate_ocsf_event(&ocsf);
            assert!(validation.valid, "{action}: {:?}", validation.errors);
        }
        // A named or identified resource still maps, type included.
        let event = AuditEvent::builder(AuditSource::Auth, "logout")
            .resource("session", None, Some("web".to_string()))
            .build();
        let ocsf = event.to_ocsf_event(Utc::now());
        assert_eq!(ocsf["resources"][0]["type"], "session");
        assert_eq!(ocsf["resources"][0]["name"], "web");
    }

    #[test]
    fn ocsf_optional_attributes_are_absent_not_fabricated() {
        let event = AuditEvent::builder(AuditSource::Identity, "identity_sync_completed")
            .actor(Some(Uuid::now_v7()), Some("svc sync".to_string()))
            .details(json!({"reason": "scheduled"}))
            .build();
        let ocsf = event.to_ocsf_event(Utc::now());
        let user = ocsf["actor"]["user"].as_object().unwrap();
        assert!(!user.contains_key("email_addr"), "a non-email name is not an email");
        assert!(!user.contains_key("credential_uid"));
        assert!(ocsf.get("resources").is_none(), "no resource → no all-null entry");
        // A success event's `reason` is not a status detail.
        assert!(ocsf.get("status_detail").is_none());
        assert_eq!(ocsf["severity_id"], 1);
        assert_eq!(ocsf["severity"], "Informational");
        // No request context → no api.request / status_code (NAN-3227).
        assert!(ocsf["api"].get("request").is_none());
        assert!(ocsf.get("status_code").is_none());

        for not_email in ["a@b", "@nano.rs", "dan@", "dan @nano.rs", "a@b@c.io", "dan@.rs"] {
            let event = AuditEvent::builder(AuditSource::Auth, "logout")
                .actor(None, Some(not_email.to_string()))
                .build();
            assert!(event.actor_email().is_none(), "{not_email}");
        }
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3227: SQL-built audit rows are classified by
    /// `nano_shared.ocsf_api_activity_id` (migration 9012100). Its verb lists
    /// must equal the Rust ones, in order, or the same action would get a
    /// different OCSF activity depending on which writer built the row.
    #[test]
    fn sql_activity_verbs_match_rust() {
        // Runtime read, not `include_str!`: the open-core mirror strips
        // migrations/postgres-enterprise, and a compile-time include there
        // breaks this crate's lib test target (NAN-2169, NAN-3307). Skip only
        // when the file is genuinely absent; any other IO error fails.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../migrations/postgres-enterprise/9012100_platform_audit_ocsf_iam_classes.sql"
        );
        let sql = match std::fs::read_to_string(path) {
            Ok(sql) => sql,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping: {path} is absent (open-core tree)");
                return;
            }
            Err(err) => panic!("read {path}: {err}"),
        };
        let section = sql
            .split("-- BEGIN OCSF ACTIVITY VERBS")
            .nth(1)
            .and_then(|rest| rest.split("-- END OCSF ACTIVITY VERBS").next())
            .expect("verb section markers");
        let list = |name: &str| -> Vec<String> {
            let decl = format!("{name} CONSTANT TEXT[] := ARRAY[");
            let start = section.find(&decl).unwrap_or_else(|| panic!("{name} missing")) + decl.len();
            let end = start + section[start..].find("];").expect("array terminator");
            section[start..end]
                .split(',')
                .map(|verb| verb.trim().trim_matches('\'').to_string())
                .collect()
        };
        for (name, rust) in [
            ("create_verbs", OCSF_CREATE_VERBS),
            ("read_verbs", OCSF_READ_VERBS),
            ("update_verbs", OCSF_UPDATE_VERBS),
            ("delete_verbs", OCSF_DELETE_VERBS),
            ("non_crud_verbs", OCSF_NON_CRUD_VERBS),
        ] {
            assert_eq!(list(name), rust, "{name} drifted between Rust and 9012100");
        }
    }

    /// NAN-3227: the request id comes from the request context, the status
    /// code only from an explicit, known value.
    #[test]
    fn request_uid_and_status_code_map_to_ocsf() {
        let ctx = ClientContext::new(Some("10.0.0.1".into()), Some("ua".into()))
            .with_request_id(Some("0199c1d2-req".into()));
        let event = AuditEvent::builder(AuditSource::Auth, AUTH_DENIED)
            .actor(Some(Uuid::now_v7()), Some("Dan".into()))
            .client_context(&ctx)
            .status_code(403)
            .success(false)
            .build();
        let ocsf = event.to_ocsf_event(Utc::now());
        assert_eq!(ocsf["api"]["request"]["uid"], "0199c1d2-req");
        assert_eq!(ocsf["api"]["operation"], AUTH_DENIED);
        assert_eq!(ocsf["status_code"], "403");
        assert_eq!(ocsf["src_endpoint"]["ip"], "10.0.0.1");
        // A domain object's `request_id` in details is not the API request.
        let domain = AuditEvent::builder(AuditSource::Ingest, "ingest_credential_requested")
            .details(json!({"request_id": "domain-object"}))
            .build()
            .to_ocsf_event(Utc::now());
        assert!(domain["api"].get("request").is_none());
        // Recovery serialization keeps both, and old payloads load without them.
        let restored: AuditEvent =
            serde_json::from_value(serde_json::to_value(&event).unwrap()).unwrap();
        assert_eq!(restored.request_uid.as_deref(), Some("0199c1d2-req"));
        assert_eq!(restored.status_code.as_deref(), Some("403"));
        let mut legacy = serde_json::to_value(&event).unwrap();
        legacy.as_object_mut().unwrap().remove("request_uid");
        legacy.as_object_mut().unwrap().remove("status_code");
        let legacy: AuditEvent = serde_json::from_value(legacy).unwrap();
        assert!(legacy.request_uid.is_none() && legacy.status_code.is_none());
    }

    /// NAN-3227: an unnamed but known actor is not "system" in the message.
    #[test]
    fn unnamed_actor_is_not_rendered_as_system() {
        let actor = Uuid::now_v7();
        let event = AuditEvent::builder(AuditSource::Case, "case_created")
            .actor(Some(actor), None)
            .build();
        assert!(event.build_message().ends_with(&format!("by user {actor}")));
        let system = AuditEvent::builder(AuditSource::Storage, "partition_dropped").build();
        assert!(system.build_message().ends_with("by system"));
    }
}
