// SPDX-License-Identifier: AGPL-3.0-or-later

//! Platform audit action → OCSF 1.9 class + activity (NAN-3460).
//!
//! One table decides how every nano audit `action` is classified:
//!
//! * **Authentication (3002)** — a principal proving (or failing to prove)
//!   who it is, or ending that proof: logon, logoff, MFA steps, API-key
//!   authentication, session renewal. `user` is the principal.
//! * **Account Change (3001)** — the lifecycle of a user account itself:
//!   create, enable/disable, password change/reset, lock/unlock, MFA factor
//!   enable/disable, delete. `user` is the account changed.
//! * **API Activity (6003)** — everything else (an actor operating on a nano
//!   object), with the CRUD activity taken from the action's verb
//!   ([`super::AuditEvent::ocsf_activity`]); 99 Other only for executions,
//!   decisions and authorizations that are genuinely not CRUD.
//!
//! The IAM classes are emitted only with [`IAM_CLASSES_ENV`] on (rollout
//! gate, default off); off, every action is API Activity as before.
//!
//! [`IAM_ACTIONS`] lists the actions that leave API Activity, verbatim; every
//! other action stays API Activity. The SQL copy in
//! enterprise migration `9012100_platform_audit_ocsf_iam_classes.sql`
//! (`nano_shared.platform_audit_ocsf_iam_class`, used to classify SQL-built
//! audit rows) must list exactly the same rows — `sql_iam_table_matches_rust`
//! enforces it. The golden test (`ocsf_mapping_tests.rs`) pins the class and
//! activity of every audit action string the codebase emits.

/// Rollout flag (default OFF): emit the IAM classes (3001 / 3002). Off, every
/// audit record stays API Activity 6003 — the only class the lean audit lanes
/// built before NAN-3460 (zero-nan3304-v2 / zero-nan3339-v2) admit; a writer
/// may flip it only once every reader (each lean tenant's Worker base, the
/// lake worker) admits the IAM classes. The database copy of this switch is
/// `nano_shared.platform_audit_ocsf_settings` (9012100).
pub const IAM_CLASSES_ENV: &str = "NANO_AUDIT_OCSF_IAM_CLASSES";

/// Whether [`IAM_CLASSES_ENV`] is on (`1` / `true` / `on` / `yes`). Read per
/// call: audit volume is low and it keeps the switch testable.
pub fn iam_classes_enabled() -> bool {
    std::env::var(IAM_CLASSES_ENV)
        .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"))
        .unwrap_or(false)
}

/// OCSF event class of a platform audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcsfAuditClass {
    /// 3001 Account Change (Identity & Access Management).
    AccountChange,
    /// 3002 Authentication (Identity & Access Management).
    Authentication,
    /// 6003 API Activity (Application Activity).
    ApiActivity,
}

impl OcsfAuditClass {
    pub const fn class_uid(self) -> i64 {
        match self {
            Self::AccountChange => 3001,
            Self::Authentication => 3002,
            Self::ApiActivity => 6003,
        }
    }

    pub const fn class_name(self) -> &'static str {
        match self {
            Self::AccountChange => "Account Change",
            Self::Authentication => "Authentication",
            Self::ApiActivity => "API Activity",
        }
    }

    pub const fn category_uid(self) -> i64 {
        match self {
            Self::AccountChange | Self::Authentication => 3,
            Self::ApiActivity => 6,
        }
    }

    pub const fn category_name(self) -> &'static str {
        match self {
            Self::AccountChange | Self::Authentication => "Identity & Access Management",
            Self::ApiActivity => "Application Activity",
        }
    }

    /// OCSF 1.9 `activity_name` caption of `activity_id` in this class.
    pub fn activity_name(self, activity_id: i64) -> &'static str {
        match (self, activity_id) {
            (_, 0) => "Unknown",
            (Self::ApiActivity, 1) => "Create",
            (Self::ApiActivity, 2) => "Read",
            (Self::ApiActivity, 3) => "Update",
            (Self::ApiActivity, 4) => "Delete",
            (Self::Authentication, 1) => "Logon",
            (Self::Authentication, 2) => "Logoff",
            (Self::Authentication, 3) => "Authentication Ticket",
            (Self::Authentication, 4) => "Service Ticket Request",
            (Self::Authentication, 5) => "Service Ticket Renew",
            (Self::Authentication, 6) => "Preauth",
            (Self::Authentication, 7) => "Account Switch",
            (Self::AccountChange, 1) => "Create",
            (Self::AccountChange, 2) => "Enable",
            (Self::AccountChange, 3) => "Password Change",
            (Self::AccountChange, 4) => "Password Reset",
            (Self::AccountChange, 5) => "Disable",
            (Self::AccountChange, 6) => "Delete",
            (Self::AccountChange, 7) => "Attach Policy",
            (Self::AccountChange, 8) => "Detach Policy",
            (Self::AccountChange, 9) => "Lock",
            (Self::AccountChange, 10) => "MFA Factor Enable",
            (Self::AccountChange, 11) => "MFA Factor Disable",
            (Self::AccountChange, 12) => "Unlock",
            _ => "Other",
        }
    }
}

/// OCSF `auth_protocol_id` / `auth_protocol` of an Authentication event,
/// only where nano knows which credential was presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAuthProtocol {
    /// Local account password (OCSF has no enum member: 99 Other).
    Password,
    /// OpenID Connect single sign-on (OCSF 4 OpenID).
    OpenId,
    /// nano API key / automation key (99 Other).
    ApiKey,
    /// Time-based one-time password or a single-use backup code (99 Other).
    Totp,
}

impl AuditAuthProtocol {
    pub const fn id_and_name(self) -> (i64, &'static str) {
        match self {
            Self::Password => (99, "Password"),
            Self::OpenId => (4, "OpenID"),
            Self::ApiKey => (99, "API Key"),
            Self::Totp => (99, "TOTP"),
        }
    }

    /// The protocol's name in the SQL copy of the table.
    pub const fn sql_name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::OpenId => "openid",
            Self::ApiKey => "apikey",
            Self::Totp => "totp",
        }
    }
}

/// Whose account an IAM-class record is about (the OCSF `user`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSubject {
    /// The authenticating principal: the actor, else a `user` resource.
    Actor,
    /// The account acted on: a `user` resource, else the actor (self-service).
    Account,
    /// Only a `user` resource (an administrator ending someone's sessions).
    AccountOnly,
}

/// One row of the IAM table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IamAction {
    pub class: OcsfAuditClass,
    pub activity_id: i64,
    pub subject: AuditSubject,
    pub protocol: Option<AuditAuthProtocol>,
    /// `is_mfa` when the action itself proves it (an MFA step). `None` means
    /// "decided by the event" (e.g. `login_success` after MFA carries
    /// `details.mfa_verified`) or unknown.
    pub mfa: Option<bool>,
}

const fn auth(activity_id: i64, protocol: Option<AuditAuthProtocol>, mfa: Option<bool>) -> IamAction {
    IamAction { class: OcsfAuditClass::Authentication, activity_id, subject: AuditSubject::Actor, protocol, mfa }
}

const fn account(activity_id: i64) -> IamAction {
    IamAction { class: OcsfAuditClass::AccountChange, activity_id, subject: AuditSubject::Account, protocol: None, mfa: None }
}

use AuditAuthProtocol::{ApiKey, OpenId, Password, Totp};

/// Every audit action that is not API Activity, with its OCSF class and
/// activity. Keep in lockstep with the SQL copy (see the module docs).
// BEGIN OCSF IAM ACTIONS
pub const IAM_ACTIONS: &[(&str, IamAction)] = &[
    // Authentication 3002 — 1 Logon, 2 Logoff, 5 Service Ticket Renew, 6 Preauth.
    ("login_success", auth(1, Some(Password), None)),
    ("login_failed", auth(1, Some(Password), None)),
    ("oidc_login", auth(1, Some(OpenId), None)),
    ("apikey_authenticated", auth(1, Some(ApiKey), Some(false))),
    ("mfa_challenge_failed", auth(1, Some(Totp), Some(true))),
    ("auth_session_created", auth(1, None, None)),
    ("logout", auth(2, None, None)),
    ("auth_session_removed", auth(2, None, None)),
    (
        "session_terminated",
        IamAction { class: OcsfAuditClass::Authentication, activity_id: 2, subject: AuditSubject::AccountOnly, protocol: None, mfa: None },
    ),
    (
        "user_sessions_terminated",
        IamAction { class: OcsfAuditClass::Authentication, activity_id: 2, subject: AuditSubject::AccountOnly, protocol: None, mfa: None },
    ),
    ("token_refresh", auth(5, None, None)),
    ("auth_session_refreshed", auth(5, None, None)),
    ("mfa_challenge_issued", auth(6, Some(Totp), Some(true))),
    ("mfa_challenge_success", auth(6, Some(Totp), Some(true))),
    ("mfa_backup_code_used", auth(6, Some(Totp), Some(true))),
    // Account Change 3001.
    ("user_created", account(1)),
    ("oidc_user_provisioned", account(1)),
    ("user_enabled", account(2)),
    // A hosted-shared invitee activating their local account (NAN-3436).
    ("enterprise_shared_local_activation", account(2)),
    ("password_changed", account(3)),
    ("password_reset_complete", account(4)),
    ("user_disabled", account(5)),
    ("user_deleted", account(6)),
    ("user_locked", account(9)),
    ("mfa_setup_complete", account(10)),
    ("mfa_disabled", account(11)),
    ("mfa_admin_reset", account(11)),
    ("user_unlocked", account(12)),
];
// END OCSF IAM ACTIONS

/// The IAM row of `action` (exact, case-insensitive), if it leaves API Activity.
pub fn iam_action(action: &str) -> Option<IamAction> {
    IAM_ACTIONS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(action))
        .map(|(_, row)| *row)
}

#[cfg(test)]
#[path = "ocsf_mapping_tests.rs"]
pub(crate) mod tests;
