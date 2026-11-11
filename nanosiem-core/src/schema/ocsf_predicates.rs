// SPDX-License-Identifier: AGPL-3.0-or-later

//! OCSF concept predicates (NAN-5271 E).
//!
//! UDM answered "is this an auth event / was it blocked / is this a network
//! logon" with string VALUES on a handful of columns (`category`, `action`,
//! `auth_type`, `file_action`). Under OCSF those questions are answered by
//! enum INTs on different columns — `class_uid`, `category_uid`,
//! `activity_id`, `status_id`, `disposition_id`, `action_id`,
//! `logon_type_id` — and a UDM alias that lands on a valid column can still
//! carry the wrong meaning (`action` → `activity` holds HTTP methods, not
//! block/allow; `auth_type` → `auth_protocol_id` is NTLM/Kerberos, not a logon
//! type). This module is the ONE place raw-SQL builders get those concepts
//! from, so `| lateral`, the asset dossier, the timeline classifier and the
//! nPL concept translation all agree on the row set.
//!
//! Every predicate is a parenthesized boolean SQL expression over plain
//! promoted `ocsf_logs` columns (no binds, no user input), safe to splice into
//! a WHERE / `countIf` / CASE. Enum ids come from the vendored OCSF dictionary
//! (`docs/ocsf/1.8.0/dictionary.json`, class files under `events/`) and are
//! pinned by the tests below.
//!
//! Entity resolution (which column holds the host / user / IP) is NOT here —
//! that is `ocsf/entities` (lane C). This module answers "what kind of event",
//! never "about whom".

/// `category_uid` — OCSF event categories.
pub mod category {
    pub const SYSTEM_ACTIVITY: u32 = 1;
    pub const FINDINGS: u32 = 2;
    pub const IAM: u32 = 3;
    pub const NETWORK_ACTIVITY: u32 = 4;
    pub const DISCOVERY: u32 = 5;
    pub const APPLICATION_ACTIVITY: u32 = 6;
}

/// `class_uid` — the OCSF event classes nano's concepts key off.
pub mod class {
    pub const FILE_SYSTEM_ACTIVITY: u32 = 1001;
    pub const MODULE_ACTIVITY: u32 = 1005;
    pub const PROCESS_ACTIVITY: u32 = 1007;
    pub const AUTHENTICATION: u32 = 3002;
    pub const AUTHORIZE_SESSION: u32 = 3003;
    pub const NETWORK_ACTIVITY: u32 = 4001;
    pub const HTTP_ACTIVITY: u32 = 4002;
    pub const DNS_ACTIVITY: u32 = 4003;
    pub const API_ACTIVITY: u32 = 6003;
    /// Windows extension classes.
    pub const REGISTRY_KEY_ACTIVITY: u32 = 201001;
    pub const REGISTRY_VALUE_ACTIVITY: u32 = 201002;
}

/// Authentication (3002) `activity_id`.
pub mod auth_activity {
    pub const LOGON: i32 = 1;
    pub const LOGOFF: i32 = 2;
}

/// `status_id` (base event).
pub mod status {
    pub const SUCCESS: i32 = 1;
    pub const FAILURE: i32 = 2;
}

/// `logon_type_id` (Authentication). Interactive = a person at a console or
/// RDP session (Interactive, Remote Interactive, Cached Interactive, Cached
/// Remote Interactive); network = credentials presented over the wire
/// (Network, Network Cleartext). Unlock / batch / service / new-credentials are
/// neither.
pub mod logon_type {
    pub const INTERACTIVE: i32 = 2;
    pub const NETWORK: i32 = 3;
    pub const NETWORK_CLEARTEXT: i32 = 8;
    pub const REMOTE_INTERACTIVE: i32 = 10;
    pub const CACHED_INTERACTIVE: i32 = 11;
    pub const CACHED_REMOTE_INTERACTIVE: i32 = 12;
}

/// `disposition_id` (base event / profiles) and `action_id` (security control
/// profile). Block/allow lives here, NOT in `activity` (HTTP methods etc.).
pub mod disposition {
    pub const ALLOWED: i32 = 1;
    pub const BLOCKED: i32 = 2;
    pub const QUARANTINED: i32 = 3;
    pub const ISOLATED: i32 = 4;
    pub const DROPPED: i32 = 6;
    pub const APPROVED: i32 = 8;
    pub const REJECTED: i32 = 25;
    pub const UNAUTHORIZED: i32 = 26;
}
pub mod action {
    pub const ALLOWED: i32 = 1;
    pub const DENIED: i32 = 2;
}

/// A security-operations concept with a fixed OCSF predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Concept {
    /// Any Identity & Access Management event (category 3): authentication,
    /// authorize-session, account / group / entity management. The asset
    /// timeline's "auth" lane.
    IamEvent,
    /// Authentication class (3002), every activity (logon, logoff, tickets).
    AuthEvent,
    /// An authentication ATTEMPT: Authentication class minus Logoff (a logoff
    /// is the end of a session, not a credential use). The `| lateral` auth hop.
    AuthAttempt,
    /// Successful authentication attempt.
    AuthSuccess,
    /// Failed authentication attempt.
    AuthFailure,
    /// Logon activity (3002 / activity 1), any logon type.
    Logon,
    /// Interactive logon (console / RDP / cached).
    InteractiveLogon,
    /// Network logon (SMB / WinRM / network cleartext).
    NetworkLogon,
    /// A security control blocked / dropped / rejected the activity.
    Blocked,
    /// A security control allowed the activity.
    Allowed,
    /// File System Activity (1001).
    FileEvent,
    /// Process Activity (1007).
    ProcessEvent,
    /// Module Activity / image load (1005).
    ModuleEvent,
    /// Windows registry key / value activity (201001 / 201002).
    RegistryEvent,
    /// Any Network Activity category event (4xxx: network, HTTP, DNS, …).
    NetworkEvent,
    /// DNS Activity (4003).
    DnsEvent,
    /// HTTP Activity (4002).
    HttpEvent,
}

// Literal predicate bodies. Kept as `const &str` (not built at runtime) so
// callers can splice them anywhere a `&'static str` is expected, and so the
// tests can pin the exact enum ids against the dictionary constants above.
pub const IAM_EVENT: &str = "(category_uid = 3)";
pub const AUTH_EVENT: &str = "(class_uid = 3002)";
pub const AUTH_ATTEMPT: &str = "(class_uid = 3002 AND activity_id != 2)";
pub const AUTH_SUCCESS: &str = "(class_uid = 3002 AND activity_id != 2 AND status_id = 1)";
pub const AUTH_FAILURE: &str = "(class_uid = 3002 AND activity_id != 2 AND status_id = 2)";
pub const LOGON: &str = "(class_uid = 3002 AND activity_id = 1)";
pub const INTERACTIVE_LOGON: &str =
    "(class_uid = 3002 AND activity_id = 1 AND logon_type_id IN (2, 10, 11, 12))";
pub const NETWORK_LOGON: &str = "(class_uid = 3002 AND activity_id = 1 AND logon_type_id IN (3, 8))";
/// `disposition_id` is authoritative when the producer set it; `action_id`
/// (Allowed / Denied) is the fallback for producers that only fill the
/// security-control `action`. The `disposition_id = 0` guard keeps BLOCKED and
/// ALLOWED mutually exclusive.
pub const BLOCKED: &str =
    "(disposition_id IN (2, 3, 4, 6, 25, 26) OR (disposition_id = 0 AND action_id = 2))";
pub const ALLOWED: &str = "(disposition_id IN (1, 8) OR (disposition_id = 0 AND action_id = 1))";
pub const FILE_EVENT: &str = "(class_uid = 1001)";
pub const PROCESS_EVENT: &str = "(class_uid = 1007)";
pub const MODULE_EVENT: &str = "(class_uid = 1005)";
pub const REGISTRY_EVENT: &str = "(class_uid IN (201001, 201002))";
pub const NETWORK_EVENT: &str = "(category_uid = 4)";
pub const DNS_EVENT: &str = "(class_uid = 4003)";
pub const HTTP_EVENT: &str = "(class_uid = 4002)";

impl Concept {
    /// The physical columns the predicate reads — what a field-pruned stage
    /// must project for a later `| where` to evaluate it.
    pub const fn columns(self) -> &'static [&'static str] {
        match self {
            Concept::IamEvent | Concept::NetworkEvent => &["category_uid"],
            Concept::AuthEvent
            | Concept::FileEvent
            | Concept::ProcessEvent
            | Concept::ModuleEvent
            | Concept::RegistryEvent
            | Concept::DnsEvent
            | Concept::HttpEvent => &["class_uid"],
            Concept::AuthAttempt | Concept::Logon => &["class_uid", "activity_id"],
            Concept::AuthSuccess | Concept::AuthFailure => &["class_uid", "activity_id", "status_id"],
            Concept::InteractiveLogon | Concept::NetworkLogon => {
                &["class_uid", "activity_id", "logon_type_id"]
            }
            Concept::Blocked | Concept::Allowed => &["disposition_id", "action_id"],
        }
    }

    /// The OCSF SQL predicate for this concept.
    pub const fn sql(self) -> &'static str {
        match self {
            Concept::IamEvent => IAM_EVENT,
            Concept::AuthEvent => AUTH_EVENT,
            Concept::AuthAttempt => AUTH_ATTEMPT,
            Concept::AuthSuccess => AUTH_SUCCESS,
            Concept::AuthFailure => AUTH_FAILURE,
            Concept::Logon => LOGON,
            Concept::InteractiveLogon => INTERACTIVE_LOGON,
            Concept::NetworkLogon => NETWORK_LOGON,
            Concept::Blocked => BLOCKED,
            Concept::Allowed => ALLOWED,
            Concept::FileEvent => FILE_EVENT,
            Concept::ProcessEvent => PROCESS_EVENT,
            Concept::ModuleEvent => MODULE_EVENT,
            Concept::RegistryEvent => REGISTRY_EVENT,
            Concept::NetworkEvent => NETWORK_EVENT,
            Concept::DnsEvent => DNS_EVENT,
            Concept::HttpEvent => HTTP_EVENT,
        }
    }
}

/// nPL concept translation for UDM-semantic `field=value` filters whose VALUE
/// names a concept that OCSF stores elsewhere (NAN-5271 E).
///
/// Only `action` is translated, and only for the block/allow vocabulary: UDM
/// (CIM) `action=blocked` means "a control blocked it", but the OCSF `action`
/// alias resolves to `activity` (the class activity caption: Get / Post /
/// Logon / Create …). No OCSF 1.8 activity caption is one of these words (the
/// closest, Network Activity "Refuse", is deliberately not in the list), so
/// before this translation such a filter matched ZERO rows on every class; the
/// translation therefore changes no query that used to return data. Every
/// other `action` value (`action=Get`, `action=logon`) keeps its `activity`
/// meaning for HTTP / auth users.
///
/// Returns the predicate for `field == value`; `None` → normal resolution.
pub fn npl_value_concept(field: &str, value: &str) -> Option<Concept> {
    if !field.eq_ignore_ascii_case("action") {
        return None;
    }
    match value.trim().to_ascii_lowercase().as_str() {
        "blocked" | "block" | "denied" | "deny" | "dropped" | "drop" | "rejected" | "reject"
        | "prevented" => Some(Concept::Blocked),
        "allowed" | "allow" | "permitted" | "permit" | "accepted" | "accept" => {
            Some(Concept::Allowed)
        }
        _ => None,
    }
}

/// Human-readable caption column for a UDM-semantic field whose OCSF alias is
/// an enum INT (`auth_type` → `auth_protocol_id`). Raw-SQL builders that
/// DISPLAY the value (lateral edge labels, dossier recent list) project this
/// sibling String instead of the int, so a label reads "Kerberos" / "Failure",
/// not "2".
pub fn display_caption_column(udm_field: &str) -> Option<&'static str> {
    match udm_field {
        "auth_type" => Some("auth_protocol"),
        "auth_result" => Some("status"),
        _ => None,
    }
}

#[cfg(test)]
#[path = "ocsf_predicates_tests.rs"]
mod tests;
