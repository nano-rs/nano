// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pins the OCSF concept predicates (NAN-5271 E) against the vendored OCSF
//! dictionary so a wrong enum id cannot ship silently.

use super::*;

const DICTIONARY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/ocsf/1.8.0/dictionary.json"
));
const AUTHENTICATION_CLASS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/ocsf/1.8.0/events/iam/authentication.json"
));

/// Caption of `attr`'s enum member `id` in a dictionary / class document.
fn caption(doc: &str, attr: &str, id: i32) -> String {
    let v: serde_json::Value = serde_json::from_str(doc).expect("valid OCSF json");
    v["attributes"][attr]["enum"][id.to_string()]["caption"]
        .as_str()
        .unwrap_or_else(|| panic!("{attr} has no enum member {id}"))
        .to_string()
}

#[test]
fn enum_ids_match_the_ocsf_dictionary() {
    let d = DICTIONARY;
    assert_eq!(caption(d, "status_id", status::SUCCESS), "Success");
    assert_eq!(caption(d, "status_id", status::FAILURE), "Failure");

    assert_eq!(caption(d, "logon_type_id", logon_type::INTERACTIVE), "Interactive");
    assert_eq!(caption(d, "logon_type_id", logon_type::NETWORK), "Network");
    assert_eq!(caption(d, "logon_type_id", logon_type::NETWORK_CLEARTEXT), "Network Cleartext");
    assert_eq!(caption(d, "logon_type_id", logon_type::REMOTE_INTERACTIVE), "Remote Interactive");
    assert_eq!(caption(d, "logon_type_id", logon_type::CACHED_INTERACTIVE), "Cached Interactive");
    assert_eq!(
        caption(d, "logon_type_id", logon_type::CACHED_REMOTE_INTERACTIVE),
        "Cached Remote Interactive"
    );

    assert_eq!(caption(d, "disposition_id", disposition::ALLOWED), "Allowed");
    assert_eq!(caption(d, "disposition_id", disposition::BLOCKED), "Blocked");
    assert_eq!(caption(d, "disposition_id", disposition::QUARANTINED), "Quarantined");
    assert_eq!(caption(d, "disposition_id", disposition::ISOLATED), "Isolated");
    assert_eq!(caption(d, "disposition_id", disposition::DROPPED), "Dropped");
    assert_eq!(caption(d, "disposition_id", disposition::APPROVED), "Approved");
    assert_eq!(caption(d, "disposition_id", disposition::REJECTED), "Rejected");
    assert_eq!(caption(d, "disposition_id", disposition::UNAUTHORIZED), "Unauthorized");

    assert_eq!(caption(d, "action_id", action::ALLOWED), "Allowed");
    assert_eq!(caption(d, "action_id", action::DENIED), "Denied");

    let a = AUTHENTICATION_CLASS;
    assert_eq!(caption(a, "activity_id", auth_activity::LOGON), "Logon");
    assert_eq!(caption(a, "activity_id", auth_activity::LOGOFF), "Logoff");
}

/// The literal predicate bodies must use exactly the named ids — a typo in the
/// SQL string (not just the constant) is what this guards.
#[test]
fn predicate_literals_use_the_named_ids() {
    let ids = |xs: &[i32]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ");
    assert_eq!(IAM_EVENT, format!("(category_uid = {})", category::IAM));
    assert_eq!(AUTH_EVENT, format!("(class_uid = {})", class::AUTHENTICATION));
    assert_eq!(
        AUTH_ATTEMPT,
        format!("(class_uid = {} AND activity_id != {})", class::AUTHENTICATION, auth_activity::LOGOFF)
    );
    assert_eq!(
        AUTH_SUCCESS,
        format!(
            "(class_uid = {} AND activity_id != {} AND status_id = {})",
            class::AUTHENTICATION,
            auth_activity::LOGOFF,
            status::SUCCESS
        )
    );
    assert_eq!(
        AUTH_FAILURE,
        format!(
            "(class_uid = {} AND activity_id != {} AND status_id = {})",
            class::AUTHENTICATION,
            auth_activity::LOGOFF,
            status::FAILURE
        )
    );
    assert_eq!(LOGON, format!("(class_uid = {} AND activity_id = {})", class::AUTHENTICATION, auth_activity::LOGON));
    assert_eq!(
        INTERACTIVE_LOGON,
        format!(
            "(class_uid = {} AND activity_id = {} AND logon_type_id IN ({}))",
            class::AUTHENTICATION,
            auth_activity::LOGON,
            ids(&[
                logon_type::INTERACTIVE,
                logon_type::REMOTE_INTERACTIVE,
                logon_type::CACHED_INTERACTIVE,
                logon_type::CACHED_REMOTE_INTERACTIVE
            ])
        )
    );
    assert_eq!(
        NETWORK_LOGON,
        format!(
            "(class_uid = {} AND activity_id = {} AND logon_type_id IN ({}))",
            class::AUTHENTICATION,
            auth_activity::LOGON,
            ids(&[logon_type::NETWORK, logon_type::NETWORK_CLEARTEXT])
        )
    );
    assert_eq!(
        BLOCKED,
        format!(
            "(disposition_id IN ({}) OR (disposition_id = 0 AND action_id = {}))",
            ids(&[
                disposition::BLOCKED,
                disposition::QUARANTINED,
                disposition::ISOLATED,
                disposition::DROPPED,
                disposition::REJECTED,
                disposition::UNAUTHORIZED
            ]),
            action::DENIED
        )
    );
    assert_eq!(
        ALLOWED,
        format!(
            "(disposition_id IN ({}) OR (disposition_id = 0 AND action_id = {}))",
            ids(&[disposition::ALLOWED, disposition::APPROVED]),
            action::ALLOWED
        )
    );
    assert_eq!(FILE_EVENT, format!("(class_uid = {})", class::FILE_SYSTEM_ACTIVITY));
    assert_eq!(PROCESS_EVENT, format!("(class_uid = {})", class::PROCESS_ACTIVITY));
    assert_eq!(MODULE_EVENT, format!("(class_uid = {})", class::MODULE_ACTIVITY));
    assert_eq!(
        REGISTRY_EVENT,
        format!("(class_uid IN ({}, {}))", class::REGISTRY_KEY_ACTIVITY, class::REGISTRY_VALUE_ACTIVITY)
    );
    assert_eq!(NETWORK_EVENT, format!("(category_uid = {})", category::NETWORK_ACTIVITY));
    assert_eq!(DNS_EVENT, format!("(class_uid = {})", class::DNS_ACTIVITY));
    assert_eq!(HTTP_EVENT, format!("(class_uid = {})", class::HTTP_ACTIVITY));
}

/// The NAN-5271 #6 bug: `status_id != 0` is true for every OCSF class, so it
/// can never be an "is auth" signal. No auth-family concept may lean on a bare
/// status / auth-protocol test.
#[test]
fn auth_concepts_key_off_the_class_not_status() {
    for c in [
        Concept::AuthEvent,
        Concept::AuthAttempt,
        Concept::AuthSuccess,
        Concept::AuthFailure,
        Concept::Logon,
        Concept::InteractiveLogon,
        Concept::NetworkLogon,
    ] {
        let sql = c.sql();
        assert!(sql.starts_with("(class_uid = 3002"), "{c:?}: {sql}");
        assert!(!sql.contains("status_id != 0"), "{c:?}: {sql}");
        assert!(!sql.contains("auth_protocol_id"), "{c:?}: {sql}");
    }
    // Interactive vs network logon never overlap.
    assert!(!INTERACTIVE_LOGON.contains(" 3,") && !INTERACTIVE_LOGON.contains("(3"));
}

#[test]
fn blocked_and_allowed_never_read_activity() {
    for sql in [BLOCKED, ALLOWED] {
        assert!(!sql.contains("activity"), "{sql}");
        assert!(sql.contains("disposition_id"), "{sql}");
    }
}

#[test]
fn every_predicate_is_parenthesized_and_balanced() {
    for c in [
        Concept::IamEvent,
        Concept::AuthEvent,
        Concept::AuthAttempt,
        Concept::AuthSuccess,
        Concept::AuthFailure,
        Concept::Logon,
        Concept::InteractiveLogon,
        Concept::NetworkLogon,
        Concept::Blocked,
        Concept::Allowed,
        Concept::FileEvent,
        Concept::ProcessEvent,
        Concept::ModuleEvent,
        Concept::RegistryEvent,
        Concept::NetworkEvent,
        Concept::DnsEvent,
        Concept::HttpEvent,
    ] {
        let sql = c.sql();
        assert!(sql.starts_with('(') && sql.ends_with(')'), "{c:?}: {sql}");
        assert_eq!(sql.matches('(').count(), sql.matches(')').count(), "{c:?}: {sql}");
    }
}

#[test]
fn npl_value_concept_translates_only_block_allow_words_on_action() {
    for v in ["blocked", "Blocked", "BLOCK", "denied", "deny", "dropped", "rejected"] {
        assert_eq!(npl_value_concept("action", v), Some(Concept::Blocked), "{v}");
    }
    for v in ["allowed", "Allow", "permitted", "accepted"] {
        assert_eq!(npl_value_concept("action", v), Some(Concept::Allowed), "{v}");
    }
    // OCSF activity captions keep their `activity` meaning (HTTP methods, logon).
    for v in ["Get", "post", "logon", "Create", "Refuse", "success", "failure", ""] {
        assert_eq!(npl_value_concept("action", v), None, "{v}");
    }
    // Only the `action` alias is translated.
    for f in ["activity", "disposition_id", "category", "status"] {
        assert_eq!(npl_value_concept(f, "blocked"), None, "{f}");
    }
}

/// No OCSF activity caption is in the translated vocabulary, so the
/// translation cannot change any query that used to match data.
#[test]
fn translated_vocabulary_never_collides_with_an_activity_caption() {
    let classes = [
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/ocsf/1.8.0/events/iam/authentication.json")),
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/ocsf/1.8.0/events/network/network_activity.json")),
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/ocsf/1.8.0/events/network/http_activity.json")),
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/ocsf/1.8.0/events/network/dns_activity.json")),
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/ocsf/1.8.0/events/network/email_activity.json")),
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/ocsf/1.8.0/events/system/file_activity.json")),
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/ocsf/1.8.0/events/system/process_activity.json")),
    ];
    for doc in classes {
        let v: serde_json::Value = serde_json::from_str(doc).unwrap();
        let members = v["attributes"]["activity_id"]["enum"].as_object().unwrap();
        for (id, m) in members {
            let cap = m["caption"].as_str().unwrap();
            assert_eq!(
                npl_value_concept("action", cap),
                None,
                "activity caption {cap:?} (id {id}) would be hijacked by the action concept translation"
            );
        }
    }
}

#[test]
fn display_caption_columns() {
    assert_eq!(display_caption_column("auth_type"), Some("auth_protocol"));
    assert_eq!(display_caption_column("auth_result"), Some("status"));
    assert_eq!(display_caption_column("user"), None);
}
