// SPDX-License-Identifier: AGPL-3.0-or-later

//! UDM → OCSF alias SEMANTICS guard (NAN-5271 E).
//!
//! An alias can land on a real, populated column and still mean something
//! else: `category` → URL categories while a caller meant the event class,
//! `action` → the activity caption (HTTP methods) while a caller meant
//! block/allow, `auth_type` → the auth PROTOCOL while a caller meant the logon
//! type. Those bugs compile, return 200 and silently match 0 rows. This test
//! pins every semantically sensitive alias to its reviewed target, and makes
//! any NEW alias onto an enum / taxonomy / array column fail until someone
//! adds it to the curated table below.

use std::collections::HashMap;

use super::ocsf_predicates::{npl_value_concept, Concept};
use super::{OcsfProfile, SchemaProfile};

const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/ocsf/events/promoted.json"));

/// (UDM alias, expected OCSF column, why the meaning matches).
const CURATED: &[(&str, &str, &str)] = &[
    // --- Taxonomy / enum ints ---------------------------------------------
    // CIM `category` is the CONTENT category (web filtering), NOT the event
    // class (NAN-1464 moved event class to UDM `tags`). The OCSF analog is
    // `http_request.url.categories`. Event-class questions use the
    // `ocsf_predicates` concepts (class_uid / category_uid), never this alias.
    ("category", "http_request.url.categories", "CIM content category = URL categories"),
    // `action` keeps the activity caption (Get / Post / Logon …) so OCSF
    // HTTP/auth queries keep their meaning; block/allow VALUES translate to
    // `disposition_id` via `npl_value_concept` (asserted below).
    ("action", "activity", "activity caption; block/allow values → disposition concept"),
    ("auth_result", "status_id", "auth outcome = event status (Success/Failure)"),
    // The auth PROTOCOL (NTLM / Kerberos), not the logon type — logon type is
    // `logon_type_id` (Concept::InteractiveLogon / NetworkLogon).
    ("auth_type", "auth_protocol_id", "auth protocol, NOT logon type"),
    ("severity", "severity_id", "normalized severity"),
    ("event_type", "activity_id", "class-scoped activity"),
    ("file_action", "activity_id", "File System Activity activity (Create/Read/…)"),
    ("change_type", "activity_id", "registry/file change activity"),
    ("status", "status", "status caption"),
    ("protocol", "connection_info.protocol_num", "IANA protocol number"),
    ("mfa_used", "is_mfa", "MFA flag"),
    ("http_status_code", "http_response.code", "HTTP response code"),
    ("status_code", "http_response.code", "HTTP response code"),
    // --- Arrays -----------------------------------------------------------
    ("answer", "answers.rdata", "DNS answers"),
    ("recipient", "email.to", "email recipients"),
    ("resource_id", "resources.uid", "cloud resource ids"),
    ("resource_name", "resources.name", "cloud resource names"),
    ("resource_type", "resources.type", "cloud resource types"),
    ("cve", "vulnerabilities.cve.uid", "CVE ids"),
    // --- Actor vs target splits that have bitten before -----------------
    ("src_user", "actor.user.name", "acting user"),
    ("parent_command_line", "actor.process.cmd_line", "parent = acting process"),
    ("parent_process_path", "actor.process.file.path", "parent = acting process"),
    ("parent_process_name", "process.parent_process.name", "parent process name"),
    ("process_name", "process.name", "target process"),
    ("query", "query.hostname", "DNS question"),
    ("url_domain", "http_request.url.hostname", "HTTP host"),
];

#[derive(serde::Deserialize)]
struct Entry {
    ch_column_name: String,
    ch_type: String,
    #[serde(default)]
    udm_fields: Vec<String>,
}

/// UDM alias → target column, first mapping wins (same rule as the registry).
fn manifest_aliases() -> (HashMap<String, String>, HashMap<String, String>) {
    let entries: Vec<Entry> = serde_json::from_str(MANIFEST).unwrap();
    let mut alias = HashMap::new();
    let mut types = HashMap::new();
    for e in &entries {
        types.insert(e.ch_column_name.clone(), e.ch_type.clone());
        for u in &e.udm_fields {
            alias.entry(u.clone()).or_insert_with(|| e.ch_column_name.clone());
        }
    }
    (alias, types)
}

/// Columns whose VALUES carry taxonomy semantics a UDM string alias can
/// silently misread: enum ints, the taxonomy captions, and arrays.
fn is_semantically_sensitive(col: &str, ch_type: &str) -> bool {
    col.ends_with("_id")
        || col.ends_with("_uid") && !col.contains('.')
        || matches!(col, "activity" | "status" | "severity" | "is_mfa")
        || col == "connection_info.protocol_num"
        || col == "http_response.code"
        || ch_type.starts_with("Array(")
}

#[test]
fn curated_aliases_land_on_their_reviewed_targets() {
    let (alias, _) = manifest_aliases();
    // `action` → `activity` comes from the nano-derived ALIAS column table,
    // not the manifest; resolve it through the live profile instead.
    let p = OcsfProfile::new();
    for (udm, expected, why) in CURATED {
        let got = alias.get(*udm).cloned().or_else(|| p.display_field_name(udm));
        assert_eq!(
            got.as_deref(),
            Some(*expected),
            "UDM alias `{udm}` must resolve to `{expected}` ({why}); a different target changes \
             what every saved UDM-style query means — review it and update CURATED"
        );
    }
}

#[test]
fn every_sensitive_alias_is_curated() {
    let (alias, types) = manifest_aliases();
    let curated: std::collections::HashSet<&str> = CURATED.iter().map(|(u, _, _)| *u).collect();
    let mut missing = Vec::new();
    for (udm, col) in &alias {
        let ty = types.get(col).map(String::as_str).unwrap_or("");
        if is_semantically_sensitive(col, ty) && !curated.contains(udm.as_str()) {
            missing.push(format!("{udm} → {col} ({ty})"));
        }
    }
    missing.sort();
    assert!(
        missing.is_empty(),
        "new UDM aliases onto enum / taxonomy / array columns need a semantic review — add them to \
         CURATED in ocsf_alias_semantics_tests.rs: {missing:?}"
    );
}

/// The decisions the curated table leans on.
#[test]
fn concept_translation_backs_the_action_alias() {
    assert_eq!(npl_value_concept("action", "blocked"), Some(Concept::Blocked));
    assert_eq!(npl_value_concept("action", "allowed"), Some(Concept::Allowed));
    assert_eq!(npl_value_concept("action", "Get"), None);
    let p = OcsfProfile::new();
    assert_eq!(p.concept_value_predicate("action", "blocked"), Some(Concept::Blocked.sql()));
    assert_eq!(p.concept_value_predicate("category", "authentication"), None);
}

/// `category` is a content category: its target must never be the event
/// taxonomy, and it must get array membership semantics.
#[test]
fn category_is_never_the_event_class() {
    let p = OcsfProfile::new();
    let col = p.udm_column_sql("category").unwrap_or_default();
    for forbidden in ["class_uid", "category_uid", "category_name", "class_name"] {
        assert!(!col.contains(forbidden), "category → {col}");
    }
    assert!(p.is_array_field("category"));
}
