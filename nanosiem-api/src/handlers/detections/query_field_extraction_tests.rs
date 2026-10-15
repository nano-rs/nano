// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2361: the rule editor's field validator against OCSF 1.9 paths.
//!
//! The reported symptom was a valid OCSF rule rejected in the editor:
//!
//! ```text
//! class_uid=4001
//! | where connection_info.protocol_num=6
//!
//! Unknown field 'protocol_num'. Did you mean 'src_ip', 'dest_ip', 'user', 'src_host'?
//! ```
//!
//! Two independent defects, both pinned here: the extraction regex kept only the
//! segment after the last dot (so the validator was asked about a field nobody
//! wrote), and the suggestion list was a hardcoded UDM one that named four
//! fields an OCSF tenant does not have.

use super::{extract_referenced_fields, nearest_profile_fields};

/// The exact query from the report. `connection_info.protocol_num` must survive
/// extraction whole — asking about the `protocol_num` leaf is what produced the
/// false rejection, because that leaf genuinely is not a field.
#[test]
fn dotted_ocsf_paths_survive_extraction_whole() {
    let fields =
        extract_referenced_fields("class_uid=4001\n| where connection_info.protocol_num=6");
    assert_eq!(
        fields,
        vec![
            "class_uid".to_string(),
            "connection_info.protocol_num".to_string()
        ]
    );
    assert!(
        !fields.iter().any(|f| f == "protocol_num"),
        "the bare leaf must never be extracted — that was the bug"
    );
}

/// Every shape of OCSF path the shipped content uses, including a three-segment
/// one and a `!=` operator.
#[test]
fn every_ocsf_path_shape_is_extracted() {
    for (query, expected) in [
        (r#"src_endpoint.ip="10.0.0.1""#, "src_endpoint.ip"),
        ("metadata.log_source=windows_sysmon", "metadata.log_source"),
        (r#"process.file.path!="""#, "process.file.path"),
        ("dst_endpoint.port>=443", "dst_endpoint.port"),
        ("actor.process.name=cmd.exe", "actor.process.name"),
    ] {
        let fields = extract_referenced_fields(query);
        assert!(
            fields.iter().any(|f| f == expected),
            "expected {expected:?} from {query:?}, got {fields:?}"
        );
    }
}

/// The UDM half must be untouched — this validator serves both profiles, and a
/// flat field has no dot to widen the match.
#[test]
fn flat_udm_fields_are_unchanged() {
    assert_eq!(
        extract_referenced_fields("src_ip=1.2.3.4 and dest_port>=443"),
        vec!["src_ip".to_string(), "dest_port".to_string()]
    );
    assert_eq!(
        extract_referenced_fields("| eval total=a+b | where total>10"),
        vec!["total".to_string()]
    );
}

/// A value that merely contains dots must not be mistaken for a field path, and
/// a bare `IN (...)` list references no field via this lexical pass.
#[test]
fn values_and_non_comparisons_do_not_become_fields() {
    // The IP is on the value side of the `=`; only `src_ip` is a field.
    assert_eq!(
        extract_referenced_fields("src_ip=10.0.0.1"),
        vec!["src_ip".to_string()]
    );
    assert!(extract_referenced_fields("class_uid IN (4001,4002)").is_empty());
}

/// The whole point of the fix: the canonical path the editor rejected really is
/// a known field under OCSF, so extracting it whole makes the rule validate.
/// If this ever fails, the manifest lost the field rather than the regex
/// regressing.
#[test]
fn the_rejected_field_is_canonical_under_ocsf() {
    let profile = nanosiem_core::schema::OcsfProfile::new();
    use nanosiem_core::schema::SchemaProfile;
    assert!(
        profile.is_known_field("connection_info.protocol_num"),
        "connection_info.protocol_num must be a known OCSF field"
    );
    assert!(
        !profile.is_known_field("protocol_num"),
        "the bare leaf is correctly NOT a field — which is why truncating broke the editor"
    );
}

/// Suggestions must come from the active profile. Under OCSF the old hardcoded
/// list (`src_ip`, `dest_ip`, `user`, `src_host`) named fields that do not exist
/// in the tenant's schema, which is worse than no hint at all.
#[test]
fn suggestions_come_from_the_active_profile() {
    let profile = nanosiem_core::schema::OcsfProfile::new();
    let suggestions = nearest_profile_fields(
        &profile as &dyn nanosiem_core::schema::SchemaProfile,
        "protocol_num",
        4,
    );
    assert!(
        suggestions
            .iter()
            .any(|s| s.ends_with("protocol_num") || s.contains("protocol")),
        "a near miss on an OCSF leaf should point at the OCSF path, got {suggestions:?}"
    );
    assert!(
        !suggestions.iter().any(|s| s == "src_host"),
        "UDM-only names must not be suggested to an OCSF tenant, got {suggestions:?}"
    );
}

/// installutil_execution: the string literal `"/LogFile="` is a value, not a
/// field, so the validator must not report `LogFile` as unknown.
#[test]
fn string_literal_contents_are_never_fields() {
    let fields = extract_referenced_fields(
        r#"class_uid=1007 | where process.cmd_line CONTAINS "/U" OR process.cmd_line CONTAINS "/LogFile=""#,
    );
    assert_eq!(fields, vec!["class_uid".to_string()]);
}
