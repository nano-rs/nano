// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5265: a doubled spill namespace (`unmapped.unmapped.*`, `ext.ext.*`) is a
//! client bug that used to match nothing silently; it is now a field error.

use super::*;
use crate::query::parse_query;
use crate::schema::{OcsfProfile, UdmProfile};

fn errors(q: &str, profile: &dyn crate::schema::SchemaProfile) -> Vec<FieldValidationError> {
    validate_query_fields_with_profile(&parse_query(q).unwrap(), Some(profile))
}

#[test]
fn doubled_unmapped_prefix_is_rejected_with_the_single_prefix_suggestion() {
    let ocsf = OcsfProfile::new();
    let errs = errors("source_type=windows_sysmon unmapped.unmapped.task=7 | stats count", &ocsf);
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert_eq!(errs[0].field_name, "unmapped.unmapped.task");
    assert_eq!(errs[0].suggestions, vec!["unmapped.task".to_string()]);
    assert!(errs[0].message.contains("unmapped.task"), "{}", errs[0].message);
}

#[test]
fn doubled_prefix_is_caught_in_every_field_position() {
    let ocsf = OcsfProfile::new();
    for q in [
        "unmapped.unmapped.event_data.utc_time=*",
        "* | where unmapped.unmapped.task=7",
        "* | stats count by unmapped.unmapped.task",
        "unmapped.unmapped.task IN (1, 7)",
    ] {
        let errs = errors(q, &ocsf);
        assert_eq!(errs.len(), 1, "{q}: {errs:?}");
        assert!(errs[0].field_name.starts_with("unmapped.unmapped."), "{q}");
    }
    let udm = UdmProfile::new();
    let errs = errors("ext.ext.custom_key=5", &udm);
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert_eq!(errs[0].suggestions, vec!["ext.custom_key".to_string()]);
}

/// The single-prefix forms the fields panel now emits, and the documented
/// `ext.unmapped.*` composition, stay valid.
#[test]
fn single_prefix_and_ext_alias_forms_are_accepted() {
    let ocsf = OcsfProfile::new();
    for q in [
        "source_type=windows_sysmon unmapped.task=7 | stats count",
        "unmapped.event_data.utc_time=*",
        "ext.unmapped.task=7",
        "module.file.company_name=\"Microsoft Corporation\"",
    ] {
        assert!(errors(q, &ocsf).is_empty(), "{q} must stay valid");
    }
    assert!(errors("ext.custom_key=5", &UdmProfile::new()).is_empty());
}

/// The search paths (batch, streaming, explain) share this gate: the doubled
/// form becomes a 400-class `FieldNotFound` with the fix, not a silent zero.
#[test]
fn search_gate_returns_field_not_found_for_the_doubled_form() {
    let ocsf = OcsfProfile::new();
    let q = parse_query("source_type=windows_sysmon unmapped.unmapped.task=7 | stats count").unwrap();
    match crate::search::service::validate_query_field_names(&q, &ocsf) {
        Err(crate::search::SearchError::FieldNotFound { field, suggestions, .. }) => {
            assert_eq!(field, "unmapped.unmapped.task");
            assert_eq!(suggestions, vec!["unmapped.task".to_string()]);
        }
        other => panic!("expected FieldNotFound, got {other:?}"),
    }
    let ok = parse_query("source_type=windows_sysmon unmapped.task=7 | stats count").unwrap();
    assert!(crate::search::service::validate_query_field_names(&ok, &ocsf).is_ok());
}
