// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for parser service

use super::*;

/// NAN-2361: `connect_lazy` never contacts the database, but it still requires
/// a Tokio context to build its pool — so these sync `#[test]`s panicked at
/// construction, which is why the whole file sat behind `#![cfg(any())]` rather
/// than any assertion actually being wrong. `#[tokio::test]` supplies the
/// runtime; no database is involved.
fn test_service() -> ParserService {
    // Lazy pool: never connected, only needed to construct the service.
    let pool = sqlx::PgPool::connect_lazy("postgresql://localhost/test").unwrap();
    ParserService::new(pool)
}

#[tokio::test]
async fn test_validate_parser_fields_with_valid_udm_fields() {
    let service = test_service();

    let vrl = r#"
        .timestamp = now()
        .src_ip = .source_ip
        .dest_ip = .destination_ip
        .user = .username
        .action = "login"
        .status = "success"
    "#;

    let result = service.validate_parser_fields(vrl);
    assert!(result.valid);
    assert!(result.error.is_none());
    // Should have no warnings since all fields are valid
    assert!(result.warnings.is_empty());
}

#[tokio::test]
async fn test_validate_parser_fields_with_unknown_fields() {
    let service = test_service();

    let vrl = r#"
        .timestamp = now()
        .src_ip = .source_ip
        .custom_field_not_in_udm = "value"
        .another_unknown_field = 123
    "#;

    let result = service.validate_parser_fields(vrl);
    assert!(result.valid); // Still valid, just warnings
    assert!(result.error.is_none());
    // Should have warnings for unknown fields
    assert!(!result.warnings.is_empty());
    assert!(result.warnings[0].contains("custom_field_not_in_udm"));
    assert!(result.warnings[0].contains("another_unknown_field"));
}

#[tokio::test]
async fn test_validate_parser_fields_ignores_metadata() {
    let service = test_service();

    let vrl = r#"
        .metadata = {}
        .metadata.event_id = 4624
        .udm = {}
        .udm.timestamp = now()
        .src_ip = .source_ip
    "#;

    let result = service.validate_parser_fields(vrl);
    assert!(result.valid);
    assert!(result.error.is_none());
    // Should not warn about .metadata or .udm
    assert!(result.warnings.is_empty());
}

#[tokio::test]
async fn test_validate_parser_fields_with_mixed_fields() {
    let service = test_service();

    let vrl = r#"
        .timestamp = now()
        .src_ip = .source_ip
        .dest_ip = .destination_ip
        .user = .username
        .custom_app_field = "myapp"
        .action = "login"
    "#;

    let result = service.validate_parser_fields(vrl);
    assert!(result.valid);
    assert!(result.error.is_none());
    // Should warn about custom_app_field only
    assert_eq!(result.warnings.len(), 1);
    assert!(result.warnings[0].contains("custom_app_field"));
    assert!(!result.warnings[0].contains("src_ip"));
    assert!(!result.warnings[0].contains("timestamp"));
}

#[tokio::test]
async fn test_validate_parser_fields_with_array_access() {
    let service = test_service();

    let vrl = r#"
        .timestamp = now()
        .src_ip[0] = .source_ips[0]
        .user = .username
    "#;

    let result = service.validate_parser_fields(vrl);
    assert!(result.valid);
    assert!(result.error.is_none());
    // Should recognize src_ip even with array access
    assert!(result.warnings.is_empty());
}

/// NAN-2361: only ASSIGNMENT TARGETS are UDM's business.
///
/// The old pattern scanned anywhere in the line, so a source field on the
/// right-hand side was reported as an unknown UDM field that "will be preserved
/// in metadata" — describing neither what it was nor what happens to it.
#[tokio::test]
async fn source_fields_on_the_right_hand_side_are_never_warned_about() {
    let service = test_service();

    // Every RHS name here is deliberately absent from the UDM.
    let vrl = r#"
        .src_ip = .totally_unknown_source
        .dest_ip = .another_unknown_source[0]
        .user = parse_json!(.raw_payload_blob).name
    "#;

    let result = service.validate_parser_fields(vrl);
    assert!(result.valid);
    assert!(
        result.warnings.is_empty(),
        "read-only source fields must not warn: {:?}",
        result.warnings
    );
}

/// Writes into the documented spill objects are not unknown fields.
#[tokio::test]
async fn metadata_and_udm_subfield_writes_are_not_unknown_fields() {
    let service = test_service();

    let vrl = r#"
        .metadata.event_id = 4624
        .metadata.deeply.nested.thing = "x"
        .udm.timestamp = now()
        .src_ip = .source_ip
    "#;

    let result = service.validate_parser_fields(vrl);
    assert!(result.valid);
    assert!(
        result.warnings.is_empty(),
        "metadata/udm writes must not warn: {:?}",
        result.warnings
    );
}

/// A genuinely unknown assignment target must STILL warn — the fix narrows the
/// false positives without going quiet on the real case.
#[tokio::test]
async fn unknown_assignment_targets_still_warn() {
    let service = test_service();

    let vrl = r#"
        .src_ip = .source_ip
        .some_vendor_specific_field = "value"
    "#;

    let result = service.validate_parser_fields(vrl);
    assert_eq!(result.warnings.len(), 1, "{:?}", result.warnings);
    assert!(result.warnings[0].contains("some_vendor_specific_field"));
}

/// An equality COMPARISON is not an assignment.
#[tokio::test]
async fn comparisons_are_not_treated_as_assignments() {
    let service = test_service();

    let vrl = r#"
        if .some_unknown_probe_field == "x" { .src_ip = .source_ip }
        .action = "login"
    "#;

    let result = service.validate_parser_fields(vrl);
    assert!(
        result.warnings.is_empty(),
        "a comparison must not register as a write: {:?}",
        result.warnings
    );
}

/// `.udm.<leaf>` IS the UDM namespace, so the leaf must be validated.
///
/// NAN-2361: skipping the whole `.udm` subtree switches validation off for any
/// parser written that way — the shipped Windows Event Log parser makes 452 of
/// its assignments as `.udm.*`, so a subtree skip means it is never checked at
/// all while still reporting "valid".
#[tokio::test]
async fn udm_namespace_writes_validate_their_leaf() {
    let service = test_service();

    let good = service.validate_parser_fields(".udm.src_ip = .source_ip\n.udm.timestamp = now()\n");
    assert!(
        good.warnings.is_empty(),
        "real UDM leaves must not warn: {:?}",
        good.warnings
    );

    let bad = service.validate_parser_fields(".udm.definitely_not_a_udm_field = \"x\"\n");
    assert_eq!(bad.warnings.len(), 1, "{:?}", bad.warnings);
    assert!(bad.warnings[0].contains("definitely_not_a_udm_field"));

    // A bare container init assigns no field and must stay silent.
    let init = service.validate_parser_fields(".udm = {}\n.metadata = {}\n");
    assert!(init.warnings.is_empty(), "{:?}", init.warnings);
}
