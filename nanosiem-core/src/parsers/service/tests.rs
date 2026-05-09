// SPDX-License-Identifier: AGPL-3.0-or-later

#![cfg(any())]

//! Tests for parser service

use super::*;

fn test_service() -> ParserService {
    // Create a mock pool (won't be used for validation tests)
    let pool = sqlx::PgPool::connect_lazy("postgresql://localhost/test").unwrap();
    ParserService::new(pool)
}

#[test]
fn test_validate_parser_fields_with_valid_udm_fields() {
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

#[test]
fn test_validate_parser_fields_with_unknown_fields() {
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

#[test]
fn test_validate_parser_fields_ignores_metadata() {
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

#[test]
fn test_validate_parser_fields_with_mixed_fields() {
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

#[test]
fn test_validate_parser_fields_with_array_access() {
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
