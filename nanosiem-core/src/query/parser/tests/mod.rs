// SPDX-License-Identifier: AGPL-3.0-or-later

mod error_messages;
mod syntax_fixes;

use crate::query::{parse_query, Command, Query};

#[test]
fn test_ai_command_basic() {
    let query = parse_query(r#"* | ai prompt="Classify these events""#).unwrap();
    match query {
        Query::Piped { command, .. } => match command {
            Command::Ai { prompt, max_rows } => {
                assert_eq!(prompt, "Classify these events");
                assert_eq!(max_rows, 100); // default
            }
            other => panic!("Expected Ai command, got {:?}", other),
        },
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_ai_command_with_max_rows() {
    let query = parse_query(r#"* | ai prompt="score" max_rows=50"#).unwrap();
    match query {
        Query::Piped { command, .. } => match command {
            Command::Ai { max_rows, .. } => assert_eq!(max_rows, 50),
            other => panic!("Expected Ai command, got {:?}", other),
        },
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_ai_command_hard_cap() {
    let query = parse_query(r#"* | ai prompt="score" max_rows=9999"#).unwrap();
    match query {
        Query::Piped { command, .. } => match command {
            Command::Ai { max_rows, .. } => assert_eq!(max_rows, 500), // capped
            other => panic!("Expected Ai command, got {:?}", other),
        },
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_ai_command_with_post_pipe() {
    let query = parse_query(r#"* | ai prompt="Classify" | where ai_verdict="TP""#).unwrap();
    // The outer command should be `where`, with `ai` deeper in the tree
    match query {
        Query::Piped { source, command } => {
            assert!(matches!(command, Command::Where { .. }));
            match *source {
                Query::Piped { command, .. } => {
                    assert!(matches!(command, Command::Ai { .. }));
                }
                _ => panic!("Expected inner Piped with Ai command"),
            }
        }
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_ai_not_greedy() {
    // "aim" should NOT match the ai command — boundary guard
    let query = parse_query(r#"* | where action="aim""#).unwrap();
    match query {
        Query::Piped { command, .. } => {
            assert!(matches!(command, Command::Where { .. }));
        }
        _ => panic!("Expected Piped query with Where"),
    }
}

// NAN-620: numeric/hyphenated cloud account ids must parse without quotes —
// the cloud overview emits `account=<aws_account_id>` (12 digits) when the
// user clicks an account tile, and field_name-based parsing rejected them.
#[test]
fn test_cloud_account_numeric_aws_id() {
    let query =
        parse_query("source_type=aws_cloudtrail | cloud account=234567890123").unwrap();
    match query {
        Query::Piped { command, .. } => match command {
            Command::Cloud { account, .. } => {
                assert_eq!(account.as_deref(), Some("234567890123"));
            }
            other => panic!("Expected Cloud command, got {:?}", other),
        },
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_cloud_account_hyphenated_value() {
    let query = parse_query("* | cloud account=my-gcp-project-1").unwrap();
    match query {
        Query::Piped { command, .. } => match command {
            Command::Cloud { account, .. } => {
                assert_eq!(account.as_deref(), Some("my-gcp-project-1"));
            }
            other => panic!("Expected Cloud command, got {:?}", other),
        },
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_cloud_principal_unquoted_with_dot_and_hyphen() {
    let query = parse_query("* | cloud principal=role-name.session").unwrap();
    match query {
        Query::Piped { command, .. } => match command {
            Command::Cloud { principal, .. } => {
                assert_eq!(principal.as_deref(), Some("role-name.session"));
            }
            other => panic!("Expected Cloud command, got {:?}", other),
        },
        _ => panic!("Expected Piped query"),
    }
}
