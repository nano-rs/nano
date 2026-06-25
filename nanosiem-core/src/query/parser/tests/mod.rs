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

// ── Command-page directives (NAN-1560) ────────────────────────────────────

#[test]
fn test_services_command_bare() {
    let query = parse_query("* | services").unwrap();
    match query {
        Query::Piped { command, .. } => {
            assert_eq!(command, Command::Services, "expected Services, got {command:?}")
        }
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_service_command_with_name() {
    let query = parse_query("* | service checkout-api").unwrap();
    match query {
        Query::Piped { command, .. } => match command {
            Command::Service { name } => assert_eq!(name, "checkout-api"),
            other => panic!("Expected Service command, got {other:?}"),
        },
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_services_not_parsed_as_service() {
    // `| services` must NOT be a Service command with name "services".
    let query = parse_query("* | services").unwrap();
    match query {
        Query::Piped { command, .. } => {
            assert!(
                matches!(command, Command::Services),
                "plural `services` mis-parsed as {command:?}"
            );
        }
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_trace_command_with_hex_id() {
    let query = parse_query("* | trace deadbeef00112233").unwrap();
    match query {
        Query::Piped { command, .. } => match command {
            Command::Trace { trace_id } => assert_eq!(trace_id, "deadbeef00112233"),
            other => panic!("Expected Trace command, got {other:?}"),
        },
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_metric_command_service_scope() {
    // `service=` scoping is now supported (NAN-1564): it parses to
    // `service: Some(...)` and is carried to MetricsExplorer as the promoted
    // `service_name` column filter, so the chart opens genuinely scoped.
    let query = parse_query("* | metric http.server.duration service=api").unwrap();
    match query {
        Query::Piped { command, .. } => match command {
            Command::Metric { name, service } => {
                assert_eq!(name, "http.server.duration");
                assert_eq!(service, Some("api".to_string()));
            }
            other => panic!("Expected Metric command, got {other:?}"),
        },
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_metric_command_bare_name() {
    let query = parse_query("* | metric http.server.duration").unwrap();
    match query {
        Query::Piped { command, .. } => match command {
            Command::Metric { name, service } => {
                assert_eq!(name, "http.server.duration");
                assert_eq!(service, None);
            }
            other => panic!("Expected Metric command, got {other:?}"),
        },
        _ => panic!("Expected Piped query"),
    }
}

#[test]
fn test_metric_command_not_greedy_on_pipe() {
    // `| metric x | head 5` — the metric name must not swallow the pipe.
    let query = parse_query("* | metric latency | head 5").unwrap();
    // Terminal command is head; its source is the metric command.
    match query {
        Query::Piped { command, source } => {
            assert!(
                matches!(command, Command::Head { .. }),
                "expected trailing Head, got {command:?}"
            );
            match *source {
                Query::Piped { command: inner, .. } => match inner {
                    Command::Metric { name, service } => {
                        assert_eq!(name, "latency");
                        assert_eq!(service, None);
                    }
                    other => panic!("Expected inner Metric command, got {other:?}"),
                },
                _ => panic!("Expected inner Piped query"),
            }
        }
        _ => panic!("Expected Piped query"),
    }
}
