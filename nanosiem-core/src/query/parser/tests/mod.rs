// SPDX-License-Identifier: AGPL-3.0-or-later

mod error_messages;
mod syntax_fixes;

use crate::query::{parse_query, Command, Query};
// NAN-1580 retro-hunt parser tests use these AST types directly.
use crate::query::{RetroAxis, SearchExpr, Value};

// === NAN-1580: `ioc` observable term + `retro` command parsing ===

#[test]
fn test_parse_ioc_equals_single_value() {
    let result = parse_query(r#"ioc="1.2.3.4""#).unwrap();
    match result {
        Query::Search(SearchExpr::IocMatch { values, feed, lookup }) => {
            assert_eq!(values, vec![Value::String("1.2.3.4".to_string())]);
            assert_eq!(feed, None);
            assert_eq!(lookup, None);
        }
        other => panic!("Expected IocMatch single value, got {other:?}"),
    }
}

#[test]
fn test_parse_ioc_unquoted_hash_starting_with_digit() {
    // Regression: an unquoted hash starting with a digit must capture the WHOLE
    // token, not number-match the leading digit (most hashes start with a digit).
    let hash = "5fb90fd28458d16e61a7d6e08ae2ed28cb9b35e535aa6bc0e5a487f7c7702288";
    let result = parse_query(&format!("ioc={hash} | retro")).unwrap();
    // `ioc=<hash> | retro` → Piped { Search(IocMatch), Retro }
    match result {
        Query::Piped { source, .. } => match *source {
            Query::Search(SearchExpr::IocMatch { values, .. }) => {
                assert_eq!(values, vec![Value::String(hash.to_string())]);
            }
            other => panic!("Expected IocMatch source, got {other:?}"),
        },
        other => panic!("Expected piped retro query, got {other:?}"),
    }
}

#[test]
fn test_parse_ioc_in_list_unquoted_mixed() {
    // Unquoted IP + digit-leading hash + domain in one list.
    let result =
        parse_query("ioc in [1.2.3.4, 5fb90fde, evil.com]").unwrap();
    match result {
        Query::Search(SearchExpr::IocMatch { values, .. }) => {
            assert_eq!(
                values,
                vec![
                    Value::String("1.2.3.4".to_string()),
                    Value::String("5fb90fde".to_string()),
                    Value::String("evil.com".to_string()),
                ]
            );
        }
        other => panic!("Expected IocMatch list, got {other:?}"),
    }
}

#[test]
fn test_parse_ioc_in_list() {
    let result = parse_query(r#"ioc in ["1.2.3.4", "evil.com", "deadbeef"]"#).unwrap();
    match result {
        Query::Search(SearchExpr::IocMatch { values, feed, lookup }) => {
            assert_eq!(
                values,
                vec![
                    Value::String("1.2.3.4".to_string()),
                    Value::String("evil.com".to_string()),
                    Value::String("deadbeef".to_string()),
                ]
            );
            assert_eq!(feed, None);
            assert_eq!(lookup, None);
        }
        other => panic!("Expected IocMatch list, got {other:?}"),
    }
}

#[test]
fn test_parse_ioc_in_list_parens() {
    // Parenthesized list form is also accepted.
    let result = parse_query(r#"ioc in ("a", "b")"#).unwrap();
    match result {
        Query::Search(SearchExpr::IocMatch { values, feed, lookup }) => {
            assert_eq!(values.len(), 2);
            assert_eq!(feed, None);
            assert_eq!(lookup, None);
        }
        other => panic!("Expected IocMatch paren list, got {other:?}"),
    }
}

#[test]
fn test_parse_ioc_in_feed() {
    let result = parse_query(r#"ioc in threatfox("apt29")"#).unwrap();
    match result {
        Query::Search(SearchExpr::IocMatch { values, feed, lookup }) => {
            assert!(values.is_empty());
            assert_eq!(lookup, None);
            let feed = feed.expect("expected feed source");
            assert_eq!(feed.name, "threatfox");
            assert_eq!(feed.arg, "apt29");
        }
        other => panic!("Expected IocMatch feed, got {other:?}"),
    }
}

#[test]
fn test_parse_ioc_in_lookup() {
    let result = parse_query(r#"ioc in lookup("threat_iocs")"#).unwrap();
    match result {
        Query::Search(SearchExpr::IocMatch { values, feed, lookup }) => {
            assert!(values.is_empty());
            assert_eq!(feed, None);
            let lookup = lookup.expect("expected lookup source");
            assert_eq!(lookup.table, "threat_iocs");
            assert_eq!(lookup.column, None);
        }
        other => panic!("Expected IocMatch lookup, got {other:?}"),
    }
}

#[test]
fn test_parse_ioc_in_lookup_with_column() {
    let result = parse_query(r#"ioc in lookup("threat_iocs", "indicator")"#).unwrap();
    match result {
        Query::Search(SearchExpr::IocMatch { values, feed, lookup }) => {
            assert!(values.is_empty());
            assert_eq!(feed, None);
            let lookup = lookup.expect("expected lookup source");
            assert_eq!(lookup.table, "threat_iocs");
            assert_eq!(lookup.column.as_deref(), Some("indicator"));
        }
        other => panic!("Expected IocMatch lookup with column, got {other:?}"),
    }
}

#[test]
fn test_parse_ioc_in_inputlookup_alias() {
    // `ioc in [inputlookup <name>]` aliases to the same lookup source.
    let result = parse_query(r#"ioc in [inputlookup threat_iocs]"#).unwrap();
    match result {
        Query::Search(SearchExpr::IocMatch { values, feed, lookup }) => {
            assert!(values.is_empty());
            assert_eq!(feed, None);
            let lookup = lookup.expect("expected lookup source");
            assert_eq!(lookup.table, "threat_iocs");
            assert_eq!(lookup.column, None);
        }
        other => panic!("Expected IocMatch inputlookup alias, got {other:?}"),
    }
}

#[test]
fn test_parse_ioc_in_lookup_with_retro_pipeline() {
    let result = parse_query(r#"ioc in lookup("threat_iocs") | retro"#).unwrap();
    match result {
        Query::Piped { source, command } => {
            assert_eq!(command, Command::Retro { axis: RetroAxis::Indicator });
            match *source {
                Query::Search(SearchExpr::IocMatch { lookup: Some(l), .. }) => {
                    assert_eq!(l.table, "threat_iocs");
                }
                other => panic!("Expected IocMatch lookup source, got {other:?}"),
            }
        }
        other => panic!("Expected piped ioc|retro, got {other:?}"),
    }
}

#[test]
fn test_parse_ioc_not_confused_with_ioc_prefixed_field() {
    // `ioc_score=5` must NOT parse as the ioc pseudo-field — it's a normal field.
    let result = parse_query("ioc_score=5").unwrap();
    match result {
        Query::Search(SearchExpr::FieldFilter { field, .. }) => {
            assert_eq!(field, "ioc_score");
        }
        other => panic!("Expected FieldFilter on ioc_score, got {other:?}"),
    }
}

#[test]
fn test_parse_retro_bare_defaults_to_indicator() {
    let result = parse_query(r#"ioc="1.2.3.4" | retro"#).unwrap();
    match result {
        Query::Piped {
            command: Command::Retro { axis },
            ..
        } => assert_eq!(axis, RetroAxis::Indicator),
        other => panic!("Expected bare retro command, got {other:?}"),
    }
}

#[test]
fn test_parse_retro_by_asset() {
    let result = parse_query(r#"ioc="1.2.3.4" | retro by asset"#).unwrap();
    match result {
        Query::Piped {
            command: Command::Retro { axis },
            ..
        } => assert_eq!(axis, RetroAxis::Asset),
        other => panic!("Expected retro by asset, got {other:?}"),
    }
}

#[test]
fn test_parse_retro_by_user() {
    let result = parse_query(r#"ioc="jsmith" | retro by user"#).unwrap();
    match result {
        Query::Piped {
            command: Command::Retro { axis },
            ..
        } => assert_eq!(axis, RetroAxis::User),
        other => panic!("Expected retro by user, got {other:?}"),
    }
}

#[test]
fn test_parse_retro_axis_aliases_normalize_to_asset() {
    // host / ip / entity / account all normalize to the Asset axis.
    for kw in ["host", "ip", "entity", "account"] {
        let q = format!(r#"ioc="x" | retro by {kw}"#);
        let result = parse_query(&q).unwrap();
        match result {
            Query::Piped {
                command: Command::Retro { axis },
                ..
            } => assert_eq!(axis, RetroAxis::Asset, "axis for `by {kw}`"),
            other => panic!("Expected retro by {kw}, got {other:?}"),
        }
    }
}

#[test]
fn test_parse_ioc_feed_with_retro_pipeline() {
    // End-to-end: feed-sourced ioc term feeds a retro pivot command.
    let result = parse_query(r#"ioc in threatfox("apt29") | retro by asset"#).unwrap();
    match result {
        Query::Piped { source, command } => {
            assert_eq!(command, Command::Retro { axis: RetroAxis::Asset });
            match *source {
                Query::Search(SearchExpr::IocMatch { feed: Some(_), .. }) => {}
                other => panic!("Expected IocMatch feed source, got {other:?}"),
            }
        }
        other => panic!("Expected piped ioc|retro, got {other:?}"),
    }
}

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

// === NAN-1711 / audit D15: internal `_bounds=` token on top/rare ===

#[test]
fn test_top_rare_bounds_token_parses_and_defaults_false() {
    // Default: no token → inject_bounds=false.
    match parse_query("* | top src_ip").unwrap() {
        Query::Piped {
            command: Command::Top { inject_bounds, .. },
            ..
        } => assert!(!inject_bounds, "bare top must default inject_bounds=false"),
        other => panic!("Expected Top, got {other:?}"),
    }

    // The internal token (emitted by detection query enrichment via
    // pretty_print) round-trips back into the flag.
    match parse_query("* | top limit=10 src_ip _bounds=true").unwrap() {
        Query::Piped {
            command:
                Command::Top {
                    field,
                    limit,
                    inject_bounds,
                    ..
                },
            ..
        } => {
            assert_eq!(field, "src_ip");
            assert_eq!(limit, 10);
            assert!(inject_bounds);
        }
        other => panic!("Expected Top, got {other:?}"),
    }

    // With a by-clause the token must not be swallowed as a by-field.
    match parse_query("* | rare limit=5 status by user _bounds=true").unwrap() {
        Query::Piped {
            command:
                Command::Rare {
                    field,
                    by_fields,
                    inject_bounds,
                    ..
                },
            ..
        } => {
            assert_eq!(field, "status");
            assert_eq!(by_fields, vec!["user".to_string()]);
            assert!(inject_bounds);
        }
        other => panic!("Expected Rare, got {other:?}"),
    }

    // Mixed with the existing trailing params, any order.
    match parse_query("* | top src_ip _bounds=true showperc=false").unwrap() {
        Query::Piped {
            command:
                Command::Top {
                    inject_bounds,
                    show_percent,
                    ..
                },
            ..
        } => {
            assert!(inject_bounds);
            assert!(!show_percent);
        }
        other => panic!("Expected Top, got {other:?}"),
    }
}
