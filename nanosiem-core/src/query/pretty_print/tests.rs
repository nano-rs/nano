// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the pretty-print module.

use super::super::ast::*;
use super::helpers::format_duration;
use super::PrettyPrint;
use std::net::Ipv4Addr;
use std::time::Duration;

#[test]
fn test_pretty_print_keyword() {
    let query = Query::Search(SearchExpr::Keyword("error".to_string()));
    assert_eq!(query.pretty_print(), "error");
}

#[test]
fn test_pretty_print_keyword_with_spaces() {
    let query = Query::Search(SearchExpr::Keyword("hello world".to_string()));
    assert_eq!(query.pretty_print(), "\"hello world\"");
}

#[test]
fn test_pretty_print_field_filter() {
    let query = Query::Search(SearchExpr::FieldFilter {
        field: "status".to_string(),
        op: Comparator::Eq,
        value: Value::Number(500.0),
    });
    assert_eq!(query.pretty_print(), "status=500");
}

#[test]
fn test_pretty_print_field_filter_ip() {
    let query = Query::Search(SearchExpr::FieldFilter {
        field: "src_ip".to_string(),
        op: Comparator::Eq,
        value: Value::Ip(std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
    });
    assert_eq!(query.pretty_print(), "src_ip=192.168.1.1");
}

#[test]
fn test_pretty_print_and() {
    let query = Query::Search(SearchExpr::And(
        Box::new(SearchExpr::Keyword("error".to_string())),
        Box::new(SearchExpr::FieldFilter {
            field: "status".to_string(),
            op: Comparator::Eq,
            value: Value::Number(500.0),
        }),
    ));
    assert_eq!(query.pretty_print(), "error status=500");
}

#[test]
fn test_pretty_print_or() {
    let query = Query::Search(SearchExpr::Or(
        Box::new(SearchExpr::Keyword("error".to_string())),
        Box::new(SearchExpr::Keyword("warning".to_string())),
    ));
    assert_eq!(query.pretty_print(), "error OR warning");
}

#[test]
fn test_pretty_print_not() {
    let query = Query::Search(SearchExpr::Not(Box::new(SearchExpr::Keyword(
        "debug".to_string(),
    ))));
    assert_eq!(query.pretty_print(), "NOT debug");
}

#[test]
fn test_pretty_print_group() {
    let query = Query::Search(SearchExpr::Group(Box::new(SearchExpr::Or(
        Box::new(SearchExpr::Keyword("error".to_string())),
        Box::new(SearchExpr::Keyword("warning".to_string())),
    ))));
    assert_eq!(query.pretty_print(), "(error OR warning)");
}

#[test]
fn test_pretty_print_stats() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
        command: Command::Stats {
            aggregations: vec![Aggregation::new(AggFunc::Count, None)],
            group_by: Some(vec!["src_ip".to_string()]),
        },
    };
    assert_eq!(query.pretty_print(), "error | stats count() by src_ip");
}

#[test]
fn test_pretty_print_stats_with_alias() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Stats {
            aggregations: vec![Aggregation::with_alias(
                AggFunc::Count,
                None,
                "total".to_string(),
            )],
            group_by: None,
        },
    };
    assert_eq!(query.pretty_print(), "* | stats count() as total");
}

#[test]
fn test_pretty_print_where() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Where {
            condition: SearchExpr::FieldFilter {
                field: "status".to_string(),
                op: Comparator::Gte,
                value: Value::Number(400.0),
            },
        },
    };
    assert_eq!(query.pretty_print(), "* | where status>=400");
}

#[test]
fn test_pretty_print_sort_desc() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
        command: Command::Sort {
            fields: vec![SortField { field: "timestamp".to_string(), descending: true }],
            limit: None,
        },
    };
    assert_eq!(query.pretty_print(), "error | sort -timestamp");
}

#[test]
fn test_pretty_print_sort_asc() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
        command: Command::Sort {
            fields: vec![SortField { field: "timestamp".to_string(), descending: false }],
            limit: None,
        },
    };
    // The printer emits an explicit `+` for ascending so the direction
    // survives a round trip unambiguously.
    assert_eq!(query.pretty_print(), "error | sort +timestamp");
}

#[test]
fn test_pretty_print_head() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
        command: Command::Head { count: 10 },
    };
    assert_eq!(query.pretty_print(), "error | head 10");
}

#[test]
fn test_pretty_print_tail() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
        command: Command::Tail { count: 5 },
    };
    assert_eq!(query.pretty_print(), "error | tail 5");
}

#[test]
fn test_pretty_print_timechart() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
        command: Command::Timechart {
            span: Duration::from_secs(3600),
            aggregations: vec![Aggregation::new(AggFunc::Count, None)],
            split_by: vec!["src_ip".to_string()],
            limit: None,
            cont: false,
        },
    };
    assert_eq!(
        query.pretty_print(),
        "error | timechart span=1h count() by src_ip"
    );
}

#[test]
fn test_pretty_print_table() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
        command: Command::Table {
            fields: vec![
                TableField {
                    name: "src_ip".to_string(),
                    alias: None,
                },
                TableField {
                    name: "dest_ip".to_string(),
                    alias: None,
                },
                TableField {
                    name: "timestamp".to_string(),
                    alias: None,
                },
            ],
        },
    };
    assert_eq!(
        query.pretty_print(),
        "error | table src_ip, dest_ip, timestamp"
    );
}

#[test]
fn test_pretty_print_table_with_aliases() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Table {
            fields: vec![
                TableField {
                    name: "src_ip".to_string(),
                    alias: Some("source".to_string()),
                },
                TableField {
                    name: "dest_ip".to_string(),
                    alias: Some("destination".to_string()),
                },
            ],
        },
    };
    assert_eq!(
        query.pretty_print(),
        "* | table src_ip as source, dest_ip as destination"
    );
}

#[test]
fn test_pretty_print_rename_single() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Rename {
            mappings: vec![FieldRename {
                from: "src_ip".to_string(),
                to: "source_address".to_string(),
            }],
        },
    };
    assert_eq!(query.pretty_print(), "* | rename src_ip as source_address");
}

#[test]
fn test_pretty_print_rename_multiple() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Rename {
            mappings: vec![
                FieldRename {
                    from: "src_ip".to_string(),
                    to: "source".to_string(),
                },
                FieldRename {
                    from: "dest_ip".to_string(),
                    to: "destination".to_string(),
                },
            ],
        },
    };
    assert_eq!(
        query.pretty_print(),
        "* | rename src_ip as source, dest_ip as destination"
    );
}

#[test]
fn test_pretty_print_multiple_pipes() {
    let query = Query::Piped {
        source: Box::new(Query::Piped {
            source: Box::new(Query::Piped {
                source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
                command: Command::Stats {
                    aggregations: vec![Aggregation::new(AggFunc::Count, None)],
                    group_by: Some(vec!["src_ip".to_string()]),
                },
            }),
            command: Command::Sort {
                fields: vec![SortField { field: "count".to_string(), descending: true }],
                limit: None,
            },
        }),
        command: Command::Head { count: 10 },
    };
    assert_eq!(
        query.pretty_print(),
        "error | stats count() by src_ip | sort -count | head 10"
    );
}

#[test]
fn test_format_duration() {
    assert_eq!(format_duration(Duration::from_secs(30)), "30s");
    assert_eq!(format_duration(Duration::from_secs(60)), "1m");
    assert_eq!(format_duration(Duration::from_secs(300)), "5m");
    assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
    assert_eq!(format_duration(Duration::from_secs(86400)), "1d");
}

#[test]
fn test_pretty_print_all_comparators() {
    let comparators = [
        (Comparator::Eq, "="),
        (Comparator::Ne, "!="),
        (Comparator::Gt, ">"),
        (Comparator::Lt, "<"),
        (Comparator::Gte, ">="),
        (Comparator::Lte, "<="),
    ];

    for (op, expected) in comparators {
        let query = Query::Search(SearchExpr::FieldFilter {
            field: "field".to_string(),
            op,
            value: Value::String("value".to_string()),
        });
        assert!(query.pretty_print().contains(expected));
    }

    // Test regex with /pattern/ syntax
    let regex_query = Query::Search(SearchExpr::FieldFilter {
        field: "field".to_string(),
        op: Comparator::Regex,
        value: Value::Regex("pattern".to_string()),
    });
    assert!(regex_query.pretty_print().contains("/pattern/"));
}

#[test]
fn test_pretty_print_lookup_basic() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Lookup {
            table_name: "assets".to_string(),
            key_field: "src_ip".to_string(),
            output_fields: None,
            case_insensitive: false,
        },
    };
    assert_eq!(query.pretty_print(), "* | lookup assets src_ip");
}

#[test]
fn test_pretty_print_lookup_with_output() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
        command: Command::Lookup {
            table_name: "users".to_string(),
            key_field: "user".to_string(),
            output_fields: Some(vec!["name".to_string(), "email".to_string()]),
            case_insensitive: false,
        },
    };
    assert_eq!(
        query.pretty_print(),
        "error | lookup users user OUTPUT name, email"
    );
}

#[test]
fn test_pretty_print_lookup_case_insensitive() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Lookup {
            table_name: "threats".to_string(),
            key_field: "ip".to_string(),
            output_fields: None,
            case_insensitive: true,
        },
    };
    assert_eq!(
        query.pretty_print(),
        "* | lookup threats ip CASE_INSENSITIVE"
    );
}

#[test]
fn test_pretty_print_lookup_full() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Lookup {
            table_name: "threat_intel".to_string(),
            key_field: "src_ip".to_string(),
            output_fields: Some(vec!["threat_level".to_string(), "category".to_string()]),
            case_insensitive: true,
        },
    };
    assert_eq!(
        query.pretty_print(),
        "* | lookup threat_intel src_ip OUTPUT threat_level, category CASE_INSENSITIVE"
    );
}

#[test]
fn test_pretty_print_risk_basic() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Risk {
            score: RiskScoreExpr::Literal(50),
            entity_field: None,
            factor: None,
            weight: None,
        },
    };
    assert_eq!(query.pretty_print(), "* | risk score=50");
}

#[test]
fn test_pretty_print_risk_with_entity() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Risk {
            score: RiskScoreExpr::Literal(75),
            entity_field: Some("src_ip".to_string()),
            factor: None,
            weight: None,
        },
    };
    assert_eq!(query.pretty_print(), "* | risk score=75 entity=src_ip");
}

#[test]
fn test_pretty_print_risk_full() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Risk {
            score: RiskScoreExpr::Literal(90),
            entity_field: Some("user".to_string()),
            factor: Some(EvalExpression::Literal(Value::String(
                "brute_force".to_string(),
            ))),
            weight: None,
        },
    };
    assert_eq!(
        query.pretty_print(),
        "* | risk score=90 entity=user factor=\"brute_force\""
    );
}

#[test]
fn test_pretty_print_risk_with_weight() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Risk {
            score: RiskScoreExpr::Literal(50),
            entity_field: Some("user".to_string()),
            factor: None,
            weight: Some(0.5),
        },
    };
    assert_eq!(
        query.pretty_print(),
        "* | risk score=50 entity=user weight=0.5"
    );
}

#[test]
fn test_pretty_print_risk_dynamic_score() {
    // Test with field reference
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Risk {
            score: RiskScoreExpr::Dynamic(EvalExpression::Field("severity_level".to_string())),
            entity_field: Some("user".to_string()),
            factor: None,
            weight: None,
        },
    };
    assert_eq!(
        query.pretty_print(),
        "* | risk score=severity_level entity=user"
    );

    // Test with arithmetic expression
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("*".to_string()))),
        command: Command::Risk {
            score: RiskScoreExpr::Dynamic(EvalExpression::BinaryOp {
                left: Box::new(EvalExpression::Field("count".to_string())),
                op: BinaryOperator::Mul,
                right: Box::new(EvalExpression::Literal(Value::Number(10.0))),
            }),
            entity_field: Some("src_ip".to_string()),
            factor: None,
            weight: None,
        },
    };
    // The printer emits the expression unparenthesized. Verified round-trip
    // safe: `score=count * 10 entity=src_ip` and `score=(count * 10) …` parse
    // to the identical AST, so the parser knows where the score expression
    // ends without the parens.
    assert_eq!(
        query.pretty_print(),
        "* | risk score=count * 10 entity=src_ip"
    );
}

// ---------------------------------------------------------------------------
// NAN-2184: `npl_quoted_body` doubles backslashes so `parse(pretty_print(x))`
// preserves values carrying CONSECUTIVE backslashes. The parser collapses
// `\\` → `\` after taking the literal (values.rs::double_quoted_string), so
// emitting them raw silently dropped one — invisible for lone backslashes
// (Windows paths), lossy for UNC paths and regexes matching a literal `\`.
// ---------------------------------------------------------------------------

/// Round-trip a filter value through pretty_print → parse and hand back what
/// the parser actually reconstructed.
fn round_trip_value(raw: &str) -> String {
    use crate::query::parse_query;
    let q = Query::Search(SearchExpr::FieldFilter {
        field: "file_path".to_string(),
        op: Comparator::Eq,
        value: Value::String(raw.to_string()),
    });
    let printed = q.pretty_print();
    let reparsed = parse_query(&printed)
        .unwrap_or_else(|e| panic!("pretty_print produced unparseable nPL {printed:?}: {e:?}"));
    match reparsed {
        Query::Search(SearchExpr::FieldFilter { value: Value::String(s), .. }) => s,
        other => panic!("round trip changed structure for {raw:?}: {other:?}"),
    }
}

#[test]
fn unc_path_survives_round_trip() {
    // Before NAN-2184 this came back as `\fileserver\share` — one backslash lost.
    assert_eq!(round_trip_value(r"\\fileserver\share"), r"\\fileserver\share");
}

#[test]
fn lone_backslash_path_still_round_trips() {
    // Regression guard: the case that always worked must keep working.
    assert_eq!(round_trip_value(r"C:\Windows\System32"), r"C:\Windows\System32");
    assert_eq!(round_trip_value(r"C:\Windows\System32\"), r"C:\Windows\System32\");
}

#[test]
fn regex_escapes_survive_round_trip() {
    assert_eq!(round_trip_value(r"a\.b\d\w"), r"a\.b\d\w");
    // A pattern matching a LITERAL backslash — previously collapsed to `\.`.
    assert_eq!(round_trip_value(r"\\."), r"\\.");
}

// ---------------------------------------------------------------------------
// NAN-2241: a `"`-bearing value is re-quoted with `'`, not stripped.
//
// The pre-NAN-2241 helper deleted every `"` unconditionally. That was safe but
// LOSSY, and the loss was silent: a `rex` pattern's `[^"]+` reached ClickHouse
// as `[^]+` — a different, never-matching regex — and the query returned zero
// rows with no error. nPL has two interchangeable literal forms and only the
// delimiter can terminate one, so the fix is to pick the delimiter the value
// does not contain. Nothing about the breakout guarantee changes: the emitted
// literal still cannot be closed from within.
// ---------------------------------------------------------------------------

/// Round-trip a filter value and hand back BOTH the emitted nPL and what the
/// parser reconstructed, so a test can assert on the wire form as well.
fn round_trip_value_with_text(raw: &str) -> (String, String) {
    use crate::query::parse_query;
    let q = Query::Search(SearchExpr::FieldFilter {
        field: "file_path".to_string(),
        op: Comparator::Eq,
        value: Value::String(raw.to_string()),
    });
    let printed = q.pretty_print();
    let reparsed = parse_query(&printed)
        .unwrap_or_else(|e| panic!("pretty_print produced unparseable nPL {printed:?}: {e:?}"));
    match reparsed {
        Query::Search(SearchExpr::FieldFilter { value: Value::String(s), .. }) => (printed, s),
        other => panic!("round trip changed structure for {raw:?}: {other:?}"),
    }
}

#[test]
fn embedded_quote_survives_by_switching_the_delimiter() {
    // Before NAN-2241 this came back as `a OR src_ip=10.0.0.9` — the `"` was
    // deleted. The value must now survive byte-for-byte...
    let (printed, back) = round_trip_value_with_text(r#"a" OR src_ip=10.0.0.9"#);
    assert_eq!(back, r#"a" OR src_ip=10.0.0.9"#);
    // ...as ONE single-quoted literal, not as query structure. The
    // `round_trip_value_with_text` match arm already proves the AST shape is a
    // single FieldFilter; this pins the wire form that makes that true.
    assert_eq!(printed, r#"file_path='a" OR src_ip=10.0.0.9'"#);
}

#[test]
fn quote_after_backslash_cannot_reopen_the_literal() {
    // The backslash-doubling pass and the delimiter choice must not interact:
    // `\"` inside a single-quoted literal is an ordinary backslash followed by
    // an ordinary quote, and both survive.
    assert_eq!(round_trip_value(r#"trail\"next"#), r#"trail\"next"#);
}

#[test]
fn values_without_double_quotes_keep_the_double_quoted_form() {
    // Byte-identical to pre-NAN-2241 output for the overwhelmingly common case
    // — a single quote in the value is inert inside `"…"` and must not flip the
    // delimiter (that would gratuitously churn every serialized query).
    let (printed, back) = round_trip_value_with_text("O'Connor");
    assert_eq!(printed, r#"file_path="O'Connor""#);
    assert_eq!(back, "O'Connor");
}

#[test]
fn both_quote_kinds_are_unrepresentable_and_fall_back_to_the_old_strip() {
    // nPL cannot express a literal containing BOTH quote characters: each form
    // is terminated by its own delimiter and neither has an escape (NAN-1157).
    // This is unreachable from `parse_query` — see the next test — so the
    // pre-NAN-2241 behaviour is kept for it: double-quote, drop the `"`. Still
    // no breakout (the `'` is inert inside `"…"`), just lossy.
    let (printed, back) = round_trip_value_with_text(r#"a"b'c"#);
    assert_eq!(printed, r#"file_path="ab'c""#);
    assert_eq!(back, "ab'c");
}

#[test]
fn both_quote_kinds_cannot_come_out_of_the_parser() {
    // The reachability claim behind the fallback above: every string the parser
    // can put in the AST comes from a quoted literal (which stops at its own
    // delimiter) or from an unquoted token (no quotes at all), so no parsed
    // value can carry both `"` and `'`.
    use crate::query::parse_query;
    for npl in [
        r#"file_path='has " and no apostrophe'"#,
        r#"file_path="has ' and no double quote""#,
        r#"* | rex field=message '"k":"(?<v>[^"]+)"'"#,
        r#"* | eval x='say "hi"'"#,
        r#"'a" OR source_type=audit'"#,
    ] {
        let parsed = parse_query(npl).unwrap_or_else(|e| panic!("{npl} must parse: {e:?}"));
        let printed = parsed.pretty_print();
        assert_eq!(
            parse_query(&printed).unwrap_or_else(|e| panic!("{printed} must re-parse: {e:?}")),
            parsed,
            "pretty_print must round-trip {npl} to an identical AST (printed: {printed})"
        );
    }
}

#[test]
fn rex_pattern_with_double_quotes_round_trips_intact() {
    // The reported NAN-2241 repro, at the AST level: a Google Workspace token
    // hunt pulling `app_name` out of a JSON message.
    use crate::query::parse_query;
    let pattern = r#""name":"app_name","value":"(?<app>[^"]+)""#;
    let npl = format!("source_type=gws_token | rex field=message '{pattern}' | head 1");
    let parsed = parse_query(&npl).unwrap_or_else(|e| panic!("repro must parse: {e:?}"));
    let printed = parsed.pretty_print();
    assert!(
        printed.contains(pattern),
        "the pattern must appear verbatim in the serialized query: {printed}"
    );
    match parse_query(&printed).unwrap_or_else(|e| panic!("{printed} must re-parse: {e:?}")) {
        Query::Piped { source, .. } => match *source {
            Query::Piped { command: Command::Rex { pattern: p, .. }, .. } => {
                assert_eq!(p, pattern, "the character class `[^\"]+` must not be mangled");
            }
            other => panic!("expected a rex stage, got {other:?}"),
        },
        other => panic!("expected a piped query, got {other:?}"),
    }
}

#[test]
fn sed_mode_rex_round_trips_with_a_quote_bearing_pattern() {
    // The sed expression is ONE literal (`"s/pat/repl/"`), so the delimiter has
    // to be chosen for the whole thing, not per part.
    use crate::query::parse_query;
    let npl = r#"* | rex mode=sed field=message 's/pass="[^"]*"/REDACTED/'"#;
    let parsed = parse_query(npl).unwrap_or_else(|e| panic!("{npl} must parse: {e:?}"));
    let printed = parsed.pretty_print();
    assert!(
        printed.contains(r#"pass="[^"]*""#),
        "sed pattern lost its quotes: {printed}"
    );
    assert_eq!(
        parse_query(&printed).unwrap_or_else(|e| panic!("{printed} must re-parse: {e:?}")),
        parsed
    );
}

#[test]
fn newlines_are_stripped_so_the_query_stays_one_line() {
    let printed = Query::Search(SearchExpr::FieldFilter {
        field: "message".to_string(),
        op: Comparator::Eq,
        value: Value::String("evil\n| head 1".to_string()),
    })
    .pretty_print();
    assert!(!printed.contains('\n'), "pretty_print leaked a newline: {printed:?}");
    assert_eq!(round_trip_value("evil\n| head 1"), "evil| head 1");
}

#[test]
fn inert_characters_are_preserved() {
    assert_eq!(round_trip_value("cmd|powershell"), "cmd|powershell");
    assert_eq!(round_trip_value("(foo|bar)[1]"), "(foo|bar)[1]");
}
