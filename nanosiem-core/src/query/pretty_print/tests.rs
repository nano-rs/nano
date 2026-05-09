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
            field: "timestamp".to_string(),
            descending: true,
        },
    };
    assert_eq!(query.pretty_print(), "error | sort -timestamp");
}

#[test]
fn test_pretty_print_sort_asc() {
    let query = Query::Piped {
        source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
        command: Command::Sort {
            field: "timestamp".to_string(),
            descending: false,
        },
    };
    assert_eq!(query.pretty_print(), "error | sort timestamp");
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
                field: "count".to_string(),
                descending: true,
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
    assert_eq!(
        query.pretty_print(),
        "* | risk score=(count * 10) entity=src_ip"
    );
}
