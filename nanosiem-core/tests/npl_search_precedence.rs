// SPDX-License-Identifier: AGPL-3.0-or-later

use nanosiem_core::query::{
    parse_query, ClickHouseSqlGenerator, Command, PrettyPrint, Query, SearchExpr,
};

fn source(query: &Query) -> &SearchExpr {
    match query {
        Query::Search(expr) => expr,
        Query::Piped { source, .. } => source_expr(source),
    }
}

fn source_expr(query: &Query) -> &SearchExpr {
    source(query)
}

fn roundtrip(query: &str) -> Query {
    let parsed = parse_query(query).unwrap();
    let printed = parsed.pretty_print();
    assert_eq!(
        parsed,
        parse_query(&printed).unwrap(),
        "{query} -> {printed}"
    );
    parsed
}

#[test]
fn splunk_search_precedence() {
    for text in ["a b OR c", "a AND b OR c", "a | search a AND b OR c"] {
        let parsed = roundtrip(text);
        let expr = match &parsed {
            Query::Piped {
                command: Command::Where { condition },
                ..
            } => condition,
            _ => source(&parsed),
        };
        assert!(
            matches!(expr, SearchExpr::And(_, right) if matches!(&**right, SearchExpr::Or(_, _))),
            "{text}: {expr:?}"
        );
    }
    assert!(
        matches!(source(&roundtrip("NOT a OR b")), SearchExpr::Or(left, _) if matches!(&**left, SearchExpr::Not(_)))
    );
    assert!(
        matches!(source(&roundtrip("a OR b c OR d")), SearchExpr::And(left, right) if matches!(&**left, SearchExpr::Or(_, _)) && matches!(&**right, SearchExpr::Or(_, _)))
    );
    assert!(
        matches!(source(&roundtrip("(a b) OR (c d)")), SearchExpr::Or(left, right) if matches!(&**left, SearchExpr::Group(_)) && matches!(&**right, SearchExpr::Group(_)))
    );
}

#[test]
fn where_keeps_and_before_or() {
    let parsed = roundtrip("a | where a AND b OR c");
    assert!(
        matches!(parsed, Query::Piped { command: Command::Where { condition: SearchExpr::Or(left, _) }, .. } if matches!(&*left, SearchExpr::And(_, _)))
    );
}

#[test]
fn sequence_conditions_keep_their_existing_order() {
    let parsed = roundtrip("* | sequence by user maxspan=5m [a b OR c] [d]");
    assert!(
        matches!(parsed, Query::Piped { command: Command::Sequence { conditions, .. }, .. }
        if matches!(&conditions[0], SearchExpr::Or(left, _) if matches!(&**left, SearchExpr::And(_, _))))
    );
}

#[test]
fn sql_generation_uses_search_tree() {
    let parsed = parse_query("a b OR c").unwrap();
    let sql = ClickHouseSqlGenerator::new()
        .generate_search_expr(source(&parsed))
        .unwrap();
    assert!(sql.contains(" AND ") && sql.contains(" OR "), "{sql}");
    assert!(
        sql.find(" AND ").unwrap() < sql.find(" OR ").unwrap(),
        "{sql}"
    );
}
