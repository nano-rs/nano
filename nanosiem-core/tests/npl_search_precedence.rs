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
    let generator = ClickHouseSqlGenerator::new();
    let atom = |text: &str| {
        generator
            .generate_search_expr(source(&parse_query(text).unwrap()))
            .unwrap()
    };
    assert_eq!(sql, format!("({} AND ({} OR {}))", atom("a"), atom("b"), atom("c")));

    // Literal comparisons exercise the production parser and SQL generator
    // without depending on a log schema. Pin the FULL parenthesized predicate,
    // since SQL's AND-before-OR default is the opposite of search semantics.
    for a in [false, true] {
        for b in [false, true] {
            for c in [false, true] {
                let predicate = |value| if value { "\"yes\"=\"yes\"" } else { "\"yes\"=\"no\"" };
                let (a, b, c) = (predicate(a), predicate(b), predicate(c));
                let query = parse_query(&format!("{a} AND {b} OR {c}")).unwrap();
                assert_eq!(
                    generator.generate_search_expr(source(&query)).unwrap(),
                    format!("({} AND ({} OR {}))", atom(a), atom(b), atom(c))
                );
                let query = roundtrip(&format!("* | where {a} AND {b} OR {c}"));
                let Query::Piped { command: Command::Where { condition }, .. } = query else {
                    panic!("expected where");
                };
                assert_eq!(
                    generator.generate_search_expr(&condition).unwrap(),
                    format!("(({} AND {}) OR {})", atom(a), atom(b), atom(c))
                );
            }
        }
    }
}
