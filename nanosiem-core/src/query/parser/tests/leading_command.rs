// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-1843: a query may open with a bare command instead of a search term.
//!
//! `stats count by source_type` must parse as `* | stats count by source_type`.
//! Before this, the leading `stats` was swallowed by `search_expr` as free-text
//! keywords, so the query became a keyword hunt for the words "stats", "count",
//! "by", "source_type" — which either failed downstream with a raw ClickHouse
//! error (`sort -count` ordering by a column that doesn't exist) or, worse,
//! silently returned the wrong rows.
//!
//! The non-regression half matters just as much: command names are ordinary
//! words, and a keyword search that happens to start with one must stay a
//! keyword search.

use crate::query::{parse_query, validate_query_fields, Command, Query, SearchExpr};

/// The base of a piped chain — what the query actually scans.
fn source_of(query: &Query) -> &SearchExpr {
    match query {
        Query::Search(expr) => expr,
        Query::Piped { source, .. } => source_of(source),
    }
}

fn commands_of(query: &Query) -> Vec<&Command> {
    match query {
        Query::Search(_) => Vec::new(),
        Query::Piped { source, command } => {
            let mut cmds = commands_of(source);
            cmds.push(command);
            cmds
        }
    }
}

// === Leading command implies a wildcard source ===

#[test]
fn test_leading_stats_is_equivalent_to_explicit_pipe() {
    // The original NAN-1843 repro.
    let bare = parse_query("stats count by source_type | sort -count | head 25").unwrap();
    let piped = parse_query("| stats count by source_type | sort -count | head 25").unwrap();
    assert_eq!(bare, piped);

    assert_eq!(source_of(&bare), &SearchExpr::Keyword("*".to_string()));
    assert!(matches!(commands_of(&bare)[0], Command::Stats { .. }));
    assert_eq!(commands_of(&bare).len(), 3);
}

#[test]
fn test_leading_stats_without_further_pipes() {
    let query = parse_query("stats count by src_ip").unwrap();
    assert_eq!(query, parse_query("| stats count by src_ip").unwrap());
    assert!(matches!(commands_of(&query)[..], [Command::Stats { .. }]));
}

#[test]
fn test_other_aggregating_commands_may_open_a_query() {
    for (bare, piped) in [
        ("timechart span=1h count", "| timechart span=1h count"),
        ("top src_ip | head 10", "| top src_ip | head 10"),
        ("rare dest_port", "| rare dest_port"),
        ("chart count by user", "| chart count by user"),
        (
            "eventstats avg(bytes_out) by src_ip",
            "| eventstats avg(bytes_out) by src_ip",
        ),
    ] {
        assert_eq!(
            parse_query(bare).unwrap(),
            parse_query(piped).unwrap(),
            "leading command `{bare}` should parse like `{piped}`"
        );
    }
}

// === Non-regression: keyword searches that collide with command names ===

#[test]
fn test_bare_command_word_stays_a_keyword_search() {
    // A lone command name takes no arguments, so it is always a search term.
    // `reverse` is the one that bites: hunting for reverse shells by keyword
    // must not parse as the zero-arg `reverse` command, which would drop the
    // filter and return every event in the time range.
    let query = parse_query("reverse").unwrap();
    assert!(
        matches!(query, Query::Search(_)),
        "bare `reverse` must be a keyword search, got {query:?}"
    );
    assert!(commands_of(&query).is_empty());

    for word in ["stats", "table", "top", "head", "sort"] {
        let query = parse_query(word).unwrap();
        assert!(
            matches!(query, Query::Search(_)),
            "bare `{word}` must be a keyword search, got {query:?}"
        );
    }

    // The command form is still one pipe away.
    assert!(matches!(
        commands_of(&parse_query("| reverse").unwrap())[..],
        [Command::Reverse]
    ));
}

#[test]
fn test_trailing_words_keep_it_a_keyword_search() {
    // `head 10` parses, but the dangling `records` proves these were search
    // terms all along — a command owns the whole segment or none of it.
    let query = parse_query("head 10 records").unwrap();
    assert!(
        matches!(query, Query::Search(_)),
        "expected keyword search, got {query:?}"
    );
}

#[test]
fn test_post_processing_commands_do_not_open_a_query() {
    // The dangerous class, and the reason bare-command recognition is limited to
    // aggregating/generating commands. These are all plausible keyword searches
    // whose first word is a command name and whose arguments are REAL fields, so
    // they parse cleanly as commands AND pass field validation. If they were
    // allowed to open a query they would silently return the wrong rows — a
    // keyword hunt turned into "sort every event in the time range."
    //
    // They stay keyword searches. The command form is one pipe away.
    for query in [
        "sort timestamp",
        "table message",
        "head 10",
        "fields user",
        "dedup src_ip",
        "where is my log file",
    ] {
        let parsed = parse_query(query).unwrap();
        assert!(
            matches!(parsed, Query::Search(_)),
            "`{query}` must stay a keyword search — a post-processing command \
             must not open a query. Got {parsed:?}"
        );
    }

    // ...and they still work with an explicit pipe.
    assert!(matches!(
        commands_of(&parse_query("| sort timestamp").unwrap())[..],
        [Command::Sort { .. }]
    ));
}

#[test]
fn test_explicit_search_keyword_suppresses_command_recognition() {
    // `search` is the user saying "these are keywords." It must win, even over
    // an allowlisted command name that would otherwise open a query.
    for query in ["search top user", "search stats count by src_ip"] {
        let parsed = parse_query(query).unwrap();
        assert!(
            matches!(parsed, Query::Search(_)),
            "`{query}` explicitly asked for a keyword search, got {parsed:?}"
        );
    }
}

#[test]
fn test_allowlisted_collision_resolves_to_the_command() {
    // The residual ambiguity, stated as a contract: an aggregating command whose
    // arguments are real fields resolves to the command. `top user` is both a
    // reasonable aggregation and a conceivable keyword hunt; in a query bar the
    // aggregation is overwhelmingly the intent, and its output is unmistakably
    // not a list of events. Both escapes above force the search reading.
    let query = parse_query("top user").unwrap();
    assert!(matches!(commands_of(&query)[..], [Command::Top { .. }]));

    // `top` takes a space-separated field list, so this fits the command shape
    // exactly and resolves to the command too. Its arguments are not real fields,
    // so it comes back as a single bucket with an empty key — visibly an
    // aggregation over nothing, not a list of matching events. (It used to come
    // back as a bare `{"count": N}` that read as a grand total; that was its own
    // bug, NAN-1848, and is fixed separately.)
    assert!(matches!(
        commands_of(&parse_query("top secret documents").unwrap())[..],
        [Command::Top { .. }]
    ));

    // But a dangling fragment still proves it was a search all along (guard 3),
    // and falling back keeps that search working rather than failing the parse.
    assert!(matches!(
        parse_query("top secret (classified)").unwrap(),
        Query::Search(_)
    ));
}

#[test]
fn test_fixed_query_passes_field_validation() {
    // The bug report's query. `count` used to be read as a *field* — there is no
    // such column, hence `Unknown field 'count'` / ClickHouse Code 47. Parsed as
    // a real pipeline, `count` is the aggregation's output alias and validates.
    let query = parse_query("stats count by source_type | sort -count | head 25").unwrap();
    let errors = validate_query_fields(&query);
    assert!(
        errors.is_empty(),
        "the reported query must validate cleanly, got {errors:?}"
    );
}

#[test]
fn test_quoting_forces_a_keyword_search() {
    // Escape hatch for terms that fully collide with a command's argument shape.
    for query in [r#""top secret""#, r#""top secret documents""#] {
        let parsed = parse_query(query).unwrap();
        assert!(
            matches!(parsed, Query::Search(_)),
            "quoted phrase `{query}` must be a keyword search, got {parsed:?}"
        );
    }
}

#[test]
fn test_ordinary_searches_are_untouched() {
    for query in [
        "error",
        "status=500",
        r#"src_ip="192.168.1.1" | stats count by user"#,
        "failed login | head 10",
    ] {
        let parsed = parse_query(query).unwrap();
        assert!(
            !matches!(source_of(&parsed), SearchExpr::Keyword(k) if k == "*"),
            "`{query}` must keep its own search term, got {parsed:?}"
        );
    }
}

#[test]
fn test_leading_search_keyword_still_strips() {
    // PPL compatibility: `search status=500` == `status=500`.
    assert_eq!(
        parse_query("search status=500").unwrap(),
        parse_query("status=500").unwrap()
    );
}
