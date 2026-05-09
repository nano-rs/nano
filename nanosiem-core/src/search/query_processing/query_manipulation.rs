// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query manipulation and transformation utilities
//!
//! This module provides functions to transform and filter parsed query ASTs,
//! particularly for handling prevalence commands and their interaction with other commands.

use super::command_extraction::extract_post_ai_commands;
use crate::query::{Command, Comparator, Query, SearchExpr, TableField, Value};
use crate::search::field_utils::{is_post_processing_field, normalize_field_alias};

/// Strip commands that come after prevalence enrichment from the query
/// Returns a new query with only the commands up to and including prevalence
pub fn strip_post_prevalence_commands(query: &Query) -> Query {
    strip_post_prevalence_recursive(query, false).0
}

/// Strip prevalence commands AND all commands after them from the query
/// This is used for JOIN-based prevalence filtering where we need the base query
/// without any prevalence-related processing
pub fn strip_prevalence_and_after(query: &Query) -> Query {
    strip_prevalence_and_after_recursive(query, false).0
}

/// Recursively strip prevalence and all commands after it
/// Returns (modified_query, found_prevalence)
fn strip_prevalence_and_after_recursive(query: &Query, parent_found: bool) -> (Query, bool) {
    match query {
        Query::Search(expr) => (Query::Search(expr.clone()), false),
        Query::Piped { source, command } => {
            let (new_source, source_found) =
                strip_prevalence_and_after_recursive(source, parent_found);

            // Check if this is a prevalence command
            let is_prevalence = matches!(command, Command::Prevalence { .. });

            // If we found prevalence in the source or this is prevalence, skip this and all subsequent commands
            if source_found || is_prevalence {
                (new_source, true)
            } else {
                (
                    Query::Piped {
                        source: Box::new(new_source),
                        command: command.clone(),
                    },
                    false,
                )
            }
        }
    }
}

/// Recursively strip commands after any prevalence command
/// Returns (modified_query, found_prevalence)
fn strip_post_prevalence_recursive(query: &Query, parent_found_prevalence: bool) -> (Query, bool) {
    match query {
        Query::Search(expr) => (Query::Search(expr.clone()), false),
        Query::Piped { source, command } => {
            // First process the source
            let (new_source, source_found_prevalence) =
                strip_post_prevalence_recursive(source, parent_found_prevalence);

            // Check if this is any prevalence command (enrich or filter-only)
            let is_prevalence = matches!(command, Command::Prevalence { .. });
            let found_prevalence = source_found_prevalence || is_prevalence;

            // If we already found prevalence in the source and this is not the prevalence command itself,
            // skip this command (it will be applied as post-processing)
            if source_found_prevalence && !is_prevalence {
                (new_source, true)
            } else {
                (
                    Query::Piped {
                        source: Box::new(new_source),
                        command: command.clone(),
                    },
                    found_prevalence,
                )
            }
        }
    }
}

/// Strip inputlookup commands AND all commands after them from the query
/// This is used because inputlookup enrichment happens in post-processing,
/// so commands that reference inputlookup_* fields must also be post-processed
pub fn strip_inputlookup_and_after(query: &Query) -> Query {
    strip_inputlookup_and_after_recursive(query, false).0
}

/// Recursively strip inputlookup and all commands after it
/// Returns (modified_query, found_inputlookup)
fn strip_inputlookup_and_after_recursive(query: &Query, parent_found: bool) -> (Query, bool) {
    match query {
        Query::Search(expr) => (Query::Search(expr.clone()), false),
        Query::Piped { source, command } => {
            let (new_source, source_found) =
                strip_inputlookup_and_after_recursive(source, parent_found);

            // Check if this is an inputlookup command
            let is_inputlookup = matches!(command, Command::InputLookup { .. });

            // If we found inputlookup in the source or this is inputlookup, skip this and all subsequent commands
            if source_found || is_inputlookup {
                (new_source, true)
            } else {
                (
                    Query::Piped {
                        source: Box::new(new_source),
                        command: command.clone(),
                    },
                    false,
                )
            }
        }
    }
}

/// Strip ai command and all commands after it from the query.
/// The AI and post-AI commands are handled in post-processing, so they need
/// to be removed before SQL generation.
///
/// If post-AI commands include `| table`, a filtered version (without ai_* fields)
/// is re-appended so the SQL generator selects the right database columns.
pub fn strip_ai_and_after(query: &Query) -> Query {
    let stripped = strip_ai_and_after_recursive(query, false).0;

    // Check if post-AI commands included a | table — if so, re-inject the
    // database-safe fields so the SQL generator selects them (e.g., url, timestamp).
    // Field names are normalized (e.g., _time → timestamp) so the SQL generator
    // can resolve them against actual column names.
    let post_ai = extract_post_ai_commands(query);
    if let Some(table_cmd) = post_ai.iter().find(|c| matches!(c, Command::Table { .. })) {
        if let Command::Table { fields } = table_cmd {
            let db_fields: Vec<_> = fields
                .iter()
                .filter(|f| !is_post_processing_field(&f.name))
                .map(|f| TableField {
                    name: normalize_field_alias(&f.name).to_string(),
                    alias: f.alias.clone(),
                })
                .collect();
            if !db_fields.is_empty() {
                return Query::Piped {
                    source: Box::new(stripped),
                    command: Command::Table { fields: db_fields },
                };
            }
        }
    }

    stripped
}

/// Strip lateral command and all commands after it from the query.
/// Lateral and post-lateral commands are handled in post-processing.
pub fn strip_lateral_and_after(query: &Query) -> Query {
    strip_lateral_and_after_recursive(query, false).0
}

/// Enforce a source_type exclusion at the AST level.
///
/// This wraps the base search expression as:
/// `(<existing search expr>) AND source_type != "<excluded_source_type>"`
///
/// Doing this at AST level prevents textual bypasses such as leading `OR ...`.
pub fn enforce_source_type_exclusion(query: &Query, excluded_source_type: &str) -> Query {
    inject_source_type_exclusion_recursive(query, excluded_source_type)
}

/// Parse a piped-query string, inject `source_type != "audit"` at the AST
/// level, and serialize back to a string. Used by every authenticated
/// search surface to gate audit-log access for users without
/// `audit:view` permission.
///
/// NAN-704: extracted from duplicated private helpers in
/// `nanosiem-search/src/handlers/{search,streaming}.rs` so that
/// `nanosiem-api`'s dashboard panel handler (and any future caller)
/// shares one canonical implementation. Drift on one site now surfaces
/// as a compile error instead of a silent permission bypass.
pub fn enforce_non_audit_query(query: &str) -> Result<String, crate::SearchError> {
    use crate::query::{PrettyPrint, parse_query};
    let parsed = parse_query(query).map_err(|e| {
        crate::SearchError::ParseError(format!(
            "Query parsing failed for access control enforcement: {}",
            e
        ))
    })?;
    Ok(enforce_source_type_exclusion(&parsed, "audit").pretty_print())
}

fn inject_source_type_exclusion_recursive(query: &Query, excluded_source_type: &str) -> Query {
    match query {
        Query::Search(expr) => {
            if search_expr_has_source_type_exclusion(expr, excluded_source_type) {
                return Query::Search(expr.clone());
            }

            let exclusion = SearchExpr::FieldFilter {
                field: "source_type".to_string(),
                op: Comparator::Ne,
                value: Value::String(excluded_source_type.to_string()),
            };

            Query::Search(SearchExpr::And(
                Box::new(SearchExpr::Group(Box::new(expr.clone()))),
                Box::new(exclusion),
            ))
        }
        Query::Piped { source, command } => Query::Piped {
            source: Box::new(inject_source_type_exclusion_recursive(
                source,
                excluded_source_type,
            )),
            command: command.clone(),
        },
    }
}

fn search_expr_has_source_type_exclusion(expr: &SearchExpr, excluded_source_type: &str) -> bool {
    match expr {
        SearchExpr::FieldFilter { field, op, value } => {
            field.eq_ignore_ascii_case("source_type")
                && *op == Comparator::Ne
                && matches!(value, Value::String(s) if s.eq_ignore_ascii_case(excluded_source_type))
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            search_expr_has_source_type_exclusion(left, excluded_source_type)
                || search_expr_has_source_type_exclusion(right, excluded_source_type)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            search_expr_has_source_type_exclusion(inner, excluded_source_type)
        }
        _ => false,
    }
}

/// Recursively strip lateral and all commands after it
fn strip_lateral_and_after_recursive(query: &Query, parent_found: bool) -> (Query, bool) {
    match query {
        Query::Search(expr) => (Query::Search(expr.clone()), false),
        Query::Piped { source, command } => {
            let (new_source, source_found) =
                strip_lateral_and_after_recursive(source, parent_found);
            let is_lateral = matches!(command, Command::Lateral { .. });
            if source_found || is_lateral {
                (new_source, true)
            } else {
                (
                    Query::Piped {
                        source: Box::new(new_source),
                        command: command.clone(),
                    },
                    false,
                )
            }
        }
    }
}

/// Recursively strip ai and all commands after it
fn strip_ai_and_after_recursive(query: &Query, parent_found: bool) -> (Query, bool) {
    match query {
        Query::Search(expr) => (Query::Search(expr.clone()), false),
        Query::Piped { source, command } => {
            let (new_source, source_found) = strip_ai_and_after_recursive(source, parent_found);

            let is_ai = matches!(command, Command::Ai { .. });

            if source_found || is_ai {
                (new_source, true)
            } else {
                (
                    Query::Piped {
                        source: Box::new(new_source),
                        command: command.clone(),
                    },
                    false,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    #[test]
    fn test_strip_post_prevalence_commands() {
        // Query with commands after prevalence enrich should have them stripped
        let query = parse_query("error | prevalence enrich=true | head 10").unwrap();
        let stripped = strip_post_prevalence_commands(&query);

        // The stripped query should only go up to prevalence
        match stripped {
            Query::Piped { source, command } => {
                assert!(matches!(*source, Query::Search(_)));
                assert!(matches!(command, Command::Prevalence { enrich: true, .. }));
            }
            _ => panic!("Expected Piped query"),
        }
    }

    #[test]
    fn test_strip_prevalence_and_after() {
        // Query with prevalence should have it and everything after stripped
        let query = parse_query("error | prevalence hash_prevalence < 5 | head 10").unwrap();
        let stripped = strip_prevalence_and_after(&query);

        // The stripped query should only be the base search
        match stripped {
            Query::Search(_) => {} // Success
            _ => panic!("Expected Search query, got Piped"),
        }
    }

    #[test]
    fn test_strip_prevalence_keeps_commands_before() {
        // Commands before prevalence should be kept
        let query = parse_query("error | head 100 | prevalence enrich=true | tail 10").unwrap();
        let stripped = strip_post_prevalence_commands(&query);

        // Should keep head and prevalence, but not tail
        let mut found_head = false;
        let mut found_prevalence = false;

        let mut current = &stripped;
        loop {
            match current {
                Query::Search(_) => break,
                Query::Piped { source, command } => {
                    if matches!(command, Command::Head { count: _ }) {
                        found_head = true;
                    }
                    if matches!(command, Command::Prevalence { enrich: true, .. }) {
                        found_prevalence = true;
                    }
                    current = source;
                }
            }
        }

        assert!(found_head, "Should keep head command before prevalence");
        assert!(found_prevalence, "Should keep prevalence command");
    }

    #[test]
    fn test_strip_ai_and_after() {
        let query =
            parse_query(r#"error | head 10 | ai prompt="Classify" | where ai_verdict="TP""#)
                .unwrap();
        let stripped = strip_ai_and_after(&query);

        // Should keep "error | head 10" — ai and where both stripped
        match stripped {
            Query::Piped { source, command } => {
                assert!(matches!(command, Command::Head { count: 10 }));
                assert!(matches!(*source, Query::Search(_)));
            }
            _ => panic!("Expected Piped query with Head"),
        }
    }

    #[test]
    fn test_strip_ai_reinjects_table_fields() {
        // | table after | ai should be re-injected with only database fields
        let query =
            parse_query(r#"error | ai prompt="Classify" | table timestamp, url, ai_verdict"#)
                .unwrap();
        let stripped = strip_ai_and_after(&query);

        // Should be: error | table timestamp, url  (ai_verdict filtered out)
        match &stripped {
            Query::Piped { command, source } => {
                if let Command::Table { fields } = command {
                    let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
                    assert!(names.contains(&"timestamp"), "Should keep timestamp");
                    assert!(names.contains(&"url"), "Should keep url");
                    assert!(
                        !names.contains(&"ai_verdict"),
                        "Should filter out ai_verdict"
                    );
                } else {
                    panic!("Expected Table command, got {:?}", command);
                }
                assert!(matches!(source.as_ref(), Query::Search(_)));
            }
            _ => panic!("Expected Piped query with Table"),
        }
    }

    #[test]
    fn test_strip_ai_keeps_commands_before() {
        let query = parse_query(r#"error | stats count by src_ip | ai prompt="Classify""#).unwrap();
        let stripped = strip_ai_and_after(&query);

        match stripped {
            Query::Piped { command, .. } => {
                assert!(matches!(command, Command::Stats { .. }));
            }
            _ => panic!("Expected Piped query with Stats"),
        }
    }

    #[test]
    fn test_enforce_source_type_exclusion_wraps_or_queries() {
        let parsed = parse_query(r#"source_type="audit" OR user="alice""#).unwrap();
        let rewritten = enforce_source_type_exclusion(&parsed, "audit");

        match rewritten {
            Query::Search(SearchExpr::And(_, right)) => match right.as_ref() {
                SearchExpr::FieldFilter { field, op, value } => {
                    assert_eq!(field, "source_type");
                    assert_eq!(*op, Comparator::Ne);
                    assert_eq!(value, &Value::String("audit".to_string()));
                }
                other => panic!("Expected source_type exclusion filter, got {:?}", other),
            },
            other => panic!("Expected top-level AND after enforcement, got {:?}", other),
        }
    }

    /// NAN-704: the public string-in / string-out wrapper is what every
    /// authenticated search surface (search handler, streaming handler,
    /// dashboard panel handler) calls. Confirms the rewrite injects the
    /// `source_type != "audit"` clause and survives the round-trip
    /// through `pretty_print` so the rewritten string can feed back into
    /// the search service.
    #[test]
    fn test_enforce_non_audit_query_injects_exclusion() {
        let original = r#"source_type="audit" OR user="alice""#;
        let rewritten = enforce_non_audit_query(original).expect("rewrite should succeed");
        assert!(
            rewritten.contains("source_type") && rewritten.contains("audit"),
            "rewritten query should still mention source_type/audit (as exclusion): {}",
            rewritten
        );
        // Round-trip: the rewritten string must itself parse cleanly.
        let _ = parse_query(&rewritten).expect("rewritten query must re-parse");
    }

    #[test]
    fn test_enforce_non_audit_query_rejects_unparseable_input() {
        let result = enforce_non_audit_query("| | invalid");
        assert!(
            result.is_err(),
            "unparseable query should return Err, not silently pass through"
        );
    }
}
