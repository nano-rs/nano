// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which lookup tables does an nPL query depend on?
//!
//! The lookup delete guard used to scan rule text for one spelling, `@<name>`,
//! so a rule using the normal syntax (`| lookup asset_inventory src_ip`,
//! `| inputlookup asset_inventory`, `ioc in lookup("asset_inventory")`) did
//! not count as a reference: the table could be deleted out from under an
//! active detection, which then failed lookup validation on every run.
//!
//! References are now read off the parsed query with the real nPL parser,
//! walking every stage and every subsearch. Rule text that does not parse is
//! treated conservatively: a word-bounded mention of the name counts, so an
//! unparseable rule can block a delete but never lets one through.

use std::collections::BTreeSet;

use crate::query::{parse_query, Command, Query, SearchExpr};

/// `inputlookup <name>` is parsed into this internal URL scheme.
const LOOKUP_SCHEME: &str = "lookup://";

/// Every lookup table `query` reads, lowercased.
pub fn referenced_lookup_tables(query: &Query) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    walk_query(query, &mut out);
    out
}

/// Does the nPL text `query_text` depend on lookup table `table`?
///
/// Parsed queries are judged by their AST (plus the legacy `@<name>` token,
/// which some saved rules still carry). Unparseable text falls back to a
/// word-bounded, case-insensitive mention of the name.
pub fn query_text_references_lookup(query_text: &str, table: &str) -> bool {
    let table_lc = table.to_lowercase();
    if table_lc.is_empty() {
        return false;
    }
    if has_word_bounded(query_text, &format!("@{table_lc}")) {
        return true;
    }
    match parse_query(strip_search_prefix(query_text)) {
        Ok(query) => referenced_lookup_tables(&query).contains(&table_lc),
        Err(_) => has_word_bounded(query_text, &table_lc),
    }
}

/// Saved rules sometimes keep a leading `search ` keyword.
fn strip_search_prefix(text: &str) -> &str {
    let trimmed = text.trim_start();
    match trimmed.get(..7) {
        Some(head) if head.eq_ignore_ascii_case("search ") => &trimmed[7..],
        _ => trimmed,
    }
}

fn walk_query(query: &Query, out: &mut BTreeSet<String>) {
    match query {
        Query::Search(expr) => walk_expr(expr, out),
        Query::Piped { source, command } => {
            walk_query(source, out);
            walk_command(command, out);
        }
    }
}

fn walk_command(command: &Command, out: &mut BTreeSet<String>) {
    match command {
        Command::Lookup { table_name, .. } => {
            out.insert(table_name.to_lowercase());
        }
        Command::InputLookup { url, .. } => {
            if let Some(name) = url.template.strip_prefix(LOOKUP_SCHEME) {
                out.insert(name.trim().to_lowercase());
            }
        }
        Command::Append { subsearch, .. } | Command::Join { subsearch, .. } => {
            walk_query(subsearch, out)
        }
        Command::Where { condition } => walk_expr(condition, out),
        Command::Transaction {
            startswith,
            endswith,
            ..
        } => {
            for expr in startswith.iter().chain(endswith.iter()) {
                walk_expr(expr, out);
            }
        }
        Command::Sequence { conditions, .. } => {
            for expr in conditions {
                walk_expr(expr, out);
            }
        }
        Command::Funnel { steps, .. } => {
            for (_, expr) in steps {
                walk_expr(expr, out);
            }
        }
        _ => {}
    }
}

fn walk_expr(expr: &SearchExpr, out: &mut BTreeSet<String>) {
    match expr {
        SearchExpr::IocMatch {
            lookup: Some(lookup),
            ..
        } => {
            out.insert(lookup.table.to_lowercase());
        }
        SearchExpr::And(l, r) | SearchExpr::Or(l, r) => {
            walk_expr(l, out);
            walk_expr(r, out);
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => walk_expr(inner, out),
        SearchExpr::InSubsearch { subsearch, .. } => walk_query(subsearch, out),
        _ => {}
    }
}

/// Case-insensitive `token` occurrence that is not followed by an identifier
/// character and not preceded by one (when the token itself starts with one).
fn has_word_bounded(haystack: &str, token_lc: &str) -> bool {
    let hay = haystack.to_lowercase();
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let leading_ident = token_lc.chars().next().is_some_and(is_ident);
    let mut start = 0;
    while let Some(idx) = hay[start..].find(token_lc) {
        let pos = start + idx;
        let end = pos + token_lc.len();
        let before_ok = !leading_ident || !hay[..pos].chars().next_back().is_some_and(is_ident);
        let after_ok = !hay[end..].chars().next().is_some_and(is_ident);
        if before_ok && after_ok {
            return true;
        }
        start = end;
    }
    false
}

#[cfg(test)]
#[path = "references_tests.rs"]
mod references_tests;
