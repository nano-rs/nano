// SPDX-License-Identifier: AGPL-3.0-or-later
//! `| lookup` as a Nano-side execution boundary (NAN-4933, codex P1).
//!
//! Lookup enrichment runs in Rust after the ClickHouse query returns, but the
//! lookup itself compiled to a pass-through stage, so every command AFTER it
//! ran in ClickHouse BEFORE the enrichment existed: `| lookup assets src_ip AS
//! ip OUTPUT owner | where owner="bob"` filtered on a column the lookup had not
//! written yet (an unknown-column error, or a plausible wrong answer when an
//! event column of that name existed). The query is now cut at the first
//! `lookup` (like `inputlookup`): ClickHouse runs the prefix, the lookups
//! enrich the rows, and the suffix is replayed by the Nano-side evaluator.
//!
//! Shapes that cannot be ordered correctly are refused, never run wrong.

use crate::query::{Command, Query};

fn commands_in_order(query: &Query) -> Vec<&Command> {
    let mut out = Vec::new();
    let mut node = query;
    while let Query::Piped { source, command } = node {
        out.push(command);
        node = source;
    }
    out.reverse();
    out
}

fn is_enrichment(command: &Command) -> bool {
    matches!(command, Command::Lookup { .. } | Command::InputLookup { .. })
}

fn is_other_boundary(command: &Command) -> bool {
    matches!(
        command,
        Command::Prevalence { .. } | Command::Lateral { .. } | Command::Ai { .. }
    )
}

/// Whether the query is cut at its first `lookup` (`Ok(true)`), runs with the
/// lookups inside another Nano-side stage's suffix (`Ok(false)`: no lookup,
/// or the lookups follow a prevalence/lateral/ai stage, whose suffix already
/// replays Nano-side after enrichment), or cannot be ordered (`Err`).
pub fn lookup_boundary_plan(query: &Query) -> Result<bool, String> {
    let commands = commands_in_order(query);
    let Some(first_lookup) = commands.iter().position(|c| matches!(c, Command::Lookup { .. })) else {
        return Ok(false);
    };
    if let Some(other) = commands.iter().position(|c| is_other_boundary(c)) {
        if other < first_lookup {
            return Ok(false);
        }
        // Lookup before prevalence/lateral/ai: only further enrichment may
        // sit between them; anything else would run in SQL before the lookup.
        if commands[first_lookup..other].iter().all(|c| is_enrichment(c)) {
            return Ok(false);
        }
        return Err(
            "`lookup` followed by other commands before a prevalence, lateral or ai stage \
             cannot be ordered: move the lookup after that stage, or the commands after it."
                .into(),
        );
    }
    // Lookups are applied together before the suffix replays: a lookup after
    // a non-enrichment suffix command would run out of order.
    let mut seen_other = false;
    for command in &commands[first_lookup..] {
        if is_enrichment(command) {
            if seen_other && matches!(command, Command::Lookup { .. }) {
                return Err(
                    "a `lookup` after other commands that follow an earlier lookup is not \
                     supported: put the lookups next to each other."
                        .into(),
                );
            }
        } else {
            seen_other = true;
        }
    }
    Ok(true)
}

/// The commands after the first `lookup` / `inputlookup`, minus the enrichment
/// commands themselves (applied by the caller), in pipeline order.
pub fn extract_post_enrichment_commands(query: &Query) -> Vec<Command> {
    let commands = commands_in_order(query);
    let Some(first) = commands.iter().position(|c| is_enrichment(c)) else {
        return Vec::new();
    };
    commands[first..]
        .iter()
        .filter(|c| !is_enrichment(c))
        .map(|c| (*c).clone())
        .collect()
}

/// The query up to (excluding) its first `lookup` / `inputlookup`.
pub fn strip_enrichment_and_after(query: &Query) -> Query {
    match query {
        Query::Search(_) => query.clone(),
        Query::Piped { source, command } => {
            let stripped_source = strip_enrichment_and_after(source);
            if commands_in_order(source).iter().any(|c| is_enrichment(c)) || is_enrichment(command) {
                stripped_source
            } else {
                Query::Piped { source: Box::new(stripped_source), command: command.clone() }
            }
        }
    }
}

#[cfg(test)]
#[path = "lookup_boundary_tests.rs"]
mod tests;
