// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5285 (v2.0.13 retest F9): say what `action` shows on OCSF.
//!
//! Under OCSF, `action` is the UDM alias of the `activity` caption ("Get",
//! "Logon"). Since NAN-5271 E (#9250) a FILTER on the block/allow vocabulary
//! (`action=blocked`, `action=allowed`, `action=denied`, …) is the disposition
//! concept instead (`disposition_id` / `action_id`), because no activity is
//! called "blocked". So `action=blocked | table action` lists the blocked
//! events with "Get" in the action column, which reads like a contradiction.
//!
//! Projecting the disposition under `action` would break every other filter
//! value (`action=Get` keeps the activity meaning) and saved content, so the
//! column keeps its meaning and the search says, once, what it is and where
//! the block/allow answer lives.

use crate::query::{Command, Query};
use crate::search::types::QueryWarningOutput;

pub const OCSF_ACTION_COLUMN_CODE: &str = "OCSF_ACTION_IS_ACTIVITY";

fn names_action(field: &str) -> bool {
    field.eq_ignore_ascii_case("action")
}

fn command_shows_action(command: &Command) -> bool {
    match command {
        Command::Table { fields } => fields.iter().any(|f| names_action(&f.name)),
        Command::Fields { fields, keep: true } => fields.iter().any(|f| names_action(f)),
        Command::Stats { group_by, .. } | Command::Chart { group_by, .. } => group_by
            .as_ref()
            .is_some_and(|by| by.iter().any(|f| names_action(f))),
        Command::Top { field, by_fields, .. } | Command::Rare { field, by_fields, .. } => {
            names_action(field) || by_fields.iter().any(|f| names_action(f))
        }
        _ => false,
    }
}

fn shows_action(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => command_shows_action(command) || shows_action(source),
    }
}

/// The info note for an OCSF search that displays `action`, else `None`.
pub fn ocsf_action_column_note(query: &Query, is_ocsf: bool) -> Option<QueryWarningOutput> {
    if !is_ocsf || !shows_action(query) {
        return None;
    }
    Some(QueryWarningOutput {
        severity: "info".to_string(),
        code: OCSF_ACTION_COLUMN_CODE.to_string(),
        message: "On OCSF data the action column is the event's activity (for example Get or \
                  Logon). A filter like action=blocked or action=allowed matches the \
                  disposition instead."
            .to_string(),
        suggestion: Some(
            "To show whether an event was blocked or allowed, add disposition (or \
             disposition_id) to the table or the stats by clause."
                .to_string(),
        ),
        impact: None,
    })
}

#[cfg(test)]
#[path = "ocsf_action_note_tests.rs"]
mod tests;
