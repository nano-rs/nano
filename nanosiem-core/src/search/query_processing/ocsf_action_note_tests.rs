// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::query::parse_query;

fn note(query: &str, ocsf: bool) -> Option<QueryWarningOutput> {
    ocsf_action_column_note(&parse_query(query).unwrap(), ocsf)
}

#[test]
fn ocsf_queries_that_display_action_get_the_note() {
    for q in [
        "action=blocked | table action, src_endpoint.ip",
        "class_uid=4002 | stats count by action",
        "* | top action",
        "* | rare limit=5 user by action",
        "action=allowed | fields action",
        "* | chart count by action",
    ] {
        let n = note(q, true).unwrap_or_else(|| panic!("{q}: expected the note"));
        assert_eq!(n.code, OCSF_ACTION_COLUMN_CODE);
        assert_eq!(n.severity, "info");
        assert!(n.suggestion.unwrap().contains("disposition"));
    }
}

#[test]
fn no_note_when_action_is_not_displayed_or_on_udm() {
    // Filtering alone: the result rows carry no action column to misread.
    assert!(note("action=blocked", true).is_none());
    assert!(note("action=blocked | table src_endpoint.ip", true).is_none());
    assert!(note("* | fields - action", true).is_none());
    // UDM: action is the event_type column; one meaning only.
    assert!(note("action=blocked | table action", false).is_none());
}
