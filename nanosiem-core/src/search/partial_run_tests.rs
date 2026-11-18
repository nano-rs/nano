// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

#[tokio::test]
async fn notes_inside_a_scope_are_collected_once_each() {
    let ((), notes) = collect(async {
        note("rescue dropped 3");
        note("rescue dropped 3");
        note("other");
    })
    .await;
    assert_eq!(notes, vec!["rescue dropped 3".to_string(), "other".to_string()]);
    assert_eq!(
        partial_run_message(&notes).as_deref(),
        Some("[partial] rescue dropped 3; other")
    );
}

#[tokio::test]
async fn a_note_outside_any_scope_is_a_no_op() {
    note("nobody listens");
    let ((), notes) = collect(async {}).await;
    assert!(notes.is_empty());
    assert_eq!(partial_run_message(&notes), None);
}

#[tokio::test]
async fn spawned_search_work_inherits_the_scope() {
    let ((), notes) = collect(async {
        tokio::spawn(crate::search::request_actor::inherit(async {
            note("from a spawned task");
        }))
        .await
        .unwrap();
    })
    .await;
    assert_eq!(notes, vec!["from a spawned task".to_string()]);
}
