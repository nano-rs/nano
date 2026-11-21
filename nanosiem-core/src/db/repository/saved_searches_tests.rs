// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5695 / NAN-5696: saved-search description normalization.

use super::*;

#[test]
fn absent_description_stays_absent() {
    assert_eq!(normalize_saved_search_description(None).unwrap(), None);
}

#[test]
fn blank_description_is_stored_as_null() {
    assert_eq!(normalize_saved_search_description(Some("")).unwrap(), None);
    assert_eq!(normalize_saved_search_description(Some("  \n\t ")).unwrap(), None);
}

#[test]
fn description_is_trimmed() {
    assert_eq!(
        normalize_saved_search_description(Some("  failed console logins by user \n")).unwrap(),
        Some("failed console logins by user".to_string())
    );
}

#[test]
fn description_at_the_limit_is_kept_and_over_it_is_rejected() {
    let at_limit = "é".repeat(SAVED_SEARCH_DESCRIPTION_MAX_CHARS);
    assert_eq!(
        normalize_saved_search_description(Some(&at_limit)).unwrap(),
        Some(at_limit.clone())
    );
    let over = format!("{at_limit}x");
    assert!(matches!(
        normalize_saved_search_description(Some(&over)),
        Err(SavedSearchRepositoryError::InvalidInput(_))
    ));
}

#[test]
fn non_owner_mutation_of_a_hidden_search_is_not_found() {
    let id = Uuid::new_v4();
    assert!(matches!(
        owned_mutation_denied_error(id, false),
        SavedSearchRepositoryError::NotFound(got) if got == id
    ));
}

#[test]
fn non_owner_mutation_of_a_visible_search_is_access_denied() {
    assert!(matches!(
        owned_mutation_denied_error(Uuid::new_v4(), true),
        SavedSearchRepositoryError::AccessDenied
    ));
}
