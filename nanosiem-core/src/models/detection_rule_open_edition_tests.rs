// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5056: the open edition has no case groups, so a rule that asks for
//! group case visibility is refused with a validation error (HTTP 400) instead
//! of saving while silently dropping its `case_group_ids`.

use super::{FieldValidationError, UpdateDetectionRule};
use uuid::Uuid;

#[test]
fn group_case_visibility_is_refused_in_the_open_edition() {
    let update = UpdateDetectionRule {
        case_visibility: Some("group".to_string()),
        case_group_ids: Some(vec![Uuid::new_v4()]),
        ..Default::default()
    };
    assert_eq!(
        update.validate_fields(),
        Err(FieldValidationError::CaseGroupsRequireEnterprise)
    );
}

#[test]
fn case_group_ids_alone_are_refused_in_the_open_edition() {
    let update = UpdateDetectionRule {
        case_group_ids: Some(vec![Uuid::new_v4()]),
        ..Default::default()
    };
    assert_eq!(
        update.validate_fields(),
        Err(FieldValidationError::CaseGroupsRequireEnterprise)
    );
}

#[test]
fn public_visibility_and_empty_groups_still_validate() {
    let update = UpdateDetectionRule {
        case_visibility: Some("public".to_string()),
        case_group_ids: Some(Vec::new()),
        ..Default::default()
    };
    assert!(update.validate_fields().is_ok());
}
