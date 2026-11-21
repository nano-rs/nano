// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5711: an owner-scoped dashboard delete that removes nothing reports a
//! missing or hidden dashboard as 404 and only a visible, foreign one as 403.

use super::*;

#[test]
fn missing_dashboard_is_not_found() {
    let id = Uuid::new_v4();
    assert!(matches!(
        owned_delete_miss_error(id, false, false),
        DashboardRepositoryError::NotFound(got) if got == id
    ));
}

#[test]
fn dashboard_hidden_from_the_caller_is_not_found_so_existence_does_not_leak() {
    let id = Uuid::new_v4();
    assert!(matches!(
        owned_delete_miss_error(id, true, false),
        DashboardRepositoryError::NotFound(got) if got == id
    ));
}

#[test]
fn visible_dashboard_owned_by_someone_else_is_access_denied() {
    let id = Uuid::new_v4();
    assert!(matches!(
        owned_delete_miss_error(id, true, true),
        DashboardRepositoryError::AccessDenied(got) if got == id
    ));
}
