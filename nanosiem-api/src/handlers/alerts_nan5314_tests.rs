// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5314: `assigned_to` holds a user typeid. `assigned_user_id` is the
//! single gate both the assignee-name resolution and the assignment
//! notification use; only `user_…` typeids and bare UUIDs name a user.

use super::assigned_user_id;
use uuid::Uuid;

#[test]
fn user_typeid_resolves_to_user_id() {
    let id = Uuid::now_v7();
    let tid = nanosiem_core::typeid::encode(nanosiem_core::typeid::user::PREFIX, &id);
    assert_eq!(assigned_user_id(&tid), Some(id));
}

#[test]
fn bare_uuid_resolves_to_user_id() {
    let id = Uuid::now_v7();
    assert_eq!(assigned_user_id(&id.to_string()), Some(id));
}

#[test]
fn non_user_prefix_and_free_text_do_not_resolve() {
    let id = Uuid::now_v7();
    let case_tid = nanosiem_core::typeid::encode(nanosiem_core::typeid::case::PREFIX, &id);
    assert_eq!(assigned_user_id(&case_tid), None);
    assert_eq!(assigned_user_id("bob"), None);
    assert_eq!(assigned_user_id(""), None);
}

// NAN-5774: an alert assigned to a deleted user reads "deleted user", the
// notebook / case wording (NAN-5721), never the raw `user_…` id.
#[test]
fn a_deleted_assignee_reads_deleted_user() {
    use super::{assignee_label, DELETED_USER_LABEL};
    use nanosiem_core::auth::UserRepositoryError;
    let label = assignee_label(Err(UserRepositoryError::NotFound(Uuid::now_v7())));
    assert_eq!(label.as_deref(), Some(DELETED_USER_LABEL));
    assert_eq!(DELETED_USER_LABEL, "deleted user");
}

#[test]
fn a_failed_lookup_is_not_reported_as_deleted() {
    use super::assignee_label;
    use nanosiem_core::auth::UserRepositoryError;
    let label = assignee_label(Err(UserRepositoryError::DatabaseError(sqlx::Error::PoolTimedOut)));
    assert_eq!(label, None);
}
