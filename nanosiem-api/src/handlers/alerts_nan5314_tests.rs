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
