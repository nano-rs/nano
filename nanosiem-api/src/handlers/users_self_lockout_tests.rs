// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5707: nobody disables or deletes the account their request acts as.
//! The guard runs in `disable_user`, `delete_user` and `update_user`
//! (`status: "disabled"`) before any authority lookup or write.

use super::{refuse_self_lockout, SelfLockoutAction};
use axum::http::StatusCode;
use uuid::Uuid;

#[test]
fn disabling_yourself_is_refused_with_a_clean_403() {
    let me = Uuid::new_v4();
    let (status, body) = refuse_self_lockout(me, me, SelfLockoutAction::Disable).unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body.error, "cannot_modify_self");
    assert!(body.message.contains("disable your own account"), "{}", body.message);
}

#[test]
fn deleting_yourself_is_refused_with_a_clean_403() {
    let me = Uuid::new_v4();
    let (status, body) = refuse_self_lockout(me, me, SelfLockoutAction::Delete).unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body.error, "cannot_modify_self");
    assert!(body.message.contains("delete your own account"), "{}", body.message);
}

#[test]
fn acting_on_another_user_is_not_this_guards_business() {
    let me = Uuid::new_v4();
    let other = Uuid::new_v4();
    assert!(refuse_self_lockout(me, other, SelfLockoutAction::Disable).is_ok());
    assert!(refuse_self_lockout(me, other, SelfLockoutAction::Delete).is_ok());
}

/// The guard must be wired into every handler that can disable or delete a
/// user, ahead of the write. Source-level so a refactor that drops a call
/// fails here rather than in an e2e run.
#[test]
fn every_disable_and_delete_path_calls_the_guard() {
    let src = include_str!("users.rs");
    let body_of = |name: &str| -> &str {
        let start = src
            .find(&format!("pub async fn {name}("))
            .unwrap_or_else(|| panic!("handler {name} not found"));
        let rest = &src[start..];
        let end = rest[1..].find("\npub async fn ").map(|i| i + 1).unwrap_or(rest.len());
        &rest[..end]
    };

    let delete = body_of("delete_user");
    let guard = delete
        .find("refuse_self_lockout(auth.user_id(), *id, SelfLockoutAction::Delete)")
        .expect("delete_user must refuse self-delete");
    let write = delete
        .find("PrincipalAction::Delete")
        .expect("delete_user writes PrincipalAction::Delete");
    assert!(guard < write, "delete_user must refuse self-delete before the write");

    let disable = body_of("disable_user");
    let guard = disable
        .find("refuse_self_lockout(auth.user_id(), *id, SelfLockoutAction::Disable)")
        .expect("disable_user must refuse self-disable");
    let write = disable
        .find("PrincipalAction::Disable")
        .expect("disable_user writes PrincipalAction::Disable");
    assert!(guard < write, "disable_user must refuse self-disable before the write");

    let update = body_of("update_user");
    assert!(
        update.contains("refuse_self_lockout(auth.user_id(), *id, SelfLockoutAction::Disable)"),
        "update_user must refuse status=disabled on yourself"
    );
}

/// NAN-5707 (review): removing your own Admin access, or leaving the tenant
/// with no active administrator, is refused by the repository inside the
/// write transaction; the API surfaces both as clean JSON errors.
#[test]
fn admin_retention_errors_map_to_clean_responses() {
    use nanosiem_core::auth::UserRepositoryError;
    let (status, body) = super::UserApiError::from_repo_error(&UserRepositoryError::CannotRemoveOwnAdmin);
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body.error, "cannot_modify_self");
    let (status, body) = super::UserApiError::from_repo_error(&UserRepositoryError::LastAdminRequired);
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body.error, "last_admin_required");
}

/// Both group-replacing handlers pass the caller to the repository, which is
/// what lets it tell "removing my own Admin" from "removing someone else's".
#[test]
fn group_writes_pass_the_actor_to_the_admin_guard() {
    let src = include_str!("users.rs");
    assert!(src.contains(".set_user_groups_authorized(*id, &request.group_ids, grant_stamp, auth.user_id())"));
    let update = &src[src.find(".update_user_with_groups_authorized(").expect("call")..];
    assert!(update[..200].contains("auth.user_id(),"), "{}", &update[..200]);
}

/// NAN-5721: a user delete blocked by a foreign key is a 409 with a stable
/// code, never the generic 500, and the constraint name stays server-side.
#[test]
fn still_referenced_delete_maps_to_conflict() {
    use nanosiem_core::auth::UserRepositoryError;
    let (status, body) = super::UserApiError::from_repo_error(&UserRepositoryError::StillReferenced {
        constraint: "siem_health_reports_triggered_by_fkey".to_string(),
    });
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body.error, "user_still_referenced");
    assert!(!body.message.contains("fkey"), "{}", body.message);
}

/// NAN-5742: a NOT NULL / CHECK broken by the delete's SET NULL cascade is a
/// schema bug. The client still gets the 409, and the admin sees which
/// constraint (or column) so it can be reported.
#[test]
fn broken_constraint_on_delete_maps_to_conflict_naming_it() {
    use nanosiem_core::auth::{DeleteIntegrityViolation, UserRepositoryError};
    let check = DeleteIntegrityViolation {
        sqlstate: "23514".to_string(),
        table: Some("case_handoffs".to_string()),
        column: None,
        constraint: Some("case_handoffs_target_present".to_string()),
    };
    let (status, body) =
        super::UserApiError::from_repo_error(&UserRepositoryError::DeleteBreaksConstraint(check));
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body.error, "user_still_referenced");
    assert!(body.message.contains("case_handoffs_target_present"), "{}", body.message);
    assert!(body.message.contains("23514"), "{}", body.message);

    let not_null = DeleteIntegrityViolation {
        sqlstate: "23502".to_string(),
        table: Some("widgets".to_string()),
        column: Some("owner_id".to_string()),
        constraint: None,
    };
    let (status, body) =
        super::UserApiError::from_repo_error(&UserRepositoryError::DeleteBreaksConstraint(not_null));
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.message.contains("widgets.owner_id"), "the column is kept: {}", body.message);
}
