// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3620 scope contract: creating new stored cloud credentials is retired
//! on hosted SHARED tenants only (rotate/rollback of existing rows stay). Open core and dedicated deployments keep the full
//! create / rotate / rollback surface, served by `handlers::credentials` on
//! every non-shared product, with no retirement refusal in that handler.

const ROUTES: &str = include_str!("../src/routes.rs");
const DEDICATED: &str = include_str!("../src/handlers/credentials.rs");
#[cfg(feature = "enterprise")]
const SHARED: &str =
    include_str!("../../nanosiem-enterprise/src/handlers/enterprise_shared_sources_credentials.rs");

/// The `.route_if(...)` call that mounts `handler`, whitespace-collapsed.
fn mount_of(handler: &str) -> String {
    let at = ROUTES
        .find(handler)
        .unwrap_or_else(|| panic!("{handler} is not mounted"));
    let start = ROUTES[..at]
        .rfind(".route_if(")
        .unwrap_or_else(|| panic!("{handler} is not mounted via route_if"));
    ROUTES[start..at + handler.len()]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn open_core_and_dedicated_still_mount_credential_writes() {
    for (path, handler) in [
        ("\"/api/credentials\",", "post(handlers::credentials::create_credential)"),
        ("\"/api/credentials/{id}/rotate\",", "post(handlers::credentials::rotate_credential)"),
        ("\"/api/credentials/{id}/rollback\",", "post(handlers::credentials::rollback_credential)"),
    ] {
        let mount = mount_of(handler);
        assert!(mount.starts_with(".route_if(!shared_product,"), "{handler}: {mount}");
        assert!(mount.contains(path), "{handler}: {mount}");
    }
}

#[test]
fn dedicated_create_still_writes_and_never_refuses_as_retired() {
    assert!(!DEDICATED.contains("credentials_retired_on_shared"));
    assert!(!DEDICATED.contains("ApiError::Retired"));
    assert!(!DEDICATED.contains("StatusCode::GONE"));
    // The dedicated create still answers 201 with the stored credential.
    let create = &DEDICATED[DEDICATED.find("pub async fn create_credential(").unwrap()..];
    let create = &create[..create.find("\n}\n").unwrap()];
    assert!(create.contains("StatusCode::CREATED"));
    assert!(create.contains("check_permission(&auth, \"credentials:create\")"));
}

#[cfg(feature = "enterprise")]
#[test]
fn shared_refusal_lives_only_in_the_shared_adapter() {
    assert!(SHARED.contains("pub async fn create_credential() -> ApiError"));
    // Existing rows stay fully manageable on shared, rotate and rollback
    // included (an enrichment-linked key must stay rotatable).
    for keep in [
        "pub async fn rotate_credential<S",
        "pub async fn rollback_credential<S",
        "pub async fn update_credential<S",
        "pub async fn list_credentials<S",
        "pub async fn get_credential<S",
        "pub async fn delete_credential<S",
        "pub async fn list_credential_versions<S",
    ] {
        assert!(SHARED.contains(keep), "{keep}");
    }
}
