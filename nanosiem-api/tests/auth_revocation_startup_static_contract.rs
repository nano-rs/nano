// SPDX-License-Identifier: AGPL-3.0-or-later

#[test]
fn revocations_are_awaited_on_the_async_constructor_runtime() {
    let sync_constructor = include_str!("../src/state/mod.rs");
    let async_constructor = include_str!("../src/state/constructors.rs");
    assert!(!sync_constructor.contains("std::thread::spawn"));
    assert!(!sync_constructor.contains("tokio::runtime::Runtime::new"));
    assert!(!sync_constructor.contains("load_revoked_tokens("));
    assert_eq!(async_constructor.matches("load_revoked_tokens(").count(), 1);
    let auth = async_constructor.find("Self::init_auth_services(").unwrap();
    let load = async_constructor.find("load_revoked_tokens(").unwrap();
    let settings = async_constructor[load..].find("let local_auth_settings").unwrap() + load;
    assert!(auth < load && load < settings);
    assert!(async_constructor[load..settings].contains(".await"));
    assert!(async_constructor[load..settings].contains("&token_service.revoked_jtis_handle()"));
    assert!(sync_constructor.contains("new_with_shared_denylist"));
}
