//! Consumer contracts use the validated production parser and never perform IO.
use nanosiem_core::crypto::{CredentialScope, EncryptionService};
use std::collections::HashMap;
use uuid::Uuid;

fn cipher() -> EncryptionService {
    EncryptionService::from_config("0123456789abcdef0123456789abcdef").unwrap()
}

#[test]
fn mfa_readers_accept_legacy_and_v2_but_reject_other_accounts_and_fields() {
    use nanosiem_core::auth::mfa;
    let user = Uuid::from_u128(1);
    let root = cipher();
    let account = root.with_context(CredentialScope::Account(user), "account.totp", user);
    let wrong = root.with_context(
        CredentialScope::Account(Uuid::from_u128(2)),
        "account.totp",
        user,
    );
    let backups = account.with_purpose("account.backup-codes");
    for envelope in [
        mfa::encrypt_secret("BASE32SECRET", &account).unwrap(),
        account.seal_v2(b"BASE32SECRET").unwrap(),
    ] {
        let (ct, nonce) = envelope.to_bytea().unwrap();
        assert_eq!(
            mfa::decrypt_secret(&ct, &nonce, &account).unwrap(),
            "BASE32SECRET"
        );
        if nonce.starts_with("nck2:") {
            assert!(mfa::decrypt_secret(&ct, &nonce, &wrong).is_err());
            assert!(mfa::decrypt_secret(&ct, &nonce, &backups).is_err());
            let selected_tenant =
                root.with_context(CredentialScope::Tenant(user), "account.totp", user);
            assert!(mfa::decrypt_secret(&ct, &nonce, &selected_tenant).is_err());
        }
    }
    let hashes = vec!["fixture-hash".to_owned()];
    let envelope = backups
        .seal_v2(&serde_json::to_vec(&hashes).unwrap())
        .unwrap();
    let (ct, nonce) = envelope.to_bytea().unwrap();
    assert_eq!(
        mfa::decrypt_backup_codes(&ct, &nonce, &backups).unwrap(),
        hashes
    );
    assert!(mfa::decrypt_backup_codes(&ct, &nonce, &account).is_err());
}

#[test]
fn export_reader_keeps_crypto_and_embedded_tenant_checks() {
    use nanosiem_core::iceberg_export;
    let root = cipher();
    let tenant = Uuid::from_u128(1);
    let values = HashMap::from([
        ("catalog_credential".into(), "catalog".into()),
        ("access_key_id".into(), "access".into()),
        ("secret_access_key".into(), "secret".into()),
    ]);
    let (ct, nonce) = iceberg_export::seal(&root, tenant, values.clone()).unwrap();
    assert_eq!(
        iceberg_export::open(&root, tenant, &ct, &nonce).unwrap(),
        values
    );
    let scoped = root.with_context(CredentialScope::Tenant(tenant), "iceberg.export", tenant);
    for embedded in [tenant, Uuid::from_u128(2)] {
        let mut bound = values.clone();
        bound.insert("tenant_id".into(), embedded.to_string());
        let (ct, nonce) = scoped
            .seal_v2(&serde_json::to_vec(&bound).unwrap())
            .unwrap()
            .to_bytea()
            .unwrap();
        assert_eq!(
            iceberg_export::open(&root, tenant, &ct, &nonce).is_ok(),
            embedded == tenant
        );
        assert!(iceberg_export::open(&root, Uuid::from_u128(2), &ct, &nonce).is_err());
    }
}

#[test]
fn webhook_request_builder_preserves_scope_row_and_separate_field_purposes() {
    use nanosiem_core::webhooks::{models::Webhook, service::build_signed_request};
    let id = Uuid::from_u128(1);
    let root = cipher();
    let now = chrono::Utc::now();
    let client = reqwest::Client::new();
    for scope in [
        CredentialScope::Deployment,
        CredentialScope::Tenant(Uuid::from_u128(3)),
    ] {
        let scoped = root.with_context(scope, "webhook.url", id);
        let mut hook = Webhook {
            id,
            name: "fixture".into(),
            url: "https://example.test/hook".into(),
            url_encrypted: None,
            url_host: None,
            headers_encrypted: Some(
                scoped
                    .with_purpose("webhook.headers")
                    .seal_v2(br#"{"Authorization":"Bearer fixture"}"#)
                    .unwrap()
                    .to_json_bytes()
                    .unwrap(),
            ),
            secret_encrypted: Some(
                scoped
                    .with_purpose("webhook.secret")
                    .seal_v2(b"fixture-signing-secret")
                    .unwrap()
                    .to_json_bytes()
                    .unwrap(),
            ),
            severity_filter: None,
            event_types: vec![],
            channel_type: "generic".into(),
            channel_config: serde_json::json!({}),
            rule_filter: None,
            health_category_filter: None,
            health_resource_filter: None,
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        let request = build_signed_request(&scoped, &client, &hook, b"{}", true)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(request.headers()["Authorization"], "Bearer fixture");
        assert!(request.headers().contains_key("X-NanoSIEM-Signature"));
        for wrong in [
            root.with_context(CredentialScope::Platform, "webhook.url", id),
            root.with_context(scope, "webhook.url", Uuid::from_u128(2)),
            root.with_context(
                CredentialScope::Tenant(Uuid::from_u128(4)),
                "webhook.url",
                id,
            ),
        ] {
            assert!(build_signed_request(&wrong, &client, &hook, b"{}", true).is_err());
        }
        std::mem::swap(&mut hook.headers_encrypted, &mut hook.secret_encrypted);
        assert!(build_signed_request(&scoped, &client, &hook, b"{}", true).is_err());
    }
}

#[cfg(feature = "enterprise")]
#[test]
fn lookup_reader_keeps_null_and_rejects_cross_tenant_or_webhook_substitution() {
    use nanosiem_core::enterprise_shared_lookup_ingestion::decrypt_auth_headers;
    let root = cipher();
    let tenant = Uuid::from_u128(1);
    let lookup = Uuid::from_u128(2);
    let scoped = root.with_context(CredentialScope::Tenant(tenant), "lookup.headers", lookup);
    assert!(decrypt_auth_headers(&scoped, None).unwrap().is_empty());
    let envelope = scoped
        .seal_v2(br#"{"Authorization":"Bearer fixture"}"#)
        .unwrap()
        .to_json_bytes()
        .unwrap();
    assert_eq!(
        decrypt_auth_headers(&scoped, Some(&envelope)).unwrap()["Authorization"],
        "Bearer fixture"
    );
    for wrong in [
        root.with_context(
            CredentialScope::Tenant(Uuid::from_u128(3)),
            "lookup.headers",
            lookup,
        ),
        scoped.with_purpose("webhook.headers"),
        root.with_context(
            CredentialScope::Tenant(tenant),
            "lookup.headers",
            Uuid::from_u128(4),
        ),
    ] {
        assert!(decrypt_auth_headers(&wrong, Some(&envelope)).is_err());
    }
}
