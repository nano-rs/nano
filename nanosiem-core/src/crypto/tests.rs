use super::*;
use serde_json::json;
use std::process::Command;
use uuid::Uuid;

const ROOT: &str = "0123456789abcdef0123456789abcdef";
const OTHER: &str = "fedcba9876543210fedcba9876543210";
fn config(legacy: &[(&str, &str)]) -> String {
    let mut keys = vec![json!({"id":"active", "key":STANDARD.encode(ROOT)})];
    keys.extend(
        legacy
            .iter()
            .map(|(id, value)| json!({"id":id, "legacy":value})),
    );
    json!({"version":1,"active":"active","keys":keys,"legacy_decrypt_ids":legacy.iter().map(|(id,_)| *id).collect::<Vec<_>>()}).to_string()
}
fn service() -> EncryptionService {
    EncryptionService::from_config(&config(&[])).unwrap()
}
fn tenant() -> EncryptionService {
    service().with_context(
        CredentialScope::Tenant(Uuid::from_u128(1)),
        "connector.vendor",
        "feed-1",
    )
}

#[test]
fn permanent_plain_string_import_preserves_ascii_hex_bytes() {
    let generated = format!("{ROOT}{OTHER}");
    let cipher = EncryptionService::from_config(&generated).unwrap();
    assert_eq!(cipher.active_key_id(), "legacy-0");
    let data = cipher.encrypt(b"secret").unwrap();
    assert_eq!(
        EncryptionService::from_config(ROOT)
            .unwrap()
            .decrypt(&data)
            .unwrap(),
        b"secret"
    );
    assert!(!data.nonce.contains(':'));
    // UTF-8 is truncated by byte, even across a character boundary.
    let utf8 = format!("{}é", "a".repeat(31));
    let utf8_service = EncryptionService::from_config(&utf8).unwrap();
    let old_effective = [vec![b'a'; 31], vec![0xc3]].concat();
    assert_eq!(
        EncryptionService::new(&old_effective)
            .decrypt(&utf8_service.encrypt(b"ok").unwrap())
            .unwrap(),
        b"ok"
    );
}
#[test]
fn short_legacy_requires_valid_active_and_explicit_decrypt_entry() {
    let short = "old-16-byte-key!!";
    assert!(EncryptionService::from_config(short).is_err());
    let ring = EncryptionService::from_config(&config(&[("legacy-0", short)])).unwrap();
    let mut old_key = [0; 32];
    old_key[..short.len()].copy_from_slice(short.as_bytes());
    // Fixture from the old effective key, not a bypass for the ring under test.
    let old = EncryptionService::new(&old_key)
        .encrypt(b"old secret")
        .unwrap();
    assert_eq!(ring.decrypt(&old).unwrap(), b"old secret");
    assert!(EncryptionService::from_config(&config(&[("legacy-0", "too-short")])).is_err());
    let bad =
        config(&[("legacy-0", short)]).replace("\"active\":\"active\"", "\"active\":\"legacy-0\"");
    assert!(EncryptionService::from_config(&bad).is_err());
}
#[test]
fn public_default_explicit_decrypt_only_and_never_active() {
    let public = "nanosiem-default-key-32bytes!!";
    let ring = EncryptionService::from_config(&config(&[("legacy-0", public)])).unwrap();
    let mut key = [0; 32];
    key[..public.len()].copy_from_slice(public.as_bytes());
    let nonce = [1; 12];
    let ct = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(Nonce::from_slice(&nonce), b"old public secret".as_slice())
        .unwrap();
    assert_eq!(
        ring.decrypt(&EncryptedData::from_bytea(&ct, &STANDARD.encode(nonce)))
            .unwrap(),
        b"old public secret"
    );
    assert!(EncryptionService::from_config(&format!("{public}00000000")).is_err());
    let bad =
        config(&[("legacy-0", public)]).replace("\"active\":\"active\"", "\"active\":\"legacy-0\"");
    assert!(EncryptionService::from_config(&bad).is_err());
    let mut value: serde_json::Value =
        serde_json::from_str(&config(&[("legacy-0", public)])).unwrap();
    value["legacy_decrypt_ids"] = json!([]);
    assert!(EncryptionService::from_config(&value.to_string()).is_err());
}
#[test]
fn parser_refuses_malformed_unbounded_duplicate_or_missing_key_configuration() {
    for value in [
        "",
        "short",
        "{",
        "{}",
        "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32",
    ] {
        assert!(EncryptionService::from_config(value).is_err());
    }
    let valid = config(&[]);
    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
    for mutation in [
        json!({"version":2}),
        json!({"active":"absent"}),
        json!({"keys":[]}),
        json!({"unknown":"secret"}),
        json!({"legacy_decrypt_ids":["absent"]}),
    ] {
        let mut bad = value.clone();
        for (k, v) in mutation.as_object().unwrap() {
            bad[k] = v.clone();
        }
        assert!(EncryptionService::from_config(&bad.to_string()).is_err());
    }
    value["keys"] = json!([value["keys"][0].clone(), value["keys"][0].clone()]);
    assert!(EncryptionService::from_config(&value.to_string()).is_err());
    assert!(EncryptionService::from_config(&format!("{{{}", "x".repeat(65537))).is_err());
    for bytes in [vec![7; 31], vec![7; 33], vec![0; 32]] {
        let mut bad: serde_json::Value = serde_json::from_str(&valid).unwrap();
        bad["keys"][0]["key"] = json!(STANDARD.encode(bytes));
        assert!(EncryptionService::from_config(&bad.to_string()).is_err());
    }
}
#[test]
fn active_legacy_writes_are_readable_even_when_only_old_ids_are_listed() {
    let service = EncryptionService::from_config(&config(&[("legacy-0", OTHER)])).unwrap();
    let data = service.encrypt_json(&json!({"token":"value"})).unwrap();
    assert!(!data.nonce.contains(':'));
    assert_eq!(
        service.decrypt_json::<serde_json::Value>(&data).unwrap(),
        json!({"token":"value"})
    );
}
#[test]
fn all_storage_adapters_preserve_key_id_and_context() {
    let service = tenant();
    let value = service.seal_v2(br#"{"token":"value"}"#).unwrap();
    let (bytes, nonce) = value.to_bytea().unwrap();
    let b = EncryptedData::from_bytea(&bytes, &nonce);
    let j = EncryptedData::from_json_bytes(&value.to_json_bytes().unwrap()).unwrap();
    let t = EncryptedData::from_text_bytea(value.ciphertext.as_bytes(), &nonce).unwrap();
    let (raw, nonce, version) = value.to_raw_nonce().unwrap();
    assert_eq!(version, 2);
    assert_eq!(nonce.len(), 12);
    let d = EncryptedData::from_raw_nonce(&raw, &nonce, version).unwrap();
    for data in [b, j, t, d] {
        assert_eq!(
            service
                .decrypt_credentials_bytea(&data.to_bytea().unwrap().0, &data.nonce)
                .unwrap()["token"],
            "value"
        );
    }
    assert!(EncryptedData::from_raw_nonce(&raw, &nonce, 3).is_err());
    assert!(EncryptedData::from_raw_nonce(&raw, &nonce[..11], 2).is_err());
}
#[test]
fn different_tenant_actual_derivations_cannot_open_each_others_data() {
    let a = tenant();
    let b = service().with_context(
        CredentialScope::Tenant(Uuid::from_u128(2)),
        "connector.vendor",
        "feed-1",
    );
    let ca = a.context.as_ref().unwrap();
    let cb = b.context.as_ref().unwrap();
    let ka = derive(ROOT.as_bytes(), ca).unwrap();
    let kb = derive(ROOT.as_bytes(), cb).unwrap();
    assert_ne!(ka.as_ref(), kb.as_ref());
    let ct = a.seal_v2(b"tenant secret").unwrap();
    assert!(b.decrypt(&ct).is_err());
    assert!(a.decrypt(&b.seal_v2(b"b secret").unwrap()).is_err());
    let bytes = STANDARD.decode(&ct.ciphertext).unwrap();
    let (_, head, body) = envelope::parse(&bytes).unwrap();
    let nonce = decode_nonce(ct.nonce.strip_prefix(envelope::V2_NONCE_PREFIX).unwrap()).unwrap();
    assert!(Aes256Gcm::new_from_slice(kb.as_ref())
        .unwrap()
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: body,
                aad: &ca.aad(head).unwrap()
            }
        )
        .is_err());
}
#[test]
fn platform_cannot_open_in_tenant_account_or_deployment_scope() {
    let platform = service().with_context(CredentialScope::Platform, "ai.provider", "provider");
    let data = platform.seal_v2(b"platform").unwrap();
    for scope in [
        CredentialScope::Tenant(Uuid::from_u128(1)),
        CredentialScope::Account(Uuid::from_u128(1)),
        CredentialScope::Deployment,
    ] {
        let other = service().with_context(scope, "ai.provider", "provider");
        assert!(other.decrypt(&data).is_err());
        assert!(platform.decrypt(&other.seal_v2(b"other").unwrap()).is_err());
    }
    assert!(service().decrypt(&data).is_err());
}
#[test]
fn wrong_account_purpose_row_and_nil_identity_are_rejected() {
    let scope = CredentialScope::Account(Uuid::from_u128(1));
    let account = service().with_context(scope, "account.totp", "user");
    let data = account.seal_v2(b"totp").unwrap();
    for (scope, purpose, row) in [
        (
            CredentialScope::Account(Uuid::from_u128(2)),
            "account.totp",
            "user",
        ),
        (scope, "account.backup", "user"),
        (scope, "account.totp", "other"),
    ] {
        assert!(service()
            .with_context(scope, purpose, row)
            .decrypt(&data)
            .is_err());
    }
    assert!(service()
        .with_context(CredentialScope::Tenant(Uuid::nil()), "purpose", "row")
        .seal_v2(b"x")
        .is_err());
}
#[test]
fn tampering_and_format_downgrades_fail_closed() {
    let service = tenant();
    let data = service.seal_v2(b"value").unwrap();
    let original = STANDARD.decode(&data.ciphertext).unwrap();
    for index in 0..original.len() {
        let mut bytes = original.clone();
        bytes[index] ^= 1;
        let changed = EncryptedData::from_bytea(&bytes, &data.nonce);
        assert!(service.decrypt(&changed).is_err());
    }
    let mut changed = data.clone();
    changed.nonce = changed.nonce.replace("nck2:", "");
    assert!(service.decrypt(&changed).is_err());
    changed.nonce = data.nonce.replace("nck2:", "nck3:");
    assert!(service.decrypt(&changed).is_err());
    for nonce in ["nck2:", "nck2:AAAA", "not base64"] {
        assert!(service
            .decrypt(&EncryptedData {
                ciphertext: data.ciphertext.clone(),
                nonce: nonce.into()
            })
            .is_err());
    }
}
#[test]
fn retired_v2_roots_remain_readable_and_nonces_are_unique() {
    let old = tenant();
    let a = old.seal_v2(b"secret").unwrap();
    let b = old.seal_v2(b"secret").unwrap();
    assert_ne!(a.nonce, b.nonce);
    let cfg = json!({"version":1,"active":"next","keys":[{"id":"next","key":STANDARD.encode(OTHER)},{"id":"active","key":STANDARD.encode(ROOT)}],"legacy_decrypt_ids":[]});
    let next = EncryptionService::from_config(&cfg.to_string())
        .unwrap()
        .with_context(
            CredentialScope::Tenant(Uuid::from_u128(1)),
            "connector.vendor",
            "feed-1",
        );
    assert_eq!(next.decrypt(&a).unwrap(), b"secret");
}
#[test]
fn redacted_debug_and_configuration_errors_never_echo_material() {
    let secret = "NEVER_PRINT_THIS_MATERIAL";
    let bad = format!(
        r#"{{"version":1,"active":"{secret}","keys":[{{"id":"x","key":"{secret}"}}],"legacy_decrypt_ids":[]}}"#
    );
    let error = EncryptionService::from_config(&bad)
        .err()
        .unwrap()
        .to_string();
    assert!(!error.contains(secret));
    let data = service().encrypt(secret.as_bytes()).unwrap();
    assert_eq!(format!("{data:?}"), "EncryptedData([redacted])");
}
#[test]
#[ignore = "subprocess production constructor probe"]
fn boot_probe() {
    let _tracing = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .try_init();
    let _ = EncryptionService::from_env();
}
#[test]
#[ignore = "subprocess production JWT constructor probe"]
fn jwt_boot_probe() {
    let _ = crate::auth::TokenConfig::default();
}
fn probe(
    name: &str,
    key: Option<&str>,
    oidc: Option<&str>,
    jwt: Option<&str>,
) -> std::process::Output {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", name, "--ignored", "--nocapture"])
        .env_clear();
    if let Some(key) = key {
        cmd.env("NANOSIEM_ENCRYPTION_KEY", key);
    }
    if let Some(key) = oidc {
        cmd.env("OIDC_SECRET_KEY", key);
    }
    if let Some(key) = jwt {
        cmd.env("JWT_SECRET", key);
    }
    cmd.output().unwrap()
}
#[test]
fn boot_refusal_subprocess_uses_guarded_production_loader() {
    for key in [
        None,
        Some(""),
        Some("short"),
        Some("old-16-byte-key!!"),
        Some("{"),
        Some("CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32"),
    ] {
        assert!(!probe("crypto::tests::boot_probe", key, None, None)
            .status
            .success());
    }
    for key in [ROOT, &config(&[])] {
        assert!(probe("crypto::tests::boot_probe", Some(key), None, None)
            .status
            .success());
    }
    let result = probe("crypto::tests::boot_probe", None, Some(ROOT), None);
    assert!(!result.status.success());
    let output = String::from_utf8_lossy(&result.stderr);
    assert!(output.contains("move the existing OIDC_SECRET_KEY value"));
    assert!(!output.contains(ROOT));
    let result = probe(
        "crypto::tests::boot_probe",
        Some(&config(&[("legacy-0", "nanosiem-default-key-32bytes!!")])),
        None,
        None,
    );
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("PUBLIC DEFAULT"));
}
#[test]
fn jwt_refuses_missing_short_and_public_secrets_in_production_constructor() {
    for key in [
        None,
        Some("short"),
        Some("nanosiem-dev-secret-change-in-production"),
        Some("default-dev-jwt-secret-32chars!!"),
    ] {
        assert!(!probe("crypto::tests::jwt_boot_probe", None, None, key)
            .status
            .success());
    }
    assert!(
        probe("crypto::tests::jwt_boot_probe", None, None, Some(ROOT))
            .status
            .success()
    );
}

#[test]
fn independent_fixed_legacy_fixtures_open_through_every_storage_adapter() {
    let fixtures: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("legacy-fixtures.json")).unwrap();
    for fixture in fixtures {
        let input = fixture["key_input"].as_str().unwrap();
        let config = if input.len() < 32 {
            config(&[("legacy-0", input)])
        } else {
            input.to_string()
        };
        let service = EncryptionService::from_config(&config).unwrap();
        let data = EncryptedData {
            ciphertext: fixture["ciphertext"].as_str().unwrap().into(),
            nonce: fixture["nonce"].as_str().unwrap().into(),
        };
        let (bytes, nonce) = data.to_bytea().unwrap();
        let raw_nonce = STANDARD.decode(&nonce).unwrap();
        for encoded in [
            EncryptedData::from_bytea(&bytes, &nonce),
            EncryptedData::from_json_bytes(&data.to_json_bytes().unwrap()).unwrap(),
            EncryptedData::from_text_bytea(data.ciphertext.as_bytes(), &nonce).unwrap(),
            EncryptedData::from_raw_nonce(&bytes, &raw_nonce, 1).unwrap(),
        ] {
            assert_eq!(
                service.decrypt(&encoded).unwrap(),
                fixture["plaintext"].as_str().unwrap().as_bytes()
            );
        }
    }
}
#[test]
fn raw_constructor_cannot_bypass_active_key_validation() {
    for key in [vec![1; 16], vec![1; 31], vec![1; 33], vec![0; 32]] {
        assert!(std::panic::catch_unwind(|| EncryptionService::new(&key)).is_err());
    }
}
#[test]
fn removed_escape_hatch_cannot_enable_public_keys() {
    for name in ["crypto::tests::boot_probe", "crypto::tests::jwt_boot_probe"] {
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--ignored", "--nocapture"])
            .env_clear()
            .env("NANOSIEM_ALLOW_DEFAULT_KEYS", "true")
            .env("NANOSIEM_DEV_MODE", "true")
            .output()
            .unwrap();
        assert!(!result.status.success());
    }
}

#[test]
fn signature_verifier_uses_recorded_id_and_never_active_fallback() {
    let old = EncryptionService::from_config(ROOT).unwrap();
    let sig = old.keyed_mac_sha512(b"ledger", b"message");
    let cfg = json!({"version":1,"active":"next","keys":[{"id":"next","key":STANDARD.encode(OTHER)},{"id":"legacy-0","key":STANDARD.encode(ROOT)}],"legacy_decrypt_ids":["legacy-0"]});
    let next = EncryptionService::from_config(&cfg.to_string()).unwrap();
    assert!(next
        .verify_mac_sha512("legacy-0", b"ledger", b"message", &sig)
        .is_ok());
    for id in ["next", "missing"] {
        assert!(next
            .verify_mac_sha512(id, b"ledger", b"message", &sig)
            .is_err());
    }
    assert!(next
        .verify_mac_sha512("legacy-0", b"other", b"message", &sig)
        .is_err());
    assert!(next
        .verify_mac_sha512("legacy-0", b"ledger", b"changed", &sig)
        .is_err());
    assert!(next
        .verify_mac_sha512("legacy-0", b"ledger", b"message", &sig[..63])
        .is_err());
    assert!(next
        .verify_mac_sha512(
            next.active_key_id(),
            b"ledger",
            b"message",
            &next.keyed_mac_sha512(b"ledger", b"message")
        )
        .is_ok());
}
#[cfg(feature = "enterprise")]
#[test]
#[ignore = "subprocess control-plane production constructor probe"]
fn control_boot_probe() {
    crate::enterprise_shared_platform_ai_provider::encryption_service_from_env().unwrap();
}
#[cfg(feature = "enterprise")]
#[test]
fn control_boot_constructor_allows_absent_but_refuses_present_invalid() {
    assert!(
        probe("crypto::tests::control_boot_probe", None, Some(ROOT), None)
            .status
            .success()
    );
    assert!(!probe(
        "crypto::tests::control_boot_probe",
        Some("short"),
        None,
        None
    )
    .status
    .success());
    assert!(
        probe("crypto::tests::control_boot_probe", Some(ROOT), None, None)
            .status
            .success()
    );
}

#[test]
fn independent_legacy_hmac_vector_remains_verifiable() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("legacy-hmac.json")).unwrap();
    let domain = fixture["domain"].as_str().unwrap().as_bytes();
    let message = hex::decode(fixture["message_hex"].as_str().unwrap()).unwrap();
    let expected = hex::decode(fixture["signature_hex"].as_str().unwrap()).unwrap();
    let cipher = EncryptionService::from_config(ROOT).unwrap();
    assert_eq!(
        cipher.keyed_mac_sha512(domain, &message).as_slice(),
        expected
    );
    assert!(cipher
        .verify_mac_sha512("legacy-0", domain, &message, &expected)
        .is_ok());
}

#[test]
fn duplicate_json_fields_invalid_ids_and_excessive_root_lists_are_rejected() {
    assert!(EncryptionService::from_config(
        r#"{"version":1,"version":1,"active":"a","keys":[],"legacy_decrypt_ids":[]}"#
    )
    .is_err());
    for id in ["", "bad:id", &"x".repeat(65)] {
        let cfg = json!({"version":1,"active":id,"keys":[{"id":id,"key":STANDARD.encode(ROOT)}],"legacy_decrypt_ids":[]});
        assert!(EncryptionService::from_config(&cfg.to_string()).is_err());
    }
    let keys: Vec<_> = (0..33)
        .map(|i| json!({"id":format!("k{i}"),"key":STANDARD.encode(ROOT)}))
        .collect();
    let cfg = json!({"version":1,"active":"k0","keys":keys,"legacy_decrypt_ids":[]});
    assert!(EncryptionService::from_config(&cfg.to_string()).is_err());
    for entry in [
        json!({"id":"active","key":"invalid base64"}),
        json!({"id":"active","key":STANDARD.encode(ROOT),"legacy":ROOT}),
    ] {
        let cfg = json!({"version":1,"active":"active","keys":[entry],"legacy_decrypt_ids":[]});
        assert!(EncryptionService::from_config(&cfg.to_string()).is_err());
    }
    let cfg = json!({"version":1,"active":"active","keys":[{"id":"active","key":STANDARD.encode(ROOT)}],"legacy_decrypt_ids":["active","active"]});
    assert!(EncryptionService::from_config(&cfg.to_string()).is_err());
}
#[test]
fn maximum_existing_bytea_payloads_remain_readable() {
    let service = EncryptionService::from_config(ROOT).unwrap();
    for bound in [4096, 16384, 32768, 65536] {
        let original = vec![b'x'; bound - 16];
        let data = service.encrypt(&original).unwrap();
        let (ct, nonce) = data.to_bytea().unwrap();
        assert_eq!(ct.len(), bound);
        assert_eq!(
            service
                .decrypt(&EncryptedData::from_bytea(&ct, &nonce))
                .unwrap(),
            original
        );
    }
}

#[test]
fn json_looking_legacy_keys_require_explicit_import_and_never_fallback() {
    let old = "  {historical-key-material-that-looks-like-json";
    assert!(EncryptionService::from_config(old).is_err());
    let ring = EncryptionService::from_config(&config(&[("legacy-0", old)])).unwrap();
    let data = EncryptionService::new(&old.as_bytes()[..32])
        .encrypt(b"historical")
        .unwrap();
    assert_eq!(ring.decrypt(&data).unwrap(), b"historical");
}

#[test]
fn historical_import_cannot_rename_the_signature_key_id() {
    let valid = config(&[("legacy-0", OTHER)]);
    let renamed = valid.replace("legacy-0", "renamed");
    let error = EncryptionService::from_config(&renamed)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("legacy-0"));
    assert!(!error.contains(OTHER));
    let old = EncryptionService::from_config(OTHER).unwrap();
    let signature = old.keyed_mac_sha512(b"ledger", b"historical");
    let ring = EncryptionService::from_config(&valid).unwrap();
    assert!(ring
        .verify_mac_sha512("legacy-0", b"ledger", b"historical", &signature)
        .is_ok());
}
