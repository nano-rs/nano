// SPDX-License-Identifier: AGPL-3.0-or-later
//! Key ring compatibility, rotation and fail-closed proofs (NAN-4933; the v2
//! envelope and parser cases are ported from main's NAN-4401 CP2a suite).
use super::*;
use serde_json::json;
use uuid::Uuid;

const ROOT: &str = "0123456789abcdef0123456789abcdef";
const OTHER: &str = "fedcba9876543210fedcba9876543210";
const THIRD: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";

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
/// A ring whose active key is `active_id` among two base64 roots.
fn two_key_ring(active_id: &str) -> EncryptionService {
    EncryptionService::from_config(
        &json!({
            "version": 1,
            "active": active_id,
            "keys": [
                {"id": "k1", "key": STANDARD.encode(ROOT)},
                {"id": "k2", "key": STANDARD.encode(OTHER)},
            ],
        })
        .to_string(),
    )
    .unwrap()
}

// ---- existing single-key installs ---------------------------------------

#[test]
fn legacy_ciphertext_decrypts_under_plain_string_import() {
    // The installer's 64-hex value: the old cipher used its first 32 ASCII
    // bytes, NOT the hex-decoded bytes. Old ciphertext must still open.
    let generated = format!("{ROOT}{OTHER}");
    let old = EncryptionService::new(ROOT.as_bytes())
        .encrypt(b"pre-ring secret")
        .unwrap();
    let ring = EncryptionService::from_config(&generated).unwrap();
    assert_eq!(ring.active_key_id(), LEGACY_ID);
    assert_eq!(ring.decrypt(&old).unwrap(), b"pre-ring secret");
    // And the ring's own writes are byte-compatible with the old reader.
    let fresh = ring.encrypt(b"new").unwrap();
    assert!(!fresh.nonce.contains(':'));
    assert_eq!(
        EncryptionService::new(ROOT.as_bytes())
            .decrypt(&fresh)
            .unwrap(),
        b"new"
    );
}

#[test]
fn short_single_keys_from_earlier_releases_keep_working() {
    // 16-31 byte keys were accepted (zero padded) by every earlier release.
    let short = "old-16-byte-key!!";
    let old = EncryptionService::new(short.as_bytes())
        .encrypt(b"old secret")
        .unwrap();
    let ring = EncryptionService::from_config(short).unwrap();
    assert_eq!(ring.decrypt(&old).unwrap(), b"old secret");
    assert!(EncryptionService::from_config("too-short").is_err());
}

#[test]
fn independent_fixed_legacy_fixtures_open_through_every_storage_adapter() {
    let fixtures: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("legacy-fixtures.json")).unwrap();
    for fixture in fixtures {
        let input = fixture["key_input"].as_str().unwrap();
        let config = if input.len() < 32 || keyring::is_public_plain(input) {
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
fn public_placeholder_never_active_but_readable_as_decrypt_only() {
    let public = "nanosiem-default-key-32bytes!!";
    assert!(EncryptionService::from_config(public).is_err());
    assert!(EncryptionService::from_config("CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32").is_err());
    let old = EncryptionService::new(public.as_bytes())
        .encrypt(b"dev secret")
        .unwrap();
    let ring = EncryptionService::from_config(&config(&[("legacy-0", public)])).unwrap();
    assert_eq!(ring.decrypt(&old).unwrap(), b"dev secret");
    // ...and the re-wrap moves it onto the real key.
    let (fresh, from) = ring.rewrap(&old).unwrap().unwrap();
    assert_eq!(from, "legacy-0");
    assert!(EncryptionService::new(public.as_bytes()).decrypt(&fresh).is_err());
    let bad =
        config(&[("legacy-0", public)]).replace("\"active\":\"active\"", "\"active\":\"legacy-0\"");
    assert!(EncryptionService::from_config(&bad).is_err());
}

#[test]
fn parser_refuses_malformed_unbounded_duplicate_or_missing_key_configuration() {
    for value in ["", "short", "{", "{}"] {
        assert!(EncryptionService::from_config(value).is_err());
    }
    let valid = config(&[]);
    let value: serde_json::Value = serde_json::from_str(&valid).unwrap();
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
    let mut dup = value.clone();
    dup["keys"] = json!([value["keys"][0].clone(), value["keys"][0].clone()]);
    assert!(EncryptionService::from_config(&dup.to_string()).is_err());
    assert!(EncryptionService::from_config(&format!("{{{}", "x".repeat(65537))).is_err());
    for bytes in [vec![7; 31], vec![7; 33], vec![0; 32]] {
        let mut bad: serde_json::Value = serde_json::from_str(&valid).unwrap();
        bad["keys"][0]["key"] = json!(STANDARD.encode(bytes));
        assert!(EncryptionService::from_config(&bad.to_string()).is_err());
    }
    for id in ["", "bad:id", &"x".repeat(65)] {
        let cfg = json!({"version":1,"active":id,"keys":[{"id":id,"key":STANDARD.encode(ROOT)}]});
        assert!(EncryptionService::from_config(&cfg.to_string()).is_err());
    }
    // A renamed historical import is refused.
    assert!(EncryptionService::from_config(&config(&[("renamed", OTHER)])).is_err());
}

#[test]
fn json_looking_legacy_keys_require_explicit_import() {
    let old = "  {historical-key-material-that-looks-like-json";
    assert!(EncryptionService::from_config(old).is_err());
    let ring = EncryptionService::from_config(&config(&[("legacy-0", old)])).unwrap();
    let data = EncryptionService::new(&old.as_bytes()[..32])
        .encrypt(b"historical")
        .unwrap();
    assert_eq!(ring.decrypt(&data).unwrap(), b"historical");
}

// ---- rotation ------------------------------------------------------------

#[test]
fn mixed_key_rows_all_decrypt_and_report_their_key() {
    let under_k1 = two_key_ring("k1").encrypt(b"row on k1").unwrap();
    let under_k2 = two_key_ring("k2").encrypt(b"row on k2").unwrap();
    let legacy = EncryptionService::from_config(THIRD)
        .unwrap()
        .encrypt(b"row on legacy-0")
        .unwrap();
    let ring = EncryptionService::from_config(
        &json!({
            "version": 1,
            "active": "k2",
            "keys": [
                {"id": "k2", "key": STANDARD.encode(OTHER)},
                {"id": "k1", "key": STANDARD.encode(ROOT)},
                {"id": "legacy-0", "legacy": THIRD},
            ],
        })
        .to_string(),
    )
    .unwrap();
    for (data, plain, id) in [
        (&under_k1, &b"row on k1"[..], "k1"),
        (&under_k2, &b"row on k2"[..], "k2"),
        (&legacy, &b"row on legacy-0"[..], "legacy-0"),
    ] {
        let (opened, key_id) = ring.decrypt_with_key_id(data).unwrap();
        assert_eq!(opened, plain);
        assert_eq!(key_id, id);
    }
}

#[test]
fn rotation_rewrap_moves_old_rows_to_active_and_is_idempotent() {
    let old_ring = two_key_ring("k1");
    let rows: Vec<_> = (0..5)
        .map(|i| old_ring.encrypt(format!("secret-{i}").as_bytes()).unwrap())
        .collect();
    let new_ring = two_key_ring("k2");
    for (i, row) in rows.iter().enumerate() {
        let (fresh, from) = new_ring.rewrap(row).unwrap().expect("old row is re-wrapped");
        assert_eq!(from, "k1");
        let (plain, id) = new_ring.decrypt_with_key_id(&fresh).unwrap();
        assert_eq!(plain, format!("secret-{i}").as_bytes());
        assert_eq!(id, "k2");
        // Already on the active key: nothing to do.
        assert!(new_ring.rewrap(&fresh).unwrap().is_none());
        // After k1 leaves the ring, the re-wrapped row still opens.
        let k2_only = EncryptionService::from_config(
            &json!({"version":1,"active":"k2","keys":[{"id":"k2","key":STANDARD.encode(OTHER)}]})
                .to_string(),
        )
        .unwrap();
        assert_eq!(k2_only.decrypt(&fresh).unwrap(), format!("secret-{i}").as_bytes());
    }
}

#[test]
fn omitted_legacy_list_means_every_non_active_key_decrypts() {
    let old = two_key_ring("k1").encrypt(b"x").unwrap();
    assert_eq!(two_key_ring("k2").decrypt(&old).unwrap(), b"x");
    // An explicit empty list keeps main's strict meaning: k1 opens only v2.
    let strict = EncryptionService::from_config(
        &json!({
            "version": 1, "active": "k2",
            "keys": [{"id": "k2", "key": STANDARD.encode(OTHER)}, {"id": "k1", "key": STANDARD.encode(ROOT)}],
            "legacy_decrypt_ids": [],
        })
        .to_string(),
    )
    .unwrap();
    assert!(strict.decrypt(&old).is_err());
    let roles: Vec<_> = strict.ring_keys().into_iter().map(|k| (k.id, k.role)).collect();
    assert!(roles.contains(&("k1".into(), KeyRole::V2Only)));
    assert!(roles.contains(&("k2".into(), KeyRole::Active)));
}

#[test]
fn wrong_key_fails_closed() {
    let data = two_key_ring("k1").encrypt(b"secret").unwrap();
    let wrong = EncryptionService::from_config(THIRD).unwrap();
    assert!(matches!(wrong.decrypt(&data), Err(CryptoError::InvalidEnvelope)));
    assert!(wrong.rewrap(&data).is_err());
    assert!(wrong.decrypt_json::<serde_json::Value>(&data).is_err());
    // Truncated / bit-flipped legacy ciphertext never yields plaintext.
    let ring = two_key_ring("k1");
    let mut bytes = STANDARD.decode(&data.ciphertext).unwrap();
    bytes[0] ^= 1;
    assert!(ring
        .decrypt(&EncryptedData::from_bytea(&bytes, &data.nonce))
        .is_err());
    let short_nonce = EncryptedData {
        ciphertext: data.ciphertext.clone(),
        nonce: STANDARD.encode(b"short"),
    };
    assert!(matches!(ring.decrypt(&short_nonce), Err(CryptoError::InvalidNonce)));
}

#[test]
fn fingerprints_identify_material_without_revealing_it() {
    let a = two_key_ring("k1").ring_keys();
    let b = two_key_ring("k2").ring_keys();
    let fp = |keys: &[RingKeyInfo], id: &str| keys.iter().find(|k| k.id == id).unwrap().fingerprint.clone();
    assert_eq!(fp(&a, "k1"), fp(&b, "k1"));
    assert_ne!(fp(&a, "k1"), fp(&a, "k2"));
    assert_eq!(fp(&a, "k1").len(), 16);
    for key in [&a, &b].into_iter().flatten() {
        assert!(!key.fingerprint.contains(&hex::encode(ROOT)));
        assert!(!format!("{key:?}").contains(ROOT));
    }
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

/// `try_from_env` reads only env vars no other test in this binary sets, so
/// this single sequential test owns them (NAN-1355 gating preserved).
#[test]
fn env_loader_gates_default_key_and_reads_ring_json() {
    fn save(k: &str) -> Option<String> {
        std::env::var(k).ok()
    }
    let names = [
        "NANOSIEM_ENCRYPTION_KEY",
        "NANOSIEM_ENCRYPTION_KEY_FILE",
        "OIDC_SECRET_KEY",
        "NANOSIEM_ALLOW_DEFAULT_KEYS",
        "NANOSIEM_DEV_MODE",
    ];
    let saved: Vec<_> = names.iter().map(|k| (*k, save(k))).collect();
    for k in names {
        std::env::remove_var(k);
    }

    // dev-mode alone never unlocks the public key.
    std::env::set_var("NANOSIEM_DEV_MODE", "true");
    assert!(EncryptionService::try_from_env().is_err());
    // allow-default-keys does, and writes stay readable by the old reader.
    std::env::set_var("NANOSIEM_ALLOW_DEFAULT_KEYS", "true");
    let dev = EncryptionService::try_from_env().unwrap();
    let ct = dev.encrypt(b"secret").unwrap();
    assert_eq!(
        EncryptionService::new(PUBLIC_DEV_KEY).decrypt(&ct).unwrap(),
        b"secret"
    );
    std::env::remove_var("NANOSIEM_ALLOW_DEFAULT_KEYS");

    // Deprecated OIDC fallback still loads an existing install.
    std::env::set_var("OIDC_SECRET_KEY", ROOT);
    assert_eq!(EncryptionService::try_from_env().unwrap().active_key_id(), LEGACY_ID);
    std::env::remove_var("OIDC_SECRET_KEY");

    // Ring JSON from a file (trailing newline ignored).
    let dir = std::env::temp_dir().join(format!("nan4933-ring-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ring.json");
    std::fs::write(&path, format!("{}\n", config(&[("legacy-0", OTHER)]))).unwrap();
    std::env::set_var("NANOSIEM_ENCRYPTION_KEY_FILE", &path);
    let ring = EncryptionService::try_from_env().unwrap();
    assert_eq!(ring.active_key_id(), "active");
    let old = EncryptionService::new(OTHER.as_bytes()).encrypt(b"o").unwrap();
    assert_eq!(ring.decrypt(&old).unwrap(), b"o");
    std::fs::remove_dir_all(&dir).ok();

    for (k, v) in saved {
        match v {
            Some(val) => std::env::set_var(k, val),
            None => std::env::remove_var(k),
        }
    }
}

// ---- v2 envelopes (compatible readers, ported from main CP2a) ------------

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
    let d = EncryptedData::from_raw_nonce(&raw, &nonce, version).unwrap();
    for data in [b, j, t, d] {
        assert_eq!(
            service
                .decrypt_credentials_bytea(&data.to_bytea().unwrap().0, &data.nonce)
                .unwrap()["token"],
            "value"
        );
        assert_eq!(v2_key_id(&data).unwrap(), "active");
    }
    assert!(EncryptedData::from_raw_nonce(&raw, &nonce, 3).is_err());
    assert!(EncryptedData::from_raw_nonce(&raw, &nonce[..11], 2).is_err());
    // A context-bound v2 envelope is never re-wrapped context-free.
    assert!(service.rewrap(&value).unwrap().is_none());
}

#[test]
fn different_scopes_cannot_open_each_others_v2_data() {
    let a = tenant();
    let b = service().with_context(
        CredentialScope::Tenant(Uuid::from_u128(2)),
        "connector.vendor",
        "feed-1",
    );
    assert!(b.decrypt(&a.seal_v2(b"tenant secret").unwrap()).is_err());
    let platform = service().with_context(CredentialScope::Platform, "ai.provider", "provider");
    let data = platform.seal_v2(b"platform").unwrap();
    for scope in [
        CredentialScope::Tenant(Uuid::from_u128(1)),
        CredentialScope::Account(Uuid::from_u128(1)),
        CredentialScope::Deployment,
    ] {
        assert!(service().with_context(scope, "ai.provider", "provider").decrypt(&data).is_err());
    }
    assert!(service().decrypt(&data).is_err());
    assert!(service()
        .with_context(CredentialScope::Tenant(Uuid::nil()), "purpose", "row")
        .seal_v2(b"x")
        .is_err());
}

#[test]
fn v2_tampering_and_format_downgrades_fail_closed() {
    let service = tenant();
    let data = service.seal_v2(b"value").unwrap();
    let original = STANDARD.decode(&data.ciphertext).unwrap();
    for index in 0..original.len() {
        let mut bytes = original.clone();
        bytes[index] ^= 1;
        assert!(service
            .decrypt(&EncryptedData::from_bytea(&bytes, &data.nonce))
            .is_err());
    }
    let mut changed = data.clone();
    changed.nonce = changed.nonce.replace("nck2:", "");
    assert!(service.decrypt(&changed).is_err());
    changed.nonce = data.nonce.replace("nck2:", "nck3:");
    assert!(service.decrypt(&changed).is_err());
}

#[test]
fn retired_v2_roots_remain_readable_while_in_ring() {
    let old = tenant();
    let a = old.seal_v2(b"secret").unwrap();
    let cfg = json!({"version":1,"active":"next","keys":[{"id":"next","key":STANDARD.encode(OTHER)},{"id":"active","key":STANDARD.encode(ROOT)}],"legacy_decrypt_ids":[]});
    let next = EncryptionService::from_config(&cfg.to_string())
        .unwrap()
        .with_context(
            CredentialScope::Tenant(Uuid::from_u128(1)),
            "connector.vendor",
            "feed-1",
        );
    assert_eq!(next.decrypt(&a).unwrap(), b"secret");
    let reader = V2CredentialReader::from_root("active", ROOT.as_bytes()).unwrap();
    assert_eq!(
        &*reader
            .open(CredentialScope::Tenant(Uuid::from_u128(1)), "connector.vendor", "feed-1", &a)
            .unwrap(),
        b"secret"
    );
}

// ---- rotation inventory ----------------------------------------------------

/// Every column that stores `EncryptionService` output must be a re-wrap
/// target, or rotation silently strands it. A new secret column fails here
/// until it is added to `rotation::TARGETS`.
#[test]
fn rotation_targets_cover_every_encrypted_column() {
    let expected = [
        "cloud_credentials.credentials_encrypted",
        "cloud_credential_versions.credentials_encrypted",
        "marketplace_catalog.credentials_encrypted",
        "system_settings.tiering_s3_credentials_encrypted",
        "detection_code_targets.token_encrypted",
        "users.totp_secret_encrypted",
        "users.backup_codes_encrypted",
        "integration_instances.credentials_encrypted",
        "soar_connections.credentials_encrypted",
        "oidc_providers.client_secret_encrypted",
        "oidc_providers.google_service_account_encrypted",
        "provider_credentials.credentials_encrypted",
        "agent_enrichment_providers.api_key_encrypted",
        "identity_providers.credentials_encrypted",
        "webhooks.url_encrypted",
        "webhooks.headers_encrypted",
        "webhooks.secret_encrypted",
    ];
    let names: Vec<_> = rotation::TARGETS.iter().map(|t| t.name).collect();
    assert_eq!(names, expected);
    for target in rotation::TARGETS {
        assert_eq!(target.name, format!("{}.{}", target.table, target.column));
    }
}

// ---- key policy (Dan, 2026-11-03) -----------------------------------------

#[test]
fn short_pre_ring_key_stays_active_but_carries_a_visible_warning() {
    let ring = EncryptionService::from_config("old-16-byte-key!!").unwrap();
    let keys = ring.ring_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].role, KeyRole::Active);
    let warning = keys[0].warning.as_deref().expect("short key is flagged");
    assert!(warning.contains("shorter than 32 bytes"));
    assert!(!warning.contains("old-16-byte-key"), "warning never echoes material");
    // Full-length keys carry no warning.
    assert!(EncryptionService::from_config(ROOT).unwrap().ring_keys()[0].warning.is_none());
    assert!(two_key_ring("k1").ring_keys().iter().all(|k| k.warning.is_none()));
    // A short import kept as decrypt-only during rotation stays flagged.
    let rotated = EncryptionService::from_config(&config(&[("legacy-0", "old-16-byte-key!!")])).unwrap();
    assert!(rotated.ring_keys().iter().any(|k| k.id == "legacy-0" && k.warning.is_some()));
}

#[test]
fn every_new_ring_key_must_be_exactly_32_bytes() {
    for bytes in [vec![9u8; 16], vec![9u8; 24], vec![9u8; 31], vec![9u8; 33]] {
        let cfg = json!({"version":1,"active":"next","keys":[{"id":"next","key":STANDARD.encode(&bytes)}]});
        let error = EncryptionService::from_config(&cfg.to_string()).err().expect("refused").to_string();
        assert!(error.contains("exactly 32 bytes"), "{error}");
    }
    // A short key cannot be smuggled in as a new active `legacy` entry either.
    let cfg = json!({"version":1,"active":"legacy-0","keys":[{"id":"legacy-0","legacy":"old-16-byte-key!!"}]});
    assert!(EncryptionService::from_config(&cfg.to_string()).is_err());
}

/// Security review 2026-11-08 (NAN-5037): `.env.example` used to ship a
/// concrete 64-hex key that the ring accepted as a real secret. It is now known
/// public material, so it can no longer be the active key, and an install that
/// copied it must keep decrypting every credential it already stored. This is
/// the exact ring shape `scripts/lib/generated-secrets.sh` writes on upgrade: a
/// generated active key plus the old value as decrypt-only `legacy-0`.
#[test]
fn example_env_key_is_refused_as_active_but_its_ciphertext_survives_the_upgrade() {
    let example = "29131984fc00b782da58a3dfed607c3394506e9d11d01264719d91ec2fa8f7fd";
    // Before the upgrade: the plain key encrypted credentials (pre-ring
    // interpretation: first 32 UTF-8 bytes, which is what `new` reproduces).
    let stored = EncryptionService::new(example.as_bytes())
        .encrypt(b"{\"sasl_password\":\"kafka-secret\"}")
        .unwrap();
    // After the upgrade the plain value no longer boots...
    let err = EncryptionService::from_config(example).err().expect("public key refused");
    assert!(err.to_string().contains("public placeholder"), "{err}");
    // ...and the migrated ring still opens the old credential.
    let new_root = STANDARD.encode(OTHER);
    let migrated = json!({
        "version": 1,
        "active": "k-20261108",
        "keys": [
            {"id": "k-20261108", "key": new_root},
            {"id": "legacy-0", "legacy": example},
        ],
        "legacy_decrypt_ids": ["legacy-0"],
    })
    .to_string();
    let ring = EncryptionService::from_config(&migrated).unwrap();
    assert_eq!(
        ring.decrypt(&stored).unwrap(),
        b"{\"sasl_password\":\"kafka-secret\"}"
    );
    // The background re-wrap moves it onto the generated key; the public key
    // can then no longer read it.
    let (rewrapped, from) = ring.rewrap(&stored).unwrap().expect("needs rewrap");
    assert_eq!(from, "legacy-0");
    assert_eq!(
        ring.decrypt(&rewrapped).unwrap(),
        b"{\"sasl_password\":\"kafka-secret\"}"
    );
    assert!(EncryptionService::new(example.as_bytes()).decrypt(&rewrapped).is_err());
    assert!(ring.rewrap(&rewrapped).unwrap().is_none(), "already on the active key");
}
