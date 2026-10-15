// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for durable job record signing (NAN-2361).

use super::*;

fn master() -> DurableJobSigningMasterKey {
    DurableJobSigningMasterKey::from_bytes([0x42; 32])
}

const TENANT_A: Uuid = Uuid::from_u128(0x4047ace1_208c_42b9_b997_f40851c949f6);
const TENANT_B: Uuid = Uuid::from_u128(0x8b672aca_e503_4c43_81fb_3c7f5550d86a);

#[test]
fn portable_envelope_preserves_existing_signature_and_rejects_rebinding() {
    let tenant = TENANT_A.to_string();
    let key = master().derive_tenant_key(TENANT_A);
    let physical = "hosted-job:v1:tenant-a:retention-1:assignment-1:epoch-1:job-1";
    let record = record(physical, &tenant);
    let envelope = DurableJobEnvelope {
        tenant_id: record.tenant_id.into(), job_id: record.job_id.into(),
        backend: record.backend.into(), user_id: record.user_id.into(),
        priority: record.priority.into(), created_at_ms: record.created_at_ms.into(),
        request_json: record.request_json.into(), task_json: record.task_json.into(),
        generation_pin_json: record.generation_pin_json.into(), authority_json: record.authority_json.into(),
        scope_deny: record.scope_deny.into(), scope_artifact_deny: record.scope_artifact_deny.into(),
        signature: key.sign(&record),
    };
    let job_id = Uuid::parse_str(record.job_id).unwrap();
    let bytes = serde_json::to_vec(&envelope).unwrap();
    let mut decoded: DurableJobEnvelope = serde_json::from_slice(&bytes).unwrap();
    decoded.verify(&key, physical, job_id).unwrap();
    assert_eq!(decoded.signed_record(physical).canonical_bytes(), record.canonical_bytes());
    assert!(decoded.verify(&key, "different-recovery-epoch", job_id).is_err());
    assert!(decoded.verify(&key, physical, Uuid::nil()).is_err());
    assert!(decoded.verify(&master().derive_tenant_key(TENANT_B), physical, job_id).is_err());
    decoded.scope_deny = "[]".into();
    assert!(decoded.verify(&key, physical, job_id).is_err());
    assert!(!format!("{envelope:?}").contains("src_ip"));
    let mut value = serde_json::to_value(envelope).unwrap();
    value["job_key"] = serde_json::json!(physical);
    assert!(serde_json::from_value::<DurableJobEnvelope>(value).is_err());
}

fn record<'a>(job_key: &'a str, tenant: &'a str) -> DurableJobSignedRecord<'a> {
    DurableJobSignedRecord {
        job_key,
        tenant_id: tenant,
        job_id: "0192b1c2-0000-7000-8000-000000000001",
        backend: "lake_durable",
        user_id: "0192b1c2-0000-7000-8000-0000000000aa",
        priority: "analytics",
        created_at_ms: "1757174400000",
        request_json: r#"{"query":"src_ip=10.0.0.1 | stats count by user"}"#,
        task_json: r#"{"kind":"search_npl_v1"}"#,
        generation_pin_json: r#"{"generation_id":"gen-1","event_config_sha256":"ab"}"#,
        authority_json: r#"{"tenant_id":"4047ace1-208c-42b9-b997-f40851c949f6","user_id":"0192b1c2-0000-7000-8000-0000000000aa","credential":{"kind":"session","access_jti":"0192b1c2-0000-7000-8000-0000000000bb","credential_time_micros":1757174400000000},"membership_authority_revision":3,"entitlement_assignment_revision":1,"retention_revision":1,"retention_days":90,"irreversible_event_time_floor_micros":0,"roles":["analyst"],"permissions":["search:execute"]}"#,
        scope_deny: r#"["audit"]"#,
        scope_artifact_deny: "[]",
    }
}

#[test]
fn hkdf_sha256_matches_rfc5869_test_case_1() {
    let ikm = [0x0b_u8; 22];
    let salt: Vec<u8> = (0x00..=0x0c).collect();
    let info: Vec<u8> = (0xf0..=0xf9).collect();
    let okm = hkdf_sha256_32(&ikm, &salt, &info);
    assert_eq!(
        hex::encode(okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    );
}

#[test]
fn sign_then_verify_round_trips() {
    let key = master().derive_tenant_key(TENANT_A);
    let key_str = format!("search:{{jobs:{TENANT_A}:assignment:1}}:job:x");
    let tenant = TENANT_A.to_string();
    let rec = record(&key_str, &tenant);
    let signature = key.sign(&rec);
    assert_eq!(signature.len(), 64);
    key.verify(&rec, &signature).expect("valid signature verifies");
}

#[test]
fn derived_keys_are_tenant_specific_and_deterministic() {
    let a1 = master().derive_tenant_key(TENANT_A);
    let a2 = master().derive_tenant_key(TENANT_A);
    let b = master().derive_tenant_key(TENANT_B);
    assert_eq!(a1.to_hex(), a2.to_hex());
    assert_ne!(a1.to_hex(), b.to_hex());
    // A different master yields a different tenant key.
    let other = DurableJobSigningMasterKey::from_bytes([0x43; 32]).derive_tenant_key(TENANT_A);
    assert_ne!(a1.to_hex(), other.to_hex());
}

#[test]
fn wrong_tenant_key_rejects_a_copied_record() {
    let key_a = master().derive_tenant_key(TENANT_A);
    let key_b = master().derive_tenant_key(TENANT_B);
    let key_str = format!("search:{{jobs:{TENANT_A}:assignment:1}}:job:x");
    let tenant = TENANT_A.to_string();
    let rec = record(&key_str, &tenant);
    let signature = key_a.sign(&rec);
    assert!(matches!(
        key_b.verify(&rec, &signature),
        Err(DurableJobSigningError::Mismatch)
    ));
}

#[test]
fn every_signed_field_is_tamper_evident() {
    let key = master().derive_tenant_key(TENANT_A);
    let key_str = format!("search:{{jobs:{TENANT_A}:assignment:1}}:job:x");
    let other_key_str = format!("search:{{jobs:{TENANT_A}:assignment:2}}:job:x");
    let tenant = TENANT_A.to_string();
    let other_tenant = TENANT_B.to_string();
    let base = record(&key_str, &tenant);
    let signature = key.sign(&base);

    let mutants: Vec<DurableJobSignedRecord<'_>> = vec![
        DurableJobSignedRecord { job_key: &other_key_str, ..base.clone() },
        DurableJobSignedRecord { tenant_id: &other_tenant, ..base.clone() },
        DurableJobSignedRecord { job_id: "evil", ..base.clone() },
        DurableJobSignedRecord { backend: "inline", ..base.clone() },
        DurableJobSignedRecord { user_id: "0192b1c2-0000-7000-8000-0000000000ff", ..base.clone() },
        DurableJobSignedRecord { priority: "interactive", ..base.clone() },
        DurableJobSignedRecord { created_at_ms: "1757174400001", ..base.clone() },
        DurableJobSignedRecord { request_json: r#"{"query":"*"}"#, ..base.clone() },
        DurableJobSignedRecord { task_json: r#"{"kind":"prevalence_export_v1"}"#, ..base.clone() },
        DurableJobSignedRecord { generation_pin_json: r#"{"generation_id":"gen-2"}"#, ..base.clone() },
        DurableJobSignedRecord { authority_json: r#"{"roles":["admin"]}"#, ..base.clone() },
        DurableJobSignedRecord { scope_deny: "[]", ..base.clone() },
        DurableJobSignedRecord { scope_artifact_deny: r#"["x"]"#, ..base.clone() },
    ];
    for mutant in mutants {
        assert!(
            matches!(key.verify(&mutant, &signature), Err(DurableJobSigningError::Mismatch)),
            "mutant must not verify: {mutant:?}"
        );
    }
}

#[test]
fn length_prefixing_prevents_field_boundary_shifts() {
    // Moving one byte across a field boundary produces distinct canonical bytes.
    let key_str = "search:{jobs}:job:x";
    let a = DurableJobSignedRecord { scope_deny: "ab", scope_artifact_deny: "c", ..record(key_str, "") };
    let b = DurableJobSignedRecord { scope_deny: "a", scope_artifact_deny: "bc", ..record(key_str, "") };
    assert_ne!(a.canonical_bytes(), b.canonical_bytes());
}

#[test]
fn unsigned_and_malformed_signatures_are_typed() {
    let key = master().derive_tenant_key(TENANT_A);
    let rec = record("search:{jobs}:job:x", "");
    assert!(matches!(key.verify(&rec, ""), Err(DurableJobSigningError::Unsigned)));
    assert!(matches!(key.verify(&rec, "abc"), Err(DurableJobSigningError::Malformed)));
    assert!(matches!(
        key.verify(&rec, &"zz".repeat(32)),
        Err(DurableJobSigningError::Malformed)
    ));
    let flipped = {
        let mut s = key.sign(&rec).into_bytes();
        s[0] = if s[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(s).unwrap()
    };
    assert!(matches!(key.verify(&rec, &flipped), Err(DurableJobSigningError::Mismatch)));
}

#[test]
fn key_material_accepts_raw_and_hex_only() {
    assert!(parse_key_material(&[7_u8; 32]).is_ok());
    let hex_text = format!("{}\n", "ab".repeat(32));
    assert_eq!(parse_key_material(hex_text.as_bytes()).unwrap(), [0xab; 32]);
    assert!(matches!(parse_key_material(&[7_u8; 31]), Err(DurableJobSigningError::KeyLength)));
    assert!(matches!(parse_key_material(&[7_u8; 33]), Err(DurableJobSigningError::KeyLength)));
    assert!(matches!(
        parse_key_material("zz".repeat(32).as_bytes()),
        Err(DurableJobSigningError::KeyLength)
    ));
}

#[cfg(unix)]
#[test]
fn key_file_requires_owner_only_regular_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signing-key");
    std::fs::write(&path, "cd".repeat(32)).unwrap();

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        DurableJobSigningMasterKey::from_file(&path),
        Err(DurableJobSigningError::KeyFile(_))
    ));

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let master = DurableJobSigningMasterKey::from_file(&path).expect("0600 key loads");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    let derived = DurableJobSigningKey::from_file(&path, TENANT_A).expect("0400 key loads");
    assert_eq!(
        master.derive_tenant_key(TENANT_A).to_hex(),
        DurableJobSigningMasterKey::from_bytes([0xcd; 32])
            .derive_tenant_key(TENANT_A)
            .to_hex()
    );
    assert_eq!(derived.tenant_id(), TENANT_A);

    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(matches!(
        DurableJobSigningMasterKey::from_file(&link),
        Err(DurableJobSigningError::KeyFile(_))
    ));
    assert!(matches!(
        DurableJobSigningMasterKey::from_file(Path::new("relative/key")),
        Err(DurableJobSigningError::KeyFile(_))
    ));
}
