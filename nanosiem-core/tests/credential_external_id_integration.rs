// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-2186: `external_id` round-trips as UNENCRYPTED metadata across the
//! credential lifecycle.
//!
//! This is hand-written SQL with no compile-time `query!` verification, and the
//! change threaded a new bind through six statements (create parent + v1,
//! rotate parent + vN, rollback parent + vN, plus the `get_decrypted` merge).
//! Bind-order mistakes there are silent — you get the wrong column populated,
//! not a compile error — so the round trip is only really proven at runtime.
//!
//! The property that matters: an ExternalId must be READABLE after creation.
//! It lived in the encrypted payload originally, and `GET /api/credentials`
//! returns no payload at all, so it was write-only — the operator could never
//! retrieve the value the account owner needs for their trust policy.
//!
//! `#[ignore]`d DB suite — run via `pg-integration-tests` CI or
//! `docker compose up -d postgres` + `cargo test -- --ignored`.

mod common;

use nanosiem_core::parsers::{
    CreateCloudCredential, CredentialRepository, RollbackCloudCredential, RotateCloudCredential,
};

fn role_credential(name: &str, external_id: Option<&str>) -> CreateCloudCredential {
    CreateCloudCredential {
        name: name.to_string(),
        provider: "aws_s3".to_string(),
        credentials: serde_json::json!({
            "assume_role_arn": "arn:aws:iam::210987654321:role/nano-ingest",
        }),
        external_id: external_id.map(str::to_string),
        description: None,
        region: Some("ap-south-1".to_string()),
        environment: None,
        expires_at: None,
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn external_id_is_readable_after_creation() {
    let pool = common::migrated_pool().await;
    let repo = CredentialRepository::new(pool.clone());

    let created = repo
        .create(&role_credential("nan2186-create", Some("ext-create")), None)
        .await
        .expect("create");
    assert_eq!(created.external_id.as_deref(), Some("ext-create"));

    // The point of the whole change: a plain read returns it, with no decrypt.
    let fetched = repo.get(created.id).await.expect("get");
    assert_eq!(fetched.external_id.as_deref(), Some("ext-create"));

    let listed = repo.list().await.expect("list");
    let found = listed
        .iter()
        .find(|c| c.id == created.id)
        .expect("credential in list");
    assert_eq!(found.external_id.as_deref(), Some("ext-create"));
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn get_decrypted_merges_external_id_for_the_config_generators() {
    // The generators consume ONE credential JSON. The column is the sole store,
    // so `get_decrypted` has to merge it back in or `aws_auth_table` never sees
    // it and emits `assume_role` with no `external_id`.
    let pool = common::migrated_pool().await;
    let repo = CredentialRepository::new(pool.clone());

    let created = repo
        .create(&role_credential("nan2186-decrypt", Some("ext-merge")), None)
        .await
        .expect("create");

    let decrypted = repo.get_decrypted(created.id).await.expect("decrypt");
    assert_eq!(
        decrypted["external_id"].as_str(),
        Some("ext-merge"),
        "get_decrypted must merge the column into the generator's JSON",
    );
    assert_eq!(
        decrypted["assume_role_arn"].as_str(),
        Some("arn:aws:iam::210987654321:role/nano-ingest"),
        "the encrypted payload must survive the merge",
    );
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn rotation_rewrites_the_external_id() {
    // A rotation can change POSTURE — static keys today, a cross-account role
    // tomorrow — so it must overwrite the column rather than inherit.
    let pool = common::migrated_pool().await;
    let repo = CredentialRepository::new(pool.clone());

    let created = repo
        .create(&role_credential("nan2186-rotate", Some("ext-v1")), None)
        .await
        .expect("create");

    let (rotated, _version) = repo
        .rotate(
            created.id,
            &RotateCloudCredential {
                credentials: serde_json::json!({
                    "assume_role_arn": "arn:aws:iam::210987654321:role/nano-ingest-v2",
                }),
                external_id: Some("ext-v2".to_string()),
                note: Some("posture change".to_string()),
            },
            None,
        )
        .await
        .expect("rotate");

    assert_eq!(rotated.external_id.as_deref(), Some("ext-v2"));
    let decrypted = repo.get_decrypted(created.id).await.expect("decrypt");
    assert_eq!(decrypted["external_id"].as_str(), Some("ext-v2"));
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn rotating_to_static_keys_clears_the_external_id() {
    let pool = common::migrated_pool().await;
    let repo = CredentialRepository::new(pool.clone());

    let created = repo
        .create(&role_credential("nan2186-clear", Some("ext-role")), None)
        .await
        .expect("create");

    let (rotated, _) = repo
        .rotate(
            created.id,
            &RotateCloudCredential {
                credentials: serde_json::json!({
                    "access_key_id": "AKIAEXAMPLE",
                    "secret_access_key": "secret",
                }),
                external_id: None,
                note: None,
            },
            None,
        )
        .await
        .expect("rotate");

    assert!(
        rotated.external_id.is_none(),
        "moving back to static keys must clear the id, not strand the old one",
    );
    let decrypted = repo.get_decrypted(created.id).await.expect("decrypt");
    assert!(
        decrypted.get("external_id").is_none(),
        "a cleared column must not reappear in the generator JSON",
    );
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn rollback_restores_the_external_id_belonging_to_that_version() {
    // The id is a trust-policy condition ON the role ARN, and the ARN is in the
    // versioned payload. Carrying the CURRENT id backwards would pair a
    // restored role with an id its trust policy never referenced — an
    // AssumeRole that fails with an error pointing nowhere near here.
    let pool = common::migrated_pool().await;
    let repo = CredentialRepository::new(pool.clone());

    let created = repo
        .create(&role_credential("nan2186-rollback", Some("ext-v1")), None)
        .await
        .expect("create");

    repo.rotate(
        created.id,
        &RotateCloudCredential {
            credentials: serde_json::json!({
                "assume_role_arn": "arn:aws:iam::210987654321:role/nano-ingest-v2",
            }),
            external_id: Some("ext-v2".to_string()),
            note: None,
        },
        None,
    )
    .await
    .expect("rotate");

    let (rolled_back, _) = repo
        .rollback(
            created.id,
            &RollbackCloudCredential {
                version: 1,
                note: Some("back to v1".to_string()),
            },
            None,
        )
        .await
        .expect("rollback");

    assert_eq!(
        rolled_back.external_id.as_deref(),
        Some("ext-v1"),
        "rollback must restore v1's id, not keep v2's",
    );
    let decrypted = repo.get_decrypted(created.id).await.expect("decrypt");
    assert_eq!(
        decrypted["assume_role_arn"].as_str(),
        Some("arn:aws:iam::210987654321:role/nano-ingest"),
        "the payload and the id must move together",
    );
    assert_eq!(decrypted["external_id"].as_str(), Some("ext-v1"));
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn static_key_credentials_carry_no_external_id() {
    let pool = common::migrated_pool().await;
    let repo = CredentialRepository::new(pool.clone());

    let created = repo
        .create(
            &CreateCloudCredential {
                name: "nan2186-keys".to_string(),
                provider: "aws_s3".to_string(),
                credentials: serde_json::json!({
                    "access_key_id": "AKIAEXAMPLE",
                    "secret_access_key": "secret",
                }),
                external_id: None,
                description: None,
                region: Some("ap-south-1".to_string()),
                environment: None,
                expires_at: None,
            },
            None,
        )
        .await
        .expect("create");

    assert!(created.external_id.is_none());
    let decrypted = repo.get_decrypted(created.id).await.expect("decrypt");
    assert!(decrypted.get("external_id").is_none());
}
