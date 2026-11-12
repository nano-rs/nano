// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5079: the hash-bound OCSF sample-validation receipt on `log_sources`
//! (migration 379). A receipt matches only its exact contract version and
//! parser fingerprint, stores no sample content, and the CHECK constraint
//! refuses a half-written receipt.

mod common;

use nanosiem_core::log_sources::LogSourceRepository;
use uuid::Uuid;

const PARSER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PARSER_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SAMPLES: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

async fn source(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO log_sources (id, name, source_type, parser_vrl)
         VALUES ($1, $2, 'routed', '. = {}')",
    )
    .bind(id)
    .bind(format!("nan-5079-{id}"))
    .execute(pool)
    .await
    .expect("create log source");
    id
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn a_new_source_has_no_receipt() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());
    let id = source(&pool).await;
    assert!(repo.ocsf_validation_attestation(id).await.unwrap().is_none());
    assert!(!repo
        .has_ocsf_validation_attestation(id, "1.9.0", PARSER_A)
        .await
        .unwrap());
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn a_receipt_matches_only_its_version_and_parser_fingerprint() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());
    let id = source(&pool).await;
    repo.set_ocsf_validation_attestation(id, "1.9.0", PARSER_A, SAMPLES, 3)
        .await
        .unwrap();

    assert!(repo.has_ocsf_validation_attestation(id, "1.9.0", PARSER_A).await.unwrap());
    assert!(
        !repo.has_ocsf_validation_attestation(id, "1.9.0", PARSER_B).await.unwrap(),
        "an edited parser must not reuse the receipt"
    );
    assert!(
        !repo.has_ocsf_validation_attestation(id, "2.0.0", PARSER_A).await.unwrap(),
        "a newer contract must not reuse the receipt"
    );
    let (version, parser, count, _at) = repo.ocsf_validation_attestation(id).await.unwrap().unwrap();
    assert_eq!((version.as_str(), parser.as_str(), count), ("1.9.0", PARSER_A, 3));

    // Advancing the receipt replaces it.
    repo.set_ocsf_validation_attestation(id, "1.9.0", PARSER_B, SAMPLES, 1)
        .await
        .unwrap();
    assert!(!repo.has_ocsf_validation_attestation(id, "1.9.0", PARSER_A).await.unwrap());
    assert!(repo.has_ocsf_validation_attestation(id, "1.9.0", PARSER_B).await.unwrap());
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn the_constraint_refuses_a_partial_or_malformed_receipt() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());
    let id = source(&pool).await;

    assert!(
        repo.set_ocsf_validation_attestation(id, "1.9.0", "not-a-hash", SAMPLES, 1)
            .await
            .is_err(),
        "a non-hex fingerprint is refused"
    );
    assert!(
        repo.set_ocsf_validation_attestation(id, "1.9.0", PARSER_A, SAMPLES, 0)
            .await
            .is_err(),
        "a receipt with no samples is refused"
    );
    let partial = sqlx::query(
        "UPDATE log_sources SET ocsf_validation_parser_sha256 = $2 WHERE id = $1",
    )
    .bind(id)
    .bind(PARSER_A)
    .execute(&pool)
    .await;
    assert!(partial.is_err(), "a half-written receipt is refused");
    assert!(repo.ocsf_validation_attestation(id).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn setting_a_receipt_on_a_missing_source_is_not_found() {
    let pool = common::migrated_pool().await;
    let repo = LogSourceRepository::new(pool.clone());
    assert!(repo
        .set_ocsf_validation_attestation(Uuid::now_v7(), "1.9.0", PARSER_A, SAMPLES, 1)
        .await
        .is_err());
}
