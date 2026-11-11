// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5249: the install ID against a real PostgreSQL and a mock nano-main.
//!
//! Proves: migration 327 creates exactly one ID; reading it is stable and
//! idempotent; if the row is missing, many hosts creating it at once agree on
//! one ID; the ID rides on the licence check-in as `X-Nano-Install-Id`.
//!
//! DB-backed: `#[ignore]`d; run with `-- --ignored` against a disposable
//! `DATABASE_URL` (and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1). Enterprise only (the
//! licence module is not in the open build).
#![cfg(feature = "enterprise")]

mod common;

use std::sync::Arc;

use chrono::{Duration, Utc};
use nanosiem_core::license::checker::LicenseCheckerConfig;
use nanosiem_core::license::{InstallIdentityRepository, LicenseChecker, LicenseStatus, INSTALL_ID_HEADER};
use tokio::sync::RwLock;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DEPLOYMENT: &str = "dep_nan5249_test";

fn is_wire_form(id: &str) -> bool {
    id.strip_prefix("inst_").is_some_and(|suffix| {
        suffix.len() == 26
            && (b'0'..=b'7').contains(&suffix.as_bytes()[0])
            && suffix.bytes().all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b))
    })
}

#[tokio::test]
#[ignore = "requires a disposable DATABASE_URL (pg-integration-tests)"]
async fn install_id_is_created_once_and_shared_by_every_host() {
    let pool = common::migrated_pool().await;
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM install_identity")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1, "the migration seeds exactly one row");

    let repo = InstallIdentityRepository::new(pool.clone());
    let first = repo.get_or_create().await.unwrap();
    assert!(is_wire_form(&first), "{first}");
    assert_eq!(repo.get_or_create().await.unwrap(), first, "stable across reads");
    assert_eq!(
        InstallIdentityRepository::new(pool.clone()).get_or_create().await.unwrap(),
        first,
        "another process sharing the database reads the same ID"
    );

    // Row lost (e.g. a hand-edited database): eight hosts racing to recreate
    // it all end up with the one ID that won.
    sqlx::query("DELETE FROM install_identity").execute(&pool).await.unwrap();
    let racers: Vec<_> = (0..8)
        .map(|_| {
            let repo = InstallIdentityRepository::new(pool.clone());
            tokio::spawn(async move { repo.get_or_create().await.unwrap() })
        })
        .collect();
    let mut ids = Vec::new();
    for racer in racers {
        ids.push(racer.await.unwrap());
    }
    ids.dedup();
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert!(is_wire_form(&ids[0]));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM install_identity")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
}

#[tokio::test]
#[ignore = "requires a disposable DATABASE_URL (pg-integration-tests)"]
async fn install_id_rides_on_the_licence_check_in() {
    let pool = common::migrated_pool().await;
    let id = InstallIdentityRepository::new(pool.clone()).get_or_create().await.unwrap();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/license/status"))
        .and(query_param("deploymentId", DEPLOYMENT))
        .and(header(INSTALL_ID_HEADER, id.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "valid": true, "tier": "licensed", "locked": false, "lockedReason": null,
            "expiresAt": (Utc::now() + Duration::days(30)).to_rfc3339(), "graceEndsAt": null,
        })))
        .expect(2)
        .mount(&server)
        .await;
    let checker = LicenseChecker::new(
        LicenseCheckerConfig::from_license_url(
            &format!("{}/api/license/status", server.uri()),
            "deployment-token".into(),
            DEPLOYMENT.into(),
            86_400,
        ),
        pool.clone(),
        Arc::new(RwLock::new(LicenseStatus::default())),
    );
    checker.check_license().await.expect("check-in with the install ID");
    // The second check-in reuses the cached ID.
    checker.check_license().await.expect("second check-in");
}
