// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5194: a rejected licence token rides the real check-in path
//! (`LicenseChecker::check_license`) against a mock nano-main, with the
//! cached licence status in a real Postgres.
//!
//! Proves: a 401 records the rejection (banner data + critical SIEM Health
//! finding with the 14-day lock date) without changing admission; a repeat
//! keeps the first rejection time; a 503 or network error records nothing;
//! the next 200 clears it.
//!
//! DB-backed: `#[ignore]`d; run with `-- --ignored` against a disposable
//! `DATABASE_URL` (and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1). Enterprise only.
#![cfg(feature = "enterprise")]

mod common;

use std::sync::Arc;

use chrono::{Duration, Utc};
use nanosiem_core::license::checker::LicenseCheckerConfig;
use nanosiem_core::license::token_rejection::{lock_date, recommendation};
use nanosiem_core::license::{LicenseChecker, LicenseRepository, LicenseState, LicenseStatus};
use sqlx::PgPool;
use tokio::sync::RwLock;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn admitted() -> serde_json::Value {
    serde_json::json!({
        "valid": true, "tier": "licensed", "locked": false, "lockedReason": null,
        "expiresAt": (Utc::now() + Duration::days(30)).to_rfc3339(), "graceEndsAt": null,
    })
}

fn checker(url: &str, pool: &PgPool, status: Arc<RwLock<LicenseStatus>>) -> LicenseChecker {
    LicenseChecker::new(
        LicenseCheckerConfig::from_license_url(url, "old-token".into(), "dep_nan5194".into(), 86_400),
        pool.clone(),
        status,
    )
}

async fn server_answering(status: u16) -> MockServer {
    let server = MockServer::start().await;
    let template = if status == 200 {
        ResponseTemplate::new(200).set_body_json(admitted())
    } else {
        ResponseTemplate::new(status)
    };
    Mock::given(method("GET"))
        .and(path("/api/license/status"))
        .respond_with(template)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
#[ignore = "requires a disposable DATABASE_URL (pg-integration-tests)"]
async fn rejected_token_is_raised_kept_under_the_grace_bound_and_cleared_by_success() {
    let pool = common::migrated_pool().await;
    let repo = LicenseRepository::new(pool.clone());
    let status = Arc::new(RwLock::new(LicenseStatus::default()));

    // A successful check-in seeds the cache (and the last-success time).
    let ok = server_answering(200).await;
    let ok_url = format!("{}/api/license/status", ok.uri());
    checker(&ok_url, &pool, status.clone()).check_license().await.expect("200 succeeds");
    assert!(repo.get_token_rejected_notice().await.unwrap().is_none());
    let last_success = status.read().await.last_checked_at.expect("observed");

    // 503 and a refused connection: transient, nothing recorded.
    let flaky = server_answering(503).await;
    checker(&format!("{}/api/license/status", flaky.uri()), &pool, status.clone())
        .check_license()
        .await
        .expect_err("503 fails");
    checker("http://127.0.0.1:1/api/license/status", &pool, status.clone())
        .check_license()
        .await
        .expect_err("network error");
    assert!(repo.get_token_rejected_notice().await.unwrap().is_none());

    // 401: recorded with the lock date; admission unchanged.
    let revoked = server_answering(401).await;
    let revoked_url = format!("{}/api/license/status", revoked.uri());
    checker(&revoked_url, &pool, status.clone()).check_license().await.expect_err("401 fails");
    let first = repo.get_token_rejected_notice().await.unwrap().expect("rejection recorded");
    assert_eq!(first.http_status, 401);
    assert_eq!(first.locks_at, lock_date(Some(last_success)));
    assert!(first.message.contains("Update LICENSE_TOKEN in .env"));
    assert_eq!(status.read().await.state, LicenseState::Active, "no early lock");
    assert_eq!(repo.get_status().await.unwrap().last_checked_at, Some(last_success));
    let finding = recommendation(&first);
    assert_eq!(finding.priority, "critical");

    // A repeat keeps the first rejection time and refreshes the last.
    checker(&revoked_url, &pool, status.clone()).check_license().await.expect_err("401 again");
    let second = repo.get_token_rejected_notice().await.unwrap().expect("still recorded");
    assert_eq!(second.first_rejected_at, first.first_rejected_at);
    assert!(second.last_rejected_at >= first.last_rejected_at);

    // A 200 whose local admission then fails still proves the token was
    // accepted: the rejection clears even though the check-in errors.
    sqlx::query("ALTER TABLE system_settings RENAME TO system_settings_nan5194")
        .execute(&pool)
        .await
        .unwrap();
    let admission = checker(&ok_url, &pool, status.clone()).check_license().await;
    sqlx::query("ALTER TABLE system_settings_nan5194 RENAME TO system_settings")
        .execute(&pool)
        .await
        .unwrap();
    assert!(admission.is_err(), "admission fails without system_settings");
    assert!(
        repo.get_token_rejected_notice().await.unwrap().is_none(),
        "a parsed 200 clears the banner even when admission fails"
    );

    // Rejected again, then a fully successful check-in also clears it.
    checker(&revoked_url, &pool, status.clone()).check_license().await.expect_err("401");
    assert!(repo.get_token_rejected_notice().await.unwrap().is_some());

    // The next successful check-in clears it.
    checker(&ok_url, &pool, status.clone()).check_license().await.expect("200 succeeds");
    assert!(repo.get_token_rejected_notice().await.unwrap().is_none());
}
