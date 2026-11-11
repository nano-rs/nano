// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5194: a rejected licence token is classified apart from transient
//! failures, raises a critical SIEM Health finding with the 14-day lock date,
//! and nothing else (network errors, 5xx) raises it.

use std::sync::Arc;

use chrono::TimeZone;
use reqwest::StatusCode;
use tokio::sync::RwLock;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::license::checker::{classify_failure, LicenseCheckError, LicenseCheckerConfig};
use crate::license::{LicenseChecker, LicenseStatus};
use crate::siem_health::types::{DimensionDetails, HealthStatus};

/// A healthy report with no findings (what a Fresh deployment produces).
fn healthy_report() -> AnalysisResult {
    let detail = || "ok".to_string();
    AnalysisResult {
        overall_score: 100,
        ingestion_score: 100,
        parsing_score: 100,
        enrichment_score: 100,
        detection_score: 100,
        alerting_score: 100,
        summary: String::new(),
        recommendations: Vec::new(),
        dimension_details: DimensionDetails {
            ingestion: detail(),
            parsing: detail(),
            enrichment: detail(),
            detection: detail(),
            alerting: detail(),
        },
    }
}

fn at(y: i32, m: u32, d: u32, h: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap()
}

const NANO_MAIN_403: &str = r#"{"error":"Deployment token revoked"}"#;
const PROXY_403: &str = "<html><body><h1>403 Forbidden</h1>Blocked by policy</body></html>";

#[test]
fn only_401_and_a_nano_main_403_are_credential_rejections() {
    assert!(matches!(
        classify_failure(StatusCode::UNAUTHORIZED, "nope"),
        LicenseCheckError::TokenRejected(401)
    ));
    assert!(matches!(
        classify_failure(StatusCode::FORBIDDEN, NANO_MAIN_403),
        LicenseCheckError::TokenRejected(403)
    ));
    // A proxy, WAF or CDN refusal is not nano-main's answer.
    for (status, body) in [
        (StatusCode::FORBIDDEN, PROXY_403),
        (StatusCode::FORBIDDEN, ""),
        (StatusCode::FORBIDDEN, r#"{"error":{"code":1}}"#),
        (StatusCode::FORBIDDEN, r#"{"message":"denied"}"#),
        (StatusCode::PROXY_AUTHENTICATION_REQUIRED, ""),
    ] {
        assert!(
            matches!(classify_failure(status, body), LicenseCheckError::ServerError(_)),
            "{status} {body:?} stays transient"
        );
        assert!(is_intermediary_refusal(status, body), "{status} {body:?}");
    }
    assert!(!is_intermediary_refusal(StatusCode::FORBIDDEN, NANO_MAIN_403));
    assert!(!is_intermediary_refusal(StatusCode::UNAUTHORIZED, ""));
    for status in [
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::BAD_GATEWAY,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::NOT_FOUND,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        assert!(
            matches!(classify_failure(status, ""), LicenseCheckError::ServerError(_)),
            "{status} stays a transient server error"
        );
    }
}

#[test]
fn rejection_error_carries_no_response_body() {
    let error = classify_failure(StatusCode::UNAUTHORIZED, "Bearer secret-token-echo");
    assert!(!error.to_string().contains("secret"), "{error}");
}

#[test]
fn lock_date_is_fourteen_days_after_the_last_successful_check_in() {
    assert_eq!(lock_date(Some(at(2026, 11, 1, 9))), Some(at(2026, 11, 15, 9)));
    assert_eq!(lock_date(None), None);
}

#[test]
fn notice_message_names_the_fix_and_the_lock_date() {
    let rejection = TokenRejection::new(401, at(2026, 11, 9, 12));
    let notice = TokenRejectedNotice::new(rejection, Some(at(2026, 11, 1, 9)));
    assert_eq!(notice.locks_at, Some(at(2026, 11, 15, 9)));
    assert_eq!(
        notice.message,
        "Licence token was rejected by app.nano.rs. Update LICENSE_TOKEN in .env and re-run \
         ./install.sh. This install locks on 2026-11-15 09:00 UTC (14 days after the last \
         successful check-in)."
    );
    let never = TokenRejectedNotice::new(TokenRejection::new(403, at(2026, 11, 9, 12)), None);
    assert_eq!(never.locks_at, None);
    assert!(never.message.contains("never completed a successful check-in"));
}

#[test]
fn rejection_raises_one_critical_finding_and_caps_the_score() {
    let mut analysis = healthy_report();
    let notice = TokenRejectedNotice::new(
        TokenRejection::new(401, at(2026, 11, 9, 12)),
        Some(at(2026, 11, 1, 9)),
    );
    ensure_token_rejected_finding(&mut analysis, Some(&notice));
    assert_eq!(analysis.recommendations.len(), 1);
    let rec = &analysis.recommendations[0];
    assert_eq!(rec.title, TOKEN_REJECTED_FINDING_TITLE);
    assert_eq!(rec.priority, "critical");
    assert!(rec.description.contains("locks on 2026-11-15 09:00 UTC"), "{}", rec.description);
    assert!(rec.description.contains("HTTP 401"));
    assert_eq!(HealthStatus::from_score(analysis.overall_score), HealthStatus::Critical);
    // Idempotent across report paths.
    ensure_token_rejected_finding(&mut analysis, Some(&notice));
    assert_eq!(analysis.recommendations.len(), 1);
}

#[test]
fn no_rejection_adds_nothing() {
    let mut analysis = healthy_report();
    let before = analysis.overall_score;
    ensure_token_rejected_finding(&mut analysis, None);
    assert!(analysis.recommendations.is_empty());
    assert_eq!(analysis.overall_score, before);
}

/// The real check-in path against a mock licence server. PostgreSQL is
/// unreachable here (writes fail and are logged), so only the classification
/// of each HTTP outcome is under test.
fn checker(url: &str) -> LicenseChecker {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy("postgres://nobody@127.0.0.1:1/none")
        .expect("lazy pool");
    LicenseChecker::new(
        LicenseCheckerConfig::from_license_url(url, "token".into(), "dep_test".into(), 86_400),
        pool,
        Arc::new(RwLock::new(LicenseStatus::default())),
    )
    // NAN-5249: no PostgreSQL here, so seed the install ID the check-in needs.
    .with_install_id("inst_01jcz8m0f6e9w3t5y7r2q4p6n8")
}

async fn check_in_answering(status: u16) -> LicenseCheckError {
    check_in_answering_with(status, "denied").await
}

async fn check_in_answering_with(status: u16, body: &str) -> LicenseCheckError {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/license/status"))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(&server)
        .await;
    checker(&format!("{}/api/license/status", server.uri()))
        .check_license()
        .await
        .expect_err("non-2xx fails the check-in")
}

#[tokio::test]
async fn check_in_401_and_nano_main_403_are_token_rejections() {
    assert!(matches!(check_in_answering(401).await, LicenseCheckError::TokenRejected(401)));
    assert!(matches!(
        check_in_answering_with(403, NANO_MAIN_403).await,
        LicenseCheckError::TokenRejected(403)
    ));
}

#[tokio::test]
async fn check_in_html_403_and_407_from_a_proxy_are_not_token_rejections() {
    assert!(matches!(
        check_in_answering_with(403, PROXY_403).await,
        LicenseCheckError::ServerError(_)
    ));
    assert!(matches!(
        check_in_answering_with(407, "Proxy Authentication Required").await,
        LicenseCheckError::ServerError(_)
    ));
}

#[tokio::test]
async fn check_in_5xx_and_network_errors_are_not_token_rejections() {
    assert!(matches!(check_in_answering(500).await, LicenseCheckError::ServerError(_)));
    assert!(matches!(check_in_answering(503).await, LicenseCheckError::ServerError(_)));
    let unreachable = checker("http://127.0.0.1:1/api/license/status")
        .check_license()
        .await
        .expect_err("connection refused");
    assert!(matches!(unreachable, LicenseCheckError::Network(_)), "{unreachable}");
}
