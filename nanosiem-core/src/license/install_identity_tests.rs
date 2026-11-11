// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// The exact shape nano-main validates: `^inst_[0-7][0-9a-hjkmnp-tv-z]{25}$`.
fn matches_wire_format(id: &str) -> bool {
    let Some(suffix) = id.strip_prefix("inst_") else {
        return false;
    };
    suffix.len() == 26
        && suffix.as_bytes()[0].is_ascii_digit()
        && suffix.as_bytes()[0] <= b'7'
        && suffix
            .bytes()
            .all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b))
}

#[test]
fn wire_form_is_an_inst_typeid_nano_main_accepts() {
    for _ in 0..256 {
        let id = encode_install_id(&Uuid::new_v4());
        assert!(matches_wire_format(&id), "{id}");
    }
    assert_eq!(encode_install_id(&Uuid::nil()), "inst_00000000000000000000000000");
    assert_eq!(encode_install_id(&Uuid::from_u128(u128::MAX)), "inst_7zzzzzzzzzzzzzzzzzzzzzzzzz");
}

#[test]
fn wire_form_round_trips() {
    let id = Uuid::new_v4();
    let wire = encode_install_id(&id);
    assert_eq!(crate::typeid::decode(INSTALL_ID_PREFIX, &wire).unwrap(), id);
}

#[test]
fn header_name_is_the_documented_contract() {
    assert_eq!(INSTALL_ID_HEADER, "X-Nano-Install-Id");
    assert!(reqwest::header::HeaderName::from_bytes(INSTALL_ID_HEADER.as_bytes()).is_ok());
}

/// An install whose ID cannot be read (PostgreSQL unreachable here) does not
/// check in at all: nano-main would answer a v2 check-in without an ID with
/// "upgrade required". The attempt fails like an outage, so the cached status
/// (bounded by the 14-day staleness lock) is kept.
#[tokio::test]
async fn check_in_without_a_readable_id_is_not_sent() {
    use crate::license::checker::{LicenseCheckError, LicenseCheckerConfig};
    use crate::license::{LicenseChecker, LicenseStatus};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/license/status"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy("postgres://nobody@127.0.0.1:1/none")
        .expect("lazy pool");
    let checker = LicenseChecker::new(
        LicenseCheckerConfig::from_license_url(
            &format!("{}/api/license/status", server.uri()),
            "token".into(),
            "dep_test".into(),
            86_400,
        ),
        pool,
        std::sync::Arc::new(tokio::sync::RwLock::new(LicenseStatus::default())),
    );
    let err = checker.check_license().await.expect_err("no ID, no check-in");
    assert!(matches!(err, LicenseCheckError::InstallIdUnavailable), "{err}");
}
