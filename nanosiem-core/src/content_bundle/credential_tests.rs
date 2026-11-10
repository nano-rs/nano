// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

#[test]
fn debug_never_prints_the_licence_or_the_token() {
    let signed = format!("{:?}", DistributionCredential::SignedLicense(b"secret-licence-bytes".to_vec()));
    assert!(!signed.contains("secret"), "{signed}");
    let enrolled = format!(
        "{:?}",
        DistributionCredential::Enrollment {
            deployment_id: "deploy_1".into(),
            token: "tok-very-secret".into(),
            licence_origin: "https://api.nano.rs".into(),
        }
    );
    assert!(!enrolled.contains("tok-very-secret"), "{enrolled}");
    assert!(enrolled.contains("deploy_1"));
}

#[test]
fn origin_is_scheme_host_and_explicit_port() {
    assert_eq!(url_origin("https://API.nano.rs/api/license/status").as_deref(), Some("https://api.nano.rs"));
    assert_eq!(url_origin("https://api.nano.rs:443/x").as_deref(), Some("https://api.nano.rs"));
    assert_eq!(url_origin("http://127.0.0.1:8787/api/content/v1").as_deref(), Some("http://127.0.0.1:8787"));
    assert_ne!(url_origin("https://api.nano.rs.evil.example/"), url_origin("https://api.nano.rs/"));
    assert_eq!(url_origin("not a url"), None);
}
