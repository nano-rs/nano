// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5266: completing a validated ID token from userinfo (Okta puts the
//! email / profile scope claims only there when an access token is issued),
//! and the generic-OIDC verified-domains option.

use super::oidc::{groups_from_validated_claims, oidc_user_from_claims};
use super::sso_policy::is_microsoft_issuer;
use super::types::OidcProvider;
use super::oidc_userinfo::{
    fetch_userinfo, fetch_userinfo_pinned, merge_userinfo, needs_userinfo, userinfo_url,
    UserInfoClaims, USERINFO_MAX_BYTES,
};
use super::{IdTokenClaims, OidcAssertedIdentity, OidcError, SsoAccessPolicy};
use reqwest::Client;
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

const OKTA: &str = "https://acme.okta.com/oauth2/default";
const ENTRA_TENANT: &str = "11111111-1111-4111-8111-111111111111";
const ENTRA_ISSUER: &str =
    "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0";
const GOOGLE: &str = "https://accounts.google.com";

/// A validated ID token as Okta mints it when an access token is also
/// issued: base claims only, no email / email_verified / profile.
fn okta_base_token(patch: Value) -> IdTokenClaims {
    let mut value = json!({
        "iss": OKTA, "sub": "00u1abcd", "aud": "client", "exp": 2_000_000_000i64,
        "iat": 1_900_000_000i64, "nonce": "n", "auth_time": 1_900_000_000i64,
        "amr": ["pwd", "mfa"], "idp": "00o1", "at_hash": "x", "ver": 1, "jti": "ID.1"
    });
    value.as_object_mut().unwrap().extend(patch.as_object().unwrap().clone());
    IdTokenClaims::from_validated_value(value).unwrap()
}

fn token(issuer: &str, patch: Value) -> IdTokenClaims {
    let mut value = json!({
        "iss": issuer, "sub": "subject", "aud": "client", "exp": 2_000_000_000i64,
        "iat": 1_900_000_000i64, "email": "member@example.com"
    });
    value.as_object_mut().unwrap().extend(patch.as_object().unwrap().clone());
    IdTokenClaims::from_validated_value(value).unwrap()
}

fn userinfo(value: Value) -> UserInfoClaims {
    serde_json::from_value(value).unwrap()
}

fn okta_userinfo() -> Value {
    json!({
        "sub": "00u1abcd", "email": "Analyst@Acme.example", "email_verified": true,
        "name": "Ana Lyst", "given_name": "Ana", "family_name": "Lyst",
        "preferred_username": "analyst@acme.example", "groups": ["nano-analysts"]
    })
}

// ---------------------------------------------------------------- merging

#[test]
fn userinfo_fills_only_missing_email_and_profile_claims() {
    let mut claims = okta_base_token(json!({}));
    assert!(needs_userinfo(&claims));
    merge_userinfo(&mut claims, userinfo(okta_userinfo()), Some("groups")).unwrap();
    assert_eq!(claims.email.as_deref(), Some("Analyst@Acme.example"));
    assert_eq!(claims.email_verified, Some(true));
    assert_eq!(claims.name.as_deref(), Some("Ana Lyst"));
    // Only taken because userinfo also supplied the email.
    assert_eq!(claims.preferred_username.as_deref(), Some("analyst@acme.example"));
    assert!(claims.verified_email());
    assert!(!needs_userinfo(&claims), "merge is complete, a second fetch is not needed");
    // Identity, issuer and nonce are never touched.
    assert_eq!(claims.sub, "00u1abcd");
    assert_eq!(claims.iss, OKTA);
    assert_eq!(claims.nonce.as_deref(), Some("n"));
}

#[test]
fn userinfo_never_overrides_what_the_id_token_asserted() {
    let mut claims = okta_base_token(json!({
        "email": "real@acme.example", "email_verified": false, "name": "Real Name",
        "groups": ["from-id-token"]
    }));
    merge_userinfo(
        &mut claims,
        userinfo(json!({
            "sub": "00u1abcd", "email": "other@acme.example", "email_verified": true,
            "name": "Other", "groups": ["nano-admins"]
        })),
        Some("groups"),
    )
    .unwrap();
    assert_eq!(claims.email.as_deref(), Some("real@acme.example"));
    assert_eq!(claims.email_verified, Some(false));
    assert_eq!(claims.name.as_deref(), Some("Real Name"));
    assert_eq!(claims.groups, vec!["from-id-token"]);
}

#[test]
fn email_verified_applies_only_to_the_address_it_was_issued_for() {
    // ID token has an email but no flag; userinfo verifies a DIFFERENT address.
    let mut claims = okta_base_token(json!({"email": "victim@acme.example"}));
    merge_userinfo(
        &mut claims,
        userinfo(json!({"sub": "00u1abcd", "email": "attacker@acme.example", "email_verified": true})),
        None,
    )
    .unwrap();
    assert_eq!(claims.email.as_deref(), Some("victim@acme.example"));
    assert_eq!(claims.email_verified, None);
    assert!(!claims.verified_email());

    // A flag with no address in userinfo is not applied either.
    let mut claims = okta_base_token(json!({"email": "a@acme.example"}));
    merge_userinfo(&mut claims, userinfo(json!({"sub": "00u1abcd", "email_verified": true})), None)
        .unwrap();
    assert_eq!(claims.email_verified, None);

    // An ID-token flag with no ID-token address does not vouch for the
    // userinfo address on its own.
    let mut claims = okta_base_token(json!({"email_verified": true}));
    merge_userinfo(
        &mut claims,
        userinfo(json!({"sub": "00u1abcd", "email": "x@acme.example", "email_verified": false})),
        None,
    )
    .unwrap();
    assert_eq!(claims.email_verified, Some(false));
    let mut claims = okta_base_token(json!({"email_verified": true}));
    merge_userinfo(
        &mut claims,
        userinfo(json!({"sub": "00u1abcd", "email": "x@acme.example", "email_verified": true})),
        None,
    )
    .unwrap();
    assert_eq!(claims.email_verified, Some(true));

    // Same address, different case: applied.
    let mut claims = okta_base_token(json!({"email": "a@acme.example"}));
    merge_userinfo(
        &mut claims,
        userinfo(json!({"sub": "00u1abcd", "email": "A@ACME.example", "email_verified": true})),
        None,
    )
    .unwrap();
    assert_eq!(claims.email_verified, Some(true));
}

#[test]
fn userinfo_subject_mismatch_is_rejected_and_nothing_is_merged() {
    let mut claims = okta_base_token(json!({}));
    let mut forged = okta_userinfo();
    forged["sub"] = json!("00u-someone-else");
    assert!(matches!(
        merge_userinfo(&mut claims, userinfo(forged), Some("groups")),
        Err(OidcError::UserinfoSubjectMismatch)
    ));
    assert!(claims.email.is_none() && claims.email_verified.is_none());
    assert!(claims.groups.is_empty());
    // Case and whitespace differences are mismatches too (exact compare).
    for sub in ["00U1ABCD", " 00u1abcd", ""] {
        let mut claims = okta_base_token(json!({}));
        let mut info = okta_userinfo();
        info["sub"] = json!(sub);
        assert!(merge_userinfo(&mut claims, userinfo(info), None).is_err(), "{sub:?}");
    }
    // A userinfo body with no `sub` at all does not even parse.
    assert!(serde_json::from_value::<UserInfoClaims>(json!({"email": "a@b.example"})).is_err());
}

#[test]
fn email_verified_string_forms_are_accepted_and_junk_is_absent() {
    for (raw, expected) in [
        (json!(true), Some(true)),
        (json!("true"), Some(true)),
        (json!("FALSE"), Some(false)),
        (json!(1), None),
        (json!("yes"), None),
        (Value::Null, None),
    ] {
        let info = userinfo(json!({"sub": "s", "email_verified": raw}));
        assert_eq!(info.email_verified, expected, "{raw}");
    }
}

// ---------------------------------------------------------------- groups

#[test]
fn groups_come_from_userinfo_only_when_the_id_token_lacks_the_claim() {
    // Okta "Userinfo / id_token request" groups claim: only in userinfo.
    let mut claims = okta_base_token(json!({}));
    merge_userinfo(&mut claims, userinfo(okta_userinfo()), Some("groups")).unwrap();
    assert_eq!(
        groups_from_validated_claims(&claims, Some("groups")).unwrap(),
        vec!["nano-analysts"]
    );

    // An explicitly empty ID-token groups claim is an assertion: kept.
    let mut claims = okta_base_token(json!({"groups": []}));
    merge_userinfo(&mut claims, userinfo(okta_userinfo()), Some("groups")).unwrap();
    assert!(claims.groups.is_empty());

    // Configured claim is `roles`: userinfo `groups` is not read.
    let mut claims = okta_base_token(json!({}));
    merge_userinfo(&mut claims, userinfo(okta_userinfo()), Some("roles")).unwrap();
    assert!(claims.groups.is_empty() && claims.roles.is_empty());

    // Unsupported claim name: nothing taken (still refused later).
    let mut claims = okta_base_token(json!({}));
    merge_userinfo(&mut claims, userinfo(okta_userinfo()), Some("department")).unwrap();
    assert!(claims.groups.is_empty());
}

/// NAN-5266 L3: membership comes from userinfo only for an explicitly
/// configured group claim. Unset, the ID token is the only source.
#[test]
fn unset_group_claim_never_reads_membership_from_userinfo() {
    let mut claims = okta_base_token(json!({"roles": ["viewer"]}));
    merge_userinfo(&mut claims, userinfo(okta_userinfo()), None).unwrap();
    assert!(claims.groups.is_empty());
    assert_eq!(groups_from_validated_claims(&claims, None).unwrap(), vec!["viewer"]);

    // Neither claim in the ID token: still nothing from userinfo.
    let mut claims = okta_base_token(json!({}));
    let mut info = okta_userinfo();
    info["roles"] = json!(["r"]);
    merge_userinfo(&mut claims, userinfo(info), None).unwrap();
    assert!(claims.groups.is_empty() && claims.roles.is_empty());
    assert!(groups_from_validated_claims(&claims, None).unwrap().is_empty());
    // The rest of the merge still happened.
    assert_eq!(claims.email_verified, Some(true));
}

#[test]
fn malformed_or_oversized_userinfo_groups_are_ignored() {
    for bad in [
        json!("nano-admins"),
        json!([1, 2]),
        json!({"0": "nano-admins"}),
        Value::Array((0..2049).map(|i| json!(format!("g{i}"))).collect()),
    ] {
        let mut claims = okta_base_token(json!({}));
        let mut info = okta_userinfo();
        info["groups"] = bad;
        merge_userinfo(&mut claims, userinfo(info), Some("groups")).unwrap();
        assert!(claims.groups.is_empty());
        assert!(!claims.asserts("groups"));
        // The rest of the merge still happened.
        assert_eq!(claims.email_verified, Some(true));
    }
}

// ---------------------------------------------------------------- when / where

#[test]
fn userinfo_is_used_only_for_generic_issuers_missing_email_claims() {
    assert!(needs_userinfo(&okta_base_token(json!({}))));
    assert!(needs_userinfo(&okta_base_token(json!({"email": "a@acme.example"}))));
    assert!(needs_userinfo(&okta_base_token(json!({"email_verified": true}))));
    assert!(!needs_userinfo(&okta_base_token(
        json!({"email": "a@acme.example", "email_verified": false})
    )));
    // Google and Microsoft keep their existing paths, even with no email.
    for issuer in [
        GOOGLE,
        ENTRA_ISSUER,
        "https://login.microsoftonline.com/common/v2.0",
        "https://sts.windows.net/11111111-1111-4111-8111-111111111111/",
    ] {
        let mut c = token(issuer, json!({}));
        c.email = None;
        assert!(!needs_userinfo(&c), "{issuer}");
    }
}

#[test]
fn userinfo_endpoint_must_be_https_on_the_issuer_host() {
    for ok in [
        "https://acme.okta.com/oauth2/default/v1/userinfo",
        "https://acme.okta.com/oauth2/v1/userinfo",
        "https://ACME.okta.com:443/oauth2/default/v1/userinfo",
    ] {
        assert!(userinfo_url(OKTA, ok).is_ok(), "{ok}");
    }
    for bad in [
        "http://acme.okta.com/oauth2/default/v1/userinfo",
        "https://evil.example/userinfo",
        "https://acme.okta.com.evil.example/userinfo",
        "https://evil.acme.okta.com/userinfo",
        "https://acme.okta.com:8443/userinfo",
        "https://user:pw@acme.okta.com/userinfo",
        "https://acme.okta.com/userinfo#frag",
        "file:///etc/passwd",
        "not a url",
    ] {
        assert!(
            matches!(userinfo_url(OKTA, bad), Err(OidcError::UserinfoUnavailable(_))),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn pinned_fetch_refuses_before_any_request_for_a_bad_endpoint() {
    // No network: every case fails in URL / SSRF validation.
    for (issuer, endpoint, token) in [
        (OKTA, "https://evil.example/userinfo", "t"),
        (OKTA, "http://acme.okta.com/oauth2/default/v1/userinfo", "t"),
        (OKTA, "https://acme.okta.com/oauth2/default/v1/userinfo", ""),
        ("https://127.0.0.1", "https://127.0.0.1/userinfo", "t"),
        ("https://169.254.169.254", "https://169.254.169.254/userinfo", "t"),
    ] {
        assert!(
            matches!(
                fetch_userinfo_pinned(issuer, endpoint, token).await,
                Err(OidcError::UserinfoUnavailable(_))
            ),
            "{endpoint}"
        );
    }
}

// ---------------------------------------------------------------- mock provider

/// A mock Okta authorization server: the validated ID token carries base
/// claims only; userinfo (bearer-authenticated) carries email,
/// email_verified, profile and groups. The completed claims are admitted.
#[tokio::test]
async fn mock_okta_id_token_without_email_is_completed_from_userinfo() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/default/v1/userinfo"))
        .and(header("authorization", "Bearer access-token-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json;charset=UTF-8")
                .set_body_json(okta_userinfo()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let issuer = format!("{}/oauth2/default", server.uri());
    let mut claims = okta_base_token(json!({"iss": issuer}));
    let provider_policy = SsoAccessPolicy::default();

    // Before: exactly the reported failure.
    assert!(!provider_policy.verifies_email(&claims));

    assert!(needs_userinfo(&claims));
    let url = url::Url::parse(&format!("{issuer}/v1/userinfo")).unwrap();
    let info = fetch_userinfo(&Client::new(), url, "access-token-1").await.unwrap();
    merge_userinfo(&mut claims, info, Some("groups")).unwrap();

    assert!(provider_policy.verifies_email(&claims));
    assert_eq!(claims.email.as_deref(), Some("Analyst@Acme.example"));
    assert_eq!(
        groups_from_validated_claims(&claims, Some("groups")).unwrap(),
        vec!["nano-analysts"]
    );
    let identity = OidcAssertedIdentity {
        issuer: claims.iss.clone(),
        subject: claims.sub.clone(),
        email: claims.email.clone(),
        email_verified: provider_policy.verifies_email(&claims),
    };
    assert_eq!(identity.audit_actor(), "Analyst@Acme.example");
}

#[tokio::test]
async fn mock_userinfo_for_another_subject_is_refused() {
    let server = MockServer::start().await;
    let mut body = okta_userinfo();
    body["sub"] = json!("00u-other");
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    let mut claims = okta_base_token(json!({}));
    let url = url::Url::parse(&format!("{}/userinfo", server.uri())).unwrap();
    let info = fetch_userinfo(&Client::new(), url, "t").await.unwrap();
    assert!(matches!(
        merge_userinfo(&mut claims, info, Some("groups")),
        Err(OidcError::UserinfoSubjectMismatch)
    ));
}

#[tokio::test]
async fn unusable_userinfo_responses_are_unavailable_not_fatal() {
    let big = json!({"sub": "00u1abcd", "pad": "x".repeat(USERINFO_MAX_BYTES)});
    for response in [
        ResponseTemplate::new(401).set_body_json(json!({"error": "invalid_token"})),
        ResponseTemplate::new(200)
            .insert_header("content-type", "application/jwt")
            .set_body_string("eyJhbGciOiJSUzI1NiJ9.e30.sig"),
        ResponseTemplate::new(200)
            .insert_header("content-type", "text/html")
            .set_body_string("<html>login</html>"),
        ResponseTemplate::new(200)
            .insert_header("content-type", "application/json")
            .set_body_string("not json"),
        ResponseTemplate::new(200).set_body_json(big),
        ResponseTemplate::new(302).insert_header("location", "https://evil.example/userinfo"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET")).respond_with(response).mount(&server).await;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let url = url::Url::parse(&format!("{}/userinfo", server.uri())).unwrap();
        assert!(matches!(
            fetch_userinfo(&client, url, "t").await,
            Err(OidcError::UserinfoUnavailable(_))
        ));
    }
}

// ---------------------------------------------------------------- verified domains

#[test]
fn generic_oidc_verified_domains_are_an_admin_assertion() {
    let policy = SsoAccessPolicy {
        verified_domains: vec!["acme.example".into()],
        ..Default::default()
    };
    // No email_verified at all: trusted by assertion.
    let mut c = token(OKTA, json!({"email": "analyst@acme.example"}));
    assert!(policy.verifies_email(&c));
    // Other domains, subdomains and malformed addresses are not.
    for email in [
        "analyst@evil.example",
        "analyst@sub.acme.example",
        "analyst@acme.example.evil",
        "@acme.example",
        "a b@acme.example",
        "a@b@acme.example",
    ] {
        c.email = Some(email.into());
        assert!(!policy.verifies_email(&c), "{email}");
    }
    c.email = None;
    assert!(!policy.verifies_email(&c));
    // Without the option, an Okta token still needs email_verified=true.
    let c = token(OKTA, json!({"email": "analyst@acme.example"}));
    assert!(!SsoAccessPolicy::default().verifies_email(&c));
    let c = token(OKTA, json!({"email": "analyst@acme.example", "email_verified": true}));
    assert!(SsoAccessPolicy::default().verifies_email(&c));
}

#[test]
fn verified_domains_left_from_an_entra_configuration_do_not_apply_elsewhere() {
    let policy = SsoAccessPolicy {
        entra_tenant_id: Some(Uuid::parse_str(ENTRA_TENANT).unwrap()),
        verified_domains: vec!["acme.example".into()],
        ..Default::default()
    };
    let c = token(OKTA, json!({"email": "analyst@acme.example"}));
    assert!(!policy.verifies_email(&c));
}

/// NAN-5266 M1: a domain fills only an ABSENT flag; the IdP saying the
/// address is NOT verified always wins.
#[test]
fn explicit_email_verified_false_beats_a_verified_domain() {
    let policy = SsoAccessPolicy {
        verified_domains: vec!["acme.example".into()],
        ..Default::default()
    };
    let c = token(OKTA, json!({"email": "analyst@acme.example", "email_verified": false}));
    assert!(!policy.verifies_email(&c));
    // Also when the explicit false arrived from userinfo.
    let mut c = okta_base_token(json!({}));
    merge_userinfo(
        &mut c,
        userinfo(json!({"sub": "00u1abcd", "email": "analyst@acme.example", "email_verified": false})),
        None,
    )
    .unwrap();
    assert!(!policy.verifies_email(&c));
}

/// NAN-5266 M2: public suffixes and free-mail providers can never be
/// verified domains.
#[test]
fn verified_domains_refuse_public_suffixes_and_free_mail() {
    for bad in [
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
        "yahoo.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com",
        "gmx.de", "mail.ru", "yandex.ru", "zoho.com", "qq.com", "163.com",
        // Country variants of free-mail brands.
        "hotmail.fr", "yahoo.co.uk", "live.com.au", "gmx.at", "outlook.de",
        // Public suffixes.
        "co.uk", "com.au", "ac.jp", "org.nz", "github.io", "herokuapp.com", "blogspot.com",
    ] {
        let policy = SsoAccessPolicy { verified_domains: vec![bad.into()], ..Default::default() };
        let err = policy.validate().expect_err(bad);
        assert!(err.contains("free email") || err.contains("public suffix"), "{bad}: {err}");
    }
    // A refused domain already stored (written before this validation) is
    // never trusted at sign-in either.
    let legacy = SsoAccessPolicy { verified_domains: vec!["gmail.com".into()], ..Default::default() };
    assert!(!legacy.verifies_email(&token(OKTA, json!({"email": "ceo@gmail.com"}))));
    for ok in ["acme.example", "corp.co.uk", "example.com.au", "mail.acme.example", "acme.com"] {
        let policy = SsoAccessPolicy { verified_domains: vec![ok.into()], ..Default::default() };
        assert!(policy.validate().is_ok(), "{ok}");
    }
}

/// NAN-5266 L2: every Microsoft identity host is recognised, and verified
/// domains on a Microsoft issuer need the tenant ID (nOAuth).
#[test]
fn microsoft_issuers_are_recognised_and_need_a_tenant_for_domains() {
    for issuer in [
        "https://login.microsoftonline.com/common/v2.0",
        "https://login.microsoftonline.us/11111111-1111-4111-8111-111111111111/v2.0",
        "https://login.partner.microsoftonline.cn/x/v2.0",
        "https://login.chinacloudapi.cn/x/v2.0",
        "https://sts.windows.net/11111111-1111-4111-8111-111111111111/",
        "https://contoso.b2clogin.com/tfp/x/v2.0/",
        "https://contoso.ciamlogin.com/x/v2.0",
        "https://LOGIN.MICROSOFTONLINE.COM/x/v2.0",
    ] {
        assert!(is_microsoft_issuer(issuer), "{issuer}");
        let mut c = token(issuer, json!({}));
        c.email = None;
        assert!(!needs_userinfo(&c), "{issuer}");
        // Generic domain trust never applies to a Microsoft issuer.
        let domains = SsoAccessPolicy {
            verified_domains: vec!["example.com".into()],
            ..Default::default()
        };
        assert!(!domains.verifies_email(&token(issuer, json!({}))), "{issuer}");
        assert!(domains.validate_for_issuer(issuer).is_err(), "{issuer}");
        let with_tenant = SsoAccessPolicy {
            entra_tenant_id: Some(Uuid::parse_str(ENTRA_TENANT).unwrap()),
            ..domains
        };
        assert!(with_tenant.validate_for_issuer(issuer).is_ok(), "{issuer}");
    }
    for not_microsoft in [
        OKTA,
        GOOGLE,
        "https://login.microsoftonline.com.evil.example/x",
        "https://b2clogin.com.evil.example/x",
        "https://evilb2clogin.com/x",
    ] {
        assert!(!is_microsoft_issuer(not_microsoft), "{not_microsoft}");
    }
    let domains = SsoAccessPolicy {
        verified_domains: vec!["example.com".into()],
        ..Default::default()
    };
    assert!(domains.validate_for_issuer(OKTA).is_ok());
}

fn provider_with(policy: SsoAccessPolicy, group_claim: Option<&str>) -> OidcProvider {
    OidcProvider {
        id: Uuid::new_v4(),
        name: "Okta".into(),
        slug: "okta".into(),
        issuer: OKTA.into(),
        client_id: "client".into(),
        client_secret_encrypted: vec![],
        scopes: vec!["openid".into(), "email".into()],
        group_claim: group_claim.map(str::to_string),
        enabled: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        access_policy: policy,
        google_service_account_encrypted: None,
    }
}

/// NAN-5266 H1: `email_verified: true` with no `email` claim never verifies
/// a `preferred_username` stand-in, and userinfo never supplies the
/// username while there is no email.
#[test]
fn a_verified_flag_never_vouches_for_a_username_stand_in() {
    let domains = SsoAccessPolicy {
        verified_domains: vec!["corp.example".into()],
        ..Default::default()
    };
    // The username offered by userinfo: not taken, no address at all.
    let mut claims = okta_base_token(json!({"email_verified": true}));
    merge_userinfo(
        &mut claims,
        userinfo(json!({"sub": "00u1abcd", "preferred_username": "admin@corp.example"})),
        Some("groups"),
    )
    .unwrap();
    assert!(claims.preferred_username.is_none());
    assert!(matches!(
        oidc_user_from_claims(&claims, &provider_with(domains.clone(), Some("groups"))),
        Err(OidcError::MissingEmail)
    ));

    // The username in the ID token itself: used as the address, never verified.
    let claims = okta_base_token(json!({
        "email_verified": true, "preferred_username": "admin@corp.example"
    }));
    for policy in [SsoAccessPolicy::default(), domains] {
        assert!(!policy.verifies_email(&claims));
        let who = oidc_user_from_claims(&claims, &provider_with(policy, None)).unwrap();
        assert_eq!(who.email, "admin@corp.example");
        assert!(!who.email_verified);
    }
    // A real, verified email is still verified.
    let claims = okta_base_token(json!({"email": "a@corp.example", "email_verified": true}));
    let who = oidc_user_from_claims(&claims, &provider_with(SsoAccessPolicy::default(), None))
        .unwrap();
    assert!(who.email_verified);
    // Blank email never verifies.
    let claims = okta_base_token(json!({"email": " ", "email_verified": true}));
    assert!(!SsoAccessPolicy::default().verifies_email(&claims));
}

// ---------------------------------------------------------------- regressions

#[test]
fn google_behaviour_is_unchanged() {
    let domains = SsoAccessPolicy {
        verified_domains: vec!["example.com".into()],
        ..Default::default()
    };
    // Google needs email_verified=true; verified domains never apply.
    let c = token(GOOGLE, json!({}));
    assert!(!SsoAccessPolicy::default().verifies_email(&c));
    assert!(!domains.verifies_email(&c));
    let c = token(GOOGLE, json!({"email_verified": false}));
    assert!(!domains.verifies_email(&c));
    let c = token(GOOGLE, json!({"email_verified": true}));
    assert!(SsoAccessPolicy::default().verifies_email(&c));
    assert!(!needs_userinfo(&token(GOOGLE, json!({}))));
}

#[test]
fn entra_behaviour_is_unchanged() {
    let tid = Uuid::parse_str(ENTRA_TENANT).unwrap();
    let with_tenant = SsoAccessPolicy {
        entra_tenant_id: Some(tid),
        verified_domains: vec!["example.com".into()],
        ..Default::default()
    };
    let without_tenant = SsoAccessPolicy {
        verified_domains: vec!["example.com".into()],
        ..Default::default()
    };
    let c = token(ENTRA_ISSUER, json!({"tid": ENTRA_TENANT}));
    assert!(with_tenant.verifies_email(&c));
    // The generic option does not apply to Entra: the tenant is still required.
    assert!(!without_tenant.verifies_email(&c));
    assert!(token(ENTRA_ISSUER, json!({"tid": ENTRA_TENANT, "xms_edov": true})).verified_email());
    // Microsoft issuers without a bound tenant never get the generic option.
    for issuer in [
        "https://login.microsoftonline.com/common/v2.0",
        "https://sts.windows.net/11111111-1111-4111-8111-111111111111/",
    ] {
        let c = token(issuer, json!({"tid": ENTRA_TENANT}));
        assert!(!without_tenant.verifies_email(&c), "{issuer}");
    }
    assert!(!needs_userinfo(&token(ENTRA_ISSUER, json!({"tid": ENTRA_TENANT}))));
}

#[test]
fn validated_value_records_which_claims_the_token_carried() {
    let c = token(OKTA, json!({"groups": []}));
    assert!(c.asserts("groups") && c.asserts("email") && !c.asserts("roles"));
    // Deserializing without from_validated_value records nothing.
    let raw: IdTokenClaims = serde_json::from_value(json!({
        "iss": OKTA, "sub": "s", "aud": "c", "exp": 1, "iat": 1, "groups": ["g"]
    }))
    .unwrap();
    assert!(raw.asserted_claims.is_empty());
}
