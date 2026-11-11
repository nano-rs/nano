// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5220: which license an enterprise channel presents, decided without a
//! network or a database (the pool is lazy and never connected).
use super::*;
use crate::content_bundle::credential::{CredentialLookup, CredentialOrigin, CredentialSource, DistributionCredential};
use crate::schema::SchemaId;

struct Fixed(CredentialLookup);

#[async_trait]
impl CredentialSource for Fixed {
    async fn lookup(&self) -> CredentialLookup {
        self.0.clone()
    }
}

fn consumer(license: Option<Vec<u8>>, base_url: &str, source: Option<CredentialLookup>) -> ContentConsumer {
    let pool = sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://unused@127.0.0.1:1/unused").unwrap();
    let mut config = ContentConfig::from_env(true, SchemaId::Ocsf, true);
    config.license = license;
    config.base_url = base_url.into();
    struct NoApply;
    #[async_trait]
    impl ContentApplier for NoApply {
        async fn apply(&self, _: &'static Channel, _: &VerifiedContent, _: bool) -> Result<String, String> {
            Ok(String::new())
        }
    }
    ContentConsumer::new(ContentStore::new(pool), config, Arc::new(NoApply))
        .with_credential_source(source.map(|l| Arc::new(Fixed(l)) as Arc<dyn CredentialSource>))
}

fn enrollment(origin: &str) -> CredentialLookup {
    CredentialLookup::Found {
        credential: DistributionCredential::Enrollment {
            deployment_id: "deploy_1".into(),
            token: "tok".into(),
            licence_origin: origin.into(),
        },
        origin: CredentialOrigin::Online,
    }
}

#[tokio::test]
async fn the_open_edition_has_no_source_and_presents_nothing() {
    // Nothing in the open library registers a source.
    assert!(credential::credential_source().is_none());
    let c = consumer(None, DEFAULT_BASE_URL, None);
    let err = c.enterprise_credential().await.unwrap_err();
    assert!(err.contains("no license installed"), "{err}");
    // And it never subscribes to a license-routed channel at all.
    for profile in [SchemaId::Ocsf, SchemaId::Udm] {
        assert!(channels::subscribed(profile, false).iter().all(|c| c.route == Route::Open));
    }
}

#[tokio::test]
async fn the_env_file_override_wins_over_the_installed_licence() {
    let installed = CredentialLookup::Found {
        credential: DistributionCredential::SignedLicense(b"installed".to_vec()),
        origin: CredentialOrigin::Installed,
    };
    let c = consumer(Some(b"file".to_vec()), DEFAULT_BASE_URL, Some(installed.clone()));
    assert_eq!(
        c.enterprise_credential().await.unwrap(),
        (DistributionCredential::SignedLicense(b"file".to_vec()), CredentialOrigin::File)
    );
    let c = consumer(None, DEFAULT_BASE_URL, Some(installed));
    assert_eq!(c.enterprise_credential().await.unwrap().1, CredentialOrigin::Installed);
}

#[tokio::test]
async fn the_enrollment_token_goes_only_to_its_licence_server() {
    let c = consumer(None, DEFAULT_BASE_URL, Some(enrollment("https://api.nano.rs")));
    assert_eq!(c.enterprise_credential().await.unwrap().1, CredentialOrigin::Online);
    for elsewhere in ["https://mirror.example.com/api/content/v1", "http://api.nano.rs/api/content/v1"] {
        let c = consumer(None, elsewhere, Some(enrollment("https://api.nano.rs")));
        let err = c.enterprise_credential().await.unwrap_err();
        assert!(err.contains("only to its license server"), "{elsewhere}: {err}");
    }
}

#[tokio::test]
async fn a_missing_licence_reason_is_passed_through() {
    let c = consumer(None, DEFAULT_BASE_URL, Some(CredentialLookup::Missing { reason: "say why".into() }));
    assert_eq!(c.enterprise_credential().await.unwrap_err(), "say why");
    assert_eq!(
        LicenseAvailability::of(&c.enterprise_credential().await),
        LicenseAvailability { available: false, origin: None, reason: Some("say why".into()) }
    );
}
