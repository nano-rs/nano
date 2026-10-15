// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reviewed public collector specs. A request selects a name, never supplies code.
use crate::service::admin::{plan_from_catalog, AdminError, FeedPlan};
use serde_json::json;
use uuid::Uuid;

pub const SPECS: &[(&str, &str)] = &[
    (
        "okta_system_log",
        include_str!("../specs/okta_system_log.yaml"),
    ),
    ("slack", include_str!("../specs/slack.yaml")),
    // NAN-3767: directory sync (kind: identity) for dedicated deployments:
    // the self-hosted variants (vendor credentials, no hosted broker).
    ("okta_users", include_str!("../specs/okta_users.yaml")),
    ("entra_directory", include_str!("../specs/entra_directory.yaml")),
];

/// Whether a bundled spec is directory sync (`kind: identity`).
pub fn is_identity(name: &str) -> bool {
    plan(name).is_ok_and(|p| p.spec.kind == crate::spec::Kind::Identity)
}

pub fn plan(name: &str) -> Result<FeedPlan, AdminError> {
    let (_, spec) = SPECS
        .iter()
        .find(|(slug, _)| *slug == name)
        .ok_or_else(|| AdminError::CatalogNotFound(name.into()))?;
    plan_from_catalog(
        Uuid::nil(),
        name,
        &json!({
            "runtime": "connector", "connector_spec": spec,
            "connector_spec_sha256": crate::service::feed::spec_sha256(spec),
        }),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn bundled_specs_validate_and_require_no_hosted_broker() {
        for (slug, _) in super::SPECS {
            let plan = super::plan(slug).unwrap();
            assert!(!plan.spec.auth.kind.ends_with("broker"), "{slug}");
            let identity = matches!(*slug, "okta_users" | "entra_directory");
            let kind = if identity { crate::spec::Kind::Identity } else { crate::spec::Kind::Collector };
            assert_eq!(plan.spec.kind, kind, "{slug}");
            assert_eq!(super::is_identity(slug), identity, "{slug}");
        }
        assert!(super::plan("../../private").is_err());
        assert!(!super::is_identity("../../private"));
    }

    /// The shipped directory specs are the reviewed self-hosted fixtures the
    /// replay tests run (one source of truth).
    #[test]
    fn shipped_directory_specs_match_the_tested_fixtures() {
        assert_eq!(
            include_str!("../specs/okta_users.yaml"),
            include_str!("../tests/fixtures/directory/okta_users.connector.yaml")
        );
        assert_eq!(
            include_str!("../specs/entra_directory.yaml"),
            include_str!("../tests/fixtures/directory/entra_directory.connector.yaml")
        );
    }
}
