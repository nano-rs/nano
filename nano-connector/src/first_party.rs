// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reviewed bundled collector and identity specs. A feed request selects one by name and
//! never supplies code; the spec is pinned on the feed by sha256.
//!
//! Each entry names the credentials-store provider its vendor secret lives
//! under (`cloud_credentials.provider`, migration 298), so a feed can only
//! bind a credential made for that vendor.

use crate::service::admin::{AdminError, FeedPlan, plan_from_spec};

/// A bundled spec: slug, display name, credential provider, YAML.
pub struct BundledSpec {
    pub slug: &'static str,
    pub display_name: &'static str,
    pub credential_provider: &'static str,
    pub yaml: &'static str,
}

pub const SPECS: &[BundledSpec] = &[
    BundledSpec {
        slug: "okta_system_log",
        display_name: "Okta System Log",
        credential_provider: "okta",
        yaml: include_str!("../specs/okta_system_log.yaml"),
    },
    BundledSpec {
        slug: "google_workspace",
        display_name: "Google Workspace audit (service account, domain-wide delegation)",
        credential_provider: "google_workspace",
        yaml: include_str!("../specs/google_workspace.yaml"),
    },
    BundledSpec {
        slug: "slack",
        display_name: "Slack access logs",
        credential_provider: "slack",
        yaml: include_str!("../specs/slack.yaml"),
    },
    BundledSpec {
        slug: "netskope",
        display_name: "Netskope events (data export iterator)",
        credential_provider: "saas_api",
        yaml: include_str!("../specs/netskope.yaml"),
    },
    // G22: identity directory syncs (`kind: identity`): users and group
    // memberships into the user directory, no parser lane.
    BundledSpec {
        slug: "okta_users",
        display_name: "Okta directory (users, groups, admin roles)",
        credential_provider: "okta",
        yaml: include_str!("../specs/okta_users.yaml"),
    },
    BundledSpec {
        slug: "entra_directory",
        display_name: "Microsoft Entra ID directory (users, groups, directory roles)",
        credential_provider: "saas_api",
        yaml: include_str!("../specs/entra_directory.yaml"),
    },
];

pub fn get(name: &str) -> Result<&'static BundledSpec, AdminError> {
    SPECS.iter().find(|s| s.slug == name).ok_or_else(|| AdminError::CatalogNotFound(name.into()))
}

pub fn plan(name: &str) -> Result<FeedPlan, AdminError> {
    let spec = get(name)?;
    plan_from_spec(spec.slug, spec.yaml)
}
