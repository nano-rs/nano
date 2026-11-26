// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reviewed bundled collector and identity specs. A feed request selects one by name and
//! never supplies code; the spec is pinned on the feed by sha256.
//!
//! Each entry names the credentials-store provider its vendor secret lives
//! under (`cloud_credentials.provider`, migration 298), so a feed can only
//! bind a credential made for that vendor.

use crate::service::admin::{AdminError, FeedPlan, plan_from_spec};

/// A bundled spec: slug, display name, credential provider, YAML, and the
/// form and parser metadata the feed UI and the lane setup read (NAN-5903).
///
/// The metadata lives here, not in the YAML: a feed pins its spec by sha256,
/// so a label edit in the YAML would flag every existing feed with a spec
/// update.
pub struct BundledSpec {
    pub slug: &'static str,
    pub display_name: &'static str,
    pub credential_provider: &'static str,
    pub yaml: &'static str,
    /// Catalog parser names (`parser.yaml` `name`) that parse this
    /// connector's events, first match wins: the OCSF parser, then the
    /// legacy one. A feed whose lanes have no log source gets one from the
    /// first of these the parser catalog holds. Empty for an identity spec
    /// (no lane, no parser).
    pub parsers: &'static [&'static str],
    /// Plain-English label, help and known values for each config key.
    pub config_fields: &'static [FieldInfo],
    /// Plain-English label and help for each credential field.
    pub credential_fields: &'static [FieldInfo],
}

/// How a form shows one config or credential key.
pub struct FieldInfo {
    pub key: &'static str,
    /// Short plain-English label ("Admin email to act as").
    pub label: &'static str,
    /// One or two plain sentences for the tooltip.
    pub help: &'static str,
    /// An example value, shown greyed out in an empty field.
    pub placeholder: Option<&'static str>,
    /// Known values for a comma-separated list (a fan-out such as
    /// `STREAMS`): the form shows a multi-select of these, with the
    /// `default` ones ticked. Empty for a free-text field.
    pub choices: &'static [Choice],
}

/// One known value of a list field.
pub struct Choice {
    pub value: &'static str,
    pub label: &'static str,
    /// Ticked on a new feed.
    pub default: bool,
}

const fn field(key: &'static str, label: &'static str, help: &'static str, placeholder: Option<&'static str>) -> FieldInfo {
    FieldInfo { key, label, help, placeholder, choices: &[] }
}

const fn choice(value: &'static str, label: &'static str, default: bool) -> Choice {
    Choice { value, label, default }
}

const OKTA_DOMAIN: FieldInfo = field(
    "OKTA_DOMAIN",
    "Okta domain",
    "Your Okta org address, without https://. For example acme.okta.com.",
    Some("acme.okta.com"),
);

const OKTA_API_TOKEN: FieldInfo = field(
    "API_TOKEN",
    "Okta API token",
    "A token from a read-only Okta admin. Create it in the Okta Admin Console under Security, then API, then Tokens.",
    None,
);

const PRIVILEGED_GROUPS: FieldInfo = field(
    "PRIVILEGED_GROUPS",
    "Admin groups",
    "Optional. A comma-separated list of group names or IDs. Members of these groups are marked as privileged users.",
    Some("Domain Admins, IT Admins"),
);

const ALLOW_SHRINK: FieldInfo = field(
    crate::identity::ALLOW_SHRINK_CONFIG,
    "Allow a full sync to drop more than half the directory",
    "Off by default. When off, a full sync that would remove more than half of the users is refused and the directory stays as it was.",
    None,
);

/// Google Reports API applications (`applicationName`). Ticked: the ones
/// a security team reads first.
const GWS_APPLICATIONS: &[Choice] = &[
    choice("login", "Sign-ins", true),
    choice("admin", "Admin console changes", true),
    choice("token", "App access (OAuth tokens)", true),
    choice("drive", "Drive file activity", true),
    choice("groups", "Groups changes", true),
    choice("saml", "SAML app sign-ins", true),
    choice("user_accounts", "User account changes", true),
    choice("calendar", "Calendar", false),
    choice("chat", "Chat", false),
    choice("meet", "Meet", false),
    choice("mobile", "Mobile devices", false),
    choice("chrome", "Chrome browser", false),
    choice("rules", "Rules and alerts", false),
    choice("context_aware_access", "Context-aware access", false),
    choice("access_transparency", "Access Transparency", false),
    choice("groups_enterprise", "Groups for Business", false),
    choice("gcp", "Google Cloud", false),
    choice("vault", "Vault", false),
];

/// Netskope Data Export event types (`/api/v2/events/dataexport/events/<type>`).
const NETSKOPE_EVENT_TYPES: &[Choice] = &[
    choice("alert", "Alerts", true),
    choice("application", "App activity", true),
    choice("audit", "Admin audit", true),
    choice("network", "Network (private access)", false),
    choice("page", "Web pages", false),
    choice("connection", "Connections", false),
    choice("incident", "Incidents", false),
    choice("infrastructure", "Infrastructure", false),
    choice("endpoint", "Endpoint", false),
];

pub const SPECS: &[BundledSpec] = &[
    BundledSpec {
        slug: "okta_system_log",
        display_name: "Okta System Log",
        credential_provider: "okta",
        yaml: include_str!("../specs/okta_system_log.yaml"),
        parsers: &["okta_ocsf", "okta"],
        config_fields: &[OKTA_DOMAIN],
        credential_fields: &[OKTA_API_TOKEN],
    },
    BundledSpec {
        slug: "google_workspace",
        display_name: "Google Workspace audit (service account, domain-wide delegation)",
        credential_provider: "google_workspace",
        yaml: include_str!("../specs/google_workspace.yaml"),
        parsers: &["google_workspace_ocsf", "google_workspace"],
        config_fields: &[
            field(
                "ADMIN_EMAIL",
                "Admin email to act as",
                "The email of a Workspace admin. The service account reads the audit logs on this admin's behalf.",
                Some("admin@example.com"),
            ),
            FieldInfo {
                key: "STREAMS",
                label: "Which Workspace apps to collect",
                help: "Each app's audit log is collected on its own. Pick the ones you want.",
                placeholder: None,
                choices: GWS_APPLICATIONS,
            },
        ],
        credential_fields: &[
            field(
                "CLIENT_EMAIL",
                "Service account email",
                "The client_email from the service account's JSON key.",
                Some("nano@project.iam.gserviceaccount.com"),
            ),
            field(
                "PRIVATE_KEY",
                "Service account private key",
                "The private_key from the service account's JSON key.",
                None,
            ),
        ],
    },
    BundledSpec {
        slug: "slack",
        display_name: "Slack access logs",
        credential_provider: "slack",
        yaml: include_str!("../specs/slack.yaml"),
        parsers: &["slack_access_ocsf", "slack_access"],
        config_fields: &[field(
            "TEAM_ID",
            "Workspace ID",
            "Optional. Only for Enterprise Grid: the ID of the one workspace to collect. Leave it blank for a single workspace.",
            Some("T0123456789"),
        )],
        credential_fields: &[field(
            "USER_TOKEN",
            "Slack user token",
            "A user token (starts with xoxp-) from a workspace admin, with the admin scope.",
            None,
        )],
    },
    BundledSpec {
        slug: "netskope",
        display_name: "Netskope events (data export iterator)",
        credential_provider: "saas_api",
        yaml: include_str!("../specs/netskope.yaml"),
        parsers: &["netskope_ocsf", "netskope"],
        config_fields: &[
            field(
                "TENANT_HOST",
                "Netskope tenant address",
                "Your Netskope tenant host name, without https://. For example acme.goskope.com.",
                Some("acme.goskope.com"),
            ),
            field(
                "INDEX_NAME",
                "Read position name",
                "Optional. Netskope remembers how far nano has read under this name. Change it only if another tool already uses the name nano.",
                Some("nano"),
            ),
            FieldInfo {
                key: "STREAMS",
                label: "Which event types to collect",
                help: "Each event type is collected on its own. Web pages and connections can be very busy.",
                placeholder: None,
                choices: NETSKOPE_EVENT_TYPES,
            },
        ],
        credential_fields: &[field(
            "API_TOKEN",
            "Netskope API token",
            "A REST API v2 token with read access to the Data Export events endpoints.",
            None,
        )],
    },
    // G22: identity directory syncs (`kind: identity`): users and group
    // memberships into the user directory, no parser lane.
    BundledSpec {
        slug: "okta_users",
        display_name: "Okta directory (users, groups, admin roles)",
        credential_provider: "okta",
        yaml: include_str!("../specs/okta_users.yaml"),
        parsers: &[],
        config_fields: &[OKTA_DOMAIN, PRIVILEGED_GROUPS, ALLOW_SHRINK],
        credential_fields: &[OKTA_API_TOKEN],
    },
    BundledSpec {
        slug: "entra_directory",
        display_name: "Microsoft Entra ID directory (users, groups, directory roles)",
        credential_provider: "saas_api",
        yaml: include_str!("../specs/entra_directory.yaml"),
        parsers: &[],
        config_fields: &[
            field(
                "DIRECTORY_ID",
                "Directory (tenant) ID",
                "The Directory (tenant) ID from the app registration's overview page in the Entra admin center.",
                Some("00000000-0000-0000-0000-000000000000"),
            ),
            field(
                "CLIENT_ID",
                "Application (client) ID",
                "The Application (client) ID of the app registration nano signs in as.",
                Some("00000000-0000-0000-0000-000000000000"),
            ),
            PRIVILEGED_GROUPS,
            ALLOW_SHRINK,
        ],
        credential_fields: &[field(
            "CLIENT_SECRET",
            "Client secret",
            "A client secret of the app registration. It needs the User.Read.All, GroupMember.Read.All and RoleManagement.Read.Directory permissions.",
            None,
        )],
    },
];

pub fn get(name: &str) -> Result<&'static BundledSpec, AdminError> {
    SPECS.iter().find(|s| s.slug == name).ok_or_else(|| AdminError::CatalogNotFound(name.into()))
}

pub fn plan(name: &str) -> Result<FeedPlan, AdminError> {
    let spec = get(name)?;
    plan_from_spec(spec.slug, spec.yaml)
}

impl BundledSpec {
    /// The form metadata for config key `key`, if declared.
    pub fn config_field(&self, key: &str) -> Option<&'static FieldInfo> {
        self.config_fields.iter().find(|f| f.key == key)
    }

    /// The form metadata for credential field `key`, if declared.
    pub fn credential_field(&self, key: &str) -> Option<&'static FieldInfo> {
        self.credential_fields.iter().find(|f| f.key == key)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::service::admin;

    /// NAN-5903: every key a form shows has a plain-English label and help,
    /// and nothing is declared for a key the spec does not read. A new
    /// connector (or a new config key) fails here until it is described.
    #[test]
    fn every_form_field_is_described() {
        for spec in SPECS {
            let plan = plan(spec.slug).unwrap();
            let keys = admin::config_keys(&plan.spec_yaml).unwrap();
            let declared: BTreeSet<String> = spec.config_fields.iter().map(|f| f.key.to_string()).collect();
            assert_eq!(declared, keys, "{}: config field metadata must match the keys the spec reads", spec.slug);
            let creds = admin::credential_fields(&plan.spec).unwrap();
            let declared: BTreeSet<String> = spec.credential_fields.iter().map(|f| f.key.to_string()).collect();
            assert_eq!(declared, creds, "{}: credential field metadata must match the auth fields", spec.slug);
            for f in spec.config_fields.iter().chain(spec.credential_fields) {
                assert!(!f.label.is_empty() && !f.help.is_empty(), "{} {}", spec.slug, f.key);
                assert!(!f.label.contains('_') || f.label.contains(' '), "{} {}: label is a raw key", spec.slug, f.key);
                for text in [f.label, f.help] {
                    assert!(!text.contains('\u{2014}'), "{} {}: no em dashes in UI copy", spec.slug, f.key);
                }
            }
        }
    }

    /// A fan-out field lists known values, at least one ticked, and each value
    /// makes a lane the admin API accepts.
    #[test]
    fn fan_out_fields_offer_known_values() {
        for spec in SPECS {
            let plan = plan(spec.slug).unwrap();
            for f in spec.config_fields.iter().filter(|f| !f.choices.is_empty()) {
                assert!(f.choices.iter().any(|c| c.default), "{} {}: nothing ticked by default", spec.slug, f.key);
                let all: Vec<&str> = f.choices.iter().map(|c| c.value).collect();
                let mut config = serde_json::Map::new();
                for k in admin::config_keys(&plan.spec_yaml).unwrap() {
                    config.insert(k, serde_json::Value::String("x".into()));
                }
                config.insert(f.key.to_string(), serde_json::Value::String(all.join(",")));
                let lanes = admin::lanes(&plan, &config).unwrap();
                assert_eq!(lanes.len(), all.len(), "{} {}", spec.slug, f.key);
            }
        }
    }

    /// Collectors name the catalog parser that parses them; identity specs
    /// write the user directory and name none.
    #[test]
    fn collectors_name_a_parser_identity_specs_do_not() {
        for spec in SPECS {
            let plan = plan(spec.slug).unwrap();
            let identity = plan.spec.kind == crate::spec::Kind::Identity;
            assert_eq!(spec.parsers.is_empty(), identity, "{}", spec.slug);
        }
    }
}
