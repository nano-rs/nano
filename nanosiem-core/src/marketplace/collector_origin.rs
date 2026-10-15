// SPDX-License-Identifier: AGPL-3.0-or-later

//! Where a pull collector reads its events from (NAN-3762).
//!
//! A pull collector's display delivery is the API the customer connected
//! (`Pull · Microsoft Graph`), never the internal transport the connector
//! runner posts over. Every hosted feed delivers through a per-feed HEC
//! credential; that is a platform detail and must not leak into the label.

/// The vendor API a pull collector reads, from its catalog slug. A manifest
/// may declare its own `origin`; that wins when it is a usable label.
pub fn collector_origin(slug: &str, manifest_origin: Option<&str>) -> String {
    if let Some(origin) = manifest_origin.map(str::trim).filter(|o| usable(o)) {
        return origin.to_string();
    }
    let slug = slug.trim().to_ascii_lowercase();
    let has = |prefix: &str| slug == prefix || slug.starts_with(&format!("{prefix}_")) || slug.starts_with(&format!("{prefix}-"));
    let known = if ["entra", "azure_ad", "microsoft_entra", "microsoft_365", "m365", "o365", "office_365", "intune", "defender"]
        .iter()
        .any(|p| has(p))
    {
        "Microsoft Graph"
    } else if has("okta") {
        "Okta API"
    } else if has("google_workspace") || has("gws") || has("google_directory") {
        "Google Workspace Admin SDK"
    } else if has("active_directory") || has("ad") || has("ldap") {
        "Active Directory (LDAP)"
    } else if has("workday") {
        "Workday API"
    } else if has("onelogin") {
        "OneLogin API"
    } else if has("jumpcloud") {
        "JumpCloud API"
    } else if has("duo") {
        "Duo Admin API"
    } else {
        ""
    };
    if !known.is_empty() {
        return known.to_string();
    }
    let vendor = slug
        .trim_end_matches("_mock")
        .split(['_', '-'])
        .filter(|w| !w.is_empty() && !is_hec(w))
        .map(|w| {
            let mut c = w.chars();
            c.next().map(|f| f.to_uppercase().chain(c).collect::<String>()).unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ");
    if vendor.is_empty() {
        "Vendor API".into()
    } else {
        format!("{vendor} API")
    }
}

/// The delivery label a pull collector card shows.
pub fn collector_delivery_label(slug: &str, manifest_origin: Option<&str>) -> String {
    format!("Pull · {}", collector_origin(slug, manifest_origin))
}

fn is_hec(word: &str) -> bool {
    word.eq_ignore_ascii_case("hec")
}

/// A manifest origin is usable when it is non-empty, short, and does not name
/// the internal HEC delivery as a word.
fn usable(origin: &str) -> bool {
    !origin.is_empty()
        && origin.len() <= 64
        && !origin.split(|c: char| !c.is_ascii_alphanumeric()).any(is_hec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names_hec(label: &str) -> bool {
        label.split(|c: char| !c.is_ascii_alphanumeric()).any(is_hec)
    }

    #[test]
    fn identity_and_saas_collectors_show_their_vendor_api() {
        for (slug, origin) in [
            ("entra_directory", "Microsoft Graph"),
            ("entra_signin_logs", "Microsoft Graph"),
            ("azure_ad", "Microsoft Graph"),
            ("okta_system_log", "Okta API"),
            ("okta_users", "Okta API"),
            ("okta_system_log_mock", "Okta API"),
            ("google_workspace", "Google Workspace Admin SDK"),
            ("gws_admin", "Google Workspace Admin SDK"),
            ("active_directory", "Active Directory (LDAP)"),
            ("workday", "Workday API"),
            ("workday_audit", "Workday API"),
            ("onelogin", "OneLogin API"),
            ("jumpcloud_directory", "JumpCloud API"),
            ("duo_auth", "Duo Admin API"),
            ("acme_saas-audit", "Acme Saas Audit API"),
        ] {
            assert_eq!(collector_origin(slug, None), origin, "{slug}");
            assert_eq!(collector_delivery_label(slug, None), format!("Pull · {origin}"));
        }
        // Prefixes match whole words only: `adobe` is not Active Directory.
        assert_eq!(collector_origin("adobe_audit", None), "Adobe Audit API");
    }

    #[test]
    fn no_pull_collector_label_names_hec() {
        for slug in [
            "entra_directory", "okta_system_log", "google_workspace", "active_directory", "workday",
            "connector_hec", "hec", "acme_hec_logs", "", "checkpoint_firewall",
        ] {
            let label = collector_delivery_label(slug, None);
            assert!(label.starts_with("Pull · "), "{slug}: {label}");
            assert!(!names_hec(&label), "{slug}: {label}");
        }
        // A manifest origin that names HEC is ignored, not shown.
        assert_eq!(collector_origin("okta_users", Some("connector → HEC")), "Okta API");
        assert_eq!(collector_origin("okta_users", Some("  ")), "Okta API");
        // A usable manifest origin wins; vendor words containing "hec" stay.
        assert_eq!(collector_origin("acme", Some("Check Point Management API")), "Check Point Management API");
        assert_eq!(collector_origin("checkpoint_firewall", None), "Checkpoint Firewall API");
    }
}
