// SPDX-License-Identifier: AGPL-3.0-or-later

//! Namespace validation for log sources.
//!
//! Namespaces isolate identity resolution between environments with overlapping
//! private IP ranges (e.g. multiple AWS VPCs, on-prem data centers).
//!
//! Format:
//! - `default` (special — used when no isolation is required)
//! - `<provider>:<suffix>` where `provider` is one of `aws | gcp | azure | onprem`
//!   and `suffix` is non-empty and built from `[a-z0-9._\-:]` (case-insensitive).
//!
//! Examples:
//! - `aws:123456789012:vpc-abc`
//! - `gcp:my-project:prod`
//! - `onprem:dc-east`

/// Returns true when `ns` is a syntactically valid namespace.
pub fn is_valid_namespace(ns: &str) -> bool {
    if ns == "default" {
        return true;
    }

    let Some((prefix, suffix)) = ns.split_once(':') else {
        return false;
    };

    if !matches!(prefix, "aws" | "gcp" | "azure" | "onprem") {
        return false;
    }

    if suffix.is_empty() {
        return false;
    }

    suffix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        assert!(is_valid_namespace("default"));
    }

    #[test]
    fn aws_account_vpc_is_valid() {
        assert!(is_valid_namespace("aws:123456789012:vpc-abc"));
    }

    #[test]
    fn onprem_dc_is_valid() {
        assert!(is_valid_namespace("onprem:dc-east"));
    }

    #[test]
    fn gcp_project_is_valid() {
        assert!(is_valid_namespace("gcp:my-project.prod"));
    }

    #[test]
    fn azure_is_valid() {
        assert!(is_valid_namespace("azure:tenant_a"));
    }

    #[test]
    fn unknown_prefix_rejected() {
        assert!(!is_valid_namespace("digitalocean:nyc1"));
    }

    #[test]
    fn missing_colon_rejected() {
        assert!(!is_valid_namespace("awsfoo"));
    }

    #[test]
    fn empty_suffix_rejected() {
        assert!(!is_valid_namespace("aws:"));
    }

    #[test]
    fn invalid_chars_rejected() {
        assert!(!is_valid_namespace("aws:foo bar"));
        assert!(!is_valid_namespace("aws:foo/bar"));
        assert!(!is_valid_namespace("aws:foo$bar"));
    }

    #[test]
    fn empty_string_rejected() {
        assert!(!is_valid_namespace(""));
    }
}
