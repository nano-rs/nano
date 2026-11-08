// SPDX-License-Identifier: AGPL-3.0-or-later
//! Internal DNS names: hosts, never internet domains.
//!
//! A name under an internal DNS suffix is an internal HOST: it is not a domain
//! prevalence / rarity artifact and is not labelled an external domain. Every
//! edition applies the built-in [`BUILTIN_INTERNAL_SUFFIXES`] (the NAN-3213 /
//! ClickHouse 111 list). The enterprise edition adds the Settings > Risk list
//! (NAN-3226 / NAN-3230), whose validation, storage and change notifications
//! live in the enterprise-only `internal_domains_store` module; [`effective`]
//! is the one seam the shared readers call, and it returns the built-ins on
//! the open edition (no query, no column).
//!
//! Matching is on DNS label boundaries (suffix `prod` matches `prod` and
//! `db1.prod`, never `myprod.com`) over IDNA A-labels: a U-label candidate
//! (`db.bücher.corp`) and its A-label (`db.xn--bcher-kva.corp`) are the same
//! name.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Built-in internal / non-public suffixes, always internal.
/// Parity: `clickhouse/111_filter_internal_tlds_domain_prevalence.sql`.
pub const BUILTIN_INTERNAL_SUFFIXES: &[&str] = &[
    "local",
    "corp",
    "internal",
    "lan",
    "home",
    "localdomain",
    "intranet",
    "private",
    "arpa",
];

/// Upper bound on added suffixes (keeps the per-name check and the
/// ClickHouse read-time predicate cheap).
pub const MAX_TENANT_SUFFIXES: usize = 256;

/// Upper bound on one name (a DNS name is at most 253 octets).
pub const MAX_SUFFIX_LEN: usize = 253;

/// Canonical form of a DNS name for matching: trimmed, trailing root dot
/// removed, IDNA-mapped to lowercase A-labels (`Bücher.Corp.` ->
/// `xn--bcher-kva.corp`). `None` for an empty value, an IP address, or
/// anything that is not a DNS name (empty label, bad characters, a label over
/// 63 octets, a leading/trailing hyphen, over 253 octets).
pub fn canonical_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let ascii = match url::Host::parse(trimmed) {
        Ok(url::Host::Domain(domain)) => domain,
        _ => return None,
    };
    if ascii.len() > MAX_SUFFIX_LEN {
        return None;
    }
    let valid_label = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    ascii.split('.').all(valid_label).then_some(ascii)
}

/// Whether `host` is equal to or under `suffix` on a label boundary. Both
/// must already be canonical ([`canonical_host`]).
pub fn host_has_suffix(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// The effective internal-suffix set: built-ins plus any added suffixes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternalDomains {
    /// Added suffixes only (canonical, sorted; built-ins are implicit).
    tenant: Vec<String>,
}

impl InternalDomains {
    /// Built-in suffixes only.
    pub fn builtin() -> Self {
        Self::default()
    }

    /// Built-ins plus `suffixes`, each canonicalized ([`canonical_host`]).
    /// Entries that are not DNS names or are built-ins are dropped; at most
    /// [`MAX_TENANT_SUFFIXES`] are kept. Policy (which suffixes an
    /// administrator may add) is the caller's job: this is the matcher only.
    pub fn with_suffixes<I, S>(suffixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut tenant: Vec<String> = suffixes
            .into_iter()
            .filter_map(|s| canonical_host(s.as_ref().trim().trim_start_matches("*.").trim_start_matches('.')))
            .filter(|s| !BUILTIN_INTERNAL_SUFFIXES.contains(&s.as_str()))
            .collect();
        tenant.sort();
        tenant.dedup();
        tenant.truncate(MAX_TENANT_SUFFIXES);
        Self { tenant }
    }

    /// The added suffixes (canonical, sorted).
    pub fn tenant_suffixes(&self) -> &[String] {
        &self.tenant
    }

    /// Every effective suffix: built-ins first, then the added list.
    pub fn all_suffixes(&self) -> impl Iterator<Item = &str> {
        BUILTIN_INTERNAL_SUFFIXES
            .iter()
            .copied()
            .chain(self.tenant.iter().map(String::as_str))
    }

    /// Whether `name` is an internal name (case-insensitive, IDNA-equivalent,
    /// trailing dot ignored, label-boundary match against every suffix).
    pub fn is_internal(&self, name: &str) -> bool {
        let Some(host) = canonical_host(name) else {
            return false;
        };
        self.all_suffixes().any(|suffix| host_has_suffix(&host, suffix))
    }
}

impl InternalDomains {
    /// ClickHouse predicate that is true when `expr` (a hostname column
    /// expression) is NOT an internal name, using every effective suffix and
    /// the same canonical form as [`Self::is_internal`] (lowercase, IDNA
    /// A-labels, trailing dot ignored). Put it in the WHERE so internal names
    /// never consume a `DISTINCT ... LIMIT` budget. Suffixes are canonical
    /// DNS names (`[a-z0-9_.-]`) and escaped anyway.
    pub fn sql_not_internal(&self, expr: &str) -> String {
        let list = self
            .all_suffixes()
            .map(|s| format!("'{}'", crate::sql_hygiene::escape_sql_string(s)))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "NOT arrayExists(s -> endsWith(concat('.', trimRight(tryIdnaEncode(lower({expr})), '.')), concat('.', s)), [{list}])"
        )
    }
}

/// The effective list for the shared readers (prevalence lists, discovery,
/// case-entity reads, shadow investigation, enrichment): the built-ins plus,
/// on the enterprise edition, the Settings > Risk list (cached 30 s, read
/// errors fall back to the built-ins). Open edition: built-ins, no query.
pub async fn effective(pool: &sqlx::PgPool) -> Arc<InternalDomains> {
    #[cfg(feature = "enterprise")]
    {
        store::cached(pool).await
    }
    #[cfg(not(feature = "enterprise"))]
    {
        let _ = pool;
        Arc::new(InternalDomains::builtin())
    }
}

/// Enterprise-only: suffix policy (validation, public-suffix refusal and
/// warnings), storage on `system_settings`, change notifications and the
/// cached reader behind [`effective`]. Stripped from the open mirror.
#[cfg(feature = "enterprise")]
#[path = "internal_domains_store.rs"]
pub mod store;

#[cfg(test)]
#[path = "internal_domains_tests.rs"]
mod tests;
