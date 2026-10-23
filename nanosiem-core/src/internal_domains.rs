// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tenant "Internal domains" (NAN-3226).
//!
//! A name under an internal DNS suffix is an internal HOST, never an internet
//! DOMAIN: it is not a domain prevalence / rarity artifact, not a domain-typed
//! risk object, not labelled an external domain by entity typing, and never
//! sent to an external TI / WHOIS / passive-DNS provider. IOC matching is
//! unaffected (an explicit indicator still matches).
//!
//! The effective list is the built-in [`BUILTIN_INTERNAL_SUFFIXES`] (the
//! NAN-3213 / migration-111 TLD list) UNIONED with the tenant's own suffixes.
//! Tenant suffixes may be multi-label (`corp.example.com`) and may be
//! low-volume public TLDs a company plausibly uses internally (`prod`,
//! `cloud`): that is the point of a per-tenant list.
//!
//! The list is a detection-blinding lever (NAN-3230): every name under a
//! listed suffix loses domain rarity, domain risk typing and external TI /
//! WHOIS enrichment, attacker-registered ones included. So:
//!
//! * high-volume public suffixes are REFUSED ([`refusal_reason`]): the
//!   [`REFUSED_PUBLIC_TLDS`] gTLDs (`com`, `net`, `io`, `app`, ...), every
//!   bare ccTLD (`uk`, `de`) and every multi-label public suffix under one of
//!   those (`co.uk`, `com.au`, `github.io`, `workers.dev`). Refused entries
//!   are also dropped on READ ([`InternalDomains::with_tenant`]), so a list
//!   stored before the refusal existed never blinds anything;
//! * every other public suffix (`cloud`, `prod`) is accepted with a warning
//!   ([`public_suffix_warning_text`]);
//! * every change notifies the tenant's `settings:system` holders
//!   ([`InternalDomainsChange`]).
//!
//! Matching is on DNS label boundaries: suffix `prod` matches `prod`,
//! `db1.prod` and `db1.prod.`, never `myprod.com` or `db1.myprod`.

use serde::{Deserialize, Serialize};

/// Built-in internal / non-public suffixes, always internal for every tenant.
/// Dedicated parity: `clickhouse/111_filter_internal_tlds_domain_prevalence.sql`.
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

/// Upper bound on tenant suffixes (keeps the distributed config file small and
/// the per-name check cheap).
pub const MAX_TENANT_SUFFIXES: usize = 256;

/// Upper bound on one suffix (a DNS name is at most 253 octets).
pub const MAX_SUFFIX_LEN: usize = 253;

/// Why a tenant suffix was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SuffixError {
    #[error("suffix is empty")]
    Empty,
    #[error("suffix `{0}` is longer than 253 characters")]
    TooLong(String),
    #[error("suffix `{0}` is not a DNS name (letters, digits, hyphens and dots; no empty labels)")]
    Invalid(String),
    #[error("suffix `{0}` is an IP address, not a DNS suffix")]
    IpAddress(String),
    #[error("at most {MAX_TENANT_SUFFIXES} suffixes may be configured")]
    TooMany,
}

/// Normalize one entered suffix: trim, lowercase, drop a leading `*.` / `.`
/// and a trailing root dot, then validate it as a DNS name. `*.Corp.Example.COM.`
/// becomes `corp.example.com`.
pub fn normalize_suffix(raw: &str) -> Result<String, SuffixError> {
    let mut s = raw.trim().to_ascii_lowercase();
    if let Some(rest) = s.strip_prefix("*.") {
        s = rest.to_string();
    }
    let s = s.trim_start_matches('.').trim_end_matches('.').to_string();
    if s.is_empty() {
        return Err(SuffixError::Empty);
    }
    if s.len() > MAX_SUFFIX_LEN {
        return Err(SuffixError::TooLong(s));
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return Err(SuffixError::IpAddress(s));
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
    if !s.split('.').all(valid_label) {
        return Err(SuffixError::Invalid(s));
    }
    Ok(s)
}

/// Normalize, validate, de-duplicate and sort a tenant list. Built-in suffixes
/// are dropped (they are always applied), so the stored list is only what the
/// tenant added.
pub fn normalize_tenant_suffixes<I, S>(raw: I) -> Result<Vec<String>, SuffixError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = std::collections::BTreeSet::new();
    for item in raw {
        let suffix = normalize_suffix(item.as_ref())?;
        if !BUILTIN_INTERNAL_SUFFIXES.contains(&suffix.as_str()) {
            out.insert(suffix);
        }
    }
    if out.len() > MAX_TENANT_SUFFIXES {
        return Err(SuffixError::TooMany);
    }
    Ok(out.into_iter().collect())
}

/// Whether `host` is equal to or under `suffix` on a label boundary. Both
/// must already be lowercase; a trailing root dot on `host` is ignored.
pub fn host_has_suffix(host: &str, suffix: &str) -> bool {
    let host = host.trim_end_matches('.');
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// High-volume public gTLDs refused outright as internal suffixes (NAN-3230):
/// the bulk of the internet (and of attacker infrastructure) lives under
/// them, so listing one would switch off domain rarity, domain risk typing
/// and external enrichment for that whole namespace. Every bare ccTLD and
/// every public suffix under one of these is refused too ([`refusal_reason`]).
pub const REFUSED_PUBLIC_TLDS: &[&str] = &[
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "info", "biz", "app", "dev",
    // High-volume / heavily abused gTLDs nobody uses as an internal namespace.
    "ai", "me", "tv", "cc", "ws", "xyz", "top", "online", "site", "shop", "store", "live", "click",
    "link", "icu", "vip", "club", "page", "mobi", "name", "pro", "tech",
];

/// Why a syntactically valid suffix is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SuffixRefusal {
    /// A high-volume public gTLD (`com`, `io`, `app`, ...).
    HighVolumeTld,
    /// A bare country-code TLD (`uk`, `de`, `au`).
    CountryCodeTld,
    /// A multi-label public suffix under a refused or country-code TLD
    /// (`co.uk`, `com.au`, `github.io`).
    PublicRegistrySuffix,
}

/// One refused entry, as returned in the `422` details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RefusedSuffix {
    /// The normalized suffix.
    pub suffix: String,
    pub reason: SuffixRefusal,
    /// Human-readable explanation, safe to show inline next to the entry.
    pub message: String,
}

fn is_country_code_tld(label: &str) -> bool {
    label.len() == 2 && label.bytes().all(|b| b.is_ascii_lowercase()) && is_public_suffix(label)
}

/// Whether a NORMALIZED suffix must be refused, and why. `None` = allowed
/// (possibly with a public-suffix warning).
pub fn refusal_reason(suffix: &str) -> Option<SuffixRefusal> {
    let tld = suffix.rsplit('.').next().unwrap_or(suffix);
    let refused_tld = REFUSED_PUBLIC_TLDS.contains(&tld);
    let cc_tld = is_country_code_tld(tld);
    if !suffix.contains('.') {
        return if refused_tld {
            Some(SuffixRefusal::HighVolumeTld)
        } else if cc_tld {
            Some(SuffixRefusal::CountryCodeTld)
        } else {
            None
        };
    }
    ((refused_tld || cc_tld) && is_public_suffix(suffix))
        .then_some(SuffixRefusal::PublicRegistrySuffix)
}

fn refusal_message(suffix: &str, reason: SuffixRefusal) -> String {
    let what = match reason {
        SuffixRefusal::HighVolumeTld => "is a high-volume public TLD",
        SuffixRefusal::CountryCodeTld => "is a country-code TLD",
        SuffixRefusal::PublicRegistrySuffix => "is a public registry suffix",
    };
    format!(
        "{suffix} {what}: listing it would switch off threat-intel enrichment and domain rarity \
         for every domain under it, attacker-registered ones included. Use your own domain \
         instead, such as corp.example.{suffix}."
    )
}

/// The refused entries of a normalized list (empty = all allowed).
pub fn refused_suffixes(suffixes: &[String]) -> Vec<RefusedSuffix> {
    suffixes
        .iter()
        .filter_map(|suffix| {
            refusal_reason(suffix).map(|reason| RefusedSuffix {
                suffix: suffix.clone(),
                reason,
                message: refusal_message(suffix, reason),
            })
        })
        .collect()
}

/// Why a tenant list was rejected by [`validate_tenant_suffixes`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InternalDomainsRejection {
    #[error(transparent)]
    Invalid(#[from] SuffixError),
    #[error("{}", refused_summary(.0))]
    Refused(Vec<RefusedSuffix>),
}

fn refused_summary(refused: &[RefusedSuffix]) -> String {
    let names: Vec<&str> = refused.iter().map(|r| r.suffix.as_str()).collect();
    format!(
        "refused internal domain suffix{} {}: high-volume public suffixes would blind domain \
         enrichment and rarity for everything under them; use a narrower suffix such as \
         corp.example.{}",
        if names.len() == 1 { "" } else { "es" },
        names.join(", "),
        names.first().copied().unwrap_or("com"),
    )
}

/// [`normalize_tenant_suffixes`] plus the NAN-3230 refusal: the write-path
/// validator for both the dedicated and the hosted-shared handlers.
pub fn validate_tenant_suffixes<I, S>(raw: I) -> Result<Vec<String>, InternalDomainsRejection>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let suffixes = normalize_tenant_suffixes(raw)?;
    let refused = refused_suffixes(&suffixes);
    if refused.is_empty() {
        Ok(suffixes)
    } else {
        Err(InternalDomainsRejection::Refused(refused))
    }
}

/// Inline warning for an accepted public suffix (`cloud`, `prod`).
pub fn public_suffix_warning_text(suffix: &str) -> String {
    format!(
        "Domains under .{suffix} will no longer get threat-intel enrichment or domain rarity, \
         including attacker-registered ones like evil.{suffix}. Prefer a narrower suffix such as \
         corp.example.{suffix}."
    )
}

/// What one save changed (NAN-3230 notification + audit payload).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternalDomainsChange {
    /// Suffixes in the new list but not the previous one (sorted).
    pub added: Vec<String>,
    /// Suffixes in the previous list but not the new one (sorted).
    pub removed: Vec<String>,
    /// Entries of `added` that are public suffixes (`cloud`, `prod`): the
    /// starter detection raises severity on these.
    pub public_suffixes_added: Vec<String>,
}

impl InternalDomainsChange {
    /// Diff two lists (each normalized; order-insensitive).
    pub fn between(previous: &[String], next: &[String]) -> Self {
        let before: std::collections::BTreeSet<&str> =
            previous.iter().map(String::as_str).collect();
        let after: std::collections::BTreeSet<&str> = next.iter().map(String::as_str).collect();
        let added: Vec<String> = after
            .difference(&before)
            .map(|s| (*s).to_string())
            .collect();
        let removed = before
            .difference(&after)
            .map(|s| (*s).to_string())
            .collect();
        let public_suffixes_added = added
            .iter()
            .filter(|s| is_public_suffix(s))
            .cloned()
            .collect();
        Self {
            added,
            removed,
            public_suffixes_added,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Fields merged into the `internal_domains_updated` audit details.
    pub fn audit_details(&self, previous: &[String], suffixes: &[String]) -> serde_json::Value {
        serde_json::json!({
            "previous": previous,
            "suffixes": suffixes,
            "added": self.added,
            "removed": self.removed,
            "public_suffixes_added": self.public_suffixes_added,
            "public_suffix_added": !self.public_suffixes_added.is_empty(),
        })
    }

    /// Inbox `(title, message)` naming the actor and both deltas.
    pub fn notification_text(&self, actor: &str) -> (String, String) {
        let list = |items: &[String]| {
            const SHOWN: usize = 10;
            let mut text = items
                .iter()
                .take(SHOWN)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            if items.len() > SHOWN {
                text.push_str(&format!(" and {} more", items.len() - SHOWN));
            }
            text
        };
        let mut parts = Vec::new();
        if !self.added.is_empty() {
            parts.push(format!("Added: {}.", list(&self.added)));
        }
        if !self.removed.is_empty() {
            parts.push(format!("Removed: {}.", list(&self.removed)));
        }
        if !self.public_suffixes_added.is_empty() {
            parts.push(format!(
                "Public suffixes added ({}): every domain under them, attacker-registered ones \
                 included, no longer gets threat-intel enrichment or domain rarity.",
                list(&self.public_suffixes_added)
            ));
        } else if !self.added.is_empty() {
            parts.push(
                "Names under added suffixes no longer get threat-intel enrichment or domain rarity."
                    .to_string(),
            );
        }
        (
            format!("Internal domains changed by {actor}"),
            parts.join(" "),
        )
    }

    /// Inbox metadata (not source-linked: never source-scope filtered).
    pub fn notification_metadata(&self, actor_id: uuid::Uuid, actor: &str) -> serde_json::Value {
        serde_json::json!({
            "setting": "internal_domains",
            "actor_id": actor_id.to_string(),
            "actor": actor,
            "added": self.added,
            "removed": self.removed,
            "public_suffixes_added": self.public_suffixes_added,
        })
    }
}

/// Inbox link for internal-domain change notifications (Settings → Risk).
pub const INTERNAL_DOMAINS_SETTINGS_LINK: &str = "/settings/risk";

/// The actor label an internal-domains change notification names: the user's
/// name and email when known, the API key when the change came through one.
pub fn actor_label(
    name: Option<&str>,
    email: Option<&str>,
    api_key_name: Option<&str>,
    actor_id: uuid::Uuid,
) -> String {
    let person = match (
        name.map(str::trim).filter(|s| !s.is_empty()),
        email.map(str::trim).filter(|s| !s.is_empty()),
    ) {
        (Some(name), Some(email)) if name != email => format!("{name} ({email})"),
        (Some(name), _) => name.to_string(),
        (None, Some(email)) => email.to_string(),
        (None, None) => format!("user {actor_id}"),
    };
    match api_key_name.map(str::trim).filter(|s| !s.is_empty()) {
        Some(key) => format!("{person} via API key '{key}'"),
        None => person,
    }
}

/// The effective internal-suffix set for one tenant: built-ins ∪ tenant list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternalDomains {
    /// Tenant-added suffixes only (normalized; built-ins are implicit).
    tenant: Vec<String>,
}

impl InternalDomains {
    /// Built-in suffixes only (no tenant list configured).
    pub fn builtin() -> Self {
        Self::default()
    }

    /// Built-ins plus an already-normalized tenant list. Entries that fail
    /// normalization are dropped (fail open to the built-ins, never panic on a
    /// hand-edited config file), and so are refused high-volume suffixes
    /// (NAN-3230: a list stored before the refusal, or a hand-edited file,
    /// never blinds `.com`).
    pub fn with_tenant<I, S>(suffixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut tenant: Vec<String> = suffixes
            .into_iter()
            .filter_map(|s| normalize_suffix(s.as_ref()).ok())
            .filter(|s| !BUILTIN_INTERNAL_SUFFIXES.contains(&s.as_str()))
            .filter(|s| refusal_reason(s).is_none())
            .take(MAX_TENANT_SUFFIXES)
            .collect();
        tenant.sort();
        tenant.dedup();
        Self { tenant }
    }

    /// The tenant-added suffixes (normalized, sorted).
    pub fn tenant_suffixes(&self) -> &[String] {
        &self.tenant
    }

    /// Every effective suffix: built-ins first, then the tenant list.
    pub fn all_suffixes(&self) -> impl Iterator<Item = &str> {
        BUILTIN_INTERNAL_SUFFIXES
            .iter()
            .copied()
            .chain(self.tenant.iter().map(String::as_str))
    }

    /// Whether `name` is an internal name (case-insensitive, trailing dot
    /// ignored, label-boundary match against built-ins ∪ tenant suffixes).
    pub fn is_internal(&self, name: &str) -> bool {
        let trimmed = name.trim();
        let lowered;
        let host = if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            lowered = trimmed.to_ascii_lowercase();
            lowered.as_str()
        } else {
            trimmed
        };
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            return false;
        }
        self.all_suffixes()
            .any(|suffix| host_has_suffix(host, suffix))
    }
}

/// Whether a normalized suffix is itself a known public suffix (an ICANN /
/// private Public Suffix List entry such as `cloud`, `prod`, `app` or
/// `co.uk`). High-volume ones are refused ([`refusal_reason`]); the settings
/// API warns on the rest and the UI suggests a more specific suffix
/// (`corp.example.cloud`): every name under a public suffix becomes internal
/// for this tenant.
pub fn is_public_suffix(suffix: &str) -> bool {
    psl::suffix(suffix.as_bytes())
        .is_some_and(|found| found.is_known() && found.as_bytes() == suffix.as_bytes())
}

/// Whether the saved list reached the components that read it outside the
/// API (the lake ingest workers on shared; the ClickHouse prevalence filter on
/// dedicated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InternalDomainsDistribution {
    /// Published to the tenant's workers / ClickHouse filter table.
    Published,
    /// Nothing outside the API reads the list on this deployment.
    NotApplicable,
    /// Saved, but publication failed; saving again retries.
    Failed,
}

/// `GET/PUT /api/settings/internal-domains` response (shared and dedicated).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct InternalDomainsSettings {
    /// Tenant-added suffixes (normalized, sorted; built-ins excluded).
    pub suffixes: Vec<String>,
    /// Built-in suffixes that are always internal.
    pub builtin: Vec<String>,
    /// Entries of `suffixes` that are public suffixes (`cloud`, `prod`, ...).
    pub public_suffix_warnings: Vec<String>,
    /// One explanation per `public_suffix_warnings` entry, same order.
    ///
    #[serde(default)]
    pub public_suffix_warning_messages: Vec<String>,
    pub distribution: InternalDomainsDistribution,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution_error: Option<String>,
}

impl InternalDomainsSettings {
    pub fn new(suffixes: Vec<String>, distribution: InternalDomainsDistribution) -> Self {
        let public_suffix_warnings: Vec<String> = suffixes
            .iter()
            .filter(|s| is_public_suffix(s))
            .cloned()
            .collect();
        let public_suffix_warning_messages = public_suffix_warnings
            .iter()
            .map(|s| public_suffix_warning_text(s))
            .collect();
        Self {
            suffixes,
            public_suffix_warning_messages,
            builtin: BUILTIN_INTERNAL_SUFFIXES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            public_suffix_warnings,
            distribution,
            distribution_error: None,
        }
    }
}

/// `PUT /api/settings/internal-domains` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateInternalDomainsRequest {
    pub suffixes: Vec<String>,
}

/// Dedicated storage: `system_settings.internal_domain_suffixes` (enterprise
/// migration 9011200). A deployment without the column (open core, or before
/// the migration) has no tenant list: built-ins only.
pub async fn load_dedicated_suffixes(pool: &sqlx::PgPool) -> Result<Vec<String>, sqlx::Error> {
    let stored: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT internal_domain_suffixes FROM system_settings WHERE id = 'default'",
    )
    .fetch_optional(pool)
    .await?;
    Ok(stored.unwrap_or_default())
}

/// Dedicated inbox recipients cap for one change notification.
pub const MAX_CHANGE_RECIPIENTS: i64 = 50;

/// Dedicated write path (NAN-3230): store the list and, when it changed,
/// notify every active `settings:system` holder (group → role → permission,
/// the same resolution `GroupRepository::get_user_permissions` uses), all in
/// one transaction so a stored change is never un-notified. Returns the
/// previous list, the change and the inbox rows written.
pub async fn store_dedicated_suffixes_and_notify(
    pool: &sqlx::PgPool,
    suffixes: &[String],
    actor_id: uuid::Uuid,
    actor_label: &str,
) -> Result<(Vec<String>, InternalDomainsChange, u64), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let previous: Vec<String> = sqlx::query_scalar::<_, Option<Vec<String>>>(
        "SELECT internal_domain_suffixes FROM system_settings WHERE id = 'default' FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await?
    .flatten()
    .unwrap_or_default();
    sqlx::query("UPDATE system_settings SET internal_domain_suffixes = $1, updated_at = NOW() WHERE id = 'default'")
        .bind(suffixes)
        .execute(&mut *tx)
        .await?;
    let change = InternalDomainsChange::between(&previous, suffixes);
    let mut notified = 0;
    if !change.is_empty() {
        let (title, message) = change.notification_text(actor_label);
        notified = sqlx::query(
            r#"
            INSERT INTO notifications (user_id, notification_type, title, message, link, metadata)
            SELECT admin.id, $1, $2, $3, $4, $5
              FROM (
                SELECT DISTINCT u.id FROM users u
                 WHERE u.status = 'active'
                   AND EXISTS (
                       SELECT 1 FROM user_groups ug
                         JOIN group_roles gr ON gr.group_id = ug.group_id
                         JOIN role_permissions rp ON rp.role_id = gr.role_id
                        WHERE ug.user_id = u.id AND rp.permission_id = 'settings:system')
                 ORDER BY u.id
                 LIMIT $6
              ) admin
            "#,
        )
        .bind(crate::models::notification::NotificationType::InternalDomainsChanged.to_string())
        .bind(&title)
        .bind(&message)
        .bind(INTERNAL_DOMAINS_SETTINGS_LINK)
        .bind(change.notification_metadata(actor_id, actor_label))
        .bind(MAX_CHANGE_RECIPIENTS)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }
    tx.commit().await?;
    Ok((previous, change, notified))
}

/// Dedicated readers on hot paths (finding logging, entity extraction): the
/// effective list, cached for 30 s. Any read error yields the built-ins (the
/// pre-NAN-3226 behavior), never a failed detection.
pub async fn dedicated_cached(pool: &sqlx::PgPool) -> std::sync::Arc<InternalDomains> {
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    let epoch = DEDICATED_EPOCH.load(Ordering::Relaxed);
    if let Some((at, cached_epoch, value)) =
        DEDICATED_CACHE.lock().ok().and_then(|guard| guard.clone())
    {
        if cached_epoch == epoch && at.elapsed() < Duration::from_secs(30) {
            return value;
        }
    }
    let value = match load_dedicated_suffixes(pool).await {
        Ok(suffixes) => std::sync::Arc::new(InternalDomains::with_tenant(suffixes)),
        Err(error) => {
            tracing::debug!(error = %error, "internal domains: dedicated list unavailable; built-ins only");
            std::sync::Arc::new(InternalDomains::builtin())
        }
    };
    if let Ok(mut guard) = DEDICATED_CACHE.lock() {
        *guard = Some((std::time::Instant::now(), epoch, value.clone()));
    }
    value
}

/// Drop the dedicated cache after a settings write so this process applies
/// the new list immediately (other replicas pick it up within 30 s).
pub fn invalidate_dedicated_cache() {
    DEDICATED_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

type DedicatedCacheEntry = (std::time::Instant, u64, std::sync::Arc<InternalDomains>);
static DEDICATED_CACHE: std::sync::Mutex<Option<DedicatedCacheEntry>> = std::sync::Mutex::new(None);
static DEDICATED_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_boundary_matching() {
        let d = InternalDomains::with_tenant(["prod", "corp.example.com"]);
        assert!(d.is_internal("prod"));
        assert!(d.is_internal("db1.prod"));
        assert!(d.is_internal("DB1.PROD."), "case and trailing dot");
        assert!(!d.is_internal("myprod.com"));
        assert!(!d.is_internal("db1.myprod"));
        assert!(!d.is_internal("prod.example.com"));
        assert!(d.is_internal("hr.corp.example.com"));
        assert!(d.is_internal("corp.example.com"));
        assert!(!d.is_internal("evilcorp.example.com"));
        assert!(!d.is_internal("example.com"));
        assert!(!d.is_internal(""));
        assert!(!d.is_internal("."));
    }

    #[test]
    fn union_with_builtins() {
        let builtin = InternalDomains::builtin();
        assert!(builtin.is_internal("ws-legal-066.corp.local"));
        assert!(builtin.is_internal("x.arpa"));
        assert!(!builtin.is_internal("db1.prod"));
        let tenant = InternalDomains::with_tenant(["prod"]);
        assert!(
            tenant.is_internal("ws-legal-066.corp.local"),
            "built-ins stay"
        );
        assert!(tenant.is_internal("db1.prod"), "tenant list added");
        assert_eq!(
            tenant.all_suffixes().count(),
            BUILTIN_INTERNAL_SUFFIXES.len() + 1
        );
    }

    #[test]
    fn tenant_isolation() {
        let a = InternalDomains::with_tenant(["prod"]);
        let b = InternalDomains::with_tenant(["cloud"]);
        assert!(a.is_internal("db.prod") && !a.is_internal("api.nano.cloud"));
        assert!(b.is_internal("api.nano.cloud") && !b.is_internal("db.prod"));
    }

    #[test]
    fn normalization_and_validation() {
        assert_eq!(
            normalize_suffix("  *.Corp.Example.COM. ").unwrap(),
            "corp.example.com"
        );
        assert_eq!(normalize_suffix(".prod").unwrap(), "prod");
        assert_eq!(normalize_suffix(""), Err(SuffixError::Empty));
        assert_eq!(normalize_suffix(" . "), Err(SuffixError::Empty));
        assert!(matches!(
            normalize_suffix("a..b"),
            Err(SuffixError::Invalid(_))
        ));
        assert!(matches!(
            normalize_suffix("bad host"),
            Err(SuffixError::Invalid(_))
        ));
        assert!(matches!(
            normalize_suffix("-bad.com"),
            Err(SuffixError::Invalid(_))
        ));
        assert!(matches!(
            normalize_suffix("10.0.0.1"),
            Err(SuffixError::IpAddress(_))
        ));
        assert!(matches!(
            normalize_suffix(&"a".repeat(254)),
            Err(SuffixError::TooLong(_))
        ));
        assert_eq!(
            normalize_tenant_suffixes(["Prod", "prod.", "local", "nano.cloud"]).unwrap(),
            vec!["nano.cloud".to_string(), "prod".to_string()],
            "dedup, sorted, built-ins dropped"
        );
        let many: Vec<String> = (0..=MAX_TENANT_SUFFIXES)
            .map(|i| format!("s{i}.example"))
            .collect();
        assert_eq!(normalize_tenant_suffixes(many), Err(SuffixError::TooMany));
        // A hand-edited config never panics: invalid entries are dropped.
        assert_eq!(
            InternalDomains::with_tenant(["", "a..b", "ok.example"]).tenant_suffixes(),
            ["ok.example"]
        );
    }

    #[test]
    fn public_suffix_warning() {
        assert!(is_public_suffix("cloud") && is_public_suffix("prod") && is_public_suffix("co.uk"));
        assert!(!is_public_suffix("corp.example.cloud"));
        assert!(!is_public_suffix("mycorp-internal"));
        assert!(!is_public_suffix("local"));
    }

    #[test]
    fn refuse_list_high_volume_cc_and_registry_suffixes() {
        for tld in [
            "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "info", "biz", "app",
            "dev",
        ] {
            assert_eq!(
                refusal_reason(tld),
                Some(SuffixRefusal::HighVolumeTld),
                "{tld}"
            );
        }
        for cc in ["uk", "de", "au", "jp", "us", "ca", "fr", "br"] {
            assert_eq!(
                refusal_reason(cc),
                Some(SuffixRefusal::CountryCodeTld),
                "{cc}"
            );
        }
        for registry in [
            "co.uk",
            "com.au",
            "co.jp",
            "com.br",
            "org.uk",
            "ac.uk",
            "github.io",
            "herokuapp.com",
        ] {
            assert_eq!(
                refusal_reason(registry),
                Some(SuffixRefusal::PublicRegistrySuffix),
                "{registry}"
            );
        }
        // A company's own name under a refused TLD is fine.
        for own in [
            "corp.example.com",
            "example.co.uk",
            "internal.example.io",
            "nano.dev",
        ] {
            assert_eq!(refusal_reason(own), None, "{own}");
        }
        // Private-use two-letter labels are not ccTLDs.
        assert_eq!(refusal_reason("zz"), None);
    }

    #[test]
    fn warn_list_low_volume_public_suffixes_are_allowed() {
        for warned in ["cloud", "prod", "corp-like", "office", "systems"] {
            if !is_public_suffix(warned) {
                continue; // `corp-like` is not a suffix: allowed, no warning.
            }
            assert_eq!(refusal_reason(warned), None, "{warned}");
        }
        assert_eq!(refusal_reason("cloud"), None);
        assert_eq!(refusal_reason("prod"), None);
        let settings = InternalDomainsSettings::new(
            vec!["cloud".into(), "corp.example.cloud".into()],
            InternalDomainsDistribution::Published,
        );
        assert_eq!(settings.public_suffix_warnings, ["cloud"]);
        assert_eq!(settings.public_suffix_warning_messages.len(), 1);
        let text = &settings.public_suffix_warning_messages[0];
        assert!(
            text.contains(
                "Domains under .cloud will no longer get threat-intel enrichment or domain rarity"
            ),
            "{text}"
        );
        assert!(
            text.contains("evil.cloud") && text.contains("corp.example.cloud"),
            "{text}"
        );
    }

    #[test]
    fn validate_refuses_each_entry_and_accepts_the_rest() {
        assert_eq!(
            validate_tenant_suffixes(["prod", "corp.example.com"]).unwrap(),
            vec!["corp.example.com".to_string(), "prod".to_string()]
        );
        let Err(InternalDomainsRejection::Refused(refused)) =
            validate_tenant_suffixes(["COM.", "prod", "*.co.uk", "uk"])
        else {
            panic!("expected refusal");
        };
        let names: Vec<_> = refused
            .iter()
            .map(|r| (r.suffix.as_str(), r.reason))
            .collect();
        assert_eq!(
            names,
            [
                ("co.uk", SuffixRefusal::PublicRegistrySuffix),
                ("com", SuffixRefusal::HighVolumeTld),
                ("uk", SuffixRefusal::CountryCodeTld),
            ]
        );
        assert!(refused.iter().all(|r| r.message.contains(&r.suffix)));
        assert!(matches!(
            validate_tenant_suffixes(["a..b"]),
            Err(InternalDomainsRejection::Invalid(SuffixError::Invalid(_)))
        ));
    }

    #[test]
    fn stored_refused_entries_never_take_effect() {
        let d = InternalDomains::with_tenant(["com", "co.uk", "prod"]);
        assert_eq!(d.tenant_suffixes(), ["prod"]);
        assert!(!d.is_internal("evil.com"));
        assert!(!d.is_internal("evil.co.uk"));
        assert!(d.is_internal("db1.prod"));
    }

    #[test]
    fn change_diff_and_notification_text() {
        let previous = vec!["old.example".to_string(), "prod".to_string()];
        let next = vec![
            "cloud".to_string(),
            "corp.example.com".to_string(),
            "prod".to_string(),
        ];
        let change = InternalDomainsChange::between(&previous, &next);
        assert_eq!(change.added, ["cloud", "corp.example.com"]);
        assert_eq!(change.removed, ["old.example"]);
        assert_eq!(change.public_suffixes_added, ["cloud"]);
        assert!(!change.is_empty());
        assert!(InternalDomainsChange::between(&next, &next).is_empty());

        let (title, message) = change.notification_text("Ada (ada@example.com)");
        assert_eq!(title, "Internal domains changed by Ada (ada@example.com)");
        assert!(
            message.contains("Added: cloud, corp.example.com."),
            "{message}"
        );
        assert!(message.contains("Removed: old.example."), "{message}");
        assert!(
            message.contains("Public suffixes added (cloud)"),
            "{message}"
        );

        let details = change.audit_details(&previous, &next);
        assert_eq!(details["public_suffix_added"], true);
        assert_eq!(details["added"][0], "cloud");
        let removal_only = InternalDomainsChange::between(&previous, &["prod".to_string()]);
        assert_eq!(
            removal_only.audit_details(&previous, &["prod".to_string()])["public_suffix_added"],
            false
        );
        let (_, message) = removal_only.notification_text("x");
        assert_eq!(message, "Removed: old.example.");
    }

    #[test]
    fn actor_label_shapes() {
        let id = uuid::Uuid::nil();
        assert_eq!(
            actor_label(Some("Ada"), Some("ada@x.io"), None, id),
            "Ada (ada@x.io)"
        );
        assert_eq!(
            actor_label(None, Some("ada@x.io"), Some("ci"), id),
            "ada@x.io via API key 'ci'"
        );
        assert_eq!(actor_label(Some(" "), None, None, id), format!("user {id}"));
    }
}
