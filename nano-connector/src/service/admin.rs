//! Feed administration (NAN-3490 item 2): create a feed from a marketplace
//! catalog entry, list feeds, enable / disable them.
//!
//! The operator surface is the `nano-connector-runner feed ...` CLI; the
//! functions here are the reusable core an API handler can call later. They
//! never take the tenant, the spec, or (on hosted-shared) the ingest URL
//! from the caller's free input:
//! - the tenant comes from the store's tenant inventory (on shared: the
//!   worker-assignment ledger), and every write is a signed tenant
//!   transaction;
//! - the spec is the catalog entry's `config.connector_spec`, checked against
//!   `config.connector_spec_sha256` and pinned on the feed;
//! - the hosted ingest URL is derived from the tenant's own slug and the
//!   deployment's ingest domain (`https://<slug>.<domain>/services/collector/event`),
//!   so a platform-held token is never pointed at another tenant's ingress;
//! - config and vendor credentials must be exactly what the spec reads.

use std::collections::{BTreeSet, HashMap};

use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::spec::{ConnectorSpec, Kind};

/// The catalog marker the content lane writes (`config.runtime`).
pub const CONNECTOR_RUNTIME: &str = "connector";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdminError {
    #[error("catalog entry `{0}` not found")]
    CatalogNotFound(String),
    #[error("catalog entry `{slug}` is not a connector-runtime entry: {why}")]
    NotConnector { slug: String, why: String },
    #[error("catalog spec for `{0}` does not match its connector_spec_sha256; re-sync the catalog")]
    SpecDigestMismatch(String),
    #[error("connector spec is invalid: {0}")]
    InvalidSpec(String),
    #[error("feed input is invalid: {0}")]
    InvalidInput(String),
    #[error("tenant {0} is not served by this runner")]
    UnknownTenant(Uuid),
    #[error("feed {0} not found")]
    FeedNotFound(Uuid),
    #[error("{0}")]
    Backend(String),
}

/// What a catalog entry pins onto a new feed.
#[derive(Debug, Clone)]
pub struct FeedPlan {
    pub catalog_id: Uuid,
    pub connector: String,
    pub spec_yaml: String,
    pub spec_sha256: String,
    /// The lane the feed's ingest credential is bound to: the spec's single
    /// stream `source_type`.
    pub source_slug: String,
    pub spec: ConnectorSpec,
}

/// Operator input for a new feed (never the tenant, the spec or, on shared,
/// the ingest URL).
#[derive(Debug, Clone, Default)]
pub struct NewFeed {
    pub name: String,
    pub config: Map<String, Value>,
    pub vendor_credentials: HashMap<String, String>,
    pub schedule: Option<String>,
    pub max_run_secs: Option<i32>,
    pub enabled: bool,
}

/// A feed as an operator sees it. No secret material.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FeedSummary {
    pub id: Uuid,
    pub name: String,
    pub connector: String,
    pub source_slug: String,
    pub spec_sha256: String,
    pub enabled: bool,
    pub ingest_url: String,
    /// `ready` (token stored), `pending` (issuance in flight), `none`, or
    /// `not_required` (identity feeds).
    pub credential: String,
    pub credential_error: Option<String>,
    pub next_run_at: chrono::DateTime<chrono::Utc>,
    pub last_status: Option<String>,
    pub last_error: Option<String>,
    pub last_success_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn is_source_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 100
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
        && s != "unknown"
}

/// Turn a catalog row (`id`, `slug`, `config`) into a feed plan.
pub fn plan_from_catalog(catalog_id: Uuid, slug: &str, config: &Value) -> Result<FeedPlan, AdminError> {
    let not = |why: &str| AdminError::NotConnector { slug: slug.to_string(), why: why.to_string() };
    if config.get("runtime").and_then(Value::as_str) != Some(CONNECTOR_RUNTIME) {
        return Err(not("config.runtime is not `connector`"));
    }
    let spec_yaml = config.get("connector_spec").and_then(Value::as_str).ok_or_else(|| not("config.connector_spec is missing"))?;
    let digest = config
        .get("connector_spec_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| not("config.connector_spec_sha256 is missing"))?;
    let actual = super::feed::spec_sha256(spec_yaml);
    if !actual.eq_ignore_ascii_case(digest) {
        return Err(AdminError::SpecDigestMismatch(slug.to_string()));
    }
    let spec = ConnectorSpec::from_yaml(spec_yaml).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
    crate::preview::validate_static(&spec).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
    if spec.kind == Kind::Identity {
        // No ingest lane: the feed writes the tenant's identity directory.
        // `source_slug` only names the feed's connector.
        if !is_source_slug(&spec.name) {
            return Err(AdminError::InvalidSpec(format!("identity connector name `{}` is not a slug", spec.name)));
        }
        return Ok(FeedPlan {
            catalog_id,
            connector: spec.name.clone(),
            spec_yaml: spec_yaml.to_string(),
            spec_sha256: actual,
            source_slug: spec.name.clone(),
            spec,
        });
    }
    if spec.kind != Kind::Collector {
        return Err(AdminError::InvalidSpec("only collector and identity specs run as feeds".into()));
    }
    let slugs: BTreeSet<&str> = spec.streams.iter().filter_map(|s| s.source_type.as_deref()).collect();
    if spec.streams.iter().any(|s| s.source_type.is_none()) || slugs.len() != 1 {
        // One feed = one source credential. A multi-source spec needs a
        // collector credential (follow-up).
        return Err(AdminError::InvalidSpec(format!(
            "a feed needs every stream on one source_type; this spec has {}",
            if slugs.is_empty() { "none".to_string() } else { slugs.into_iter().collect::<Vec<_>>().join(", ") }
        )));
    }
    let source_slug = slugs.into_iter().next().unwrap_or_default().to_string();
    if !is_source_slug(&source_slug) {
        return Err(AdminError::InvalidSpec(format!("source_type `{source_slug}` is not a source slug")));
    }
    Ok(FeedPlan {
        catalog_id,
        connector: spec.name.clone(),
        spec_yaml: spec_yaml.to_string(),
        spec_sha256: actual,
        source_slug,
        spec,
    })
}

/// Live-validation catalog entries (NAN-3490 item 5): a shipped spec copy
/// pinned to a public mock vendor. Their slug ends in this suffix, which the
/// marketplace reserves (a repository sync skips such manifests).
pub const MOCK_SLUG_SUFFIX: &str = nanosiem_core::marketplace::VALIDATION_MOCK_SLUG_SUFFIX;
/// The value this CLI stamps on a mock entry, as `author` and as
/// `config.validation_mock`; remove only ever deletes rows carrying it, and
/// the marketplace hides and refuses to edit any row with the config key.
pub const MOCK_AUTHOR: &str = "nano-connector-runner:validation-mock";
/// The only place a mock vendor may live: a Cloudflare workers.dev host.
#[cfg(feature = "enterprise")]
pub const MOCK_HOST_SUFFIX: &str = ".workers.dev";

/// Refuse a slug that is not a `_mock` catalog slug.
pub fn check_mock_slug(slug: &str) -> Result<(), AdminError> {
    let ok = slug.len() > MOCK_SLUG_SUFFIX.len()
        && slug.len() <= 64
        && slug.ends_with(MOCK_SLUG_SUFFIX)
        && is_source_slug(slug)
        && !slug.contains('-');
    if ok {
        Ok(())
    } else {
        Err(AdminError::InvalidInput(format!("`{slug}` is not a mock catalog slug (lowercase, `_`-separated, ending in `{MOCK_SLUG_SUFFIX}`)")))
    }
}

/// Refuse anything but one plain DNS label as the workers.dev account
/// subdomain (`<account>` in `<worker>.<account>.workers.dev`).
#[cfg(feature = "enterprise")]
pub fn check_mock_account(account: &str) -> Result<(), AdminError> {
    let ok = !account.is_empty()
        && account.len() <= 63
        && !account.starts_with('-')
        && !account.ends_with('-')
        && account.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(AdminError::InvalidInput(format!("`{account}` is not a workers.dev account subdomain (one lowercase DNS label)")))
    }
}

/// Plan a mock catalog entry: an ordinary connector entry (same checks as
/// `plan_from_catalog`) whose spec is named after the slug and may reach
/// exactly one host, a literal `<worker>.<account>.workers.dev` name on the
/// operator's own Cloudflare `account` subdomain.
#[cfg(feature = "enterprise")]
pub fn plan_mock_catalog(slug: &str, config: &Value, account: &str) -> Result<FeedPlan, AdminError> {
    check_mock_slug(slug)?;
    check_mock_account(account)?;
    let plan = plan_from_catalog(Uuid::nil(), slug, config)?;
    if plan.spec.name != slug {
        return Err(AdminError::InvalidSpec(format!("a mock spec must be named after its slug `{slug}`, not `{}`", plan.spec.name)));
    }
    let [rule] = plan.spec.allow.as_slice() else {
        return Err(AdminError::InvalidSpec(format!("a mock spec must allow exactly one host; it has {} rules", plan.spec.allow.len())));
    };
    let host = rule.host.as_deref().unwrap_or_default();
    let account_suffix = format!(".{account}{MOCK_HOST_SUFFIX}");
    let worker = host.strip_suffix(account_suffix.as_str()).unwrap_or_default();
    if host.contains("{{")
        || !rule.host_suffixes.is_empty()
        || !crate::policy::is_plain_hostname(host)
        || worker.is_empty()
        || worker.contains('.')
    {
        return Err(AdminError::InvalidSpec(format!(
            "a mock spec's allow host must be one literal <worker>{account_suffix} name, not {host:?}{}",
            if rule.host_suffixes.is_empty() { "" } else { " with host_suffixes" }
        )));
    }
    Ok(plan)
}

/// Every config key the spec reads: each `{{config.X}}` template reference
/// and each `.config.X` read inside a stream's VRL `program` (NAN-3767: e.g.
/// the directory specs' `PRIVILEGED_GROUPS`).
pub fn config_keys(spec_yaml: &str) -> Result<BTreeSet<String>, AdminError> {
    let doc: Value = serde_yaml::from_str(spec_yaml).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
    let mut out = template_keys(&doc)?;
    out.extend(program_config_keys(&doc));
    Ok(out)
}

/// The config keys only `{{config.X}}` templates read (no VRL program
/// reads). A stored feed config keeps these even when empty; a key only a
/// program reads is optional and dropped when empty.
pub fn template_config_keys(spec_yaml: &str) -> Result<BTreeSet<String>, AdminError> {
    let doc: Value = serde_yaml::from_str(spec_yaml).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
    template_keys(&doc)
}

fn template_keys(doc: &Value) -> Result<BTreeSet<String>, AdminError> {
    let mut out = BTreeSet::new();
    let mut stack = vec![doc];
    while let Some(v) = stack.pop() {
        match v {
            Value::String(s) => {
                for r in crate::template::references(s).map_err(|e| AdminError::InvalidSpec(e.to_string()))? {
                    if let Some(k) = r.strip_prefix("config.") {
                        out.insert(k.to_string());
                    }
                }
            }
            Value::Array(a) => stack.extend(a.iter()),
            Value::Object(m) => stack.extend(m.values()),
            _ => {}
        }
    }
    Ok(out)
}

/// Config keys read by `.config.X` paths in VRL `program` strings. A program
/// reads its input fallibly (`string(.config.X) ?? ""`), so these keys are
/// optional unless a template also reads them.
fn program_config_keys(doc: &Value) -> BTreeSet<String> {
    fn scan(src: &str, out: &mut BTreeSet<String>) {
        const NEEDLE: &str = ".config.";
        let mut rest = src;
        while let Some(i) = rest.find(NEEDLE) {
            let after = &rest[i + NEEDLE.len()..];
            let key: String = after.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if key.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
                out.insert(key);
            }
            rest = after;
        }
    }
    let mut out = BTreeSet::new();
    let mut stack = vec![doc];
    while let Some(v) = stack.pop() {
        match v {
            Value::Array(a) => stack.extend(a.iter()),
            Value::Object(m) => {
                for (k, x) in m {
                    match (k.as_str(), x) {
                        ("program", Value::String(src)) => scan(src, &mut out),
                        _ => stack.push(x),
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Config keys a feed may leave out: every reference to them is a whole
/// request query value (`param: "{{config.X}}"`). The engine omits a query
/// parameter whose value renders empty, so leaving such a key unset (or
/// empty) simply drops the parameter (e.g. Google's optional `customerId`).
pub fn optional_config_keys(spec_yaml: &str) -> Result<BTreeSet<String>, AdminError> {
    fn walk(v: &Value, under_query: bool, seen: &mut BTreeSet<String>, other: &mut BTreeSet<String>) -> Result<(), AdminError> {
        match v {
            Value::String(s) => {
                let refs = crate::template::references(s).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
                let whole = refs.len() == 1 && s.trim() == format!("{{{{{}}}}}", refs[0]);
                for r in refs {
                    if let Some(k) = r.strip_prefix("config.") {
                        if under_query && whole { seen.insert(k.to_string()) } else { other.insert(k.to_string()) };
                    }
                }
            }
            Value::Array(a) => {
                for x in a {
                    walk(x, false, seen, other)?;
                }
            }
            Value::Object(m) => {
                for (k, x) in m {
                    if k == "request" {
                        if let Value::Object(req) = x {
                            for (rk, rv) in req {
                                match (rk.as_str(), rv) {
                                    ("query", Value::Object(q)) => {
                                        for qv in q.values() {
                                            walk(qv, true, seen, other)?;
                                        }
                                    }
                                    _ => walk(rv, false, seen, other)?,
                                }
                            }
                            continue;
                        }
                    }
                    walk(x, false, seen, other)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let doc: Value = serde_yaml::from_str(spec_yaml).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
    let (mut seen, mut other) = (BTreeSet::new(), BTreeSet::new());
    walk(&doc, false, &mut seen, &mut other)?;
    // NAN-3767: keys only VRL programs read are optional.
    seen.extend(program_config_keys(&doc));
    Ok(seen.difference(&other).cloned().collect())
}

/// The vendor credential fields the spec's auth scheme reads.
pub fn credential_fields(spec: &ConnectorSpec) -> Result<BTreeSet<String>, AdminError> {
    let plugin = crate::auth::build(&spec.auth.kind, &spec.auth.params).map_err(|e| AdminError::InvalidSpec(e.to_string()))?;
    Ok(plugin.credential_fields().into_iter().collect())
}

/// Config and credentials must be exactly what the spec reads: nothing
/// missing (a run would fail) and nothing extra (a typo, or a secret in the
/// wrong place).
pub fn check_inputs(plan: &FeedPlan, feed: &NewFeed) -> Result<(), AdminError> {
    let name = feed.name.trim();
    if name.is_empty() || name.chars().count() > 100 || name != feed.name || name.chars().any(char::is_control) {
        return Err(AdminError::InvalidInput("name must be 1-100 characters, trimmed, no control characters".into()));
    }
    let wanted = config_keys(&plan.spec_yaml)?;
    let optional = optional_config_keys(&plan.spec_yaml)?;
    let given: BTreeSet<String> = feed.config.keys().cloned().collect();
    let missing: Vec<_> = wanted.difference(&given).filter(|k| !optional.contains(*k)).cloned().collect();
    let extra: Vec<_> = given.difference(&wanted).cloned().collect();
    if !missing.is_empty() {
        return Err(AdminError::InvalidInput(format!("config is missing {}", missing.join(", "))));
    }
    if !extra.is_empty() {
        return Err(AdminError::InvalidInput(format!("config has keys the spec never reads: {}", extra.join(", "))));
    }
    if let Some((k, _)) = feed
        .config
        .iter()
        .find(|(k, v)| v.is_null() || (!optional.contains(*k) && v.as_str().is_some_and(|s| s.trim().is_empty())))
    {
        return Err(AdminError::InvalidInput(format!("config `{k}` is empty")));
    }
    let wanted = credential_fields(&plan.spec)?;
    let given: BTreeSet<String> = feed.vendor_credentials.keys().cloned().collect();
    let missing: Vec<_> = wanted.difference(&given).cloned().collect();
    let extra: Vec<_> = given.difference(&wanted).cloned().collect();
    if !missing.is_empty() {
        return Err(AdminError::InvalidInput(format!("credentials are missing {}", missing.join(", "))));
    }
    if !extra.is_empty() {
        return Err(AdminError::InvalidInput(format!("credentials have fields the spec never reads: {}", extra.join(", "))));
    }
    if let Some((k, _)) = feed.vendor_credentials.iter().find(|(_, v)| v.trim().is_empty()) {
        return Err(AdminError::InvalidInput(format!("credential `{k}` is empty")));
    }
    if let Some(s) = &feed.schedule {
        super::feed::next_scheduled(s, chrono::Utc::now())
            .map_err(|e| AdminError::InvalidInput(format!("schedule `{s}` is not a valid cron expression: {e}")))?;
    }
    if feed.max_run_secs.is_some_and(|m| !(10..=3600).contains(&m)) {
        return Err(AdminError::InvalidInput("max_run_secs must be 10..=3600".into()));
    }
    Ok(())
}

/// The hosted HEC URL for a tenant: `https://<slug>.<domain>/services/collector/event`
/// (the tenant Worker's custom-domain route, NAN-2644). `host_suffix` is the
/// runner's `CONNECTOR_INGEST_HOST_SUFFIX`; the URL must satisfy it.
pub fn hosted_ingest_url(tenant_slug: &str, ingest_domain: &str, host_suffix: Option<&str>) -> Result<String, AdminError> {
    let domain = ingest_domain.trim().trim_matches('.').to_ascii_lowercase();
    let label_ok = |l: &str| {
        let b = l.as_bytes();
        !b.is_empty()
            && b.len() <= 63
            && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
    };
    if domain.is_empty() || domain.len() > 200 || !domain.split('.').all(label_ok) || !domain.contains('.') {
        return Err(AdminError::InvalidInput("the ingest domain is not a DNS name".into()));
    }
    if !label_ok(tenant_slug) {
        return Err(AdminError::InvalidInput("tenant slug is not a DNS label; the ingest hostname cannot be derived".into()));
    }
    let host = format!("{tenant_slug}.{domain}");
    if let Some(suffix) = host_suffix {
        let suffix = suffix.trim().to_ascii_lowercase();
        let suffix = suffix.trim_start_matches('.');
        if !(host == suffix || host.ends_with(&format!(".{suffix}"))) {
            return Err(AdminError::InvalidInput(format!("ingest host {host} is outside CONNECTOR_INGEST_HOST_SUFFIX {suffix}")));
        }
    }
    Ok(format!("https://{host}/services/collector/event"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = include_str!("../../tests/fixtures/specs/okta_system_log.yaml");

    fn catalog(spec: &str) -> Value {
        serde_json::json!({
            "runtime": "connector",
            "connector_spec": spec,
            "connector_spec_sha256": super::super::feed::spec_sha256(spec),
        })
    }

    fn feed() -> NewFeed {
        NewFeed {
            name: "Okta".into(),
            config: serde_json::json!({ "OKTA_DOMAIN": "acme.okta.com" }).as_object().unwrap().clone(),
            vendor_credentials: HashMap::from([("API_TOKEN".into(), "00abc".into())]),
            enabled: true,
            ..Default::default()
        }
    }

    #[cfg(feature = "enterprise")]
    fn mock_catalog(slug: &str, host_line: &str) -> Value {
        let spec = SPEC.replacen("name: okta_system_log\n", &format!("name: {slug}\n"), 1).replacen(
            "  - host: \"{{config.OKTA_DOMAIN}}\"\n    host_suffixes: [\".okta.com\", \".oktapreview.com\", \".okta-emea.com\", \".okta-gov.com\", \".okta.mil\"]\n",
            host_line,
            1,
        );
        catalog(&spec)
    }

    #[test]
    #[cfg(feature = "enterprise")]
    fn mock_catalog_entries_are_pinned_to_one_workers_dev_host() {
        let good = "  - host: \"nano-okta-mock.acct.workers.dev\"\n";
        let plan = plan_mock_catalog("okta_system_log_mock", &mock_catalog("okta_system_log_mock", good), "acct").unwrap();
        assert_eq!((plan.connector.as_str(), plan.source_slug.as_str()), ("okta_system_log_mock", "okta"));

        // The slug must end in _mock, and the spec must carry that name.
        for slug in ["okta_system_log", "okta-system-log_mock", "_mock", "Okta_mock", "okta_mockx"] {
            assert!(matches!(plan_mock_catalog(slug, &mock_catalog(slug, good), "acct"), Err(AdminError::InvalidInput(_))), "{slug}");
        }
        assert!(matches!(
            plan_mock_catalog("other_mock", &mock_catalog("okta_system_log_mock", good), "acct"),
            Err(AdminError::InvalidSpec(_))
        ));
        // The shipped spec (Okta suffixes, templated host) is refused.
        assert!(matches!(plan_mock_catalog("okta_system_log_mock", &catalog(SPEC), "acct"), Err(AdminError::InvalidSpec(_))));
        for bad in [
            "  - host: \"{{config.OKTA_DOMAIN}}\"\n    host_suffixes: [\".workers.dev\"]\n",
            "  - host: \"acct.workers.dev\"\n",
            "  - host: \"workers.dev\"\n",
            "  - host: \"mock.example.com\"\n",
            "  - host: \"mock.acct.workers.dev.evil.com\"\n",
            "  - host: \"mock.acct.workers.dev\"\n  - host: \"mock2.acct.workers.dev\"\n",
            // nano-red M4: the account label is pinned, so another
            // Cloudflare account's worker (or a nested name) is refused.
            "  - host: \"nano-okta-mock.other.workers.dev\"\n",
            "  - host: \"nano-okta-mock.xacct.workers.dev\"\n",
            "  - host: \"a.nano-okta-mock.acct.workers.dev\"\n",
            "  - host: \".acct.workers.dev\"\n",
        ] {
            let r = plan_mock_catalog("okta_system_log_mock", &mock_catalog("okta_system_log_mock", bad), "acct");
            assert!(matches!(r, Err(AdminError::InvalidSpec(_))), "{bad}: {r:?}");
        }
        // The account itself must be one lowercase DNS label.
        for account in ["", "Acct", "acct.workers", "-acct", "acct-", "ac ct", "acct.workers.dev"] {
            let r = plan_mock_catalog("okta_system_log_mock", &mock_catalog("okta_system_log_mock", good), account);
            assert!(matches!(r, Err(AdminError::InvalidInput(_))), "{account:?}: {r:?}");
        }
    }

    #[test]
    fn plans_the_okta_catalog_entry() {
        let plan = plan_from_catalog(Uuid::nil(), "okta_system_log", &catalog(SPEC)).unwrap();
        assert_eq!(plan.connector, "okta_system_log");
        assert_eq!(plan.source_slug, "okta");
        assert_eq!(plan.spec_sha256, super::super::feed::spec_sha256(SPEC));
        assert_eq!(config_keys(SPEC).unwrap(), BTreeSet::from(["OKTA_DOMAIN".to_string()]));
        assert_eq!(credential_fields(&plan.spec).unwrap(), BTreeSet::from(["API_TOKEN".to_string()]));
        check_inputs(&plan, &feed()).unwrap();
    }

    #[test]
    fn refuses_non_connector_entries_and_tampered_specs() {
        let mut c = catalog(SPEC);
        c["runtime"] = "deno".into();
        assert!(matches!(plan_from_catalog(Uuid::nil(), "x", &c), Err(AdminError::NotConnector { .. })));
        let mut c = catalog(SPEC);
        c["connector_spec"] = Value::String(SPEC.replace("*/2 * * * *", "* * * * *"));
        assert_eq!(plan_from_catalog(Uuid::nil(), "x", &c).unwrap_err(), AdminError::SpecDigestMismatch("x".into()));
        assert!(matches!(plan_from_catalog(Uuid::nil(), "x", &serde_json::json!({})), Err(AdminError::NotConnector { .. })));
    }

    #[test]
    fn refuses_missing_extra_and_empty_inputs() {
        let plan = plan_from_catalog(Uuid::nil(), "okta_system_log", &catalog(SPEC)).unwrap();
        let mut f = feed();
        f.config.clear();
        assert!(check_inputs(&plan, &f).unwrap_err().to_string().contains("missing OKTA_DOMAIN"));
        let mut f = feed();
        f.config.insert("OKTA_DOMIAN".into(), "x".into());
        assert!(check_inputs(&plan, &f).unwrap_err().to_string().contains("never reads: OKTA_DOMIAN"));
        let mut f = feed();
        f.vendor_credentials.clear();
        assert!(check_inputs(&plan, &f).unwrap_err().to_string().contains("missing API_TOKEN"));
        let mut f = feed();
        f.vendor_credentials.insert("PASSWORD".into(), "x".into());
        assert!(check_inputs(&plan, &f).unwrap_err().to_string().contains("never reads: PASSWORD"));
        let mut f = feed();
        f.vendor_credentials.insert("API_TOKEN".into(), " ".into());
        assert!(check_inputs(&plan, &f).is_err());
        let mut f = feed();
        f.name = " Okta".into();
        assert!(check_inputs(&plan, &f).is_err());
        let mut f = feed();
        f.schedule = Some("every minute".into());
        assert!(check_inputs(&plan, &f).is_err());
        let mut f = feed();
        f.max_run_secs = Some(5);
        assert!(check_inputs(&plan, &f).is_err());
    }

    #[test]
    fn hosted_ingest_url_comes_from_the_tenant_slug() {
        assert_eq!(
            hosted_ingest_url("acme", "ingest.nano.rs", Some(".ingest.nano.rs")).unwrap(),
            "https://acme.ingest.nano.rs/services/collector/event"
        );
        assert!(hosted_ingest_url("acme", "ingest.nano.rs", Some(".other.example")).is_err());
        assert!(hosted_ingest_url("Acme", "ingest.nano.rs", None).is_err());
        assert!(hosted_ingest_url("acme.evil", "ingest.nano.rs", None).is_err());
        assert!(hosted_ingest_url("acme", "localhost", None).is_err());
        assert!(hosted_ingest_url("acme", "ingest.nano.rs/x", None).is_err());
    }
}
