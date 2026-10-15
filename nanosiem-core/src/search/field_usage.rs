// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field-usage ranking for search autocomplete (NAN-3812).
//!
//! The search bar orders field suggestions as "Recent (you)" → "Popular in
//! this workspace" → curated defaults → everything else. Both ranked groups
//! are derived from the search history the product already stores (open core:
//! `search_history`; hosted shared: the RLS `tenant_search_history` ledger).
//! There is no new tracking: each stored query is re-parsed with the nPL
//! parser and only the *field names* it references are kept. Values, keywords
//! and literals never leave this module.
//!
//! Storage access lives with each backend; this module is pure (parse, rank)
//! plus a short-lived per-(tenant, user) cache shared by both handlers.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::query::{parse_query, Command, Query, SearchExpr};

/// Fields in the "Recent (you)" group.
pub const RECENT_LIMIT: usize = 5;
/// Fields returned for "Popular in this workspace". The UI drops fields
/// already shown under Recent and caps the group at 10, so return a few more.
pub const POPULAR_LIMIT: usize = 15;
/// Most recent history rows of the caller considered for Recent.
pub const USER_ROW_LIMIT: i64 = 200;
/// Most recent tenant-wide history rows considered for Popular.
pub const TENANT_ROW_LIMIT: i64 = 2_000;
/// History older than this does not count toward either group.
pub const HISTORY_WINDOW_DAYS: i64 = 90;
/// Recency half-life for the Recent score.
const RECENT_HALF_LIFE_HOURS: f64 = 24.0 * 7.0;
/// One heavy user cannot dominate Popular: each user contributes at most this
/// many queries per field.
const POPULAR_PER_USER_CAP: usize = 20;
/// Longest field name we report. Anything longer is not a real field.
const MAX_FIELD_LEN: usize = 128;
/// Longest stored query we bother parsing.
const MAX_QUERY_LEN: usize = 10_000;

/// `GET /api/me/field-usage` response: field names only, best first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchFieldUsage {
    /// Fields the caller used most recently / most often (recency-weighted).
    pub recent: Vec<String>,
    /// Fields most used across all members of the caller's tenant.
    pub popular: Vec<String>,
}

/// One stored history row, as read by either backend. The backend must have
/// already restricted rows to the caller's tenant.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FieldUsageRow {
    pub user_id: Uuid,
    pub query: String,
    pub created_at: DateTime<Utc>,
}

/// Field names referenced by an nPL query, in first-use order, deduplicated.
///
/// Only names the user typed as *fields* count: filter left-hand sides,
/// `where` conditions, `stats … by`, aggregation inputs, `table`/`fields`,
/// `sort`, `dedup`, `top`/`rare`, and similar. Names the pipeline itself
/// creates (eval targets, aggregation aliases, rename targets) are skipped.
/// An unparseable query yields nothing.
pub fn extract_query_fields(query: &str) -> Vec<String> {
    if query.trim().is_empty() || query.len() > MAX_QUERY_LEN {
        return Vec::new();
    }
    let Ok(parsed) = parse_query(query) else {
        return Vec::new();
    };
    let mut collector = Collector::default();
    collector.query(&parsed);
    collector.out
}

#[derive(Default)]
struct Collector {
    out: Vec<String>,
    seen: HashSet<String>,
    /// Names created earlier in the pipeline; later references are not "field use".
    derived: HashSet<String>,
}

impl Collector {
    fn field(&mut self, name: &str) {
        let name = name.trim();
        if !is_reportable_field(name) || self.derived.contains(name) {
            return;
        }
        if self.seen.insert(name.to_string()) {
            self.out.push(name.to_string());
        }
    }

    fn fields<'a>(&mut self, names: impl IntoIterator<Item = &'a String>) {
        for name in names {
            self.field(name);
        }
    }

    fn derive(&mut self, name: &str) {
        self.derived.insert(name.trim().to_string());
    }

    fn query(&mut self, query: &Query) {
        match query {
            Query::Search(expr) => self.expr(expr),
            Query::Piped { source, command } => {
                self.query(source);
                self.command(command);
            }
        }
    }

    fn expr(&mut self, expr: &SearchExpr) {
        match expr {
            SearchExpr::FieldFilter { field, .. }
            | SearchExpr::FieldFunctionFilter { field, .. }
            | SearchExpr::InList { field, .. } => self.field(field),
            SearchExpr::InSubsearch { field, subsearch, .. } => {
                self.field(field);
                // The subsearch runs on the same tenant's data; its fields count too.
                let mut inner = Collector::default();
                inner.query(subsearch);
                for name in inner.out {
                    self.field(&name);
                }
            }
            SearchExpr::And(a, b) | SearchExpr::Or(a, b) => {
                self.expr(a);
                self.expr(b);
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => self.expr(inner),
            // Keywords, literals, IOC sweeps and computed predicates carry no
            // plain field name we can attribute without guessing.
            _ => {}
        }
    }

    fn aggregations(&mut self, aggregations: &[crate::query::Aggregation]) {
        for agg in aggregations {
            if let Some(field) = agg.field.as_deref() {
                self.field(field);
            }
        }
        // The output column (explicit alias or the implicit name such as
        // `count`) is created here; later references are not field use.
        for agg in aggregations {
            self.derive(&agg.output_alias());
        }
    }

    fn command(&mut self, command: &Command) {
        match command {
            Command::Stats { aggregations, group_by }
            | Command::Chart { aggregations, group_by }
            | Command::StreamStats { aggregations, group_by, .. }
            | Command::EventStats { aggregations, group_by } => {
                if let Some(group_by) = group_by {
                    self.fields(group_by);
                }
                self.aggregations(aggregations);
            }
            Command::Timechart { aggregations, split_by, .. } => {
                self.fields(split_by);
                self.aggregations(aggregations);
            }
            Command::Where { condition } => self.expr(condition),
            Command::Sort { fields, .. } => {
                for f in fields {
                    self.field(&f.field);
                }
            }
            Command::Table { fields } => {
                for f in fields {
                    self.field(&f.name);
                }
            }
            Command::Fields { fields, .. } | Command::Dedup { fields, .. } | Command::Transaction { fields, .. } => {
                self.fields(fields)
            }
            Command::Top { field, by_fields, .. } | Command::Rare { field, by_fields, .. } => {
                self.field(field);
                self.fields(by_fields);
            }
            Command::Rename { mappings } => {
                for m in mappings {
                    self.field(&m.from);
                    self.derive(&m.to);
                }
            }
            Command::Eval { assignments } => {
                for a in assignments {
                    self.derive(&a.field);
                }
            }
            Command::Lookup { event_field, output_fields, output_renames, .. } => {
                self.field(event_field);
                for name in output_fields.iter().flatten() {
                    self.derive(name);
                }
                for r in output_renames {
                    self.derive(&r.to);
                }
            }
            Command::Mvexpand { field, .. } => self.field(field),
            Command::Fillnull { fields: Some(fields), .. } => self.fields(fields),
            Command::Rex { field: Some(field), .. } => self.field(field),
            Command::Bin { field, alias, .. } => {
                if let Some(field) = field {
                    self.field(field);
                }
                if let Some(alias) = alias {
                    self.derive(alias);
                }
            }
            Command::Join { fields, .. } => self.fields(fields),
            Command::Sequence { group_by, conditions, .. } => {
                self.fields(group_by);
                for c in conditions {
                    self.expr(c);
                }
            }
            Command::Funnel { group_by, steps, .. } => {
                self.fields(group_by);
                for (_, c) in steps {
                    self.expr(c);
                }
            }
            _ => {}
        }
    }
}

/// A plausible field identifier: no spaces, quotes, operators or wildcards.
/// This is also the guarantee that nothing value-shaped is ever reported.
fn is_reportable_field(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_FIELD_LEN {
        return false;
    }
    let first = name.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_' || first == b'@') {
        return false;
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'@' | b'-')) {
        return false;
    }
    // Pseudo-fields the parser treats as selectors, not columns.
    !matches!(name, "dataset" | "ioc" | "index")
}

/// Rank Recent and Popular from tenant-scoped history rows.
///
/// `user_rows` are the caller's own rows; `tenant_rows` are rows of every
/// member of the caller's tenant (they may include the caller). Both are
/// assumed already filtered to one tenant by the backend.
pub fn rank_field_usage(
    actor: Uuid,
    user_rows: &[FieldUsageRow],
    tenant_rows: &[FieldUsageRow],
    now: DateTime<Utc>,
) -> SearchFieldUsage {
    let cutoff = now - chrono::Duration::days(HISTORY_WINDOW_DAYS);
    let mut parsed: HashMap<String, Vec<String>> = HashMap::new();
    let mut fields_of = |query: &str| -> Vec<String> {
        // Parse each distinct query text once even if it repeats.
        if let Some(fields) = parsed.get(query) {
            return fields.clone();
        }
        let fields = extract_query_fields(query);
        parsed.insert(query.to_string(), fields.clone());
        fields
    };

    // Recent: recency-weighted sum over the caller's own queries.
    let mut recent: HashMap<String, (f64, DateTime<Utc>)> = HashMap::new();
    for row in user_rows.iter().filter(|r| r.user_id == actor && r.created_at >= cutoff) {
        let age_hours = (now - row.created_at).num_minutes().max(0) as f64 / 60.0;
        let weight = 0.5_f64.powf(age_hours / RECENT_HALF_LIFE_HOURS);
        for field in fields_of(&row.query) {
            let entry = recent.entry(field).or_insert((0.0, row.created_at));
            entry.0 += weight;
            if row.created_at > entry.1 {
                entry.1 = row.created_at;
            }
        }
    }
    let mut recent: Vec<(String, (f64, DateTime<Utc>))> = recent.into_iter().collect();
    recent.sort_by(|(an, (asc, at)), (bn, (bsc, bt))| {
        bsc.partial_cmp(asc).unwrap_or(std::cmp::Ordering::Equal).then(bt.cmp(at)).then(an.cmp(bn))
    });

    // Popular: per-user-capped query counts across the tenant.
    let mut per_user: HashMap<(String, Uuid), usize> = HashMap::new();
    for row in tenant_rows.iter().filter(|r| r.created_at >= cutoff) {
        for field in fields_of(&row.query) {
            *per_user.entry((field, row.user_id)).or_default() += 1;
        }
    }
    let mut popular: HashMap<String, (usize, usize)> = HashMap::new();
    for ((field, _user), count) in per_user {
        let entry = popular.entry(field).or_default();
        entry.0 += count.min(POPULAR_PER_USER_CAP);
        entry.1 += 1;
    }
    let mut popular: Vec<(String, (usize, usize))> = popular.into_iter().collect();
    popular.sort_by(|(an, (ac, au)), (bn, (bc, bu))| bc.cmp(ac).then(bu.cmp(au)).then(an.cmp(bn)));

    SearchFieldUsage {
        recent: recent.into_iter().take(RECENT_LIMIT).map(|(f, _)| f).collect(),
        popular: popular.into_iter().take(POPULAR_LIMIT).map(|(f, _)| f).collect(),
    }
}

/// How long a computed ranking is served before history is re-read.
pub const FIELD_USAGE_CACHE_TTL: Duration = Duration::from_secs(60);
const FIELD_USAGE_CACHE_MAX_ENTRIES: usize = 10_000;

/// Short-lived cache of ranked field names. "Recent" is cached per
/// `(tenant, user)`; "Popular" once per tenant, so the tenant-wide history
/// scan runs at most once per TTL per tenant however many members type.
/// Open core has one tenant per deployment and keys it as [`Uuid::nil`]. The
/// tenant is part of every key, so one tenant's ranking is never served to
/// another tenant's member.
pub struct FieldUsageCache {
    ttl: Duration,
    /// `(tenant, Some(user))` → Recent; `(tenant, None)` → Popular.
    entries: DashMap<(Uuid, Option<Uuid>), (Instant, Vec<String>)>,
}

/// What the cache already holds for one request; `None` parts must be computed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CachedFieldUsage {
    pub recent: Option<Vec<String>>,
    pub popular: Option<Vec<String>>,
}

impl CachedFieldUsage {
    /// Both parts cached: serve without touching history.
    pub fn complete(&self) -> Option<SearchFieldUsage> {
        Some(SearchFieldUsage { recent: self.recent.clone()?, popular: self.popular.clone()? })
    }
    pub fn needs_user_rows(&self) -> bool {
        self.recent.is_none()
    }
    pub fn needs_tenant_rows(&self) -> bool {
        self.popular.is_none()
    }
}

impl FieldUsageCache {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, entries: DashMap::new() }
    }

    fn fresh(&self, key: (Uuid, Option<Uuid>)) -> Option<Vec<String>> {
        let hit = self.entries.get(&key)?;
        (hit.0.elapsed() < self.ttl).then(|| hit.1.clone())
    }

    fn put(&self, key: (Uuid, Option<Uuid>), value: Vec<String>) {
        if self.entries.len() >= FIELD_USAGE_CACHE_MAX_ENTRIES {
            let ttl = self.ttl;
            self.entries.retain(|_, (at, _)| at.elapsed() < ttl);
            if self.entries.len() >= FIELD_USAGE_CACHE_MAX_ENTRIES {
                self.entries.clear();
            }
        }
        self.entries.insert(key, (Instant::now(), value));
    }

    pub fn lookup(&self, tenant: Uuid, user: Uuid) -> CachedFieldUsage {
        CachedFieldUsage { recent: self.fresh((tenant, Some(user))), popular: self.fresh((tenant, None)) }
    }

    /// Store the parts that were computed (those missing from `cached`) and
    /// return the full answer: cached parts win over the empty placeholders
    /// `computed` carries for groups whose rows were not read.
    pub fn fill(&self, tenant: Uuid, user: Uuid, cached: CachedFieldUsage, computed: SearchFieldUsage) -> SearchFieldUsage {
        let recent = match cached.recent {
            Some(recent) => recent,
            None => {
                self.put((tenant, Some(user)), computed.recent.clone());
                computed.recent
            }
        };
        let popular = match cached.popular {
            Some(popular) => popular,
            None => {
                self.put((tenant, None), computed.popular.clone());
                computed.popular
            }
        };
        SearchFieldUsage { recent, popular }
    }

    /// Drop the caller's Recent so a search they just ran shows up on the next
    /// request. Popular refreshes on its TTL.
    pub fn invalidate(&self, tenant: Uuid, user: Uuid) {
        self.entries.remove(&(tenant, Some(user)));
    }
}

/// Process-wide cache used by both the open-core and the hosted handler.
pub static FIELD_USAGE_CACHE: Lazy<FieldUsageCache> = Lazy::new(|| FieldUsageCache::new(FIELD_USAGE_CACHE_TTL));

#[cfg(test)]
mod tests {
    use super::*;

    fn row(user: Uuid, query: &str, hours_ago: i64, now: DateTime<Utc>) -> FieldUsageRow {
        FieldUsageRow { user_id: user, query: query.into(), created_at: now - chrono::Duration::hours(hours_ago) }
    }

    #[test]
    fn extracts_filter_and_command_fields_in_order() {
        let fields = extract_query_fields(
            r#"metadata.log_source="aws_cloudtrail" src_endpoint.ip=10.0.0.1 | where actor.user.name="root" | stats count by dst_endpoint.ip | sort -count"#,
        );
        assert_eq!(fields, vec!["metadata.log_source", "src_endpoint.ip", "actor.user.name", "dst_endpoint.ip"]);
    }

    #[test]
    fn never_reports_values_keywords_or_derived_names() {
        let q = r#"powershell "secret-token" user="alice@corp.example" src_ip IN ("10.1.1.1", "10.2.2.2") | eval risky=1 | rename user AS who | stats count AS hits by who, risky | table hits, who"#;
        let fields = extract_query_fields(q);
        assert_eq!(fields, vec!["user", "src_ip"]);
        for leaked in ["powershell", "secret-token", "alice@corp.example", "10.1.1.1", "risky", "who", "hits"] {
            assert!(!fields.iter().any(|f| f == leaked), "{leaked} leaked: {fields:?}");
        }
    }

    #[test]
    fn unparseable_or_empty_queries_yield_nothing() {
        assert!(extract_query_fields("").is_empty());
        assert!(extract_query_fields("| | |").is_empty());
        assert!(extract_query_fields(&"a".repeat(MAX_QUERY_LEN + 1)).is_empty());
    }

    #[test]
    fn recent_is_the_callers_own_recency_weighted_fields() {
        let now = Utc::now();
        let me = Uuid::new_v4();
        let other = Uuid::new_v4();
        let user_rows = vec![
            row(me, "src_endpoint.ip=1.2.3.4", 1, now),
            row(me, "user=bob", 24 * 60, now),
            row(me, "user=carol", 24 * 61, now),
            // A row for someone else must never count toward my Recent.
            row(other, "process.name=cmd.exe", 0, now),
        ];
        let usage = rank_field_usage(me, &user_rows, &[], now);
        assert_eq!(usage.recent.first().map(String::as_str), Some("src_endpoint.ip"));
        assert!(usage.recent.contains(&"user".to_string()));
        assert!(!usage.recent.contains(&"process.name".to_string()));
    }

    #[test]
    fn recent_ignores_history_outside_the_window() {
        let now = Utc::now();
        let me = Uuid::new_v4();
        let rows = vec![row(me, "file.path=x", 24 * (HISTORY_WINDOW_DAYS + 1), now)];
        assert!(rank_field_usage(me, &rows, &rows, now).recent.is_empty());
    }

    #[test]
    fn popular_reflects_other_members_and_caps_one_heavy_user() {
        let now = Utc::now();
        let (me, a, b, heavy) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut tenant = vec![
            row(a, "dst_endpoint.ip=1.1.1.1", 2, now),
            row(b, "dst_endpoint.ip=8.8.8.8 | stats count by device.hostname", 3, now),
        ];
        // 25 queries from one user on one field count as POPULAR_PER_USER_CAP.
        for i in 0..25 {
            tenant.push(row(heavy, "http_request.url.hostname=x", i, now));
        }
        for i in 0..11 {
            tenant.push(row(a, "class_uid=3002", i, now));
            tenant.push(row(b, "class_uid=3002", i, now));
        }
        let usage = rank_field_usage(me, &[], &tenant, now);
        assert_eq!(usage.popular[0], "class_uid", "{:?}", usage.popular);
        assert_eq!(usage.popular[1], "http_request.url.hostname");
        assert!(usage.popular.contains(&"dst_endpoint.ip".to_string()));
        assert!(usage.popular.contains(&"device.hostname".to_string()));
        assert!(usage.recent.is_empty());
    }

    #[test]
    fn limits_are_respected() {
        let now = Utc::now();
        let me = Uuid::new_v4();
        let rows: Vec<_> = (0..40).map(|i| row(me, &format!("f{i}=1"), i, now)).collect();
        let usage = rank_field_usage(me, &rows, &rows, now);
        assert_eq!(usage.recent.len(), RECENT_LIMIT);
        assert_eq!(usage.popular.len(), POPULAR_LIMIT);
        assert_eq!(usage.recent[0], "f0");
    }

    #[test]
    fn cache_is_keyed_by_tenant_and_user_and_expires() {
        let cache = FieldUsageCache::new(Duration::from_secs(60));
        let (tenant_a, tenant_b, user, other) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let computed = SearchFieldUsage { recent: vec!["a.mine".into()], popular: vec!["a.secret_field".into()] };
        let served = cache.fill(tenant_a, user, CachedFieldUsage::default(), computed.clone());
        assert_eq!(served, computed);
        assert_eq!(cache.lookup(tenant_a, user).complete(), Some(computed));

        // Another member of the same tenant shares Popular but not Recent.
        let peer = cache.lookup(tenant_a, other);
        assert_eq!(peer.popular, Some(vec!["a.secret_field".to_string()]));
        assert!(peer.needs_user_rows() && !peer.needs_tenant_rows());

        // Negative cross-tenant: the same user id in another tenant misses both.
        let foreign = cache.lookup(tenant_b, user);
        assert_eq!(foreign, CachedFieldUsage::default());
        assert!(foreign.needs_user_rows() && foreign.needs_tenant_rows());

        // A cached part beats the empty placeholder of an unread group.
        let merged = cache.fill(tenant_a, other, peer, SearchFieldUsage { recent: vec!["x".into()], popular: vec![] });
        assert_eq!(merged.popular, vec!["a.secret_field".to_string()]);

        cache.invalidate(tenant_a, user);
        let after = cache.lookup(tenant_a, user);
        assert!(after.needs_user_rows() && !after.needs_tenant_rows());

        let expired = FieldUsageCache::new(Duration::ZERO);
        expired.fill(tenant_a, user, CachedFieldUsage::default(), SearchFieldUsage::default());
        assert_eq!(expired.lookup(tenant_a, user), CachedFieldUsage::default());
    }
}
