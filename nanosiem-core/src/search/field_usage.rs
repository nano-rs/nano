// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field-usage ranking for search autocomplete (NAN-3812).
//!
//! The search bar orders field suggestions as "Recent (you)" → "Popular in
//! this workspace" → curated defaults → everything else. Both ranked groups
//! are derived from the `search_history` table the product already stores
//! (one workspace per deployment).
//! There is no new tracking: each stored query is re-parsed with the nPL
//! parser and only the *field names* it references are kept. Values, keywords
//! and literals never leave this module.
//!
//! Storage access lives in `SearchHistoryRepository::field_usage_rows`; this
//! module is pure (parse, rank) plus a short-lived per-user cache.

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
/// Most recent workspace-wide history rows considered for Popular.
pub const WORKSPACE_ROW_LIMIT: i64 = 2_000;
/// History older than this does not count toward either group.
pub const HISTORY_WINDOW_DAYS: i64 = 90;
/// Recency half-life for the Recent score.
const RECENT_HALF_LIFE_HOURS: f64 = 24.0 * 7.0;
/// One heavy user cannot dominate Popular: each user contributes at most this
/// many queries per field.
const POPULAR_PER_USER_CAP: usize = 20;
/// A field is "popular in this workspace" only once this many DISTINCT users
/// searched it: Popular must never reveal what one colleague is looking at.
pub const POPULAR_MIN_DISTINCT_USERS: usize = 3;
/// Longest field name we report. Anything longer is not a real field.
const MAX_FIELD_LEN: usize = 128;
/// Longest stored query we bother parsing.
const MAX_QUERY_LEN: usize = 10_000;

/// `GET /api/me/field-usage` response: field names only, best first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchFieldUsage {
    /// Fields the caller used most recently / most often (recency-weighted).
    pub recent: Vec<String>,
    /// Fields most used across every user of this deployment.
    pub popular: Vec<String>,
}

/// One stored history row (`search_history.user_id, query, created_at`).
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
                // The subsearch's own field references count too.
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
            Command::Lookup { event_field, key_field, output_fields, output_renames, .. } => {
                self.field(&Command::lookup_event_field(event_field, key_field));
                for name in output_fields.iter().flatten() {
                    let target = output_renames.iter().find(|r| &r.from == name).map_or(name, |r| &r.to);
                    self.derive(target);
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

/// Whether `name` is a field of a public schema registry (UDM or OCSF
/// promoted columns), and so safe to share across users. `ext.*` and every
/// other name outside the registries are private to their author.
pub fn is_public_schema_field(name: &str) -> bool {
    static PUBLIC: once_cell::sync::Lazy<HashSet<String>> = once_cell::sync::Lazy::new(|| {
        use crate::schema::SchemaProfile;
        let udm = crate::schema::UdmProfile;
        let ocsf = crate::schema::OcsfProfile::new();
        udm.fields()
            .iter()
            .chain(ocsf.fields().iter())
            .map(|f| f.name.to_string())
            .collect()
    });
    !name.starts_with("ext.") && PUBLIC.contains(name)
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

/// Rank Recent and Popular from history rows.
///
/// `user_rows` are the caller's own rows; `workspace_rows` are rows of every
/// user of this deployment (they may include the caller).
pub fn rank_field_usage(
    actor: Uuid,
    user_rows: &[FieldUsageRow],
    workspace_rows: &[FieldUsageRow],
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

    // Popular: per-user-capped query counts across the workspace.
    let mut per_user: HashMap<(String, Uuid), usize> = HashMap::new();
    for row in workspace_rows.iter().filter(|r| r.created_at >= cutoff) {
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
    // Cross-user results are limited to public schema fields (the UDM / OCSF
    // registries) searched by enough distinct users. Custom and dynamic names
    // (`ext.*`, parser-specific keys) can encode what a restricted source holds
    // or what one analyst is investigating; they stay in that user's Recent.
    let mut popular: Vec<(String, (usize, usize))> = popular
        .into_iter()
        .filter(|(field, (_, users))| *users >= POPULAR_MIN_DISTINCT_USERS && is_public_schema_field(field))
        .collect();
    popular.sort_by(|(an, (ac, au)), (bn, (bc, bu))| bc.cmp(ac).then(bu.cmp(au)).then(an.cmp(bn)));

    SearchFieldUsage {
        recent: recent.into_iter().take(RECENT_LIMIT).map(|(f, _)| f).collect(),
        popular: popular.into_iter().take(POPULAR_LIMIT).map(|(f, _)| f).collect(),
    }
}

/// How long a computed ranking is served before history is re-read.
pub const FIELD_USAGE_CACHE_TTL: Duration = Duration::from_secs(60);
const FIELD_USAGE_CACHE_MAX_ENTRIES: usize = 10_000;

/// Short-lived cache of ranked field names. "Recent" is cached per user;
/// "Popular" once for the deployment, so the workspace-wide history scan runs
/// at most once per TTL however many users type.
pub struct FieldUsageCache {
    ttl: Duration,
    /// `Some(user)` → Recent; `None` → Popular.
    entries: DashMap<Option<Uuid>, (Instant, Vec<String>)>,
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
    pub fn needs_workspace_rows(&self) -> bool {
        self.popular.is_none()
    }
}

impl FieldUsageCache {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, entries: DashMap::new() }
    }

    fn fresh(&self, key: Option<Uuid>) -> Option<Vec<String>> {
        let hit = self.entries.get(&key)?;
        (hit.0.elapsed() < self.ttl).then(|| hit.1.clone())
    }

    fn put(&self, key: Option<Uuid>, value: Vec<String>) {
        if self.entries.len() >= FIELD_USAGE_CACHE_MAX_ENTRIES {
            let ttl = self.ttl;
            self.entries.retain(|_, (at, _)| at.elapsed() < ttl);
            if self.entries.len() >= FIELD_USAGE_CACHE_MAX_ENTRIES {
                self.entries.clear();
            }
        }
        self.entries.insert(key, (Instant::now(), value));
    }

    pub fn lookup(&self, user: Uuid) -> CachedFieldUsage {
        CachedFieldUsage { recent: self.fresh(Some(user)), popular: self.fresh(None) }
    }

    /// Store the parts that were computed (those missing from `cached`) and
    /// return the full answer: cached parts win over the empty placeholders
    /// `computed` carries for groups whose rows were not read.
    pub fn fill(&self, user: Uuid, cached: CachedFieldUsage, computed: SearchFieldUsage) -> SearchFieldUsage {
        let recent = match cached.recent {
            Some(recent) => recent,
            None => {
                self.put(Some(user), computed.recent.clone());
                computed.recent
            }
        };
        let popular = match cached.popular {
            Some(popular) => popular,
            None => {
                self.put(None, computed.popular.clone());
                computed.popular
            }
        };
        SearchFieldUsage { recent, popular }
    }

    /// Drop the caller's Recent so a search they just ran shows up on the next
    /// request. Popular refreshes on its TTL.
    pub fn invalidate(&self, user: Uuid) {
        self.entries.remove(&Some(user));
    }
}

/// Process-wide cache used by `GET /api/me/field-usage`.
pub static FIELD_USAGE_CACHE: Lazy<FieldUsageCache> = Lazy::new(|| FieldUsageCache::new(FIELD_USAGE_CACHE_TTL));

#[cfg(test)]
#[path = "field_usage_tests.rs"]
mod tests;
