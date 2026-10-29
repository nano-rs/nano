// SPDX-License-Identifier: AGPL-3.0-or-later

//! query[T]'s identity resolution over the lean identity observation index
//! (NAN-3058, [`crate::identity_observations`]).
//!
//! # Sources
//!
//! For the parts overlapping `[min(ref) - 30 d, max(ref)]`:
//!
//! - an **indexed** part (its entity-range partial carries the coverage row
//!   and that row counts every part row) answers from its own signed partial;
//! - any other part answers from its **backfill** file: the same rows derived
//!   by this role from the part's data files, cached at
//!   `<state>/identity-index/v1/<part_id>.parquet` ([`backfill_once`]);
//! - a part with neither is **missing**. The response reports the index state
//!   (`complete` or `backfilling` with counts) and the caller decides; nano's
//!   search service falls back to its bounded event scan (NAN-3057) and says
//!   so in the result's `source`.
//!
//! The sources a lookup reads are folded into one merged, value-sorted file
//! by the background pass (NAN-3399, [`super::identity_merged`]): a lookup
//! reads that file for the live sources it covers and only the newer ones
//! one by one.
//!
//! # Semantics (parity with ClickHouse `identity_observations`)
//!
//! Per item: among observations of the item's key at or before its reference
//! time and at most 30 days older, the highest `source_priority`, then the
//! newest. An hourly row whose range straddles the reference time counts at
//! its first observation (still ≤ ref). The viewer's deny set drops
//! observations of denied sources before selection. `nat_candidate` (IP
//! lookups): some hour in the 7 days up to the reference time saw 3+
//! distinct hostnames for the IP (`nat_candidates_view`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use super::engine::{PartQueryEngine, PartQueryError, QueryResult};
use super::fetch::FileSet;
use crate::identity_observations::{
    decode_value, IdentityAccumulator, BACKFILL_BYTES_CAP, COVERAGE_VALUE, EVENT_SOURCE_PRIORITY, IDENTITY_PATH,
    LOOKBACK_US, NAT_MIN_HOSTS, NAT_WINDOW_US,
};
use crate::part_ingest::partials::{write_sorted, EntityRangeRow};
use crate::parts::format::PartId;
use crate::parts::part_log::PartRef;
use crate::parts::provenance::PartialKind;

pub const MAX_ITEMS: usize = 500;
const MAX_DENIED: usize = 1_024;
const MAX_VALUE_BYTES: usize = 1_024;
/// Parts one backfill pass derives at most (NAN-3077: one, so the pass is
/// short and the next idle check comes soon).
pub const BACKFILL_PARTS_PER_TICK: usize = 1;
const BACKFILL_DIR: &str = "identity-index/v1";
/// Needles per `multiSearchAnyCaseInsensitive` call (ClickHouse accepts
/// fewer than 256).
const KEY_NEEDLES_PER_CALL: usize = 200;
/// Up to this many distinct IP keys each get their own value range; above
/// it, one spanning range plus a key-set test (NAN-3394: 500 OR-ed ranges
/// were 6x slower per row than the set test, 5 ranges 2x faster).
const IP_RANGE_KEYS: usize = 16;

fn invalid(message: impl Into<String>) -> PartQueryError {
    PartQueryError::Invalid(message.into())
}

fn internal(error: impl std::fmt::Display) -> PartQueryError {
    super::engine::internal_text(error.to_string())
}

/// What an item is looked up by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupKind {
    Ip,
    Host,
    User,
}

impl LookupKind {
    pub fn parse(value: &str) -> QueryResult<Self> {
        match value {
            "ip" => Ok(Self::Ip),
            "host" => Ok(Self::Host),
            "user" => Ok(Self::User),
            _ => Err(invalid("identity entity type must be ip, host, or user")),
        }
    }

    /// Normalize a request key the way the index stores it.
    pub fn normalize(self, value: &str) -> QueryResult<String> {
        let value = value.trim();
        if value.is_empty() || value.len() > MAX_VALUE_BYTES || value.chars().any(char::is_control) {
            return Err(invalid("identity lookup value is empty, too long, or has control characters"));
        }
        match self {
            Self::Ip => crate::identity_observations::canonical_ip(value)
                .ok_or_else(|| invalid("identity lookup value is not an IP address")),
            Self::Host | Self::User => Ok(value.to_lowercase()),
        }
    }

    /// The observation expression(s) an item key matches (one row per key).
    fn key_expr(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Host => "arrayJoin(arrayDistinct([lower(hostname), lower(fqdn)]))",
            Self::User => "lower(user)",
        }
    }
}

/// One normalized lookup: `(ordinal, key, reference time µs)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub ordinal: usize,
    pub key: String,
    pub reference_us: i64,
}

pub fn normalize_items(kind: LookupKind, raw: &[(String, String)]) -> QueryResult<Vec<Item>> {
    if raw.is_empty() || raw.len() > MAX_ITEMS {
        return Err(invalid(format!("identity lookup must contain between 1 and {MAX_ITEMS} items")));
    }
    raw.iter()
        .enumerate()
        .map(|(ordinal, (value, reference))| {
            Ok(Item { ordinal, key: kind.normalize(value)?, reference_us: super::engine::rfc3339_us(reference)? })
        })
        .collect()
}

pub fn normalize_denied(deny: &BTreeSet<String>) -> QueryResult<Vec<String>> {
    if deny.len() > MAX_DENIED || deny.iter().any(|s| s.is_empty() || s.len() > 512 || s.chars().any(char::is_control)) {
        return Err(invalid("identity source scope exceeds its bound"));
    }
    Ok(deny.iter().map(|s| s.trim().to_lowercase()).collect::<BTreeSet<_>>().into_iter().collect())
}

fn sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn items_param(items: &[Item]) -> String {
    let body = items
        .iter()
        .map(|item| format!("({},{},{})", item.ordinal, sql_string(&item.key), item.reference_us))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

pub(super) fn strings_param(values: &[String]) -> String {
    format!("[{}]", values.iter().map(|v| sql_string(v)).collect::<Vec<_>>().join(","))
}

/// NAN-3394: the scan predicate that binds the observation rows to the
/// items' keys, evaluated by the Parquet reader before any value is decoded
/// or joined. Without it every lookup decoded and joined every observation
/// of the 30-day window, so a miss cost as much as a hit and the cost grew
/// with the tenant's history instead of with the items.
///
/// A value is the compact JSON array [`crate::identity_observations::encode_value`]
/// writes: `["<ip>",<hour>,"<hostname>","<fqdn>","<mac>","<user>","<source>"]`.
///
/// - IP: the item's observations are exactly the values that start with
///   `["<ip>",` (the JSON string encoding is injective and `"` ends it), the
///   range `[ "[<ip>,", "[<ip>-" )` (`-` follows `,`). Partials are sorted by
///   `(path, value)`, so the row-group statistics skip every other entity.
/// - Host / user: the key matches `lower(hostname)`, `lower(fqdn)` or
///   `lower(user)` exactly, so its quoted JSON form occurs in the value up to
///   ASCII case. The needle test is a superset; the join stays the exact
///   match.
fn key_filter(kind: LookupKind, items: &[Item]) -> (String, Vec<(String, String)>) {
    let quoted = items
        .iter()
        .map(|item| serde_json::to_string(&item.key).expect("a string serializes"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut params = Vec::new();
    let terms = match kind {
        LookupKind::Ip if quoted.len() > IP_RANGE_KEYS => {
            // Many keys: hundreds of OR-ed ranges cost more per row than the
            // decode they save. One range spanning every key still prunes
            // row groups; the first array element's text (an IP has no
            // quote or escape) is then tested against the key set.
            let lo = quoted.iter().map(|key| format!("[{key},")).min().expect("keys");
            let hi = quoted.iter().map(|key| format!("[{key}-")).max().expect("keys");
            params.push(("identity_key_lo_0".to_string(), lo));
            params.push(("identity_key_hi_0".to_string(), hi));
            let keys = quoted.iter().map(|key| key[1..key.len() - 1].to_string()).collect::<Vec<_>>();
            params.push(("identity_keys".to_string(), strings_param(&keys)));
            vec![
                "(value >= {identity_key_lo_0:String} AND value < {identity_key_hi_0:String} \
                  AND has({identity_keys:Array(String)}, substring(value, 3, position(value, '\"', 3) - 3)))"
                    .to_string(),
            ]
        }
        LookupKind::Ip => quoted
            .iter()
            .enumerate()
            .map(|(n, key)| {
                params.push((format!("identity_key_lo_{n}"), format!("[{key},")));
                params.push((format!("identity_key_hi_{n}"), format!("[{key}-")));
                format!("(value >= {{identity_key_lo_{n}:String}} AND value < {{identity_key_hi_{n}:String}})")
            })
            .collect::<Vec<_>>(),
        LookupKind::Host | LookupKind::User => quoted
            .chunks(KEY_NEEDLES_PER_CALL)
            .enumerate()
            .map(|(n, needles)| {
                params.push((format!("identity_needles_{n}"), strings_param(needles)));
                format!("multiSearchAnyCaseInsensitive(value, {{identity_needles_{n}:Array(String)}})")
            })
            .collect(),
    };
    if terms.is_empty() {
        return (" AND 0".to_string(), params);
    }
    (format!(" AND ({})", terms.join(" OR ")), params)
}

/// What a lookup statement scans (NAN-3399): sources read directly, and / or
/// the merged index restricted to the live sources it serves
/// ([`super::identity_merged`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Relation {
    /// A path spec over the sources read directly.
    pub files: Option<String>,
    /// The merged file and the ids of the sources it serves.
    pub merged: Option<(String, Vec<u32>)>,
}

impl Relation {
    /// Only sources read directly.
    pub fn files(spec: &str) -> Self {
        Self { files: Some(spec.to_string()), merged: None }
    }

    fn params(&self) -> Vec<(String, String)> {
        let mut params = Vec::new();
        if let Some(spec) = &self.files {
            params.push(("identity_sources".to_string(), spec.clone()));
        }
        params.push(("identity_path".to_string(), IDENTITY_PATH.to_string()));
        if let Some((path, live)) = &self.merged {
            params.push(("identity_merged".to_string(), path.clone()));
            params.push((
                "identity_merged_live".to_string(),
                format!("[{}]", live.iter().map(u32::to_string).collect::<Vec<_>>().join(",")),
            ));
        }
        params
    }
}

/// The decoded observation relation over `relation`, restricted by
/// `key_filter` ([`key_filter`]) inside each scan.
fn observations_sql(relation: &Relation, key_filter: &str) -> String {
    const COLUMNS: &str = "SELECT JSONExtractString(value, 1) AS ip, JSONExtractInt(value, 2) AS hour_us, \
                JSONExtractString(value, 3) AS hostname, JSONExtractString(value, 4) AS fqdn, \
                JSONExtractString(value, 5) AS mac, JSONExtractString(value, 6) AS user, \
                JSONExtractString(value, 7) AS source";
    if let (Some(_), None) = (&relation.files, &relation.merged) {
        // Sources only (cold start, kill switch): the pre-NAN-3399
        // statement, byte for byte.
        return format!(
            "{COLUMNS}, toUInt8({EVENT_SOURCE_PRIORITY}) AS source_priority, \
                    toUnixTimestamp64Micro(first_time) AS first_us, toUnixTimestamp64Micro(last_time) AS last_us \
             FROM file({{identity_sources:String}}, Parquet) \
             WHERE path = {{identity_path:String}} AND value != ''{key_filter} \
               AND toUnixTimestamp64Micro(last_time) >= {{window_start_us:Int64}} \
               AND toUnixTimestamp64Micro(first_time) <= {{window_end_us:Int64}}"
        );
    }
    let window = "toUnixTimestamp64Micro(last_time) >= {window_start_us:Int64} \
                  AND toUnixTimestamp64Micro(first_time) <= {window_end_us:Int64}";
    let mut arms = Vec::new();
    if relation.files.is_some() {
        arms.push(format!(
            "SELECT value, first_time, last_time FROM file({{identity_sources:String}}, Parquet) \
             WHERE path = {{identity_path:String}} AND value != ''{key_filter} AND {window}"
        ));
    }
    if relation.merged.is_some() {
        // Merged rows are identity rows only; rows of sources that are not
        // live for this lookup are never read as observations.
        arms.push(format!(
            "SELECT value, first_time, last_time FROM file({{identity_merged:String}}, Parquet) \
             WHERE has({{identity_merged_live:Array(UInt32)}}, src) AND value != ''{key_filter} AND {window}"
        ));
    }
    if arms.is_empty() {
        // Unreachable from `lookup_bounds` (it returns early without files);
        // an empty relation, not a statement over nothing.
        arms.push("SELECT '' AS value, toDateTime64(0, 6, 'UTC') AS first_time, toDateTime64(0, 6, 'UTC') AS last_time WHERE 0".to_string());
    }
    format!(
        "{COLUMNS}, toUInt8({EVENT_SOURCE_PRIORITY}) AS source_priority, \
                toUnixTimestamp64Micro(first_time) AS first_us, toUnixTimestamp64Micro(last_time) AS last_us \
         FROM ({})",
        arms.join(" UNION ALL ")
    )
}

/// The lookup statement and its parameters. `settings` is appended verbatim.
pub fn plan_lookup(sources: &str, kind: LookupKind, items: &[Item], denied: &[String], settings: &str) -> (String, Vec<(String, String)>) {
    plan_lookup_over(&Relation::files(sources), kind, items, denied, settings)
}

/// [`plan_lookup`] over a [`Relation`] (sources and / or the merged index).
pub fn plan_lookup_over(relation: &Relation, kind: LookupKind, items: &[Item], denied: &[String], settings: &str) -> (String, Vec<(String, String)>) {
    let window_start = items.iter().map(|i| i.reference_us).min().unwrap_or(0).saturating_sub(LOOKBACK_US);
    let window_end = items.iter().map(|i| i.reference_us).max().unwrap_or(0);
    let key = kind.key_expr();
    let (filter, key_params) = key_filter(kind, items);
    let sql = format!(
        "SELECT ordinal, argMax(ip, rank) AS ip, argMax(hostname, rank) AS hostname, argMax(fqdn, rank) AS fqdn, \
                argMax(mac, rank) AS mac, argMax(user, rank) AS user, argMax(source, rank) AS source, \
                tupleElement(max(rank), 1) AS source_priority, tupleElement(max(rank), 2) AS observed_us \
         FROM ( \
           SELECT i.ordinal AS ordinal, o.ip AS ip, o.hostname AS hostname, o.fqdn AS fqdn, o.mac AS mac, \
                  o.user AS user, o.source AS source, \
                  tuple(o.source_priority, if(o.last_us <= i.reference_us, o.last_us, o.first_us)) AS rank \
           FROM (SELECT tupleElement(t, 1) AS ordinal, tupleElement(t, 2) AS lookup, tupleElement(t, 3) AS reference_us \
                 FROM (SELECT arrayJoin({{identity_items:Array(Tuple(UInt32, String, Int64))}}) AS t)) AS i \
           INNER JOIN (SELECT *, {key} AS lookup FROM ({obs}) WHERE NOT has({{identity_denied:Array(String)}}, lower(source))) AS o \
             ON o.lookup = i.lookup \
           WHERE o.first_us <= i.reference_us \
             AND if(o.last_us <= i.reference_us, o.last_us, o.first_us) >= {{window_start_us:Int64}} \
             AND if(o.last_us <= i.reference_us, o.last_us, o.first_us) >= i.reference_us - {{identity_lookback_us:Int64}} \
         ) GROUP BY ordinal ORDER BY ordinal{settings}",
        obs = observations_sql(relation, &filter),
    );
    let mut params = relation.params();
    params.extend([
        ("identity_items".to_string(), items_param(items)),
        ("identity_denied".to_string(), strings_param(denied)),
        ("identity_lookback_us".to_string(), LOOKBACK_US.to_string()),
        ("window_start_us".to_string(), window_start.to_string()),
        ("window_end_us".to_string(), window_end.to_string()),
    ]);
    params.extend(key_params);
    (sql, params)
}

/// Per IP item: the largest hourly distinct-hostname count in the 7 days up
/// to its reference time.
pub fn plan_nat(sources: &str, items: &[Item], denied: &[String], settings: &str) -> (String, Vec<(String, String)>) {
    plan_nat_over(&Relation::files(sources), items, denied, settings)
}

/// [`plan_nat`] over a [`Relation`].
pub fn plan_nat_over(relation: &Relation, items: &[Item], denied: &[String], settings: &str) -> (String, Vec<(String, String)>) {
    let window_start = items.iter().map(|i| i.reference_us).min().unwrap_or(0).saturating_sub(NAT_WINDOW_US + 3_600_000_000);
    let window_end = items.iter().map(|i| i.reference_us).max().unwrap_or(0);
    let (filter, key_params) = key_filter(LookupKind::Ip, items);
    let sql = format!(
        "SELECT ordinal, max(hosts) AS nat_host_count FROM ( \
           SELECT i.ordinal AS ordinal, o.hour_us AS hour_us, uniqExact(o.hostname) AS hosts \
           FROM (SELECT tupleElement(t, 1) AS ordinal, tupleElement(t, 2) AS lookup, tupleElement(t, 3) AS reference_us \
                 FROM (SELECT arrayJoin({{identity_items:Array(Tuple(UInt32, String, Int64))}}) AS t)) AS i \
           INNER JOIN (SELECT * FROM ({obs}) WHERE NOT has({{identity_denied:Array(String)}}, lower(source))) AS o \
             ON o.ip = i.lookup \
           WHERE o.first_us <= i.reference_us AND o.hour_us + 3600000000 > i.reference_us - {{identity_nat_window_us:Int64}} \
           GROUP BY ordinal, hour_us \
         ) GROUP BY ordinal ORDER BY ordinal{settings}",
        obs = observations_sql(relation, &filter),
    );
    let mut params = relation.params();
    params.extend([
        ("identity_items".to_string(), items_param(items)),
        ("identity_denied".to_string(), strings_param(denied)),
        ("identity_nat_window_us".to_string(), NAT_WINDOW_US.to_string()),
        ("window_start_us".to_string(), window_start.to_string()),
        ("window_end_us".to_string(), window_end.to_string()),
    ]);
    params.extend(key_params);
    (sql, params)
}

/// The coverage row of every entity-range partial in `sources`.
pub fn plan_coverage(sources: &str, settings: &str) -> (String, Vec<(String, String)>) {
    (
        format!(
            "SELECT _path AS file, sum(events) AS covered FROM file({{coverage_sources:String}}, Parquet) \
             WHERE path = {{identity_path:String}} AND value = {{coverage_value:String}} GROUP BY file{settings}"
        ),
        vec![
            ("coverage_sources".to_string(), sources.to_string()),
            ("identity_path".to_string(), IDENTITY_PATH.to_string()),
            ("coverage_value".to_string(), COVERAGE_VALUE.to_string()),
        ],
    )
}

fn int(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

fn text(row: &Value, key: &str) -> String {
    row.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

/// RFC 3339 with microseconds, the gen1 identity route's `observed_at` shape.
pub fn format_us(us: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_micros(us)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
        .unwrap_or_default()
}

/// Wire rows (`ordinal, value, ip, hostname, fqdn, user, mac, source,
/// source_priority, observed_at, nat_candidate, nat_host_count`) from the
/// lookup and NAT outputs. Items without a match produce no row.
pub fn output_rows(kind: LookupKind, items: &[Item], lookup: &[Value], nat: &[Value]) -> QueryResult<Vec<Value>> {
    let nat = nat
        .iter()
        .filter_map(|row| Some((int(row.get("ordinal")?)? as usize, int(row.get("nat_host_count")?)?)))
        .collect::<BTreeMap<_, _>>();
    let mut out = Vec::with_capacity(lookup.len());
    for row in lookup {
        let ordinal = row.get("ordinal").and_then(int).ok_or_else(|| internal("identity lookup row has no ordinal"))? as usize;
        let item = items.get(ordinal).ok_or_else(|| internal("identity lookup returned an unknown ordinal"))?;
        let observed = row.get("observed_us").and_then(int).ok_or_else(|| internal("identity lookup row has no time"))?;
        if observed > item.reference_us {
            return Err(internal("identity lookup returned an observation after its reference time"));
        }
        let ip = text(row, "ip");
        if kind == LookupKind::Ip && ip != item.key {
            return Err(internal("identity lookup substituted an IP binding"));
        }
        let hosts = if kind == LookupKind::Ip { nat.get(&ordinal).copied().unwrap_or(0) } else { 0 };
        out.push(json!({
            "ordinal": ordinal, "value": item.key, "ip": ip,
            "hostname": text(row, "hostname"), "fqdn": text(row, "fqdn"),
            "user": text(row, "user"), "mac": text(row, "mac"), "source": text(row, "source"),
            "source_priority": row.get("source_priority").and_then(int).unwrap_or(i64::from(EVENT_SOURCE_PRIORITY)),
            "observed_at": format_us(observed),
            "nat_candidate": hosts >= NAT_MIN_HOSTS as i64, "nat_host_count": hosts,
        }));
    }
    Ok(out)
}

/// What one identity source is, independent of where this call found it.
///
/// A leased partial's path is `pins/{lease}/{sha256}.bin`, a directory new
/// to every lease, so the path never names the same source twice; the
/// merged index (NAN-3399) keys its coverage by this instead.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceKey {
    /// A part's entity-range partial: immutable, content-addressed.
    Partial { part: PartId, sha256: String },
    /// A part's backfill file, written once under the state directory.
    Backfill(PartId),
}

/// One identity source: its stable identity and the local path to read it
/// at for the duration of this call's lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub key: SourceKey,
    pub path: PathBuf,
}

/// Where each window part's identity rows come from.
#[derive(Debug, Default)]
pub struct IndexSources {
    /// Entity-range partials of indexed parts.
    pub partials: Vec<Source>,
    /// Backfill files of the parts that are not indexed.
    pub backfilled: Vec<Source>,
    /// Parts with neither.
    pub missing: Vec<PartRef>,
    pub parts: usize,
    /// Held while the partial files are read.
    pub leases: Option<super::fetch::LocalParts>,
    /// NAN-4799: parts whose partial in `partials` was classified from the
    /// coverage memo without a lease (see [`Leasing::Unscanned`]); their
    /// `path` is empty until [`IndexSources::lease_partials`] leases them.
    pub unleased: Vec<PartRef>,
}

impl IndexSources {
    pub fn complete(&self) -> bool {
        self.missing.is_empty()
    }

    /// Every source, partials first.
    pub fn all(&self) -> Vec<Source> {
        self.partials.iter().chain(&self.backfilled).cloned().collect()
    }

    /// NAN-4799: lease the partials of `sources` this classification did
    /// not lease ([`Leasing::Unscanned`]) and set their paths. The returned
    /// lease must be held while those paths are read.
    pub async fn lease_partials(&self, engine: &PartQueryEngine, sources: &mut [Source]) -> QueryResult<Option<super::fetch::LocalParts>> {
        let wanted = sources
            .iter()
            .filter(|source| source.path.as_os_str().is_empty())
            .filter_map(|source| match &source.key {
                SourceKey::Partial { part, .. } => self.unleased.iter().find(|unleased| &unleased.part_id == part).cloned(),
                SourceKey::Backfill(_) => None,
            })
            .collect::<Vec<_>>();
        if wanted.is_empty() {
            return Ok(None);
        }
        let local = engine
            .fetcher()
            .ensure(&wanted, &[FileSet::Partial(PartialKind::EntityRanges)])
            .await
            .map_err(|error| internal(format!("{error:#}")))?;
        for source in sources.iter_mut().filter(|source| source.path.as_os_str().is_empty()) {
            let SourceKey::Partial { part, sha256 } = &source.key else { continue };
            let file = local
                .of(FileSet::Partial(PartialKind::EntityRanges))
                .find(|file| &file.part_id == part && &file.sha256 == sha256)
                .ok_or_else(|| internal(format!("identity partial of part {} was not leased", part.as_str())))?;
            source.path = file.path.clone();
        }
        Ok(Some(local))
    }

    pub fn state(&self) -> Value {
        json!({
            "state": if self.complete() { "complete" } else { "backfilling" },
            "parts": self.parts, "indexed": self.partials.len(),
            "backfilled": self.backfilled.len(), "missing": self.missing.len(),
        })
    }
}

pub fn backfill_path(state_dir: &Path, part: &PartId) -> PathBuf {
    state_dir.join(BACKFILL_DIR).join(format!("{}.parquet", part.as_str()))
}

/// Marker of a part the backfill could not index (row count or cap): it is
/// never re-derived (NAN-3077: such parts were re-fetched and re-decoded,
/// ~140 MB each, every pass, forever). Lookups over it use the event scan.
pub fn unindexable_path(state_dir: &Path, part: &PartId) -> PathBuf {
    state_dir.join(BACKFILL_DIR).join(format!("{}.unindexable", part.as_str()))
}

/// Niceness of the backfill derivation thread (lowest CPU priority).
const BACKFILL_NICE: libc::c_int = 19;

/// Which entity-range partials [`index_sources_leasing`] leases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leasing {
    /// Every indexed part's partial, including sources in the merged index.
    All,
    /// NAN-4799: only partials whose coverage this process has not scanned
    /// yet. A memoized part is classified from its signed provenance digest
    /// alone, so a background pass over the 30-day window re-reads no
    /// partial (a hosted tenant: ~350-420k R2 GETs/day of partials evicted
    /// outside the hot window, leased twice every 5 s pass). Its source's `path` stays
    /// empty; [`IndexSources::lease_partials`] leases it when it is read.
    Unscanned,
}

/// Classify the parts of `[from_us, to_us]`, leasing every indexed partial.
pub async fn index_sources(engine: &PartQueryEngine, state_dir: &Path, from_us: i64, to_us: i64) -> QueryResult<IndexSources> {
    index_sources_leasing(engine, state_dir, from_us, to_us, Leasing::All).await
}

/// Classify the parts of `[from_us, to_us]`, leasing per `leasing`.
pub async fn index_sources_leasing(
    engine: &PartQueryEngine, state_dir: &Path, from_us: i64, to_us: i64, leasing: Leasing,
) -> QueryResult<IndexSources> {
    let (parts, _, _, _) = engine.snapshot(from_us, to_us).await?;
    let mut sources = IndexSources { parts: parts.len(), ..IndexSources::default() };
    if parts.is_empty() {
        return Ok(sources);
    }
    // Signed records are memoized by the fetcher (`ensure` reads them too).
    let records = engine.fetcher().records(&parts).await.map_err(|error| internal(format!("{error:#}")))?;
    let digests = parts
        .iter()
        .zip(&records)
        .filter_map(|(part, record)| {
            super::fetch::file_digest(record, super::fetch::PartFile::Partial(PartialKind::EntityRanges))
                .map(|(_, sha256, _)| (part.part_id.clone(), sha256.to_string()))
        })
        .collect::<BTreeMap<_, _>>();
    let leased = parts
        .iter()
        .filter(|part| leasing == Leasing::All || engine.identity_coverage(&part.part_id).is_none())
        .cloned()
        .collect::<Vec<_>>();
    let local = if leased.is_empty() {
        None
    } else {
        Some(
            engine
                .fetcher()
                .ensure(&leased, &[FileSet::Partial(PartialKind::EntityRanges)])
                .await
                .map_err(|error| internal(format!("{error:#}")))?,
        )
    };
    let files = local
        .iter()
        .flat_map(|local| local.of(FileSet::Partial(PartialKind::EntityRanges)))
        .map(|file| (file.path.clone(), file.part_id.clone(), file.sha256.clone()))
        .collect::<Vec<_>>();
    // NAN-3077: a part's partial is immutable, so its coverage is scanned
    // once per process, not over the whole 30-day window on every lookup
    // and every backfill pass.
    let mut covered = BTreeMap::new();
    let mut unscanned = Vec::new();
    for part in &parts {
        if !digests.contains_key(&part.part_id) {
            continue;
        }
        match engine.identity_coverage(&part.part_id) {
            Some(Some(events)) => {
                covered.insert(part.part_id.clone(), events);
            }
            Some(None) => {}
            None => {
                if let Some((path, _, _)) = files.iter().find(|(_, id, _)| *id == part.part_id) {
                    unscanned.push((path.clone(), part.part_id.clone()));
                }
            }
        }
    }
    if !unscanned.is_empty() {
        let spec = super::partials::path_set(&unscanned.iter().map(|(path, _)| path.clone()).collect::<Vec<_>>())?;
        let (sql, params) = plan_coverage(&spec, &super::partials::settings(engine));
        let mut scanned = unscanned.iter().map(|(_, part)| (part.clone(), None)).collect::<BTreeMap<_, Option<i64>>>();
        for row in engine.execute_sql(sql, params).await? {
            let file = PathBuf::from(text(&row, "file"));
            if let (Some((_, part)), Some(events)) = (unscanned.iter().find(|(path, _)| same_file(path, &file)), row.get("covered").and_then(int)) {
                covered.insert(part.clone(), events);
                scanned.insert(part.clone(), Some(events));
            }
        }
        engine.remember_identity_coverage(scanned);
    }
    for part in parts {
        let file = match files.iter().find(|(_, id, _)| *id == part.part_id) {
            Some((path, _, sha256)) => Some((path.clone(), sha256.clone(), true)),
            // Memoized coverage, not leased: the signed digest names it.
            None => digests.get(&part.part_id).map(|sha256| (PathBuf::new(), sha256.clone(), false)),
        };
        match (file, covered.get(&part.part_id)) {
            (Some((path, sha256, leased)), Some(events)) if u64::try_from(*events).ok() == Some(part.rows) => {
                sources.partials.push(Source { key: SourceKey::Partial { part: part.part_id.clone(), sha256 }, path });
                if !leased {
                    sources.unleased.push(part);
                }
            }
            _ => {
                let backfill = backfill_path(state_dir, &part.part_id);
                if backfill.is_file() {
                    sources.backfilled.push(Source { key: SourceKey::Backfill(part.part_id.clone()), path: backfill });
                } else {
                    sources.missing.push(part);
                }
            }
        }
    }
    sources.leases = local;
    Ok(sources)
}

fn same_file(a: &Path, b: &Path) -> bool {
    a == b || std::fs::canonicalize(a).ok().zip(std::fs::canonicalize(b).ok()).is_some_and(|(a, b)| a == b)
}

/// Resolve `items` against the index. Returns the wire rows and the index state.
pub async fn lookup(
    engine: &PartQueryEngine,
    state_dir: &Path,
    kind: LookupKind,
    items: &[Item],
    denied: &[String],
) -> QueryResult<(Vec<Value>, Value)> {
    lookup_bounds(engine, state_dir, kind, items, denied, (i64::MIN, i64::MAX)).await
}

/// The durable lane bounds identity evidence by its moving retention receipt.
pub async fn lookup_bounds(
    engine: &PartQueryEngine, state_dir: &Path, kind: LookupKind, items: &[Item], denied: &[String],
    window: (i64, i64),
) -> QueryResult<(Vec<Value>, Value)> {
    if items.iter().any(|item| item.reference_us < window.0 || item.reference_us > window.1) {
        return Err(invalid("identity reference escaped the job window"));
    }
    let from = items.iter().map(|i| i.reference_us).min().unwrap_or(0).saturating_sub(LOOKBACK_US).max(window.0);
    let to = items.iter().map(|i| i.reference_us).max().unwrap_or(0).min(window.1);
    let started = std::time::Instant::now();
    // Classify first: the merged index already holds most sources. Leasing
    // all partials here re-fetches the cold 30-day window on every lookup,
    // even when neither statement below reads a single original partial.
    let sources = index_sources_leasing(engine, state_dir, from, to, Leasing::Unscanned).await?;
    let sources_s = started.elapsed().as_secs_f64();
    let files = sources.all();
    let mut state = sources.state();
    // NAN-3394: numeric per-phase evidence (the envelope's `planner`).
    let mut timing = json!({
        "identity_items": items.len(),
        "identity_keys": items.iter().map(|item| item.key.as_str()).collect::<BTreeSet<_>>().len(),
        "identity_files": files.len(),
        "identity_sources_s": sources_s,
        "identity_partial_leases": sources.leases.iter()
            .map(|local| local.of(FileSet::Partial(PartialKind::EntityRanges)).count()).sum::<usize>(),
    });
    if files.is_empty() {
        state["timing"] = timing;
        return Ok((Vec::new(), state));
    }
    // NAN-3399: the merged index serves the live sources it covers; only
    // the rest (parts newer than its last build) are read one by one.
    let mut scan = super::identity_merged::scan(engine.identity_merged().for_lookup(), &files);
    let tail_lease = sources.lease_partials(engine, &mut scan.tail).await?;
    timing["identity_sources_s"] = json!(started.elapsed().as_secs_f64());
    timing["identity_partial_leases"] = json!(sources.leases.iter().chain(tail_lease.iter())
        .map(|local| local.of(FileSet::Partial(PartialKind::EntityRanges)).count()).sum::<usize>());
    let relation = Relation {
        files: if scan.tail.is_empty() { None } else {
            Some(super::partials::path_set(&scan.tail.iter().map(|source| source.path.clone()).collect::<Vec<_>>())?)
        },
        merged: match &scan.merged {
            Some((merged, live)) => Some((
                merged.path().to_str().ok_or_else(|| internal("identity merged path is not UTF-8"))?.to_string(),
                live.clone(),
            )),
            None => None,
        },
    };
    timing["identity_merged_sources"] = json!(scan.merged.as_ref().map_or(0, |(_, live)| live.len()));
    timing["identity_tail_files"] = json!(scan.tail.len());
    let settings = super::partials::settings(engine);
    let (sql, mut params) = plan_lookup_over(&relation, kind, items, denied, &settings);
    for (name, value) in &mut params {
        if name == "window_start_us" { *value = from.to_string(); }
    }
    let lookup_started = std::time::Instant::now();
    let found = engine.execute_sql(sql, params).await?;
    timing["identity_lookup_s"] = json!(lookup_started.elapsed().as_secs_f64());
    let nat_started = std::time::Instant::now();
    let nat = if kind == LookupKind::Ip && !found.is_empty() {
        let (sql, mut params) = plan_nat_over(&relation, items, denied, &settings);
        for (name, value) in &mut params {
            if name == "window_start_us" {
                let initial = value.parse::<i64>().map_err(internal)?;
                *value = initial.max(window.0).to_string();
            }
        }
        engine.execute_sql(sql, params).await?
    } else {
        Vec::new()
    };
    timing["identity_nat_s"] = json!(nat_started.elapsed().as_secs_f64());
    state["timing"] = timing;
    // The merged file and the source leases outlive both statements.
    drop(scan);
    drop(tail_lease);
    drop(sources);
    Ok((output_rows(kind, items, &found, &nat)?, state))
}

/// Derive one part's identity rows from its data files (Parquet, projected
/// to the leaves the derivation reads).
pub fn derive_from_data_files(paths: &[PathBuf], cap_bytes: usize) -> anyhow::Result<IdentityAccumulator> {
    let mut accumulator = IdentityAccumulator::new(cap_bytes);
    projected_batches(paths, 8_192, |batch| {
        accumulator.add_batch(&batch)?;
        Ok(!accumulator.overflowed())
    })?;
    Ok(accumulator)
}

pub(super) fn projected_batches(paths: &[PathBuf], batch_rows: usize, mut consume: impl FnMut(arrow_array::RecordBatch) -> anyhow::Result<bool>) -> anyhow::Result<()> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use parquet::arrow::ProjectionMask;
    const LEAVES: [&str; 9] = [
        "time", "src_endpoint.ip", "src_endpoint.hostname", "device.hostname", "src_endpoint.mac",
        "user.name", "actor.user.name", "metadata.log_source", "metadata.product.name",
    ];
    for path in paths {
        let builder = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?;
        let schema = builder.parquet_schema();
        let leaves = (0..schema.num_columns())
            .filter(|&index| {
                let name = schema.column(index).path().string();
                LEAVES.iter().any(|leaf| name == *leaf || name.starts_with(&format!("{leaf}.")))
            })
            .collect::<Vec<_>>();
        let mask = ProjectionMask::leaves(schema, leaves);
        for batch in builder.with_projection(mask).with_batch_size(batch_rows).build()? {
            if !consume(batch?)? { return Ok(()); }
        }
    }
    Ok(())
}

/// What one backfill pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BackfillReport {
    pub derived: usize,
    pub remaining: usize,
    pub removed: usize,
    /// Parts marked unindexable this pass (never retried).
    pub unindexable: usize,
}

/// One bounded, resumable backfill pass over the lookback window: derive up
/// to `budget` missing parts (newest first), each into its own file (written
/// to a temporary name and renamed, so a crash leaves nothing half-done and
/// the next pass resumes at the next missing part), and delete backfill files
/// of parts that left the window or the log.
///
/// `slot` (NAN-3077) is the admission slot the caller took for the chDB
/// coverage read; it is released before any part is fetched or derived
/// (neither uses a query lane), so the backfill never holds a lane an
/// interactive or detect request could use.
pub async fn backfill_once(
    engine: &PartQueryEngine,
    state_dir: &Path,
    now_us: i64,
    budget: usize,
    slot: Option<super::engine::AdmissionSlot>,
) -> QueryResult<BackfillReport> {
    // NAN-4799: the pass reads only `missing`; memoized partials stay unleased.
    let sources = index_sources_leasing(engine, state_dir, now_us.saturating_sub(LOOKBACK_US), now_us, Leasing::Unscanned).await?;
    drop(slot);
    let mut report = BackfillReport::default();
    let dir = state_dir.join(BACKFILL_DIR);
    // Retire files of parts that are no longer live in the window.
    let (live, _, _, _) = engine.snapshot(now_us.saturating_sub(LOOKBACK_US), now_us).await?;
    let live = live
        .iter()
        .flat_map(|part| [format!("{}.parquet", part.part_id.as_str()), format!("{}.unindexable", part.part_id.as_str())])
        .collect::<BTreeSet<_>>();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".identity-spill-") && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                // A process crash can leave local spill runs. They are never
                // index sources and are retired before the next serial pass.
                if std::fs::remove_dir_all(entry.path()).is_ok() { report.removed += 1; }
            } else if !live.contains(&name) && std::fs::remove_file(entry.path()).is_ok() {
                report.removed += 1;
            }
        }
    }
    let missing = backfill_queue(state_dir, sources.missing.clone());
    drop(sources);
    report.remaining = missing.len();
    std::fs::create_dir_all(&dir).map_err(internal)?;
    let spill = super::identity_spill::enabled();
    for part in missing.into_iter().take(budget) {
        let local = engine.fetcher().ensure(std::slice::from_ref(&part), &[FileSet::AllData]).await.map_err(|error| internal(format!("{error:#}")))?;
        let paths = local.of(FileSet::AllData).map(|file| file.path.clone()).collect::<Vec<_>>();
        let target = backfill_path(state_dir, &part.part_id);
        let temporary = dir.join(format!(".{}.{}.tmp", part.part_id.as_str(), uuid::Uuid::new_v4().simple()));
        let rows = part.rows;
        let written = run_niced(move || -> anyhow::Result<bool> {
            if spill {
                if !super::identity_spill::derive(&paths, &temporary, rows)? { return Ok(false); }
                std::fs::rename(&temporary, &target)?;
                return Ok(true);
            }
            let acc = derive_from_data_files(&paths, BACKFILL_BYTES_CAP)?;
            if acc.overflowed() || acc.covered_rows() != rows {
                return Ok(false);
            }
            let entities = acc
                .into_rows()
                .into_iter()
                .map(|(value, range)| EntityRangeRow {
                    key: (IDENTITY_PATH.to_string(), value),
                    first_time: range.first_us,
                    last_time: range.last_us,
                    events: range.events,
                })
                .collect::<Vec<_>>();
            write_sorted(entities, &temporary)?;
            std::fs::rename(&temporary, &target)?;
            Ok(true)
        })
        .await?;
        drop(local);
        if written {
            report.derived += 1;
            report.remaining -= 1;
        } else {
            let marker = if spill { super::identity_spill::MARKER } else { b"" };
            std::fs::write(unindexable_path(state_dir, &part.part_id), marker).map_err(internal)?;
            report.unindexable += 1;
            report.remaining -= 1;
            tracing::warn!(part = %part.part_id.as_str(), "identity backfill could not index a part (row count or cap); lookups over it use the event scan; not retried");
        }
    }
    Ok(report)
}

/// The parts a backfill pass may derive, newest first: missing parts not
/// marked unindexable.
fn backfill_queue(state_dir: &Path, missing: Vec<PartRef>) -> Vec<PartRef> {
    backfill_queue_for(state_dir, missing, super::identity_spill::enabled())
}

fn backfill_queue_for(state_dir: &Path, mut missing: Vec<PartRef>, spill: bool) -> Vec<PartRef> {
    missing.retain(|part| {
        let marker = unindexable_path(state_dir, &part.part_id);
        if !spill { return !marker.is_file(); }
        // Retry old cap-only failures once under the new derivation. A current
        // marker (or unreadable marker) never starts an idle retry loop.
        match std::fs::read(&marker) {
            Ok(bytes) => bytes != super::identity_spill::MARKER,
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        }
    });
    missing.sort_by_key(|part| std::cmp::Reverse(part.max_time_us));
    missing
}

/// Run `work` on a dedicated thread at the lowest CPU priority (Linux
/// niceness is per thread), so the backfill's decode never competes with a
/// query lane for a core.
async fn run_niced<T: Send + 'static>(work: impl FnOnce() -> anyhow::Result<T> + Send + 'static) -> QueryResult<T> {
    let (done, result) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("identity-backfill".to_string())
        .spawn(move || {
            // SAFETY: plain syscalls on this thread's own id.
            unsafe {
                let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
                libc::setpriority(libc::PRIO_PROCESS, tid, BACKFILL_NICE);
            }
            let _ = done.send(work());
        })
        .map_err(internal)?;
    result.await.map_err(internal)?.map_err(|error| internal(format!("{error:#}")))
}

/// Poll interval of the background backfill once nothing is missing.
pub const BACKFILL_INTERVAL: Duration = Duration::from_secs(60);
/// Poll interval while parts are missing: one part per pass, and only when
/// every query slot is free (NAN-3077).
pub const BACKFILL_BUSY_POLL: Duration = Duration::from_secs(5);

/// Decode every observation row of a partial or backfill file (tests, lab).
pub fn read_observations(path: &Path) -> anyhow::Result<Vec<(crate::identity_observations::Observation, i64, i64, i64, u64)>> {
    use crate::part_ingest::partials::PartialRow;
    let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?.build()?;
    let mut out = Vec::new();
    for batch in reader {
        for row in EntityRangeRow::from_batch(&batch?)? {
            if row.key.0 != IDENTITY_PATH {
                continue;
            }
            if let Some((observation, hour)) = decode_value(&row.key.1) {
                out.push((observation, hour, row.first_time, row.last_time, row.events));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(ordinal: usize, key: &str, reference_us: i64) -> Item {
        Item { ordinal, key: key.into(), reference_us }
    }

    fn sample_part() -> PartRef {
        PartRef {
            part_id: PartId::new(1_790_000_000_000).unwrap(),
            level: crate::parts::levels::Level::Hour,
            event_hour: 0,
            event_day: None,
            rows: 1,
            min_time_us: 0,
            max_time_us: 0,
            schema_fingerprint: String::new(),
            provenance_sha256: String::new(),
            merkle_root: String::new(),
            sorted: true,
            data_bytes: 0,
            row_groups: 1,
            data_files: 1,
        }
    }

    #[test]
    fn unindexable_parts_leave_the_backfill_queue_for_good() {
        // NAN-3077: a part that cannot be indexed was re-derived every pass.
        let dir = tempfile::tempdir().unwrap();
        let part = |ms: i64| PartRef { part_id: PartId::new(ms).unwrap(), ..sample_part() };
        let (old, new) = (part(1_790_000_000_000), part(1_790_000_100_000));
        let queue = |parts: Vec<PartRef>| backfill_queue_for(dir.path(), parts, false).into_iter().map(|p| p.part_id).collect::<Vec<_>>();
        std::fs::create_dir_all(dir.path().join(BACKFILL_DIR)).unwrap();
        let mut old_first = old.clone();
        old_first.max_time_us = 1;
        let mut new_last = new.clone();
        new_last.max_time_us = 2;
        assert_eq!(queue(vec![old_first.clone(), new_last.clone()]), vec![new.part_id.clone(), old.part_id.clone()], "newest first");
        std::fs::write(unindexable_path(dir.path(), &new.part_id), b"").unwrap();
        assert_eq!(queue(vec![old_first, new_last]), vec![old.part_id.clone()]);
    }

    #[test]
    fn spill_backfill_retries_legacy_cap_markers_once_per_derivation_version() {
        let dir = tempfile::tempdir().unwrap();
        let part = sample_part();
        std::fs::create_dir_all(dir.path().join(BACKFILL_DIR)).unwrap();
        let marker = unindexable_path(dir.path(), &part.part_id);
        std::fs::write(&marker, b"").unwrap();
        assert!(backfill_queue_for(dir.path(), vec![part.clone()], false).is_empty());
        assert_eq!(backfill_queue_for(dir.path(), vec![part.clone()], true).len(), 1);
        std::fs::write(marker, super::super::identity_spill::MARKER).unwrap();
        assert!(backfill_queue_for(dir.path(), vec![part.clone()], true).is_empty());
        assert!(backfill_queue_for(dir.path(), vec![part], false).is_empty());
    }

    #[test]
    fn background_work_takes_a_slot_only_when_every_slot_is_free() {
        use std::sync::Arc;
        let admission = Arc::new(tokio::sync::Semaphore::new(2));
        let background = super::super::engine::idle_permit(&admission, 2).expect("idle engine");
        // The other slot stays free for a search; a second background pass
        // is refused while anything runs.
        let search = admission.clone().try_acquire_owned().expect("a search is never blocked by one background pass");
        assert!(super::super::engine::idle_permit(&admission, 2).is_none());
        drop(background);
        assert!(super::super::engine::idle_permit(&admission, 2).is_none(), "a running search keeps background work out");
        drop(search);
        assert!(super::super::engine::idle_permit(&admission, 2).is_some());
    }

    #[test]
    fn items_are_bounded_and_normalized_per_kind() {
        let raw = |v: &str| vec![(v.to_string(), "2026-09-29T12:00:00Z".to_string())];
        assert_eq!(normalize_items(LookupKind::Ip, &raw(" 10.1.3.7 ")).unwrap()[0].key, "10.1.3.7");
        assert_eq!(normalize_items(LookupKind::Ip, &raw("2001:DB8::1")).unwrap()[0].key, "2001:db8::1");
        assert!(normalize_items(LookupKind::Ip, &raw("10.0.0.1' OR 1")).is_err());
        assert_eq!(normalize_items(LookupKind::Host, &raw("WS-IT-052")).unwrap()[0].key, "ws-it-052");
        assert!(normalize_items(LookupKind::User, &raw("a\u{7}b")).is_err());
        assert!(normalize_items(LookupKind::Ip, &[]).is_err());
        let many = (0..=MAX_ITEMS).map(|i| (format!("10.0.{}.{}", i / 250, i % 250), "2026-09-29T12:00:00Z".to_string())).collect::<Vec<_>>();
        assert!(normalize_items(LookupKind::Ip, &many).is_err());
        assert!(normalize_items(LookupKind::Ip, &[("10.0.0.1".into(), "yesterday".into())]).is_err());
    }

    #[test]
    fn values_reach_sql_only_as_escaped_parameters() {
        let items = vec![item(0, "o'brien\\x", 5)];
        let (sql, params) = plan_lookup("/c/x.parquet", LookupKind::User, &items, &["a'b".into()], "");
        assert!(!sql.contains("o'brien"));
        let map = params.into_iter().collect::<BTreeMap<_, _>>();
        assert_eq!(map["identity_items"], "[(0,'o\\'brien\\\\x',5)]");
        assert_eq!(map["identity_denied"], "['a\\'b']");
        assert_eq!(map["identity_path"], IDENTITY_PATH);
        assert_eq!(map["window_start_us"], (5 - LOOKBACK_US).to_string());
        assert!(sql.contains("lower(user) AS lookup"));
        let (host_sql, _) = plan_lookup("/c/x.parquet", LookupKind::Host, &items, &[], "");
        assert!(host_sql.contains("arrayDistinct([lower(hostname), lower(fqdn)])"));
    }

    #[test]
    fn a_sources_only_relation_is_the_pre_merge_statement_byte_for_byte() {
        // NAN-3399: cold start and the kill switch must plan exactly what
        // shipped before the merged index (no wrapping subquery).
        let filter = " AND (value >= {k0:String})";
        let frozen = format!(
            "SELECT JSONExtractString(value, 1) AS ip, JSONExtractInt(value, 2) AS hour_us, \
             JSONExtractString(value, 3) AS hostname, JSONExtractString(value, 4) AS fqdn, \
             JSONExtractString(value, 5) AS mac, JSONExtractString(value, 6) AS user, \
             JSONExtractString(value, 7) AS source, toUInt8({EVENT_SOURCE_PRIORITY}) AS source_priority, \
             toUnixTimestamp64Micro(first_time) AS first_us, toUnixTimestamp64Micro(last_time) AS last_us \
             FROM file({{identity_sources:String}}, Parquet) \
             WHERE path = {{identity_path:String}} AND value != ''{filter} \
             AND toUnixTimestamp64Micro(last_time) >= {{window_start_us:Int64}} \
             AND toUnixTimestamp64Micro(first_time) <= {{window_end_us:Int64}}"
        );
        assert_eq!(observations_sql(&Relation::files("/c/x.parquet"), filter), frozen);
        let merged = Relation { files: None, merged: Some(("/s/m.parquet".into(), vec![1, 2])) };
        assert!(observations_sql(&merged, filter).contains("has({identity_merged_live:Array(UInt32)}, src)"));
        let params = Relation::files("/c/x.parquet").params();
        assert_eq!(params[0], ("identity_sources".to_string(), "/c/x.parquet".to_string()));
        assert_eq!(params[1], ("identity_path".to_string(), IDENTITY_PATH.to_string()));
    }

    /// The scan's `FROM file(...) WHERE ...` text: the predicates the Parquet
    /// reader evaluates before any `JSONExtract` or the item join.
    fn scan_where(sql: &str) -> &str {
        let start = sql.find("FROM file({identity_sources:String}, Parquet)").expect("observation scan");
        let end = start + sql[start..].find(") WHERE NOT has(").expect("deny filter after the scan");
        &sql[start..end]
    }

    #[test]
    fn ip_lookup_pushes_distinct_item_keys_into_the_scan_as_value_ranges() {
        // NAN-3394: the scan decoded every observation of the 30-day window
        // and joined afterwards (a miss cost the same as a hit). Each item's
        // key now bounds `value` in the scan itself, so the sorted partial's
        // row-group statistics skip every other entity.
        let items = vec![item(0, "10.1.2.46", 5), item(1, "10.1.3.7", 6), item(2, "10.1.2.46", 7)];
        for (sql, params) in [
            plan_lookup("/c/x.parquet", LookupKind::Ip, &items, &[], ""),
            plan_nat("/c/x.parquet", &items, &[], ""),
        ] {
            assert_eq!(sql.matches("FROM file(").count(), 1, "one scan, one statement: {sql}");
            let scan = scan_where(&sql);
            for n in 0..2 {
                assert!(
                    scan.contains(&format!(
                        "(value >= {{identity_key_lo_{n}:String}} AND value < {{identity_key_hi_{n}:String}})"
                    )),
                    "{scan}"
                );
            }
            assert!(!scan.contains("identity_key_lo_2"), "duplicate keys share one range: {scan}");
            assert!(!sql.contains("10.1.2.46"), "keys reach SQL only as parameters");
            let map = params.into_iter().collect::<BTreeMap<_, _>>();
            assert_eq!(map["identity_key_lo_0"], r#"["10.1.2.46","#);
            assert_eq!(map["identity_key_hi_0"], r#"["10.1.2.46"-"#);
            assert_eq!(map["identity_key_lo_1"], r#"["10.1.3.7","#);
        }
    }

    #[test]
    fn many_ip_keys_use_one_spanning_range_and_a_key_set() {
        let items = (0..=IP_RANGE_KEYS).map(|i| item(i, &format!("10.0.0.{}", i + 1), 5)).collect::<Vec<_>>();
        let (sql, params) = plan_lookup("/c/x.parquet", LookupKind::Ip, &items, &[], "");
        let scan = scan_where(&sql);
        assert!(scan.contains("value >= {identity_key_lo_0:String} AND value < {identity_key_hi_0:String}"), "{scan}");
        assert!(scan.contains("has({identity_keys:Array(String)}, substring(value, 3, position(value, '\"', 3) - 3))"), "{scan}");
        assert!(!scan.contains("identity_key_lo_1"), "{scan}");
        let map = params.into_iter().collect::<BTreeMap<_, _>>();
        assert_eq!(map["identity_key_lo_0"], r#"["10.0.0.1","#, "the smallest key's range start");
        assert_eq!(map["identity_key_hi_0"], r#"["10.0.0.9"-"#, "the largest key's range end");
        assert!(map["identity_keys"].starts_with("['10.0.0.1','10.0.0.10',"), "{}", map["identity_keys"]);
    }

    #[test]
    fn ip_value_range_is_exactly_the_items_observations() {
        use crate::identity_observations::{encode_value, Observation};
        let observation = |ip: &str| Observation {
            ip: ip.into(), hostname: "ws-a".into(), fqdn: "ws-a.corp.local".into(),
            mac: String::new(), user: "alice".into(), source: "windows_sysmon".into(),
        };
        let (_, params) = plan_lookup("/c/x.parquet", LookupKind::Ip, &[item(0, "10.0.0.1", 5)], &[], "");
        let map = params.into_iter().collect::<BTreeMap<_, _>>();
        let (lo, hi) = (map["identity_key_lo_0"].as_str(), map["identity_key_hi_0"].as_str());
        let in_range = |value: &str| lo <= value && value < hi;
        assert!(in_range(&encode_value(&observation("10.0.0.1"), 0)));
        assert!(in_range(&encode_value(&observation("10.0.0.1"), i64::MAX)));
        for other in ["10.0.0.10", "10.0.0.", "10.0.0.2", "10.0.0.0", "2001:db8::1"] {
            assert!(!in_range(&encode_value(&observation(other), 0)), "{other}");
        }
        assert!(!in_range(""), "the coverage row is not an observation");
    }

    #[test]
    fn host_and_user_lookups_prefilter_the_scan_by_quoted_key() {
        // A host key matches hostname or FQDN anywhere in the value, in any
        // ASCII case: the prefilter is a superset; the join stays exact.
        let items = vec![item(0, "ws-it-052", 5), item(1, "ws-it-052", 6), item(2, "o\"brien", 7)];
        for kind in [LookupKind::Host, LookupKind::User] {
            let (sql, params) = plan_lookup("/c/x.parquet", kind, &items, &[], "");
            let scan = scan_where(&sql);
            assert!(
                scan.contains("multiSearchAnyCaseInsensitive(value, {identity_needles_0:Array(String)})"),
                "{scan}"
            );
            let map = params.into_iter().collect::<BTreeMap<_, _>>();
            assert_eq!(map["identity_needles_0"], r#"['"o\\"brien"','"ws-it-052"']"#);
        }
        // Needle lists stay under multiSearchAny's needle bound.
        let many = (0..MAX_ITEMS).map(|i| item(i, &format!("host-{i}"), 5)).collect::<Vec<_>>();
        let (sql, params) = plan_lookup("/c/x.parquet", LookupKind::Host, &many, &[], "");
        let chunks = params.iter().filter(|(name, _)| name.starts_with("identity_needles_")).count();
        assert_eq!(chunks, MAX_ITEMS.div_ceil(KEY_NEEDLES_PER_CALL));
        assert_eq!(scan_where(&sql).matches("multiSearchAnyCaseInsensitive").count(), chunks);
    }

    #[test]
    fn output_rows_bind_ordinals_and_refuse_substitution_or_future_rows() {
        let items = vec![item(0, "10.1.3.7", 1_000), item(1, "10.9.9.9", 1_000)];
        let lookup = vec![json!({"ordinal": 0, "ip": "10.1.3.7", "hostname": "ws-it-052", "fqdn": "ws-it-052.corp.local",
            "user": "jhernandez", "mac": "", "source": "windows_sysmon", "source_priority": 50, "observed_us": "900"})];
        let nat = vec![json!({"ordinal": 0, "nat_host_count": "3"})];
        let rows = output_rows(LookupKind::Ip, &items, &lookup, &nat).unwrap();
        assert_eq!(rows.len(), 1, "the miss has no row");
        assert_eq!(rows[0]["hostname"], "ws-it-052");
        assert_eq!(rows[0]["nat_candidate"], true);
        assert_eq!(rows[0]["observed_at"], "1970-01-01T00:00:00.000900Z");
        let mut swapped = lookup.clone();
        swapped[0]["ip"] = json!("10.1.3.8");
        assert!(output_rows(LookupKind::Ip, &items, &swapped, &[]).is_err());
        let mut future = lookup.clone();
        future[0]["observed_us"] = json!(1_001);
        assert!(output_rows(LookupKind::Ip, &items, &future, &[]).is_err());
        let mut unknown = lookup;
        unknown[0]["ordinal"] = json!(7);
        assert!(output_rows(LookupKind::Ip, &items, &unknown, &[]).is_err());
    }

    #[test]
    fn backfill_derivation_reads_projected_part_files_and_matches_ingest() {
        use arrow_array::{ArrayRef, RecordBatch, StringArray, StructArray, TimestampMicrosecondArray};
        use arrow_schema::{DataType, Field, Fields, Schema, TimeUnit};
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let strings = |values: Vec<Option<&str>>| Arc::new(StringArray::from(values)) as ArrayRef;
        let endpoint_fields = Fields::from(vec![
            Field::new("ip", DataType::Utf8, true), Field::new("hostname", DataType::Utf8, true),
        ]);
        let endpoint = StructArray::new(endpoint_fields.clone(), vec![
            strings(vec![Some("10.1.3.7"), Some("8.8.8.8"), Some("10.1.3.7")]),
            strings(vec![Some("ws-it-052.corp.local"), Some("x"), Some("ws-it-052.corp.local")]),
        ], None);
        let meta_fields = Fields::from(vec![Field::new("log_source", DataType::Utf8, true), Field::new("uid", DataType::Utf8, true)]);
        let meta = StructArray::new(meta_fields.clone(), vec![
            strings(vec![Some("windows_sysmon"); 3]), strings(vec![Some("a"), Some("b"), Some("c")]),
        ], None);
        let time_type = DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into()));
        let schema = Arc::new(Schema::new(vec![
            Field::new("time", time_type, false),
            Field::new("src_endpoint", DataType::Struct(endpoint_fields), true),
            Field::new("metadata", DataType::Struct(meta_fields), true),
            Field::new("message", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(schema.clone(), vec![
            Arc::new(TimestampMicrosecondArray::from(vec![10, 20, 3_600_000_010]).with_timezone("+00:00")),
            Arc::new(endpoint), Arc::new(meta), strings(vec![Some("m"); 3]),
        ]).unwrap();
        let path = dir.path().join("data-00000.parquet");
        let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();

        let derived = derive_from_data_files(&[path], BACKFILL_BYTES_CAP).unwrap();
        let mut ingest = IdentityAccumulator::new(BACKFILL_BYTES_CAP);
        ingest.add_batch(&batch).unwrap();
        assert_eq!(derived.covered_rows(), 3);
        assert_eq!(derived.into_rows(), ingest.into_rows(), "backfill and ingest derive identical rows");
    }
}
