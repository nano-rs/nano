// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5718: decorate the rows a plain `| prevalence enrich=true` RETURNS with
//! the real-time summary truth for the artifacts the prevalence dicts miss.
//!
//! The pushdown decorates every row from `dictGetOrDefault` on the prevalence
//! CACHE dicts. Those negative-cache a brand-new artifact for their LIFETIME
//! (15–30 min), so a binary first seen minutes ago decorates as
//! `host_count NULL, is_rare 0, prevalence_score 0`, while the filter form
//! (NAN-1705 rescue) and `POST /api/prevalence/bulk` report it rare.
//!
//! Scope, by design narrow:
//! - Only a plain decorating `enrich=true` ([`page_rescue_applies`]). The
//!   filter forms and `enrich=true | where host_count < N` / `| where is_rare`
//!   (rarity rules) keep the NAN-1705 in-SQL rescue unchanged.
//! - Only the rows actually returned: the keys come from the fetched rows'
//!   own `_domain_lookup` / `_ip_lookup` / `_hash_lookup` columns, so there is
//!   no re-scan of the base and no drift on timestamp ties or offsets.
//! - Only TRUE dict misses: the row's own dict projection reads the 9999
//!   sentinel AND the dict's `last_seen` is the epoch-0 default. A common
//!   (>= 1000 hosts) artifact is cached in the dict with its real `last_seen`,
//!   so it is never probed and no `uniqMerge` runs over it.
//! - One combined probe (a `UNION ALL` over the three summaries' primary
//!   keys), carrying the request's derived query id and ClickHouse settings.
//! - Misses beyond [`PREVALENCE_RESCUE_MISS_KEY_CAP`] are counted, never
//!   silently dropped: the run is flagged PARTIAL.

use super::prevalence_processing::{
    decorated_filter_rescue_threshold, RescuedArtifact, PREVALENCE_DICT_HOST_COUNT_CUTOFF,
    PREVALENCE_RESCUE_MISS_KEY_CAP,
};
use super::prevalence_scan::PrevalenceScanPlan;
use super::*;
use crate::prevalence::{ArtifactType, PrevalenceRepository};
use crate::search::companion_query_id::CompanionQuery;
use crate::sql_hygiene::escape_sql_string;
use std::collections::{HashMap, HashSet};

/// One prevalence dimension of the pushdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MissKind {
    Domain,
    Ip,
    Hash,
}

impl MissKind {
    /// Tie order of the pushdown's winner selection (domain → ip → hash).
    pub(crate) const ALL: [MissKind; 3] = [MissKind::Domain, MissKind::Ip, MissKind::Hash];

    /// The `_dp` / `_ip` / `_hp` prefix of the row's per-dimension columns.
    fn prefix(self) -> &'static str {
        match self {
            MissKind::Domain => "_dp",
            MissKind::Ip => "_ip",
            MissKind::Hash => "_hp",
        }
    }

    fn lookup_col(self) -> &'static str {
        match self {
            MissKind::Domain => "_domain_lookup",
            MissKind::Ip => "_ip_lookup",
            MissKind::Hash => "_hash_lookup",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            MissKind::Domain => "domain",
            MissKind::Ip => "ip",
            MissKind::Hash => "hash",
        }
    }

    fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.label() == label)
    }

    fn dict(self) -> &'static str {
        match self {
            MissKind::Domain => "nanosiem.domain_prevalence_dict",
            MissKind::Ip => "nanosiem.ip_prevalence_dict",
            MissKind::Hash => "nanosiem.hash_prevalence_dict",
        }
    }

    pub(crate) fn summary_table(self) -> &'static str {
        match self {
            MissKind::Domain => "domain_prevalence_summary",
            MissKind::Ip => "ip_prevalence_summary",
            MissKind::Hash => "hash_prevalence_summary",
        }
    }

    /// (key column, host-count state column, extra summary predicate) — the
    /// dict source contract (`clickhouse/130_memory_bound_dict_source_queries.sql`),
    /// same as `PrevalenceRepository::get_bulk_summary_prevalence`.
    fn summary_columns(self) -> (&'static str, &'static str, &'static str) {
        match self {
            MissKind::Domain => ("domain", "source_host_count", ""),
            MissKind::Ip => ("ip", "source_host_count", "is_private = 0 AND "),
            MissKind::Hash => ("file_hash", "host_count", ""),
        }
    }

    /// The key as the summary stores it, or `None` when this dimension can
    /// never hold it: a hash must be hex of a real digest length (a
    /// single-label hostname such as `ws-01` is not), a domain must be a
    /// dotted domain, an IP must be public (the ip summary keeps
    /// `is_private = 0` only). Hash and domain are MV-lowercased; IP is raw.
    pub(crate) fn rescuable_key(self, raw: &str) -> Option<String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        match self {
            MissKind::Hash => {
                let key = raw.to_ascii_lowercase();
                (matches!(key.len(), 32 | 40 | 64 | 128)
                    && key.chars().all(|c| c.is_ascii_hexdigit()))
                .then_some(key)
            }
            MissKind::Domain => {
                let key = raw.to_lowercase();
                ArtifactType::detect(&key).is_domain().then_some(key)
            }
            MissKind::Ip => {
                (ArtifactType::detect(raw) == ArtifactType::IpAddress).then(|| raw.to_string())
            }
        }
    }
}

/// Whether a pushdown's returned rows get the page rescue: a plain
/// decorating `enrich=true`. Everything else keeps its previous behavior:
/// - filter forms (`| prevalence hash_prevalence < N`, first_seen) and
///   `enrich=true | where host_count < N` / `| where is_rare` (what rarity
///   rules run) already re-resolve dict-blind artifacts in SQL (NAN-1705);
/// - a `| where` or `| eval` after the decoration runs IN the SQL over the
///   dict values, so correcting the returned rows afterwards could not fix
///   what those already computed;
/// - a pushed aggregation returns no event rows to correct;
/// - a projected output (`table`/`fields` folded into the SELECT) carries no
///   lookup keys.
pub(crate) fn page_rescue_applies(
    prevalence_commands: &[PrevalenceCommandInfo],
    post_prevalence_commands: &[Command],
    scan: &PrevalenceScanPlan,
    rarity_threshold: u64,
) -> bool {
    prevalence_commands.iter().any(|cmd| cmd.enrich)
        && prevalence_commands.iter().all(|cmd| cmd.conditions.is_empty())
        && decorated_filter_rescue_threshold(post_prevalence_commands, rarity_threshold).is_none()
        && !post_prevalence_commands.iter().any(|cmd| {
            matches!(
                cmd,
                Command::Where { .. }
                    | Command::Eval { .. }
                    | Command::Stats { .. }
                    | Command::Top { .. }
                    | Command::Rare { .. }
                    | Command::Timechart { .. }
            )
        })
        && scan.output_columns.is_none()
}

/// The distinct dict-missed keys of a page, newest row first, and how many
/// more there were past the cap.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct MissKeys {
    pub keys: Vec<(MissKind, String)>,
    /// Distinct dict-missed keys NOT probed (past the cap): the run is PARTIAL.
    pub dropped: usize,
}

fn as_u64(v: Option<&serde_json::Value>) -> Option<u64> {
    match v? {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn as_i64(v: Option<&serde_json::Value>) -> Option<i64> {
    match v? {
        serde_json::Value::Number(n) => n.as_i64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// The dict's `toDateTime64(0, 6)` default: the key is not in the dict at all.
fn is_epoch_zero(v: Option<&serde_json::Value>) -> bool {
    match v {
        Some(serde_json::Value::String(s)) => {
            s.starts_with("1970-01-01 00:00:00") || s.starts_with("1970-01-01T00:00:00")
        }
        Some(serde_json::Value::Number(n)) => n.as_i64() == Some(0),
        _ => false,
    }
}

/// The row's normalized key for `kind` when its dict lookup was a TRUE miss
/// (sentinel host count and epoch-0 `last_seen`).
fn missed_key(row: &serde_json::Map<String, serde_json::Value>, kind: MissKind) -> Option<String> {
    let p = kind.prefix();
    if as_u64(row.get(&format!("{p}_host_count"))) != Some(9999) {
        return None;
    }
    if !is_epoch_zero(row.get(&format!("{p}_last_seen"))) {
        return None;
    }
    kind.rescuable_key(row.get(kind.lookup_col())?.as_str()?)
}

/// Collect the page's TRUE dict misses FIRST, then cap. Dict hits, common
/// artifacts and keys a dimension can never hold never count against the cap.
pub(crate) fn collect_miss_keys(rows: &[serde_json::Value], cap: usize) -> MissKeys {
    let mut seen: HashSet<(MissKind, String)> = HashSet::new();
    let mut out = MissKeys::default();
    for row in rows {
        let Some(obj) = row.as_object() else { continue };
        for kind in MissKind::ALL {
            let Some(key) = missed_key(obj, kind) else { continue };
            if !seen.insert((kind, key.clone())) {
                continue;
            }
            if out.keys.len() < cap {
                out.keys.push((kind, key));
            } else {
                out.dropped += 1;
            }
        }
    }
    out
}

/// ONE probe for every kind's keys: a `UNION ALL` of point lookups on each
/// summary's primary key, under the dict source contract (`host_count < 1000`,
/// `last_seen` inside the window, public IPs only). `None` when there is
/// nothing to probe. `dict_miss_guard` re-checks the dict in SQL (for callers
/// that could not see the dict's `last_seen`) so a dict-cached common artifact
/// is filtered out BEFORE its `uniqMerge`.
pub(crate) fn build_miss_probe_sql(
    keys: &[(MissKind, String)],
    table: impl Fn(MissKind) -> String,
    window_cutoff_sql: &str,
    dict_miss_guard: bool,
) -> Option<String> {
    let branches: Vec<String> = MissKind::ALL
        .into_iter()
        .filter_map(|kind| {
            let list: Vec<String> = keys
                .iter()
                .filter(|(k, _)| *k == kind)
                .map(|(_, key)| format!("'{}'", escape_sql_string(key)))
                .collect();
            if list.is_empty() {
                return None;
            }
            let (key_col, state_col, extra) = kind.summary_columns();
            let guard = if dict_miss_guard {
                format!(
                    " AND dictGetOrDefault('{dict}', 'last_seen', {key_col}, toDateTime64(0, 6)) = toDateTime64(0, 6)",
                    dict = kind.dict()
                )
            } else {
                String::new()
            };
            Some(format!(
                "SELECT '{label}' AS kind, artifact, toUInt64(_hc) AS host_count, \
toUnixTimestamp64Micro(_fs) AS fs_us, toUnixTimestamp64Micro(_ls) AS ls_us, \
toUInt64(_occ) AS total_occurrences FROM (SELECT {key_col} AS artifact, \
toUInt16(least(9998, uniqMerge({state_col}))) AS _hc, min(first_seen) AS _fs, \
max(last_seen) AS _ls, toUInt64(sum(total_count)) AS _occ FROM {table} \
WHERE {extra}{key_col} IN ({list}){guard} GROUP BY {key_col}) \
WHERE _hc < {cutoff} AND _ls >= {window_cutoff_sql}",
                label = kind.label(),
                table = table(kind),
                list = list.join(", "),
                cutoff = PREVALENCE_DICT_HOST_COUNT_CUTOFF,
            ))
        })
        .collect();
    (!branches.is_empty()).then(|| branches.join("\nUNION ALL\n"))
}

/// Probe rows by (kind, key).
pub(crate) fn parse_probe_rows(
    rows: Vec<serde_json::Value>,
) -> HashMap<(MissKind, String), RescuedArtifact> {
    let mut out = HashMap::new();
    for row in rows {
        let Some(kind) = row.get("kind").and_then(|v| v.as_str()).and_then(MissKind::from_label)
        else {
            continue;
        };
        let Some(artifact) = row.get("artifact").and_then(|v| v.as_str()) else { continue };
        let Some(host_count) = as_u64(row.get("host_count")) else { continue };
        out.insert(
            (kind, artifact.to_string()),
            RescuedArtifact {
                artifact: artifact.to_string(),
                host_count,
                first_seen_us: as_i64(row.get("fs_us")).unwrap_or(0),
                last_seen_us: as_i64(row.get("ls_us")).unwrap_or(0),
                total_occurrences: as_u64(row.get("total_occurrences")).unwrap_or(0),
            },
        );
    }
    out
}

/// A DateTime64(6) as ClickHouse renders it in the row (`YYYY-MM-DD HH:MM:SS.ffffff`).
fn ch_datetime64(us: i64) -> serde_json::Value {
    chrono::DateTime::from_timestamp_micros(us)
        .map(|dt| serde_json::Value::String(dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string()))
        .unwrap_or(serde_json::Value::Null)
}

/// Overwrite each rescued dimension of every row with its summary values and
/// recompute the decorations EXACTLY as the pushdown SELECT does (rarest
/// wins, ties domain → ip → hash; score as the Prevalence API computes it).
/// Returns the number of rows changed.
pub(crate) fn apply_page_rescue(
    rows: &mut [serde_json::Value],
    found: &HashMap<(MissKind, String), RescuedArtifact>,
    rarity_threshold: u64,
) -> usize {
    if found.is_empty() {
        return 0;
    }
    let mut changed = 0;
    for row in rows.iter_mut() {
        let Some(obj) = row.as_object_mut() else { continue };
        let mut touched = false;
        for kind in MissKind::ALL {
            let Some(key) = missed_key(obj, kind) else { continue };
            let Some(r) = found.get(&(kind, key)) else { continue };
            let p = kind.prefix();
            obj.insert(format!("{p}_host_count"), serde_json::json!(r.host_count));
            obj.insert(format!("{p}_first_seen"), ch_datetime64(r.first_seen_us));
            obj.insert(format!("{p}_last_seen"), ch_datetime64(r.last_seen_us));
            obj.insert(format!("{p}_total_occurrences"), serde_json::json!(r.total_occurrences));
            touched = true;
        }
        if touched {
            redecorate(obj, rarity_threshold);
            changed += 1;
        }
    }
    changed
}

/// The pushdown's decoration CASEs, over the row's per-dimension columns.
pub(crate) fn redecorate(obj: &mut serde_json::Map<String, serde_json::Value>, rarity_threshold: u64) {
    let hc = |kind: MissKind| as_u64(obj.get(&format!("{}_host_count", kind.prefix()))).unwrap_or(9999);
    let (dp, ip, hp) = (hc(MissKind::Domain), hc(MissKind::Ip), hc(MissKind::Hash));
    let m = dp.min(ip).min(hp);
    let winner = if dp < 9999 && dp <= ip && dp <= hp {
        Some(MissKind::Domain)
    } else if ip < 9999 && ip <= hp {
        Some(MissKind::Ip)
    } else if hp < 9999 {
        Some(MissKind::Hash)
    } else {
        None
    };
    let rt = rarity_threshold.max(1);
    let field = |kind: Option<MissKind>, suffix: &str| -> serde_json::Value {
        kind.and_then(|k| obj.get(&format!("{}_{suffix}", k.prefix())).cloned())
            .unwrap_or(serde_json::Value::Null)
    };
    let first_seen = field(winner, "first_seen");
    let last_seen = field(winner, "last_seen");
    let total = field(winner, "total_occurrences");
    let artifact = winner
        .and_then(|k| obj.get(k.lookup_col()).cloned())
        .unwrap_or(serde_json::Value::Null);
    let rare = m < 9999 && m < rt;
    let score = if m >= 9999 || m == 0 {
        0
    } else {
        PrevalenceRepository::calculate_prevalence_score(m, rt)
    };
    let is_rare = match obj.get("is_rare") {
        Some(serde_json::Value::Bool(_)) => serde_json::Value::Bool(rare),
        _ => serde_json::json!(u8::from(rare)),
    };
    obj.insert(
        "host_count".into(),
        if m >= 9999 { serde_json::Value::Null } else { serde_json::json!(m) },
    );
    obj.insert("prevalence_first_seen".into(), first_seen);
    obj.insert("prevalence_last_seen".into(), last_seen);
    obj.insert("total_occurrences".into(), total);
    obj.insert("is_rare".into(), is_rare);
    obj.insert("prevalence_score".into(), serde_json::json!(score));
    obj.insert(
        "prevalence_type".into(),
        winner.map_or(serde_json::Value::Null, |k| serde_json::json!(k.label())),
    );
    obj.insert("prevalence_artifact".into(), artifact);
}

/// The partial-run message for misses left past the cap.
pub(crate) fn page_rescue_partial_message(dropped: usize) -> String {
    format!(
        "prevalence enrich: {dropped} artifact(s) the prevalence dictionaries have not loaded yet \
         were past the {PREVALENCE_RESCUE_MISS_KEY_CAP}-artifact re-check cap and were not \
         re-checked; their rows may show no prevalence"
    )
}

impl SearchService {
    /// Run the page rescue over the fetched rows (see the module docs).
    /// Returns the number of dict-missed artifacts left un-probed past the cap
    /// (the caller reports them as PARTIAL). Fail-open: a probe error leaves
    /// the rows as the dict decorated them.
    pub(crate) async fn rescue_page_prevalence(
        &self,
        rows: &mut [serde_json::Value],
        time_window: PrevalenceTimeWindow,
        rarity_threshold: u64,
        query_id: &str,
    ) -> usize {
        let misses = collect_miss_keys(rows, PREVALENCE_RESCUE_MISS_KEY_CAP);
        if misses.dropped > 0 {
            report_page_rescue_overflow(misses.dropped);
        }
        let Ok(window_cutoff_sql) = Self::prevalence_window_cutoff_sql(time_window) else {
            return misses.dropped;
        };
        let Some(sql) = build_miss_probe_sql(
            &misses.keys,
            |kind| self.table_names.read(kind.summary_table()),
            window_cutoff_sql,
            false,
        ) else {
            return misses.dropped;
        };
        let Some(executor) = self.ch_executor.as_ref() else {
            return misses.dropped;
        };
        let probe_qid = prevalence_rescue_query_id(query_id);
        let started = Instant::now();
        let probed = self.execute_companion_dynamic(executor, &sql, &probe_qid).await;
        match probed {
            Ok(rows_found) => {
                let found = parse_probe_rows(rows_found);
                let changed = apply_page_rescue(rows, &found, rarity_threshold);
                tracing::info!(
                    missed = misses.keys.len(),
                    resolved = found.len(),
                    rows_changed = changed,
                    duration_ms = started.elapsed().as_millis() as u64,
                    "Prevalence enrich: dict-missed artifacts on the page re-checked against the real-time summary"
                );
            }
            Err(e) => tracing::warn!(
                error = %e,
                missed = misses.keys.len(),
                "Prevalence enrich page rescue failed; rows keep their dict decoration"
            ),
        }
        misses.dropped
    }
}

/// The page rescue probe's query id, derived from the search's (cancelled
/// with it: see `search::companion_query_id`).
pub(crate) fn prevalence_rescue_query_id(query_id: &str) -> String {
    CompanionQuery::PrevalenceRescue.query_id(query_id)
}

impl SearchService {
    /// Run a companion probe under its derived id (cancel kills it) and the
    /// request's ClickHouse settings when set (NAN-5723).
    pub(crate) async fn execute_companion_dynamic(
        &self,
        executor: &crate::search::execution::clickhouse_executor::ClickHouseExecutor,
        sql: &str,
        companion_id: &str,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        match self.active_ch_settings.as_ref() {
            Some(settings) => {
                executor
                    .execute_dynamic_query_with_settings(sql, companion_id, settings, false)
                    .await
            }
            None => {
                executor
                    .execute_dynamic_query_with_query_id(sql, companion_id, false)
                    .await
            }
        }
    }
}

/// WARN, metric, PARTIAL note: dict-missed artifacts past the cap were not
/// re-checked.
pub(crate) fn report_page_rescue_overflow(dropped: usize) {
    tracing::warn!(
        dropped,
        cap = PREVALENCE_RESCUE_MISS_KEY_CAP,
        "Prevalence enrich page rescue cap hit; remaining dict-missed artifacts were not re-checked (PARTIAL)"
    );
    metrics::counter!("nanosiem_prevalence_rescue_dropped_artifacts_total").increment(dropped as u64);
    crate::search::partial_run::note(page_rescue_partial_message(dropped));
}

/// The residual (non-pushdown) enrichment's keys to re-check: every key of a
/// kind the dimension can hold that the dict lookup did not resolve, in
/// order, capped AFTER that filtering.
pub(crate) fn residual_miss_keys(
    candidates: [(MissKind, &[String], &HashMap<String, PrevalenceData>); 3],
    cap: usize,
) -> MissKeys {
    let mut seen: HashSet<(MissKind, String)> = HashSet::new();
    let mut out = MissKeys::default();
    for (kind, list, resolved) in candidates {
        for raw in list {
            let Some(key) = kind.rescuable_key(raw) else { continue };
            if resolved.contains_key(&key) || !seen.insert((kind, key.clone())) {
                continue;
            }
            if out.keys.len() < cap {
                out.keys.push((kind, key));
            } else {
                out.dropped += 1;
            }
        }
    }
    out
}

impl SearchService {
    /// NAN-5718: the residual enrichment path's counterpart of
    /// [`Self::rescue_page_prevalence`]. The maps are keyed like the dict
    /// lookup returns them (hash/domain lowercased, IP raw).
    ///
    /// - A `PrevalenceData::empty` placeholder (served from the shared
    ///   `PrevalenceCache` for an artifact looked up before it was ingested)
    ///   is a miss, not "0 hosts, rare": it is dropped and re-checked.
    /// - Private IPs and single-label hostnames are never probed (no summary
    ///   can hold them).
    /// - The probe re-checks the dict in SQL (`dict_miss_guard`), so a
    ///   dict-cached common artifact never reaches `uniqMerge`.
    pub(crate) async fn rescue_residual_enrichment(
        &self,
        hashes: &[String],
        domains: &[String],
        ips: &[String],
        maps: [&mut HashMap<String, PrevalenceData>; 3],
        prevalence_service: &crate::prevalence::PrevalenceService,
        time_window: PrevalenceTimeWindow,
        query_id: &str,
    ) {
        let [hash_map, domain_map, ip_map] = maps;
        for map in [&mut *hash_map, &mut *domain_map, &mut *ip_map] {
            map.retain(|_, data| !data.is_miss());
        }
        let misses = residual_miss_keys(
            [
                (MissKind::Hash, hashes, &*hash_map),
                (MissKind::Domain, domains, &*domain_map),
                (MissKind::Ip, ips, &*ip_map),
            ],
            PREVALENCE_RESCUE_MISS_KEY_CAP,
        );
        if misses.dropped > 0 {
            report_page_rescue_overflow(misses.dropped);
        }
        let Ok(window_cutoff_sql) = Self::prevalence_window_cutoff_sql(time_window) else {
            return;
        };
        let Some(sql) = build_miss_probe_sql(
            &misses.keys,
            |kind| self.table_names.read(kind.summary_table()),
            window_cutoff_sql,
            true,
        ) else {
            return;
        };
        let Some(executor) = self.ch_executor.as_ref() else { return };
        let recheck_qid = CompanionQuery::PrevalenceRecheck.query_id(query_id);
        let rows = match self.execute_companion_dynamic(executor, &sql, &recheck_qid).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(error = %e, "Prevalence enrichment summary re-check failed; dict-missed artifacts stay undecorated");
                return;
            }
        };
        let rarity_threshold = prevalence_service.rarity_threshold().await;
        for ((kind, key), r) in parse_probe_rows(rows) {
            let data = PrevalenceData {
                artifact_type: ArtifactType::detect(&key),
                host_count: Some(r.host_count),
                total_occurrences: r.total_occurrences,
                first_seen: PrevalenceRepository::micros_to_datetime(r.first_seen_us),
                last_seen: PrevalenceRepository::micros_to_datetime(r.last_seen_us),
                is_rare: r.host_count < rarity_threshold,
                prevalence_score: PrevalenceRepository::calculate_prevalence_score(
                    r.host_count,
                    rarity_threshold,
                ),
                artifact: key.clone(),
            };
            let map = match kind {
                MissKind::Hash => &mut *hash_map,
                MissKind::Domain => &mut *domain_map,
                MissKind::Ip => &mut *ip_map,
            };
            map.insert(key, data);
        }
    }
}
