// SPDX-License-Identifier: AGPL-3.0-or-later

//! The durable IOC retro-hunt (`retro_v1`) assembly, shared by the gen1 job
//! child and the lean query[T] job path (NAN-3086), so both lanes issue the
//! same reads and publish byte-compatible artifacts.
//!
//! Every read is a sub-window of the job's admitted `[start, end]`:
//! * the rarity denominator over `[end - 6h, end]` (clipped to `start`);
//! * one summary rollup per indicator over `[start, end]`;
//! * the summary's top-entity read over `[start, end]`;
//! * the pivot's grouped reads over disjoint bisected slices of
//!   `[start, end]`.
//!
//! The caller's reader is the only way to storage. On a lean cell it is the
//! view-job reader, which additionally clamps every read to the retention
//! proof's CURRENT cutoff and refuses a compiled window outside it, so a
//! retro whose admitted range crosses the cutoff never counts an expired row.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use crate::product_payloads::{row_string, row_u64};

/// Rows one grouped pivot slice may return before it is bisected.
pub const DURABLE_RETRO_SLICE_ROWS: usize = 50_000;
/// Coordinator bound on bisected pivot slices (not on matching events).
pub const DURABLE_RETRO_MAX_SLICES: usize = 4_096;

/// Denominator window, in lockstep with `LAKE_RETRO_DENOMINATOR_WINDOW_HOURS`
/// in nanosiem-core. Keep these equal AND keep the anchor equal: both measure
/// the population over [request_end - window, request_end]. Matching the
/// duration while disagreeing on the anchor (one on `now()`, one on the request
/// end) still produced different populations — and therefore different rarity
/// verdicts — for a historical-ended hunt depending on which lane ran it.
pub const DURABLE_RETRO_DENOMINATOR_WINDOW_HOURS: i64 = 6;

// Host identity for the durable retro path. Named hosts ONLY -- must match
// `LAKE_RETRO_HOST_FIELDS` (nanosiem-core/src/search/service/retro.rs), the
// interactive path's identical constant. That one already had its IP legs
// removed (NAN-1592, ~280x denominator inflation on Saturn: 1.78M "hosts",
// 99.8% public IPs, vs ~4.3K real hostnames -- a remote endpoint IP is not
// one of your assets).
const DURABLE_RETRO_HOST_FIELDS: &[&str] = &[
    "device.hostname",
    "src_endpoint.hostname",
    "dst_endpoint.hostname",
];

// NUMERATOR identity -- "which asset touched this indicator". Must match
// `LAKE_RETRO_ASSET_FIELDS` (nanosiem-core/src/search/service/retro.rs).
//
// NAN-2361: source-side only, with `src_endpoint.ip` as a legitimate fallback.
// `dst_endpoint.hostname` is EXCLUDED because on a row matched by a domain/URL
// indicator the destination hostname IS the indicator -- coalescing over it
// resolved every row to the indicator's own name, collapsing the hunt to a
// single fake asset. `src_endpoint.ip` is INCLUDED because proxy/HTTP
// telemetry carries no hostname at all, so those sightings otherwise have no
// identity; the NAN-1592 "no IP legs" rule constrains the DENOMINATOR, not
// the numerator, where the source IP is the client being asked about.
const DURABLE_RETRO_ASSET_FIELDS: &[&str] = &[
    "device.hostname",
    "src_endpoint.hostname",
    "src_endpoint.ip",
];
const DURABLE_RETRO_USER_FIELDS: &[&str] = &["user.name", "actor.user.name"];
const DURABLE_RETRO_ALL_IOC_FIELDS: &[&str] = &[
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "file.hashes.value",
    "process.file.hashes.value",
    "actor.process.file.hashes.value",
    "http_request.url.url_string",
    "url.url_string",
    "http_request.url.hostname",
    "url.hostname",
    "query.hostname",
    "dst_endpoint.hostname",
    "user.uid",
    "user.name",
    "actor.user.uid",
    "actor.user.name",
    "email.from",
    "email.to",
    "vulnerabilities.cve.uid",
    "answers.rdata",
];

/// One read's rows, and whether more rows matched than `limit`.
pub struct RetroRead {
    pub rows: Vec<Value>,
    pub has_more: bool,
}

/// The typed inputs of one `retro_v1` task.
pub struct RetroJob<'a> {
    pub indicators: &'a [String],
    pub axis: &'a str,
    pub submode: &'a str,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Default)]
struct DurableRetroIndicator {
    hits: u64,
    hosts: u64,
    first_seen: Option<String>,
    last_seen: Option<String>,
    fields: Vec<(String, u64)>,
}

#[derive(Default)]
struct DurableRetroPivot {
    indicators: BTreeSet<String>,
    first_seen: Option<String>,
    last_seen: Option<String>,
}

/// Run one retro task over `[start, end]` through `read` and return its
/// typed artifact row. `read(query, start, end, limit, suffix)` executes one
/// nPL read; the caller owns scope, budget and (on a cell) the retention clamp.
pub async fn run_retro<F, Fut>(
    read: F,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    job: &RetroJob<'_>,
) -> Result<Value>
where
    F: Fn(String, DateTime<Utc>, DateTime<Utc>, usize, String) -> Fut,
    Fut: Future<Output = Result<RetroRead>>,
{
    if start >= end {
        bail!("retro job window is empty");
    }
    let RetroJob { indicators, axis, submode, offset, limit } = *job;
    if !matches!(submode, "summary" | "list" | "pivot") {
        bail!("retro job submode is not summary, list or pivot");
    }
    // The denominator is anchored on the admitted END (both lanes) and never
    // reads before the admitted start.
    let host_start = (end - ChronoDuration::hours(DURABLE_RETRO_DENOMINATOR_WINDOW_HOURS)).max(start);
    let host_query = format!(
        "* | eval retro_host=coalesce({}) | stats dc(retro_host) as total_hosts",
        DURABLE_RETRO_HOST_FIELDS.join(",")
    );
    let hosts = read(host_query, host_start, end, 1, "retro-hosts".to_string()).await?;
    let total_hosts = hosts
        .rows
        .first()
        .map(|row| row_u64(row, "total_hosts"))
        .unwrap_or_default();

    let mut summaries = BTreeMap::new();
    let mut pivots: BTreeMap<String, DurableRetroPivot> = BTreeMap::new();
    for (index, indicator) in indicators.iter().enumerate() {
        let encoded = serde_json::to_string(indicator)?;
        let fields = durable_retro_ioc_fields(indicator);
        let mut aggregates = vec![
            "count() as hits".to_string(),
            "dc(retro_host) as distinct_hosts".to_string(),
            "min(time) as first_seen".to_string(),
            "max(time) as last_seen".to_string(),
        ];
        for (field_index, field) in fields.iter().enumerate() {
            let predicate = durable_retro_field_match(field, &encoded);
            aggregates.push(format!("count(eval({predicate})) as retro_field_{field_index}"));
        }
        let summary_query = format!(
            "ioc={encoded} | eval retro_host=coalesce({}) | stats {}",
            DURABLE_RETRO_ASSET_FIELDS.join(","),
            aggregates.join(", ")
        );
        let result = read(summary_query, start, end, 1, format!("retro-summary-{index}")).await?;
        let row = result.rows.first().context("retro summary returned no row")?;
        let mut summary = DurableRetroIndicator {
            hits: row_u64(row, "hits"),
            hosts: row_u64(row, "distinct_hosts"),
            first_seen: row_string(row, "first_seen").filter(|value| !value.is_empty()),
            last_seen: row_string(row, "last_seen").filter(|value| !value.is_empty()),
            fields: Vec::new(),
        };
        if summary.hits == 0 {
            // An empty aggregate still reports its min/max defaults.
            summary.first_seen = None;
            summary.last_seen = None;
        }
        for (field_index, field) in fields.iter().enumerate() {
            let hits = row_u64(row, &format!("retro_field_{field_index}"));
            if hits > 0 {
                summary.fields.push(((*field).to_string(), hits));
            }
        }
        summary
            .fields
            .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        summaries.insert(indicator.clone(), summary);

        if submode == "pivot" {
            let entity_fields = if axis == "user" {
                DURABLE_RETRO_USER_FIELDS
            } else {
                DURABLE_RETRO_ASSET_FIELDS
            };
            let grouped_query = format!(
                "ioc={encoded} | stats count() as hits,min(time) as first_seen,max(time) as last_seen by {} | eval retro_entity=coalesce({}) | where retro_entity!=\"\" | stats sum(hits) as hits,min(first_seen) as first_seen,max(last_seen) as last_seen by retro_entity",
                entity_fields.join(","),
                entity_fields.join(",")
            );
            let grouped =
                grouped_slices(&read, &grouped_query, start, end, &format!("retro-pivot-{index}")).await?;
            for row in grouped {
                let Some(entity) = row_string(&row, "retro_entity").filter(|value| !value.is_empty()) else {
                    continue;
                };
                let pivot = pivots.entry(entity).or_default();
                pivot.indicators.insert(indicator.clone());
                update_bounds(&mut pivot.first_seen, &mut pivot.last_seen, row_string(&row, "first_seen").as_deref());
                update_bounds(&mut pivot.first_seen, &mut pivot.last_seen, row_string(&row, "last_seen").as_deref());
            }
        }
    }

    let payload = if submode == "summary" {
        let indicator = indicators.first().context("retro summary has no indicator")?;
        let summary = summaries.get(indicator).context("retro summary accumulator is missing")?;
        let encoded = serde_json::to_string(indicator)?;
        let top_query = format!(
            "ioc={encoded} | stats count() as hits by {} | eval retro_host=coalesce({}) | where retro_host!=\"\" | stats sum(hits) as hits by retro_host | sort -hits | head 10",
            DURABLE_RETRO_ASSET_FIELDS.join(","),
            DURABLE_RETRO_ASSET_FIELDS.join(",")
        );
        let top = read(top_query, start, end, 10, "retro-top".to_string()).await?;
        let top_entities = top
            .rows
            .iter()
            .filter_map(|row| {
                row_string(row, "retro_host")
                    .filter(|id| !id.is_empty())
                    .map(|id| json!({"id": id, "hits": row_u64(row, "hits"), "kind": "asset"}))
            })
            .collect::<Vec<_>>();
        json!({
            "submode": "summary",
            "axis": axis,
            "total_hosts": total_hosts,
            "indicator": {
                "value": indicator,
                "type": durable_retro_indicator_type(indicator),
                "source": "query",
                "campaign": null,
                "confidence": 0,
                "hits": summary.hits,
                "first_seen": summary.first_seen,
                "last_seen": summary.last_seen,
                "matched_fields": summary.fields,
                "distinct_hosts": summary.hosts,
                "total_hosts": total_hosts,
                "verdict": durable_retro_verdict(summary.hosts, total_hosts),
                "top_entities": top_entities,
            }
        })
    } else if submode == "list" {
        let no_hits = indicators
            .iter()
            .filter(|indicator| summaries.get(*indicator).is_none_or(|summary| summary.hits == 0))
            .cloned()
            .collect::<Vec<_>>();
        let mut rows = summaries
            .iter()
            .filter(|(_, summary)| summary.hits > 0)
            .map(|(indicator, summary)| {
                json!({
                    "value": indicator,
                    "type": durable_retro_indicator_type(indicator),
                    "hits": summary.hits,
                    "hosts": summary.hosts,
                    "total_hosts": total_hosts,
                    "first_seen": summary.first_seen,
                    "last_seen": summary.last_seen,
                    "field": summary.fields.first().map(|entry| entry.0.as_str()).unwrap_or(""),
                    "verdict": durable_retro_verdict(summary.hosts, total_hosts),
                })
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            row_u64(left, "hosts")
                .cmp(&row_u64(right, "hosts"))
                .then_with(|| row_u64(left, "hits").cmp(&row_u64(right, "hits")))
                .then_with(|| row_string(left, "value").cmp(&row_string(right, "value")))
        });
        let total = rows.len();
        let rows = rows.into_iter().skip(offset).take(limit).collect::<Vec<_>>();
        json!({
            "submode": "list",
            "axis": axis,
            "total_hosts": total_hosts,
            "total_indicators": total,
            "rows": rows,
            "no_hits": no_hits,
            "offset": offset,
            "limit": limit,
            "has_more": total > offset.saturating_add(limit),
        })
    } else {
        let mut rows = pivots
            .into_iter()
            .map(|(id, pivot)| {
                let mut indicators = pivot.indicators.into_iter().collect::<Vec<_>>();
                indicators.sort();
                let worst = indicators
                    .iter()
                    .filter_map(|indicator| summaries.get(indicator))
                    .map(|summary| durable_retro_verdict_rank(summary.hosts, total_hosts))
                    .min()
                    .unwrap_or((0, "rare"));
                let iocs = indicators.len();
                indicators.truncate(8);
                json!({
                    "id": id,
                    "name": id,
                    "sub": null,
                    "iocs": iocs,
                    "indicators": indicators,
                    "first_seen": pivot.first_seen,
                    "last_seen": pivot.last_seen,
                    "worst_verdict": worst.1,
                })
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            row_string(left, "first_seen")
                .cmp(&row_string(right, "first_seen"))
                .then_with(|| row_string(left, "id").cmp(&row_string(right, "id")))
        });
        let total = rows.len();
        let rows = rows.into_iter().skip(offset).take(limit).collect::<Vec<_>>();
        json!({
            "submode": "pivot",
            "axis": axis,
            "total_hosts": total_hosts,
            "pivot_rows": rows,
            "offset": offset,
            "limit": limit,
            "has_more": total > offset.saturating_add(limit),
        })
    };
    Ok(payload)
}

/// Grouped reads over disjoint slices of `[start, end]`, bisecting any slice
/// whose group count saturates the slice bound, merged exactly.
async fn grouped_slices<F, Fut>(
    read: &F,
    query: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    suffix: &str,
) -> Result<Vec<Value>>
where
    F: Fn(String, DateTime<Utc>, DateTime<Utc>, usize, String) -> Fut,
    Fut: Future<Output = Result<RetroRead>>,
{
    let mut pending = vec![(start, end)];
    let mut completed = 0_usize;
    let mut merged: BTreeMap<String, (u64, Option<String>, Option<String>)> = BTreeMap::new();
    while let Some((slice_start, slice_end)) = pending.pop() {
        if completed.saturating_add(pending.len()) >= DURABLE_RETRO_MAX_SLICES {
            bail!("durable retro grouped aggregation exceeded its coordinator slice bound");
        }
        let result = read(
            query.to_string(),
            slice_start,
            slice_end,
            DURABLE_RETRO_SLICE_ROWS,
            format!("{suffix}-{completed}"),
        )
        .await?;
        if result.has_more || result.rows.len() >= DURABLE_RETRO_SLICE_ROWS {
            let width_us = (slice_end - slice_start).num_microseconds().unwrap_or_default();
            if width_us < 2 {
                bail!("durable retro grouped result exceeds the per-microsecond safety bound");
            }
            let right_start = slice_start + ChronoDuration::microseconds(width_us / 2);
            pending.push((slice_start, right_start - ChronoDuration::microseconds(1)));
            pending.push((right_start, slice_end));
            continue;
        }
        completed += 1;
        for row in result.rows {
            let Some(entity) = row_string(&row, "retro_entity") else {
                continue;
            };
            let entry = merged.entry(entity).or_default();
            entry.0 = entry.0.saturating_add(row_u64(&row, "hits"));
            update_bounds(&mut entry.1, &mut entry.2, row_string(&row, "first_seen").as_deref());
            update_bounds(&mut entry.1, &mut entry.2, row_string(&row, "last_seen").as_deref());
        }
    }
    Ok(merged
        .into_iter()
        .map(|(entity, (hits, first_seen, last_seen))| {
            json!({
                "retro_entity": entity,
                "hits": hits,
                "first_seen": first_seen,
                "last_seen": last_seen,
            })
        })
        .collect())
}

pub fn durable_retro_indicator_type(value: &str) -> &'static str {
    let value = value.trim();
    if value.parse::<std::net::IpAddr>().is_ok() {
        "ip"
    } else if matches!(value.len(), 32 | 40 | 64) && value.chars().all(|character| character.is_ascii_hexdigit()) {
        "hash"
    } else if value.starts_with("http://") || value.starts_with("https://") {
        "url"
    } else if value.to_ascii_lowercase().starts_with("cve-") {
        "cve"
    } else if value.contains('@') {
        "user"
    } else if value.contains('.') && !value.contains(' ') {
        "domain"
    } else {
        "other"
    }
}

fn durable_retro_ioc_fields(value: &str) -> &'static [&'static str] {
    match durable_retro_indicator_type(value) {
        "ip" => &["src_endpoint.ip", "dst_endpoint.ip"],
        "hash" => &[
            "file.hashes.value",
            "process.file.hashes.value",
            "actor.process.file.hashes.value",
        ],
        // NAN-2361: must match core's domain observable list
        // (`clickhouse_sql_gen/search_expr.rs`).
        "domain" => &[
            "http_request.url.hostname",
            "url.hostname",
            "query.hostname",
            "dst_endpoint.hostname",
        ],
        "url" => &["http_request.url.url_string", "url.url_string"],
        "cve" => &["vulnerabilities.cve.uid"],
        "user" => &[
            "user.uid",
            "user.name",
            "actor.user.uid",
            "actor.user.name",
            "email.from",
            "email.to",
        ],
        _ => DURABLE_RETRO_ALL_IOC_FIELDS,
    }
}

fn durable_retro_ioc_field_is_array(field: &str) -> bool {
    matches!(
        field,
        "file.hashes.value" | "process.file.hashes.value" | "actor.process.file.hashes.value"
    )
}

fn durable_retro_field_match(field: &str, encoded: &str) -> String {
    if durable_retro_ioc_field_is_array(field) {
        // The comparison keeps compatibility with the historical scalar
        // array_contains() return type while the OCSF 1.9 compiler lowers the
        // function itself to exact arrayExists membership.
        format!("array_contains({field},{encoded})>0")
    } else {
        format!("{field}={encoded}")
    }
}

fn update_bounds(first_seen: &mut Option<String>, last_seen: &mut Option<String>, timestamp: Option<&str>) {
    let Some(timestamp) = timestamp.filter(|value| !value.is_empty()) else {
        return;
    };
    if first_seen.as_deref().is_none_or(|current| timestamp < current) {
        *first_seen = Some(timestamp.to_string());
    }
    if last_seen.as_deref().is_none_or(|current| timestamp > current) {
        *last_seen = Some(timestamp.to_string());
    }
}

fn durable_retro_verdict(hosts: u64, total_hosts: u64) -> &'static str {
    durable_retro_verdict_rank(hosts, total_hosts).1
}

fn durable_retro_verdict_rank(hosts: u64, total_hosts: u64) -> (u8, &'static str) {
    if total_hosts == 0 || hosts as f64 / total_hosts as f64 <= 0.02 {
        (0, "rare")
    } else if hosts as f64 / total_hosts as f64 <= 0.15 {
        (1, "uncommon")
    } else {
        (2, "common")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Mutex;

    #[test]
    fn durable_retro_scopes_ioc_fields_and_verdicts() {
        assert_eq!(
            durable_retro_ioc_fields("198.51.100.25"),
            ["src_endpoint.ip", "dst_endpoint.ip"]
        );
        assert_eq!(
            durable_retro_ioc_fields(
                "eb7533166139d123fa4e5ca321ae69af0bc743aa0bd698e49f66fb730054a6bc"
            ),
            [
                "file.hashes.value",
                "process.file.hashes.value",
                "actor.process.file.hashes.value"
            ]
        );
        assert_eq!(durable_retro_verdict(0, 0), "rare");
        assert_eq!(durable_retro_verdict(2, 100), "rare");
        assert_eq!(durable_retro_verdict(3, 100), "uncommon");
        assert_eq!(durable_retro_verdict(16, 100), "common");
        assert!(durable_retro_ioc_field_is_array("file.hashes.value"));
        assert!(!durable_retro_ioc_field_is_array("src_endpoint.ip"));
        assert_eq!(
            durable_retro_field_match("file.hashes.value", "\"abc\""),
            "array_contains(file.hashes.value,\"abc\")>0"
        );
    }

    /// Every read a retro job issues is a sub-window of its admitted range:
    /// the denominator never reaches before the admitted start even when the
    /// range is shorter than the denominator window, and pivot slices tile
    /// the range without leaving it.
    #[tokio::test]
    async fn every_retro_read_stays_inside_the_admitted_range() {
        let start = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap();
        let end = start + ChronoDuration::hours(2);
        for (submode, axis, indicators) in [
            ("summary", "indicator", vec!["1.2.3.4".to_string()]),
            ("list", "indicator", vec!["1.2.3.4".to_string(), "evil.test".to_string()]),
            ("pivot", "asset", vec!["1.2.3.4".to_string(), "evil.test".to_string()]),
        ] {
            let reads = Mutex::new(Vec::new());
            let read = |query: String, from: DateTime<Utc>, to: DateTime<Utc>, _limit: usize, suffix: String| {
                reads.lock().unwrap().push((suffix, from, to));
                let row = if query.contains("total_hosts") {
                    json!({"total_hosts": "10"})
                } else if query.contains("retro_entity") {
                    json!({"retro_entity": "ws-1", "hits": "2", "first_seen": "2026-09-01 00:10:00", "last_seen": "2026-09-01 01:10:00"})
                } else {
                    json!({"hits": "2", "distinct_hosts": "1", "first_seen": "2026-09-01 00:10:00", "last_seen": "2026-09-01 01:10:00", "retro_field_0": "2", "retro_host": "ws-1"})
                };
                async move { Ok(RetroRead { rows: vec![row], has_more: false }) }
            };
            let job = RetroJob { indicators: &indicators, axis, submode, offset: 0, limit: 50 };
            let payload = run_retro(read, start, end, &job).await.unwrap();
            assert_eq!(payload["submode"], submode);
            assert_eq!(payload["total_hosts"], 10);
            let reads = reads.into_inner().unwrap();
            assert!(!reads.is_empty());
            for (suffix, from, to) in &reads {
                assert!(*from >= start && *to <= end && from < to, "{submode}: {suffix} read {from}..{to}");
            }
            // The denominator is clipped to the admitted start.
            assert!(reads.iter().any(|(suffix, from, to)| suffix == "retro-hosts" && *from == start && *to == end));
        }
    }

    /// A hunt with no hits reports no first/last seen instead of the empty
    /// aggregate's defaults.
    #[tokio::test]
    async fn a_hunt_without_hits_reports_no_bounds() {
        let start = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap();
        let end = start + ChronoDuration::days(1);
        let read = |query: String, _: DateTime<Utc>, _: DateTime<Utc>, _: usize, _: String| {
            let row = if query.contains("total_hosts") {
                json!({"total_hosts": 4})
            } else {
                json!({"hits": 0, "distinct_hosts": 0, "first_seen": "1970-01-01 00:00:00", "last_seen": "1970-01-01 00:00:00"})
            };
            async move { Ok(RetroRead { rows: vec![row], has_more: false }) }
        };
        let indicators = vec!["1.2.3.4".to_string()];
        let job = RetroJob { indicators: &indicators, axis: "indicator", submode: "summary", offset: 0, limit: 50 };
        let payload = run_retro(read, start, end, &job).await.unwrap();
        assert_eq!(payload["indicator"]["hits"], 0);
        assert!(payload["indicator"]["first_seen"].is_null());
        assert!(payload["indicator"]["last_seen"].is_null());
    }
}
