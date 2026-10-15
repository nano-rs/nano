// SPDX-License-Identifier: AGPL-3.0-or-later

//! Point-in-time IP → identity resolution on the lake (NAN-3057, NAN-3058).
//!
//! # One path
//!
//! Every lean consumer (`/api/identity/resolve`, nPL `| resolve_identity`,
//! lateral-movement hostname fill, asset host widening and the global host
//! count) resolves through [`SearchService::resolve_lake_identity_ips`]:
//!
//! 1. **The identity observation index.** query[T]'s `/v1/identity/*`
//!    routes answer from the per-part index the cell derives at ingest
//!    (`nanosiem_lake_worker::identity_observations`): ClickHouse
//!    `identity_observations` parity (private source IPs, junk hosts
//!    dropped, short `.corp.` hostnames, priority then newest ≤ ref over
//!    30 days, NAT candidates), ≤ 500 items per request, the viewer's deny
//!    set applied before selection.
//! 2. **The bounded event scan, while the index backfills.** When query[T]
//!    reports the window not yet fully indexed (the cell flag is off, or the
//!    parts that predate it are still being derived), the batch falls back to
//!    the NAN-3057 scan over the tenant's own events through its `broad_npl`
//!    route and marks every answer `resolved_via = event_scan` with a
//!    `source` of `event_scan:<log_source>`.
//!
//! Either way every failure is an `Err` (fail closed), never a miss.
//!
//! # The event scan
//!
//! The NAN-3057 observation rule: the most recent event at or before the
//! reference time where the IP is the event's source endpoint
//! (`src_endpoint.ip`) or its device (`device.ip`) and the event names a host
//! or a user for it. The hostname comes from the SAME side the IP matched on
//! (`src_endpoint.hostname` for a source match, `device.hostname` for a
//! device match): on Windows Security events `device.hostname` is the logging
//! host, not the source. It walks `[ref-24h, ref]` then `[ref-7d, ref-24h)`,
//! clamped to retention. One IP runs the `head 1` form; a batch runs one
//! `stats … by <side>.ip` per side per window over `IN (…)` of its IPs at the
//! same exact reference time, and the second window only for the misses.
//! query[T] folds the viewer's deny set into the nPL before compilation, so a
//! denied source can never win.

use std::collections::BTreeSet;
use std::net::IpAddr;

use chrono::{DateTime, Duration, NaiveDateTime, Utc};

use super::*;
use crate::search::lake::{
    LakeIdentityBatchItem, LakeIdentityObservation, LakeIdentityResolution, EVENT_SCAN_SOURCE_PREFIX,
};

/// Lookback windows, nearest first. A hit in the first window returns without
/// scanning the second; the second covers only `[ref - 7d, ref - 24h)`.
pub(super) const LAKE_IDENTITY_LOOKBACKS_HOURS: [i64; 2] = [24, 24 * 7];

const OBSERVED_AT_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.6fZ";

/// The fixed nPL for one IP. `ip` must already be a canonical `IpAddr`
/// string; nothing else from the request reaches the query text.
pub(super) fn lake_identity_query(ip: &IpAddr) -> String {
    let ip = ip.to_string();
    format!(
        "((src_endpoint.ip=\"{ip}\" AND (src_endpoint.hostname=* OR user.name=* OR actor.user.name=*)) \
         OR (device.ip=\"{ip}\" AND (device.hostname=* OR user.name=* OR actor.user.name=*))) \
         | sort -time | head 1 \
         | table time, metadata.log_source, src_endpoint.ip, src_endpoint.hostname, \
         device.ip, device.hostname, user.name, actor.user.name"
    )
}

fn row_value<'a>(row: &'a serde_json::Value, field: &str) -> Option<&'a serde_json::Value> {
    if let Some(value) = row.get(field) {
        return Some(value);
    }
    let mut value = row;
    for segment in field.split('.') {
        value = value.get(segment)?;
    }
    Some(value)
}

fn row_string(row: &serde_json::Value, field: &str) -> String {
    match row_value(row, field) {
        Some(serde_json::Value::String(value)) => value.trim().to_string(),
        _ => String::new(),
    }
}

fn same_ip(value: &str, ip: &IpAddr) -> bool {
    value.trim().parse::<IpAddr>().is_ok_and(|parsed| parsed == *ip)
}

pub(super) fn parse_observed_at(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
        })
}

/// Map one query row to an observation. `None` when the row does not carry the
/// IP on either side, names neither a host nor a user, or lies after the
/// reference time (defensive: the window already ends there).
pub(super) fn lake_identity_observation(
    row: &serde_json::Value,
    ip: &IpAddr,
    reference_time: DateTime<Utc>,
) -> Option<LakeIdentityObservation> {
    let observed_at = parse_observed_at(&row_string(row, "time"))?;
    if observed_at > reference_time {
        return None;
    }
    let hostname = if same_ip(&row_string(row, "src_endpoint.ip"), ip) {
        row_string(row, "src_endpoint.hostname")
    } else if same_ip(&row_string(row, "device.ip"), ip) {
        row_string(row, "device.hostname")
    } else {
        return None;
    };
    // nPL's `user` alias: `user.name` when set, else the actor.
    let user = Some(row_string(row, "user.name"))
        .filter(|user| !user.is_empty())
        .unwrap_or_else(|| row_string(row, "actor.user.name"));
    if hostname.is_empty() && user.is_empty() {
        return None;
    }
    Some(scan_observation(hostname, user, row_string(row, "metadata.log_source"), observed_at))
}

fn scan_observation(hostname: String, user: String, source: String, observed_at: DateTime<Utc>) -> LakeIdentityObservation {
    LakeIdentityObservation {
        fqdn: hostname.clone(),
        hostname,
        user,
        mac: String::new(),
        source: format!("{EVENT_SCAN_SOURCE_PREFIX}{source}"),
        observed_at: observed_at.format(OBSERVED_AT_FORMAT).to_string(),
        nat_candidate: false,
        resolved_via: LakeIdentityResolution::EventScan,
    }
}

/// Items per identity request (query[T]'s and the gen1 worker's bound).
pub(crate) const LAKE_IDENTITY_BATCH_CAP: usize = 500;

/// The batch event-scan nPL for one side (`src_endpoint` or `device`) over
/// canonical IPs; nothing else from a request reaches the text.
pub(super) fn lake_identity_batch_query(side: &str, ips: &[IpAddr]) -> String {
    let list = ips.iter().map(|ip| format!("\"{ip}\"")).collect::<Vec<_>>().join(",");
    format!(
        "{side}.ip IN ({list}) ({side}.hostname=* OR user.name=* OR actor.user.name=*) \
         | eval nano_identity_user=coalesce(user.name, actor.user.name) \
         | stats max(time) as observed_at, last({side}.hostname) as hostname, \
         last(nano_identity_user) as user, last(metadata.log_source) as source by {side}.ip"
    )
}

/// One `stats` row of [`lake_identity_batch_query`] → `(ip, observation)`.
pub(super) fn lake_identity_batch_row(
    row: &serde_json::Value,
    side: &str,
    reference_time: DateTime<Utc>,
) -> Option<(IpAddr, LakeIdentityObservation)> {
    let ip: IpAddr = row_string(row, &format!("{side}.ip")).parse().ok()?;
    let observed_at = parse_observed_at(&row_string(row, "observed_at"))?;
    if observed_at > reference_time {
        return None;
    }
    let (hostname, user) = (row_string(row, "hostname"), row_string(row, "user"));
    if hostname.is_empty() && user.is_empty() {
        return None;
    }
    Some((ip, scan_observation(hostname, user, row_string(row, "source"), observed_at)))
}

fn index_observation(
    hostname: String,
    fqdn: String,
    user: String,
    mac: String,
    source: String,
    observed_at: String,
    nat_candidate: bool,
) -> LakeIdentityObservation {
    LakeIdentityObservation {
        hostname, fqdn, user, mac, source, observed_at, nat_candidate,
        resolved_via: LakeIdentityResolution::Index,
    }
}

/// `[start, end)` windows walked nearest first, clamped to the retention
/// cutoff; windows wholly before the cutoff are dropped.
pub(super) fn lake_identity_windows(
    reference_time: DateTime<Utc>,
    cutoff: Option<DateTime<Utc>>,
) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    // query[T]'s range end is exclusive; include an event stamped exactly at
    // the reference time. Storage timestamps are microseconds: round down
    // before advancing so a nanosecond reference cannot admit the next tick.
    let mut end = DateTime::from_timestamp_micros(reference_time.timestamp_micros())
        .expect("identity reference is representable at storage precision")
        + Duration::microseconds(1);
    let mut windows = Vec::new();
    for hours in LAKE_IDENTITY_LOOKBACKS_HOURS {
        let mut start = reference_time - Duration::hours(hours);
        if let Some(cutoff) = cutoff {
            start = start.max(cutoff);
        }
        if start < end {
            windows.push((start, end));
        }
        end = start;
    }
    windows
}

/// Group ordinals without changing the caller's result order or merging
/// distinct point-in-time bindings.
fn identity_reference_groups(
    indices: &[usize],
    items: &[(IpAddr, DateTime<Utc>)],
) -> std::collections::BTreeMap<DateTime<Utc>, Vec<usize>> {
    let mut groups = std::collections::BTreeMap::<_, Vec<_>>::new();
    for &index in indices {
        groups.entry(items[index].1).or_default().push(index);
    }
    groups
}

impl SearchService {
    /// Resolve one point-in-time IP identity (see the module docs): a batch
    /// of one. Product handlers call this only on a tenant-pinned lake view;
    /// there is no ClickHouse fallback on this boundary. `Ok(None)` is a real
    /// miss; every failure is an `Err` (fail closed).
    pub async fn resolve_lake_identity_ip(
        &self,
        ip: &str,
        reference_time: DateTime<Utc>,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<Option<LakeIdentityObservation>, SearchError> {
        let ip: IpAddr = ip.trim().parse().map_err(|_| {
            SearchError::SqlValidationError("identity resolution requires an IP address".to_string())
        })?;
        Ok(self
            .resolve_lake_identity_ips(&[(ip, reference_time)], deny_source_types)
            .await?
            .pop()
            .flatten())
    }

    pub(super) fn lake_identity_client(&self) -> Result<&crate::search::lake::LakeQueryClient, SearchError> {
        if self.lake_query.mode != LakeQueryMode::Primary {
            return Err(SearchError::SqlValidationError(
                "lake identity resolution requires the lake log backend".to_string(),
            ));
        }
        self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError("lake identity client is unavailable".to_string())
        })
    }

    /// Resolve point-in-time IP identities, one answer per item in order
    /// (see the module docs). Items before the retention cutoff are misses
    /// without a request.
    pub async fn resolve_lake_identity_ips(
        &self,
        items: &[(IpAddr, DateTime<Utc>)],
        deny_source_types: &BTreeSet<String>,
    ) -> Result<Vec<Option<LakeIdentityObservation>>, SearchError> {
        let client = self.lake_identity_client()?;
        let cutoff = self.retention_cutoff_at(Utc::now())?;
        let mut answers = vec![None; items.len()];
        // Deduplicate before splitting the wire batches: repeated event bindings
        // can straddle the 500-item cap, otherwise repeating both index reads
        // and historical fallback scans. Reuse is request-local and bound to
        // the exact IP/reference pair, tenant, retention and source scope.
        let mut bindings = std::collections::BTreeMap::<_, Vec<usize>>::new();
        let mut live = Vec::new();
        for (index, item) in items.iter().enumerate() {
            if cutoff.is_some_and(|cutoff| item.1 < cutoff) {
                continue;
            }
            let ordinals = bindings.entry(*item).or_default();
            if ordinals.is_empty() {
                live.push(index);
            }
            ordinals.push(index);
        }
        for chunk in live.chunks(LAKE_IDENTITY_BATCH_CAP) {
            let batch = chunk
                .iter()
                .map(|&index| LakeIdentityBatchItem {
                    ip: items[index].0.to_string(),
                    reference_time: items[index].1.to_rfc3339(),
                })
                .collect::<Vec<_>>();
            let answer = client.resolve_identity_batch(&batch, deny_source_types).await?;
            if answer.complete {
                let mut seen = BTreeSet::new();
                for row in answer.rows {
                    let (Some(&index), Some(item)) = (chunk.get(row.ordinal), batch.get(row.ordinal)) else {
                        return Err(SearchError::SqlValidationError(
                            "lake identity answer returned an out-of-range ordinal".to_string(),
                        ));
                    };
                    if !seen.insert(row.ordinal) || !same_ip(&row.ip, &items[index].0) {
                        return Err(SearchError::SqlValidationError(format!(
                            "lake identity answer substituted the binding of {}",
                            item.ip
                        )));
                    }
                    if parse_observed_at(&row.observed_at).is_none_or(|at| at > items[index].1) {
                        return Err(SearchError::SqlValidationError(
                            "lake identity answer violates its point-in-time binding".to_string(),
                        ));
                    }
                    answers[index] = Some(index_observation(
                        row.hostname, row.fqdn, row.user, row.mac, row.source, row.observed_at, row.nat_candidate,
                    ));
                }
                continue;
            }
            // A grouped scan returns the latest observation before ONE reference
            // time. Sharing the newest reference across a mixed-time batch can
            // attribute a future hostname/user to an earlier event. Batch only
            // items with the exact same reference; duplicate bindings fan out
            // from the same answer without another scan.
            for (reference_time, indices) in identity_reference_groups(chunk, items) {
                let group = indices.iter().map(|&index| items[index]).collect::<Vec<_>>();
                debug_assert!(group.iter().all(|(_, at)| *at == reference_time));
                let scanned = self
                    .scan_lake_identity(client, &group, cutoff, deny_source_types)
                    .await?;
                for (index, observation) in indices.into_iter().zip(scanned) {
                    answers[index] = observation;
                }
            }
        }
        for ordinals in bindings.values() {
            let observation = answers[ordinals[0]].clone();
            for &index in &ordinals[1..] {
                answers[index] = observation.clone();
            }
        }
        Ok(answers)
    }

    /// The NAN-3057 bounded event scan for a batch (see the module docs).
    async fn scan_lake_identity(
        &self,
        client: &crate::search::lake::LakeQueryClient,
        items: &[(IpAddr, DateTime<Utc>)],
        cutoff: Option<DateTime<Utc>>,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<Vec<Option<LakeIdentityObservation>>, SearchError> {
        let distinct = items.iter().map(|(ip, _)| *ip).collect::<BTreeSet<_>>();
        let Some(reference_time) = items.iter().map(|(_, at)| *at).max() else {
            return Ok(Vec::new());
        };
        let mut found: std::collections::BTreeMap<IpAddr, LakeIdentityObservation> = Default::default();
        if distinct.len() == 1 {
            // One IP at one reference: duplicate items reuse the `head 1` read.
            let mut out = Vec::with_capacity(items.len());
            let ip = distinct.iter().next().expect("nonempty identity batch");
            let observation = self
                .scan_lake_identity_ip(client, ip, reference_time, cutoff, deny_source_types)
                .await?;
            out.resize(items.len(), observation);
            return Ok(out);
        }
        for (start, end) in lake_identity_windows(reference_time, cutoff) {
            let pending = distinct.iter().filter(|ip| !found.contains_key(ip)).copied().collect::<Vec<_>>();
            if pending.is_empty() {
                break;
            }
            for side in ["src_endpoint", "device"] {
                let rows = self
                    .lake_identity_scan(client, lake_identity_batch_query(side, &pending), start, end, pending.len(), deny_source_types)
                    .await?;
                for row in &rows {
                    let Some((ip, observation)) = lake_identity_batch_row(row, side, reference_time) else { continue };
                    if !pending.contains(&ip) {
                        continue;
                    }
                    // The newer observation wins; a tie keeps the source side.
                    let newer = found.get(&ip).is_none_or(|current| {
                        parse_observed_at(&observation.observed_at) > parse_observed_at(&current.observed_at)
                    });
                    if newer {
                        found.insert(ip, observation);
                    }
                }
            }
        }
        Ok(items.iter().map(|(ip, _)| found.get(ip).cloned()).collect())
    }

    async fn scan_lake_identity_ip(
        &self,
        client: &crate::search::lake::LakeQueryClient,
        ip: &IpAddr,
        reference_time: DateTime<Utc>,
        cutoff: Option<DateTime<Utc>>,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<Option<LakeIdentityObservation>, SearchError> {
        let query = lake_identity_query(ip);
        for (start, end) in lake_identity_windows(reference_time, cutoff) {
            let rows = self.lake_identity_scan(client, query.clone(), start, end, 1, deny_source_types).await?;
            if let Some(observation) = rows.iter().find_map(|row| lake_identity_observation(row, ip, reference_time)) {
                return Ok(Some(observation));
            }
        }
        Ok(None)
    }

    async fn lake_identity_scan(
        &self,
        client: &crate::search::lake::LakeQueryClient,
        query: String,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let request_id = format!("identity-resolve-{}", uuid::Uuid::now_v7());
        let request = SearchRequest {
            query,
            time_range: TimeRangeInput::new(start, end),
            limit: Some(limit),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: Some(request_id.clone()),
            async_mode: false,
            priority: Some("interactive".to_string()),
            dataset: Some("logs".to_string()),
        };
        Ok(client.search(&request, &request_id, None, deny_source_types).await?.results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn query_is_fixed_text_around_a_canonical_ip() {
        let q = lake_identity_query(&"10.1.3.7".parse().unwrap());
        assert!(q.contains("src_endpoint.ip=\"10.1.3.7\""));
        assert!(q.contains("device.ip=\"10.1.3.7\""));
        assert!(q.contains("| sort -time | head 1"));
        // Explicit parens: nPL search-term OR binds tighter than AND.
        assert!(q.starts_with("((src_endpoint.ip="));
        let v6 = lake_identity_query(&"2001:DB8::1".parse().unwrap());
        assert!(v6.contains("src_endpoint.ip=\"2001:db8::1\""));
    }

    #[test]
    fn source_match_takes_the_source_hostname_not_the_logging_device() {
        // Windows Security 4624 shape: device is the DC that logged it.
        let row = json!({
            "time": "2026-09-29 23:46:00.683000", "metadata.log_source": "windows_event",
            "src_endpoint.ip": "10.1.8.119", "src_endpoint.hostname": "lt-legal-050",
            "device.ip": null, "device.hostname": "dc01.corp.local",
            "user.name": "dnguyen", "actor.user.name": null,
        });
        let obs = lake_identity_observation(&row, &"10.1.8.119".parse().unwrap(), at("2026-09-30T00:00:00Z")).unwrap();
        assert_eq!(obs.hostname, "lt-legal-050");
        assert_eq!(obs.user, "dnguyen");
        assert_eq!(obs.source, "event_scan:windows_event");
        assert_eq!(obs.resolved_via, LakeIdentityResolution::EventScan);
        assert_eq!(obs.observed_at, "2026-09-29T23:46:00.683000Z");
    }

    #[test]
    fn device_match_takes_the_device_hostname_and_actor_user() {
        let row = json!({
            "time": "2026-09-29T10:00:00Z", "metadata": {"log_source": "windows_sysmon"},
            "src_endpoint": {"ip": "10.9.9.9", "hostname": "other"},
            "device": {"ip": "10.1.3.7", "hostname": "ws-it-052.corp.local"},
            "user": {"name": ""}, "actor": {"user": {"name": "jhernandez"}},
        });
        let obs = lake_identity_observation(&row, &"10.1.3.7".parse().unwrap(), at("2026-09-29T11:00:00Z")).unwrap();
        assert_eq!(obs.hostname, "ws-it-052.corp.local");
        assert_eq!(obs.user, "jhernandez");
        assert_eq!(obs.source, "event_scan:windows_sysmon");
    }

    #[test]
    fn rows_that_do_not_bind_the_ip_or_name_nobody_are_misses() {
        let ip: IpAddr = "10.1.3.7".parse().unwrap();
        let reference = at("2026-09-29T11:00:00Z");
        let other_ip = json!({"time": "2026-09-29T10:00:00Z", "src_endpoint.ip": "10.1.3.8", "src_endpoint.hostname": "x"});
        assert!(lake_identity_observation(&other_ip, &ip, reference).is_none());
        let anonymous = json!({"time": "2026-09-29T10:00:00Z", "src_endpoint.ip": "10.1.3.7"});
        assert!(lake_identity_observation(&anonymous, &ip, reference).is_none());
        let future = json!({"time": "2026-09-29T12:00:00Z", "src_endpoint.ip": "10.1.3.7", "src_endpoint.hostname": "x"});
        assert!(lake_identity_observation(&future, &ip, reference).is_none());
        let no_time = json!({"src_endpoint.ip": "10.1.3.7", "src_endpoint.hostname": "x"});
        assert!(lake_identity_observation(&no_time, &ip, reference).is_none());
    }

    #[test]
    fn batch_scan_query_is_fixed_text_per_side() {
        let ips: Vec<IpAddr> = vec!["10.1.3.7".parse().unwrap(), "2001:DB8::1".parse().unwrap()];
        let q = lake_identity_batch_query("src_endpoint", &ips);
        assert!(q.starts_with("src_endpoint.ip IN (\"10.1.3.7\",\"2001:db8::1\") (src_endpoint.hostname=*"));
        assert!(q.ends_with("by src_endpoint.ip"));
        assert!(q.contains("last(src_endpoint.hostname) as hostname"));
        let d = lake_identity_batch_query("device", &ips[..1]);
        assert!(d.starts_with("device.ip IN (\"10.1.3.7\") (device.hostname=*"));
        assert!(d.contains("last(device.hostname) as hostname"));
    }

    #[test]
    fn batch_scan_rows_bind_their_side_and_reference_time() {
        let reference = at("2026-09-30T00:00:00Z");
        let row = json!({"src_endpoint.ip": "10.1.3.7", "observed_at": "2026-09-29 23:48:45.669000",
            "hostname": "ws-it-052.corp.local", "user": "jhernandez", "source": "windows_sysmon"});
        let (ip, obs) = lake_identity_batch_row(&row, "src_endpoint", reference).unwrap();
        assert_eq!(ip, "10.1.3.7".parse::<IpAddr>().unwrap());
        assert_eq!((obs.hostname.as_str(), obs.user.as_str()), ("ws-it-052.corp.local", "jhernandez"));
        assert_eq!(obs.source, "event_scan:windows_sysmon");
        assert!(lake_identity_batch_row(&row, "device", reference).is_none(), "wrong side");
        assert!(lake_identity_batch_row(&row, "src_endpoint", at("2026-09-29T23:00:00Z")).is_none(), "after ref");
        let nobody = json!({"src_endpoint.ip": "10.1.3.7", "observed_at": "2026-09-29 23:48:45", "hostname": "", "user": null});
        assert!(lake_identity_batch_row(&nobody, "src_endpoint", reference).is_none());
    }

    #[test]
    fn exclusive_end_does_not_admit_the_next_microsecond() {
        let reference = at("2026-09-29T12:00:00.123456500Z");
        let windows = lake_identity_windows(reference, None);
        assert_eq!(windows[0].1, at("2026-09-29T12:00:00.123457Z"));
        assert!(windows[0].1 > reference);
        assert!(windows[0].1 - reference < Duration::microseconds(1));
    }

    #[test]
    fn windows_walk_nearest_first_without_overlap_and_respect_retention() {
        let reference = at("2026-09-29T12:00:00Z");
        let windows = lake_identity_windows(reference, None);
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0], (reference - Duration::hours(24), reference + Duration::microseconds(1)));
        assert_eq!(windows[1], (reference - Duration::days(7), reference - Duration::hours(24)));

        let cutoff = reference - Duration::hours(48);
        let clamped = lake_identity_windows(reference, Some(cutoff));
        assert_eq!(clamped[1], (cutoff, reference - Duration::hours(24)));

        let recent_cutoff = reference - Duration::hours(2);
        let only_first = lake_identity_windows(reference, Some(recent_cutoff));
        assert_eq!(only_first, vec![(recent_cutoff, reference + Duration::microseconds(1))]);
    }
}
