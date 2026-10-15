// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lean identity observations (NAN-3058): the per-part IP → host/user index
//! that replaces ClickHouse's `identity_observations` table and its
//! `ocsf_identity_observations_mv` on lean-lake cells.
//!
//! # Derivation (parity with `clickhouse/ocsf/init.sql`)
//!
//! One observation per event whose `src_endpoint.ip` is a private IPv4
//! address (10/8, 172.16/12, 192.168/16) and whose unified source host
//! (`src_endpoint.hostname`, else `device.hostname`) is not junk (`''`,
//! `localhost`, `-`, `unknown`, `UNKNOWN`):
//!
//! | column     | value                                                                 |
//! |------------|-----------------------------------------------------------------------|
//! | `ip`       | `src_endpoint.ip`                                                     |
//! | `fqdn`     | the unified source host                                               |
//! | `hostname` | the short name (before the first `.`) when the host contains `.corp.`, else the host |
//! | `mac`      | `src_endpoint.mac`                                                    |
//! | `user`     | `user.name`, else `actor.user.name`                                   |
//! | `source`   | lower(`metadata.log_source`) unless empty/`unknown`, else lower(`metadata.product.name`), else `unknown` |
//! | priority   | 50 (the table default; no event-derived row ever set another)         |
//!
//! # Storage
//!
//! Observations are deduplicated per `(ip, hour, hostname, fqdn, mac, user,
//! source)`: one row per combination per hour keeps first/last observed time
//! and a count. They are stored as rows of the part's signed entity-range
//! partial (`partials/entity_ranges.parquet`) under the reserved path
//! [`IDENTITY_PATH`], whose `value` is the JSON array
//! `[ip, hour_us, hostname, fqdn, mac, user, source]`. The entity-range
//! combine (min first, max last, sum events) IS the per-hour dedupe, so part
//! merges carry the index forward exactly, part GC retires it with its part,
//! and nothing about the part contract, its key fence or its provenance
//! changes. The query role never serves the reserved path through
//! `/v1/entity/ranges` (that route admits only bloom paths).
//!
//! Every indexed part also carries one coverage row (`value = ""`) whose
//! `events` is the number of source rows the derivation saw. A part is
//! indexed iff that count equals its row count: merges sum it exactly (a merge
//! that drops duplicates rebuilds every partial from its output rows), so a
//! merge with any pre-index input is simply not indexed. A part whose
//! derivation would exceed [`INGEST_BYTES_CAP`] writes no identity rows and
//! no coverage row; the query role backfills it (see
//! `part_query::identity`).
//!
//! # Feature flag
//!
//! Writers emit the rows only when [`set_enabled`] was called with `true`
//! (cell feature `lean_identity_observations_v1`, cell.json
//! `identity_observations`). Readers always understand them.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};

use arrow_array::RecordBatch;

use crate::generation::{event_time_us_from_array, CompiledStringPath};

/// Reserved entity-range path of identity observation rows.
pub const IDENTITY_PATH: &str = "nano.identity_observation.v1";
/// The value of the per-part coverage row.
pub const COVERAGE_VALUE: &str = "";
/// Priority of an event-derived observation (the ClickHouse table default).
pub const EVENT_SOURCE_PRIORITY: u8 = 50;
/// Lookback of a resolution (the ClickHouse table TTL).
pub const LOOKBACK_US: i64 = 30 * 86_400 * 1_000_000;
/// NAT window and threshold (`nat_candidates_view`: 3+ distinct hostnames in
/// one hour within the last 7 days).
pub const NAT_WINDOW_US: i64 = 7 * 86_400 * 1_000_000;
pub const NAT_MIN_HOSTS: u64 = 3;
const HOUR_US: i64 = 3_600 * 1_000_000;
/// Accounted bytes one ingest part may spend on observations before it gives
/// up and leaves the part to the query role's backfill (see [`entry_cost`]).
/// `ingest_heap_stays_under_the_cap` measures the real heap of a full
/// accumulator (worst case, every event distinct): its peak stays below the
/// accounted bytes (1.76 MB measured at a 2 MiB cap), so one part's
/// accumulator stays under 16 MiB (one per open part writer) of the ingest
/// role's 4.5 GiB. Merges that combine partial files never hold one.
pub const INGEST_BYTES_CAP: usize = 16 * 1024 * 1024;
/// The query role's backfill derives one part at a time with more room.
pub const BACKFILL_BYTES_CAP: usize = 64 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 1_024;

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Turn observation writing on for this process (cell feature
/// `lean_identity_observations_v1`, assignment `identity_observations`).
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

/// Whether part writers in this process derive identity observations.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// One derived observation of one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub ip: String,
    pub hostname: String,
    pub fqdn: String,
    pub mac: String,
    pub user: String,
    pub source: String,
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

fn clean(value: Option<String>) -> String {
    value.map(|v| v.trim().to_string()).filter(|v| v.len() <= MAX_FIELD_BYTES && !v.chars().any(char::is_control)).unwrap_or_default()
}

fn is_junk_host(host: &str) -> bool {
    matches!(host, "" | "localhost" | "-" | "unknown" | "UNKNOWN")
}

/// `hostname` of the MV: the short name for a `.corp.` FQDN.
pub fn short_hostname(fqdn: &str) -> &str {
    if fqdn.contains('.') && fqdn.contains(".corp.") {
        fqdn.split('.').next().unwrap_or(fqdn)
    } else {
        fqdn
    }
}

/// The raw leaf values one event offers; `None` = absent.
#[derive(Debug, Default, Clone)]
pub struct EventFields {
    pub src_ip: Option<String>,
    pub src_hostname: Option<String>,
    pub device_hostname: Option<String>,
    pub src_mac: Option<String>,
    pub user_name: Option<String>,
    pub actor_user_name: Option<String>,
    pub log_source: Option<String>,
    pub product_name: Option<String>,
}

/// The MV's row filter and projection for one event.
pub fn observe(fields: EventFields) -> Option<Observation> {
    let ip: Ipv4Addr = clean(fields.src_ip).parse().ok()?;
    if !is_private_v4(&ip) {
        return None;
    }
    let src_host = clean(fields.src_hostname);
    let fqdn = if src_host.is_empty() { clean(fields.device_hostname) } else { src_host };
    if is_junk_host(&fqdn) {
        return None;
    }
    let user_name = clean(fields.user_name);
    let user = if user_name.is_empty() { clean(fields.actor_user_name) } else { user_name };
    let log_source = clean(fields.log_source).to_lowercase();
    let source = if !log_source.is_empty() && log_source != "unknown" {
        log_source
    } else {
        Some(clean(fields.product_name).to_lowercase()).filter(|p| !p.is_empty()).unwrap_or_else(|| "unknown".to_string())
    };
    Some(Observation {
        ip: ip.to_string(),
        hostname: short_hostname(&fqdn).to_string(),
        mac: clean(fields.src_mac),
        user,
        source,
        fqdn,
    })
}

/// The reserved row value: `[ip, hour_us, hostname, fqdn, mac, user, source]`.
pub fn encode_value(observation: &Observation, hour_us: i64) -> String {
    serde_json::json!([
        observation.ip, hour_us, observation.hostname, observation.fqdn,
        observation.mac, observation.user, observation.source
    ])
    .to_string()
}

/// Inverse of [`encode_value`]; `None` for the coverage row or a malformed value.
pub fn decode_value(value: &str) -> Option<(Observation, i64)> {
    let array: Vec<serde_json::Value> = serde_json::from_str(value).ok()?;
    if array.len() != 7 {
        return None;
    }
    let text = |i: usize| array[i].as_str().map(str::to_string);
    Some((
        Observation {
            ip: text(0)?, hostname: text(2)?, fqdn: text(3)?, mac: text(4)?, user: text(5)?, source: text(6)?,
        },
        array[1].as_i64()?,
    ))
}

/// Accounted heap of one distinct entry: the key string twice (map key and
/// the value built at write), the tuple, and hash-map slack.
fn entry_cost(value: &str) -> usize {
    2 * value.len() + 96
}

/// First/last observed time and count of one (combination, hour).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub first_us: i64,
    pub last_us: i64,
    pub events: u64,
}

/// Accumulates one part's observations under a byte cap.
#[derive(Debug)]
pub struct IdentityAccumulator {
    entries: HashMap<String, Range>,
    bytes: usize,
    cap_bytes: usize,
    overflowed: bool,
    covered_rows: u64,
    min_us: i64,
    max_us: i64,
}

const PATHS: [&str; 8] = [
    "src_endpoint.ip", "src_endpoint.hostname", "device.hostname", "src_endpoint.mac",
    "user.name", "actor.user.name", "metadata.log_source", "metadata.product.name",
];

impl IdentityAccumulator {
    pub fn new(cap_bytes: usize) -> Self {
        Self { entries: HashMap::new(), bytes: 0, cap_bytes, overflowed: false, covered_rows: 0, min_us: i64::MAX, max_us: i64::MIN }
    }

    pub fn accounted_bytes(&self) -> usize {
        self.bytes
    }

    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    pub fn covered_rows(&self) -> u64 {
        self.covered_rows
    }

    /// Record one event at `time_us`.
    pub fn add(&mut self, fields: EventFields, time_us: i64) {
        if self.overflowed {
            return;
        }
        self.covered_rows += 1;
        self.min_us = self.min_us.min(time_us);
        self.max_us = self.max_us.max(time_us);
        let Some(observation) = observe(fields) else { return };
        let value = encode_value(&observation, time_us.div_euclid(HOUR_US) * HOUR_US);
        if let Some(range) = self.entries.get_mut(&value) {
            range.first_us = range.first_us.min(time_us);
            range.last_us = range.last_us.max(time_us);
            range.events += 1;
            return;
        }
        let cost = entry_cost(&value);
        if self.bytes.saturating_add(cost) > self.cap_bytes {
            // Past the cap the part is left unindexed rather than indexed
            // partially: drop what was gathered so the memory returns now.
            self.overflowed = true;
            self.entries = HashMap::new();
            self.bytes = 0;
            return;
        }
        self.bytes += cost;
        self.entries.insert(value, Range { first_us: time_us, last_us: time_us, events: 1 });
    }

    /// Record every row of a part batch (the part's own `time` and OCSF leaves).
    pub fn add_batch(&mut self, batch: &RecordBatch) -> anyhow::Result<()> {
        if self.overflowed {
            return Ok(());
        }
        let time = batch.column_by_name("time").ok_or_else(|| anyhow::anyhow!("part batch has no time"))?;
        let paths = PATHS.map(|path| CompiledStringPath::new(batch, path));
        let first = |index: usize, row: usize| -> Option<String> {
            paths[index].as_ref().and_then(|path| path.strings(row).into_iter().find(|v| !v.trim().is_empty()))
        };
        for row in 0..batch.num_rows() {
            let Some(time_us) = event_time_us_from_array(time.as_ref(), row) else {
                // A row without time cannot be indexed; the coverage count
                // then never matches and the part stays unindexed.
                continue;
            };
            self.add(
                EventFields {
                    src_ip: first(0, row), src_hostname: first(1, row), device_hostname: first(2, row),
                    src_mac: first(3, row), user_name: first(4, row), actor_user_name: first(5, row),
                    log_source: first(6, row), product_name: first(7, row),
                },
                time_us,
            );
            if self.overflowed {
                return Ok(());
            }
        }
        Ok(())
    }

    /// `(value, range)` rows sorted by value, plus the coverage row; empty
    /// when the cap was hit.
    pub fn into_rows(self) -> Vec<(String, Range)> {
        if self.overflowed {
            return Vec::new();
        }
        let (first_us, last_us) = if self.covered_rows == 0 { (0, 0) } else { (self.min_us, self.max_us) };
        let mut rows = Vec::with_capacity(self.entries.len() + 1);
        rows.push((COVERAGE_VALUE.to_string(), Range { first_us, last_us, events: self.covered_rows }));
        rows.extend(self.entries);
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }
}

/// Canonical form of an IP lookup key (`None` when not an IP).
pub fn canonical_ip(value: &str) -> Option<String> {
    value.trim().parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(ip: &str, host: &str) -> EventFields {
        EventFields {
            src_ip: Some(ip.into()), src_hostname: Some(host.into()),
            log_source: Some("Windows_Sysmon".into()), ..Default::default()
        }
    }

    #[test]
    fn only_private_ipv4_sources_are_observed() {
        for ip in ["10.1.3.7", "172.16.0.1", "172.31.255.1", "192.168.1.9"] {
            assert!(observe(fields(ip, "ws1")).is_some(), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "172.15.0.1", "100.64.0.1", "127.0.0.1", "0.0.0.0", "fd00::1", "::1", "not-an-ip", ""] {
            assert!(observe(fields(ip, "ws1")).is_none(), "{ip}");
        }
    }

    #[test]
    fn junk_hosts_are_dropped_and_the_device_host_is_the_fallback() {
        for host in ["", "localhost", "-", "unknown", "UNKNOWN", "  "] {
            assert!(observe(fields("10.0.0.1", host)).is_none(), "{host:?}");
        }
        let via_device = observe(EventFields {
            src_ip: Some("10.0.0.1".into()), device_hostname: Some("dc01.corp.local".into()), ..Default::default()
        })
        .unwrap();
        assert_eq!(via_device.fqdn, "dc01.corp.local");
        assert_eq!(via_device.hostname, "dc01");
        // The source host wins over the device.
        let both = observe(EventFields {
            src_ip: Some("10.0.0.1".into()), src_hostname: Some("ws-it-052.corp.local".into()),
            device_hostname: Some("dc01.corp.local".into()), ..Default::default()
        })
        .unwrap();
        assert_eq!(both.fqdn, "ws-it-052.corp.local");
    }

    #[test]
    fn short_hostname_only_for_corp_fqdns() {
        assert_eq!(short_hostname("ws-it-052.corp.local"), "ws-it-052");
        assert_eq!(short_hostname("web01.example.com"), "web01.example.com");
        assert_eq!(short_hostname("ws-it-052"), "ws-it-052");
        assert_eq!(short_hostname("corp.local"), "corp.local");
    }

    #[test]
    fn user_and_source_fallbacks_follow_the_mv() {
        let o = observe(EventFields {
            src_ip: Some("10.0.0.1".into()), src_hostname: Some("h".into()),
            user_name: Some(" ".into()), actor_user_name: Some("jhernandez".into()),
            log_source: Some("unknown".into()), product_name: Some("Sysmon".into()),
            src_mac: Some("aa:bb".into()), ..Default::default()
        })
        .unwrap();
        assert_eq!((o.user.as_str(), o.source.as_str(), o.mac.as_str()), ("jhernandez", "sysmon", "aa:bb"));
        let o = observe(EventFields { src_ip: Some("10.0.0.1".into()), src_hostname: Some("h".into()), ..Default::default() }).unwrap();
        assert_eq!((o.user.as_str(), o.source.as_str()), ("", "unknown"));
        let o = observe(fields("10.0.0.1", "h")).unwrap();
        assert_eq!(o.source, "windows_sysmon");
    }

    #[test]
    fn values_round_trip_and_the_coverage_row_is_not_an_observation() {
        let o = observe(fields("10.1.3.7", "ws-it-052.corp.local")).unwrap();
        let value = encode_value(&o, 7_200_000_000);
        assert_eq!(decode_value(&value), Some((o, 7_200_000_000)));
        assert_eq!(decode_value(COVERAGE_VALUE), None);
    }

    #[test]
    fn observations_dedupe_per_hour_and_coverage_counts_every_row() {
        let mut acc = IdentityAccumulator::new(INGEST_BYTES_CAP);
        let t0 = 1_000 * HOUR_US;
        acc.add(fields("10.0.0.1", "a"), t0 + 5);
        acc.add(fields("10.0.0.1", "a"), t0 + 50);
        acc.add(fields("10.0.0.1", "a"), t0 + HOUR_US + 1);
        acc.add(fields("10.0.0.1", "b"), t0 + 9);
        acc.add(fields("8.8.8.8", "a"), t0 + 9); // counted, not observed
        let rows = acc.into_rows();
        assert_eq!(rows.len(), 4, "coverage + (a, h0) + (a, h1) + (b, h0)");
        assert_eq!(rows[0].0, COVERAGE_VALUE);
        assert_eq!(rows[0].1, Range { first_us: t0 + 5, last_us: t0 + HOUR_US + 1, events: 5 });
        let a0 = rows.iter().find(|(v, _)| decode_value(v).is_some_and(|(o, h)| o.hostname == "a" && h == t0)).unwrap();
        assert_eq!(a0.1, Range { first_us: t0 + 5, last_us: t0 + 50, events: 2 });
    }

    #[test]
    fn past_the_cap_the_part_is_left_unindexed() {
        let mut acc = IdentityAccumulator::new(4 * 1024);
        for i in 0..1_000 {
            acc.add(fields(&format!("10.0.{}.{}", i / 250, i % 250), &format!("host-{i}")), 1_000);
            assert!(acc.accounted_bytes() <= 4 * 1024);
        }
        assert!(acc.overflowed());
        assert!(acc.into_rows().is_empty(), "no rows and no coverage row");
    }

    /// Measures the real heap of a capped accumulator (distinct IP/host per
    /// event, the worst case) against its accounted cap.
    #[test]
    fn ingest_heap_stays_under_the_cap() {
        let _serial = crate::test_heap::MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());
        let cap = 2 * 1024 * 1024;
        let (peak, accounted) = std::thread::spawn(move || {
            crate::test_heap::track_current_thread(true);
            let base = crate::test_heap::reset_peak();
            let mut acc = IdentityAccumulator::new(cap);
            let mut i = 0_u32;
            while !acc.overflowed() {
                let ip = Ipv4Addr::from(0x0a00_0000 | (i & 0x00ff_ffff));
                acc.add(
                    EventFields {
                        src_ip: Some(ip.to_string()), src_hostname: Some(format!("workstation-{i:08}.corp.example.com")),
                        user_name: Some(format!("user-{i:08}")), log_source: Some("windows_sysmon".into()),
                        src_mac: Some("00:11:22:33:44:55".into()), ..Default::default()
                    },
                    1_000,
                );
                if acc.accounted_bytes() + 1_024 > cap {
                    break;
                }
                i += 1;
            }
            let accounted = acc.accounted_bytes();
            let peak = crate::test_heap::peak() - base;
            drop(acc);
            crate::test_heap::track_current_thread(false);
            (peak, accounted)
        })
        .join()
        .unwrap();
        eprintln!("identity accumulator: accounted {accounted} B, measured peak heap {peak} B, cap {cap} B");
        assert!(accounted > cap / 2, "the scenario filled the cap ({accounted})");
        // The accounting (key twice + fixed overhead) covers the table's
        // growth: the measured peak, rehash included, stays under the cap.
        assert!(peak as usize <= cap, "peak heap {peak} B exceeds the {cap} B cap");
    }
}
