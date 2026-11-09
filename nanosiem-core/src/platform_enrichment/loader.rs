// SPDX-License-Identifier: AGPL-3.0-or-later
//! ClickHouse loader for a verified platform feed bundle (NAN-4948).
//!
//! The ClickHouse product stamps enrichment at insert time through
//! dictionaries, so "installing" a feed means writing it into the tables those
//! dictionaries are refreshed from:
//!
//! | feed             | table                       | dictionary → columns                                   |
//! |------------------|-----------------------------|--------------------------------------------------------|
//! | `ipinfo_lite`    | `ip_enrichments`            | `ip_enrichment_dict` → `enriched_*`, OCSF location/ASN |
//! | `threatfox`      | `custom_enrichment_results` | `ioc_enrichment_dict` → `ioc_*` (marketplace IOC rows) |
//! | `tor_exit_nodes` | `custom_enrichment_results` | `ioc_enrichment_dict` → `ioc_*` (`threat_type=tor_exit`) |
//!
//! ## Atomic swap, last good kept
//!
//! Every feed of an install is written under its own generation key,
//! `platform_feed/<feed>/<sequence>` (the IP rows' `source_id`, the IOC rows'
//! `namespace`). Nothing is visible until ONE row per feed lands in
//! `nanosiem.platform_feed_commits` in a single INSERT (CH migration 184). Rows
//! the loader writes carry the `platform_feed = 1` ownership marker; visibility
//! and reclaim key on that marker, never on the name, so tenant data cannot be
//! hidden or deleted by a colliding namespace. The
//! dictionary refresh views and every Rust reader of
//! `custom_enrichment_results` only see platform rows whose key is the latest
//! commit for their feed ([`visible_predicate`]). So:
//!
//! - a load that fails part-way is never visible; the previous generation
//!   keeps stamping, and the orphaned rows are reclaimed;
//! - the new generation replaces the old one at once, including indicators the
//!   new bundle dropped (no tombstones needed);
//! - a withdrawal (feed past its hard expiry)
//!   commits an empty key, which matches no row.
//!
//! Writes go to the LOCAL tables (per-shard, NAN-1728); reads, the dict
//! refreshes and the commit subquery go through the `_distributed` wrappers
//! on clusters. Superseded generations are deleted best-effort (`ON CLUSTER`).

use std::{collections::BTreeMap, fs::File, net::IpAddr, sync::Arc};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clickhouse::Row;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::nanpfb::IocSnapshotInput;
use super::payload::{self, Sections};
use super::portable::{Descriptor, FeedEntry};
use crate::db::dual_pool::{on_cluster_clause, TableNames};

pub use super::state::{
    storage_key, visible_predicate, PLATFORM_FEED_COMMITS_TABLE, PLATFORM_FEED_MARKER,
    PLATFORM_FEED_NAMESPACE,
};
/// The feed whose payload is the MMDB section.
pub const IPINFO_FEED: &str = "ipinfo_lite";

const IP_TABLE: &str = "ip_enrichments";
const IOC_TABLE: &str = "custom_enrichment_results";
const IP_DICT_REFRESH: &str = "nanosiem.ip_enrichment_dict_refresh";
const IOC_DICT: &str = "nanosiem.ioc_enrichment_dict";
const IOC_DICT_REFRESH: &str = "nanosiem.ioc_enrichment_dict_refresh";
/// Server-side insert block bound for feed loads (NAN-4957).
const LOAD_INSERT_BLOCK_ROWS: &str = "131072";
const LOAD_INSERT_BLOCK_BYTES: &str = "33554432";
/// Rows per IOC INSERT block.
const IOC_CHUNK: usize = 10_000;
/// IP rows handed from the MMDB walker to the writer per message.
const IP_CHUNK: usize = 20_000;
/// Upper bound on one refresh + reload; past it the data still applies on the
/// views' own cadence plus the dictionary lifetime.
const ACTIVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Map a bundle feed's IOC type onto the `custom_enrichment_results` key type
/// the ingest dictionary and the IOC readers use, and its lookup value.
/// ThreatFox `ip:port` indicators are keyed by the IP (ingest matches the
/// event's `src_ip` / `dest_ip`); the full indicator stays in `data`.
pub fn ioc_key(ioc_type: &str, value: &str) -> Option<(&'static str, String)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    match ioc_type {
        "ip" => value
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ("ip", ip.to_string())),
        "ip:port" => split_ip_port(value).map(|ip| ("ip", ip.to_string())),
        "domain" => Some(("domain", value.to_ascii_lowercase())),
        "url" => Some(("url", value.to_string())),
        "md5_hash" | "sha1_hash" | "sha256_hash" | "hash" => {
            Some(("hash", value.to_ascii_lowercase()))
        }
        _ => None,
    }
}

fn split_ip_port(value: &str) -> Option<IpAddr> {
    if let Ok(socket) = value.parse::<std::net::SocketAddr>() {
        return Some(socket.ip());
    }
    let (host, port) = value.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    host.trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()
        .ok()
}

/// Deterministic `enrichment_id` of a platform feed (UUID-shaped SHA-256 of a
/// fixed label), so every install's rows of one feed share an id.
pub fn feed_enrichment_id(feed: &str) -> Uuid {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("nano/platform-feed/{feed}").as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// One `custom_enrichment_results` row (RowBinary; DateTime64(3) = millis).
#[derive(Debug, Clone, PartialEq, Row, Serialize)]
pub struct IocRow {
    pub namespace: String,
    #[serde(with = "clickhouse::serde::uuid")]
    pub enrichment_id: Uuid,
    pub enrichment_name: String,
    pub key_type: String,
    pub key_value: String,
    pub risk_score: Option<u8>,
    pub tags: Vec<String>,
    pub data: String,
    pub fetched_at: i64,
    pub expires_at: i64,
    pub version: u32,
    pub is_ioc: u8,
    pub threat_type: String,
    pub malware: String,
    pub confidence: u8,
    pub is_marketplace: u8,
    /// Ownership marker ([`PLATFORM_FEED_MARKER`]): always 1.
    pub platform_feed: u8,
}

/// Convert one bundle IOC row into its stored form. `None`: a type the
/// ClickHouse product cannot match (counted, not loaded) or already expired.
pub fn ioc_row(
    row: &IocSnapshotInput,
    entry: &FeedEntry,
    sequence: u64,
    fetched_at: DateTime<Utc>,
) -> Option<IocRow> {
    let (key_type, key_value) = ioc_key(&row.ioc_type, &row.ioc_value)?;
    // An indicator's own expiry (ThreatFox `effective_valid_until`, unix
    // seconds) can be sooner than the feed's signed hard expiry; never later.
    let mut expires = entry.hard_expiry.timestamp_millis();
    if let Some(own) = row.data.get("effective_valid_until").and_then(|v| v.as_i64()) {
        expires = expires.min(own.saturating_mul(1000));
    }
    if expires <= fetched_at.timestamp_millis() {
        return None;
    }
    let mut data = serde_json::json!({
        "platform_feed": row.source_id,
        "feed_revision": entry.revision,
        "bundle_sequence": sequence,
        "ioc_type": row.ioc_type,
        "ioc_value": row.ioc_value,
    });
    if let (Some(extra), Some(out)) = (row.data.as_object(), data.as_object_mut()) {
        for (k, v) in extra {
            out.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    Some(IocRow {
        namespace: storage_key(&row.source_id, sequence),
        enrichment_id: feed_enrichment_id(&row.source_id),
        enrichment_name: row.source_id.clone(),
        key_type: key_type.to_string(),
        key_value,
        risk_score: row.risk_score.map(|r| r.clamp(0, 100) as u8),
        tags: row.tags.clone(),
        data: data.to_string(),
        fetched_at: fetched_at.timestamp_millis(),
        expires_at: expires,
        version: entry.revision.clamp(1, u32::MAX as i64) as u32,
        is_ioc: u8::from(row.is_ioc),
        threat_type: row.threat_type.clone(),
        malware: row.malware.clone(),
        confidence: row.confidence_level.clamp(0, 100) as u8,
        is_marketplace: 1,
        platform_feed: 1,
    })
}

/// One `ip_enrichments` row (explicit generation stamp, NAN-1441).
#[derive(Debug, Clone, PartialEq, Row, Serialize)]
pub struct IpRow {
    pub network: String,
    pub country: String,
    pub country_code: String,
    pub continent: String,
    pub continent_code: String,
    pub asn: String,
    pub as_name: String,
    pub as_domain: String,
    pub source_id: String,
    pub updated_at: i64,
    pub deleted: u8,
    /// Ownership marker ([`PLATFORM_FEED_MARKER`]): always 1.
    pub platform_feed: u8,
}

/// IPinfo Lite MMDB record (`ipinfo_lite.mmdb` schema).
#[derive(Debug, Default, Deserialize)]
struct IpinfoRecord<'a> {
    #[serde(default, borrow)]
    country: Option<&'a str>,
    #[serde(default, borrow)]
    country_code: Option<&'a str>,
    #[serde(default, borrow)]
    continent: Option<&'a str>,
    #[serde(default, borrow)]
    continent_code: Option<&'a str>,
    #[serde(default, borrow)]
    asn: Option<&'a str>,
    #[serde(default, borrow)]
    as_name: Option<&'a str>,
    #[serde(default, borrow)]
    as_domain: Option<&'a str>,
}

/// Exact CIDR aggregation of an in-order network stream: two sibling blocks
/// with identical records become their parent. The MMDB tree splits upstream
/// ranges into more leaves than IPinfo has rows (5.7M leaves for 4.4M rows on
/// the 2026-11 bundle); merging back keeps the `ip_enrichment_dict` IP_TRIE
/// (built in ClickHouse memory) as small as the data allows. Lookups are
/// unchanged: a merged block only ever covers addresses that all carried the
/// same record.
struct CidrMerger {
    /// Pending blocks in address order: (base, prefix, bits, record).
    stack: Vec<(u128, u8, u8, IpRow)>,
}

impl CidrMerger {
    fn new() -> Self {
        Self { stack: Vec::new() }
    }

    fn same_record(a: &IpRow, b: &IpRow) -> bool {
        (&a.country, &a.country_code, &a.continent, &a.continent_code, &a.asn, &a.as_name, &a.as_domain)
            == (&b.country, &b.country_code, &b.continent, &b.continent_code, &b.asn, &b.as_name, &b.as_domain)
    }

    fn size(prefix: u8, bits: u8) -> u128 {
        if prefix == 0 {
            // Only the whole space; never merged further.
            u128::MAX
        } else {
            1u128 << (bits - prefix)
        }
    }

    fn is_right_child(base: u128, prefix: u8, bits: u8) -> bool {
        prefix > 0 && base & Self::size(prefix, bits) != 0
    }

    fn render(base: u128, prefix: u8, bits: u8) -> String {
        if bits == 32 {
            format!("{}/{prefix}", std::net::Ipv4Addr::from(base as u32))
        } else {
            format!("{}/{prefix}", std::net::Ipv6Addr::from(base))
        }
    }

    fn flush(&mut self, emit: &mut impl FnMut(IpRow) -> Result<()>) -> Result<()> {
        for (base, prefix, bits, mut row) in self.stack.drain(..) {
            row.network = Self::render(base, prefix, bits);
            emit(row)?;
        }
        Ok(())
    }

    /// Add the next block (strictly after every pending one, same family).
    fn push(
        &mut self,
        mut base: u128,
        mut prefix: u8,
        bits: u8,
        row: IpRow,
        emit: &mut impl FnMut(IpRow) -> Result<()>,
    ) -> Result<()> {
        if let Some(&(top_base, top_prefix, top_bits, _)) = self.stack.last() {
            if top_bits != bits {
                self.flush(emit)?;
            } else if !(top_prefix == prefix
                && prefix > 0
                && top_base ^ base == Self::size(prefix, bits)
                && !Self::is_right_child(top_base, top_prefix, bits))
            {
                // Not the top's sibling. If the new block starts past the
                // top's sibling region, the top (and everything pending below
                // it, whose sibling regions contain the top) can never merge.
                let sibling_end = top_base
                    .saturating_add(Self::size(top_prefix, bits))
                    .saturating_add(Self::size(top_prefix, bits));
                if Self::is_right_child(top_base, top_prefix, bits) || base >= sibling_end {
                    self.flush(emit)?;
                }
            }
        }
        // Merge upward while the top is our left sibling with the same record.
        while let Some((top_base, top_prefix, top_bits, top_row)) = self.stack.last() {
            let sibling = *top_bits == bits
                && *top_prefix == prefix
                && prefix > 0
                && top_base ^ base == Self::size(prefix, bits)
                && !Self::is_right_child(*top_base, prefix, bits);
            if !(sibling && Self::same_record(top_row, &row)) {
                break;
            }
            base = *top_base;
            prefix -= 1;
            self.stack.pop();
        }
        if Self::is_right_child(base, prefix, bits) {
            // A right child that did not merge left is final, and so is
            // everything pending to its left.
            self.flush(emit)?;
            let mut row = row;
            row.network = Self::render(base, prefix, bits);
            return emit(row);
        }
        self.stack.push((base, prefix, bits, row));
        Ok(())
    }
}

/// Walk every network of an IPinfo Lite MMDB in CIDR form (IPv4 networks as
/// IPv4, the IPv4 subtree of an IPv6 database is not repeated as IPv6, and
/// aliases such as `::ffff:0:0/96` are skipped), merging sibling blocks with
/// identical records ([`CidrMerger`]), calling `emit` per row. Returns the rows
/// emitted.
pub fn walk_mmdb(
    mmdb: &[u8],
    source_id: &str,
    updated_at: i64,
    mut emit: impl FnMut(IpRow) -> Result<()>,
) -> Result<u64> {
    let reader = maxminddb::Reader::from_source(mmdb).context("IPinfo MMDB")?;
    let mut count = 0u64;
    let mut counted = |row: IpRow| -> Result<()> {
        count += 1;
        emit(row)
    };
    let mut merger = CidrMerger::new();
    let row_of = |record: IpinfoRecord<'_>| {
        let s = |v: Option<&str>| v.unwrap_or_default().to_string();
        IpRow {
            network: String::new(),
            country: s(record.country),
            country_code: s(record.country_code),
            continent: s(record.continent),
            continent_code: s(record.continent_code),
            asn: s(record.asn),
            as_name: s(record.as_name),
            as_domain: s(record.as_domain),
            source_id: source_id.to_string(),
            updated_at,
            deleted: 0,
            platform_feed: 1,
        }
    };
    let v4: ipnetwork::IpNetwork = "0.0.0.0/0".parse().expect("valid");
    for item in reader.within(v4, Default::default()).context("IPinfo MMDB IPv4")? {
        let item = item.context("IPinfo MMDB network")?;
        let network = item.network().context("IPinfo MMDB network")?;
        let ipnetwork::IpNetwork::V4(net) = network else {
            continue;
        };
        if let Some(record) = item.decode::<IpinfoRecord<'_>>()? {
            merger.push(u32::from(net.network()) as u128, net.prefix(), 32, row_of(record), &mut counted)?;
        }
    }
    merger.flush(&mut counted)?;
    if reader.metadata().ip_version == 6 {
        let v6: ipnetwork::IpNetwork = "::/0".parse().expect("valid");
        for item in reader.within(v6, Default::default()).context("IPinfo MMDB IPv6")? {
            let item = item.context("IPinfo MMDB network")?;
            let network = item.network().context("IPinfo MMDB network")?;
            let ipnetwork::IpNetwork::V6(net) = network else {
                continue;
            };
            // The IPv4 subtree lives at ::/96 in an IPv6 database; it was
            // emitted as IPv4 above.
            if net.prefix() >= 96 && net.network().segments()[..6] == [0u16; 6] {
                continue;
            }
            if let Some(record) = item.decode::<IpinfoRecord<'_>>()? {
                merger.push(u128::from(net.network()), net.prefix(), 128, row_of(record), &mut counted)?;
            }
        }
        merger.flush(&mut counted)?;
    }
    Ok(count)
}

/// One `platform_feed_commits` row.
#[derive(Debug, Clone, PartialEq, Row, Serialize)]
pub struct CommitRow {
    pub sequence: u64,
    pub feed_id: String,
    /// The generation key now active for the feed; empty withdraws it.
    pub storage_key: String,
    pub revision: i64,
    pub hard_expiry: i64,
    pub committed_at: i64,
    /// The install receipt (`state::InstallReceipt` JSON, signed descriptor
    /// included), identical on every row of one commit: ClickHouse is the
    /// durable record of what is active, PostgreSQL is repaired from it.
    pub receipt: String,
}

#[derive(Debug, Row, Deserialize)]
struct ReceiptRow {
    sequence: u64,
    receipt: String,
}

#[derive(Debug, Row, Deserialize)]
struct HighWaterRow {
    feed_id: String,
    revision: i64,
}


#[derive(Debug, Row, Deserialize)]
struct ActiveRow {
    feed_id: String,
    storage_key: String,
}

/// Rows loaded per feed.
pub type LoadedCounts = BTreeMap<String, u64>;

/// Writes verified bundles into ClickHouse.
#[derive(Clone)]
pub struct ClickHouseLoader {
    ch: clickhouse::Client,
    ch_admin: clickhouse::Client,
    on_cluster: String,
    names: TableNames,
    database: String,
}

impl ClickHouseLoader {
    /// `ch` writes and reads; `ch_admin` runs `SYSTEM REFRESH VIEW` (the
    /// runtime user may not hold it).
    pub fn new(ch: clickhouse::Client, ch_admin: clickhouse::Client) -> Self {
        let on_cluster = on_cluster_clause();
        let names = TableNames::new(!on_cluster.is_empty());
        Self {
            ch,
            ch_admin,
            on_cluster,
            names,
            database: "nanosiem".to_string(),
        }
    }

    /// Target another database (isolated integration tests). The dictionary
    /// activation still names the production views.
    pub fn with_database(mut self, database: &str) -> Self {
        self.database = database.to_string();
        self
    }

    fn table(&self, bare: &str) -> String {
        format!("{}.{bare}", self.database)
    }

    fn writer(&self) -> clickhouse::Client {
        self.ch
            .clone()
            .with_validation(false)
            .with_option("async_insert", "0")
            .with_option("wait_end_of_query", "1")
            // NAN-4957: the IPinfo load streams 4.38M rows through ONE insert,
            // which the server cut into 1,048,449-row blocks: 465 MiB per block
            // on a 2G box (limit 1.6 GiB), where it hit 241 and the feed never
            // installed. Smaller blocks bound the writer, not the result: each
            // generation stays invisible until its commit row.
            .with_option("max_insert_block_size", LOAD_INSERT_BLOCK_ROWS)
            .with_option("min_insert_block_size_rows", LOAD_INSERT_BLOCK_ROWS)
            .with_option("min_insert_block_size_bytes", LOAD_INSERT_BLOCK_BYTES)
    }

    fn commits_read(&self) -> String {
        let read = self.names.read(PLATFORM_FEED_COMMITS_TABLE);
        match read.strip_prefix("nanosiem.") {
            Some(bare) => self.table(bare),
            None => read,
        }
    }

    /// Load the IPinfo MMDB of the verified container open as `file` under
    /// `key`. Rows are invisible until committed. `expected` is the signed
    /// row count (a mismatch is logged, not fatal: the MMDB is the data).
    pub async fn load_ipinfo(
        &self,
        file: &File,
        sections: &Sections,
        key: &str,
        expected: u64,
    ) -> Result<u64> {
        let mmdb = payload::read_mmdb(file, sections)?;
        if mmdb.is_empty() {
            bail!("bundle carries no IPinfo section");
        }
        let updated_at = Utc::now().timestamp_millis();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<IpRow>>(4);
        let source_id = key.to_string();
        let walker = tokio::task::spawn_blocking(move || -> Result<u64> {
            let mut chunk = Vec::with_capacity(IP_CHUNK);
            let count = walk_mmdb(&mmdb, &source_id, updated_at, |row| {
                chunk.push(row);
                if chunk.len() >= IP_CHUNK {
                    let full = std::mem::replace(&mut chunk, Vec::with_capacity(IP_CHUNK));
                    tx.blocking_send(full)
                        .map_err(|_| anyhow::anyhow!("IPinfo writer stopped"))?;
                }
                Ok(())
            })?;
            if !chunk.is_empty() {
                tx.blocking_send(chunk)
                    .map_err(|_| anyhow::anyhow!("IPinfo writer stopped"))?;
            }
            Ok(count)
        });
        let writer = self.writer();
        let write = async {
            let mut insert = writer.insert::<IpRow>(&self.table(IP_TABLE)).await?;
            let mut written = 0u64;
            while let Some(rows) = rx.recv().await {
                for row in &rows {
                    insert.write(row).await?;
                }
                written += rows.len() as u64;
            }
            insert.end().await?;
            anyhow::Ok(written)
        };
        let written = match write.await {
            Ok(n) => n,
            Err(error) => {
                walker.abort();
                return Err(error.context("IPinfo insert"));
            }
        };
        let walked = walker.await.context("IPinfo MMDB walker")??;
        anyhow::ensure!(walked == written, "IPinfo rows walked {walked} != written {written}");
        anyhow::ensure!(written > 0, "IPinfo MMDB has no networks");
        if written != expected {
            tracing::warn!(written, expected, "IPinfo networks differ from the signed row count");
        }
        Ok(written)
    }

    /// Load every IOC row of the verified container open as `file` whose feed is in
    /// `feeds` (feed → its signed entry), under `storage_key(feed, sequence)`.
    /// Returns rows loaded per feed and rows skipped (unmatchable type or
    /// already expired).
    pub async fn load_iocs(
        &self,
        file: Arc<File>,
        sections: &Sections,
        descriptor: &Descriptor,
        feeds: &BTreeMap<String, FeedEntry>,
    ) -> Result<(LoadedCounts, u64)> {
        let sections = *sections;
        let sequence = descriptor.sequence;
        let carried: BTreeMap<String, FeedEntry> = descriptor.feeds.clone();
        let wanted = feeds.clone();
        let fetched_at = Utc::now();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<IocRow>>(4);
        let reader = tokio::task::spawn_blocking(move || -> Result<(LoadedCounts, u64, u64)> {
            let mut rows = payload::ioc_rows(file, &sections);
            let mut counts = LoadedCounts::new();
            let mut skipped = 0u64;
            let mut chunk = Vec::with_capacity(IOC_CHUNK);
            while let Some(row) = rows.next_row()? {
                let Some(entry) = carried.get(&row.source_id) else {
                    bail!("IOC row names feed {:?} the descriptor does not carry", row.source_id);
                };
                if !wanted.contains_key(&row.source_id) {
                    continue;
                }
                match ioc_row(&row, entry, sequence, fetched_at) {
                    Some(stored) => {
                        *counts.entry(row.source_id.clone()).or_default() += 1;
                        chunk.push(stored);
                    }
                    None => skipped += 1,
                }
                if chunk.len() >= IOC_CHUNK {
                    let full = std::mem::replace(&mut chunk, Vec::with_capacity(IOC_CHUNK));
                    tx.blocking_send(full)
                        .map_err(|_| anyhow::anyhow!("IOC writer stopped"))?;
                }
            }
            if !chunk.is_empty() {
                tx.blocking_send(chunk)
                    .map_err(|_| anyhow::anyhow!("IOC writer stopped"))?;
            }
            Ok((counts, skipped, rows.count()))
        });
        let writer = self.writer();
        let write = async {
            let mut written = 0u64;
            while let Some(rows) = rx.recv().await {
                let mut insert = writer.insert::<IocRow>(&self.table(IOC_TABLE)).await?;
                for row in &rows {
                    insert.write(row).await?;
                }
                insert.end().await?;
                written += rows.len() as u64;
            }
            anyhow::Ok(written)
        };
        let written = match write.await {
            Ok(n) => n,
            Err(error) => {
                reader.abort();
                return Err(error.context("IOC insert"));
            }
        };
        let (counts, skipped, _read) = reader.await.context("IOC reader")??;
        anyhow::ensure!(
            counts.values().sum::<u64>() == written,
            "IOC rows converted != written"
        );
        Ok((counts, skipped))
    }

    /// Make `commits` the active generations, in ONE insert (atomic).
    pub async fn commit(&self, commits: &[CommitRow]) -> Result<()> {
        if commits.is_empty() {
            return Ok(());
        }
        let mut insert = self
            .writer()
            .insert::<CommitRow>(&self.table(PLATFORM_FEED_COMMITS_TABLE))
            .await?;
        for row in commits {
            insert.write(row).await?;
        }
        insert.end().await?;
        Ok(())
    }

    /// The active generation key per feed (empty = withdrawn).
    pub async fn active_keys(&self) -> Result<BTreeMap<String, String>> {
        let rows: Vec<ActiveRow> = self
            .ch
            .query(&format!(
                "SELECT toString(feed_id) AS feed_id, argMax(storage_key, (sequence, committed_at)) AS storage_key \
                 FROM {} GROUP BY feed_id",
                self.commits_read()
            ))
            .fetch_all()
            .await?;
        Ok(rows.into_iter().map(|r| (r.feed_id, r.storage_key)).collect())
    }

    /// The receipt of the latest commit (by `(sequence, committed_at)`), if
    /// any commit carries one.
    pub async fn latest_receipt(&self) -> Result<Option<(u64, String)>> {
        let rows: Vec<ReceiptRow> = self
            .ch
            .query(&format!(
                "SELECT sequence, receipt FROM {} WHERE receipt != '' \
                 ORDER BY sequence DESC, committed_at DESC LIMIT 1",
                self.commits_read()
            ))
            .fetch_all()
            .await?;
        Ok(rows.into_iter().next().map(|r| (r.sequence, r.receipt)))
    }

    /// The highest revision ever committed per feed (the per-feed rollback
    /// fence, independent of the current descriptor's feed set).
    pub async fn high_water(&self) -> Result<BTreeMap<String, i64>> {
        let rows: Vec<HighWaterRow> = self
            .ch
            .query(&format!(
                "SELECT toString(feed_id) AS feed_id, max(revision) AS revision FROM {} GROUP BY feed_id",
                self.commits_read()
            ))
            .fetch_all()
            .await?;
        Ok(rows.into_iter().map(|r| (r.feed_id, r.revision)).collect())
    }

    /// Rows that look like platform generations by NAME but are not owned by
    /// the loader (pre-existing tenant data in a `platform_feed/…`
    /// namespace). They stay visible and are never reclaimed; counted so an
    /// operator can see the collision.
    pub async fn foreign_named_rows(&self) -> Result<u64> {
        let table = self.names.read(IOC_TABLE);
        let table = match table.strip_prefix("nanosiem.") {
            Some(bare) => self.table(bare),
            None => table,
        };
        Ok(self
            .ch
            .query(&format!(
                "SELECT count() FROM {table} WHERE {PLATFORM_FEED_MARKER} = 0 \
                 AND startsWith(namespace, '{PLATFORM_FEED_NAMESPACE}/')"
            ))
            .fetch_one::<u64>()
            .await?)
    }

    /// Delete every platform generation that is not active. Best effort:
    /// inactive rows are invisible to readers either way. Callers serialize
    /// installs, so no in-flight generation is deleted.
    pub async fn reclaim(&self) {
        let active = match self.active_keys().await {
            Ok(active) => active,
            Err(error) => {
                tracing::warn!(%error, "platform feed reclaim skipped: active generations unreadable");
                return;
            }
        };
        let keep: Vec<String> = active.into_values().filter(|k| !k.is_empty()).collect();
        let keep_list = if keep.is_empty() {
            "''".to_string()
        } else {
            keep.iter()
                .map(|k| crate::sql_hygiene::string_literal(k))
                .collect::<Vec<_>>()
                .join(", ")
        };
        for (table, column) in [(IP_TABLE, "source_id"), (IOC_TABLE, "namespace")] {
            let table = self.table(table);
            let sql = format!(
                "ALTER TABLE {table}{} DELETE WHERE {PLATFORM_FEED_MARKER} = 1 \
                 AND {column} NOT IN ({keep_list})",
                self.on_cluster
            );
            if let Err(error) = self.ch.query(&sql).execute().await {
                tracing::warn!(table = %table, %error, "could not reclaim superseded platform feed rows; they stay invisible");
            }
        }
    }

    /// Refresh the dictionary staging views and reload the dictionaries so a
    /// commit stamps new events now. On a cluster the refresh runs ON CLUSTER
    /// and the reload is issued only after EVERY replica reports the refresh
    /// finished after it was triggered (`clusterAllReplicas` over
    /// `system.view_refreshes`), so no node reloads the old staging data.
    /// Returns whether activation completed everywhere; `false` is a
    /// retryable state (the data still applies on the views' own cadence).
    pub async fn activate(&self, ip: bool, ioc: bool) -> bool {
        if self.database != "nanosiem" {
            // An isolated test database has no dictionaries of its own.
            return false;
        }
        let mut ok = true;
        for (wanted, view, is_ip) in [(ip, IP_DICT_REFRESH, true), (ioc, IOC_DICT_REFRESH, false)] {
            if !wanted {
                continue;
            }
            match tokio::time::timeout(ACTIVATION_TIMEOUT, self.activate_one(view, is_ip)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    ok = false;
                    tracing::warn!(view, error = %format!("{error:#}"), "platform feed dictionary activation incomplete; will retry");
                }
                Err(_) => {
                    ok = false;
                    tracing::warn!(view, "platform feed dictionary activation timed out; will retry");
                }
            }
        }
        ok
    }

    /// Refresh the staging view everywhere, then reload what reads it: the IP
    /// geo pair as one generation (NAN-4957, `enrichment::ip_geo::reload_pair`
    /// — never the old single `ip_enrichment_dict`, whose reload loads a
    /// 1.32 GiB trie), or the IOC dictionary.
    async fn activate_one(&self, view: &str, is_ip: bool) -> Result<()> {
        crate::enrichment::ip_geo::refresh_view_and_wait(&self.ch_admin, view, &self.on_cluster).await?;
        if is_ip {
            crate::enrichment::ip_geo::reload_pair(&self.ch_admin, &self.ch, &self.on_cluster).await?;
        } else {
            self.ch
                .query(&format!("SYSTEM RELOAD DICTIONARY{} {IOC_DICT}", self.on_cluster))
                .execute()
                .await?;
        }
        Ok(())
    }

    /// NAN-4957: reload the IP geo pair when the staging table changed after
    /// the trie loaded (the pair has no LIFETIME of its own). Leader tick.
    pub async fn reload_ip_geo_if_stale(&self) -> Result<bool> {
        if self.database != "nanosiem" {
            return Ok(false);
        }
        crate::enrichment::ip_geo::reload_if_stale(&self.ch_admin, &self.ch, &self.on_cluster).await
    }
}

/// Where refresh state is read: every replica on a cluster, else the node.
pub fn refresh_status_source(cluster: Option<&str>) -> String {
    match cluster.map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) => format!("clusterAllReplicas('{}', system.view_refreshes)", c.replace('\'', "")),
        None => "system.view_refreshes".to_string(),
    }
}

/// Per-view refresh progress since `?` (unix seconds): replicas that report
/// the view, how many finished a refresh after the trigger, and how many
/// failed one after it.
pub fn refresh_probe_sql(source: &str, db: &str, view: &str) -> String {
    format!(
        "SELECT count() AS replicas, \
                countIf(status != 'Running' AND last_success_time >= toDateTime(?)) AS done, \
                countIf(exception != '' AND last_refresh_time >= toDateTime(?)) AS failed, \
                any(exception) AS error \
         FROM {source} WHERE database = '{db}' AND view = '{view}'"
    )
}

#[cfg(test)]
#[path = "loader_tests.rs"]
mod tests;
