// SPDX-License-Identifier: AGPL-3.0-or-later
//! Installed platform feed bundle: PostgreSQL record and status contract
//! (NAN-4948).
//!
//! `platform_feed_state` (PG migration 305) is a singleton holding the LAST
//! GOOD install: the verified signed descriptor (the rollback reference for
//! the next install), what was loaded per feed, where it came from, and the
//! outcome of the latest check. A failed or refused check only updates the
//! `last_*` columns; the installed bundle and its ClickHouse generations stay.
//!
//! [`FeedsStatus`] is the JSON of `GET /api/enrichment/platform-feeds`. Its
//! fields up to `notice` are main's contract (NAN-4759, the marketplace
//! PlatformFeedsCard reads them); the rest are additive.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::BTreeMap;

/// Generation-key stem of every platform feed row (CH migration 184).
pub const PLATFORM_FEED_NAMESPACE: &str = "platform_feed";
/// Bare name of the commit-marker table (CH migration 184).
pub const PLATFORM_FEED_COMMITS_TABLE: &str = "platform_feed_commits";

/// Generation key of `feed` in the install with `sequence`.
pub fn storage_key(feed: &str, sequence: u64) -> String {
    format!("{PLATFORM_FEED_NAMESPACE}/{feed}/{sequence}")
}

/// Ownership marker column on `custom_enrichment_results` and
/// `ip_enrichments` (CH migration 184): 1 only on rows the platform feed
/// loader wrote. Every pre-existing or tenant-written row has the column
/// DEFAULT 0, so no name — not even a tenant namespace that happens to start
/// with `platform_feed/` — can make a row hidden or reclaimable (NAN-4948
/// review P1).
pub const PLATFORM_FEED_MARKER: &str = "platform_feed";

/// SQL predicate over `key_column` (`namespace` of
/// `custom_enrichment_results`, `source_id` of `ip_enrichments`): the row is
/// not a platform feed row (marker 0), or it belongs to its feed's active
/// (latest committed) generation. `commits_table` is the fully-qualified,
/// cluster-routed commits table.
pub fn visible_predicate(key_column: &str, commits_table: &str) -> String {
    format!(
        "({PLATFORM_FEED_MARKER} = 0 OR {key_column} GLOBAL IN \
         (SELECT argMax(storage_key, (sequence, committed_at)) FROM {commits_table} GROUP BY feed_id))"
    )
}

/// Bundle feeds whose rows go to `custom_enrichment_results` (the IOC feeds).
pub const IOC_BUNDLE_FEEDS: &[&str] = &["threatfox", "tor_exit_nodes"];

/// NAN-4959 (IOC parity): the row-level visibility predicate for
/// `custom_enrichment_results`, matching CH migration 187's IOC dictionary
/// refresh. On top of [`visible_predicate`] (`namespace` key), a legacy
/// MARKETPLACE IOC row (marker 0, `is_marketplace = 1`: a retired Deno
/// ThreatFox / Tor install or an air-gap IOC import) is visible only while the
/// bundle has never committed a ThreatFox or Tor generation. User custom
/// enrichments and IOC lists (`is_marketplace = 0`) are untouched.
pub fn ioc_visible_predicate(commits_table: &str) -> String {
    let feeds = IOC_BUNDLE_FEEDS.iter().map(|f| format!("'{f}'")).collect::<Vec<_>>().join(", ");
    format!(
        "(({PLATFORM_FEED_MARKER} = 0 AND (is_marketplace = 0 OR 'ioc' GLOBAL NOT IN \
         (SELECT 'ioc' FROM {commits_table} WHERE feed_id IN ({feeds}) AND storage_key != ''))) \
         OR ({PLATFORM_FEED_MARKER} = 1 AND namespace GLOBAL IN \
         (SELECT argMax(storage_key, (sequence, committed_at)) FROM {commits_table} GROUP BY feed_id)))"
    )
}

/// A feed produced longer ago than this is reported stale. It still stamps
/// until its `hard_expiry`.
pub const STALE_AFTER_DAYS: i64 = 7;

/// `source` of a bundle fetched from a distribution endpoint.
pub const SOURCE_ONLINE: &str = "online";
/// `source` of a bundle imported from a file (air-gap).
pub const SOURCE_OFFLINE: &str = "offline";

/// Freshness of one installed feed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = PlatformFeedState)]
pub enum FeedState {
    /// Stamping, produced within [`STALE_AFTER_DAYS`].
    Fresh,
    /// Still stamping, but older than [`STALE_AFTER_DAYS`]: update the bundle.
    Stale,
    /// Past `hard_expiry`: new events are no longer stamped from this feed.
    Expired,
}

/// Freshness of one feed at `now`.
pub fn feed_state(
    produced_at: Option<DateTime<Utc>>,
    hard_expiry: DateTime<Utc>,
    now: DateTime<Utc>,
) -> FeedState {
    if hard_expiry <= now {
        FeedState::Expired
    } else if produced_at.is_none_or(|at| now - at > Duration::days(STALE_AFTER_DAYS)) {
        FeedState::Stale
    } else {
        FeedState::Fresh
    }
}

/// Product name of a platform feed id.
pub fn feed_display_name(feed: &str) -> String {
    match feed {
        "ipinfo_lite" => "IPinfo Lite",
        "threatfox" => "ThreatFox",
        "tor_exit_nodes" => "Tor exit nodes",
        "urlhaus" => "URLhaus",
        "malwarebazaar" => "MalwareBazaar",
        other => other,
    }
    .to_string()
}

/// One installed feed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[schema(as = PlatformFeedStatus)]
pub struct FeedStatus {
    pub feed_id: String,
    pub name: String,
    pub revision: i64,
    pub produced_at: Option<DateTime<Utc>>,
    pub hard_expiry: DateTime<Utc>,
    pub age_seconds: Option<i64>,
    pub state: FeedState,
    pub license_id: Option<String>,
    pub terms_revision: Option<String>,
    /// Records the signed descriptor states for this feed.
    pub records: Option<u64>,
    /// NAN-4948: this feed currently stamps new events from the bundle (false
    /// when expired and withdrawn, or not loaded yet).
    #[serde(default)]
    pub active: bool,
    /// NAN-4948: rows loaded into ClickHouse for this feed.
    #[serde(default)]
    pub loaded: Option<u64>,
    /// NAN-4948: why the feed is not active, when it is not.
    #[serde(default)]
    pub detail: Option<String>,
}

/// Installed platform feed bundle and the latest check.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[schema(as = PlatformFeedsStatus)]
pub struct FeedsStatus {
    /// This deployment consumes the platform feed bundle.
    pub available: bool,
    /// A verified bundle is installed.
    pub installed: bool,
    /// SHA-256 of the installed NANPFB01 payload (the descriptor's
    /// `payload.sha256`).
    pub bundle_sha256: Option<String>,
    /// `online` (fetched) or `offline` (imported from a file).
    pub source: Option<String>,
    pub installed_at: Option<DateTime<Utc>>,
    pub stale_after_days: i64,
    pub feeds: Vec<FeedStatus>,
    /// Attribution that must be shown with the data (IPinfo CC BY-SA 4.0).
    pub notice: Option<String>,
    /// NAN-4948: the installed descriptor's sequence (strictly increasing).
    #[serde(default)]
    pub sequence: Option<u64>,
    /// NAN-4948: `open`, `sovereign` (license-authenticated), `mirror` (an
    /// operator-configured https URL) or `file`.
    #[serde(default)]
    pub channel: Option<String>,
    /// NAN-4948: the scheduled online check runs on this deployment (false in
    /// air-gap mode or when disabled; offline import still works).
    #[serde(default)]
    pub auto_update: bool,
    /// NAN-4948: when the latest check (scheduled, manual or import) ran.
    #[serde(default)]
    pub last_check_at: Option<DateTime<Utc>>,
    /// NAN-4948: `installed`, `current`, `checking`, `busy` (another install held
    /// the lock), `refused` or `failed`.
    #[serde(default)]
    pub last_check_status: Option<String>,
    /// NAN-4948: why the latest check did not install (the installed bundle
    /// is kept).
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_error_at: Option<DateTime<Utc>>,
    /// NAN-4948: the bundle is committed but some ClickHouse node has not yet
    /// rebuilt its dictionary from it; retried by the leader every few minutes.
    #[serde(default)]
    pub activation_pending: bool,
    /// NAN-4959: when the scheduled online check is next due (the latest check
    /// plus the poll interval, or the retry delay after a failed one). `None`
    /// when online updates are off (air-gap) or no check has run yet.
    #[serde(default)]
    pub next_check_at: Option<DateTime<Utc>>,
}

/// What an install loaded for one feed (`platform_feed_state.feeds`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FeedInstall {
    /// Rows written to ClickHouse (0 when not loaded).
    pub loaded: u64,
    /// The feed's generation is the committed, visible one.
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The `platform_feed_state` row.
#[derive(Clone, Debug, Default)]
pub struct StateRow {
    /// The verified signed descriptor, as stored JSON. Kept as JSON so this
    /// module (and the status endpoint) builds without the unix-only
    /// verifier; the consumer re-validates it before using it.
    pub signed_descriptor: Option<serde_json::Value>,
    pub sequence: Option<i64>,
    pub payload_sha256: Option<String>,
    pub container_sha256: Option<String>,
    pub source: Option<String>,
    pub channel: Option<String>,
    pub installed_at: Option<DateTime<Utc>>,
    pub feeds: BTreeMap<String, FeedInstall>,
    pub last_check_at: Option<DateTime<Utc>>,
    pub last_check_status: Option<String>,
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub activation_pending: bool,
}

#[derive(sqlx::FromRow)]
struct DbRow {
    signed_descriptor: Option<serde_json::Value>,
    sequence: Option<i64>,
    payload_sha256: Option<String>,
    container_sha256: Option<String>,
    source: Option<String>,
    channel: Option<String>,
    installed_at: Option<DateTime<Utc>>,
    feeds: serde_json::Value,
    last_check_at: Option<DateTime<Utc>>,
    last_check_status: Option<String>,
    last_error: Option<String>,
    last_error_at: Option<DateTime<Utc>>,
    activation_pending: bool,
}

/// The durable record of an install. It is written into EVERY ClickHouse
/// commit row of the install (the atomic commit point), so a crash or a
/// PostgreSQL failure after the commit is repaired from ClickHouse before the
/// next accept / expiry / reclaim decision; `platform_feed_state` is a cache
/// of the latest receipt (NAN-4948 review P1).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InstallReceipt {
    pub signed_descriptor: serde_json::Value,
    pub sequence: u64,
    pub payload_sha256: String,
    pub container_sha256: String,
    pub source: String,
    pub channel: String,
    pub installed_at: DateTime<Utc>,
    pub feeds: BTreeMap<String, FeedInstall>,
}

/// PostgreSQL access to `platform_feed_state`.
#[derive(Clone)]
pub struct StateRepository {
    pool: PgPool,
}

impl StateRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn get(&self) -> Result<Option<StateRow>, sqlx::Error> {
        let row = sqlx::query_as::<_, DbRow>(
            "SELECT signed_descriptor, sequence, payload_sha256, container_sha256, source, channel, \
                    installed_at, feeds, last_check_at, last_check_status, last_error, last_error_at, \
                    activation_pending \
             FROM platform_feed_state WHERE id = TRUE",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| StateRow {
            signed_descriptor: r.signed_descriptor,
            sequence: r.sequence,
            payload_sha256: r.payload_sha256,
            container_sha256: r.container_sha256,
            source: r.source,
            channel: r.channel,
            installed_at: r.installed_at,
            feeds: serde_json::from_value(r.feeds).unwrap_or_default(),
            last_check_at: r.last_check_at,
            last_check_status: r.last_check_status,
            last_error: r.last_error,
            last_error_at: r.last_error_at,
            activation_pending: r.activation_pending,
        }))
    }

    /// Store `receipt` as the installed bundle. `checked`: this is a new
    /// install by this process (marks the check `installed`, clears the last
    /// error); otherwise a repair from ClickHouse, which leaves the check
    /// fields alone.
    pub async fn record_install(&self, receipt: &InstallReceipt, checked: bool) -> Result<(), sqlx::Error> {
        let feeds = serde_json::to_value(&receipt.feeds).unwrap_or_default();
        sqlx::query(
            "INSERT INTO platform_feed_state (id, signed_descriptor, sequence, payload_sha256, container_sha256, \
                 source, channel, installed_at, feeds, last_check_at, last_check_status, updated_at) \
             VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, $8, CASE WHEN $9 THEN $7 END, CASE WHEN $9 THEN 'installed' END, NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
                 signed_descriptor = EXCLUDED.signed_descriptor, sequence = EXCLUDED.sequence, \
                 payload_sha256 = EXCLUDED.payload_sha256, container_sha256 = EXCLUDED.container_sha256, \
                 source = EXCLUDED.source, channel = EXCLUDED.channel, installed_at = EXCLUDED.installed_at, \
                 feeds = EXCLUDED.feeds, \
                 last_check_at = CASE WHEN $9 THEN EXCLUDED.installed_at ELSE platform_feed_state.last_check_at END, \
                 last_check_status = CASE WHEN $9 THEN 'installed' ELSE platform_feed_state.last_check_status END, \
                 last_error = CASE WHEN $9 THEN NULL ELSE platform_feed_state.last_error END, \
                 last_error_at = CASE WHEN $9 THEN NULL ELSE platform_feed_state.last_error_at END, \
                 updated_at = NOW()",
        )
        .bind(&receipt.signed_descriptor)
        .bind(receipt.sequence as i64)
        .bind(&receipt.payload_sha256)
        .bind(&receipt.container_sha256)
        .bind(&receipt.source)
        .bind(&receipt.channel)
        .bind(receipt.installed_at)
        .bind(feeds)
        .bind(checked)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Whether some ClickHouse node still has to rebuild its dictionaries
    /// from the committed generation.
    pub async fn set_activation_pending(&self, pending: bool) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE platform_feed_state SET activation_pending = $1, updated_at = NOW() WHERE id = TRUE")
            .bind(pending)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Record a check that did not install (`current`, `refused`, `failed`).
    /// The installed bundle is untouched. `error` replaces the last error;
    /// `None` keeps it for `current` (a later success clears it).
    pub async fn record_check(
        &self,
        status: &str,
        error: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO platform_feed_state (id, last_check_at, last_check_status, last_error, last_error_at, updated_at) \
             VALUES (TRUE, $1, $2, $3, CASE WHEN $3::text IS NULL THEN NULL ELSE $1 END, NOW()) \
             ON CONFLICT (id) DO UPDATE SET \
                 last_check_at = EXCLUDED.last_check_at, last_check_status = EXCLUDED.last_check_status, \
                 last_error = CASE WHEN $3::text IS NULL AND EXCLUDED.last_check_status = 'current' \
                     THEN NULL ELSE COALESCE($3, platform_feed_state.last_error) END, \
                 last_error_at = CASE WHEN $3::text IS NULL AND EXCLUDED.last_check_status = 'current' \
                     THEN NULL WHEN $3::text IS NULL THEN platform_feed_state.last_error_at ELSE $1 END, \
                 updated_at = NOW()",
        )
        .bind(now)
        .bind(status)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// Inputs of [`build_status`] that do not come from the stored row.
pub struct StatusContext {
    pub auto_update: bool,
    pub now: DateTime<Utc>,
}

/// Build the status from the stored row. The descriptor fields are read from
/// the stored (already verified) JSON; a row that does not parse reports
/// nothing installed rather than failing the endpoint.
pub fn build_status(row: Option<&StateRow>, ctx: &StatusContext) -> FeedsStatus {
    let mut status = FeedsStatus {
        available: true,
        installed: false,
        bundle_sha256: None,
        source: None,
        installed_at: None,
        stale_after_days: STALE_AFTER_DAYS,
        feeds: Vec::new(),
        notice: None,
        sequence: None,
        channel: None,
        auto_update: ctx.auto_update,
        last_check_at: None,
        last_check_status: None,
        last_error: None,
        last_error_at: None,
        activation_pending: false,
        next_check_at: None,
    };
    let Some(row) = row else { return status };
    status.activation_pending = row.activation_pending;
    status.last_check_at = row.last_check_at;
    status.last_check_status = row.last_check_status.clone();
    status.last_error = row.last_error.clone();
    status.last_error_at = row.last_error_at;
    let Some(descriptor) = row
        .signed_descriptor
        .as_ref()
        .and_then(|signed| signed.get("descriptor"))
    else {
        return status;
    };
    #[derive(Deserialize)]
    struct Entry {
        revision: i64,
        license_id: String,
        terms_revision: String,
        produced_at: DateTime<Utc>,
        hard_expiry: DateTime<Utc>,
        row_count: u64,
    }
    let feeds: BTreeMap<String, Entry> = descriptor
        .get("feeds")
        .cloned()
        .and_then(|f| serde_json::from_value(f).ok())
        .unwrap_or_default();
    status.installed = !feeds.is_empty();
    status.bundle_sha256 = row.payload_sha256.clone();
    status.source = row.source.clone();
    status.channel = row.channel.clone();
    status.installed_at = row.installed_at;
    status.sequence = row.sequence.map(|s| s as u64);
    status.notice = descriptor
        .get("notice")
        .and_then(|n| n.as_str())
        .map(str::to_string);
    status.feeds = feeds
        .into_iter()
        .map(|(feed_id, entry)| {
            let install = row.feeds.get(&feed_id).cloned().unwrap_or_default();
            let state = feed_state(Some(entry.produced_at), entry.hard_expiry, ctx.now);
            let active = install.active && state != FeedState::Expired;
            let detail = if active {
                None
            } else if state == FeedState::Expired {
                Some("Past its hard expiry: no longer stamps new events. Update the feed bundle.".to_string())
            } else {
                install.detail.clone()
            };
            FeedStatus {
                name: feed_display_name(&feed_id),
                feed_id,
                revision: entry.revision,
                produced_at: Some(entry.produced_at),
                hard_expiry: entry.hard_expiry,
                age_seconds: Some((ctx.now - entry.produced_at).num_seconds().max(0)),
                state,
                license_id: Some(entry.license_id),
                terms_revision: Some(entry.terms_revision),
                records: Some(entry.row_count),
                active,
                loaded: Some(install.loaded),
                detail,
            }
        })
        .collect();
    status
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
