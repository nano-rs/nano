// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log sources for a pull feed's lanes (NAN-5903).
//!
//! A pull feed delivers each event to the local Vector HEC listener under a
//! lane (`sourcetype`), such as `okta` or `gws_login`. A lane with no
//! enabled, deployed HEC log source drops its events, so a feed is refused
//! until every lane has one. Before this, an operator had to hand-create and
//! deploy each of them first (seven for a typical Google Workspace feed).
//!
//! Submitting the feed now sets them up:
//!
//! * A lane an enabled, deployed, active HEC source already claims is
//!   **reused**, whoever made it.
//! * Every other lane is claimed by ONE log source running the catalog
//!   parser that matches the connector (`google_workspace_ocsf` for every
//!   `gws_*` lane). One parser, one source: two enabled sources claiming one
//!   lane would double-write its events. In order of preference:
//!   1. the parser's catalog import, while it is *pristine*: exactly what the
//!      catalog ships (linked, the parser and its published version
//!      untouched, no extension, no sampling, explicit match values, active)
//!      and either on or never live;
//!   2. a pristine connector-owned pull source (`<connector>_pull`, or
//!      `<connector>_pull_2` ... when a name is taken) an earlier setup made;
//!   3. a fresh linked import, exactly as the parser-import UI makes it, when
//!      the parser has no import and its name is free;
//!   4. otherwise a NEW connector-owned pull source with the catalog parser,
//!      under the first free pull-source name, so a customized, forked or
//!      turned-off source of the operator's is never changed.
//!
//!   Its `match_values` grow to cover the lanes (additive only). A source
//!   that is not live yet gives up any value another enabled HEC source
//!   claims, so turning it on cannot collide.
//! * It is then deployed through the normal path, OCSF sample gate included
//!   (the gate runs the parser's bundled samples), and every lane is checked.
//!
//! The rules that shape it:
//!
//! * **Same permissions as by hand.** Importing a catalog parser needs
//!   `parser_repositories:import` plus what the import consumes
//!   (`log_sources:create`, and `source_configs:edit` when it binds a source
//!   configuration); creating a pull source needs `log_sources:create`;
//!   widening an existing source needs `log_sources:edit`; deploying needs
//!   `log_sources:deploy`. All are checked before the first write.
//! * **One setup at a time, without holding a connection.** Every start of a
//!   feed onto lanes (create, resume, adopt) runs under the setup *lease*
//!   ([`SetupLease`]): a row in `connector_feed_setup_leases`, claimed
//!   atomically, renewed while a long deploy runs and released when the
//!   start is done (or expired if its holder dies). The whole sequence (plan,
//!   writes, deploy, check, rollback, starting the feed) runs under it, so a
//!   second start never sees a half-done setup: it waits briefly, then gets
//!   409 "try again shortly".
//! * **Never destructive.** Nothing is deleted on failure. A source made
//!   before a failed deploy stays (disabled, as a failed first deploy leaves
//!   it) and the next submit picks it up; lanes added to a live source are
//!   taken back off. What was created is always reported, so the caller
//!   audits it even on failure.
//! * **Never shadows an operator's source.** A lane an enabled HEC source
//!   claims but cannot serve (not deployed, not active) is refused with the
//!   source's name rather than claimed a second time, and names are checked
//!   against Vector's generated identifiers, so a clash is a clear 409.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{permissions, TargetEffect, TargetGrants};
use crate::log_sources::{ingest_transport, LogSource, LogSourceRepository};
use crate::parser_repository::{
    ParserImportRequest, ParserImportType, ParserRepositoryError, ParserRepositoryService,
};
use crate::vector_naming::safe_name;

/// The ingestion method of a pull feed's lane source: the connector runner
/// delivers to Vector's HEC listener.
pub const PULL_FEED_TRANSPORT: &str = "splunk_hec";

/// The one lease every pull-feed start onto lanes takes.
const LEASE_KEY: &str = "pull_feed_lane_setup";

/// How long a lease lives without renewal (a dead holder's lease lapses).
const LEASE_TTL_SECS: i64 = 600;

/// How often a held lease is renewed.
const LEASE_RENEW_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// How many pull-source names (`_pull`, `_pull_2` ... ) setup tries.
const PULL_NAME_TRIES: usize = 9;

/// The connector-owned source's name: `google_workspace_pull`, then
/// `google_workspace_pull_2` ... (`attempt` from 1).
pub fn owned_source_name(connector: &str, attempt: usize) -> String {
    if attempt <= 1 {
        format!("{connector}_pull")
    } else {
        format!("{connector}_pull_{attempt}")
    }
}

/// Whether `transport` is the HEC transport a pull feed delivers on.
pub fn is_hec_transport(transport: &str) -> bool {
    ingest_transport::canonical(transport) == Some(PULL_FEED_TRANSPORT)
}

/// Whether a log source is a HEC parser claiming `lane`, exactly as Vector
/// routes it: its `match_values`, or with none the Vector-safe form of its
/// name (`vector_naming::claim_keys`, the key the router and the collision
/// check use).
pub fn hec_source_claims(transport: &str, name: &str, values: Option<&[String]>, lane: &str) -> bool {
    is_hec_transport(transport) && crate::vector_naming::claim_keys(values, name).iter().any(|s| s == lane)
}

fn claims(source: &LogSource, lane: &str) -> bool {
    source.kind == "log" && hec_source_claims(&source.source_type, &source.name, source.match_values.as_deref(), lane)
}

/// Whether `source` serves `lane` now: an enabled, deployed, active HEC
/// parser claiming it.
pub fn serves(source: &LogSource, lane: &str) -> bool {
    claims(source, lane) && source.enabled && source.deployed && source.lifecycle_status == "active"
}

/// What setup does to one log source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LaneSourceAction {
    /// Already serves its lanes; nothing changes.
    Reuse,
    /// A new log source running the catalog parser.
    Create,
    /// An existing source made to cover more lanes (and redeployed).
    Extend,
    /// An existing source covering the lanes, deployed (turned on).
    TurnOn,
}

/// What kind of source setup uses for the missing lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LaneSourceOrigin {
    /// The parser's linked catalog import (made by a parser import).
    CatalogImport,
    /// A connector-owned pull source (`<connector>_pull`), a plain log source
    /// running the catalog parser.
    PullSource,
}

/// One log source a feed's lanes use, and what setup does to it.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct LaneSourceStep {
    pub action: LaneSourceAction,
    /// `None` only for a source that does not exist yet (a plan's `create`).
    #[serde(with = "crate::typeid::log_source::opt")]
    #[schema(value_type = Option<String>)]
    pub log_source_id: Option<Uuid>,
    pub log_source_name: String,
    /// The feed's lanes this source serves.
    pub lanes: Vec<String>,
    /// The lanes setup adds to it (`create` / `extend`).
    pub added_lanes: Vec<String>,
    /// The catalog parser it comes from (`google_workspace_ocsf`), for a
    /// source setup creates or changes.
    pub parser: Option<String>,
    /// For a source setup creates or changes: a catalog import or a pull
    /// source. `None` for a reused one.
    pub origin: Option<LaneSourceOrigin>,
}

/// The catalog parser a connector's missing lanes are set up from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogParser {
    pub repository_id: Uuid,
    pub path: String,
    pub name: String,
    pub display_name: String,
    /// The parser's VRL as the catalog ships it.
    pub parser_vrl: String,
}

/// The connector a feed runs.
#[derive(Debug, Clone, Copy)]
pub struct FeedConnector<'a> {
    /// `google_workspace`
    pub slug: &'a str,
    /// For messages ("Google Workspace audit").
    pub display: &'a str,
    /// Catalog parser names, in preference order.
    pub parsers: &'a [&'a str],
}

/// What submitting a feed would do to its lanes' log sources. Read only.
#[derive(Debug, Clone)]
pub struct LaneSetupPlan {
    pub steps: Vec<LaneSourceStep>,
    /// Permissions THIS plan needs beyond starting the feed: what the same
    /// change takes by hand. Empty when every lane is already served.
    pub required_permissions: Vec<&'static str>,
    target: Option<Target>,
}

#[derive(Debug, Clone)]
enum TargetKind {
    /// A fresh linked catalog import.
    Import { effects: Vec<TargetEffect> },
    /// A new connector-owned pull source under this name.
    CreateOwned { name: String },
    /// An existing pristine source (the catalog import or a pull source).
    Existing(Box<LogSource>, LaneSourceOrigin),
}

#[derive(Debug, Clone)]
struct Target {
    parser: CatalogParser,
    kind: TargetKind,
    /// Lanes the target must newly claim.
    add_lanes: Vec<String>,
    /// Values an existing, not-live target gives up because another enabled
    /// HEC source claims them.
    withhold: Vec<String>,
}

impl LaneSetupPlan {
    /// Whether submitting changes anything (creates, extends or deploys).
    pub fn changes_anything(&self) -> bool {
        self.target.is_some()
    }

    /// How many log sources setup would create (0 or 1).
    pub fn creates(&self) -> usize {
        self.steps.iter().filter(|s| s.action == LaneSourceAction::Create).count()
    }
}

/// Why setup refused or failed. Every message is plain English for the
/// person submitting the feed.
#[derive(Debug, thiserror::Error)]
pub enum LaneSetupError {
    /// The connector names no catalog parser.
    #[error("nano has no parser for {connector} events yet, so it cannot set up log sources for {lanes}. Set them up under Log sources first.")]
    NoParserForConnector { connector: String, lanes: String },
    /// The connector's parser is not in the synced parser catalog.
    #[error("nano could not find the {connector} parser ({parser}) in your parser catalog, so it cannot set up log sources for {lanes}. Sync the nano-rs/parsers catalog under Settings, Parser repositories, then try again.")]
    ParserNotInCatalog { connector: String, parser: String, lanes: String },
    /// An enabled HEC source claims a lane but cannot serve it.
    #[error("The log source \"{source_name}\" already takes {lane} events, but it is {why}. Fix it under Log sources, or turn it off, then try again.")]
    LaneHeldByAnotherSource { lane: String, source_name: String, why: &'static str },
    /// Every name setup could give its source is taken.
    #[error("nano could not name a new log source for these events: \"{name}\" and the names after it are taken (\"{holder}\" uses the same name in Vector). Rename that log source under Log sources, then try again.")]
    NameTaken { name: String, holder: String },
    /// The caller lacks a permission setup needs.
    #[error("Setting up the log sources this feed needs also takes the {} permission{}. Ask an admin to give you {}, or to set up these log sources under Log sources first.", .missing.join(", "), if .missing.len() == 1 { "" } else { "s" }, if .missing.len() == 1 { "it" } else { "them" })]
    NotPermitted { missing: Vec<&'static str> },
    /// The data-source tier cap.
    #[error("{0}")]
    TierLimit(String),
    /// Another feed's setup holds the lease.
    #[error("nano is setting up log sources for another pull feed right now. Try again shortly.")]
    Busy,
    /// This setup's lease lapsed and was taken over (it stalled longer than
    /// the lease); it stopped before changing anything more.
    #[error("nano stopped setting up log sources for this feed because the setup took too long and another one started. Nothing more was changed. Try again.")]
    LeaseLost,
    /// A source was set up but did not go live.
    #[error("nano set up the log source \"{source_name}\" but could not turn it on: {message}. The feed was not started. Fix the problem and try again; nano reuses what it already set up.")]
    DeployFailed { source_name: String, message: String },
    #[error("Could not set up the log sources: {0}")]
    Internal(String),
}

impl LaneSetupError {
    /// HTTP status class: 403 for a missing permission or a plan limit,
    /// 409 for a lane or name another source holds or a held lease, 500 for
    /// an internal fault, everything else 400.
    pub fn is_forbidden(&self) -> bool {
        matches!(self, Self::NotPermitted { .. } | Self::TierLimit(_))
    }
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::LaneHeldByAnotherSource { .. } | Self::NameTaken { .. } | Self::Busy | Self::LeaseLost)
    }
    pub fn is_internal(&self) -> bool {
        matches!(self, Self::Internal(_))
    }
}

impl From<ParserRepositoryError> for LaneSetupError {
    fn from(e: ParserRepositoryError) -> Self {
        match e {
            ParserRepositoryError::TierLimitExceeded(m) => Self::TierLimit(m),
            ParserRepositoryError::Forbidden(p) => Self::NotPermitted { missing: vec![permission_name(&p)] },
            other => Self::Internal(other.to_string()),
        }
    }
}

impl From<crate::log_sources::LogSourceRepositoryError> for LaneSetupError {
    fn from(e: crate::log_sources::LogSourceRepositoryError) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<sqlx::Error> for LaneSetupError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(e.to_string())
    }
}

fn permission_name(p: &str) -> &'static str {
    [
        permissions::LOG_SOURCES_CREATE,
        permissions::LOG_SOURCES_EDIT,
        permissions::LOG_SOURCES_DEPLOY,
        permissions::SOURCE_CONFIGS_EDIT,
        permissions::PARSER_REPOSITORIES_IMPORT,
    ]
    .into_iter()
    .find(|k| *k == p)
    .unwrap_or("log_sources:create")
}

/// Deploys one log source through the normal path (OCSF gate included).
/// The API implements it; tests fake it.
#[async_trait::async_trait]
pub trait LaneSourceDeployer: Send + Sync {
    /// `Err` carries a plain reason ("the OCSF check failed: ...").
    async fn deploy(&self, log_source_id: Uuid) -> Result<(), String>;
}

/// What a setup run did. Filled in as it goes, so a failure still reports
/// the sources it created or changed (they stay, and must be audited).
#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct LaneSetupOutcome {
    pub steps: Vec<LaneSourceStep>,
    /// The identity routing rule the catalog import added to a source
    /// configuration, if any (audited as its own resource).
    #[serde(skip)]
    pub routing_rule_id: Option<Uuid>,
    /// Lane values a not-yet-live source gave up because another enabled
    /// HEC source already claims them (they would be parsed twice).
    pub withheld_values: Vec<String>,
    /// Whether this run deployed a source.
    pub deployed: bool,
}

impl LaneSetupOutcome {
    /// The sources this run created.
    pub fn created(&self) -> impl Iterator<Item = &LaneSourceStep> {
        self.steps.iter().filter(|s| s.action == LaneSourceAction::Create)
    }
}

/// The setup lease: a row in `connector_feed_setup_leases`, claimed with
/// one atomic statement (insert, or take over an expired row), renewed by a
/// background task while held and deleted on release. No database
/// connection is held while it is held.
///
/// **Fenced.** Every claim bumps the row's `generation`; the holder's
/// `(owner, generation)` is its fencing token. [`SetupLease::ensure_held`]
/// is checked before each step, and every write setup makes is conditioned
/// on the token still holding an unexpired lease, so a holder whose lease
/// lapsed and was taken over (a stall longer than the lease) can change
/// nothing more. The renewal task notices a lost lease and stops.
///
/// Dropping it without a completed [`SetupLease::release`] (including a
/// release cancelled mid-way) deletes the row in the background; expiry is
/// the backstop.
pub struct SetupLease {
    pool: PgPool,
    owner: Uuid,
    generation: i64,
    lost: std::sync::Arc<std::sync::atomic::AtomicBool>,
    renew: Option<tokio::task::JoinHandle<()>>,
    released: bool,
}

impl SetupLease {
    /// Claim the lease, retrying every half second for up to `wait`;
    /// [`LaneSetupError::Busy`] after that.
    pub async fn acquire(pool: &PgPool, purpose: &str, wait: std::time::Duration) -> Result<Self, LaneSetupError> {
        let owner = Uuid::new_v4();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(generation) = Self::try_claim(pool, owner, purpose).await? {
                let lost = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let (renew_pool, renew_lost) = (pool.clone(), lost.clone());
                let renew = tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(LEASE_RENEW_EVERY).await;
                        let renewed = sqlx::query(
                            "UPDATE connector_feed_setup_leases SET expires_at = now() + make_interval(secs => $4) \
                             WHERE key = $1 AND owner = $2 AND generation = $3 AND expires_at > now()",
                        )
                        .bind(LEASE_KEY)
                        .bind(owner)
                        .bind(generation)
                        .bind(LEASE_TTL_SECS as f64)
                        .execute(&renew_pool)
                        .await;
                        match renewed {
                            Ok(r) if r.rows_affected() == 0 => {
                                tracing::warn!("the pull feed setup lease lapsed and was lost; this setup stops");
                                renew_lost.store(true, std::sync::atomic::Ordering::SeqCst);
                                return;
                            }
                            Ok(_) => {}
                            Err(e) => tracing::warn!(error = %e, "could not renew the pull feed setup lease"),
                        }
                    }
                });
                return Ok(Self { pool: pool.clone(), owner, generation, lost, renew: Some(renew), released: false });
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(LaneSetupError::Busy);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    /// The claimed generation, or `None` when another holder has it.
    async fn try_claim(pool: &PgPool, owner: Uuid, purpose: &str) -> Result<Option<i64>, LaneSetupError> {
        let row: Option<(Uuid, i64)> = sqlx::query_as(
            "INSERT INTO connector_feed_setup_leases (key, owner, purpose, expires_at, generation) \
             VALUES ($1, $2, $3, now() + make_interval(secs => $4), 1) \
             ON CONFLICT (key) DO UPDATE SET owner = EXCLUDED.owner, purpose = EXCLUDED.purpose, \
               expires_at = EXCLUDED.expires_at, claimed_at = now(), \
               generation = connector_feed_setup_leases.generation + 1 \
             WHERE connector_feed_setup_leases.expires_at < now() \
             RETURNING owner, generation",
        )
        .bind(LEASE_KEY)
        .bind(owner)
        .bind(purpose)
        .bind(LEASE_TTL_SECS as f64)
        .fetch_optional(pool)
        .await?;
        Ok(row.and_then(|(o, g)| (o == owner).then_some(g)))
    }

    /// Fail with [`LaneSetupError::LeaseLost`] unless this holder still holds
    /// an unexpired lease. Checked before every step.
    pub async fn ensure_held(&self) -> Result<(), LaneSetupError> {
        if self.lost.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(LaneSetupError::LeaseLost);
        }
        let held: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM connector_feed_setup_leases l WHERE l.key = $1 AND l.owner = $2 \
             AND l.generation = $3 AND l.expires_at > now())",
        )
            .bind(LEASE_KEY)
            .bind(self.owner)
            .bind(self.generation)
            .fetch_one(&self.pool)
            .await?;
        if held {
            Ok(())
        } else {
            self.lost.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(LaneSetupError::LeaseLost)
        }
    }

    /// Bind this holder's fencing token as the next three parameters of a
    /// fenced statement (`l.key`, `l.owner`, `l.generation`).
    fn bind_fence<'q>(
        &self,
        query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
        query.bind(LEASE_KEY).bind(self.owner).bind(self.generation)
    }

    /// Release the lease (only if still ours). Best effort: if it fails or is
    /// cancelled, the drop guard and then expiry release it.
    pub async fn release(mut self) {
        if let Some(renew) = self.renew.take() {
            renew.abort();
        }
        match Self::delete(&self.pool, self.owner, self.generation).await {
            Ok(()) => self.released = true,
            Err(e) => tracing::warn!(error = %e, "could not release the pull feed setup lease; it lapses on its own"),
        }
    }

    async fn delete(pool: &PgPool, owner: Uuid, generation: i64) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM connector_feed_setup_leases WHERE key = $1 AND owner = $2 AND generation = $3")
            .bind(LEASE_KEY)
            .bind(owner)
            .bind(generation)
            .execute(pool)
            .await
            .map(|_| ())
    }
}

impl Drop for SetupLease {
    fn drop(&mut self) {
        if let Some(renew) = self.renew.take() {
            renew.abort();
        }
        if !self.released {
            let (pool, owner, generation) = (self.pool.clone(), self.owner, self.generation);
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = Self::delete(&pool, owner, generation).await;
                });
            }
        }
    }
}

/// Lane setup for pull feeds.
pub struct FeedLaneSetup<'a> {
    pool: &'a PgPool,
    parsers: &'a ParserRepositoryService,
    log_sources: LogSourceRepository,
}

impl<'a> FeedLaneSetup<'a> {
    pub fn new(pool: &'a PgPool, parsers: &'a ParserRepositoryService) -> Self {
        Self { pool, parsers, log_sources: LogSourceRepository::new(pool.clone()) }
    }

    /// Find the first of `names` (catalog parser names, in preference order)
    /// in an enabled first-party parser catalog.
    pub async fn find_catalog_parser(&self, names: &[&str]) -> Result<Option<CatalogParser>, LaneSetupError> {
        let repos: Vec<Uuid> = self
            .parsers
            .list_repositories()
            .await?
            .into_iter()
            .filter(|r| r.enabled)
            .map(|r| r.id)
            .collect();
        if repos.is_empty() {
            return Ok(None);
        }
        for name in names {
            type CatalogRow = (Uuid, String, Option<String>, Option<String>, Option<String>);
            let row: Option<CatalogRow> = sqlx::query_as(
                "SELECT repository_id, file_path, name, display_name, parser_vrl FROM repository_parsers \
                 WHERE repository_id = ANY($1) AND kind = 'parser' AND lower(name) = lower($2) \
                 ORDER BY updated_at DESC LIMIT 1",
            )
            .bind(&repos)
            .bind(name)
            .fetch_optional(self.pool)
            .await?;
            if let Some((repository_id, path, parser_name, display_name, parser_vrl)) = row {
                let name = parser_name.unwrap_or_else(|| (*name).to_string());
                return Ok(Some(CatalogParser {
                    repository_id,
                    path,
                    display_name: display_name.unwrap_or_else(|| name.clone()),
                    name,
                    parser_vrl: parser_vrl.unwrap_or_default(),
                }));
            }
        }
        Ok(None)
    }

    /// Whether `source` may be used as-is: exactly what the catalog ships
    /// (linked when imported, working copy AND published version running the
    /// catalog parser with no extension, no sampling, explicit match values,
    /// a pull-feed HEC log source, active) and either on, or never live (a
    /// fresh or failed setup). Anything else, including a source the operator
    /// undeployed or turned off after it went live, is theirs and is left
    /// alone.
    async fn pristine(&self, source: &LogSource, parser: &CatalogParser, import_type: Option<&str>) -> Result<bool, LaneSetupError> {
        let shape = import_type.is_none_or(|t| t.eq_ignore_ascii_case("linked"))
            && source.kind == "log"
            && is_hec_transport(&source.source_type)
            && source.lifecycle_status == "active"
            && source.parser_vrl.trim() == parser.parser_vrl.trim()
            && !source.extension_enabled
            && source.sampling_ratio.is_none_or(|r| r >= 1.0)
            && source.sampling_exclude_condition.as_deref().is_none_or(|c| c.trim().is_empty())
            && source.match_values.as_deref().is_some_and(|v| !v.is_empty());
        if !shape {
            return Ok(false);
        }
        // Off: usable only if it was NEVER live (a fresh or failed setup).
        // An operator's undeploy clears `deployed_at`, so "ever live" is read
        // from what undeploy keeps: `first_deployed_at` (migration 399) and,
        // for sources older than it, a successful deploy in the history.
        if !source.enabled {
            let ever_live: bool = sqlx::query_scalar(
                "SELECT first_deployed_at IS NOT NULL OR EXISTS ( \
                   SELECT 1 FROM log_source_deployments d \
                   WHERE d.log_source_id = ls.id AND d.action = 'deploy' AND d.status = 'success') \
                 FROM log_sources ls WHERE ls.id = $1",
            )
            .bind(source.id)
            .fetch_optional(self.pool)
            .await?
            .unwrap_or(true);
            if ever_live {
                return Ok(false);
            }
        }
        // Vector deploys the ACTIVE published version, not the working copy.
        let active: Option<(String, bool)> = sqlx::query_as(
            "SELECT parser_vrl, extension_enabled FROM log_source_versions \
             WHERE log_source_id = $1 AND is_active = TRUE ORDER BY version_number DESC, id DESC LIMIT 1",
        )
        .bind(source.id)
        .fetch_optional(self.pool)
        .await?;
        Ok(active.is_none_or(|(vrl, ext)| vrl.trim() == parser.parser_vrl.trim() && !ext))
    }

    /// The pull source for the missing lanes: the first pristine one an
    /// earlier setup made, or the first free pull-source name (by Vector's
    /// generated identifier) for a new one.
    async fn pull_source(
        &self,
        connector: FeedConnector<'_>,
        parser: &CatalogParser,
        sources: &[LogSource],
    ) -> Result<TargetKind, LaneSetupError> {
        let mut first_free: Option<String> = None;
        let mut last_holder = String::new();
        for attempt in 1..=PULL_NAME_TRIES {
            let name = owned_source_name(connector.slug, attempt);
            let id = safe_name(&name);
            match sources.iter().find(|s| safe_name(&s.name) == id) {
                Some(s) if s.name == name && self.pristine(s, parser, None).await? => {
                    return Ok(TargetKind::Existing(Box::new(s.clone()), LaneSourceOrigin::PullSource));
                }
                Some(s) => last_holder = s.name.clone(),
                None => {
                    if first_free.is_none() {
                        first_free = Some(name);
                    }
                }
            }
        }
        match first_free {
            Some(name) => Ok(TargetKind::CreateOwned { name }),
            None => Err(LaneSetupError::NameTaken { name: owned_source_name(connector.slug, 1), holder: last_holder }),
        }
    }

    /// What submitting a feed with `lanes` would do. Read only; refusals
    /// that need no write (no parser, a lane or every name held by another
    /// source) come back as `Err`.
    pub async fn plan(&self, connector: FeedConnector<'_>, lanes: &BTreeSet<String>) -> Result<LaneSetupPlan, LaneSetupError> {
        let sources = self.log_sources.list(&Default::default()).await?;
        self.plan_with(connector, lanes, &sources).await
    }

    async fn plan_with(
        &self,
        connector: FeedConnector<'_>,
        lanes: &BTreeSet<String>,
        sources: &[LogSource],
    ) -> Result<LaneSetupPlan, LaneSetupError> {
        // Lanes already served, grouped by the source serving them.
        let mut served: BTreeMap<Uuid, (String, Vec<String>)> = BTreeMap::new();
        let mut missing = Vec::new();
        for lane in lanes {
            if let Some(s) = sources.iter().find(|s| serves(s, lane)) {
                served.entry(s.id).or_insert_with(|| (s.name.clone(), Vec::new())).1.push(lane.clone());
            } else {
                missing.push(lane.clone());
            }
        }
        let mut steps: Vec<LaneSourceStep> = served
            .into_iter()
            .map(|(id, (name, lanes))| LaneSourceStep {
                action: LaneSourceAction::Reuse,
                log_source_id: Some(id),
                log_source_name: name,
                lanes,
                added_lanes: Vec::new(),
                parser: None,
                origin: None,
            })
            .collect();
        if missing.is_empty() {
            return Ok(LaneSetupPlan { steps, required_permissions: Vec::new(), target: None });
        }
        let lane_list = || missing.iter().map(|l| format!("`{l}`")).collect::<Vec<_>>().join(", ");
        if connector.parsers.is_empty() {
            return Err(LaneSetupError::NoParserForConnector { connector: connector.display.to_string(), lanes: lane_list() });
        }
        let Some(parser) = self.find_catalog_parser(connector.parsers).await? else {
            return Err(LaneSetupError::ParserNotInCatalog {
                connector: connector.display.to_string(),
                parser: connector.parsers[0].to_string(),
                lanes: lane_list(),
            });
        };

        // Which source takes the missing lanes (module docs, in order).
        let preview = self.parsers.preview_import(parser.repository_id, &parser.path).await?;
        let import = match preview.existing_log_source_id {
            Some(id) if preview.already_imported => sources.iter().find(|s| s.id == id),
            _ => None,
        };
        let import_free = !preview.already_imported
            && !sources.iter().any(|s| safe_name(&s.name) == safe_name(&preview.proposed_name));
        let kind = match import {
            Some(i) if self.pristine(i, &parser, preview.existing_import_type.as_deref()).await? => {
                TargetKind::Existing(Box::new(i.clone()), LaneSourceOrigin::CatalogImport)
            }
            _ => match self.pull_source(connector, &parser, sources).await? {
                existing @ TargetKind::Existing(..) => existing,
                // No import yet and its name is free: import, as by hand.
                TargetKind::CreateOwned { .. } if import_free => TargetKind::Import {
                    effects: self
                        .parsers
                        .plan_import(parser.repository_id, &parser.path, &import_request())
                        .await?
                        .required_effects(),
                },
                create => create,
            },
        };
        let target_id = match &kind {
            TargetKind::Existing(e, _) => Some(e.id),
            _ => None,
        };

        // A missing lane another ENABLED HEC source claims would be claimed
        // twice: refuse and name it.
        for lane in &missing {
            if let Some(other) =
                sources.iter().find(|s| s.enabled && claims(s, lane) && Some(s.id) != target_id)
            {
                let why = if other.lifecycle_status != "active" { "still a draft" } else { "not deployed" };
                return Err(LaneSetupError::LaneHeldByAnotherSource { lane: lane.clone(), source_name: other.name.clone(), why });
            }
        }

        let mut required: Vec<&'static str> = Vec::new();
        let (action, id, name, add_lanes, withhold, origin) = match &kind {
            TargetKind::Existing(e, origin) => {
                let have = e.match_values.clone().unwrap_or_default();
                let add: Vec<String> = missing.iter().filter(|l| !have.contains(l)).cloned().collect();
                // A source that is not live yet gives up values another
                // enabled HEC source claims, so turning it on cannot collide.
                let withhold: Vec<String> = if e.enabled {
                    Vec::new()
                } else {
                    have.iter()
                        .filter(|v| sources.iter().any(|s| s.id != e.id && s.enabled && claims(s, v)))
                        .cloned()
                        .collect()
                };
                if !add.is_empty() || !withhold.is_empty() {
                    required.push(permissions::LOG_SOURCES_EDIT);
                }
                let action = if add.is_empty() { LaneSourceAction::TurnOn } else { LaneSourceAction::Extend };
                (action, Some(e.id), e.name.clone(), add, withhold, *origin)
            }
            TargetKind::CreateOwned { name } => {
                required.push(permissions::LOG_SOURCES_CREATE);
                (LaneSourceAction::Create, None, name.clone(), missing.clone(), Vec::new(), LaneSourceOrigin::PullSource)
            }
            TargetKind::Import { effects } => {
                required.push(permissions::PARSER_REPOSITORIES_IMPORT);
                required.extend(effects.iter().map(|e| e.permission()));
                (
                    LaneSourceAction::Create,
                    None,
                    preview.proposed_name.clone(),
                    missing.clone(),
                    Vec::new(),
                    LaneSourceOrigin::CatalogImport,
                )
            }
        };
        required.push(permissions::LOG_SOURCES_DEPLOY);
        let mut seen = BTreeSet::new();
        required.retain(|p| seen.insert(*p));
        steps.push(LaneSourceStep {
            action,
            log_source_id: id,
            log_source_name: name,
            lanes: missing.clone(),
            added_lanes: add_lanes.clone(),
            parser: Some(parser.name.clone()),
            origin: Some(origin),
        });
        Ok(LaneSetupPlan {
            steps,
            required_permissions: required,
            target: Some(Target { parser, kind, add_lanes, withhold }),
        })
    }

    /// Set up the log sources `lanes` need: plan, writes, deploy, check and
    /// (on a failed deploy) rollback, all under the caller's [`SetupLease`],
    /// which the caller keeps until it has started the feed.
    ///
    /// `has` answers whether the caller holds a permission (checked before
    /// any write); `grants` are the caller's target grants, re-checked at the
    /// writes themselves. Returns what was done; on `Err` the outcome still
    /// lists what was created or changed before the failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_up(
        &self,
        lease: &SetupLease,
        connector: FeedConnector<'_>,
        lanes: &BTreeSet<String>,
        has: &(dyn Fn(&str) -> bool + Send + Sync),
        grants: &TargetGrants,
        user_id: Option<Uuid>,
        deployer: &dyn LaneSourceDeployer,
    ) -> (LaneSetupOutcome, Result<(), LaneSetupError>) {
        let mut outcome = LaneSetupOutcome::default();
        if let Err(e) = lease.ensure_held().await {
            return (outcome, Err(e));
        }
        let result = match self.write(lease, connector, lanes, has, grants, user_id, &mut outcome).await {
            Ok(Some(w)) => self.deploy_and_verify(lease, lanes, w, deployer, &mut outcome).await,
            Ok(None) => Ok(()),
            Err(e) => Err(e),
        };
        (outcome, result)
    }

    /// The writes, each fenced on the lease. `None`: nothing to do.
    #[allow(clippy::too_many_arguments)]
    async fn write(
        &self,
        lease: &SetupLease,
        connector: FeedConnector<'_>,
        lanes: &BTreeSet<String>,
        has: &(dyn Fn(&str) -> bool + Send + Sync),
        grants: &TargetGrants,
        user_id: Option<Uuid>,
        outcome: &mut LaneSetupOutcome,
    ) -> Result<Option<Written>, LaneSetupError> {
        let sources = self.log_sources.list(&Default::default()).await?;
        let plan = self.plan_with(connector, lanes, &sources).await?;
        let missing: Vec<&'static str> = plan.required_permissions.iter().copied().filter(|p| !has(p)).collect();
        if !missing.is_empty() {
            return Err(LaneSetupError::NotPermitted { missing });
        }
        outcome.steps = plan.steps.iter().filter(|s| s.action == LaneSourceAction::Reuse).cloned().collect();
        let Some(target) = plan.target else {
            return Ok(None);
        };
        let step = plan.steps.iter().find(|s| s.action != LaneSourceAction::Reuse).cloned().expect("a target has a step");
        let ensure = |effect: TargetEffect| {
            grants.ensure(effect).map_err(|e| LaneSetupError::NotPermitted { missing: vec![e.permission()] })
        };

        match &target.kind {
            TargetKind::Existing(existing, _) => {
                if !target.add_lanes.is_empty() || !target.withhold.is_empty() {
                    ensure(TargetEffect::LogSourceEdit)?;
                    // One statement: drop the withheld values, then append the
                    // new lanes not already there (order kept, primary first).
                    let update = sqlx::query(
                        "UPDATE log_sources SET match_values = \
                           ARRAY(SELECT v FROM unnest(COALESCE(match_values, ARRAY[]::TEXT[])) WITH ORDINALITY AS t(v, i) \
                                 WHERE NOT (v = ANY($3)) ORDER BY i) \
                           || ARRAY(SELECT n FROM unnest($2::TEXT[]) WITH ORDINALITY AS a(n, i) \
                                 WHERE NOT (n = ANY(COALESCE(match_values, ARRAY[]::TEXT[]))) ORDER BY i), \
                         updated_at = NOW() WHERE id = $1 AND EXISTS (SELECT 1 FROM connector_feed_setup_leases l WHERE l.key = $4 AND l.owner = $5 AND l.generation = $6 AND l.expires_at > now())",
                    )
                    .bind(existing.id)
                    .bind(&target.add_lanes)
                    .bind(&target.withhold);
                    if lease.bind_fence(update).execute(self.pool).await?.rows_affected() == 0 {
                        return Err(LaneSetupError::LeaseLost);
                    }
                    outcome.withheld_values = target.withhold.clone();
                }
                outcome.steps.push(step);
                Ok(Some(Written {
                    id: existing.id,
                    name: existing.name.clone(),
                    rollback_lanes: if existing.enabled { target.add_lanes.clone() } else { Vec::new() },
                }))
            }
            TargetKind::CreateOwned { name } => {
                ensure(TargetEffect::LogSourceCreate)?;
                lease.ensure_held().await?;
                crate::log_sources::enforce_data_source_limit(self.pool).await.map_err(|e| LaneSetupError::TierLimit(e.to_string()))?;
                let created = self
                    .log_sources
                    .create(&crate::log_sources::NewLogSource {
                        name: name.clone(),
                        description: Some(format!(
                            "Pull feed log source for {} with the {} parser, made by pull feed setup so an existing source of that parser stays as it is.",
                            connector.display, target.parser.name
                        )),
                        namespace: "default".into(),
                        timezone: "UTC".into(),
                        source_type: PULL_FEED_TRANSPORT.into(),
                        parser_vrl: target.parser.parser_vrl.clone(),
                        output_fields: None,
                        dispatch_source_config_id: None,
                        category: None,
                        vendor: None,
                        product: None,
                        icon: None,
                        color: None,
                        match_field: None,
                        match_pattern: None,
                        match_values: Some(target.add_lanes.clone()),
                        sampling_ratio: None,
                        sampling_exclude_condition: None,
                        lifecycle_status: None,
                    })
                    .await
                    .map_err(|e| name_taken_or(e.to_string(), name))?;
                outcome.steps.push(LaneSourceStep { log_source_id: Some(created.id), log_source_name: name.clone(), ..step });
                Ok(Some(Written { id: created.id, name: name.clone(), rollback_lanes: Vec::new() }))
            }
            TargetKind::Import { effects } => {
                for effect in effects {
                    ensure(*effect)?;
                }
                lease.ensure_held().await?;
                let imported = self
                    .parsers
                    .import_parser(target.parser.repository_id, &target.parser.path, &import_request(), user_id, grants)
                    .await
                    .map_err(|e| match e {
                        ParserRepositoryError::LogSourceService(m) | ParserRepositoryError::Internal(m) => {
                            name_taken_or(m, &step.log_source_name)
                        }
                        other => other.into(),
                    })?;
                outcome.routing_rule_id = imported.routing_rule_id;
                outcome.steps.push(LaneSourceStep {
                    log_source_id: Some(imported.log_source_id),
                    log_source_name: imported.log_source_name.clone(),
                    ..step
                });
                // The import claims the parser's own `match_values`. Keep the
                // ones no other enabled HEC source claims, then add the lanes.
                let fresh = self.log_sources.find_by_id(imported.log_source_id).await?;
                let mut values: Vec<String> = Vec::new();
                for v in crate::vector_naming::claim_keys(fresh.match_values.as_deref(), &fresh.name) {
                    if values.contains(&v) {
                        continue;
                    }
                    if sources.iter().any(|s| s.id != fresh.id && s.enabled && claims(s, &v)) {
                        outcome.withheld_values.push(v);
                    } else {
                        values.push(v);
                    }
                }
                for lane in &target.add_lanes {
                    if !values.contains(lane) {
                        values.push(lane.clone());
                    }
                }
                let update = sqlx::query(
                    "UPDATE log_sources SET match_values = $2, updated_at = NOW() WHERE id = $1 \
                     AND EXISTS (SELECT 1 FROM connector_feed_setup_leases l WHERE l.key = $3 AND l.owner = $4 AND l.generation = $5 AND l.expires_at > now())",
                )
                .bind(fresh.id)
                .bind(&values);
                if lease.bind_fence(update).execute(self.pool).await?.rows_affected() == 0 {
                    return Err(LaneSetupError::LeaseLost);
                }
                Ok(Some(Written { id: imported.log_source_id, name: imported.log_source_name, rollback_lanes: Vec::new() }))
            }
        }
    }

    /// Deploy the target, then check every lane.
    async fn deploy_and_verify(
        &self,
        lease: &SetupLease,
        lanes: &BTreeSet<String>,
        w: Written,
        deployer: &dyn LaneSourceDeployer,
        outcome: &mut LaneSetupOutcome,
    ) -> Result<(), LaneSetupError> {
        lease.ensure_held().await?;
        if let Err(message) = deployer.deploy(w.id).await {
            // A source that was already on keeps routing its old values
            // through a failed redeploy; the lanes just added must come back
            // off, or they would be rendered by the next unrelated deploy (or
            // read as served while it is `deployed`). The source is then as it
            // was, and a retry adds them again. Under the lease, so no other
            // setup added the same lanes meanwhile.
            // Fenced: a holder whose lease lapsed never strips lanes a newer
            // setup may have deployed meanwhile.
            if !w.rollback_lanes.is_empty() {
                let rollback = sqlx::query(
                    "UPDATE log_sources SET match_values = ARRAY(SELECT v FROM unnest(match_values) WITH ORDINALITY AS t(v, i) \
                     WHERE NOT (v = ANY($2)) ORDER BY i), updated_at = NOW() WHERE id = $1 \
                     AND EXISTS (SELECT 1 FROM connector_feed_setup_leases l WHERE l.key = $3 AND l.owner = $4 AND l.generation = $5 AND l.expires_at > now())",
                )
                .bind(w.id)
                .bind(&w.rollback_lanes);
                match lease.bind_fence(rollback).execute(self.pool).await {
                    Ok(r) if r.rows_affected() == 0 => {
                        tracing::warn!(log_source_id = %w.id, "lease lost: lanes added before a failed deploy were left for the setup that holds it")
                    }
                    Ok(_) => outcome.steps.retain(|s| !(s.log_source_id == Some(w.id) && s.action == LaneSourceAction::Extend)),
                    Err(e) => tracing::error!(log_source_id = %w.id, error = %e, "could not take back lanes added before a failed deploy"),
                }
            }
            return Err(LaneSetupError::DeployFailed { source_name: w.name, message });
        }
        outcome.deployed = true;
        // The feed is started only when every lane is served now.
        let after = self.log_sources.list(&Default::default()).await?;
        if let Some(lane) = lanes.iter().find(|l| !after.iter().any(|s| serves(s, l))) {
            return Err(LaneSetupError::DeployFailed {
                source_name: w.name,
                message: format!("it still does not take `{lane}` events after the deploy"),
            });
        }
        Ok(())
    }
}

/// A name clash at the write (a source appeared since the plan) is a 409
/// naming it, never a 500.
fn name_taken_or(message: String, name: &str) -> LaneSetupError {
    let lower = message.to_ascii_lowercase();
    if lower.contains("already exists")
        || lower.contains("duplicate")
        || lower.contains("generated_vector_identity")
        || lower.contains("unique")
    {
        LaneSetupError::NameTaken { name: name.to_string(), holder: name.to_string() }
    } else {
        LaneSetupError::Internal(message)
    }
}

/// What the writes produced, for the deploy.
struct Written {
    id: Uuid,
    name: String,
    /// Lanes to take back off if the deploy fails (added to a source that
    /// was already on).
    rollback_lanes: Vec<String>,
}

fn import_request() -> ParserImportRequest {
    ParserImportRequest {
        // Linked: an upstream parser fix reaches this source like any import.
        import_type: ParserImportType::Linked,
        // The parser's own primary match value stays first.
        source_type: None,
        ingestion_method: Some(PULL_FEED_TRANSPORT.to_string()),
        dispatch_source_config_id: None,
    }
}

#[cfg(test)]
#[path = "feed_lane_setup_tests.rs"]
mod tests;
