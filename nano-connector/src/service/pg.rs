// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL feed store (migration `293_connector_feeds.sql`), single-tenant.
//!
//! A feed's vendor secret is a credential in the credentials store
//! (`cloud_credentials`), opened here at claim time with the deployment
//! cipher. The runner is a trusted system workflow: binding a credential to a
//! feed required `credentials:use` at the API, so the runner opens it with the
//! system grant. A rotated credential is picked up by the next run.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use nanosiem_core::auth::CredentialUseGrant;
use nanosiem_core::crypto::EncryptionService;
use nanosiem_core::parsers::CredentialRepository;
use serde::Serialize;
use serde_json::{Map, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::admin::{AdminError, FeedPlan, NewFeed};
use super::feed::{ClaimedFeed, FeedDefinition, RunRecord, RunStatus, Secret};
use super::store::{FeedStore, StoreError};
use crate::spec::ConnectorSpec;

/// Run records older than this are pruned when a run finishes.
const RUN_RETENTION_DAYS: i32 = 30;

fn db(e: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn admin_db(e: sqlx::Error) -> AdminError {
    if let sqlx::Error::Database(d) = &e {
        if d.constraint() == Some("connector_feeds_name_unique") {
            return AdminError::DuplicateName;
        }
        if d.code().as_deref() == Some("23503") {
            return AdminError::InvalidInput("the credential does not exist".into());
        }
    }
    AdminError::Backend(e.to_string())
}

/// A feed as an operator sees it. No secret material.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FeedSummary {
    pub id: Uuid,
    pub name: String,
    pub connector: String,
    pub source_type: String,
    pub spec_sha256: String,
    pub enabled: bool,
    pub schedule: Option<String>,
    pub config: Map<String, Value>,
    pub credential_id: Option<Uuid>,
    pub max_run_secs: Option<i32>,
    pub next_run_at: DateTime<Utc>,
    pub running: bool,
    pub consecutive_failures: i32,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    pub last_error: Option<String>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// One run as an operator sees it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RunSummary {
    pub id: Uuid,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub events: i64,
    pub pages: i32,
    pub error: Option<String>,
}

/// One stream checkpoint's metadata (never its contents, which can hold
/// vendor tokens).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CheckpointSummary {
    pub stream_id: String,
    pub kind: &'static str,
    pub commits: i64,
    pub updated_at: DateTime<Utc>,
}

const SUMMARY_COLUMNS: &str = "id, name, connector, source_type, spec_sha256, enabled, schedule, config, credential_id, \
     max_run_secs, next_run_at, (lease_expires_at IS NOT NULL AND lease_expires_at > now()) AS running, \
     consecutive_failures, last_run_at, last_status, last_error, last_success_at, created_at";

fn row_to_summary(r: &sqlx::postgres::PgRow) -> Result<FeedSummary, sqlx::Error> {
    let config: Value = r.try_get("config")?;
    Ok(FeedSummary {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        connector: r.try_get("connector")?,
        source_type: r.try_get("source_type")?,
        spec_sha256: r.try_get("spec_sha256")?,
        enabled: r.try_get("enabled")?,
        schedule: r.try_get("schedule")?,
        config: match config {
            Value::Object(m) => m,
            _ => Map::new(),
        },
        credential_id: r.try_get("credential_id")?,
        max_run_secs: r.try_get("max_run_secs")?,
        next_run_at: r.try_get("next_run_at")?,
        running: r.try_get("running")?,
        consecutive_failures: r.try_get("consecutive_failures")?,
        last_run_at: r.try_get("last_run_at")?,
        last_status: r.try_get("last_status")?,
        last_error: r.try_get("last_error")?,
        last_success_at: r.try_get("last_success_at")?,
        created_at: r.try_get("created_at")?,
    })
}

pub struct PgFeedStore {
    pool: PgPool,
    credentials: CredentialRepository,
}

impl PgFeedStore {
    pub fn new(pool: PgPool, cipher: EncryptionService) -> Self {
        Self { credentials: CredentialRepository::with_crypto(pool.clone(), cipher), pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The bound credential's fields the spec reads.
    async fn open_vendor(&self, feed_id: Uuid, spec_yaml: &str, credential_id: Option<Uuid>) -> Result<HashMap<String, Secret>, StoreError> {
        let feed_err = |message: String| StoreError::Feed { feed_id, message };
        let spec = ConnectorSpec::from_yaml(spec_yaml).map_err(|e| feed_err(format!("spec: {e}")))?;
        let Some(credential_id) = credential_id else {
            return super::admin::vendor_secrets(&spec, &Value::Object(Map::new())).map_err(feed_err);
        };
        CredentialUseGrant::system().ensure().map_err(|e| feed_err(e.to_string()))?;
        let payload = self
            .credentials
            .get_decrypted(credential_id)
            .await
            .map_err(|e| feed_err(format!("the bound credential could not be opened: {e}")))?;
        super::admin::vendor_secrets(&spec, &payload).map_err(feed_err)
    }

    // ------------------------------------------------------------- admin

    pub async fn create_feed(&self, plan: &FeedPlan, feed: &NewFeed, actor: Option<Uuid>) -> Result<Uuid, AdminError> {
        super::admin::check_inputs(plan, feed)?;
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO public.connector_feeds
                (name, connector, spec_yaml, spec_sha256, source_type, enabled, schedule, config,
                 credential_id, max_run_secs, next_run_at, created_by, updated_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now(), $11, $11)
             RETURNING id",
        )
        .bind(&feed.name)
        .bind(&plan.connector)
        .bind(&plan.spec_yaml)
        .bind(&plan.spec_sha256)
        .bind(&plan.source_type)
        .bind(feed.enabled)
        .bind(feed.schedule.as_deref())
        .bind(Value::Object(feed.config.clone()))
        .bind(feed.credential_id)
        .bind(feed.max_run_secs)
        .bind(actor)
        .fetch_one(&self.pool)
        .await
        .map_err(admin_db)?;
        Ok(id)
    }

    /// NAN-4931: explicit operator adoption of this build's bundled spec for
    /// one feed (no automatic re-pin: a spec change can alter cursors,
    /// external-id mapping or row semantics while keeping stream names).
    /// The feed must still fit the new spec ([`super::admin::repin_compatible`]).
    /// Adoption bumps the lease generation (a run in flight under the old
    /// spec cannot write or commit) and clears the feed's checkpoints so the
    /// next run starts fresh under the new contract; an identity stream keeps
    /// only its shrink-guard baseline. `Ok(None)` when the feed already runs
    /// the bundled spec.
    pub async fn adopt_bundled_spec(&self, id: Uuid, actor: Option<Uuid>) -> Result<Option<AdoptOutcome>, AdminError> {
        let mut tx = self.pool.begin().await.map_err(admin_db)?;
        let row = sqlx::query(
            "SELECT name, connector, spec_yaml, spec_sha256, config, credential_id, schedule, max_run_secs, enabled
               FROM public.connector_feeds WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(admin_db)?
        .ok_or(AdminError::FeedNotFound(id))?;
        let connector: String = row.try_get("connector").map_err(admin_db)?;
        let pinned_sha: String = row.try_get("spec_sha256").map_err(admin_db)?;
        let bundled = crate::first_party::get(&connector)?;
        let plan = super::admin::plan_from_spec(&connector, bundled.yaml)?;
        if plan.spec_sha256.eq_ignore_ascii_case(&pinned_sha) {
            return Ok(None);
        }
        let pinned_yaml: String = row.try_get("spec_yaml").map_err(admin_db)?;
        let config = match row.try_get::<Value, _>("config").map_err(admin_db)? {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let feed = super::admin::NewFeed {
            name: row.try_get("name").map_err(admin_db)?,
            config,
            credential_id: row.try_get("credential_id").map_err(admin_db)?,
            schedule: row.try_get("schedule").map_err(admin_db)?,
            max_run_secs: row.try_get("max_run_secs").map_err(admin_db)?,
            enabled: row.try_get("enabled").map_err(admin_db)?,
        };
        super::admin::repin_compatible(&pinned_yaml, &plan, &feed).map_err(AdminError::InvalidInput)?;
        sqlx::query(
            "UPDATE public.connector_feeds
                SET spec_yaml = $2, spec_sha256 = $3, source_type = $4,
                    lease_generation = lease_generation + 1, lease_owner = NULL, lease_expires_at = NULL,
                    next_run_at = now(), updated_by = $5, updated_at = now()
              WHERE id = $1",
        )
        .bind(id)
        .bind(&plan.spec_yaml)
        .bind(&plan.spec_sha256)
        .bind(&plan.source_type)
        .bind(actor)
        .execute(&mut *tx)
        .await
        .map_err(admin_db)?;
        // Fresh checkpoints under the new contract; an identity stream keeps
        // its last full-run count so the shrink guard still protects its
        // first run under the new spec.
        let cleared = sqlx::query(
            "UPDATE public.connector_feed_checkpoints
                SET state = CASE WHEN state ? $2 THEN jsonb_build_object($2, state -> $2) ELSE '{}'::jsonb END,
                    run_id = NULL, commits = commits + 1, updated_at = now()
              WHERE feed_id = $1",
        )
        .bind(id)
        .bind(crate::engine::IDENTITY_LAST_FULL_ROWS)
        .execute(&mut *tx)
        .await
        .map_err(admin_db)?
        .rows_affected();
        tx.commit().await.map_err(admin_db)?;
        Ok(Some(AdoptOutcome { previous_sha256: pinned_sha, spec_sha256: plan.spec_sha256, checkpoints_reset: cleared }))
    }

    pub async fn list_feeds(&self) -> Result<Vec<FeedSummary>, AdminError> {
        let rows = sqlx::query(&format!("SELECT {SUMMARY_COLUMNS} FROM public.connector_feeds ORDER BY name"))
            .fetch_all(&self.pool)
            .await
            .map_err(admin_db)?;
        rows.iter().map(row_to_summary).collect::<Result<_, _>>().map_err(admin_db)
    }

    pub async fn get_feed(&self, id: Uuid) -> Result<FeedSummary, AdminError> {
        let row = sqlx::query(&format!("SELECT {SUMMARY_COLUMNS} FROM public.connector_feeds WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(admin_db)?
            .ok_or(AdminError::FeedNotFound(id))?;
        row_to_summary(&row).map_err(admin_db)
    }

    /// Pause or resume. Either way the lease is cleared and the generation
    /// bumped, so a run in flight cannot commit a cursor or an outcome over
    /// the change; a resumed feed is due at once.
    pub async fn set_enabled(&self, id: Uuid, enabled: bool, actor: Option<Uuid>) -> Result<(), AdminError> {
        let n = sqlx::query(
            "UPDATE public.connector_feeds
                SET enabled = $2, lease_owner = NULL, lease_expires_at = NULL,
                    lease_generation = lease_generation + 1,
                    next_run_at = CASE WHEN $2 THEN now() ELSE next_run_at END,
                    consecutive_failures = CASE WHEN $2 THEN 0 ELSE consecutive_failures END,
                    updated_by = $3, updated_at = now()
              WHERE id = $1",
        )
        .bind(id)
        .bind(enabled)
        .bind(actor)
        .execute(&self.pool)
        .await
        .map_err(admin_db)?
        .rows_affected();
        if n == 0 {
            return Err(AdminError::FeedNotFound(id));
        }
        Ok(())
    }

    /// Remove a feed with its checkpoints and run records (cascade). A run in
    /// flight loses its lease on the next checkpoint write.
    pub async fn delete_feed(&self, id: Uuid) -> Result<(), AdminError> {
        let n = sqlx::query("DELETE FROM public.connector_feeds WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(admin_db)?
            .rows_affected();
        if n == 0 {
            return Err(AdminError::FeedNotFound(id));
        }
        Ok(())
    }

    pub async fn list_runs(&self, id: Uuid, limit: i64) -> Result<Vec<RunSummary>, AdminError> {
        let rows = sqlx::query(
            "SELECT id, status, started_at, finished_at, events, pages, error
               FROM public.connector_feed_runs WHERE feed_id = $1
              ORDER BY started_at DESC LIMIT $2",
        )
        .bind(id)
        .bind(limit.clamp(1, 200))
        .fetch_all(&self.pool)
        .await
        .map_err(admin_db)?;
        rows.iter()
            .map(|r| {
                Ok(RunSummary {
                    id: r.try_get("id")?,
                    status: r.try_get("status")?,
                    started_at: r.try_get("started_at")?,
                    finished_at: r.try_get("finished_at")?,
                    events: r.try_get("events")?,
                    pages: r.try_get("pages")?,
                    error: r.try_get("error")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(admin_db)
    }

    pub async fn list_checkpoints(&self, id: Uuid) -> Result<Vec<CheckpointSummary>, AdminError> {
        let rows = sqlx::query(
            "SELECT stream_id, state, commits, updated_at FROM public.connector_feed_checkpoints
              WHERE feed_id = $1 ORDER BY stream_id",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(admin_db)?;
        rows.iter()
            .map(|r| {
                let state: Value = r.try_get("state")?;
                Ok(CheckpointSummary {
                    stream_id: r.try_get("stream_id")?,
                    kind: super::reset::checkpoint_kind(Some(&state)),
                    commits: r.try_get("commits")?,
                    updated_at: r.try_get("updated_at")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(admin_db)
    }

    /// Re-anchor one time-window stream at now − 5 min (never earlier): see
    /// [`super::reset`]. The feed row is locked and its generation bumped in
    /// the same transaction, so a run in flight cannot commit over it.
    pub async fn reset_stream(&self, id: Uuid, stream: &str) -> Result<super::reset::ResetOutcome, AdminError> {
        let mut tx = self.pool.begin().await.map_err(admin_db)?;
        let outcome = super::reset::reset_stream_checkpoint(&mut tx, id, stream, Utc::now())
            .await
            .map_err(|e| match e {
                super::reset::ResetError::Database(e) => admin_db(e),
                other => AdminError::InvalidInput(other.to_string()),
            })?
            .ok_or(AdminError::FeedNotFound(id))?;
        tx.commit().await.map_err(admin_db)?;
        Ok(outcome)
    }
}

#[async_trait::async_trait]
impl FeedStore for PgFeedStore {
    async fn ingestion_paused(&self) -> bool {
        match sqlx::query_scalar::<_, bool>(
            "SELECT ingestion_paused FROM public.system_settings WHERE id = 'default'",
        )
        .fetch_optional(&self.pool)
        .await
        {
            Ok(paused) => paused.unwrap_or(false),
            Err(error) => {
                tracing::warn!(%error, "connector runner: ingestion pause state unreadable; not pausing");
                false
            }
        }
    }

    async fn claim_due(
        &self,
        node: &str,
        limit: usize,
        lease_secs: &(dyn Fn(Option<u64>) -> u64 + Send + Sync),
    ) -> Result<Vec<ClaimedFeed>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        // Pick due, unleased feeds without blocking on a row another runner
        // is claiming, then lease them (generation + 1).
        let due: Vec<(Uuid, Option<i32>)> = sqlx::query_as(
            "SELECT id, max_run_secs FROM public.connector_feeds
              WHERE enabled AND next_run_at <= now()
                AND (lease_expires_at IS NULL OR lease_expires_at < now())
              ORDER BY next_run_at, id
              LIMIT $1
              FOR UPDATE SKIP LOCKED",
        )
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let mut leased = Vec::with_capacity(due.len());
        for (id, max_run) in due {
            let lease = lease_secs(max_run.map(|v| v.max(1) as u64)) as f64;
            let row = sqlx::query(
                "UPDATE public.connector_feeds
                    SET lease_owner = $2, lease_generation = lease_generation + 1,
                        lease_expires_at = now() + make_interval(secs => $3),
                        last_run_at = now(), updated_at = now()
                  WHERE id = $1
                  RETURNING id, name, connector, spec_yaml, spec_sha256, source_type, schedule, config,
                            credential_id, max_run_secs, consecutive_failures, lease_generation,
                            now() AS claimed_at",
            )
            .bind(id)
            .bind(node)
            .bind(lease)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            let generation: i64 = row.try_get("lease_generation").map_err(db)?;
            let claimed_at: DateTime<Utc> = row.try_get("claimed_at").map_err(db)?;
            let run_id = Uuid::now_v7();
            let spec_sha: String = row.try_get("spec_sha256").map_err(db)?;
            sqlx::query(
                "INSERT INTO public.connector_feed_runs (id, feed_id, lease_generation, node, status, started_at, spec_sha256)
                 VALUES ($1, $2, $3, $4, 'running', $5, $6)",
            )
            .bind(run_id)
            .bind(id)
            .bind(generation)
            .bind(node)
            .bind(claimed_at)
            .bind(&spec_sha)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
            let config: Value = row.try_get("config").map_err(db)?;
            let max_run: Option<i32> = row.try_get("max_run_secs").map_err(db)?;
            let failures: i32 = row.try_get("consecutive_failures").map_err(db)?;
            leased.push(ClaimedFeed {
                feed: FeedDefinition {
                    feed_id: id,
                    name: row.try_get("name").map_err(db)?,
                    connector: row.try_get("connector").map_err(db)?,
                    spec_yaml: row.try_get("spec_yaml").map_err(db)?,
                    spec_sha256: spec_sha,
                    source_type: row.try_get("source_type").map_err(db)?,
                    schedule: row.try_get("schedule").map_err(db)?,
                    config: match config {
                        Value::Object(m) => m,
                        _ => Map::new(),
                    },
                    credential_id: row.try_get("credential_id").map_err(db)?,
                    vendor_credentials: HashMap::new(),
                    max_run_secs: max_run.map(|v| v.max(1) as u64),
                    consecutive_failures: failures.max(0) as u32,
                },
                lease_generation: generation,
                node: node.to_string(),
                run_id,
                claimed_at,
            });
        }
        tx.commit().await.map_err(db)?;

        // Open each claimed feed's credential outside the claim transaction
        // (decryption is CPU work, and a slow DB read must not hold row
        // locks). A feed whose credential cannot be opened is recorded as a
        // failed run and backed off an hour, not run with empty secrets.
        let mut out = Vec::with_capacity(leased.len());
        for mut claim in leased {
            match self.open_vendor(claim.feed.feed_id, &claim.feed.spec_yaml, claim.feed.credential_id).await {
                Ok(secrets) => {
                    claim.feed.vendor_credentials = secrets;
                    out.push(claim);
                }
                Err(e) => {
                    tracing::warn!(feed_id = %claim.feed.feed_id, error = %e, "connector feed credential unusable");
                    let mut rec = RunRecord::started(claim.claimed_at);
                    rec.status = RunStatus::Failed;
                    rec.finished_at = Utc::now();
                    rec.errors = 1;
                    rec.error = Some(e.to_string().chars().take(1000).collect());
                    rec.next_run_at = Utc::now() + chrono::Duration::hours(1);
                    if let Err(e) = self.finish(&claim, &rec).await {
                        tracing::warn!(feed_id = %claim.feed.feed_id, error = %e, "connector feed failure could not be recorded");
                    }
                }
            }
        }
        Ok(out)
    }

    async fn load_checkpoints(&self, claim: &ClaimedFeed) -> Result<HashMap<String, Value>, StoreError> {
        let rows: Vec<(String, Value)> =
            sqlx::query_as("SELECT stream_id, state FROM public.connector_feed_checkpoints WHERE feed_id = $1")
                .bind(claim.feed.feed_id)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?;
        Ok(rows.into_iter().collect())
    }

    async fn save_checkpoint(&self, claim: &ClaimedFeed, stream: &str, state: &Value) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        // FOR SHARE on the feed row serializes against a concurrent claim,
        // pause or reset (which take it FOR UPDATE / UPDATE), so the fence
        // cannot be raced.
        let holds: Option<i64> = sqlx::query_scalar(
            "SELECT lease_generation FROM public.connector_feeds
              WHERE id = $1 AND lease_generation = $2 AND lease_owner = $3
                AND lease_expires_at > now()
              FOR SHARE",
        )
        .bind(claim.feed.feed_id)
        .bind(claim.lease_generation)
        .bind(&claim.node)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if holds.is_none() {
            let _ = tx.rollback().await;
            return Err(StoreError::LeaseLost);
        }
        sqlx::query(
            "INSERT INTO public.connector_feed_checkpoints (feed_id, stream_id, state, lease_generation, run_id)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (feed_id, stream_id) DO UPDATE
                SET state = EXCLUDED.state, lease_generation = EXCLUDED.lease_generation,
                    run_id = EXCLUDED.run_id, commits = public.connector_feed_checkpoints.commits + 1,
                    updated_at = now()",
        )
        .bind(claim.feed.feed_id)
        .bind(stream)
        .bind(state)
        .bind(claim.lease_generation)
        .bind(claim.run_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }

    async fn finish(&self, claim: &ClaimedFeed, rec: &RunRecord) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let ok = rec.ok();
        let fed = sqlx::query(
            "UPDATE public.connector_feeds
                SET lease_owner = NULL, lease_expires_at = NULL, next_run_at = $4,
                    consecutive_failures = CASE WHEN $5 THEN 0 WHEN $9 THEN consecutive_failures ELSE LEAST(consecutive_failures + 1, 1000000) END,
                    last_status = $6, last_error = $7,
                    last_success_at = CASE WHEN $5 THEN $8 ELSE last_success_at END,
                    updated_at = now()
              WHERE id = $1 AND lease_generation = $2 AND lease_owner = $3",
        )
        .bind(claim.feed.feed_id)
        .bind(claim.lease_generation)
        .bind(&claim.node)
        .bind(rec.next_run_at)
        .bind(ok)
        .bind(rec.status.as_str())
        .bind(rec.error.as_deref())
        .bind(rec.finished_at)
        .bind(rec.deferred)
        .execute(&mut *tx)
        .await
        .map_err(db)?
        .rows_affected();
        let status = if fed == 0 { RunStatus::LeaseLost } else { rec.status };
        sqlx::query(
            "UPDATE public.connector_feed_runs
                SET status = $2, finished_at = $3, events = $4, bytes = $5, batches = $6, pages = $7,
                    requests = $8, ingest_retries = $9, rejected_events = $10, dropped_duplicates = $11,
                    checkpoints_committed = $12, errors = $13, error = $14, last_receipt = $15
              WHERE id = $1",
        )
        .bind(claim.run_id)
        .bind(status.as_str())
        .bind(rec.finished_at)
        .bind(rec.events as i64)
        .bind(rec.bytes as i64)
        .bind(rec.batches as i64)
        .bind(rec.pages as i32)
        .bind(rec.requests as i32)
        .bind(rec.ingest_retries as i64)
        .bind(rec.rejected_events as i64)
        .bind(rec.dropped_duplicates as i64)
        .bind(rec.checkpoints_committed as i64)
        .bind(rec.errors as i32)
        .bind(rec.error.as_deref())
        .bind(rec.last_receipt.as_deref().map(|r| r.chars().take(200).collect::<String>()))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        sqlx::query(
            "DELETE FROM public.connector_feed_runs
              WHERE feed_id = $1 AND started_at < now() - make_interval(days => $2)",
        )
        .bind(claim.feed.feed_id)
        .bind(RUN_RETENTION_DAYS)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        if fed == 0 && rec.status != RunStatus::LeaseLost {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }

    async fn fenced<'a>(&self, claim: &ClaimedFeed, op: crate::identity::FencedWrite<'a>) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(|e| format!("feed store: {e}"))?;
        // FOR SHARE on the feed row for the whole write: a pause, reset,
        // delete or re-pin (UPDATE / DELETE of the row) waits until it is
        // done, and runs after it see a bumped generation.
        let holds: Option<i64> = sqlx::query_scalar(
            "SELECT lease_generation FROM public.connector_feeds
              WHERE id = $1 AND lease_generation = $2 AND lease_owner = $3
                AND lease_expires_at > now()
              FOR SHARE",
        )
        .bind(claim.feed.feed_id)
        .bind(claim.lease_generation)
        .bind(&claim.node)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("feed store: {e}"))?;
        if holds.is_none() {
            let _ = tx.rollback().await;
            return Err(super::store::LEASE_LOST_WRITE.into());
        }
        let out = op.await;
        let _ = tx.commit().await;
        out
    }
}

/// The result of [`PgFeedStore::adopt_bundled_spec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptOutcome {
    pub previous_sha256: String,
    pub spec_sha256: String,
    pub checkpoints_reset: u64,
}
