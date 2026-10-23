//! Postgres feed store (migrations `339` / `9012400_connector_feeds.sql`,
//! credential issuance columns `340` / `9012510`).
//!
//! Tenancy mirrors the lean runners (`custom_enrichment_shared_runtime`):
//! - [`Tenancy::Shared`] (the hosted shared deployment mode): the tenant
//!   inventory is the provisioned detection worker-assignment ledger for this
//!   process's worker identity (`TenantDetectionWorkerDiscovery`), never a
//!   global scan, and every statement runs in a signed tenant transaction
//!   acting as the tenant's worker service member. The connector tables are
//!   FORCE RLS, so a statement can only ever touch that tenant's rows.
//! - [`Tenancy::Dedicated`] (dedicated / self-hosted): one deployment, the
//!   plain pool, tenants = those with an enabled feed.
//!
//! Secrets (vendor credentials, the ingest token) are sealed with the
//! deployment cipher (`NANOSIEM_ENCRYPTION_KEY`, the marketplace
//! `credentials_encrypted` + `credentials_nonce` shape) and opened only here.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use nanosiem_core::crypto::EncryptionService;
#[cfg(feature = "enterprise")]
use nanosiem_core::enterprise_shared_security::TenantDetectionWorkerDiscovery;
use nanosiem_core::tenant_db::TenantDbContextSigner;
use serde_json::{Map, Value};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[cfg(feature = "enterprise")]
use super::credential::{REVEAL_KEY_ALG, RevealKey};
use super::feed::{ClaimedFeed, FeedDefinition, RunRecord, RunStatus, Secret, TenantSlot};
use super::store::{CredentialPass, FeedStore, PendingDelete, StoreError, delete_backoff};

/// Tenants enumerated per poll at most (the detection runtimes' bound).
#[cfg(feature = "enterprise")]
const MAX_TENANTS: i64 = 1_024;
/// Run records older than this are pruned when a run finishes.
const RUN_RETENTION_DAYS: i32 = 30;

pub enum Tenancy {
    #[cfg(feature = "enterprise")]
    Shared {
        pool: PgPool,
        signer: Arc<TenantDbContextSigner>,
        discovery: Arc<TenantDetectionWorkerDiscovery>,
        worker_identity: String,
    },
    /// Signed tenant transactions for a fixed tenant set (a runner pinned
    /// to known tenants, e.g. one hosted collector runner per tenant; tests).
    SignedStatic {
        pool: PgPool,
        signer: Arc<TenantDbContextSigner>,
        tenants: Vec<TenantSlot>,
    },
    Dedicated {
        pool: PgPool,
    },
}

pub struct PgFeedStore {
    tenancy: Tenancy,
    cipher: EncryptionService,
    /// `connector_feeds.sink` exists (migration 350 / 9013180). A runner
    /// started before the migration runs in legacy mode: every feed is a
    /// HEC feed and identity feeds are disabled ([`Self::probe_schema`]).
    sink_column: bool,
    /// The pending delete columns exist (migration 352 / 9013220). Before
    /// them no uninstalled feed can exist, and none is claimed.
    delete_columns: bool,
}

/// `connector_feeds.sink`: where a feed's rows go (migration 350 / 9013180).
pub const SINK_HEC: &str = "hec";
pub const SINK_IDENTITY: &str = "identity";

/// A recorded delete error, within the column's 2048-byte bound.
fn truncate_error(message: &str) -> String {
    let mut end = message.len().min(2000);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_string()
}

fn db(e: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(e.to_string())
}

impl PgFeedStore {
    pub fn new(tenancy: Tenancy, cipher: EncryptionService) -> Self {
        Self { tenancy, cipher, sink_column: true, delete_columns: true }
    }

    fn pool(&self) -> &PgPool {
        match &self.tenancy {
            #[cfg(feature = "enterprise")]
            Tenancy::Shared { pool, .. } => pool,
            Tenancy::SignedStatic { pool, .. } | Tenancy::Dedicated { pool } => pool,
        }
    }

    /// Check for `connector_feeds.sink` at startup. Missing (the runner
    /// rolled before migration 350 / 9013180): legacy mode, where no query
    /// names the column, every feed is a HEC feed and identity feeds cannot
    /// be created. Migrate first, then roll the runner.
    pub async fn probe_schema(mut self) -> Result<Self, String> {
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns
                             WHERE table_schema = 'public' AND table_name = 'connector_feeds' AND column_name = 'sink')",
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| format!("connector_feeds schema probe failed: {e}"))?;
        if !present {
            tracing::warn!(
                "connector_feeds.sink is missing (migration 350 / 9013180 not applied): legacy mode, identity feeds disabled; apply the migration and restart the runner"
            );
        }
        self.sink_column = present;
        let deletes: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns
                             WHERE table_schema = 'public' AND table_name = 'connector_feeds' AND column_name = 'delete_requested_at')",
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| format!("connector_feeds schema probe failed: {e}"))?;
        if !deletes {
            tracing::warn!("connector_feeds pending delete columns are missing (migration 352 / 9013220 not applied): uninstalled feeds are not processed");
        }
        self.delete_columns = deletes;
        Ok(self)
    }

    /// Whether identity feeds can run (the sink column exists).
    pub fn identity_enabled(&self) -> bool {
        self.sink_column
    }

    /// The feed's sink as a select expression.
    fn sink_sql(&self) -> &'static str {
        if self.sink_column { "sink" } else { "'hec'::text AS sink" }
    }

    async fn begin(&self, slot: &TenantSlot) -> Result<Transaction<'_, Postgres>, StoreError> {
        match &self.tenancy {
            #[cfg(feature = "enterprise")]
            Tenancy::Shared { pool, signer, .. } => {
                signer.begin_transaction(pool, slot.tenant_id, slot.actor_id).await.map_err(db)
            }
            Tenancy::SignedStatic { pool, signer, .. } => {
                signer.begin_transaction(pool, slot.tenant_id, slot.actor_id).await.map_err(db)
            }
            Tenancy::Dedicated { pool } => pool.begin().await.map_err(db),
        }
    }

    fn open(&self, feed_id: Uuid, ct: Option<Vec<u8>>, nonce: Option<String>) -> Result<HashMap<String, Secret>, StoreError> {
        let (Some(ct), Some(nonce)) = (ct, nonce) else {
            return Ok(HashMap::new());
        };
        self.cipher
            .decrypt_credentials_bytea(&ct, &nonce)
            .map(|m| m.into_iter().map(|(k, v)| (k, Secret::new(v))).collect())
            .map_err(|e| StoreError::Feed { feed_id, message: format!("credentials could not be opened: {e}") })
    }

    /// Seal a credential map the way this store opens it (bytes, nonce).
    pub fn seal(cipher: &EncryptionService, values: &HashMap<String, String>) -> Result<(Vec<u8>, String), String> {
        use base64::Engine;
        let sealed = cipher.encrypt_json(values).map_err(|e| e.to_string())?;
        let ct = base64::engine::general_purpose::STANDARD.decode(sealed.ciphertext).map_err(|e| e.to_string())?;
        Ok((ct, sealed.nonce))
    }

    fn row_to_feed(&self, tenant_id: Uuid, r: &sqlx::postgres::PgRow) -> Result<FeedDefinition, StoreError> {
        let feed_id: Uuid = r.try_get("id").map_err(db)?;
        let config: Value = r.try_get("config").map_err(db)?;
        let vendor = self.open(feed_id, r.try_get("vendor_credentials_encrypted").map_err(db)?, r.try_get("vendor_credentials_nonce").map_err(db)?)?;
        // Identity feeds (`sink = 'identity'`) have no ingest credential.
        let identity = r.try_get::<String, _>("sink").map_err(db)? == SINK_IDENTITY;
        let ingest_token = if identity {
            Secret::new("")
        } else {
            let ingest = self.open(feed_id, Some(r.try_get("ingest_token_encrypted").map_err(db)?), Some(r.try_get("ingest_token_nonce").map_err(db)?))?;
            ingest
                .get("token")
                .cloned()
                .ok_or_else(|| StoreError::Feed { feed_id, message: "sealed ingest credential has no `token`".into() })?
        };
        let max_run: Option<i32> = r.try_get("max_run_secs").map_err(db)?;
        let failures: i32 = r.try_get("consecutive_failures").map_err(db)?;
        Ok(FeedDefinition {
            tenant_id,
            feed_id,
            name: r.try_get("name").map_err(db)?,
            connector: r.try_get("connector").map_err(db)?,
            spec_yaml: r.try_get("spec_yaml").map_err(db)?,
            spec_sha256: r.try_get("spec_sha256").map_err(db)?,
            source_slug: r.try_get("source_slug").map_err(db)?,
            schedule: r.try_get("schedule").map_err(db)?,
            config: match config {
                Value::Object(m) => m,
                _ => Map::new(),
            },
            vendor_credentials: vendor,
            ingest_url: r.try_get::<Option<String>, _>("ingest_url").map_err(db)?.unwrap_or_default(),
            ingest_token,
            max_run_secs: max_run.map(|v| v.max(1) as u64),
            consecutive_failures: failures.max(0) as u32,
        })
    }
}

/// The tenants a tenancy serves: shared = the worker-assignment ledger for
/// this identity, signed-static = its fixed set, dedicated = tenants with an
/// enabled feed.
async fn tenant_slots(tenancy: &Tenancy, pending_deletes: bool) -> Result<Vec<TenantSlot>, StoreError> {
    match tenancy {
        #[cfg(feature = "enterprise")]
        Tenancy::Shared { discovery, worker_identity, .. } => {
            let rows = discovery
                .enumerate_provisioned_detection_workers(worker_identity, MAX_TENANTS + 1)
                .await
                .map_err(db)?;
            if rows.len() as i64 > MAX_TENANTS {
                return Err(StoreError::Backend(format!("more than {MAX_TENANTS} tenants assigned to this worker identity")));
            }
            Ok(rows.into_iter().map(|r| TenantSlot { tenant_id: r.tenant_id, actor_id: r.worker_actor_id }).collect())
        }
        Tenancy::SignedStatic { tenants, .. } => Ok(tenants.clone()),
        Tenancy::Dedicated { pool } => {
            // A tenant whose only feed is uninstalled still needs its delete.
            let sql = if pending_deletes {
                "SELECT DISTINCT tenant_id FROM public.connector_feeds WHERE enabled OR delete_requested_at IS NOT NULL ORDER BY tenant_id"
            } else {
                "SELECT DISTINCT tenant_id FROM public.connector_feeds WHERE enabled ORDER BY tenant_id"
            };
            let ids: Vec<Uuid> = sqlx::query_scalar(sql)
                .fetch_all(pool)
                .await
                .map_err(db)?;
            Ok(ids.into_iter().map(|tenant_id| TenantSlot { tenant_id, actor_id: Uuid::nil() }).collect())
        }
    }
}

#[async_trait::async_trait]
impl FeedStore for PgFeedStore {
    async fn tenants(&self) -> Result<Vec<TenantSlot>, StoreError> {
        tenant_slots(&self.tenancy, self.delete_columns).await
    }

    async fn claim_due(
        &self,
        slot: &TenantSlot,
        node: &str,
        limit: usize,
        lease_secs: &(dyn Fn(Option<u64>) -> u64 + Send + Sync),
    ) -> Result<Vec<ClaimedFeed>, StoreError> {
        let mut tx = self.begin(slot).await?;
        // Pick due, unleased feeds without blocking on a row another runner
        // is claiming, then lease them (generation + 1).
        let identity = if self.sink_column { " OR sink = 'identity'" } else { "" };
        let due: Vec<(Uuid, Option<i32>)> = sqlx::query_as(&format!(
            "SELECT id, max_run_secs FROM public.connector_feeds
              WHERE tenant_id = $1 AND enabled AND next_run_at <= now()
                AND (ingest_token_encrypted IS NOT NULL{identity})
                AND (lease_expires_at IS NULL OR lease_expires_at < now())
              ORDER BY next_run_at, id
              LIMIT $2
              FOR UPDATE SKIP LOCKED",
        ))
        .bind(slot.tenant_id)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let mut out = Vec::with_capacity(due.len());
        for (id, max_run) in due {
            let lease = lease_secs(max_run.map(|v| v.max(1) as u64)) as f64;
            let row = sqlx::query(&format!(
                "UPDATE public.connector_feeds
                    SET lease_owner = $3, lease_generation = lease_generation + 1,
                        lease_expires_at = now() + make_interval(secs => $4),
                        last_run_at = now(), updated_at = now()
                  WHERE tenant_id = $1 AND id = $2
                  RETURNING id, name, connector, spec_yaml, spec_sha256, source_slug, schedule, config,
                            vendor_credentials_encrypted, vendor_credentials_nonce, ingest_url,
                            ingest_token_encrypted, ingest_token_nonce, max_run_secs,
                            consecutive_failures, lease_generation, {}, now() AS claimed_at",
                self.sink_sql()
            ))
            .bind(slot.tenant_id)
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
                "INSERT INTO public.connector_feed_runs (tenant_id, id, feed_id, lease_generation, node, status, started_at, spec_sha256)
                 VALUES ($1, $2, $3, $4, $5, 'running', $6, $7)",
            )
            .bind(slot.tenant_id)
            .bind(run_id)
            .bind(id)
            .bind(generation)
            .bind(node)
            .bind(claimed_at)
            .bind(&spec_sha)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
            // A feed whose secrets cannot be opened is still claimed (so its
            // failure is recorded and backed off), with empty secrets.
            let feed = match self.row_to_feed(slot.tenant_id, &row) {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(tenant_id = %slot.tenant_id, feed_id = %id, error = %e, "connector feed definition unusable");
                    sqlx::query(
                        "UPDATE public.connector_feeds SET lease_owner = NULL, lease_expires_at = NULL,
                                next_run_at = now() + interval '1 hour', consecutive_failures = consecutive_failures + 1,
                                last_status = 'failed', last_error = $3
                          WHERE tenant_id = $1 AND id = $2",
                    )
                    .bind(slot.tenant_id)
                    .bind(id)
                    .bind(e.to_string().chars().take(1000).collect::<String>())
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
                    sqlx::query("UPDATE public.connector_feed_runs SET status = 'failed', finished_at = now(), errors = 1, error = $3 WHERE tenant_id = $1 AND id = $2")
                        .bind(slot.tenant_id)
                        .bind(run_id)
                        .bind(e.to_string().chars().take(1000).collect::<String>())
                        .execute(&mut *tx)
                        .await
                        .map_err(db)?;
                    continue;
                }
            };
            out.push(ClaimedFeed { slot: *slot, feed, lease_generation: generation, node: node.to_string(), run_id, claimed_at });
        }
        tx.commit().await.map_err(db)?;
        Ok(out)
    }

    async fn load_checkpoints(&self, claim: &ClaimedFeed) -> Result<HashMap<String, Value>, StoreError> {
        let mut tx = self.begin(&claim.slot).await?;
        let rows: Vec<(String, Value)> = sqlx::query_as(
            "SELECT stream_id, state FROM public.connector_feed_checkpoints WHERE tenant_id = $1 AND feed_id = $2",
        )
        .bind(claim.slot.tenant_id)
        .bind(claim.feed.feed_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(rows.into_iter().collect())
    }

    async fn save_checkpoint(&self, claim: &ClaimedFeed, stream: &str, state: &Value) -> Result<(), StoreError> {
        let mut tx = self.begin(&claim.slot).await?;
        // FOR SHARE on the feed row serializes against a concurrent claim
        // (which takes it FOR UPDATE), so the fence cannot be raced.
        let holds: Option<i64> = sqlx::query_scalar(
            "SELECT lease_generation FROM public.connector_feeds
              WHERE tenant_id = $1 AND id = $2 AND lease_generation = $3 AND lease_owner = $4
                AND lease_expires_at > now()
              FOR SHARE",
        )
        .bind(claim.slot.tenant_id)
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
            "INSERT INTO public.connector_feed_checkpoints (tenant_id, feed_id, stream_id, state, lease_generation, run_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, feed_id, stream_id) DO UPDATE
                SET state = EXCLUDED.state, lease_generation = EXCLUDED.lease_generation,
                    run_id = EXCLUDED.run_id, commits = public.connector_feed_checkpoints.commits + 1,
                    updated_at = now()",
        )
        .bind(claim.slot.tenant_id)
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

    async fn provision_credentials(&self, slot: &TenantSlot, limit: usize) -> Result<CredentialPass, StoreError> {
        // Issuance is the hosted NAN-2590 path; a dedicated / open-core feed
        // gets its token when it is created (the local ingress has no
        // issuance service).
        if matches!(self.tenancy, Tenancy::Dedicated { .. }) || limit == 0 {
            return Ok(CredentialPass::default());
        }
        #[cfg(feature = "enterprise")]
        {
            self.credential_pass(slot, limit).await
        }
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = slot;
            Ok(CredentialPass::default())
        }
    }

    async fn claim_deletes(&self, slot: &TenantSlot, node: &str, limit: usize, lease_secs: u64) -> Result<Vec<PendingDelete>, StoreError> {
        if !self.delete_columns || limit == 0 {
            return Ok(Vec::new());
        }
        let mut tx = self.begin(slot).await?;
        let due: Vec<(Uuid, String, i32)> = sqlx::query_as(&format!(
            "SELECT id, {}, delete_attempts FROM public.connector_feeds
              WHERE tenant_id = $1 AND delete_requested_at IS NOT NULL
                AND (delete_next_attempt_at IS NULL OR delete_next_attempt_at <= now())
                AND (lease_expires_at IS NULL OR lease_expires_at < now())
              ORDER BY delete_requested_at, id
              LIMIT $2
              FOR UPDATE SKIP LOCKED",
            self.sink_sql()
        ))
        .bind(slot.tenant_id)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let mut out = Vec::with_capacity(due.len());
        for (id, sink, attempts) in due {
            let generation: i64 = sqlx::query_scalar(
                "UPDATE public.connector_feeds
                    SET lease_owner = $3, lease_generation = lease_generation + 1,
                        lease_expires_at = now() + make_interval(secs => $4), updated_at = now()
                  WHERE tenant_id = $1 AND id = $2
                  RETURNING lease_generation",
            )
            .bind(slot.tenant_id)
            .bind(id)
            .bind(node)
            .bind(lease_secs as f64)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            out.push(PendingDelete {
                slot: *slot,
                feed_id: id,
                identity: sink == SINK_IDENTITY,
                lease_generation: generation,
                node: node.to_string(),
                attempts: attempts.max(0) as u32,
            });
        }
        tx.commit().await.map_err(db)?;
        Ok(out)
    }

    async fn finish_delete(&self, claim: &PendingDelete, outcome: Result<(), String>) -> Result<(), StoreError> {
        let mut tx = self.begin(&claim.slot).await?;
        let changed = match outcome {
            // Checkpoints and run records go with the row (ON DELETE CASCADE).
            Ok(()) => sqlx::query(
                "DELETE FROM public.connector_feeds
                  WHERE tenant_id = $1 AND id = $2 AND lease_generation = $3 AND lease_owner = $4
                    AND delete_requested_at IS NOT NULL",
            )
            .bind(claim.slot.tenant_id)
            .bind(claim.feed_id)
            .bind(claim.lease_generation)
            .bind(&claim.node)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected(),
            Err(message) => {
                let attempts = claim.attempts.saturating_add(1);
                sqlx::query(
                    "UPDATE public.connector_feeds
                        SET delete_attempts = $5, delete_last_error = $6,
                            delete_next_attempt_at = now() + make_interval(secs => $7),
                            lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
                      WHERE tenant_id = $1 AND id = $2 AND lease_generation = $3 AND lease_owner = $4",
                )
                .bind(claim.slot.tenant_id)
                .bind(claim.feed_id)
                .bind(claim.lease_generation)
                .bind(&claim.node)
                .bind(attempts.min(i32::MAX as u32) as i32)
                .bind(truncate_error(&message))
                .bind(delete_backoff(attempts).num_seconds() as f64)
                .execute(&mut *tx)
                .await
                .map_err(db)?
                .rows_affected()
            }
        };
        tx.commit().await.map_err(db)?;
        if changed == 0 {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }

    async fn finish(&self, claim: &ClaimedFeed, rec: &RunRecord) -> Result<(), StoreError> {
        let mut tx = self.begin(&claim.slot).await?;
        let ok = rec.ok();
        let fed = sqlx::query(
            "UPDATE public.connector_feeds
                SET lease_owner = NULL, lease_expires_at = NULL, next_run_at = $5,
                    consecutive_failures = CASE WHEN $6 THEN 0 WHEN $10 THEN consecutive_failures ELSE LEAST(consecutive_failures + 1, 1000000) END,
                    last_status = $7, last_error = $8,
                    last_success_at = CASE WHEN $6 THEN $9 ELSE last_success_at END,
                    updated_at = now()
              WHERE tenant_id = $1 AND id = $2 AND lease_generation = $3 AND lease_owner = $4",
        )
        .bind(claim.slot.tenant_id)
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
                SET status = $3, finished_at = $4, events = $5, bytes = $6, batches = $7, pages = $8,
                    requests = $9, ingest_retries = $10, rejected_events = $11, dropped_duplicates = $12,
                    checkpoints_committed = $13, errors = $14, error = $15, last_receipt = $16
              WHERE tenant_id = $1 AND id = $2",
        )
        .bind(claim.slot.tenant_id)
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
              WHERE tenant_id = $1 AND feed_id = $2 AND started_at < now() - make_interval(days => $3)",
        )
        .bind(claim.slot.tenant_id)
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
}

/// NAN-3490: the effective parser rollout state of a marketplace feed's
/// source, as a SQL scalar over the `connector_feeds` row aliased `feed`.
/// Shared by the runner's enrollment gate and the hosted-collector status so
/// the two never disagree.
///
/// - the latest rollout request row for the feed's `marketplace_source_id`
///   is `live` or still in flight (`pending`/`building`/`validated`/
///   `rolling`): that state;
/// - latest row `failed` with exactly `failure_component = 'roll:no_change'`
///   AND the lane in the active bundle (below): `live`. The platform ends a
///   tenant publish whose published set already compiles to the ACTIVE
///   bundle that way (it cannot roll identical content). The arm overlaps
///   the next one on purpose: `no_change` alone is never trusted;
/// - otherwise (latest row `failed`/`rolled_back`, or none): `live` when the
///   source's lane is in the tenant's ACTIVE parser bundle
///   (`nano_shared.tenant_parser_lane_active`, 9013110: the signed tenant's
///   active composition `overlay_sources` carries `feed.source_slug`), else
///   the latest row's state. A `platform_release` roll rebuilds the whole
///   published set without writing rollout rows, so after a failed tenant
///   roll this is the only signal that the lane went live.
///
/// Every read is the signed tenant's own (RLS on the rollout rows,
/// `current_tenant_id()` inside the definer). Signed tenant runtime only.
#[cfg(feature = "enterprise")]
pub fn marketplace_rollout_state_sql(feed: &str) -> String {
    debug_assert!(!feed.is_empty() && feed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    format!(
        "(SELECT CASE WHEN latest.state IN ('live','pending','building','validated','rolling') THEN latest.state
                      WHEN latest.state='failed' AND latest.failure_component='roll:no_change'
                           AND nano_shared.tenant_parser_lane_active({feed}.source_slug) THEN 'live'
                      WHEN nano_shared.tenant_parser_lane_active({feed}.source_slug) THEN 'live'
                      ELSE latest.state END
            FROM (SELECT 1) seed
            LEFT JOIN LATERAL (SELECT r.state, r.failure_component FROM public.enterprise_shared_parser_rollout_requests r
                                WHERE r.tenant_id={feed}.tenant_id AND r.log_source_id={feed}.marketplace_source_id
                                ORDER BY r.requested_at DESC,r.id DESC LIMIT 1) latest ON TRUE)"
    )
}

#[cfg(feature = "enterprise")]
/// Pending-request poll cadence: quick while nano-main normally answers,
/// slower once a request has waited (e.g. a source not enrolled yet).
const CREDENTIAL_POLL_FAST_SECS: i64 = 15;
#[cfg(feature = "enterprise")]
const CREDENTIAL_POLL_SLOW_SECS: i64 = 120;
#[cfg(feature = "enterprise")]
const CREDENTIAL_POLL_FAST_WINDOW_SECS: i64 = 600;
/// Floor before a fresh request after a request had to be abandoned, so a
/// failure that repeats (e.g. a rotated deployment cipher) cannot hot-loop
/// requests; the platform also rate-limits issuance.
#[cfg(feature = "enterprise")]
const CREDENTIAL_RESTART_SECS: i64 = 60;

#[cfg(feature = "enterprise")]
/// One feed waiting for its ingest credential.
struct PendingCredential {
    feed_id: Uuid,
    name: String,
    source_slug: String,
    /// The feed's installer (`created_by`): the delegating authority a
    /// worker-actor request is checked against (9013120), audited with it.
    installer: Option<Uuid>,
    request_id: Option<Uuid>,
    reveal_key: Option<(Vec<u8>, String)>,
    waited_secs: i64,
    /// NAN-3660: the credential a rotation is replacing. It stays valid until
    /// the new one is stored on the feed, the new request fails, or
    /// [`ROTATION_GRACE_SECS`] pass; then it is revoked.
    previous_credential: Option<Uuid>,
}

#[cfg(feature = "enterprise")]
/// NAN-3660: the longest a rotation keeps the previous credential valid
/// while its replacement is still pending.
pub const ROTATION_GRACE_SECS: i64 = 3600;

#[cfg(feature = "enterprise")]
/// What one feed's issuance step concluded.
enum CredentialStep {
    Requested(Uuid),
    Waiting,
    Issued { request_id: Uuid, credential_id: Option<Uuid> },
    /// Record `code`, retry after `retry_secs`; `restart` forgets the
    /// request (a fresh one is made next time); `revoke` names an issued
    /// credential this feed will never hold, revoked best-effort.
    Failed { code: String, retry_secs: i64, restart: bool, revoke: Option<Uuid> },
}

#[cfg(feature = "enterprise")]
fn failed(code: impl Into<String>, retry_secs: i64, restart: bool, revoke: Option<Uuid>) -> CredentialStep {
    CredentialStep::Failed { code: code.into(), retry_secs, restart, revoke }
}

#[cfg(feature = "enterprise")]
/// `connector feed: <name>`, at most 128 characters (the request label bound).
fn credential_label(name: &str) -> String {
    format!("connector feed: {name}").chars().take(128).collect()
}

#[cfg(feature = "enterprise")]
fn credential_audit(event: &str, tenant_id: Uuid, feed_id: Uuid, detail: Value) {
    let fields = serde_json::json!({ "event": event, "tenant_id": tenant_id, "feed_id": feed_id, "detail": detail });
    if event.ends_with("failed") {
        tracing::warn!(target: "nano_connector::audit", credential = %fields, "connector feed ingest credential");
    } else {
        tracing::info!(target: "nano_connector::audit", credential = %fields, "connector feed ingest credential");
    }
}

#[cfg(feature = "enterprise")]
impl PgFeedStore {
    /// Pass for one tenant, in ONE signed transaction (rows locked FOR
    /// UPDATE SKIP LOCKED, so two runners never work the same feed). Each
    /// feed's step runs in a savepoint: a refusal raised by the 9001640
    /// guard rolls back only that feed's step, never the reveal of another.
    async fn credential_pass(&self, slot: &TenantSlot, limit: usize) -> Result<CredentialPass, StoreError> {
        let mut tx = self.begin(slot).await?;
        // Marketplace-owned feeds wait for their source's parser lane to be
        // live (latest rollout row live, or - after a failed tenant roll - the
        // lane in the tenant's active bundle; `marketplace_rollout_state_sql`)
        // before requesting their source-bound ingest credential. Legacy and
        // dedicated feeds keep their previous issuance behavior.
        let enrollment = if matches!(&self.tenancy, Tenancy::Shared { .. } | Tenancy::SignedStatic { .. }) {
            format!(" AND (feed.marketplace_source_id IS NULL OR {}='live')", marketplace_rollout_state_sql("feed"))
        } else { String::new() };
        let hec = if self.sink_column { "sink = 'hec'" } else { "TRUE" };
        let rows = sqlx::query(&format!(
            "SELECT id, name, source_slug, created_by, ingest_credential_request_id, ingest_credential_id,
                    ingest_reveal_key_encrypted, ingest_reveal_key_nonce,
                    COALESCE(EXTRACT(EPOCH FROM now() - ingest_credential_requested_at)::bigint, 0) AS waited_secs
               FROM public.connector_feeds feed
              WHERE tenant_id = $1 AND enabled AND {hec} AND ingest_token_encrypted IS NULL AND next_run_at <= now(){enrollment}
              ORDER BY next_run_at, id
              LIMIT $2
              FOR UPDATE OF feed SKIP LOCKED",
        ))
        .bind(slot.tenant_id)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let mut pass = CredentialPass::default();
        for r in rows {
            let ct: Option<Vec<u8>> = r.try_get("ingest_reveal_key_encrypted").map_err(db)?;
            let nonce: Option<String> = r.try_get("ingest_reveal_key_nonce").map_err(db)?;
            let feed = PendingCredential {
                feed_id: r.try_get("id").map_err(db)?,
                name: r.try_get("name").map_err(db)?,
                source_slug: r.try_get("source_slug").map_err(db)?,
                installer: r.try_get("created_by").map_err(db)?,
                request_id: r.try_get("ingest_credential_request_id").map_err(db)?,
                reveal_key: ct.zip(nonce),
                waited_secs: r.try_get("waited_secs").map_err(db)?,
                previous_credential: r.try_get("ingest_credential_id").map_err(db)?,
            };
            let step = {
                let mut sp = sqlx::Connection::begin(&mut *tx).await.map_err(db)?;
                let step = match feed.request_id {
                    None => self.request_credential(&mut sp, slot, &feed).await,
                    Some(request_id) => self.collect_credential(&mut sp, slot, &feed, request_id).await,
                };
                match step {
                    Ok(step @ (CredentialStep::Requested(_) | CredentialStep::Waiting | CredentialStep::Issued { .. })) => {
                        sp.commit().await.map_err(db)?;
                        step
                    }
                    Ok(step) => {
                        sp.rollback().await.map_err(db)?;
                        step
                    }
                    Err(e) => {
                        sp.rollback().await.map_err(db)?;
                        failed(format!("backend: {e}"), 60, false, None)
                    }
                }
            };
            match step {
                CredentialStep::Requested(request_id) => {
                    pass.requested += 1;
                    credential_audit("connector_feed_credential_requested", slot.tenant_id, feed.feed_id,
                        serde_json::json!({ "request_id": request_id, "source_slug": feed.source_slug,
                            "requested_by": slot.actor_id, "delegated_by": feed.installer }));
                }
                CredentialStep::Waiting => {
                    pass.waiting += 1;
                    // NAN-3660: bound the rotation overlap.
                    if let Some(previous) = feed.previous_credential.filter(|_| feed.waited_secs > ROTATION_GRACE_SECS) {
                        self.retire_previous(&mut tx, slot, &feed, previous, "rotation grace period passed").await?;
                    }
                }
                CredentialStep::Issued { request_id, credential_id } => {
                    pass.issued += 1;
                    // NAN-3660: the replacement is stored; end the overlap.
                    if let Some(previous) = feed.previous_credential.filter(|p| Some(*p) != credential_id) {
                        self.revoke_orphan(&mut tx, slot, previous, "nano-connector: feed credential rotated").await;
                        credential_audit("connector_feed_credential_retired", slot.tenant_id, feed.feed_id,
                            serde_json::json!({ "credential_id": previous, "replaced_by": credential_id, "reason": "rotated" }));
                    }
                    credential_audit("connector_feed_credential_issued", slot.tenant_id, feed.feed_id,
                        serde_json::json!({ "request_id": request_id, "credential_id": credential_id, "source_slug": feed.source_slug,
                            "requested_by": slot.actor_id, "delegated_by": feed.installer }));
                }
                CredentialStep::Failed { code, retry_secs, restart, revoke } => {
                    pass.failed += 1;
                    if let Some(credential_id) = revoke {
                        self.revoke_orphan(&mut tx, slot, credential_id, "nano-connector: issued feed credential could not be stored").await;
                    }
                    // NAN-3660: a failed replacement ends the rotation overlap.
                    if let Some(previous) = feed.previous_credential.filter(|_| restart) {
                        self.retire_previous(&mut tx, slot, &feed, previous, "replacement request failed").await?;
                    }
                    let code: String = code.chars().take(1000).collect();
                    sqlx::query(
                        "UPDATE public.connector_feeds
                            SET ingest_credential_error = $3,
                                next_run_at = now() + make_interval(secs => $4),
                                ingest_credential_request_id = CASE WHEN $5 THEN NULL ELSE ingest_credential_request_id END,
                                ingest_reveal_key_encrypted = CASE WHEN $5 THEN NULL ELSE ingest_reveal_key_encrypted END,
                                ingest_reveal_key_nonce = CASE WHEN $5 THEN NULL ELSE ingest_reveal_key_nonce END,
                                ingest_credential_requested_at = CASE WHEN $5 THEN NULL ELSE ingest_credential_requested_at END,
                                updated_at = now()
                          WHERE tenant_id = $1 AND id = $2",
                    )
                    .bind(slot.tenant_id)
                    .bind(feed.feed_id)
                    .bind(&code)
                    .bind(retry_secs as f64)
                    .bind(restart)
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
                    credential_audit("connector_feed_credential_failed", slot.tenant_id, feed.feed_id,
                        serde_json::json!({ "error": code, "restart": restart, "revoked_credential_id": revoke,
                            "requested_by": slot.actor_id, "delegated_by": feed.installer }));
                }
            }
        }
        tx.commit().await.map_err(db)?;
        Ok(pass)
    }

    /// No request yet: make a reveal key and insert the NAN-2590 request as
    /// this tenant's worker member.
    async fn request_credential(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        slot: &TenantSlot,
        feed: &PendingCredential,
    ) -> Result<CredentialStep, StoreError> {
        use nanosiem_core::enterprise_shared_sources::{Error as SrcError, IngestCredentialRequestInput, insert_ingest_credential_request};
        let key = match RevealKey::generate() {
            Ok(k) => k,
            Err(e) => return Ok(failed(format!("reveal_key: {e}"), 300, true, None)),
        };
        let public_key = match key.public_key_b64u() {
            Ok(k) => k,
            Err(e) => return Ok(failed(format!("reveal_key: {e}"), 300, true, None)),
        };
        let input = IngestCredentialRequestInput {
            protocol: "hec".into(),
            label: credential_label(&feed.name),
            kind: "source".into(),
            source_slugs: vec![feed.source_slug.clone()],
            source_aliases: None,
            reveal_public_key: public_key,
            reveal_key_alg: Some(REVEAL_KEY_ALG.into()),
            restricted_sources_acknowledged: false,
            log_source_id: None,
            reason: Some(format!("nano-connector feed {}", feed.feed_id)),
        };
        let request = match insert_ingest_credential_request(tx, slot.tenant_id, slot.actor_id, &input).await {
            Ok(r) => r,
            Err(SrcError::Refused(code)) => return Ok(failed(format!("credential_refused: {code}"), 3600, true, None)),
            Err(SrcError::CapacityExceeded) => {
                return Ok(failed("credential_capacity: too many pending ingest credential requests for this tenant", 300, true, None));
            }
            Err(SrcError::InvalidInput(m)) => return Ok(failed(format!("credential_invalid: {m}"), 3600, true, None)),
            Err(e) => return Err(StoreError::Backend(e.to_string())),
        };
        let seed = key.seed_hex();
        let (ct, nonce) = Self::seal(&self.cipher, &HashMap::from([("seed".to_string(), seed.to_string())]))
            .map_err(StoreError::Backend)?;
        sqlx::query(
            "UPDATE public.connector_feeds
                SET ingest_credential_request_id = $3, ingest_reveal_key_encrypted = $4, ingest_reveal_key_nonce = $5,
                    ingest_credential_requested_at = now(), ingest_credential_error = NULL,
                    next_run_at = now() + make_interval(secs => $6), updated_at = now()
              WHERE tenant_id = $1 AND id = $2",
        )
        .bind(slot.tenant_id)
        .bind(feed.feed_id)
        .bind(request.id)
        .bind(ct)
        .bind(nonce)
        .bind(CREDENTIAL_POLL_FAST_SECS as f64)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
        Ok(CredentialStep::Requested(request.id))
    }

    /// A request is in flight: read its state; once issued, reveal it, open
    /// it with the feed's reveal key and seal the token onto the feed, in
    /// this one transaction (a failure rolls the reveal back too).
    async fn collect_credential(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        slot: &TenantSlot,
        feed: &PendingCredential,
        request_id: Uuid,
    ) -> Result<CredentialStep, StoreError> {
        use base64::Engine as _;
        use nanosiem_core::enterprise_shared_sources::{Error as SrcError, reveal_ingest_credential_request};
        let state = match reveal_ingest_credential_request(tx, slot.tenant_id, slot.actor_id, request_id, false).await {
            Ok(s) => s,
            Err(SrcError::NotFound) => return Ok(failed("credential_request_gone: the issuance request no longer exists", CREDENTIAL_RESTART_SECS, true, None)),
            Err(e) => return Err(StoreError::Backend(e.to_string())),
        };
        match state.state.as_str() {
            "pending" => {
                let wait = if feed.waited_secs < CREDENTIAL_POLL_FAST_WINDOW_SECS { CREDENTIAL_POLL_FAST_SECS } else { CREDENTIAL_POLL_SLOW_SECS };
                sqlx::query(
                    "UPDATE public.connector_feeds SET next_run_at = now() + make_interval(secs => $3), updated_at = now()
                      WHERE tenant_id = $1 AND id = $2",
                )
                .bind(slot.tenant_id)
                .bind(feed.feed_id)
                .bind(wait as f64)
                .execute(&mut **tx)
                .await
                .map_err(db)?;
                return Ok(CredentialStep::Waiting);
            }
            "rejected" => {
                let why = state.disposition.unwrap_or_else(|| "no disposition".into());
                return Ok(failed(format!("credential_rejected: {why}"), 3600, true, None));
            }
            "revoked" => return Ok(failed("credential_revoked: the issued credential was revoked before it was stored", CREDENTIAL_RESTART_SECS, true, None)),
            "issued" if state.sealed_token_ready => {}
            "issued" => {
                // Revealed elsewhere, or the seal expired: this feed can never
                // hold that credential, so retire it and start over.
                return Ok(failed("credential_unrevealable: the sealed token expired or was already revealed", CREDENTIAL_RESTART_SECS, true, state.credential_id));
            }
            other => return Ok(failed(format!("credential_state: unexpected request state {other}"), 3600, true, None)),
        }
        let Some((ct, nonce)) = feed.reveal_key.clone() else {
            return Ok(failed("credential_reveal_key_missing", CREDENTIAL_RESTART_SECS, true, state.credential_id));
        };
        let key = match self.open(feed.feed_id, Some(ct), Some(nonce)).ok().and_then(|m| m.get("seed").cloned()) {
            Some(seed) => RevealKey::from_seed_hex(seed.expose()),
            None => return Ok(failed("credential_reveal_key_unreadable", CREDENTIAL_RESTART_SECS, true, state.credential_id)),
        };
        let key = match key {
            Ok(k) => k,
            Err(e) => return Ok(failed(format!("credential_reveal_key_unreadable: {e}"), CREDENTIAL_RESTART_SECS, true, state.credential_id)),
        };
        let reveal = match reveal_ingest_credential_request(tx, slot.tenant_id, slot.actor_id, request_id, true).await {
            Ok(r) => r,
            Err(SrcError::Gone(code)) => return Ok(failed(format!("credential_gone: {code}"), CREDENTIAL_RESTART_SECS, true, state.credential_id)),
            Err(SrcError::Refused(code)) => return Ok(failed(format!("credential_refused: {code}"), CREDENTIAL_RESTART_SECS, true, state.credential_id)),
            Err(e) => return Err(StoreError::Backend(e.to_string())),
        };
        let Some(sealed_b64) = reveal.sealed_token.as_deref() else {
            return Ok(failed("credential_not_sealed", CREDENTIAL_RESTART_SECS, true, reveal.credential_id));
        };
        let sealed = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sealed_b64) {
            Ok(b) => b,
            Err(_) => return Ok(failed("credential_envelope: sealed token is not base64url", CREDENTIAL_RESTART_SECS, true, reveal.credential_id)),
        };
        let token = match key.open(&sealed, request_id, slot.tenant_id) {
            Ok(t) => t,
            Err(e) => return Ok(failed(format!("credential_envelope: {e}"), CREDENTIAL_RESTART_SECS, true, reveal.credential_id)),
        };
        let (ct, nonce) = Self::seal(&self.cipher, &HashMap::from([("token".to_string(), token.expose().to_string())]))
            .map_err(StoreError::Backend)?;
        sqlx::query(
            "UPDATE public.connector_feeds
                SET ingest_token_encrypted = $3, ingest_token_nonce = $4, ingest_credential_id = $5,
                    ingest_credential_issued_at = now(), ingest_credential_error = NULL,
                    ingest_reveal_key_encrypted = NULL, ingest_reveal_key_nonce = NULL,
                    next_run_at = now(), updated_at = now()
              WHERE tenant_id = $1 AND id = $2",
        )
        .bind(slot.tenant_id)
        .bind(feed.feed_id)
        .bind(ct)
        .bind(nonce)
        .bind(reveal.credential_id)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
        Ok(CredentialStep::Issued { request_id, credential_id: reveal.credential_id })
    }

    /// NAN-3660: revoke the credential a rotation replaced and forget it.
    async fn retire_previous(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        slot: &TenantSlot,
        feed: &PendingCredential,
        previous: Uuid,
        why: &str,
    ) -> Result<(), StoreError> {
        self.revoke_orphan(tx, slot, previous, &format!("nano-connector: feed credential rotated ({why})")).await;
        sqlx::query(
            "UPDATE public.connector_feeds SET ingest_credential_id = NULL, updated_at = now()
              WHERE tenant_id = $1 AND id = $2 AND ingest_token_encrypted IS NULL AND ingest_credential_id = $3",
        )
        .bind(slot.tenant_id)
        .bind(feed.feed_id)
        .bind(previous)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
        credential_audit("connector_feed_credential_retired", slot.tenant_id, feed.feed_id,
            serde_json::json!({ "credential_id": previous, "reason": why }));
        Ok(())
    }

    /// Best-effort: revoke an issued credential no feed will ever hold.
    async fn revoke_orphan(&self, tx: &mut Transaction<'_, Postgres>, slot: &TenantSlot, credential_id: Uuid, reason: &str) {
        use nanosiem_core::enterprise_shared_sources::{RevokeIngestCredentialInput, revoke_ingest_credential_row};
        let Ok(mut sp) = sqlx::Connection::begin(&mut **tx).await else { return };
        let input = RevokeIngestCredentialInput { reason: reason.chars().take(200).collect() };
        match revoke_ingest_credential_row(&mut sp, slot.tenant_id, slot.actor_id, credential_id, &input).await {
            Ok(_) => {
                let _ = sp.commit().await;
            }
            Err(e) => {
                tracing::warn!(tenant_id = %slot.tenant_id, %credential_id, error = %e, "orphaned connector feed credential not revoked");
                let _ = sp.rollback().await;
            }
        }
    }
}

/// Insert a feed (operator tooling and tests; the authoring UI is another
/// lane). Returns the feed id. `ingest_token: None` leaves the credential to
/// the runner's issuance pass (hosted-shared, [`super::credential`]).
#[allow(clippy::too_many_arguments)]
pub async fn insert_feed(
    tx: &mut Transaction<'_, Postgres>,
    cipher: &EncryptionService,
    tenant_id: Uuid,
    name: &str,
    connector: &str,
    spec_yaml: &str,
    source_slug: &str,
    config: &Value,
    vendor_credentials: &HashMap<String, String>,
    ingest_url: &str,
    ingest_token: Option<&str>,
    catalog_id: Option<Uuid>,
) -> Result<Uuid, String> {
    let (vct, vnonce) = if vendor_credentials.is_empty() {
        (None, None)
    } else {
        let (c, n) = PgFeedStore::seal(cipher, vendor_credentials)?;
        (Some(c), Some(n))
    };
    let (ict, inonce) = match ingest_token {
        Some(token) => {
            let (c, n) = PgFeedStore::seal(cipher, &HashMap::from([("token".to_string(), token.to_string())]))?;
            (Some(c), Some(n))
        }
        None => (None, None),
    };
    sqlx::query_scalar(
        "INSERT INTO public.connector_feeds
            (tenant_id, name, connector, catalog_id, spec_yaml, spec_sha256, source_slug, config,
             vendor_credentials_encrypted, vendor_credentials_nonce, ingest_url, ingest_token_encrypted, ingest_token_nonce)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(name)
    .bind(connector)
    .bind(catalog_id)
    .bind(spec_yaml)
    .bind(super::feed::spec_sha256(spec_yaml))
    .bind(source_slug)
    .bind(config)
    .bind(vct)
    .bind(vnonce)
    .bind(ingest_url)
    .bind(ict)
    .bind(inonce)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| e.to_string())
}

fn admin_db(e: sqlx::Error) -> super::admin::AdminError {
    use super::admin::AdminError;
    match e.as_database_error().and_then(|d| d.code()).as_deref() {
        Some("23505") => AdminError::InvalidInput("a feed with that name already exists for this tenant".into()),
        Some("54000") => AdminError::InvalidInput("connector feed limit reached for this tenant (64)".into()),
        Some("23514") => AdminError::InvalidInput("a feed value violates a table constraint".into()),
        _ => AdminError::Backend(e.to_string()),
    }
}

/// Feed administration (`nano-connector-runner feed ...`, [`super::admin`]).
impl PgFeedStore {
    /// The slot this store acts as for `tenant`. On hosted-shared only a
    /// tenant in this worker identity's assignment ledger resolves.
    pub async fn slot_for(&self, tenant: Uuid) -> Result<TenantSlot, super::admin::AdminError> {
        use super::admin::AdminError;
        match &self.tenancy {
            Tenancy::Dedicated { pool } => {
                let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM public.tenants WHERE id = $1)")
                    .bind(tenant)
                    .fetch_one(pool)
                    .await
                    .map_err(admin_db)?;
                if exists { Ok(TenantSlot { tenant_id: tenant, actor_id: Uuid::nil() }) } else { Err(AdminError::UnknownTenant(tenant)) }
            }
            _ => self
                .tenants()
                .await
                .map_err(|e| AdminError::Backend(e.to_string()))?
                .into_iter()
                .find(|s| s.tenant_id == tenant)
                .ok_or(AdminError::UnknownTenant(tenant)),
        }
    }

    /// The tenant's slug (its ingest hostname label). On hosted-shared it
    /// comes from the same control-plane discovery that admits the tenant to
    /// this runner (the runtime role cannot read `tenants`); a dedicated
    /// deployment reads `tenants`. A pinned (`SignedStatic`) tenancy has no
    /// slug source and refuses.
    pub async fn tenant_slug(&self, slot: &TenantSlot) -> Result<String, super::admin::AdminError> {
        use super::admin::AdminError;
        match &self.tenancy {
            #[cfg(feature = "enterprise")]
            Tenancy::Shared { discovery, worker_identity, .. } => discovery
                .enumerate_provisioned_detection_workers(worker_identity, MAX_TENANTS + 1)
                .await
                .map_err(|e| AdminError::Backend(e.to_string()))?
                .into_iter()
                .find(|w| w.tenant_id == slot.tenant_id)
                .map(|w| w.tenant_slug)
                .ok_or(AdminError::UnknownTenant(slot.tenant_id)),
            Tenancy::Dedicated { pool } => sqlx::query_scalar::<_, String>("SELECT slug FROM public.tenants WHERE id = $1")
                .bind(slot.tenant_id)
                .fetch_optional(pool)
                .await
                .map_err(admin_db)?
                .ok_or(AdminError::UnknownTenant(slot.tenant_id)),
            Tenancy::SignedStatic { .. } => {
                Err(AdminError::Backend("a pinned tenancy has no tenant slug source; use enterprise_shared discovery".into()))
            }
        }
    }

    /// Create a feed pinned to `plan`. `ingest_token: None` leaves the token
    /// to the issuance pass (hosted-shared).
    pub async fn create_feed(
        &self,
        slot: &TenantSlot,
        plan: &super::admin::FeedPlan,
        feed: &super::admin::NewFeed,
        ingest_url: &str,
        ingest_token: Option<&str>,
    ) -> Result<Uuid, super::admin::AdminError> {
        use super::admin::AdminError;
        super::admin::check_inputs(plan, feed)?;
        let identity = plan.spec.kind == crate::spec::Kind::Identity;
        if identity && !self.sink_column {
            return Err(AdminError::InvalidInput(
                "identity feeds need migration 350 / 9013180 (connector_feeds.sink); apply it first".into(),
            ));
        }
        if identity {
            if !ingest_url.is_empty() || ingest_token.is_some() {
                return Err(AdminError::InvalidInput("an identity feed has no ingest URL or token".into()));
            }
        } else {
            super::hec::HecSink::new(
                ingest_url,
                Secret::new(ingest_token.unwrap_or("validation-only")),
                Uuid::nil(),
                &plan.connector,
                super::hec::HecConfig { allow_http: true, ..Default::default() },
            )
            .map_err(|e| AdminError::InvalidInput(format!("ingest_url: {e}")))?;
        }
        let (vct, vnonce) = if feed.vendor_credentials.is_empty() {
            (None, None)
        } else {
            let (c, n) = Self::seal(&self.cipher, &feed.vendor_credentials).map_err(AdminError::Backend)?;
            (Some(c), Some(n))
        };
        let (ict, inonce) = match ingest_token {
            Some(t) => {
                let (c, n) = Self::seal(&self.cipher, &HashMap::from([("token".to_string(), t.to_string())])).map_err(AdminError::Backend)?;
                (Some(c), Some(n))
            }
            None => (None, None),
        };
        let actor = (!slot.actor_id.is_nil()).then_some(slot.actor_id);
        let mut tx = self.begin(slot).await.map_err(|e| AdminError::Backend(e.to_string()))?;
        // Legacy schema (no sink column): every feed is HEC; the column and
        // its bind are left out.
        let (sink_col, sink_val) = if self.sink_column { (", sink", ", $19") } else { ("", "") };
        let sql = format!(
            "INSERT INTO public.connector_feeds
                (tenant_id, name, connector, catalog_id, spec_yaml, spec_sha256, source_slug, enabled, schedule, config,
                 vendor_credentials_encrypted, vendor_credentials_nonce, ingest_url, ingest_token_encrypted, ingest_token_nonce,
                 backfill_from, max_run_secs, created_by, updated_by{sink_col})
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $18{sink_val})
             RETURNING id",
        );
        let mut insert = sqlx::query_scalar::<_, Uuid>(&sql)
        .bind(slot.tenant_id)
        .bind(&feed.name)
        .bind(&plan.connector)
        .bind(plan.catalog_id)
        .bind(&plan.spec_yaml)
        .bind(&plan.spec_sha256)
        .bind(&plan.source_slug)
        .bind(feed.enabled)
        .bind(&feed.schedule)
        .bind(Value::Object(feed.config.clone()))
        .bind(vct)
        .bind(vnonce)
        .bind((!identity).then_some(ingest_url))
        .bind(ict)
        .bind(inonce)
        // NAN-3697: no backfill option; the legacy column stays NULL.
        .bind(None::<chrono::DateTime<chrono::Utc>>)
        .bind(feed.max_run_secs)
        .bind(actor);
        if self.sink_column {
            insert = insert.bind(if identity { SINK_IDENTITY } else { SINK_HEC });
        }
        let id = insert.fetch_one(&mut *tx).await.map_err(admin_db)?;
        tx.commit().await.map_err(admin_db)?;
        tracing::info!(
            target: "nano_connector::audit",
            feed = %serde_json::json!({
                "event": "connector_feed_created", "tenant_id": slot.tenant_id, "feed_id": id, "actor_id": actor,
                "connector": plan.connector, "catalog_id": plan.catalog_id, "spec_sha256": plan.spec_sha256,
                "source_slug": plan.source_slug, "ingest_url": ingest_url, "token": if identity { "not_required" } else if ingest_token.is_some() { "given" } else { "issued" },
            }),
            "connector feed"
        );
        Ok(id)
    }

    /// Delete only this tenant's feed. A collector's row goes now (cascading
    /// rows and outstanding leases vanish). An identity feed (NAN-3767) is
    /// disabled and marked for delete instead: the runner's pending-delete
    /// pass removes its `<feed>:users` / `<feed>:groups` directory data at
    /// the coordinator first, then the row, so a deleted feed's people stop
    /// enriching events. Without the pending-delete columns the row goes now.
    pub async fn delete_feed(
        &self,
        slot: &TenantSlot,
        id: Uuid,
    ) -> Result<(), super::admin::AdminError> {
        let mut tx = self
            .begin(slot)
            .await
            .map_err(|e| super::admin::AdminError::Backend(e.to_string()))?;
        let pending = self.sink_column && self.delete_columns;
        let n = if pending {
            let marked = sqlx::query(
                "UPDATE public.connector_feeds
                    SET enabled = false, delete_requested_at = COALESCE(delete_requested_at, now()),
                        delete_next_attempt_at = NULL, updated_at = now(), revision = revision + 1
                  WHERE tenant_id = $1 AND id = $2 AND sink = $3",
            )
            .bind(slot.tenant_id)
            .bind(id)
            .bind(SINK_IDENTITY)
            .execute(&mut *tx)
            .await
            .map_err(admin_db)?
            .rows_affected();
            if marked > 0 {
                marked
            } else {
                sqlx::query("DELETE FROM public.connector_feeds WHERE tenant_id = $1 AND id = $2 AND sink <> $3")
                    .bind(slot.tenant_id)
                    .bind(id)
                    .bind(SINK_IDENTITY)
                    .execute(&mut *tx)
                    .await
                    .map_err(admin_db)?
                    .rows_affected()
            }
        } else {
            sqlx::query("DELETE FROM public.connector_feeds WHERE tenant_id = $1 AND id = $2")
                .bind(slot.tenant_id)
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(admin_db)?
                .rows_affected()
        };
        tx.commit().await.map_err(admin_db)?;
        if n == 0 {
            return Err(super::admin::AdminError::FeedNotFound(id));
        }
        Ok(())
    }

    pub async fn list_feeds(&self, slot: &TenantSlot) -> Result<Vec<super::admin::FeedSummary>, super::admin::AdminError> {
        let mut tx = self.begin(slot).await.map_err(|e| super::admin::AdminError::Backend(e.to_string()))?;
        let rows = sqlx::query(
            &format!("SELECT id, name, connector, source_slug, spec_sha256, enabled, COALESCE(ingest_url, '') AS ingest_url,
                    CASE WHEN {} THEN 'not_required'
                         WHEN ingest_token_encrypted IS NOT NULL THEN 'ready'
                         WHEN ingest_credential_request_id IS NOT NULL THEN 'pending' ELSE 'none' END AS credential,
                    ingest_credential_error, next_run_at, {} AS last_status, {} AS last_error, last_success_at
               FROM public.connector_feeds WHERE tenant_id = $1 ORDER BY name",
            if self.sink_column { "sink = 'identity'" } else { "FALSE" },
            // NAN-3767: an identity feed awaiting its directory delete.
            if self.delete_columns {
                "CASE WHEN delete_requested_at IS NOT NULL THEN 'deleting' ELSE last_status END"
            } else {
                "last_status"
            },
            if self.delete_columns {
                "CASE WHEN delete_requested_at IS NOT NULL THEN delete_last_error ELSE last_error END"
            } else {
                "last_error"
            },
        ))
        .bind(slot.tenant_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(admin_db)?;
        tx.commit().await.map_err(admin_db)?;
        rows.iter()
            .map(|r| {
                Ok(super::admin::FeedSummary {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    connector: r.try_get("connector")?,
                    source_slug: r.try_get("source_slug")?,
                    spec_sha256: r.try_get("spec_sha256")?,
                    enabled: r.try_get("enabled")?,
                    ingest_url: r.try_get("ingest_url")?,
                    credential: r.try_get("credential")?,
                    credential_error: r.try_get("ingest_credential_error")?,
                    next_run_at: r.try_get("next_run_at")?,
                    last_status: r.try_get("last_status")?,
                    last_error: r.try_get("last_error")?,
                    last_success_at: r.try_get("last_success_at")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(admin_db)
    }

    /// Enable (due now) or disable a feed. A run in flight finishes; its
    /// lease still fences it.
    pub async fn set_enabled(&self, slot: &TenantSlot, feed_id: Uuid, enabled: bool) -> Result<(), super::admin::AdminError> {
        let actor = (!slot.actor_id.is_nil()).then_some(slot.actor_id);
        let mut tx = self.begin(slot).await.map_err(|e| super::admin::AdminError::Backend(e.to_string()))?;
        let n = sqlx::query(
            if self.delete_columns {
                // A feed being deleted cannot be resumed.
                "UPDATE public.connector_feeds
                    SET enabled = $3, next_run_at = CASE WHEN $3 THEN now() ELSE next_run_at END,
                        updated_by = $4, updated_at = now(), revision = revision + 1
                  WHERE tenant_id = $1 AND id = $2 AND delete_requested_at IS NULL"
            } else {
                "UPDATE public.connector_feeds
                    SET enabled = $3, next_run_at = CASE WHEN $3 THEN now() ELSE next_run_at END,
                        updated_by = $4, updated_at = now(), revision = revision + 1
                  WHERE tenant_id = $1 AND id = $2"
            },
        )
        .bind(slot.tenant_id)
        .bind(feed_id)
        .bind(enabled)
        .bind(actor)
        .execute(&mut *tx)
        .await
        .map_err(admin_db)?
        .rows_affected();
        tx.commit().await.map_err(admin_db)?;
        if n == 0 {
            return Err(super::admin::AdminError::FeedNotFound(feed_id));
        }
        tracing::info!(target: "nano_connector::audit",
            feed = %serde_json::json!({ "event": if enabled { "connector_feed_enabled" } else { "connector_feed_disabled" },
                "tenant_id": slot.tenant_id, "feed_id": feed_id, "actor_id": actor }),
            "connector feed");
        Ok(())
    }
}

/// The catalog entry by slug (`marketplace_catalog` is the operator-owned
/// global catalog; on hosted-shared read it with the control pool).
pub async fn read_catalog_entry(pool: &PgPool, slug: &str) -> Result<(Uuid, Value), super::admin::AdminError> {
    let row: Option<(Uuid, Value)> = sqlx::query_as("SELECT id, config FROM public.marketplace_catalog WHERE slug = $1")
        .bind(slug)
        .fetch_optional(pool)
        .await
        .map_err(admin_db)?;
    row.ok_or_else(|| super::admin::AdminError::CatalogNotFound(slug.to_string()))
}

/// Insert or refresh a live-validation mock catalog entry (NAN-3490 item 5).
/// `config` must already have passed `admin::plan_mock_catalog`. The row is a
/// disabled, uninstalled custom collector stamped `admin::MOCK_AUTHOR` both as
/// `author` and as `config.validation_mock`. The config key is the marker the
/// rest of the platform keys on (`nanosiem_core::marketplace::
/// VALIDATION_MOCK_CONFIG_KEY`: the marketplace listings and lookups hide the
/// row, the custom-collector API cannot edit or delete it, a repository sync
/// never overwrites it), and the one this module matches on. An existing row
/// with the slug that is not a marked mock is never overwritten. Returns the
/// entry id. Run with the control pool on hosted-shared.
pub async fn put_mock_catalog_entry(pool: &PgPool, slug: &str, config: &Value) -> Result<Uuid, super::admin::AdminError> {
    use super::admin::{AdminError, MOCK_AUTHOR};
    // Only the keys a connector entry needs, plus the marker; anything else
    // in the operator's file is dropped, not stored.
    let mut stored = serde_json::Map::new();
    for k in ["runtime", "connector_spec", "connector_spec_sha256"] {
        let v = config.get(k).ok_or_else(|| AdminError::InvalidInput(format!("catalog config is missing `{k}`")))?;
        stored.insert(k.into(), v.clone());
    }
    stored.insert("validation_mock".into(), Value::String(MOCK_AUTHOR.into()));
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO public.marketplace_catalog
             (slug, name, description, category, source_type, execution_backend, author, config, enabled, installed)
         VALUES ($1, $1, 'Live-validation mock. Remove after the run.', 'collector', 'custom', 'collector', $2, $3, false, false)
         ON CONFLICT (slug) DO UPDATE SET config = EXCLUDED.config, updated_at = now()
           WHERE marketplace_catalog.source_type = 'custom' AND marketplace_catalog.config->>'validation_mock' = $2
         RETURNING id",
    )
    .bind(slug)
    .bind(MOCK_AUTHOR)
    .bind(Value::Object(stored))
    .fetch_optional(pool)
    .await
    .map_err(|e| AdminError::Backend(format!("marketplace_catalog: {e}")))?;
    id.ok_or_else(|| AdminError::InvalidInput(format!("catalog entry `{slug}` exists and is not a validation mock; refusing to overwrite it")))
}

/// What still points at a catalog entry (nano-red M3, checked before
/// `remove-mock`). Deleting the row cascades into `integration_instances`
/// (FK ON DELETE CASCADE) and silently orphans a feed's provenance
/// (`connector_feeds.catalog_id` has no FK; the feed runs its pinned spec).
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CatalogReferences {
    pub enabled_feeds: i64,
    pub disabled_feeds: i64,
    pub integration_instances: i64,
    /// Tenants looked at (shared: the ones assigned to this runner's worker
    /// identity; dedicated: the whole deployment, reported as 1).
    pub tenants_checked: usize,
}

impl CatalogReferences {
    /// Whether removal must be refused without `--force-with-instances`:
    /// any integration instance (the delete would cascade into it) or any
    /// enabled feed. A disabled feed keeps its pinned spec and is only
    /// reported.
    pub fn blocks_removal(&self) -> bool {
        self.enabled_feeds > 0 || self.integration_instances > 0
    }
}

async fn count_catalog_references(tx: &mut Transaction<'_, Postgres>, catalog_id: Uuid) -> Result<(i64, i64, i64), sqlx::Error> {
    let (enabled, disabled): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE enabled), count(*) FILTER (WHERE NOT enabled)
           FROM public.connector_feeds WHERE catalog_id = $1",
    )
    .bind(catalog_id)
    .fetch_one(&mut **tx)
    .await?;
    // integration_instances is an enterprise table; open core has none.
    let has_instances: bool = sqlx::query_scalar("SELECT to_regclass('public.integration_instances') IS NOT NULL")
        .fetch_one(&mut **tx)
        .await?;
    let instances: i64 = if has_instances {
        sqlx::query_scalar("SELECT count(*) FROM public.integration_instances WHERE catalog_id = $1")
            .bind(catalog_id)
            .fetch_one(&mut **tx)
            .await?
    } else {
        0
    };
    Ok((enabled, disabled, instances))
}

/// Count the feeds and integration instances that reference `catalog_id`.
/// On hosted-shared both tables are FORCE RLS, so every tenant this
/// runner serves is checked in its own signed transaction; a read error
/// refuses (it never counts as zero).
pub async fn catalog_references(tenancy: &Tenancy, catalog_id: Uuid) -> Result<CatalogReferences, super::admin::AdminError> {
    use super::admin::AdminError;
    let backend = |e: sqlx::Error| AdminError::Backend(format!("catalog references: {e}"));
    let mut refs = CatalogReferences::default();
    let mut add = |(e, d, i): (i64, i64, i64)| {
        refs.enabled_feeds += e;
        refs.disabled_feeds += d;
        refs.integration_instances += i;
        refs.tenants_checked += 1;
    };
    match tenancy {
        Tenancy::Dedicated { pool } => {
            let mut tx = pool.begin().await.map_err(backend)?;
            add(count_catalog_references(&mut tx, catalog_id).await.map_err(backend)?);
        }
        #[cfg(feature = "enterprise")]
        Tenancy::Shared { pool, signer, .. } => {
            for slot in tenant_slots(tenancy, false).await.map_err(|e| AdminError::Backend(e.to_string()))? {
                let mut tx = signer.begin_transaction(pool, slot.tenant_id, slot.actor_id).await.map_err(|e| AdminError::Backend(e.to_string()))?;
                add(count_catalog_references(&mut tx, catalog_id).await.map_err(backend)?);
            }
        }
        Tenancy::SignedStatic { pool, signer, .. } => {
            for slot in tenant_slots(tenancy, false).await.map_err(|e| AdminError::Backend(e.to_string()))? {
                let mut tx = signer.begin_transaction(pool, slot.tenant_id, slot.actor_id).await.map_err(|e| AdminError::Backend(e.to_string()))?;
                add(count_catalog_references(&mut tx, catalog_id).await.map_err(backend)?);
            }
        }
    }
    Ok(refs)
}

/// The id of a mock catalog entry this CLI created, if there is one.
pub async fn mock_catalog_id(pool: &PgPool, slug: &str) -> Result<Option<Uuid>, super::admin::AdminError> {
    use super::admin::{AdminError, MOCK_AUTHOR};
    sqlx::query_scalar(
        "SELECT id FROM public.marketplace_catalog
          WHERE slug = $1 AND source_type = 'custom' AND config->>'validation_mock' = $2",
    )
    .bind(slug)
    .bind(MOCK_AUTHOR)
    .fetch_optional(pool)
    .await
    .map_err(|e| AdminError::Backend(format!("marketplace_catalog: {e}")))
}

/// Delete a mock catalog entry this CLI created (slug, marker and custom
/// source must all match). Returns the deleted id. Callers check
/// [`catalog_references`] first.
pub async fn remove_mock_catalog_entry(pool: &PgPool, slug: &str) -> Result<Uuid, super::admin::AdminError> {
    use super::admin::{AdminError, MOCK_AUTHOR};
    let id: Option<Uuid> = sqlx::query_scalar(
        "DELETE FROM public.marketplace_catalog
          WHERE slug = $1 AND source_type = 'custom' AND config->>'validation_mock' = $2
          RETURNING id",
    )
    .bind(slug)
    .bind(MOCK_AUTHOR)
    .fetch_optional(pool)
    .await
    .map_err(|e| AdminError::Backend(format!("marketplace_catalog: {e}")))?;
    id.ok_or_else(|| AdminError::CatalogNotFound(slug.to_string()))
}
