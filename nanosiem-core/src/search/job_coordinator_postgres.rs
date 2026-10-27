// SPDX-License-Identifier: AGPL-3.0-or-later
//! PostgreSQL implementation of the existing typed coordinator protocol. The
//! caller supplies customer-owned runtime authority; no ambient URL or cache.
use super::{
    job_coordinator_client::{
        HostedAssignment, HostedCoordinatorClient, HostedCoordinatorPolicy, HostedCoordinatorRole,
    },
    job_signing::DurableJobSigningKey,
    jobs::DurableJobStoreError,
    tenant::SearchTenantScope,
};
use crate::tenant_db::TenantDbContextSigner;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;
mod state;
use state::Job;

/// Installation-owned configuration, not a public request or an environment
/// selector. The sovereign root derives the epoch from approved C01 facts.
#[derive(Clone)]
pub struct PostgresJobConfig {
    pub installation_id: String,
    pub epoch: String,
    pub tenant: SearchTenantScope,
    pub assignment: HostedAssignment,
    pub policy: HostedCoordinatorPolicy,
    pub result_bucket: String,
    /// Approved installation revision, release, placement and privacy epochs.
    pub authority_epochs: [u64; 4],
}
impl PostgresJobConfig {
    fn validate(&self) -> Result<Uuid, DurableJobStoreError> {
        let tenant = self
            .tenant
            .tenant_id()
            .filter(|id| !id.is_nil())
            .ok_or_else(rejected)?;
        let (retention_revision, retention_days, retention_floor) = self
            .tenant
            .require_retention_identity()
            .map_err(|_| rejected())?;
        if retention_revision <= 0
            || !matches!(retention_days, 30 | 90 | 180 | 365)
            || retention_floor < 0
        {
            return Err(rejected());
        }
        if !identifier(&self.installation_id)
            || !identifier(&self.epoch)
            || self.assignment.entitlement_revision <= 0
            || self.assignment.entitlement_revision > 9_007_199_254_740_991
            || self.assignment.worker_revision == 0
            || self.assignment.worker_revision > 9_007_199_254_740_991
            || self
                .authority_epochs
                .iter()
                .any(|n| *n == 0 || *n > 9_007_199_254_740_991)
            || !(1..=10).contains(&self.policy.max_execution_failures)
            || !(1..=10).contains(&self.policy.max_lease_recoveries)
            || !(3..=63).contains(&self.result_bucket.len())
            || !self
                .result_bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !self.result_bucket.as_bytes()[0].is_ascii_alphanumeric()
            || !self.result_bucket.as_bytes()[self.result_bucket.len() - 1].is_ascii_alphanumeric()
        {
            return Err(rejected());
        }
        Ok(tenant)
    }
    fn binding(&self) -> Result<Vec<u8>, DurableJobStoreError> {
        let tenant = self.validate()?;
        let retention = self
            .tenant
            .require_retention_identity()
            .map_err(|_| rejected())?;
        let bytes = serde_json::to_vec(&json!([
            "sovereign-jobs-v1",
            self.installation_id,
            tenant,
            self.epoch,
            retention,
            self.assignment.entitlement_revision,
            self.assignment.worker_revision,
            self.policy,
            self.result_bucket,
            self.authority_epochs
        ]))
        .map_err(|_| rejected())?;
        Ok(Sha256::digest(bytes).to_vec())
    }
}

/// Bounds customer authority IO even while a namespace transaction is held.
/// This is a protocol deadline, not an operator-configurable runtime switch.
pub const JOB_AUTHORITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Revalidates the caller's current installation/tenant/purpose grant. The
/// sovereign root implements this with C01's consistent authority snapshot.
#[async_trait::async_trait]
pub trait JobNamespaceAuthority: Send + Sync {
    async fn revalidate(&self) -> Result<(), DurableJobStoreError>;
}

/// Commands are crate-private and role scoped. Public users only receive the
/// existing producer/control or execution-only runner interfaces.
pub struct PostgresJobCoordinator {
    pool: PgPool,
    context: Arc<TenantDbContextSigner>,
    actor: Uuid,
    config: PostgresJobConfig,
    tenant: Uuid,
    role: HostedCoordinatorRole,
    key_fingerprint: Vec<u8>,
    authority: Arc<dyn JobNamespaceAuthority>,
}
impl PostgresJobCoordinator {
    pub async fn connect(
        pool: PgPool,
        context: Arc<TenantDbContextSigner>,
        actor: Uuid,
        config: PostgresJobConfig,
        role: HostedCoordinatorRole,
        signer: Arc<DurableJobSigningKey>,
        authority: Arc<dyn JobNamespaceAuthority>,
    ) -> Result<HostedCoordinatorClient, DurableJobStoreError> {
        let tenant = config.validate()?;
        if actor.is_nil() || signer.tenant_id() != tenant {
            return Err(rejected());
        }
        let coordinator = Arc::new(Self {
            pool,
            context,
            actor,
            config: config.clone(),
            tenant,
            role,
            key_fingerprint: signer.verification_fingerprint().to_vec(),
            authority,
        });
        HostedCoordinatorClient::connect_postgres(coordinator, &config, role, signer).await
    }

    /// Installation/control uses the existing execute-only provisioner login.
    /// It receives one narrow namespace CAS function and no tenant table DML.
    pub async fn provision(
        provisioner: &PgPool,
        config: &PostgresJobConfig,
        signer: &DurableJobSigningKey,
    ) -> Result<(), DurableJobStoreError> {
        Self::configure_namespace(provisioner, None, config, signer).await
    }

    /// Lifecycle calls this before exposing replacement C01 authority. The
    /// SQL entrypoint fences old work atomically, and retries its exact receipt.
    pub async fn rotate(
        provisioner: &PgPool,
        expected: &PostgresJobConfig,
        next: &PostgresJobConfig,
        signer: &DurableJobSigningKey,
    ) -> Result<(), DurableJobStoreError> {
        expected.validate()?;
        if next.installation_id != expected.installation_id
            || next.tenant.tenant_id() != expected.tenant.tenant_id()
            || next.epoch == expected.epoch
            || next
                .authority_epochs
                .iter()
                .zip(expected.authority_epochs)
                .any(|(n, e)| *n < e)
            || next.authority_epochs == expected.authority_epochs
        {
            return Err(rejected());
        }
        Self::configure_namespace(provisioner, Some(expected), next, signer).await
    }

    async fn configure_namespace(
        provisioner: &PgPool,
        expected: Option<&PostgresJobConfig>,
        config: &PostgresJobConfig,
        signer: &DurableJobSigningKey,
    ) -> Result<(), DurableJobStoreError> {
        if !cfg!(feature = "enterprise") {
            return Err(DurableJobStoreError::Unsupported);
        }
        let tenant = config.validate()?;
        if tenant != signer.tenant_id() {
            return Err(rejected());
        }
        let binding = config.binding()?;
        let fingerprint = signer.verification_fingerprint().to_vec();
        let receipt: Value = sqlx::query_scalar(
            "SELECT nano_shared.configure_sovereign_job_namespace($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(&config.installation_id)
        .bind(tenant)
        .bind(expected.map(|c| &c.epoch))
        .bind(expected.map(PostgresJobConfig::binding).transpose()?)
        .bind(&config.epoch)
        .bind(&binding)
        .bind(&fingerprint)
        .bind(config.authority_epochs.map(|n| n as i64).to_vec())
        .fetch_one(provisioner)
        .await
        .map_err(unavailable)?;
        if receipt
            != json!({"installation_id":config.installation_id,"tenant_id":tenant,"epoch":config.epoch,
            "binding_sha256":hex::encode(binding),"key_sha256":hex::encode(fingerprint),"authority_epochs":config.authority_epochs})
        {
            return Err(rejected());
        }
        Ok(())
    }

    pub(super) fn result_prefix(&self) -> String {
        format!(
            "s3://{}/{}/{}/{}",
            self.config.result_bucket, self.config.installation_id, self.config.epoch, self.tenant
        )
    }
    pub(super) fn signing_namespace(&self) -> Result<Vec<u8>, DurableJobStoreError> {
        self.config.binding()
    }

    async fn transaction(&self) -> Result<Transaction<'_, Postgres>, DurableJobStoreError> {
        if !cfg!(feature = "enterprise") {
            return Err(DurableJobStoreError::Unsupported);
        }
        tokio::time::timeout(JOB_AUTHORITY_TIMEOUT, self.authority.revalidate())
            .await
            .map_err(|_| unavailable(()))??;
        let mut tx = self
            .context
            .begin_transaction(&self.pool, self.tenant, self.actor)
            .await
            .map_err(|_| unavailable(()))?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query("SET LOCAL statement_timeout='10s'")
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        // One durable transaction lock per installation/tenant, independent of
        // epoch so rotation and old work cannot run concurrently. A hash
        // collision only serializes unrelated namespaces; it confers no access.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "sovereign-jobs:{}:{}",
                self.config.installation_id, self.tenant
            ))
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let row: Option<(String, Vec<u8>, Vec<u8>)> = sqlx::query_as("SELECT epoch,binding_sha256,key_sha256 FROM nano_shared.sovereign_job_namespaces WHERE installation_id=$1 AND tenant_id=$2")
            .bind(&self.config.installation_id).bind(self.tenant).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        if row
            != Some((
                self.config.epoch.clone(),
                self.config.binding()?,
                self.key_fingerprint.clone(),
            ))
        {
            return Err(rejected());
        }
        Ok(tx)
    }

    async fn get(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<Job>, DurableJobStoreError> {
        if !cfg!(feature = "enterprise") {
            return Err(DurableJobStoreError::Unsupported);
        }
        let row: Option<(sqlx::types::Json<Job>,)> = sqlx::query_as("SELECT value FROM nano_shared.sovereign_jobs WHERE installation_id=$1 AND tenant_id=$2 AND epoch=$3 AND id=$4")
            .bind(&self.config.installation_id).bind(self.tenant).bind(&self.config.epoch).bind(id)
            .fetch_optional(&mut **tx).await.map_err(unavailable)?;
        Ok(row.map(|row| row.0.0))
    }

    async fn save(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        job: &Job,
        now: i64,
        kind: &str,
        queue_order: Option<i64>,
    ) -> Result<(), DurableJobStoreError> {
        if !cfg!(feature = "enterprise") {
            return Err(DurableJobStoreError::Unsupported);
        }
        job.validate()?;
        sqlx::query("INSERT INTO nano_shared.sovereign_jobs(installation_id,tenant_id,epoch,id,status,created,expires,queue_order,small,value,deadline) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$6+86400000) ON CONFLICT(installation_id,tenant_id,epoch,id) DO UPDATE SET status=EXCLUDED.status,expires=EXCLUDED.expires,value=EXCLUDED.value,queue_order=COALESCE($11,sovereign_jobs.queue_order)")
            .bind(&self.config.installation_id).bind(self.tenant).bind(&self.config.epoch).bind(job.id)
            .bind(&job.status).bind(job.created).bind(job.expires).bind(queue_order.unwrap_or(job.created))
            .bind(job.small()).bind(sqlx::types::Json(job)).bind(queue_order)
            .execute(&mut **tx).await.map_err(unavailable)?;
        sqlx::query("INSERT INTO nano_shared.sovereign_job_events(installation_id,tenant_id,epoch,job_id,attempt,fence,kind,observed_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&self.config.installation_id).bind(self.tenant).bind(&self.config.epoch).bind(job.id)
            .bind(i64::from(job.attempt)).bind(job.fence as i64).bind(kind).bind(now)
            .execute(&mut **tx).await.map_err(unavailable)?;
        Ok(())
    }

    async fn recover(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        now: i64,
    ) -> Result<usize, DurableJobStoreError> {
        if !cfg!(feature = "enterprise") {
            return Err(DurableJobStoreError::Unsupported);
        }
        let rows: Vec<(sqlx::types::Json<Job>,)> = sqlx::query_as("SELECT value FROM nano_shared.sovereign_jobs WHERE installation_id=$1 AND tenant_id=$2 AND epoch=$3 AND ((status='running' AND expires<=$4) OR (status IN('running','queued') AND deadline<=$4)) ORDER BY deadline,expires,id LIMIT 100")
            .bind(&self.config.installation_id).bind(self.tenant).bind(&self.config.epoch).bind(now)
            .fetch_all(&mut **tx).await.map_err(unavailable)?;
        let count = rows.len();
        for (sqlx::types::Json(mut job),) in rows {
            job.expire(now, self.config.policy)?;
            self.save(tx, &job, now, "lease_expired", None).await?;
        }
        Ok(count)
    }

    pub(super) async fn execute(&self, command: &Value) -> Result<Value, DurableJobStoreError> {
        if !cfg!(feature = "enterprise") {
            return Err(DurableJobStoreError::Unsupported);
        }
        let op = command["op"].as_str().ok_or_else(rejected)?;
        if command["epoch"].as_str() != Some(&self.config.epoch) {
            return Err(rejected());
        }
        let allowed = match self.role {
            HostedCoordinatorRole::Producer => {
                matches!(op, "describe" | "submit" | "get" | "list_page" | "cancel")
            }
            HostedCoordinatorRole::Runner => matches!(
                op,
                "describe"
                    | "claim"
                    | "renew"
                    | "progress"
                    | "complete"
                    | "fail"
                    | "cancel_claim"
                    | "release_claim"
                    | "reconcile"
            ),
        };
        if !allowed {
            return Err(rejected());
        }
        let mut tx = self.transaction().await?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
                .fetch_one(&mut *tx)
                .await
                .map_err(unavailable)?;
        // Carry the pre-mutation lease across the final external authority IO.
        // Renew/complete must not commit on a lease that expired during that wait.
        let mut valid_until = None;
        let result = match op {
            "describe" => {
                json!({"tenant":self.tenant,"epoch":self.config.epoch,"role":self.role,"policy":self.config.policy})
            }
            "get" => serde_json::to_value(self.get(&mut tx, job_id(command)?).await?)
                .map_err(|_| rejected())?,
            "list_page" => self.page(&mut tx, command).await?,
            "reconcile" => json!(self.recover(&mut tx, now).await?),
            "claim" => {
                self.recover(&mut tx, now).await?;
                let claimed = self.claim(&mut tx, command, now).await?;
                if !claimed.is_null() {
                    valid_until = Some(claimed["expires"].as_i64().ok_or_else(rejected)?);
                }
                claimed
            }
            "submit" => {
                let id = job_id(command)?;
                let payload = command["payload"]
                    .as_str()
                    .filter(|p| p.len() <= 65_536)
                    .ok_or_else(rejected)?;
                if let Some(job) = self.get(&mut tx, id).await? {
                    if job.payload != payload {
                        return Err(rejected());
                    }
                    json!(job)
                } else {
                    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM nano_shared.sovereign_jobs WHERE installation_id=$1 AND tenant_id=$2 AND epoch=$3 AND status IN('queued','running')")
                        .bind(&self.config.installation_id).bind(self.tenant).bind(&self.config.epoch).fetch_one(&mut *tx).await.map_err(unavailable)?;
                    if count >= 1000 {
                        return Err(rejected());
                    }
                    let job = Job::queued(id, payload.to_owned(), now);
                    self.save(&mut tx, &job, now, op, None).await?;
                    json!(job)
                }
            }
            _ => {
                if let Some(mut job) = self.get(&mut tx, job_id(command)?).await? {
                    let before = job.clone();
                    let accepted = job.transition(command, now, self.config.policy)?;
                    if accepted && op != "cancel" && before.status == "running" {
                        valid_until = Some(
                            before
                                .expires
                                .ok_or_else(rejected)?
                                .min(before.created + state::DEADLINE_MS),
                        );
                    }
                    if job != before {
                        self.save(
                            &mut tx,
                            &job,
                            now,
                            op,
                            if op == "release_claim" {
                                Some(now)
                            } else {
                                None
                            },
                        )
                        .await?;
                    }
                    json!(accepted)
                } else {
                    json!(false)
                }
            }
        };
        tokio::time::timeout(JOB_AUTHORITY_TIMEOUT, self.authority.revalidate())
            .await
            .map_err(|_| unavailable(()))??;
        if let Some(deadline) = valid_until {
            let fresh_now: i64 = sqlx::query_scalar(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
            if fresh_now >= deadline {
                return Err(rejected());
            }
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(result)
    }

    async fn claim(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        command: &Value,
        now: i64,
    ) -> Result<Value, DurableJobStoreError> {
        if !cfg!(feature = "enterprise") {
            return Err(DurableJobStoreError::Unsupported);
        }
        let owner = command["owner"]
            .as_str()
            .filter(|o| identifier(o))
            .ok_or_else(rejected)?;
        let lease = state::lease(command, now)?;
        let small = match command.get("lane") {
            None => false,
            Some(v) if v == "small" => true,
            _ => return Err(rejected()),
        };
        let existing: Option<(sqlx::types::Json<Job>,)> = sqlx::query_as("SELECT value FROM nano_shared.sovereign_jobs WHERE installation_id=$1 AND tenant_id=$2 AND epoch=$3 AND status='running' AND value->>'owner'=$4 AND expires>$5 LIMIT 1")
            .bind(&self.config.installation_id).bind(self.tenant).bind(&self.config.epoch).bind(owner).bind(now)
            .fetch_optional(&mut **tx).await.map_err(unavailable)?;
        if let Some((job,)) = existing {
            // An owner may have only one live claim. A repeated small-lane poll
            // cannot return its larger claim or acquire a second small job.
            return Ok(if small && !job.0.small() {
                Value::Null
            } else {
                json!(job.0)
            });
        }
        let row: Option<(sqlx::types::Json<Job>,)> = sqlx::query_as("SELECT value FROM nano_shared.sovereign_jobs WHERE installation_id=$1 AND tenant_id=$2 AND epoch=$3 AND status='queued' AND (NOT $4 OR (small AND value->>'resource_class'<>'large')) ORDER BY queue_order,id LIMIT 1")
            .bind(&self.config.installation_id).bind(self.tenant).bind(&self.config.epoch).bind(small)
            .fetch_optional(&mut **tx).await.map_err(unavailable)?;
        let Some((sqlx::types::Json(mut job),)) = row else {
            return Ok(Value::Null);
        };
        job.claim(owner, lease)?;
        self.save(tx, &job, now, "claim", None).await?;
        Ok(json!(job))
    }

    async fn page(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        command: &Value,
    ) -> Result<Value, DurableJobStoreError> {
        if !cfg!(feature = "enterprise") {
            return Err(DurableJobStoreError::Unsupported);
        }
        let limit = command["limit"]
            .as_i64()
            .filter(|n| (1..=25).contains(n))
            .ok_or_else(rejected)?;
        let after = command.get("after").ok_or_else(rejected)?;
        let (created, id) = if after.is_null() {
            (None, None)
        } else {
            (
                Some(
                    after["created"]
                        .as_i64()
                        .filter(|n| *n > 0)
                        .ok_or_else(rejected)?,
                ),
                Some(job_id(&json!({"job_id":after["id"]}))?),
            )
        };
        let rows: Vec<(sqlx::types::Json<Job>,)> = sqlx::query_as("SELECT value FROM nano_shared.sovereign_jobs WHERE installation_id=$1 AND tenant_id=$2 AND epoch=$3 AND ($4::bigint IS NULL OR (created,id)<($4,$5::uuid)) ORDER BY created DESC,id DESC LIMIT $6")
            .bind(&self.config.installation_id).bind(self.tenant).bind(&self.config.epoch).bind(created).bind(id).bind(limit+1)
            .fetch_all(&mut **tx).await.map_err(unavailable)?;
        let mut selected = Vec::new();
        for (sqlx::types::Json(job),) in &rows {
            if selected.len() == limit as usize {
                break;
            }
            let total = serde_json::to_vec(&selected).map_err(|_| rejected())?.len()
                + serde_json::to_vec(job).map_err(|_| rejected())?.len();
            if total > 140_000 {
                break;
            }
            selected.push(job);
        }
        if !rows.is_empty() && selected.is_empty() {
            return Err(rejected());
        }
        let next = if selected.len() < rows.len() {
            selected
                .last()
                .map(|j| json!({"created":j.created,"id":j.id}))
        } else {
            None
        };
        Ok(json!({"jobs":selected,"next":next}))
    }
}
fn job_id(command: &Value) -> Result<Uuid, DurableJobStoreError> {
    command["job_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .filter(|id| !id.is_nil())
        .ok_or_else(rejected)
}
fn identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn rejected() -> DurableJobStoreError {
    DurableJobStoreError::ClaimRejected
}
fn unavailable<T>(_: T) -> DurableJobStoreError {
    // SQL diagnostics may carry signed envelopes, raw queries or credentials.
    DurableJobStoreError::Unavailable("PostgreSQL job authority unavailable".into())
}
