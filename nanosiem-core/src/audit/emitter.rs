// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit Event Emitter
//!
//! Writes audit events directly to ClickHouse for searchability.

use crate::request_timing::RequestDb;

use chrono::Utc;

use super::AuditEvent;
use crate::db::DualPool;
use crate::ingestion::ClickHouseLogRow;

/// Audit event emitter for storing platform audit events
///
/// This writes audit events directly to ClickHouse as searchable logs
/// with source_type='audit'.
///
/// The UDM row always goes to the cluster-aware UDM logs table
/// (`DualPool::logs_table()`): the audit *page* reads that table under both
/// schema profiles (`audit/query.rs`), so it is the canonical audit store.
/// Under the OCSF profile an OCSF mirror row (API Activity 6003, or
/// Authentication 3002 / Account Change 3001 for IAM actions — NAN-3460) is
/// additionally written to the profile's `ocsf_logs` table so AUDIT_VIEW
/// principals can find audit events from the search bar, which reads
/// `ocsf_logs` under OCSF (NAN-1390 / G16).
pub struct AuditEmitter {
    dual_pool: DualPool,
    /// Whether the active schema profile is OCSF (resolved once at
    /// construction; the profile is boot-fixed env config). Drives the
    /// `ocsf_logs` mirror write.
    mirror_to_ocsf: bool,
    /// Primary-lake deployments keep platform audit in the PostgreSQL control
    /// plane. Customer event Parquet remains OCSF-only and no compatibility
    /// ClickHouse insert sits on the request/detection critical path.
    lake_mode: bool,
    #[cfg(feature = "enterprise")]
    enterprise_shared: bool,
}

/// Process-global backstop bound on concurrent audit ClickHouse inserts
/// (NAN-1625). EVERY audit insert — whether dispatched by the API layer
/// (`AppState::emit_audit`) or issued by a DIRECT caller that holds its own
/// `AuditEmitter` (the health scheduler, the disk-pressure monitor, …) — funnels
/// through [`AuditEmitter::emit_batch_inner`], which acquires a permit here. That
/// makes the whole audit subsystem provably bounded with no bypass: at most this
/// many audit inserts hit ClickHouse concurrently, regardless of caller. It is a
/// `static` (not a struct field) precisely because direct callers each construct
/// their own emitter — a per-instance bound would not be global.
///
/// Sized well above the API-layer caps (`DURABLE_AUDIT_INSERTS` 12 +
/// `ROUTINE_AUDIT_INSERTS` 64 = 76) so it never throttles the normal dispatch
/// path; it is the ceiling that also covers the low-volume direct callers.
static AUDIT_INSERT_BOUND: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(128);

/// Backstop timeout for a single audit insert at the emitter level. Generous on
/// purpose — API callers wrap their own tighter 4s/5s bounds on top of this; the
/// backstop only exists so a slow/unresponsive ClickHouse can never hold a permit
/// (or block a direct caller's background loop) indefinitely.
const AUDIT_INSERT_BACKSTOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Record an audit event (or batch) not confirmed by the emitter-level backstop —
/// Logs do not prove the associated mutation committed and must never be
/// replayed as success without independent commit evidence. Logs the event and
/// increments the shared
/// `nanosiem_audit_emit_failures_total{action, critical, reason}` counter.
/// `reason` is `emitter_saturated` (concurrency bound full) or `emitter_timeout`
/// (insert exceeded the backstop timeout).
fn record_unconfirmed(events: &[AuditEvent], durable: bool, reason: &'static str) {
    for event in events {
        let event_json =
            serde_json::to_string(event).unwrap_or_else(|_| "<unserializable>".to_string());
        tracing::error!(
            source = %event.source,
            action = %event.action,
            reason = %reason,
            event = %event_json,
            "Audit persistence unconfirmed; retained event is diagnostic evidence, not a commit receipt",
        );
        metrics::counter!(
            "nanosiem_audit_emit_failures_total",
            "action" => event.action.clone(),
            "critical" => if durable { "true" } else { "false" },
            "reason" => reason,
        )
        .increment(1);
    }
}

impl AuditEmitter {
    /// Create a new audit emitter with DualPool for ClickHouse storage
    pub fn new(dual_pool: DualPool) -> Self {
        let mirror_to_ocsf = crate::schema::active_profile_from_env()
            .map(|p| p.id() == crate::schema::SchemaId::Ocsf)
            // A malformed profile env fails boot before this (NAN-800
            // fail-fast); defaulting UDM here just keeps audit emission alive
            // no matter what.
            .unwrap_or(false);
        let lake_mode = crate::schema::log_query_backend_is_lake();
        Self {
            dual_pool,
            mirror_to_ocsf,
            lake_mode,
            #[cfg(feature = "enterprise")]
            enterprise_shared: std::env::var("DEPLOYMENT_MODE")
                .is_ok_and(|mode| mode == "enterprise_shared"),
        }
    }

    /// Emit an audit event to ClickHouse (default fire-and-forget async-insert
    /// semantics — see [`Self::emit_durable`] for the synchronous variant).
    pub async fn emit(&self, event: &AuditEvent) -> Result<(), AuditEmitError> {
        self.emit_batch(std::slice::from_ref(event)).await?;

        tracing::debug!(
            source = %event.source,
            action = %event.action,
            "Emitted audit event"
        );

        Ok(())
    }

    /// Emit a single audit event **durably** (NAN-1625).
    ///
    /// Unlike [`Self::emit`], this forces a *synchronous* ClickHouse write:
    /// `async_insert=0` disables server-side insert buffering and
    /// `wait_end_of_query=1` holds the HTTP response until the data has been
    /// flushed to a part. Awaiting this call therefore genuinely guarantees the
    /// row landed on disk.
    ///
    /// This is the key correctness point: under the *default* async-insert
    /// path, ClickHouse acks on **receipt**, not flush (which is also why
    /// `written_rows` is always 0), so merely awaiting `emit` does NOT prove
    /// durability. Only `emit_durable` does.
    ///
    /// Reserved for the low-volume, non-floodable security actions in
    /// [`crate::audit::SECURITY_CRITICAL_ACTIONS`]; routine events keep the
    /// cheaper async-insert path.
    pub async fn emit_durable(&self, event: &AuditEvent) -> Result<(), AuditEmitError> {
        self.emit_batch_inner(std::slice::from_ref(event), true)
            .await?;

        tracing::debug!(
            source = %event.source,
            action = %event.action,
            "Emitted audit event (durable, synchronous insert)"
        );

        Ok(())
    }

    /// Emit multiple audit events in a batch (async-insert / fire-and-forget).
    pub async fn emit_batch(&self, events: &[AuditEvent]) -> Result<(), AuditEmitError> {
        self.emit_batch_inner(events, false).await
    }

    /// Shared batch-insert entry point — applies the emitter-level global
    /// concurrency backstop ([`AUDIT_INSERT_BOUND`]) + timeout
    /// ([`AUDIT_INSERT_BACKSTOP_TIMEOUT`]) around every audit insert, then
    /// delegates to [`Self::perform_insert`]. This is the single chokepoint all
    /// three public entry points (`emit`, `emit_batch`, `emit_durable`) funnel
    /// through, so no caller can issue an unbounded audit insert.
    ///
    /// Saturation and timeout are reported as errors, with a recovery log and
    /// metric. A caller awaiting durability must never mistake a dropped or
    /// indeterminate insert for a committed event.
    async fn emit_batch_inner(
        &self,
        events: &[AuditEvent],
        durable: bool,
    ) -> Result<(), AuditEmitError> {
        if events.is_empty() {
            return Ok(());
        }

        bounded_audit_insert(
            &AUDIT_INSERT_BOUND,
            AUDIT_INSERT_BACKSTOP_TIMEOUT,
            events,
            durable,
            self.perform_insert(events, durable),
        )
        .await
    }

    /// Perform the actual ClickHouse insert(s) for a batch.
    ///
    /// When `durable` is true, both the UDM insert and the OCSF mirror write go
    /// through a client cloned with synchronous-write options
    /// (`async_insert=0` + `wait_end_of_query=1`) so the await blocks until the
    /// write is flushed. When false (routine events), the client is cloned with
    /// fire-and-forget options (`async_insert=1` + `wait_for_async_insert=0`) so
    /// the write ACKs on receipt and never blocks on the `logs` materialized-
    /// column + MV cascade (NAN-1724).
    ///
    /// Callers reach this only via [`Self::emit_batch_inner`], which holds the
    /// [`AUDIT_INSERT_BOUND`] permit and applies the backstop timeout.
    async fn perform_insert(
        &self,
        events: &[AuditEvent],
        durable: bool,
    ) -> Result<(), AuditEmitError> {
        let ingest_time = Utc::now();

        if self.lake_mode {
            return self.perform_postgres_insert(events).await;
        }

        // Convert all events to ClickHouse rows
        let rows: Vec<ClickHouseLogRow> = events
            .iter()
            .map(|e| {
                let parsed_log = e.to_parsed_log();
                ClickHouseLogRow::from_parsed_log(&parsed_log, ingest_time)
            })
            .collect();

        // Insert into the cluster-aware UDM logs table ("logs_distributed" on
        // clustered deployments, "logs" otherwise) — previously hardcoded
        // "logs", which wrote to the local shard only under clustering.
        //
        // For the durable path, clone the client with synchronous-write options
        // so the insert (and the OCSF mirror write below) genuinely block until
        // the row is flushed to a part rather than merely received (NAN-1625).
        // The options are HTTP query params applied to every request the client
        // makes, so both writes inherit them.
        //
        // NAN-1724: the NON-durable (routine) path must be genuinely
        // fire-and-forget. The ambient `dual_pool.clickhouse()` sets no
        // async_insert option and the server default is `async_insert=0`, so the
        // "async" routine path was in fact a SYNCHRONOUS insert — it blocked on
        // the `logs` table's ~79 MATERIALIZED-column (dictGet) computation + ~13
        // MVs + the OCSF mirror write, and under CH load intermittently exceeded
        // the caller's timeout (`ASYNC_AUDIT_EMIT_TIMEOUT`). Setting
        // `async_insert=1, wait_for_async_insert=0` makes ClickHouse buffer the
        // row and ACK on receipt (the materialized-column + MV work runs in the
        // background on flush), so a routine audit write can never block on that
        // cascade. Routine events tolerate this fire-and-forget contract (the
        // path already drops under extreme pressure); security-critical events
        // use the durable branch above, which stays fully synchronous.
        let write_client;
        let client = if durable {
            let mut c = self
                .dual_pool
                .clickhouse()
                .clone()
                .with_option("async_insert", "0")
                .with_option("wait_end_of_query", "1");
            // NAN-1728 (H7): on a clustered deployment the durable insert targets
            // `logs_distributed`. With the default `insert_distributed_sync=0` the
            // ACK only means "queued in the receiving node's `.bin` distribution
            // send buffer", NOT committed on a shard — so an acked security-audit
            // event can be lost if that node dies before the buffer forwards,
            // breaking the NAN-1625 durability contract. `insert_distributed_sync=1`
            // makes the write block until the row is committed on the target shard,
            // so the ACK means durable. No-op on single-node: `is_clustered()` is
            // false there and the write goes to the local `logs` MergeTree (not a
            // Distributed table), so the emitted request is byte-identical.
            if self.dual_pool.is_clustered() {
                c = c.with_option("insert_distributed_sync", "1");
            }
            write_client = c;
            &write_client
        } else {
            write_client = self
                .dual_pool
                .clickhouse()
                .clone()
                .with_option("async_insert", "1")
                .with_option("wait_for_async_insert", "0");
            &write_client
        };
        let mut insert = client
            .insert::<ClickHouseLogRow>(self.dual_pool.logs_table())
            .await
            .map_err(|e| AuditEmitError::Storage(e.to_string()))?;

        for row in &rows {
            insert
                .write(row)
                .await
                .map_err(|e| AuditEmitError::Storage(e.to_string()))?;
        }

        insert
            .end()
            .await
            .map_err(|e| AuditEmitError::Storage(e.to_string()))?;

        // Under the OCSF profile, mirror each event into `ocsf_logs` as an
        // OCSF API Activity (6003) record so the search bar — which reads
        // `ocsf_logs` under OCSF — can surface audit events to AUDIT_VIEW
        // principals (NAN-1390 / G16). Same write contract as the NAN-1254
        // Detection Finding writer: `event` JSON + explicit `timestamp`
        // (DateTime64(3) ← millis) + operational `source_type`; `id` and
        // `_inserted_at` are server-defaulted, everything else derives from
        // `event`. NAN-1443: write into the `ocsf_logs_raw` ENGINE=Null landing
        // table — the `ocsf_logs_raw_mv` MV derives the stored row into
        // `ocsf_logs` (which no longer stores `event`). Always the local table:
        // a Null landing table has no distributed wrapper.
        if self.mirror_to_ocsf {
            let ocsf_table = self.dual_pool.table_names().local("ocsf_logs_raw");
            let placeholders = vec!["(?, ?, 'audit')"; events.len()].join(", ");
            let ocsf_query = format!(
                "INSERT INTO {} (event, timestamp, source_type) VALUES {}",
                ocsf_table, placeholders
            );
            let mut query = client.query(&ocsf_query);
            for event in events {
                query = query
                    .bind(event.to_ocsf_event(ingest_time).to_string())
                    .bind(ingest_time.timestamp_millis());
            }
            query
                .execute().request_db()
                .await
                .map_err(|e| AuditEmitError::Storage(e.to_string()))?;
        }

        tracing::debug!(count = events.len(), "Emitted batch of audit events");

        Ok(())
    }

    async fn perform_postgres_insert(
        &self,
        events: &[AuditEvent],
    ) -> Result<(), AuditEmitError> {
        #[cfg(feature = "enterprise")]
        if self.enterprise_shared {
            return Err(AuditEmitError::TenantContextRequired);
        }
        let tenant_id = std::env::var("NANO_LAKE_TENANT_ID")
            .unwrap_or_default()
            .trim()
            .to_string();
        if tenant_id.is_empty() {
            return Err(AuditEmitError::Storage(
                "NANO_LAKE_TENANT_ID is required for lake audit publication".to_string(),
            ));
        }
        let mut transaction = self
            .dual_pool
            .postgres()
            .begin().request_db()
            .await
            .map_err(|error| AuditEmitError::Storage(error.to_string()))?;

        for event in events {
            persist_postgres_audit_event(&mut transaction, event, &tenant_id).await?;
        }

        transaction
            .commit().request_db()
            .await
            .map_err(|error| AuditEmitError::Storage(error.to_string()))?;
        tracing::debug!(count = events.len(), "Emitted PostgreSQL audit batch");
        Ok(())
    }
}

/// Append to the existing lake audit outbox through the exact execute-only
/// capability. The signed transaction binds tenant and actor; the caller must
/// commit its security mutation and this event together before returning success.
pub async fn append_tenant_audit_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &crate::auth::TrustedTenantContext,
    event: &AuditEvent,
) -> Result<(), AuditEmitError> {
    if tenant.tenant_id.is_nil() || event.actor_id.is_none_or(|actor| actor.is_nil()) {
        return Err(AuditEmitError::TenantContextRequired);
    }
    bounded_audit_insert(
        &AUDIT_INSERT_BOUND,
        AUDIT_INSERT_BACKSTOP_TIMEOUT,
        std::slice::from_ref(event),
        true,
        async {
            let authorized: bool = sqlx::query_scalar(
                "SELECT nano_shared.current_tenant_id() = $1 \
                 AND current_setting('nano_shared.actor_id')::uuid = $2",
            )
            .bind(tenant.tenant_id)
            .bind(event.actor_id)
            .fetch_one(&mut **transaction).request_db()
            .await
            .map_err(|error| retryable_database_or(error, |_| AuditEmitError::TenantContextRequired))?;
            if !authorized {
                return Err(AuditEmitError::TenantContextRequired);
            }
            bind_postgres_audit(
                "SELECT nano_shared.append_tenant_audit($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
                event, &tenant.tenant_id.to_string(),
            ).execute(&mut **transaction).request_db().await
                .map_err(|error| retryable_database_or(error, |error| AuditEmitError::Storage(error.to_string())))?;
            Ok(())
        },
    ).await
}

/// Append a bounded batch through the existing execute-only audit capability.
/// One database round trip preserves the same signed tenant/actor checks,
/// canonical event rendering, immutable retry identity and emitter deadline.
pub async fn append_tenant_audit_batch_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &crate::auth::TrustedTenantContext,
    events: &[AuditEvent],
) -> Result<(), AuditEmitError> {
    if events.is_empty() {
        return Ok(());
    }
    if events.len() > 5_000 {
        return Err(AuditEmitError::InvalidBatch);
    }
    let actor = events[0].actor_id;
    if tenant.tenant_id.is_nil() || actor.is_none_or(|id| id.is_nil())
        || events.iter().any(|event| event.actor_id != actor)
    {
        return Err(AuditEmitError::TenantContextRequired);
    }
    let tenant_id = tenant.tenant_id.to_string();
    let mut payload = Vec::with_capacity(events.len());
    let mut bytes = 0usize;
    for event in events {
        // Match SQLx's microsecond timestamp precision. PostgreSQL rounds
        // finer JSON text timestamps, which could cross an OCSF millisecond.
        let time = chrono::DateTime::from_timestamp_micros(event.occurred_at().timestamp_micros())
            .ok_or(AuditEmitError::InvalidBatch)?;
        let row = serde_json::json!({
            "event_id": event.event_id(),
            "occurred_at": time,
            "actor_id": event.actor_id, "actor_name": event.actor_name,
            "api_key_id": event.api_key_id, "api_key_name": event.api_key_name,
            "action": event.action, "source": event.source.to_string(),
            "resource_type": event.resource_type, "resource_id": event.resource_id,
            "resource_name": event.resource_name, "ip_address": event.ip_address,
            "user_agent": event.user_agent, "success": event.success,
            "status": if event.success { "success" } else { "failure" },
            "message": event.build_message(), "metadata": postgres_audit_metadata(event),
            "ocsf_event": event.to_ocsf_event_for_lake(
                time, event.event_id(), &tenant_id),
        });
        let row_bytes = serde_json::to_vec(&row).map_err(|_| AuditEmitError::InvalidBatch)?.len();
        bytes = bytes.saturating_add(row_bytes);
        if row_bytes > 262_144 || bytes > 16 * 1024 * 1024 {
            return Err(AuditEmitError::InvalidBatch);
        }
        payload.push(row);
    }
    bounded_audit_insert(&AUDIT_INSERT_BOUND, AUDIT_INSERT_BACKSTOP_TIMEOUT, events, true, async {
        sqlx::query(r#"
            SELECT nano_shared.append_tenant_audit(
                e.event_id,$1,e.ocsf_event,e.occurred_at,e.actor_id,e.actor_name,
                e.api_key_id,e.api_key_name,e.action,e.source,e.resource_type,e.resource_id,
                e.resource_name,e.ip_address,e.user_agent,e.success,e.status,e.message,e.metadata)
              FROM jsonb_to_recordset($2::jsonb) AS e(
                event_id uuid,occurred_at timestamptz,actor_id uuid,actor_name text,
                api_key_id uuid,api_key_name text,action text,source text,resource_type text,
                resource_id uuid,resource_name text,ip_address text,user_agent text,
                success boolean,status text,message text,metadata jsonb,ocsf_event jsonb)
        "#).bind(&tenant_id).bind(serde_json::Value::Array(payload))
            .execute(&mut **transaction).request_db().await
            .map_err(|error| retryable_database_or(error, |error| AuditEmitError::Storage(error.to_string())))?;
        Ok(())
    }).await
}

/// NAN-3790: actorless pre-authentication auth audit (login failure, lockout,
/// password-reset request/completion) into one tenant, through the closed
/// `nano_shared.append_tenant_preauth_audit` definer (9013575). There is no
/// verified actor to sign a tenant transaction as; the definer pins the
/// source, the action set, an absent actor/key/resource id and an active
/// tenant. Bounded by the same global audit concurrency cap as every insert,
/// so an attacker-driven failure flood degrades to a loud drop, never a pool
/// exhaustion.
#[cfg(feature = "enterprise")]
pub(crate) async fn append_tenant_preauth_audit(
    pool: &sqlx::PgPool,
    tenant_id: uuid::Uuid,
    event: &AuditEvent,
) -> Result<(), AuditEmitError> {
    if tenant_id.is_nil() || event.actor_id.is_some() || event.api_key_id.is_some() {
        return Err(AuditEmitError::TenantContextRequired);
    }
    let tenant = tenant_id.to_string();
    bounded_audit_insert(
        &AUDIT_INSERT_BOUND,
        AUDIT_INSERT_BACKSTOP_TIMEOUT,
        std::slice::from_ref(event),
        true,
        async {
            bind_postgres_audit(
                "SELECT nano_shared.append_tenant_preauth_audit($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
                event, &tenant,
            ).execute(pool).request_db().await
                .map_err(|error| AuditEmitError::Storage(error.to_string()))?;
            Ok(())
        },
    ).await
}

/// Keep the SQLSTATE of a transient conflict (serialization failure,
/// deadlock, lock timeout) so a caller that owns the transaction can retry it
/// in a fresh one; every other failure keeps its existing bounded shape.
fn retryable_database_or(
    error: sqlx::Error,
    otherwise: impl FnOnce(sqlx::Error) -> AuditEmitError,
) -> AuditEmitError {
    let retryable = error
        .as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|code| matches!(code.as_ref(), "40001" | "40P01" | "55P03"));
    if retryable {
        AuditEmitError::Database(error)
    } else {
        otherwise(error)
    }
}

/// Mirror a specific immutable control-plane ledger row. This is intentionally
/// crate-private and accepts no caller-supplied tenant, actor, or event payload.
/// The source row and the outbox commit together with the key mutation/decision.
#[cfg(feature = "enterprise")]
pub(crate) async fn mirror_automation_key_audit_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event_id: uuid::Uuid,
) -> Result<(), AuditEmitError> {
    bounded_audit_insert(&AUDIT_INSERT_BOUND, AUDIT_INSERT_BACKSTOP_TIMEOUT,
        &[], true, async {
            sqlx::query("SELECT nano_shared.mirror_automation_key_audit($1)")
                .bind(event_id).execute(&mut **transaction).request_db().await
                .map_err(AuditEmitError::Database)?;
            Ok(())
        },
    ).await
}

/// Dedicated security mutations publish their audit outbox row atomically.
/// Shared callers must use the signed tenant capability instead.
pub async fn append_dedicated_audit_in_transaction(
    transaction: &mut sqlx::Transaction<'_,sqlx::Postgres>,
    tenant: uuid::Uuid,
    event: &AuditEvent,
) -> Result<(),AuditEmitError> {
    persist_postgres_audit_event(transaction,event,&tenant.to_string()).await
}

/// Persist one pre-identified event in the caller's transaction. No commit is
/// performed here: mutation repositories can commit their change and outbox
/// atomically. The caller must install its database tenant authority first.
async fn persist_postgres_audit_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event: &AuditEvent,
    tenant_id: &str,
) -> Result<(), AuditEmitError> {
    let inserted = bind_postgres_audit(
        "INSERT INTO platform_audit_events \
         (event_id, tenant_id, ocsf_event, occurred_at, actor_id, actor_name, api_key_id, api_key_name, action, source, \
          resource_type, resource_id, resource_name, ip_address, user_agent, success, status, message, metadata) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) \
         ON CONFLICT (event_id) DO NOTHING",
        event, tenant_id,
    ).execute(&mut **transaction).request_db().await
        .map_err(|error| AuditEmitError::Storage(error.to_string()))?;
    if inserted.rows_affected() == 1 {
        return Ok(());
    }
    // Separate statement obtains a new READ COMMITTED snapshot after waiting
    // on a concurrent inserter. Compare the stable identity of what happened
    // (RETRY_IDENTITY_MATCHES); publication acknowledgments are deliberately
    // excluded and never reset by a retry.
    let existing = bind_postgres_audit(RETRY_IDENTITY_MATCHES, event, tenant_id).fetch_optional(&mut **transaction).request_db().await
        .map_err(|error| AuditEmitError::Storage(error.to_string()))?;
    use sqlx::Row;
    if existing.is_some_and(|row| row.get::<bool, _>("matches")) {
        Ok(())
    } else {
        Err(AuditEmitError::IdentityConflict)
    }
}

/// Retry identity of a stored audit event (NAN-3227): who did what to which
/// resource, when, from where, with which outcome and details. The derived
/// columns — `ocsf_event`, `message`, the `metadata` envelope — and display
/// names are excluded: a write first attempted under one OCSF mapping and
/// retried after a deploy that changed the mapping (or started resolving
/// actor names) is the same event, and the first committed row stays
/// canonical. Changing the action, outcome, resource, actor, key, tenant,
/// time, client or details is still an `IdentityConflict`. Same contract as
/// the shared `nano_shared.append_tenant_audit` (9011300, 9012100).
const RETRY_IDENTITY_MATCHES: &str =
    "SELECT ROW(tenant_id, occurred_at, actor_id, api_key_id, action, source, resource_type, \
       resource_id, ip_address, user_agent, success, status, metadata->'details') \
     IS NOT DISTINCT FROM ROW($2, $4, $5, $7, $9, $10, $11, $12, $14, $15, $16, $17, $19::jsonb->'details') \
     AS matches FROM platform_audit_events WHERE event_id = $1";

fn bind_postgres_audit<'a>(
    statement: &'a str,
    event: &'a AuditEvent,
    tenant_id: &'a str,
) -> sqlx::query::Query<'a, sqlx::Postgres, sqlx::postgres::PgArguments> {
    let metadata = postgres_audit_metadata(event);
    sqlx::query(statement)
        .bind(event.event_id())
        .bind(tenant_id)
        .bind(event.to_ocsf_event_for_lake(event.occurred_at(), event.event_id(), tenant_id))
        .bind(event.occurred_at())
        .bind(event.actor_id)
        .bind(&event.actor_name)
        .bind(event.api_key_id)
        .bind(&event.api_key_name)
        .bind(&event.action)
        .bind(event.source.to_string())
        .bind(&event.resource_type)
        .bind(event.resource_id)
        .bind(&event.resource_name)
        .bind(&event.ip_address)
        .bind(&event.user_agent)
        .bind(event.success)
        .bind(if event.success { "success" } else { "failure" })
        .bind(event.build_message())
        .bind(metadata)
}

fn postgres_audit_metadata(event: &AuditEvent) -> serde_json::Value {
    serde_json::json!({
        "actor_id": event.actor_id.map(|id| id.to_string()),
        "actor_name": event.actor_name,
        "api_key_id": event.api_key_id.map(|id| id.to_string()),
        "api_key_name": event.api_key_name,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id.map(|id| id.to_string()),
        "resource_name": event.resource_name,
        "success": event.success,
        "details": event.details,
    })
}

/// Bound resource use without turning failed durability into a successful ACK.
/// A timed-out insert may have committed; callers must treat it as indeterminate.
async fn bounded_audit_insert<F>(
    bound: &tokio::sync::Semaphore,
    timeout: std::time::Duration,
    events: &[AuditEvent],
    durable: bool,
    insert: F,
) -> Result<(), AuditEmitError>
where
    F: std::future::Future<Output = Result<(), AuditEmitError>>,
{
    let _permit = bound.try_acquire().map_err(|_| {
        record_unconfirmed(events, durable, "emitter_saturated");
        AuditEmitError::Saturated
    })?;
    tokio::time::timeout(timeout, insert).await.map_err(|_| {
        record_unconfirmed(events, durable, "emitter_timeout");
        AuditEmitError::Timeout
    })?
}

/// Errors that can occur when emitting audit events
#[derive(Debug, thiserror::Error)]
pub enum AuditEmitError {
    #[error("Transactional audit batch exceeds its count or byte bounds")]
    InvalidBatch,
    #[error("Shared audit requires a verified tenant and actor transaction")]
    TenantContextRequired,
    #[error("Audit event identity conflicts with retained content or tenant")]
    IdentityConflict,
    #[error("Audit insert concurrency capacity exhausted")]
    Saturated,
    #[error("Audit insert timed out; commit outcome is unknown")]
    Timeout,
    /// Preserve SQLSTATE for callers that own and may retry the transaction.
    #[error("Database error: {0}")]
    Database(#[source] sqlx::Error),
    #[error("Storage error: {0}")]
    Storage(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "requires explicitly owned disposable PostgreSQL"]
    async fn postgres_audit_retry_preserves_content_and_transaction_atomicity() {
        assert_eq!(std::env::var("NANOSIEM_ALLOW_DESTRUCTIVE_TESTS").as_deref(), Ok("1"));
        let pool = sqlx::PgPool::connect(
            &std::env::var("NANOSIEM_AUDIT_TEST_URL").unwrap(),
        ).await.unwrap();
        let database: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&pool).request_db().await.unwrap();
        assert_eq!(database, "nan2361_audit_contract");
        sqlx::raw_sql(include_str!("../../../migrations/postgres/287_platform_audit_events.sql"))
            .execute(&pool).request_db().await.unwrap();
        sqlx::raw_sql(include_str!("../../../migrations/postgres/290_platform_audit_lake_publication.sql"))
            .execute(&pool).request_db().await.unwrap();
        let event = AuditEvent::builder(super::super::AuditSource::Auth, "logout").build();
        let mut first = pool.begin().request_db().await.unwrap();
        persist_postgres_audit_event(&mut first, &event, "tenant-a").await.unwrap();
        first.commit().request_db().await.unwrap();
        sqlx::query("UPDATE platform_audit_events SET lake_published_snapshot_id='retained-generation', lake_published_at=now() WHERE event_id=$1")
            .bind(event.event_id()).execute(&pool).request_db().await.unwrap();
        let mut retry = pool.begin().request_db().await.unwrap();
        persist_postgres_audit_event(&mut retry, &event, "tenant-a").await.unwrap();
        retry.commit().request_db().await.unwrap();
        let row: (i64, String) = sqlx::query_as(
            "SELECT count(*)::bigint, min(lake_published_snapshot_id) FROM platform_audit_events WHERE event_id=$1",
        ).bind(event.event_id()).fetch_one(&pool).request_db().await.unwrap();
        assert_eq!(row, (1, "retained-generation".to_string()));

        // NAN-3227: a write first stored under an older rendering (OCSF
        // mapping, message, metadata envelope, unresolved actor name) and
        // retried after a deploy is the same event — not an IdentityConflict.
        let rendered = AuditEvent::builder(super::super::AuditSource::Ingest, "ingest_credential_revoked")
            .details(serde_json::json!({"reason": "rotation"}))
            .build();
        let mut first = pool.begin().request_db().await.unwrap();
        persist_postgres_audit_event(&mut first, &rendered, "tenant-a").await.unwrap();
        first.commit().request_db().await.unwrap();
        sqlx::query("UPDATE platform_audit_events SET ocsf_event=ocsf_event||'{\"activity_id\":1,\"type_uid\":600301}', \
            message='older rendering', metadata=metadata||'{\"legacy\":true}' WHERE event_id=$1")
            .bind(rendered.event_id()).execute(&pool).request_db().await.unwrap();
        let mut renamed = rendered.clone();
        renamed.actor_name = Some("resolved later".to_string());
        for retry_event in [&rendered, &renamed] {
            let mut retry = pool.begin().request_db().await.unwrap();
            persist_postgres_audit_event(&mut retry, retry_event, "tenant-a").await.unwrap();
            retry.commit().request_db().await.unwrap();
        }
        let kept: (i64, String, i64) = sqlx::query_as(
            "SELECT count(*)::bigint, min(message), min((ocsf_event->>'activity_id')::bigint) FROM platform_audit_events WHERE event_id=$1",
        ).bind(rendered.event_id()).fetch_one(&pool).request_db().await.unwrap();
        assert_eq!(kept, (1, "older rendering".to_string(), 1), "first committed rendering stays canonical");
        let mut changed_details = rendered.clone();
        changed_details.details = Some(serde_json::json!({"reason": "other"}));
        let mut conflict = pool.begin().request_db().await.unwrap();
        assert!(matches!(
            persist_postgres_audit_event(&mut conflict, &changed_details, "tenant-a").await,
            Err(AuditEmitError::IdentityConflict),
        ));
        conflict.rollback().request_db().await.unwrap();

        for (candidate, tenant) in [(event.clone(), "tenant-b"), ({
            let mut changed = event.clone();
            changed.action = "login_success".to_string();
            changed
        }, "tenant-a")] {
            let mut conflict = pool.begin().request_db().await.unwrap();
            assert!(matches!(
                persist_postgres_audit_event(&mut conflict, &candidate, tenant).await,
                Err(AuditEmitError::IdentityConflict),
            ));
            conflict.rollback().request_db().await.unwrap();
        }
        sqlx::query("CREATE TABLE audit_test_mutations (id UUID PRIMARY KEY)")
            .execute(&pool).request_db().await.unwrap();
        let rolled_back = AuditEvent::builder(super::super::AuditSource::Auth, "logout").build();
        let mut mutation = pool.begin().request_db().await.unwrap();
        sqlx::query("INSERT INTO audit_test_mutations(id) VALUES($1)")
            .bind(rolled_back.event_id()).execute(&mut *mutation).request_db().await.unwrap();
        persist_postgres_audit_event(&mut mutation, &rolled_back, "tenant-a").await.unwrap();
        mutation.rollback().request_db().await.unwrap();
        for table in ["audit_test_mutations", "platform_audit_events"] {
            let column = if table == "audit_test_mutations" { "id" } else { "event_id" };
            let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE {column}=$1"))
                .bind(rolled_back.event_id()).fetch_one(&pool).request_db().await.unwrap();
            assert_eq!(count, 0);
        }
        pool.close().await;
    }

    #[tokio::test]
    async fn saturated_insert_returns_error_without_polling_storage() {
        let bound = tokio::sync::Semaphore::new(0);
        for durable in [false, true] {
            let result = bounded_audit_insert(
                &bound, Duration::from_secs(1), &[], durable,
                async { panic!("saturated emitter must not start storage") },
            ).await;
            assert!(matches!(result, Err(AuditEmitError::Saturated)));
        }
    }

    #[tokio::test]
    async fn timed_out_insert_returns_error_and_releases_capacity() {
        let bound = tokio::sync::Semaphore::new(1);
        for durable in [false, true] {
            let result = bounded_audit_insert(
                &bound, Duration::from_millis(1), &[], durable,
                std::future::pending(),
            ).await;
            assert!(matches!(result, Err(AuditEmitError::Timeout)));
            assert_eq!(bound.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn storage_result_is_preserved_and_capacity_released() {
        let bound = tokio::sync::Semaphore::new(1);
        let result = bounded_audit_insert(
            &bound, Duration::from_secs(1), &[], true,
            async { Err(AuditEmitError::Storage("unavailable".to_string())) },
        ).await;
        assert!(matches!(result, Err(AuditEmitError::Storage(_))));
        assert_eq!(bound.available_permits(), 1);
        bounded_audit_insert(
            &bound, Duration::from_secs(1), &[], true, async { Ok(()) },
        ).await.unwrap();
        assert_eq!(bound.available_permits(), 1);
    }
}
