// SPDX-License-Identifier: AGPL-3.0-or-later
//! Online credential key rotation (NAN-4933).
//!
//! The ring makes rotation a configuration change: put a new generated root
//! in `NANOSIEM_ENCRYPTION_KEY` as `active` and keep the old one as a
//! decrypt-only entry. New writes immediately use the new root. This module
//! then moves existing ciphertext:
//!
//! - [`scan`] reads every registered secret column and reports, per ring key,
//!   how many stored values only that key opens (the "still on old key"
//!   count), plus values no ring key opens.
//! - [`rewrap`] re-encrypts each value not on the active key, with an
//!   optimistic `WHERE column = <old bytes>` guard so a concurrent writer
//!   always wins. Plaintext lives only inside [`EncryptionService::rewrap`].
//! - [`CredentialKeyRepository::retire`] marks an old key retired only after
//!   a fresh scan proves nothing references it and no live process still
//!   writes with it. The operator then removes it from the configuration.
//!
//! [`TARGETS`] is the inventory of every column that stores
//! `EncryptionService` output. A new secret column MUST be added here, or its
//! rows silently keep the old key and retirement strands them; the
//! `rotation_targets_cover_every_encrypted_column` test pins the list.
use super::{CryptoError, EncryptedData, EncryptionService};
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::collections::BTreeMap;
use uuid::Uuid;

/// How a column stores an [`EncryptedData`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Storage {
    /// Raw ciphertext BYTEA plus a text column holding the base64 nonce.
    Bytea { nonce_column: &'static str },
    /// BYTEA holding the JSON `{"ciphertext": "...", "nonce": "..."}`.
    JsonBytes,
}

/// One secret-bearing column.
#[derive(Clone, Copy, Debug)]
pub struct Target {
    /// Stable name shown in status output (`table.column`).
    pub name: &'static str,
    pub table: &'static str,
    /// Primary-key column (compared as text).
    pub pk: &'static str,
    pub column: &'static str,
    pub storage: Storage,
    /// Updates fire the Vector config publication trigger, which locks the
    /// publication singleton first; take it first to keep the global order.
    pub lock_vector_publication: bool,
    /// What the secret is (status output only).
    pub kind: &'static str,
}

const fn bytea(
    name: &'static str,
    table: &'static str,
    column: &'static str,
    nonce_column: &'static str,
    kind: &'static str,
) -> Target {
    Target {
        name,
        table,
        pk: "id",
        column,
        storage: Storage::Bytea { nonce_column },
        lock_vector_publication: false,
        kind,
    }
}

const fn json(
    name: &'static str,
    table: &'static str,
    pk: &'static str,
    column: &'static str,
    kind: &'static str,
) -> Target {
    Target {
        name,
        table,
        pk,
        column,
        storage: Storage::JsonBytes,
        lock_vector_publication: false,
        kind,
    }
}

/// Every column holding `EncryptionService` ciphertext on clickhouse/dev.
/// Enterprise-only tables are listed too; a table or column absent from the
/// database (open build) is skipped at run time.
pub const TARGETS: &[Target] = &[
    Target {
        lock_vector_publication: true,
        ..bytea(
            "cloud_credentials.credentials_encrypted",
            "cloud_credentials",
            "credentials_encrypted",
            "nonce",
            "stored credential (active version)",
        )
    },
    bytea(
        "cloud_credential_versions.credentials_encrypted",
        "cloud_credential_versions",
        "credentials_encrypted",
        "nonce",
        "stored credential (version history)",
    ),
    bytea(
        "marketplace_catalog.credentials_encrypted",
        "marketplace_catalog",
        "credentials_encrypted",
        "credentials_nonce",
        "marketplace install credentials",
    ),
    bytea(
        "system_settings.tiering_s3_credentials_encrypted",
        "system_settings",
        "tiering_s3_credentials_encrypted",
        "tiering_s3_credentials_nonce",
        "storage tiering S3 credentials",
    ),
    bytea(
        "detection_code_targets.token_encrypted",
        "detection_code_targets",
        "token_encrypted",
        "token_nonce",
        "detections-as-code repository token",
    ),
    bytea(
        "users.totp_secret_encrypted",
        "users",
        "totp_secret_encrypted",
        "totp_secret_nonce",
        "MFA TOTP secret",
    ),
    bytea(
        "users.backup_codes_encrypted",
        "users",
        "backup_codes_encrypted",
        "backup_codes_nonce",
        "MFA backup code hashes",
    ),
    bytea(
        "integration_instances.credentials_encrypted",
        "integration_instances",
        "credentials_encrypted",
        "credentials_nonce",
        "integration instance credentials",
    ),
    bytea(
        "soar_connections.credentials_encrypted",
        "soar_connections",
        "credentials_encrypted",
        "credentials_nonce",
        "SOAR connection credentials",
    ),
    json(
        "oidc_providers.client_secret_encrypted",
        "oidc_providers",
        "id",
        "client_secret_encrypted",
        "SSO client secret",
    ),
    json(
        "oidc_providers.google_service_account_encrypted",
        "oidc_providers",
        "id",
        "google_service_account_encrypted",
        "SSO Google service account key",
    ),
    json(
        "provider_credentials.credentials_encrypted",
        "provider_credentials",
        "provider",
        "credentials_encrypted",
        "AI provider / gateway API key",
    ),
    json(
        "agent_enrichment_providers.api_key_encrypted",
        "agent_enrichment_providers",
        "id",
        "api_key_encrypted",
        "enrichment provider API key",
    ),
    json(
        "identity_providers.credentials_encrypted",
        "identity_providers",
        "id",
        "credentials_encrypted",
        "identity provider credentials",
    ),
    json(
        "webhooks.url_encrypted",
        "webhooks",
        "id",
        "url_encrypted",
        "webhook destination URL",
    ),
    json(
        "webhooks.headers_encrypted",
        "webhooks",
        "id",
        "headers_encrypted",
        "webhook headers",
    ),
    json(
        "webhooks.secret_encrypted",
        "webhooks",
        "id",
        "secret_encrypted",
        "webhook signing secret",
    ),
];

#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("key {0} is not known to this deployment")]
    UnknownKey(String),
    #[error("key {key_id} is the active key of {holder}; make another key active first (a stopped process deregisters at shutdown; a killed one stops counting 15 min after its last report)")]
    KeyActive { key_id: String, holder: String },
    #[error("key {key_id} still encrypts {count} stored value(s); run the re-wrap first")]
    StillReferenced { key_id: String, count: u64 },
    #[error("{count} stored value(s) open with no key in this process's ring, so it cannot prove {key_id} is unreferenced; restore the key to the ring and re-run the re-wrap")]
    Unprovable { key_id: String, count: u64 },
    #[error("key id {0} was previously registered with different key material; key ids are immutable")]
    FingerprintMismatch(String),
    #[error("the configured active credential key {0} is not registered; start an api or jobs process with this ring first")]
    ActiveKeyNotRegistered(String),
    #[error("the configured active credential key {0} is retired; configure the current key ring (a retired key may only remain as decrypt-only)")]
    ActiveKeyRetired(String),
}

/// Usage of one target.
#[derive(Clone, Debug, Default, Serialize, utoipa::ToSchema)]
pub struct TargetUsage {
    pub name: String,
    pub kind: String,
    /// False when the table/column does not exist in this database.
    pub present: bool,
    pub rows: u64,
    /// Rows per key id that opened them.
    pub by_key: BTreeMap<String, u64>,
    /// Rows no ring key opens (or whose stored envelope is malformed).
    pub undecryptable: u64,
    /// Context-bound v2 envelopes (not re-wrapped; their key id is authenticated).
    pub v2: u64,
}

/// Result of a full scan.
#[derive(Clone, Debug, Default, Serialize, utoipa::ToSchema)]
pub struct KeyUsageReport {
    pub active_key_id: String,
    pub scanned: u64,
    /// Rows per key id, across every target.
    pub by_key: BTreeMap<String, u64>,
    /// Rows not on the active key (the re-wrap backlog).
    pub pending_rewrap: u64,
    pub undecryptable: u64,
    pub targets: Vec<TargetUsage>,
}

/// Result of a re-wrap pass.
#[derive(Clone, Debug, Default, Serialize, utoipa::ToSchema)]
pub struct RewrapOutcome {
    pub active_key_id: String,
    pub scanned: u64,
    pub rewrapped: u64,
    /// Rows changed by a concurrent writer between read and update (left as is).
    pub conflicts: u64,
    pub undecryptable: u64,
    /// Rewrapped rows per source key id.
    pub from_key: BTreeMap<String, u64>,
}

const PAGE: i64 = 500;

async fn target_present(conn: &mut sqlx::PgConnection, target: &Target) -> Result<bool, sqlx::Error> {
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = $1",
    )
    .bind(target.table)
    .fetch_all(&mut *conn)
    .await?;
    let needed = [Some(target.pk), Some(target.column), nonce_column(target)];
    Ok(needed
        .iter()
        .flatten()
        .all(|column| columns.iter().any(|c| c == column)))
}

fn nonce_column(target: &Target) -> Option<&'static str> {
    match target.storage {
        Storage::Bytea { nonce_column } => Some(nonce_column),
        Storage::JsonBytes => None,
    }
}

/// One stored value, as read.
struct StoredRow {
    pk: String,
    raw: Vec<u8>,
    nonce: Option<String>,
}

impl StoredRow {
    fn envelope(&self, storage: Storage) -> Option<EncryptedData> {
        match storage {
            Storage::Bytea { .. } => self
                .nonce
                .as_ref()
                .map(|nonce| EncryptedData::from_bytea(&self.raw, nonce)),
            Storage::JsonBytes => EncryptedData::from_json_bytes(&self.raw).ok(),
        }
    }
}

async fn read_page(
    conn: &mut sqlx::PgConnection,
    target: &Target,
    after: &str,
) -> Result<Vec<StoredRow>, sqlx::Error> {
    // Identifiers come only from the static TARGETS list, never from input.
    let nonce = nonce_column(target)
        .map(|c| format!("{c}::text"))
        .unwrap_or_else(|| "NULL::text".into());
    let sql = format!(
        "SELECT {pk}::text AS pk, {col} AS raw, {nonce} AS nonce FROM public.{table} \
          WHERE {col} IS NOT NULL AND {pk}::text > $1 ORDER BY {pk}::text LIMIT $2",
        pk = target.pk,
        col = target.column,
        table = target.table,
    );
    let rows = sqlx::query(&sql)
        .bind(after)
        .bind(PAGE)
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| StoredRow {
            pk: row.get("pk"),
            raw: row.get("raw"),
            nonce: row.get("nonce"),
        })
        .collect())
}

fn classify(cipher: &EncryptionService, storage: Storage, row: &StoredRow) -> Classified {
    let Some(envelope) = row.envelope(storage) else {
        return Classified::Undecryptable;
    };
    if envelope.nonce.starts_with(super::envelope::V2_NONCE_PREFIX) {
        return match super::v2_key_id(&envelope) {
            Ok(id) => Classified::V2(id),
            Err(_) => Classified::Undecryptable,
        };
    }
    match cipher.decrypt_with_key_id(&envelope) {
        Ok((plain, id)) => {
            drop(zeroize::Zeroizing::new(plain));
            Classified::Key(id)
        }
        Err(_) => Classified::Undecryptable,
    }
}

enum Classified {
    Key(String),
    V2(String),
    Undecryptable,
}

/// Count stored values per key across every target. Read-only.
pub async fn scan(pool: &PgPool, cipher: &EncryptionService) -> Result<KeyUsageReport, RotationError> {
    let mut conn = pool.acquire().await?;
    scan_on(&mut conn, cipher).await
}

/// [`scan`] on a given connection (retirement runs it inside its own
/// transaction, so it never needs a second pool connection).
pub async fn scan_on(
    conn: &mut sqlx::PgConnection,
    cipher: &EncryptionService,
) -> Result<KeyUsageReport, RotationError> {
    let mut report = KeyUsageReport {
        active_key_id: cipher.active_key_id().to_owned(),
        ..Default::default()
    };
    for target in TARGETS {
        let mut usage = TargetUsage {
            name: target.name.into(),
            kind: target.kind.into(),
            ..Default::default()
        };
        usage.present = target_present(&mut *conn, target).await?;
        if usage.present {
            let mut after = String::new();
            loop {
                let page = read_page(&mut *conn, target, &after).await?;
                let Some(last) = page.last() else { break };
                after = last.pk.clone();
                for row in &page {
                    usage.rows += 1;
                    match classify(cipher, target.storage, row) {
                        Classified::Key(id) => *usage.by_key.entry(id).or_default() += 1,
                        Classified::V2(id) => {
                            usage.v2 += 1;
                            *usage.by_key.entry(id).or_default() += 1;
                        }
                        Classified::Undecryptable => usage.undecryptable += 1,
                    }
                }
                if (page.len() as i64) < PAGE {
                    break;
                }
            }
        }
        report.scanned += usage.rows;
        report.undecryptable += usage.undecryptable;
        for (id, count) in &usage.by_key {
            *report.by_key.entry(id.clone()).or_default() += count;
        }
        report.targets.push(usage);
    }
    report.pending_rewrap = report
        .by_key
        .iter()
        .filter(|(id, _)| **id != report.active_key_id)
        .map(|(_, count)| *count)
        .sum();
    Ok(report)
}

/// Re-encrypt every value not on the active key. Idempotent and safe to run
/// concurrently with writers and with another re-wrap (optimistic guard).
pub async fn rewrap(pool: &PgPool, cipher: &EncryptionService) -> Result<RewrapOutcome, RotationError> {
    let mut outcome = RewrapOutcome {
        active_key_id: cipher.active_key_id().to_owned(),
        ..Default::default()
    };
    let mut conn = pool.acquire().await?;
    for target in TARGETS {
        if !target_present(&mut conn, target).await? {
            continue;
        }
        let mut after = String::new();
        loop {
            let page = read_page(&mut conn, target, &after).await?;
            let Some(last) = page.last() else { break };
            after = last.pk.clone();
            let mut pending = Vec::new();
            for row in &page {
                outcome.scanned += 1;
                let Some(envelope) = row.envelope(target.storage) else {
                    outcome.undecryptable += 1;
                    continue;
                };
                match cipher.rewrap(&envelope) {
                    Ok(Some((fresh, from))) => pending.push((row, fresh, from)),
                    Ok(None) => {}
                    Err(_) => outcome.undecryptable += 1,
                }
            }
            if !pending.is_empty() {
                apply_page(pool, target, pending, &mut outcome).await?;
            }
            if (page.len() as i64) < PAGE {
                break;
            }
        }
    }
    Ok(outcome)
}

async fn apply_page(
    pool: &PgPool,
    target: &Target,
    pending: Vec<(&StoredRow, EncryptedData, String)>,
    outcome: &mut RewrapOutcome,
) -> Result<(), RotationError> {
    let mut tx = pool.begin().await?;
    if target.lock_vector_publication {
        // Same global lock order as CredentialRepository::rotate: the
        // publication trigger locks this singleton before credential rows.
        sqlx::query(
            "SELECT singleton FROM vector_config_publication_state \
              WHERE singleton = TRUE FOR UPDATE",
        )
        .fetch_optional(&mut *tx)
        .await?;
    }
    for (row, fresh, from) in pending {
        let affected = match target.storage {
            Storage::Bytea { nonce_column } => {
                let (bytes, nonce) = fresh.to_bytea()?;
                let sql = format!(
                    "UPDATE public.{table} SET {col} = $1, {nonce_column} = $2 \
                      WHERE {pk}::text = $3 AND {col} = $4 AND {nonce_column}::text IS NOT DISTINCT FROM $5",
                    table = target.table,
                    col = target.column,
                    pk = target.pk,
                );
                sqlx::query(&sql)
                    .bind(bytes)
                    .bind(nonce)
                    .bind(&row.pk)
                    .bind(&row.raw)
                    .bind(&row.nonce)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
            }
            Storage::JsonBytes => {
                let bytes = fresh.to_json_bytes()?;
                let sql = format!(
                    "UPDATE public.{table} SET {col} = $1 WHERE {pk}::text = $2 AND {col} = $3",
                    table = target.table,
                    col = target.column,
                    pk = target.pk,
                );
                sqlx::query(&sql)
                    .bind(bytes)
                    .bind(&row.pk)
                    .bind(&row.raw)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
            }
        };
        if affected == 1 {
            outcome.rewrapped += 1;
            *outcome.from_key.entry(from).or_default() += 1;
        } else {
            outcome.conflicts += 1;
        }
    }
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Write fence (migration 304)
// ---------------------------------------------------------------------------

/// Session setting the credential write-fence trigger reads: the key this
/// process encrypts new secrets with.
pub const WRITE_KEY_SETTING: &str = "nano.credential_write_key";

/// Declare `key_id` as the write key on every connection of a pool, so the
/// write-fence trigger can refuse secrets written under a retired key.
pub fn declare_write_key(
    options: sqlx::postgres::PgPoolOptions,
    key_id: String,
) -> sqlx::postgres::PgPoolOptions {
    options.after_connect(move |conn, _meta| {
        let key_id = key_id.clone();
        Box::pin(async move {
            sqlx::query("SELECT set_config($1, $2, false)")
                .bind(WRITE_KEY_SETTING)
                .bind(key_id)
                .execute(conn)
                .await?;
            Ok(())
        })
    })
}

// ---------------------------------------------------------------------------
// Key ring bookkeeping (migration 300)
// ---------------------------------------------------------------------------

/// A process counts as live for retirement checks if it reported within this.
pub const MEMBER_LIVENESS_SECS: i64 = 15 * 60;

/// One known key.
#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct KnownKey {
    pub key_id: String,
    pub fingerprint: String,
    /// `in_use` or `retired`.
    pub state: String,
    /// Stored values only this key opens, as of the last scan/re-wrap.
    pub referenced_rows: Option<i64>,
    pub first_seen_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
    pub last_active_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_scanned_at: Option<chrono::DateTime<chrono::Utc>>,
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,
    pub retired_by: Option<Uuid>,
}

/// A process holding a ring.
#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct RingMember {
    pub node_id: String,
    pub service: String,
    pub active_key_id: String,
    pub key_ids: Vec<String>,
    pub seen_at: chrono::DateTime<chrono::Utc>,
    pub live: bool,
}

/// A recorded re-wrap pass.
#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct RewrapRun {
    pub id: i64,
    pub trigger: String,
    pub node_id: String,
    pub active_key_id: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub scanned: i64,
    pub rewrapped: i64,
    pub conflicts: i64,
    pub undecryptable: i64,
    pub error: Option<String>,
}

/// Persistence for ring bookkeeping. Stores ids and fingerprints only.
#[derive(Clone)]
pub struct CredentialKeyRepository {
    pool: PgPool,
}

/// Serializes ring bookkeeping writes (retire vs. register vs. re-wrap record).
const RING_LOCK: i64 = 0x4e53_4b52_494e; // "NSKRIN"

impl CredentialKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Record this process's ring: upsert every key (refusing an id whose
    /// material changed) and this node's membership row. Warns about ring
    /// keys already retired and about in-use keys missing from the ring.
    pub async fn register(
        &self,
        cipher: &EncryptionService,
        node_id: &str,
        service: &str,
    ) -> Result<(), RotationError> {
        let ring = cipher.ring_keys();
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(RING_LOCK)
            .execute(&mut *tx)
            .await?;
        for key in &ring {
            let existing: Option<(String, String)> = sqlx::query_as(
                "SELECT fingerprint, state FROM credential_keys WHERE key_id = $1 FOR UPDATE",
            )
            .bind(&key.id)
            .fetch_optional(&mut *tx)
            .await?;
            match existing {
                Some((fingerprint, _)) if fingerprint != key.fingerprint => {
                    return Err(RotationError::FingerprintMismatch(key.id.clone()));
                }
                Some((_, state)) => {
                    if state == "retired" {
                        // NAN-4933 (review P1): encrypting new secrets under a
                        // retired key would strand them once its material is
                        // deleted. Fatal for the active key; a decrypt-only
                        // leftover is only a warning.
                        if key.id == cipher.active_key_id() {
                            return Err(RotationError::ActiveKeyRetired(key.id.clone()));
                        }
                        tracing::warn!(key_id = %key.id, "credential key is retired but still configured as decrypt-only; remove it from NANOSIEM_ENCRYPTION_KEY");
                    }
                    sqlx::query("UPDATE credential_keys SET last_seen_at = now() WHERE key_id = $1")
                        .bind(&key.id)
                        .execute(&mut *tx)
                        .await?;
                }
                None => {
                    sqlx::query(
                        "INSERT INTO credential_keys (key_id, fingerprint) VALUES ($1, $2)",
                    )
                    .bind(&key.id)
                    .bind(&key.fingerprint)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }
        sqlx::query("UPDATE credential_keys SET last_active_at = now() WHERE key_id = $1")
            .bind(cipher.active_key_id())
            .execute(&mut *tx)
            .await?;
        let ids: Vec<String> = ring.iter().map(|k| k.id.clone()).collect();
        sqlx::query(
            "INSERT INTO credential_key_ring_members (node_id, service, active_key_id, key_ids, seen_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (node_id) DO UPDATE SET service = EXCLUDED.service, \
               active_key_id = EXCLUDED.active_key_id, key_ids = EXCLUDED.key_ids, seen_at = now()",
        )
        .bind(node_id)
        .bind(service)
        .bind(cipher.active_key_id())
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
        let missing: Vec<(String, Option<i64>)> = sqlx::query_as(
            "SELECT key_id, referenced_rows FROM credential_keys \
              WHERE state = 'in_use' AND NOT (key_id = ANY($1)) AND COALESCE(referenced_rows, 1) > 0",
        )
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        for (key_id, rows) in missing {
            tracing::error!(%key_id, referenced_rows = ?rows, "credential key is not in this process's ring but stored values may still need it; those values will fail to decrypt until it is restored");
        }
        Ok(())
    }

    /// Read-only check that this ring's key material is the registered
    /// material: every ring key already in `credential_keys` must have the
    /// same fingerprint, and the active key must be registered. Mandatory
    /// before any scan, re-wrap or retirement that does not come from a
    /// process that registered its ring at boot (the CLI).
    pub async fn verify_ring(&self, cipher: &EncryptionService) -> Result<(), RotationError> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key_id, fingerprint FROM credential_keys")
                .fetch_all(&self.pool)
                .await?;
        for key in cipher.ring_keys() {
            match rows.iter().find(|(id, _)| *id == key.id) {
                Some((_, fingerprint)) if *fingerprint != key.fingerprint => {
                    return Err(RotationError::FingerprintMismatch(key.id));
                }
                None if key.id == cipher.active_key_id() => {
                    return Err(RotationError::ActiveKeyNotRegistered(key.id));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Switch the write fence to enforced (one-way; migration 306): from now
    /// on a secret write from a session that declares no key is refused. The
    /// UPDATE waits for every in-flight undeclared write to commit. Returns
    /// whether this call flipped it.
    pub async fn enforce_fence(&self, by: &str) -> Result<bool, RotationError> {
        let flipped = sqlx::query(
            "UPDATE credential_write_fence_state SET enforce = TRUE, enforced_at = now(), enforced_by = $1 \
              WHERE singleton AND NOT enforce",
        )
        .bind(by)
        .execute(&self.pool)
        .await?
        .rows_affected()
            > 0;
        if flipped {
            tracing::warn!(by, "credential write fence is now enforced: undeclared sessions can no longer write secrets");
        }
        Ok(flipped)
    }

    /// Whether the write fence refuses undeclared writers.
    pub async fn fence_enforced(&self) -> Result<bool, RotationError> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT enforce FROM credential_write_fence_state WHERE singleton",
        )
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(true))
    }

    /// Remove this node's membership (graceful shutdown), so its active key
    /// stops blocking retirement immediately instead of after the liveness window.
    pub async fn deregister(&self, node_id: &str) -> Result<(), RotationError> {
        sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1")
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Persist a scan's per-key counts (keys absent from the scan count 0).
    pub async fn record_usage(&self, report: &KeyUsageReport) -> Result<(), RotationError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(RING_LOCK)
            .execute(&mut *tx)
            .await?;
        let ids: Vec<String> = report.by_key.keys().cloned().collect();
        let counts: Vec<i64> = report.by_key.values().map(|c| *c as i64).collect();
        sqlx::query(
            "UPDATE credential_keys k SET last_scanned_at = now(), referenced_rows = COALESCE( \
               (SELECT u.n FROM unnest($1::text[], $2::bigint[]) AS u(id, n) WHERE u.id = k.key_id), 0)",
        )
        .bind(&ids)
        .bind(&counts)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn start_run(
        &self,
        trigger: &str,
        node_id: &str,
        active_key_id: &str,
    ) -> Result<i64, RotationError> {
        Ok(sqlx::query_scalar(
            "INSERT INTO credential_key_rewrap_runs (trigger, node_id, active_key_id) \
             VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(trigger)
        .bind(node_id)
        .bind(active_key_id)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Stamp the jobs lease epoch on a run (migration 301).
    pub async fn set_run_epoch(&self, id: i64, epoch: i64) -> Result<(), RotationError> {
        sqlx::query("UPDATE credential_key_rewrap_runs SET leader_epoch = $2 WHERE id = $1")
            .bind(id)
            .bind(epoch)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn finish_run(
        &self,
        id: i64,
        result: &Result<(RewrapOutcome, KeyUsageReport), RotationError>,
    ) -> Result<(), RotationError> {
        let (scanned, rewrapped, conflicts, undecryptable, per_key, error) = match result {
            Ok((outcome, report)) => (
                outcome.scanned as i64,
                outcome.rewrapped as i64,
                outcome.conflicts as i64,
                report.undecryptable as i64,
                serde_json::to_value(&report.by_key).ok(),
                None,
            ),
            Err(error) => (0, 0, 0, 0, None, Some(error.to_string())),
        };
        sqlx::query(
            "UPDATE credential_key_rewrap_runs SET finished_at = now(), scanned = $2, rewrapped = $3, \
               conflicts = $4, undecryptable = $5, per_key = $6, error = $7 WHERE id = $1",
        )
        .bind(id)
        .bind(scanned)
        .bind(rewrapped)
        .bind(conflicts)
        .bind(undecryptable)
        .bind(per_key)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn known_keys(&self) -> Result<Vec<KnownKey>, RotationError> {
        let rows = sqlx::query(
            "SELECT key_id, fingerprint, state, referenced_rows, first_seen_at, last_seen_at, \
                    last_active_at, last_scanned_at, retired_at, retired_by \
               FROM credential_keys ORDER BY first_seen_at, key_id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| KnownKey {
                key_id: r.get("key_id"),
                fingerprint: r.get("fingerprint"),
                state: r.get("state"),
                referenced_rows: r.get("referenced_rows"),
                first_seen_at: r.get("first_seen_at"),
                last_seen_at: r.get("last_seen_at"),
                last_active_at: r.get("last_active_at"),
                last_scanned_at: r.get("last_scanned_at"),
                retired_at: r.get("retired_at"),
                retired_by: r.get("retired_by"),
            })
            .collect())
    }

    pub async fn members(&self) -> Result<Vec<RingMember>, RotationError> {
        let rows = sqlx::query(
            "SELECT node_id, service, active_key_id, key_ids, seen_at, \
                    seen_at > now() - make_interval(secs => $1) AS live \
               FROM credential_key_ring_members ORDER BY seen_at DESC",
        )
        .bind(MEMBER_LIVENESS_SECS as f64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| RingMember {
                node_id: r.get("node_id"),
                service: r.get("service"),
                active_key_id: r.get("active_key_id"),
                key_ids: r.get("key_ids"),
                seen_at: r.get("seen_at"),
                live: r.get("live"),
            })
            .collect())
    }

    pub async fn recent_runs(&self, limit: i64) -> Result<Vec<RewrapRun>, RotationError> {
        let rows = sqlx::query(
            "SELECT id, trigger, node_id, active_key_id, started_at, finished_at, scanned, \
                    rewrapped, conflicts, undecryptable, error \
               FROM credential_key_rewrap_runs ORDER BY id DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| RewrapRun {
                id: r.get("id"),
                trigger: r.get("trigger"),
                node_id: r.get("node_id"),
                active_key_id: r.get("active_key_id"),
                started_at: r.get("started_at"),
                finished_at: r.get("finished_at"),
                scanned: r.get("scanned"),
                rewrapped: r.get("rewrapped"),
                conflicts: r.get("conflicts"),
                undecryptable: r.get("undecryptable"),
                error: r.get("error"),
            })
            .collect())
    }

    /// Retirement refusals that need no scan: unknown key, the caller's own
    /// active key, or a key some live process still reports as active.
    async fn retire_prechecks<'c, E>(
        &self,
        cipher: &EncryptionService,
        key_id: &str,
        executor: E,
    ) -> Result<(), RotationError>
    where
        E: sqlx::Executor<'c, Database = sqlx::Postgres>,
    {
        if cipher.active_key_id() == key_id {
            return Err(RotationError::KeyActive {
                key_id: key_id.into(),
                holder: "this process".into(),
            });
        }
        let row: Option<(bool, Option<String>)> = sqlx::query_as(
            "SELECT TRUE, (SELECT service || ' ' || node_id FROM credential_key_ring_members \
                            WHERE active_key_id = $1 AND seen_at > now() - make_interval(secs => $2) LIMIT 1) \
               FROM credential_keys WHERE key_id = $1",
        )
        .bind(key_id)
        .bind(MEMBER_LIVENESS_SECS as f64)
        .fetch_optional(executor)
        .await?;
        match row {
            None => Err(RotationError::UnknownKey(key_id.into())),
            Some((_, Some(holder))) => Err(RotationError::KeyActive {
                key_id: key_id.into(),
                holder,
            }),
            Some((_, None)) => Ok(()),
        }
    }

    /// Mark `key_id` retired after proving that a fresh scan finds no value it
    /// opens.
    ///
    /// The authority is the durable write fence (migration 304): the
    /// `FOR UPDATE` on the key's `credential_keys` row below waits for every
    /// in-flight write that declared this key (they hold `FOR SHARE` through
    /// the trigger) and blocks new ones until this transaction ends, after
    /// which they see `retired` and are refused. So the scan sees every write
    /// that will ever land under the key. The live-membership check is only an
    /// early, friendlier refusal (a live process still writing with the key
    /// would otherwise start failing its writes); it is not relied on.
    pub async fn retire(
        &self,
        cipher: &EncryptionService,
        key_id: &str,
        retired_by: Option<Uuid>,
    ) -> Result<KeyUsageReport, RotationError> {
        // The process's key bytes must be the registered ones: an id present
        // in the ring is only evidence when its fingerprint matches.
        self.verify_ring(cipher).await?;
        // Refuse early (without enforcing anything) when the key is unknown,
        // this process's active key, or still active in a live process; the
        // same checks repeat under the locks below.
        self.retire_prechecks(cipher, key_id, &self.pool).await?;
        // Undeclared writers stop here: the flip waits for in-flight ones.
        self.enforce_fence("retirement").await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(RING_LOCK)
            .execute(&mut *tx)
            .await?;
        let state: Option<String> =
            sqlx::query_scalar("SELECT state FROM credential_keys WHERE key_id = $1 FOR UPDATE")
                .bind(key_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(state) = state else {
            return Err(RotationError::UnknownKey(key_id.into()));
        };
        self.retire_prechecks(cipher, key_id, &mut *tx).await?;
        // The scan runs on this transaction's own connection (no second pool
        // connection needed), while the row lock above holds every writer of
        // this key out (write fence). READ COMMITTED: each statement sees
        // writes committed before the lock was granted.
        let report = scan_on(&mut tx, cipher).await?;
        let count = report.by_key.get(key_id).copied().unwrap_or(0);
        if count > 0 {
            return Err(RotationError::StillReferenced {
                key_id: key_id.into(),
                count,
            });
        }
        let in_ring = cipher.ring_keys().iter().any(|k| k.id == key_id);
        if !in_ring && report.undecryptable > 0 {
            return Err(RotationError::Unprovable {
                key_id: key_id.into(),
                count: report.undecryptable,
            });
        }
        if state != "retired" {
            sqlx::query(
                "UPDATE credential_keys SET state = 'retired', retired_at = now(), retired_by = $2, \
                   referenced_rows = 0, last_scanned_at = now() WHERE key_id = $1",
            )
            .bind(key_id)
            .bind(retired_by)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(report)
    }
}

/// One full pass: re-wrap, then a confirming scan whose counts are stored.
/// Records the run. Used by the jobs scheduler, the boot pass and the admin
/// endpoint.
pub async fn run_pass(
    repo: &CredentialKeyRepository,
    cipher: &EncryptionService,
    trigger: &str,
    node_id: &str,
) -> Result<(RewrapOutcome, KeyUsageReport), RotationError> {
    run_pass_fenced(repo, cipher, trigger, node_id, None).await
}

/// [`run_pass`] recording the jobs lease epoch that ran it (scheduled passes).
pub async fn run_pass_fenced(
    repo: &CredentialKeyRepository,
    cipher: &EncryptionService,
    trigger: &str,
    node_id: &str,
    leader_epoch: Option<i64>,
) -> Result<(RewrapOutcome, KeyUsageReport), RotationError> {
    repo.verify_ring(cipher).await?;
    let run_id = repo.start_run(trigger, node_id, cipher.active_key_id()).await?;
    if let Some(epoch) = leader_epoch {
        repo.set_run_epoch(run_id, epoch).await?;
    }
    let result = async {
        let outcome = rewrap(repo.pool(), cipher).await?;
        let report = scan(repo.pool(), cipher).await?;
        repo.record_usage(&report).await?;
        Ok::<_, RotationError>((outcome, report))
    }
    .await;
    if let Err(error) = repo.finish_run(run_id, &result).await {
        tracing::warn!(%error, "failed to record credential re-wrap run");
    }
    match &result {
        Ok((outcome, report)) if outcome.rewrapped > 0 || report.pending_rewrap > 0 || report.undecryptable > 0 => {
            tracing::info!(
                active_key_id = %report.active_key_id,
                rewrapped = outcome.rewrapped,
                conflicts = outcome.conflicts,
                pending = report.pending_rewrap,
                undecryptable = report.undecryptable,
                "credential key re-wrap pass"
            );
        }
        Ok(_) => tracing::debug!("credential key re-wrap pass: nothing to do"),
        Err(error) => tracing::warn!(%error, "credential key re-wrap pass failed"),
    }
    result
}

/// The stored column bytes (and nonce column value) of an envelope in a format.
#[doc(hidden)]
pub fn encode_for(storage: Storage, data: &EncryptedData) -> Result<(Vec<u8>, Option<String>), CryptoError> {
    match storage {
        Storage::Bytea { .. } => {
            let (bytes, nonce) = data.to_bytea()?;
            Ok((bytes, Some(nonce)))
        }
        Storage::JsonBytes => Ok((data.to_json_bytes()?, None)),
    }
}
