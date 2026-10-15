// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3499: backfill control evidence for committed part files that have no
//! lake_part writer receipt.
//!
//! Before NAN-3499 the detect finding drain PUT finding parts with its own
//! credential, outside the owner writer authority, and the ingest cell
//! committed their `add`. Control therefore has no completion receipt for
//! those files and `lake_part_delete_attest` refuses every delete of them
//! (NL007, HTTP 404 `lake_part_object_not_found`).
//!
//! The reconciler, per tenant:
//! 1. reads the gaps from control (`nano_shared.lake_part_receipt_gaps`, or
//!    the same read-only query inline where migration 9012600 is not yet
//!    applied): committed, indexed entries that added a part none of whose
//!    files has a receipt;
//! 2. proves each part from the bucket: the entry's bytes hash to the
//!    entry sha256 control indexed (control indexed it against its own
//!    lake_part_log receipt), the entry names the part, the part's
//!    `provenance.json` hashes to the entry's `provenance_sha256`, and the
//!    provenance names every file with its sha256 and size;
//! 3. lists the part directory for each file's strong ETag and size; a
//!    file that is absent, differs in size, or carries a weak ETag is
//!    refused, never backfilled;
//! 4. dry run (the default): prints the plan. `--apply`: calls
//!    `nano_shared.backfill_lake_part_receipt` per file, which re-binds the
//!    key to the committed entry in SQL and is idempotent.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use serde::Serialize;
use serde_json::{json, Value};

use crate::parts::format::PartKeys;
use crate::parts::part_log::{LogEntry, LogOp, PartRef};
use crate::parts::provenance::SignedProvenance;
use crate::parts::sha256_hex;

/// One committed part with no receipt for any of its files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReceiptGap {
    pub part_id: String,
    pub added_seq: i64,
    pub op_kind: String,
    pub entry_key: String,
    pub entry_sha256: String,
    pub committed_at: chrono::DateTime<chrono::Utc>,
    pub live: bool,
    pub removed_seq: Option<i64>,
}

/// A listed object: quoted strong ETag and size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedObject {
    pub key: String,
    pub etag: String,
    pub size: u64,
}

/// Control's side: the gap read and the operator write.
#[async_trait]
pub trait ReceiptLedger: Send + Sync {
    async fn gaps(&self, tenant: uuid::Uuid, limit: i32) -> Result<Vec<ReceiptGap>>;
    async fn backfill(&self, tenant: uuid::Uuid, file: &PlannedFile, reason: &str, evidence: &Value) -> Result<Value>;
}

/// The bucket's side: whole-object reads (log entry, provenance) and a
/// listing with strong ETags and sizes.
#[async_trait]
pub trait BucketEvidence: Send + Sync {
    /// Evidence `source` recorded with each backfill.
    fn source(&self) -> &'static str;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn list(&self, prefix: &str) -> Result<Vec<ObservedObject>>;
}

/// One file the reconciler would backfill (or refuses to).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlannedFile {
    pub key: String,
    pub part_id: String,
    pub added_seq: i64,
    pub added_entry_sha256: String,
    pub sha256: String,
    pub size: u64,
    pub etag: Option<String>,
    pub observed_size: Option<u64>,
    /// `None`: backfill. `Some(reason)`: refused, never written.
    pub refused: Option<String>,
}

/// The plan for one part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlannedPart {
    pub gap: ReceiptGap,
    /// Why the whole part is refused (the chain did not verify).
    pub refused: Option<String>,
    pub files: Vec<PlannedFile>,
    /// Listed objects in the part directory that its provenance does not
    /// name. Reported, never backfilled.
    pub unexpected: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ReconcileSummary {
    pub gap_parts: usize,
    pub refused_parts: usize,
    pub files_planned: usize,
    pub files_refused: usize,
    pub backfilled: usize,
    pub already_backfilled: usize,
    pub already_receipted: usize,
    pub apply_errors: usize,
    pub windows: Vec<GapWindow>,
}

/// Consecutive gap entries within 15 minutes of each other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GapWindow {
    pub first_seq: i64,
    pub last_seq: i64,
    pub parts: usize,
    pub first_committed_at: chrono::DateTime<chrono::Utc>,
    pub last_committed_at: chrono::DateTime<chrono::Utc>,
}

pub fn gap_windows(gaps: &[ReceiptGap]) -> Vec<GapWindow> {
    let mut windows: Vec<GapWindow> = Vec::new();
    for gap in gaps {
        match windows.last_mut() {
            Some(window) if gap.committed_at - window.last_committed_at <= chrono::Duration::minutes(15) => {
                window.last_seq = gap.added_seq;
                window.last_committed_at = gap.committed_at;
                window.parts += 1;
            }
            _ => windows.push(GapWindow { first_seq: gap.added_seq, last_seq: gap.added_seq, parts: 1,
                first_committed_at: gap.committed_at, last_committed_at: gap.committed_at }),
        }
    }
    windows
}

fn strong_etag(etag: &str) -> bool {
    etag.len() >= 3 && etag.len() <= 128 && etag.starts_with('"') && etag.ends_with('"')
        && !etag[1..etag.len() - 1].chars().any(|c| c == '"' || c.is_control())
}

/// The part reference the committed entry carries for `part_id`.
fn entry_part(entry: &LogEntry, part_id: &str) -> Option<PartRef> {
    let parts: Vec<&PartRef> = match &entry.op {
        LogOp::Add { parts, .. } => parts.iter().collect(),
        LogOp::Merge { output, .. } | LogOp::Rewrite { output, .. } => vec![output],
        _ => Vec::new(),
    };
    parts.into_iter().find(|part| part.part_id.as_str() == part_id).cloned()
}

/// Prove one gap part from the bucket and plan its files.
pub async fn plan_part(tenant: uuid::Uuid, gap: &ReceiptGap, bucket: &dyn BucketEvidence) -> Result<PlannedPart> {
    let tenant_id = tenant.to_string();
    let refuse = |reason: String| PlannedPart { gap: gap.clone(), refused: Some(reason), files: Vec::new(), unexpected: Vec::new() };
    let Some(entry_bytes) = bucket.get(&gap.entry_key).await? else {
        return Ok(refuse("committed log entry is absent from the bucket".into()));
    };
    if sha256_hex(&entry_bytes) != gap.entry_sha256 {
        return Ok(refuse("log entry bytes differ from the sha256 control indexed".into()));
    }
    let entry = match LogEntry::parse_bytes(&entry_bytes, &tenant_id) {
        Ok(entry) if i64::try_from(entry.seq).ok() == Some(gap.added_seq) => entry,
        Ok(_) => return Ok(refuse("log entry seq differs from the indexed seq".into())),
        Err(error) => return Ok(refuse(format!("log entry does not parse: {error:#}"))),
    };
    let Some(part) = entry_part(&entry, &gap.part_id) else {
        return Ok(refuse("committed entry does not add this part".into()));
    };
    let keys = match PartKeys::new(&tenant_id, part.level, part.event_hour, &part.part_id) {
        Ok(keys) => keys,
        Err(error) => return Ok(refuse(format!("part keys: {error:#}"))),
    };
    let Some(provenance_bytes) = bucket.get(&keys.provenance()).await? else {
        return Ok(refuse("part provenance is absent from the bucket".into()));
    };
    if sha256_hex(&provenance_bytes) != part.provenance_sha256 {
        return Ok(refuse("part provenance differs from the committed provenance_sha256".into()));
    }
    let signed: SignedProvenance = match serde_json::from_slice(&provenance_bytes) {
        Ok(signed) => signed,
        Err(error) => return Ok(refuse(format!("part provenance does not parse: {error}"))),
    };
    if signed.record.part_id != part.part_id || signed.record.tenant_id != tenant_id {
        return Ok(refuse("provenance names another part or tenant".into()));
    }
    let mut wanted: Vec<(String, String, u64)> = signed.record.files.all().into_iter()
        .map(|(name, sha, size)| (keys.file(name), sha.to_owned(), size)).collect();
    wanted.push((keys.provenance(), part.provenance_sha256.clone(), provenance_bytes.len() as u64));
    let dir = keys.file("");
    let listed: BTreeMap<String, ObservedObject> = bucket.list(&dir).await?.into_iter()
        .filter(|object| object.key.starts_with(&dir))
        .map(|object| (object.key.clone(), object)).collect();
    let named: BTreeSet<&str> = wanted.iter().map(|(key, _, _)| key.as_str()).collect();
    let unexpected = listed.keys().filter(|key| !named.contains(key.as_str())).cloned().collect();
    let files = wanted.into_iter().map(|(key, sha256, size)| {
        let observed = listed.get(&key);
        let refused = match observed {
            None => Some("object is absent from the bucket".to_owned()),
            Some(object) if object.size != size => Some(format!("stored size {} differs from provenance {size}", object.size)),
            Some(object) if !strong_etag(&object.etag) => Some("stored ETag is not a strong ETag".to_owned()),
            Some(_) => None,
        };
        PlannedFile { key, part_id: gap.part_id.clone(), added_seq: gap.added_seq, added_entry_sha256: gap.entry_sha256.clone(),
            sha256, size, etag: observed.map(|o| o.etag.clone()), observed_size: observed.map(|o| o.size), refused }
    }).collect();
    Ok(PlannedPart { gap: gap.clone(), refused: None, files, unexpected })
}

/// The exact evidence `backfill_lake_part_receipt` checks.
pub fn evidence(tenant: uuid::Uuid, file: &PlannedFile, source: &str, observed_at: chrono::DateTime<chrono::Utc>) -> Result<Value> {
    let etag = file.etag.as_deref().context("planned file has no observed ETag")?;
    Ok(json!({
        "bucket": format!("nano-shared-r2-{tenant}"), "key": file.key, "source": source,
        "etag": etag, "length": file.size, "sha256": file.sha256, "sha256_source": "signed_provenance",
        "added_seq": file.added_seq, "added_entry_sha256": file.added_entry_sha256,
        "observed_at": observed_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        // mirror-gate: wire (persisted evidence field)
        "issue": "NAN-3499",
    }))
}

/// Plan every gap of `tenant`; with `apply`, backfill the unrefused files.
/// `emit` receives one JSON line per part (and per applied file).
pub async fn reconcile(
    tenant: uuid::Uuid, ledger: &dyn ReceiptLedger, bucket: &dyn BucketEvidence, limit: i32, apply: bool, reason: &str,
    emit: &mut dyn FnMut(Value),
) -> Result<ReconcileSummary> {
    if apply {
        ensure!(!reason.trim().is_empty() && reason.len() <= 2000, "--apply needs a reason (1..2000 chars)");
    }
    let gaps = ledger.gaps(tenant, limit).await?;
    let mut summary = ReconcileSummary { gap_parts: gaps.len(), windows: gap_windows(&gaps), ..Default::default() };
    for gap in &gaps {
        let planned = plan_part(tenant, gap, bucket).await?;
        if planned.refused.is_some() {
            summary.refused_parts += 1;
        }
        summary.files_planned += planned.files.iter().filter(|f| f.refused.is_none()).count();
        summary.files_refused += planned.files.iter().filter(|f| f.refused.is_some()).count();
        emit(json!({"kind": "part", "tenant": tenant, "plan": planned}));
        if !apply || planned.refused.is_some() {
            continue;
        }
        for file in planned.files.iter().filter(|f| f.refused.is_none()) {
            // Re-observe right before the write: control refuses evidence
            // older than five minutes.
            let fresh = bucket.list(&file.key).await?.into_iter().find(|o| o.key == file.key);
            let outcome = match fresh {
                Some(object) if Some(&object.etag) == file.etag.as_ref() && object.size == file.size => {
                    let evidence = evidence(tenant, file, bucket.source(), chrono::Utc::now())?;
                    ledger.backfill(tenant, file, reason, &evidence).await
                }
                _ => Err(anyhow::anyhow!("object changed between plan and apply")),
            };
            match outcome {
                Ok(result) => {
                    match result["status"].as_str() {
                        Some("backfilled") => summary.backfilled += 1,
                        Some("already_backfilled") => summary.already_backfilled += 1,
                        Some("already_receipted") => summary.already_receipted += 1,
                        other => bail!("unexpected backfill status {other:?} for {}", file.key),
                    }
                    emit(json!({"kind": "applied", "tenant": tenant, "key": file.key, "result": result}));
                }
                Err(error) => {
                    summary.apply_errors += 1;
                    emit(json!({"kind": "apply_error", "tenant": tenant, "key": file.key, "error": format!("{error:#}")}));
                }
            }
        }
    }
    Ok(summary)
}

/// Read-only gap query for a control database that predates 9012600 (no
/// backfill ledger yet): the function's body minus the ledger.
pub const INLINE_GAPS_SQL: &str = "
WITH head AS (
    SELECT h.indexed_through_seq FROM nano_shared.lake_part_log_index_heads h WHERE h.tenant_id = $1
), added AS (
    SELECT e.seq, e.op_kind, e.entry_key, e.entry_sha256, e.committed_at, a.part_id
      FROM nano_shared.lake_part_log_index_entries e
     CROSS JOIN LATERAL unnest(e.added_part_ids) AS a(part_id)
     WHERE e.tenant_id = $1 AND e.seq <= (SELECT indexed_through_seq FROM head)
       AND e.op_kind IN ('add', 'merge', 'rewrite')
), covered AS (
    SELECT DISTINCT substring(c.object_key FROM '/([0-9]{13}-[0-9a-f]{16})/') AS part_id
      FROM public.enterprise_shared_r2_writer_completion_receipts c
     WHERE c.tenant_id = $1 AND c.object_bucket = 'nano-shared-r2-' || $1::text
       AND c.object_key ~>=~ ('lake/parts/v1/tenant=' || $1::text || '/parts/')
       AND c.object_key ~<~ ('lake/parts/v1/tenant=' || $1::text || '/parts/~')
       AND c.writer_class = 'lake_part' AND c.key_family = 'lake_part_file'
)
SELECT a.part_id, a.seq AS added_seq, a.op_kind, a.entry_key, a.entry_sha256, a.committed_at,
       EXISTS (SELECT 1 FROM nano_shared.lake_part_log_index_live l WHERE l.tenant_id = $1 AND l.part_id = a.part_id) AS live,
       (SELECT min(r.seq) FROM nano_shared.lake_part_log_index_removals r
         WHERE r.tenant_id = $1 AND r.removed_part_ids @> ARRAY[a.part_id]) AS removed_seq
  FROM added a
 WHERE NOT EXISTS (SELECT 1 FROM covered c WHERE c.part_id = a.part_id)
 ORDER BY a.seq, a.part_id
 LIMIT $2";

/// Control over Postgres (the operator role, or the migrator for reads).
pub struct PgReceiptLedger {
    pub pool: sqlx::PgPool,
}

#[async_trait]
impl ReceiptLedger for PgReceiptLedger {
    async fn gaps(&self, tenant: uuid::Uuid, limit: i32) -> Result<Vec<ReceiptGap>> {
        use sqlx::Row;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY").execute(&mut *tx).await?;
        let has_function: bool = sqlx::query_scalar(
            "SELECT to_regprocedure('nano_shared.lake_part_receipt_gaps(uuid,integer)') IS NOT NULL")
            .fetch_one(&mut *tx).await?;
        let sql = if has_function { "SELECT * FROM nano_shared.lake_part_receipt_gaps($1, $2)" } else { INLINE_GAPS_SQL };
        let rows = sqlx::query(sql).bind(tenant).bind(limit).fetch_all(&mut *tx).await?;
        tx.rollback().await?;
        rows.into_iter().map(|row| Ok(ReceiptGap {
            part_id: row.try_get("part_id")?, added_seq: row.try_get("added_seq")?, op_kind: row.try_get("op_kind")?,
            entry_key: row.try_get("entry_key")?, entry_sha256: row.try_get("entry_sha256")?,
            committed_at: row.try_get("committed_at")?, live: row.try_get("live")?, removed_seq: row.try_get("removed_seq")?,
        })).collect()
    }

    async fn backfill(&self, tenant: uuid::Uuid, file: &PlannedFile, reason: &str, evidence: &Value) -> Result<Value> {
        let etag = file.etag.as_deref().context("planned file has no ETag")?;
        Ok(sqlx::query_scalar("SELECT nano_shared.backfill_lake_part_receipt($1, $2, $3, $4, $5, $6, $7, $8, $9)")
            .bind(tenant).bind(&file.key).bind(etag).bind(i64::try_from(file.size)?).bind(&file.sha256)
            .bind(file.added_seq).bind(&file.added_entry_sha256).bind(reason).bind(evidence)
            .fetch_one(&self.pool).await?)
    }
}

/// The tenant bucket through its S3 API (a `lake_part` read credential).
pub struct S3BucketEvidence {
    pub store: crate::part_ingest::s3_store::S3ObjectStore,
}

#[async_trait]
impl BucketEvidence for S3BucketEvidence {
    fn source(&self) -> &'static str { "r2_list" }
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        crate::parts::part_log::ObjectStore::get(&self.store, key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<ObservedObject>> {
        Ok(self.store.list_with_metadata(prefix).await?.into_iter()
            .map(|o| ObservedObject { key: o.key, etag: o.strong_etag, size: o.content_length }).collect())
    }
}

/// The tenant bucket through the Cloudflare R2 REST API (an account API
/// token with R2 read). Read-only: GET object and list objects only.
pub struct CloudflareBucketEvidence {
    pub client: reqwest::Client,
    pub api_base: String,
    pub account_id: String,
    pub bucket: String,
    pub token: zeroize::Zeroizing<String>,
}

impl CloudflareBucketEvidence {
    pub fn new(account_id: &str, bucket: &str, token: zeroize::Zeroizing<String>) -> Result<Self> {
        ensure!(!account_id.is_empty() && account_id.chars().all(|c| c.is_ascii_hexdigit()), "invalid Cloudflare account id");
        ensure!(bucket.starts_with("nano-shared-r2-"), "not a tenant lake bucket");
        Ok(Self {
            client: reqwest::Client::builder().timeout(std::time::Duration::from_secs(60))
                .redirect(reqwest::redirect::Policy::none()).build()?,
            api_base: "https://api.cloudflare.com/client/v4".into(),
            account_id: account_id.into(), bucket: bucket.into(), token,
        })
    }

    fn objects_url(&self) -> String {
        format!("{}/accounts/{}/r2/buckets/{}/objects", self.api_base, self.account_id, self.bucket)
    }
}

fn percent_encode_key(key: &str) -> String {
    key.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

#[async_trait]
impl BucketEvidence for CloudflareBucketEvidence {
    fn source(&self) -> &'static str { "r2_list" }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let response = self.client.get(format!("{}/{}", self.objects_url(), percent_encode_key(key)))
            .bearer_auth(self.token.as_str()).send().await?;
        match response.status().as_u16() {
            200 => {
                let bytes = response.bytes().await?;
                ensure!(bytes.len() <= 16 * 1024 * 1024, "object exceeds the reconciler read cap");
                Ok(Some(bytes.to_vec()))
            }
            404 => Ok(None),
            status => bail!("Cloudflare R2 GET answered HTTP {status}"),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObservedObject>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..64 {
            let mut query = vec![("prefix", prefix.to_owned()), ("per_page", "1000".to_owned())];
            if let Some(cursor) = &cursor {
                query.push(("cursor", cursor.clone()));
            }
            let page: Value = self.client.get(self.objects_url()).bearer_auth(self.token.as_str()).query(&query)
                .send().await?.error_for_status()?.json().await?;
            ensure!(page["success"] == true, "Cloudflare R2 list failed: {}", page["errors"]);
            for object in page["result"].as_array().context("R2 list result is not an array")? {
                let key = object["key"].as_str().context("listed object has no key")?;
                let etag = object["etag"].as_str().context("listed object has no etag")?;
                let size = object["size"].as_u64().context("listed object has no size")?;
                let etag = if etag.starts_with('"') { etag.to_owned() } else { format!("\"{etag}\"") };
                out.push(ObservedObject { key: key.to_owned(), etag, size });
            }
            match page["result_info"]["cursor"].as_str().filter(|c| !c.is_empty()) {
                Some(next) if page["result_info"]["is_truncated"] == true => cursor = Some(next.to_owned()),
                _ => return Ok(out),
            }
        }
        bail!("Cloudflare R2 listing exceeded 64 pages under {prefix}")
    }
}

#[cfg(test)]
mod tests;
