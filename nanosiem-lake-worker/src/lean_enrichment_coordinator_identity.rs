// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity directory writes for the tenant coordinator (NAN-3500). The
//! coordinator is the only holder of the tenant's read-write enrichment
//! credential, so it is the single writer of `identity/` in tenant R2.
//!
//! - `POST   /v1/identity/directory/deltas`                         one delta (adds, updates, tombstones)
//! - `POST   /v1/identity/directory/feeds/{feed}/runs/{run}/rows`   stage one chunk of a full feed run
//! - `POST   /v1/identity/directory/feeds/{feed}/runs/{run}/commit` replace the feed with the staged rows
//! - `DELETE /v1/identity/directory/feeds/{feed}/runs/{run}`        abandon a staged run
//! - `DELETE /v1/identity/directory/feeds/{feed}`                   remove the feed's rows
//! - `POST   /v1/identity/directory/compact`                        fold deltas into a snapshot
//!
//! The first four (the runner's write path) also accept the tenant's
//! identity-writer token (NAN-3503), and so does feed delete for a connector
//! feed's own sub-feeds (`<feed uuid>:users`, `<feed uuid>:groups`: the
//! runner removes an uninstalled directory feed); any other feed delete and
//! compact need the full token. A commit of zero rows (an empty snapshot)
//! needs `allow_empty: true`. Every body names its tenant and must equal the assignment. Staged runs
//! live in the process scratch only: a restart loses them, and the caller
//! re-runs (commit answers 409 `staged run is unknown`). A commit retried
//! after its answer was lost answers 200 again (the feed's last committed
//! run is remembered). Deltas may ask for patch semantics and name managers
//! by id (`patch`, `manager_refs`; NAN-3503).

use std::path::PathBuf;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{authorize, CoordinatorError, LeanCoordinatorState, Scope};
use crate::lean_identity_snapshot::{
    validate_feed_id, write_sorted_rows, IdentityPublication, IdentityRow, IdentityStore,
    IdentityStoreError, ManagerRef, IDENTITY_MAX_ROWS,
};

/// Ceiling on staged chunks in one run (the 5M-row cap at 20k-row export pages).
const MAX_STAGED_CHUNKS: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RowsRequest {
    tenant_id: Uuid,
    /// Optional optimistic-concurrency guard; absent means "on top of current".
    #[serde(default)]
    expected_revision: Option<Uuid>,
    rows: Vec<IdentityRow>,
    /// Patch semantics (NAN-3503): an empty or absent field of a live row
    /// keeps the current value instead of clearing it. Vendor deltas (Graph
    /// `users/delta`, Okta `lastUpdated`) carry changed users, and Graph only
    /// their changed properties.
    #[serde(default)]
    patch: bool,
    /// Managers named by id only, resolved here into `manager_upn`.
    #[serde(default)]
    manager_refs: Vec<ManagerRef>,
}

/// One chunk of a full feed run. Chunks are numbered by the caller, so a
/// retried chunk replaces itself instead of being counted twice.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageRequest {
    tenant_id: Uuid,
    chunk: u32,
    rows: Vec<IdentityRow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitRequest {
    tenant_id: Uuid,
    /// The number of rows the caller sent for this run (the snapshot-end count).
    expected_rows: u64,
    /// Required to commit zero rows: an empty snapshot empties the feed, so
    /// a vendor answering "no users" cannot do it by accident.
    #[serde(default)]
    allow_empty: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRequest {
    tenant_id: Uuid,
}

#[derive(Debug, Serialize)]
pub(super) struct IdentityResponse {
    status: &'static str,
    tenant_id: Uuid,
    revision: Uuid,
    snapshot_sha256: Option<String>,
    snapshot_rows: u64,
    deltas: usize,
    changed: bool,
    compacted: bool,
}

impl IdentityResponse {
    fn from(publication: IdentityPublication) -> Self {
        let manifest = publication.manifest;
        Self {
            status: if publication.changed {
                "published"
            } else {
                "unchanged"
            },
            tenant_id: manifest.tenant_id,
            revision: manifest.revision,
            snapshot_rows: manifest.snapshot.as_ref().map_or(0, |s| s.rows),
            snapshot_sha256: manifest.snapshot.map(|s| s.sha256),
            deltas: manifest.deltas.len(),
            changed: publication.changed,
            compacted: publication.compacted,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct StagedResponse {
    status: &'static str,
    tenant_id: Uuid,
    feed_id: String,
    run_id: String,
    staged_rows: u64,
    chunks: usize,
}

fn store_error(error: anyhow::Error) -> CoordinatorError {
    match error.downcast_ref::<IdentityStoreError>() {
        Some(IdentityStoreError::Conflict) => {
            CoordinatorError(StatusCode::CONFLICT, "tenant identity revision changed")
        }
        Some(IdentityStoreError::Invalid(_)) => {
            tracing::info!(error = %format!("{error:#}"), "identity mutation refused");
            CoordinatorError(StatusCode::BAD_REQUEST, "tenant identity mutation refused")
        }
        Some(IdentityStoreError::TooLarge(_)) => CoordinatorError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "tenant identity input exceeds its cap",
        ),
        None => {
            tracing::warn!(error = %format!("{error:#}"), "identity publication failed");
            CoordinatorError(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant identity store unavailable",
            )
        }
    }
}

fn bound<T: for<'de> Deserialize<'de>>(
    state: &LeanCoordinatorState,
    headers: &HeaderMap,
    body: &Bytes,
    scope: Scope,
    tenant: impl Fn(&T) -> Uuid,
) -> Result<T, CoordinatorError> {
    authorize(state, headers, scope)?;
    let request: T = serde_json::from_slice(body)
        .map_err(|_| CoordinatorError(StatusCode::BAD_REQUEST, "invalid identity request"))?;
    if tenant(&request) != state.tenant_id {
        return Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "tenant identity differs from assignment",
        ));
    }
    Ok(request)
}

fn run_token(value: &str) -> Result<(), CoordinatorError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b));
    if valid {
        Ok(())
    } else {
        Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "invalid identity run id",
        ))
    }
}

/// `<feed uuid>:users` or `<feed uuid>:groups` (lowercase hyphenated
/// uuid): the sub-feeds a connector identity feed writes.
fn connector_subfeed(feed: &str) -> bool {
    feed.split_once(':').is_some_and(|(id, sub)| {
        matches!(sub, "users" | "groups")
            && Uuid::parse_str(id).is_ok_and(|uuid| uuid.hyphenated().to_string() == id)
    })
}

fn feed_token(value: &str) -> Result<(), CoordinatorError> {
    validate_feed_id(value)
        .map_err(|_| CoordinatorError(StatusCode::BAD_REQUEST, "invalid identity feed id"))
}

fn identity_store(state: &LeanCoordinatorState) -> Result<IdentityStore<'_>, CoordinatorError> {
    IdentityStore::new(state.tenant_id, &*state.objects, &state.scratch).map_err(|_| {
        CoordinatorError(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant identity store unavailable",
        )
    })
}

/// `<scratch>/identity-staging/<feed>/<run>/` (both tokens validated).
fn run_dir(state: &LeanCoordinatorState, feed: &str, run: &str) -> PathBuf {
    state.scratch.join("identity-staging").join(feed).join(run)
}

/// `<scratch>/identity-staging/<feed>/.committed`: `<run> <expected_rows>`
/// of the feed's last committed run, so a retried commit is idempotent.
/// Not a run directory (the sweep's `remove_dir_all` skips files).
fn committed_marker(state: &LeanCoordinatorState, feed: &str) -> PathBuf {
    state
        .scratch
        .join("identity-staging")
        .join(feed)
        .join(".committed")
}

/// Staged runs untouched this long are abandoned (a crashed or superseded
/// export or connector run) and removed on the next staging call.
const STAGED_RUN_TTL: std::time::Duration = std::time::Duration::from_secs(6 * 3600);

fn sweep_abandoned_runs(state: &LeanCoordinatorState) {
    let root = state.scratch.join("identity-staging");
    let Ok(feeds) = std::fs::read_dir(&root) else {
        return;
    };
    for feed in feeds.flatten() {
        let Ok(runs) = std::fs::read_dir(feed.path()) else {
            continue;
        };
        for run in runs.flatten() {
            let stale = run
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age > STAGED_RUN_TTL);
            if stale {
                let _ = std::fs::remove_dir_all(run.path());
            }
        }
    }
}

fn staged_chunks(dir: &std::path::Path) -> std::io::Result<Vec<PathBuf>> {
    let mut chunks: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "parquet"))
        .collect();
    chunks.sort();
    Ok(chunks)
}

/// Rows the caller submitted for the run (before de-duplication), summed
/// over each chunk's `<chunk>.count` sidecar.
fn staged_count(dir: &std::path::Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "count"))
                .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
                .filter_map(|text| text.trim().parse::<u64>().ok())
                .sum()
        })
        .unwrap_or(0)
}

pub(super) async fn deltas(
    State(state): State<LeanCoordinatorState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<IdentityResponse>, CoordinatorError> {
    let request: RowsRequest = bound(
        &state,
        &headers,
        &body,
        Scope::IdentityWrite,
        |r: &RowsRequest| r.tenant_id,
    )?;
    let _guard = state.writer.lock().await;
    let store = identity_store(&state)?;
    let current = store.current().await.map_err(store_error)?;
    let expected = request
        .expected_revision
        .or(current.as_ref().map(|m| m.revision));
    let rows = if request.patch || !request.manager_refs.is_empty() {
        // Prepared against `current`: a different expected revision is the
        // conflict append_delta reports.
        store
            .prepare_delta(
                current.as_ref(),
                request.rows,
                request.patch,
                &request.manager_refs,
            )
            .await
            .map_err(store_error)?
    } else {
        request.rows
    };
    let publication = store
        .append_delta(expected, rows)
        .await
        .map_err(store_error)?;
    Ok(Json(IdentityResponse::from(publication)))
}

pub(super) async fn stage_rows(
    State(state): State<LeanCoordinatorState>,
    Path((feed, run)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<StagedResponse>, CoordinatorError> {
    let request: StageRequest = bound(
        &state,
        &headers,
        &body,
        Scope::IdentityWrite,
        |r: &StageRequest| r.tenant_id,
    )?;
    feed_token(&feed)?;
    run_token(&run)?;
    if request.chunk as usize >= MAX_STAGED_CHUNKS {
        return Err(CoordinatorError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "tenant identity input exceeds its cap",
        ));
    }
    if request.rows.iter().any(|row| row.feed_id != feed) {
        return Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "staged identity rows belong to another feed",
        ));
    }
    let _guard = state.writer.lock().await;
    sweep_abandoned_runs(&state);
    let dir = run_dir(&state, &feed, &run);
    std::fs::create_dir_all(&dir).map_err(|_| {
        CoordinatorError(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity staging unavailable",
        )
    })?;
    let path = dir.join(format!("{:04}.parquet", request.chunk));
    let count = dir.join(format!("{:04}.count", request.chunk));
    // A retried chunk replaces its earlier copy.
    let _ = std::fs::remove_file(&count);
    let rows = request.rows.len() as u64;
    if staged_count(&dir) + rows > IDENTITY_MAX_ROWS {
        return Err(CoordinatorError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "tenant identity input exceeds its cap",
        ));
    }
    if let Err(error) = write_sorted_rows(&path, request.rows) {
        let _ = std::fs::remove_file(&path);
        return Err(store_error(error));
    }
    std::fs::write(&count, rows.to_string()).map_err(|_| {
        CoordinatorError(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity staging unavailable",
        )
    })?;
    Ok(Json(StagedResponse {
        status: "staged",
        tenant_id: state.tenant_id,
        feed_id: feed,
        run_id: run,
        staged_rows: staged_count(&dir),
        chunks: staged_chunks(&dir).map(|c| c.len()).unwrap_or(0),
    }))
}

/// One line of `POST /v1/identity/directory/ingest` (NAN-3767): the
/// Vector `lake_identity_directory` sink's NDJSON contract. Rows arrive
/// through the tenant's Vector enrichment lane (runner or provider sync →
/// Vector `:8090` `nano_enrich` → this route), so a line may be delivered
/// twice (a retried request) or a runner page may be split across requests.
/// Both are harmless:
/// - `stage`: the row joins run `run_id` of sub-feed `feed_id`. A staged
///   chunk is named by its content digest (a retried request replaces
///   itself) and keeps the digests of its `external_id`s, so the commit
///   counts DISTINCT users, however the rows were split or repeated.
/// - `delta`: an upsert or tombstone keyed by `(feed_id, external_id)`,
///   the highest `version` winning; a repeated line changes nothing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "op", rename_all = "snake_case")]
enum IngestLine {
    Stage {
        feed_id: String,
        run_id: String,
        row: IdentityRow,
    },
    Delta {
        row: IdentityRow,
        #[serde(default)]
        patch: bool,
        #[serde(default)]
        manager_ref: Option<ManagerRef>,
    },
}

#[derive(Debug, Serialize)]
pub(super) struct IngestResponse {
    status: &'static str,
    tenant_id: Uuid,
    staged_rows: u64,
    delta_rows: u64,
    revision: Option<Uuid>,
}

/// Most staged chunk files one run may hold over the NDJSON route (a
/// 5M-user run at the sink's 20k-row batches is 250).
const MAX_INGEST_CHUNKS: usize = 4096;

/// 16-byte digest of a staged row's key, kept in `<chunk>.keys`.
fn key_digest(feed: &str, external_id: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(feed.as_bytes());
    h.update([0u8]);
    h.update(external_id.as_bytes());
    let full = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Distinct staged keys over every `<chunk>.keys` sidecar of a run.
fn distinct_keys(dir: &std::path::Path) -> u64 {
    let mut keys = std::collections::HashSet::<[u8; 16]>::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    for entry in entries.flatten() {
        if !entry.path().extension().is_some_and(|ext| ext == "keys") {
            continue;
        }
        if let Ok(bytes) = std::fs::read(entry.path()) {
            for key in bytes.chunks_exact(16) {
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                keys.insert(k);
            }
        }
    }
    keys.len() as u64
}

/// Rows of a run as the commit counts them: the legacy chunks' submitted
/// counts plus the NDJSON chunks' distinct keys.
fn run_rows(dir: &std::path::Path) -> u64 {
    staged_count(dir) + distinct_keys(dir)
}

fn ingest_refused(message: &'static str) -> CoordinatorError {
    CoordinatorError(StatusCode::BAD_REQUEST, message)
}

/// `POST /v1/identity/directory/ingest`: NDJSON `stage` / `delta` lines
/// for this tenant (`X-Nano-Tenant-ID`). The whole request is refused when
/// any line is invalid, so Vector reports the failure back to its sender.
pub(super) async fn ingest(
    State(state): State<LeanCoordinatorState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<IngestResponse>, CoordinatorError> {
    authorize(&state, &headers, Scope::IdentityWrite)?;
    super::tenant_header(&state, &headers)?;
    let mut staged: std::collections::BTreeMap<(String, String), Vec<IdentityRow>> = Default::default();
    let mut deltas: [Vec<IdentityRow>; 2] = [Vec::new(), Vec::new()];
    let mut refs: Vec<ManagerRef> = Vec::new();
    let mut lines = 0usize;
    for line in body.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        lines += 1;
        if lines > crate::lean_identity_snapshot::IDENTITY_MAX_BATCH_ROWS {
            return Err(CoordinatorError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "tenant identity input exceeds its cap",
            ));
        }
        match serde_json::from_slice::<IngestLine>(line)
            .map_err(|_| ingest_refused("invalid identity NDJSON line"))?
        {
            IngestLine::Stage { feed_id, run_id, row } => {
                feed_token(&feed_id)?;
                run_token(&run_id)?;
                if row.feed_id != feed_id {
                    return Err(ingest_refused("staged identity rows belong to another feed"));
                }
                staged.entry((feed_id, run_id)).or_default().push(row);
            }
            IngestLine::Delta { row, patch, manager_ref } => {
                if let Some(r) = manager_ref {
                    if !patch {
                        return Err(ingest_refused("identity manager references need patch deltas"));
                    }
                    if r.feed_id != row.feed_id || r.external_id != row.external_id {
                        return Err(ingest_refused("identity manager reference names another row"));
                    }
                    refs.push(r);
                }
                deltas[usize::from(patch)].push(row);
            }
        }
    }
    if lines == 0 {
        return Err(ingest_refused("identity batch is empty"));
    }
    let _guard = state.writer.lock().await;
    sweep_abandoned_runs(&state);
    let mut staged_rows = 0u64;
    for ((feed, run), rows) in staged {
        let dir = run_dir(&state, &feed, &run);
        std::fs::create_dir_all(&dir).map_err(|_| {
            CoordinatorError(StatusCode::SERVICE_UNAVAILABLE, "identity staging unavailable")
        })?;
        let mut keys: Vec<[u8; 16]> = rows.iter().map(|r| key_digest(&r.feed_id, &r.external_id)).collect();
        // Content-named: the same rows again (a retried request) land on
        // the same file.
        let digest = {
            use sha2::{Digest, Sha256};
            let mut sorted: Vec<Vec<u8>> = rows
                .iter()
                .map(|r| serde_json::to_vec(r).unwrap_or_default())
                .collect();
            sorted.sort();
            let mut h = Sha256::new();
            for r in &sorted {
                h.update(r);
                h.update([b'\n']);
            }
            hex::encode(&h.finalize()[..16])
        };
        let path = dir.join(format!("n-{digest}.parquet"));
        let keys_path = dir.join(format!("n-{digest}.keys"));
        if !keys_path.exists() {
            let chunks = staged_chunks(&dir).map(|c| c.len()).unwrap_or(0);
            if chunks >= MAX_INGEST_CHUNKS || run_rows(&dir) + rows.len() as u64 > IDENTITY_MAX_ROWS {
                return Err(CoordinatorError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "tenant identity input exceeds its cap",
                ));
            }
        }
        staged_rows += rows.len() as u64;
        if let Err(error) = write_sorted_rows(&path, rows) {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(&keys_path);
            return Err(store_error(error));
        }
        keys.sort_unstable();
        keys.dedup();
        let tmp = dir.join(format!("n-{digest}.keys.tmp"));
        std::fs::write(&tmp, keys.concat())
            .and_then(|_| std::fs::rename(&tmp, &keys_path))
            .map_err(|_| {
                CoordinatorError(StatusCode::SERVICE_UNAVAILABLE, "identity staging unavailable")
            })?;
    }
    let mut delta_rows = 0u64;
    let mut revision = None;
    let [plain, patched] = deltas;
    for (rows, patch) in [(plain, false), (patched, true)] {
        if rows.is_empty() {
            continue;
        }
        delta_rows += rows.len() as u64;
        let store = identity_store(&state)?;
        let current = store.current().await.map_err(store_error)?;
        let expected = current.as_ref().map(|m| m.revision);
        let rows = if patch {
            store
                .prepare_delta(current.as_ref(), rows, true, &refs)
                .await
                .map_err(store_error)?
        } else {
            rows
        };
        let publication = store.append_delta(expected, rows).await.map_err(store_error)?;
        revision = Some(publication.manifest.revision);
    }
    Ok(Json(IngestResponse {
        status: "accepted",
        tenant_id: state.tenant_id,
        staged_rows,
        delta_rows,
        revision,
    }))
}

pub(super) async fn commit_run(
    State(state): State<LeanCoordinatorState>,
    Path((feed, run)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<IdentityResponse>, CoordinatorError> {
    let request: CommitRequest = bound(
        &state,
        &headers,
        &body,
        Scope::IdentityWrite,
        |r: &CommitRequest| r.tenant_id,
    )?;
    feed_token(&feed)?;
    run_token(&run)?;
    if request.expected_rows == 0 && !request.allow_empty {
        return Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "an empty identity snapshot needs allow_empty",
        ));
    }
    let _guard = state.writer.lock().await;
    let dir = run_dir(&state, &feed, &run);
    let marker = committed_marker(&state, &feed);
    let receipt = format!("{run} {}", request.expected_rows);
    let chunks = match staged_chunks(&dir) {
        Ok(chunks) => chunks,
        // An allowed empty snapshot stages nothing (a chunk cannot be
        // empty): the commit empties the feed.
        Err(_)
            if request.expected_rows == 0
                && std::fs::read_to_string(&marker).ok().as_deref() != Some(receipt.as_str()) =>
        {
            Vec::new()
        }
        Err(_) => {
            // A retried commit (the first answer was lost to a timeout) finds
            // its run already folded in: answer 200 with the current revision
            // so the caller saves its cursor instead of looping on full runs.
            if std::fs::read_to_string(&marker).is_ok_and(|last| last == receipt) {
                let store = identity_store(&state)?;
                if let Some(manifest) = store.current().await.map_err(store_error)? {
                    return Ok(Json(IdentityResponse::from(IdentityPublication {
                        manifest,
                        changed: false,
                        compacted: false,
                    })));
                }
            }
            return Err(CoordinatorError(
                StatusCode::CONFLICT,
                "staged run is unknown",
            ));
        }
    };
    if run_rows(&dir) != request.expected_rows {
        return Err(CoordinatorError(
            StatusCode::CONFLICT,
            "staged row count differs from the run's snapshot-end count",
        ));
    }
    let store = identity_store(&state)?;
    let expected = store
        .current()
        .await
        .map_err(store_error)?
        .map(|m| m.revision);
    let result = store.replace_feed(expected, &feed, &chunks).await;
    let _ = std::fs::remove_dir_all(&dir);
    let publication = result.map_err(store_error)?;
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(error) = std::fs::write(&marker, &receipt) {
        tracing::warn!(error = %error.kind(), "identity commit receipt not kept; a retried commit answers 409");
    }
    Ok(Json(IdentityResponse::from(publication)))
}

pub(super) async fn abort_run(
    State(state): State<LeanCoordinatorState>,
    Path((feed, run)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, CoordinatorError> {
    bound(
        &state,
        &headers,
        &body,
        Scope::IdentityWrite,
        |r: &TenantRequest| r.tenant_id,
    )?;
    feed_token(&feed)?;
    run_token(&run)?;
    let _guard = state.writer.lock().await;
    let _ = std::fs::remove_dir_all(run_dir(&state, &feed, &run));
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn delete_feed(
    State(state): State<LeanCoordinatorState>,
    Path(feed): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<IdentityResponse>, CoordinatorError> {
    // The runner may remove only a connector feed's own sub-feeds; push,
    // observed and any other feed need the full token.
    let scope = if connector_subfeed(&feed) {
        Scope::IdentityWrite
    } else {
        Scope::Full
    };
    bound(&state, &headers, &body, scope, |r: &TenantRequest| {
        r.tenant_id
    })?;
    feed_token(&feed)?;
    let _guard = state.writer.lock().await;
    let store = identity_store(&state)?;
    let Some(current) = store.current().await.map_err(store_error)? else {
        return Err(CoordinatorError(
            StatusCode::NOT_FOUND,
            "tenant identity directory is empty",
        ));
    };
    let publication = store
        .delete_feed(Some(current.revision), &feed)
        .await
        .map_err(store_error)?;
    Ok(Json(IdentityResponse::from(publication)))
}

pub(super) async fn compact(
    State(state): State<LeanCoordinatorState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<IdentityResponse>, CoordinatorError> {
    bound(&state, &headers, &body, Scope::Full, |r: &TenantRequest| {
        r.tenant_id
    })?;
    let _guard = state.writer.lock().await;
    let store = identity_store(&state)?;
    let Some(current) = store.current().await.map_err(store_error)? else {
        return Err(CoordinatorError(
            StatusCode::NOT_FOUND,
            "tenant identity directory is empty",
        ));
    };
    let publication = store
        .compact(Some(current.revision))
        .await
        .map_err(store_error)?;
    Ok(Json(IdentityResponse::from(publication)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lean_enrichment_coordinator::auth_digest;
    use crate::lean_identity_snapshot::SourceKind;
    use crate::parts::part_log::{LocalObjectStore, ObjectStore};
    use std::sync::Arc;

    const TOKEN: &str = "identity-coordinator-test-bearer-token-0123";

    fn setup(
        tenant: Uuid,
        dir: &std::path::Path,
    ) -> (LeanCoordinatorState, Arc<dyn ObjectStore>, HeaderMap) {
        let objects: Arc<dyn ObjectStore> =
            Arc::new(LocalObjectStore::new(dir.join("r2")).unwrap());
        let state = LeanCoordinatorState::new(
            tenant,
            auth_digest(TOKEN),
            objects.clone(),
            dir.join("scratch"),
        )
        .unwrap();
        let headers = HeaderMap::from_iter([(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {TOKEN}").parse().unwrap(),
        )]);
        (state, objects, headers)
    }

    fn rows_body(tenant: Uuid, rows: &[IdentityRow]) -> Bytes {
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({"tenant_id": tenant, "rows": rows})).unwrap(),
        )
    }

    fn stage_body(tenant: Uuid, chunk: u32, rows: &[IdentityRow]) -> Bytes {
        Bytes::from(
            serde_json::to_vec(
                &serde_json::json!({"tenant_id": tenant, "chunk": chunk, "rows": rows}),
            )
            .unwrap(),
        )
    }

    fn row(feed: &str, id: &str) -> IdentityRow {
        let mut row = IdentityRow::new(feed, id, SourceKind::Pull, 1);
        row.email = format!("{id}@example.com");
        row
    }

    #[tokio::test]
    async fn an_empty_commit_needs_allow_empty_and_retries_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let (state, objects, headers) = setup(tenant, dir.path());
        let _ = deltas(
            State(state.clone()),
            headers.clone(),
            rows_body(tenant, &[row("okta", "a"), row("other", "b")]),
        )
        .await
        .unwrap();
        // Nothing is staged (a chunk cannot be empty).
        let commit = |body: serde_json::Value| {
            commit_run(
                State(state.clone()),
                Path(("okta".to_string(), "run-0".to_string())),
                headers.clone(),
                Bytes::from(serde_json::to_vec(&body).unwrap()),
            )
        };
        let refused = commit(serde_json::json!({"tenant_id": tenant, "expected_rows": 0}))
            .await
            .unwrap_err();
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        let refused = commit(
            serde_json::json!({"tenant_id": tenant, "expected_rows": 0, "allow_empty": false}),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        let allowed =
            serde_json::json!({"tenant_id": tenant, "expected_rows": 0, "allow_empty": true});
        let first = commit(allowed.clone()).await.unwrap().0;
        assert!(first.changed);
        // A retry after a lost answer is still a 200.
        let again = commit(allowed).await.unwrap().0;
        assert_eq!((again.changed, again.revision), (false, first.revision));
        let store = IdentityStore::new(tenant, &*objects, &dir.path().join("read")).unwrap();
        let view = store
            .load_view(&store.current().await.unwrap().unwrap())
            .await
            .unwrap();
        assert!(view.get("okta", "a").unwrap().is_none());
        assert!(view.get("other", "b").unwrap().is_some());
    }

    fn ingest_body(lines: &[serde_json::Value]) -> Bytes {
        let mut out = Vec::new();
        for line in lines {
            out.extend(serde_json::to_vec(line).unwrap());
            out.push(b'\n');
        }
        Bytes::from(out)
    }

    fn with_tenant(headers: &HeaderMap, tenant: Uuid) -> HeaderMap {
        let mut h = headers.clone();
        h.insert("x-nano-tenant-id", tenant.to_string().parse().unwrap());
        h
    }

    fn stage_line(feed: &str, run: &str, id: &str) -> serde_json::Value {
        serde_json::json!({"op": "stage", "feed_id": feed, "run_id": run, "row": row(feed, id)})
    }

    #[tokio::test]
    async fn ingest_split_and_retried_stage_lines_commit_distinct_users() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let (state, objects, headers) = setup(tenant, dir.path());
        let h = with_tenant(&headers, tenant);
        let feed = "0199a0c4-2222-7000-8000-000000000001:users";
        // One runner page of three users, split by Vector into two requests,
        // the first delivered twice and the second overlapping it.
        let first = ingest_body(&[stage_line(feed, "run-1", "a"), stage_line(feed, "run-1", "b")]);
        let second = ingest_body(&[stage_line(feed, "run-1", "b"), stage_line(feed, "run-1", "c")]);
        for body in [first.clone(), first, second] {
            let ok = ingest(State(state.clone()), h.clone(), body).await.unwrap().0;
            assert_eq!(ok.tenant_id, tenant);
        }
        let commit = |expected: u64| {
            commit_run(
                State(state.clone()),
                Path((feed.to_string(), "run-1".to_string())),
                headers.clone(),
                Bytes::from(
                    serde_json::to_vec(&serde_json::json!({"tenant_id": tenant, "expected_rows": expected}))
                        .unwrap(),
                ),
            )
        };
        // The submitted-line count (6) is not the user count.
        assert_eq!(commit(6).await.unwrap_err().0, StatusCode::CONFLICT);
        let published = commit(3).await.unwrap().0;
        assert!(published.changed);
        assert_eq!(published.snapshot_rows, 3);
        let store = IdentityStore::new(tenant, &*objects, &dir.path().join("read")).unwrap();
        let view = store.load_view(&store.current().await.unwrap().unwrap()).await.unwrap();
        for id in ["a", "b", "c"] {
            assert!(view.get(feed, id).unwrap().is_some(), "{id}");
        }
    }

    #[tokio::test]
    async fn ingest_deltas_are_idempotent_and_versioned() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let (state, objects, headers) = setup(tenant, dir.path());
        let h = with_tenant(&headers, tenant);
        let mut old = row("push:okta", "u1");
        old.department = "Sales".into();
        let mut new = old.clone();
        new.version = 2;
        new.department = "Security".into();
        let line = |r: &IdentityRow| serde_json::json!({"op": "delta", "row": r});
        // Out of order and repeated: the highest version wins, one row.
        for body in [ingest_body(&[line(&new)]), ingest_body(&[line(&old)]), ingest_body(&[line(&new)])] {
            let _ = ingest(State(state.clone()), h.clone(), body).await.unwrap();
        }
        let store = IdentityStore::new(tenant, &*objects, &dir.path().join("read")).unwrap();
        let view = store.load_view(&store.current().await.unwrap().unwrap()).await.unwrap();
        assert_eq!(view.get("push:okta", "u1").unwrap().unwrap().department, "Security");
    }

    #[tokio::test]
    async fn ingest_refuses_other_tenants_bad_lines_and_wrong_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let (state, _objects, headers) = setup(tenant, dir.path());
        let feed = "0199a0c4-2222-7000-8000-000000000001:users";
        let body = ingest_body(&[stage_line(feed, "run-1", "a")]);
        // No tenant header, another tenant.
        assert_eq!(ingest(State(state.clone()), headers.clone(), body.clone()).await.unwrap_err().0, StatusCode::BAD_REQUEST);
        let other = with_tenant(&headers, Uuid::new_v4());
        assert_eq!(ingest(State(state.clone()), other, body.clone()).await.unwrap_err().0, StatusCode::BAD_REQUEST);
        // Wrong bearer.
        let mut bad = with_tenant(&headers, tenant);
        bad.insert(axum::http::header::AUTHORIZATION, "Bearer nope-nope-nope-nope-nope-nope-nope".parse().unwrap());
        assert_eq!(ingest(State(state.clone()), bad, body).await.unwrap_err().0, StatusCode::UNAUTHORIZED);
        let h = with_tenant(&headers, tenant);
        // A stage row naming another feed, an unknown op, an unknown field,
        // a manager reference on a whole-row delta, an empty body.
        let mut stray = stage_line(feed, "run-1", "a");
        stray["feed_id"] = serde_json::json!("okta");
        let bad_ref = serde_json::json!({"op": "delta", "row": row("okta", "a"),
            "manager_ref": {"feed_id": "okta", "external_id": "a", "manager_external_id": "m"}});
        for body in [
            ingest_body(&[stray]),
            ingest_body(&[serde_json::json!({"op": "commit"})]),
            ingest_body(&[serde_json::json!({"op": "delta", "row": row("okta", "a"), "tenant_id": tenant})]),
            ingest_body(&[bad_ref]),
            Bytes::from_static(b"\n\n"),
        ] {
            assert_eq!(ingest(State(state.clone()), h.clone(), body).await.unwrap_err().0, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn connector_subfeeds_are_exactly_uuid_users_or_groups() {
        let id = "0199a0c4-2222-7000-8000-000000000001";
        assert!(connector_subfeed(&format!("{id}:users")));
        assert!(connector_subfeed(&format!("{id}:groups")));
        for bad in [
            "okta".to_string(),
            "push:okta".to_string(),
            "observed".to_string(),
            format!("{id}:roles"),
            format!("{id}:users:x"),
            format!("{}:users", id.to_uppercase()),
            format!("{}:users", id.replace('-', "")),
            ":users".to_string(),
            format!("{id}:"),
        ] {
            assert!(!connector_subfeed(&bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn staged_run_replaces_the_feed_and_checks_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let (state, objects, headers) = setup(tenant, dir.path());
        let feed_run = || Path(("okta".to_string(), "run-1".to_string()));
        let _ = stage_rows(
            State(state.clone()),
            feed_run(),
            headers.clone(),
            stage_body(tenant, 0, &[row("okta", "a")]),
        )
        .await
        .unwrap();
        // A retried chunk replaces itself rather than counting twice.
        let _ = stage_rows(
            State(state.clone()),
            feed_run(),
            headers.clone(),
            stage_body(tenant, 0, &[row("okta", "a")]),
        )
        .await
        .unwrap();
        let staged = stage_rows(
            State(state.clone()),
            feed_run(),
            headers.clone(),
            stage_body(tenant, 1, &[row("okta", "b")]),
        )
        .await
        .unwrap()
        .0;
        assert_eq!((staged.staged_rows, staged.chunks), (2, 2));
        let wrong = commit_run(
            State(state.clone()),
            feed_run(),
            headers.clone(),
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({"tenant_id": tenant, "expected_rows": 3}))
                    .unwrap(),
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(wrong.0, StatusCode::CONFLICT);
        let committed = commit_run(
            State(state.clone()),
            feed_run(),
            headers.clone(),
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({"tenant_id": tenant, "expected_rows": 2}))
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .0;
        assert_eq!((committed.snapshot_rows, committed.changed), (2, true));
        // The staged run is consumed; a retried commit of the same run (its
        // answer lost to a timeout) answers 200 without changing anything.
        let commit = |run: &str, rows: u64| {
            commit_run(
                State(state.clone()),
                Path(("okta".to_string(), run.to_string())),
                headers.clone(),
                Bytes::from(
                    serde_json::to_vec(
                        &serde_json::json!({"tenant_id": tenant, "expected_rows": rows}),
                    )
                    .unwrap(),
                ),
            )
        };
        let again = commit("run-1", 2).await.unwrap().0;
        assert_eq!(
            (again.snapshot_rows, again.changed, again.revision),
            (2, false, committed.revision)
        );
        // Another count, or another run, is still unknown.
        assert_eq!(
            commit("run-1", 3).await.unwrap_err().0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            commit("run-2", 2).await.unwrap_err().0,
            StatusCode::CONFLICT
        );
        let store = IdentityStore::new(tenant, &*objects, &dir.path().join("read")).unwrap();
        let view = store
            .load_view(&store.current().await.unwrap().unwrap())
            .await
            .unwrap();
        assert_eq!(view.len(), 2);
    }

    fn delta_body(tenant: Uuid, rows: &[IdentityRow], extra: serde_json::Value) -> Bytes {
        let mut body = serde_json::json!({"tenant_id": tenant, "rows": rows});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        Bytes::from(serde_json::to_vec(&body).unwrap())
    }

    #[tokio::test]
    async fn patch_deltas_keep_unsent_fields_and_resolve_managers_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let (state, objects, headers) = setup(tenant, dir.path());
        let user = |id: &str, version: i64| {
            let mut r = IdentityRow::new("okta:users", id, SourceKind::Pull, version);
            r.upn = format!("{id}@acme.example");
            r.title = "Engineer".into();
            r.department = "R&D".into();
            r.account_status = "active".into();
            r.account_enabled = Some(true);
            r
        };
        let mut boss = user("boss", 1);
        boss.title = "VP".into();
        let mut u1 = user("u1", 1);
        u1.manager_upn = "boss@acme.example".into();
        let _ = deltas(
            State(state.clone()),
            headers.clone(),
            delta_body(
                tenant,
                &[boss, u1.clone(), user("u2", 1)],
                serde_json::json!({}),
            ),
        )
        .await
        .unwrap();
        // A delta naming only u1's changed title (Graph sends changed
        // properties only), a new hire whose unchanged manager is not in
        // the delta, and a hire managed by another hire of the same delta.
        let mut u1_change = IdentityRow::new("okta:users", "u1", SourceKind::Pull, 2);
        u1_change.title = "Staff Engineer".into();
        let mut hire = user("u3", 2);
        hire.title = "New".into();
        let lead = user("u4", 2);
        let report = user("u5", 2);
        let refs = serde_json::json!({"patch": true, "manager_refs": [
            {"feed_id": "okta:users", "external_id": "u1", "manager_external_id": "boss"},
            {"feed_id": "okta:users", "external_id": "u3", "manager_external_id": "boss"},
            {"feed_id": "okta:users", "external_id": "u5", "manager_external_id": "u4"},
            {"feed_id": "okta:users", "external_id": "u2", "manager_external_id": "nobody"},
        ]});
        let mut u2_change = IdentityRow::new("okta:users", "u2", SourceKind::Pull, 2);
        u2_change.department = "Sales".into();
        let _ = deltas(
            State(state.clone()),
            headers.clone(),
            delta_body(tenant, &[u1_change, hire, lead, report, u2_change], refs),
        )
        .await
        .unwrap();
        let store = IdentityStore::new(tenant, &*objects, &dir.path().join("read")).unwrap();
        let view = store
            .load_view(&store.current().await.unwrap().unwrap())
            .await
            .unwrap();
        let get = |id: &str| view.get("okta:users", id).unwrap().unwrap();
        let u1 = get("u1");
        assert_eq!(
            (
                u1.title.as_str(),
                u1.manager_upn.as_str(),
                u1.upn.as_str(),
                u1.department.as_str()
            ),
            (
                "Staff Engineer",
                "boss@acme.example",
                "u1@acme.example",
                "R&D"
            )
        );
        assert_eq!((u1.version, u1.account_enabled), (2, Some(true)));
        assert_eq!(get("u3").manager_upn, "boss@acme.example");
        assert_eq!(get("u5").manager_upn, "u4@acme.example");
        let u2 = get("u2");
        assert_eq!(
            (
                u2.department.as_str(),
                u2.manager_upn.as_str(),
                u2.title.as_str()
            ),
            ("Sales", "", "Engineer")
        );

        // Without `patch`, a delta row still replaces the whole row.
        let bare = IdentityRow::new("okta:users", "u1", SourceKind::Pull, 3);
        let _ = deltas(
            State(state.clone()),
            headers.clone(),
            delta_body(tenant, &[bare], serde_json::json!({})),
        )
        .await
        .unwrap();
        let view = store
            .load_view(&store.current().await.unwrap().unwrap())
            .await
            .unwrap();
        assert_eq!(view.get("okta:users", "u1").unwrap().unwrap().title, "");

        // A reference to a row the request does not carry is refused.
        let refused = deltas(
            State(state.clone()),
            headers.clone(),
            delta_body(
                tenant,
                &[user("u6", 4)],
                serde_json::json!({"patch": true, "manager_refs": [
                    {"feed_id": "okta:users", "external_id": "u9", "manager_external_id": "boss"}]}),
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn deltas_delete_and_compact() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let (state, _objects, headers) = setup(tenant, dir.path());
        let first = deltas(
            State(state.clone()),
            headers.clone(),
            rows_body(tenant, &[row("okta", "a"), row("entra", "a")]),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(first.deltas, 1);
        let compacted = compact(
            State(state.clone()),
            headers.clone(),
            Bytes::from(serde_json::to_vec(&serde_json::json!({"tenant_id": tenant})).unwrap()),
        )
        .await
        .unwrap()
        .0;
        assert_eq!((compacted.deltas, compacted.snapshot_rows), (0, 2));
        let deleted = delete_feed(
            State(state.clone()),
            Path("okta".into()),
            headers.clone(),
            Bytes::from(serde_json::to_vec(&serde_json::json!({"tenant_id": tenant})).unwrap()),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(deleted.snapshot_rows, 1);
        let stale = deltas(State(state), headers,
            Bytes::from(serde_json::to_vec(&serde_json::json!({"tenant_id": tenant, "expected_revision": first.revision, "rows": [row("okta", "z")]})).unwrap())).await.unwrap_err();
        assert_eq!(stale.0, StatusCode::CONFLICT);
    }

    /// Negative cross-tenant test at the HTTP boundary: a body naming another
    /// tenant, a bad token, a foreign feed in a staged chunk, and a path
    /// traversal attempt are all refused without writing anything.
    #[tokio::test]
    async fn refuses_other_tenants_and_bad_input_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let (state, objects, headers) = setup(tenant, dir.path());
        let other = deltas(
            State(state.clone()),
            headers.clone(),
            rows_body(Uuid::new_v4(), &[row("okta", "a")]),
        )
        .await
        .unwrap_err();
        assert_eq!(other.0, StatusCode::BAD_REQUEST);
        let unauthenticated = deltas(
            State(state.clone()),
            HeaderMap::new(),
            rows_body(tenant, &[row("okta", "a")]),
        )
        .await
        .unwrap_err();
        assert_eq!(unauthenticated.0, StatusCode::UNAUTHORIZED);
        let foreign = stage_rows(
            State(state.clone()),
            Path(("okta".into(), "r".into())),
            headers.clone(),
            stage_body(tenant, 0, &[row("entra", "a")]),
        )
        .await
        .unwrap_err();
        assert_eq!(foreign.0, StatusCode::BAD_REQUEST);
        let traversal = stage_rows(
            State(state.clone()),
            Path(("okta".into(), "..".into())),
            headers.clone(),
            stage_body(tenant, 0, &[row("okta", "a")]),
        )
        .await
        .unwrap_err();
        assert_eq!(traversal.0, StatusCode::BAD_REQUEST);
        let bad_feed = stage_rows(
            State(state.clone()),
            Path(("ok/ta".into(), "r".into())),
            headers.clone(),
            stage_body(tenant, 0, &[row("okta", "a")]),
        )
        .await
        .unwrap_err();
        assert_eq!(bad_feed.0, StatusCode::BAD_REQUEST);
        let dotted = stage_rows(
            State(state.clone()),
            Path(("..".into(), "r".into())),
            headers.clone(),
            stage_body(tenant, 0, &[row("..", "a")]),
        )
        .await
        .unwrap_err();
        assert_eq!(dotted.0, StatusCode::BAD_REQUEST);
        let mut invalid = row("okta", "a");
        invalid.account_status = "frozen".into();
        let refused = deltas(State(state), headers, rows_body(tenant, &[invalid]))
            .await
            .unwrap_err();
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert!(objects.list("identity/").await.unwrap().is_empty());
    }
}
