// SPDX-License-Identifier: AGPL-3.0-or-later

//! Air-gapped enrichment bundle import (enterprise).
//!
//! WS3 of NAN-1201 (NAN-1205). For deployments with no outbound internet the
//! marketplace / IPinfo-Lite sync paths can't reach their feeds. Instead an
//! operator side-loads a signed bundle produced offline by the WS1 generator.
//! The bundle is an Ed25519-signed archive (see [`nanosiem_core::airgap`]); we
//! verify the signature + per-file checksums *before* any row lands, reject the
//! wrong `bundle_type`, then stream the verified payload into ClickHouse.
//!
//! Two payload shapes:
//!  - **IP** (`BundleType::IpEnrichment`): an IPinfo-Lite-format CSV (~400MB).
//!    We STREAM the verified payload reader straight through a `csv::Reader`
//!    into batched `INSERT`s — never buffering the whole payload — mirroring
//!    `EnrichmentService::stream_and_insert_ipinfo`. After the load we
//!    `SYSTEM RELOAD DICTIONARY nanosiem.ip_enrichment_dict` so lookups pick up
//!    the new generation immediately.
//!  - **IOC** (`BundleType::Ioc`): NDJSON of IOC records, landed into
//!    `nanosiem.custom_enrichment_results` (the canonical IOC store — PG
//!    `ioc_enrichments` is legacy, NAN-1112) via the shared
//!    `store_enrichment_records` batch writer, then a reload of the IOC dict.
//!
//! The checksum + byte-count for each payload are only enforced once the
//! payload `Read` hits EOF, so every code path drains the reader to completion
//! (the CSV iterator / NDJSON line loop run to the end; a mismatch surfaces as
//! a `BundleError::ChecksumMismatch`).

// Enterprise-only: the whole air-gap import surface is gated. Gating the module
// (rather than per-item) also avoids dead-code warnings on its helpers in the
// open edition.
#![cfg(feature = "enterprise")]

use axum::{
    extract::{Multipart, State},
    Extension, Json,
};
use nanosiem_core::airgap::{verify_bundle, BundleError, BundleType, VerifiedBundle};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, ENRICHMENT_SYNCED};
use nanosiem_core::auth::permissions;
use nanosiem_core::enrichment::IpInfoLiteRecord;
use serde::Serialize;
use std::io::Read;
use utoipa::ToSchema;

use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// `source_id` stamped on every CH IP-enrichment row imported from a bundle.
/// Distinct from the online `ipinfo_lite` source so an air-gap import never
/// purges (or is purged by) an online sync's generation — the stale-row DELETE
/// in both paths is scoped by `source_id`.
const AIRGAP_IP_SOURCE_ID: &str = "airgap_ip_enrichment";

/// Namespace + enrichment id for IOC rows imported from a bundle. The IOC dicts
/// partition `custom_enrichment_results` on `is_marketplace`; an air-gap import
/// is operator-provided OOTB content, so it lands as a marketplace IOC feed
/// (the `ioc_*` UDM columns), matching how the online ThreatFox feed lands.
const AIRGAP_IOC_NAMESPACE: &str = "airgap";
const AIRGAP_IOC_ENRICHMENT_ID: &str = "airgap_ioc";
const AIRGAP_IOC_ENRICHMENT_NAME: &str = "Air-gap IOC bundle";

/// Rows per ClickHouse INSERT. Matches `stream_and_insert_ipinfo`'s batch size;
/// keeps memory bounded while collapsing a 400MB feed into a few thousand
/// round-trips rather than one-per-row.
const IP_BATCH_SIZE: usize = 10_000;

/// Response for a completed air-gap enrichment import.
#[derive(Debug, Serialize, ToSchema)]
pub struct AirgapEnrichmentImportResponse {
    /// `"ip_enrichment"` or `"ioc"` — the bundle type that was imported.
    pub bundle_type: String,
    /// Content version string from the bundle manifest (operator-facing).
    pub content_version: String,
    /// Number of records landed into ClickHouse.
    pub records_imported: u64,
    /// Whether the backing dictionary was reloaded after the import.
    pub dictionary_reloaded: bool,
}

/// Map a `BundleError` to an `ApiError`. Signature / checksum / schema failures
/// are client-facing 400s (the operator uploaded a bad or tampered bundle);
/// I/O against ClickHouse is a 500.
fn bundle_err(e: BundleError) -> ApiError {
    match e {
        BundleError::Io(msg) => ApiError::InternalError(format!("Bundle I/O error: {msg}")),
        other => ApiError::BadRequest(format!("Invalid enrichment bundle: {other}")),
    }
}

/// Pull the single `file` field out of the multipart body as raw bytes.
///
/// The bundle is small enough as a wire envelope to read into memory here (the
/// ~400MB *payload* is streamed from the in-memory archive cursor into CH, not
/// re-buffered per row). `verify_bundle` needs a `Read + 'static`, which a
/// `Cursor<Vec<u8>>` satisfies.
async fn read_bundle_field(mut multipart: Multipart) -> Result<Vec<u8>, ApiError> {
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") {
            return Ok(field
                .bytes()
                .await
                .map_err(|e| ApiError::BadRequest(format!("Failed to read bundle: {e}")))?
                .to_vec());
        }
    }
    Err(ApiError::BadRequest(
        "No `file` field in multipart body".to_string(),
    ))
}

/// Import a signed air-gap enrichment bundle (IP geo/ASN or IOC).
///
/// POST /api/airgap/enrichment/import
///
/// Multipart form with one `file` field carrying the signed bundle archive.
/// The bundle's `manifest.json` `bundle_type` discriminates IP vs IOC; an
/// unexpected type (e.g. a parsers or license bundle) is rejected.
///
/// Requires: enrichments:configure
#[utoipa::path(
    post,
    path = "/api/airgap/enrichment/import",
    tag = "airgap",
    request_body(
        content = inline(AirgapEnrichmentImportResponse),
        description = "Multipart form with a `file` field: the signed enrichment bundle",
        content_type = "multipart/form-data"
    ),
    responses(
        (status = 200, description = "Bundle verified and imported", body = AirgapEnrichmentImportResponse),
        (status = 400, description = "Bad bundle: bad signature, checksum mismatch, wrong bundle_type, or unsupported schema"),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 500, description = "ClickHouse write error"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
#[cfg(feature = "enterprise")]
pub async fn import_enrichment_bundle(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    multipart: Multipart,
) -> Result<Json<AirgapEnrichmentImportResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let bytes = read_bundle_field(multipart).await?;

    // The verified bundle reader is `!Send` (a self-referential gzip/tar stream),
    // so it cannot be held across an `.await`. Do all verification + payload
    // reading on a blocking thread and drive the async ClickHouse inserts via
    // `Handle::block_on` — mirroring the license handler. Memory stays bounded
    // (one batch at a time); the ~400MB IP feed is never buffered whole.
    let ch = state.dual_pool.clickhouse().clone();
    let handle = tokio::runtime::Handle::current();
    let response = tokio::task::spawn_blocking(
        move || -> Result<AirgapEnrichmentImportResponse, ApiError> {
            // Signature + every per-file checksum is established here, before a
            // single row is written. `verify_bundle` uses the embedded build-time key.
            let bundle = verify_bundle(std::io::Cursor::new(bytes)).map_err(bundle_err)?;
            let content_version = bundle.manifest().content_version.clone();
            match bundle.bundle_type() {
                BundleType::IpEnrichment => import_ip_bundle(&ch, &handle, bundle, &content_version),
                BundleType::Ioc => import_ioc_bundle(&ch, &handle, bundle, &content_version),
                other => Err(ApiError::BadRequest(format!(
                    "Expected an ip_enrichment or ioc bundle, got {}",
                    bundle_type_str(other)
                ))),
            }
        },
    )
    .await
    .map_err(|e| ApiError::InternalError(format!("enrichment import task panicked: {e}")))??;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Enrichment, ENRICHMENT_SYNCED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "enrichment",
                None,
                Some(format!("airgap:{}", response.bundle_type)),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(response))
}

/// Human/string form of a `BundleType` for error + audit copy. Mirrors the
/// serde `snake_case` rename on the WS0 enum.
fn bundle_type_str(t: BundleType) -> &'static str {
    match t {
        BundleType::Parsers => "parsers",
        BundleType::IpEnrichment => "ip_enrichment",
        BundleType::Ioc => "ioc",
        BundleType::License => "license",
        BundleType::Rules => "rules",
        BundleType::Playbooks => "playbooks",
    }
}

/// Stream an IP-enrichment (IPinfo-Lite-format CSV) payload into ClickHouse.
///
/// The payload is read line-by-line through a `csv::Reader` — only one batch
/// (`IP_BATCH_SIZE` records) is held in memory at a time, so a ~400MB feed
/// never lands in a single buffer. We drain the reader to EOF so the WS0
/// checksum + byte-count guard fires; a mismatch surfaces as an io::Error whose
/// inner is `BundleError::ChecksumMismatch`.
#[cfg(feature = "enterprise")]
fn import_ip_bundle<R: Read + 'static>(
    ch: &clickhouse::Client,
    handle: &tokio::runtime::Handle,
    mut bundle: VerifiedBundle<R>,
    content_version: &str,
) -> Result<AirgapEnrichmentImportResponse, ApiError> {
    // One generation stamp for every row in this import; the post-load DELETE
    // purges this source's older CIDRs. fromUnixTimestamp64Milli at insert +
    // delete keeps the ms scale explicit (NAN-1123).
    let run_ms = chrono::Utc::now().timestamp_millis() as u64;

    let payload = bundle
        .next_payload()
        .map_err(bundle_err)?
        .ok_or_else(|| ApiError::BadRequest("IP bundle has no payload file".to_string()))?;

    // `csv::Reader` over the verified payload `Read`. has_headers=true skips the
    // IPinfo-Lite CSV header row; quoted fields (e.g. `as_name` = "Amazon.com,
    // Inc.") are handled by the csv crate, matching the online parse path.
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(payload);

    let mut total_inserted = 0u64;
    let mut batch: Vec<IpInfoLiteRecord> = Vec::with_capacity(IP_BATCH_SIZE);

    for result in reader.deserialize::<IpInfoLiteRecord>() {
        let record = result.map_err(map_csv_err)?;
        batch.push(record);

        if batch.len() >= IP_BATCH_SIZE {
            total_inserted += handle.block_on(insert_ip_batch(ch, run_ms, &batch))?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        total_inserted += handle.block_on(insert_ip_batch(ch, run_ms, &batch))?;
    }

    // Empty-feed footgun (mirrors stream_and_insert_ipinfo): a zero-row import
    // must NOT purge the prior generation, or the dict reloads empty.
    let mut dictionary_reloaded = false;
    if total_inserted > 0 {
        handle
            .block_on(
                ch.query(
                    "ALTER TABLE nanosiem.ip_enrichments \
                     DELETE WHERE source_id = ? AND updated_at < fromUnixTimestamp64Milli(toInt64(?))",
                )
                .bind(AIRGAP_IP_SOURCE_ID)
                .bind(run_ms)
                .execute(),
            )
            .map_err(|e| ApiError::InternalError(format!("Stale-row purge failed: {e}")))?;

        if let Err(e) = handle.block_on(
            ch.query("SYSTEM RELOAD DICTIONARY nanosiem.ip_enrichment_dict")
                .execute(),
        ) {
            tracing::warn!("Failed to reload ip_enrichment_dict after airgap import: {e}");
        } else {
            dictionary_reloaded = true;
        }
    } else {
        tracing::warn!("Air-gap IP enrichment bundle produced zero rows; keeping prior generation");
    }

    tracing::info!(
        records = total_inserted,
        content_version,
        "Air-gap IP enrichment bundle imported"
    );

    Ok(AirgapEnrichmentImportResponse {
        bundle_type: "ip_enrichment".to_string(),
        content_version: content_version.to_string(),
        records_imported: total_inserted,
        dictionary_reloaded,
    })
}

/// Map a CSV parse error, recovering an underlying `BundleError::ChecksumMismatch`
/// when the payload `Read` failed its EOF integrity check (csv wraps our io::Error).
fn map_csv_err(e: csv::Error) -> ApiError {
    if let csv::ErrorKind::Io(io_err) = e.kind() {
        // The payload Read surfaces a checksum/byte-count mismatch as an
        // io::Error whose into_inner() downcasts to BundleError.
        if let Some(inner) = io_err.get_ref() {
            if inner.downcast_ref::<BundleError>().is_some() {
                return ApiError::BadRequest(format!("Bundle integrity check failed: {inner}"));
            }
        }
    }
    ApiError::BadRequest(format!("Malformed IP enrichment CSV: {e}"))
}

/// Build + execute one multi-row INSERT for an IP-enrichment batch. Mirrors
/// `EnrichmentService::insert_ch_rows`: `network` is the verbatim CIDR String
/// (the IP_TRIE keys on CIDR text — do not coerce to a CH IP type); `updated_at`
/// (DateTime64(3)) is wrapped in fromUnixTimestamp64Milli (NAN-1123). On a
/// whole-chunk failure we retry record-by-record so one bad CIDR can't sink the
/// batch.
#[cfg(feature = "enterprise")]
async fn insert_ip_batch(
    ch: &clickhouse::Client,
    run_ms: u64,
    records: &[IpInfoLiteRecord],
) -> Result<u64, ApiError> {
    const COLUMNS: &str = "(network, source_id, country, country_code, continent, \
         continent_code, asn, as_name, as_domain, updated_at, deleted)";
    const VALUE_TUPLE: &str =
        "(?, ?, ?, ?, ?, ?, ?, ?, ?, fromUnixTimestamp64Milli(toInt64(?)), ?)";
    const CHUNK_SIZE: usize = 5000;

    let mut inserted = 0u64;
    for chunk in records.chunks(CHUNK_SIZE) {
        match insert_ip_rows(ch, run_ms, COLUMNS, VALUE_TUPLE, chunk).await {
            Ok(()) => inserted += chunk.len() as u64,
            Err(e) => {
                tracing::warn!(
                    chunk_size = chunk.len(),
                    error = %e,
                    "Air-gap IP batch insert failed; retrying records individually"
                );
                for record in chunk {
                    match insert_ip_rows(
                        ch,
                        run_ms,
                        COLUMNS,
                        VALUE_TUPLE,
                        std::slice::from_ref(record),
                    )
                    .await
                    {
                        Ok(()) => inserted += 1,
                        Err(e) => {
                            tracing::warn!(network = %record.network, error = %e, "Failed to store IP enrichment record");
                        }
                    }
                }
            }
        }
    }
    Ok(inserted)
}

/// One multi-row INSERT for `rows` (length >= 1).
#[cfg(feature = "enterprise")]
async fn insert_ip_rows(
    ch: &clickhouse::Client,
    run_ms: u64,
    columns: &str,
    value_tuple: &str,
    rows: &[IpInfoLiteRecord],
) -> Result<(), clickhouse::error::Error> {
    let tuples = vec![value_tuple; rows.len()].join(", ");
    let sql = format!("INSERT INTO nanosiem.ip_enrichments {columns} VALUES {tuples}");

    let mut q = ch.query(&sql);
    for record in rows {
        q = q
            .bind(&record.network)
            .bind(AIRGAP_IP_SOURCE_ID)
            .bind(&record.country)
            .bind(&record.country_code)
            .bind(&record.continent)
            .bind(&record.continent_code)
            .bind(&record.asn)
            .bind(&record.as_name)
            .bind(&record.as_domain)
            .bind(run_ms)
            .bind(0u8);
    }
    q.execute().await
}

/// Land an IOC bundle (NDJSON of IOC records) into the canonical CH IOC store
/// via the shared `store_enrichment_records` batch writer (NAN-1113), then
/// reload the IOC dictionary.
///
/// Each NDJSON line is one IOC record in the shape `store_enrichment_records`
/// expects (top-level `key` / `threat_type` / `malware` / `confidence`, plus
/// `data` / `tags` / `risk_score` / optional `key_type`). We parse a batch then
/// hand it off, never holding the whole payload. The payload is drained to EOF
/// (the line loop runs to completion) so the checksum guard fires.
#[cfg(feature = "enterprise")]
fn import_ioc_bundle<R: Read + 'static>(
    ch: &clickhouse::Client,
    handle: &tokio::runtime::Handle,
    mut bundle: VerifiedBundle<R>,
    content_version: &str,
) -> Result<AirgapEnrichmentImportResponse, ApiError> {
    use std::io::{BufRead, BufReader};

    let payload = bundle
        .next_payload()
        .map_err(bundle_err)?
        .ok_or_else(|| ApiError::BadRequest("IOC bundle has no payload file".to_string()))?;

    let reader = BufReader::new(payload);
    let mut batch: Vec<serde_json::Value> = Vec::with_capacity(1000);
    let mut total: u64 = 0;

    for line_result in reader.lines() {
        let line = line_result.map_err(map_io_err)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| ApiError::BadRequest(format!("Malformed IOC NDJSON line: {e}")))?;
        batch.push(record);

        if batch.len() >= 1000 {
            total += handle.block_on(store_ioc_batch(ch, &batch));
            batch.clear();
        }
    }
    if !batch.is_empty() {
        total += handle.block_on(store_ioc_batch(ch, &batch));
    }

    let mut dictionary_reloaded = false;
    if total > 0 {
        if let Err(e) = handle.block_on(
            ch.query("SYSTEM RELOAD DICTIONARY nanosiem.ioc_enrichment_dict")
                .execute(),
        ) {
            tracing::warn!("Failed to reload ioc_enrichment_dict after airgap import: {e}");
        } else {
            dictionary_reloaded = true;
        }
    }

    tracing::info!(
        records = total,
        content_version,
        "Air-gap IOC bundle imported"
    );

    Ok(AirgapEnrichmentImportResponse {
        bundle_type: "ioc".to_string(),
        content_version: content_version.to_string(),
        records_imported: total,
        dictionary_reloaded,
    })
}

/// Store one IOC batch via the shared enterprise writer. `key_type` defaults to
/// `"ip"` but each record may carry its own; `store_enrichment_records` takes a
/// single key_type per call, so we group by the per-record `key_type` to keep
/// IP/domain/hash IOCs in their right buckets.
#[cfg(feature = "enterprise")]
async fn store_ioc_batch(ch: &clickhouse::Client, batch: &[serde_json::Value]) -> u64 {
    use std::collections::HashMap;

    // Group records by key_type so a mixed bundle (ip + domain + hash) lands
    // with the correct per-record type without one call clobbering another.
    let mut by_type: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    for record in batch {
        let key_type = record
            .get("key_type")
            .and_then(|v| v.as_str())
            .unwrap_or("ip")
            .to_string();
        by_type.entry(key_type).or_default().push(record.clone());
    }

    let mut stored = 0u64;
    for (key_type, records) in by_type {
        // Air-gap IOCs are operator-provided OOTB feed content → marketplace
        // bucket (is_marketplace=true) + IOC (is_ioc=true) so they populate the
        // `ioc_*` UDM columns via ioc_enrichment_dict.
        let n = nanosiem_enterprise::custom_enrichment::store_enrichment_records(
            ch,
            AIRGAP_IOC_NAMESPACE,
            AIRGAP_IOC_ENRICHMENT_ID,
            AIRGAP_IOC_ENRICHMENT_NAME,
            &key_type,
            true, // is_ioc
            true, // is_marketplace
            &records,
        )
        .await;
        stored += n.max(0) as u64;
    }
    stored
}

/// Recover a `BundleError::ChecksumMismatch` from an io::Error raised while
/// draining the IOC payload (BufReader::lines wraps our payload Read).
fn map_io_err(e: std::io::Error) -> ApiError {
    if let Some(inner) = e.get_ref() {
        if inner.downcast_ref::<BundleError>().is_some() {
            return ApiError::BadRequest(format!("Bundle integrity check failed: {inner}"));
        }
    }
    ApiError::BadRequest(format!("IOC payload read error: {e}"))
}

/// OpenAPI documentation for air-gap enrichment import endpoints.
#[cfg(feature = "enterprise")]
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(import_enrichment_bundle),
    components(schemas(AirgapEnrichmentImportResponse))
)]
pub struct AirgapEnrichmentApiDoc;
