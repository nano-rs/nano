// SPDX-License-Identifier: AGPL-3.0-or-later

//! Async search job endpoints: polling, cancel, list, admin operations.

use axum::{
    body::{Body, Bytes},
    extract::{Extension, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures::Stream;
use nanosiem_core::{
    audit::{AuditEvent, AuditSource},
    auth::permissions,
    search::{AdminSearchJobSummary, AdmissionStats, DurableJobStoreError, SearchJobStatus, SearchJobSummary},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::pin::Pin;

use crate::error::ErrorResponse;
use crate::{error::SearchError, SearchState};

pub(super) fn map_job_store_error(error: DurableJobStoreError) -> SearchError {
    match error {
        DurableJobStoreError::Unavailable(detail) => {
            tracing::warn!(error = %detail, "durable search job state is unavailable");
            SearchError::ServiceUnavailable(
                "Search job state is temporarily unavailable; retry shortly".to_string(),
            )
        }
        DurableJobStoreError::Unsupported
        | DurableJobStoreError::Invalid(_)
        | DurableJobStoreError::ClaimRejected => {
            tracing::error!(error = %error, "durable search job state could not be read");
            SearchError::InternalError("Failed to read search job state".to_string())
        }
        // NAN-2361: a durable record whose signature does not verify is
        // treated as absent from the API surface; the detail is server-side.
        DurableJobStoreError::SignatureRejected(_) => {
            tracing::error!(error = %error, "durable search job record failed signature verification");
            SearchError::NotFound("Search job not found".to_string())
        }
    }
}

/// Shared job routes require the current server-resolved retention identity.
/// Completed result payloads are checked separately against their immutable
/// moving-cutoff receipt; list/cancel/status metadata remains usable so an
/// expired result cannot strand a still-running job.
pub(super) fn require_retention_safe_job_surface(auth: &crate::AuthContext) -> Result<(), SearchError> {
    if crate::is_shared_scope(auth.tenant_scope)
        && auth.tenant_scope.require_retention_identity().is_err()
    {
        return Err(SearchError::ServiceUnavailable(
            "Enterprise-shared search retention identity is unavailable".to_string(),
        ));
    }
    Ok(())
}

/// NAN-3286: a stored prevalence result is prevalence data. Its owner may
/// lose `prevalence:view` / `prevalence:export`, or the tenant its prevalence
/// plan component, after submission; every read re-decides that against the
/// caller's CURRENT authority. Denials are the same 404 a missing job returns.
pub(super) fn require_job_task_read_authority(
    auth: &crate::AuthContext,
    job: &nanosiem_core::search::SearchJob,
) -> Result<(), SearchError> {
    if !matches!(
        job.task,
        Some(nanosiem_core::search::DurableLakeTask::PrevalenceExportV1 { .. })
    ) {
        return Ok(());
    }
    // A rare list is a `prevalence:view` read; anything else is an export.
    let needed = if job.request.query.starts_with("prevalence rare ") {
        permissions::PREVALENCE_VIEW
    } else {
        permissions::PREVALENCE_EXPORT
    };
    if !auth.claims.has_permission(needed)
        || super::require_shared_prevalence_component(auth).is_err()
    {
        return Err(SearchError::NotFound(format!("Job not found: {}", job.id)));
    }
    Ok(())
}

pub(super) fn require_job_retention_visible(
    auth: &crate::AuthContext,
    job: &nanosiem_core::search::SearchJob,
) -> Result<(), SearchError> {
    if !crate::is_shared_scope(auth.tenant_scope) {
        return Ok(());
    }
    if job.backend != nanosiem_core::search::SearchJobBackend::LakeDurable {
        return job
            .verify_interactive_retention(auth.tenant_scope, chrono::Utc::now())
            .map_err(|_| SearchError::NotFound(format!("Job not found: {}", job.id)));
    }
    if job.status == nanosiem_core::search::SearchJobStatus::Completed {
        let reference = job
            .result_ref
            .as_ref()
            .ok_or_else(|| SearchError::NotFound(format!("Job not found: {}", job.id)))?;
        reference
            .verify_retention_for_range(
                auth.tenant_scope,
                &job.request.time_range,
                chrono::Utc::now(),
            )
            .map_err(|error| {
                tracing::warn!(
                    job_id = %job.id,
                    error = %error,
                    "shared durable result hidden by moving retention frontier"
                );
                SearchError::NotFound(format!("Job not found: {}", job.id))
            })?;
    }
    Ok(())
}

// ============================================================================
// Async Search Jobs
// ============================================================================

/// NAN-2109: composite gate for the cross-user search-job admin surface.
///
/// `settings:system` authorizes *administering* the search service; it is not a
/// substitute for the capability that governs search CONTENT. The admin
/// responses carry other principals' query text and user ids — exactly the
/// bytes `search:execute` protects on the ordinary routes (NAN-2032) — so both
/// capabilities are required (`AllOf`). Without this, a settings-only key that
/// is forbidden from listing its OWN jobs could enumerate everyone else's.
pub(super) fn require_search_admin(auth: &crate::AuthContext) -> Result<(), SearchError> {
    require_permission(auth, permissions::SETTINGS_SYSTEM)?;
    super::require_search_execute(auth)
}

/// Get the status of an async search job
///
/// Returns the job status, progress (if running), results (if completed),
/// or error message (if failed).
#[utoipa::path(
    get,
    path = "/api/search/jobs/{job_id}",
    tag = "search",
    params(
        ("job_id" = String, Path, description = "Async search job ID")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Job status and optional results", body = nanosiem_core::search::SearchJobStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
        (status = 404, description = "Job not found", body = ErrorResponse),
        (status = 503, description = "Durable job state is temporarily unavailable; search authority unavailable (search_authority_unavailable), Retry-After: 2", body = ErrorResponse),
    )
)]
pub async fn get_search_job(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path(job_id): Path<String>,
) -> Result<Json<nanosiem_core::search::SearchJobStatusResponse>, SearchError> {
    // NAN-2032: results are search output — require search:execute BEFORE the
    // ownership check, so revoking the capability revokes access to prior jobs.
    // Ownership is object-level authz, not the feature-capability gate. Admins
    // (settings:system) still bypass ownership below.
    super::require_search_execute(&auth)?;
    require_retention_safe_job_surface(&auth)?;
    let search = state.search_for_auth(&auth)?;

    let is_admin = auth.claims.has_permission(permissions::SETTINGS_SYSTEM);
    let (job, snapshot_status) = if crate::is_shared_scope(auth.tenant_scope) {
        let (job, status) = search.job_control().get_snapshot_checked(&job_id).await.map_err(map_job_store_error)?
            .ok_or_else(|| SearchError::NotFound(format!("Job not found: {job_id}")))?;
        (job, Some(status))
    } else {
        let job = search.job_control().get_checked(&job_id).await.map_err(map_job_store_error)?
            .ok_or_else(|| SearchError::NotFound(format!("Job not found: {job_id}")))?;
        (job, None)
    };

    if !is_admin && job.user_id != Some(auth.claims.sub) {
        return Err(SearchError::NotFound(format!("Job not found: {}", job_id)));
    }

    // NAN-2096: a stored result is not authorized by ownership + capability
    // alone. The rows were frozen under the deny-set the job EXECUTED with, so
    // re-decide the data-plane question against the caller's CURRENT effective
    // scope on every poll. A source restricted (or a grant revoked) after
    // submission makes the snapshot unreadable — including for an admin whose
    // own scope is narrower than the submitter's. Legacy/unstamped jobs fail
    // closed. The response is the SAME 404 a missing job returns, so this is not
    // an existence oracle. Applies to both job stores: the predicate reads the
    // stamp carried on `SearchJob`, which `InMemoryJobStore` and `RedisJobStore`
    // both populate at creation.
    if !job.result_visible_under(super::search::effective_scope(&auth).deny_set()) {
        tracing::warn!(
            job_id = %job_id,
            user_id = %auth.claims.sub,
            "Async search job hidden: caller's source scope narrowed since submission"
        );
        return Err(SearchError::NotFound(format!("Job not found: {}", job_id)));
    }
    require_job_retention_visible(&auth, &job)?;
    require_job_task_read_authority(&auth, &job)?;

    let status = match snapshot_status {
        Some(status) => Some(status),
        None => search.get_job_status_checked(&job_id).await.map_err(map_job_store_error)?,
    };
    match status {
        Some(mut status) => {
            status.task_kind = job.task.as_ref().map(|task| task.kind().to_string());
            status.query = Some(job.request.query.clone());
            status.time_range = Some(job.request.time_range.clone());
            status.dataset = job.request.dataset.clone();
            if let Some(reference) = status.result_ref.take() {
                status.durable_result = Some(nanosiem_core::search::SearchJobResultSummary {
                    rows: reference.rows,
                    pages: reference.parts,
                    page_rows: reference.page_rows,
                    has_more: reference.has_more,
                });
            }
            // NAN-3078: a post-processed durable search answers inline with
            // its Nano-side suffix applied. Its candidate pages are an
            // intermediate artifact and are never summarized or exposed.
            if let Some(nanosiem_core::search::DurableLakeTask::SearchNplPostV1 {
                post_query, ..
            }) = job.task.as_ref()
            {
                status.query = Some(post_query.clone());
                status.durable_result = None;
                if status.status == SearchJobStatus::Completed {
                    let response = search
                        .durable_post_processed_result(&job, &super::search::effective_scope(&auth))
                        .await
                        .map_err(|error| {
                            tracing::error!(job_id = %job_id, error = %error, "durable post-processing failed");
                            match error {
                                nanosiem_core::SearchError::ServiceUnavailable(_) => {
                                    SearchError::ServiceUnavailable(
                                        "Durable result storage is temporarily unavailable; retry shortly"
                                            .to_string(),
                                    )
                                }
                                other => SearchError::from(other),
                            }
                        })?;
                    status.result = Some(response);
                }
            }
            super::require_current_shared_authority(&state, &auth).await?;
            Ok(Json(status))
        }
        None => Err(SearchError::NotFound(format!("Job not found: {}", job_id))),
    }
}

/// NAN-3078: a post-processed search's pages hold its pre-suffix candidate
/// set, not its answer. They are read only by
/// `SearchService::durable_post_processed_result`, never served raw.
fn result_pages_are_intermediate(task: Option<&nanosiem_core::search::DurableLakeTask>) -> bool {
    matches!(task, Some(nanosiem_core::search::DurableLakeTask::SearchNplPostV1 { .. }))
}

/// Read one verified page from a completed durable search result.
#[utoipa::path(
    get,
    path = "/api/search/jobs/{job_id}/results/{page}",
    tag = "search",
    params(
        ("job_id" = String, Path, description = "Async search job ID"),
        ("page" = usize, Path, description = "Zero-based result page")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Verified durable result page", body = nanosiem_core::search::SearchJobResultPage),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
        (status = 404, description = "Job or result page not found", body = ErrorResponse),
        (status = 409, description = "The job's result is served inline on the job status (post-processed search)", body = ErrorResponse),
        (status = 503, description = "Durable job state is temporarily unavailable; search authority unavailable (search_authority_unavailable), Retry-After: 2", body = ErrorResponse),
    )
)]
pub async fn get_search_job_result_page(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path((job_id, page)): Path<(String, usize)>,
) -> Result<Json<nanosiem_core::search::SearchJobResultPage>, SearchError> {
    super::require_search_execute(&auth)?;
    require_retention_safe_job_surface(&auth)?;
    let search = state.search_for_auth(&auth)?;
    let is_admin = auth.claims.has_permission(permissions::SETTINGS_SYSTEM);
    let job = search
        .job_control()
        .get_checked(&job_id)
        .await
        .map_err(map_job_store_error)?
        .ok_or_else(|| SearchError::NotFound(format!("Job not found: {job_id}")))?;
    if (!is_admin && job.user_id != Some(auth.claims.sub))
        || !job.result_visible_under(super::search::effective_scope(&auth).deny_set())
    {
        return Err(SearchError::NotFound(format!("Job not found: {job_id}")));
    }
    require_job_retention_visible(&auth, &job)?;
    require_job_task_read_authority(&auth, &job)?;
    // NAN-3078: the pages of a post-processed search are its pre-suffix
    // candidate set; its answer is served inline on the job status.
    if result_pages_are_intermediate(job.task.as_ref()) {
        return Err(SearchError::Conflict(
            "This job's result is served on GET /api/search/jobs/{job_id}".to_string(),
        ));
    }
    let reference = job
        .result_ref
        .as_ref()
        .filter(|reference| page < reference.parts)
        .ok_or_else(|| SearchError::NotFound("Durable result page not found".to_string()))?;
    reference
        .verify_tenant(auth.tenant_scope)
        .map_err(|_| SearchError::NotFound("Durable result page not found".to_string()))?;
    let result = search
        .get_durable_job_result_page(&job_id, reference, page)
        .await
        .map_err(|error| {
            tracing::error!(job_id = %job_id, page, error = %error, "durable result page read failed");
            match error {
                nanosiem_core::SearchError::ServiceUnavailable(_) => {
                    SearchError::ServiceUnavailable(
                        "Durable result storage is temporarily unavailable; retry shortly"
                            .to_string(),
                    )
                }
                _ => SearchError::QueryError("Failed to read durable result page".to_string()),
            }
        })?;
    super::require_current_shared_authority(&state, &auth).await?;
    Ok(Json(result))
}

#[derive(Debug, Default, Deserialize)]
pub struct JobDownloadQuery {
    format: Option<String>,
}

/// Stream a completed search or typed Prevalence export from verified durable
/// pages. Every page traverses the tenant, scope, manifest, and checksum fences.
#[utoipa::path(
    get,
    path = "/api/search/jobs/{job_id}/download",
    tag = "search",
    params(("job_id" = String, Path, description = "Completed durable search or Prevalence export job ID")),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Streamed CSV, JSON, or NDJSON export", body = String),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
        (status = 404, description = "Job not found", body = ErrorResponse),
        (status = 409, description = "Job is incomplete or not downloadable", body = ErrorResponse),
        (status = 503, description = "Durable result storage is unavailable; search authority unavailable (search_authority_unavailable), Retry-After: 2", body = ErrorResponse),
    )
)]
pub async fn download_search_job_result(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path(job_id): Path<String>,
    Query(options): Query<JobDownloadQuery>,
) -> Result<Response, SearchError> {
    super::require_search_execute(&auth)?;
    require_retention_safe_job_surface(&auth)?;
    let search = state.search_for_auth(&auth)?;
    let is_admin = auth.claims.has_permission(permissions::SETTINGS_SYSTEM);
    let job = search
        .job_control()
        .get_checked(&job_id)
        .await
        .map_err(map_job_store_error)?
        .ok_or_else(|| SearchError::NotFound(format!("Job not found: {job_id}")))?;
    if (!is_admin && job.user_id != Some(auth.claims.sub))
        || !job.result_visible_under(super::search::effective_scope(&auth).deny_set())
    {
        return Err(SearchError::NotFound(format!("Job not found: {job_id}")));
    }
    require_job_retention_visible(&auth, &job)?;
    require_job_task_read_authority(&auth, &job)?;
    let format = match job.task.as_ref() {
        Some(nanosiem_core::search::DurableLakeTask::PrevalenceExportV1 { format, .. }) => {
            if options.format.as_deref().is_some_and(|requested| requested != format) {
                return Err(SearchError::Conflict("This export has a fixed format".to_string()));
            }
            format.clone()
        }
        Some(nanosiem_core::search::DurableLakeTask::SearchNplV1
            | nanosiem_core::search::DurableLakeTask::SearchNplShedV1 { .. }) => {
            let requested = options.format.as_deref().unwrap_or("json");
            if !matches!(requested, "csv" | "json" | "ndjson") {
                return Err(SearchError::Conflict("Unsupported search export format".to_string()));
            }
            requested.to_string()
        }
        _ => {
            return Err(SearchError::Conflict(
                "This durable job does not expose a download artifact".to_string(),
            ));
        }
    };
    let reference = job
        .result_ref
        .clone()
        .ok_or_else(|| SearchError::Conflict("Durable export has not completed".to_string()))?;
    reference
        .verify_tenant(auth.tenant_scope)
        .map_err(|_| SearchError::NotFound(format!("Job not found: {job_id}")))?;
    super::require_current_shared_authority(&state, &auth).await?;
    // CSV needs a stable header even if fields first appear on a later page.
    // This bounded first pass reads each verified page without retaining rows.
    let mut csv_columns = BTreeSet::new();
    let is_search = matches!(job.task, Some(nanosiem_core::search::DurableLakeTask::SearchNplV1
        | nanosiem_core::search::DurableLakeTask::SearchNplShedV1 { .. }));
    if is_search && format == "csv" {
        for page_number in 0..reference.parts {
            super::require_current_shared_authority(&state, &auth).await?;
            let page = search.get_durable_job_result_page(&job_id, &reference, page_number).await
                .map_err(|_| SearchError::ServiceUnavailable("Durable result storage is temporarily unavailable".to_string()))?;
            for row in page.rows {
                let object = row.as_object().ok_or_else(|| SearchError::QueryError("Durable result row is not an object".to_string()))?;
                csv_columns.extend(object.keys().cloned());
                if csv_columns.len() > 1_024 {
                    return Err(SearchError::QueryError("Durable result has too many CSV columns".to_string()));
                }
            }
        }
    }
    let csv_columns: Vec<String> = csv_columns.into_iter().collect();
    let stream_job_id = job_id.clone();
    let stream_format = format.clone();
    let stream_auth_state = state.auth_state.clone();
    let stream_auth = auth.clone();
    let stream_columns = csv_columns;
    let stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>> = Box::pin(
        async_stream::try_stream! {
            crate::middleware::revalidate_shared_context(
                &stream_auth_state,
                &stream_auth,
            )
            .await.into_result().map_err(|error| {
                    let kind = if error.status_code() == axum::http::StatusCode::FORBIDDEN {
                        std::io::ErrorKind::PermissionDenied
                    } else {
                        std::io::ErrorKind::Interrupted
                    };
                    std::io::Error::new(kind, error)
                })?;
            let mut first_json = true;
            if stream_format == "json" {
                yield Bytes::from_static(b"[\n");
            } else if stream_format == "csv" && is_search {
                yield Bytes::from(csv_header(&stream_columns));
            } else if stream_format == "csv" {
                yield Bytes::from_static(
                    b"artifact,type,host_count,total_occurrences,first_seen,last_seen,is_rare,prevalence_score\n",
                );
            }
            for page_number in 0..reference.parts {
                crate::middleware::revalidate_shared_context(
                    &stream_auth_state,
                    &stream_auth,
                )
                .await.into_result().map_err(|error| {
                    let kind = if error.status_code() == axum::http::StatusCode::FORBIDDEN {
                        std::io::ErrorKind::PermissionDenied
                    } else {
                        std::io::ErrorKind::Interrupted
                    };
                    std::io::Error::new(kind, error)
                })?;
                let page = search
                    .get_durable_job_result_page(&stream_job_id, &reference, page_number)
                    .await
                    .map_err(|error| {
                        tracing::error!(
                            job_id = %stream_job_id,
                            page = page_number,
                            %error,
                            "durable export page stream failed"
                        );
                        std::io::Error::other("durable export page stream failed")
                    })?;
                crate::middleware::revalidate_shared_context(
                    &stream_auth_state,
                    &stream_auth,
                )
                .await.into_result().map_err(|error| {
                    let kind = if error.status_code() == axum::http::StatusCode::FORBIDDEN {
                        std::io::ErrorKind::PermissionDenied
                    } else {
                        std::io::ErrorKind::Interrupted
                    };
                    std::io::Error::new(kind, error)
                })?;
                let mut rows_since_revalidation = 0usize;
                for row in page.rows {
                    if rows_since_revalidation >= 128 {
                        crate::middleware::revalidate_shared_context(
                            &stream_auth_state,
                            &stream_auth,
                        )
                        .await.into_result().map_err(|error| {
                    let kind = if error.status_code() == axum::http::StatusCode::FORBIDDEN {
                        std::io::ErrorKind::PermissionDenied
                    } else {
                        std::io::ErrorKind::Interrupted
                    };
                    std::io::Error::new(kind, error)
                })?;
                        rows_since_revalidation = 0;
                    }
                    if stream_format == "json" {
                        let mut encoded = Vec::new();
                        if !first_json {
                            encoded.extend_from_slice(b",\n");
                        }
                        serde_json::to_writer(&mut encoded, &row)
                            .map_err(std::io::Error::other)?;
                        first_json = false;
                        yield Bytes::from(encoded);
                    } else if stream_format == "ndjson" {
                        let mut encoded = serde_json::to_vec(&row).map_err(std::io::Error::other)?;
                        encoded.push(b'\n');
                        yield Bytes::from(encoded);
                    } else if is_search {
                        yield Bytes::from(search_csv_row(&row, &stream_columns)?);
                    } else {
                        yield Bytes::from(prevalence_csv_row(&row)?);
                    }
                    rows_since_revalidation += 1;
                }
            }
            if stream_format == "json" {
                yield Bytes::from_static(b"\n]\n");
            }
        },
    );
    let extension = format.as_str();
    let content_type = match format.as_str() {
        "json" => "application/json",
        "ndjson" => "application/x-ndjson",
        _ => "text/csv; charset=utf-8",
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}_export.{extension}\"", if is_search { "search" } else { "prevalence" }),
            ),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

fn prevalence_csv_row(row: &serde_json::Value) -> Result<String, std::io::Error> {
    let object = row
        .as_object()
        .ok_or_else(|| std::io::Error::other("durable export row is not an object"))?;
    let mut output = String::new();
    for (index, field) in [
        "artifact",
        "artifact_type",
        "host_count",
        "total_occurrences",
        "first_seen",
        "last_seen",
        "is_rare",
        "prevalence_score",
    ]
    .iter()
    .enumerate()
    {
        if index > 0 {
            output.push(',');
        }
        // CSV is routinely opened in a spreadsheet: csv_cell neutralizes
        // formula prefixes before quoting attacker-controlled artifact text.
        output.push_str(&csv_cell(object.get(*field).unwrap_or(&serde_json::Value::Null)));
    }
    output.push('\n');
    Ok(output)
}

fn csv_cell(value: &serde_json::Value) -> String {
    let value = value.as_str().map(str::to_string).unwrap_or_else(|| {
        if value.is_null() { String::new() } else { value.to_string() }
    });
    nanosiem_core::csv_safe::escape_field(&value)
}

fn csv_header(columns: &[String]) -> String {
    let mut line = columns.iter().map(|column| csv_cell(&serde_json::Value::String(column.clone())))
        .collect::<Vec<_>>().join(",");
    line.push('\n');
    line
}

fn search_csv_row(row: &serde_json::Value, columns: &[String]) -> Result<String, std::io::Error> {
    let object = row.as_object().ok_or_else(|| std::io::Error::other("durable result row is not an object"))?;
    let mut line = columns.iter().map(|column| csv_cell(object.get(column).unwrap_or(&serde_json::Value::Null)))
        .collect::<Vec<_>>().join(",");
    line.push('\n');
    Ok(line)
}

#[cfg(test)]
mod export_format_tests {
    use super::*;

    #[test]
    fn search_csv_neutralizes_formulas_behind_whitespace_and_controls() {
        for payload in ["=1+1", "  =1+1", "\t=1+1", "\r=1+1", "\n=1+1", " @SUM(A1)"] {
            let cell = csv_cell(&serde_json::Value::String(payload.into()));
            assert!(cell.trim_start_matches('"').starts_with('\''), "{payload:?}");
        }
        assert!(csv_header(&[" =1+1".into()]).starts_with('\''));
        // Genuine negative numbers stay numeric; prevalence artifacts are neutralized.
        assert_eq!(csv_cell(&serde_json::json!(-5)), "-5");
        let row = prevalence_csv_row(&serde_json::json!({"artifact": " =HYPERLINK(\"x\")", "artifact_type": "domain"})).unwrap();
        assert!(row.starts_with("\"' =HYPERLINK"), "{row}");
    }

    #[test]
    fn search_csv_keeps_columns_from_later_pages_and_quotes_cells() {
        let mut columns = BTreeSet::new();
        for page in [vec![serde_json::json!({"host": "a"})], vec![serde_json::json!({"note": "=1+1", "host": "b,c"})]] {
            for row in page { columns.extend(row.as_object().unwrap().keys().cloned()); }
        }
        let columns = columns.into_iter().collect::<Vec<_>>();
        assert_eq!(csv_header(&columns), "host,note\n");
        assert_eq!(search_csv_row(&serde_json::json!({"host": "a"}), &columns).unwrap(), "a,\n");
        assert_eq!(search_csv_row(&serde_json::json!({"host": "b,c", "note": "=1+1"}), &columns).unwrap(), "\"b,c\",'=1+1\n");
    }
}

/// Response for cancel_search_job endpoint
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CancelJobResponse {
    /// Whether the job was found and cancelled
    pub cancelled: bool,
}

/// Cancel a running async search job
///
/// Cancels the ClickHouse query and marks the job as cancelled.
#[utoipa::path(
    delete,
    path = "/api/search/jobs/{job_id}",
    tag = "search",
    params(
        ("job_id" = String, Path, description = "Async search job ID")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Cancellation result", body = CancelJobResponse),
        (status = 400, description = "Failed to cancel", body = ErrorResponse),
        (status = 404, description = "Job unavailable to caller", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
        (status = 503, description = "Durable job state is temporarily unavailable; search authority unavailable (search_authority_unavailable), Retry-After: 2", body = ErrorResponse),
    )
)]
pub async fn cancel_search_job(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path(job_id): Path<String>,
) -> Result<Json<CancelJobResponse>, SearchError> {
    // NAN-2032: require search:execute before ownership resolution (see get_search_job).
    super::require_search_execute(&auth)?;
    require_retention_safe_job_surface(&auth)?;

    // NAN-2096 deliberately does NOT apply the source-scope re-check here.
    // Cancelling destroys rather than reads the result, so an owner whose scope
    // just narrowed must stay able to stop their own now-unreadable job instead
    // of leaving it running to completion.
    //
    // Missing, foreign and no-longer-cancellable jobs share a 404 response.
    // Never consult a query backend for an absent tenant-pinned job.
    tracing::info!("Received cancel request for job_id: {}", job_id);
    let search = state.search_for_auth(&auth)?;

    let is_admin = auth.claims.has_permission(permissions::SETTINGS_SYSTEM);
    let job = match search
        .job_control()
        .get_checked(&job_id)
        .await
        .map_err(map_job_store_error)?
    {
        Some(job) => job,
        None => return Err(SearchError::NotFound(format!("Job not found: {job_id}"))),
    };
    if !is_admin && job.user_id != Some(auth.claims.sub) {
        return Err(SearchError::NotFound(format!("Job not found: {job_id}")));
    }
    if !matches!(job.status, SearchJobStatus::Queued | SearchJobStatus::Running) {
        return Err(SearchError::NotFound(format!("Job not found: {job_id}")));
    }

    // The durable ownership lookup above is an await point. Revalidate shared
    // membership and feature authority immediately before cancellation so a
    // revoke cannot race a stale request into a destructive action.
    super::require_current_shared_authority(&state, &auth).await?;
    let cancelled = search.cancel_job(&job_id).await.map_err(|e| {
        tracing::error!(error = %e, job_id = %job_id, "Failed to cancel job");
        SearchError::QueryError("Failed to cancel job".to_string())
    })?;

    if cancelled {
        tracing::info!("Successfully cancelled job: {}", job_id);
    } else {
        tracing::debug!("Job not found or already completed: {}", job_id);
    }

    if !cancelled {
        return Err(SearchError::NotFound(format!("Job not found: {job_id}")));
    }
    Ok(Json(CancelJobResponse { cancelled }))
}

// ============================================================================
// List Search Jobs (Active Searches Panel)
// ============================================================================

/// List the current user's active and recent search jobs
///
/// Returns all queued, running, and recently completed/failed jobs for the
/// authenticated user. Hosted history covers the most recent 250 tenant jobs
/// and may be cached for two seconds. Used by the Active Searches panel in the UI.
#[utoipa::path(
    get,
    path = "/api/search/jobs",
    tag = "search",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "List of user's search jobs", body = Vec<SearchJobSummary>),
        (status = 503, description = "Job coordinator temporarily unavailable; search authority unavailable (search_authority_unavailable), Retry-After: 2", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
    )
)]
pub async fn list_search_jobs(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
) -> Result<Json<Vec<SearchJobSummary>>, SearchError> {
    // NAN-2032: require search:execute before listing the caller's jobs.
    super::require_search_execute(&auth)?;
    require_retention_safe_job_surface(&auth)?;

    // NAN-2096: intentionally NOT scope-filtered, unlike the admin list. Every
    // row here is the caller's OWN job and the preview is the query text they
    // themselves submitted, so nothing is disclosed that they did not author.
    // Hiding a still-running job from its owner's Active Searches panel would
    // also strand it — they could no longer see or cancel it. The result
    // payload stays protected on the poll route.
    let search = state.search_for_auth(&auth)?;
    let jobs = list_jobs_for_principal(&search.job_control(), &auth).await?;
    super::require_current_shared_authority(&state, &auth).await?;
    Ok(Json(jobs))
}

/// The tenant-scoped body of `GET /api/search/jobs`, separated from the
/// service/state plumbing so the shared contract can be proven against a
/// tenant-pinned store fixture: the view passed here is already keyed by the
/// server-resolved `SearchTenantScope` (Redis keyspace or in-memory storage
/// key), so a caller can only ever see their own jobs inside their own tenant.
pub(crate) async fn list_jobs_for_principal(
    view: &nanosiem_core::search::job_control_store::JobControlView<'_>,
    auth: &crate::AuthContext,
) -> Result<Vec<SearchJobSummary>, SearchError> {
    view.list_for_user_checked(auth.claims.sub)
        .await
        .map_err(map_job_store_error)
}

// ============================================================================
// Admin Search Jobs
// ============================================================================

/// Helper to check a permission from AuthContext, returning 403 if missing
fn require_permission(auth: &crate::AuthContext, permission: &str) -> Result<(), SearchError> {
    if auth.claims.has_permission(permission) {
        Ok(())
    } else {
        Err(SearchError::Forbidden(format!(
            "Missing permission: {}",
            permission
        )))
    }
}

/// Response for admin list search jobs endpoint
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AdminSearchJobsResponse {
    /// All search jobs across all users
    pub jobs: Vec<AdminSearchJobSummary>,
    /// Admission control statistics
    pub stats: AdmissionStats,
}

/// List all search jobs across all users (admin only)
///
/// Returns all jobs in the registry plus admission control statistics.
/// Requires BOTH `settings:system` AND `search:execute` — the
/// response carries every principal's query preview and user id.
#[utoipa::path(
    get,
    path = "/api/search/admin/jobs",
    tag = "search-admin",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "All search jobs with admission stats", body = AdminSearchJobsResponse),
        (status = 503, description = "Job coordinator temporarily unavailable; search authority unavailable (search_authority_unavailable), Retry-After: 2", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires settings:system AND search:execute", body = ErrorResponse),
    )
)]
pub async fn admin_list_search_jobs(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
) -> Result<Json<AdminSearchJobsResponse>, SearchError> {
    require_search_admin(&auth)?;
    require_retention_safe_job_surface(&auth)?;
    let search = state.search_for_auth(&auth)?;

    // NAN-2096/NAN-2109: the admin summary carries every principal's query
    // preview, which can name a source this admin may not read. Filter by the
    // admin's OWN current scope so the list can never advertise a job whose
    // result `get_search_job` would refuse them. The predicate lives inside
    // `list_all` so a future admin variant cannot omit it.
    let jobs = search
        .job_control()
        .list_all_checked(super::search::effective_scope(&auth).deny_set())
        .await.map_err(map_job_store_error)?;
    let stats = match search.admission_controller() {
        Some(ac) => ac.stats().await,
        None => AdmissionStats {
            active_adhoc: 0,
            queued: 0,
            per_user_counts: vec![],
            per_tenant_counts: vec![],
        },
    };

    super::require_current_shared_authority(&state, &auth).await?;

    Ok(Json(AdminSearchJobsResponse { jobs, stats }))
}

/// Get admission control statistics (admin only)
///
/// Returns current admission stats: active queries, queue depth, per-user
/// breakdown. The per-user breakdown identifies which principals are searching,
/// so this takes the same composite gate as the job list.
#[utoipa::path(
    get,
    path = "/api/search/admin/stats",
    tag = "search-admin",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 503, description = "Search authority temporarily unavailable (search_authority_unavailable); Retry-After: 2", body = crate::error::ErrorResponse),
        (status = 200, description = "Admission control statistics", body = AdmissionStats),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires settings:system AND search:execute", body = ErrorResponse),
    )
)]
pub async fn admin_get_stats(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
) -> Result<Json<AdmissionStats>, SearchError> {
    require_search_admin(&auth)?;
    require_retention_safe_job_surface(&auth)?;
    let search = state.search_for_auth(&auth)?;

    let stats = match search.admission_controller() {
        Some(ac) => ac.stats().await,
        None => AdmissionStats {
            active_adhoc: 0,
            queued: 0,
            per_user_counts: vec![],
            per_tenant_counts: vec![],
        },
    };

    super::require_current_shared_authority(&state, &auth).await?;

    Ok(Json(stats))
}

/// Cancel any user's search job (admin only)
///
/// Cancels a running or queued search job by ID. Audit logged.
/// Requires BOTH `settings:system` AND `search:execute` — this acts
/// on another principal's search.
#[utoipa::path(
    delete,
    path = "/api/search/admin/jobs/{job_id}",
    tag = "search-admin",
    params(
        ("job_id" = String, Path, description = "Search job ID to cancel")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 503, description = "Search authority temporarily unavailable (search_authority_unavailable); Retry-After: 2", body = crate::error::ErrorResponse),
        (status = 200, description = "Cancellation result", body = CancelJobResponse),
        (status = 400, description = "Failed to cancel", body = ErrorResponse),
        (status = 404, description = "Job unavailable to caller", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires settings:system AND search:execute", body = ErrorResponse),
    )
)]
pub async fn admin_cancel_search_job(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path(job_id): Path<String>,
) -> Result<Json<CancelJobResponse>, SearchError> {
    require_search_admin(&auth)?;
    require_retention_safe_job_surface(&auth)?;
    let search = state.search_for_auth(&auth)?;

    tracing::info!(
        admin_user = %auth.claims.sub,
        job_id = %job_id,
        "Admin cancelling search job"
    );

    let job = search
        .job_control()
        .get_checked(&job_id)
        .await
        .map_err(map_job_store_error)?
        .ok_or_else(|| SearchError::NotFound(format!("Job not found: {job_id}")))?;

    if !matches!(job.status, SearchJobStatus::Queued | SearchJobStatus::Running) {
        return Err(SearchError::NotFound(format!("Job not found: {job_id}")));
    }

    // `search_for_auth` and the request-entry capability gate both precede an
    // awaitable destructive action. Revalidate shared membership, session,
    // and entitlement authority at that boundary so a concurrent revoke
    // cannot leave an enterprise-shared administrator able to cancel another
    // principal's job with stale authority.
    super::require_current_shared_authority(&state, &auth).await?;
    let cancelled = search.cancel_job(&job_id).await.map_err(|e| {
        tracing::error!(error = %e, job_id = %job_id, "Failed to admin-cancel job");
        SearchError::QueryError("Failed to cancel job".to_string())
    })?;

    // Audit log the admin cancellation
    state.emit_audit(
        AuditEvent::builder(AuditSource::Search, "search_job_admin_cancelled")
            .actor(Some(auth.claims.sub), None)
            .resource("search_job", None, Some(job_id.clone()))
            .details(serde_json::json!({ "cancelled": cancelled }))
            .build(),
    );

    if !cancelled {
        return Err(SearchError::NotFound(format!("Job not found: {job_id}")));
    }
    Ok(Json(CancelJobResponse { cancelled }))
}

#[cfg(test)]
mod tests {
    use super::{list_jobs_for_principal, prevalence_csv_row, result_pages_are_intermediate};
    use crate::error::SearchError;
    use crate::test_support::{capture_logs, logged_at_least};
    use axum::{http::StatusCode, response::IntoResponse, Json};
    use nanosiem_core::{
        auth::{permissions, ScopeSet, TokenClaims},
        search::{
            job_control_store::JobControlView, DurableJobStoreError, InMemoryJobStore,
            QueryPriority, SearchJobStore, SearchJobSummary, SearchRequest, SearchTenantScope,
            TimeRangeInput,
        },
    };
    use uuid::Uuid;

    const TENANT_A: Uuid = Uuid::from_u128(0xa);
    const TENANT_B: Uuid = Uuid::from_u128(0xb);
    const ASSIGNMENT_REVISION: u64 = 7;

    /// A shared-tenant session context exactly as `auth_middleware` builds it
    /// after the signed envelope, membership, entitlement, and retention gates:
    /// a retained tenant scope plus `search:execute`.
    #[cfg(feature = "enterprise")]
    fn shared_session(tenant_id: Uuid, user_id: Uuid) -> crate::AuthContext {
        let mut auth = crate::AuthContext::from_jwt(TokenClaims {
            iss: "iss".to_string(),
            aud: "aud".to_string(),
            sub: user_id,
            roles: vec!["analyst".to_string()],
            permissions: vec![permissions::SEARCH_EXECUTE.to_string()],
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        });
        auth.tenant_scope = SearchTenantScope::enterprise_shared_retained(tenant_id, 3, 90, 0)
            .expect("valid retained scope");
        auth.shared_search_entitlement_revision = Some(ASSIGNMENT_REVISION);
        auth
    }

    #[cfg(feature = "enterprise")]
    fn request(query: &str) -> SearchRequest {
        SearchRequest {
            query: query.to_string(),
            time_range: TimeRangeInput {
                start: chrono::Utc::now(),
                end: chrono::Utc::now(),
            },
            limit: None,
            offset: None,
            include_sql: None,
            skip_histogram: false,
            skip_field_stats: false,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            priority: None,
            dataset: None,
        }
    }

    /// NAN-3286: a stored prevalence result re-decides the caller's current
    /// prevalence permission and the tenant's plan component on every read.
    #[cfg(feature = "enterprise")]
    #[test]
    fn prevalence_job_reads_recheck_permission_and_entitlement() {
        let job = |query: &str| {
            let mut job = nanosiem_core::search::SearchJob::new(
                "job-1".to_string(),
                request(query),
                &ScopeSet::default(),
            );
            job.task = Some(nanosiem_core::search::DurableLakeTask::PrevalenceExportV1 {
                window: "24h".to_string(),
                artifact_type: None,
                max_prevalence: 5,
                format: "json".to_string(),
            });
            job
        };
        let rare = job("prevalence rare window=24h type=all max_prevalence=5 format=json");
        let export = job("prevalence export window=24h type=all max_prevalence=5 format=csv");
        let with = |permissions: &[&str], entitled: bool| {
            let mut auth = shared_session(TENANT_A, Uuid::from_u128(1));
            auth.claims.permissions.extend(permissions.iter().map(|p| p.to_string()));
            auth.shared_prevalence_entitled = entitled;
            auth
        };
        let denied = |result: Result<(), SearchError>| {
            matches!(result, Err(SearchError::NotFound(_)))
        };
        // Current authority admits.
        assert!(super::require_job_task_read_authority(
            &with(&[permissions::PREVALENCE_VIEW], true), &rare).is_ok());
        assert!(super::require_job_task_read_authority(
            &with(&[permissions::PREVALENCE_EXPORT], true), &export).is_ok());
        // Permission removed after submission → same 404 as a missing job.
        assert!(denied(super::require_job_task_read_authority(&with(&[], true), &rare)));
        assert!(denied(super::require_job_task_read_authority(
            &with(&[permissions::PREVALENCE_VIEW], true), &export)));
        // Plan downgraded after submission → 404.
        assert!(denied(super::require_job_task_read_authority(
            &with(&[permissions::PREVALENCE_VIEW, permissions::PREVALENCE_EXPORT], false), &rare)));
        assert!(denied(super::require_job_task_read_authority(
            &with(&[permissions::PREVALENCE_VIEW, permissions::PREVALENCE_EXPORT], false), &export)));
        // Non-prevalence jobs are unaffected.
        let plain = nanosiem_core::search::SearchJob::new(
            "job-2".to_string(), request("*"), &ScopeSet::default());
        assert!(super::require_job_task_read_authority(&with(&[], false), &plain).is_ok());
    }

    #[cfg(feature = "enterprise")]
    async fn queue(store: &InMemoryJobStore, user: Uuid, query: &str) -> String {
        store
            .create_queued(
                request(query),
                user,
                QueryPriority::Interactive,
                &ScopeSet::default(),
            )
            .await
            .expect("queued")
    }

    /// The exact response shape `list_search_jobs` returns, rendered through
    /// the same `IntoResponse` path so the status is the one a client sees.
    #[cfg(feature = "enterprise")]
    fn render(
        result: Result<Vec<SearchJobSummary>, SearchError>,
    ) -> (StatusCode, Vec<SearchJobSummary>) {
        match result {
            Ok(jobs) => {
                let response = Json(&jobs).into_response();
                (response.status(), jobs)
            }
            Err(error) => (error.into_response().status(), Vec::new()),
        }
    }

    /// NAN-2361: on the shared lake the job view handed to the list route is
    /// already pinned to the server-resolved tenant + worker assignment, so a
    /// principal sees their own jobs inside their own tenant and nothing else
    /// — not another user's jobs in the same tenant, not their own jobs in
    /// another tenant sharing the same physical registry.
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn shared_job_list_returns_200_with_only_the_tenants_jobs_for_the_principal() {
        let registry = InMemoryJobStore::new();
        let view_a = registry.enterprise_shared_assignment_view(TENANT_A, ASSIGNMENT_REVISION);
        let view_b = registry.enterprise_shared_assignment_view(TENANT_B, ASSIGNMENT_REVISION);
        let dan = Uuid::from_u128(0xdad);
        let colleague = Uuid::from_u128(0xc0ffee);

        let dan_in_a = queue(&view_a, dan, "tenant-a dan").await;
        let _colleague_in_a = queue(&view_a, colleague, "tenant-a colleague").await;
        let dan_in_b = queue(&view_b, dan, "tenant-b dan").await;

        let (status, jobs) = render(
            list_jobs_for_principal(&JobControlView::legacy(&view_a), &shared_session(TENANT_A, dan))
                .await,
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            jobs.iter().map(|job| job.job_id.as_str()).collect::<Vec<_>>(),
            vec![dan_in_a.as_str()],
            "tenant A must list exactly Dan's tenant-A job"
        );
        assert_eq!(jobs[0].query, "tenant-a dan");

        let (status, jobs) = render(
            list_jobs_for_principal(&JobControlView::legacy(&view_b), &shared_session(TENANT_B, dan))
                .await,
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            jobs.iter().map(|job| job.job_id.as_str()).collect::<Vec<_>>(),
            vec![dan_in_b.as_str()]
        );

        // A tenant with no jobs for this principal is an empty 200, not an error.
        let (status, jobs) = render(
            list_jobs_for_principal(
                &JobControlView::legacy(&view_a),
                &shared_session(TENANT_A, Uuid::from_u128(0x5eed)),
            )
            .await,
        );
        assert_eq!((status, jobs.len()), (StatusCode::OK, 0));
    }

    /// A job store that cannot reach its registry — the shape of a Dragonfly
    /// outage on the shared lake.
    #[derive(Debug)]
    struct RegistryOutage;

    #[async_trait::async_trait]
    impl SearchJobStore for RegistryOutage {
        async fn create(&self, _: SearchRequest, _: &ScopeSet) -> Option<String> {
            None
        }
        async fn create_queued(
            &self,
            _: SearchRequest,
            _: Uuid,
            _: QueryPriority,
            _: &ScopeSet,
        ) -> Option<String> {
            None
        }
        async fn get(&self, _: &str) -> Option<nanosiem_core::search::SearchJob> {
            None
        }
        async fn get_status(
            &self,
            _: &str,
        ) -> Option<nanosiem_core::search::SearchJobStatusResponse> {
            None
        }
        async fn get_query_id(&self, _: &str) -> Option<String> {
            None
        }
        async fn set_query_id(&self, _: &str, _: String) {}
        async fn complete(&self, _: &str, _: nanosiem_core::SearchResponse) {}
        async fn fail(&self, _: &str, _: String) {}
        async fn cancel(&self, _: &str) {}
        async fn start(&self, _: &str) {}
        async fn remove(&self, _: &str) -> Option<nanosiem_core::search::SearchJob> {
            None
        }
        async fn set_queue_position(&self, _: &str, _: u32) {}
        async fn list_for_user(&self, _: Uuid) -> Vec<SearchJobSummary> {
            Vec::new()
        }
        async fn list_for_user_checked(
            &self,
            _: Uuid,
        ) -> Result<Vec<SearchJobSummary>, DurableJobStoreError> {
            Err(DurableJobStoreError::Unavailable(
                "connection refused (dragonfly:6379)".to_string(),
            ))
        }
        async fn list_all(
            &self,
            _: &std::collections::BTreeSet<String>,
        ) -> Vec<nanosiem_core::search::AdminSearchJobSummary> {
            Vec::new()
        }
        async fn active_count(&self) -> usize {
            0
        }
        async fn total_count(&self) -> usize {
            0
        }
    }

    /// NAN-2361: a registry outage on the list route is a 503 that names the
    /// dependency in the log. It must never render as "no jobs" (the pre-fix
    /// `list_for_user` swallowed the transport error into an empty list) and
    /// never as a bare 503 with no operator-facing line.
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn shared_job_list_outage_is_a_logged_503_not_an_empty_list() {
        let (events, _guard) = capture_logs();
        let (status, jobs) = render(
            list_jobs_for_principal(
                &JobControlView::legacy(&RegistryOutage),
                &shared_session(TENANT_A, Uuid::from_u128(0xdad)),
            )
            .await,
        );
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(jobs.is_empty());
        assert!(
            logged_at_least(&events, tracing::Level::WARN, "connection refused (dragonfly:6379)"),
            "the outage detail must reach the log: {:?}",
            events.lock().unwrap()
        );
        assert!(
            logged_at_least(&events, tracing::Level::ERROR, "search request refused with 503"),
            "every 503 response must log at error level: {:?}",
            events.lock().unwrap()
        );
    }

    #[test]
    fn post_processed_candidate_pages_are_never_served_raw() {
        use nanosiem_core::search::DurableLakeTask;
        assert!(result_pages_are_intermediate(Some(&DurableLakeTask::SearchNplPostV1 {
            post_query: "* | prevalence enrich=true".into(),
            requested_limit: 10,
            requested_offset: 0,
            required_scan_bytes: 0,
        })));
        assert!(!result_pages_are_intermediate(Some(&DurableLakeTask::SearchNplV1)));
        assert!(!result_pages_are_intermediate(None));
    }

    #[test]
    fn prevalence_csv_stream_escapes_attacker_controlled_cells() {
        let row = serde_json::json!({
            "artifact": "evil,\"hash\"\nnext",
            "artifact_type": "hash_sha256",
            "host_count": 2,
            "total_occurrences": 7,
            "first_seen": "2026-08-15T00:00:00Z",
            "last_seen": "2026-08-15T01:00:00Z",
            "is_rare": true,
            "prevalence_score": 13
        });
        assert_eq!(
            prevalence_csv_row(&row).unwrap(),
            "\"evil,\"\"hash\"\"\nnext\",hash_sha256,2,7,2026-08-15T00:00:00Z,2026-08-15T01:00:00Z,true,13\n"
        );

        let formula = serde_json::json!({"artifact": "=cmd", "artifact_type": "domain"});
        assert!(prevalence_csv_row(&formula)
            .unwrap()
            .starts_with("'=cmd,domain,"));
    }
}
