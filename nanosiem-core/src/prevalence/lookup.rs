// SPDX-License-Identifier: AGPL-3.0-or-later

//! Storage-neutral prevalence lookup contract.
//!
//! Historical event storage is not part of this interface. Callers select a
//! tenant-pinned immutable prevalence snapshot through deployment config and
//! submit only artifact values plus their effective derived-artifact scope.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    ArtifactDetailResponse, ArtifactExplorerResponse, ArtifactType, PrevalenceData,
    PrevalenceError, PrevalenceExplorerCursor, PrevalenceService, TimeWindow,
};
use crate::auth::ArtifactScope;
use crate::lake_http::LakeRequestBuilderExt;

const DEFAULT_TIMEOUT_SECS: u64 = 10;
const MAX_LOOKUPS_PER_REQUEST: usize = 10_000;
const MAX_EXPLORER_PAGE_SIZE: i64 = 200;
const MAX_LEGACY_EXPLORER_OFFSET: i64 = 50_000;
const MAX_EXPORT_ROWS: usize = 10_000;
const WORKER_ASSIGNMENT_ID_HEADER: &str = "x-nano-worker-assignment-id";
const WORKER_ASSIGNMENT_REVISION_HEADER: &str = "x-nano-worker-assignment-revision";

#[derive(Debug, Clone)]
pub struct LakePrevalenceExportResult {
    pub artifacts: Vec<PrevalenceData>,
    pub truncated: bool,
}

/// Point-serving boundary used by search and scheduled detection queries.
///
/// The existing ClickHouse prevalence service and the immutable lake snapshot
/// client both implement this point contract. Ordered explorer/detail/export
/// reads are separate bounded methods on the lake client.
#[async_trait]
pub trait PrevalenceLookup: Send + Sync {
    async fn rarity_threshold(&self) -> u64;

    async fn lookup(
        &self,
        artifacts: &[String],
        time_window: TimeWindow,
        scope: &ArtifactScope,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError>;

    /// ClickHouse CACHE dictionaries can temporarily miss newly added keys and
    /// need a summary-table rescue. Immutable lake snapshots do not: a missing
    /// key is an exact unmeasured result for the pinned version.
    fn needs_fresh_miss_rescue(&self) -> bool {
        false
    }

    async fn lookup_fresh(
        &self,
        artifacts: &[String],
        time_window: TimeWindow,
        scope: &ArtifactScope,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError> {
        self.lookup(artifacts, time_window, scope).await
    }
}

#[async_trait]
impl PrevalenceLookup for PrevalenceService {
    async fn rarity_threshold(&self) -> u64 {
        PrevalenceService::rarity_threshold(self).await
    }

    async fn lookup(
        &self,
        artifacts: &[String],
        time_window: TimeWindow,
        scope: &ArtifactScope,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError> {
        self.get_bulk_prevalence_via_dict(artifacts, time_window, scope)
            .await
    }

    fn needs_fresh_miss_rescue(&self) -> bool {
        true
    }

    async fn lookup_fresh(
        &self,
        artifacts: &[String],
        time_window: TimeWindow,
        scope: &ArtifactScope,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError> {
        self.get_bulk_summary_prevalence(artifacts, time_window, scope)
            .await
    }
}

#[derive(Debug, Clone, Default)]
struct SnapshotIds {
    one_hour: Option<String>,
    twenty_four_hours: Option<String>,
    seven_days: Option<String>,
    thirty_days: Option<String>,
}

/// The prevalence snapshot windows the lake serves, in canonical order. The
/// lake worker's builder (`PREVALENCE_WINDOWS`), its contracted empty-WAL
/// predicate and the Nano Main owner (`generation-bundle-prevalence-windows.json`)
/// are pinned to this list.
pub const PREVALENCE_SNAPSHOT_WINDOWS: [&str; 4] = ["1h", "24h", "7d", "30d"];

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakePrevalenceSnapshots {
    pub one_hour: String,
    pub twenty_four_hours: String,
    pub seven_days: String,
    pub thirty_days: String,
}

impl LakePrevalenceSnapshots {
    pub fn validate(&self) -> Result<(), String> {
        self.validated_ids().map(|_| ())
    }

    fn validated_ids(&self) -> Result<SnapshotIds, String> {
        for (window, value) in PREVALENCE_SNAPSHOT_WINDOWS.into_iter().zip([
            self.one_hour.as_str(),
            self.twenty_four_hours.as_str(),
            self.seven_days.as_str(),
            self.thirty_days.as_str(),
        ]) {
            validate_opaque_id(&format!("{window} prevalence snapshot"), value)?;
        }
        Ok(SnapshotIds {
            one_hour: Some(self.one_hour.clone()),
            twenty_four_hours: Some(self.twenty_four_hours.clone()),
            seven_days: Some(self.seven_days.clone()),
            thirty_days: Some(self.thirty_days.clone()),
        })
    }
}

impl SnapshotIds {
    fn from_env() -> Result<Option<Self>, String> {
        let ids = Self {
            one_hour: optional_snapshot_env("NANO_LAKE_PREVALENCE_SNAPSHOT_1H")?,
            twenty_four_hours: optional_snapshot_env("NANO_LAKE_PREVALENCE_SNAPSHOT_24H")?,
            seven_days: optional_snapshot_env("NANO_LAKE_PREVALENCE_SNAPSHOT_7D")?,
            thirty_days: optional_snapshot_env("NANO_LAKE_PREVALENCE_SNAPSHOT_30D")?,
        };
        if !ids.is_empty() {
            return Ok(Some(ids));
        }
        // No explicit override: derive the assignment from the coordinator's own
        // worker config, which already names a snapshot per window and is rewritten
        // atomically on every promotion. These four env vars used to be the ONLY
        // source, so a deployment that lost them (or never set them) answered 503
        // on every prevalence surface while the assignment sat in the config the
        // process had already loaded.
        Self::from_active_worker_config()
    }

    fn is_empty(&self) -> bool {
        self.one_hour.is_none()
            && self.twenty_four_hours.is_none()
            && self.seven_days.is_none()
            && self.thirty_days.is_none()
    }

    /// Map the config's `prevalence_snapshots` to windows using each entry's
    /// declared `window`, not its key spelling, so a naming change cannot silently
    /// unassign a window.
    fn from_active_worker_config() -> Result<Option<Self>, String> {
        let Some(config) = crate::schema::active_worker_config()? else {
            return Ok(None);
        };
        let Some(snapshots) = config
            .get("prevalence_snapshots")
            .and_then(serde_json::Value::as_object)
        else {
            return Ok(None);
        };
        let mut ids = Self::default();
        for (snapshot_id, entry) in snapshots {
            let Some(window) = entry.get("window").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let slot = match window.trim().to_ascii_lowercase().as_str() {
                "1h" => &mut ids.one_hour,
                "24h" => &mut ids.twenty_four_hours,
                "7d" => &mut ids.seven_days,
                "30d" => &mut ids.thirty_days,
                _ => continue,
            };
            *slot = Some(snapshot_id.clone());
        }
        if ids.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ids))
        }
    }

    fn get(&self, window: TimeWindow) -> Option<&str> {
        match window {
            TimeWindow::OneHour => self.one_hour.as_deref(),
            TimeWindow::TwentyFourHours => self.twenty_four_hours.as_deref(),
            TimeWindow::SevenDays => self.seven_days.as_deref(),
            TimeWindow::ThirtyDays => self.thirty_days.as_deref(),
        }
    }
}

/// Internal client for immutable prevalence snapshots served by the lake
/// worker. The worker maps `(tenant_id, snapshot_id)` to its own object-store
/// configuration; object URLs and credentials never cross this interface.
#[derive(Clone)]
pub struct LakePrevalenceClient {
    http: reqwest::Client,
    base_url: String,
    tenant_id: String,
    bearer_token: String,
    snapshots: SnapshotIds,
    /// The deployment default (`NANO_LAKE_PREVALENCE_RARITY_THRESHOLD`, or
    /// the tenant assignment's). Only a fallback when `rarity_setting` holds
    /// the Settings value (NAN-3451).
    rarity_threshold: u64,
    /// NAN-3451: the Settings → Prevalence rarity threshold, live. Wins over
    /// `rarity_threshold` whenever it holds a value.
    rarity_setting: Option<super::settings::RarityThresholdSetting>,
    expected_worker_identity: Option<String>,
    expected_worker_revision: Option<u64>,
    /// NAN-2891: `base_url` is a lean-lake cell's per-tenant `query[T]`
    /// prefix. query[T] computes prevalence over the tenant's verified part
    /// log at request time: there is no immutable snapshot id to pin (the
    /// response is bound by tenant + window instead). Detail reads verified
    /// event parts; export uses the separate durable jobs path.
    lake_cell: bool,
    /// Cell clients re-read the router bearer from this configured path on
    /// every call; `bearer_token` is unused on a cell client.
    router_token_file: Option<PathBuf>,
}

impl LakePrevalenceClient {
    /// Construct from a previously validated, tenant-pinned detect lane.
    pub(crate) fn from_cell_detection_parts(base_url: &str, tenant_id: &str, token_file: &Path,
        rarity_threshold: u64, timeout: Duration) -> Result<Self, String> {
        let parsed = url::Url::parse(base_url).map_err(|e| e.to_string())?;
        let expected = format!("/v1/tenants/{tenant_id}/detect");
        if parsed.path() != expected || parsed.query().is_some() || parsed.fragment().is_some() {
            return Err("detect prevalence route differs from authenticated tenant".into());
        }
        let http = reqwest::Client::builder().timeout(timeout).build().map_err(|e| e.to_string())?;
        Ok(Self { http, base_url: base_url.to_string(), tenant_id: tenant_id.to_string(), bearer_token: String::new(),
            snapshots: SnapshotIds::default(), rarity_threshold, rarity_setting: None, expected_worker_identity: None,
            expected_worker_revision: None, lake_cell: true, router_token_file: Some(token_file.to_path_buf()) })
    }

    /// NAN-2891: a client for one tenant's lean-lake `query[T]` behind its
    /// cell router. The base URL and bearer come only from the tenant's own
    /// route (rendered from the authenticated tenant UUID).
    pub fn from_lake_cell_route(
        route: &crate::search::LakeCellRoute,
        rarity_threshold: u64,
        timeout: Duration,
    ) -> Result<Self, String> {
        let tenant_id = route.tenant_id.as_hyphenated().to_string();
        route.validate_query_base()?;
        let http = crate::search::lake_cell::lake_cell_http_client_builder(timeout)
            .build()
            .map_err(|error| format!("failed to build lake cell prevalence HTTP client: {error}"))?;
        Ok(Self {
            http,
            base_url: route.query_base_url.trim_end_matches('/').to_string(),
            tenant_id,
            bearer_token: String::new(),
            snapshots: SnapshotIds::default(),
            rarity_threshold,
            rarity_setting: None,
            expected_worker_identity: None,
            expected_worker_revision: None,
            lake_cell: true,
            router_token_file: Some(route.router_token_file.clone()),
        })
    }

    /// NAN-3451: let the Settings rarity threshold drive this client. The
    /// constructor's threshold (env / assignment) stays the fallback for as
    /// long as `setting` holds no value.
    pub fn with_rarity_setting(mut self, setting: super::settings::RarityThresholdSetting) -> Self {
        self.rarity_setting = Some(setting);
        self
    }

    /// The threshold in force: the Settings value when bound and set, else
    /// the configured default.
    fn effective_rarity_threshold(&self) -> u64 {
        self.rarity_setting
            .as_ref()
            .and_then(super::settings::RarityThresholdSetting::get)
            .unwrap_or(self.rarity_threshold)
    }

    /// The bearer for the next request (a cell client re-reads its token).
    fn bearer(&self) -> Result<std::borrow::Cow<'_, str>, PrevalenceError> {
        match &self.router_token_file {
            None => Ok(std::borrow::Cow::Borrowed(self.bearer_token.as_str())),
            Some(path) => crate::search::lake_cell::router_bearer(path, &self.base_url)
                .map(std::borrow::Cow::Owned)
                .map_err(|error| {
                    PrevalenceError::Backend(format!("lean-lake cell router token is unavailable: {error}"))
                }),
        }
    }

    /// A cell router 401 is a token mismatch, not a query failure.
    fn cell_unauthorized(&self, status: reqwest::StatusCode) -> Option<PrevalenceError> {
        (self.lake_cell && status == reqwest::StatusCode::UNAUTHORIZED).then(|| {
            PrevalenceError::Backend(
                "lean-lake cell router rejected the router token (HTTP 401): the mounted token does not match the cell's".into(),
            )
        })
    }

    /// Whether this client talks to a lean-lake cell's `query[T]`.
    pub fn is_lake_cell(&self) -> bool {
        self.lake_cell
    }

    /// The pinned snapshot for `time_window`: `None` on a cell client (no
    /// snapshots exist over parts); an error on a gen1 client without one.
    fn snapshot_for(&self, time_window: TimeWindow) -> Result<Option<&str>, PrevalenceError> {
        if self.lake_cell {
            return Ok(None);
        }
        self.snapshots.get(time_window).map(Some).ok_or_else(|| {
            PrevalenceError::Backend(format!(
                "no immutable lake prevalence snapshot is configured for {time_window}"
            ))
        })
    }

    fn lake_cell_unsupported(&self, what: &str) -> PrevalenceError {
        PrevalenceError::Backend(format!(
            "{what} is not served for lean-lake tenants yet (query[T] has no equivalent route)"
        ))
    }

    /// The response is bound to the request: gen1 by its immutable snapshot,
    /// a cell by the window and route query[T] echoes (plus the tenant, which
    /// every caller checks).
    fn response_binding_matches(
        &self,
        snapshot_id: Option<&str>,
        response_snapshot: Option<&str>,
        response_route: Option<&str>,
        expected_route: &str,
    ) -> bool {
        if self.lake_cell {
            response_route == Some(expected_route)
        } else {
            snapshot_id.is_some() && response_snapshot == snapshot_id
        }
    }
    pub fn from_shared_assignment(
        base_url: &str,
        tenant_id: uuid::Uuid,
        credential_file: &std::path::Path,
        snapshots: &LakePrevalenceSnapshots,
        rarity_threshold: u64,
        timeout: Duration,
        expected_worker_identity: String,
        expected_worker_revision: u64,
    ) -> Result<Self, String> {
        let bearer_token = std::fs::read_to_string(credential_file).map_err(|error| {
            format!(
                "failed to read shared lake prevalence credential reference {}: {error}",
                credential_file.display()
            )
        })?;
        Self::new(
            base_url,
            tenant_id.to_string(),
            bearer_token.trim().to_string(),
            snapshots.validated_ids()?,
            rarity_threshold,
            timeout,
            Some(expected_worker_identity),
            Some(expected_worker_revision),
        )
    }

    /// Build from the lake worker's process-level assignment. No snapshot env
    /// variables means prevalence serving is intentionally not configured.
    ///
    /// NAN-3492: a trusted-local install's dedicated lean cell serves
    /// prevalence from its `query[T]` (no snapshot ids; part-log windows).
    pub fn from_env() -> Result<Option<Self>, String> {
        if let Some(route) = crate::search::lake_cell::dedicated_route_from_env()? {
            let rarity_threshold = std::env::var("NANO_LAKE_PREVALENCE_RARITY_THRESHOLD")
                .ok()
                .map(|raw| {
                    raw.parse::<u64>().map_err(|_| {
                        "NANO_LAKE_PREVALENCE_RARITY_THRESHOLD must be an integer".to_string()
                    })
                })
                .transpose()?
                .unwrap_or(crate::search::lake_cell::LAKE_CELL_PREVALENCE_RARITY_THRESHOLD);
            return Self::from_lake_cell_route(
                &route,
                rarity_threshold,
                Duration::from_secs(crate::search::lake_cell::DEDICATED_CELL_TIMEOUT_SECS),
            )
            .map(Some);
        }
        let Some(snapshots) = SnapshotIds::from_env()? else {
            return Ok(None);
        };
        let base_url = required_env("NANO_LAKE_QUERY_URL")?;
        let tenant_id = required_env("NANO_LAKE_TENANT_ID")?;
        let token_file = PathBuf::from(required_env("NANO_LAKE_QUERY_TOKEN_FILE")?);
        let bearer_token = std::fs::read_to_string(&token_file)
            .map_err(|error| {
                format!(
                    "failed to read NANO_LAKE_QUERY_TOKEN_FILE {}: {error}",
                    token_file.display()
                )
            })?
            .trim()
            .to_string();
        let timeout_secs = std::env::var("NANO_LAKE_PREVALENCE_TIMEOUT_SECS")
            .ok()
            .map(|raw| {
                raw.parse::<u64>()
                    .map_err(|_| "NANO_LAKE_PREVALENCE_TIMEOUT_SECS must be an integer".to_string())
            })
            .transpose()?
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        if timeout_secs == 0 || timeout_secs > 300 {
            return Err("NANO_LAKE_PREVALENCE_TIMEOUT_SECS must be between 1 and 300".to_string());
        }
        let rarity_threshold = std::env::var("NANO_LAKE_PREVALENCE_RARITY_THRESHOLD")
            .ok()
            .map(|raw| {
                raw.parse::<u64>().map_err(|_| {
                    "NANO_LAKE_PREVALENCE_RARITY_THRESHOLD must be an integer".to_string()
                })
            })
            .transpose()?
            .unwrap_or(3);
        Self::new(
            &base_url,
            tenant_id,
            bearer_token,
            snapshots,
            rarity_threshold,
            Duration::from_secs(timeout_secs),
            None,
            None,
        )
        .map(Some)
    }

    fn new(
        base_url: &str,
        tenant_id: String,
        bearer_token: String,
        snapshots: SnapshotIds,
        rarity_threshold: u64,
        timeout: Duration,
        expected_worker_identity: Option<String>,
        expected_worker_revision: Option<u64>,
    ) -> Result<Self, String> {
        validate_opaque_id("tenant ID", &tenant_id)?;
        if bearer_token.len() < 32 {
            return Err("lake prevalence bearer token must contain at least 32 characters".into());
        }
        let parsed = Url::parse(base_url)
            .map_err(|error| format!("invalid NANO_LAKE_QUERY_URL: {error}"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !matches!(parsed.path(), "" | "/")
        {
            return Err(
                "NANO_LAKE_QUERY_URL must be an HTTP(S) origin without credentials, query, fragment, or path"
                    .into(),
            );
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| format!("failed to build lake prevalence HTTP client: {error}"))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            tenant_id,
            bearer_token,
            snapshots,
            rarity_threshold,
            rarity_setting: None,
            expected_worker_identity,
            expected_worker_revision,
            lake_cell: false,
            router_token_file: None,
        })
    }

    fn verify_response_assignment(
        &self,
        headers: &reqwest::header::HeaderMap,
    ) -> Result<(), PrevalenceError> {
        let Some(expected_identity) = self.expected_worker_identity.as_deref() else {
            return Ok(());
        };
        let Some(expected_revision) = self.expected_worker_revision else {
            return Err(PrevalenceError::Backend(
                "lake prevalence worker assignment expectation is incomplete".into(),
            ));
        };
        let actual_identity = headers
            .get(WORKER_ASSIGNMENT_ID_HEADER)
            .and_then(|value| value.to_str().ok());
        let actual_revision = headers
            .get(WORKER_ASSIGNMENT_REVISION_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if actual_identity != Some(expected_identity) || actual_revision != Some(expected_revision)
        {
            return Err(PrevalenceError::Backend(
                "lake prevalence response assignment identity/revision mismatch".into(),
            ));
        }
        Ok(())
    }

    async fn lookup_chunk(
        &self,
        artifacts: &[String],
        time_window: TimeWindow,
        scope: &ArtifactScope,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError> {
        let snapshot_id = self.snapshot_for(time_window)?;
        let request_id = uuid::Uuid::now_v7().to_string();
        let request = LakePrevalenceRequest {
            request_id: &request_id,
            tenant_id: &self.tenant_id,
            snapshot_id,
            window: time_window.to_string(),
            artifacts,
            rarity_threshold: self.lake_cell.then_some(self.effective_rarity_threshold()),
            deny_source_types: scope.deny_bind_values(),
        };
        let response = self
            .http
            .post(format!("{}/v1/prevalence/lookup", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&request)
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| {
                PrevalenceError::Backend(format!("lake prevalence request failed: {error}"))
            })?;
        let status = response.status();
        if let Some(error) = self.cell_unauthorized(status) {
            return Err(error);
        }
        self.verify_response_assignment(response.headers())?;
        let body = response.bytes().await.map_err(|error| {
            PrevalenceError::Backend(format!("lake prevalence response read failed: {error}"))
        })?;
        let envelope: LakePrevalenceResponse = serde_json::from_slice(&body).map_err(|error| {
            PrevalenceError::Backend(format!(
                "lake prevalence worker returned invalid JSON ({status}): {error}"
            ))
        })?;
        if !status.is_success() || !envelope.ok {
            return Err(PrevalenceError::Backend(envelope.error.unwrap_or_else(
                || format!("lake prevalence worker returned HTTP {status}"),
            )));
        }
        if envelope.tenant_id.as_deref() != Some(self.tenant_id.as_str()) {
            return Err(PrevalenceError::Backend(
                "lake prevalence response tenant did not match the pinned tenant".into(),
            ));
        }
        if !self.response_binding_matches(
            snapshot_id,
            envelope.snapshot_id.as_deref(),
            envelope.route.as_deref(),
            "prevalence_lookup",
        ) || (self.lake_cell && envelope.window.as_deref() != Some(request.window.as_str()))
        {
            return Err(PrevalenceError::Backend(
                "lake prevalence response snapshot did not match the pinned immutable version"
                    .into(),
            ));
        }

        let requested: BTreeSet<String> = artifacts.iter().map(|v| normalize_artifact(v)).collect();
        let mut seen = BTreeSet::new();
        for item in &envelope.results {
            let normalized = normalize_artifact(&item.artifact);
            if !requested.contains(&normalized) {
                return Err(PrevalenceError::Backend(
                    "lake prevalence worker returned an artifact that was not requested".into(),
                ));
            }
            if !seen.insert(normalized) {
                return Err(PrevalenceError::Backend(
                    "lake prevalence worker returned a duplicate artifact".into(),
                ));
            }
        }
        Ok(envelope
            .results
            .into_iter()
            .map(|mut item| {
                item.is_rare =
                    !item.host_count_saturated && item.host_count < self.effective_rarity_threshold();
                item.prevalence_score = if item.host_count_saturated {
                    100
                } else {
                    super::PrevalenceRepository::calculate_prevalence_score(
                        item.host_count,
                        self.effective_rarity_threshold(),
                    )
                };
                item
            })
            .collect())
    }

    /// Read the bounded ordered-list companion for the pinned immutable
    /// snapshot. Object coordinates remain entirely inside worker config.
    pub async fn explore(
        &self,
        artifact_type: Option<ArtifactType>,
        time_window: TimeWindow,
        risk_level: Option<&str>,
        first_seen_since: Option<chrono::DateTime<chrono::Utc>>,
        search: Option<&str>,
        limit: i64,
        offset: i64,
        cursor: Option<&PrevalenceExplorerCursor>,
        scope: &ArtifactScope,
    ) -> Result<ArtifactExplorerResponse, PrevalenceError> {
        if !(1..=MAX_EXPLORER_PAGE_SIZE).contains(&limit)
            || offset < 0
            || (cursor.is_none() && offset.saturating_add(limit) > MAX_LEGACY_EXPLORER_OFFSET)
            || (cursor.is_some() && offset != 0)
        {
            return Err(PrevalenceError::Backend(format!(
                "lake prevalence explorer requires limit 1-{MAX_EXPLORER_PAGE_SIZE}, a paired cursor with offset 0, or legacy offset + limit <= {MAX_LEGACY_EXPLORER_OFFSET}"
            )));
        }
        // NAN-3802: forward the RFC 3339 form even when the client still holds
        // a legacy-format cursor from before the roll.
        let cursor = cursor.map(validated_explorer_cursor).transpose()?;
        let cursor = cursor.as_ref();
        if !matches!(risk_level, None | Some("rare") | Some("new")) {
            return Err(PrevalenceError::Backend(
                "lake prevalence explorer risk level must be rare or new".into(),
            ));
        }
        if search.is_some_and(|value| value.len() > 512) {
            return Err(PrevalenceError::Backend(
                "lake prevalence explorer search must not exceed 512 bytes".into(),
            ));
        }
        let snapshot_id = self.snapshot_for(time_window)?;
        let request_id = uuid::Uuid::now_v7().to_string();
        let request = LakePrevalenceExplorerRequest {
            request_id: &request_id,
            tenant_id: &self.tenant_id,
            snapshot_id,
            // A cell always takes the client's threshold. A gen1 worker has
            // its own configured default and is only sent the Settings value
            // when one is bound (NAN-3451), so env-only deployments send
            // exactly what they did before.
            rarity_threshold: if self.lake_cell {
                Some(self.effective_rarity_threshold())
            } else {
                self.rarity_setting
                    .as_ref()
                    .and_then(super::settings::RarityThresholdSetting::get)
            },
            window: time_window.to_string(),
            artifact_type: artifact_type.map(artifact_type_filter),
            risk_level,
            first_seen_since: first_seen_since.map(|value| value.to_rfc3339()),
            search,
            limit,
            offset,
            cursor,
            deny_source_types: scope.deny_bind_values(),
        };
        let response = self
            .http
            .post(format!("{}/v1/prevalence/explorer", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&request)
            .send_idempotent_with_recovery_within(self.lake_cell.then_some(Duration::from_secs(20)))
            .await
            .map_err(|error| {
                PrevalenceError::Backend(format!(
                    "lake prevalence explorer request failed: {error}"
                ))
            })?;
        let status = response.status();
        if let Some(error) = self.cell_unauthorized(status) {
            return Err(error);
        }
        self.verify_response_assignment(response.headers())?;
        let body = response.bytes().await.map_err(|error| {
            PrevalenceError::Backend(format!(
                "lake prevalence explorer response read failed: {error}"
            ))
        })?;
        let envelope: LakePrevalenceExplorerResponse =
            serde_json::from_slice(&body).map_err(|error| {
                PrevalenceError::Backend(format!(
                    "lake prevalence explorer returned invalid JSON ({status}): {error}"
                ))
            })?;
        if !status.is_success() || !envelope.ok {
            return Err(PrevalenceError::Backend(envelope.error.unwrap_or_else(
                || format!("lake prevalence explorer returned HTTP {status}"),
            )));
        }
        // query[T]'s explorer envelope carries no window; gen1's does.
        if envelope.tenant_id.as_deref() != Some(self.tenant_id.as_str())
            || !self.response_binding_matches(
                snapshot_id,
                envelope.snapshot_id.as_deref(),
                envelope.route.as_deref(),
                "prevalence_explorer",
            )
            || (!self.lake_cell && envelope.window.as_deref() != Some(request.window.as_str()))
        {
            return Err(PrevalenceError::Backend(
                "lake prevalence explorer response identity did not match the pinned tenant snapshot"
                    .into(),
            ));
        }
        let mut result = envelope.result.ok_or_else(|| {
            PrevalenceError::Backend("lake prevalence explorer omitted its result".into())
        })?;
        // NAN-3802: a not-yet-rolled cell may still answer with a legacy-form
        // cursor; hand the client the RFC 3339 form it can send back.
        if let Some(next) = result.next_cursor.as_ref() {
            result.next_cursor = Some(validated_explorer_cursor(next)?);
        }
        if result.limit != limit
            || result.offset != offset
            || result.artifacts.len() > limit as usize
            || result.has_more != result.next_cursor.is_some()
        {
            return Err(PrevalenceError::Backend(
                "lake prevalence explorer returned an invalid pagination envelope".into(),
            ));
        }
        if first_seen_since
            .is_some_and(|since| result.artifacts.iter().any(|item| item.first_seen < since))
        {
            return Err(PrevalenceError::Backend(
                "lake prevalence explorer returned an artifact older than the requested first-seen boundary"
                    .into(),
            ));
        }
        Ok(result)
    }

    /// Fetch bounded raw-event facets for one artifact. The caller supplies
    /// only the effective live-row deny set; the worker owns the immutable
    /// event coordinates and applies a positive source allow-list.
    pub async fn detail(
        &self,
        artifact: &str,
        time_window: TimeWindow,
        denied_source_types: &BTreeSet<String>,
    ) -> Result<ArtifactDetailResponse, PrevalenceError> {
        let snapshot_id = self.snapshot_for(time_window)?;
        let request_id = uuid::Uuid::now_v7().to_string();
        let request = LakePrevalenceDetailRequest {
            request_id: &request_id,
            tenant_id: &self.tenant_id,
            snapshot_id,
            window: time_window.to_string(),
            artifact,
            deny_source_types: crate::auth::deny_bind_values(denied_source_types),
        };
        let response = self
            .http
            .post(format!("{}/v1/prevalence/detail", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&request)
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| {
                PrevalenceError::Backend(format!("lake prevalence detail request failed: {error}"))
            })?;
        let status = response.status();
        self.verify_response_assignment(response.headers())?;
        let body = response.bytes().await.map_err(|error| {
            PrevalenceError::Backend(format!(
                "lake prevalence detail response read failed: {error}"
            ))
        })?;
        let envelope: LakePrevalenceDetailResponse =
            serde_json::from_slice(&body).map_err(|error| {
                PrevalenceError::Backend(format!(
                    "lake prevalence detail returned invalid JSON ({status}): {error}"
                ))
            })?;
        if !status.is_success() || !envelope.ok {
            return Err(PrevalenceError::Backend(envelope.error.unwrap_or_else(
                || format!("lake prevalence detail returned HTTP {status}"),
            )));
        }
        if envelope.tenant_id.as_deref() != Some(self.tenant_id.as_str())
            || !self.response_binding_matches(snapshot_id, envelope.snapshot_id.as_deref(), envelope.route.as_deref(), "prevalence_detail")
            || envelope.window.as_deref() != Some(request.window.as_str())
        {
            return Err(PrevalenceError::Backend(
                "lake prevalence detail response identity did not match the pinned tenant snapshot"
                    .into(),
            ));
        }
        let result = envelope.result.ok_or_else(|| {
            PrevalenceError::Backend("lake prevalence detail omitted its result".into())
        })?;
        if normalize_artifact(&result.artifact) != normalize_artifact(artifact) {
            return Err(PrevalenceError::Backend(
                "lake prevalence detail returned a different artifact".into(),
            ));
        }
        let identity_pivot = self.lake_cell && result.artifact_type == ArtifactType::Identity
            && ArtifactType::detect(artifact) == ArtifactType::HashUnknown;
        if (!identity_pivot && artifact_type_filter(result.artifact_type)
            != artifact_type_filter(ArtifactType::detect(artifact)))
            || result.top_hosts.len() > 10
            || result.top_users.len() > 10
            || result.source_types.len() > 10
            || result.processes.len() > 10
            || result.top_file_names.len() > 5
            || result.network.len() > 10
        {
            return Err(PrevalenceError::Backend(
                "lake prevalence detail returned an invalid bounded result".into(),
            ));
        }
        Ok(result)
    }

    /// Export a bounded rare-artifact set from one pinned immutable snapshot.
    pub async fn export(
        &self,
        artifact_type: Option<ArtifactType>,
        time_window: TimeWindow,
        max_prevalence: u64,
        limit: usize,
        scope: &ArtifactScope,
    ) -> Result<LakePrevalenceExportResult, PrevalenceError> {
        if self.lake_cell {
            return Err(self.lake_cell_unsupported("prevalence export"));
        }
        if !(1..=MAX_EXPORT_ROWS).contains(&limit) {
            return Err(PrevalenceError::Backend(format!(
                "lake prevalence export requires limit 1-{MAX_EXPORT_ROWS}"
            )));
        }
        let snapshot_id = self.snapshots.get(time_window).ok_or_else(|| {
            PrevalenceError::Backend(format!(
                "no immutable lake prevalence snapshot is configured for {time_window}"
            ))
        })?;
        let request_id = uuid::Uuid::now_v7().to_string();
        let request = LakePrevalenceExportRequest {
            request_id: &request_id,
            tenant_id: &self.tenant_id,
            snapshot_id,
            window: time_window.to_string(),
            artifact_type: artifact_type.map(artifact_type_filter),
            max_prevalence,
            limit,
            deny_source_types: scope.deny_bind_values(),
        };
        let response = self
            .http
            .post(format!("{}/v1/prevalence/export", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&request)
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| {
                PrevalenceError::Backend(format!("lake prevalence export request failed: {error}"))
            })?;
        let status = response.status();
        self.verify_response_assignment(response.headers())?;
        let body = response.bytes().await.map_err(|error| {
            PrevalenceError::Backend(format!(
                "lake prevalence export response read failed: {error}"
            ))
        })?;
        let envelope: LakePrevalenceExportResponse =
            serde_json::from_slice(&body).map_err(|error| {
                PrevalenceError::Backend(format!(
                    "lake prevalence export returned invalid JSON ({status}): {error}"
                ))
            })?;
        if !status.is_success() || !envelope.ok {
            return Err(PrevalenceError::Backend(envelope.error.unwrap_or_else(
                || format!("lake prevalence export returned HTTP {status}"),
            )));
        }
        if envelope.tenant_id.as_deref() != Some(self.tenant_id.as_str())
            || envelope.snapshot_id.as_deref() != Some(snapshot_id)
            || envelope.window.as_deref() != Some(request.window.as_str())
        {
            return Err(PrevalenceError::Backend(
                "lake prevalence export response identity did not match the pinned tenant snapshot"
                    .into(),
            ));
        }
        if envelope.results.len() > limit {
            return Err(PrevalenceError::Backend(
                "lake prevalence export exceeded its requested row limit".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        // NAN-3451: the worker filters rare by its own configured threshold;
        // the Settings threshold may be stricter, so anything at or above it
        // is dropped here rather than treated as a protocol violation.
        let threshold = self.effective_rarity_threshold();
        let mut artifacts = envelope.results;
        artifacts.retain(|item| item.host_count < threshold);
        for item in &mut artifacts {
            if item.host_count > max_prevalence
                || !seen.insert(normalize_artifact(&item.artifact))
            {
                return Err(PrevalenceError::Backend(
                    "lake prevalence export returned an invalid artifact set".into(),
                ));
            }
            if artifact_type.is_some_and(|requested| {
                artifact_type_filter(requested) != artifact_type_filter(item.artifact_type)
            }) {
                return Err(PrevalenceError::Backend(
                    "lake prevalence export returned an artifact outside the requested type".into(),
                ));
            }
            item.is_rare = true;
            item.prevalence_score =
                super::PrevalenceRepository::calculate_prevalence_score(item.host_count, threshold);
        }
        Ok(LakePrevalenceExportResult {
            artifacts,
            truncated: envelope.truncated,
        })
    }
}

#[async_trait]
impl PrevalenceLookup for LakePrevalenceClient {
    async fn rarity_threshold(&self) -> u64 {
        self.effective_rarity_threshold()
    }

    async fn lookup(
        &self,
        artifacts: &[String],
        time_window: TimeWindow,
        scope: &ArtifactScope,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError> {
        let mut by_artifact = HashMap::new();
        for chunk in artifacts.chunks(MAX_LOOKUPS_PER_REQUEST) {
            for item in self.lookup_chunk(chunk, time_window, scope).await? {
                by_artifact.insert(normalize_artifact(&item.artifact), item);
            }
        }
        Ok(artifacts
            .iter()
            .filter_map(|artifact| by_artifact.remove(&normalize_artifact(artifact)))
            .collect())
    }
}

#[derive(Serialize)]
struct LakePrevalenceRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<&'a str>,
    window: String,
    artifacts: &'a [String],
    /// Cell (query[T]) requests only; gen1 readers take it from config.
    #[serde(skip_serializing_if = "Option::is_none")]
    rarity_threshold: Option<u64>,
    deny_source_types: &'a [String],
}

#[derive(Serialize)]
struct LakePrevalenceExplorerRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<&'a str>,
    /// Cells always; gen1 workers only when Settings hold a threshold
    /// (NAN-3451). A gen1 worker older than NAN-3451 rejects the field
    /// (`deny_unknown_fields`), so roll the worker with or before the API.
    #[serde(skip_serializing_if = "Option::is_none")]
    rarity_threshold: Option<u64>,
    window: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_level: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_seen_since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    search: Option<&'a str>,
    limit: i64,
    offset: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a PrevalenceExplorerCursor>,
    deny_source_types: &'a [String],
}

#[derive(Serialize)]
struct LakePrevalenceDetailRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<&'a str>,
    window: String,
    artifact: &'a str,
    deny_source_types: Vec<String>,
}

#[derive(Serialize)]
struct LakePrevalenceExportRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    snapshot_id: &'a str,
    window: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_type: Option<&'static str>,
    max_prevalence: u64,
    limit: usize,
    deny_source_types: &'a [String],
}

#[derive(Deserialize)]
struct LakePrevalenceResponse {
    ok: bool,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    snapshot_id: Option<String>,
    #[serde(default)]
    route: Option<String>,
    #[serde(default)]
    window: Option<String>,
    #[serde(default)]
    results: Vec<PrevalenceData>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct LakePrevalenceExplorerResponse {
    ok: bool,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    snapshot_id: Option<String>,
    #[serde(default)]
    route: Option<String>,
    #[serde(default)]
    window: Option<String>,
    #[serde(default)]
    result: Option<ArtifactExplorerResponse>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct LakePrevalenceDetailResponse {
    ok: bool,
    #[serde(default)]
    route: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    snapshot_id: Option<String>,
    #[serde(default)]
    window: Option<String>,
    #[serde(default)]
    result: Option<ArtifactDetailResponse>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct LakePrevalenceExportResponse {
    ok: bool,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    snapshot_id: Option<String>,
    #[serde(default)]
    window: Option<String>,
    #[serde(default)]
    results: Vec<PrevalenceData>,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    error: Option<String>,
}

fn required_env(name: &str) -> Result<String, String> {
    let value = std::env::var(name).unwrap_or_default();
    let value = value.trim();
    if value.is_empty() {
        Err(format!(
            "{name} is required when lake prevalence is configured"
        ))
    } else {
        Ok(value.to_string())
    }
}

fn optional_snapshot_env(name: &str) -> Result<Option<String>, String> {
    let value = std::env::var(name).unwrap_or_default();
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    validate_opaque_id(name, value)?;
    Ok(Some(value.to_string()))
}

fn validate_opaque_id(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        return Err(format!(
            "{label} must be a 1-256 character opaque ID, not an object-store coordinate"
        ));
    }
    Ok(())
}

fn normalize_artifact(value: &str) -> String {
    match ArtifactType::detect(value) {
        kind if kind.is_hash() || kind.is_domain() => value.trim().to_ascii_lowercase(),
        _ => value.trim().to_string(),
    }
}

fn artifact_type_filter(artifact_type: ArtifactType) -> &'static str {
    if artifact_type == ArtifactType::Identity {
        "identity"
    } else if artifact_type.is_hash() {
        "hash"
    } else if artifact_type.is_domain() {
        "domain"
    } else {
        "ip"
    }
}

/// Validate an explorer continuation cursor and normalize its `last_seen` to
/// RFC 3339 (NAN-3802: the legacy `YYYY-MM-DD HH:MM:SS.ffffff` form is still
/// accepted).
pub fn validated_explorer_cursor(
    cursor: &PrevalenceExplorerCursor,
) -> Result<PrevalenceExplorerCursor, PrevalenceError> {
    cursor.validated().ok_or_else(|| {
        PrevalenceError::Backend("lake prevalence explorer cursor is invalid".into())
    })
}

#[cfg(test)]
mod tests {
    /// Prevalence must resolve from the coordinator's worker config when no env
    /// override is present. Before this, four missing env vars silently answered
    /// 503 on every prevalence surface while the assignment sat in the config the
    /// process had already loaded.
    #[test]
    fn snapshot_ids_derive_from_the_worker_config_by_declared_window() {
        let config = serde_json::json!({
            "prevalence_snapshots": {
                // Deliberately unconventional keys: the window field is authoritative,
                // not the key spelling.
                "pv-a": {"window": "24h"},
                "pv-b": {"window": "1h"},
                "pv-c": {"window": "30d"},
                "pv-d": {"window": "7d"},
                "pv-e": {"window": "90d"},
                "pv-f": {}
            }
        });
        let snapshots = config
            .get("prevalence_snapshots")
            .and_then(serde_json::Value::as_object)
            .expect("object");
        let mut ids = SnapshotIds::default();
        for (snapshot_id, entry) in snapshots {
            let Some(window) = entry.get("window").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let slot = match window {
                "1h" => &mut ids.one_hour,
                "24h" => &mut ids.twenty_four_hours,
                "7d" => &mut ids.seven_days,
                "30d" => &mut ids.thirty_days,
                _ => continue,
            };
            *slot = Some(snapshot_id.clone());
        }
        assert_eq!(ids.get(TimeWindow::OneHour), Some("pv-b"));
        assert_eq!(ids.get(TimeWindow::TwentyFourHours), Some("pv-a"));
        assert_eq!(ids.get(TimeWindow::SevenDays), Some("pv-d"));
        assert_eq!(ids.get(TimeWindow::ThirtyDays), Some("pv-c"));
        assert!(!ids.is_empty());
        // An unknown window and a windowless entry are ignored, not fatal.
        assert!(SnapshotIds::default().is_empty());
    }

    use super::*;
    use chrono::{TimeZone, Utc};
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn snapshots() -> SnapshotIds {
        SnapshotIds {
            twenty_four_hours: Some("prev-24h-v17".into()),
            ..SnapshotIds::default()
        }
    }

    async fn client(server: &MockServer) -> LakePrevalenceClient {
        LakePrevalenceClient::new(
            &server.uri(),
            "tenant-a".into(),
            "0123456789abcdef0123456789abcdef".into(),
            snapshots(),
            5,
            Duration::from_secs(2),
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn shared_prevalence_response_requires_exact_worker_assignment_headers() {
        let client = LakePrevalenceClient::new(
            "http://query-a.nano.svc:8080",
            "tenant-a".into(),
            "0123456789abcdef0123456789abcdef".into(),
            snapshots(),
            5,
            Duration::from_secs(2),
            Some("worker-a".into()),
            Some(7),
        )
        .unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        assert!(client.verify_response_assignment(&headers).is_err());
        headers.insert(
            WORKER_ASSIGNMENT_ID_HEADER,
            reqwest::header::HeaderValue::from_static("worker-a"),
        );
        headers.insert(
            WORKER_ASSIGNMENT_REVISION_HEADER,
            reqwest::header::HeaderValue::from_static("7"),
        );
        assert!(client.verify_response_assignment(&headers).is_ok());
        headers.insert(
            WORKER_ASSIGNMENT_ID_HEADER,
            reqwest::header::HeaderValue::from_static("worker-b"),
        );
        assert!(client.verify_response_assignment(&headers).is_err());
    }

    fn result(artifact: &str) -> serde_json::Value {
        json!({
            "artifact": artifact,
            "artifact_type": "domain",
            "host_count": 2,
            "total_occurrences": 7,
            "first_seen": Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap(),
            "last_seen": Utc.with_ymd_and_hms(2026, 8, 10, 1, 0, 0).unwrap(),
            "is_rare": true,
            "prevalence_score": 40
        })
    }

    fn explorer_result() -> serde_json::Value {
        json!({
            "artifacts": [{
                "artifact": "example.com",
                "artifact_type": "domain",
                "host_count": 2,
                "total_occurrences": 7,
                "first_seen": Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap(),
                "last_seen": Utc.with_ymd_and_hms(2026, 8, 10, 1, 0, 0).unwrap(),
                "is_rare": true,
                "prevalence_score": 40,
                "daily_counts": [],
                "daily_start": ""
            }],
            "total": 1,
            "limit": 50,
            "offset": 0,
            "has_more": false,
            "rarity_threshold": 5,
            "rare_count": 1,
            "new_count": 1,
            "high_risk_asset_count": 1,
            "counts_approximate": false
        })
    }

    pub(super) fn detail_result() -> serde_json::Value {
        json!({
            "artifact": "example.com",
            "artifact_type": "domain",
            "top_hosts": [{
                "host": "host-a",
                "count": 2,
                "last_seen": Utc.with_ymd_and_hms(2026, 8, 10, 1, 0, 0).unwrap()
            }],
            "top_users": [{"user": "alice", "count": 2}],
            "source_types": [{"source_type": "edr", "count": 2}],
            "network": [{"dest_port": 443, "protocol": "6", "count": 2}],
            "geo": [],
            "threat_intel": []
        })
    }

    #[tokio::test]
    async fn sends_only_pinned_tenant_snapshot_artifacts_and_scope() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/lookup"))
            .and(header(
                "authorization",
                "Bearer 0123456789abcdef0123456789abcdef",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "prev-24h-v17",
                "results": [result("example.com")]
            })))
            .mount(&server)
            .await;

        let client = client(&server).await;
        let denied = BTreeSet::from(["restricted".to_string()]);
        let scope = ArtifactScope::from_denied(&denied);
        let rows = client
            .lookup(&["Example.COM".into()], TimeWindow::TwentyFourHours, &scope)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].artifact, "example.com");
        assert_eq!(rows[0].host_count, 2);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["tenant_id"], "tenant-a");
        assert_eq!(body["snapshot_id"], "prev-24h-v17");
        assert_eq!(body["window"], "24h");
        assert_eq!(body["artifacts"], json!(["Example.COM"]));
        assert_eq!(
            body["deny_source_types"],
            json!(["__nano:unresolved_source__", "restricted"])
        );
    }

    #[tokio::test]
    async fn saturated_host_counts_are_never_reported_as_rare_or_under_scored() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/lookup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "prev-24h-v17",
                "results": [{
                    "artifact": "example.com",
                    "artifact_type": "domain",
                    "host_count": 65,
                    "host_count_saturated": true,
                    "total_occurrences": 700,
                    "first_seen": Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap(),
                    "last_seen": Utc.with_ymd_and_hms(2026, 8, 10, 1, 0, 0).unwrap(),
                    "is_rare": true,
                    "prevalence_score": 10
                }]
            })))
            .mount(&server)
            .await;

        let rows = client(&server)
            .await
            .lookup(
                &["example.com".into()],
                TimeWindow::TwentyFourHours,
                &ArtifactScope::system(),
            )
            .await
            .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host_count, 65);
        assert!(rows[0].host_count_saturated);
        assert!(!rows[0].is_rare);
        assert_eq!(rows[0].prevalence_score, 100);
    }

    #[tokio::test]
    async fn rejects_worker_snapshot_substitution() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/lookup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "different-snapshot",
                "results": [result("example.com")]
            })))
            .mount(&server)
            .await;

        let error = client(&server)
            .await
            .lookup(
                &["example.com".into()],
                TimeWindow::TwentyFourHours,
                &ArtifactScope::system(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("snapshot did not match"));
    }

    #[tokio::test]
    async fn explorer_sends_bounded_filters_scope_and_pinned_identity() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/explorer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "prev-24h-v17",
                "window": "24h",
                "result": explorer_result()
            })))
            .mount(&server)
            .await;

        let denied = BTreeSet::from(["restricted".to_string()]);
        let result = client(&server)
            .await
            .explore(
                Some(ArtifactType::Domain),
                TimeWindow::TwentyFourHours,
                Some("rare"),
                None,
                Some("example"),
                50,
                0,
                None,
                &ArtifactScope::from_denied(&denied),
            )
            .await
            .unwrap();
        assert_eq!(result.total, 1);
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["tenant_id"], "tenant-a");
        assert_eq!(body["snapshot_id"], "prev-24h-v17");
        assert_eq!(body["artifact_type"], "domain");
        assert_eq!(body["risk_level"], "rare");
        assert_eq!(body["search"], "example");
        assert_eq!(body["limit"], 50);
        assert_eq!(
            body["deny_source_types"],
            json!(["__nano:unresolved_source__", "restricted"])
        );
    }

    /// NAN-3451: the Settings rarity threshold wins over the env/assignment
    /// default once bound and set; an empty setting keeps the default, and a
    /// gen1 explorer request only carries a threshold when Settings set one.
    #[tokio::test]
    async fn settings_rarity_threshold_wins_over_the_configured_default() {
        let server = MockServer::start().await;
        let mut stamped = result("example.com");
        stamped["host_count"] = json!(6);
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/lookup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "prev-24h-v17",
                "results": [stamped]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/explorer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "prev-24h-v17",
                "window": "24h",
                "result": explorer_result()
            })))
            .mount(&server)
            .await;
        let lookup_rare = |client: LakePrevalenceClient| async move {
            let threshold = PrevalenceLookup::rarity_threshold(&client).await;
            let rows = client
                .lookup(&["example.com".into()], TimeWindow::TwentyFourHours, &ArtifactScope::system())
                .await
                .unwrap();
            client
                .explore(None, TimeWindow::TwentyFourHours, Some("rare"), None, None, 50, 0, None, &ArtifactScope::system())
                .await
                .unwrap();
            (threshold, rows[0].is_rare)
        };

        // The configured default (5): host_count 6 is not rare.
        assert_eq!(lookup_rare(client(&server).await).await, (5, false));
        // Bound but never read from Settings: still the default.
        let unset = super::super::settings::RarityThresholdSetting::default();
        assert_eq!(
            lookup_rare(client(&server).await.with_rarity_setting(unset.clone())).await,
            (5, false)
        );
        // Settings say 10: rare, and the live value follows later changes.
        unset.set(10);
        assert_eq!(
            lookup_rare(client(&server).await.with_rarity_setting(unset.clone())).await,
            (10, true)
        );
        unset.set(2);
        assert_eq!(
            lookup_rare(client(&server).await.with_rarity_setting(unset)).await,
            (2, false)
        );

        let explorer_bodies = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.url.path() == "/v1/prevalence/explorer")
            .map(|request| serde_json::from_slice::<serde_json::Value>(&request.body).unwrap())
            .map(|body| body.get("rarity_threshold").cloned())
            .collect::<Vec<_>>();
        assert_eq!(explorer_bodies, vec![None, None, Some(json!(10)), Some(json!(2))]);
    }

    /// NAN-3451: a stricter Settings threshold than the worker's own drops
    /// the export rows at or above it instead of failing the export.
    #[tokio::test]
    async fn export_drops_rows_at_or_above_a_stricter_settings_threshold() {
        let server = MockServer::start().await;
        let mut kept = result("rare.example");
        kept["host_count"] = json!(1);
        let mut dropped = result("less-rare.example");
        dropped["host_count"] = json!(2);
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/export"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "prev-24h-v17",
                "window": "24h",
                "truncated": false,
                "results": [kept, dropped]
            })))
            .mount(&server)
            .await;
        let client = client(&server)
            .await
            .with_rarity_setting(super::super::settings::RarityThresholdSetting::fixed(2));
        let exported = client
            .export(None, TimeWindow::TwentyFourHours, 4, 100, &ArtifactScope::system())
            .await
            .unwrap();
        let artifacts = exported
            .artifacts
            .iter()
            .map(|item| item.artifact.as_str())
            .collect::<Vec<_>>();
        assert_eq!(artifacts, vec!["rare.example"]);
        assert!(exported.artifacts[0].is_rare);
    }

    #[tokio::test]
    async fn explorer_sends_and_validates_stable_cursor() {
        let server = MockServer::start().await;
        let next_cursor = PrevalenceExplorerCursor {
            last_seen: "2026-08-10T00:30:00.000000Z".into(),
            kind: "domain".into(),
            artifact: "next.example".into(),
        };
        let mut worker_result = explorer_result();
        worker_result["has_more"] = json!(true);
        worker_result["next_cursor"] = json!(next_cursor);
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/explorer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "prev-24h-v17",
                "window": "24h",
                "result": worker_result
            })))
            .mount(&server)
            .await;

        let cursor = PrevalenceExplorerCursor {
            last_seen: "2026-08-10T01:00:00.000000Z".into(),
            kind: "domain".into(),
            artifact: "example.com".into(),
        };
        let result = client(&server)
            .await
            .explore(
                Some(ArtifactType::Domain),
                TimeWindow::TwentyFourHours,
                None,
                None,
                None,
                50,
                0,
                Some(&cursor),
                &ArtifactScope::system(),
            )
            .await
            .unwrap();
        assert!(result.has_more);
        assert_eq!(result.next_cursor, Some(next_cursor));

        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["offset"], 0);
        assert_eq!(body["cursor"], json!(cursor));
    }

    /// NAN-3802: across the roll a browser may send, and a not-yet-rolled cell
    /// may answer with, the legacy `YYYY-MM-DD HH:MM:SS.ffffff` cursor. The
    /// API accepts both directions and only ever exposes RFC 3339.
    #[tokio::test]
    async fn explorer_normalizes_legacy_text_cursors_both_ways() {
        let server = MockServer::start().await;
        let mut worker_result = explorer_result();
        worker_result["has_more"] = json!(true);
        worker_result["next_cursor"] = json!({
            "last_seen": "2026-08-10 00:30:00.250000", "kind": "domain", "artifact": "next.example"
        });
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/explorer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "prev-24h-v17",
                "window": "24h",
                "result": worker_result
            })))
            .mount(&server)
            .await;
        let legacy = PrevalenceExplorerCursor {
            last_seen: "2026-08-10 01:00:00.000000".into(),
            kind: "domain".into(),
            artifact: "example.com".into(),
        };
        let result = client(&server)
            .await
            .explore(
                Some(ArtifactType::Domain),
                TimeWindow::TwentyFourHours,
                None,
                None,
                None,
                50,
                0,
                Some(&legacy),
                &ArtifactScope::system(),
            )
            .await
            .unwrap();
        assert_eq!(
            result.next_cursor.unwrap().last_seen,
            "2026-08-10T00:30:00.250000Z"
        );
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["cursor"]["last_seen"], "2026-08-10T01:00:00.000000Z");
    }

    #[tokio::test]
    async fn detail_uses_live_row_scope_and_pinned_identity() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/detail"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "prev-24h-v17",
                "window": "24h",
                "result": detail_result()
            })))
            .mount(&server)
            .await;

        let denied = BTreeSet::from(["AUDIT".to_string(), " Restricted ".to_string()]);
        let result = client(&server)
            .await
            .detail("Example.COM", TimeWindow::TwentyFourHours, &denied)
            .await
            .unwrap();
        assert_eq!(result.artifact, "example.com");
        assert_eq!(result.top_hosts[0].host, "host-a");
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["tenant_id"], "tenant-a");
        assert_eq!(body["snapshot_id"], "prev-24h-v17");
        assert_eq!(body["window"], "24h");
        assert_eq!(body["artifact"], "Example.COM");
        assert_eq!(
            body["deny_source_types"],
            json!(["__nano:unresolved_source__", "audit", "restricted"])
        );
        assert!(body.get("source").is_none());
    }

    #[tokio::test]
    async fn export_is_bounded_scoped_and_snapshot_pinned() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/export"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "prev-24h-v17",
                "window": "24h",
                "results": [result("example.com")],
                "truncated": true
            })))
            .mount(&server)
            .await;

        let denied = BTreeSet::from(["restricted".to_string()]);
        let result = client(&server)
            .await
            .export(
                Some(ArtifactType::Domain),
                TimeWindow::TwentyFourHours,
                2,
                50,
                &ArtifactScope::from_denied(&denied),
            )
            .await
            .unwrap();
        assert_eq!(result.artifacts.len(), 1);
        assert!(result.truncated);
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["tenant_id"], "tenant-a");
        assert_eq!(body["snapshot_id"], "prev-24h-v17");
        assert_eq!(body["artifact_type"], "domain");
        assert_eq!(body["max_prevalence"], 2);
        assert_eq!(body["limit"], 50);
        assert_eq!(
            body["deny_source_types"],
            json!(["__nano:unresolved_source__", "restricted"])
        );
        assert!(body.get("scan_source").is_none());
    }

    #[tokio::test]
    async fn export_rejects_worker_snapshot_substitution() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/prevalence/export"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "tenant_id": "tenant-a",
                "snapshot_id": "different-snapshot",
                "window": "24h",
                "results": [],
                "truncated": false
            })))
            .mount(&server)
            .await;

        let error = client(&server)
            .await
            .export(
                None,
                TimeWindow::TwentyFourHours,
                3,
                10,
                &ArtifactScope::system(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("identity did not match"));
    }

    #[test]
    fn opaque_snapshot_ids_reject_object_coordinates() {
        assert!(validate_opaque_id("snapshot", "prev-24h-v17").is_ok());
        assert!(validate_opaque_id("snapshot", "s3://bucket/key").is_err());
        assert!(validate_opaque_id("snapshot", "../state/current").is_err());
    }
}

#[cfg(test)]
mod lake_cell_prevalence_tests {
    //! NAN-2891: prevalence for lean-lake cell tenants goes to the tenant's
    //! own `query[T]` (`/v1/prevalence/*` behind the cell router).
    use super::*;
    use crate::search::LakeCellRoute;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TOKEN: &str = "router-token-router-token-router-token-xyz";

    fn client(server: &MockServer, dir: &tempfile::TempDir, tenant: uuid::Uuid) -> LakePrevalenceClient {
        let token = dir.path().join("router.token");
        std::fs::write(&token, TOKEN).unwrap();
        let route = LakeCellRoute::for_test(tenant, &server.uri(), token);
        LakePrevalenceClient::from_lake_cell_route(&route, 3, Duration::from_secs(5)).unwrap()
    }

    fn item(artifact: &str) -> serde_json::Value {
        json!({"artifact": artifact, "artifact_type": "domain", "host_count": 1, "total_occurrences": 4,
               "first_seen": "2026-09-25T00:00:00Z", "last_seen": "2026-09-25T01:00:00Z",
               "is_rare": true, "prevalence_score": 10})
    }

    #[tokio::test]
    async fn cell_lookup_posts_to_the_tenant_prefix_without_a_snapshot_pin() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = uuid::Uuid::from_u128(0xa);
        let t = tenant.to_string();
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{t}/query/v1/prevalence/lookup")))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(body_partial_json(json!({"tenant_id": t, "window": "24h", "rarity_threshold": 3,
                                          "artifacts": ["example.com"]})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true, "tenant_id": t, "route": "prevalence_lookup", "source_mode": "parts",
                "window": "24h", "results": [item("example.com")]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = client(&server, &dir, tenant);
        assert!(client.is_lake_cell());
        let found = client
            .lookup(&["example.com".to_string()], TimeWindow::TwentyFourHours, &ArtifactScope::system())
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].is_rare);
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert!(body.get("snapshot_id").is_none(), "query[T] denies unknown fields: {body}");
    }

    #[tokio::test]
    async fn cell_lookup_refuses_another_tenants_or_unbound_answer() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = uuid::Uuid::from_u128(0xa);
        let other = uuid::Uuid::from_u128(0xb).to_string();
        for body in [
            json!({"ok": true, "tenant_id": other, "route": "prevalence_lookup", "window": "24h",
                   "results": [item("example.com")]}),
            json!({"ok": true, "tenant_id": tenant.to_string(), "window": "24h", "results": [item("example.com")]}),
            json!({"ok": true, "tenant_id": tenant.to_string(), "route": "prevalence_lookup", "window": "7d",
                   "results": [item("example.com")]}),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
                .mount(&server)
                .await;
            let result = client(&server, &dir, tenant)
                .lookup(&["example.com".to_string()], TimeWindow::TwentyFourHours, &ArtifactScope::system())
                .await;
            assert!(result.is_err(), "accepted {body}");
        }
    }

    #[tokio::test]
    async fn cell_explorer_is_bound_by_tenant_and_route_and_export_fails_closed() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = uuid::Uuid::from_u128(0xa);
        let t = tenant.to_string();
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{t}/query/v1/prevalence/explorer")))
            .and(body_partial_json(json!({"tenant_id": t, "window": "7d", "limit": 50, "rarity_threshold": 3})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true, "request_id": "x", "tenant_id": t, "route": "prevalence_explorer", "source_mode": "parts",
                "result": {"artifacts": [], "total": 0, "limit": 50, "offset": 0, "has_more": false,
                           "next_cursor": null, "rarity_threshold": 3, "rare_count": 0, "new_count": 0,
                           "high_risk_asset_count": 0, "counts_approximate": false}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = client(&server, &dir, tenant);
        let page = client
            .explore(None, TimeWindow::SevenDays, None, None, None, 50, 0, None, &ArtifactScope::system())
            .await
            .unwrap();
        assert_eq!(page.total, 0);
        assert!(client.export(None, TimeWindow::SevenDays, 3, 10, &ArtifactScope::system()).await.is_err());
    }

    #[tokio::test]
    async fn cell_detail_sends_window_and_scope_without_gen1_snapshot_and_checks_tenant_route() {
        for (response_tenant, route, accepted) in [(10, "prevalence_detail", true), (11, "prevalence_detail", false), (10, "prevalence_explorer", false)] {
            let server = MockServer::start().await;
            let dir = tempfile::tempdir().unwrap();
            let tenant = uuid::Uuid::from_u128(10);
            Mock::given(method("POST"))
                .and(path(format!("/v1/tenants/{tenant}/query/v1/prevalence/detail")))
                .and(body_partial_json(json!({"tenant_id": tenant.to_string(), "artifact": "Example.COM", "window": "24h", "deny_source_types": ["__nano:unresolved_source__", "hidden"]})))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "ok": true, "tenant_id": uuid::Uuid::from_u128(response_tenant).to_string(),
                    "route": route, "window": "24h", "result": super::tests::detail_result()
                }))).expect(1).mount(&server).await;
            let client = client(&server, &dir, tenant);
            let result = client.detail("Example.COM", TimeWindow::TwentyFourHours, &BTreeSet::from(["hidden".into()])).await;
            assert_eq!(result.is_ok(), accepted, "{result:?}");
            if accepted { assert!(!result.unwrap().top_hosts.is_empty()); }
            let received = server.received_requests().await.unwrap();
            let sent: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
            assert!(sent.get("snapshot_id").is_none());
        }
    }

    #[test]
    fn cell_client_refuses_a_route_for_another_tenants_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("router.token");
        std::fs::write(&token, TOKEN).unwrap();
        let (a, b) = (uuid::Uuid::from_u128(0xa), uuid::Uuid::from_u128(0xb));
        let mut route = LakeCellRoute::for_test(a, "http://nano-cell-cell-us-1.nano-lake-cells.svc:8790", token);
        route.query_base_url = format!("http://nano-cell-cell-us-1.nano-lake-cells.svc:8790/v1/tenants/{b}/query");
        assert!(LakePrevalenceClient::from_lake_cell_route(&route, 3, Duration::from_secs(5)).is_err());
    }
}
