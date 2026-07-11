// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pinned, bounded MITRE ATT&CK catalog synchronization.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use futures::StreamExt;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{info, warn};

use crate::mitre::repository::MitreRepository;
use crate::mitre::types::{MitreTactic, MitreTechnique, StixBundle, StixObject};

const MITRE_SYNC_LOCK_ID: i64 = 0x4d49_5452_455f_5359;
const MITRE_RELEASE: &str = "v19.1";
const MITRE_CTI_URL: &str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.1/enterprise-attack/enterprise-attack.json";
const MITRE_SHA256: &str = "bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3";
const MITRE_BUNDLE_ID: &str = "bundle--64af0946-bfeb-481d-96df-a38e2709e3db";
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
struct SyncSource {
    release: String,
    url: String,
    sha256: String,
    bundle_id: String,
    max_bytes: usize,
    min_objects: usize,
    min_tactics: usize,
    min_techniques: usize,
}

impl SyncSource {
    fn pinned() -> Self {
        Self {
            release: MITRE_RELEASE.to_string(),
            url: MITRE_CTI_URL.to_string(),
            sha256: MITRE_SHA256.to_string(),
            bundle_id: MITRE_BUNDLE_ID.to_string(),
            max_bytes: MAX_BUNDLE_BYTES,
            min_objects: 20_000,
            min_tactics: 15,
            min_techniques: 650,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitreSyncResult {
    pub release: String,
    pub source_url: String,
    pub source_sha256: String,
    pub tactic_count: i32,
    pub technique_count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MitreSyncOutcome {
    Synced(MitreSyncResult),
    AlreadyCurrent,
    RetryBackoff,
    AlreadyRunning,
}

#[derive(Debug, Error)]
pub enum MitreSyncError {
    #[error("MITRE source request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("MITRE source returned HTTP {0}")]
    HttpStatus(reqwest::StatusCode),
    #[error("MITRE bundle exceeds {limit} bytes (observed at least {observed})")]
    BundleTooLarge { observed: usize, limit: usize },
    #[error("MITRE bundle digest mismatch (expected {expected}, got {actual})")]
    DigestMismatch { expected: String, actual: String },
    #[error("MITRE bundle JSON is invalid: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("MITRE bundle validation failed: {0}")]
    InvalidBundle(String),
    #[error("MITRE catalog database operation failed: {0}")]
    Database(#[from] sqlx::Error),
}

/// Service for syncing MITRE ATT&CK data.
pub struct MitreSync {
    repository: MitreRepository,
    source: SyncSource,
}

impl MitreSync {
    pub fn new(repository: MitreRepository) -> Self {
        Self {
            repository,
            source: SyncSource::pinned(),
        }
    }

    pub fn release(&self) -> &str {
        &self.source.release
    }

    pub fn source_url(&self) -> &str {
        &self.source.url
    }

    pub fn source_sha256(&self) -> &str {
        &self.source.sha256
    }

    /// Force a synchronization attempt, still respecting the cross-node
    /// single-flight lock.
    pub async fn sync(&self) -> Result<MitreSyncOutcome, MitreSyncError> {
        self.run(true).await
    }

    /// Synchronize only when the pinned release is not already complete and
    /// the durable retry window has elapsed.
    pub async fn sync_if_due(&self) -> Result<MitreSyncOutcome, MitreSyncError> {
        self.run(false).await
    }

    async fn run(&self, force: bool) -> Result<MitreSyncOutcome, MitreSyncError> {
        let Some(mut connection) = self
            .repository
            .try_acquire_sync_connection(MITRE_SYNC_LOCK_ID)
            .await?
        else {
            return Ok(MitreSyncOutcome::AlreadyRunning);
        };

        let result = self.run_locked(&mut connection, force).await;
        if let Err(error) = &result {
            if let Err(state_error) =
                MitreRepository::mark_sync_failed_on(&mut connection, &error.to_string()).await
            {
                warn!(%state_error, "Failed to persist MITRE sync failure state");
            }
        }

        // The connection is close-on-drop, so cancellation or unlock failure
        // cannot leak this session-level lock back into the pool.
        if let Err(error) = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
            .bind(MITRE_SYNC_LOCK_ID)
            .fetch_one(&mut *connection)
            .await
        {
            warn!(%error, "Failed to explicitly release MITRE sync advisory lock");
        }

        result
    }

    async fn run_locked(
        &self,
        connection: &mut sqlx::PgConnection,
        force: bool,
    ) -> Result<MitreSyncOutcome, MitreSyncError> {
        if !force {
            if MitreRepository::catalog_is_current_on(
                connection,
                &self.source.release,
                &self.source.sha256,
            )
            .await?
            {
                return Ok(MitreSyncOutcome::AlreadyCurrent);
            }
            if !MitreRepository::retry_allowed_on(connection).await? {
                return Ok(MitreSyncOutcome::RetryBackoff);
            }
        }

        MitreRepository::mark_sync_started_on(
            connection,
            &self.source.release,
            &self.source.url,
            &self.source.sha256,
        )
        .await?;

        info!(
            release = %self.source.release,
            source = %self.source.url,
            "Fetching pinned MITRE ATT&CK catalog"
        );
        let bundle = self.fetch_bundle().await?;
        let (tactics, techniques) = self.parse_catalog(&bundle)?;

        // NAN-1774 / NAN-1766 (D3): `replace_catalog_on` writes the catalog,
        // reconciles existing detection-rule mappings against it, and flips the
        // sync state to `succeeded` — all inside one transaction. Reconciliation
        // is no longer a separate pool round-trip after the commit, so a crash
        // can never leave state `succeeded` with stale rule mappings still live.
        let quarantined = MitreRepository::replace_catalog_on(
            connection,
            &tactics,
            &techniques,
            &self.source.release,
            &self.source.url,
            &self.source.sha256,
        )
        .await?;

        if quarantined > 0 {
            warn!(
                quarantined,
                "Quarantined legacy detection-rule mappings that are invalid in the synced ATT&CK catalog"
            );
        }

        let result = MitreSyncResult {
            release: self.source.release.clone(),
            source_url: self.source.url.clone(),
            source_sha256: self.source.sha256.clone(),
            tactic_count: tactics.len() as i32,
            technique_count: techniques.len() as i32,
        };
        info!(
            release = %result.release,
            tactics = result.tactic_count,
            techniques = result.technique_count,
            "MITRE ATT&CK catalog sync completed"
        );
        Ok(MitreSyncOutcome::Synced(result))
    }

    async fn fetch_bundle(&self) -> Result<StixBundle, MitreSyncError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("nanosiem-mitre-sync")
            .build()?;
        let response = client.get(&self.source.url).send().await?;
        if !response.status().is_success() {
            return Err(MitreSyncError::HttpStatus(response.status()));
        }
        if let Some(length) = response.content_length() {
            if length > self.source.max_bytes as u64 {
                return Err(MitreSyncError::BundleTooLarge {
                    observed: length.min(usize::MAX as u64) as usize,
                    limit: self.source.max_bytes,
                });
            }
        }

        let mut body = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or_default()
                .min(self.source.max_bytes as u64) as usize,
        );
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if body.len().saturating_add(chunk.len()) > self.source.max_bytes {
                return Err(MitreSyncError::BundleTooLarge {
                    observed: body.len().saturating_add(chunk.len()),
                    limit: self.source.max_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }

        let actual_digest = hex::encode(Sha256::digest(&body));
        if actual_digest != self.source.sha256 {
            return Err(MitreSyncError::DigestMismatch {
                expected: self.source.sha256.clone(),
                actual: actual_digest,
            });
        }

        let bundle: StixBundle = serde_json::from_slice(&body)?;
        if bundle.bundle_type != "bundle" || bundle.id != self.source.bundle_id {
            return Err(MitreSyncError::InvalidBundle(format!(
                "unexpected identity type={} id={}",
                bundle.bundle_type, bundle.id
            )));
        }
        if bundle.objects.len() < self.source.min_objects {
            return Err(MitreSyncError::InvalidBundle(format!(
                "only {} STIX objects (minimum {})",
                bundle.objects.len(),
                self.source.min_objects
            )));
        }
        Ok(bundle)
    }

    fn parse_catalog(
        &self,
        bundle: &StixBundle,
    ) -> Result<(Vec<MitreTactic>, Vec<MitreTechnique>), MitreSyncError> {
        let mut tactic_map = HashMap::new();
        let mut tactic_ids = HashSet::new();
        let mut tactics = Vec::new();

        for object in bundle.objects.iter().filter(|object| {
            object.object_type == "x-mitre-tactic"
                && object.revoked != Some(true)
                && object.x_mitre_deprecated != Some(true)
        }) {
            let tactic = self.parse_tactic(object)?;
            if !tactic_ids.insert(tactic.id.clone()) {
                return Err(MitreSyncError::InvalidBundle(format!(
                    "duplicate tactic {}",
                    tactic.id
                )));
            }
            if tactic_map
                .insert(tactic.short_name.clone(), tactic.id.clone())
                .is_some()
            {
                return Err(MitreSyncError::InvalidBundle(format!(
                    "duplicate tactic short name {}",
                    tactic.short_name
                )));
            }
            tactics.push(tactic);
        }
        if tactics.len() < self.source.min_tactics {
            return Err(MitreSyncError::InvalidBundle(format!(
                "only {} active tactics (minimum {})",
                tactics.len(),
                self.source.min_tactics
            )));
        }

        // ATT&CK v10+ moved data sources off the technique. Resolve each
        // technique's data components once for the whole bundle (keyed by
        // technique STIX id) by walking the detection graph.
        let data_source_labels = resolve_data_source_labels(bundle);

        let mut technique_ids = HashSet::new();
        let mut techniques = Vec::new();
        for object in bundle.objects.iter().filter(|object| {
            object.object_type == "attack-pattern"
                && object.revoked != Some(true)
                && object.x_mitre_deprecated != Some(true)
        }) {
            let technique = self.parse_technique(object, &tactic_map, &data_source_labels)?;
            if !technique_ids.insert(technique.id.clone()) {
                return Err(MitreSyncError::InvalidBundle(format!(
                    "duplicate technique {}",
                    technique.id
                )));
            }
            techniques.push(technique);
        }
        if techniques.len() < self.source.min_techniques {
            return Err(MitreSyncError::InvalidBundle(format!(
                "only {} active techniques (minimum {})",
                techniques.len(),
                self.source.min_techniques
            )));
        }

        for technique in &techniques {
            if technique.tactic_ids.is_empty() {
                return Err(MitreSyncError::InvalidBundle(format!(
                    "technique {} has no enterprise tactic",
                    technique.id
                )));
            }
            if let Some(parent_id) = &technique.parent_id {
                if !technique_ids.contains(parent_id) {
                    return Err(MitreSyncError::InvalidBundle(format!(
                        "sub-technique {} references missing parent {}",
                        technique.id, parent_id
                    )));
                }
            }
        }

        tactics.sort_by(|left, right| left.id.cmp(&right.id));
        techniques.sort_by_key(|technique| (technique.is_subtechnique, technique.id.clone()));
        Ok((tactics, techniques))
    }

    fn parse_tactic(&self, object: &StixObject) -> Result<MitreTactic, MitreSyncError> {
        let id = mitre_external_id(object, "TA")?;
        if !valid_tactic_id(&id) {
            return Err(MitreSyncError::InvalidBundle(format!(
                "invalid tactic id {id}"
            )));
        }
        let name = required_text(object.name.as_deref(), "tactic name", &id, 100)?;
        let short_name = required_text(
            object.x_mitre_shortname.as_deref(),
            "tactic short name",
            &id,
            50,
        )?;
        Ok(MitreTactic {
            id,
            name,
            short_name,
            description: object.description.as_deref().map(truncate_description),
            url: mitre_url(object)?,
        })
    }

    fn parse_technique(
        &self,
        object: &StixObject,
        tactic_map: &HashMap<String, String>,
        data_source_labels: &HashMap<String, Vec<String>>,
    ) -> Result<MitreTechnique, MitreSyncError> {
        let id = mitre_external_id(object, "T")?;
        if !valid_technique_id(&id) {
            return Err(MitreSyncError::InvalidBundle(format!(
                "invalid technique id {id}"
            )));
        }
        let name = required_text(object.name.as_deref(), "technique name", &id, 200)?;
        let mut tactic_ids = Vec::new();
        for phase in object.kill_chain_phases.as_deref().unwrap_or_default() {
            if phase.kill_chain_name.as_deref() != Some("mitre-attack") {
                continue;
            }
            let phase_name = phase.phase_name.as_deref().ok_or_else(|| {
                MitreSyncError::InvalidBundle(format!("technique {id} has an unnamed phase"))
            })?;
            let tactic_id = tactic_map.get(phase_name).ok_or_else(|| {
                MitreSyncError::InvalidBundle(format!(
                    "technique {id} references unknown tactic phase {phase_name}"
                ))
            })?;
            tactic_ids.push(tactic_id.clone());
        }
        tactic_ids.sort();
        tactic_ids.dedup();

        let is_subtechnique = object.x_mitre_is_subtechnique.unwrap_or(false);
        let parent_id = is_subtechnique.then(|| id.split('.').next().unwrap_or(&id).to_string());
        // Pre-v10 bundles carry `x_mitre_data_sources` inline; v10+ bundles
        // resolve to data-component labels via `resolve_data_source_labels`.
        // Prefer the inline form when present, else fall back to the graph.
        let mut data_sources = object.x_mitre_data_sources.clone().unwrap_or_default();
        if data_sources.is_empty() {
            if let Some(labels) = data_source_labels.get(&object.id) {
                data_sources = labels.clone();
            }
        }
        data_sources.sort();
        data_sources.dedup();

        Ok(MitreTechnique {
            id,
            name,
            description: object.description.as_deref().map(truncate_description),
            url: mitre_url(object)?,
            is_subtechnique,
            parent_id,
            tactic_ids,
            deprecated: false,
            data_sources,
        })
    }
}

/// Resolve each technique's ATT&CK data components from the v10+ STIX detection
/// graph, keyed by technique STIX id.
///
/// ATT&CK ≥ v10 removed the inline `x_mitre_data_sources` technique field. In
/// v10–v18 a `detects` relationship links a data component directly to a
/// technique; in v19+ it links an `x-mitre-detection-strategy` to the technique,
/// and the strategy fans out through `x_mitre_analytic_refs` →
/// `x-mitre-analytic` → `x_mitre_log_source_references[].x_mitre_data_component_ref`.
/// Both shapes are handled. Returns sorted, deduped data-component names (e.g.
/// `"Process Creation"`) — the same component labels `nanosiem_sources_for`
/// keys on, so downstream telemetry-readiness mapping is unchanged.
fn resolve_data_source_labels(bundle: &StixBundle) -> HashMap<String, Vec<String>> {
    // x-mitre-data-component id -> display name
    let mut component_names: HashMap<&str, &str> = HashMap::new();
    // x-mitre-analytic id -> the data-component ids it observes
    let mut analytic_components: HashMap<&str, Vec<&str>> = HashMap::new();
    // x-mitre-detection-strategy id -> the analytic ids it references
    let mut strategy_analytics: HashMap<&str, &[String]> = HashMap::new();
    for object in &bundle.objects {
        if object.revoked == Some(true) || object.x_mitre_deprecated == Some(true) {
            continue;
        }
        match object.object_type.as_str() {
            "x-mitre-data-component" => {
                if let Some(name) = object.name.as_deref() {
                    component_names.insert(object.id.as_str(), name);
                }
            }
            "x-mitre-analytic" => {
                let refs: Vec<&str> = object
                    .x_mitre_log_source_references
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|reference| reference.x_mitre_data_component_ref.as_deref())
                    .collect();
                if !refs.is_empty() {
                    analytic_components.insert(object.id.as_str(), refs);
                }
            }
            "x-mitre-detection-strategy" => {
                if let Some(refs) = object.x_mitre_analytic_refs.as_deref() {
                    strategy_analytics.insert(object.id.as_str(), refs);
                }
            }
            _ => {}
        }
    }

    let mut labels: HashMap<String, std::collections::BTreeSet<String>> = HashMap::new();
    for object in &bundle.objects {
        if object.object_type != "relationship"
            || object.relationship_type.as_deref() != Some("detects")
            || object.revoked == Some(true)
        {
            continue;
        }
        let (Some(source_ref), Some(target_ref)) =
            (object.source_ref.as_deref(), object.target_ref.as_deref())
        else {
            continue;
        };
        let entry = labels.entry(target_ref.to_string()).or_default();

        // v10–v18: the detects source is a data component directly.
        if let Some(name) = component_names.get(source_ref) {
            entry.insert((*name).to_string());
            continue;
        }
        // v19+: the detects source is a detection strategy -> analytics -> components.
        if let Some(analytics) = strategy_analytics.get(source_ref) {
            for analytic_id in analytics.iter() {
                let Some(component_ids) = analytic_components.get(analytic_id.as_str()) else {
                    continue;
                };
                for component_id in component_ids {
                    if let Some(name) = component_names.get(component_id) {
                        entry.insert((*name).to_string());
                    }
                }
            }
        }
    }

    labels
        .into_iter()
        .filter(|(_, set)| !set.is_empty())
        .map(|(technique_id, set)| (technique_id, set.into_iter().collect()))
        .collect()
}

fn mitre_external_id(object: &StixObject, prefix: &str) -> Result<String, MitreSyncError> {
    object
        .external_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|reference| reference.source_name.as_deref() == Some("mitre-attack"))
        .and_then(|reference| reference.external_id.clone())
        .filter(|id| id.starts_with(prefix))
        .ok_or_else(|| {
            MitreSyncError::InvalidBundle(format!(
                "object {} has no canonical {prefix} external id",
                object.id
            ))
        })
}

fn mitre_url(object: &StixObject) -> Result<Option<String>, MitreSyncError> {
    let url = object
        .external_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|reference| reference.source_name.as_deref() == Some("mitre-attack"))
        .and_then(|reference| reference.url.clone());
    if url.as_ref().is_some_and(|url| url.len() > 255) {
        return Err(MitreSyncError::InvalidBundle(format!(
            "object {} URL exceeds database limit",
            object.id
        )));
    }
    Ok(url)
}

fn required_text(
    value: Option<&str>,
    field: &str,
    id: &str,
    max_chars: usize,
) -> Result<String, MitreSyncError> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| MitreSyncError::InvalidBundle(format!("{id} has no {field}")))?;
    if value.chars().count() > max_chars {
        return Err(MitreSyncError::InvalidBundle(format!(
            "{id} {field} exceeds {max_chars} characters"
        )));
    }
    Ok(value.to_string())
}

fn truncate_description(description: &str) -> String {
    let first_paragraph = description.split("\n\n").next().unwrap_or(description);
    if first_paragraph.chars().count() <= 500 {
        return first_paragraph.to_string();
    }
    format!(
        "{}...",
        first_paragraph.chars().take(497).collect::<String>()
    )
}

fn valid_tactic_id(id: &str) -> bool {
    id.len() == 6 && id.starts_with("TA") && id[2..].bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_technique_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix('T') else {
        return false;
    };
    match rest.split_once('.') {
        None => rest.len() == 4 && rest.bytes().all(|byte| byte.is_ascii_digit()),
        Some((parent, child)) => {
            parent.len() == 4
                && parent.bytes().all(|byte| byte.is_ascii_digit())
                && child.len() == 3
                && child.bytes().all(|byte| byte.is_ascii_digit())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_BUNDLE: &str = r#"{
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--test",
                "name": "Execution",
                "description": "Execution description",
                "x_mitre_shortname": "execution",
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": "TA0002",
                    "url": "https://attack.mitre.org/tactics/TA0002/"
                }]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--test",
                "name": "Command and Scripting Interpreter",
                "description": "Technique description",
                "x_mitre_is_subtechnique": false,
                "kill_chain_phases": [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "execution"
                }],
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": "T1059",
                    "url": "https://attack.mitre.org/techniques/T1059/"
                }]
            }
        ]
    }"#;

    fn test_sync(url: String, body: &[u8], bundle_id: &str, max_bytes: usize) -> MitreSync {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@localhost/nanosiem_test")
            .expect("lazy pool");
        MitreSync {
            repository: MitreRepository::new(pool),
            source: SyncSource {
                release: "test".to_string(),
                url,
                sha256: hex::encode(Sha256::digest(body)),
                bundle_id: bundle_id.to_string(),
                max_bytes,
                min_objects: 2,
                min_tactics: 1,
                min_techniques: 1,
            },
        }
    }

    #[test]
    fn unicode_description_truncation_is_boundary_safe() {
        let description = "é".repeat(600);
        let truncated = truncate_description(&description);
        assert_eq!(truncated.chars().count(), 500);
        assert!(truncated.ends_with("..."));
    }

    #[tokio::test]
    async fn parse_catalog_resolves_v19_detection_strategy_data_sources() {
        // ATT&CK v19 (the pinned release) has no inline `x_mitre_data_sources`.
        // A `detects` relationship links a detection-strategy to the technique;
        // the strategy fans out through analytics to data components. The parser
        // must resolve that chain so telemetry-readiness (M4) has data.
        let bundle: StixBundle = serde_json::from_str(
            r#"{
            "type": "bundle",
            "id": "bundle--ds",
            "objects": [
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--test",
                    "name": "Execution",
                    "x_mitre_shortname": "execution",
                    "external_references": [{"source_name":"mitre-attack","external_id":"TA0002","url":"https://attack.mitre.org/tactics/TA0002/"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--test",
                    "name": "Command and Scripting Interpreter",
                    "x_mitre_is_subtechnique": false,
                    "kill_chain_phases": [{"kill_chain_name":"mitre-attack","phase_name":"execution"}],
                    "external_references": [{"source_name":"mitre-attack","external_id":"T1059","url":"https://attack.mitre.org/techniques/T1059/"}]
                },
                {"type":"x-mitre-data-component","id":"dc--create","name":"Process Creation"},
                {"type":"x-mitre-data-component","id":"dc--cmd","name":"Command Execution"},
                {"type":"x-mitre-analytic","id":"an--1","name":"Analytic 1","x_mitre_log_source_references":[{"x_mitre_data_component_ref":"dc--create","name":"WinEventLog:Sysmon"},{"x_mitre_data_component_ref":"dc--cmd","name":"WinEventLog:Security"}]},
                {"type":"x-mitre-detection-strategy","id":"det--1","name":"Strategy 1","x_mitre_analytic_refs":["an--1"]},
                {"type":"relationship","id":"rel--1","relationship_type":"detects","source_ref":"det--1","target_ref":"attack-pattern--test"}
            ]
        }"#,
        )
        .expect("bundle parses");

        let sync = test_sync("http://x".to_string(), b"x", "bundle--ds", 1_048_576);
        let (_tactics, techniques) = sync.parse_catalog(&bundle).expect("catalog parses");
        let technique = techniques
            .iter()
            .find(|t| t.id == "T1059")
            .expect("technique present");
        // Resolved through strategy -> analytic -> components, sorted+deduped;
        // these are exactly the labels nanosiem_sources_for keys on.
        assert_eq!(
            technique.data_sources,
            vec!["Command Execution".to_string(), "Process Creation".to_string()]
        );
    }

    #[test]
    fn attack_ids_are_strictly_canonical() {
        assert!(valid_tactic_id("TA0001"));
        assert!(!valid_tactic_id("ta0001"));
        assert!(valid_technique_id("T1059"));
        assert!(valid_technique_id("T1059.001"));
        assert!(!valid_technique_id("T1059.1"));
        assert!(!valid_technique_id("t1059"));
    }

    #[tokio::test]
    async fn bounded_fetch_validates_and_parses_the_pinned_shape() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_BUNDLE, "application/json"))
            .mount(&server)
            .await;
        let sync = test_sync(
            server.uri(),
            TEST_BUNDLE.as_bytes(),
            "bundle--test",
            16 * 1024,
        );

        let bundle = sync.fetch_bundle().await.expect("valid bundle");
        let (tactics, techniques) = sync.parse_catalog(&bundle).expect("valid catalog");
        assert_eq!(tactics.len(), 1);
        assert_eq!(techniques.len(), 1);
        assert_eq!(techniques[0].tactic_ids, vec!["TA0002"]);
    }

    #[tokio::test]
    async fn fetch_rejects_bad_status_before_parsing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let sync = test_sync(server.uri(), TEST_BUNDLE.as_bytes(), "bundle--test", 1024);

        assert!(matches!(
            sync.fetch_bundle().await,
            Err(MitreSyncError::HttpStatus(status)) if status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
    }

    #[tokio::test]
    async fn fetch_rejects_oversized_body() {
        let server = MockServer::start().await;
        let body = b"body larger than the configured ceiling";
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
        let sync = test_sync(server.uri(), body, "bundle--test", 4);

        assert!(matches!(
            sync.fetch_bundle().await,
            Err(MitreSyncError::BundleTooLarge { limit: 4, .. })
        ));
    }

    #[tokio::test]
    async fn fetch_rejects_digest_and_bundle_identity_mismatches() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_BUNDLE, "application/json"))
            .mount(&server)
            .await;

        let mut bad_digest = test_sync(
            server.uri(),
            TEST_BUNDLE.as_bytes(),
            "bundle--test",
            16 * 1024,
        );
        bad_digest.source.sha256 = "0".repeat(64);
        assert!(matches!(
            bad_digest.fetch_bundle().await,
            Err(MitreSyncError::DigestMismatch { .. })
        ));

        let bad_identity = test_sync(
            server.uri(),
            TEST_BUNDLE.as_bytes(),
            "bundle--different",
            16 * 1024,
        );
        assert!(matches!(
            bad_identity.fetch_bundle().await,
            Err(MitreSyncError::InvalidBundle(_))
        ));
    }

    #[tokio::test]
    #[ignore = "networked verification of the reviewed upstream release artifact"]
    async fn pinned_release_digest_and_catalog_shape_match() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@localhost/nanosiem_test")
            .expect("lazy pool");
        let sync = MitreSync::new(MitreRepository::new(pool));

        let bundle = sync.fetch_bundle().await.expect("pinned bundle");
        let (tactics, techniques) = sync.parse_catalog(&bundle).expect("pinned catalog");
        assert_eq!(tactics.len(), 15);
        assert_eq!(techniques.len(), 697);
    }
}
