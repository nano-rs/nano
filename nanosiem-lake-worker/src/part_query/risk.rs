// SPDX-License-Identifier: AGPL-3.0-or-later

//! Risk over parts (design 3.2 "Risk", contract 3.5).
//!
//! **Finding rows.** Detection findings enter the part log as OCSF Detection
//! Finding rows (class 2004) written by the tenant's authenticated
//! `detect[T]` outbox drain. Each row
//! carries the outbox's compact finding verbatim as the string leaf
//! [`COMPACT_FINDING_PATH`] (`unmapped.nano_compact_finding`). That is the
//! lossless record `lake_risk_publish` serves from today, so risk results are
//! identical by construction. [`finding_event`] builds the row and
//! [`risk_partial_rows`] the part's `partials/risk.parquet` rows (3.5).
//!
//! **Query.** A risk partial identifies a part carrying findings, but a
//! compacted part can also contain ordinary events. The query role maintains
//! immutable compact ledgers from authenticated finding columns, reusing them
//! by the selected signed finding inventory rather than the moving timestamp
//! or unrelated ingest head. [`crate::risk::RiskService`] applies exact time,
//! decay, clear and source predicates to that small state on every read.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::engine::{BroadNplRequest, PartQueryEngine, PartQueryError, QueryResult};
use crate::config::LoadedRiskSnapshotConfig;
use crate::parts::provenance::PartialKind;
use crate::risk::{RiskRequest, RiskService};

/// Where a finding row carries its compact finding (a JSON string).
pub const COMPACT_FINDING_PATH: &str = "unmapped.nano_compact_finding";
pub const TRUSTED_FINDING_PATH: &str = "unmapped.nano_finding_outbox_trusted";
/// `metadata.log_source` of every finding row: the ClickHouse product's
/// `source_type` for detection findings, so `source_type=findings` selects
/// them in a tenant's logs search.
pub const FINDING_LOG_SOURCE: &str = "findings";
/// `lake_risk_publish`'s ledger structure (kept byte-identical).
pub const FINDING_STRUCTURE: &str = "id String, timestamp_us Int64, entity String, stamped_entity_type String, risk_score Int64, rule_id String, rule_name String, severity String, origin_source_types Array(String), mitre_tactics Array(String)";
const DAY_US: i64 = 86_400_000_000;
const GLOBAL_CLEAR_ENTITY: &str = "__nano_global_clear_boundary__";

/// The outbox's compact finding (`findings.rs::prepare_lake_outbox_payload`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactFinding {
    pub id: String,
    pub timestamp_us: i64,
    pub entity: String,
    pub stamped_entity_type: String,
    pub risk_score: i64,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub origin_source_types: Vec<String>,
    pub mitre_tactics: Vec<String>,
}

/// The OCSF finding row a finding part stores: the outbox's `ocsf_event`
/// plus the compact finding under [`COMPACT_FINDING_PATH`].
pub fn finding_event(ocsf_event: &Value, compact: &CompactFinding) -> Result<Value> {
    let mut event = ocsf_event.clone();
    let object = event.as_object_mut().context("finding event is not an object")?;
    if object.get("class_uid").and_then(Value::as_i64) != Some(2004) {
        bail!("finding event is not an OCSF Detection Finding");
    }
    if object.get("metadata").and_then(|value| value.get("uid")).and_then(Value::as_str) != Some(compact.id.as_str()) {
        bail!("finding event uid and compact finding id differ");
    }
    // ClickHouse-product search parity: findings were searched as
    // `source_type=findings`, and on the lake `source_type` resolves to
    // `metadata.log_source`. The drain, not the producer, stamps it.
    object
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .context("finding metadata is not an object")?
        .insert("log_source".to_string(), Value::String(FINDING_LOG_SOURCE.to_string()));
    let unmapped = object.entry("unmapped").or_insert_with(|| json!({}));
    let unmapped = unmapped.as_object_mut().context("finding unmapped is not an object")?;
    unmapped.insert("nano_compact_finding".to_string(), Value::String(serde_json::to_string(compact)?));
    unmapped.insert("nano_finding_outbox_trusted".to_string(), Value::String("v1".to_string()));
    Ok(event)
}

/// One `partials/risk.parquet` row (contract 3.5).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RiskPartialRow {
    #[serde(skip)]
    pub(crate) key: (String, String, String, i64),
    pub entity: String,
    pub entity_type: String,
    pub rule_id: String,
    pub bucket_start_us: i64,
    pub findings: u64,
    pub risk_score_sum: i64,
    pub max_severity_id: i32,
}

/// The reader's entity typing (`risk.rs::aggregate_sql`).
pub fn entity_type(stamped: &str, entity: &str) -> &'static str {
    let octets = entity.split('.').collect::<Vec<_>>();
    let is_ipv4 = octets.len() == 4
        && octets.iter().all(|octet| (1..=3).contains(&octet.len()) && octet.bytes().all(|b| b.is_ascii_digit()));
    if stamped == "cloud_account" {
        "cloud_account"
    } else if is_ipv4 {
        "ip"
    } else if entity.contains('@') {
        "email"
    } else if entity.contains('.') {
        "hostname"
    } else {
        "user"
    }
}

fn severity_id(severity: &str) -> i32 {
    match severity {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" | "informational" => 1,
        _ => 0,
    }
}

/// The keyed per-minute risk partial of a finding part's compact findings.
pub fn risk_partial_rows(findings: &[CompactFinding]) -> Vec<RiskPartialRow> {
    let mut rows: BTreeMap<(String, String, String, i64), RiskPartialRow> = BTreeMap::new();
    for finding in findings {
        let bucket = finding.timestamp_us.div_euclid(60_000_000) * 60_000_000;
        let entity_type = entity_type(&finding.stamped_entity_type, &finding.entity).to_string();
        let key = (finding.entity.clone(), entity_type.clone(), finding.rule_id.clone(), bucket);
        let row = rows.entry(key).or_insert_with(|| RiskPartialRow {
            key: (finding.entity.clone(), entity_type.clone(), finding.rule_id.clone(), bucket),
            entity: finding.entity.clone(),
            entity_type,
            rule_id: finding.rule_id.clone(),
            bucket_start_us: bucket,
            findings: 0,
            risk_score_sum: 0,
            max_severity_id: 0,
        });
        row.findings += 1;
        row.risk_score_sum = row.risk_score_sum.saturating_add(finding.risk_score);
        row.max_severity_id = row.max_severity_id.max(severity_id(&finding.severity));
    }
    rows.into_values().collect()
}

/// Maintain the compact findings of the live parts overlapping the request.
/// Cache whole immutable parts; RiskService applies the exact request bounds.
pub(super) async fn ledger(engine: &PartQueryEngine, state_dir: &Path, from_us: i64, to_us: i64) -> Result<(PathBuf, Option<u64>)> {
    // Select exact overlapping live parts. Compacted parts may also carry
    // unrelated events; only their authenticated compact findings enter state.
    static BUILD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    // NAN-3148: with a product role the ledger lives in product[T]'s dir.
    let queue_dir = state_dir;
    let state_dir = super::product_state::dir_for(engine, state_dir);
    let (parts, _, head, _) = engine.snapshot(from_us, to_us).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let records = futures::future::try_join_all(parts.iter().map(|part| engine.fetcher().record(part))).await?;
    let finding_parts = parts.into_iter().zip(records)
        .filter(|(_, record)| record.files.partials.iter().any(|partial| partial.kind == PartialKind::Risk))
        .map(|(part, _)| part).collect::<Vec<_>>();
    // Ingest-only head advances and a moving anchor do not change immutable
    // findings. Exact time predicates remain in RiskService, not this cache.
    use sha2::{Digest, Sha256};
    let mut identities = finding_parts.iter().map(|part| serde_json::to_vec(part)).collect::<std::result::Result<Vec<_>, _>>()?;
    identities.sort();
    let mut digest = Sha256::new();
    for identity in identities { digest.update((identity.len() as u64).to_le_bytes()); digest.update(identity); }
    let path = state_dir.join(format!("risk-ledger-v2-{}.parquet", hex::encode(digest.finalize())));
    if path.is_file() {
        if super::product_publish::writes(engine) {
            std::fs::File::open(&path)?.set_modified(std::time::SystemTime::now())?;
        }
        return Ok((path, head));
    }
    if !super::product_state::building() {
        let work = super::product_state::Work::Risk(from_us, to_us);
        // A consumer serves product[T]'s newest ledger of this lookback
        // (its findings up to that build) while it is recent.
        if let Some((published, entry)) = super::product_publish::latest(engine, &super::product_publish::risk_key(from_us, to_us), &work) {
            return Ok((published, entry.log_head));
        }
        super::product_state::request_at(engine, queue_dir, work);
        bail!(super::product_state::WARMING);
    }
    let _build = BUILD.lock().await;
    // Reject filesystem faults before native INSERT opens an output sink.
    std::fs::create_dir_all(state_dir).context("prepare risk state directory")?;
    engine.writer().context("risk needs the read-write lane")?;
    let temporary = state_dir.join(format!(".risk-ledger-{}.parquet", uuid::Uuid::new_v4().simple()));
    if finding_parts.is_empty() {
        super::risk_ledger::write_empty(&temporary)?;
        std::fs::rename(&temporary, &path)?;
        return Ok((path, head));
    }
    let mut params = vec![
        ("ledger_output".to_string(), temporary.to_str().context("state path is not UTF-8")?.to_string()),
        ("ledger_structure".to_string(), FINDING_STRUCTURE.to_string()),
    ];
    let select = {
        let mut paths = Vec::new();
        for part in &finding_parts {
            paths.push(super::risk_ledger::part_ledger(engine, state_dir, part).await?
                .to_str().context("ledger path is not UTF-8")?.to_string());
        }
        params.push(("finding_source".to_string(), crate::planner::local_path_spec(&mut paths)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?));
        // Deduplicate across parts exactly as the former full-data ledger did.
        "SELECT * FROM file({finding_source:String}, Parquet, {ledger_structure:String}) ORDER BY id LIMIT 1 BY id".to_string()
    };
    let statement = format!(
        "INSERT INTO FUNCTION file({{ledger_output:String}}, Parquet, {{ledger_structure:String}}) {select} \
         SETTINGS {}, max_memory_usage={}, use_query_cache=0",
        // NAN-3168: the product thread budget under build authority.
        super::product_state::thread_settings(engine.settings().threads),
        engine.settings().max_memory_bytes
    );
    let _slot = super::product_state::idle(engine).await;
    let result = engine.with_job_statements(engine.run_sql(statement, params)).await;
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(anyhow::anyhow!(error.to_string()));
    }
    std::fs::rename(&temporary, &path)?;
    // Retain recently read ledgers until bounded native readers have finished.
    if let Ok(entries) = std::fs::read_dir(state_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if (name.starts_with("risk-ledger-") || name.starts_with("risk-part-v1-") || name.starts_with(".risk-")) && entry.path() != path
                && entry.metadata().ok().and_then(|m| m.modified().ok())
                    .and_then(|at| at.elapsed().ok())
                    .is_some_and(|age| age.as_secs() > 7_200) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    Ok((path, head))
}

/// Maintain the seven-day compact state independently of readiness and after
/// part-log advances, rather than charging the first page for a rebuild.
pub async fn prewarm(engine: &PartQueryEngine, state_dir: &Path) -> Result<()> {
    if engine.writer().is_none() { return Ok(()); }
    let anchor = chrono::Utc::now().timestamp_micros();
    let meter = super::product_state::BuildMeter::start();
    let (path, _) = super::product_state::BUILD.scope((), ledger(engine, state_dir, anchor - 7 * DAY_US, anchor)).await?;
    use parquet::file::reader::FileReader;
    let rows = parquet::file::reader::SerializedFileReader::new(std::fs::File::open(path)?)?;
    let threads = super::product_state::BUILD.scope((), async { super::product_state::statement_threads(engine.settings().threads) }).await;
    tracing::info!(state = "risk", rows = rows.metadata().file_metadata().num_rows(), wall_ms = meter.wall_ms(), cpu_ms = meter.cpu_ms(),
        cpu_scope = super::product_state::CPU_SCOPE, threads, "product state ready");
    Ok(())
}

/// `/v1/risk` over parts: the reader's RiskService over the part ledger.
pub async fn risk(engine: &PartQueryEngine, state_dir: &Path, request: &RiskRequest) -> Result<Value> {
    if request.tenant_id != engine.settings().tenant_id {
        bail!("request tenant is not this process's tenant");
    }
    let lookback_days = request.lookback_days.unwrap_or(7).clamp(7, 400);
    let from_us = request.anchor_us - lookback_days * DAY_US;
    let (path, head) = ledger(engine, state_dir, from_us, request.anchor_us).await?;
    let metadata = std::fs::metadata(&path)?;
    let service = RiskService::new(LoadedRiskSnapshotConfig {
        snapshot_id: format!("parts-{}", head.unwrap_or(0)),
        snapshot_version: format!("{}", head.unwrap_or(0)),
        source: path,
        bytes: metadata.len(),
        modified: metadata.modified()?,
        clear_snapshot_version: None,
        clear_source: None,
        clear_bytes: 0,
        clear_modified: None,
        clear_published_revision: request.minimum_clear_revision.unwrap_or(0),
        global_clear_us: request.clear_boundaries.get(GLOBAL_CLEAR_ENTITY).copied().unwrap_or(0),
    });
    let tenant = engine.limits_tenant();
    let result = service
        .execute(engine.executor(), &tenant, request)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    cell_response(result, request, head)
}

/// Wrap the reader's `RiskService` output as the `/v1/risk` answer.
///
/// Same flat envelope the gen1 reader returns (`risk_query` merges its
/// identity keys into the service output): `result.rows` sits at the top
/// level, never nested under a second `result` (NAN-3035). The API parses it
/// with [`nanosiem_core::risk::wire::RiskReadEnvelope`].
pub(crate) fn cell_response(mut service_output: Value, request: &RiskRequest, head: Option<u64>) -> Result<Value> {
    let object = service_output
        .as_object_mut()
        .context("risk service output is not an object")?;
    object.insert("ok".to_string(), Value::Bool(true));
    object.insert("request_id".to_string(), json!(request.request_id));
    object.insert("tenant_id".to_string(), json!(request.tenant_id));
    object.insert("route".to_string(), json!("risk"));
    object.insert("source_mode".to_string(), json!(nanosiem_core::risk::wire::CELL_SOURCE_MODE));
    object.insert("log_seq".to_string(), json!(head));
    Ok(service_output)
}

pub async fn broad_npl(
    engine: &PartQueryEngine,
    state_dir: &Path,
    request: &BroadNplRequest,
) -> QueryResult<Value> {
    super::engine::validate_broad_npl(request, &engine.settings().tenant_id)?;
    if request.tenant_id != engine.settings().tenant_id || request.dataset != "risk" {
        return Err(PartQueryError::Invalid(
            "risk nPL tenant or dataset differs".into(),
        ));
    }
    let anchor_us = request
        .anchor_us
        .ok_or_else(|| PartQueryError::Invalid("risk nPL needs a resolved anchor".into()))?;
    let decay = request
        .decay
        .clone()
        .ok_or_else(|| PartQueryError::Invalid("risk nPL needs resolved decay".into()))?;
    let compiled = engine.compile(request, BTreeMap::new()).await?;
    let (path, head) = ledger(engine, state_dir, anchor_us - 7 * DAY_US, anchor_us)
        .await
        .map_err(|error| PartQueryError::Unavailable(error.to_string()))?;
    let metadata =
        std::fs::metadata(&path).map_err(|error| PartQueryError::Unavailable(error.to_string()))?;
    let risk_request = RiskRequest {
        request_id: request.request_id.clone(),
        tenant_id: request.tenant_id.clone(),
        risk_operation: "npl".into(),
        anchor_us,
        decay,
        clear_boundaries: request.clear_boundaries.clone(),
        watch_weights: request.watch_weights.clone(),
        minimum_clear_revision: request.minimum_clear_revision,
        deny_source_types: request.deny_source_types.iter().cloned().collect(),
        window: None,
        entity_type_filter: None,
        min_score: None,
        max_score: None,
        min_score_24h: None,
        min_score_7d: None,
        limit: None,
        offset: None,
        entities: Vec::new(),
        lookback_days: None,
        suggest_patterns: Vec::new(),
    };
    let service = RiskService::new(LoadedRiskSnapshotConfig {
        snapshot_id: format!("parts-{}", head.unwrap_or(0)),
        snapshot_version: head.unwrap_or(0).to_string(),
        source: path,
        bytes: metadata.len(),
        modified: metadata
            .modified()
            .map_err(|error| super::engine::internal_text(error.to_string()))?,
        clear_snapshot_version: None,
        clear_source: None,
        clear_bytes: 0,
        clear_modified: None,
        clear_published_revision: request.minimum_clear_revision.unwrap_or(0),
        global_clear_us: request
            .clear_boundaries
            .get(GLOBAL_CLEAR_ENTITY)
            .copied()
            .unwrap_or(0),
    });
    let (source, params, bytes) = service
        .npl_source(&risk_request)
        .map_err(|error| PartQueryError::Invalid(error.to_string()))?;
    let plan = crate::planner::plan_broad_risk_query(
        &engine.limits_tenant(),
        &compiled,
        &source,
        params,
        bytes,
    )
    .map_err(|error| PartQueryError::Invalid(error.to_string()))?;
    let budget = serde_json::to_value(&plan.budget)
        .map_err(|error| super::engine::internal_text(error.to_string()))?;
    let output = engine.execute(plan).await?;
    let rows = super::engine::decode_rows(&output.data)?;
    let (rows, has_more) =
        super::engine::page_decoded(rows, &Default::default(), request.offset, request.limit);
    Ok(json!({
        "ok": true, "schema_version": 1, "request_id": request.request_id,
        "tenant_id": request.tenant_id, "route": "broad_npl", "source_mode": "parts",
        "log_head": engine.head_json().await,
        "query_sha256": compiled.query_sha256, "budget": budget,
        "schema_defaults": [], "planner": {"risk_log_seq": head},
        "result": {"result_rows": rows.len(), "rows": rows,
            "page_offset": request.offset, "page_limit": request.limit, "page_has_more": has_more,
            "engine_seconds": output.elapsed.as_secs_f64(),
            "storage_rows": output.storage_rows_read, "storage_bytes": output.storage_bytes_read,
            "query_result_cache_hit": false}
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(entity: &str, at: i64, score: i64, severity: &str) -> CompactFinding {
        CompactFinding {
            id: format!("detection:{entity}{at}"),
            timestamp_us: at,
            entity: entity.into(),
            stamped_entity_type: String::new(),
            risk_score: score,
            rule_id: "r1".into(),
            rule_name: "Rule".into(),
            severity: severity.into(),
            origin_source_types: vec!["windows_sysmon".into()],
            mitre_tactics: vec!["execution".into()],
        }
    }

    /// NAN-3035 contract: the cell's real `/v1/risk` answer (the reader's
    /// `RiskService` envelope wrapped by [`cell_response`]) serialized to
    /// bytes and parsed with the API's envelope type, rows and empty alike.
    #[test]
    fn cell_risk_response_parses_with_the_api_envelope() {
        use nanosiem_core::risk::wire::RiskReadEnvelope;
        let tenant_id = "aaaaaaaa-0000-4000-8000-000000000001";
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("risk-ledger.parquet");
        std::fs::write(&ledger, b"ledger").unwrap();
        let metadata = std::fs::metadata(&ledger).unwrap();
        let service = RiskService::new(LoadedRiskSnapshotConfig {
            snapshot_id: "parts-5533".into(),
            snapshot_version: "5533".into(),
            source: ledger,
            bytes: metadata.len(),
            modified: metadata.modified().unwrap(),
            clear_snapshot_version: None,
            clear_source: None,
            clear_bytes: 0,
            clear_modified: None,
            clear_published_revision: 0,
            global_clear_us: 0,
        });
        let tenant = crate::planner::TenantQueryConfig {
            tenant_id: tenant_id.into(),
            source: "s3://bucket/parts".into(),
            iceberg_metadata_file_path: "lake-parts-v1".into(),
            max_query_bytes: 1 << 36,
            max_memory_bytes: 1 << 30,
            max_execution_seconds: 30,
            threads: 2,
            credentials: crate::planner::ObjectStoreCredentials::DefaultChain,
            snapshot_cache: None,
        };
        let request: RiskRequest = serde_json::from_value(json!({
            "request_id": "01a0ed9f-d020-70c2-aa82-9c7be7087828",
            "tenant_id": tenant_id,
            "risk_operation": "entity_types",
            "anchor_us": 1_790_693_572_000_000_i64,
            "decay": {"decay_0_24h": 1.0, "decay_1_3d": 0.75, "decay_3_5d": 0.5, "decay_5_7d": 0.25},
        }))
        .unwrap();

        #[derive(serde::Deserialize)]
        struct EntityTypeRow {
            entity_type: String,
            entity_count: i64,
        }
        let rows = vec![json!({"entity_type": "hostname", "entity_count": 2})];
        let body = serde_json::to_vec(
            &cell_response(service.envelope(&tenant, rows, 0.04, 3, 426), &request, Some(5533)).unwrap(),
        )
        .unwrap();
        let parsed: Vec<EntityTypeRow> = serde_json::from_slice::<RiskReadEnvelope<EntityTypeRow>>(&body)
            .unwrap()
            .into_cell_rows(tenant_id)
            .unwrap();
        assert_eq!((parsed[0].entity_type.as_str(), parsed[0].entity_count), ("hostname", 2));

        // No findings yet: `rows: []` is a valid answer, not an error.
        let empty = serde_json::to_vec(
            &cell_response(service.envelope(&tenant, Vec::new(), 0.04, 0, 0), &request, Some(5533)).unwrap(),
        )
        .unwrap();
        let parsed = serde_json::from_slice::<RiskReadEnvelope<EntityTypeRow>>(&empty)
            .unwrap()
            .into_cell_rows(tenant_id)
            .unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn partials_bucket_by_minute_and_type_entities_like_the_reader() {
        let rows = risk_partial_rows(&[
            finding("10.0.0.1", 60_000_000, 10, "low"),
            finding("10.0.0.1", 119_999_999, 5, "high"),
            finding("alice@corp.io", 0, 7, "medium"),
        ]);
        assert_eq!(rows.len(), 2);
        let ip = rows.iter().find(|row| row.entity == "10.0.0.1").unwrap();
        assert_eq!((ip.entity_type.as_str(), ip.findings, ip.risk_score_sum, ip.max_severity_id), ("ip", 2, 15, 4));
        assert_eq!(entity_type("", "host.corp"), "hostname");
        assert_eq!(entity_type("", "bob"), "user");
        assert_eq!(entity_type("cloud_account", "123"), "cloud_account");
    }

    #[test]
    fn finding_rows_carry_the_compact_finding_losslessly() {
        let compact = finding("bob", 5, 3, "low");
        let row = finding_event(&json!({"class_uid": 2004, "metadata": {"uid": compact.id}, "unmapped": {"rule_mode": "alerting"}}), &compact).unwrap();
        let carried: CompactFinding = serde_json::from_str(row["unmapped"]["nano_compact_finding"].as_str().unwrap()).unwrap();
        assert_eq!(carried, compact);
        assert_eq!(row["unmapped"]["rule_mode"], "alerting");
        assert_eq!(row["unmapped"]["nano_finding_outbox_trusted"], "v1");
        assert_eq!(row["metadata"]["log_source"], FINDING_LOG_SOURCE, "the drain stamps the finding source");
        let relabeled = finding_event(&json!({"class_uid": 2004, "metadata": {"uid": compact.id, "log_source": "signals"}}), &compact).unwrap();
        assert_eq!(relabeled["metadata"]["log_source"], FINDING_LOG_SOURCE);
        assert!(finding_event(&json!({"class_uid": 1007}), &compact).is_err());
        assert!(finding_event(&json!({"class_uid": 2004, "metadata": {"uid": "other-tenant-finding"}}), &compact).is_err());
    }
}
