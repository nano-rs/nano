// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact, generation-pinned hourly count rollups.
//!
//! Rollups accelerate only the algebra they can reproduce exactly. The worker
//! combines these base-snapshot rows with raw partial buckets and the signed
//! hot tail before returning a result. Request data selects a known field and
//! values only; it can never supply SQL or storage coordinates.

use crate::config::{LoadedCountRollupConfig, VerifiedArtifact};
use crate::derivative_tier::{ArtifactRef, DerivativeTier, PinnedArtifact};
use crate::planner::{
    CountPredicate, CountPredicateKind, DASHBOARD_BREAKDOWN_FIELD, ObjectStoreCredentials,
    TenantQueryConfig, append_count_predicate,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const COUNT_ROLLUP_VERSION: &str = "nano-ocsf-5m-count-v5";
const LEGACY_COUNT_ROLLUP_VERSION: &str = "nano-ocsf-5m-count-v4";
pub const COUNT_ROLLUP_BUCKET_US: i64 = 300_000_000;
const MAX_PARTS_PER_QUERY: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CountRollupField {
    pub field_id: u16,
    pub source_path: &'static str,
    pub multi_value: bool,
}

macro_rules! scalar_field {
    ($field_id:literal, $source_path:expr) => {
        CountRollupField {
            field_id: $field_id,
            source_path: $source_path,
            multi_value: false,
        }
    };
}

macro_rules! multi_field {
    ($field_id:literal, $source_path:expr) => {
        CountRollupField {
            field_id: $field_id,
            source_path: $source_path,
            multi_value: true,
        }
    };
}

/// Whether `field` is a rollup field and, if so, whether it is multi-valued.
/// Static: the answer depends on the contract, not on any built rollup, so
/// the bootstrap generation (which has no rollup) validates requests exactly
/// like a real one (NAN-2361 wave 8).
pub fn count_rollup_field_multi_value(field: &str) -> Option<bool> {
    COUNT_ROLLUP_FIELDS
        .iter()
        .find(|candidate| candidate.source_path == field)
        .map(|candidate| candidate.multi_value)
}

pub const COUNT_ROLLUP_FIELDS: &[CountRollupField] = &[
    scalar_field!(0, "metadata.log_source"),
    scalar_field!(1, "process.name"),
    scalar_field!(2, "process.cmd_line"),
    scalar_field!(3, "actor.process.name"),
    scalar_field!(4, "actor.process.cmd_line"),
    scalar_field!(5, "device.hostname"),
    scalar_field!(6, "src_endpoint.hostname"),
    scalar_field!(7, "dst_endpoint.hostname"),
    scalar_field!(8, "src_endpoint.ip"),
    scalar_field!(9, "dst_endpoint.ip"),
    scalar_field!(10, "user.name"),
    scalar_field!(11, "actor.user.name"),
    scalar_field!(12, "file.name"),
    scalar_field!(13, "file.path"),
    scalar_field!(14, "module.file.name"),
    scalar_field!(15, "module.file.path"),
    scalar_field!(16, "http_request.url.hostname"),
    scalar_field!(17, "http_request.url.url_string"),
    scalar_field!(18, "severity"),
    scalar_field!(19, "class_name"),
    scalar_field!(20, "category_name"),
    scalar_field!(21, "activity_name"),
    scalar_field!(22, "src_endpoint.mac"),
    scalar_field!(23, "dst_endpoint.mac"),
    scalar_field!(24, "user.uid"),
    scalar_field!(25, "actor.user.uid"),
    scalar_field!(26, "process.uid"),
    scalar_field!(27, "actor.process.uid"),
    scalar_field!(28, "url.hostname"),
    scalar_field!(29, "url.url_string"),
    scalar_field!(30, "query.hostname"),
    scalar_field!(31, "email.from"),
    scalar_field!(32, "email.to"),
    scalar_field!(33, "vulnerabilities.cve.uid"),
    multi_field!(34, "file.hashes.value"),
    multi_field!(35, "process.file.hashes.value"),
    multi_field!(36, "actor.process.file.hashes.value"),
    multi_field!(37, "answers.rdata"),
    multi_field!(38, "resources.ip"),
    multi_field!(39, "resources.hostname"),
    multi_field!(40, "resources.device.hostname"),
    multi_field!(41, "resources.user.name"),
    multi_field!(42, "resources.user.uid"),
    multi_field!(43, "resources.uid"),
    multi_field!(44, "evidences.query.hostname"),
    multi_field!(45, "evidences.url.url_string"),
    scalar_field!(46, DASHBOARD_BREAKDOWN_FIELD),
    scalar_field!(47, "class_uid"),
    scalar_field!(48, "category_uid"),
    scalar_field!(49, "activity_id"),
    scalar_field!(50, "type_uid"),
    scalar_field!(51, "severity_id"),
    scalar_field!(52, "status"),
    scalar_field!(53, "status_id"),
    scalar_field!(54, "src_endpoint.port"),
    scalar_field!(55, "dst_endpoint.port"),
    scalar_field!(56, "src_endpoint.location.country"),
    scalar_field!(57, "dst_endpoint.location.country"),
    scalar_field!(58, "api.service.name"),
    scalar_field!(59, "metadata.product.name"),
    scalar_field!(60, "metadata.product.vendor_name"),
    scalar_field!(61, "cloud.provider"),
    scalar_field!(62, "cloud.region"),
    scalar_field!(63, "cloud.account.uid"),
    scalar_field!(64, "finding_info.analytic.name"),
    scalar_field!(65, "finding_info.title"),
    scalar_field!(66, "unmapped.error_code"),
    scalar_field!(67, "unmapped.threat_tier"),
    scalar_field!(68, "unmapped.threat_blocked"),
    multi_field!(69, "enrichments.name"),
    multi_field!(70, "enrichments.value"),
    multi_field!(71, "enrichments.type"),
    multi_field!(72, "enrichments.provider"),
    multi_field!(73, "enrichments.short_desc"),
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CountRollupManifest {
    pub schema_version: u64,
    pub rollup_version: String,
    pub tenant_id: String,
    pub event_snapshot_id: i64,
    pub object_stamp_sha256: String,
    pub bucket_width_us: i64,
    pub fields: Vec<CountRollupManifestField>,
    pub objects: Vec<CountRollupObject>,
    pub rows: u64,
    pub bytes: u64,
    #[serde(default)]
    pub build_seconds: f64,
    #[serde(default)]
    pub reused_objects: usize,
    #[serde(default)]
    pub built_objects: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CountRollupManifestField {
    pub field_id: u16,
    pub source_path: String,
    pub multi_value: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CountRollupObject {
    /// Positional file locator within this manifest (`object-{id:04}.parquet`
    /// at array position id). NOT a stable identity — count-rollup parts embed
    /// no id in their bytes, so restamping this on reuse is metadata-only.
    #[serde(default)]
    pub object_id: u32,
    #[serde(default)]
    pub event_object_key: String,
    #[serde(default)]
    pub event_object_version: String,
    #[serde(default)]
    pub event_object_bytes: u64,
    pub relative_path: String,
    pub min_bucket_start_us: i64,
    pub max_bucket_start_us: i64,
    pub rows: u64,
    pub bytes: u64,
    pub sha256: String,
}

/// Where one immutable rollup part is served from. `Local` parts passed the
/// on-disk digest fence at load; `Tiered` parts were absent locally and are
/// resolved at plan time — pinned cache hit or a direct object-storage read.
#[derive(Clone, Debug)]
enum PartLocation {
    Local(PathBuf),
    Tiered(ArtifactRef),
}

#[derive(Clone, Debug)]
struct LoadedPart {
    location: PartLocation,
    min_bucket_start_us: i64,
    max_bucket_start_us: i64,
    bytes: u64,
}

#[derive(Clone, Debug)]
pub struct CountRollup {
    event_snapshot_id: i64,
    fields: BTreeMap<String, (u16, bool)>,
    parts: Vec<LoadedPart>,
    tier: Option<Arc<DerivativeTier>>,
}

#[derive(Debug)]
pub struct CountRollupSql {
    pub sql: String,
    pub params: Vec<(String, String)>,
    pub bytes: u64,
    pub parts: usize,
    /// Parts this plan reads directly from object storage (cache misses).
    pub remote_parts: usize,
    /// Cache pins for every tiered part this plan resolved locally. Held for
    /// the life of the plan so eviction cannot unlink a file the engine has
    /// not opened yet. Callers keep the plan alive until execution finishes.
    pub pins: Vec<PinnedArtifact>,
}

/// One verified, locally leased rollup partial of a part (NAN-2869).
#[derive(Clone, Debug)]
pub struct LocalRollupPartial {
    pub path: PathBuf,
    /// Inclusive bucket bounds the partial can hold (from the part's event
    /// time bounds; conservative is fine, the SQL fences buckets exactly).
    pub min_bucket_start_us: i64,
    pub max_bucket_start_us: i64,
    pub bytes: u64,
}

impl CountRollup {
    /// A rollup over part partials (contract 3.2: the same
    /// `nano-ocsf-5m-count-v5` rows), so [`Self::plan`] is reused unchanged.
    pub fn from_local_partials(partials: Vec<LocalRollupPartial>) -> Self {
        Self {
            event_snapshot_id: 0,
            fields: COUNT_ROLLUP_FIELDS
                .iter()
                .map(|field| (field.source_path.to_string(), (field.field_id, field.multi_value)))
                .collect(),
            parts: partials
                .into_iter()
                .map(|partial| LoadedPart {
                    location: PartLocation::Local(partial.path),
                    min_bucket_start_us: partial.min_bucket_start_us,
                    max_bucket_start_us: partial.max_bucket_start_us,
                    bytes: partial.bytes,
                })
                .collect(),
            tier: None,
        }
    }

    pub fn load(
        configured: LoadedCountRollupConfig,
        expected_tenant_id: &str,
        expected_snapshot_id: i64,
        expected_object_stamp_sha256: &str,
    ) -> Result<Self> {
        Self::load_tiered(
            configured,
            expected_tenant_id,
            expected_snapshot_id,
            expected_object_stamp_sha256,
            None,
        )
    }

    /// Load a rollup whose parts may be tiered to object storage. Without a
    /// tier this is byte-for-byte the strict local load: every part must be
    /// present and pass its digest fence. With a tier, a part that is absent
    /// locally is recorded as a remote artifact addressed by the sha256 in
    /// this digest-fenced manifest; anything present locally must still pass
    /// the full local fence — a corrupt local file is a fault, not a miss.
    pub fn load_tiered(
        configured: LoadedCountRollupConfig,
        expected_tenant_id: &str,
        expected_snapshot_id: i64,
        expected_object_stamp_sha256: &str,
        tier: Option<Arc<DerivativeTier>>,
    ) -> Result<Self> {
        Self::load_tiered_proven(configured, expected_tenant_id, expected_snapshot_id, expected_object_stamp_sha256, tier, None)
    }

    pub fn load_tiered_proven(
        configured: LoadedCountRollupConfig,
        expected_tenant_id: &str,
        expected_snapshot_id: i64,
        expected_object_stamp_sha256: &str,
        tier: Option<Arc<DerivativeTier>>,
        proof: Option<&crate::generation_proof::Body>,
    ) -> Result<Self> {
        let manifest: CountRollupManifest = serde_json::from_slice(
            &std::fs::read(&configured.manifest)
                .with_context(|| format!("read {}", configured.manifest.display()))?,
        )?;
        if manifest.schema_version != 1
            || !matches!(
                manifest.rollup_version.as_str(),
                COUNT_ROLLUP_VERSION | LEGACY_COUNT_ROLLUP_VERSION
            )
            || manifest.tenant_id != expected_tenant_id
            || manifest.event_snapshot_id != expected_snapshot_id
            || manifest.object_stamp_sha256 != expected_object_stamp_sha256
            || manifest.bucket_width_us != COUNT_ROLLUP_BUCKET_US
            || manifest.objects.is_empty()
            || (manifest.rollup_version == COUNT_ROLLUP_VERSION
                && manifest.reused_objects + manifest.built_objects != manifest.objects.len())
        {
            bail!("count rollup differs from the assigned immutable event generation");
        }
        let expected_fields = COUNT_ROLLUP_FIELDS
            .iter()
            .map(|field| {
                (
                    field.source_path.to_string(),
                    (field.field_id, field.multi_value),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let manifest_fields = manifest
            .fields
            .iter()
            .map(|field| {
                (
                    field.source_path.clone(),
                    (field.field_id, field.multi_value),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if manifest_fields != expected_fields || manifest.fields.len() != expected_fields.len() {
            bail!("count rollup field contract is incomplete or ambiguous");
        }

        let mut seen = BTreeSet::new();
        let mut parts = Vec::with_capacity(manifest.objects.len());
        let mut rows = 0_u64;
        let mut bytes = 0_u64;
        let mut local_fence = crate::verify::VerificationPlan::new();
        let version = manifest.rollup_version.clone();
        for (position, object) in manifest.objects.into_iter().enumerate() {
            if object.relative_path.is_empty()
                || object.relative_path.contains('/')
                || object.relative_path.contains("..")
                || object.min_bucket_start_us > object.max_bucket_start_us
                || object.rows == 0
                || object.bytes == 0
                || !seen.insert(object.relative_path.clone())
                || (version == COUNT_ROLLUP_VERSION
                    && (object.object_id as usize != position
                        || object.relative_path != format!("object-{position:04}.parquet")
                        || !object.event_object_key.starts_with("s3://")
                        || object.event_object_version.is_empty()
                        || object.event_object_bytes == 0))
            {
                bail!("count rollup manifest contains an invalid part");
            }
            let path = configured.data_directory.join(&object.relative_path);
            let location = match std::fs::metadata(&path) {
                Ok(metadata) => {
                    if metadata.len() != object.bytes {
                        bail!("count rollup part failed its immutable manifest fence");
                    }
                    // NAN-2361: the digest fence of every local part is
                    // deferred to one bounded-parallel batch below instead
                    // of one serial stream per part (this is the SECOND
                    // read of the rollup on an untiered boot -- the
                    // whole-tree digest in config.rs was the first).
                    if !proof.is_some_and(|proof| proof.file_digest(&path) == Some(object.sha256.as_str())) {
                        local_fence.file(&VerifiedArtifact { path: path.clone(), sha256: object.sha256.clone() });
                    }
                    PartLocation::Local(path)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && tier.is_some() => {
                    PartLocation::Tiered(ArtifactRef::new(
                        "count-rollup",
                        &version,
                        &object.sha256,
                        object.bytes,
                    )?)
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("read count rollup part {}", path.display()));
                }
            };
            rows = rows
                .checked_add(object.rows)
                .context("count rollup row overflow")?;
            bytes = bytes
                .checked_add(object.bytes)
                .context("count rollup byte overflow")?;
            parts.push(LoadedPart {
                location,
                min_bucket_start_us: object.min_bucket_start_us,
                max_bucket_start_us: object.max_bucket_start_us,
                bytes: object.bytes,
            });
        }
        if rows != manifest.rows || bytes != manifest.bytes {
            bail!("count rollup totals differ from its immutable manifest");
        }
        if !local_fence.is_empty() {
            // All-or-nothing, same message as the serial fence: a corrupt
            // local part is a fault, never a miss, tiered or not.
            local_fence
                .run(crate::verify::verify_workers())
                .map_err(|error| match error {
                    crate::config::ConfigError::Invalid(_) => {
                        anyhow::anyhow!("count rollup part failed its immutable manifest fence")
                    }
                    other => anyhow::Error::new(other).context("read count rollup part"),
                })?;
        }
        Ok(Self {
            event_snapshot_id: manifest.event_snapshot_id,
            fields: expected_fields,
            parts,
            tier,
        })
    }

    pub fn event_snapshot_id(&self) -> i64 {
        self.event_snapshot_id
    }

    pub fn supports(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }

    pub fn is_multi_value(&self, field: &str) -> Option<bool> {
        self.fields.get(field).map(|(_, multi_value)| *multi_value)
    }

    pub fn plan(
        &self,
        tenant: &TenantQueryConfig,
        field: &str,
        group_results: bool,
        predicate: Option<&CountPredicate>,
        bucket_span_us: Option<i64>,
        start_us: i64,
        end_exclusive_us: i64,
        source_filter: Option<&str>,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<Vec<CountRollupSql>> {
        self.plan_inner(
            tenant,
            field,
            group_results,
            predicate,
            bucket_span_us,
            start_us,
            end_exclusive_us,
            source_filter,
            deny_source_types,
            false,
            false,
        )
    }

    /// [`Self::plan`] that can group by the row's log source instead of the
    /// field's value (NAN-3153): `F=v | stats count by metadata.log_source`.
    #[allow(clippy::too_many_arguments)]
    pub fn plan_with_source_groups(
        &self,
        tenant: &TenantQueryConfig,
        field: &str,
        group_results: bool,
        group_by_source: bool,
        predicate: Option<&CountPredicate>,
        bucket_span_us: Option<i64>,
        start_us: i64,
        end_exclusive_us: i64,
        source_filter: Option<&str>,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<Vec<CountRollupSql>> {
        self.plan_inner(
            tenant,
            field,
            group_results,
            predicate,
            bucket_span_us,
            start_us,
            end_exclusive_us,
            source_filter,
            deny_source_types,
            false,
            group_by_source,
        )
    }

    /// [`Self::plan`] kept apart per rollup file (NAN-3093): every row also
    /// carries `part_path` (the file's `_path`) and its own 5-minute
    /// `bucket_start_us`, so a caller can memoize each immutable part's
    /// answer and merge any window or span from it. Local partials only.
    pub fn plan_by_part(
        &self,
        tenant: &TenantQueryConfig,
        field: &str,
        group_results: bool,
        predicate: Option<&CountPredicate>,
        start_us: i64,
        end_exclusive_us: i64,
        source_filter: Option<&str>,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<Vec<CountRollupSql>> {
        self.plan_by_part_with_source_groups(
            tenant,
            field,
            group_results,
            false,
            predicate,
            start_us,
            end_exclusive_us,
            source_filter,
            deny_source_types,
        )
    }

    /// [`Self::plan_by_part`] with [`Self::plan_with_source_groups`]'s grouping.
    #[allow(clippy::too_many_arguments)]
    pub fn plan_by_part_with_source_groups(
        &self,
        tenant: &TenantQueryConfig,
        field: &str,
        group_results: bool,
        group_by_source: bool,
        predicate: Option<&CountPredicate>,
        start_us: i64,
        end_exclusive_us: i64,
        source_filter: Option<&str>,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<Vec<CountRollupSql>> {
        self.plan_inner(
            tenant,
            field,
            group_results,
            predicate,
            Some(COUNT_ROLLUP_BUCKET_US),
            start_us,
            end_exclusive_us,
            source_filter,
            deny_source_types,
            true,
            group_by_source,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn plan_inner(
        &self,
        tenant: &TenantQueryConfig,
        field: &str,
        group_results: bool,
        predicate: Option<&CountPredicate>,
        bucket_span_us: Option<i64>,
        start_us: i64,
        end_exclusive_us: i64,
        source_filter: Option<&str>,
        deny_source_types: &BTreeSet<String>,
        by_part: bool,
        group_by_source: bool,
    ) -> Result<Vec<CountRollupSql>> {
        let (field_id, multi_value) = self
            .fields
            .get(field)
            .copied()
            .context("count rollup does not cover the requested field")?;
        if start_us >= end_exclusive_us
            || start_us.rem_euclid(COUNT_ROLLUP_BUCKET_US) != 0
            || end_exclusive_us.rem_euclid(COUNT_ROLLUP_BUCKET_US) != 0
            || source_filter.is_some_and(|source| source.is_empty() || source.len() > 512)
            || deny_source_types
                .iter()
                .any(|source| source.is_empty() || source.len() > 512)
            || bucket_span_us.is_some_and(|span| {
                span < COUNT_ROLLUP_BUCKET_US
                    || span % COUNT_ROLLUP_BUCKET_US != 0
                    || span > 31_622_400_000_000
            })
            || (multi_value
                && (group_results
                    || predicate.is_none_or(|predicate| predicate.kind != CountPredicateKind::Eq)))
            || (group_by_source
                && (group_results
                    || field_id == 0
                    || field == DASHBOARD_BREAKDOWN_FIELD))
        {
            bail!("count rollup request violates its bucket, source, or scope contract");
        }
        let selected = self
            .parts
            .iter()
            .filter(|part| {
                part.max_bucket_start_us >= start_us && part.min_bucket_start_us < end_exclusive_us
            })
            .collect::<Vec<_>>();
        let mut plans = Vec::new();
        for (chunk_index, chunk) in selected.chunks(MAX_PARTS_PER_QUERY).enumerate() {
            let mut params = vec![
                ("rollup_field_id".to_string(), field_id.to_string()),
                ("rollup_start_us".to_string(), start_us.to_string()),
                ("rollup_end_us".to_string(), end_exclusive_us.to_string()),
            ];
            let mut local_paths = Vec::with_capacity(chunk.len());
            let mut cached_paths = Vec::new();
            let mut remote_urls = Vec::new();
            let mut pins = Vec::new();
            let mut chunk_bytes = 0_u64;
            for part in chunk {
                match &part.location {
                    PartLocation::Local(path) => local_paths.push(path.clone()),
                    PartLocation::Tiered(artifact) => {
                        let tier = self.tier.as_ref().context(
                            "count rollup holds a tiered part without a configured tier",
                        )?;
                        if let Some(pin) = tier.pin(artifact) {
                            cached_paths.push(pin.path().to_path_buf());
                            pins.push(pin);
                        } else {
                            // Cache miss: read this part straight from object
                            // storage and hydrate in the background. The read
                            // never waits on hydration.
                            remote_urls.push(tier.remote_url(artifact));
                            tier.begin_hydration(artifact.clone());
                        }
                    }
                }
                chunk_bytes = chunk_bytes
                    .checked_add(part.bytes)
                    .context("count rollup query byte overflow")?;
            }
            if chunk_bytes > tenant.max_query_bytes {
                bail!("count rollup part set exceeds the trusted tenant query budget");
            }
            let remote_parts = remote_urls.len();
            let mut sources = Vec::new();
            if !local_paths.is_empty() {
                let name = format!("rollup_source_{chunk_index}");
                params.push((name.clone(), path_set(&local_paths)?));
                sources.push(format!("file({{{name}:String}}, Parquet)"));
            }
            if !cached_paths.is_empty() {
                let name = format!("rollup_cache_source_{chunk_index}");
                params.push((name.clone(), path_set(&cached_paths)?));
                sources.push(format!("file({{{name}:String}}, Parquet)"));
            }
            if !remote_urls.is_empty() {
                let name = format!("rollup_remote_source_{chunk_index}");
                params.push((name.clone(), url_set(&remote_urls)?));
                let arguments = match &tenant.credentials {
                    ObjectStoreCredentials::DefaultChain => format!("{{{name}:String}}"),
                    ObjectStoreCredentials::Static {
                        access_key,
                        secret_key,
                        session_token,
                    } => {
                        params.push(("rollup_tier_access_key".to_string(), access_key.clone()));
                        params.push(("rollup_tier_secret_key".to_string(), secret_key.clone()));
                        if let Some(token) = session_token {
                            params.push(("rollup_tier_session_token".to_string(), token.clone()));
                            format!(
                                "{{{name}:String}}, {{rollup_tier_access_key:String}}, {{rollup_tier_secret_key:String}}, {{rollup_tier_session_token:String}}"
                            )
                        } else {
                            format!(
                                "{{{name}:String}}, {{rollup_tier_access_key:String}}, {{rollup_tier_secret_key:String}}"
                            )
                        }
                    }
                };
                sources.push(format!("s3({arguments}, Parquet)"));
            }
            if by_part && (sources.len() != 1 || !cached_paths.is_empty() || remote_parts != 0) {
                bail!("a per-part count rollup reads local partials only");
            }
            let source = match sources.len() {
                0 => bail!("count rollup chunk resolved to no readable source"),
                1 => sources.remove(0),
                _ => format!(
                    "({})",
                    sources
                        .iter()
                        .map(|source| {
                            format!(
                                "SELECT bucket_start_us, field_id, source_type, value, events FROM {source}"
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" UNION ALL ")
                ),
            };
            let mut predicates = vec![
                "_nano_rollup.field_id = {rollup_field_id:UInt16}".to_string(),
                "_nano_rollup.bucket_start_us >= {rollup_start_us:Int64}".to_string(),
                "_nano_rollup.bucket_start_us < {rollup_end_us:Int64}".to_string(),
            ];
            if let Some(source) = source_filter {
                predicates.push(
                    "lower(_nano_rollup.source_type) = lower({rollup_source:String})".to_string(),
                );
                params.push(("rollup_source".to_string(), source.to_string()));
            }
            for (index, source) in deny_source_types.iter().enumerate() {
                let name = format!("rollup_deny_source_{index}");
                predicates.push(format!(
                    "lower(_nano_rollup.source_type) != lower({{{name}:String}})"
                ));
                params.push((name, source.clone()));
            }
            append_count_predicate(
                &mut predicates,
                &mut params,
                "_nano_rollup.value",
                predicate,
                "rollup_count_predicate",
                false,
            )?;
            let mut projections = Vec::new();
            let mut groupings = Vec::new();
            if by_part {
                projections.push("_path AS part_path".to_string());
                groupings.push("part_path");
            }
            if let Some(span) = bucket_span_us {
                projections.push(format!(
                    "intDiv(_nano_rollup.bucket_start_us, {span}) * {span} AS bucket_start_us"
                ));
                groupings.push("bucket_start_us");
            }
            if group_by_source {
                // The row's first non-blank log source; '' means none, which
                // a raw fragment reports as NULL (`count_source_group_expression`).
                projections.push(
                    "nullIf(_nano_rollup.source_type, '') AS value".to_string(),
                );
                groupings.push("value");
            } else if group_results {
                projections.push("_nano_rollup.value AS value".to_string());
                groupings.push("value");
            } else {
                projections.push("CAST(NULL AS Nullable(String)) AS value".to_string());
            }
            let grouping = if groupings.is_empty() {
                String::new()
            } else {
                format!(" GROUP BY {}", groupings.join(", "))
            };
            let sql = format!(
                "SELECT {}, toUInt64(sum(_nano_rollup.events)) AS events FROM {} AS _nano_rollup WHERE {}{grouping} SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, max_memory_usage={}, use_query_cache=0",
                projections.join(", "),
                source,
                predicates.join(" AND "),
                tenant.threads,
                tenant.max_execution_seconds,
                tenant.max_query_bytes,
                tenant.max_memory_bytes,
            );
            plans.push(CountRollupSql {
                sql,
                params,
                bytes: chunk_bytes,
                parts: chunk.len(),
                remote_parts,
                pins,
            });
        }
        Ok(plans)
    }
}

fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .context("count rollup path is not UTF-8")
}

/// One bounded object-storage source naming an exact remote artifact set,
/// mirroring [`path_set`]: a single URL, or `prefix/{a,b}` when every URL
/// shares one immutable content-addressed directory.
fn url_set(urls: &[String]) -> Result<String> {
    let Some(first) = urls.first() else {
        bail!("count rollup remote url set is empty");
    };
    if urls.len() == 1 {
        return Ok(first.clone());
    }
    let (prefix, _) = first
        .rsplit_once('/')
        .context("count rollup remote url has no directory")?;
    let mut names = Vec::with_capacity(urls.len());
    for url in urls {
        let (parent, name) = url
            .rsplit_once('/')
            .context("count rollup remote url has no directory")?;
        if parent != prefix {
            bail!("count rollup remote urls do not share one immutable prefix");
        }
        if name.is_empty() || name.contains([',', '{', '}']) {
            bail!("count rollup remote url is unsafe for a bounded object set");
        }
        names.push(name);
    }
    Ok(format!("{prefix}/{{{}}}", names.join(",")))
}

fn path_set(paths: &[PathBuf]) -> Result<String> {
    let Some(first) = paths.first() else {
        bail!("count rollup path set is empty");
    };
    if paths.len() == 1 {
        return path_string(first);
    }
    let parent = first.parent().context("count rollup part has no parent")?;
    if paths.iter().any(|path| path.parent() != Some(parent)) {
        // NAN-2869: part partials live in one directory per part. Name them
        // under their common root instead (the planner's bounded brace set).
        let mut strings = paths.iter().map(|path| path_string(path)).collect::<Result<Vec<_>>>()?;
        return crate::planner::local_path_spec(&mut strings).map_err(|error| anyhow::anyhow!(error.to_string()));
    }
    let mut names = Vec::with_capacity(paths.len());
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("count rollup filename is not UTF-8")?;
        if name.contains([',', '{', '}']) {
            bail!("count rollup filename is unsafe for a bounded file set");
        }
        names.push(name);
    }
    Ok(format!("{}/{{{}}}", parent.display(), names.join(",")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivative_tier::RemoteArtifactStore;
    use sha2::{Digest, Sha256};

    /// NAN-3093: search plans rollup reads from its own mirror of this
    /// contract (`nanosiem_core::search::LAKE_COUNT_ROLLUP_FIELDS`); it must
    /// name exactly these fields, in order, with the same multi-value flags.
    #[test]
    fn search_mirrors_the_count_rollup_field_contract_exactly() {
        let worker = COUNT_ROLLUP_FIELDS
            .iter()
            .map(|field| (field.source_path, field.multi_value))
            .collect::<Vec<_>>();
        assert_eq!(nanosiem_core::search::LAKE_COUNT_ROLLUP_FIELDS, worker.as_slice());
    }

    /// `plan_by_part` keeps every file's rows apart at the rollup bucket.
    #[test]
    fn per_part_plan_groups_by_file_and_raw_bucket() {
        let rollup = CountRollup::from_local_partials(vec![LocalRollupPartial {
            path: PathBuf::from("/cache/objects/a.parquet"),
            min_bucket_start_us: 0,
            max_bucket_start_us: COUNT_ROLLUP_BUCKET_US,
            bytes: 10,
        }]);
        let plans = rollup
            .plan_by_part(
                &test_tenant(),
                "src_endpoint.hostname",
                true,
                None,
                0,
                2 * COUNT_ROLLUP_BUCKET_US,
                Some("windows_sysmon"),
                &BTreeSet::new(),
            )
            .unwrap();
        assert_eq!(plans.len(), 1);
        let sql = &plans[0].sql;
        assert!(sql.contains("_path AS part_path"), "{sql}");
        assert!(sql.contains("GROUP BY part_path, bucket_start_us, value"), "{sql}");
        assert!(sql.contains(&format!("intDiv(_nano_rollup.bucket_start_us, {COUNT_ROLLUP_BUCKET_US})")), "{sql}");
        // The merged plan is unchanged.
        let merged = rollup
            .plan(&test_tenant(), "src_endpoint.hostname", true, None, None, 0, 2 * COUNT_ROLLUP_BUCKET_US, None, &BTreeSet::new())
            .unwrap();
        assert!(!merged[0].sql.contains("_path"), "{}", merged[0].sql);
    }

    fn test_tenant() -> TenantQueryConfig {
        TenantQueryConfig {
            tenant_id: "tenant-a".to_string(),
            source: "s3://bucket/table".to_string(),
            iceberg_metadata_file_path: "metadata/v1.json".to_string(),
            max_query_bytes: 1_000_000,
            max_memory_bytes: crate::planner::DEFAULT_QUERY_MEMORY_BYTES,
            max_execution_seconds: 30,
            threads: 4,
            credentials: ObjectStoreCredentials::Static {
                access_key: "tier-access".to_string(),
                secret_key: "tier-secret".to_string(),
                session_token: None,
            },
            snapshot_cache: None,
        }
    }

    struct MapStore(BTreeMap<String, Vec<u8>>);

    impl RemoteArtifactStore for MapStore {
        fn get(&self, key: &str) -> Result<Vec<u8>> {
            self.0
                .get(key)
                .cloned()
                .with_context(|| format!("missing remote artifact {key}"))
        }
    }

    struct TieredFixture {
        _directory: tempfile::TempDir,
        manifest_path: PathBuf,
        data_directory: PathBuf,
        cache_directory: PathBuf,
        local_bytes: Vec<u8>,
        remote_bytes: Vec<u8>,
        remote_sha256: String,
        remote_key: String,
        stamp_sha256: String,
    }

    /// Two-part rollup generation: part 0 present locally and digest-fenced,
    /// part 1 absent locally with its bytes living only in object storage.
    fn tiered_fixture() -> TieredFixture {
        let directory = tempfile::TempDir::new().unwrap();
        let data_directory = directory.path().join("count-rollup");
        std::fs::create_dir(&data_directory).unwrap();
        let cache_directory = directory.path().join("tier-cache");
        let local_bytes = b"local-part-parquet-bytes".to_vec();
        let remote_bytes = b"remote-part-parquet-bytes".to_vec();
        std::fs::write(data_directory.join("object-0000.parquet"), &local_bytes).unwrap();
        let sha = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
        let remote_sha256 = sha(&remote_bytes);
        let stamp_sha256 = sha(b"stamp");
        let object = |id: u32, bytes: &[u8]| CountRollupObject {
            object_id: id,
            event_object_key: format!("s3://bucket/table/data/event_hour=496346/{id}.parquet"),
            event_object_version: "v1".to_string(),
            event_object_bytes: 10,
            relative_path: format!("object-{id:04}.parquet"),
            min_bucket_start_us: 0,
            max_bucket_start_us: COUNT_ROLLUP_BUCKET_US,
            rows: 1,
            bytes: bytes.len() as u64,
            sha256: sha(bytes),
        };
        let manifest = CountRollupManifest {
            schema_version: 1,
            rollup_version: COUNT_ROLLUP_VERSION.to_string(),
            tenant_id: "tenant-a".to_string(),
            event_snapshot_id: 7,
            object_stamp_sha256: stamp_sha256.clone(),
            bucket_width_us: COUNT_ROLLUP_BUCKET_US,
            fields: COUNT_ROLLUP_FIELDS
                .iter()
                .map(|field| CountRollupManifestField {
                    field_id: field.field_id,
                    source_path: field.source_path.to_string(),
                    multi_value: field.multi_value,
                })
                .collect(),
            objects: vec![object(0, &local_bytes), object(1, &remote_bytes)],
            rows: 2,
            bytes: (local_bytes.len() + remote_bytes.len()) as u64,
            build_seconds: 0.0,
            reused_objects: 0,
            built_objects: 2,
        };
        let manifest_path = data_directory.join("manifest.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        TieredFixture {
            manifest_path,
            data_directory,
            cache_directory,
            local_bytes,
            remote_key: format!(
                "count-rollup/{COUNT_ROLLUP_VERSION}/sha256/{remote_sha256}.parquet"
            ),
            remote_sha256,
            remote_bytes,
            stamp_sha256,
            _directory: directory,
        }
    }

    impl TieredFixture {
        fn config(&self) -> LoadedCountRollupConfig {
            LoadedCountRollupConfig {
                manifest: self.manifest_path.clone(),
                data_directory: self.data_directory.clone(),
            }
        }
    }

    const TIER_ROOT: &str = "http://object-store:9000/nano-lake/derivatives/tenant-a";

    fn tier_with_store(
        fixture: &TieredFixture,
        store: MapStore,
        max_cache_bytes: u64,
    ) -> Arc<DerivativeTier> {
        DerivativeTier::new(
            TIER_ROOT,
            &fixture.cache_directory,
            max_cache_bytes,
            Arc::new(store),
        )
        .unwrap()
    }

    #[test]
    fn missing_part_without_tier_still_fails_the_strict_local_load() {
        let fixture = tiered_fixture();
        let error = CountRollup::load(fixture.config(), "tenant-a", 7, &fixture.stamp_sha256)
            .unwrap_err();
        assert!(error.to_string().contains("object-0001.parquet"));
    }

    #[test]
    fn local_miss_is_planned_as_a_remote_read_and_admitted_after_hydration() {
        let fixture = tiered_fixture();
        let store = MapStore(BTreeMap::from([(
            fixture.remote_key.clone(),
            fixture.remote_bytes.clone(),
        )]));
        let tier = tier_with_store(&fixture, store, 1_000_000);
        let rollup = CountRollup::load_tiered(
            fixture.config(),
            "tenant-a",
            7,
            &fixture.stamp_sha256,
            Some(tier.clone()),
        )
        .unwrap();
        let tenant = test_tenant();
        let plan = |rollup: &CountRollup| {
            let mut plans = rollup
                .plan(
                    &tenant,
                    "process.name",
                    true,
                    None,
                    None,
                    0,
                    COUNT_ROLLUP_BUCKET_US * 2,
                    None,
                    &BTreeSet::new(),
                )
                .unwrap();
            assert_eq!(plans.len(), 1);
            plans.remove(0)
        };

        // Cold: the absent part must be READ, not dropped — a direct
        // object-storage source alongside the local file source.
        let cold = plan(&rollup);
        assert_eq!(cold.parts, 2);
        assert_eq!(cold.remote_parts, 1);
        assert!(cold.sql.contains("UNION ALL"));
        assert!(cold.sql.contains("s3({rollup_remote_source_0:String}"));
        assert!(cold.sql.contains("file({rollup_source_0:String}"));
        let remote_url = cold
            .params
            .iter()
            .find(|(name, _)| name == "rollup_remote_source_0")
            .map(|(_, value)| value.clone())
            .unwrap();
        assert_eq!(remote_url, format!("{TIER_ROOT}/{}", fixture.remote_key));
        assert!(
            cold.params
                .iter()
                .any(|(name, value)| name == "rollup_tier_access_key" && value == "tier-access")
        );

        // Hydration was started by the cold plan and never blocked it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while tier.admitted_count() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "hydration did not admit the artifact"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Warm: the same request is now served locally from the cache, the
        // cached bytes are exactly the fenced originals, and the plan pins
        // the cache entry for its own lifetime.
        let warm = plan(&rollup);
        assert_eq!(warm.remote_parts, 0);
        assert!(!warm.sql.contains("s3("));
        assert!(warm.sql.contains("file({rollup_source_0:String}"));
        assert!(warm.sql.contains("file({rollup_cache_source_0:String}"));
        assert_eq!(warm.pins.len(), 1);
        let cached = std::fs::read(warm.pins[0].path()).unwrap();
        assert_eq!(cached, fixture.remote_bytes);
        assert_ne!(cached, fixture.local_bytes);
    }

    #[test]
    fn remote_artifact_with_a_wrong_digest_is_rejected_not_served() {
        let fixture = tiered_fixture();
        // The store serves TAMPERED bytes under the correct content address.
        let store = MapStore(BTreeMap::from([(
            fixture.remote_key.clone(),
            b"remote-part-parquet-bytEs".to_vec(),
        )]));
        let tier = tier_with_store(&fixture, store, 1_000_000);
        let artifact = crate::derivative_tier::ArtifactRef::new(
            "count-rollup",
            COUNT_ROLLUP_VERSION,
            &fixture.remote_sha256,
            fixture.remote_bytes.len() as u64,
        )
        .unwrap();
        let error = tier.hydrate_blocking(&artifact).unwrap_err();
        assert!(error.to_string().contains("digest fence"));
        // Nothing was admitted: no pin, no cache file, zero cached bytes.
        assert!(tier.pin(&artifact).is_none());
        assert_eq!(tier.cached_bytes(), 0);
        let residue = std::fs::read_dir(&fixture.cache_directory)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "parquet"))
            .count();
        assert_eq!(residue, 0);
        // A rollup over this tier keeps serving the part from object storage.
        let rollup = CountRollup::load_tiered(
            fixture.config(),
            "tenant-a",
            7,
            &fixture.stamp_sha256,
            Some(tier.clone()),
        )
        .unwrap();
        let plans = rollup
            .plan(
                &test_tenant(),
                "process.name",
                true,
                None,
                None,
                0,
                COUNT_ROLLUP_BUCKET_US * 2,
                None,
                &BTreeSet::new(),
            )
            .unwrap();
        assert_eq!(plans[0].remote_parts, 1);
        assert!(plans[0].sql.contains("s3("));
    }

    #[test]
    fn eviction_never_unlinks_an_artifact_pinned_by_an_in_flight_plan() {
        let fixture = tiered_fixture();
        let second_bytes = b"a-second-remote-artifact-that-overflows-the-budget".to_vec();
        let second_sha256 = hex::encode(Sha256::digest(&second_bytes));
        let second_key =
            format!("count-rollup/{COUNT_ROLLUP_VERSION}/sha256/{second_sha256}.parquet");
        let store = MapStore(BTreeMap::from([
            (fixture.remote_key.clone(), fixture.remote_bytes.clone()),
            (second_key, second_bytes.clone()),
        ]));
        // Budget fits ONE artifact: admitting the second forces eviction.
        let tier = tier_with_store(&fixture, store, fixture.remote_bytes.len() as u64);
        let first = crate::derivative_tier::ArtifactRef::new(
            "count-rollup",
            COUNT_ROLLUP_VERSION,
            &fixture.remote_sha256,
            fixture.remote_bytes.len() as u64,
        )
        .unwrap();
        let second = crate::derivative_tier::ArtifactRef::new(
            "count-rollup",
            COUNT_ROLLUP_VERSION,
            &second_sha256,
            second_bytes.len() as u64,
        )
        .unwrap();
        tier.hydrate_blocking(&first).unwrap();
        let pin = tier.pin(&first).expect("first artifact is cached");
        // In-flight plan holds the pin; over-budget admission must not evict it.
        tier.hydrate_blocking(&second).unwrap();
        assert_eq!(
            std::fs::read(pin.path()).unwrap(),
            fixture.remote_bytes,
            "pinned artifact was unlinked or altered under an in-flight plan"
        );
        // The plan finished: drop the pin and force the next eviction pass.
        drop(pin);
        tier.hydrate_blocking(&second).unwrap();
        assert!(
            tier.pin(&first).is_none(),
            "unpinned over-budget artifact should be evicted"
        );
    }
    use crate::planner::ObjectStoreCredentials;

    #[test]
    fn supported_fields_are_unique() {
        let ids = COUNT_ROLLUP_FIELDS
            .iter()
            .map(|field| field.field_id)
            .collect::<BTreeSet<_>>();
        let paths = COUNT_ROLLUP_FIELDS
            .iter()
            .map(|field| field.source_path)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), COUNT_ROLLUP_FIELDS.len());
        assert_eq!(paths.len(), COUNT_ROLLUP_FIELDS.len());
    }

    #[test]
    fn ungrouped_rollup_predicates_are_qualified_against_the_source_alias() {
        let rollup = CountRollup {
            event_snapshot_id: 1,
            fields: BTreeMap::from([("process.name".to_string(), (1, false))]),
            parts: vec![LoadedPart {
                location: PartLocation::Local(PathBuf::from("/cache/count.parquet")),
                min_bucket_start_us: 0,
                max_bucket_start_us: COUNT_ROLLUP_BUCKET_US,
                bytes: 100,
            }],
            tier: None,
        };
        let tenant = TenantQueryConfig {
            tenant_id: "tenant-a".to_string(),
            source: "s3://bucket/table".to_string(),
            iceberg_metadata_file_path: "metadata/v1.json".to_string(),
            max_query_bytes: 1_000,
            max_memory_bytes: crate::planner::DEFAULT_QUERY_MEMORY_BYTES,
            max_execution_seconds: 30,
            threads: 4,
            credentials: ObjectStoreCredentials::DefaultChain,
            snapshot_cache: None,
        };
        let predicate = CountPredicate {
            kind: CountPredicateKind::Eq,
            values: vec!["ngen.exe".to_string()],
        };
        let plans = rollup
            .plan(
                &tenant,
                "process.name",
                false,
                Some(&predicate),
                None,
                0,
                COUNT_ROLLUP_BUCKET_US * 2,
                None,
                &BTreeSet::new(),
            )
            .unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].params.len(), 5);
        assert_eq!(plans[0].parts, 1);
        assert!(plans[0].sql.contains("lower(toString(_nano_rollup.value))"));
        assert!(!plans[0].sql.contains("lower(toString(value))"));
        assert!(plans[0].sql.contains("sum(_nano_rollup.events)"));
        assert!(plans[0].sql.contains("FROM file("));
        assert!(!plans[0].sql.contains("FROM (file("));
    }

    /// NAN-3153: `F=v | stats count by metadata.log_source` reads field F's
    /// rows, filters their value and groups by the row's source key.
    #[test]
    fn source_grouped_rollup_filters_the_field_and_groups_by_source() {
        let rollup = CountRollup {
            event_snapshot_id: 1,
            fields: BTreeMap::from([
                ("metadata.log_source".to_string(), (0, false)),
                ("device.hostname".to_string(), (5, false)),
                ("file.hashes.value".to_string(), (34, true)),
            ]),
            parts: vec![LoadedPart {
                location: PartLocation::Local(PathBuf::from("/cache/count.parquet")),
                min_bucket_start_us: 0,
                max_bucket_start_us: COUNT_ROLLUP_BUCKET_US,
                bytes: 100,
            }],
            tier: None,
        };
        let tenant = TenantQueryConfig {
            tenant_id: "tenant-a".to_string(),
            source: "s3://bucket/table".to_string(),
            iceberg_metadata_file_path: "metadata/v1.json".to_string(),
            max_query_bytes: 1_000,
            max_memory_bytes: crate::planner::DEFAULT_QUERY_MEMORY_BYTES,
            max_execution_seconds: 30,
            threads: 4,
            credentials: ObjectStoreCredentials::DefaultChain,
            snapshot_cache: None,
        };
        let host = CountPredicate { kind: CountPredicateKind::HostEq, values: vec!["ws-1".into()] };
        let plan = |field: &str, group_results: bool, predicate: &CountPredicate| {
            rollup.plan_by_part_with_source_groups(
                &tenant, field, group_results, true, Some(predicate), 0, COUNT_ROLLUP_BUCKET_US * 2, None, &BTreeSet::new(),
            )
        };
        let plans = plan("device.hostname", false, &host).unwrap();
        assert_eq!(plans.len(), 1);
        let sql = &plans[0].sql;
        assert!(sql.contains("nullIf(_nano_rollup.source_type, '') AS value"), "{sql}");
        assert!(!sql.contains("_nano_rollup.value AS value"));
        assert!(sql.contains("startsWith(lower(toString(_nano_rollup.value))"), "{sql}");
        assert!(sql.contains("GROUP BY part_path, bucket_start_us, value"), "{sql}");
        assert!(plans[0].params.contains(&("rollup_field_id".to_string(), "5".to_string())));
        // Never combined with value groups, the source field itself, or a
        // multi-value field without exact membership.
        assert!(plan("device.hostname", true, &host).is_err());
        assert!(plan("metadata.log_source", false, &host).is_err());
        assert!(plan("file.hashes.value", false, &host).is_err());
        let eq = CountPredicate { kind: CountPredicateKind::Eq, values: vec!["abc".into()] };
        assert!(plan("file.hashes.value", false, &eq).is_ok());
    }

    /// NAN-3163: search now plans a scoped caller's rollups from the query
    /// without its injected source-scope gate, so the rollup SQL itself must
    /// drop every denied source (case-insensitively) from the counted rows,
    /// grouped by source or not.
    #[test]
    fn rollup_plans_exclude_every_denied_source() {
        let rollup = CountRollup {
            event_snapshot_id: 1,
            fields: BTreeMap::from([
                ("metadata.log_source".to_string(), (0, false)),
                ("device.hostname".to_string(), (5, false)),
            ]),
            parts: vec![LoadedPart {
                location: PartLocation::Local(PathBuf::from("/cache/count.parquet")),
                min_bucket_start_us: 0,
                max_bucket_start_us: COUNT_ROLLUP_BUCKET_US,
                bytes: 100,
            }],
            tier: None,
        };
        let tenant = TenantQueryConfig {
            tenant_id: "tenant-a".to_string(),
            source: "s3://bucket/table".to_string(),
            iceberg_metadata_file_path: "metadata/v1.json".to_string(),
            max_query_bytes: 1_000,
            max_memory_bytes: crate::planner::DEFAULT_QUERY_MEMORY_BYTES,
            max_execution_seconds: 30,
            threads: 4,
            credentials: ObjectStoreCredentials::DefaultChain,
            snapshot_cache: None,
        };
        let deny = BTreeSet::from(["audit".to_string(), "Windows_Security".to_string()]);
        let host = CountPredicate {
            kind: CountPredicateKind::Eq,
            values: vec!["ws-hr-132.corp.local".into()],
        };
        for group_by_source in [true, false] {
            let plans = rollup
                .plan_by_part_with_source_groups(
                    &tenant,
                    "device.hostname",
                    false,
                    group_by_source,
                    Some(&host),
                    0,
                    COUNT_ROLLUP_BUCKET_US * 2,
                    None,
                    &deny,
                )
                .unwrap();
            assert_eq!(plans.len(), 1);
            let sql = &plans[0].sql;
            for (index, source) in deny.iter().enumerate() {
                let name = format!("rollup_deny_source_{index}");
                assert!(
                    sql.contains(&format!(
                        "lower(_nano_rollup.source_type) != lower({{{name}:String}})"
                    )),
                    "{sql}"
                );
                assert!(
                    plans[0].params.contains(&(name, source.clone())),
                    "{:?}",
                    plans[0].params
                );
            }
            // The exclusions are conjuncts of the one WHERE, never ORed away.
            let filter = sql.split(" WHERE ").nth(1).unwrap();
            assert!(!filter.contains(" OR "), "{sql}");
        }
    }

    #[test]
    fn many_rollup_parts_use_one_bounded_file_source() {
        let directory = PathBuf::from("/cache/rollup");
        let rollup = CountRollup {
            event_snapshot_id: 1,
            fields: BTreeMap::from([("process.name".to_string(), (1, false))]),
            parts: (0..202)
                .map(|id| LoadedPart {
                    location: PartLocation::Local(
                        directory.join(format!("object-{id:04}.parquet")),
                    ),
                    min_bucket_start_us: 0,
                    max_bucket_start_us: COUNT_ROLLUP_BUCKET_US,
                    bytes: 10,
                })
                .collect(),
            tier: None,
        };
        let tenant = TenantQueryConfig {
            tenant_id: "tenant-a".to_string(),
            source: "s3://bucket/table".to_string(),
            iceberg_metadata_file_path: "metadata/v1.json".to_string(),
            max_query_bytes: 10_000,
            max_memory_bytes: crate::planner::DEFAULT_QUERY_MEMORY_BYTES,
            max_execution_seconds: 30,
            threads: 4,
            credentials: ObjectStoreCredentials::DefaultChain,
            snapshot_cache: None,
        };
        let plans = rollup
            .plan(
                &tenant,
                "process.name",
                true,
                None,
                None,
                0,
                COUNT_ROLLUP_BUCKET_US * 2,
                None,
                &BTreeSet::new(),
            )
            .unwrap();

        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].parts, 202);
        assert_eq!(plans[0].params.len(), 4);
        assert_eq!(plans[0].sql.matches("file(").count(), 1);
        let source = plans[0]
            .params
            .iter()
            .find(|(name, _)| name == "rollup_source_0")
            .map(|(_, value)| value)
            .unwrap();
        assert!(source.starts_with("/cache/rollup/{object-0000.parquet,"));
        assert!(source.ends_with("object-0201.parquet}"));
    }


    #[test]
    fn a_tampered_local_part_is_a_fault_not_a_miss_through_the_parallel_fence() {
        // NAN-2361: the per-part digest fence moved from one serial hash per
        // part to one bounded-parallel batch. The contract is unchanged: a
        // local part whose bytes differ from the sha-pinned manifest fails
        // the load with the same message, even with a tier that COULD have
        // served the part from object storage.
        let fixture = tiered_fixture();
        let store = MapStore(BTreeMap::from([(
            fixture.remote_key.clone(),
            fixture.remote_bytes.clone(),
        )]));
        let tier = tier_with_store(&fixture, store, 1_000_000);
        CountRollup::load_tiered(
            fixture.config(),
            "tenant-a",
            7,
            &fixture.stamp_sha256,
            Some(tier.clone()),
        )
        .expect("intact local part loads");
        // Same length, one flipped byte: only the digest can catch it.
        let mut tampered = fixture.local_bytes.clone();
        tampered[3] ^= 0x01;
        std::fs::write(fixture.data_directory.join("object-0000.parquet"), &tampered).unwrap();
        let error = CountRollup::load_tiered(
            fixture.config(),
            "tenant-a",
            7,
            &fixture.stamp_sha256,
            Some(tier),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("immutable manifest fence"),
            "unexpected error: {error:#}"
        );
    }
}
