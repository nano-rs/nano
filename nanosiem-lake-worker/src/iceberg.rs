// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rust-native OCSF event publication into an Apache Iceberg REST catalog.
//!
//! The product write path accepts only Nano's canonical OCSF 1.9 Signal and
//! API Activity outbox shapes. It deliberately does not carry the beta UDM or
//! `unmapped` compatibility upgrader: old rows are a one-time migration, while
//! every new product row must satisfy the pinned OCSF contract before it can be
//! written. Unknown physical leaves also fail closed so chDB never encounters
//! a sparse mixed-schema generation.

use anyhow::{bail, Context, Result};
use arrow_array::{
    Array, ArrayRef, BooleanArray, Int64Array, LargeStringArray, RecordBatch, StringArray,
    StringViewArray, StructArray, TimestampMicrosecondArray, TimestampMillisecondArray,
    TimestampNanosecondArray, TimestampSecondArray,
};
use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::{LineDelimitedWriter, ReaderBuilder};
use arrow_schema::{DataType, Field, Schema as ArrowSchema, TimeUnit};
use arrow_select::filter::filter_record_batch;
use chrono::{DateTime, Utc};
use iceberg::io::{
    S3_ACCESS_KEY_ID, S3_DISABLE_CONFIG_LOAD, S3_DISABLE_EC2_METADATA, S3_ENDPOINT,
    S3_PATH_STYLE_ACCESS, S3_REGION, S3_SECRET_ACCESS_KEY, S3_SESSION_TOKEN,
};
use iceberg::spec::{
    DataContentType, DataFile, DataFileBuilder, DataFileFormat, Literal, ManifestContentType,
    ManifestStatus, PartitionKey, Struct, Transform, Type, UnboundPartitionField,
    UnboundPartitionSpec,
};
use iceberg::table::Table;
use iceberg::transaction::{AddColumn, ApplyTransactionAction, Transaction};
use iceberg::writer::base_writer::data_file_writer::DataFileWriterBuilder;
use iceberg::writer::file_writer::location_generator::{
    DefaultFileNameGenerator, DefaultLocationGenerator,
};
use iceberg::writer::file_writer::rolling_writer::RollingFileWriterBuilder;
use iceberg::writer::file_writer::ParquetWriterBuilder;
use iceberg::writer::{IcebergWriter, IcebergWriterBuilder};
use iceberg::{Catalog, CatalogBuilder, TableCreation, TableIdent};
use iceberg_catalog_rest::{
    RestCatalog, RestCatalogBuilder, REST_CATALOG_PROP_URI, REST_CATALOG_PROP_WAREHOUSE,
};
use iceberg_storage_opendal::OpenDalStorageFactory;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

pub const OCSF_VERSION: &str = "1.9.0";
pub const OUTBOX_BATCH_PROPERTY: &str = "nano.outbox-batch-sha256";
/// Only snapshots carrying this explicit fence may become an indexed serving
/// generation. Bronze/outbox appends intentionally omit it and remain in the
/// bounded hot tail until compaction publishes a replacement snapshot.
pub const GENERATION_READY_PROPERTY: &str = "nano.generation-ready";
pub const GENERATION_READY_VALUE: &str = "true";
/// Whole-generation rewrites are a bounded migration/compaction primitive.
/// Steady-state large tenants compact independent hour partitions instead of
/// accumulating an entire tenant in memory.
pub const MAX_GENERATION_REWRITE_ROWS: usize = 1_000_000;
/// Upgrade-only ceiling for reconstructing the historical row-content digest
/// of a reservation made before deterministic input-bound reservations. New
/// compactions never use this buffer; old ones fail closed instead of turning
/// highly-compressible payloads into another unbounded resident allocation.
const LEGACY_COMPACTION_DIGEST_BYTES_CEILING: u64 = 4 * 1_024 * 1_024 * 1_024;

/// Build the exact chDB projection and logical path inventory for the current
/// Iceberg schema. Hot-tail publication uses this after every ledger revision:
/// Bronze admission has already committed any additive OCSF fields, so the
/// catalog is the single schema authority for both staged and product events.
pub fn table_read_contract(table: &Table) -> Result<(String, Vec<String>)> {
    let arrow = iceberg::arrow::schema_to_arrow_schema(table.metadata().current_schema().as_ref())?;
    let read_schema = clickhouse_read_schema(&arrow)?;
    let mut paths = Vec::new();
    for field in arrow.fields() {
        collect_arrow_paths(field.as_ref(), "", &mut paths)?;
    }
    paths.sort();
    paths.dedup();
    if paths.is_empty() || paths.len() > 100_000 {
        bail!("serving schema path inventory is empty or exceeds its bound");
    }
    Ok((read_schema, paths))
}

/// NAN-3366: leaf path -> type of the table's current schema, in the same
/// vocabulary a generation records per object (`generation::schema_leaf_types`).
/// The bootstrap generation has no object, so this is its field inventory.
pub fn table_field_types(table: &Table) -> Result<BTreeMap<String, String>> {
    let arrow = iceberg::arrow::schema_to_arrow_schema(table.metadata().current_schema().as_ref())?;
    let field_types = crate::generation::schema_leaf_types(&arrow);
    if field_types.is_empty() || field_types.len() > 100_000 {
        bail!("serving schema field inventory is empty or exceeds its bound");
    }
    Ok(field_types)
}

pub fn clickhouse_read_schema(schema: &ArrowSchema) -> Result<String> {
    if schema.fields().is_empty() || schema.fields().len() > 10_000 {
        bail!("serving snapshot schema is empty or exceeds its field bound");
    }
    schema
        .fields()
        .iter()
        .map(|field| {
            Ok(format!(
                "{} {}",
                clickhouse_identifier(field.name())?,
                clickhouse_field_type(field)?
            ))
        })
        .collect::<Result<Vec<_>>>()
        .map(|fields| fields.join(", "))
}

fn collect_arrow_paths(field: &Field, parent: &str, paths: &mut Vec<String>) -> Result<()> {
    let path = if parent.is_empty() {
        field.name().to_string()
    } else {
        format!("{parent}.{}", field.name())
    };
    if path.len() > 2_048 || path.chars().any(char::is_control) {
        bail!("serving schema contains an invalid field path");
    }
    collect_arrow_type_paths(field.data_type(), &path, paths)
}

fn collect_arrow_type_paths(
    data_type: &DataType,
    path: &str,
    paths: &mut Vec<String>,
) -> Result<()> {
    match data_type {
        DataType::Struct(fields) if !fields.is_empty() => {
            for field in fields {
                collect_arrow_paths(field.as_ref(), path, paths)?;
            }
        }
        DataType::List(child)
        | DataType::ListView(child)
        | DataType::LargeList(child)
        | DataType::LargeListView(child)
        | DataType::FixedSizeList(child, _) => match child.data_type() {
            DataType::Struct(fields) if !fields.is_empty() => {
                for field in fields {
                    collect_arrow_paths(field.as_ref(), path, paths)?;
                }
            }
            _ => paths.push(path.to_string()),
        },
        // Map keys are not exposed as stable dotted OCSF leaves. The map root
        // remains queryable through the normal typed Map operators.
        _ => paths.push(path.to_string()),
    }
    Ok(())
}

fn clickhouse_field_type(field: &Field) -> Result<String> {
    let value = clickhouse_data_type(field.data_type())?;
    if field.is_nullable() && clickhouse_type_supports_nullable(field.data_type()) {
        Ok(format!("Nullable({value})"))
    } else {
        Ok(value)
    }
}

fn clickhouse_type_supports_nullable(data_type: &DataType) -> bool {
    !matches!(
        data_type,
        DataType::Struct(_)
            | DataType::List(_)
            | DataType::ListView(_)
            | DataType::LargeList(_)
            | DataType::LargeListView(_)
            | DataType::FixedSizeList(_, _)
            | DataType::Map(_, _)
    )
}

fn clickhouse_data_type(data_type: &DataType) -> Result<String> {
    let value = match data_type {
        DataType::Boolean => "Bool".to_string(),
        DataType::Int8 => "Int8".to_string(),
        DataType::Int16 => "Int16".to_string(),
        DataType::Int32 => "Int32".to_string(),
        DataType::Int64 => "Int64".to_string(),
        DataType::UInt8 => "UInt8".to_string(),
        DataType::UInt16 => "UInt16".to_string(),
        DataType::UInt32 => "UInt32".to_string(),
        DataType::UInt64 => "UInt64".to_string(),
        DataType::Float16 | DataType::Float32 => "Float32".to_string(),
        DataType::Float64 => "Float64".to_string(),
        DataType::Timestamp(unit, timezone) => {
            let precision = match unit {
                TimeUnit::Second => 0,
                TimeUnit::Millisecond => 3,
                TimeUnit::Microsecond => 6,
                TimeUnit::Nanosecond => 9,
            };
            match timezone.as_deref() {
                Some("+00:00" | "+0000" | "+00" | "Z" | "Etc/UTC" | "UTC") => {
                    format!("DateTime64({precision}, 'UTC')")
                }
                Some(timezone) => format!(
                    "DateTime64({precision}, '{}')",
                    timezone.replace('\'', "''")
                ),
                None => format!("DateTime64({precision})"),
            }
        }
        DataType::Date32 => "Date32".to_string(),
        DataType::Date64 => "DateTime64(3)".to_string(),
        DataType::Time32(_) => "Int32".to_string(),
        DataType::Time64(_) | DataType::Duration(_) => "Int64".to_string(),
        DataType::Binary
        | DataType::LargeBinary
        | DataType::BinaryView
        | DataType::Utf8
        | DataType::LargeUtf8
        | DataType::Utf8View => "String".to_string(),
        DataType::FixedSizeBinary(size) if *size > 0 => format!("FixedString({size})"),
        DataType::List(child)
        | DataType::ListView(child)
        | DataType::LargeList(child)
        | DataType::LargeListView(child) => {
            format!("Array({})", clickhouse_field_type(child.as_ref())?)
        }
        DataType::FixedSizeList(child, size) if *size > 0 => {
            format!("Array({})", clickhouse_field_type(child.as_ref())?)
        }
        DataType::Struct(fields) if !fields.is_empty() => format!(
            "Tuple({})",
            fields
                .iter()
                .map(|field| {
                    Ok(format!(
                        "{} {}",
                        clickhouse_identifier(field.name())?,
                        clickhouse_field_type(field)?
                    ))
                })
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        ),
        DataType::Map(entries, _) => {
            let DataType::Struct(fields) = entries.data_type() else {
                bail!("Iceberg map entries are not a struct");
            };
            if fields.len() != 2 {
                bail!("Iceberg map does not contain one key and value");
            }
            format!(
                "Map({}, {})",
                clickhouse_field_type(fields[0].as_ref())?,
                clickhouse_field_type(fields[1].as_ref())?
            )
        }
        DataType::Dictionary(_, value) => clickhouse_data_type(value)?,
        DataType::Decimal32(precision, scale)
        | DataType::Decimal64(precision, scale)
        | DataType::Decimal128(precision, scale)
        | DataType::Decimal256(precision, scale) => {
            format!("Decimal({precision}, {scale})")
        }
        unsupported => bail!("unsupported serving Arrow type: {unsupported:?}"),
    };
    Ok(value)
}

fn clickhouse_identifier(value: &str) -> Result<String> {
    if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        bail!("serving snapshot contains an invalid field name");
    }
    Ok(format!("`{}`", value.replace('`', "``")))
}

/// Return true when a long-lived REST catalog session must be recreated.
///
/// OAuth-enabled REST catalogs may issue a bounded-lifetime token
/// when `RestCatalog` is constructed. The current embedded client can surface
/// expiration as a nested 401 instead of refreshing it. Keep this deliberately
/// narrow: other failures retain normal backoff instead of creating a hot
/// credential-refresh loop.
pub fn catalog_session_expired(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("401 Unauthorized") || message.contains("status: 401")
    })
}

#[derive(Debug, Clone)]
pub struct CatalogConfig {
    pub uri: String,
    pub warehouse: String,
    /// Optional OAuth client credential in the Iceberg REST `credential`
    /// property. Local or workload-identity catalogs may not need one.
    pub credential: Option<String>,
    /// Optional bearer-token file for projected Kubernetes workload identity.
    /// It is reread whenever a catalog session is constructed after expiry.
    pub token_file: Option<PathBuf>,
    /// Optional OAuth scope used only for client-credential token exchange.
    /// Catalog deployments own this value; it must not be Polaris-specific.
    pub oauth_scope: Option<String>,
    /// Optional OAuth audience used only for client-credential token exchange.
    pub oauth_audience: Option<String>,
    /// Optional OAuth token endpoint. Plain REST catalogs generally rely on an
    /// external issuer; Polaris can keep using its catalog-relative default.
    pub oauth_server_uri: Option<String>,
    /// Optional compatibility header for catalogs that use a realm selector.
    /// Lakekeeper and other plain REST catalogs leave this unset.
    pub realm: Option<String>,
    /// Permit an unauthenticated catalog only for an explicitly isolated local
    /// validation deployment. Production callers must leave this false.
    pub allow_anonymous: bool,
    pub s3_endpoint: String,
    pub s3_region: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub s3_session_token: Option<String>,
    pub s3_path_style_access: bool,
    pub s3_default_credentials: bool,
    pub vended_credentials: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRow {
    pub event_uid: String,
    pub event_kind: EventKind,
    pub ocsf_event: Value,
}

/// One bounded batch whose canonical rows, tenant, and partitions were
/// established together, and whose source identity can be sealed exactly once.
///
/// The fields are deliberately private: staged encoding must not be handed a
/// digest from one row set alongside normalized values from another. Bronze
/// admission constructs this once, before optional prevalence decoration, and
/// every staging phase borrows that same object.
#[derive(Debug)]
pub struct NormalizedEventBatch {
    tenant_id: String,
    source_batch_sha256: Option<String>,
    event_hours: Vec<i32>,
    rows: Vec<EventRow>,
}

impl NormalizedEventBatch {
    fn normalize(rows: &[EventRow], tenant_id: &str) -> Result<Self> {
        let source_batch_sha256 = batch_digest(rows)?;
        let normalized = rows
            .iter()
            .map(|row| {
                let (event_hour, ocsf_event) = normalize_event(row, tenant_id)?;
                Ok((
                    event_hour,
                    EventRow {
                        event_uid: row.event_uid.clone(),
                        event_kind: row.event_kind,
                        ocsf_event,
                    },
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Self::from_parts(tenant_id, Some(source_batch_sha256), normalized)
    }

    pub(crate) fn from_admitted(tenant_id: &str, normalized: Vec<(i32, EventRow)>) -> Result<Self> {
        let (event_hours, rows): (Vec<_>, Vec<_>) = normalized.into_iter().unzip();
        Self::from_fields(tenant_id, None, event_hours, rows)
    }

    fn from_parts(
        tenant_id: &str,
        source_batch_sha256: Option<String>,
        normalized: Vec<(i32, EventRow)>,
    ) -> Result<Self> {
        let (event_hours, rows) = normalized.into_iter().unzip();
        Self::from_fields(tenant_id, source_batch_sha256, event_hours, rows)
    }

    fn from_fields(
        tenant_id: &str,
        source_batch_sha256: Option<String>,
        event_hours: Vec<i32>,
        rows: Vec<EventRow>,
    ) -> Result<Self> {
        let batch = Self {
            tenant_id: tenant_id.to_string(),
            source_batch_sha256,
            event_hours,
            rows,
        };
        batch.validate_binding()?;
        Ok(batch)
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn rows(&self) -> &[EventRow] {
        &self.rows
    }

    pub fn into_rows(self) -> Vec<EventRow> {
        self.rows
    }

    /// Seal the source identity exactly once, after final multi-object
    /// admission and before optional prevalence decoration.
    pub fn seal_source_identity(&mut self) -> Result<&str> {
        if self.source_batch_sha256.is_none() {
            self.source_batch_sha256 = Some(batch_digest(&self.rows)?);
        }
        self.source_batch_sha256
            .as_deref()
            .context("normalized event batch source identity was not sealed")
    }

    pub fn source_batch_sha256(&self) -> Option<&str> {
        self.source_batch_sha256.as_deref()
    }

    /// Narrow an already admitted batch to the identities that won a durable
    /// cross-cycle claim. The source seal is cleared because staged bytes now
    /// represent a different (strictly smaller) canonical row set.
    pub fn retain_source_event_uids(&mut self, keep: &BTreeSet<String>) -> Result<()> {
        if keep.is_empty() {
            bail!("normalized event batch cannot retain an empty UID set");
        }
        let mut event_hours = Vec::with_capacity(keep.len());
        let mut rows = Vec::with_capacity(keep.len());
        for (event_hour, row) in self.event_hours.drain(..).zip(self.rows.drain(..)) {
            if keep.contains(&row.event_uid) {
                event_hours.push(event_hour);
                rows.push(row);
            }
        }
        self.event_hours = event_hours;
        self.rows = rows;
        self.source_batch_sha256 = None;
        self.validate_binding()?;
        if self.rows.len() != keep.len() {
            bail!("normalized event batch UID selection contains an unknown identity");
        }
        Ok(())
    }

    pub(crate) fn event_values_mut(&mut self) -> impl Iterator<Item = &mut Value> {
        self.rows.iter_mut().map(|row| &mut row.ocsf_event)
    }

    fn validate_binding(&self) -> Result<()> {
        if self.tenant_id.is_empty()
            || self.tenant_id.len() > 256
            || self.tenant_id.chars().any(char::is_control)
            || self.rows.is_empty()
            || self.rows.len() > 250_000
            || self.rows.len() != self.event_hours.len()
            || self.source_batch_sha256.as_ref().is_some_and(|digest| {
                digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            bail!("normalized event batch binding is invalid");
        }
        for (event_hour, row) in self.event_hours.iter().zip(&self.rows) {
            let metadata = row
                .ocsf_event
                .get("metadata")
                .and_then(Value::as_object)
                .context("normalized event batch row has no metadata")?;
            if metadata.get("uid").and_then(Value::as_str) != Some(row.event_uid.as_str())
                || metadata.get("tenant_uid").and_then(Value::as_str)
                    != Some(self.tenant_id.as_str())
                || metadata.get("version").and_then(Value::as_str) != Some(OCSF_VERSION)
            {
                bail!("normalized event batch row conflicts with its bound identity");
            }
            let actual_hour = ocsf_time_millis(row.ocsf_event.get("time"))
                .and_then(DateTime::<Utc>::from_timestamp_millis)
                .and_then(|timestamp| i32::try_from(timestamp.timestamp().div_euclid(3_600)).ok())
                .context("normalized event batch row has no bounded event hour")?;
            if actual_hour != *event_hour {
                bail!("normalized event batch row conflicts with its bound partition");
            }
        }
        Ok(())
    }

    fn validate_for_staging(&self) -> Result<()> {
        self.validate_binding()?;
        if self.source_batch_sha256.is_none() {
            bail!("normalized event batch source identity was not sealed");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Source,
    Signal,
    PlatformAudit,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventPublishResult {
    pub status: &'static str,
    pub batch_sha256: String,
    pub snapshot_id: i64,
    pub rows: usize,
    pub metadata_location: String,
}

#[derive(Debug, Clone)]
pub struct StagedEventFile {
    pub event_hour: i32,
    pub min_time_ms: i64,
    pub max_time_ms: i64,
    /// Path relative to the assigned Iceberg table root. The object is not
    /// catalog-visible until compaction commits its rows as a sized append.
    pub relative_path: String,
    pub bytes: Vec<u8>,
    pub rows: u64,
    /// Identical replay rows removed while merging exact staged objects.
    /// Fresh Bronze batches have already enforced uniqueness, so this is zero
    /// until two independently admitted batches are packed together.
    pub duplicate_rows_removed: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GenerationRewriteResult {
    pub status: &'static str,
    pub source_table: String,
    pub source_snapshot_id: i64,
    pub destination_table: String,
    pub destination_snapshot_id: i64,
    pub metadata_location: String,
    pub source_rows: usize,
    pub addition_rows: usize,
    pub replaced_rows: usize,
    /// Byte-identical source rows removed because they shared one canonical
    /// metadata.uid. This makes replay repair observable instead of silently
    /// changing the generation's row count.
    pub duplicate_rows_removed: usize,
    /// Source rows whose conflicting metadata.uid was deterministically
    /// repaired during an explicitly authorized migration.
    pub repaired_uid_rows: usize,
    pub rows: usize,
    pub batch_sha256: String,
    pub schema_fields: usize,
    pub schema_generation: String,
}

impl CatalogConfig {
    pub async fn load(&self) -> Result<RestCatalog> {
        // sqlx enables rustls/ring while reqwest 0.13 enables rustls/aws-lc.
        // With both providers compiled, rustls deliberately refuses to guess
        // and panics on the first HTTPS request unless the application chooses
        // one. Catalog access is the common boundary for every HTTPS-backed
        // lake runtime, so make that choice once before constructing either the
        // REST client or its S3 storage. Respect an already-installed provider
        // when an embedding application made the process-level choice first.
        static RUSTLS_PROVIDER: OnceLock<()> = OnceLock::new();
        RUSTLS_PROVIDER.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
        for (name, value) in [
            ("catalog URI", self.uri.as_str()),
            ("warehouse", self.warehouse.as_str()),
            ("S3 region", self.s3_region.as_str()),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                bail!("{name} is empty or contains control characters");
            }
        }
        match (
            self.credential.is_some(),
            self.token_file.is_some(),
            self.allow_anonymous,
        ) {
            (false, false, false) => bail!(
                "catalog authentication is required; anonymous access needs an explicit local-validation override"
            ),
            (true, true, _) => {
                bail!("catalog OAuth credential and workload-token file are mutually exclusive")
            }
            (true, false, true) | (false, true, true) => bail!(
                "anonymous catalog override cannot be combined with authenticated catalog access"
            ),
            _ => {}
        }
        if (self.oauth_scope.is_some()
            || self.oauth_audience.is_some()
            || self.oauth_server_uri.is_some())
            && self.credential.is_none()
        {
            bail!("catalog OAuth scope/audience requires an OAuth client credential");
        }
        for (name, value) in [
            ("catalog credential", self.credential.as_deref()),
            ("catalog OAuth scope", self.oauth_scope.as_deref()),
            ("catalog OAuth audience", self.oauth_audience.as_deref()),
            ("catalog OAuth server URI", self.oauth_server_uri.as_deref()),
            ("catalog realm", self.realm.as_deref()),
        ] {
            if value
                .is_some_and(|value| value.trim().is_empty() || value.chars().any(char::is_control))
            {
                bail!("{name} is empty or contains control characters");
            }
        }
        // A credential of the form `client_id:` is a NON-EMPTY string carrying an
        // EMPTY secret, so the checks above pass and the only symptom is a bare
        // `401 invalid_client` from the token endpoint minutes later. That is the
        // exact shape compose produces when a secret interpolates to empty --
        // `${NANO_LAKEKEEPER_RUNTIME_CLIENT_SECRET:-}` with the variable unset --
        // which happens whenever a single service is recreated without the full
        // deployment environment. Diagnose it here instead.
        if let Some(credential) = self.credential.as_deref() {
            // ONLY the `client_id:client_secret` form is validated here. A
            // colon-less credential is the bare-token form the REST catalog also
            // accepts, and treating it as a client id would both misdiagnose it and
            // -- because the whole value would land in the message -- print the
            // secret to the logs.
            if let Some((client_id, secret)) = credential.split_once(':') {
                if client_id.trim().is_empty() {
                    bail!(
                        "catalog credential has an empty client id; expected \
                         `client_id:client_secret`"
                    );
                }
                if secret.trim().is_empty() {
                    // Never interpolate any part of the credential: a client id is
                    // not secret, but this message is reached with malformed input
                    // and the halves cannot be trusted to be what they claim.
                    bail!(
                        "the catalog credential carries an EMPTY client secret; the deployment \
                         environment is incomplete (a compose `${{VAR:-}}` default renders a \
                         missing secret as empty). Supply the client secret rather than \
                         recreating a single service with a partial environment."
                    );
                }
            }
        }
        if self.s3_default_credentials {
            if !self.s3_access_key.is_empty()
                || !self.s3_secret_key.is_empty()
                || self.s3_session_token.is_some()
            {
                bail!("default S3 credentials cannot be combined with static credentials");
            }
        } else {
            for (name, value) in [
                ("S3 endpoint", self.s3_endpoint.as_str()),
                ("S3 access key", self.s3_access_key.as_str()),
                ("S3 secret key", self.s3_secret_key.as_str()),
            ] {
                if value.trim().is_empty() || value.chars().any(char::is_control) {
                    bail!("{name} is empty or contains control characters");
                }
            }
        }
        if self
            .s3_session_token
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.chars().any(char::is_control))
        {
            bail!("S3 session token is empty or contains control characters");
        }
        let mut properties = HashMap::from([
            (REST_CATALOG_PROP_URI.to_string(), self.uri.clone()),
            (
                REST_CATALOG_PROP_WAREHOUSE.to_string(),
                self.warehouse.clone(),
            ),
            (S3_REGION.to_string(), self.s3_region.clone()),
            (
                S3_PATH_STYLE_ACCESS.to_string(),
                self.s3_path_style_access.to_string(),
            ),
        ]);
        if let Some(credential) = &self.credential {
            properties.insert("credential".to_string(), credential.clone());
            if let Some(scope) = &self.oauth_scope {
                properties.insert("scope".to_string(), scope.clone());
            }
            if let Some(audience) = &self.oauth_audience {
                properties.insert("audience".to_string(), audience.clone());
            }
            if let Some(uri) = &self.oauth_server_uri {
                properties.insert("oauth2-server-uri".to_string(), uri.clone());
            }
        }
        if let Some(path) = &self.token_file {
            let mut token = std::fs::read(path)
                .with_context(|| format!("read catalog workload token {}", path.display()))?;
            while matches!(token.last(), Some(b'\n' | b'\r')) {
                token.pop();
            }
            if !(32..=16_384).contains(&token.len())
                || token.iter().any(|byte| byte.is_ascii_control())
            {
                bail!("catalog workload token must contain 32-16384 non-control bytes");
            }
            properties.insert(
                "token".to_string(),
                String::from_utf8(token).context("catalog workload token is not UTF-8")?,
            );
        }
        if let Some(realm) = &self.realm {
            properties.insert("header.Polaris-Realm".to_string(), realm.clone());
        }
        if !self.s3_endpoint.is_empty() {
            properties.insert(S3_ENDPOINT.to_string(), self.s3_endpoint.clone());
        }
        if !self.s3_default_credentials {
            properties.insert(S3_ACCESS_KEY_ID.to_string(), self.s3_access_key.clone());
            properties.insert(S3_SECRET_ACCESS_KEY.to_string(), self.s3_secret_key.clone());
            if let Some(token) = &self.s3_session_token {
                properties.insert(S3_SESSION_TOKEN.to_string(), token.clone());
            }
            properties.insert(S3_DISABLE_CONFIG_LOAD.to_string(), "true".to_string());
            properties.insert(S3_DISABLE_EC2_METADATA.to_string(), "true".to_string());
        }
        if self.vended_credentials {
            properties.insert(
                "header.X-Iceberg-Access-Delegation".to_string(),
                "vended-credentials".to_string(),
            );
        }
        crate::r2_ops::install_iceberg_http_client();
        RestCatalogBuilder::default()
            .with_storage_factory(Arc::new(OpenDalStorageFactory::S3 {
                customized_credential_load: None,
            }))
            .load("nano-security-event-publisher", properties)
            .await
            .context("load Iceberg REST catalog")
    }
}

pub fn table_ident(value: &str) -> Result<TableIdent> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || part.len() > 255
                || !part
                    .chars()
                    .all(|value| value.is_ascii_alphanumeric() || value == '_' || value == '-')
        })
    {
        bail!("Iceberg table must be one bounded namespace.table identifier");
    }
    TableIdent::from_strs(parts).context("build Iceberg table identifier")
}

pub fn normalize_event(row: &EventRow, tenant_id: &str) -> Result<(i32, Value)> {
    normalize_event_with(row, tenant_id, true)
}

/// `stabilize_unmapped = false` reproduces the pre-NAN-2764-follow-up
/// canonical form. Only commit verification uses it, to recognise a
/// reservation that was staged by the previous publisher build.
fn normalize_event_with(
    row: &EventRow,
    tenant_id: &str,
    stabilize_unmapped: bool,
) -> Result<(i32, Value)> {
    if row.event_uid.is_empty()
        || row.event_uid.len() > 4_096
        || row.event_uid.chars().any(char::is_control)
        || tenant_id.is_empty()
        || tenant_id.len() > 256
        || tenant_id.chars().any(char::is_control)
    {
        bail!("outbox event or tenant identity is invalid");
    }
    let mut event = row
        .ocsf_event
        .as_object()
        .cloned()
        .context("OCSF outbox event must be an object")?;
    // NAN-3003: nano platform stamps sit outside the OCSF 1.9 contract, so
    // they are format-checked here and set aside while the strict validator
    // runs, then restored. Source rows only: product rows never carry them.
    let mut platform_stamps = Vec::new();
    if row.event_kind == EventKind::Source {
        normalize_source_semantics(&mut event);
        sanitize_unmapped_keys(&mut event);
        platform_stamps = take_platform_metadata_stamps(&mut event)?;
        let raw_data = event
            .get("raw_data")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 16 * 1024 * 1024)
            .context("source OCSF event must preserve one bounded non-empty raw_data value")?;
        let raw_size = event
            .get("raw_data_size")
            .and_then(Value::as_u64)
            .context("source OCSF event must preserve raw_data_size")?;
        if raw_size != raw_data.len() as u64 {
            bail!("source OCSF raw_data_size does not match its encoded byte length");
        }
    }
    // NAN-3460: platform audit is API Activity, Authentication (logons) or
    // Account Change (account lifecycle).
    let expected: Option<(&[i64], &str)> = match row.event_kind {
        EventKind::Source => None,
        EventKind::Signal => Some((&[2_004], "signals")),
        EventKind::PlatformAudit => Some((&[6_003, 3_002, 3_001], "audit")),
    };
    if let Some((expected_classes, _)) = expected {
        let class = event.get("class_uid").and_then(Value::as_i64);
        if !class.is_some_and(|class| expected_classes.contains(&class)) {
            bail!("outbox event class does not match its durable event kind");
        }
    }
    let metadata = event
        .get("metadata")
        .and_then(Value::as_object)
        .context("OCSF outbox event lacks metadata")?;
    for (name, expected_value) in [
        ("uid", row.event_uid.as_str()),
        ("tenant_uid", tenant_id),
        ("version", OCSF_VERSION),
    ] {
        if metadata.get(name).and_then(Value::as_str) != Some(expected_value) {
            bail!("OCSF metadata.{name} conflicts with the durable outbox identity");
        }
    }
    let log_source = metadata
        .get("log_source")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        })
        .context("OCSF metadata.log_source is invalid")?;
    if let Some((_, expected_source)) = expected {
        if log_source != expected_source {
            bail!("OCSF metadata.log_source conflicts with the durable outbox identity");
        }
    }
    let time_ms = ocsf_time_millis(event.get("time"))
        .filter(|value| *value > 0)
        .context("OCSF event time must be positive epoch milliseconds")?;
    let timestamp = DateTime::<Utc>::from_timestamp_millis(time_ms)
        .context("OCSF event time is outside the supported range")?;
    event.insert("time".to_string(), Value::from(time_ms));
    // SQL170 omitted this required object on operator credential audits. Their
    // immutable source records never captured a client address: represent that
    // unknown value only for the exact historical producer, without inventing
    // an IP, repairing other classes, or replacing an explicitly supplied field.
    let operator_action = event.get("api").and_then(|api| api.pointer("/operation"))
        .and_then(Value::as_str);
    if row.event_kind == EventKind::PlatformAudit && !event.contains_key("src_endpoint")
        && matches!(operator_action, Some("ingest_credential_created" | "ingest_credential_revoked"))
        && event.get("api").and_then(|api| api.pointer("/service/name")).and_then(Value::as_str) == Some("operator")
        && event.get("unmapped").and_then(|value| value.get("source")).and_then(Value::as_str) == Some("operator")
        && event.get("unmapped").and_then(|value| value.get("action")).and_then(Value::as_str) == operator_action
        && event.get("unmapped").and_then(|value| value.get("resource_type")).and_then(Value::as_str) == Some("ingest_credential")
    {
        event.insert("src_endpoint".to_string(), serde_json::json!({"ip": null}));
    }
    synthesize_audit_service_endpoint(row.event_kind, &mut event);
    let validation = nanosiem_core::parsers::validate_ocsf_event(&Value::Object(event.clone()));
    if !validation.valid {
        let preview = validation
            .errors
            .iter()
            .take(4)
            .map(|error| format!("{}: {}", error.attribute_path, error.message))
            .collect::<Vec<_>>()
            .join("; ");
        let first = validation.errors.first();
        return Err(OcsfValidationRejected {
            code: first.map(|error| error.code.clone()).unwrap_or_default(),
            attribute_path: first.map(|error| error.attribute_path.clone()).unwrap_or_default(),
            preview,
        }
        .into());
    }
    if !platform_stamps.is_empty() {
        let metadata = event
            .get_mut("metadata")
            .and_then(Value::as_object_mut)
            .context("validated OCSF event lost its metadata")?;
        metadata.extend(platform_stamps);
    }
    if stabilize_unmapped {
        stabilize_product_unmapped(row.event_kind, &mut event)?;
    }
    event.insert("time".to_string(), Value::String(timestamp.to_rfc3339()));
    let hour = i32::try_from(timestamp.timestamp().div_euclid(3_600))
        .context("OCSF event hour exceeds Iceberg partition range")?;
    Ok((hour, Value::Object(event)))
}

/// The validator's diagnostic codes (`ocsf_validation.rs`), as static reasons.
const OCSF_REASONS: &[(&str, &str)] = &[
    ("attribute_enum_value_unknown", "ocsf_attribute_enum_value_unknown"),
    ("attribute_max_len_exceeded", "ocsf_attribute_max_len_exceeded"),
    ("attribute_range_failed", "ocsf_attribute_range_failed"),
    ("attribute_regex_failed", "ocsf_attribute_regex_failed"),
    ("attribute_required_missing", "ocsf_attribute_required_missing"),
    ("attribute_unknown", "ocsf_attribute_unknown"),
    ("attribute_value_unknown", "ocsf_attribute_value_unknown"),
    ("attribute_wrong_type", "ocsf_attribute_wrong_type"),
    ("class_uid_missing_or_invalid", "ocsf_class_uid_missing_or_invalid"),
    ("class_uid_unknown", "ocsf_class_uid_unknown"),
    ("constraint_failed", "ocsf_constraint_failed"),
    ("event_wrong_type", "ocsf_event_wrong_type"),
    ("profile_unknown", "ocsf_profile_unknown"),
    ("schema_contract_invalid", "ocsf_schema_contract_invalid"),
    ("schema_contract_unavailable", "ocsf_schema_contract_unavailable"),
    ("type_uid_incorrect", "ocsf_type_uid_incorrect"),
    ("version_incompatible", "ocsf_version_incompatible"),
];

/// The strict OCSF 1.9 check refused an event. Its message (the validator
/// preview) may quote values; `code` and `attribute_path` are the value-free
/// first diagnostic, for refusal logging (NAN-3490).
#[derive(Debug, thiserror::Error)]
#[error("OCSF 1.9 validation rejected outbox event: {preview}")]
pub struct OcsfValidationRejected {
    /// The validator's diagnostic code (e.g. `attribute_required_missing`).
    pub code: String,
    /// The OCSF attribute path of the first diagnostic.
    pub attribute_path: String,
    preview: String,
}

impl OcsfValidationRejected {
    /// The diagnostic code as a bounded static reason (`ocsf_<code>` for the
    /// validator's known codes, `ocsf_invalid` otherwise).
    pub fn reason(&self) -> &'static str {
        OCSF_REASONS
            .iter()
            .find(|(code, _)| *code == self.code)
            .map_or("ocsf_invalid", |(_, reason)| reason)
    }
}

/// `metadata.nano_credential_id`: the ingest credential a collector-capable
/// (v2) platform base attributes the row to (NAN-2596).
pub const METADATA_CREDENTIAL_ID: &str = "nano_credential_id";
/// `metadata.nano_parser_bundle_sha256`: the parser bundle the cell was
/// started with, stamped by the v2 platform base lake prepare (NAN-2645).
pub const METADATA_PARSER_BUNDLE_SHA256: &str = "nano_parser_bundle_sha256";
/// `metadata.ingress_transport`: the ingress lane a source row arrived on,
/// stamped by the Vector lake storage stage from `%ingress_transport`
/// (NAN-2361 wave 8) and read by the per-source ingest counters. Every
/// self-hosted lane sets it, so before it was admitted here the strict OCSF
/// check rejected every event a user sent (NAN-3373).
pub const METADATA_INGRESS_TRANSPORT: &str = "ingress_transport";

/// The nano platform stamps a platform base's `ocsf_lake_storage_prepare`
/// writes into `metadata` of every source row, outside the OCSF 1.9 schema
/// (NAN-3003). Each is admitted only in its exact stamped form: this is a
/// closed list of known platform fields, not a relaxation of the strict
/// OCSF check, which still refuses every other unknown attribute.
///
/// Both stamps are lowercase by construction (the base `downcase`s them and
/// they are refused otherwise), so they need no entry in the provenance
/// `LOWERCASED_AT_REST` attestation.
pub const PLATFORM_METADATA_STAMPS: &[&str] = &[
    METADATA_CREDENTIAL_ID,
    METADATA_PARSER_BUNDLE_SHA256,
    METADATA_INGRESS_TRANSPORT,
];

/// The ingress-lane spellings the Vector lanes stamp (`config/vector/0[0-3]-*`:
/// `nano_https`, `vector`, `hec`, `otlp`) plus the aliases the per-source
/// counters already map onto the ingest-route vocabulary, plus the open-core
/// OCSF bucket drop's `landing_bucket` (NAN-3807, stamped by
/// `lake_landing_ingest`). A closed list: any other value is refused like
/// every other malformed platform stamp.
pub fn is_platform_ingress_transport(text: &str) -> bool {
    matches!(
        text,
        "nano_https"
            | "http"
            | "https"
            | "hec"
            | "splunk_hec"
            | "otlp"
            | "otlp_http"
            | "vector"
            | "vector_native"
            | "landing_bucket"
    )
}

/// 64 lowercase hex characters.
pub fn is_platform_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The hyphenated lowercase UUID the v2 base stamps, exactly its VRL regex
/// `^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`.
pub fn is_platform_credential_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
        && matches!(bytes[14], b'1'..=b'8')
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// Remove the [`PLATFORM_METADATA_STAMPS`] from `metadata`, refusing a
/// malformed one, and return the well-formed ones for re-insertion after OCSF
/// validation. An empty string is the base's own "unknown" spelling (the
/// bundle stamp is always written, `""` when the cell has no pinned sha) and
/// is dropped rather than stored.
fn take_platform_metadata_stamps(
    event: &mut serde_json::Map<String, Value>,
) -> Result<Vec<(String, Value)>> {
    let Some(Value::Object(metadata)) = event.get_mut("metadata") else {
        return Ok(Vec::new());
    };
    let mut stamps = Vec::new();
    for &name in PLATFORM_METADATA_STAMPS {
        let Some(value) = metadata.remove(name) else {
            continue;
        };
        let text = match &value {
            Value::String(text) => text.as_str(),
            _ => bail!("OCSF metadata.{name} must be a string platform stamp"),
        };
        if text.is_empty() {
            continue;
        }
        let valid = match name {
            METADATA_PARSER_BUNDLE_SHA256 => is_platform_sha256(text),
            METADATA_CREDENTIAL_ID => is_platform_credential_id(text),
            METADATA_INGRESS_TRANSPORT => is_platform_ingress_transport(text),
            _ => false,
        };
        if !valid {
            bail!("OCSF metadata.{name} is not a well-formed nano platform stamp");
        }
        stamps.push((name.to_string(), value));
    }
    Ok(stamps)
}

/// Suffix of the `unmapped` key that carries one free-form nested value of a
/// product event as a single JSON string (NAN-2764).
pub const UNMAPPED_JSON_SUFFIX: &str = "_json";

fn unmapped_needs_stabilization(kind: EventKind, event: &Value) -> bool {
    matches!(kind, EventKind::Signal | EventKind::PlatformAudit)
        && event
            .get("unmapped")
            .and_then(Value::as_object)
            .is_some_and(|unmapped| {
                unmapped.values().any(|value| value.is_object() || value.is_array())
            })
}

/// NAN-2764 follow-up. Product events (Detection Findings and platform
/// audits) carry producer-defined payloads under `unmapped`: an audit's
/// `details` object and a finding's `matched_events_sample` are whatever the
/// emitting code put there, so the same path can be a boolean in one row and
/// an object in the next (`unmapped.details.created` wedged tenant1's
/// 1000-row reservation on 2026-09-24 because Arrow inference cannot merge
/// them). No per-row validation can catch that, and the Iceberg table can
/// only ever widen a column additively.
///
/// So a nested (object or array) top-level `unmapped` value is published as
/// ONE JSON string under `<key>_json`, which has the same physical type in
/// every row and every table. Top-level scalars (`action`, `source`,
/// `success`, `resource_id`, ...) are the nano audit/finding envelope, stay
/// typed and queryable, and every OCSF-typed field is untouched. The value is
/// serialized losslessly; the stored source row is never rewritten.
///
/// Idempotent: a read-back of a published row carries only scalars here, so
/// staged-object and commit verification re-normalize it to itself. A
/// producer that already set `<key>_json` alongside a nested `<key>` is
/// rejected (and quarantined by the publisher), never overwritten. Source
/// events are out of scope: their `unmapped` shape is owned by the parsers.
fn stabilize_product_unmapped(
    kind: EventKind,
    event: &mut serde_json::Map<String, Value>,
) -> Result<()> {
    if !matches!(kind, EventKind::Signal | EventKind::PlatformAudit) {
        return Ok(());
    }
    let Some(Value::Object(unmapped)) = event.get_mut("unmapped") else {
        return Ok(());
    };
    let nested = unmapped
        .iter()
        .filter(|(_, value)| value.is_object() || value.is_array())
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    for key in nested {
        let derived = format!("{key}{UNMAPPED_JSON_SUFFIX}");
        if unmapped.contains_key(&derived) {
            bail!(
                "OCSF unmapped.{key} is free-form but unmapped.{derived} is already set; \
                 refusing to overwrite the producer's value"
            );
        }
        let value = unmapped
            .remove(&key)
            .context("free-form unmapped value disappeared during stabilization")?;
        unmapped.insert(derived, Value::String(serde_json::to_string(&value)?));
    }
    Ok(())
}

/// JSON shape class that Arrow inference cannot merge across. Integers and
/// floats share one class (they widen to Float64); `null` has none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShapeKind {
    Boolean,
    Number,
    String,
    Object,
    Array,
}

impl ShapeKind {
    fn of(value: &Value) -> Option<Self> {
        match value {
            Value::Null => None,
            Value::Bool(_) => Some(Self::Boolean),
            Value::Number(_) => Some(Self::Number),
            Value::String(_) => Some(Self::String),
            Value::Object(_) => Some(Self::Object),
            Value::Array(_) => Some(Self::Array),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Boolean => "a boolean",
            Self::Number => "a number",
            Self::String => "a string",
            Self::Object => "an object",
            Self::Array => "an array",
        }
    }
}

/// NAN-2764 backstop for one publication batch: the first row to reach a
/// path fixes its shape, and a later row that disagrees (object vs scalar,
/// boolean vs string, scalar vs array, ...) is refused with the path named,
/// so the caller can reject that ROW instead of failing the batch. Stricter
/// than Arrow inference on purpose: mixed scalars would infer as Utf8 and then
/// fail to decode, and a scalar/array mix would infer a list that the scalar
/// cannot fill. Every set of admitted rows therefore infers one schema.
#[derive(Debug, Default)]
pub struct BatchShapeIndex {
    kinds: HashMap<String, ShapeKind>,
}

impl BatchShapeIndex {
    /// Admit one normalized event, or return why it cannot share this batch.
    /// A refused row leaves the index unchanged.
    pub fn admit(&mut self, event: &Value) -> std::result::Result<(), String> {
        let mut row = BTreeMap::new();
        collect_shape(event, "", &mut row)?;
        for (path, kind) in &row {
            if let Some(existing) = self.kinds.get(path) {
                if existing != kind {
                    return Err(format!(
                        "OCSF field {path} is {} but earlier rows of this batch carry {}",
                        kind.name(),
                        existing.name()
                    ));
                }
            }
        }
        self.kinds.extend(row);
        Ok(())
    }
}

fn collect_shape(
    value: &Value,
    path: &str,
    out: &mut BTreeMap<String, ShapeKind>,
) -> std::result::Result<(), String> {
    let Some(kind) = ShapeKind::of(value) else {
        return Ok(());
    };
    if !path.is_empty() {
        match out.get(path) {
            Some(existing) if *existing != kind => {
                return Err(format!(
                    "OCSF field {path} is both {} and {} within one event",
                    existing.name(),
                    kind.name()
                ));
            }
            Some(_) => {}
            None => {
                out.insert(path.to_string(), kind);
            }
        }
    }
    match value {
        Value::Object(values) => {
            for (name, child) in values {
                collect_shape(child, &child_path(path, name), out)?;
            }
        }
        Value::Array(values) => {
            let element = format!("{path}[]");
            for child in values {
                collect_shape(child, &element, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// First path at which `value` contradicts a column the live table already
/// has, mirroring what `additive_columns` refuses and the JSON decoder cannot
/// fill. A field the table lacks is never a conflict (it is an addition), and
/// a physically-null value never is either. `None` means the event can be
/// admitted additively.
fn value_conflict_path(value: &Value, data_type: &DataType, path: &str) -> Option<String> {
    if physically_null(value) {
        return None;
    }
    let conflict = || Some(if path.is_empty() { "<root>".to_string() } else { path.to_string() });
    match (value, data_type) {
        (Value::Object(values), DataType::Struct(fields)) => values.iter().find_map(|(name, child)| {
            fields
                .iter()
                .find(|field| field.name() == name)
                .and_then(|field| value_conflict_path(child, field.data_type(), &child_path(path, name)))
        }),
        (Value::Object(values), DataType::Map(field, _)) => {
            let DataType::Struct(entries) = field.data_type() else {
                return conflict();
            };
            let Some(value_type) = entries.iter().find(|entry| entry.name() == "value") else {
                return conflict();
            };
            values.iter().find_map(|(name, child)| {
                value_conflict_path(child, value_type.data_type(), &child_path(path, name))
            })
        }
        (
            Value::Array(values),
            DataType::List(field)
            | DataType::LargeList(field)
            | DataType::ListView(field)
            | DataType::LargeListView(field)
            | DataType::FixedSizeList(field, _),
        ) => {
            let element = format!("{path}[]");
            values
                .iter()
                .find_map(|child| value_conflict_path(child, field.data_type(), &element))
        }
        (Value::Bool(_), DataType::Boolean) => None,
        (Value::Number(number), data_type) => {
            let admitted = if number.is_f64() {
                matches!(data_type, DataType::Float64 | DataType::Timestamp(_, _))
            } else {
                matches!(
                    data_type,
                    DataType::Int64 | DataType::Float64 | DataType::Timestamp(_, _)
                )
            };
            if admitted { None } else { conflict() }
        }
        (Value::String(_), data_type)
            if matches!(
                data_type,
                DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View | DataType::Timestamp(_, _)
            ) =>
        {
            None
        }
        _ => conflict(),
    }
}

/// NAN-2764 backstop against the LIVE table: normalize each row on its own
/// and name every row whose shape contradicts a column the tenant's event
/// table already has (for example a typed OCSF field a producer changed from
/// a string to an object). Those rows can never be admitted additively and
/// would otherwise fail the whole batch forever. Returns `(index, reason)`
/// in input order; an absent table has no columns to contradict.
pub async fn event_rows_conflicting_with_table(
    catalog: &impl Catalog,
    table_id: &TableIdent,
    table_location: &str,
    tenant_id: &str,
    rows: &[EventRow],
) -> Result<Vec<(usize, String)>> {
    if !catalog.table_exists(table_id).await? {
        return Ok(Vec::new());
    }
    let table = load_bound_event_table(catalog, table_id, table_location, tenant_id).await?;
    let arrow: ArrowSchema = table
        .metadata()
        .current_schema()
        .as_ref()
        .try_into()
        .context("convert Iceberg OCSF schema to Arrow for row conflict check")?;
    let root = DataType::Struct(arrow.fields().clone());
    let mut conflicts = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        match normalize_event(row, tenant_id) {
            Ok((_, event)) => {
                if let Some(path) = value_conflict_path(&event, &root, "") {
                    conflicts.push((
                        index,
                        format!(
                            "OCSF field {path} conflicts with the live Iceberg column type; \
                             schema generation rewrite required"
                        ),
                    ));
                }
            }
            Err(error) => conflicts.push((index, format!("{error:#}"))),
        }
    }
    Ok(conflicts)
}

/// `unmapped` marker naming an endpoint the publisher derived, so the lake
/// never presents it as an observed client address.
pub const SYNTHESIZED_SRC_ENDPOINT_MARKER: &str = "synthesized:emitting_service";

/// NAN-2764. OCSF 1.9 requires `src_endpoint` on API Activity (6003), but
/// service, operator and SQL-side audit producers (the platform fulfilment,
/// operator route/cell/assignment changes, tenant self-revocation through a
/// SECURITY DEFINER function) have no client address to record. Rejecting
/// those rows wedged tenant1's product-event reservation for ~36 hours, and
/// dropping them would lose audit trail. Instead, describe what IS known, the
/// emitting service, with no IP, and mark it in `unmapped`.
///
/// Scope is exact: platform audits of class 6003 whose producer omitted the
/// key. A present endpoint (including an explicit null or an invalid one) is
/// the producer's claim and is never replaced, and no other event kind or
/// class is touched. The stored source row is never rewritten, so the same
/// derivation applies deterministically on every retry and verification.
fn synthesize_audit_service_endpoint(
    kind: EventKind,
    event: &mut serde_json::Map<String, Value>,
) {
    if kind != EventKind::PlatformAudit
        || event.get("class_uid").and_then(Value::as_i64) != Some(6_003)
        || event.contains_key("src_endpoint")
    {
        return;
    }
    let bounded = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
            })
            .map(str::to_string)
    };
    let field = |top: &str, path: &str| event.get(top).and_then(|value| value.pointer(path));
    let service = bounded(field("api", "/service/name"))
        .or_else(|| bounded(field("metadata", "/product/name")))
        .unwrap_or_else(|| "nano".to_string());
    match event.get_mut("unmapped") {
        Some(Value::Object(unmapped)) => {
            unmapped.insert(
                "nano_src_endpoint".to_string(),
                Value::from(SYNTHESIZED_SRC_ENDPOINT_MARKER),
            );
        }
        None => {
            event.insert(
                "unmapped".to_string(),
                serde_json::json!({"nano_src_endpoint": SYNTHESIZED_SRC_ENDPOINT_MARKER}),
            );
        }
        // A non-object `unmapped` already fails OCSF validation; leave the
        // producer's value and the endpoint alone so that row is quarantined
        // with its real error rather than a half-repaired payload.
        Some(_) => return,
    }
    event.insert(
        "src_endpoint".to_string(),
        serde_json::json!({"name": service, "svc_name": service, "type": "Other", "type_id": 99}),
    );
}

pub(crate) fn ocsf_time_millis(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    if let Some(value) = value.as_i64() {
        return Some(value);
    }
    let value = value.as_str()?;
    DateTime::parse_from_rfc3339(value)
        .or_else(|_| DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f%:z"))
        .ok()
        .map(|value| value.timestamp_millis())
}

/// NAN-3422: rename producer keys under `unmapped` that are not query
/// identifiers (`[A-Za-z_][A-Za-z0-9_]*`), at every depth, before the schema is
/// inferred. Beats/Logstash feeds carry `@timestamp`, `@version` and
/// `@metadata`; stored verbatim they became Parquet leaves no query could
/// address, and the strict query contract refused the whole tenant. Each
/// illegal character becomes `_` and a leading non-letter gains a `_` prefix
/// (`@timestamp` -> `_timestamp`, `Event-ID` -> `Event_ID`); a clash with an
/// existing key appends `_` until free. Dots are kept: each dotted component
/// is renamed on its own. Idempotent, so re-normalizing a stored row is
/// stable. The verbatim event stays in `raw_data`.
pub(crate) fn sanitize_unmapped_keys(event: &mut serde_json::Map<String, Value>) {
    if let Some(unmapped) = event.get_mut("unmapped") {
        sanitize_value_keys(unmapped);
    }
}

fn sanitize_value_keys(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if map.keys().any(|key| !is_query_identifier(key)) {
                let entries = std::mem::take(map);
                let (valid, invalid): (Vec<_>, Vec<_>) =
                    entries.into_iter().partition(|(key, _)| is_query_identifier(key));
                map.extend(valid);
                for (key, value) in invalid {
                    let mut name = query_identifier_for(&key);
                    while map.contains_key(&name) {
                        name.push('_');
                    }
                    map.insert(name, value);
                }
            }
            map.values_mut().for_each(sanitize_value_keys);
        }
        Value::Array(values) => values.iter_mut().for_each(sanitize_value_keys),
        _ => {}
    }
}

/// A parser's residual spill writes flat dotted keys under `unmapped`
/// (`event_data.destination_is_ipv_6`, NAN-3401) that chDB resolves as nested
/// paths, so each dot-separated component is checked on its own.
fn is_query_identifier(key: &str) -> bool {
    key.split('.').all(|segment| {
        let mut bytes = segment.bytes();
        matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn query_identifier_for(key: &str) -> String {
    key.split('.')
        .map(|segment| {
            let mut name = segment
                .chars()
                .map(|character| if character.is_ascii_alphanumeric() || character == '_' { character } else { '_' })
                .collect::<String>();
            if !name.starts_with(|character: char| character.is_ascii_alphabetic() || character == '_') {
                name.insert(0, '_');
            }
            name
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn normalize_source_semantics(event: &mut serde_json::Map<String, Value>) {
    const LOWERCASE_PATHS: &[&str] = &[
        "src_endpoint.ip",
        "dst_endpoint.ip",
        "src_endpoint.mac",
        "dst_endpoint.mac",
        "src_endpoint.hostname",
        "device.hostname",
        "dst_endpoint.hostname",
        "user.name",
        "actor.user.name",
        "user.domain",
        "file.hashes.value",
        "process.file.hashes.value",
        "actor.process.file.hashes.value",
        "email.from",
        "email.to",
        "metadata.log_source",
        "enrichments.value",
    ];
    let mut value = Value::Object(std::mem::take(event));
    for path in LOWERCASE_PATHS {
        lowercase_json_path(&mut value, &mut path.split('.'));
    }
    *event = value
        .as_object_mut()
        .map(std::mem::take)
        .unwrap_or_default();
}

fn lowercase_json_path<'a, I>(value: &mut Value, path: &mut I)
where
    I: Iterator<Item = &'a str> + Clone,
{
    if let Value::Array(values) = value {
        for value in values {
            let mut child_path = path.clone();
            lowercase_json_path(value, &mut child_path);
        }
        return;
    }
    let Some(name) = path.next() else {
        if let Value::String(value) = value {
            *value = value.trim().to_ascii_lowercase();
        }
        return;
    };
    let Some(child) = value.as_object_mut().and_then(|value| value.get_mut(name)) else {
        return;
    };
    lowercase_json_path(child, path);
}

pub fn batch_digest(rows: &[EventRow]) -> Result<String> {
    if rows.is_empty() || rows.len() > 250_000 {
        bail!("event batch must contain one to 250000 rows");
    }
    event_rows_digest(rows)
}

/// Digest a complete bounded rewrite input without weakening the smaller
/// steady-state append limit enforced by [`batch_digest`].
fn generation_digest(rows: &[EventRow]) -> Result<String> {
    if rows.is_empty() || rows.len() > MAX_GENERATION_REWRITE_ROWS {
        bail!("generation must contain one to {MAX_GENERATION_REWRITE_ROWS} rows");
    }
    let mut identifiers = BTreeSet::new();
    let mut sorted = rows.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        (left.event_uid.as_str(), left.event_kind)
            .cmp(&(right.event_uid.as_str(), right.event_kind))
    });
    let mut digest = Sha256::new();
    digest.update(b"nano:iceberg:generation-digest:v1\0");
    for row in sorted {
        if !identifiers.insert(row.event_uid.as_str()) {
            bail!("generation contains duplicate event UIDs");
        }
        let encoded = serde_json::to_vec(row)?;
        digest.update((encoded.len() as u64).to_be_bytes());
        digest.update(encoded);
    }
    Ok(hex::encode(digest.finalize()))
}

fn event_rows_digest(rows: &[EventRow]) -> Result<String> {
    let mut identifiers = BTreeSet::new();
    let mut sorted = rows.to_vec();
    sorted.sort_by(|left, right| {
        (left.event_uid.as_str(), left.event_kind)
            .cmp(&(right.event_uid.as_str(), right.event_kind))
    });
    for row in &sorted {
        if !identifiers.insert(row.event_uid.as_str()) {
            bail!("event batch contains duplicate event UIDs");
        }
    }
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&sorted)?)))
}

pub fn snapshot_for_batch(table: &Table, digest: &str) -> Option<i64> {
    table
        .metadata()
        .snapshots()
        .find(|snapshot| {
            snapshot
                .summary()
                .additional_properties
                .get(OUTBOX_BATCH_PROPERTY)
                .is_some_and(|value| value == digest)
        })
        .map(|snapshot| snapshot.snapshot_id())
}

/// Return only the Parquet files added by one immutable snapshot.
///
/// Product-event publication uses this after both a fresh commit and an
/// idempotent replay so the same exact objects can be exposed through the
/// signed hot tail before the next indexed generation is promoted.
pub async fn snapshot_added_data_files(table: &Table, snapshot_id: i64) -> Result<Vec<DataFile>> {
    snapshot_added_data_files_counted(table, snapshot_id, None).await
}

/// `manifest_loads` counts each manifest body fetched from object storage
/// (one GET each); tests use it to pin the verification cost (NAN-2785).
async fn snapshot_added_data_files_counted(
    table: &Table,
    snapshot_id: i64,
    manifest_loads: Option<&std::sync::atomic::AtomicUsize>,
) -> Result<Vec<DataFile>> {
    let snapshot = table
        .metadata()
        .snapshot_by_id(snapshot_id)
        .context("event publication snapshot is absent from Iceberg metadata")?;
    let list = table
        .manifest_list_reader(snapshot)
        .load()
        .await
        .context("load event publication manifest list")?;
    let mut files = Vec::new();
    let mut paths = BTreeSet::new();
    for descriptor in list.consume_entries() {
        if descriptor.content != ManifestContentType::Data {
            bail!("event publication snapshot unexpectedly references a delete manifest");
        }
        // An ADDED entry for this snapshot is only ever written into a
        // manifest this snapshot itself added; manifests carried forward from
        // earlier commits (and rewritten ones) hold its files as EXISTING at
        // most. Skipping them before the fetch makes verification cost the
        // snapshot's own manifests instead of every manifest in the table.
        if descriptor.added_snapshot_id != snapshot_id || descriptor.added_files_count == Some(0) {
            continue;
        }
        if let Some(loads) = manifest_loads {
            loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let manifest = descriptor
            .load_manifest(table.file_io())
            .await
            .context("load event publication manifest")?;
        for entry in manifest.entries() {
            if entry.status() != ManifestStatus::Added || entry.snapshot_id() != Some(snapshot_id) {
                continue;
            }
            if entry.content_type() != DataContentType::Data
                || entry.file_format() != DataFileFormat::Parquet
                || !paths.insert(entry.file_path().to_string())
            {
                bail!("event publication snapshot contains an invalid added file");
            }
            files.push(entry.data_file().clone());
        }
    }
    if files.is_empty() {
        bail!("event publication snapshot contains no added Parquet files");
    }
    Ok(files)
}

pub async fn publish_events(
    catalog: &RestCatalog,
    table_id: &TableIdent,
    tenant_id: &str,
    rows: &[EventRow],
) -> Result<EventPublishResult> {
    crate::shared_mode::require_serialized_primary_iceberg_authority(
        "event publication",
    )?;
    let digest = batch_digest(rows)?;
    let mut table = catalog
        .load_table(table_id)
        .await
        .context("load Iceberg event table")?;
    if let Some(snapshot_id) = snapshot_for_batch(&table, &digest) {
        return Ok(EventPublishResult {
            status: "no_change",
            batch_sha256: digest,
            snapshot_id,
            rows: rows.len(),
            metadata_location: required_metadata_location(&table)?.to_string(),
        });
    }

    let data_files = write_data_files(&table, tenant_id, rows, &digest, true).await?;
    let source_batch = rows.iter().all(|row| row.event_kind == EventKind::Source);
    if !source_batch && rows.iter().any(|row| row.event_kind == EventKind::Source) {
        bail!("source and product-outbox events cannot share one publication batch");
    }
    let properties = HashMap::from([
        (
            "nano.writer".to_string(),
            if source_batch {
                "rust-vector-bronze"
            } else {
                "rust-security-event-outbox"
            }
            .to_string(),
        ),
        ("nano.ocsf-version".to_string(), OCSF_VERSION.to_string()),
        ("nano.tenant-id".to_string(), tenant_id.to_string()),
        (OUTBOX_BATCH_PROPERTY.to_string(), digest.clone()),
    ]);
    let commit_uuid = uuid::Uuid::from_slice(&hex::decode(&digest)?[..16])?;
    let mut last_error = None;
    for _ in 0..5 {
        let transaction = Transaction::new(&table);
        let action = transaction
            .fast_append()
            .set_commit_uuid(commit_uuid)
            .set_snapshot_properties(properties.clone())
            .add_data_files(data_files.clone());
        let transaction = action.apply(transaction)?;
        match transaction.commit(catalog).await {
            Ok(committed) => {
                let snapshot = committed
                    .metadata()
                    .current_snapshot()
                    .context("Iceberg commit has no current snapshot")?;
                if snapshot
                    .summary()
                    .additional_properties
                    .get(OUTBOX_BATCH_PROPERTY)
                    != Some(&digest)
                {
                    bail!("Iceberg append did not expose the committed outbox batch");
                }
                return Ok(EventPublishResult {
                    status: "published",
                    batch_sha256: digest,
                    snapshot_id: snapshot.snapshot_id(),
                    rows: rows.len(),
                    metadata_location: required_metadata_location(&committed)?.to_string(),
                });
            }
            Err(error) => last_error = Some(error),
        }
        table = catalog.load_table(table_id).await?;
        if let Some(snapshot_id) = snapshot_for_batch(&table, &digest) {
            return Ok(EventPublishResult {
                status: "no_change",
                batch_sha256: digest,
                snapshot_id,
                rows: rows.len(),
                metadata_location: required_metadata_location(&table)?.to_string(),
            });
        }
    }
    Err(last_error
        .context("Iceberg event commit exhausted optimistic retries")?
        .into())
}

/// Commit a bounded set of previously staged canonical rows as one normal
/// Iceberg append. This is the only steady-state Vector path that advances the
/// catalog, and its explicit fence allows the generation manager to build and
/// activate matching derivatives.
pub async fn publish_compacted_events(
    catalog: &RestCatalog,
    table_id: &TableIdent,
    tenant_id: &str,
    rows: &[EventRow],
) -> Result<EventPublishResult> {
    crate::shared_mode::require_serialized_primary_iceberg_authority(
        "staged compaction",
    )?;
    let digest = generation_digest(rows)?;
    let mut table = catalog
        .load_table(table_id)
        .await
        .context("load Iceberg event table for staged compaction")?;
    if let Some(snapshot_id) = snapshot_for_batch(&table, &digest) {
        return Ok(EventPublishResult {
            status: "no_change",
            batch_sha256: digest,
            snapshot_id,
            rows: rows.len(),
            metadata_location: required_metadata_location(&table)?.to_string(),
        });
    }
    let data_files = write_data_files(&table, tenant_id, rows, &digest, true).await?;
    let properties = HashMap::from([
        (
            "nano.writer".to_string(),
            "rust-vector-tail-compaction".to_string(),
        ),
        ("nano.ocsf-version".to_string(), OCSF_VERSION.to_string()),
        ("nano.tenant-id".to_string(), tenant_id.to_string()),
        (
            GENERATION_READY_PROPERTY.to_string(),
            GENERATION_READY_VALUE.to_string(),
        ),
        (OUTBOX_BATCH_PROPERTY.to_string(), digest.clone()),
    ]);
    let commit_uuid = uuid::Uuid::from_slice(&hex::decode(&digest)?[..16])?;
    let mut last_error = None;
    for _ in 0..5 {
        let transaction = Transaction::new(&table);
        let action = transaction
            .fast_append()
            .set_commit_uuid(commit_uuid)
            .set_snapshot_properties(properties.clone())
            .add_data_files(data_files.clone());
        match action.apply(transaction)?.commit(catalog).await {
            Ok(committed) => {
                let snapshot = committed
                    .metadata()
                    .current_snapshot()
                    .context("staged compaction committed no Iceberg snapshot")?;
                if snapshot
                    .summary()
                    .additional_properties
                    .get(OUTBOX_BATCH_PROPERTY)
                    != Some(&digest)
                    || snapshot
                        .summary()
                        .additional_properties
                        .get(GENERATION_READY_PROPERTY)
                        .map(String::as_str)
                        != Some(GENERATION_READY_VALUE)
                {
                    bail!("staged compaction commit omitted its publication fences");
                }
                return Ok(EventPublishResult {
                    status: "compacted",
                    batch_sha256: digest,
                    snapshot_id: snapshot.snapshot_id(),
                    rows: rows.len(),
                    metadata_location: required_metadata_location(&committed)?.to_string(),
                });
            }
            Err(error) => last_error = Some(error),
        }
        table = catalog.load_table(table_id).await?;
        if let Some(snapshot_id) = snapshot_for_batch(&table, &digest) {
            return Ok(EventPublishResult {
                status: "no_change",
                batch_sha256: digest,
                snapshot_id,
                rows: rows.len(),
                metadata_location: required_metadata_location(&table)?.to_string(),
            });
        }
    }
    Err(last_error
        .context("Iceberg staged compaction exhausted optimistic retries")?
        .into())
}

/// Register one previously verified, canonical transient tail pack as an
/// Iceberg data file without decoding and rewriting all of its OCSF rows.
/// The pack already uses the current table schema and hour partition; callers
/// retain responsibility for exact-version size/digest verification first.
#[allow(clippy::too_many_arguments)]
pub async fn register_compacted_staged_file(
    catalog: &RestCatalog,
    table_id: &TableIdent,
    tenant_id: &str,
    pack_id: &str,
    object_sha256: &str,
    file_path: &str,
    event_hour: i32,
    file_size: u64,
    rows: u64,
) -> Result<EventPublishResult> {
    register_compacted_staged_file_for(
        catalog,
        table_id,
        TailIdentityProfile::Ocsf,
        tenant_id,
        pack_id,
        object_sha256,
        file_path,
        event_hour,
        file_size,
        rows,
    )
    .await
}

/// `register_compacted_staged_file` for any identity profile: the table's
/// single hour partition must be the profile's (`event_hour` for OCSF,
/// `start_time_hour` / `timestamp_hour` for OTLP) and the snapshot carries
/// the profile's `nano.*` properties, which the catalog broker pins.
#[allow(clippy::too_many_arguments)]
pub async fn register_compacted_staged_file_for(
    catalog: &impl Catalog,
    table_id: &TableIdent,
    profile: TailIdentityProfile,
    tenant_id: &str,
    pack_id: &str,
    object_sha256: &str,
    file_path: &str,
    event_hour: i32,
    file_size: u64,
    rows: u64,
) -> Result<EventPublishResult> {
    if profile != TailIdentityProfile::for_table_name(table_id.name()) {
        bail!("staged tail pack identity profile does not match the target table");
    }
    if tenant_id.is_empty()
        || pack_id.len() != 64
        || !pack_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !is_lower_sha256(object_sha256)
        || file_size == 0
        || rows == 0
    {
        bail!("staged tail pack registration identity is invalid");
    }
    let mut table = catalog
        .load_table(table_id)
        .await
        .context("load Iceberg event table for tail-pack registration")?;
    crate::shared_mode::require_tail_pack_catalog_authority(
        tenant_id,
        table.metadata().location(),
    )?;
    let required_prefix = format!(
        "{}/data/tail/tenant_sha256={}/",
        table.metadata().location().trim_end_matches('/'),
        hex::encode(Sha256::digest(tenant_id.as_bytes()))
    );
    // Accept the historical logical-ID-only path so packs already present
    // during a rolling upgrade can still be registered. Every newly encoded
    // pack includes its exact Parquet digest; this prevents a retry after an
    // additive schema change from presenting different bytes at the same key.
    let legacy_suffix = format!("/pack-{pack_id}.parquet");
    let content_addressed_suffix = format!("/pack-{pack_id}-{object_sha256}.parquet");
    if !file_path.starts_with(&required_prefix)
        || !(file_path.ends_with(&legacy_suffix) || file_path.ends_with(&content_addressed_suffix))
        || file_path.len() > 4_096
        || file_path.chars().any(char::is_control)
        || file_path.split('/').any(|part| part == "." || part == "..")
    {
        bail!("staged tail pack is outside the assigned Iceberg table");
    }
    let partition_spec = table.metadata().default_partition_spec();
    if partition_spec.fields().len() != 1
        || partition_spec.fields()[0].name != profile.partition_field_name()
        || partition_spec.fields()[0].transform != Transform::Hour
    {
        bail!(
            "event table must use exactly the {}/hour {} partition",
            profile.time_column(),
            profile.partition_field_name()
        );
    }
    if profile.is_otel() {
        let dataset = profile.otel_dataset().map(|d| d.as_str()).unwrap_or_default();
        let properties = table.metadata().properties();
        if properties.get("nano.tenant-id").map(String::as_str) != Some(tenant_id)
            || properties.get("nano.otel-dataset").map(String::as_str) != Some(dataset)
        {
            bail!("OTLP table properties do not name this tenant and dataset");
        }
        verify_native_column_order(&table, profile)?;
    }
    if let Some(snapshot_id) = snapshot_for_batch(&table, pack_id) {
        return Ok(EventPublishResult {
            status: "no_change",
            batch_sha256: pack_id.to_string(),
            snapshot_id,
            rows: usize::try_from(rows)?,
            metadata_location: required_metadata_location(&table)?.to_string(),
        });
    }
    let data_file = DataFileBuilder::default()
        .content(DataContentType::Data)
        .file_path(file_path.to_string())
        .file_format(DataFileFormat::Parquet)
        .partition_spec_id(table.metadata().default_partition_spec_id())
        .partition(Struct::from_iter([Some(Literal::int(event_hour))]))
        .record_count(rows)
        .file_size_in_bytes(file_size)
        .build()?;
    let mut properties = HashMap::from([
        ("nano.tenant-id".to_string(), tenant_id.to_string()),
        (
            GENERATION_READY_PROPERTY.to_string(),
            GENERATION_READY_VALUE.to_string(),
        ),
        (OUTBOX_BATCH_PROPERTY.to_string(), pack_id.to_string()),
    ]);
    for (key, value) in profile.snapshot_properties() {
        properties.insert(key.to_string(), value);
    }
    let commit_uuid = uuid::Uuid::from_slice(&hex::decode(pack_id)?[..16])?;
    let mut last_error = None;
    for _ in 0..5 {
        let transaction = Transaction::new(&table);
        let action = transaction
            .fast_append()
            .set_commit_uuid(commit_uuid)
            .set_snapshot_properties(properties.clone())
            .add_data_files([data_file.clone()]);
        match action.apply(transaction)?.commit(catalog).await {
            Ok(committed) => {
                let snapshot = committed
                    .metadata()
                    .current_snapshot()
                    .context("tail-pack registration committed no Iceberg snapshot")?;
                if snapshot
                    .summary()
                    .additional_properties
                    .get(OUTBOX_BATCH_PROPERTY)
                    .map(String::as_str)
                    != Some(pack_id)
                    || snapshot
                        .summary()
                        .additional_properties
                        .get(GENERATION_READY_PROPERTY)
                        .map(String::as_str)
                        != Some(GENERATION_READY_VALUE)
                {
                    bail!("tail-pack registration omitted its publication fences");
                }
                return Ok(EventPublishResult {
                    status: "compacted",
                    batch_sha256: pack_id.to_string(),
                    snapshot_id: snapshot.snapshot_id(),
                    rows: usize::try_from(rows)?,
                    metadata_location: required_metadata_location(&committed)?.to_string(),
                });
            }
            Err(error) => last_error = Some(error),
        }
        table = catalog.load_table(table_id).await?;
        if let Some(snapshot_id) = snapshot_for_batch(&table, pack_id) {
            return Ok(EventPublishResult {
                status: "no_change",
                batch_sha256: pack_id.to_string(),
                snapshot_id,
                rows: usize::try_from(rows)?,
                metadata_location: required_metadata_location(&table)?.to_string(),
            });
        }
    }
    Err(last_error
        .context("Iceberg tail-pack registration exhausted optimistic retries")?
        .into())
}

/// Encode a canonical micro-batch into deterministic Parquet objects under
/// the assigned table's `data/tail` prefix without mutating Iceberg metadata.
/// The caller must publish each object with an immutable version identity and
/// durably ledger that exact identity before exposing a signed tail manifest.
pub fn encode_staged_event_files(
    table: &Table,
    tenant_id: &str,
    rows: &[EventRow],
) -> Result<Vec<StagedEventFile>> {
    let normalized = NormalizedEventBatch::normalize(rows, tenant_id)?;
    encode_staged_event_files_normalized(table, &normalized)
}

/// `encode_staged_event_files` for a batch the caller has already normalised.
/// The opaque batch binds its normalized values to the tenant, event-hour
/// partitions, and pre-decoration source digest used in staged object paths.
pub fn encode_staged_event_files_normalized(
    table: &Table,
    normalized: &NormalizedEventBatch,
) -> Result<Vec<StagedEventFile>> {
    normalized.validate_for_staging()?;
    let digest = normalized
        .source_batch_sha256()
        .context("normalized event batch source identity was not sealed")?;
    let arrow_schema: Arc<ArrowSchema> = Arc::new(
        table
            .metadata()
            .current_schema()
            .as_ref()
            .try_into()
            .context("convert Iceberg OCSF schema to Arrow for staged tail")?,
    );
    let root_type = DataType::Struct(arrow_schema.fields().clone());
    let mut by_hour = BTreeMap::<i32, Vec<&Value>>::new();
    for (hour, row) in normalized.event_hours.iter().zip(&normalized.rows) {
        let event = &row.ocsf_event;
        validate_physical_shape(event, &root_type, "")?;
        by_hour.entry(*hour).or_default().push(event);
    }
    // NAN-2361: 4_096-row groups amortise nothing against a 261-column OCSF
    // schema -- dictionaries never pay off, RLE runs stay short, and
    // per-column-chunk metadata is written 261 times per 4k rows. Measured by
    // re-encoding a REAL 163k-row generation pack with the codec unchanged:
    // rg 4_096 -> 65_536 is 248.0 -> 217.5 B/row; -> 262_144 at zstd-9 is 201.5.
    //
    // Levels are deliberately NOT raised: the same measurement put zstd-3/6/9 at
    // 27.2/28.7/27.6 B/row, i.e. noise beside row-group size, and zstd-12 bought
    // 2% for a steep write cost. Row groups only move chunk boundaries, so this
    // is free; a level bump is paid on every batch. Staged objects stay at 6
    // because they are short-lived and on the ingest latency path.
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
        .set_max_row_group_row_count(Some(65_536))
        .build();
    // The hot-tail ledger deliberately owns one exact object per
    // (source batch, event hour). Keep that durable identity stable: splitting
    // one hour into parallel Parquet parts would require a coordinated schema
    // and replay-contract migration, not a local encoder optimization.
    let mut files = Vec::with_capacity(by_hour.len());
    for (event_hour, events) in by_hour {
        let min_time_ms = events
            .iter()
            .filter_map(|event| ocsf_time_millis(event.get("time")))
            .min()
            .context("staged event hour has no minimum event time")?;
        let max_time_ms = events
            .iter()
            .filter_map(|event| ocsf_time_millis(event.get("time")))
            .max()
            .context("staged event hour has no maximum event time")?;
        let batches = json_batches_refs(arrow_schema.clone(), &events)?;
        let mut writer =
            ArrowWriter::try_new(Vec::new(), arrow_schema.clone(), Some(properties.clone()))?;
        for batch in batches {
            writer.write(&batch)?;
        }
        let bytes = writer.into_inner()?;
        if bytes.is_empty() {
            bail!("staged event publication produced an empty Parquet object");
        }
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let relative_path = content_addressed_staged_path(
            &normalized.tenant_id,
            event_hour,
            "batch",
            digest,
            &sha256,
        )?;
        files.push(StagedEventFile {
            event_hour,
            min_time_ms,
            max_time_ms,
            relative_path,
            rows: u64::try_from(events.len())?,
            duplicate_rows_removed: 0,
            bytes,
            sha256,
        });
    }
    if files.is_empty() {
        bail!("staged event publication produced no Parquet objects");
    }
    Ok(files)
}

pub(crate) fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Bind a staged object's physical key to both its logical row-set identity
/// and the exact Parquet bytes. The latter matters because an additive schema
/// commit can legitimately change a retry's encoded null columns without
/// changing its canonical event rows.
pub(crate) fn content_addressed_staged_path(
    tenant_id: &str,
    event_hour: i32,
    object_kind: &str,
    logical_sha256: &str,
    object_sha256: &str,
) -> Result<String> {
    if tenant_id.is_empty()
        || !matches!(object_kind, "batch" | "pack")
        || !is_lower_sha256(logical_sha256)
        || !is_lower_sha256(object_sha256)
    {
        bail!("staged object content identity is invalid");
    }
    let tenant_sha256 = hex::encode(Sha256::digest(tenant_id.as_bytes()));
    Ok(format!(
        "data/tail/tenant_sha256={tenant_sha256}/event_hour={event_hour}/{object_kind}-{logical_sha256}-{object_sha256}.parquet"
    ))
}

/// NAN-3401: the event table's schema can never admit this batch, whatever
/// the catalog or object store does next. Inference of the batch's own shape,
/// a changed physical type, and an Iceberg schema update the library refuses
/// (`PreconditionFailed` / `DataInvalid`, e.g. a full-name collision) are all
/// pure functions of the batch and the live schema, so repeating the drain
/// cannot change the answer. The Bronze publisher treats this as a permanent
/// refusal and quarantines the batch after a bounded number of drains, instead
/// of retrying it ahead of every later batch forever.
#[derive(Debug, thiserror::Error)]
#[error("Iceberg event schema refused this batch: {detail}")]
pub struct SchemaAdmissionRefused {
    pub detail: String,
}

impl SchemaAdmissionRefused {
    fn wrap(error: impl std::fmt::Display) -> anyhow::Error {
        anyhow::Error::new(Self {
            detail: format!("{error:#}"),
        })
    }
}

/// True when `error` carries [`SchemaAdmissionRefused`] anywhere in its chain.
pub fn is_schema_admission_refused(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<SchemaAdmissionRefused>().is_some())
}

/// An Iceberg error raised by validating the requested schema itself, not by
/// the catalog round trip (a commit conflict is `CatalogCommitConflicts`).
fn iceberg_schema_refusal(error: &iceberg::Error) -> bool {
    matches!(
        error.kind(),
        iceberg::ErrorKind::PreconditionFailed | iceberg::ErrorKind::DataInvalid
    )
}

#[derive(Debug, Clone, PartialEq)]
struct AdditiveColumn {
    parent: Option<String>,
    name: String,
    field_type: Type,
}

/// Add optional fields present in an admitted OCSF batch but absent from the
/// current Iceberg schema. Existing Parquet objects read the additions as null.
/// A changed physical type still fails closed and requires an immutable schema
/// generation rewrite.
///
/// Query workers are pinned to exact metadata objects. They do not observe the
/// metadata-only commit in place; normal composite-generation activation moves
/// them to a later snapshot and matching derivatives. Until then their strict
/// projected reads safely omit fields they do not know about.
pub async fn ensure_additive_event_schema(
    catalog: &RestCatalog,
    table_id: &TableIdent,
    table_location: &str,
    tenant_id: &str,
    rows: &[EventRow],
) -> Result<Table> {
    let normalized = NormalizedEventBatch::normalize(rows, tenant_id)?;
    ensure_additive_event_schema_normalized(catalog, table_id, table_location, &normalized).await
}

/// One publisher's last admitted schema, bounded by catalog refresh time.
#[derive(Default)]
pub struct EventSchemaAdmissionCache {
    admitted: Option<(TableIdent, String, Table, std::time::Instant)>,
}

impl EventSchemaAdmissionCache {
    pub fn clear(&mut self) {
        self.admitted = None;
    }

    fn covered_table(
        &self,
        table_id: &TableIdent,
        table_location: &str,
        normalized: &NormalizedEventBatch,
        cache_coverage: bool,
        now: std::time::Instant,
    ) -> Result<Option<Table>> {
        if let Some((identity, schema_sha256, table, admitted_at)) = &self.admitted {
            if identity == table_id
                && now.duration_since(*admitted_at) < std::time::Duration::from_secs(60)
                && table.metadata().location().trim_end_matches('/') == table_location.trim_end_matches('/')
                && table.metadata().properties().get("nano.tenant-id") == Some(&normalized.tenant_id)
                && batch_within_current_schema_cached(table, normalized, cache_coverage)?
            {
                tracing::debug!(schema_sha256, "reused admitted event schema");
                return Ok(Some(table.clone()));
            }
        }
        Ok(None)
    }

    pub async fn admit(
        &mut self,
        catalog: &RestCatalog,
        table_id: &TableIdent,
        table_location: &str,
        normalized: &NormalizedEventBatch,
        cache_coverage: bool,
    ) -> Result<Table> {
        normalized.validate_for_staging()?;
        if let Some(table) = self.covered_table(
            table_id, table_location, normalized, cache_coverage, std::time::Instant::now(),
        )? {
            return Ok(table);
        }
        // Do not retain an old success after a failed refresh or type conflict.
        self.clear();
        let table = ensure_additive_event_schema_with_cache(
            catalog, table_id, table_location, normalized, cache_coverage,
        ).await?;
        let schema_sha256 = hex::encode(Sha256::digest(
            serde_json::to_vec(table.metadata().current_schema().as_ref())?,
        ));
        self.admitted = Some((table_id.clone(), schema_sha256, table.clone(), std::time::Instant::now()));
        Ok(table)
    }
}

/// `ensure_additive_event_schema` for a batch the caller has already
/// normalised, so a publish path does not pay a second normalisation pass over
/// rows it just normalised.
pub async fn ensure_additive_event_schema_normalized(
    catalog: &RestCatalog,
    table_id: &TableIdent,
    table_location: &str,
    normalized: &NormalizedEventBatch,
) -> Result<Table> {
    ensure_additive_event_schema_with_cache(catalog, table_id, table_location, normalized, false).await
}

#[cfg(test)]
pub(crate) fn pipeline_test_table(
    normalized: &NormalizedEventBatch,
    location: &str,
) -> Result<TableCreation> {
    let arrow = prune_inferred_null_fields(infer_generation_schema_values(normalized)?.as_ref())?;
    let schema = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(arrow.as_ref())?;
    let time_id = schema
        .field_by_name("time")
        .context("test schema time missing")?
        .id;
    let mut properties = event_table_properties(&normalized.tenant_id);
    properties.remove("format-version");
    Ok(TableCreation::builder()
        .name("events".to_string())
        .location(location.to_string())
        .schema(schema)
        .partition_spec(hour_partition_spec(time_id)?)
        .properties(properties)
        .build())
}

/// Event uid of the schema-only bootstrap seed. The seed is never written.
const BOOTSTRAP_SEED_EVENT_UID: &str = "nano-bootstrap-schema-seed";

/// The canonical OCSF 1.9 attributes every admitted source row carries,
/// shaped exactly as the Vector lake storage stage writes them. It exists only
/// to give a fresh table its first schema; real batches widen it additively.
fn bootstrap_seed_batch(tenant_id: &str) -> Result<NormalizedEventBatch> {
    let raw_data = "nano bootstrap schema seed";
    let row = EventRow {
        event_uid: BOOTSTRAP_SEED_EVENT_UID.to_string(),
        event_kind: EventKind::Source,
        ocsf_event: serde_json::json!({
            "activity_id": 0,
            "category_uid": 0,
            "class_uid": 0,
            "message": raw_data,
            "metadata": {
                "log_source": "unknown",
                "logged_time": 1_767_225_600_000_i64,
                "processed_time": 1_767_225_600_000_i64,
                "product": {"name": "Nano Generic Source", "vendor_name": "nano"},
                "tenant_uid": tenant_id,
                "uid": BOOTSTRAP_SEED_EVENT_UID,
                "version": OCSF_VERSION,
            },
            "raw_data": raw_data,
            "raw_data_size": raw_data.len(),
            "severity_id": 1,
            "time": 1_767_225_600_000_i64,
            "type_uid": 0,
        }),
    };
    NormalizedEventBatch::normalize(std::slice::from_ref(&row), tenant_id)
}

/// NAN-3366: make sure a self-hosted install's event table exists before any
/// event has been published, and report whether this call created it.
///
/// The table used to be created only by the first published Bronze batch.
/// On a fresh open-core install that batch can never happen: nano-api waits
/// for the query worker's schema, the worker waits for a first generation,
/// the generation manager waits for the table, and the Vector lake sink that
/// would feed the table is rendered by nano-api. Creating the empty table up
/// front lets the generation manager install the zero-snapshot bootstrap
/// generation, which breaks that cycle without any data.
///
/// The table is created through the same additive-schema admission the Bronze
/// publisher uses (same inference, partition spec, tenant binding, and
/// location), from a schema-only seed of canonical base attributes. Nothing
/// is committed to it, so it has no snapshot. hosted-shared tables are
/// owner-provisioned, so this refuses to run there.
pub async fn ensure_bootstrap_event_table(
    catalog: &impl Catalog,
    table_id: &TableIdent,
    table_location: &str,
    tenant_id: &str,
) -> Result<bool> {
    if crate::shared_mode::active() {
        bail!("enterprise_shared event tables are owner-provisioned; refusing to create one");
    }
    // Some catalogs report a table lookup in a missing namespace as an error
    // rather than "no table", so the namespace comes first.
    if !catalog.namespace_exists(&table_id.namespace).await? {
        catalog
            .create_namespace(&table_id.namespace, HashMap::new())
            .await
            .context("create the event table namespace for a fresh install")?;
    } else if catalog.table_exists(table_id).await? {
        return Ok(false);
    }
    let seed = bootstrap_seed_batch(tenant_id)?;
    ensure_additive_event_schema_with_cache(catalog, table_id, table_location, &seed, false)
        .await
        .context("create the empty OCSF event table for a fresh install")?;
    Ok(true)
}

pub async fn ensure_additive_event_schema_with_cache(
    catalog: &impl Catalog,
    table_id: &TableIdent,
    table_location: &str,
    normalized: &NormalizedEventBatch,
    cache_coverage: bool,
) -> Result<Table> {
    normalized.validate_for_staging()?;
    if !table_location.starts_with("s3://")
        || table_location.len() > 2_048
        || table_location.chars().any(char::is_control)
    {
        bail!("additive schema admission requires one to 250000 events");
    }

    // NAN-2380: the steady state is "this batch introduces no new OCSF field".
    // Answering that by re-serialising the whole batch to JSON and re-parsing
    // it through Arrow inference cost ~90% of the publisher's CPU (~3.5 ms per
    // event at 200 eps, a full core). Answer it from the values already in
    // memory instead, and fall through to full inference the moment anything
    // is not PROVABLY covered by the live schema. A false negative here only
    // buys the slow path; it can never skip an addition or a fail-closed type
    // conflict, because every such case leaves the batch "not covered".
    if catalog.table_exists(table_id).await? {
        let table =
            load_bound_event_table(catalog, table_id, table_location, &normalized.tenant_id)
                .await?;
        if batch_within_current_schema_cached(&table, normalized, cache_coverage)? {
            return Ok(table);
        }
    }

    // Loading the exact tenant-bound schema and proving that a batch is
    // already covered is read-only. A missing hosted-shared table still
    // fails closed: only owner-provisioned tables can use the tenant Worker's
    // exact additive-schema broker, and that broker exposes no create route.
    if crate::shared_mode::active() && !catalog.table_exists(table_id).await? {
        bail!("enterprise_shared additive schema admission requires an owner-provisioned table");
    }
    crate::shared_mode::require_additive_schema_broker_authority()?;

    let proposed_arrow = infer_generation_schema_values(normalized)
        .and_then(|inferred| prune_inferred_null_fields(inferred.as_ref()))
        .map_err(SchemaAdmissionRefused::wrap)?;
    let proposed = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(proposed_arrow.as_ref())
        .context("convert admitted OCSF batch schema to Iceberg")
        .map_err(SchemaAdmissionRefused::wrap)?;

    if !catalog.table_exists(table_id).await? {
        let time_field_id = proposed
            .field_by_name("time")
            .context("admitted OCSF schema has no time field")?
            .id;
        if !catalog.namespace_exists(&table_id.namespace).await? {
            catalog
                .create_namespace(&table_id.namespace, HashMap::new())
                .await?;
        }
        let creation = TableCreation::builder()
            .name(table_id.name.clone())
            .location(table_location.trim_end_matches('/').to_string())
            .schema(proposed.clone())
            .partition_spec(hour_partition_spec(time_field_id)?)
            .properties(event_table_properties(&normalized.tenant_id))
            .build();
        match catalog.create_table(&table_id.namespace, creation).await {
            Ok(table) => return Ok(table),
            Err(error) if catalog.table_exists(table_id).await? => {
                tracing::info!(
                    table = %table_id,
                    error = %error,
                    "another publisher created the Iceberg event table"
                );
            }
            Err(error) if iceberg_schema_refusal(&error) => {
                return Err(SchemaAdmissionRefused::wrap(
                    anyhow::Error::new(error).context("create initial OCSF Iceberg event table"),
                ));
            }
            Err(error) => return Err(error).context("create initial OCSF Iceberg event table"),
        }
    }

    let mut last_error = None;
    for _ in 0..5 {
        let table =
            load_bound_event_table(catalog, table_id, table_location, &normalized.tenant_id)
                .await?;

        let additions = additive_columns(
            &Type::Struct(table.metadata().current_schema().as_struct().clone()),
            &Type::Struct(proposed.as_struct().clone()),
            None,
        )
        .map_err(SchemaAdmissionRefused::wrap)?;
        if additions.is_empty() {
            return Ok(table);
        }

        let mut action = Transaction::new(&table).update_schema();
        for addition in additions {
            let column = if let Some(parent) = addition.parent {
                AddColumn::builder()
                    .name(addition.name)
                    .field_type(addition.field_type)
                    .parent(parent)
                    .build()
            } else {
                AddColumn::optional(addition.name, addition.field_type)
            };
            action = action.add_column(column);
        }
        match action
            .apply(Transaction::new(&table))?
            .commit(catalog)
            .await
        {
            Ok(committed) => return Ok(committed),
            // A schema refusal is NOT final on its own: the transaction's
            // internal conflict retry re-applies the action to a refreshed
            // table, so a concurrent shard that already added the same column
            // surfaces here as "name already exists". The next iteration
            // reloads and recomputes (usually: nothing left to add). Only a
            // refusal that persists against the freshly loaded schema on the
            // last attempt is classified as permanent below.
            Err(error) => last_error = Some(error),
        }
    }
    let error = last_error.context("Iceberg additive schema admission exhausted optimistic retries")?;
    if iceberg_schema_refusal(&error) {
        return Err(SchemaAdmissionRefused::wrap(
            anyhow::Error::new(error).context("Iceberg refused the additive OCSF schema"),
        ));
    }
    Err(anyhow::Error::new(error)
        .context("Iceberg additive schema admission exhausted optimistic retries"))
}

/// Normalise a batch once so every downstream consumer -- schema admission and
/// staged Parquet encoding -- shares one pass instead of repeating it.
///
/// NAN-2380: `normalize_event` previously ran three times per row per drain
/// cycle (admission, schema admission, staged encoding) with only the admission
/// pass instrumented.
pub fn normalize_batch(rows: &[EventRow], tenant_id: &str) -> Result<NormalizedEventBatch> {
    NormalizedEventBatch::normalize(rows, tenant_id)
}

/// Load the event table and re-assert the tenant and location bindings that
/// make it the table this publisher is allowed to write.
async fn load_bound_event_table(
    catalog: &impl Catalog,
    table_id: &TableIdent,
    table_location: &str,
    tenant_id: &str,
) -> Result<Table> {
    let table = catalog
        .load_table(table_id)
        .await
        .context("load Iceberg event table for additive schema admission")?;
    if table
        .metadata()
        .properties()
        .get("nano.tenant-id")
        .map(String::as_str)
        != Some(tenant_id)
    {
        bail!("Iceberg event table tenant binding changed");
    }
    if table.metadata().location().trim_end_matches('/') != table_location.trim_end_matches('/') {
        bail!("Iceberg event table location changed");
    }
    Ok(table)
}

/// True when every event in the batch is already representable by the table's
/// live schema, so additive admission has nothing to do and the batch never
/// needs full JSON schema inference.
enum SchemaCoverage {
    Struct(HashMap<String, SchemaCoverage>),
    List(Box<SchemaCoverage>),
    Scalar(DataType),
}

impl SchemaCoverage {
    fn compile(data_type: &DataType) -> Self {
        match data_type {
            DataType::Struct(fields) => Self::Struct(
                fields
                    .iter()
                    .map(|field| (field.name().clone(), Self::compile(field.data_type())))
                    .collect(),
            ),
            DataType::List(field)
            | DataType::LargeList(field)
            | DataType::ListView(field)
            | DataType::LargeListView(field)
            | DataType::FixedSizeList(field, _) => {
                Self::List(Box::new(Self::compile(field.data_type())))
            }
            other => Self::Scalar(other.clone()),
        }
    }

    fn covers(&self, value: &Value) -> bool {
        if physically_null(value) {
            return true;
        }
        match (self, value) {
            (Self::Struct(fields), Value::Object(values)) => values.iter().all(|(name, value)| {
                physically_null(value) || fields.get(name).is_some_and(|field| field.covers(value))
            }),
            (Self::List(element), Value::Array(values)) => {
                values.iter().all(|value| element.covers(value))
            }
            (Self::Scalar(data_type), value) => value_covered_by(value, data_type),
            _ => false,
        }
    }
}

fn batch_within_current_schema_cached(
    table: &Table,
    normalized: &NormalizedEventBatch,
    enabled: bool,
) -> Result<bool> {
    // Cache only the schema-derived type tree, never an admission verdict or
    // a table binding. Every pass still validates the live tenant/location and
    // every value, including fields introduced after the first row.
    static CACHE: std::sync::OnceLock<std::sync::Mutex<BTreeMap<String, Arc<SchemaCoverage>>>> =
        std::sync::OnceLock::new();
    let schema = table.metadata().current_schema();
    let compile = || -> Result<DataType> {
        let arrow: ArrowSchema = schema
            .as_ref()
            .try_into()
            .context("convert Iceberg OCSF schema to Arrow for schema coverage")?;
        Ok(DataType::Struct(arrow.fields().clone()))
    };
    if !enabled {
        let root = compile()?;
        return Ok(normalized
            .rows
            .iter()
            .all(|row| value_covered_by(&row.ocsf_event, &root)));
    }
    let root = {
        let digest = hex::encode(Sha256::digest(serde_json::to_vec(schema.as_ref())?));
        let mut cache = CACHE
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| anyhow::anyhow!("schema coverage cache lock poisoned"))?;
        if let Some(root) = cache.get(&digest) {
            root.clone()
        } else {
            let root = Arc::new(SchemaCoverage::compile(&compile()?));
            if cache.len() >= 32 {
                cache.clear();
            }
            cache.insert(digest, root.clone());
            root
        }
    };
    Ok(normalized
        .rows
        .iter()
        .all(|row| root.covers(&row.ocsf_event)))
}

/// True only when `value` is PROVABLY representable by `data_type` as it
/// already exists in the live schema.
///
/// Deliberately conservative in one direction only: anything unrecognised
/// returns false, which routes the batch through full inference and leaves
/// every existing add-column and fail-closed type decision untouched. It is
/// therefore never a correctness risk to be too strict here, only a
/// performance one -- and being too lax is impossible by construction, because
/// a missing field or a primitive that does not match its declared type both
/// fall through to `false`.
///
/// A null child is "covered" regardless of the schema: JSON-to-Arrow inference
/// gives an all-null field no physical column, so a sparse row carrying that
/// null must not force a schema addition. This mirrors `validate_physical_shape`.
fn value_covered_by(value: &Value, data_type: &DataType) -> bool {
    if physically_null(value) {
        return true;
    }
    match (value, data_type) {
        (Value::Object(values), DataType::Struct(fields)) => values.iter().all(|(name, child)| {
            physically_null(child)
                || fields
                    .iter()
                    .find(|field| field.name() == name)
                    .is_some_and(|field| value_covered_by(child, field.data_type()))
        }),
        (Value::Object(values), DataType::Map(field, _)) => {
            let DataType::Struct(entries) = field.data_type() else {
                return false;
            };
            let Some(value_type) = entries
                .iter()
                .find(|entry| entry.name() == "value")
                .map(|entry| entry.data_type())
            else {
                return false;
            };
            values
                .values()
                .all(|child| value_covered_by(child, value_type))
        }
        (
            Value::Array(values),
            DataType::List(field)
            | DataType::LargeList(field)
            | DataType::ListView(field)
            | DataType::LargeListView(field)
            | DataType::FixedSizeList(field, _),
        ) => values
            .iter()
            .all(|child| value_covered_by(child, field.data_type())),
        (Value::Bool(_), DataType::Boolean) => true,
        // The accepted sets below are exactly what `additive_columns` would
        // have let through, and no wider. It widens Double <- Float|Int|Long
        // and Long <- Int, and bails on everything else -- notably it never
        // widens Long <- Double. Anything outside these sets must fall through
        // to `false` so the slow path still raises that fail-closed error.
        (Value::Number(number), data_type) => {
            if number.is_f64() {
                // Arrow JSON inference types any fractional number as Float64.
                // A fractional value sitting in an integer column is a type
                // conflict, not a coverage question.
                matches!(data_type, DataType::Float64 | DataType::Timestamp(_, _))
            } else {
                // Integers infer as Int64 (Iceberg Long), which is accepted
                // against Long (equal) and Double (widening).
                matches!(
                    data_type,
                    DataType::Int64 | DataType::Float64 | DataType::Timestamp(_, _)
                )
            }
        }
        // Timestamp is admissible for a string because `infer_generation_schema`
        // rewrites exactly one field -- `time` -- to Timestamp, and `time` is
        // the RFC3339 string every normalised event carries. No other column
        // reaches Timestamp through inference.
        (Value::String(_), data_type) => matches!(
            data_type,
            DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View | DataType::Timestamp(_, _)
        ),
        _ => false,
    }
}

fn event_table_properties(tenant_id: &str) -> HashMap<String, String> {
    HashMap::from([
        ("format-version".to_string(), "2".to_string()),
        (
            "write.parquet.compression-codec".to_string(),
            "zstd".to_string(),
        ),
        (
            "write.metadata.delete-after-commit.enabled".to_string(),
            "false".to_string(),
        ),
        (
            "write.metadata.previous-versions-max".to_string(),
            "10".to_string(),
        ),
        ("nano.ocsf-version".to_string(), OCSF_VERSION.to_string()),
        ("nano.tenant-id".to_string(), tenant_id.to_string()),
    ])
}

fn prune_inferred_null_fields(schema: &ArrowSchema) -> Result<ArrowSchema> {
    let fields = schema
        .fields()
        .iter()
        .filter_map(|field| {
            prune_inferred_null_type(field.data_type())
                .map(|data_type| Arc::new(field.as_ref().clone().with_data_type(data_type)))
        })
        .collect::<Vec<_>>();
    if fields.is_empty() {
        bail!("admitted OCSF batch inferred no typed Iceberg fields");
    }
    Ok(ArrowSchema::new_with_metadata(
        fields,
        schema.metadata().clone(),
    ))
}

fn prune_inferred_null_type(data_type: &DataType) -> Option<DataType> {
    match data_type {
        DataType::Null => None,
        DataType::Struct(fields) => {
            let fields = fields
                .iter()
                .filter_map(|field| {
                    prune_inferred_null_type(field.data_type())
                        .map(|data_type| Arc::new(field.as_ref().clone().with_data_type(data_type)))
                })
                .collect::<Vec<_>>();
            (!fields.is_empty()).then(|| DataType::Struct(fields.into()))
        }
        DataType::List(field) => prune_inferred_null_type(field.data_type()).map(|data_type| {
            DataType::List(Arc::new(field.as_ref().clone().with_data_type(data_type)))
        }),
        DataType::LargeList(field) => {
            prune_inferred_null_type(field.data_type()).map(|data_type| {
                DataType::LargeList(Arc::new(field.as_ref().clone().with_data_type(data_type)))
            })
        }
        DataType::FixedSizeList(field, size) => {
            prune_inferred_null_type(field.data_type()).map(|data_type| {
                DataType::FixedSizeList(
                    Arc::new(field.as_ref().clone().with_data_type(data_type)),
                    *size,
                )
            })
        }
        DataType::Map(field, sorted) => {
            prune_inferred_null_type(field.data_type()).map(|data_type| {
                DataType::Map(
                    Arc::new(field.as_ref().clone().with_data_type(data_type)),
                    *sorted,
                )
            })
        }
        data_type => Some(data_type.clone()),
    }
}

fn additive_columns(
    current: &Type,
    proposed: &Type,
    parent: Option<&str>,
) -> Result<Vec<AdditiveColumn>> {
    let mut additions = Vec::new();
    collect_additive_columns(current, proposed, parent, &mut additions)?;
    additions.sort_by(|left, right| {
        (left.parent.as_deref(), left.name.as_str())
            .cmp(&(right.parent.as_deref(), right.name.as_str()))
    });
    Ok(additions)
}

/// Rows buffered per row group before sorting. Bounds memory: the packer stays
/// streaming and never materialises a whole pack.
///
/// Measured on a real 238,500-row pack: a GLOBAL sort (whole file in memory)
/// reaches 1.15x, a 131,072-row chunked sort reaches 1.14x — 98% of the benefit
/// without the memory shape that OOM-looped the bronze publisher.
const PACK_SORT_BUFFER_ROWS: usize = 131_072;

/// Reorder one buffered row group by (low-cardinality key, time).
///
/// This is the lever ClickHouse gets for free: Saturn's ORDER BY on this same
/// data is `(source_type, timestamp, src_host, src_ip, cityHash64(id))` — a
/// low-cardinality field FIRST, then time — and it reaches 131 B/row where the
/// lake's arrival order sits at 201.5. Equal values landing adjacent is what
/// lets dictionary / RLE / delta encodings find long runs.
///
/// Measured gains at rg=262_144 zstd-9 on a real pack:
///   (metadata, time)  201.5 -> 169.3 B/row  (1.19x)
///   (class_uid, time) 201.5 -> 174.9        (1.15x)
///   (time, time)      201.5 -> 201.5        (1.00x — already time-ordered)
///
/// The trade is that a row group's time range widens, so time pruning INSIDE a
/// file gets coarser. That is the same trade ClickHouse already makes here, and
/// the lake bounds it better: packs are partitioned by event_hour, finer than
/// Saturn's daily partitions.
/// True for any type that carries a comparable scalar value.
///
/// NAN-2361: this is an EXCLUDE list on purpose. An allow-list of
/// `is_primitive() || Utf8` silently drops `Utf8View` / `LargeUtf8` /
/// `Dictionary` / `Boolean`, so a metadata field whose arrow type drifts would
/// leave the clustering key with no error and no failing test -- and a
/// narrowed key costs real bytes (see `pack_sort_key_columns`).
fn is_clusterable_key_type(data_type: &DataType) -> bool {
    !matches!(
        data_type,
        DataType::Struct(_)
            | DataType::List(_)
            | DataType::LargeList(_)
            | DataType::FixedSizeList(_, _)
            | DataType::ListView(_)
            | DataType::LargeListView(_)
            | DataType::Map(_, _)
            | DataType::Union(_, _)
            | DataType::Null
    )
}

/// The clustering key for a pack buffer: every scalar column of `metadata`, in
/// struct order, falling back to top-level `class_uid`.
///
/// Sorting the FULL set of metadata columns is load-bearing, not tidiness. The
/// original implementation stringified the whole struct, which was implicitly a
/// multi-column lexicographic sort over all 13 fields, and that is what gives
/// event_code / log_name / log_provider long RLE runs. Measured on 324k real
/// rows at zstd-9 rg=262_144:
///
/// ```text
///   arrival order                 151.6 B/row
///   whole-struct Debug string     136.8
///   all scalar columns (this)     137.0
///   log_source ALONE              146.2   <-- a narrowed key costs 6.9%
/// ```
///
/// Nested children are excluded because they are not lexsort-comparable; that
/// is free here, since `product` and `profiles` hold 5 and 4 distinct values
/// and are fully correlated with the scalar fields (measured at +0.00%).
fn pack_sort_key_columns(batch: &RecordBatch) -> Vec<arrow_array::ArrayRef> {
    use arrow_array::{ArrayRef, StructArray};

    let mut key_columns: Vec<ArrayRef> = batch
        .column_by_name("metadata")
        .and_then(|metadata| metadata.as_any().downcast_ref::<StructArray>())
        .map(|metadata| {
            metadata
                .columns()
                .iter()
                .filter(|column| is_clusterable_key_type(column.data_type()))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    // Fall through when `metadata` is absent OR carries no clusterable child --
    // an all-nested struct must still get the class_uid key, not silently land
    // in arrival order.
    if key_columns.is_empty() {
        key_columns.extend(batch.column_by_name("class_uid").cloned());
    }
    key_columns
}

pub(crate) fn sort_pack_buffer(batch: &RecordBatch) -> Result<RecordBatch> {
    sort_pack_buffer_for(batch, TailIdentityProfile::Ocsf)
}

pub(crate) fn sort_pack_buffer_for(batch: &RecordBatch, profile: TailIdentityProfile) -> Result<RecordBatch> {
    use arrow_ord::sort::{lexsort_to_indices, SortColumn};

    let rows = batch.num_rows();
    if rows < 2 {
        return Ok(batch.clone());
    }

    // A missing key must never fail a pack -- this is an optimisation, and
    // arrival order is always a valid ordering.
    //
    // NAN-2361: the key is built from typed columns, never by Debug-formatting
    // a column slice. The previous implementation called
    // `format!("{:?}", col.slice(i, 1))` from inside the `sort_by` closure, so
    // every one of the O(n log n) comparisons allocated two Strings and
    // formatted a nested struct -- 3.79s per 131k-row buffer in release, vs
    // 93ms here. It also ordered `time` as TEXT, which sorts correctly only
    // while every value happens to share a digit count.
    let key_columns = if profile.is_otel() {
        profile
            .sort_key_names()
            .iter()
            .filter_map(|name| batch.column_by_name(name).cloned())
            .filter(|column| is_clusterable_key_type(column.data_type()))
            .collect::<Vec<_>>()
    } else {
        pack_sort_key_columns(batch)
    };
    if key_columns.is_empty() {
        return Ok(batch.clone());
    }

    let mut sort_columns: Vec<SortColumn> = key_columns
        .into_iter()
        .map(|values| SortColumn {
            values,
            options: None,
        })
        .collect();
    if let Some(time) = batch.column_by_name(profile.time_column()) {
        sort_columns.push(SortColumn {
            values: time.clone(),
            options: None,
        });
    }

    // Fail open: an unsortable key type must not cost us the pack.
    let indices = match lexsort_to_indices(&sort_columns, None) {
        Ok(indices) => indices,
        Err(error) => {
            tracing::warn!(%error, "pack buffer left in arrival order; sort key unsupported");
            return Ok(batch.clone());
        }
    };

    let columns = batch
        .columns()
        .iter()
        .map(|column| arrow_select::take::take(column.as_ref(), &indices, None))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("reorder pack buffer")?;
    RecordBatch::try_new(batch.schema(), columns).context("rebuild sorted pack buffer")
}

fn collect_additive_columns(
    current: &Type,
    proposed: &Type,
    parent: Option<&str>,
    additions: &mut Vec<AdditiveColumn>,
) -> Result<()> {
    match (current, proposed) {
        (Type::Struct(current), Type::Struct(proposed)) => {
            for field in proposed.fields() {
                let Some(existing) = current.field_by_name(&field.name) else {
                    additions.push(AdditiveColumn {
                        parent: parent.map(str::to_string),
                        name: field.name.clone(),
                        field_type: field.field_type.as_ref().clone(),
                    });
                    continue;
                };
                let child = match parent {
                    Some(parent) => format!("{parent}.{}", field.name),
                    None => field.name.clone(),
                };
                collect_additive_columns(
                    existing.field_type.as_ref(),
                    field.field_type.as_ref(),
                    Some(&child),
                    additions,
                )?;
            }
            Ok(())
        }
        (Type::List(current), Type::List(proposed)) => collect_additive_columns(
            current.element_field.field_type.as_ref(),
            proposed.element_field.field_type.as_ref(),
            parent,
            additions,
        ),
        (Type::Map(current), Type::Map(proposed)) => {
            if current.key_field.field_type != proposed.key_field.field_type {
                bail!(
                    "OCSF field {} changed its Iceberg map-key type; schema generation rewrite required",
                    parent.unwrap_or("<root>")
                );
            }
            collect_additive_columns(
                current.value_field.field_type.as_ref(),
                proposed.value_field.field_type.as_ref(),
                parent,
                additions,
            )
        }
        (Type::Primitive(current), Type::Primitive(proposed))
            if current == proposed
                || matches!(
                    (current, proposed),
                    (
                        iceberg::spec::PrimitiveType::Long,
                        iceberg::spec::PrimitiveType::Int
                    ) | (
                        iceberg::spec::PrimitiveType::Double,
                        iceberg::spec::PrimitiveType::Float
                            | iceberg::spec::PrimitiveType::Int
                            | iceberg::spec::PrimitiveType::Long
                    )
                ) =>
        {
            Ok(())
        }
        _ => bail!(
            "OCSF field {} changed its Iceberg physical type; schema generation rewrite required",
            parent.unwrap_or("<root>")
        ),
    }
}

/// Row-identity contract of a staged hot-tail object (NAN-2361 wave 7).
///
/// The tail packer and compactor were written for OCSF `events` objects,
/// whose identity is `metadata.uid` with delivery-local `metadata.*` leaves
/// neutralized and whose event time is the `time` column. The hosted-shared
/// OTLP drain (`otel_handoff`) stages native OTLP v1 objects into the same
/// `lake_hot_tail_objects` ledger under `event_table = otel_spans |
/// otel_metrics`; this profile lets the same physical machinery pack, dedupe
/// and commit them with the identities the drain itself uses
/// (`otel_iceberg::normalize_span` / `normalize_metric`):
///
/// * spans: `trace_id:span_id:<start_time micros>` — the same three facts the
///   drain's `row_uid` carries (its nanosecond suffix is not materialized as a
///   column; the Parquet `start_time` is microsecond precision, so two spans
///   that differ only below a microsecond collapse exactly as the drain's
///   `dedupe_otel_batch` would after Parquet encoding);
/// * metrics: the drain's materialized `metric_uid` column (sha256 over the
///   tenant, the point time and the canonical event);
/// * fingerprint: `ingest_time` (the drain's receipt time) is the only
///   delivery-local leaf, so it is neutralized; every other column is the
///   semantic payload and a same-uid/different-payload pair is refused
///   exactly like an OCSF UID conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailIdentityProfile {
    /// OCSF `events`: `metadata.uid` + `time`; `event_hour` partition.
    Ocsf,
    /// Native OTLP v1 spans: `trace_id:span_id:start_time`; `start_time_hour`.
    OtelSpans,
    /// Native OTLP v1 metrics: `metric_uid`; `timestamp_hour`.
    OtelMetrics,
}

impl TailIdentityProfile {
    /// The profile a `lake_hot_tail_objects` row belongs to. OTLP objects are
    /// recognized by the drain's store id (raw objects) or, for packs of
    /// them, by the OTLP `event_table` spelling the drain records.
    pub fn for_hot_tail_object(bronze_store_id: &str, event_table: &str) -> Result<Self> {
        match (bronze_store_id, event_table) {
            (crate::otel_handoff::OTEL_HANDOFF_STORE_ID, "otel_spans") => Ok(Self::OtelSpans),
            (crate::otel_handoff::OTEL_HANDOFF_STORE_ID, "otel_metrics") => Ok(Self::OtelMetrics),
            (crate::otel_handoff::OTEL_HANDOFF_STORE_ID, other) => {
                bail!("OTLP handoff hot-tail object names a foreign event table {other}")
            }
            (_, "otel_spans") => Ok(Self::OtelSpans),
            (_, "otel_metrics") => Ok(Self::OtelMetrics),
            _ => Ok(Self::Ocsf),
        }
    }

    /// The profile of a serving table by its Iceberg table name.
    pub fn for_table_name(table: &str) -> Self {
        match table.rsplit('.').next().unwrap_or(table) {
            "otel_spans" => Self::OtelSpans,
            "otel_metrics" => Self::OtelMetrics,
            _ => Self::Ocsf,
        }
    }

    pub fn is_otel(self) -> bool {
        !matches!(self, Self::Ocsf)
    }

    pub fn otel_dataset(self) -> Option<crate::otel_iceberg::OtelDataset> {
        match self {
            Self::Ocsf => None,
            Self::OtelSpans => Some(crate::otel_iceberg::OtelDataset::Spans),
            Self::OtelMetrics => Some(crate::otel_iceberg::OtelDataset::Metrics),
        }
    }

    /// The canonical event-time column the hour scoping is computed from.
    pub fn time_column(self) -> &'static str {
        match self {
            Self::Ocsf => "time",
            Self::OtelSpans => "start_time",
            Self::OtelMetrics => "timestamp",
        }
    }

    /// The single hour partition field the table must declare.
    pub fn partition_field_name(self) -> &'static str {
        match self {
            Self::Ocsf => "event_hour",
            Self::OtelSpans => "start_time_hour",
            Self::OtelMetrics => "timestamp_hour",
        }
    }

    /// `nano.*` snapshot properties a pack registration carries besides the
    /// tenant, generation-ready and outbox-batch facts. The catalog broker's
    /// `tail_pack_append` admission pins exactly this set per profile.
    pub fn snapshot_properties(self) -> Vec<(&'static str, String)> {
        match self {
            Self::Ocsf => vec![
                ("nano.writer", "rust-vector-tail-pack-registration".to_string()),
                ("nano.ocsf-version", OCSF_VERSION.to_string()),
            ],
            Self::OtelSpans | Self::OtelMetrics => vec![
                ("nano.writer", "rust-otlp-tail-pack-registration".to_string()),
                (
                    "nano.otel-dataset",
                    self.otel_dataset().map(|d| d.as_str()).unwrap_or_default().to_string(),
                ),
                ("nano.otel-schema-version", crate::otel_iceberg::OTEL_ICEBERG_SCHEMA_VERSION.to_string()),
            ],
        }
    }

    /// Columns a packed row group is clustered by before the time column.
    fn sort_key_names(self) -> &'static [&'static str] {
        match self {
            Self::Ocsf => &[],
            Self::OtelSpans => &["service_name", "span_name"],
            Self::OtelMetrics => &["metric_name", "service_name"],
        }
    }

    /// The native Arrow schema the drain wrote, for a pack whose Iceberg
    /// table cannot be loaded (hosted OTLP tables are provisioned by the
    /// platform; the packer must not invent one).
    pub fn native_arrow_schema(self) -> Option<ArrowSchema> {
        self.otel_dataset().map(crate::otel_iceberg::otel_arrow_schema)
    }
}

/// The hosted OTLP query side unions the committed table and the staged
/// mirror POSITIONALLY (`SELECT * ... UNION ALL SELECT * ...`), so a table
/// whose column order differs from the native schema the drain writes would
/// silently misalign columns. Refuse to commit into such a table.
pub fn verify_native_column_order(table: &Table, profile: TailIdentityProfile) -> Result<()> {
    let Some(native) = profile.native_arrow_schema() else {
        return Ok(());
    };
    let table_columns = table
        .metadata()
        .current_schema()
        .as_struct()
        .fields()
        .iter()
        .map(|field| field.name.clone())
        .collect::<Vec<_>>();
    let native_columns = native
        .fields()
        .iter()
        .map(|field| field.name().clone())
        .collect::<Vec<_>>();
    if table_columns != native_columns {
        bail!(
            "OTLP table column order differs from the native {} schema the tail was written with",
            profile.otel_dataset().map(|d| d.as_str()).unwrap_or_default()
        );
    }
    Ok(())
}

/// Physically merge already-admitted staged Parquet objects without repeating
/// JSON conversion or OCSF semantic validation. Callers must verify the exact
/// source object versions and digests first. This function then enforces the
/// current Iceberg Arrow schema on every input batch and produces one immutable
/// transient tail object; it does not mutate Iceberg metadata.
pub fn repack_staged_event_files(
    table: &Table,
    tenant_id: &str,
    event_hour: i32,
    pack_id: &str,
    paths: &[impl AsRef<Path>],
) -> Result<StagedEventFile> {
    repack_staged_event_files_with_compression(table, tenant_id, event_hour, pack_id, paths, 9)
}

/// `repack_staged_event_files` with an explicit zstd level for a deployment
/// whose ingest CPU/storage trade-off has been measured. The default wrapper
/// remains zstd-9; deployers must record any override as part of their capacity
/// profile rather than patching a binary or silently inheriting a test value.
pub fn repack_staged_event_files_with_compression(
    table: &Table,
    tenant_id: &str,
    event_hour: i32,
    pack_id: &str,
    paths: &[impl AsRef<Path>],
    compression_level: i32,
) -> Result<StagedEventFile> {
    let arrow_schema: Arc<ArrowSchema> = Arc::new(
        table
            .metadata()
            .current_schema()
            .as_ref()
            .try_into()
            .context("convert Iceberg OCSF schema to Arrow for tail packing")?,
    );
    repack_staged_files_with_profile(
        arrow_schema,
        TailIdentityProfile::Ocsf,
        tenant_id,
        event_hour,
        pack_id,
        paths,
        compression_level,
    )
}

/// `repack_staged_event_files_with_compression` for any identity profile,
/// against an explicit Arrow schema (the loaded Iceberg table's for OCSF and
/// for OTLP tables that exist; `TailIdentityProfile::native_arrow_schema`
/// for an OTLP tail whose table is not provisioned yet).
pub fn repack_staged_files_with_profile(
    arrow_schema: Arc<ArrowSchema>,
    profile: TailIdentityProfile,
    tenant_id: &str,
    event_hour: i32,
    pack_id: &str,
    paths: &[impl AsRef<Path>],
    compression_level: i32,
) -> Result<StagedEventFile> {
    if tenant_id.is_empty()
        || paths.is_empty()
        || paths.len() > 4_096
        || !(1..=22).contains(&compression_level)
        || pack_id.len() != 64
        || !pack_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("staged tail pack identity, compression, or input bound is invalid");
    }
    let mut properties = WriterProperties::builder()
        // NAN-2361: zstd-9 for the long-lived packed layout, per the Codex
        // footprint measurement -- 14.0% fewer bytes than the zstd-3
        // equivalent, and local CONTAINS p50 IMPROVED from 83.1 ms to 56.7 ms
        // because fewer compressed bytes are touched. Write time goes 1.37s ->
        // 4.43s, which is why the STAGED encoder above stays at 6: staged
        // objects are short-lived and on the ingest latency path, while these
        // are written once and read for the whole retention window. zstd-19
        // was measured too and rejected -- a 38x write penalty for another
        // 9.5% only makes sense for an explicit cold/archive rewrite.
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(compression_level)?))
        .set_max_row_group_row_count(Some(262_144));
    // Raw identity blooms also serve case-insensitive lookups: the tail reader
    // checks every bounded ASCII spelling, never just a lowercased value.
    for path in crate::tail_predicate::IDENTITY_PATHS {
        let column = parquet::schema::types::ColumnPath::new(path.split('.').map(str::to_owned).collect());
        properties = properties
            .set_column_statistics_enabled(column.clone(), parquet::file::properties::EnabledStatistics::Page)
            .set_column_bloom_filter_enabled(column.clone(), true)
            .set_column_bloom_filter_fpp(column.clone(), 0.0001)
            .set_column_bloom_filter_ndv(column, 262_144);
    }
    let properties = properties.build();
    let mut writer = ArrowWriter::try_new(Vec::new(), arrow_schema.clone(), Some(properties))?;
    // Buffer up to a row group, sort it, then write — see `sort_pack_buffer`.
    let mut sort_buffer: Vec<RecordBatch> = Vec::new();
    let mut buffered_rows = 0_usize;
    let mut rows = 0_u64;
    let mut duplicate_rows_removed = 0_u64;
    let mut min_time_ms = i64::MAX;
    let mut max_time_ms = i64::MIN;
    let mut identities = HashMap::<String, [u8; 32]>::new();
    for path in paths {
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path.as_ref())?)?
            .with_batch_size(8_192)
            .build()?;
        for batch in reader {
            let batch = batch?;
            // Staged files are immutable and may have been admitted just
            // before an additive Iceberg schema commit. Re-decode only the
            // mixed-schema batches through JSON so absent optional leaves are
            // materialized as null in the current schema. The equal-schema
            // steady state remains a zero-conversion Arrow copy.
            let batches = align_staged_batch(batch, arrow_schema.clone())?;
            for batch in batches {
                let (batch, removed) = deduplicate_staged_batch_for(batch, &mut identities, profile)?;
                duplicate_rows_removed = duplicate_rows_removed
                    .checked_add(removed)
                    .context("staged tail duplicate row count overflow")?;
                let Some(batch) = batch else {
                    continue;
                };
                let (batch_min_time_ms, batch_max_time_ms) =
                    batch_time_bounds_ms_for(&batch, profile.time_column())?;
                min_time_ms = min_time_ms.min(batch_min_time_ms);
                max_time_ms = max_time_ms.max(batch_max_time_ms);
                rows = rows
                    .checked_add(u64::try_from(batch.num_rows())?)
                    .context("staged tail pack row count overflow")?;
                buffered_rows += batch.num_rows();
                sort_buffer.push(batch);
                if buffered_rows >= PACK_SORT_BUFFER_ROWS {
                    let merged = arrow_select::concat::concat_batches(&arrow_schema, &sort_buffer)?;
                    writer.write(&sort_pack_buffer_for(&merged, profile)?)?;
                    sort_buffer.clear();
                    buffered_rows = 0;
                }
            }
        }
    }
    if buffered_rows > 0 {
        let merged = arrow_select::concat::concat_batches(&arrow_schema, &sort_buffer)?;
        writer.write(&sort_pack_buffer_for(&merged, profile)?)?;
        sort_buffer.clear();
    }
    if rows == 0 {
        bail!("staged tail pack produced no rows");
    }
    if min_time_ms == i64::MAX || max_time_ms == i64::MIN || min_time_ms > max_time_ms {
        bail!("staged tail pack has invalid event-time bounds");
    }
    let bytes = writer.into_inner()?;
    if bytes.is_empty() {
        bail!("staged tail pack produced an empty Parquet object");
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let relative_path =
        content_addressed_staged_path(tenant_id, event_hour, "pack", pack_id, &sha256)?;
    Ok(StagedEventFile {
        event_hour,
        min_time_ms,
        max_time_ms,
        relative_path,
        bytes,
        rows,
        duplicate_rows_removed,
        sha256,
    })
}

/// Enforce the OCSF event identity contract across independently admitted
/// staged batches. Arrow JSON is deterministic for one aligned schema, so its
/// row bytes provide an exact payload fingerprint without retaining every wide
/// event in memory. Identical delivery retries are removed; one UID carrying
/// different event data is rejected instead of silently choosing a winner.
fn deduplicate_staged_batch_for(
    batch: RecordBatch,
    identities: &mut HashMap<String, [u8; 32]>,
    profile: TailIdentityProfile,
) -> Result<(Option<RecordBatch>, u64)> {
    let uids = match profile {
        TailIdentityProfile::Ocsf => staged_batch_event_uids(&batch)?,
        TailIdentityProfile::OtelSpans => staged_batch_span_uids(&batch)?,
        TailIdentityProfile::OtelMetrics => staged_batch_metric_uids(&batch)?,
    };
    let semantic = match profile {
        TailIdentityProfile::Ocsf => staged_batch_for_identity_fingerprint(&batch)?,
        TailIdentityProfile::OtelSpans | TailIdentityProfile::OtelMetrics => {
            staged_otel_batch_for_identity_fingerprint(&batch)?
        }
    };
    let mut json = LineDelimitedWriter::new(Vec::new());
    json.write(&semantic)?;
    json.finish()?;
    let encoded = json.into_inner();
    let lines = encoded
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() != batch.num_rows() || uids.len() != batch.num_rows() {
        bail!("staged tail fingerprint row count changed");
    }

    let mut keep = Vec::with_capacity(lines.len());
    let mut removed = 0_u64;
    for (uid, line) in uids.into_iter().zip(lines) {
        // The previous implementation parsed every Arrow-emitted JSON row,
        // cloned its entire nested OCSF value, removed delivery-local metadata,
        // serialized it again before hashing. A full 1 TB/day tail pack spent
        // about 110 seconds on one core and fell behind a 12.5k-EPS stream.
        // `staged_batch_for_identity_fingerprint` replaces those non-semantic
        // leaves in Arrow, so one deterministic Arrow-to-JSON pass supplies
        // the same equality contract without the parse/clone/re-serialize.
        let fingerprint: [u8; 32] = Sha256::digest(line).into();
        match identities.get(uid.as_str()) {
            None => {
                identities.insert(uid, fingerprint);
                keep.push(true);
            }
            Some(existing) if existing == &fingerprint => {
                removed = removed
                    .checked_add(1)
                    .context("staged tail duplicate row count overflow")?;
                keep.push(false);
            }
            Some(_) => bail!("staged tail contains conflicting event UID {uid}"),
        }
    }
    if removed == 0 {
        return Ok((Some(batch), 0));
    }
    if removed == u64::try_from(batch.num_rows())? {
        return Ok((None, removed));
    }
    let mask = BooleanArray::from(keep);
    Ok((Some(filter_record_batch(&batch, &mask)?), removed))
}

fn staged_batch_event_uids(batch: &RecordBatch) -> Result<Vec<String>> {
    let metadata_index = batch
        .schema()
        .index_of("metadata")
        .context("staged tail batch has no metadata column")?;
    let metadata = batch
        .column(metadata_index)
        .as_any()
        .downcast_ref::<StructArray>()
        .context("staged tail metadata column is not a struct")?;
    let uid = metadata
        .column_by_name("uid")
        .context("staged tail metadata has no uid column")?;
    let mut values = Vec::with_capacity(batch.num_rows());
    for index in 0..batch.num_rows() {
        if metadata.is_null(index) || uid.is_null(index) {
            bail!("staged tail event UID is null");
        }
        let value = match uid.data_type() {
            DataType::Utf8 => uid
                .as_any()
                .downcast_ref::<StringArray>()
                .context("staged tail UTF-8 UID array has an inconsistent type")?
                .value(index),
            DataType::LargeUtf8 => uid
                .as_any()
                .downcast_ref::<LargeStringArray>()
                .context("staged tail large UTF-8 UID array has an inconsistent type")?
                .value(index),
            DataType::Utf8View => uid
                .as_any()
                .downcast_ref::<StringViewArray>()
                .context("staged tail UTF-8 view UID array has an inconsistent type")?
                .value(index),
            _ => bail!("staged tail event UID column is not a string"),
        };
        // Preserve `event_uid`'s established admission boundary exactly. The
        // packer is a physical rewrite and must not invent a stricter UID
        // character policy after Bronze has already admitted the row.
        if value.is_empty() || value.len() > 4_096 {
            bail!("staged tail event UID is invalid");
        }
        values.push(value.to_string());
    }
    Ok(values)
}

fn top_level_string_column<'a>(batch: &'a RecordBatch, name: &str) -> Result<Vec<&'a str>> {
    let index = batch
        .schema()
        .index_of(name)
        .with_context(|| format!("staged OTLP tail batch has no {name} column"))?;
    let column = batch.column(index);
    let mut values = Vec::with_capacity(batch.num_rows());
    for row in 0..batch.num_rows() {
        if column.is_null(row) {
            bail!("staged OTLP tail {name} is null");
        }
        let value = match column.data_type() {
            DataType::Utf8 => column
                .as_any()
                .downcast_ref::<StringArray>()
                .context("staged OTLP UTF-8 array has an inconsistent type")?
                .value(row),
            DataType::LargeUtf8 => column
                .as_any()
                .downcast_ref::<LargeStringArray>()
                .context("staged OTLP large UTF-8 array has an inconsistent type")?
                .value(row),
            DataType::Utf8View => column
                .as_any()
                .downcast_ref::<StringViewArray>()
                .context("staged OTLP UTF-8 view array has an inconsistent type")?
                .value(row),
            _ => bail!("staged OTLP tail {name} column is not a string"),
        };
        if value.is_empty() || value.len() > 4_096 {
            bail!("staged OTLP tail {name} is invalid");
        }
        values.push(value);
    }
    Ok(values)
}

/// Microsecond event time per row of one timestamp column (any unit).
fn timestamp_column_micros(batch: &RecordBatch, name: &str) -> Result<Vec<i64>> {
    let index = batch
        .schema()
        .index_of(name)
        .with_context(|| format!("staged OTLP tail batch has no {name} column"))?;
    let column = batch.column(index);
    let mut values = Vec::with_capacity(batch.num_rows());
    macro_rules! collect {
        ($array:ty, $to_micros:expr) => {{
            let array = column
                .as_any()
                .downcast_ref::<$array>()
                .context("staged OTLP timestamp array has an inconsistent Arrow type")?;
            for row in 0..array.len() {
                if array.is_null(row) {
                    bail!("staged OTLP tail {name} is null");
                }
                let value: i64 = array.value(row);
                values.push($to_micros(value).context("staged OTLP timestamp overflow")?);
            }
        }};
    }
    match column.data_type() {
        DataType::Timestamp(TimeUnit::Second, _) => {
            collect!(TimestampSecondArray, |v: i64| v.checked_mul(1_000_000))
        }
        DataType::Timestamp(TimeUnit::Millisecond, _) => {
            collect!(TimestampMillisecondArray, |v: i64| v.checked_mul(1_000))
        }
        DataType::Timestamp(TimeUnit::Microsecond, _) => {
            collect!(TimestampMicrosecondArray, |v: i64| Some(v))
        }
        DataType::Timestamp(TimeUnit::Nanosecond, _) => {
            collect!(TimestampNanosecondArray, |v: i64| Some(v.div_euclid(1_000)))
        }
        _ => bail!("staged OTLP tail {name} column is not a timestamp"),
    }
    Ok(values)
}

/// Span identity: `trace_id:span_id:<start_time micros>` (see
/// [`TailIdentityProfile`]).
fn staged_batch_span_uids(batch: &RecordBatch) -> Result<Vec<String>> {
    let trace_ids = top_level_string_column(batch, "trace_id")?;
    let span_ids = top_level_string_column(batch, "span_id")?;
    let starts = timestamp_column_micros(batch, "start_time")?;
    Ok(trace_ids
        .iter()
        .zip(span_ids.iter())
        .zip(starts.iter())
        .map(|((trace, span), start)| format!("{trace}:{span}:{start}"))
        .collect())
}

/// Metric identity: the drain's materialized `metric_uid` column.
fn staged_batch_metric_uids(batch: &RecordBatch) -> Result<Vec<String>> {
    Ok(top_level_string_column(batch, "metric_uid")?
        .into_iter()
        .map(str::to_string)
        .collect())
}

/// Neutralize the OTLP delivery-local leaf (`ingest_time`, the drain's
/// receipt time) so a retried batch fingerprints equal to its first delivery.
fn staged_otel_batch_for_identity_fingerprint(batch: &RecordBatch) -> Result<RecordBatch> {
    let Ok(index) = batch.schema().index_of("ingest_time") else {
        return Ok(batch.clone());
    };
    let column = batch.column(index);
    let neutral: ArrayRef = match column.data_type() {
        DataType::Timestamp(TimeUnit::Microsecond, tz) => Arc::new(
            TimestampMicrosecondArray::from_value(0, column.len()).with_timezone_opt(tz.clone()),
        ),
        DataType::Timestamp(TimeUnit::Millisecond, tz) => Arc::new(
            TimestampMillisecondArray::from_value(0, column.len()).with_timezone_opt(tz.clone()),
        ),
        DataType::Timestamp(TimeUnit::Nanosecond, tz) => Arc::new(
            TimestampNanosecondArray::from_value(0, column.len()).with_timezone_opt(tz.clone()),
        ),
        DataType::Timestamp(TimeUnit::Second, tz) => Arc::new(
            TimestampSecondArray::from_value(0, column.len()).with_timezone_opt(tz.clone()),
        ),
        _ => bail!("staged OTLP tail ingest_time column is not a timestamp"),
    };
    let mut columns = batch.columns().to_vec();
    columns[index] = neutral;
    Ok(RecordBatch::try_new(batch.schema(), columns)?)
}

fn staged_batch_for_identity_fingerprint(batch: &RecordBatch) -> Result<RecordBatch> {
    let metadata_index = batch
        .schema()
        .index_of("metadata")
        .context("staged tail batch has no metadata column")?;
    let metadata = batch
        .column(metadata_index)
        .as_any()
        .downcast_ref::<StructArray>()
        .context("staged tail metadata column is not a struct")?;
    let metadata_columns = metadata
        .fields()
        .iter()
        .zip(metadata.columns())
        .map(|(field, column)| {
            if matches!(field.name().as_str(), "logged_time" | "processed_time") {
                match column.data_type() {
                    // OCSF declares both leaves as Long. Use one non-null
                    // sentinel so this remains valid when a generated schema
                    // marks the field required; equality is the only property
                    // the fingerprint needs.
                    DataType::Int64 => {
                        Ok(Arc::new(Int64Array::from_value(0, column.len())) as ArrayRef)
                    }
                    _ => bail!("staged tail metadata timing column is not a long"),
                }
            } else if field.name() == "original_event_uid" {
                match column.data_type() {
                    // A parser may mint this diagnostic UID before a durable
                    // adapter supplies the authoritative metadata.uid. Use a
                    // fixed non-null value so retries compare their remaining
                    // semantic payload without violating required schemas.
                    DataType::Utf8 => {
                        Ok(Arc::new(StringArray::from(vec![""; column.len()])) as ArrayRef)
                    }
                    DataType::LargeUtf8 => {
                        Ok(Arc::new(LargeStringArray::from(vec![""; column.len()])) as ArrayRef)
                    }
                    DataType::Utf8View => {
                        Ok(Arc::new(StringViewArray::from(vec![""; column.len()])) as ArrayRef)
                    }
                    _ => bail!("staged tail metadata original event UID is not a string"),
                }
            } else {
                Ok(Arc::clone(column))
            }
        })
        .collect::<Result<Vec<ArrayRef>>>()?;
    let semantic_metadata = StructArray::try_new(
        metadata.fields().clone(),
        metadata_columns,
        metadata.nulls().cloned(),
    )?;
    let mut columns = batch.columns().to_vec();
    columns[metadata_index] = Arc::new(semantic_metadata);
    Ok(RecordBatch::try_new(batch.schema(), columns)?)
}

pub(crate) fn batch_time_bounds_ms(batch: &RecordBatch) -> Result<(i64, i64)> {
    batch_time_bounds_ms_for(batch, "time")
}

pub(crate) fn batch_time_bounds_ms_for(batch: &RecordBatch, time_column: &str) -> Result<(i64, i64)> {
    let index = batch
        .schema()
        .index_of(time_column)
        .with_context(|| format!("staged tail batch has no canonical {time_column} column"))?;
    let column = batch.column(index);
    let mut min_time_ms = i64::MAX;
    let mut max_time_ms = i64::MIN;
    macro_rules! bounds {
        ($array:ty, $divisor:expr, $multiplier:expr) => {{
            let values = column
                .as_any()
                .downcast_ref::<$array>()
                .context("staged tail time array has an inconsistent Arrow type")?;
            for index in 0..values.len() {
                if values.is_null(index) {
                    continue;
                }
                let value = values
                    .value(index)
                    .checked_mul($multiplier)
                    .context("staged tail timestamp overflow")?
                    .div_euclid($divisor);
                min_time_ms = min_time_ms.min(value);
                max_time_ms = max_time_ms.max(value);
            }
        }};
    }
    match column.data_type() {
        DataType::Timestamp(TimeUnit::Second, _) => bounds!(TimestampSecondArray, 1, 1_000),
        DataType::Timestamp(TimeUnit::Millisecond, _) => {
            bounds!(TimestampMillisecondArray, 1, 1)
        }
        DataType::Timestamp(TimeUnit::Microsecond, _) => {
            bounds!(TimestampMicrosecondArray, 1_000, 1)
        }
        DataType::Timestamp(TimeUnit::Nanosecond, _) => {
            bounds!(TimestampNanosecondArray, 1_000_000, 1)
        }
        _ => bail!("staged tail canonical time column is not a timestamp"),
    }
    if min_time_ms == i64::MAX || max_time_ms == i64::MIN {
        bail!("staged tail batch has no event timestamp");
    }
    Ok((min_time_ms, max_time_ms))
}

/// A failed additive alignment may mean admission advanced the catalog schema.
#[derive(Debug, thiserror::Error)]
#[error("align additive staged tail schema for packing")]
struct StagedSchemaAlignmentError;

/// Retry the entire local rewrite once with the catalog's current schema.
/// Nothing is published by the operation until it returns successfully. The
/// original table remains pinned for snapshot/identity checks by the caller.
pub async fn with_refreshed_staged_schema<T>(
    catalog: &impl Catalog,
    table_id: &TableIdent,
    table: &Table,
    mut rewrite: impl FnMut(Arc<ArrowSchema>) -> Result<T>,
) -> Result<T> {
    let schema = Arc::new(table.metadata().current_schema().as_ref().try_into()?);
    match rewrite(schema) {
        Err(error) if error.is::<StagedSchemaAlignmentError>() => {
            tracing::warn!(%table_id, %error, "refreshing catalog schema before one staged rewrite retry");
            let refreshed = catalog.load_table(table_id).await
                .context("refresh Iceberg schema after staged alignment failure")?;
            if refreshed.metadata().uuid() != table.metadata().uuid()
                || refreshed.metadata().location() != table.metadata().location()
            {
                bail!("Iceberg table identity changed during staged schema refresh");
            }
            let schema = Arc::new(refreshed.metadata().current_schema().as_ref().try_into()?);
            rewrite(schema).context("staged rewrite failed after one catalog schema refresh")
        }
        result => result,
    }
}

pub(crate) fn align_staged_batch(
    batch: RecordBatch,
    current_schema: Arc<ArrowSchema>,
) -> Result<Vec<RecordBatch>> {
    if batch.schema().as_ref() == current_schema.as_ref() {
        return Ok(vec![batch]);
    }
    let expected_rows = batch.num_rows();
    let mut json = LineDelimitedWriter::new(Vec::new());
    json.write(&batch)?;
    json.finish()?;
    let decoded = ReaderBuilder::new(current_schema)
        // NAN-2520: an older/narrower catalog schema must not silently drop
        // source columns or nested enrichment data while aligning a pack.
        // Missing optional input leaves still become null; unknown input
        // leaves require the caller to load a schema that covers the source.
        .with_strict_mode(true)
        .with_batch_size(expected_rows.max(1))
        .build(Cursor::new(json.into_inner()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context(StagedSchemaAlignmentError)?;
    if decoded.iter().map(RecordBatch::num_rows).sum::<usize>() != expected_rows {
        bail!("additive staged tail alignment changed the row count");
    }
    Ok(decoded)
}

/// Recover and revalidate canonical rows from one exact staged Parquet object
/// before its contents are committed to Iceberg. Sparse physical nulls are
/// removed because they are an Arrow representation detail, not OCSF leaves.
pub fn decode_staged_event_file(path: &Path, tenant_id: &str) -> Result<Vec<EventRow>> {
    let mut rows = Vec::new();
    visit_staged_event_file(path, tenant_id, |row| {
        rows.push(row);
        Ok(())
    })?;
    Ok(rows)
}

/// Reconstruct the historical compaction digest without retaining the much
/// larger nested `serde_json::Value` tree for every row at once. This bounded,
/// upgrade-only bridge deliberately emits the exact bytes
/// [`generation_digest`] hashes, in the same UID order, so an Arrow-native
/// compactor remains idempotent with snapshots written by the former
/// JSON-materializing implementation.
pub fn staged_event_files_generation_digest(
    paths: &[impl AsRef<Path>],
    tenant_id: &str,
) -> Result<(String, usize)> {
    if paths.is_empty() || paths.len() > 4_096 {
        bail!("staged compaction digest requires one to 4096 objects");
    }
    let mut encoded_by_uid = BTreeMap::<String, Vec<u8>>::new();
    let mut rows = 0_usize;
    let mut encoded_bytes = 0_u64;
    for path in paths {
        visit_staged_event_file(path.as_ref(), tenant_id, |row| {
            rows = rows
                .checked_add(1)
                .context("staged compaction row count overflow")?;
            if rows > MAX_GENERATION_REWRITE_ROWS {
                bail!("generation must contain one to {MAX_GENERATION_REWRITE_ROWS} rows");
            }
            let uid = row.event_uid.clone();
            let encoded = serde_json::to_vec(&row)?;
            let encoded_len = u64::try_from(encoded.len())?;
            encoded_bytes = encoded_bytes
                .checked_add(u64::try_from(uid.len())?)
                .and_then(|bytes| bytes.checked_add(encoded_len))
                .context("legacy compaction digest byte count overflow")?;
            if encoded_bytes > LEGACY_COMPACTION_DIGEST_BYTES_CEILING {
                bail!(
                    "legacy compaction digest exceeds its {}-byte upgrade buffer; migrate the exact reservation before retrying",
                    LEGACY_COMPACTION_DIGEST_BYTES_CEILING
                );
            }
            if encoded_by_uid.insert(uid, encoded).is_some() {
                bail!("generation contains duplicate event UIDs");
            }
            Ok(())
        })?;
    }
    if rows == 0 {
        bail!("generation must contain one to {MAX_GENERATION_REWRITE_ROWS} rows");
    }
    let mut digest = Sha256::new();
    digest.update(b"nano:iceberg:generation-digest:v1\0");
    for encoded in encoded_by_uid.into_values() {
        digest.update((encoded.len() as u64).to_be_bytes());
        digest.update(encoded);
    }
    Ok((hex::encode(digest.finalize()), rows))
}

/// Verifies reserved product rows in rewritten Parquet without retaining the
/// unrelated rows of a compaction. Compare the complete canonical payload,
/// including diagnostic timestamps; only physical sparse fields are omitted.
pub struct ProductEventCommitVerifier {
    tenant_id: String,
    /// Canonical payload, plus the pre-stabilization form when it differs: a
    /// reservation staged by the previous publisher build before a roll must
    /// still verify when its commit is observed by this one.
    expected: BTreeMap<String, (EventKind, Value, Option<Value>)>,
    seen: BTreeSet<String>,
}

impl ProductEventCommitVerifier {
    pub fn new(tenant_id: &str, rows: &[EventRow]) -> Result<Self> {
        if rows.is_empty() || rows.len() > MAX_GENERATION_REWRITE_ROWS {
            bail!("product-event verification requires bounded reserved rows");
        }
        let mut expected = BTreeMap::new();
        for row in rows {
            let (_, mut value) = normalize_event(row, tenant_id)?;
            prune_sparse_materialization(&mut value);
            let legacy = if unmapped_needs_stabilization(row.event_kind, &row.ocsf_event) {
                let (_, mut legacy) = normalize_event_with(row, tenant_id, false)?;
                prune_sparse_materialization(&mut legacy);
                Some(legacy)
            } else {
                None
            };
            if expected.insert(row.event_uid.clone(), (row.event_kind, value, legacy)).is_some() {
                bail!("product-event reservation contains duplicate UIDs");
            }
        }
        Ok(Self { tenant_id: tenant_id.to_owned(), expected, seen: BTreeSet::new() })
    }

    pub fn verify_file(&mut self, path: &Path, expected_rows: u64) -> Result<()> {
        if expected_rows == 0 || expected_rows > MAX_GENERATION_REWRITE_ROWS as u64 {
            bail!("product-event commit file exceeds its row bound");
        }
        // Validate the authoritative source before sparsity normalization in
        // new(). Parquet omits null-only required audit objects, so validating
        // that physical projection as a new source event would reject truthful
        // unknown initiators. Compare its complete canonical value instead.
        let rows = visit_staged_event_values(path, |mut value| {
            if value.pointer("/metadata/tenant_uid").and_then(Value::as_str) != Some(self.tenant_id.as_str()) {
                bail!("product-event commit contains a foreign tenant");
            }
            let uid = event_uid(&value)?;
            if let Some((kind, expected, legacy)) = self.expected.get(&uid) {
                let observed_kind = event_kind(&value)?;
                let time_ms = ocsf_time_millis(value.get("time"))
                    .context("product-event committed time is invalid")?;
                let timestamp = DateTime::<Utc>::from_timestamp_millis(time_ms)
                    .context("product-event committed time is outside the supported range")?;
                value["time"] = Value::String(timestamp.to_rfc3339());
                prune_sparse_materialization(&mut value);
                if observed_kind != *kind
                    || (value != *expected && legacy.as_ref() != Some(&value))
                {
                    bail!("product-event committed payload differs from its reserved source");
                }
                if !self.seen.insert(uid) {
                    bail!("product-event reserved UID appears more than once in its commit");
                }
            }
            Ok(())
        })?;
        if rows as u64 != expected_rows {
            bail!("product-event commit Parquet row count differs from its manifest");
        }
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        if self.seen.len() != self.expected.len() {
            bail!("product-event commit is missing reserved source UIDs");
        }
        Ok(())
    }
}

fn visit_staged_event_file(
    path: &Path,
    tenant_id: &str,
    mut visit: impl FnMut(EventRow) -> Result<()>,
) -> Result<usize> {
    visit_staged_event_values(path, |mut event| {
        prune_sparse_materialization(&mut event);
        let event_uid = event_uid(&event)?;
        let event_kind = event_kind(&event)?;
        let row = EventRow { event_uid, event_kind, ocsf_event: event };
        let (_, normalized) = normalize_event(&row, tenant_id)?;
        visit(EventRow { event_uid: row.event_uid, event_kind, ocsf_event: normalized })
    })
}

fn visit_staged_event_values(
    path: &Path,
    mut visit: impl FnMut(Value) -> Result<()>,
) -> Result<usize> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?
        .with_batch_size(8_192)
        .build()?;
    let mut rows = 0_usize;
    for batch in reader {
        let batch = batch?;
        let mut writer = LineDelimitedWriter::new(Vec::new());
        writer.write(&batch)?;
        writer.finish()?;
        for line in writer
            .into_inner()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            visit(serde_json::from_slice(line)?)?;
            rows = rows
                .checked_add(1)
                .context("staged Parquet row count overflow")?;
            if rows > MAX_GENERATION_REWRITE_ROWS {
                bail!("staged Parquet object exceeds the compaction row bound");
            }
        }
    }
    if rows == 0 {
        bail!("staged Parquet object contains no canonical rows");
    }
    Ok(rows)
}

/// Build a new immutable, schema-homogeneous Iceberg generation from the
/// current snapshot plus an authoritative normalized addition batch.
///
/// New nested OCSF leaves are never added in place because chDB 4.2.1 can cache
/// an incompatible physical schema across those mutations. This rewrite reads
/// the exact source snapshot, replaces matching UIDs with the authoritative
/// additions, infers one complete nullable schema, and writes every destination
/// file against that schema before any serving pointer can reference it.
pub async fn rewrite_generation(
    catalog: &RestCatalog,
    catalog_config: &CatalogConfig,
    source_id: &TableIdent,
    source_location: &str,
    destination_id: &TableIdent,
    destination_location: &str,
    tenant_id: &str,
    additions: &[EventRow],
    generation: &str,
    repair_conflicting_uids: bool,
) -> Result<GenerationRewriteResult> {
    crate::shared_mode::require_serialized_primary_iceberg_authority(
        "generation rewrite",
    )?;
    if additions.len() > MAX_GENERATION_REWRITE_ROWS
        || generation.is_empty()
        || generation.len() > 256
        || generation.chars().any(char::is_control)
        || !source_location.starts_with("s3://")
        || source_location.len() > 2_048
        || !destination_location.starts_with("s3://")
        || destination_location.len() > 2_048
        || source_location.trim_end_matches('/') == destination_location.trim_end_matches('/')
    {
        bail!("schema generation rewrite arguments exceed their bounds");
    }

    let source = catalog
        .load_table(source_id)
        .await
        .context("load source Iceberg schema generation")?;
    if source.metadata().location().trim_end_matches('/') != source_location.trim_end_matches('/') {
        bail!("source Iceberg generation is outside its assigned table location");
    }
    let source_snapshot_id = source
        .metadata()
        .current_snapshot_id()
        .context("source Iceberg generation has no current snapshot")?;
    let mut addition_uids = BTreeSet::new();
    for row in additions {
        if !addition_uids.insert(row.event_uid.as_str()) {
            bail!("schema generation additions contain duplicate event UIDs");
        }
    }
    let mut replaced_source_uids = BTreeSet::new();
    let mut conflicting_source_uids = BTreeSet::new();
    let mut repaired_uid_rows = 0_usize;
    let mut duplicate_rows_removed = 0_usize;
    let mut by_uid = BTreeMap::<String, EventRow>::new();
    // The Iceberg Arrow reader currently rejects some valid additive nested
    // schema histories before yielding a batch (for example, a historical
    // three-leaf struct beneath a current five-leaf struct). A migration must
    // be able to read those old files in their own physical schemas. Hydrate
    // the exact, version-pinned snapshot and decode each immutable Parquet
    // object independently instead of asking one Arrow stream to unify them.
    let hydration = tempfile::Builder::new()
        .prefix("nano-generation-rewrite-")
        .tempdir()
        .context("create generation rewrite hydration directory")?;
    let hydrated_root = hydration.path().join("source");
    crate::generation::hydrate_current_snapshot(
        catalog,
        catalog_config,
        source_id,
        source_location,
        &hydrated_root,
    )
    .await
    .context("hydrate exact source Iceberg generation")?;
    let object_manifest: crate::generation::ObjectStampManifest = serde_json::from_slice(
        &std::fs::read(hydrated_root.join("object-stamps.json"))
            .context("read hydrated source object manifest")?,
    )
    .context("decode hydrated source object manifest")?;
    if object_manifest.snapshot_id != source_snapshot_id
        || object_manifest.table != source_id.to_string()
    {
        bail!("hydrated source identity differs from the rewrite source snapshot");
    }
    let mut source_rows = 0_usize;
    for object in object_manifest.objects {
        let path = hydrated_root.join("data").join(&object.relative_path);
        for event in decode_parquet_event_values(&path)
            .with_context(|| format!("decode source object {}", object.source_uri))?
        {
            let uid = event_uid(&event)?;
            source_rows = source_rows
                .checked_add(1)
                .context("source generation row count overflow")?;
            if source_rows > MAX_GENERATION_REWRITE_ROWS {
                bail!("source schema generation exceeds the bounded rewrite size");
            }
            // Authoritative additions are allowed to repair a previously
            // published row that no longer satisfies the current contract.
            // Do not validate the superseded source copy before its strict
            // replacement has been admitted below.
            if addition_uids.contains(uid.as_str()) {
                replaced_source_uids.insert(uid);
                continue;
            }
            let event_kind = event_kind(&event)?;
            let row = EventRow {
                event_uid: uid.clone(),
                event_kind,
                ocsf_event: event,
            };
            let (_, normalized) = normalize_event(&row, tenant_id)
                .with_context(|| format!("validate source generation event {uid}"))?;
            let admitted = insert_source_consistent(
                &mut by_uid,
                &mut conflicting_source_uids,
                EventRow {
                    event_uid: uid,
                    event_kind,
                    ocsf_event: normalized,
                },
                repair_conflicting_uids,
            )?;
            repaired_uid_rows = repaired_uid_rows
                .checked_add(admitted.repaired_uid_rows)
                .context("repaired source UID count overflow")?;
            duplicate_rows_removed = duplicate_rows_removed
                .checked_add(admitted.duplicate_rows_removed)
                .context("duplicate source row count overflow")?;
        }
    }
    if source_rows == 0 || by_uid.is_empty() {
        bail!("source Iceberg generation contains no canonical events");
    }

    let mut normalized_additions = Vec::with_capacity(additions.len());
    let mut replaced_rows = replaced_source_uids.len();
    for row in additions {
        let (_, normalized) = normalize_event(row, tenant_id)
            .with_context(|| format!("validate schema generation addition {}", row.event_uid))?;
        let normalized = EventRow {
            event_uid: row.event_uid.clone(),
            event_kind: row.event_kind,
            ocsf_event: normalized,
        };
        if by_uid
            .insert(row.event_uid.clone(), normalized.clone())
            .is_some()
        {
            replaced_rows += 1;
        }
        normalized_additions.push(normalized);
    }

    let mut rows = by_uid.into_values().collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        let left_time = ocsf_time_millis(left.ocsf_event.get("time")).unwrap_or_default();
        let right_time = ocsf_time_millis(right.ocsf_event.get("time")).unwrap_or_default();
        (right_time, right.event_uid.as_str()).cmp(&(left_time, left.event_uid.as_str()))
    });
    let batch_sha256 = if normalized_additions.is_empty() {
        generation_digest(&rows)?
    } else {
        generation_digest(&normalized_additions)?
    };
    let (table, schema_fields) = if catalog.table_exists(destination_id).await? {
        let existing = catalog.load_table(destination_id).await?;
        verify_rewrite_destination(
            &existing,
            destination_location,
            generation,
            source_snapshot_id,
        )?;
        let schema_fields = existing
            .metadata()
            .current_schema()
            .as_struct()
            .fields()
            .len();
        if let Some(snapshot_id) = snapshot_for_batch(&existing, &batch_sha256) {
            return Ok(GenerationRewriteResult {
                status: "no_change",
                source_table: source_id.to_string(),
                source_snapshot_id,
                destination_table: destination_id.to_string(),
                destination_snapshot_id: snapshot_id,
                metadata_location: required_metadata_location(&existing)?.to_string(),
                source_rows,
                addition_rows: normalized_additions.len(),
                replaced_rows,
                duplicate_rows_removed,
                repaired_uid_rows,
                rows: rows.len(),
                batch_sha256,
                schema_fields,
                schema_generation: generation.to_string(),
            });
        }
        if existing.metadata().current_snapshot().is_some() {
            bail!("existing schema-generation destination contains a different snapshot");
        }
        (existing, schema_fields)
    } else {
        let arrow_schema = infer_generation_schema(&rows)?;
        let iceberg_schema =
            iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(arrow_schema.as_ref())
                .context("convert inferred OCSF generation schema to Iceberg")?;
        let schema_fields = iceberg_schema.as_struct().fields().len();
        let time_field_id = iceberg_schema
            .field_by_name("time")
            .context("inferred OCSF generation schema has no time field")?
            .id;
        let partition_spec = hour_partition_spec(time_field_id)?;
        if !catalog.namespace_exists(&destination_id.namespace).await? {
            catalog
                .create_namespace(&destination_id.namespace, HashMap::new())
                .await?;
        }
        let properties = HashMap::from([
            ("format-version".to_string(), "2".to_string()),
            (
                "write.parquet.compression-codec".to_string(),
                "zstd".to_string(),
            ),
            (
                "write.metadata.delete-after-commit.enabled".to_string(),
                "false".to_string(),
            ),
            (
                "write.metadata.previous-versions-max".to_string(),
                "10".to_string(),
            ),
            ("nano.ocsf-version".to_string(), OCSF_VERSION.to_string()),
            ("nano.tenant-id".to_string(), tenant_id.to_string()),
            ("nano.schema-generation".to_string(), generation.to_string()),
            (
                "nano.rewritten-from-snapshot".to_string(),
                source_snapshot_id.to_string(),
            ),
        ]);
        let creation = TableCreation::builder()
            .name(destination_id.name.clone())
            .location(destination_location.to_string())
            .schema(iceberg_schema)
            .partition_spec(partition_spec)
            .properties(properties)
            .build();
        let table = catalog
            .create_table(&destination_id.namespace, creation)
            .await
            .context("create immutable OCSF schema generation")?;
        (table, schema_fields)
    };

    // Every rewrite row was normalized above and this physical schema was
    // inferred from this exact row set. Repeating the recursive, name-based
    // shape walk here is quadratic in wide OCSF schemas; Arrow decoding below
    // remains the authoritative fail-closed physical conversion.
    let data_files = write_data_files(&table, tenant_id, &rows, &batch_sha256, false).await?;
    let properties = HashMap::from([
        (
            "nano.writer".to_string(),
            "rust-schema-generation-rewrite".to_string(),
        ),
        ("nano.ocsf-version".to_string(), OCSF_VERSION.to_string()),
        ("nano.tenant-id".to_string(), tenant_id.to_string()),
        ("nano.schema-generation".to_string(), generation.to_string()),
        (
            GENERATION_READY_PROPERTY.to_string(),
            GENERATION_READY_VALUE.to_string(),
        ),
        (OUTBOX_BATCH_PROPERTY.to_string(), batch_sha256.clone()),
    ]);
    let commit_uuid = uuid::Uuid::from_slice(&hex::decode(&batch_sha256)?[..16])?;
    let transaction = Transaction::new(&table);
    let action = transaction
        .fast_append()
        .set_commit_uuid(commit_uuid)
        .set_snapshot_properties(properties)
        .add_data_files(data_files);
    let committed = action
        .apply(transaction)?
        .commit(catalog)
        .await
        .context("commit immutable OCSF schema generation")?;
    let snapshot = committed
        .metadata()
        .current_snapshot()
        .context("schema generation rewrite committed no snapshot")?;
    if snapshot
        .summary()
        .additional_properties
        .get(OUTBOX_BATCH_PROPERTY)
        != Some(&batch_sha256)
    {
        bail!("schema generation rewrite committed a different batch digest");
    }
    Ok(GenerationRewriteResult {
        status: "rewritten",
        source_table: source_id.to_string(),
        source_snapshot_id,
        destination_table: destination_id.to_string(),
        destination_snapshot_id: snapshot.snapshot_id(),
        metadata_location: required_metadata_location(&committed)?.to_string(),
        source_rows,
        addition_rows: normalized_additions.len(),
        replaced_rows,
        duplicate_rows_removed,
        repaired_uid_rows,
        rows: rows.len(),
        batch_sha256,
        schema_fields,
        schema_generation: generation.to_string(),
    })
}

/// Decode one immutable Parquet object using its own physical Arrow schema.
/// This is intentionally separate from Iceberg's snapshot-wide Arrow reader:
/// additive nested schema evolution is represented by absent nullable leaves,
/// which JSON materialization preserves without requiring equal StructArray
/// child counts across historical files.
fn decode_parquet_event_values(path: &Path) -> Result<Vec<Value>> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?
        .with_batch_size(8_192)
        .build()?;
    let mut events = Vec::new();
    for batch in reader {
        let batch = batch?;
        let mut writer = LineDelimitedWriter::new(Vec::new());
        writer.write(&batch)?;
        writer.finish()?;
        for line in writer
            .into_inner()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let mut event: Value = serde_json::from_slice(line)?;
            prune_sparse_materialization(&mut event);
            events.push(event);
        }
    }
    Ok(events)
}

fn event_kind(event: &Value) -> Result<EventKind> {
    match event
        .pointer("/metadata/log_source")
        .and_then(Value::as_str)
    {
        Some("signals") => Ok(EventKind::Signal),
        Some("audit") => Ok(EventKind::PlatformAudit),
        Some(_) => Ok(EventKind::Source),
        None => bail!("Iceberg event has no metadata.log_source"),
    }
}

fn hour_partition_spec(time_field_id: i32) -> Result<UnboundPartitionSpec> {
    let partition_field = UnboundPartitionField::builder()
        .source_id(time_field_id)
        // REST catalogs require a stable v2 partition-field identity. Iceberg
        // partition IDs begin at 1000 for the first spec.
        .field_id(1_000)
        .name("event_hour".to_string())
        .transform(Transform::Hour)
        .build();
    let builder = UnboundPartitionSpec::builder()
        .with_spec_id(0)
        .add_partition_fields([partition_field])?;
    Ok(builder.build())
}

/// Iceberg exposes the table's union schema for every row. Arrow JSON then
/// materializes unrelated optional leaves as nulls and empty containers. They
/// are physical sparsity, not OCSF attributes present on the logical event.
fn prune_sparse_materialization(value: &mut Value) -> bool {
    match value {
        Value::Null => false,
        Value::Object(values) => {
            values.retain(|_, value| prune_sparse_materialization(value));
            !values.is_empty()
        }
        Value::Array(values) => {
            values.retain_mut(prune_sparse_materialization);
            !values.is_empty()
        }
        _ => true,
    }
}

fn event_uid(event: &Value) -> Result<String> {
    event
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
        .map(str::to_string)
        .context("Iceberg event has no bounded metadata.uid")
}

fn insert_consistent(events: &mut BTreeMap<String, EventRow>, row: EventRow) -> Result<()> {
    if let Some(existing) = events.get(&row.event_uid) {
        if crate::bronze::source_identity_digest(&existing.ocsf_event)?
            != crate::bronze::source_identity_digest(&row.ocsf_event)?
        {
            bail!(
                "source Iceberg generation contains conflicting event UID {}",
                row.event_uid
            );
        }
        return Ok(());
    }
    events.insert(row.event_uid.clone(), row);
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct SourceInsertOutcome {
    repaired_uid_rows: usize,
    duplicate_rows_removed: usize,
}

fn insert_source_consistent(
    events: &mut BTreeMap<String, EventRow>,
    conflicting_uids: &mut BTreeSet<String>,
    row: EventRow,
    repair_conflicting_uids: bool,
) -> Result<SourceInsertOutcome> {
    let original_uid = row.event_uid.clone();
    if conflicting_uids.contains(&original_uid) {
        let repaired = repair_event_uid(row, &original_uid)?;
        let duplicate_rows_removed = usize::from(events.contains_key(&repaired.event_uid));
        insert_consistent(events, repaired)?;
        return Ok(SourceInsertOutcome {
            repaired_uid_rows: 1,
            duplicate_rows_removed,
        });
    }
    let Some(existing) = events.get(&original_uid) else {
        events.insert(original_uid, row);
        return Ok(SourceInsertOutcome::default());
    };
    if crate::bronze::source_identity_digest(&existing.ocsf_event)?
        == crate::bronze::source_identity_digest(&row.ocsf_event)?
    {
        return Ok(SourceInsertOutcome {
            duplicate_rows_removed: 1,
            ..SourceInsertOutcome::default()
        });
    }
    if !repair_conflicting_uids {
        bail!("source Iceberg generation contains conflicting event UID {original_uid}");
    }

    let existing = events
        .remove(&original_uid)
        .context("conflicting source UID disappeared during repair")?;
    conflicting_uids.insert(original_uid.clone());
    insert_consistent(events, repair_event_uid(existing, &original_uid)?)?;
    insert_consistent(events, repair_event_uid(row, &original_uid)?)?;
    Ok(SourceInsertOutcome {
        repaired_uid_rows: 2,
        duplicate_rows_removed: 0,
    })
}

fn repair_event_uid(mut row: EventRow, original_uid: &str) -> Result<EventRow> {
    let mut hasher = Sha256::new();
    hasher.update(b"nano:ocsf:event-uid-repair:v1\0");
    hasher.update(original_uid.as_bytes());
    hasher.update(b"\0");
    hasher.update(crate::bronze::source_identity_digest(&row.ocsf_event)?);
    let repaired_uid = format!("nano-uid-repair-{}", hex::encode(hasher.finalize()));
    let metadata = row
        .ocsf_event
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .context("cannot repair an event without OCSF metadata")?;
    metadata
        .entry("original_event_uid".to_string())
        .or_insert_with(|| Value::String(original_uid.to_string()));
    metadata.insert("uid".to_string(), Value::String(repaired_uid.clone()));
    row.event_uid = repaired_uid;
    Ok(row)
}

fn infer_generation_schema(rows: &[EventRow]) -> Result<Arc<ArrowSchema>> {
    infer_generation_schema_events(rows.len(), rows.iter().map(|row| &row.ocsf_event))
}

/// `infer_generation_schema` for an already-normalised batch.
fn infer_generation_schema_values(rows: &NormalizedEventBatch) -> Result<Arc<ArrowSchema>> {
    infer_generation_schema_events(rows.len(), rows.rows.iter().map(|row| &row.ocsf_event))
}

fn infer_generation_schema_events<'a>(
    len: usize,
    events: impl Iterator<Item = &'a Value>,
) -> Result<Arc<ArrowSchema>> {
    if len == 0 || len > MAX_GENERATION_REWRITE_ROWS {
        bail!("schema generation inference requires one to {MAX_GENERATION_REWRITE_ROWS} events");
    }
    let mut encoded = Vec::new();
    for event in events {
        serde_json::to_writer(&mut encoded, event)?;
        encoded.push(b'\n');
    }
    let mut cursor = Cursor::new(encoded);
    let (inferred, _) = infer_json_schema_from_seekable(&mut cursor, None)
        .context("infer complete OCSF generation Arrow schema")?;
    let fields = inferred
        .fields()
        .iter()
        .map(|field| {
            if field.name() == "time" {
                Arc::new(Field::new(
                    "time",
                    DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())),
                    false,
                ))
            } else {
                field.clone()
            }
        })
        .collect::<Vec<_>>();
    if !fields.iter().any(|field| field.name() == "time") {
        bail!("inferred OCSF generation schema has no time field");
    }
    Ok(Arc::new(ArrowSchema::new_with_metadata(
        fields,
        inferred.metadata().clone(),
    )))
}

fn verify_rewrite_destination(
    table: &Table,
    location: &str,
    generation: &str,
    source_snapshot_id: i64,
) -> Result<()> {
    let properties = table.metadata().properties();
    let source_snapshot = source_snapshot_id.to_string();
    if table.metadata().location() != location
        || properties.get("nano.schema-generation").map(String::as_str) != Some(generation)
        || properties
            .get("nano.rewritten-from-snapshot")
            .map(String::as_str)
            != Some(source_snapshot.as_str())
    {
        bail!("existing schema-generation destination does not match the requested rewrite");
    }
    Ok(())
}

async fn write_data_files(
    table: &Table,
    tenant_id: &str,
    rows: &[EventRow],
    digest: &str,
    validate_shape: bool,
) -> Result<Vec<DataFile>> {
    let arrow_schema: Arc<ArrowSchema> = Arc::new(
        table
            .metadata()
            .current_schema()
            .as_ref()
            .try_into()
            .context("convert Iceberg OCSF schema to Arrow")?,
    );
    let partition_spec = table.metadata().default_partition_spec().as_ref().clone();
    if partition_spec.fields().len() != 1
        || partition_spec.fields()[0].name != "event_hour"
        || partition_spec.fields()[0].transform != iceberg::spec::Transform::Hour
    {
        bail!("event table must use exactly the time/hour event_hour partition");
    }
    let mut by_hour = BTreeMap::<i32, Vec<Value>>::new();
    for row in rows {
        let (hour, event) = normalize_event(row, tenant_id)?;
        if validate_shape {
            validate_physical_shape(&event, &DataType::Struct(arrow_schema.fields().clone()), "")?;
        }
        by_hour.entry(hour).or_default().push(event);
    }

    let properties = WriterProperties::builder()
        // NAN-2361: zstd-9 for durable event data. Every caller --
        // publish_events, publish_compacted_events, rewrite_generation --
        // produces objects that live for the whole retention window and are
        // read repeatedly, which is exactly the "hot silver layout" the Codex
        // footprint work sized: 14.0% fewer bytes than zstd-3-equivalent AND
        // local CONTAINS p50 improving 83.1 ms -> 56.7 ms, because the scan
        // touches fewer compressed bytes. The write cost (1.37s -> 4.43s per
        // ~100 MB) lands on a batched publish path, not a per-query one.
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(9)?))
        .set_max_row_group_row_count(Some(262_144))
        .build();
    let location = DefaultLocationGenerator::new(table.metadata())?;
    let mut output = Vec::new();
    for (hour, events) in by_hour {
        let batches = json_batches(arrow_schema.clone(), &events)?;
        let file_names = DefaultFileNameGenerator::new(
            format!("nano-{}", &digest[..12]),
            None,
            DataFileFormat::Parquet,
        );
        let parquet = ParquetWriterBuilder::new(
            properties.clone(),
            table.metadata().current_schema().clone(),
        );
        let rolling = RollingFileWriterBuilder::new(
            parquet,
            256 * 1_024 * 1_024,
            table.file_io().clone(),
            location.clone(),
            file_names,
        );
        let writer = DataFileWriterBuilder::new(rolling);
        let partition = PartitionKey::new(
            partition_spec.clone(),
            table.metadata().current_schema().clone(),
            Struct::from_iter([Some(Literal::int(hour))]),
        );
        let mut writer = writer.build(Some(partition)).await?;
        for batch in batches {
            writer.write(batch).await?;
        }
        output.extend(writer.close().await?);
    }
    if output.is_empty() {
        bail!("event publication produced no Iceberg data files");
    }
    Ok(output)
}

fn json_batches(schema: Arc<ArrowSchema>, rows: &[Value]) -> Result<Vec<RecordBatch>> {
    let mut bytes = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut bytes, row)?;
        bytes.push(b'\n');
    }
    ReaderBuilder::new(schema)
        .with_batch_size(rows.len().max(1))
        .build(Cursor::new(bytes))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("decode canonical OCSF JSON into the Iceberg Arrow schema")
}

fn json_batches_refs(schema: Arc<ArrowSchema>, rows: &[&Value]) -> Result<Vec<RecordBatch>> {
    let mut bytes = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut bytes, row)?;
        bytes.push(b'\n');
    }
    ReaderBuilder::new(schema)
        .with_batch_size(rows.len().max(1))
        .build(Cursor::new(bytes))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("decode canonical OCSF JSON into the Iceberg Arrow schema")
}

/// True when JSON-to-Arrow inference gives `value` NO physical column: a
/// null, an empty object or array, or an object/array whose every member is
/// itself physically null. `prune_inferred_null_fields` drops exactly these
/// from a proposed schema, so a validator that treated them as present would
/// demand a column the schema path can never add.
///
/// NAN-2361 wave 8: this is how a brand-new tenant deadlocked. Its first
/// audit events are provisioning actions with no user agent, so every row
/// carried `"http_request": {"user_agent": null}`. Inference pruned
/// `http_request`, the additive-schema path correctly added nothing, and the
/// encoder then refused the very same rows with "Iceberg serving schema is
/// missing OCSF field http_request; schema generation rewrite required" --
/// forever, because no rewrite could ever produce a column for an all-null
/// struct. Reading the value the way inference reads it closes the loop.
pub fn physically_null(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(values) => values.values().all(physically_null),
        Value::Array(values) => values.iter().all(physically_null),
        _ => false,
    }
}

fn validate_physical_shape(value: &Value, data_type: &DataType, path: &str) -> Result<()> {
    if physically_null(value) {
        return Ok(());
    }
    match (value, data_type) {
        (Value::Object(values), DataType::Struct(fields)) => {
            for (name, child) in values {
                // JSON-to-Arrow inference represents an optional field that is
                // null in every row as having no physical column. A later
                // sparse row carrying the same null is therefore compatible
                // with the current schema and must not force a meaningless
                // schema addition or generation rewrite. The same holds for a
                // struct or list whose members are all null (`physically_null`).
                if physically_null(child) {
                    continue;
                }
                let field = fields
                    .iter()
                    .find(|field| field.name() == name)
                    .with_context(|| {
                        let child_path = child_path(path, name);
                        format!(
                            "Iceberg serving schema is missing OCSF field {child_path}; schema generation rewrite required"
                        )
                    })?;
                validate_physical_shape(child, field.data_type(), &child_path(path, name))?;
            }
            Ok(())
        }
        (Value::Array(values), DataType::List(field) | DataType::LargeList(field)) => {
            for (index, child) in values.iter().enumerate() {
                validate_physical_shape(child, field.data_type(), &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        (Value::Object(values), DataType::Map(field, _)) => validate_map_shape(values, field, path),
        (Value::Object(_), _) | (Value::Array(_), _) => {
            bail!("OCSF field {path} conflicts with the Iceberg physical shape")
        }
        _ => Ok(()),
    }
}

fn validate_map_shape(
    values: &serde_json::Map<String, Value>,
    field: &Field,
    path: &str,
) -> Result<()> {
    let DataType::Struct(entries) = field.data_type() else {
        bail!("Iceberg map entry shape is invalid at {path}");
    };
    let value_type = entries
        .iter()
        .find(|field| field.name() == "value")
        .map(|field| field.data_type())
        .context("Iceberg map entry has no value field")?;
    for (name, child) in values {
        validate_physical_shape(child, value_type, &child_path(path, name))?;
    }
    Ok(())
}

fn child_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}.{child}")
    }
}

fn required_metadata_location(table: &Table) -> Result<&str> {
    table
        .metadata_location()
        .context("REST catalog table has no metadata location")
}

#[cfg(test)]
mod tests {

    // NAN-2380: `value_covered_by` is the fast path that decides whether a
    // batch can skip full JSON schema inference. Its ONLY safe failure
    // direction is "not covered" -- that just costs the slow path. Being wrong
    // the other way would silently skip a schema addition, so every case below
    // that is not provably representable must come back false.
    use super::{value_covered_by, DataType, Field, TimeUnit};

    fn live_schema() -> DataType {
        DataType::Struct(Fields::from(vec![
            Field::new("class_uid", DataType::Int64, true),
            Field::new("message", DataType::Utf8, true),
            Field::new("score", DataType::Float64, true),
            Field::new(
                "time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())),
                false,
            ),
            Field::new(
                "metadata",
                DataType::Struct(Fields::from(vec![Field::new("uid", DataType::Utf8, true)])),
                true,
            ),
            Field::new(
                "observables",
                DataType::List(std::sync::Arc::new(Field::new(
                    "item",
                    DataType::Struct(Fields::from(vec![Field::new("name", DataType::Utf8, true)])),
                    true,
                ))),
                true,
            ),
        ]))
    }

    #[test]
    fn schema_coverage_index_matches_conservative_value_validation() {
        let schema = live_schema();
        let indexed = SchemaCoverage::compile(&schema);
        for event in [
            json!({"message": "ok", "class_uid": 2004}),
            json!({"message": 3}), json!({"class_uid": 1.5}),
            json!({"metadata": {"uid": "a"}}), json!({"metadata": {"unknown": "a"}}),
            json!({"unknown": null}), json!({"unknown": "a"}),
            json!({"observables": [{"name": "ip"}]}),
            json!({"observables": [{"unexpected": 1}]}),
            json!({"observables": "invalid"}), json!({"metadata": true}),
            json!(null), json!([]), json!({}),
        ] {
            assert_eq!(indexed.covers(&event), value_covered_by(&event, &schema), "{event}");
        }
    }

    #[test]
    fn schema_coverage_accepts_a_batch_the_live_schema_already_describes() {
        let event = json!({
            "class_uid": 2004,
            "message": "hello",
            "time": "2026-08-23T00:00:00Z",
            "metadata": {"uid": "abc"},
            "observables": [{"name": "src_ip"}],
        });
        assert!(value_covered_by(&event, &live_schema()));
    }

    #[test]
    fn schema_coverage_accepts_an_epoch_number_for_a_timestamp_column() {
        // Normalised OCSF carries `time` as a number in some paths and an
        // RFC3339 string in others; both are representable by the timestamp
        // column, and treating either as "new" would defeat the fast path.
        let event = json!({"time": 1_755_000_000_000_i64});
        assert!(value_covered_by(&event, &live_schema()));
    }

    #[test]
    fn schema_coverage_rejects_a_field_the_live_schema_does_not_have() {
        let event = json!({"class_uid": 2004, "brand_new_ocsf_field": "x"});
        assert!(!value_covered_by(&event, &live_schema()));
    }

    #[test]
    fn schema_coverage_rejects_a_new_field_nested_inside_a_known_struct() {
        let event = json!({"metadata": {"uid": "abc", "correlation_uid": "new"}});
        assert!(!value_covered_by(&event, &live_schema()));
    }

    #[test]
    fn schema_coverage_rejects_a_new_field_inside_a_list_element() {
        let event = json!({"observables": [{"name": "src_ip", "type": "ip"}]});
        assert!(!value_covered_by(&event, &live_schema()));
    }

    #[test]
    fn schema_coverage_rejects_a_primitive_type_change_so_it_still_fails_closed() {
        // A string where the live schema declares Int64 must NOT be waved
        // through: the slow path is what raises the fail-closed generation
        // rewrite error, so the fast path has to route this batch there.
        let event = json!({"class_uid": "2004"});
        assert!(!value_covered_by(&event, &live_schema()));
    }

    #[test]
    fn schema_coverage_rejects_a_fraction_in_an_integer_column() {
        // `additive_columns` widens Double <- Long but NEVER Long <- Double, so
        // this is a fail-closed type conflict. The fast path must route it to
        // the slow path rather than silently staging a truncated value.
        let event = json!({"class_uid": 2004.5});
        assert!(!value_covered_by(&event, &live_schema()));
    }

    #[test]
    fn schema_coverage_accepts_an_integer_in_a_float_column() {
        // The reverse widening IS permitted (Double <- Long), so demanding the
        // slow path here would forfeit the fast path for no safety gain.
        let event = json!({"score": 3});
        assert!(value_covered_by(&event, &live_schema()));
    }

    #[test]
    fn schema_coverage_rejects_a_shape_change_from_scalar_to_struct() {
        let event = json!({"message": {"nested": "x"}});
        assert!(!value_covered_by(&event, &live_schema()));
    }

    #[test]
    fn schema_coverage_treats_an_unknown_null_field_as_covered() {
        // JSON-to-Arrow inference gives an all-null field no physical column,
        // so a sparse row carrying that null must not force a schema addition.
        // This mirrors `validate_physical_shape` and `prune_inferred_null_fields`.
        let event = json!({"class_uid": 2004, "not_in_schema_yet": null});
        assert!(value_covered_by(&event, &live_schema()));
    }

    #[test]
    fn parquet_compression_levels_match_the_measured_layout_policy() {
        // NAN-2361: the existing property test asserts only that the codec is
        // "zstd", so a LEVEL regression was invisible. The levels are not
        // arbitrary -- they come from the Codex footprint measurement, and the
        // split between them is the whole point:
        //
        //   durable generation data (write_data_files) and the default tail
        //   repack policy -> 9. 14.0% fewer bytes than zstd-3-equivalent AND faster scans
        //        (CONTAINS p50 83.1 ms -> 56.7 ms) because fewer compressed
        //        bytes are touched. Written once, read for the whole retention
        //        window, so the 3.2x write cost is worth it.
        //   staged ingest encode (encode_staged_event_files)
        //     -> 6. Short-lived objects on the ingest latency path; they get
        //        packed and superseded, so paying zstd-9 to compress bytes
        //        that are about to be rewritten is waste.
        //
        // zstd-19 was measured and REJECTED: a 38x write penalty for another
        // ~9.5% only makes sense for an explicit cold/archive rewrite.
        let source = include_str!("iceberg.rs");
        let mut durable_generation = 0_usize;
        let mut staged = 0_usize;
        let mut current_fn = String::new();
        for line in source.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("fn ")
                || trimmed.starts_with("pub fn ")
                || trimmed.contains("async fn ")
            {
                current_fn = trimmed.to_string();
            }
            if !line.contains("ZstdLevel::try_new") || line.trim_start().starts_with("//") {
                continue;
            }
            if current_fn.contains("write_data_files") {
                assert!(
                    line.contains("try_new(9)"),
                    "durable event writer must stay at zstd-9: {current_fn}"
                );
                durable_generation += 1;
            } else if current_fn.contains("repack_staged_event_files_with_compression") {
                assert!(
                    line.contains("try_new(compression_level)"),
                    "tail repack must use its validated deployment setting: {current_fn}"
                );
            } else if current_fn.contains("encode_staged_event_files") {
                assert!(
                    line.contains("try_new(6)"),
                    "staged ingest encoder must stay at zstd-6 (latency path): {current_fn}"
                );
                staged += 1;
            }
        }
        assert_eq!(
            durable_generation, 1,
            "expected the durable generation writer to be checked"
        );
        assert_eq!(staged, 1, "expected the staged encoder to be checked");
        let whitespace_insensitive_source = source.split_whitespace().collect::<String>();
        assert!(
            whitespace_insensitive_source.contains(
                "repack_staged_event_files_with_compression(table,tenant_id,event_hour,pack_id,paths,9)"
            ),
            "the compatibility repack API must retain its measured zstd-9 default"
        );
    }
    use super::*;
    use arrow_array::{Array, ArrayRef, Int64Array, StringArray, StructArray};
    use arrow_schema::Fields;
    use serde_json::json;

    #[test]
    fn staged_object_paths_bind_the_exact_parquet_digest() {
        let logical = "a".repeat(64);
        let first_sha256 = "b".repeat(64);
        let second_sha256 = "c".repeat(64);
        let first =
            content_addressed_staged_path("tenant-a", 123, "batch", &logical, &first_sha256)
                .unwrap();
        let second =
            content_addressed_staged_path("tenant-a", 123, "batch", &logical, &second_sha256)
                .unwrap();
        let pack = content_addressed_staged_path("tenant-a", 123, "pack", &logical, &first_sha256)
            .unwrap();

        assert_ne!(first, second);
        assert!(first.ends_with(&format!("/batch-{logical}-{first_sha256}.parquet")));
        assert!(second.ends_with(&format!("/batch-{logical}-{second_sha256}.parquet")));
        assert!(pack.ends_with(&format!("/pack-{logical}-{first_sha256}.parquet")));
        assert!(
            content_addressed_staged_path("tenant-a", 123, "other", &logical, &first_sha256)
                .is_err()
        );
    }

    #[test]
    fn catalog_session_refresh_is_limited_to_unauthorized_failures() {
        let expired =
            anyhow::anyhow!("Unexpected, context: {{ status: 401 Unauthorized, headers: {{}} }}")
                .context("load current Iceberg table");
        assert!(catalog_session_expired(&expired));
        assert!(!catalog_session_expired(&anyhow::anyhow!(
            "Iceberg advanced while its snapshot was being hydrated"
        )));
        assert!(!catalog_session_expired(&anyhow::anyhow!(
            "status: 403 Forbidden"
        )));
    }

    #[test]
    fn staged_tail_alignment_null_fills_additive_columns() {
        let old_schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "time",
            DataType::Int64,
            false,
        )]));
        let batch = RecordBatch::try_new(
            old_schema,
            vec![Arc::new(Int64Array::from(vec![1_i64, 2_i64]))],
        )
        .unwrap();
        let current = Arc::new(ArrowSchema::new(vec![
            Field::new("time", DataType::Int64, false),
            Field::new("src_endpoint", DataType::Utf8, true),
        ]));
        let aligned = align_staged_batch(batch, current.clone()).unwrap();
        assert_eq!(aligned.len(), 1);
        assert_eq!(aligned[0].schema(), current);
        assert_eq!(aligned[0].num_rows(), 2);
        let endpoint = aligned[0]
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(endpoint.null_count(), 2);
    }

    #[test]
    fn identity_pack_writes_statistics_and_case_safe_blooms() {
        use crate::{planner::CandidateHint, tail_predicate::object_may_match};
        use parquet::file::reader::FileReader;
        let identity = |name: &str| Field::new(name, DataType::Struct(vec![Field::new("name", DataType::Utf8, true)].into()), true);
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("metadata", DataType::Struct(vec![Field::new("uid", DataType::Utf8, false)].into()), false),
            Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())), false),
            identity("user"),
            Field::new("actor", DataType::Struct(vec![identity("user")].into()), true),
            Field::new("src_endpoint", DataType::Struct(vec![Field::new("ip", DataType::Utf8, true), Field::new("hostname", DataType::Utf8, true)].into()), true),
        ]));
        let rows = ["Alice", "JSmith", "Zoe"].iter().enumerate().map(|(i,name)| json!({
            "metadata":{"uid":format!("event-{i}")}, "time":"2026-09-21T14:00:00+00:00",
            "user":{"name":name}, "actor":{"user":{"name":"Other"}},
            "src_endpoint":{"ip":"192.0.2.1", "hostname":"Host.Example"}
        })).collect::<Vec<_>>();
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("staged.parquet");
        let mut writer = ArrowWriter::try_new(File::create(&input).unwrap(), schema.clone(), None).unwrap();
        for batch in json_batches(schema.clone(), &rows).unwrap() { writer.write(&batch).unwrap(); }
        writer.close().unwrap();
        let packed = repack_staged_files_with_profile(schema, TailIdentityProfile::Ocsf, "tenant-a", 497198, &"a".repeat(64), &[input], 3).unwrap();
        let output = dir.path().join("packed.parquet");
        std::fs::write(&output, &packed.bytes).unwrap();
        let reader = parquet::file::serialized_reader::SerializedFileReader::new(File::open(&output).unwrap()).unwrap();
        for path in ["user.name", "actor.user.name", "src_endpoint.ip", "src_endpoint.hostname"] {
            let index = reader.metadata().file_metadata().schema_descr().columns().iter().position(|c| c.path().string() == path).unwrap();
            let column = reader.metadata().row_group(0).column(index);
            assert!(column.statistics().is_some(), "{path}");
            assert!(column.bloom_filter_offset().is_some(), "{path}");
        }
        let hint = |path: &str, value: &str| CandidateHint::Entity { source_path:path.into(), value:value.into() };
        assert!(object_may_match(&output, &[hint("user.name", "jsmith")]));
        assert!(!object_may_match(&output, &[hint("user.name", "bob")])); // inside min/max, bloom proves absence
        assert!(!object_may_match(&output, &[hint("actor.user.name", "jsmith")]));
        assert!(object_may_match(&output, &[CandidateHint::Any { alternatives:vec![hint("actor.user.name", "jsmith"), hint("user.name", "jsmith")] }]));
        assert!(object_may_match(&output, &[hint("missing.name", "bob")]));
        assert!(object_may_match(&output, &[hint("user.name", "é")]));
        assert!(object_may_match(&dir.path().join("missing"), &[hint("user.name", "bob")]));
    }

    #[test]
    fn staged_tail_pack_deduplicates_retries_and_rejects_uid_conflicts() {
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new(
                "metadata",
                DataType::Struct(
                    vec![
                        Field::new("uid", DataType::Utf8, false),
                        Field::new("original_event_uid", DataType::Utf8, false),
                        Field::new("logged_time", DataType::Int64, false),
                        Field::new("processed_time", DataType::Int64, false),
                    ]
                    .into(),
                ),
                false,
            ),
            Field::new("message", DataType::Utf8, false),
            Field::new(
                "time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())),
                false,
            ),
        ]));
        let batches = json_batches(
            schema.clone(),
            &[
                json!({
                    "metadata": {"uid": "event-a", "original_event_uid": "parser-1", "logged_time": 1, "processed_time": 1},
                    "message": "same",
                    "time": "2026-08-15T12:00:00.000000+00:00"
                }),
                json!({
                    "metadata": {"uid": "event-a", "original_event_uid": "parser-2", "logged_time": 2, "processed_time": 2},
                    "message": "same",
                    "time": "2026-08-15T12:00:00.000000+00:00"
                }),
                json!({
                    "metadata": {"uid": "event-b", "original_event_uid": "parser-3", "logged_time": 1, "processed_time": 1},
                    "message": "other",
                    "time": "2026-08-15T12:00:01.000000+00:00"
                }),
            ],
        )
        .unwrap();
        let mut identities = HashMap::new();
        let (filtered, removed) =
            deduplicate_staged_batch_for(batches[0].clone(), &mut identities, TailIdentityProfile::Ocsf).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(filtered.unwrap().num_rows(), 2);
        assert_eq!(identities.len(), 2);

        let conflict = json_batches(
            schema,
            &[json!({
                "metadata": {"uid": "event-a", "original_event_uid": "parser-4", "logged_time": 3, "processed_time": 3},
                "message": "conflicting",
                "time": "2026-08-15T12:00:00.000000+00:00"
            })],
        )
        .unwrap();
        assert!(
            deduplicate_staged_batch_for(conflict[0].clone(), &mut identities, TailIdentityProfile::Ocsf)
                .unwrap_err()
                .to_string()
                .contains("conflicting event UID event-a")
        );
    }

    fn span_row(trace: &str, span: &str, start: &str, ingest: &str, name: &str) -> Value {
        json!({
            "tenant_uid": "t", "trace_id": trace, "span_id": span, "parent_span_id": "",
            "start_time": start, "end_time": start, "duration_ns": 0,
            "service_name": "api", "span_name": name, "span_kind": "server", "status_code": "OK",
            "status_message": "", "attributes_json": "{}", "resource_attributes_json": "{}",
            "events_json": "[]", "links_json": "[]", "src_ip": "", "dest_ip": "", "user": "",
            "host": "", "ingest_time": ingest, "raw_otlp_json": "{}"
        })
    }

    /// NAN-2361 wave 7: the OTLP span profile dedupes on
    /// `trace_id:span_id:start_time`, ignores the drain's `ingest_time` when
    /// fingerprinting a retry, and refuses a same-identity payload change.
    #[test]
    fn otlp_span_profile_dedupes_on_trace_span_start_and_ignores_ingest_time() {
        let schema = Arc::new(TailIdentityProfile::OtelSpans.native_arrow_schema().unwrap());
        let batches = json_batches(
            schema.clone(),
            &[
                span_row("a".repeat(32).as_str(), "b".repeat(16).as_str(), "2026-08-15T12:00:00.000000+00:00", "2026-08-15T12:00:05+00:00", "GET /"),
                span_row("a".repeat(32).as_str(), "b".repeat(16).as_str(), "2026-08-15T12:00:00.000000+00:00", "2026-08-15T12:00:09+00:00", "GET /"),
                span_row("a".repeat(32).as_str(), "c".repeat(16).as_str(), "2026-08-15T12:00:01.000000+00:00", "2026-08-15T12:00:05+00:00", "GET /x"),
            ],
        )
        .unwrap();
        let mut identities = HashMap::new();
        let (filtered, removed) =
            deduplicate_staged_batch_for(batches[0].clone(), &mut identities, TailIdentityProfile::OtelSpans).unwrap();
        assert_eq!(removed, 1, "a redelivered span differing only in ingest_time collapses");
        assert_eq!(filtered.as_ref().unwrap().num_rows(), 2);
        assert!(identities.contains_key(&format!("{}:{}:{}", "a".repeat(32), "b".repeat(16), 1_786_795_200_000_000_i64)));
        let (min_ms, max_ms) = batch_time_bounds_ms_for(filtered.as_ref().unwrap(), "start_time").unwrap();
        assert_eq!((min_ms, max_ms), (1_786_795_200_000, 1_786_795_201_000));
        assert!(batch_time_bounds_ms(filtered.as_ref().unwrap()).is_err(), "OTLP rows carry no OCSF time column");
        let conflict = json_batches(
            schema,
            &[span_row("a".repeat(32).as_str(), "b".repeat(16).as_str(), "2026-08-15T12:00:00.000000+00:00", "2026-08-15T12:00:05+00:00", "POST /")],
        )
        .unwrap();
        assert!(deduplicate_staged_batch_for(conflict[0].clone(), &mut identities, TailIdentityProfile::OtelSpans)
            .unwrap_err()
            .to_string()
            .contains("conflicting event UID"));
        // The OCSF profile cannot read an OTLP batch, and the reverse.
        assert!(deduplicate_staged_batch_for(batches[0].clone(), &mut HashMap::new(), TailIdentityProfile::Ocsf).is_err());
    }

    #[test]
    fn otlp_metric_profile_dedupes_on_metric_uid_and_sorts_by_metric_then_time() {
        let schema = Arc::new(TailIdentityProfile::OtelMetrics.native_arrow_schema().unwrap());
        let metric = |uid: &str, name: &str, at: &str, value: f64| {
            json!({
                "tenant_uid": "t", "metric_uid": uid, "metric_name": name, "metric_type": "gauge", "unit": "1",
                "timestamp": at, "value": value, "count": 0, "sum": 0.0, "bucket_counts": [], "explicit_bounds": [],
                "aggregation_temporality": 0, "attributes_json": "{}", "resource_attributes_json": "{}",
                "service_name": "api", "ingest_time": "2026-08-15T12:00:05+00:00", "raw_otlp_json": "{}"
            })
        };
        let batches = json_batches(
            schema,
            &[
                metric("m2", "cpu", "2026-08-15T12:00:02+00:00", 1.0),
                metric("m1", "cpu", "2026-08-15T12:00:01+00:00", 1.0),
                metric("m1", "cpu", "2026-08-15T12:00:01+00:00", 1.0),
                metric("m3", "alloc", "2026-08-15T12:00:00+00:00", 2.0),
            ],
        )
        .unwrap();
        let mut identities = HashMap::new();
        let (filtered, removed) =
            deduplicate_staged_batch_for(batches[0].clone(), &mut identities, TailIdentityProfile::OtelMetrics).unwrap();
        assert_eq!(removed, 1);
        let sorted = sort_pack_buffer_for(filtered.as_ref().unwrap(), TailIdentityProfile::OtelMetrics).unwrap();
        let names = sorted
            .column_by_name("metric_uid")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap()
            .iter()
            .map(|v| v.unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["m3", "m1", "m2"], "alloc sorts before cpu, then by timestamp");
    }

    #[test]
    fn identity_profiles_follow_the_ledger_and_the_table_name() {
        assert_eq!(TailIdentityProfile::for_table_name("scale04_live_f.events"), TailIdentityProfile::Ocsf);
        assert_eq!(TailIdentityProfile::for_table_name("scale04_live_f.otel_spans"), TailIdentityProfile::OtelSpans);
        assert_eq!(TailIdentityProfile::for_table_name("otel_metrics"), TailIdentityProfile::OtelMetrics);
        assert_eq!(TailIdentityProfile::for_hot_tail_object("otel-handoff-v1", "otel_spans").unwrap(), TailIdentityProfile::OtelSpans);
        assert_eq!(TailIdentityProfile::for_hot_tail_object("nano-tail-pack-v1-l0", "otel_metrics").unwrap(), TailIdentityProfile::OtelMetrics);
        assert_eq!(TailIdentityProfile::for_hot_tail_object("nano-vector-bronze-v2", "events").unwrap(), TailIdentityProfile::Ocsf);
        assert!(TailIdentityProfile::for_hot_tail_object("otel-handoff-v1", "events").is_err());
        assert_eq!(TailIdentityProfile::OtelSpans.partition_field_name(), "start_time_hour");
        assert_eq!(TailIdentityProfile::OtelMetrics.time_column(), "timestamp");
        let properties = TailIdentityProfile::OtelSpans.snapshot_properties();
        assert!(properties.iter().any(|(k, v)| *k == "nano.otel-dataset" && v == "spans"));
        assert!(!properties.iter().any(|(k, _)| *k == "nano.ocsf-version"));
        assert!(TailIdentityProfile::Ocsf.snapshot_properties().iter().any(|(k, _)| *k == "nano.ocsf-version"));
    }

    /// An empty secret half is a non-empty STRING, so it slipped past the
    /// emptiness checks and only surfaced as `401 invalid_client` from the token
    /// endpoint. That is precisely what a compose `${VAR:-}` default produces for
    /// a missing secret, and it took a live outage to diagnose.
    #[tokio::test]
    async fn a_credential_with_an_empty_secret_half_is_rejected_before_any_request() {
        let error = catalog_config(Some("nano-lakekeeper-runtime:"), false)
            .load()
            .await
            .expect_err("an empty secret half must not be accepted");
        let message = format!("{error:#}");
        assert!(
            message.contains("EMPTY client secret"),
            "error must name the empty secret: {message}"
        );

        let empty_id = format!(
            "{:#}",
            catalog_config(Some(":secret"), false)
                .load()
                .await
                .expect_err("an empty client id must not be accepted")
        );
        assert!(
            empty_id.contains("empty client id"),
            "error must name the empty client id: {empty_id}"
        );

        // A colon-less credential is the legal bare-token form (see the
        // `catalog_token` path in rest_commit.rs). It must be ACCEPTED, not parsed
        // as a client id -- doing the latter both misdiagnosed it as an empty
        // secret and interpolated the whole secret into the error message.
        catalog_config(Some("s3cr3t-bare-token-value"), false)
            .load()
            .await
            .expect("a bare-token credential is a legal form and must be accepted");
    }

    fn catalog_config(credential: Option<&str>, allow_anonymous: bool) -> CatalogConfig {
        CatalogConfig {
            uri: "http://127.0.0.1:1/catalog".to_string(),
            warehouse: "test".to_string(),
            credential: credential.map(str::to_string),
            token_file: None,
            oauth_scope: None,
            oauth_audience: None,
            oauth_server_uri: None,
            realm: None,
            allow_anonymous,
            s3_endpoint: "http://127.0.0.1:2".to_string(),
            s3_region: "us-east-1".to_string(),
            s3_access_key: "access".to_string(),
            s3_secret_key: "secret".to_string(),
            s3_session_token: None,
            s3_path_style_access: true,
            s3_default_credentials: false,
            vended_credentials: false,
        }
    }

    #[tokio::test]
    async fn anonymous_catalog_access_fails_closed_without_explicit_override() {
        let error = catalog_config(None, false).load().await.unwrap_err();
        assert!(error
            .to_string()
            .contains("catalog authentication is required"));

        let error = catalog_config(Some("client:secret"), true)
            .load()
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot be combined with authenticated catalog access"));
    }

    /// NAN-3003: the platform stamp allowance is scoped to source rows. A
    /// product row (platform audit / Detection Finding) carrying one is still
    /// refused by the strict OCSF check.
    #[test]
    fn platform_metadata_stamps_are_refused_on_product_rows() {
        for (name, value) in [
            (METADATA_PARSER_BUNDLE_SHA256, json!("ab".repeat(32))),
            (METADATA_CREDENTIAL_ID, json!("0b7f7a5e-3c1d-4f7e-9a2b-1c2d3e4f5a6b")),
            (METADATA_INGRESS_TRANSPORT, json!("hec")),
        ] {
            let mut row = event("audit-stamp");
            row.ocsf_event["metadata"][name] = value;
            let error = normalize_event(&row, "tenant-a").unwrap_err().to_string();
            assert!(error.contains(&format!("metadata.{name}")), "{error}");
        }
        assert!(normalize_event(&event("audit-stamp"), "tenant-a").is_ok());
    }

    #[test]
    fn platform_stamp_formats_are_exact() {
        assert!(is_platform_sha256(&"0a".repeat(32)));
        for bad in ["0A".repeat(32), "0a".repeat(31), format!("{}g", "0".repeat(63)), String::new()] {
            assert!(!is_platform_sha256(&bad), "{bad}");
        }
        assert!(is_platform_credential_id("0b7f7a5e-3c1d-4f7e-9a2b-1c2d3e4f5a6b"));
        for bad in [
            "0B7F7A5E-3C1D-4F7E-9A2B-1C2D3E4F5A6B", // uppercase
            "0b7f7a5e3c1d4f7e9a2b1c2d3e4f5a6b",     // simple form
            "0b7f7a5e-3c1d-9f7e-9a2b-1c2d3e4f5a6b", // version 9
            "0b7f7a5e-3c1d-4f7e-7a2b-1c2d3e4f5a6b", // variant 7
            "0b7f7a5e-3c1d-4f7e-9a2b-1c2d3e4f5a6",  // short
        ] {
            assert!(!is_platform_credential_id(bad), "{bad}");
        }
    }

    fn event(uid: &str) -> EventRow {
        EventRow {
            event_uid: uid.to_string(),
            event_kind: EventKind::PlatformAudit,
            ocsf_event: json!({
                "activity_id": 1,
                "activity_name": "Create",
                "actor": {"user": {"name": "tester"}},
                "api": {"operation": "test"},
                "category_name": "System Activity",
                "category_uid": 6,
                "class_name": "API Activity",
                "class_uid": 6003,
                "message": "test",
                "metadata": {
                    "log_name": "audit",
                    "log_source": "audit",
                    "product": {"name": "nano", "vendor_name": "nano"},
                    "tenant_uid": "tenant-a",
                    "uid": uid,
                    "version": "1.9.0"
                },
                "severity": "Informational",
                "severity_id": 1,
                "src_endpoint": {"ip": "127.0.0.1"},
                "status": "Success",
                "status_id": 1,
                "time": 1_786_435_200_000_i64,
                "type_uid": 600301,
            }),
        }
    }

    #[test]
    fn historical_operator_audit_supplies_only_a_truthful_unknown_endpoint() {
        for action in ["ingest_credential_created", "ingest_credential_revoked"] {
            let mut row = event("operator-audit");
            row.ocsf_event.as_object_mut().unwrap().remove("src_endpoint");
            row.ocsf_event["api"] = json!({"operation": action, "service": {"name":"operator"}});
            row.ocsf_event["unmapped"] = json!({"source":"operator", "action":action, "resource_type":"ingest_credential"});
            let original = row.ocsf_event.clone();
            let (_, normalized) = normalize_event(&row, "tenant-a").unwrap();
            assert_eq!(normalized["src_endpoint"], json!({"ip":null}));
            assert_eq!(normalized["actor"], original["actor"]);
            assert_eq!(normalized["metadata"], original["metadata"]);
            assert_eq!(row.ocsf_event, original, "immutable source payload is never rewritten");
            for endpoint in [Value::Null, json!("invalid"), json!({"ip":"not-an-ip"})] {
                let mut invalid = row.clone();
                invalid.ocsf_event["src_endpoint"] = endpoint;
                assert!(normalize_event(&invalid, "tenant-a").is_err(), "present invalid endpoint must not be replaced");
            }
            for (pointer,value) in [("/api/service/name","auth"), ("/api/operation","other"),
                ("/unmapped/source","auth"), ("/unmapped/action","other"), ("/unmapped/resource_type","other")] {
                let mut invalid = row.clone();
                *invalid.ocsf_event.pointer_mut(pointer).unwrap() = json!(value);
                // NAN-2764: other provenance no longer fails; it gets the
                // labelled emitting-service endpoint, never the historical
                // `{"ip": null}` form reserved for the exact SQL170 producer.
                let (_, normalized) = normalize_event(&invalid, "tenant-a").unwrap();
                assert_ne!(normalized["src_endpoint"], json!({"ip":null}), "{pointer}");
                assert_eq!(normalized["unmapped"]["nano_src_endpoint"], json!(SYNTHESIZED_SRC_ENDPOINT_MARKER));
            }
            let mut invalid = row.clone(); invalid.event_kind = EventKind::Signal;
            assert!(normalize_event(&invalid, "tenant-a").is_err());
        }
        // NAN-2764: any other API Activity audit without a recorded client
        // address now gets the emitting-service endpoint instead of failing.
        let mut unrelated = event("unrelated");
        unrelated.ocsf_event.as_object_mut().unwrap().remove("src_endpoint");
        let (_, normalized) = normalize_event(&unrelated, "tenant-a").unwrap();
        assert!(normalized["src_endpoint"]["ip"].is_null());
        assert_eq!(normalized["src_endpoint"]["svc_name"], "nano");
    }

    fn fixture_row(kind: EventKind, mut event: Value) -> EventRow {
        let uid = event["metadata"]["uid"].as_str().unwrap().to_string();
        event["metadata"]["tenant_uid"] = json!("tenant-a");
        EventRow { event_uid: uid, event_kind: kind, ocsf_event: event }
    }

    /// NAN-2764: the live 2004 Detection Finding from a sysmon process
    /// detection carries no src_endpoint/device. OCSF 1.9 defines neither as
    /// a Detection Finding attribute requirement, so it must publish as is.
    #[test]
    fn nan2764_sysmon_detection_finding_without_endpoint_publishes() {
        let finding: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/nan2764-sysmon-detection-finding.json"
        ))
        .unwrap();
        assert!(finding.get("src_endpoint").is_none() && finding.get("device").is_none());
        let row = fixture_row(EventKind::Signal, finding);
        let (_, normalized) = normalize_event(&row, "tenant-a").unwrap();
        assert_eq!(normalized["class_uid"], 2004);
        assert!(normalized.get("src_endpoint").is_none(), "a finding never gains an endpoint");
        assert!(normalize_batch(std::slice::from_ref(&row), "tenant-a").is_ok());
    }

    /// NAN-2764: platform audits written by services and operators (the platform
    /// fulfilment, operator route/cell/assignment changes, SQL-side tenant
    /// revocations) record no client address. OCSF 1.9 requires
    /// `src_endpoint` on API Activity (6003), so every such row failed
    /// validation and wedged tenant1's product-event reservation for ~36 h.
    /// The publisher must describe the emitting service instead: never an
    /// invented IP, always marked as synthesized, source row untouched.
    #[test]
    fn nan2764_system_actor_audits_publish_with_the_emitting_service_endpoint() {
        let audits: Vec<Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/nan2764-system-actor-audits.json"
        ))
        .unwrap();
        assert!(audits.len() >= 4);
        let rows: Vec<EventRow> = audits
            .into_iter()
            .map(|audit| fixture_row(EventKind::PlatformAudit, audit))
            .collect();
        for row in &rows {
            assert!(row.ocsf_event.get("src_endpoint").is_none());
            let original = row.ocsf_event.clone();
            let (_, normalized) = normalize_event(row, "tenant-a").unwrap_or_else(|error| {
                panic!("{}: {error:#}", row.ocsf_event["api"]["operation"])
            });
            let service = original["api"]["service"]["name"].as_str().unwrap();
            assert_eq!(normalized["src_endpoint"]["svc_name"], service);
            assert_eq!(normalized["src_endpoint"]["name"], service);
            assert_eq!(normalized["src_endpoint"]["type_id"], 99);
            assert!(normalized["src_endpoint"].get("ip").is_none(), "no invented client IP");
            assert_eq!(
                normalized["unmapped"]["nano_src_endpoint"],
                json!("synthesized:emitting_service")
            );
            for (key, value) in original["unmapped"].as_object().unwrap() {
                if value.is_object() || value.is_array() {
                    // Free-form payloads publish as one lossless JSON string.
                    let encoded = normalized["unmapped"][format!("{key}_json")].as_str().unwrap();
                    assert_eq!(&serde_json::from_str::<Value>(encoded).unwrap(), value);
                    assert!(normalized["unmapped"].get(key).is_none());
                } else {
                    assert_eq!(normalized["unmapped"][key], original["unmapped"][key]);
                }
            }
            assert_eq!(normalized["actor"], original["actor"]);
            assert_eq!(row.ocsf_event, original, "immutable source payload is never rewritten");
        }
        assert!(normalize_batch(&rows, "tenant-a").is_ok());

        // A present endpoint, even an invalid one, is the producer's claim and
        // is never replaced; explicit null stays invalid as before.
        let mut invalid = rows[0].clone();
        invalid.ocsf_event["src_endpoint"] = json!({"ip": "not-an-ip"});
        assert!(normalize_event(&invalid, "tenant-a").is_err());
        invalid.ocsf_event["src_endpoint"] = Value::Null;
        assert!(normalize_event(&invalid, "tenant-a").is_err());
        // Only platform audits: a Signal or source event is never repaired.
        let mut source = rows[0].clone();
        source.event_kind = EventKind::Signal;
        assert!(normalize_event(&source, "tenant-a").is_err());
    }

    #[test]
    fn canonical_event_is_validated_and_timestamp_is_normalized() {
        let (_, normalized) = normalize_event(&event("audit-1"), "tenant-a").unwrap();
        assert_eq!(normalized["time"], "2026-08-11T08:00:00+00:00");
    }

    #[test]
    fn source_event_accepts_arrow_timestamp_and_normalizes_identity_fields() {
        let mut row = event("source-1");
        row.event_kind = EventKind::Source;
        row.ocsf_event["time"] = json!("2026-08-11T08:00:00.123456+00:00");
        row.ocsf_event["metadata"]["log_source"] = json!("Windows_Event");
        row.ocsf_event["actor"]["user"]["name"] = json!("TESTER");
        row.ocsf_event["raw_data"] = json!("source payload");
        row.ocsf_event["raw_data_size"] = json!(14);
        let (_, normalized) = normalize_event(&row, "tenant-a").unwrap();
        assert_eq!(normalized["time"], "2026-08-11T08:00:00.123+00:00");
        assert_eq!(normalized["metadata"]["log_source"], "windows_event");
        assert_eq!(normalized["actor"]["user"]["name"], "tester");

        row.ocsf_event.as_object_mut().unwrap().remove("raw_data");
        assert!(normalize_event(&row, "tenant-a").is_err());
    }

    /// NAN-3422: Beats-shaped producer keys under `unmapped` are renamed to
    /// query identifiers at admission, at every depth, idempotently, so the
    /// inferred schema never carries a leaf the query contract cannot name.
    #[test]
    fn nan3422_source_unmapped_keys_become_query_identifiers() {
        let mut row = event("source-at-keys");
        row.event_kind = EventKind::Source;
        row.ocsf_event["raw_data"] = json!("source payload");
        row.ocsf_event["raw_data_size"] = json!(14);
        row.ocsf_event["unmapped"] = json!({
            "@timestamp": "2026-10-09T12:00:00Z",
            "@version": "1",
            "@metadata": {"beat": "winlogbeat", "@type": "_doc"},
            "_timestamp": "producer-owned",
            "winlog": {"event_data": [{"Event-ID": 4624}], "computer_name": "ws-1"},
            "2fa": true,
            "event_data.destination_is_ipv_6": "false",
            "event_data.@odd": "x",
            "trailing.": "y",
        });
        let (_, normalized) = normalize_event(&row, "tenant-a").unwrap();
        let unmapped = &normalized["unmapped"];
        assert_eq!(unmapped["_timestamp"], "producer-owned", "an existing valid key is never displaced");
        assert_eq!(unmapped["_timestamp_"], "2026-10-09T12:00:00Z");
        assert_eq!(unmapped["_version"], "1");
        assert_eq!(unmapped["_metadata"], json!({"beat": "winlogbeat", "_type": "_doc"}));
        assert_eq!(unmapped["winlog"]["event_data"][0]["Event_ID"], 4624);
        assert_eq!(unmapped["_2fa"], true);
        assert_eq!(unmapped["event_data.destination_is_ipv_6"], "false", "a dotted spill key is kept (NAN-3401)");
        assert_eq!(unmapped["event_data._odd"], "x");
        assert_eq!(unmapped["trailing._"], "y");
        assert_eq!(normalized["raw_data"], "source payload", "the verbatim event is kept");

        let schema = infer_generation_schema_events(1, std::iter::once(&normalized)).unwrap();
        let leaves = crate::generation::schema_leaf_types(&schema);
        assert!(
            leaves.keys().all(|path| nanosiem_core::schema::OcsfProfile::is_admissible_snapshot_field_path(path)),
            "every inferred leaf is addressable: {leaves:?}"
        );

        let again = EventRow { ocsf_event: normalized.clone(), ..row };
        assert_eq!(normalize_event(&again, "tenant-a").unwrap().1, normalized, "re-normalizing is stable");
    }

    /// NAN-3366: a fresh self-hosted install creates its empty event table
    /// before any event exists, through the publisher's own admission path.
    /// The table has no snapshot (the generation manager's bootstrap-generation
    /// input), is idempotent, and a real first batch widens it additively
    /// instead of tripping a fail-closed type conflict.
    ///
    /// The in-memory catalog refuses the reserved `format-version` property
    /// the REST catalog accepts, so (like the other admission tests) the
    /// table is created from the seed with `pipeline_test_table`, which is the
    /// production inference and partition spec minus that one property. The
    /// create call itself is exercised by the fresh-install proof.
    #[tokio::test]
    async fn bootstrap_event_table_seed_is_admissible_idempotent_and_widens() {
        use iceberg::{Catalog, CatalogBuilder};
        let catalog = iceberg::memory::MemoryCatalogBuilder::default()
            .load(
                "test",
                HashMap::from([("warehouse".to_string(), "s3://test/bootstrap".to_string())]),
            )
            .await
            .unwrap();
        let table_id = table_ident("default.events").unwrap();
        let location = "s3://test/bootstrap/default/events/";

        let seed = bootstrap_seed_batch("default").unwrap();
        catalog
            .create_namespace(&table_id.namespace, HashMap::new())
            .await
            .unwrap();
        catalog
            .create_table(&table_id.namespace, pipeline_test_table(&seed, location).unwrap())
            .await
            .unwrap();
        let table = catalog.load_table(&table_id).await.unwrap();
        assert!(table.metadata().current_snapshot_id().is_none(), "no data may be committed");
        let schema = table.metadata().current_schema();
        for field in ["time", "class_uid", "metadata.uid", "metadata.log_source", "raw_data"] {
            assert!(schema.field_by_name(field).is_some(), "seed schema lacks {field}");
        }
        assert_eq!(
            table.metadata().default_partition_spec().fields().len(),
            1,
            "the bootstrap table carries the publisher's hourly time partition"
        );
        // The publisher's tenant binding accepts the bootstrap table.
        load_bound_event_table(&catalog, &table_id, location, "default").await.unwrap();

        // Idempotent: an existing table is left alone.
        assert!(!ensure_bootstrap_event_table(&catalog, &table_id, location, "default")
            .await
            .unwrap());

        // A realistic first batch (class 6003, extra objects) is admitted
        // additively on top of the seed schema.
        let mut row = event("first-real-event");
        row.event_kind = EventKind::Source;
        row.ocsf_event["metadata"]["tenant_uid"] = json!("default");
        row.ocsf_event["raw_data"] = json!("source payload");
        row.ocsf_event["raw_data_size"] = json!(14);
        row.ocsf_event["metadata"]["processed_time"] = json!(1_786_435_200_123_i64);
        let batch = normalize_batch(&[row], "default").unwrap();
        let widened =
            ensure_additive_event_schema_with_cache(&catalog, &table_id, location, &batch, false)
                .await
                .unwrap();
        assert!(widened.metadata().current_schema().field_by_name("src_endpoint.ip").is_some());
        assert!(widened.metadata().current_snapshot_id().is_none());
    }

    /// NAN-3373: every self-hosted ingest lane stamps `%ingress_transport`,
    /// which the Vector lake storage stage writes to
    /// `metadata.ingress_transport`. The strict OCSF 1.9 check used to reject
    /// that attribute, so nothing a user sent on any lane was ever admitted.
    /// The lane literals are read from the shipped Vector configs, so a new
    /// lane (or a renamed one) cannot silently fall outside the stamp list.
    #[test]
    fn every_shipped_ingress_lane_stamp_is_admitted_and_kept() {
        let config_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/vector");
        let mut lanes = Vec::new();
        for entry in std::fs::read_dir(&config_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
                continue;
            }
            for line in std::fs::read_to_string(&path).unwrap().lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("%ingress_transport = \"") {
                    lanes.push(rest.trim_end_matches('"').to_string());
                }
            }
        }
        lanes.sort();
        assert_eq!(lanes, ["hec", "nano_https", "otlp", "vector"], "shipped lane stamps changed");
        // NAN-3807: the bucket drop's converter stamps its lane in Rust, not
        // in a Vector config.
        lanes.push(nanosiem_core::parsers::landing_ocsf::LANDING_INGRESS_TRANSPORT.to_string());
        for lane in lanes {
            let mut row = event("source-lane");
            row.event_kind = EventKind::Source;
            row.ocsf_event["raw_data"] = json!("source payload");
            row.ocsf_event["raw_data_size"] = json!(14);
            row.ocsf_event["metadata"][METADATA_INGRESS_TRANSPORT] = json!(lane);
            let (_, normalized) = normalize_event(&row, "tenant-a")
                .unwrap_or_else(|error| panic!("lane {lane} rejected: {error:#}"));
            assert_eq!(normalized["metadata"][METADATA_INGRESS_TRANSPORT], json!(lane));
        }

        // Still a closed list: an unknown spelling is refused, not stored.
        let mut row = event("source-lane");
        row.event_kind = EventKind::Source;
        row.ocsf_event["raw_data"] = json!("source payload");
        row.ocsf_event["raw_data_size"] = json!(14);
        row.ocsf_event["metadata"][METADATA_INGRESS_TRANSPORT] = json!("carrier_pigeon");
        let error = normalize_event(&row, "tenant-a").unwrap_err().to_string();
        assert!(error.contains("metadata.ingress_transport"), "{error}");
    }

    #[test]
    fn normalized_batch_binds_source_identity_tenant_and_partition() {
        let row = event("audit-1");
        let source_digest = batch_digest(std::slice::from_ref(&row)).unwrap();
        let mut batch = normalize_batch(&[row], "tenant-a").unwrap();

        assert_eq!(batch.source_batch_sha256(), Some(source_digest.as_str()));
        assert_eq!(
            batch.rows()[0].ocsf_event["time"],
            "2026-08-11T08:00:00+00:00"
        );

        // Optional post-admission decoration is intentionally outside source
        // identity, but it cannot change the bound tenant or partition.
        batch.rows[0].ocsf_event["prevalence_id"] = json!(17);
        batch.validate_binding().unwrap();
        assert_eq!(batch.source_batch_sha256(), Some(source_digest.as_str()));

        batch.rows[0].ocsf_event["time"] = json!("2026-08-11T09:00:00+00:00");
        assert!(batch.validate_binding().is_err());
    }

    #[test]
    fn admitted_normalized_batch_rejects_identity_substitution() {
        let row = event("audit-1");
        let (event_hour, ocsf_event) = normalize_event(&row, "tenant-a").unwrap();
        let mut batch = NormalizedEventBatch::from_admitted(
            "tenant-a",
            vec![(
                event_hour,
                EventRow {
                    event_uid: row.event_uid,
                    event_kind: row.event_kind,
                    ocsf_event,
                },
            )],
        )
        .unwrap();
        assert_eq!(batch.source_batch_sha256(), None);
        let sealed = batch.seal_source_identity().unwrap().to_string();
        assert_eq!(batch.source_batch_sha256(), Some(sealed.as_str()));
        batch.rows[0].ocsf_event["metadata"]["tenant_uid"] = json!("tenant-b");
        assert!(batch.validate_binding().is_err());
    }

    #[test]
    fn durable_identity_substitution_fails_closed() {
        let mut row = event("audit-1");
        row.ocsf_event["metadata"]["tenant_uid"] = json!("tenant-b");
        assert!(normalize_event(&row, "tenant-a").is_err());
    }

    #[test]
    fn batch_digest_is_order_independent_and_rejects_duplicates() {
        let left = event("audit-1");
        let right = event("audit-2");
        assert_eq!(
            batch_digest(&[left.clone(), right.clone()]).unwrap(),
            batch_digest(&[right, left.clone()]).unwrap()
        );
        assert!(batch_digest(&[left.clone(), left]).is_err());
    }

    #[test]
    fn unknown_physical_leaf_requires_a_schema_generation() {
        let schema = DataType::Struct(Fields::from(vec![Field::new(
            "metadata",
            DataType::Struct(Fields::from(vec![Field::new("uid", DataType::Utf8, true)])),
            true,
        )]));
        assert!(validate_physical_shape(
            &json!({"metadata": {"uid": "1", "future": "leaf"}}),
            &schema,
            "",
        )
        .unwrap_err()
        .to_string()
        .contains("metadata.future"));
    }

    /// NAN-2361 wave 8: the live tenant1 deadlock. Provisioning audit events
    /// carry `"http_request": {"user_agent": null}`; inference prunes the
    /// whole struct (no typed leaf), so the additive-schema path adds
    /// nothing, and the encoder must then accept the row against a schema
    /// without `http_request` instead of demanding a rewrite that can never
    /// produce a column.
    #[test]
    fn all_null_struct_does_not_require_a_physical_column() {
        let schema = DataType::Struct(Fields::from(vec![Field::new(
            "metadata",
            DataType::Struct(Fields::from(vec![Field::new("uid", DataType::Utf8, true)])),
            true,
        )]));
        for row in [
            json!({"metadata": {"uid": "1"}, "http_request": {"user_agent": null}}),
            json!({"metadata": {"uid": "1"}, "http_request": {}}),
            json!({"metadata": {"uid": "1"}, "http_request": {"url": {"path": null}}}),
            json!({"metadata": {"uid": "1"}, "resources": []}),
            json!({"metadata": {"uid": "1"}, "resources": [{"uid": null}]}),
        ] {
            validate_physical_shape(&row, &schema, "").unwrap_or_else(|error| {
                panic!("{row} must be physically null against the schema: {error:#}")
            });
            assert!(value_covered_by(&row, &schema), "{row} must be covered");
        }
        // A struct with ONE typed leaf is still a real column requirement.
        let error = validate_physical_shape(
            &json!({"metadata": {"uid": "1"}, "http_request": {"user_agent": "curl/8"}}),
            &schema,
            "",
        )
        .unwrap_err();
        assert!(error.to_string().contains("http_request"), "{error:#}");
        assert!(!value_covered_by(
            &json!({"metadata": {"uid": "1"}, "http_request": {"user_agent": "curl/8"}}),
            &schema
        ));
        // And inference agrees: the all-null struct yields no field, the
        // typed one does, so validator and schema path can no longer disagree.
        let pruned = prune_inferred_null_fields(
            &infer_generation_schema_events(
                1,
                [json!({
                    "time": "2026-01-01T00:00:00Z",
                    "metadata": {"uid": "1"},
                    "http_request": {"user_agent": null}
                })]
                .iter(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(pruned.field_with_name("http_request").is_err());
        assert!(pruned.field_with_name("metadata").is_ok());
    }

    #[test]
    fn unknown_null_leaf_does_not_require_a_physical_column() {
        let schema = DataType::Struct(Fields::from(vec![Field::new(
            "metadata",
            DataType::Struct(Fields::from(vec![Field::new("uid", DataType::Utf8, true)])),
            true,
        )]));
        validate_physical_shape(
            &json!({"metadata": {"uid": "1", "future": null}}),
            &schema,
            "",
        )
        .unwrap();
    }

    #[test]
    fn generation_schema_unions_nested_leaves_and_pins_timestamp_type() {
        let mut left = event("audit-1");
        left.event_kind = EventKind::Source;
        left.ocsf_event["unmapped"] = json!({"left": "one"});
        let mut right = event("audit-2");
        right.event_kind = EventKind::Source;
        right.ocsf_event["unmapped"] = json!({"right": 2});
        let schema = infer_generation_schema(&[left, right]).unwrap();
        assert_eq!(
            schema.field_with_name("time").unwrap().data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into()))
        );
        let unmapped = schema.field_with_name("unmapped").unwrap();
        let DataType::Struct(fields) = unmapped.data_type() else {
            panic!("unmapped must infer as a struct");
        };
        assert!(fields.iter().any(|field| field.name() == "left"));
        assert!(fields.iter().any(|field| field.name() == "right"));
        let iceberg = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(&schema).unwrap();
        assert!(iceberg.field_by_name("unmapped.left").is_some());
        assert!(iceberg.field_by_name("unmapped.right").is_some());
    }

    /// NAN-2764 follow-up, the live wedge: tenant1's 1000-row audit
    /// reservation carried `unmapped.details.created` as a boolean on
    /// `source_authority_login_*` audits and as an object on
    /// `hec_sources_enrolled` / `ingest_cell_generation_rolled` audits. Every
    /// row normalized on its own; Arrow inference over the batch failed with
    /// "Expected object json type, found: Scalar({Boolean})".
    #[test]
    fn nan2764_free_form_audit_details_never_conflict_across_rows() {
        let mut boolean = event("audit-bool");
        boolean.ocsf_event["unmapped"] =
            json!({"source": "auth", "success": true, "details": {"created": true}});
        let mut object = event("audit-object");
        object.ocsf_event["unmapped"] = json!({"source": "operator", "success": true,
            "details": {"created": {"parser_bundle": "sha256:abc", "parser_bundle_validated": true}}});
        let batch = normalize_batch(&[boolean, object], "tenant-a").unwrap();
        let schema = infer_generation_schema_values(&batch).unwrap();
        let DataType::Struct(unmapped) = schema.field_with_name("unmapped").unwrap().data_type()
        else {
            panic!("unmapped must stay a struct");
        };
        let details = unmapped.iter().find(|field| field.name() == "details_json").unwrap();
        assert_eq!(details.data_type(), &DataType::Utf8);
        assert!(unmapped.iter().all(|field| field.name() != "details"));
        // Envelope scalars stay typed.
        let success = unmapped.iter().find(|field| field.name() == "success").unwrap();
        assert_eq!(success.data_type(), &DataType::Boolean);
        // Nothing is lost: the free-form payload round-trips exactly.
        let restored: Value =
            serde_json::from_str(batch.rows[1].ocsf_event["unmapped"]["details_json"].as_str().unwrap())
                .unwrap();
        assert_eq!(
            restored,
            json!({"created": {"parser_bundle": "sha256:abc", "parser_bundle_validated": true}})
        );
    }

    #[test]
    fn nan2764_free_form_stabilization_is_idempotent_and_scoped() {
        let mut row = event("audit-1");
        row.ocsf_event["unmapped"] =
            json!({"details": {"a": [1, {"b": null}]}, "tags": ["x"], "action": "read"});
        let (_, first) = normalize_event(&row, "tenant-a").unwrap();
        assert_eq!(first["unmapped"]["action"], json!("read"));
        assert!(first["unmapped"]["details_json"].is_string());
        assert!(first["unmapped"]["tags_json"].is_string());
        // A read-back of the published row normalizes to itself.
        let reread = EventRow { ocsf_event: first.clone(), ..row.clone() };
        assert_eq!(normalize_event(&reread, "tenant-a").unwrap().1, first);
        // A producer that already claims the derived key is rejected, never
        // silently overwritten.
        let mut collision = row.clone();
        collision.ocsf_event["unmapped"]["details_json"] = json!("mine");
        assert!(normalize_event(&collision, "tenant-a").is_err());
        // Source events keep their structured `unmapped`.
        let mut source = event("source-1");
        source.event_kind = EventKind::Source;
        source.ocsf_event["unmapped"] = json!({"details": {"a": 1}});
        assert!(!unmapped_needs_stabilization(source.event_kind, &source.ocsf_event));
    }

    /// Backstop: a type conflict in a TYPED OCSF field cannot be stabilized,
    /// so the batch admits the first shape and names the rows that conflict.
    #[test]
    fn nan2764_batch_shape_index_rejects_only_conflicting_rows() {
        let mut index = BatchShapeIndex::default();
        let first = json!({"time": "2026-09-24T00:00:00Z", "api": {"request": {"uid": "r-1"}}, "count": 1});
        let second = json!({"api": {"request": "flat"}, "count": 2.5});
        let third = json!({"time": "2026-09-24T00:00:01Z", "api": {"request": {"uid": "r-3", "flags": [1]}}, "count": null});
        let fourth = json!({"api": {"request": {"flags": [{"x": 1}]}}});
        let inner = json!({"observables": [1, {"x": 1}]});
        assert!(index.admit(&first).is_ok());
        let error = index.admit(&second).unwrap_err();
        assert!(error.contains("api.request"), "{error}");
        assert!(index.admit(&third).is_ok());
        assert!(index.admit(&fourth).unwrap_err().contains("api.request.flags[]"));
        assert!(BatchShapeIndex::default().admit(&inner).is_err());
        // Admitted rows always infer one schema.
        let rows = [first, third];
        infer_generation_schema_events(rows.len(), rows.iter()).unwrap();
    }

    #[test]
    fn nan2764_table_conflict_names_the_path_and_allows_additions() {
        let schema = ArrowSchema::new(vec![
            Field::new("count", DataType::Int64, true),
            Field::new(
                "api",
                DataType::Struct(vec![Field::new("operation", DataType::Utf8, true)].into()),
                true,
            ),
        ]);
        let root = DataType::Struct(schema.fields().clone());
        assert_eq!(value_conflict_path(&json!({"count": 1, "api": {"operation": "x", "new": {"a": 1}}, "extra": true}), &root, ""), None);
        assert_eq!(value_conflict_path(&json!({"count": "1"}), &root, "").as_deref(), Some("count"));
        assert_eq!(value_conflict_path(&json!({"api": {"operation": {"a": 1}}}), &root, "").as_deref(), Some("api.operation"));
        assert_eq!(value_conflict_path(&json!({"api": {"operation": null}, "count": null}), &root, ""), None);
    }

    #[test]
    fn nan2520_stale_pack_schema_must_not_discard_stamp_fields() {
        let stamped = json!({"enrichments":[{"provider":"platform/ipinfo_lite",
            "data":{"feed_id":"ipinfo_lite", "owned_fields":["src_endpoint.location.country"]}}],
            "src_endpoint":{"location":{"country":"US"}}, "message":"source"});
        let infer = |row: &Value| {
            let mut input = Cursor::new(row.to_string().into_bytes());
            Arc::new(arrow_json::reader::infer_json_schema_from_seekable(&mut input, None).unwrap().0)
        };
        let source_schema = infer(&stamped);
        let source = json_batches(source_schema, &[stamped]).unwrap().remove(0);
        for target in [
            json!({"message":"source"}),
            json!({"message":"source", "enrichments":[{"provider":"Conduit Proxy", "data":{"score":12}}],
                "src_endpoint":{"location":{"country":"US"}}}),
        ] {
            let result = align_staged_batch(source.clone(), infer(&target));
            assert!(result.is_err(), "stale pack schema silently discarded stamp fields: {result:?}");
        }
    }

    #[test]
    fn additive_schema_plans_new_list_element_leaves_without_rewriting() {
        let mut current = event("audit-1");
        current.ocsf_event["enrichments"] = json!([{
            "name": "src_endpoint.ip",
            "data": {"score": 0.8}
        }]);
        let mut proposed = current.clone();
        proposed.ocsf_event["enrichments"] = json!([{
            "name": "src_endpoint.ip",
            "short_desc": "known IOC",
            "data": {"score": 0.8, "confidence": 95}
        }]);
        let schema_type = |row: &EventRow| {
            let arrow = infer_generation_schema(std::slice::from_ref(row)).unwrap();
            let iceberg =
                iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(arrow.as_ref()).unwrap();
            Type::Struct(iceberg.as_struct().clone())
        };
        let additions =
            additive_columns(&schema_type(&current), &schema_type(&proposed), None).unwrap();
        assert!(additions.iter().any(|column| {
            column.parent.as_deref() == Some("enrichments") && column.name == "short_desc"
        }));
        assert!(additions.iter().any(|column| {
            column.parent.as_deref() == Some("enrichments.data")
                && column.name == "confidence"
                && column.field_type == Type::Primitive(iceberg::spec::PrimitiveType::Long)
        }));
    }

    /// NAN-2361 regression guard: the clustering key must keep EVERY scalar
    /// metadata column. Narrowing it to `log_source` alone was measured at
    /// 146.2 B/row against 137.0 for the full key -- a 6.9% compression loss
    /// that no other test would catch. Nested children are excluded (they are
    /// not lexsort-comparable) and that is free: `product` and `profiles` hold
    /// a handful of values fully correlated with the scalars.
    #[test]
    fn pack_sort_key_keeps_every_scalar_metadata_column() {
        // Mirrors the real lake `metadata`: 11 scalar children of mixed type
        // plus the two nested ones.
        let mut fields: Vec<(Arc<Field>, ArrayRef)> = Vec::new();
        for name in [
            "event_code",
            "log_name",
            "log_provider",
            "log_source",
            "original_event_uid",
            "tenant_uid",
            "uid",
            "version",
            "correlation_uid",
        ] {
            fields.push((
                Arc::new(Field::new(name, DataType::Utf8, false)),
                Arc::new(StringArray::from(vec!["a", "b"])) as ArrayRef,
            ));
        }
        for name in ["logged_time", "processed_time"] {
            fields.push((
                Arc::new(Field::new(name, DataType::Int64, false)),
                Arc::new(Int64Array::from(vec![1i64, 2])) as ArrayRef,
            ));
        }
        // Nested: must be excluded from the key, not panic.
        let product = StructArray::from(vec![(
            Arc::new(Field::new("name", DataType::Utf8, false)),
            Arc::new(StringArray::from(vec!["nano", "nano"])) as ArrayRef,
        )]);
        fields.push((
            Arc::new(Field::new("product", product.data_type().clone(), false)),
            Arc::new(product) as ArrayRef,
        ));

        let metadata = StructArray::from(fields);
        let batch = RecordBatch::try_new(
            Arc::new(ArrowSchema::new(vec![Field::new(
                "metadata",
                metadata.data_type().clone(),
                false,
            )])),
            vec![Arc::new(metadata) as ArrayRef],
        )
        .expect("build batch");

        let key = pack_sort_key_columns(&batch);
        assert_eq!(
            key.len(),
            11,
            "clustering key must carry all 11 scalar metadata columns, got {}",
            key.len()
        );
        assert!(
            key.iter()
                .all(|c| !matches!(c.data_type(), DataType::Struct(_))),
            "nested children must not enter the sort key"
        );
    }

    /// A metadata struct with only nested children must still fall back to
    /// `class_uid` rather than silently landing in arrival order.
    #[test]
    fn pack_sort_key_falls_back_to_class_uid_when_metadata_has_no_scalars() {
        let nested = StructArray::from(vec![(
            Arc::new(Field::new("name", DataType::Utf8, false)),
            Arc::new(StringArray::from(vec!["nano", "nano"])) as ArrayRef,
        )]);
        let metadata = StructArray::from(vec![(
            Arc::new(Field::new("product", nested.data_type().clone(), false)),
            Arc::new(nested) as ArrayRef,
        )]);
        let batch = RecordBatch::try_new(
            Arc::new(ArrowSchema::new(vec![
                Field::new("metadata", metadata.data_type().clone(), false),
                Field::new("class_uid", DataType::Int64, false),
            ])),
            vec![
                Arc::new(metadata) as ArrayRef,
                Arc::new(Int64Array::from(vec![4001i64, 4002])) as ArrayRef,
            ],
        )
        .expect("build batch");

        let key = pack_sort_key_columns(&batch);
        assert_eq!(key.len(), 1, "expected the class_uid fallback");
        assert_eq!(key[0].data_type(), &DataType::Int64);
    }

    /// Type drift must not silently shrink the key: a Utf8View / LargeUtf8 /
    /// Boolean metadata column still clusters. An `is_primitive() || Utf8`
    /// allow-list would drop all three.
    #[test]
    fn pack_sort_key_survives_metadata_column_type_drift() {
        let metadata = StructArray::from(vec![
            (
                Arc::new(Field::new("log_source", DataType::LargeUtf8, false)),
                Arc::new(arrow_array::LargeStringArray::from(vec!["zeek", "sysmon"])) as ArrayRef,
            ),
            (
                Arc::new(Field::new("is_synthetic", DataType::Boolean, false)),
                Arc::new(arrow_array::BooleanArray::from(vec![true, false])) as ArrayRef,
            ),
        ]);
        let batch = RecordBatch::try_new(
            Arc::new(ArrowSchema::new(vec![Field::new(
                "metadata",
                metadata.data_type().clone(),
                false,
            )])),
            vec![Arc::new(metadata) as ArrayRef],
        )
        .expect("build batch");

        assert_eq!(
            pack_sort_key_columns(&batch).len(),
            2,
            "LargeUtf8 and Boolean must stay in the clustering key"
        );
    }

    /// NAN-2361: a pack buffer must cluster by log_source AND order time
    /// NUMERICALLY. The original comparator stringified `time` via Debug, so
    /// ordering was lexicographic — correct only while every value shared a
    /// digit count. These timestamps deliberately straddle digit widths
    /// (99 / 999 / 1000 / 10000), which is exactly where text ordering breaks.
    #[test]
    fn pack_buffer_clusters_by_log_source_and_orders_time_numerically() {
        let metadata = StructArray::from(vec![(
            Arc::new(Field::new("log_source", DataType::Utf8, false)),
            Arc::new(StringArray::from(vec![
                "zeek", "sysmon", "zeek", "sysmon", "zeek", "sysmon",
            ])) as ArrayRef,
        )]);
        let batch = RecordBatch::try_new(
            Arc::new(ArrowSchema::new(vec![
                Field::new("metadata", metadata.data_type().clone(), false),
                Field::new("time", DataType::Int64, false),
            ])),
            vec![
                Arc::new(metadata) as ArrayRef,
                Arc::new(Int64Array::from(vec![10000, 999, 99, 10000, 1000, 99])) as ArrayRef,
            ],
        )
        .expect("build pack buffer");

        let sorted = sort_pack_buffer(&batch).expect("sort pack buffer");
        let sources = sorted
            .column_by_name("metadata")
            .and_then(|c| c.as_any().downcast_ref::<StructArray>())
            .and_then(|m| m.column_by_name("log_source"))
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .expect("log_source column")
            .iter()
            .map(|v: Option<&str>| v.unwrap().to_string())
            .collect::<Vec<_>>();
        let times = sorted
            .column_by_name("time")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .expect("time column")
            .values()
            .to_vec();

        // Equal log_source values must be adjacent — that is what lets
        // dictionary/RLE encodings find long runs.
        let mut runs = 1;
        for pair in sources.windows(2) {
            if pair[0] != pair[1] {
                runs += 1;
            }
        }
        assert_eq!(runs, 2, "expected one run per log_source, got {sources:?}");

        // Within each run, time ascends numerically. Under the old text
        // comparator 1000 sorted before 999 and 10000 before 99.
        for source in ["sysmon", "zeek"] {
            let run = sources
                .iter()
                .zip(times.iter())
                .filter(|(s, _): &(&String, &i64)| s.as_str() == source)
                .map(|(_, t)| *t)
                .collect::<Vec<_>>();
            let mut expected = run.clone();
            expected.sort_unstable();
            assert_eq!(run, expected, "{source} times not numerically ordered");
        }
    }

    #[test]
    fn additive_schema_rejects_incompatible_physical_type_changes() {
        let error = additive_columns(
            &Type::Primitive(iceberg::spec::PrimitiveType::String),
            &Type::Primitive(iceberg::spec::PrimitiveType::Long),
            Some("enrichments.data.confidence"),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("schema generation rewrite required"));
    }

    #[test]
    fn additive_schema_ignores_all_null_inference_artifacts() {
        let schema = ArrowSchema::new(vec![
            Field::new("typed", DataType::Utf8, true),
            Field::new("empty", DataType::Null, true),
            Field::new(
                "nested",
                DataType::Struct(
                    vec![
                        Field::new("value", DataType::Int64, true),
                        Field::new("empty", DataType::Null, true),
                    ]
                    .into(),
                ),
                true,
            ),
        ]);
        let pruned = prune_inferred_null_fields(&schema).unwrap();
        assert!(pruned.field_with_name("typed").is_ok());
        assert!(pruned.field_with_name("empty").is_err());
        let DataType::Struct(fields) = pruned.field_with_name("nested").unwrap().data_type() else {
            panic!("nested field must remain a struct");
        };
        assert!(fields.iter().any(|field| field.name() == "value"));
        assert!(!fields.iter().any(|field| field.name() == "empty"));
    }

    #[test]
    fn generation_digest_is_order_independent_and_rejects_duplicates() {
        let left = event("audit-1");
        let right = event("audit-2");
        assert_eq!(
            generation_digest(&[left.clone(), right.clone()]).unwrap(),
            generation_digest(&[right, left.clone()]).unwrap()
        );
        assert!(generation_digest(&[left.clone(), left]).is_err());
    }

    #[test]
    fn staged_file_digest_preserves_the_historical_generation_identity() {
        let rows = [event("audit-2"), event("audit-1")]
            .into_iter()
            .map(|row| {
                let (_, ocsf_event) = normalize_event(&row, "tenant-a").unwrap();
                EventRow { ocsf_event, ..row }
            })
            .collect::<Vec<_>>();
        let schema = infer_generation_schema(&rows).unwrap();
        let values = rows
            .iter()
            .map(|row| row.ocsf_event.clone())
            .collect::<Vec<_>>();
        let batches = json_batches(schema.clone(), &values).unwrap();
        let mut writer = ArrowWriter::try_new(
            Vec::new(),
            schema,
            Some(WriterProperties::builder().build()),
        )
        .unwrap();
        for batch in batches {
            writer.write(&batch).unwrap();
        }
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("staged.parquet");
        std::fs::write(&path, writer.into_inner().unwrap()).unwrap();

        let (observed, observed_rows) =
            staged_event_files_generation_digest(&[&path], "tenant-a").unwrap();
        assert_eq!(observed, generation_digest(&rows).unwrap());
        assert_eq!(observed_rows, rows.len());
        assert!(
            staged_event_files_generation_digest(&[&path, &path], "tenant-a")
                .unwrap_err()
                .to_string()
                .contains("duplicate event UIDs")
        );
    }

    /// A reservation staged by the previous publisher build carries the
    /// structured `unmapped.details`; one staged by this build carries
    /// `unmapped.details_json`. Commit verification across a roll accepts
    /// exactly those two canonical forms of the reserved source row.
    #[test]
    fn nan2764_commit_verifier_accepts_both_sides_of_the_roll() {
        let temporary = tempfile::tempdir().unwrap();
        let mut reserved = event("audit-nested");
        reserved.ocsf_event["unmapped"] =
            json!({"action": "rolled", "details": {"created": {"parser_bundle": "x"}, "n": 1}});
        let write = |name: &str, stabilize: bool, row: &EventRow| {
            let value = normalize_event_with(row, "tenant-a", stabilize).unwrap().1;
            let normalized = [EventRow { ocsf_event: value.clone(), ..row.clone() }];
            let schema = infer_generation_schema(&normalized).unwrap();
            let mut writer = ArrowWriter::try_new(Vec::new(), schema.clone(), None).unwrap();
            for batch in json_batches(schema, &[value]).unwrap() {
                writer.write(&batch).unwrap();
            }
            let path = temporary.path().join(name);
            std::fs::write(&path, writer.into_inner().unwrap()).unwrap();
            path
        };
        for (name, stabilize) in [("current.parquet", true), ("legacy.parquet", false)] {
            let path = write(name, stabilize, &reserved);
            let mut verifier = ProductEventCommitVerifier::new("tenant-a", &[reserved.clone()]).unwrap();
            verifier.verify_file(&path, 1).unwrap();
            verifier.finish().unwrap();
        }
        let mut tampered = reserved.clone();
        tampered.ocsf_event["unmapped"]["details"]["n"] = json!(2);
        for (name, stabilize) in [("tampered-current.parquet", true), ("tampered-legacy.parquet", false)] {
            let path = write(name, stabilize, &tampered);
            let mut verifier = ProductEventCommitVerifier::new("tenant-a", &[reserved.clone()]).unwrap();
            assert!(verifier.verify_file(&path, 1).unwrap_err().to_string().contains("payload differs"));
        }
    }

    #[test]
    fn product_commit_verifies_rewritten_payload_and_rejects_missing_duplicate_or_changed_rows() {
        let temporary = tempfile::tempdir().unwrap();
        let write = |name: &str, rows: &[EventRow]| {
            // Encode individually so malformed duplicate-UID files reach the
            // verifier instead of being rejected by the normal batch builder.
            let normalized = rows.iter().map(|row| EventRow {
                ocsf_event: normalize_event(row, "tenant-a").unwrap().1, ..row.clone()
            }).collect::<Vec<_>>();
            let schema = infer_generation_schema(&normalized).unwrap();
            let values = normalized.iter().map(|row| row.ocsf_event.clone()).collect::<Vec<_>>();
            let mut writer = ArrowWriter::try_new(Vec::new(), schema.clone(), None).unwrap();
            for batch in json_batches(schema, &values).unwrap() { writer.write(&batch).unwrap(); }
            let path = temporary.path().join(name);
            std::fs::write(&path, writer.into_inner().unwrap()).unwrap();
            path
        };
        let mut reserved = event("audit-reserved");
        reserved.ocsf_event["metadata"]["logged_time"] = json!(123);
        reserved.ocsf_event["src_endpoint"]["hostname"] = Value::Null;
        let input = write("original.parquet", &[reserved.clone()]);
        let mut decoded = decode_staged_event_file(&input, "tenant-a").unwrap();
        decoded.push(event("unrelated-compacted-row"));
        let rewritten = write("rewritten.parquet", &decoded);
        std::fs::remove_file(input).unwrap();
        let new_verifier = || ProductEventCommitVerifier::new("tenant-a", &[reserved.clone()]).unwrap();
        let mut valid = new_verifier();
        valid.verify_file(&rewritten, 2).unwrap();
        valid.finish().unwrap();
        let mut duplicate = new_verifier();
        duplicate.verify_file(&rewritten, 2).unwrap();
        assert!(duplicate.verify_file(&rewritten, 2).unwrap_err().to_string().contains("more than once"));
        let duplicate_path = write("duplicate.parquet", &[reserved.clone(), reserved.clone()]);
        assert!(new_verifier().verify_file(&duplicate_path, 2).is_err());
        let missing_path = write("missing.parquet", &[event("different-uid")]);
        let mut missing = new_verifier();
        missing.verify_file(&missing_path, 1).unwrap();
        assert!(missing.finish().unwrap_err().to_string().contains("missing"));
        for field in ["message", "logged_time"] {
            let mut changed = reserved.clone();
            if field == "message" { changed.ocsf_event[field] = json!("tampered"); }
            else { changed.ocsf_event["metadata"][field] = json!(456); }
            let path = write("changed.parquet", &[changed]);
            assert!(new_verifier().verify_file(&path, 1).unwrap_err().to_string().contains("payload differs"));
        }
        assert!(new_verifier().verify_file(&rewritten, 1).is_err());
        assert!(ProductEventCommitVerifier::new("other-tenant", &[reserved.clone()]).is_err());
        assert!(ProductEventCommitVerifier::new("tenant-a", &[reserved.clone(), reserved]).is_err());
        let mut unknown = event("unknown-initiator");
        unknown.ocsf_event["actor"] = json!({"user":{"uid":null,"name":null}});
        unknown.ocsf_event["src_endpoint"] = json!({"ip":null});
        let unknown_path = write("unknown.parquet", &[unknown.clone()]);
        let mut unknown_verifier = ProductEventCommitVerifier::new("tenant-a", &[unknown.clone()]).unwrap();
        unknown_verifier.verify_file(&unknown_path, 1).unwrap();
        unknown_verifier.finish().unwrap();
        let mut substituted = unknown.clone();
        substituted.ocsf_event["actor"] = json!({"user":{"name":"invented-actor"}});
        let substituted_path = write("substituted.parquet", &[substituted]);
        assert!(ProductEventCommitVerifier::new("tenant-a", &[unknown.clone()]).unwrap()
            .verify_file(&substituted_path, 1).unwrap_err().to_string().contains("payload differs"));
        unknown.ocsf_event.as_object_mut().unwrap().remove("actor");
        assert!(ProductEventCommitVerifier::new("tenant-a", &[unknown]).is_err());

    }

    #[test]
    fn generation_source_duplicate_must_be_identical() {
        let mut rows = BTreeMap::new();
        let left = event("audit-1");
        insert_consistent(&mut rows, left.clone()).unwrap();
        insert_consistent(&mut rows, left).unwrap();
        let mut conflict = event("audit-1");
        conflict.ocsf_event["message"] = json!("different");
        assert!(insert_consistent(&mut rows, conflict).is_err());
    }

    #[test]
    fn explicitly_repaired_source_uid_conflicts_preserve_both_events() {
        let left = event("audit-1");
        let mut right = event("audit-1");
        right.ocsf_event["message"] = json!("different");

        let build = |first: EventRow, second: EventRow| {
            let mut rows = BTreeMap::new();
            let mut conflicts = BTreeSet::new();
            assert_eq!(
                insert_source_consistent(&mut rows, &mut conflicts, first, true).unwrap(),
                SourceInsertOutcome::default()
            );
            assert_eq!(
                insert_source_consistent(&mut rows, &mut conflicts, second, true).unwrap(),
                SourceInsertOutcome {
                    repaired_uid_rows: 2,
                    duplicate_rows_removed: 0,
                }
            );
            assert_eq!(rows.len(), 2);
            assert!(!rows.contains_key("audit-1"));
            assert!(rows.values().all(|row| {
                row.ocsf_event.pointer("/metadata/original_event_uid") == Some(&json!("audit-1"))
            }));
            rows.into_keys().collect::<BTreeSet<_>>()
        };

        assert_eq!(
            build(left.clone(), right.clone()),
            build(right, left.clone())
        );
        let mut rejected = BTreeMap::new();
        let mut conflicts = BTreeSet::new();
        insert_source_consistent(&mut rejected, &mut conflicts, left, false).unwrap();
        let mut conflict = event("audit-1");
        conflict.ocsf_event["message"] = json!("different");
        assert!(insert_source_consistent(&mut rejected, &mut conflicts, conflict, false).is_err());
    }

    #[test]
    fn generation_rewrite_counts_identical_source_replays() {
        let mut rows = BTreeMap::new();
        let mut conflicts = BTreeSet::new();
        let mut replay = event("audit-1");
        replay.ocsf_event["metadata"]["processed_time"] = json!(1);
        replay.ocsf_event["metadata"]["logged_time"] = json!(1);
        replay.ocsf_event["metadata"]["original_event_uid"] = json!("parser-attempt-1");
        assert_eq!(
            insert_source_consistent(&mut rows, &mut conflicts, replay.clone(), false).unwrap(),
            SourceInsertOutcome::default()
        );
        assert_eq!(
            insert_source_consistent(
                &mut rows,
                &mut conflicts,
                {
                    let mut later = replay;
                    later.ocsf_event["metadata"]["processed_time"] = json!(2);
                    later.ocsf_event["metadata"]["logged_time"] = json!(2);
                    later.ocsf_event["metadata"]["original_event_uid"] = json!("parser-attempt-2");
                    later
                },
                false,
            )
            .unwrap(),
            SourceInsertOutcome {
                repaired_uid_rows: 0,
                duplicate_rows_removed: 1,
            }
        );
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn generation_prunes_sparse_union_fields_and_recovers_event_kind() {
        let mut row = json!({
            "class_uid": 6003,
            "metadata": {"log_source": "audit", "uid": "audit-1"},
            "resources": [{"name": null, "uid": null, "type": null}],
            "evidences": null,
            "unmapped": {"action": "read", "empty": null}
        });
        assert!(prune_sparse_materialization(&mut row));
        assert_eq!(event_kind(&row).unwrap(), EventKind::PlatformAudit);
        assert!(row.get("resources").is_none());
        assert!(row.get("evidences").is_none());
        assert_eq!(row["unmapped"], json!({"action": "read"}));
    }

    #[test]
    fn generation_partition_spec_has_explicit_v2_identities() {
        let spec = hour_partition_spec(13).unwrap();
        assert_eq!(spec.spec_id(), Some(0));
        assert_eq!(spec.fields()[0].source_id, 13);
        assert_eq!(spec.fields()[0].field_id, Some(1_000));
        assert_eq!(spec.fields()[0].transform, Transform::Hour);
    }

    #[tokio::test]
    async fn schema_cache_requires_coverage_binding_and_unexpired_admission() {
        let batch = normalize_batch(&[event("cache-event")], "tenant-a").unwrap();
        let schema = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(
            infer_generation_schema_values(&batch).unwrap().as_ref(),
        ).unwrap();
        let location = "s3://bucket/events";
        let mut properties = event_table_properties("tenant-a");
        properties.remove("format-version");
        let creation = TableCreation::builder().name("events".to_string())
            .location(location.to_string()).schema(schema)
            .properties(properties).build();
        let metadata = iceberg::spec::TableMetadataBuilder::from_table_creation(creation)
            .unwrap().build().unwrap().metadata;
        let identity = table_ident("nano.events").unwrap();
        let table = Table::builder().identifier(identity.clone()).metadata(metadata)
            .file_io(iceberg::io::FileIO::new_with_memory())
            .runtime(iceberg::Runtime::current()).build().unwrap();
        let now = std::time::Instant::now();
        let mut cache = EventSchemaAdmissionCache {
            admitted: Some((identity.clone(), "schema-hash".to_string(), table, now)),
        };
        assert!(cache.covered_table(&identity, location, &batch, false, now).unwrap().is_some());
        assert!(cache.covered_table(&identity, "s3://other/events", &batch, false, now).unwrap().is_none());
        assert!(cache.covered_table(&table_ident("nano.other").unwrap(), location, &batch, false, now).unwrap().is_none());
        assert!(cache.covered_table(&identity, location, &batch, false, now + std::time::Duration::from_secs(60)).unwrap().is_none());
        let mut changed = batch;
        changed.rows[0].ocsf_event["new_field"] = serde_json::json!("new");
        assert!(cache.covered_table(&identity, location, &changed, false, now).unwrap().is_none());
        changed.rows[0].ocsf_event.as_object_mut().unwrap().remove("new_field");
        changed.tenant_id = "tenant-b".to_string();
        assert!(cache.covered_table(&identity, location, &changed, false, now).unwrap().is_none());
        cache.clear();
        assert!(cache.admitted.is_none());
    }

    #[test]
    fn initial_event_table_contract_is_ocsf19_zstd_and_tenant_pinned() {
        let properties = event_table_properties("tenant-a");
        assert_eq!(properties["format-version"], "2");
        assert_eq!(properties["write.parquet.compression-codec"], "zstd");
        assert_eq!(properties["nano.ocsf-version"], OCSF_VERSION);
        assert_eq!(properties["nano.tenant-id"], "tenant-a");
        assert_eq!(
            properties["write.metadata.delete-after-commit.enabled"],
            "false"
        );
    }
}

#[cfg(test)]
mod snapshot_added_files_tests {
    //! NAN-2785: verifying one snapshot's added files must cost the manifests
    //! that snapshot wrote, not every manifest the table has accumulated.
    use super::*;
    use iceberg::memory::{MemoryCatalogBuilder, MEMORY_CATALOG_WAREHOUSE};
    use iceberg::spec::{
        NestedField, PrimitiveType, Schema as IcebergSchema, Type, UnboundPartitionSpec,
    };
    use iceberg::NamespaceIdent;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    /// One fast append per element; each commit writes one new manifest and
    /// carries every earlier manifest forward in its manifest list.
    async fn table_with_appends(
        files_per_append: &[usize],
    ) -> (TempDir, Table, Vec<(i64, Vec<String>)>) {
        let directory = TempDir::new().unwrap();
        let catalog = MemoryCatalogBuilder::default()
            .load(
                "nan2785",
                HashMap::from([(
                    MEMORY_CATALOG_WAREHOUSE.to_string(),
                    directory.path().display().to_string(),
                )]),
            )
            .await
            .unwrap();
        let namespace = NamespaceIdent::new("nano".to_string());
        catalog
            .create_namespace(&namespace, HashMap::new())
            .await
            .unwrap();
        let schema = IcebergSchema::builder()
            .with_fields(vec![Arc::new(NestedField::required(
                1,
                "time",
                Type::Primitive(PrimitiveType::Timestamptz),
            ))])
            .build()
            .unwrap();
        let mut table = catalog
            .create_table(
                &namespace,
                TableCreation::builder()
                    .name("events".to_string())
                    .location(format!("{}/events", directory.path().display()))
                    .schema(schema)
                    .partition_spec(UnboundPartitionSpec::builder().with_spec_id(0).build())
                    .build(),
            )
            .await
            .unwrap();
        let location = table.metadata().location().to_string();
        let mut commits = Vec::new();
        for (append, count) in files_per_append.iter().enumerate() {
            let paths: Vec<String> = (0..*count)
                .map(|file| format!("{location}/data/append-{append}-file-{file}.parquet"))
                .collect();
            let files = paths
                .iter()
                .map(|path| {
                    DataFileBuilder::default()
                        .content(DataContentType::Data)
                        .file_path(path.clone())
                        .file_format(DataFileFormat::Parquet)
                        .partition(iceberg::spec::Struct::empty())
                        .record_count(10)
                        .file_size_in_bytes(100)
                        .partition_spec_id(0)
                        .build()
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let transaction = Transaction::new(&table);
            table = transaction
                .fast_append()
                .add_data_files(files)
                .apply(transaction)
                .unwrap()
                .commit(&catalog)
                .await
                .unwrap();
            let snapshot = table.metadata().current_snapshot().unwrap().snapshot_id();
            commits.push((snapshot, paths));
        }
        (directory, table, commits)
    }

    #[tokio::test]
    async fn verification_loads_only_the_manifests_the_snapshot_wrote() {
        // 12 commits: the last snapshot's manifest list references 12 manifests.
        let (_directory, table, commits) =
            table_with_appends(&[2, 1, 3, 1, 1, 2, 1, 1, 1, 1, 2, 3]).await;
        for (snapshot, expected_paths) in &commits {
            let loads = AtomicUsize::new(0);
            let files = snapshot_added_data_files_counted(&table, *snapshot, Some(&loads))
                .await
                .unwrap();
            let mut paths: Vec<String> = files.iter().map(|f| f.file_path().to_string()).collect();
            paths.sort();
            let mut expected = expected_paths.clone();
            expected.sort();
            assert_eq!(paths, expected, "snapshot {snapshot} returned the wrong files");
            assert_eq!(
                loads.load(Ordering::Relaxed),
                1,
                "snapshot {snapshot}: one fast append writes one manifest, so verification must fetch exactly one"
            );
        }
        // The public entry point returns the same files.
        let (last, expected) = commits.last().unwrap();
        assert_eq!(
            snapshot_added_data_files(&table, *last).await.unwrap().len(),
            expected.len()
        );
    }
}
