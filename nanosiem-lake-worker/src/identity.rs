// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed, immutable identity snapshot plans.
//!
//! Requests carry only lookup semantics. The assigned snapshot path, digest,
//! and byte budget come from trusted worker configuration.

use crate::config::LoadedIdentitySnapshotConfig;
#[cfg(test)]
use crate::native::file_sha256;
use crate::planner::{NativeQueryPlan, QueryBudget, TenantQueryConfig};
use chrono::DateTime;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;

const MAX_BATCH_ITEMS: usize = 500;
const MAX_DENIED_SOURCES: usize = 1_024;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity request is invalid: {0}")]
    InvalidRequest(String),
    #[error("identity snapshot changed after worker startup")]
    SnapshotChanged,
    #[error("identity snapshot verification failed")]
    SnapshotVerification,
}

type Result<T> = std::result::Result<T, IdentityError>;

#[derive(Debug)]
pub struct IdentitySnapshot {
    snapshot_id: String,
    by_ip: std::path::PathBuf,
    by_ip_sha256: String,
    by_ip_bytes: u64,
    by_ip_modified: std::time::SystemTime,
}

impl From<LoadedIdentitySnapshotConfig> for IdentitySnapshot {
    fn from(config: LoadedIdentitySnapshotConfig) -> Self {
        Self {
            snapshot_id: config.snapshot_id,
            by_ip: config.by_ip,
            by_ip_sha256: config.by_ip_sha256,
            by_ip_bytes: config.by_ip_bytes,
            by_ip_modified: config.by_ip_modified,
        }
    }
}

impl IdentitySnapshot {
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    pub fn snapshot_version(&self) -> String {
        format!("sha256:{}", self.by_ip_sha256)
    }

    pub fn bytes(&self) -> u64 {
        self.by_ip_bytes
    }

    fn verify(&self) -> Result<()> {
        // The exact SHA-256 is verified once before the worker accepts traffic.
        // Per request, fence normal replacement or mutation cheaply using the
        // trusted local file's size and modification stamp. Production object
        // storage uses immutable object versions instead of a mutable path.
        let metadata =
            std::fs::metadata(&self.by_ip).map_err(|_| IdentityError::SnapshotVerification)?;
        let modified = metadata
            .modified()
            .map_err(|_| IdentityError::SnapshotVerification)?;
        if metadata.len() != self.by_ip_bytes || modified != self.by_ip_modified {
            return Err(IdentityError::SnapshotChanged);
        }
        Ok(())
    }
}

pub struct IdentityResolveRequest<'a> {
    pub snapshot_id: &'a str,
    pub ip: &'a str,
    pub reference_time: &'a str,
    pub deny_source_types: &'a BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct IdentityBatchItem {
    pub ip: String,
    pub reference_time: String,
}

pub struct IdentityBatchRequest<'a> {
    pub snapshot_id: &'a str,
    pub items: &'a [IdentityBatchItem],
    pub deny_source_types: &'a BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct IdentityEntityBatchItem {
    pub value: String,
    pub reference_time: String,
}

pub struct IdentityEntityBatchRequest<'a> {
    pub snapshot_id: &'a str,
    /// One fixed semantic for the whole request: `ip`, `host`, or `user`.
    pub entity_type: &'a str,
    pub items: &'a [IdentityEntityBatchItem],
    pub deny_source_types: &'a BTreeSet<String>,
}

pub fn plan_identity_resolve(
    tenant: &TenantQueryConfig,
    snapshot: &IdentitySnapshot,
    request: &IdentityResolveRequest<'_>,
) -> Result<NativeQueryPlan> {
    validate_snapshot_binding(snapshot, request.snapshot_id)?;
    snapshot.verify()?;
    let ip = normalize_ip(request.ip)?;
    validate_reference_time(request.reference_time)?;
    let denied = normalized_denied_sources(request.deny_source_types)?;
    let mut predicates = vec![
        "ip = {identity_ip:String}".to_string(),
        "parseDateTime64BestEffort(toString(observed_at), 6, 'UTC') <= \
         parseDateTime64BestEffort({identity_reference_time:String}, 6, 'UTC')"
            .to_string(),
    ];
    let mut params = vec![
        (
            "identity_source".to_string(),
            snapshot.by_ip.to_string_lossy().into_owned(),
        ),
        ("identity_ip".to_string(), ip),
        (
            "identity_reference_time".to_string(),
            request.reference_time.to_string(),
        ),
    ];
    add_denied_predicates(&denied, "source", &mut predicates, &mut params);
    let sql = format!(
        "SELECT hostname_lc AS hostname, user_lc AS user, mac, source, \
         formatDateTime(parseDateTime64BestEffort(toString(observed_at), 6, 'UTC'), \
         '%Y-%m-%dT%H:%i:%S.%fZ', 'UTC') AS observed_at \
         FROM file({{identity_source:String}}, Parquet) WHERE {} \
         ORDER BY parseDateTime64BestEffort(toString(observed_at), 6, 'UTC') DESC LIMIT 1 \
         SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, use_query_cache=0",
        predicates.join(" AND "),
        tenant.threads,
        tenant.max_execution_seconds,
        tenant.max_query_bytes,
        tenant.max_memory_bytes,
    );
    Ok(plan(snapshot, request_digest(&params), sql, params))
}

pub fn plan_identity_batch(
    tenant: &TenantQueryConfig,
    snapshot: &IdentitySnapshot,
    request: &IdentityBatchRequest<'_>,
) -> Result<NativeQueryPlan> {
    validate_snapshot_binding(snapshot, request.snapshot_id)?;
    if request.items.is_empty() || request.items.len() > MAX_BATCH_ITEMS {
        return Err(IdentityError::InvalidRequest(
            "identity batch must contain between 1 and 500 items".to_string(),
        ));
    }
    snapshot.verify()?;
    let denied = normalized_denied_sources(request.deny_source_types)?;
    let mut tuples = Vec::with_capacity(request.items.len());
    let mut params = vec![(
        "identity_source".to_string(),
        snapshot.by_ip.to_string_lossy().into_owned(),
    )];
    for (ordinal, item) in request.items.iter().enumerate() {
        let ip = normalize_ip(&item.ip)?;
        validate_reference_time(&item.reference_time)?;
        let ordinal_name = format!("identity_ordinal_{ordinal}");
        let ip_name = format!("identity_ip_{ordinal}");
        let reference_name = format!("identity_reference_{ordinal}");
        tuples.push(format!(
            "tuple({{{ordinal_name}:UInt32}}, {{{ip_name}:String}}, \
             parseDateTime64BestEffort({{{reference_name}:String}}, 6, 'UTC'))"
        ));
        params.push((ordinal_name, ordinal.to_string()));
        params.push((ip_name, ip));
        params.push((reference_name, item.reference_time.clone()));
    }
    let mut permitted = vec!["i.observed_at <= r.reference_time".to_string()];
    add_denied_predicates(&denied, "i.source", &mut permitted, &mut params);
    let predicate = permitted.join(" AND ");
    let sql = format!(
        "SELECT r.ordinal, r.ip, \
         argMaxIf(i.hostname_lc, i.observed_at, {predicate}) AS hostname, \
         argMaxIf(i.user_lc, i.observed_at, {predicate}) AS user, \
         argMaxIf(i.mac, i.observed_at, {predicate}) AS mac, \
         argMaxIf(i.source, i.observed_at, {predicate}) AS source, \
         formatDateTime(maxIf(i.observed_at, {predicate}), \
         '%Y-%m-%dT%H:%i:%S.%fZ', 'UTC') AS observed_at \
         FROM (SELECT tupleElement(item, 1) AS ordinal, tupleElement(item, 2) AS ip, \
         tupleElement(item, 3) AS reference_time FROM \
         (SELECT arrayJoin([{}]) AS item)) AS r \
         LEFT JOIN file({{identity_source:String}}, Parquet) AS i ON i.ip = r.ip \
         GROUP BY r.ordinal, r.ip, r.reference_time \
         HAVING countIf({predicate}) > 0 ORDER BY r.ordinal \
         SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, use_query_cache=0",
        tuples.join(", "),
        tenant.threads,
        tenant.max_execution_seconds,
        tenant.max_query_bytes,
        tenant.max_memory_bytes,
    );
    Ok(plan(snapshot, request_digest(&params), sql, params))
}

/// Plan a reverse-capable identity batch over the same immutable observation
/// ledger. IP, hostname, and user are fixed enum-like request semantics; no
/// request value can select an arbitrary SQL column.
pub fn plan_identity_entity_batch(
    tenant: &TenantQueryConfig,
    snapshot: &IdentitySnapshot,
    request: &IdentityEntityBatchRequest<'_>,
) -> Result<NativeQueryPlan> {
    validate_snapshot_binding(snapshot, request.snapshot_id)?;
    if request.items.is_empty() || request.items.len() > MAX_BATCH_ITEMS {
        return Err(IdentityError::InvalidRequest(
            "identity entity batch must contain between 1 and 500 items".to_string(),
        ));
    }
    let (lookup_column, entity_type) = match request.entity_type {
        "ip" => ("i.ip", "ip"),
        "host" => ("i.hostname_lc", "host"),
        "user" => ("i.user_lc", "user"),
        _ => {
            return Err(IdentityError::InvalidRequest(
                "identity entity type must be ip, host, or user".to_string(),
            ));
        }
    };
    snapshot.verify()?;
    let denied = normalized_denied_sources(request.deny_source_types)?;
    let mut tuples = Vec::with_capacity(request.items.len());
    let mut params = vec![(
        "identity_source".to_string(),
        snapshot.by_ip.to_string_lossy().into_owned(),
    )];
    for (ordinal, item) in request.items.iter().enumerate() {
        let value = normalize_identity_entity(entity_type, &item.value)?;
        validate_reference_time(&item.reference_time)?;
        let ordinal_name = format!("identity_ordinal_{ordinal}");
        let value_name = format!("identity_value_{ordinal}");
        let reference_name = format!("identity_reference_{ordinal}");
        tuples.push(format!(
            "tuple({{{ordinal_name}:UInt32}}, {{{value_name}:String}}, \
             parseDateTime64BestEffort({{{reference_name}:String}}, 6, 'UTC'))"
        ));
        params.push((ordinal_name, ordinal.to_string()));
        params.push((value_name, value));
        params.push((reference_name, item.reference_time.clone()));
    }
    let mut permitted = vec!["i.observed_at <= r.reference_time".to_string()];
    add_denied_predicates(&denied, "i.source", &mut permitted, &mut params);
    let predicate = permitted.join(" AND ");
    let sql = format!(
        "SELECT r.ordinal, r.value, \
         argMaxIf(i.ip, i.observed_at, {predicate}) AS ip, \
         argMaxIf(i.hostname_lc, i.observed_at, {predicate}) AS hostname, \
         argMaxIf(i.user_lc, i.observed_at, {predicate}) AS user, \
         argMaxIf(i.mac, i.observed_at, {predicate}) AS mac, \
         argMaxIf(i.source, i.observed_at, {predicate}) AS source, \
         formatDateTime(maxIf(i.observed_at, {predicate}), \
         '%Y-%m-%dT%H:%i:%S.%fZ', 'UTC') AS observed_at \
         FROM (SELECT tupleElement(item, 1) AS ordinal, tupleElement(item, 2) AS value, \
         tupleElement(item, 3) AS reference_time FROM \
         (SELECT arrayJoin([{}]) AS item)) AS r \
         LEFT JOIN file({{identity_source:String}}, Parquet) AS i ON {lookup_column} = r.value \
         GROUP BY r.ordinal, r.value, r.reference_time \
         HAVING countIf({predicate}) > 0 ORDER BY r.ordinal \
         SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, use_query_cache=0",
        tuples.join(", "),
        tenant.threads,
        tenant.max_execution_seconds,
        tenant.max_query_bytes,
        tenant.max_memory_bytes,
    );
    Ok(plan(snapshot, request_digest(&params), sql, params))
}

fn plan(
    snapshot: &IdentitySnapshot,
    query_sha256: String,
    sql: String,
    params: Vec<(String, String)>,
) -> NativeQueryPlan {
    NativeQueryPlan {
        query_sha256,
        sql,
        params,
        budget: QueryBudget {
            candidate_objects: 1,
            estimated_scan_bytes: snapshot.by_ip_bytes,
            max_query_bytes: snapshot.by_ip_bytes,
        },
        native_event_rows: false,
        temporary_aliases: BTreeSet::new(),
        schema_defaults: Vec::new(), reader: Default::default(),
    }
}

fn validate_snapshot_binding(snapshot: &IdentitySnapshot, supplied: &str) -> Result<()> {
    if supplied != snapshot.snapshot_id {
        return Err(IdentityError::InvalidRequest(
            "identity snapshot is not assigned to this tenant".to_string(),
        ));
    }
    Ok(())
}

fn normalize_ip(value: &str) -> Result<String> {
    IpAddr::from_str(value.trim())
        .map(|ip| ip.to_string())
        .map_err(|_| IdentityError::InvalidRequest("IP address is invalid".to_string()))
}

fn normalize_identity_entity(entity_type: &str, value: &str) -> Result<String> {
    if entity_type == "ip" {
        return normalize_ip(value);
    }
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
        || (entity_type == "host" && !value.chars().any(|ch| ch.is_ascii_alphanumeric()))
    {
        return Err(IdentityError::InvalidRequest(
            "identity entity value is invalid".to_string(),
        ));
    }
    Ok(value)
}

fn validate_reference_time(value: &str) -> Result<()> {
    DateTime::parse_from_rfc3339(value).map_err(|_| {
        IdentityError::InvalidRequest(
            "identity reference time must be RFC3339 with a timezone".to_string(),
        )
    })?;
    Ok(())
}

fn normalized_denied_sources(sources: &BTreeSet<String>) -> Result<Vec<String>> {
    if sources.len() > MAX_DENIED_SOURCES
        || sources.iter().any(|source| {
            source.is_empty() || source.len() > 512 || source.chars().any(char::is_control)
        })
    {
        return Err(IdentityError::InvalidRequest(
            "identity source scope exceeds its bound".to_string(),
        ));
    }
    Ok(sources
        .iter()
        .map(|source| source.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn add_denied_predicates(
    denied: &[String],
    source_expression: &str,
    predicates: &mut Vec<String>,
    params: &mut Vec<(String, String)>,
) {
    for (index, source) in denied.iter().enumerate() {
        let name = format!("identity_deny_{index}");
        predicates.push(format!("lower({source_expression}) != {{{name}:String}}"));
        params.push((name, source.clone()));
    }
}

fn request_digest(params: &[(String, String)]) -> String {
    let mut hasher = Sha256::new();
    for (name, value) in params {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::ObjectStoreCredentials;

    fn tenant() -> TenantQueryConfig {
        TenantQueryConfig {
            tenant_id: "tenant-a".to_string(),
            source: "https://object.test/events".to_string(),
            iceberg_metadata_file_path: "metadata/one.json".to_string(),
            max_query_bytes: 1_000_000,
            max_memory_bytes: crate::planner::DEFAULT_QUERY_MEMORY_BYTES,
            max_execution_seconds: 30,
            threads: 4,
            credentials: ObjectStoreCredentials::Static {
                access_key: "access".to_string(),
                secret_key: "secret".to_string(),
                session_token: None,
            },
            snapshot_cache: None,
        }
    }

    fn snapshot(root: &std::path::Path) -> IdentitySnapshot {
        let path = root.join("identity.parquet");
        std::fs::write(&path, b"immutable-fixture").expect("write fixture");
        IdentitySnapshot {
            snapshot_id: "identity-v1".to_string(),
            by_ip_sha256: file_sha256(&path).expect("digest"),
            by_ip_bytes: std::fs::metadata(&path).expect("metadata").len(),
            by_ip_modified: std::fs::metadata(&path)
                .expect("metadata")
                .modified()
                .expect("modified time"),
            by_ip: path,
        }
    }

    #[test]
    fn identity_plan_binds_values_without_interpolation() {
        let root = tempfile::tempdir().expect("temporary directory");
        let snapshot = snapshot(root.path());
        let denied = BTreeSet::from(["blocked-source".to_string()]);
        let plan = plan_identity_resolve(
            &tenant(),
            &snapshot,
            &IdentityResolveRequest {
                snapshot_id: "identity-v1",
                ip: "2001:0db8::1",
                reference_time: "2026-08-11T00:00:00Z",
                deny_source_types: &denied,
            },
        )
        .expect("identity plan");
        assert!(!plan.sql.contains("2001:db8::1"));
        assert!(!plan.sql.contains("blocked-source"));
        assert!(plan.sql.contains("{identity_ip:String}"));
        assert!(plan.sql.contains("{identity_deny_0:String}"));
        assert_eq!(plan.budget.estimated_scan_bytes, 17);
    }

    #[test]
    fn identity_batch_uses_only_fixed_parameter_names() {
        let root = tempfile::tempdir().expect("temporary directory");
        let snapshot = snapshot(root.path());
        let denied = BTreeSet::new();
        let plan = plan_identity_batch(
            &tenant(),
            &snapshot,
            &IdentityBatchRequest {
                snapshot_id: "identity-v1",
                items: &[IdentityBatchItem {
                    ip: "192.0.2.7".to_string(),
                    reference_time: "2026-08-11T00:00:00Z".to_string(),
                }],
                deny_source_types: &denied,
            },
        )
        .expect("identity batch plan");
        assert!(!plan.sql.contains("192.0.2.7"));
        assert!(plan.sql.contains("{identity_ip_0:String}"));
        assert!(plan.sql.contains("{identity_reference_0:String}"));
    }

    #[test]
    fn identity_snapshot_mutation_fails_closed() {
        let root = tempfile::tempdir().expect("temporary directory");
        let snapshot = snapshot(root.path());
        std::fs::write(&snapshot.by_ip, b"mutated-fixture!").expect("mutate fixture");
        let denied = BTreeSet::new();
        assert!(matches!(
            plan_identity_resolve(
                &tenant(),
                &snapshot,
                &IdentityResolveRequest {
                    snapshot_id: "identity-v1",
                    ip: "192.0.2.7",
                    reference_time: "2026-08-11T00:00:00Z",
                    deny_source_types: &denied,
                },
            ),
            Err(IdentityError::SnapshotChanged)
        ));
    }

    #[test]
    fn identity_entity_batch_uses_fixed_reverse_lookup_column() {
        let root = tempfile::tempdir().expect("temporary directory");
        let snapshot = snapshot(root.path());
        let plan = plan_identity_entity_batch(
            &tenant(),
            &snapshot,
            &IdentityEntityBatchRequest {
                snapshot_id: "identity-v1",
                entity_type: "host",
                items: &[IdentityEntityBatchItem {
                    value: "WS-01.EXAMPLE.COM".to_string(),
                    reference_time: "2026-08-11T00:00:00Z".to_string(),
                }],
                deny_source_types: &BTreeSet::new(),
            },
        )
        .expect("reverse identity plan");
        assert!(plan.sql.contains("ON i.hostname_lc = r.value"));
        assert!(!plan.sql.contains("WS-01.EXAMPLE.COM"));
        assert!(
            plan.params
                .iter()
                .any(|(name, value)| name == "identity_value_0" && value == "ws-01.example.com")
        );
    }
}
