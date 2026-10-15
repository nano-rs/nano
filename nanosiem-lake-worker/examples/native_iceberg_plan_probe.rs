// SPDX-License-Identifier: AGPL-3.0-or-later

//! Execute trusted Nano compiler output through the Rust planner/native seam.

use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::planner::{
    CompiledQuery, ObjectStoreCredentials, TenantQueryConfig, plan_broad_log_query, read_manifest,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("{name} is required").into())
}

fn required_u64(name: &str) -> Result<u64, Box<dyn std::error::Error>> {
    required(name)?
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an unsigned integer").into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let compiled: CompiledQuery = serde_json::from_slice(&input)?;
    let manifest = read_manifest(required("NANO_CHDB_TEST_MANIFEST")?)?;
    let tenant = TenantQueryConfig {
        tenant_id: required("NANO_CHDB_TEST_TENANT_ID")?,
        source: required("NANO_CHDB_TEST_SOURCE")?,
        iceberg_metadata_file_path: required("NANO_CHDB_TEST_METADATA")?,
        max_query_bytes: required_u64("NANO_CHDB_TEST_MAX_QUERY_BYTES")?,
        max_memory_bytes: nanosiem_lake_worker::planner::DEFAULT_QUERY_MEMORY_BYTES,
        max_execution_seconds: required_u64("NANO_CHDB_TEST_MAX_EXECUTION_SECONDS")?,
        threads: required_u64("NANO_CHDB_TEST_THREADS")?,
        credentials: ObjectStoreCredentials::Static {
            access_key: required("NANO_CHDB_TEST_ACCESS_KEY")?,
            secret_key: required("NANO_CHDB_TEST_SECRET_KEY")?,
            session_token: std::env::var("NANO_CHDB_TEST_SESSION_TOKEN").ok(),
        },
        snapshot_cache: None,
    };
    let plan = plan_broad_log_query(&tenant, &manifest, &compiled)?;
    let runtime = NativeChdb::load_verified(
        required("NANO_CHDB_LIBRARY_PATH")?,
        &required("NANO_CHDB_LIBRARY_SHA256")?,
    )?;
    let connection = runtime.connect(&[])?;
    let parameters = plan
        .params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let result = connection.query_with_params(&plan.sql, "JSONEachRow", &parameters)?;
    let mut rows = Vec::new();
    for line in result.data.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut row: Value = serde_json::from_slice(line)?;
        if let Some(object) = row.as_object_mut() {
            for alias in &plan.temporary_aliases {
                object.remove(alias);
            }
        }
        rows.push(row);
    }
    let leaked_alias = rows.iter().any(|row| {
        row.as_object().is_some_and(|object| {
            object
                .keys()
                .any(|name| name.starts_with("__nano_path_"))
        })
    });
    let sql_sha256 = hex::encode(Sha256::digest(plan.sql.as_bytes()));
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "chdb_version_function": runtime.version()?,
            "engine_ms": result.elapsed.as_secs_f64() * 1_000.0,
            "native_event_rows": plan.native_event_rows,
            "query_sha256": plan.query_sha256,
            "result_rows": rows.len(),
            "schema_defaults": plan.schema_defaults,
            "sql_sha256": sql_sha256,
            "storage_bytes_read": result.storage_bytes_read,
            "storage_rows_read": result.storage_rows_read,
            "temporary_alias_leaked": leaked_alias,
            "temporary_aliases_stripped": plan.temporary_aliases.len(),
            "budget": plan.budget,
        }))?
    );
    Ok(())
}
