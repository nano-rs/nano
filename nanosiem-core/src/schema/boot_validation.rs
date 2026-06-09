// SPDX-License-Identifier: AGPL-3.0-or-later

//! Boot-time schema validation (OCSF Phase 3b, NAN-1241).
//!
//! Fail-fast probe (DualPool philosophy, NAN-800): once ClickHouse is reachable
//! and confirmed schema-current at boot, assert that the **active schema
//! profile's** logs table actually carries the columns the profile needs to
//! query. Without this, an OCSF deployment pointed at a UDM table (or vice
//! versa) would not error — it would silently return empty / wrong results at
//! query time, the exact class of silent-correctness bug the schema seam exists
//! to prevent.
//!
//! For UDM this is a **no-op in practice**: every required column
//! (`prewhere_fields()` + `timestamp`) exists in the canonical `nanosiem.logs`
//! schema the migrator already verified, so a healthy UDM deploy passes
//! unconditionally and its boot behavior is unchanged.
//!
//! The probe reads `system.columns` (rather than `DESCRIBE TABLE`) because it is
//! a plain `SELECT` — no DDL rights, distributed-table, or readonly-user
//! concerns — and it is the same introspection field-stats already uses
//! (`clickhouse_executor::field_stats::get_table_columns`).

use clickhouse::Client as ClickHouseClient;
use serde::Deserialize;

use super::SchemaProfile;

/// A single `system.columns.name` row for the column-introspection probe.
#[derive(clickhouse::Row, Deserialize)]
struct ColumnNameRow {
    name: String,
}

/// Error raised when the active schema profile's table is absent or missing the
/// columns the profile must read. A hard boot failure.
#[derive(Debug, thiserror::Error)]
pub enum SchemaValidationError {
    /// The configured logs table for the active profile does not exist.
    #[error(
        "active schema profile {schema:?} expects table `{table}` but it does not exist \
         (no columns found). The deployment selected NANO_SCHEMA_PROFILE={schema_env} but the \
         ClickHouse table is absent — point at the correct table or correct the profile."
    )]
    TableMissing {
        /// The active schema id (debug form, e.g. `Ocsf`).
        schema: String,
        /// Lowercase env-style schema id (`udm` | `ocsf`).
        schema_env: String,
        /// Fully-qualified table the profile expects (e.g. `nanosiem.ocsf_logs`).
        table: String,
    },
    /// The table exists but is missing one or more columns the profile requires.
    #[error(
        "active schema profile {schema:?} (NANO_SCHEMA_PROFILE={schema_env}) is misconfigured \
         against table `{table}`: required column(s) {missing:?} are absent. This usually means \
         the table holds a *different* schema than the active profile (e.g. an OCSF profile \
         pointed at a UDM table). Fix the profile selection or the table."
    )]
    MissingColumns {
        /// The active schema id (debug form).
        schema: String,
        /// Lowercase env-style schema id (`udm` | `ocsf`).
        schema_env: String,
        /// Fully-qualified table that was probed.
        table: String,
        /// The required columns that were not present.
        missing: Vec<String>,
    },
    /// The probe query itself failed (CH unreachable mid-boot, transport error).
    /// Treated as a soft skip by the caller, matching how other boot CH checks
    /// degrade — we do not want a transient CH read error to be indistinguishable
    /// from a genuine schema mismatch.
    #[error("schema validation probe failed to query system.columns for `{table}`: {message}")]
    ProbeFailed {
        /// The table being probed.
        table: String,
        /// Underlying transport/query error (stringified).
        message: String,
    },
}

/// The columns the active profile *must* find in its table for queries to work:
/// its PREWHERE-eligible (indexed) set plus `timestamp`. These are the hot
/// columns every search filters on; if they are absent the profile is pointed at
/// the wrong table. Kept intentionally minimal (not the full field universe) so
/// a benign column rename in the long tail does not fail boot.
fn required_columns(profile: &dyn SchemaProfile) -> Vec<String> {
    use super::types::FieldResolution;

    // A PREWHERE entry may be an ALIAS, not a physical column — e.g. UDM's
    // `sourcetype` (alias of `source_type`) and other normalize_field_name
    // aliases live in PREWHERE_FIELDS. Asserting the alias exists in
    // system.columns would fail a perfectly healthy UDM boot. So canonicalize
    // each field and keep only what resolves to a real `ExplicitColumn` (the
    // physical column name), skipping aliases / JSON-tail fields.
    let mut cols: Vec<String> = Vec::new();
    for f in profile.prewhere_fields() {
        let canonical = profile.canonicalize(f);
        if let FieldResolution::ExplicitColumn(col) = profile.resolve(canonical.as_ref()) {
            if !cols.contains(&col) {
                cols.push(col);
            }
        }
    }
    // The ordering-key timestamp is required by every time-bounded query but is
    // not always a member of prewhere_fields(), so assert it explicitly.
    if !cols.iter().any(|c| c == "timestamp") {
        cols.push("timestamp".to_string());
    }
    cols
}

/// Probe `system.columns` for the actual columns of `db`.`table`.
async fn fetch_columns(
    client: &ClickHouseClient,
    db: &str,
    table: &str,
) -> Result<Vec<String>, String> {
    // db/table come from the profile's compile-time table_name() + the
    // is_clustered table-name registry, never from user input — but bind them
    // anyway rather than format!() into the SQL.
    let rows = client
        .query("SELECT name FROM system.columns WHERE database = ? AND table = ?")
        .bind(db)
        .bind(table)
        .fetch_all::<ColumnNameRow>()
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows.into_iter().map(|r| r.name).collect())
}

/// Validate the active schema profile against its ClickHouse table.
///
/// `local_table` is the fully-qualified **local** table name (`nanosiem.logs`,
/// `nanosiem.ocsf_logs`) resolved through the tenant-aware table-name registry —
/// the caller passes `table_names.local(<key>)` so cluster mode probes the local
/// MergeTree (where columns physically live), not the `_distributed` wrapper.
///
/// On success returns `Ok(())`. A genuine mismatch (missing table / missing
/// required columns) returns the corresponding hard-fail error. A probe
/// transport failure returns [`SchemaValidationError::ProbeFailed`], which the
/// caller may downgrade to a logged skip to match how other boot CH checks
/// tolerate transient unavailability.
pub async fn validate_active_schema_table(
    client: &ClickHouseClient,
    profile: &dyn SchemaProfile,
    local_table: &str,
) -> Result<(), SchemaValidationError> {
    let schema = format!("{:?}", profile.id());
    let schema_env = schema.to_ascii_lowercase();

    // Split `db.table` (the registry always qualifies with the `nanosiem.`
    // database). Fall back to the default database if somehow unqualified.
    let (db, table) = match local_table.split_once('.') {
        Some((db, table)) => (db, table),
        None => ("nanosiem", local_table),
    };

    let actual = fetch_columns(client, db, table)
        .await
        .map_err(|message| SchemaValidationError::ProbeFailed {
            table: local_table.to_string(),
            message,
        })?;

    if actual.is_empty() {
        return Err(SchemaValidationError::TableMissing {
            schema,
            schema_env,
            table: local_table.to_string(),
        });
    }

    let actual_set: std::collections::HashSet<&str> =
        actual.iter().map(String::as_str).collect();
    let missing: Vec<String> = required_columns(profile)
        .into_iter()
        .filter(|c| !actual_set.contains(c.as_str()))
        .collect();

    if !missing.is_empty() {
        return Err(SchemaValidationError::MissingColumns {
            schema,
            schema_env,
            table: local_table.to_string(),
            missing,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{OcsfProfile, UdmProfile};

    #[test]
    fn udm_required_columns_are_physical_not_aliases() {
        use crate::schema::FieldResolution;
        let p = UdmProfile::new();
        let cols = required_columns(&p);
        assert!(cols.iter().any(|c| c == "timestamp"));
        // Regression (NAN-1241 Phase 3b): `sourcetype` is in PREWHERE_FIELDS but is
        // an ALIAS for the physical `source_type` column — asserting `sourcetype`
        // exists in system.columns would fail a healthy UDM boot. Required columns
        // must be the canonicalized physical column, never the alias.
        assert!(
            cols.iter().any(|c| c == "source_type"),
            "physical source_type must be required"
        );
        assert!(
            !cols.iter().any(|c| c == "sourcetype"),
            "alias sourcetype must NOT be required as a physical column"
        );
        // Every required column (except the explicitly-added timestamp) resolves
        // to a real ExplicitColumn.
        for c in &cols {
            if c == "timestamp" {
                continue;
            }
            assert!(
                matches!(p.resolve(c), FieldResolution::ExplicitColumn(_)),
                "required column {c} must be a physical ExplicitColumn"
            );
        }
    }

    #[test]
    fn ocsf_required_columns_include_timestamp() {
        // OCSF's prewhere set differs, but `timestamp` is always required.
        let p = OcsfProfile::new();
        let cols = required_columns(&p);
        assert!(cols.iter().any(|c| c == "timestamp"));
    }
}
