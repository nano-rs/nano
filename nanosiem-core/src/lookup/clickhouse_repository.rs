// SPDX-License-Identifier: AGPL-3.0-or-later

//! ClickHouse-backed lookup repository (NAN-1581).
//!
//! Stores lookup ROW DATA in the single shared `nanosiem.lookup_rows` table
//! (migration 146) while keeping the registry in Postgres. Registry methods
//! delegate to an inner [`PostgresLookupRepository`]; only the data methods are
//! re-implemented against ClickHouse.
//!
//! Design (see migration 146 header for the full rationale):
//! - `row_id` is an immutable surrogate (snowflake) — the dedup identity.
//! - `version` is a fresh snowflake on every write; ReplacingMergeTree keeps the
//!   highest-version row per `(lookup_table_name, row_id)`.
//! - Updates re-insert the same `row_id` at a higher version with recomputed
//!   `key_lc` + updated `cols_json`. Deletes insert a tombstone (`deleted = 1`).
//! - Reads dedup via `argMax(..., version) GROUP BY row_id` then `d = 0` — never
//!   `FINAL` (which would merge-on-read across the whole shared table).
//! - `get_table_row_count` is gated on the Postgres registry `row_count` (CH
//!   live counts are unreliable pre-merge); `get_table_size` is a display-only
//!   estimate apportioned from `system.parts`.
//!
//! KNOWN LIMITATION (foundation phase): the dedicated `key_raw`/`key_lc`
//! columns hold the value of the FIRST registry column, so the indexed
//! `key_lc IN (...)` read path can only match on that column. Lookups keyed on
//! a non-first column fall back to a full-table dedup scan (still correct, just
//! unindexed). Aligning the stored key with the registry primary key — and/or
//! storing multiple keyed columns — is deferred to the consumer-repoint phase;
//! the backend is opt-in (default postgres) until then.

use async_trait::async_trait;
use std::collections::HashMap;
use tracing::{debug, instrument};
use uuid::Uuid;

use super::postgres_repository::PostgresLookupRepository;
use super::repository::{LookupRepositoryError, LookupStore, RuleReferenceRow};
use super::snowflake;
use super::types::*;
use crate::db::dual_pool::{on_cluster_clause, TableNames};
use crate::upload::ColumnType;

/// Max value tuples per INSERT batch (mirrors identity's CH chunking).
const CH_INSERT_CHUNK: usize = 1000;

/// ClickHouse-backed lookup repository.
///
/// Carries the Postgres pool (via the inner registry repo) for registry methods
/// and a ClickHouse client for row data.
#[derive(Clone)]
pub struct ClickHouseLookupRepository {
    registry: PostgresLookupRepository,
    ch: clickhouse::Client,
}

impl ClickHouseLookupRepository {
    /// Create a new ClickHouse-backed lookup repository.
    ///
    /// `pg` backs the (always-Postgres) registry; `ch` backs the row data.
    pub fn new(pg: sqlx::PgPool, ch: clickhouse::Client) -> Self {
        Self {
            registry: PostgresLookupRepository::new(pg),
            ch,
        }
    }

    fn ch_err(e: clickhouse::error::Error) -> LookupRepositoryError {
        LookupRepositoryError::ClickHouseError(e.to_string())
    }

    /// Validate that an identifier is safe to interpolate (logical table names
    /// are still validated even though they're bound as a value, because they
    /// reach the registry as Postgres identifiers).
    fn is_valid_identifier(name: &str) -> bool {
        if name.is_empty() || name.len() > 63 {
            return false;
        }
        let first = name.chars().next().unwrap();
        if !first.is_ascii_alphabetic() && first != '_' {
            return false;
        }
        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// Stringify a JSON key value the same way the Postgres path does, so the
    /// raw/lowered comparison keys are byte-identical across backends.
    fn key_to_string(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Null => String::new(),
            other => other.to_string(),
        }
    }

    /// Split a record into its key cell (`key_field`) and the remaining columns
    /// serialized as a JSON object for `cols_json`. The key field itself is NOT
    /// duplicated into `cols_json` — it's reconstructed from `key_raw` on read.
    pub(crate) fn encode_record(
        key_field: &str,
        columns: &[LookupColumn],
        record: &HashMap<String, serde_json::Value>,
    ) -> (String, serde_json::Map<String, serde_json::Value>) {
        let key_raw = record
            .get(key_field)
            .map(Self::key_to_string)
            .unwrap_or_default();
        let mut cols = serde_json::Map::new();
        for col in columns {
            if col.name == key_field {
                continue;
            }
            let v = record
                .get(&col.name)
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            cols.insert(col.name.clone(), v);
        }
        (key_raw, cols)
    }

    /// Resolve the key field for the online write paths from the registry
    /// PRIMARY KEY (so the stored `key_raw`/`key_lc` carry the indexed value that
    /// `lookup_batch` queries by), falling back to the first column when the table
    /// declares no primary key. `LookupService::lookup_batch` queries by the
    /// registry primary key, so encoding the key from `columns.first()` would make
    /// rows on a non-first-PK table unretrievable until a merge/backfill rewrote
    /// them — mirror what `insert_backfill_rows` already does.
    async fn resolve_key_field(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
    ) -> String {
        let fallback = || columns.first().map(|c| c.name.clone()).unwrap_or_default();
        // The online row methods receive the PHYSICAL `table_name`; the registry's
        // `get_table` resolves by logical name, so match on `table_name` via
        // `list_tables` (same resolution as `get_table_row_count`).
        match self.registry.list_tables().await {
            Ok(tables) => tables
                .into_iter()
                .find(|t| t.table_name == table_name)
                .and_then(|t| t.primary_key)
                .unwrap_or_else(fallback),
            Err(_) => fallback(),
        }
    }

    /// Coerce a decoded JSON value to match the registry column type so output
    /// fields look the same as the Postgres path (numbers as numbers, etc.).
    fn coerce_to_type(value: serde_json::Value, ty: &ColumnType) -> serde_json::Value {
        match (ty, &value) {
            (ColumnType::Integer, serde_json::Value::String(s)) => s
                .parse::<i64>()
                .map(|n| serde_json::Value::Number(n.into()))
                .unwrap_or(value),
            (ColumnType::Float, serde_json::Value::String(s)) => s
                .parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64)
                .map(serde_json::Value::Number)
                .unwrap_or(value),
            (ColumnType::Boolean, serde_json::Value::String(s)) => match s.as_str() {
                "true" | "t" | "1" => serde_json::Value::Bool(true),
                "false" | "f" | "0" => serde_json::Value::Bool(false),
                _ => value,
            },
            _ => value,
        }
    }

    /// Build the deduped-read inner query (argMax over version, grouped by
    /// row_id, deleted filtered out). Exposed as an associated fn so the SQL
    /// shape is unit-testable without a live ClickHouse.
    ///
    /// `key_filter`, when present, is appended as an additional outer predicate
    /// (e.g. `key_lc IN ('a','b')` or `key_raw IN ('A','B')`).
    pub(crate) fn deduped_read_sql(select_cols: &str, key_filter: Option<&str>) -> String {
        // NAN-1728: `lookup_rows` is a per-shard ReplacingMergeTree with an
        // additive `_distributed` wrapper (in DISTRIBUTED_TABLES). Reads route
        // through the wrapper so rows uploaded to any shard are visible; the
        // `argMax(…, version) GROUP BY row_id` below already collapses cross-shard
        // duplicates of a `row_id` to its latest version, so the wrapper read is
        // correct. On single-node `.read()` returns the local name → the emitted
        // SQL is byte-identical to the pre-NAN-1728 form.
        let table = TableNames::new(!on_cluster_clause().is_empty()).read("lookup_rows");
        let mut sql = format!(
            "SELECT {select_cols} FROM (\
             SELECT row_id, \
             argMax(key_raw, version) AS key_raw, \
             argMax(key_lc, version) AS key_lc, \
             argMax(cols_json, version) AS cols_json, \
             argMax(deleted, version) AS d \
             FROM {table} \
             WHERE lookup_table_name = ? \
             GROUP BY row_id) \
             WHERE d = 0"
        );
        if let Some(filter) = key_filter {
            sql.push_str(" AND ");
            sql.push_str(filter);
        }
        sql
    }

    /// Read all live (deduped, non-deleted) rows for a logical table, optionally
    /// restricted to a set of key values (raw or lowercased per `case_insensitive`).
    async fn read_live_rows(
        &self,
        table_name: &str,
        key_values: Option<&[serde_json::Value]>,
        case_insensitive: bool,
    ) -> Result<Vec<LiveRow>, LookupRepositoryError> {
        // Build the optional key filter as an IN list of literals. The values
        // are user-supplied lookup keys; CH string-literal-escape them.
        let key_filter = key_values.map(|vals| {
            let col = if case_insensitive { "key_lc" } else { "key_raw" };
            let list = vals
                .iter()
                .map(|v| {
                    let mut s = Self::key_to_string(v);
                    if case_insensitive {
                        s = s.to_lowercase();
                    }
                    format!("'{}'", crate::sql_hygiene::escape_sql_string(&s))
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("{col} IN ({list})")
        });

        let sql = Self::deduped_read_sql("row_id, key_raw, cols_json", key_filter.as_deref());

        let mut cursor = self
            .ch
            .query(&sql)
            .bind(table_name)
            .fetch_bytes("JSONEachRow")
            .map_err(Self::ch_err)?;

        let mut bytes = Vec::new();
        while let Some(chunk) = cursor.next().await.map_err(Self::ch_err)? {
            bytes.extend_from_slice(&chunk);
        }
        let text = String::from_utf8(bytes)
            .map_err(|e| LookupRepositoryError::ClickHouseError(e.to_string()))?;

        let mut out = Vec::new();
        for line in text.lines().filter(|l| !l.is_empty()) {
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(e) => {
                    debug!(error = %e, "skipping unparsable lookup_rows JSON line");
                    continue;
                }
            };
            let key_raw = v
                .get("key_raw")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            let cols_json = v
                .get("cols_json")
                .and_then(|x| x.as_str())
                .unwrap_or("{}")
                .to_string();
            let row_id = v.get("row_id").and_then(json_u64).unwrap_or(0);
            out.push(LiveRow {
                row_id,
                key_raw,
                cols_json,
            });
        }
        Ok(out)
    }

    /// Decode a live CH row into the public HashMap shape, restricted to
    /// `output_fields` when given and typed per the registry columns. The key
    /// field is always reconstructed from `key_raw`.
    fn decode_row(
        live: &LiveRow,
        key_field: &str,
        columns: &[LookupColumn],
        output_fields: Option<&[String]>,
    ) -> HashMap<String, serde_json::Value> {
        let cols: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&live.cols_json).unwrap_or_default();

        let type_of = |name: &str| columns.iter().find(|c| c.name == name).map(|c| c.data_type);

        let mut out = HashMap::new();
        // Reconstruct the key column.
        let key_val = match type_of(key_field) {
            Some(ty) => Self::coerce_to_type(
                serde_json::Value::String(live.key_raw.clone()),
                &ty,
            ),
            None => serde_json::Value::String(live.key_raw.clone()),
        };

        let want = |name: &str| match output_fields {
            Some(fields) => fields.iter().any(|f| f == name),
            None => true,
        };

        if want(key_field) || output_fields.is_none() {
            out.insert(key_field.to_string(), key_val);
        }

        // Non-key columns from cols_json, null-filled and typed.
        for col in columns {
            if col.name == key_field {
                continue;
            }
            if !want(&col.name) {
                continue;
            }
            let raw = cols
                .get(&col.name)
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            out.insert(col.name.clone(), Self::coerce_to_type(raw, &col.data_type));
        }

        // Null-fill any explicitly requested output field absent from the row.
        if let Some(fields) = output_fields {
            for f in fields {
                out.entry(f.clone()).or_insert(serde_json::Value::Null);
            }
        }
        out
    }

    /// Backfill insert (NAN-1581 Phase 2): copy already-existing Postgres rows
    /// into `lookup_rows`, preserving the Postgres surrogate `_row_id` as the CH
    /// `row_id` (so a re-run dedups on `(lookup_table_name, row_id)` instead of
    /// duplicating) and deriving `key_raw`/`key_lc` from the registry's
    /// `key_field` (the PRIMARY KEY column, not blindly the first column).
    ///
    /// `records` are the raw Postgres rows including the `_row_id` surrogate;
    /// each record's `_row_id` becomes the CH `row_id`. The key field is excluded
    /// from `cols_json` (reconstructed from `key_raw` on read), matching the
    /// online write path's encoding so reads are byte-identical.
    pub(crate) async fn insert_backfill_rows(
        &self,
        table_name: &str,
        key_field: &str,
        columns: &[LookupColumn],
        records: &[HashMap<String, serde_json::Value>],
    ) -> Result<usize, LookupRepositoryError> {
        if records.is_empty() {
            return Ok(0);
        }
        let mut tuples = Vec::with_capacity(records.len());
        for rec in records {
            // Preserve the Postgres surrogate so re-copies dedup rather than
            // duplicate. Fall back to a fresh snowflake only if absent.
            let row_id = rec
                .get("_row_id")
                .and_then(json_u64)
                .unwrap_or_else(snowflake::next_id);
            let (key_raw, cols) = Self::encode_record(key_field, columns, rec);
            tuples.push(InsertTuple {
                row_id,
                key_raw,
                cols_json: serde_json::Value::Object(cols).to_string(),
                deleted: 0,
            });
        }
        let n = tuples.len();
        self.insert_tuples(table_name, &tuples).await?;
        Ok(n)
    }

    /// Count live (deduped, non-tombstoned) rows for a logical table directly in
    /// ClickHouse — used by the backfill verifier to compare against the source
    /// Postgres `COUNT(*)`. Unlike `get_table_row_count` (which trusts the PG
    /// registry), this reads the actual CH state.
    pub(crate) async fn deduped_live_count(
        &self,
        table_name: &str,
    ) -> Result<i64, LookupRepositoryError> {
        let rows = self.read_live_rows(table_name, None, false).await?;
        Ok(rows.len() as i64)
    }

    /// Insert a batch of (row_id, key_raw, cols_json, deleted) tuples at fresh
    /// versions. Each row gets its own snowflake version.
    async fn insert_tuples(
        &self,
        table_name: &str,
        rows: &[InsertTuple],
    ) -> Result<(), LookupRepositoryError> {
        if rows.is_empty() {
            return Ok(());
        }
        for chunk in rows.chunks(CH_INSERT_CHUNK) {
            let tuple = "(?, ?, ?, ?, ?, ?, ?)";
            let placeholders = vec![tuple; chunk.len()].join(", ");
            // INSERT targets the LOCAL name (a Distributed table isn't the insert
            // target here). NAN-1728: lookup_rows is a per-shard table with an
            // additive `_distributed` wrapper; a write lands on whichever shard
            // the connection hit. Reads route through the wrapper + argMax dedup,
            // so rows are visible cluster-wide; the DELETE/purge mutations run ON
            // CLUSTER. Single-node: the one shard holds everything.
            let sql = format!(
                "INSERT INTO nanosiem.lookup_rows \
                 (lookup_table_name, row_id, key_raw, key_lc, cols_json, version, deleted) \
                 VALUES {placeholders}"
            );
            let mut q = self.ch.query(&sql);
            for t in chunk {
                q = q
                    .bind(table_name)
                    .bind(t.row_id)
                    .bind(&t.key_raw)
                    .bind(t.key_raw.to_lowercase())
                    .bind(&t.cols_json)
                    .bind(snowflake::next_id())
                    .bind(t.deleted);
            }
            q.execute().await.map_err(Self::ch_err)?;
        }
        Ok(())
    }
}

/// A live (deduped) row read back from ClickHouse.
struct LiveRow {
    row_id: u64,
    key_raw: String,
    cols_json: String,
}

/// A row to insert (version is minted per-row inside `insert_tuples`).
struct InsertTuple {
    row_id: u64,
    key_raw: String,
    cols_json: String,
    deleted: u8,
}

/// Extract a u64 from a JSON number/string (CH JSONEachRow may emit UInt64 as a
/// string to preserve precision).
fn json_u64(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[async_trait]
impl LookupStore for ClickHouseLookupRepository {
    // ---- Registry: delegate to Postgres ----
    async fn list_tables(&self) -> Result<Vec<LookupTable>, LookupRepositoryError> {
        self.registry.list_tables().await
    }
    async fn get_table(&self, name: &str) -> Result<LookupTable, LookupRepositoryError> {
        self.registry.get_table(name).await
    }
    async fn table_exists(&self, name: &str) -> Result<bool, LookupRepositoryError> {
        self.registry.table_exists(name).await
    }
    async fn register_table(
        &self,
        new_table: &NewLookupTable,
        actual_table_name: &str,
        created_by_user_id: Option<Uuid>,
    ) -> Result<LookupTable, LookupRepositoryError> {
        self.registry
            .register_table(new_table, actual_table_name, created_by_user_id)
            .await
    }
    async fn update_table_stats(
        &self,
        name: &str,
        row_count: i64,
        size_bytes: i64,
    ) -> Result<(), LookupRepositoryError> {
        self.registry
            .update_table_stats(name, row_count, size_bytes)
            .await
    }
    async fn unregister_table(&self, name: &str) -> Result<LookupTable, LookupRepositoryError> {
        self.registry.unregister_table(name).await
    }
    async fn update_table_columns(
        &self,
        name: &str,
        columns: &[LookupColumn],
        primary_key: Option<&str>,
    ) -> Result<(), LookupRepositoryError> {
        self.registry
            .update_table_columns(name, columns, primary_key)
            .await
    }
    async fn find_rules_referencing(
        &self,
        table_name: &str,
    ) -> Result<Vec<RuleReferenceRow>, LookupRepositoryError> {
        self.registry.find_rules_referencing(table_name).await
    }

    // ---- Schema / lifecycle ----
    #[instrument(skip(self, _columns))]
    async fn create_dynamic_table(
        &self,
        table_name: &str,
        _columns: &[LookupColumn],
        _primary_key: Option<&str>,
    ) -> Result<(), LookupRepositoryError> {
        // No per-lookup CH DDL: the shared lookup_rows table is static. We only
        // validate the name so the registry-side identifier stays consistent.
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn drop_dynamic_table(&self, table_name: &str) -> Result<(), LookupRepositoryError> {
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }
        // Async mutation; the registry delete is handled by the service.
        // ON CLUSTER so the purge runs on every shard (lookup_rows is a per-shard
        // table, NAN-1728; without it a mutation only lands on the connected
        // node, leaving orphaned rows on the others).
        // `on_cluster_clause()` is empty on single-node → byte-identical DDL.
        let sql = format!(
            "ALTER TABLE nanosiem.lookup_rows{on_cluster} DELETE WHERE lookup_table_name = ?",
            on_cluster = on_cluster_clause()
        );
        self.ch
            .query(&sql)
            .bind(table_name)
            .execute()
            .await
            .map_err(Self::ch_err)
    }

    #[instrument(skip(self))]
    async fn truncate_dynamic_table(
        &self,
        table_name: &str,
    ) -> Result<(), LookupRepositoryError> {
        // Same as drop at the data level — remove all rows for this logical table.
        self.drop_dynamic_table(table_name).await
    }

    #[instrument(skip(self, _columns))]
    async fn swap_staged_table(
        &self,
        old_physical: &str,
        staging_physical: &str,
        _registry_name: &str,
        _columns: &[LookupColumn],
        _primary_key: Option<&str>,
        _row_count: i64,
    ) -> Result<(), LookupRepositoryError> {
        // Version-generation swap. The service has already inserted the new
        // generation under `staging_physical`. Re-key those staged rows to the
        // live name `old_physical` at a fresh swap-version generation, then drop
        // the prior generation (version < swap_version). If the re-key INSERT
        // fails, we skip the DELETE so the old generation stays intact.
        if !Self::is_valid_identifier(old_physical)
            || !Self::is_valid_identifier(staging_physical)
        {
            return Err(LookupRepositoryError::InvalidTableName(
                old_physical.to_string(),
            ));
        }
        let swap_version = snowflake::next_id();

        // Re-key the deduped staged rows onto the live name at versions >=
        // swap_version. snowflake() advances per call so each row's version is
        // unique and >= swap_version.
        let staged = self.read_live_rows(staging_physical, None, false).await?;
        let rekeyed: Vec<InsertTuple> = staged
            .into_iter()
            .map(|r| InsertTuple {
                row_id: r.row_id,
                key_raw: r.key_raw,
                cols_json: r.cols_json,
                deleted: 0,
            })
            .collect();
        // Insert under the LIVE name. On failure, bail before deleting.
        self.insert_tuples(old_physical, &rekeyed).await?;

        // Drop the prior live generation (everything older than this swap).
        // ON CLUSTER so the prior generation is purged on every shard (per-shard
        // table, NAN-1728); empty clause on single-node → identical DDL.
        let drop_sql = format!(
            "ALTER TABLE nanosiem.lookup_rows{on_cluster} DELETE \
             WHERE lookup_table_name = ? AND version < ?",
            on_cluster = on_cluster_clause()
        );
        self.ch
            .query(&drop_sql)
            .bind(old_physical)
            .bind(swap_version)
            .execute()
            .await
            .map_err(Self::ch_err)?;

        // Clean up the staging generation (best-effort; data is already live).
        let _ = self.drop_dynamic_table(staging_physical).await;
        Ok(())
    }

    // ---- Row data ----
    #[instrument(skip(self, columns, records))]
    async fn insert_records(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        records: &[HashMap<String, serde_json::Value>],
    ) -> Result<usize, LookupRepositoryError> {
        if records.is_empty() {
            return Ok(0);
        }
        // Encode the key from the registry PRIMARY KEY (not blindly the first
        // column) so `lookup_batch` — which queries by the primary key — can match
        // newly inserted rows on a non-first-PK table.
        let key_field = self.resolve_key_field(table_name, columns).await;
        let tuples: Vec<InsertTuple> = records
            .iter()
            .map(|rec| {
                let (key_raw, cols) = Self::encode_record(&key_field, columns, rec);
                InsertTuple {
                    row_id: snowflake::next_id(),
                    key_raw,
                    cols_json: serde_json::Value::Object(cols).to_string(),
                    deleted: 0,
                }
            })
            .collect();
        let n = tuples.len();
        self.insert_tuples(table_name, &tuples).await?;
        Ok(n)
    }

    #[instrument(skip(self))]
    async fn get_table_row_count(&self, table_name: &str) -> Result<i64, LookupRepositoryError> {
        // Return the CURRENT ClickHouse state, not the stale Postgres registry
        // `row_count`. The registry value never advances with online inserts/
        // deletes, so trusting it let the 1M-row cap check (and the stats the
        // service writes back) drift. The deduped live count
        // (argMax(deleted, version) = 0 per row_id) reflects inserts and
        // tombstones exactly. dedup is applied in `read_live_rows`, so this is
        // merge-state-independent.
        self.deduped_live_count(table_name).await
    }

    #[instrument(skip(self))]
    async fn get_table_size(&self, table_name: &str) -> Result<i64, LookupRepositoryError> {
        // Display-only estimate: apportion lookup_rows' on-disk bytes by this
        // table's share of the registry row_count. Never a full scan per edit.
        // TODO(NAN-1728): system.parts is read on the connected node only, so on
        // a cluster this reflects ONE shard's slice of lookup_rows (per-shard
        // table). Display-only, so left node-local for now; a cluster-accurate
        // figure would need `clusterAllReplicas(system.parts)` summed by shard.
        let active_bytes: i64 = {
            let mut cursor = self
                .ch
                .query(
                    "SELECT toString(sum(bytes_on_disk)) FROM system.parts \
                     WHERE database = 'nanosiem' AND table = 'lookup_rows' AND active",
                )
                .fetch_bytes("JSONEachRow")
                .map_err(Self::ch_err)?;
            let mut bytes = Vec::new();
            while let Some(chunk) = cursor.next().await.map_err(Self::ch_err)? {
                bytes.extend_from_slice(&chunk);
            }
            String::from_utf8_lossy(&bytes)
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .find_map(|v| {
                    v.as_object()
                        .and_then(|o| o.values().next().cloned())
                        .and_then(|x| x.as_str().and_then(|s| s.parse::<i64>().ok()))
                })
                .unwrap_or(0)
        };
        let tables = self.registry.list_tables().await?;
        let total_rows: i64 = tables.iter().map(|t| t.row_count.max(0)).sum();
        let this_rows = tables
            .iter()
            .find(|t| t.table_name == table_name)
            .map(|t| t.row_count.max(0))
            .unwrap_or(0);
        if total_rows == 0 {
            return Ok(0);
        }
        Ok(((active_bytes as i128 * this_rows as i128) / total_rows as i128) as i64)
    }

    #[instrument(skip(self))]
    async fn lookup(
        &self,
        table_name: &str,
        key_field: &str,
        key_value: &serde_json::Value,
        output_fields: Option<&[String]>,
        case_insensitive: bool,
    ) -> Result<Option<HashMap<String, serde_json::Value>>, LookupRepositoryError> {
        let results = self
            .lookup_batch(
                table_name,
                key_field,
                std::slice::from_ref(key_value),
                output_fields,
                case_insensitive,
            )
            .await?;
        Ok(results.into_values().next())
    }

    #[instrument(skip(self, key_values))]
    async fn lookup_batch(
        &self,
        table_name: &str,
        key_field: &str,
        key_values: &[serde_json::Value],
        output_fields: Option<&[String]>,
        case_insensitive: bool,
    ) -> Result<HashMap<String, HashMap<String, serde_json::Value>>, LookupRepositoryError> {
        if key_values.is_empty() {
            return Ok(HashMap::new());
        }
        let columns = self.registry.get_columns_for_physical(table_name).await?;
        // The stored key columns (key_raw/key_lc) hold the FIRST registry
        // column's value. Only push the indexed `key_lc/key_raw IN (...)` filter
        // down to ClickHouse when the requested key matches that column;
        // otherwise read all live rows and filter in Rust on the decoded field
        // (correct, unindexed) — see the KNOWN LIMITATION in the module header.
        let stored_key = columns.first().map(|c| c.name.as_str()).unwrap_or("");
        let pushdown = key_field == stored_key;

        let rows = if pushdown {
            self.read_live_rows(table_name, Some(key_values), case_insensitive)
                .await?
        } else {
            self.read_live_rows(table_name, None, false).await?
        };

        // Wanted set of key strings for keying + the non-pushdown Rust filter.
        let wanted: Vec<String> = key_values
            .iter()
            .map(|v| {
                let s = Self::key_to_string(v);
                if case_insensitive { s.to_lowercase() } else { s }
            })
            .collect();

        let mut out = HashMap::new();
        for r in &rows {
            let decoded = Self::decode_row(r, key_field, &columns, output_fields);
            // The lookup value of the requested key field, normalized for matching.
            let cmp_val = decoded
                .get(key_field)
                .map(|v| {
                    let s = ClickHouseLookupRepository::key_to_string(v);
                    if case_insensitive { s.to_lowercase() } else { s }
                })
                .unwrap_or_default();
            if !pushdown && !wanted.iter().any(|w| *w == cmp_val) {
                continue;
            }
            // Key the result map by the raw lookup value, matching the Postgres
            // path which keys on the raw matched key string.
            let map_key = ClickHouseLookupRepository::key_to_string(
                decoded.get(key_field).unwrap_or(&serde_json::Value::Null),
            );
            out.insert(map_key, decoded);
        }
        Ok(out)
    }

    #[instrument(skip(self))]
    async fn sample_rows(
        &self,
        table_name: &str,
        limit: i64,
    ) -> Result<Vec<HashMap<String, serde_json::Value>>, LookupRepositoryError> {
        let columns = self.registry.get_columns_for_physical(table_name).await?;
        let key_field = columns.first().map(|c| c.name.clone()).unwrap_or_default();
        let rows = self.read_live_rows(table_name, None, false).await?;
        Ok(rows
            .iter()
            .take(limit.clamp(0, 100) as usize)
            .map(|r| Self::decode_row(r, &key_field, &columns, None))
            .collect())
    }

    #[instrument(skip(self))]
    async fn list_rows(
        &self,
        table_name: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<HashMap<String, serde_json::Value>>, i64), LookupRepositoryError> {
        let columns = self.registry.get_columns_for_physical(table_name).await?;
        let key_field = columns.first().map(|c| c.name.clone()).unwrap_or_default();
        let mut rows = self.read_live_rows(table_name, None, false).await?;
        // Stable order by the immutable surrogate, matching the PG `_row_id` order.
        rows.sort_by_key(|r| r.row_id);
        let total = rows.len() as i64;
        let page: Vec<HashMap<String, serde_json::Value>> = rows
            .iter()
            .skip(offset.max(0) as usize)
            .take(limit.max(0) as usize)
            .map(|r| {
                let mut m = Self::decode_row(r, &key_field, &columns, None);
                // Expose the surrogate as `_row_id` so edit/delete targeting works,
                // matching the Postgres list_rows contract.
                m.insert(
                    "_row_id".to_string(),
                    serde_json::Value::Number(r.row_id.into()),
                );
                m
            })
            .collect();
        Ok((page, total))
    }

    #[instrument(skip(self, columns, record))]
    async fn insert_row(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        record: &HashMap<String, serde_json::Value>,
    ) -> Result<i64, LookupRepositoryError> {
        let key_field = self.resolve_key_field(table_name, columns).await;
        let (key_raw, cols) = Self::encode_record(&key_field, columns, record);
        let row_id = snowflake::next_id();
        self.insert_tuples(
            table_name,
            &[InsertTuple {
                row_id,
                key_raw,
                cols_json: serde_json::Value::Object(cols).to_string(),
                deleted: 0,
            }],
        )
        .await?;
        Ok(row_id as i64)
    }

    #[instrument(skip(self, columns, record))]
    async fn update_row(
        &self,
        table_name: &str,
        row_id: i64,
        columns: &[LookupColumn],
        record: &HashMap<String, serde_json::Value>,
    ) -> Result<(), LookupRepositoryError> {
        // Insert-on-top with the SAME row_id at a fresh version, recomputed
        // key_lc + updated cols_json. Key-mutation-safe because dedup keys on
        // row_id, not on the key cell.
        let key_field = self.resolve_key_field(table_name, columns).await;
        let (key_raw, cols) = Self::encode_record(&key_field, columns, record);
        self.insert_tuples(
            table_name,
            &[InsertTuple {
                row_id: row_id as u64,
                key_raw,
                cols_json: serde_json::Value::Object(cols).to_string(),
                deleted: 0,
            }],
        )
        .await
    }

    #[instrument(skip(self))]
    async fn delete_row(&self, table_name: &str, row_id: i64) -> Result<(), LookupRepositoryError> {
        // Tombstone: same row_id, deleted = 1, fresh version. No need to read the
        // old key.
        self.insert_tuples(
            table_name,
            &[InsertTuple {
                row_id: row_id as u64,
                key_raw: String::new(),
                cols_json: "{}".to_string(),
                deleted: 1,
            }],
        )
        .await
    }

    #[instrument(skip(self, row_ids))]
    async fn delete_rows(
        &self,
        table_name: &str,
        row_ids: &[i64],
    ) -> Result<u64, LookupRepositoryError> {
        if row_ids.is_empty() {
            return Ok(0);
        }
        let tombstones: Vec<InsertTuple> = row_ids
            .iter()
            .map(|&id| InsertTuple {
                row_id: id as u64,
                key_raw: String::new(),
                cols_json: "{}".to_string(),
                deleted: 1,
            })
            .collect();
        let n = tombstones.len() as u64;
        self.insert_tuples(table_name, &tombstones).await?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deduped_read_sql_has_argmax_groupby_and_deleted_filter() {
        let sql = ClickHouseLookupRepository::deduped_read_sql("row_id, key_raw, cols_json", None);
        assert!(sql.contains("argMax(key_raw, version)"), "{sql}");
        assert!(sql.contains("argMax(cols_json, version)"), "{sql}");
        assert!(sql.contains("argMax(deleted, version) AS d"), "{sql}");
        assert!(sql.contains("GROUP BY row_id"), "{sql}");
        assert!(sql.contains("WHERE lookup_table_name = ?"), "{sql}");
        assert!(sql.contains("WHERE d = 0"), "{sql}");
        // No FINAL — dedup is via argMax/GROUP BY.
        assert!(!sql.to_uppercase().contains("FINAL"), "{sql}");
    }

    #[test]
    fn deduped_read_sql_appends_key_lc_in_filter() {
        let sql = ClickHouseLookupRepository::deduped_read_sql(
            "row_id, key_raw, cols_json",
            Some("key_lc IN ('a', 'b')"),
        );
        assert!(sql.contains("WHERE d = 0 AND key_lc IN ('a', 'b')"), "{sql}");
    }

    #[test]
    fn deduped_read_sql_appends_key_raw_in_filter() {
        let sql = ClickHouseLookupRepository::deduped_read_sql(
            "row_id, key_raw, cols_json",
            Some("key_raw IN ('A', 'B')"),
        );
        assert!(sql.contains("WHERE d = 0 AND key_raw IN ('A', 'B')"), "{sql}");
    }

    #[test]
    fn encode_record_splits_key_and_cols() {
        let cols = vec![
            LookupColumn::text("host", false),
            LookupColumn::text("owner", true),
            LookupColumn::integer("risk", true),
        ];
        let mut rec = HashMap::new();
        rec.insert("host".to_string(), serde_json::json!("WS01"));
        rec.insert("owner".to_string(), serde_json::json!("alice"));
        rec.insert("risk".to_string(), serde_json::json!(7));
        let (key_raw, cols_json) =
            ClickHouseLookupRepository::encode_record("host", &cols, &rec);
        assert_eq!(key_raw, "WS01");
        // Key field is NOT duplicated into cols_json.
        assert!(!cols_json.contains_key("host"));
        assert_eq!(cols_json.get("owner"), Some(&serde_json::json!("alice")));
        assert_eq!(cols_json.get("risk"), Some(&serde_json::json!(7)));
    }

    /// P1-d: when the registry PRIMARY KEY is NOT the first column, encoding must
    /// key on the PK column (so `lookup_batch`, which queries by the PK, matches
    /// the inserted row). The online write paths resolve the PK via
    /// `resolve_key_field` and thread it here, mirroring `insert_backfill_rows`.
    #[test]
    fn encode_record_keys_on_non_first_primary_key() {
        let cols = vec![
            LookupColumn::text("host", false),
            LookupColumn::text("owner", true),
            LookupColumn::integer("risk", true),
        ];
        let mut rec = HashMap::new();
        rec.insert("host".to_string(), serde_json::json!("WS01"));
        rec.insert("owner".to_string(), serde_json::json!("alice"));
        rec.insert("risk".to_string(), serde_json::json!(7));
        // PK is the SECOND column (`owner`), not the first (`host`).
        let (key_raw, cols_json) =
            ClickHouseLookupRepository::encode_record("owner", &cols, &rec);
        // key_raw carries the PK value, and key_lc (derived at insert) lowercases
        // it — this is the value `lookup_batch`'s `key_lc IN (...)` filter probes.
        assert_eq!(key_raw, "alice");
        assert_eq!(key_raw.to_lowercase(), "alice");
        // The PK is excluded from cols_json; the non-PK first column round-trips.
        assert!(!cols_json.contains_key("owner"));
        assert_eq!(cols_json.get("host"), Some(&serde_json::json!("WS01")));
        assert_eq!(cols_json.get("risk"), Some(&serde_json::json!(7)));
    }

    #[test]
    fn decode_row_reconstructs_key_and_null_fills() {
        let cols = vec![
            LookupColumn::text("host", false),
            LookupColumn::text("owner", true),
            LookupColumn::integer("risk", true),
        ];
        let live = LiveRow {
            row_id: 42,
            key_raw: "WS01".to_string(),
            cols_json: r#"{"owner":"alice"}"#.to_string(),
        };
        let decoded = ClickHouseLookupRepository::decode_row(&live, "host", &cols, None);
        assert_eq!(decoded.get("host"), Some(&serde_json::json!("WS01")));
        assert_eq!(decoded.get("owner"), Some(&serde_json::json!("alice")));
        // Missing non-key column null-fills.
        assert_eq!(decoded.get("risk"), Some(&serde_json::Value::Null));
    }
}
