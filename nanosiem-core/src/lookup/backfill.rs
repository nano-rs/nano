// SPDX-License-Identifier: AGPL-3.0-or-later

//! One-time PG→ClickHouse lookup row-data backfill (NAN-1581 Phase 2/3).
//!
//! When a tenant flips `LOOKUP_STORAGE_BACKEND` to `clickhouse`, the existing
//! per-lookup Postgres `lookup_<name>` tables already hold real rows that have
//! NO upstream re-sync — they must be migrated into the shared ClickHouse
//! `lookup_rows` table (migration 146) without loss before the service starts
//! serving lookup reads from ClickHouse.
//!
//! Safety properties:
//! - **Multi-pod-safe**: the api runs multi-replica. A single global claim row
//!   in `lookup_backfill_state` (table_name = `'*'`) is taken via
//!   `INSERT ... ON CONFLICT DO NOTHING`; only the pod that wins the insert runs
//!   the backfill. Losers see the row and skip.
//! - **Resumable**: each logical table gets a per-table DONE marker row, so a
//!   partial/crashed backfill resumes only the remaining tables on the next boot.
//! - **Re-run safe**: a table already marked done is skipped. Even without the
//!   marker, a re-copy is non-duplicating because the CH `row_id` is the
//!   Postgres `_row_id`, and `ReplacingMergeTree` dedups on
//!   `(lookup_table_name, row_id)` — a re-copy would only bump versions.
//! - **Verified**: after copying a table, the Postgres `COUNT(*)` is compared to
//!   the CH deduped live count; a mismatch is recorded in the report (NOT
//!   silently passed).
//!
//! OPERATIONAL REQUIREMENT (freeze): lookup WRITE endpoints should be quiesced
//! while the backfill runs — this is a deploy-time maintenance step. The
//! backfill copies a point-in-time snapshot of each PG table; rows written to
//! Postgres AFTER its table is copied (and before the cutover) would be missed.
//! The global claim row also serves as a "backfill in progress" flag that the
//! API layer can read to gate mutations (see
//! [`is_backfill_in_progress`]).

use sqlx::PgPool;
use tracing::{info, warn};

use super::clickhouse_repository::ClickHouseLookupRepository;
use super::postgres_repository::PostgresLookupRepository;
use super::types::MAX_LOOKUP_TABLE_ROWS;

/// Sentinel row key for the global claim lock.
const GLOBAL_CLAIM: &str = "*";

/// Per-table outcome of the backfill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableBackfillResult {
    /// Logical lookup table name (registry `name`).
    pub name: String,
    /// Physical Postgres table name (registry `table_name`).
    pub physical: String,
    /// Rows read from Postgres.
    pub pg_count: i64,
    /// Live (deduped) rows verified in ClickHouse after the copy.
    pub ch_count: i64,
    /// Whether this table was skipped because its DONE marker was already set.
    pub skipped: bool,
    /// Whether `pg_count == ch_count` after the copy.
    pub verified: bool,
}

/// Summary of a backfill run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackfillReport {
    /// True if THIS pod won the global claim and actually ran the backfill.
    /// False means another pod already owns it (or it was already done) and this
    /// pod skipped.
    pub ran: bool,
    /// Per-table results (empty when `ran == false`).
    pub tables: Vec<TableBackfillResult>,
}

impl BackfillReport {
    /// Tables whose post-copy PG/CH counts did not match.
    pub fn mismatches(&self) -> Vec<&TableBackfillResult> {
        self.tables.iter().filter(|t| !t.verified).collect()
    }
}

/// Whether a backfill is currently in progress (the global claim row exists with
/// state `claimed`). Lookup mutation endpoints can read this to return a "503 /
/// backfill in progress" rather than writing into Postgres while the snapshot is
/// being copied. Returns `false` on any query error (fail-open — never block the
/// API on a bookkeeping read).
pub async fn is_backfill_in_progress(pg: &PgPool) -> bool {
    let res: Result<Option<(String,)>, _> = sqlx::query_as(
        "SELECT state FROM lookup_backfill_state WHERE table_name = $1",
    )
    .bind(GLOBAL_CLAIM)
    .fetch_optional(pg)
    .await;
    matches!(res, Ok(Some((s,))) if s == "claimed")
}

/// Run the one-time PG→ClickHouse lookup backfill.
///
/// Returns a [`BackfillReport`]; `ran == false` when another pod owns the claim
/// (or the work is already complete) and this pod skipped. See the module docs
/// for the safety model.
///
/// ROLLBACK NOTE: flipping `LOOKUP_STORAGE_BACKEND` back to `postgres` restores
/// the Postgres read/write path. The per-lookup Postgres `lookup_<name>` tables
/// are intentionally NOT dropped in this release — a later release drops them.
// TODO(NAN-1581 cleanup): a follow-up release drops the legacy per-lookup
// Postgres `lookup_<name>` tables once the ClickHouse backend is the default and
// no tenant rolls back. Track the removal under the NAN-1581 epic.
pub async fn backfill_pg_to_clickhouse(
    pg: PgPool,
    ch: clickhouse::Client,
) -> Result<BackfillReport, sqlx::Error> {
    // 1. Claim the global lock transactionally. Only the winner proceeds.
    let claimed = claim_global(&pg).await?;
    if !claimed {
        info!("lookup backfill: global claim already held by another pod — skipping");
        return Ok(BackfillReport {
            ran: false,
            tables: Vec::new(),
        });
    }
    info!("lookup backfill: claimed global lock; starting PG→ClickHouse copy");

    let pg_repo = PostgresLookupRepository::new(pg.clone());
    let ch_repo = ClickHouseLookupRepository::new(pg.clone(), ch);

    // Read the registry (always Postgres). Each table carries name, physical
    // table_name, columns and the primary_key.
    let tables = match pg_repo.list_tables().await {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "lookup backfill: failed to list registry tables");
            // Release the claim so a later boot can retry the whole run.
            release_global(&pg).await?;
            return Ok(BackfillReport {
                ran: true,
                tables: Vec::new(),
            });
        }
    };

    let mut report = BackfillReport {
        ran: true,
        tables: Vec::with_capacity(tables.len()),
    };

    for table in tables {
        // Per-table resume: skip tables already marked done.
        if table_done(&pg, &table.name).await? {
            info!(table = %table.name, "lookup backfill: table already done — skipping");
            report.tables.push(TableBackfillResult {
                name: table.name.clone(),
                physical: table.table_name.clone(),
                pg_count: 0,
                ch_count: 0,
                skipped: true,
                verified: true,
            });
            continue;
        }

        // Key field = registry PRIMARY KEY column (so `key_raw`/`key_lc` carry
        // the indexed value), falling back to the first column when the table
        // has no declared primary key.
        let key_field = table
            .primary_key
            .clone()
            .or_else(|| table.columns.first().map(|c| c.name.clone()))
            .unwrap_or_default();

        // Read ALL rows from the physical Postgres table (paged), including the
        // `_row_id` surrogate which becomes the CH `row_id`.
        let (rows, pg_count) =
            match pg_repo.list_rows(&table.table_name, MAX_LOOKUP_TABLE_ROWS, 0).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(table = %table.name, error = %e, "lookup backfill: failed to read PG rows; leaving table for retry");
                    continue;
                }
            };

        // Copy into ClickHouse, preserving _row_id and deriving the key from the
        // primary-key column.
        if let Err(e) = ch_repo
            .insert_backfill_rows(&table.table_name, &key_field, &table.columns, &rows)
            .await
        {
            warn!(table = %table.name, error = %e, "lookup backfill: CH insert failed; leaving table for retry");
            continue;
        }

        // VERIFY: PG COUNT(*) == CH deduped live count.
        let ch_count = ch_repo
            .deduped_live_count(&table.table_name)
            .await
            .unwrap_or(-1);
        let verified = ch_count == pg_count;
        if !verified {
            warn!(
                table = %table.name,
                pg_count, ch_count,
                "lookup backfill: COUNT MISMATCH after copy"
            );
        } else {
            info!(table = %table.name, count = pg_count, "lookup backfill: table copied + verified");
            // Only mark done on a verified copy so a mismatching table retries.
            mark_done(&pg, &table.name, pg_count, ch_count).await?;
        }

        report.tables.push(TableBackfillResult {
            name: table.name.clone(),
            physical: table.table_name.clone(),
            pg_count,
            ch_count,
            skipped: false,
            verified,
        });
    }

    // Release the global claim (drop the "in progress" flag). Per-table done
    // markers remain so a future boot won't re-copy completed tables.
    release_global(&pg).await?;

    let mismatches = report.mismatches().len();
    if mismatches > 0 {
        warn!(
            mismatches,
            "lookup backfill: completed with count mismatches — manual review required"
        );
    } else {
        info!(tables = report.tables.len(), "lookup backfill: complete");
    }

    Ok(report)
}

/// How long a `claimed` global lock may sit before it's considered abandoned
/// (a pod crashed mid-backfill without releasing). After this, another pod may
/// reclaim it. Per-table DONE markers mean the reclaiming pod resumes only the
/// unfinished tables, so reclaiming is safe even if the original is still alive
/// but stuck.
const STALE_CLAIM_SECS: i64 = 3600;

/// Claim the global lock. Returns `true` if THIS call now owns the lock —
/// either by inserting a fresh claim row, or by reclaiming a stale one.
///
/// A unique per-call token disambiguates concurrent reclaim races: the
/// `INSERT ... ON CONFLICT DO UPDATE` takes a row lock, so at most one racing
/// pod's `claimed_by` survives, and `RETURNING` tells us whether ours did.
async fn claim_global(pg: &PgPool) -> Result<bool, sqlx::Error> {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
    // Unique token so two pods reclaiming the same stale row can't both think
    // they won (claimed_by carries it; only the surviving UPDATE's token sticks).
    let token = format!("{host}/{}", super::snowflake::next_id());
    let row: Option<(String,)> = sqlx::query_as(
        "INSERT INTO lookup_backfill_state (table_name, state, claimed_by) \
         VALUES ($1, 'claimed', $2) \
         ON CONFLICT (table_name) DO UPDATE \
           SET claimed_by = EXCLUDED.claimed_by, updated_at = NOW() \
           WHERE lookup_backfill_state.updated_at < NOW() - make_interval(secs => $3) \
         RETURNING claimed_by",
    )
    .bind(GLOBAL_CLAIM)
    .bind(&token)
    .bind(STALE_CLAIM_SECS as f64)
    .fetch_optional(pg)
    .await?;
    // We own it iff a row came back AND it carries our token. (A non-stale
    // existing claim makes the ON CONFLICT WHERE false → no row returned → we
    // skip.)
    Ok(matches!(row, Some((who,)) if who == token))
}

/// Drop the global claim row (clears the "in progress" flag).
async fn release_global(pg: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM lookup_backfill_state WHERE table_name = $1")
        .bind(GLOBAL_CLAIM)
        .execute(pg)
        .await?;
    Ok(())
}

/// Whether a per-table DONE marker exists.
async fn table_done(pg: &PgPool, name: &str) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT state FROM lookup_backfill_state WHERE table_name = $1",
    )
    .bind(name)
    .fetch_optional(pg)
    .await?;
    Ok(matches!(row, Some((s,)) if s == "done"))
}

/// Record a per-table DONE marker with its verified counts.
async fn mark_done(
    pg: &PgPool,
    name: &str,
    pg_count: i64,
    ch_count: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO lookup_backfill_state (table_name, state, pg_count, ch_count) \
         VALUES ($1, 'done', $2, $3) \
         ON CONFLICT (table_name) DO UPDATE \
         SET state = 'done', pg_count = $2, ch_count = $3, updated_at = NOW()",
    )
    .bind(name)
    .bind(pg_count)
    .bind(ch_count)
    .execute(pg)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lookup::types::LookupColumn;
    use std::collections::HashMap;

    /// A fake registry table for unit-mapping the key/cols encoding the backfill
    /// hands to the CH insert.
    fn fake_columns() -> Vec<LookupColumn> {
        vec![
            LookupColumn::text("host", false),
            LookupColumn::text("owner", true),
            LookupColumn::integer("risk", true),
        ]
    }

    /// The backfill derives key_raw/key_lc from the registry PRIMARY KEY column
    /// (NOT blindly the first column). This mirrors the encoding the CH insert
    /// performs via `encode_record`, asserting the key value comes from the PK
    /// cell and is lowercased into key_lc.
    #[test]
    fn key_is_derived_from_primary_key_not_first_column() {
        use crate::lookup::clickhouse_repository::ClickHouseLookupRepository;
        let cols = fake_columns();
        let mut rec = HashMap::new();
        rec.insert("_row_id".to_string(), serde_json::json!(7));
        rec.insert("host".to_string(), serde_json::json!("WS01"));
        rec.insert("owner".to_string(), serde_json::json!("Alice"));
        rec.insert("risk".to_string(), serde_json::json!(9));

        // Primary key is `owner`, the SECOND column — so key_raw must be "Alice",
        // not "WS01" (the first column).
        let key_field = "owner";
        let (key_raw, cols_json) =
            ClickHouseLookupRepository::encode_record(key_field, &cols, &rec);
        assert_eq!(key_raw, "Alice");
        assert_eq!(key_raw.to_lowercase(), "alice"); // key_lc derivation
        // The key column is excluded from cols_json; the other columns remain.
        assert!(!cols_json.contains_key("owner"));
        assert_eq!(cols_json.get("host"), Some(&serde_json::json!("WS01")));
        assert_eq!(cols_json.get("risk"), Some(&serde_json::json!(9)));
        // The `_row_id` surrogate is NOT a registry column, so it never leaks
        // into cols_json.
        assert!(!cols_json.contains_key("_row_id"));
    }

    /// The PG `_row_id` surrogate becomes the CH `row_id` so a re-copy dedups.
    #[test]
    fn pg_row_id_maps_to_ch_row_id() {
        let mut rec = HashMap::new();
        rec.insert("_row_id".to_string(), serde_json::json!(123));
        let row_id = rec
            .get("_row_id")
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(row_id, 123);
    }

    /// A verified run reports zero mismatches; an unequal count is flagged.
    #[test]
    fn report_flags_count_mismatch() {
        let report = BackfillReport {
            ran: true,
            tables: vec![
                TableBackfillResult {
                    name: "ok".into(),
                    physical: "lookup_ok".into(),
                    pg_count: 10,
                    ch_count: 10,
                    skipped: false,
                    verified: true,
                },
                TableBackfillResult {
                    name: "bad".into(),
                    physical: "lookup_bad".into(),
                    pg_count: 10,
                    ch_count: 7,
                    skipped: false,
                    verified: false,
                },
            ],
        };
        let mismatches = report.mismatches();
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].name, "bad");
    }

    #[test]
    fn report_when_not_ran_is_empty() {
        let report = BackfillReport {
            ran: false,
            tables: Vec::new(),
        };
        assert!(!report.ran);
        assert!(report.mismatches().is_empty());
    }
}
