// SPDX-License-Identifier: AGPL-3.0-or-later

//! One monotonic revision for every tenant/table hot-tail visibility ledger.
//!
//! Writers bump this inside the same PostgreSQL transaction as a visibility
//! mutation. The signed-manifest publisher records the revision it observed,
//! allowing health checks to detect a frozen publisher without inferring
//! activity from event timestamps or retaining event data in PostgreSQL.

use anyhow::{Result, bail};
use sqlx::{PgConnection, Row};

fn validate_assignment(tenant_id: &str, table_location_prefix: &str) -> Result<()> {
    if tenant_id.is_empty()
        || tenant_id.len() > 512
        || tenant_id.chars().any(char::is_control)
        || !table_location_prefix.starts_with("s3://")
        || !table_location_prefix.ends_with('/')
        || table_location_prefix.len() > 2_048
    {
        bail!("hot-tail revision assignment is invalid");
    }
    Ok(())
}

pub async fn bump_hot_tail_revision(
    database: &mut PgConnection,
    tenant_id: &str,
    table_location_prefix: &str,
) -> Result<i64> {
    validate_assignment(tenant_id, table_location_prefix)?;
    let row = sqlx::query(
        r#"
        INSERT INTO lake_hot_tail_ledger_revisions (
            tenant_id, table_location_prefix, revision, updated_at
        ) VALUES ($1, $2, 1, clock_timestamp())
        ON CONFLICT (tenant_id, table_location_prefix) DO UPDATE SET
            revision = lake_hot_tail_ledger_revisions.revision + 1,
            updated_at = clock_timestamp()
        RETURNING revision
        "#,
    )
    .bind(tenant_id)
    .bind(table_location_prefix)
    .fetch_one(database)
    .await?;
    let revision: i64 = row.try_get("revision")?;
    if revision <= 0 {
        bail!("hot-tail ledger revision did not advance");
    }
    Ok(revision)
}

pub async fn load_hot_tail_revision(
    database: &mut PgConnection,
    tenant_id: &str,
    table_location_prefix: &str,
) -> Result<i64> {
    validate_assignment(tenant_id, table_location_prefix)?;
    Ok(sqlx::query_scalar(
        "SELECT revision FROM lake_hot_tail_ledger_revisions \
         WHERE tenant_id = $1 AND table_location_prefix = $2",
    )
    .bind(tenant_id)
    .bind(table_location_prefix)
    .fetch_optional(database)
    .await?
    .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_is_tenant_and_table_scoped() {
        assert!(validate_assignment("tenant-a", "s3://bucket/table/").is_ok());
        assert!(validate_assignment("", "s3://bucket/table/").is_err());
        assert!(validate_assignment("tenant-a", "s3://bucket/table").is_err());
        assert!(validate_assignment("tenant-a", "file:///tmp/table/").is_err());
    }
}

/// NAN-2361 wave 7: pin the table's current Iceberg metadata after a
/// tail-pack registration on the revision row (same transaction as the
/// revision bump) so a query side without catalog access (the hosted
/// `lake_otel_ingest`) reads committed rows from exactly what the compactor
/// committed. Idempotent for the same snapshot. Ordering between registrations
/// is the per-table compaction advisory lock, not this statement (Iceberg
/// snapshot ids are not ordered).
pub async fn pin_committed_table(
    database: &mut PgConnection,
    tenant_id: &str,
    table_location_prefix: &str,
    table_uuid: uuid::Uuid,
    metadata_location: &str,
    snapshot_id: i64,
) -> Result<()> {
    validate_assignment(tenant_id, table_location_prefix)?;
    if table_uuid.is_nil()
        || snapshot_id <= 0
        || !metadata_location.starts_with(&format!("{table_location_prefix}metadata/"))
        || metadata_location.contains("..")
        || metadata_location.len() > 2_048
        || metadata_location.chars().any(char::is_control)
    {
        bail!("committed table pin is outside its table location");
    }
    sqlx::query(
        "UPDATE lake_hot_tail_ledger_revisions \
            SET committed_table_uuid = $3, committed_metadata_location = $4, \
                committed_snapshot_id = $5, committed_at = clock_timestamp() \
          WHERE tenant_id = $1 AND table_location_prefix = $2 \
            AND (committed_snapshot_id IS NULL OR committed_table_uuid <> $3 OR committed_snapshot_id <> $5)",
    )
    .bind(tenant_id)
    .bind(table_location_prefix)
    .bind(table_uuid)
    .bind(metadata_location)
    .bind(snapshot_id)
    .execute(database)
    .await?;
    Ok(())
}

/// The committed-table pin, if any registration has happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedTablePin {
    pub table_uuid: uuid::Uuid,
    pub metadata_location: String,
    pub snapshot_id: i64,
}

pub async fn load_committed_table_pin<'e, E>(
    executor: E,
    tenant_id: &str,
    table_location_prefix: &str,
) -> Result<Option<CommittedTablePin>>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    validate_assignment(tenant_id, table_location_prefix)?;
    let row = sqlx::query(
        "SELECT committed_table_uuid, committed_metadata_location, committed_snapshot_id \
           FROM lake_hot_tail_ledger_revisions WHERE tenant_id = $1 AND table_location_prefix = $2",
    )
    .bind(tenant_id)
    .bind(table_location_prefix)
    .fetch_optional(executor)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let table_uuid: Option<uuid::Uuid> = row.try_get("committed_table_uuid")?;
    let metadata_location: Option<String> = row.try_get("committed_metadata_location")?;
    let snapshot_id: Option<i64> = row.try_get("committed_snapshot_id")?;
    match (table_uuid, metadata_location, snapshot_id) {
        (Some(table_uuid), Some(metadata_location), Some(snapshot_id)) if snapshot_id > 0 => {
            Ok(Some(CommittedTablePin { table_uuid, metadata_location, snapshot_id }))
        }
        _ => Ok(None),
    }
}

// -- NAN-2653: one hot-tail visibility rule for every serving pod -----------

/// The Iceberg snapshots a serving base already contains.
///
/// `complete` means the ids are the base snapshot's FULL parent chain (or the
/// zero-snapshot bootstrap generation's empty chain). A truncated list — the
/// pre-ancestry upgrade fallback `[base_snapshot_id]` — cannot prove that a
/// non-listed snapshot is newer than the base, so it never re-admits an
/// `'activated'` ledger row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingLineage {
    ancestor_snapshot_ids: Vec<i64>,
    complete: bool,
}

impl ServingLineage {
    pub fn complete(ancestor_snapshot_ids: Vec<i64>) -> Self {
        Self { ancestor_snapshot_ids, complete: true }
    }

    pub fn truncated(ancestor_snapshot_ids: Vec<i64>) -> Self {
        Self { ancestor_snapshot_ids, complete: false }
    }

    pub fn ancestor_snapshot_ids(&self) -> &[i64] {
        &self.ancestor_snapshot_ids
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    fn contains(&self, snapshot_id: i64) -> bool {
        self.ancestor_snapshot_ids.contains(&snapshot_id)
    }
}

/// Every hot-tail ledger row one serving base must add beside itself.
///
/// Binds: `$1` tenant, `$2` table location prefix, `$3` the base's ancestor
/// snapshot ids (`bigint[]`), `$4` whether that ancestry is complete.
/// Both the continuous tail publisher and the activation candidate tail use
/// this exact text, so the two cannot drift.
///
/// `'activated'` is a TENANT-WIDE flag: whichever pod activates generation
/// N+1 flips every row compacted into N+1's lineage. During a surge roll (or
/// on any lagging pod) another pod still serves N, which does not hold those
/// rows, so for visibility `'activated'` means the same as `'compacted'`
/// whenever the row's snapshot is NOT in this base's lineage — bounded so the
/// tail can never re-admit history the base already contains:
///
/// * `$4` — only a COMPLETE lineage can prove "not an ancestor" means "newer
///   than the base". The truncated upgrade fallback keeps the old exclusion.
/// * `physical_deleted_at IS NULL` — retention GC already removed the bytes;
///   publishing the row would sign a tail the worker cannot read.
/// * `activated_at >=` the newest flip of any row the lineage DOES cover.
///   Every flip covers the whole lineage of the generation it activates, so a
///   row of an older (listed or unlisted) ancestor is never flipped after a
///   row of a newer one; a gap in the list therefore cannot resurrect an
///   older activation, while a descendant's rows are flipped in the same or a
///   later statement. Flips are stamped with `statement_timestamp()` under
///   the tenant publication lock, so the order is the commit order.
///
/// Rows admitted this way were already in this pod's tail an instant earlier
/// (as `'compacted'` and not covered), so the rule never grows a tail beyond
/// what it served before the other pod's flip; the ledger audit prune and
/// tail GC bound the activated set tenant-wide.
pub const SELECT_VISIBLE_HOT_TAIL_OBJECTS_SQL: &str = "\
SELECT object_uri, version_id, object_etag, object_bytes, object_sha256, rows, \
       min_time_ms, max_time_ms, status \
FROM lake_hot_tail_objects \
WHERE tenant_id = $1 AND table_location_prefix = $2 \
  AND (status = 'staged' \
       OR (status = 'compacted' AND NOT (compaction_snapshot_id = ANY($3))) \
       OR (status = 'activated' AND $4::boolean \
           AND NOT (compaction_snapshot_id = ANY($3)) \
           AND physical_deleted_at IS NULL \
           AND activated_at >= COALESCE( \
               (SELECT max(covered.activated_at) FROM lake_hot_tail_objects AS covered \
                WHERE covered.tenant_id = $1 AND covered.table_location_prefix = $2 \
                  AND covered.status = 'activated' \
                  AND covered.compaction_snapshot_id = ANY($3)), \
               '-infinity'::timestamptz))) \
ORDER BY object_uri, version_id";

/// Flip every compacted row covered by a newly activated generation.
///
/// Binds: `$1` tenant, `$2` table location prefix, `$3` the activated
/// generation's ancestor snapshot ids.
///
/// `statement_timestamp()`, not `NOW()`: the caller opens its transaction
/// before it waits on the tenant publication lock, so a transaction-start
/// stamp could order a later flip before an earlier one and break the
/// covered-flip floor in [`SELECT_VISIBLE_HOT_TAIL_OBJECTS_SQL`].
pub const ACTIVATE_COVERED_HOT_TAIL_OBJECTS_SQL: &str = "\
UPDATE lake_hot_tail_objects SET status = 'activated', activated_at = statement_timestamp() \
WHERE tenant_id = $1 AND table_location_prefix = $2 AND status = 'compacted' \
  AND compaction_snapshot_id = ANY($3) RETURNING object_uri";

/// Load the rows [`SELECT_VISIBLE_HOT_TAIL_OBJECTS_SQL`] selects.
pub async fn load_visible_hot_tail_objects(
    database: &mut PgConnection,
    tenant_id: &str,
    table_location_prefix: &str,
    lineage: &ServingLineage,
) -> Result<Vec<sqlx::postgres::PgRow>> {
    Ok(sqlx::query(SELECT_VISIBLE_HOT_TAIL_OBJECTS_SQL)
        .bind(tenant_id)
        .bind(table_location_prefix)
        .bind(lineage.ancestor_snapshot_ids())
        .bind(lineage.is_complete())
        .fetch_all(database)
        .await?)
}

/// The ledger state [`hot_tail_row_is_visible`] decides on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotTailRowState<'a> {
    pub status: &'a str,
    pub compaction_snapshot_id: Option<i64>,
    /// Any value ordered like `activated_at` (tests use microseconds).
    pub activated_at: Option<i64>,
    pub physically_deleted: bool,
}

/// Pure mirror of [`SELECT_VISIBLE_HOT_TAIL_OBJECTS_SQL`].
///
/// `covered_activation_floor` is the newest `activated_at` among rows whose
/// snapshot IS in the lineage (`None` when there is none).
pub fn hot_tail_row_is_visible(
    row: HotTailRowState<'_>,
    lineage: &ServingLineage,
    covered_activation_floor: Option<i64>,
) -> bool {
    let uncovered = row
        .compaction_snapshot_id
        .is_some_and(|snapshot_id| !lineage.contains(snapshot_id));
    match row.status {
        "staged" => true,
        "compacted" => uncovered,
        "activated" => {
            uncovered
                && lineage.is_complete()
                && !row.physically_deleted
                && match (row.activated_at, covered_activation_floor) {
                    (Some(activated_at), Some(floor)) => activated_at >= floor,
                    (Some(_), None) => true,
                    (None, _) => false,
                }
        }
        _ => false,
    }
}

#[cfg(test)]
mod visibility_tests {
    use super::*;

    const OLD_BASE: i64 = 10;
    const NEW_BASE: i64 = 11;

    fn row(status: &str, snapshot: Option<i64>, activated_at: Option<i64>) -> HotTailRowState<'_> {
        HotTailRowState {
            status,
            compaction_snapshot_id: snapshot,
            activated_at,
            physically_deleted: false,
        }
    }

    #[test]
    fn a_serving_pod_keeps_rows_another_pod_activated_past_its_base() {
        // Surge roll: the old pod serves 10; the new pod activated 11 and the
        // tenant-wide flip moved 11's rows to 'activated'. 10 does not hold
        // them, so the old pod's tail must.
        let old = ServingLineage::complete(vec![OLD_BASE, 9]);
        let flipped = row("activated", Some(NEW_BASE), Some(200));
        assert!(hot_tail_row_is_visible(flipped, &old, Some(100)));
        // The same flip transaction also stamps any still-compacted rows of
        // the old lineage, so the floor can equal the new rows' stamp.
        assert!(hot_tail_row_is_visible(flipped, &old, Some(200)));
    }

    #[test]
    fn a_pod_whose_base_contains_the_snapshot_still_excludes_it() {
        let new = ServingLineage::complete(vec![NEW_BASE, OLD_BASE, 9]);
        assert!(!hot_tail_row_is_visible(row("activated", Some(NEW_BASE), Some(200)), &new, Some(200)));
        assert!(!hot_tail_row_is_visible(row("compacted", Some(NEW_BASE), None), &new, Some(200)));
    }

    #[test]
    fn compacted_staged_and_superseded_semantics_are_unchanged() {
        for lineage in [
            ServingLineage::complete(vec![OLD_BASE]),
            ServingLineage::truncated(vec![OLD_BASE]),
            ServingLineage::complete(Vec::new()),
        ] {
            assert!(hot_tail_row_is_visible(row("staged", None, None), &lineage, None));
            assert!(!hot_tail_row_is_visible(row("superseded", None, None), &lineage, None));
            assert!(hot_tail_row_is_visible(row("compacted", Some(NEW_BASE), None), &lineage, None));
        }
        let covering = ServingLineage::complete(vec![NEW_BASE]);
        assert!(!hot_tail_row_is_visible(row("compacted", Some(NEW_BASE), None), &covering, None));
    }

    #[test]
    fn a_truncated_lineage_never_resurrects_activated_rows() {
        // Upgrade fallback [base]: snapshot 5 may well be inside the base.
        let truncated = ServingLineage::truncated(vec![OLD_BASE]);
        assert!(!hot_tail_row_is_visible(row("activated", Some(5), Some(50)), &truncated, None));
        assert!(!hot_tail_row_is_visible(row("activated", Some(NEW_BASE), Some(200)), &truncated, Some(100)));
    }

    #[test]
    fn activations_older_than_the_covered_floor_stay_hidden() {
        // A gap in a lineage that claims completeness (e.g. an expired
        // ancestor) must not pull an old activation back into the tail: it
        // was flipped before the newest flip of the base's own lineage, and
        // every flip covers the whole lineage of the generation it activates.
        let gapped = ServingLineage::complete(vec![OLD_BASE]);
        assert!(!hot_tail_row_is_visible(row("activated", Some(7), Some(50)), &gapped, Some(100)));
    }

    #[test]
    fn physically_deleted_activated_rows_are_never_republished() {
        let old = ServingLineage::complete(vec![OLD_BASE]);
        let mut deleted = row("activated", Some(NEW_BASE), Some(200));
        deleted.physically_deleted = true;
        assert!(!hot_tail_row_is_visible(deleted, &old, Some(100)));
    }

    #[test]
    fn the_bootstrap_generation_keeps_rows_the_first_real_generation_activated() {
        let bootstrap = ServingLineage::complete(Vec::new());
        assert!(hot_tail_row_is_visible(row("activated", Some(NEW_BASE), Some(200)), &bootstrap, None));
    }

    const T: &str = "t";
    const P: &str = "s3://b/t/";

    /// A throwaway schema on a disposable PostgreSQL, shared by `sessions`
    /// connections. Never point `TEST_DATABASE_URL` at a shared database.
    async fn scratch_ledger(sessions: usize) -> (String, Vec<PgConnection>) {
        use sqlx::{Connection, Executor};
        let url = std::env::var("TEST_DATABASE_URL").expect("local test database required");
        let schema = format!("nan2653_{}", uuid::Uuid::new_v4().simple());
        let mut connections = Vec::new();
        for index in 0..sessions {
            let mut db = PgConnection::connect(&url).await.unwrap();
            if index == 0 {
                db.execute(format!("CREATE SCHEMA {schema}").as_str()).await.unwrap();
            }
            db.execute(format!("SET search_path TO {schema}").as_str()).await.unwrap();
            connections.push(db);
        }
        connections[0]
            .execute(
                "CREATE TABLE lake_hot_tail_objects ( \
                    tenant_id text NOT NULL, table_location_prefix text NOT NULL, \
                    object_uri text NOT NULL, version_id text NOT NULL, object_etag text, \
                    object_bytes bigint NOT NULL DEFAULT 1, object_sha256 text NOT NULL DEFAULT '', \
                    rows bigint NOT NULL DEFAULT 1, min_time_ms bigint NOT NULL DEFAULT 0, \
                    max_time_ms bigint NOT NULL DEFAULT 0, status text NOT NULL, \
                    compaction_snapshot_id bigint, compacted_at timestamptz, \
                    activated_at timestamptz, physical_deleted_at timestamptz)",
            )
            .await
            .unwrap();
        // ancient: compacted into 7 and activated long ago (a lineage gap
        // must not resurrect it); base: compacted into 10; next: compacted
        // into 11; live: still staged; foreign: another table.
        connections[0]
            .execute(
                "INSERT INTO lake_hot_tail_objects (tenant_id, table_location_prefix, object_uri, \
                    version_id, status, compaction_snapshot_id, compacted_at, activated_at) VALUES \
                 ('t','s3://b/t/','s3://b/t/data/tail/ancient','v','activated',7,NOW()-INTERVAL '2 hours',NOW()-INTERVAL '1 hour'), \
                 ('t','s3://b/t/','s3://b/t/data/tail/base','v','compacted',10,NOW(),NULL), \
                 ('t','s3://b/t/','s3://b/t/data/tail/next','v','compacted',11,NOW(),NULL), \
                 ('t','s3://b/t/','s3://b/t/data/tail/live','v','staged',NULL,NULL,NULL), \
                 ('t','s3://b/other/','s3://b/other/data/tail/foreign','v','staged',NULL,NULL,NULL)",
            )
            .await
            .unwrap();
        (schema, connections)
    }

    async fn drop_scratch_ledger(db: &mut PgConnection, schema: &str) {
        use sqlx::Executor;
        db.execute(format!("DROP SCHEMA {schema} CASCADE").as_str()).await.unwrap();
    }

    async fn visible(db: &mut PgConnection, lineage: &ServingLineage) -> Vec<String> {
        load_visible_hot_tail_objects(db, T, P, lineage)
            .await
            .unwrap()
            .iter()
            .map(|row| {
                let uri: String = row.try_get("object_uri").unwrap();
                uri.rsplit('/').next().unwrap().to_string()
            })
            .collect()
    }

    async fn flip(db: &mut PgConnection, ancestors: &[i64]) {
        sqlx::query(ACTIVATE_COVERED_HOT_TAIL_OBJECTS_SQL)
            .bind(T)
            .bind(P)
            .bind(ancestors)
            .fetch_all(db)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an explicitly assigned local TEST_DATABASE_URL"]
    async fn sql_visibility_survives_a_surge_roll_activation() {
        use sqlx::Executor;
        let (schema, mut connections) = scratch_ledger(1).await;
        let db = &mut connections[0];
        let old = ServingLineage::complete(vec![10, 9]);
        let new = ServingLineage::complete(vec![11, 10, 9]);

        // The old pod activates its own base 10.
        flip(db, &[10, 9]).await;
        assert_eq!(visible(db, &old).await, vec!["live", "next"]);
        // The new pod activates 11 while the old pod still serves 10.
        flip(db, &[11, 10, 9]).await;
        assert_eq!(
            visible(db, &old).await,
            vec!["live", "next"],
            "the old pod must keep rows its base does not contain"
        );
        assert_eq!(visible(db, &new).await, vec!["live"]);
        // Truncated upgrade ancestry keeps the pre-NAN-2653 exclusion.
        assert_eq!(visible(db, &ServingLineage::truncated(vec![10])).await, vec!["live"]);
        // A gap in a claimed-complete lineage never resurrects `ancient`.
        assert_eq!(
            visible(db, &ServingLineage::complete(vec![10])).await,
            vec!["live", "next"]
        );
        // Once GC has physically deleted `next`, nobody may publish it.
        db.execute(
            "UPDATE lake_hot_tail_objects SET physical_deleted_at = NOW() \
             WHERE object_uri LIKE '%/next'",
        )
        .await
        .unwrap();
        assert_eq!(visible(db, &old).await, vec!["live"]);
        drop_scratch_ledger(db, &schema).await;
    }

    #[tokio::test]
    #[ignore = "requires an explicitly assigned local TEST_DATABASE_URL"]
    async fn sql_visibility_orders_flips_by_commit_not_transaction_start() {
        // acknowledge_generation opens its transaction BEFORE it waits on the
        // tenant publication lock. If the new pod's transaction started
        // first but flips second, a transaction-start stamp would place 11's
        // rows before 10's and the covered floor would hide them.
        use sqlx::{Connection, Executor};
        let (schema, mut connections) = scratch_ledger(2).await;
        let (first, rest) = connections.split_at_mut(1);
        let (old_pod, new_pod) = (&mut first[0], &mut rest[0]);
        let mut late = new_pod.begin().await.unwrap();
        (&mut *late).execute("SELECT 1").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut early = old_pod.begin().await.unwrap();
        flip(&mut *early, &[10, 9]).await;
        early.commit().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        flip(&mut *late, &[11, 10, 9]).await;
        late.commit().await.unwrap();
        assert_eq!(
            visible(old_pod, &ServingLineage::complete(vec![10, 9])).await,
            vec!["live", "next"]
        );
        drop_scratch_ledger(old_pod, &schema).await;
    }
}
