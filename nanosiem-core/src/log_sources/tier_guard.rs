// SPDX-License-Identifier: AGPL-3.0-or-later

//! The data-source tier cap, in one place (NAN-2202).
//!
//! This guard used to live as a private helper inside `POST /api/log-sources`.
//! That handler is not the only thing that creates an active log source:
//! collector stream provisioning and repository parser import both
//! `INSERT ... lifecycle_status = 'active'` directly against the table, so the
//! cap was enforced on the path the UI happened to use and bypassed on the two
//! that write straight through. A tenant already at their limit could create
//! *and* activate a working feed by enabling a collector stream.
//!
//! Enforcement therefore belongs next to the INSERT, not next to the HTTP
//! route. Every caller that creates a non-draft log source calls this first.

use sqlx::PgPool;

use crate::settings::tier::{check_limit, OrganizationTier, TierError, TierSettings};

/// The data-source cap in effect, read once.
///
/// Split from the count so a caller inside a transaction can read the cap
/// BEFORE opening it. Reading tier settings borrows a second pooled connection;
/// doing that while holding an open transaction is how a small pool deadlocks —
/// the transaction will not release its connection until it commits, and the
/// commit is waiting on a connection that will never be free.
pub struct DataSourceCap {
    max: Option<u32>,
    tier: OrganizationTier,
    enforced: bool,
}

/// Read the tier's data-source cap. Do this before opening a transaction.
pub async fn data_source_cap(pool: &PgPool) -> Result<DataSourceCap, TierError> {
    let limits = TierSettings::new(pool.clone()).get_tier_limits().await?;
    Ok(DataSourceCap {
        max: limits.max_data_sources,
        tier: limits.tier,
        enforced: limits.is_enforced(),
    })
}

impl DataSourceCap {
    /// Count the tenant's real (non-draft) sources and refuse if that is already
    /// at the cap.
    ///
    /// `count_on` is an executor rather than the pool so a caller already inside
    /// a transaction can pass `&mut *tx` and have the check and the INSERT share
    /// it. `ensure_raw_collector_log_source` does exactly that, inside its
    /// per-source-type advisory lock, which stops two concurrent provisions of
    /// the same stream from both reading "one slot left" and both inserting.
    /// Callers with nothing to serialize against pass the pool and keep the
    /// best-effort semantics the HTTP handler always had.
    ///
    /// Fails CLOSED: a database error propagates rather than counting 0 and
    /// silently waving the create past the cap.
    pub async fn enforce<'c, E>(&self, count_on: E) -> Result<(), TierError>
    where
        E: sqlx::Executor<'c, Database = sqlx::Postgres>,
    {
        if !self.enforced {
            return Ok(());
        }

        // COUNT rather than list-and-filter: the caller needs a number, and
        // listing materializes every column of every source — parser VRL blobs
        // included — only to throw all of it away. `lifecycle_status` is
        // `TEXT NOT NULL DEFAULT 'active'` (migration 258), so `<> 'draft'` has
        // no NULL case to account for.
        let (source_count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM log_sources WHERE lifecycle_status <> 'draft'")
                .fetch_one(count_on)
                .await?;

        check_limit(
            "data sources",
            source_count as u32,
            self.max,
            self.tier,
            "Upgrade to Starter for unlimited data sources.",
        )
    }
}

/// Read the cap and enforce it on the same pool.
///
/// The form for callers that are not inside a transaction. Drafts are exempt
/// (NAN-1920): a feed consumes a slot only once it is real, so this runs at
/// non-draft create and again at the draft→active deploy transition.
pub async fn enforce_data_source_limit(pool: &PgPool) -> Result<(), TierError> {
    data_source_cap(pool).await?.enforce(pool).await
}
