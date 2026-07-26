// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transactional generation used by privilege-grant writers (NAN-2134).

use sqlx::PgConnection;

/// Database generation observed by an authoritative privilege-grant check.
///
/// The value is intentionally opaque outside this module. Writers must lock
/// and compare it in the transaction that performs the grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantAuthorityStamp(i64);

impl GrantAuthorityStamp {
    pub fn new(version: i64) -> Self {
        Self(version)
    }
}

/// Lock the singleton authority row and report whether `expected` is still the
/// current generation. The row lock is held until the caller's transaction
/// commits or rolls back, so entitlement-changing triggers cannot advance it
/// between this check and the protected write.
pub async fn lock_and_verify_grant_authority(
    conn: &mut PgConnection,
    expected: GrantAuthorityStamp,
) -> Result<bool, sqlx::Error> {
    let current: i64 = sqlx::query_scalar(
        "SELECT version FROM grant_authority_version WHERE singleton = TRUE FOR UPDATE",
    )
    .fetch_one(conn)
    .await?;
    Ok(current == expected.0)
}
