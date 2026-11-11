// SPDX-License-Identifier: AGPL-3.0-or-later

//! Install identity (NAN-5249).
//!
//! A Self-run licence covers two installs: production plus one for dev, DR or
//! backup. nano-main counts the installs behind one licence (one deployment
//! ID) by this random ID, and sums their daily usage.
//!
//! Wire contract: the ID is sent as the `X-Nano-Install-Id` request header on
//! `GET /api/license/status` and `POST /api/license/usage`. It is a TypeID,
//! `inst_` followed by 26 Crockford base32 characters (a random UUID). A
//! control plane that does not know the header ignores it, so nothing else
//! about either request changes.
//!
//! The ID is stored once per PostgreSQL database (`install_identity`,
//! migration 327). Every app host of an HA cluster shares that database, so
//! a cluster is one install. The row is created by the migration, and
//! re-created here idempotently if it is ever missing.

use sqlx::PgPool;
use uuid::Uuid;

/// Request header carrying the install ID.
pub const INSTALL_ID_HEADER: &str = "X-Nano-Install-Id";
/// TypeID prefix of the install ID.
pub const INSTALL_ID_PREFIX: &str = "inst";

/// The wire form of an install ID: `inst_<26 base32 chars>`.
pub fn encode_install_id(id: &Uuid) -> String {
    crate::typeid::encode(INSTALL_ID_PREFIX, id)
}

/// Reads (and if needed creates) this install's ID.
#[derive(Clone)]
pub struct InstallIdentityRepository {
    pool: PgPool,
}

impl InstallIdentityRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// This install's ID in its wire form. Idempotent and safe to call from
    /// several hosts at once: the singleton primary key admits one row, and
    /// every caller reads back whichever row won.
    pub async fn get_or_create(&self) -> Result<String, sqlx::Error> {
        sqlx::query("INSERT INTO install_identity (id) VALUES (TRUE) ON CONFLICT (id) DO NOTHING")
            .execute(&self.pool)
            .await?;
        let id: Uuid =
            sqlx::query_scalar("SELECT install_id FROM install_identity WHERE id = TRUE")
                .fetch_one(&self.pool)
                .await?;
        Ok(encode_install_id(&id))
    }
}

#[cfg(test)]
#[path = "install_identity_tests.rs"]
mod tests;
