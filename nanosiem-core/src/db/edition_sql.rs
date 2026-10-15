// SPDX-License-Identifier: AGPL-3.0-or-later

//! Edition-specific SQL fragments (NAN-3462).
//!
//! NAN-2361 tenantized the detection/alert/search-share tables, but only under
//! the enterprise overlay migrations (9000073 / 9000084 / 9000230 …). Those
//! migrations add `tenant_id` and rebuild every unique key to lead with it. The
//! open fresh-init schema (`migrations/postgres-open/000_open_init.sql` plus the
//! core `migrations/postgres/` history) never gains the column, so it keeps the
//! pre-NAN-2361 keys: `detection_daily_stats (rule_id, date)`,
//! `detection_matches (rule_id, event_hash)`, and so on.
//!
//! The edition is fixed at compile time and the enterprise overlay always runs
//! in an enterprise build, so the `enterprise` Cargo feature is an exact proxy
//! for "the tenant column exists". This is the same rule as
//! `reports::repository::RUN_CONFLICT_TARGET` and
//! `system_health::repository::OUTBOX_CONFLICT_TARGET`.
//!
//! Use [`tenant_key!`](crate::tenant_key) inside `concat!` to build an
//! `ON CONFLICT` target that is correct in both editions, keeping the SQL a
//! `&'static str`:
//!
//! ```ignore
//! sqlx::query(concat!(
//!     "INSERT INTO detection_daily_stats (rule_id, date) VALUES ($1, $2) ",
//!     "ON CONFLICT (", nanosiem_core::tenant_key!(), "rule_id, date) DO NOTHING",
//! ))
//! ```
//!
//! `open_schema_sql_scan` (nanosiem-core/tests) expands the macro to its open
//! value when it checks open SQL against the open schema, so a conflict target
//! written without it fails that test.

/// Leading tenant column of a tenant-scoped unique key: `"tenant_id, "` in the
/// enterprise edition, `""` in the open edition. See the module docs.
#[cfg(feature = "enterprise")]
#[macro_export]
macro_rules! tenant_key {
    () => {
        "tenant_id, "
    };
}

/// Leading tenant column of a tenant-scoped unique key: `"tenant_id, "` in the
/// enterprise edition, `""` in the open edition. See the module docs.
#[cfg(not(feature = "enterprise"))]
#[macro_export]
macro_rules! tenant_key {
    () => {
        ""
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn tenant_key_matches_edition() {
        let target = concat!("ON CONFLICT (", crate::tenant_key!(), "rule_id, date)");
        if cfg!(feature = "enterprise") {
            assert_eq!(target, "ON CONFLICT (tenant_id, rule_id, date)");
        } else {
            assert_eq!(target, "ON CONFLICT (rule_id, date)");
        }
    }
}
