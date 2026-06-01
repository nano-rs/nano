// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity resolution SQL generation
//!
//! Generates ASOF JOIN SQL for the `resolve_identity` command,
//! enriching events with resolved hostname/mac/user based on IP.

use super::helpers::*;
use super::ClickHouseSqlGenerator;
use crate::query::sql_gen::SqlGenError;
use std::collections::HashSet;

/// The 8 identity fields that have dedicated physical columns on the logs table.
/// (col_suffix, dict_field, default_value)
pub(crate) const IDENTITY_COLUMN_FIELDS: &[(&str, &str, &str)] = &[
    ("identity_department", "department", "''"),
    ("identity_title", "title", "''"),
    ("identity_groups", "groups", "''"),
    ("identity_account_status", "account_status", "''"),
    ("identity_employee_type", "employee_type", "''"),
    ("identity_mfa_enabled", "mfa_enabled", "toUInt8(0)"),
    ("identity_country", "country", "''"),
    ("identity_display_name", "display_name", "''"),
];

/// Identity fields only available via resolve_identity (no physical column).
/// Fields like phone and employee_id are in the PG table but not the CH dictionary,
/// so they are omitted here. They are still registered in udmfields.csv for future use.
/// (col_suffix, dict_field, default_value)
pub(crate) const IDENTITY_DICT_ONLY_FIELDS: &[(&str, &str, &str)] = &[
    ("identity_email", "email", "''"),
    ("identity_manager", "manager_display_name", "''"),
    ("identity_manager_upn", "manager_upn", "''"),
    ("identity_company", "company", "''"),
    ("identity_office_location", "office_location", "''"),
];

/// Map a resolve_identity field name to the entity prefix for output column naming.
/// e.g. field="user" → "user", field="dest_user" → "dest_user", field="src_ip" → "user"
pub(crate) fn resolve_identity_entity_prefix(field: &str) -> &'static str {
    match field {
        "user" => "user",
        "src_user" => "src_user",
        "dest_user" => "dest_user",
        // IP and hostname reverse lookups resolve to "user" entity
        _ => "user",
    }
}

/// Map a resolve_identity field name to the identity_observations column to JOIN on,
/// and whether this is a reverse lookup (user/hostname → IP).
pub(crate) fn resolve_identity_join_col(field: &str) -> (&'static str, bool) {
    match field {
        "user" | "dest_user" => ("user", true),
        "src_host" | "dest_host" => ("hostname", true),
        // All IP fields (src_ip, dest_ip, nat_ip, etc.) use the existing ip join
        _ => ("ip", false),
    }
}

/// Return the list of columns that resolve_identity should fill for a given field type.
pub(crate) fn resolve_identity_fill_targets(field: &str) -> Vec<&'static str> {
    match field {
        "user" | "dest_user" => vec!["src_host", "src_mac"],
        "src_host" | "dest_host" => vec!["src_mac", "user"],
        _ => vec!["src_host", "src_mac", "user"],
    }
}

impl ClickHouseSqlGenerator {
    /// Generate SQL for resolve_identity command using priority-aware ASOF JOIN
    ///
    /// Uses a CTE to pre-aggregate identity observations by IP and hour,
    /// selecting the highest-priority (and most recent within that priority)
    /// observation for each bucket, then ASOF JOINs against this.
    ///
    /// Priority levels:
    /// - 100: Static assets (user-defined, highest authority)
    /// - 80: DHCP sources (authoritative for IP assignment)
    /// - 50: EDR sources (observational)
    /// - 30: Other/default
    ///
    /// Supports bidirectional lookups:
    /// - IP fields (src_ip, dest_ip, *_ip): JOIN on i.ip → fill src_host, src_mac, user
    /// - User fields (user, dest_user): JOIN on i.user → fill src_ip (as identity_ip), src_host, src_mac
    /// - Hostname fields (src_host, dest_host): JOIN on i.hostname → fill src_ip (as identity_ip), src_mac, user
    ///
    /// Output includes:
    /// - Fill targets vary by lookup type (see above)
    /// - identity_confidence: high/medium/low/stale/none based on observation age
    /// - identity_observed_at: when the identity was observed
    /// - identity_source: which log source provided the identity
    /// - identity_fqdn: full FQDN if available
    /// - identity_ip: (reverse lookups only) the resolved IP address
    pub(super) fn generate_resolve_identity_sql(
        &self,
        source: &str,
        field: &str,
        max_age: &std::time::Duration,
        available_columns: &Option<HashSet<String>>,
    ) -> Result<String, SqlGenError> {
        let max_age_secs = max_age.as_secs();
        let field_escaped = escape_identifier(field);

        // Determine lookup type from field name
        let (join_col, is_reverse) = resolve_identity_join_col(field);

        // Check which fill-target columns exist in the source.
        // When a column-pruning command (table, fields keep) preceded us,
        // some columns may be absent — we can't reference or EXCEPT them.
        let has_col = |col: &str| -> bool {
            match available_columns {
                None => true, // No pruning — all columns available
                Some(set) => set.contains(col),
            }
        };

        // Determine which columns are fill targets based on lookup type
        let fill_targets = resolve_identity_fill_targets(field);

        // Build EXCEPT clause for columns we'll re-select explicitly.
        // Includes fill-target columns AND identity columns (to avoid duplicates
        // when forward user lookups read physical columns via main.*)
        let mut except_cols: Vec<String> = fill_targets
            .iter()
            .filter(|col| has_col(col))
            .map(|col| col.to_string())
            .collect();

        let is_forward_user = matches!(field, "user" | "src_user" | "dest_user");
        let entity_prefix = resolve_identity_entity_prefix(field);

        if is_forward_user {
            // Physical identity columns exist on the row — exclude them from main.*
            for (col_suffix, _, _) in IDENTITY_COLUMN_FIELDS.iter() {
                let col_name = format!("{}_{}", entity_prefix, col_suffix);
                if has_col(&col_name) {
                    except_cols.push(col_name);
                }
            }
        }

        let select_main = if except_cols.is_empty() {
            "main.*".to_string()
        } else {
            format!("main.* EXCEPT ({})", except_cols.join(", "))
        };

        // Build fill expressions for each target column
        let mut fill_exprs = Vec::new();

        for &target in &fill_targets {
            let identity_col = match target {
                "src_host" => "i.hostname",
                "src_mac" => "i.mac",
                "user" => "i.user",
                _ => continue,
            };
            let expr = if has_col(target) {
                format!(
                    "if(main.{t} = '' OR main.{t} IS NULL, coalesce({ic}, ''), main.{t}) AS {t}",
                    t = target,
                    ic = identity_col
                )
            } else {
                format!("coalesce({}, '') AS {}", identity_col, target)
            };
            fill_exprs.push(expr);
        }

        // For reverse lookups (user/hostname → IP), add identity_ip output
        if is_reverse {
            fill_exprs.push("i.ip AS identity_ip".to_string());
        }

        let fill_clause = fill_exprs.join(",\n    ");

        // Build identity enrichment lookups.
        //
        // For forward user lookups, the 8 dedicated physical columns already exist on the row
        // (populated at ingestion time), so we read them directly instead of re-querying the dict.
        // For reverse lookups (IP/hostname → user), the resolved user comes from the ASOF JOIN,
        // so we must use dictGetOrDefault.
        // Non-column fields (email, manager, etc.) always use dictGetOrDefault.
        let user_expr = if is_reverse {
            // user/hostname fields: the lookup key is directly on the event row
            format!("lower(main.{})", field_escaped)
        } else {
            // IP fields: the resolved user comes from identity_observations JOIN
            "lower(COALESCE(i.user, main.\"user\"))".to_string()
        };

        let mut dict_lookup_parts: Vec<String> = Vec::new();

        if is_forward_user {
            // Read dedicated columns directly from the row (already populated at ingestion)
            for (col_suffix, _dict_field, _default) in IDENTITY_COLUMN_FIELDS.iter() {
                dict_lookup_parts.push(format!(
                    "main.{prefix}_{suffix} AS {prefix}_{suffix}",
                    prefix = entity_prefix,
                    suffix = col_suffix,
                ));
            }
        } else {
            // Reverse/IP lookups: must use dictGetOrDefault since resolved user is from JOIN
            for (col_suffix, dict_field, default) in IDENTITY_COLUMN_FIELDS.iter() {
                dict_lookup_parts.push(format!(
                    "dictGetOrDefault('nanosiem.user_registry_dict', '{dict_field}', {user_key}, {default}) AS {prefix}_{suffix}",
                    dict_field = dict_field, user_key = user_expr, default = default,
                    prefix = entity_prefix, suffix = col_suffix,
                ));
            }
        }

        // Non-column fields always use dictGetOrDefault (not physical columns)
        for (col_suffix, dict_field, default) in IDENTITY_DICT_ONLY_FIELDS.iter() {
            dict_lookup_parts.push(format!(
                "dictGetOrDefault('nanosiem.user_registry_dict', '{dict_field}', {user_key}, {default}) AS {prefix}_{suffix}",
                dict_field = dict_field, user_key = user_expr, default = default,
                prefix = entity_prefix, suffix = col_suffix,
            ));
        }

        let dict_lookups = dict_lookup_parts.join(",\n    ");

        // ASOF equi-join key. For user/hostname (text) reverse lookups, lower() BOTH sides so a
        // mixed-case event identifier (e.g. Windows `JDoe`) matches the as-ingested observation
        // (`jdoe`) — the dict-key lookup above already lowercases, so the join must too or the
        // same field resolves inconsistently. IP joins stay raw equality (case-irrelevant, and
        // lowering would defeat the index).
        let asof_equi = if is_reverse {
            format!(
                "lower(main.{field}) = lower(i.{join_col})",
                field = field_escaped,
                join_col = join_col
            )
        } else {
            format!(
                "main.{field} = i.{join_col}",
                field = field_escaped,
                join_col = join_col
            )
        };

        Ok(format!(
            r#"  SELECT
    {select_main},
    {fill_clause},
    CASE
        WHEN i.observed_at IS NULL THEN 'none'
        WHEN i.observed_at > main.timestamp - INTERVAL 1 HOUR THEN 'high'
        WHEN i.observed_at > main.timestamp - INTERVAL 4 HOUR THEN 'medium'
        WHEN i.observed_at > main.timestamp - INTERVAL 24 HOUR THEN 'low'
        ELSE 'stale'
    END AS identity_confidence,
    i.observed_at AS identity_observed_at,
    i.source AS identity_source,
    coalesce(i.fqdn, '') AS identity_fqdn,
    {dict_lookups}
  FROM {source} AS main
  ASOF LEFT JOIN identity_observations AS i
    ON {asof_equi}
    AND main.timestamp >= i.observed_at
  WHERE i.observed_at IS NULL
     OR i.observed_at > main.timestamp - INTERVAL {max_age_secs} SECOND
  SETTINGS join_use_nulls = 1"#,
            select_main = select_main,
            fill_clause = fill_clause,
            dict_lookups = dict_lookups,
            asof_equi = asof_equi,
            source = source,
            max_age_secs = max_age_secs
        ))
    }
}
