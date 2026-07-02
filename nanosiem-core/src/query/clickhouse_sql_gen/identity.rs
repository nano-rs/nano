// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity resolution SQL generation
//!
//! Generates ASOF JOIN SQL for the `resolve_identity` command,
//! enriching events with resolved hostname/mac/user based on IP.

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
///
/// Classification is driven by the active profile's entity type so OCSF host/user
/// fields (e.g. `src_endpoint.hostname`, `actor.user.name`) route to the right
/// join key. For UDM the entity-type lookup reproduces the prior literal matches
/// exactly (`user`/`dest_user` → User, `src_host`/`dest_host` → Host), byte-identical.
pub(crate) fn resolve_identity_join_col(
    field: &str,
    profile: &dyn crate::schema::SchemaProfile,
) -> (&'static str, bool) {
    match field {
        // UDM literal fast-path — byte-identical to the prior behavior, including
        // the deliberate omission of `src_user` (forward-only) from the reverse set.
        "user" | "dest_user" => ("user", true),
        "src_host" | "dest_host" => ("hostname", true),
        _ => {
            // For OCSF (non-UDM schemas), classify the dotted field via the
            // profile's entity type so host/user reverse lookups route correctly.
            // UDM keeps the prior `_ => ("ip", false)` default verbatim, so e.g.
            // `src_user` / `user_name` stay forward-only exactly as before.
            if profile.id() != crate::schema::SchemaId::Udm {
                match profile.entity_type(field) {
                    Some(crate::schema::EntityType::User) => return ("user", true),
                    Some(crate::schema::EntityType::Host) => return ("hostname", true),
                    _ => {}
                }
            }
            // All IP fields (src_ip, dest_ip, nat_ip, etc.) use the existing ip join
            ("ip", false)
        }
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
        // When the pipeline has exactly ONE resolve_identity, the bare
        // `identity_*` names are unambiguous — emit them as extra aliases of
        // the prefixed (`{entity}_identity_*`) canonical columns so a
        // downstream `| where identity_department = …` works without the
        // prefix (NAN-1346 #5). With two resolved entities the prefix stays
        // required. The prefixed columns match the materialized enrichment
        // columns and remain the canonical output.
        emit_bare_aliases: bool,
    ) -> Result<String, SqlGenError> {
        let max_age_secs = max_age.as_secs();
        // Resolve the lookup key through the active profile so OCSF reads its
        // promoted column; for UDM `field_access_expr` returns the escaped column
        // name verbatim (byte-identical to the prior `escape_identifier`).
        let field_escaped = self.field_access_expr(field, "String");

        // Determine lookup type from field name
        let (join_col, is_reverse) = resolve_identity_join_col(field, self.profile.as_ref());

        // Check which fill-target columns exist in the source.
        // When a column-pruning command (table, fields keep) preceded us,
        // some columns may be absent — we can't reference or EXCEPT them.
        //
        // NAN-1323: when there is no explicit pruning set, a column is present iff
        // the ACTIVE SCHEMA has a physical column literally named `col`. Under UDM
        // that holds for every UDM column (`resolve()` is the identity), so this is
        // byte-identical to the prior unconditional `true`. Under OCSF the
        // fill-target UDM aliases (`src_mac`, `user`) and the `user_identity_*`
        // columns are NOT physical columns (the physical ones are dotted /
        // `user.name`), so `main.* EXCEPT (src_mac, user)` and `main.src_mac` would
        // reference a column that does not exist in `ocsf_logs` → 500. Treating them
        // as absent makes the fill fall back to the ASOF-join value instead.
        let has_col = |col: &str| -> bool {
            match available_columns {
                Some(set) => set.contains(col),
                None => matches!(
                    self.profile.resolve(col),
                    crate::schema::FieldResolution::ExplicitColumn(ref c) if c == col
                ),
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
        // NAN-1323: the COALESCE fallback to the event's own user must reference the
        // active schema's physical user column. UDM resolves to `"user"` (byte-
        // identical `main."user"`); OCSF resolves to `"user.name"` so the IP-lookup
        // user key does not reference a nonexistent `user` column → 500.
        let main_user_col = match self.profile.resolve("user") {
            crate::schema::FieldResolution::ExplicitColumn(c) => crate::query::escape_identifier(&c),
            _ => "\"user\"".to_string(),
        };
        // `field_access_expr` returns a plain (possibly quoted) column for
        // promoted fields, but a JSONExtract EXPRESSION for unpromoted OCSF
        // tail fields — prefixing that with `main.` produces
        // `main.JSONExtractString(…)`, which ClickHouse rejects as an unknown
        // function (Code 46, NAN-1346 #5). An expression's inner column refs
        // (`event`) bind to `main` anyway: the joined `i` table carries none
        // of the event columns. UDM always yields a plain identifier, so the
        // qualified form is byte-identical there.
        let main_field = if field_escaped.contains('(') {
            field_escaped.clone()
        } else {
            format!("main.{}", field_escaped)
        };
        let user_expr = if is_reverse {
            // user/hostname fields: the lookup key is directly on the event row
            format!("lower({})", main_field)
        } else {
            // IP fields: the resolved user comes from identity_observations JOIN
            format!("lower(COALESCE(i.user, main.{}))", main_user_col)
        };

        let mut dict_lookup_parts: Vec<String> = Vec::new();

        // NAN-1323: the forward-user fast path reads the 8 dedicated `user_identity_*`
        // columns straight off the row — but those are materialized only on the UDM
        // `logs` table. Under OCSF (or a pruned UDM query that dropped them) they do
        // not exist, so reading `main.user_identity_*` would 500. Gate on the columns
        // actually being present; otherwise fall through to the dictGetOrDefault path,
        // which resolves the same values via the registry dict.
        let read_physical_identity = is_forward_user
            && has_col(&format!("{}_{}", entity_prefix, IDENTITY_COLUMN_FIELDS[0].0));

        if read_physical_identity {
            // Read dedicated columns directly from the row (already populated at ingestion)
            for (col_suffix, _dict_field, _default) in IDENTITY_COLUMN_FIELDS.iter() {
                dict_lookup_parts.push(format!(
                    "main.{prefix}_{suffix} AS {prefix}_{suffix}",
                    prefix = entity_prefix,
                    suffix = col_suffix,
                ));
                if emit_bare_aliases {
                    dict_lookup_parts.push(format!(
                        "main.{prefix}_{suffix} AS {suffix}",
                        prefix = entity_prefix,
                        suffix = col_suffix,
                    ));
                }
            }
        } else {
            // Reverse/IP lookups: must use dictGetOrDefault since resolved user is from JOIN
            for (col_suffix, dict_field, default) in IDENTITY_COLUMN_FIELDS.iter() {
                dict_lookup_parts.push(format!(
                    "dictGetOrDefault('nanosiem.user_registry_dict', '{dict_field}', {user_key}, {default}) AS {prefix}_{suffix}",
                    dict_field = dict_field, user_key = user_expr, default = default,
                    prefix = entity_prefix, suffix = col_suffix,
                ));
                if emit_bare_aliases {
                    dict_lookup_parts.push(format!(
                        "dictGetOrDefault('nanosiem.user_registry_dict', '{dict_field}', {user_key}, {default}) AS {suffix}",
                        dict_field = dict_field, user_key = user_expr, default = default,
                        suffix = col_suffix,
                    ));
                }
            }
        }

        // Non-column fields always use dictGetOrDefault (not physical columns)
        for (col_suffix, dict_field, default) in IDENTITY_DICT_ONLY_FIELDS.iter() {
            dict_lookup_parts.push(format!(
                "dictGetOrDefault('nanosiem.user_registry_dict', '{dict_field}', {user_key}, {default}) AS {prefix}_{suffix}",
                dict_field = dict_field, user_key = user_expr, default = default,
                prefix = entity_prefix, suffix = col_suffix,
            ));
            if emit_bare_aliases {
                dict_lookup_parts.push(format!(
                    "dictGetOrDefault('nanosiem.user_registry_dict', '{dict_field}', {user_key}, {default}) AS {suffix}",
                    dict_field = dict_field, user_key = user_expr, default = default,
                    suffix = col_suffix,
                ));
            }
        }

        let dict_lookups = dict_lookup_parts.join(",\n    ");

        // ASOF equi-join key. For user/hostname (text) reverse lookups, lower() BOTH sides so a
        // mixed-case event identifier (e.g. Windows `JDoe`) matches the as-ingested observation
        // (`jdoe`) — the dict-key lookup above already lowercases, so the join must too or the
        // same field resolves inconsistently. IP joins stay raw equality (case-irrelevant, and
        // lowering would defeat the index).
        let asof_equi = if is_reverse {
            format!(
                "lower({field}) = lower(i.{join_col})",
                field = main_field,
                join_col = join_col
            )
        } else {
            format!(
                "{field} = i.{join_col}",
                field = main_field,
                join_col = join_col
            )
        };

        // Bound the ASOF right/build side to the query window (NAN-1638). The
        // bare-table join materializes ALL of identity_observations (62.8M rows
        // on Saturn, incl. S3 cold-tier parts) into the hash build side —
        // MEMORY_LIMIT_EXCEEDED at the production 3GiB query cap in
        // FillingRightJoinSide; the max-age filter in the outer WHERE runs only
        // after the join. Any observation an in-window event can accept
        // satisfies `observed_at ∈ (event_ts − max_age, event_ts]` ⊆
        // `[query_start − max_age, query_end]`, so this bound never removes a
        // joinable observation. The one divergence class — an event whose
        // NEWEST observation ≤ its timestamp is older than the bound — comes
        // back as no-match → kept with identity_confidence 'none', where the
        // unbounded join matched the stale row and the outer WHERE silently
        // DROPPED the event, contradicting the 'none'/'stale' taxonomy above.
        //
        // Guards — keep the legacy unbounded join when:
        //  - a prior stage rewrote `timestamp` (`bin timestamp span=X`,
        //    `eval timestamp=…`, `rex (?<timestamp>…)`, `stats … as
        //    timestamp`, `table x as timestamp`, …): binned values precede
        //    the window start by up to one span, and computed ones move
        //    arbitrarily, so the window-derived bound could cut observations
        //    those rewritten timestamps still accept. Conservative choice
        //    over widening the bound by accumulated spans: spans can
        //    chain/alias through multiple stages, and computed rewrites are
        //    unboundable anyway. Registered rewriters surface through the
        //    upstream-computed set; bin/table escape it and are tracked by
        //    the dedicated flag (see `command_rewrites_timestamp`);
        //  - no generation time range is available (direct
        //    `generate_command_sql` callers, e.g. prevalence re-embedding);
        //  - the window-start − max_age subtraction over/underflows.
        let bounded_window = if self.is_upstream_timestamp_rewritten()
            || self.is_upstream_computed_field("timestamp")
        {
            None
        } else {
            match self.generation_time_range.read() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => (**poisoned.get_ref()).clone(),
            }
        };
        let build_side = bounded_window
            .and_then(|tr| {
                // try_seconds + checked_sub_signed: a crafted max_age (the
                // parser accepts up to u64::MAX seconds) must degrade to the
                // unbounded join, not panic codegen.
                let lower = i64::try_from(max_age_secs)
                    .ok()
                    .and_then(chrono::Duration::try_seconds)
                    .and_then(|d| tr.start.checked_sub_signed(d))?;
                Some(format!(
                    "(\n    SELECT * FROM identity_observations\n    WHERE observed_at BETWEEN '{}' AND '{}'\n  )",
                    crate::sql_hygiene::format_ch_bound_micros(&lower),
                    crate::sql_hygiene::format_ch_bound_micros(&tr.end)
                ))
            })
            .unwrap_or_else(|| "identity_observations".to_string());

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
  ASOF LEFT JOIN {build_side} AS i
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
            build_side = build_side,
            max_age_secs = max_age_secs
        ))
    }
}
