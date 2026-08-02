// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command SQL generation
//!
//! Contains `generate_command_sql_inner` with its match statement dispatching
//! to simple inline arms and complex helper methods in `commands_advanced`.

use super::eval_functions::eval_expression_to_sql;
use super::helpers::*;
use super::{ClickHouseSqlGenerator, SourceStability};
use crate::query::ast::*;
use crate::query::sql_gen::SqlGenError;
use std::collections::HashSet;

impl ClickHouseSqlGenerator {
    pub(super) fn generate_command_sql_inner(
        &self,
        source: &str,
        cmd: &Command,
        available_columns: &mut Option<HashSet<String>>,
        sparkline_span_secs: Option<u64>,
        has_prior_risk: bool,
        // True if an earlier aggregating command dropped the raw `timestamp` column.
        // tail/reverse use this to avoid `ORDER BY timestamp` (which would be Code 47).
        aggregated: bool,
        // True when the pipeline has exactly one resolve_identity — the stage
        // then also emits bare `identity_*` aliases (NAN-1346 #5).
        single_resolve_identity: bool,
        // What re-executing `source` is guaranteed to yield — gates every
        // rewrite that references the source CTE more than once: the sort-free
        // dedup rewrite (NAN-1636, corrected by NAN-2264) and the eventstats /
        // anomaly map-scalar attach (NAN-2265).
        stability: SourceStability,
    ) -> Result<String, SqlGenError> {
        // Whether the raw time column still exists at this pipeline stage:
        // false after an aggregating command (stats/timechart/top/...) or after a
        // table/fields projection that dropped it. tail/reverse branch on this.
        // O27 (NAN-1721): key on the active dataset's time column (`start_time`
        // for spans), not the literal `timestamp` — which does not exist on
        // `otel_spans`, so a bare `dataset=spans * | tail 5` errored. Logs keep
        // `timestamp` byte-identical.
        let timestamp_available = !aggregated
            && match available_columns {
                None => true,
                Some(cols) => cols.contains(self.time_column()),
            };
        match cmd {
            Command::Stats {
                aggregations,
                group_by,
            } => self.generate_stats_sql(
                source,
                aggregations,
                group_by.as_deref(),
                sparkline_span_secs,
            ),
            Command::Chart {
                aggregations,
                group_by,
            } => {
                // Chart is just an alias for stats
                self.generate_stats_sql(
                    source,
                    aggregations,
                    group_by.as_deref(),
                    sparkline_span_secs,
                )
            }
            Command::Where { condition } => {
                let where_clause = self.generate_where_condition(condition)?;
                Ok(format!(
                    "  SELECT * FROM {}\n  WHERE {}",
                    source, where_clause
                ))
            }
            Command::Sort { fields, limit } => {
                let order_clauses: Vec<String> = fields
                    .iter()
                    .map(|sf| {
                        let order = if sf.descending { "DESC" } else { "ASC" };
                        // Check if field is an aggregation function (contains parentheses)
                        // If so, extract just the function name to reference the column
                        let field_expr = if sf.field.contains('(') && sf.field.contains(')') {
                            // Aggregation function like sum(bytes_out) or avg(bytes_kb)
                            // Extract function name: "avg(bytes_kb)" -> "avg"
                            if let Some(func_end) = sf.field.find('(') {
                                let func_name = &sf.field[..func_end];
                                escape_identifier(func_name)
                            } else {
                                escape_identifier(&sf.field)
                            }
                        } else if let Some(target) = self.agg_reference_alias(&sf.field) {
                            // `{func}_{field}` reference to an UN-aliased prior
                            // aggregation (NAN-1339): the output column is the bare
                            // func name — sort by it.
                            escape_identifier(&target)
                        } else if !self.is_upstream_computed_field(&sf.field)
                            && !self.is_computed_field(&sf.field)
                            && self.resolves_to_json_path(&sf.field)
                        {
                            // NAN-1911: an OCSF unmapped-tail field the base scan does
                            // NOT materialize as a bare column (e.g. `risk_score` on a
                            // wide `SELECT *` projection) must ORDER BY its extraction
                            // expression — a bare alias 500s with Code 47 "Unknown
                            // identifier". A numeric tail field extracts as `Float64`,
                            // so the sort is by value, not lexicographic. `unmapped` is
                            // projected in every OCSF stage, so the re-extraction always
                            // binds. Guarded on `resolves_to_json_path` (OCSF-only) and
                            // on NOT being a computed / prior-stage column (those are
                            // real in-scope columns, e.g. `… | stats … by risk_score |
                            // sort -risk_score`) → UDM and OCSF promoted/computed sorts
                            // stay byte-identical.
                            field_to_sql_expr(&sf.field, self).0
                        } else {
                            // Regular field - normalize (e.g., _time -> timestamp),
                            // except an upstream value-computed field, which keeps
                            // its raw (shadowing) column name (NAN-1341).
                            let normalized_field = by_field_output_name(&sf.field, self);
                            escape_identifier(normalized_field)
                        };
                        format!("{} {}", field_expr, order)
                    })
                    .collect();
                let limit_clause = limit
                    .map(|n| format!("\n  LIMIT {}", n))
                    .unwrap_or_default();
                Ok(format!(
                    "  SELECT * FROM {}\n  ORDER BY {}{}",
                    source,
                    order_clauses.join(", "),
                    limit_clause
                ))
            }
            Command::Head { count } => Ok(format!("  SELECT * FROM {}\n  LIMIT {}", source, count)),
            Command::Tail { count } => {
                if timestamp_available {
                    // Raw events: last N by time = oldest N (search default order is newest-first),
                    // presented oldest-first. Unchanged behavior. O27 (NAN-1721):
                    // order on the dataset time column (`start_time` for spans);
                    // logs keep `timestamp` byte-identical.
                    let tc = self.time_column();
                    Ok(format!(
                        "  SELECT * FROM (\n    SELECT * FROM {}\n    ORDER BY {tc} DESC\n    LIMIT {}\n  )\n  ORDER BY {tc} ASC",
                        source, count
                    ))
                } else {
                    // Post-aggregation / timestamp pruned: there is no `timestamp` to order by
                    // (was Code 47, NAN-1146). Tail = last N of the CURRENT result order; capture
                    // that order with rowNumberInAllBlocks() and take the last N in reverse.
                    Ok(format!(
                        "  SELECT * EXCEPT (__nano_rn) FROM (\n    SELECT *, rowNumberInAllBlocks() AS __nano_rn FROM {}\n  )\n  ORDER BY __nano_rn DESC\n  LIMIT {}",
                        source, count
                    ))
                }
            }
            Command::Timechart {
                span,
                aggregations,
                split_by,
                limit,
                cont,
            } => self.generate_timechart_sql(source, span, aggregations, split_by, *limit, *cont),
            Command::Table { fields } => {
                // Check for wildcard: table *
                if fields.len() == 1 && fields[0].name == "*" {
                    // With hybrid storage, UDM fields are properly typed columns that are NULL when empty
                    // No need for conditional logic - just SELECT *
                    return Ok(format!("  SELECT * FROM {}", source));
                }

                // Expand wildcard patterns (src_*, dest_*, etc.) to matching columns
                let expanded_fields: Vec<(String, Option<String>)> = fields
                    .iter()
                    .flat_map(|f| {
                        if super::is_wildcard_pattern(&f.name) {
                            // Expand wildcard to matching explicit columns AND
                            // pipeline-computed fields (no aliases for expanded fields)
                            self.expand_wildcard(&f.name)
                                .into_iter()
                                .map(|col| (col, None))
                                .collect::<Vec<_>>()
                        } else {
                            vec![(f.name.clone(), f.alias.clone())]
                        }
                    })
                    .collect();
                // A wildcard list that matched NOTHING would emit an empty
                // SELECT (CH Code 62 syntax error, NAN-1339) — refuse instead.
                if expanded_fields.is_empty() {
                    return Err(SqlGenError::InvalidQuery(format!(
                        "table: no fields match the requested pattern(s) {}. Wildcards expand \
                         against schema columns and fields computed earlier in the pipeline \
                         (rex/spath/eval outputs)",
                        fields
                            .iter()
                            .map(|f| format!("`{}`", f.name))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }

                let field_list = expanded_fields
                    .iter()
                    .map(|(name, alias)| {
                        let (field_expr, needs_alias) = field_to_sql_expr(name.as_str(), self);

                        match alias {
                            Some(a) => format!("{} AS {}", field_expr, escape_identifier(a)),
                            None => {
                                if needs_alias {
                                    format!("{} AS {}", field_expr, escape_identifier(name))
                                } else {
                                    field_expr
                                }
                            }
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");

                // Track available columns so downstream commands (resolve_identity)
                // know which columns exist after this projection
                *available_columns = Some(
                    expanded_fields
                        .iter()
                        .map(|(name, alias)| alias.as_deref().unwrap_or(name).to_lowercase())
                        .collect(),
                );

                Ok(format!("  SELECT {} FROM {}", field_list, source))
            }
            Command::Rename { mappings } => {
                let rename_exprs: Vec<String> = mappings
                    .iter()
                    .map(|m| {
                        let (from_expr, _) = field_to_sql_expr(&m.from, self);
                        format!("{} AS {}", from_expr, escape_identifier(&m.to))
                    })
                    .collect();

                let renamed_fields = rename_exprs.join(", ");
                Ok(format!("  SELECT *, {} FROM {}", renamed_fields, source))
            }
            Command::Lookup { .. } => {
                // Lookup enrichment is handled entirely in Rust post-processing
                // (`apply_lookup_enrichment` joins against the PostgreSQL-backed
                // lookup tables after the ClickHouse fetch). This stage is a
                // pass-through, like `Command::Prevalence`. The previous code
                // emitted `LEFT JOIN lookup_<name>` against ClickHouse — but
                // lookup tables have never existed in ClickHouse, so every
                // `| lookup` query died with CH Code 60 UNKNOWN_TABLE masked as
                // a generic 500 (NAN-1389).
                Ok(format!("  SELECT * FROM {}", source))
            }
            Command::Eval { assignments } => {
                let mut select_parts = vec!["*".to_string()];

                for assignment in assignments {
                    let expr_sql = eval_expression_to_sql(self, &assignment.expression)?;
                    // Escape the target alias like every other output-naming command
                    // (bin/rex/spath/mvexpand/stats/rename). The parser accepts a quoted
                    // eval alias carrying arbitrary characters (`eval "a, b"=1`), so a raw
                    // interpolation here is a SQL-injection surface; byte-identical for
                    // ordinary aliases (NAN-1352).
                    select_parts.push(format!(
                        "{} AS {}",
                        expr_sql,
                        escape_identifier(&assignment.field)
                    ));
                }

                Ok(format!(
                    "  SELECT {} FROM {}",
                    select_parts.join(", "),
                    source
                ))
            }
            Command::Dedup {
                fields,
                keep_first: _,
            } => {
                // Normalize and resolve field names through the active profile
                // (UDM-byte-identical; OCSF maps UDM aliases → promoted columns)
                let partition_fields: Vec<String> = fields
                    .iter()
                    .map(|f| by_field_sql(f, self))
                    .collect();
                let partition_by = partition_fields.join(", ");

                // Sort-free dedup (NAN-1636, corrected by NAN-2264). The legacy
                // `ORDER BY <keys>, timestamp LIMIT 1 BY <keys>` full-sorts every
                // wide (~200-column) row before the LIMIT BY — Code 241
                // (MergeSortingTransform OOM) at ≥~15min windows under the
                // production 3GiB/query profile.
                //
                // NAN-1636 replaced it with `WHERE id IN (SELECT argMin(id,
                // <time>) …)`, which is one-row-per-key ONLY if `id` is unique per
                // PHYSICAL row. It is not: `ClickHouseLogRow` derives `id` as a
                // CONTENT hash — SHA256(source_type + timestamp_micros + message)
                // — deliberately, so retried batches insert idempotently
                // (`ingestion/row.rs`). MergeTree does not enforce uniqueness, so
                // content-identical rows coexist sharing an id, and picking one as
                // survivor passed EVERY row carrying that id. A repeated
                // explicitly-supplied OCSF id had the same effect. `dedup` emitted
                // duplicates — the one thing it exists to prevent (NAN-2264).
                //
                // The correct sort-free shape restricts each group to its OLDEST
                // timestamp (an aggregate, not a sort — same keep-oldest semantics
                // as the legacy form) and then lets `LIMIT 1 BY <keys>` collapse
                // the ties. `LIMIT 1 BY` guarantees exactly one row per key by
                // construction, independent of any id, and lowers to a
                // LimitByTransform over a key-only hash map — no
                // MergeSortingTransform, so the NAN-1636 memory win is preserved.
                // `keep_first` is ignored in both shapes and timestamp ties stay
                // nondeterministic in both, as before.
                //
                // Guards — ALL must hold, else keep the legacy shape:
                //  - `source` must be the deterministic base scan: the rewrite
                //    scans the source CTE twice (outer + IN-subquery), so a
                //    nondeterministic upstream stage (`head` with no ORDER BY, a
                //    LIMITed requery base) could sample different rows per scan;
                //  - the dataset time column must still exist at this stage — an
                //    upstream include-mode `fields`/`table` that pruned it would
                //    make the IN-subquery UNKNOWN_IDENTIFIER — and must be the
                //    physical row time, not an upstream `eval timestamp=…`;
                //  - the dataset must be a physical row scan, i.e. one whose
                //    profile has a per-row identity column (`id` on logs,
                //    `span_id` on spans). The emitted SQL no longer references
                //    that column — this deliberately pins the rewrite to exactly
                //    the datasets NAN-1636 measured. `metrics` / the derived
                //    `risk` grain keep the legacy shape: relaxing the gate for
                //    them is a separate question, because double-scanning a
                //    derived aggregate base is its own performance trade.
                // O27 (NAN-1721): the time column is profile-relative — `timestamp`
                // on logs, `start_time` on spans (a literal `timestamp` does not
                // exist on `otel_spans`); the legacy ORDER BY below uses it too.
                let time_col = self.time_column();
                let base_is_physical_row_scan = self.row_identity_column().is_some();
                let time_col_available = match available_columns {
                    None => true,
                    Some(cols) => cols.contains(time_col),
                };
                let time_col_is_row_time = self.profile.core_fields().contains(&time_col)
                    && !self.is_upstream_computed_field(time_col);
                if stability.deterministic_base
                    && base_is_physical_row_scan
                    && time_col_available
                    && time_col_is_row_time
                {
                    // Null-safe candidate matching. ClickHouse's IN keeps SQL NULL
                    // semantics by default (`transform_null_in = 0`), so a tuple
                    // carrying NULL matches nothing: a bare `(<keys>, <time>) IN
                    // (…)` would DROP every row whose dedup key is NULL, where the
                    // legacy shape keeps one (GROUP BY and LIMIT BY both treat
                    // NULL as an ordinary group value). Reachable today —
                    // `enrich_time` is Nullable, as is any eval-computed key.
                    // Matching on `(isNull(k), assumeNotNull(k))` is total: NULL
                    // maps to `(1, <default>)`, a real value to `(0, <value>)`, so
                    // the two can never collide. Constant-folded away for the
                    // non-Nullable columns that carry most dedup keys. The time
                    // element needs no such wrapper: it is the dataset's primary
                    // time column, non-Nullable on every dataset table (it is the
                    // partition/ORDER BY key), and the guard above rejects an
                    // upstream reassignment of it.
                    let match_keys = partition_fields
                        .iter()
                        .map(|f| format!("isNull({f}), assumeNotNull({f})"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    Ok(format!(
                        "  SELECT * FROM {src}\n  WHERE ({match_keys}, {time_col}) IN (\n    SELECT {match_keys}, min({time_col}) FROM {src}\n    GROUP BY {partition_by}\n  )\n  LIMIT 1 BY {partition_by}",
                        src = source
                    ))
                } else {
                    // ClickHouse uses LIMIT 1 BY for deduplication
                    Ok(format!(
                        "  SELECT * FROM {}\n  ORDER BY {}, {}\n  LIMIT 1 BY {}",
                        source, partition_by, time_col, partition_by
                    ))
                }
            }
            Command::Bin {
                span,
                field,
                alias,
                window_type,
            } => {
                match span {
                    BinSpan::Time(duration) => {
                        // Generate ClickHouse SQL for time-based bin command.
                        // O7 (NAN-1721): resolve the binned field to the active
                        // dataset's time column — `bin`/`bin _time`/`bin timestamp`
                        // all bucket on `start_time` for spans (a literal
                        // `timestamp` column does not exist there), and an explicit
                        // non-time field canonicalizes through the profile. Logs
                        // keep `timestamp` byte-identical (`time_column()` matches
                        // the pre-fix literal default and the free alias map).
                        let field_name = self.bin_field_name(field.as_deref());
                        // Determine alias:
                        // - If alias provided, use it
                        // - If field was explicitly specified, use field name (in-place modification)
                        // - If no field specified (default time column), use "time_bucket"
                        let alias_name: String =
                            alias.as_deref().map(String::from).unwrap_or_else(|| {
                                if field.is_some() {
                                    field_name.clone()
                                } else {
                                    "time_bucket".to_string()
                                }
                            });
                        let span_seconds = duration.as_secs();

                        match window_type {
                            WindowType::Tumbling => {
                                // Standard tumbling window - non-overlapping fixed windows
                                let time_bucket_expr = self.generate_time_bucket(duration);

                                // `generate_time_bucket` buckets on the dataset time
                                // column; retarget it when the user binned a DIFFERENT
                                // field. O7 (NAN-1721): compare/replace against the
                                // time column, not a hardcoded `timestamp` (which is
                                // `start_time` on spans).
                                let time_col = self.time_column();
                                let bucket_expr = if field_name.as_str() != time_col {
                                    time_bucket_expr.replace(time_col, field_name.as_str())
                                } else {
                                    time_bucket_expr
                                };

                                // If alias matches the field name (in-place modification), exclude the original
                                // field from SELECT * to avoid duplicate columns
                                if alias_name == field_name {
                                    Ok(format!(
                                        "  SELECT * EXCEPT ({}), {} AS {} FROM {}",
                                        escape_identifier(&field_name),
                                        bucket_expr,
                                        escape_identifier(&alias_name),
                                        source
                                    ))
                                } else {
                                    Ok(format!(
                                        "  SELECT *, {} AS {} FROM {}",
                                        bucket_expr,
                                        escape_identifier(&alias_name),
                                        source
                                    ))
                                }
                            }
                            WindowType::Hop { advance } => {
                                // Hop window - overlapping windows that advance by a fixed interval
                                // Each event belongs to multiple windows: span/advance windows
                                let advance_seconds = advance.as_secs();
                                // NAN-2010 (F22): a zero hop (`bin ... hop=0s`) would
                                // divide-by-zero panic the codegen below. Reject cleanly.
                                if advance_seconds == 0 {
                                    return Err(SqlGenError::InvalidQuery(
                                        "bin hop must be greater than 0".into(),
                                    ));
                                }
                                let num_windows = (span_seconds / advance_seconds) as i64;

                                // Generate array of window offsets: [0, -advance, -2*advance, ...]
                                // Then ARRAY JOIN to create one row per window the event belongs to
                                Ok(format!(
                                    "  SELECT * EXCEPT ({field}), \
                                    toDateTime(toInt64(toDateTime({field})) - toInt64(toDateTime({field})) % {advance} + window_offset) AS {alias}, \
                                    toDateTime(toInt64(toDateTime({field})) - toInt64(toDateTime({field})) % {advance} + window_offset + {span}) AS {alias}_end \
                                    FROM {source} \
                                    ARRAY JOIN arrayMap(x -> -x * {advance}, range(0, {num_windows})) AS window_offset",
                                    field = escape_identifier(&field_name),
                                    advance = advance_seconds,
                                    span = span_seconds,
                                    alias = escape_identifier(&alias_name),
                                    source = source,
                                    num_windows = num_windows
                                ))
                            }
                            WindowType::Sliding => {
                                // Sliding window - each event defines its own window start
                                // The window extends from (timestamp) to (timestamp + span)
                                // Useful for per-event lookback analysis
                                Ok(format!(
                                    "  SELECT *, \
                                    {field} AS {alias}, \
                                    toDateTime(toInt64(toDateTime({field})) + {span}) AS {alias}_end \
                                    FROM {source}",
                                    field = escape_identifier(&field_name),
                                    span = span_seconds,
                                    alias = escape_identifier(&alias_name),
                                    source = source
                                ))
                            }
                        }
                    }
                    BinSpan::Numeric(bin_size) => {
                        // Numeric binning only supports tumbling windows
                        if !matches!(window_type, WindowType::Tumbling) {
                            return Err(SqlGenError::InvalidQuery(
                                "Hop and sliding windows are only supported for time-based binning"
                                    .into(),
                            ));
                        }

                        // Generate ClickHouse SQL for numeric bin command
                        // Field is required for numeric binning
                        let field_name = field.as_ref().ok_or_else(|| {
                            SqlGenError::InvalidQuery(
                                "Field is required for numeric binning".to_string(),
                            )
                        })?;

                        let alias_name = alias.as_deref().unwrap_or(field_name);

                        // Use floor(field / bin_size) * bin_size to create bins
                        let bucket_expr = format!(
                            "floor({} / {}) * {}",
                            escape_identifier(field_name),
                            bin_size,
                            bin_size
                        );

                        // If alias matches the field name (in-place modification), exclude the original
                        // field from SELECT * to avoid duplicate columns
                        if alias_name == field_name {
                            Ok(format!(
                                "  SELECT * EXCEPT ({}), {} AS {} FROM {}",
                                escape_identifier(field_name),
                                bucket_expr,
                                escape_identifier(alias_name),
                                source
                            ))
                        } else {
                            Ok(format!(
                                "  SELECT *, {} AS {} FROM {}",
                                bucket_expr,
                                escape_identifier(alias_name),
                                source
                            ))
                        }
                    }
                }
            }
            Command::Rex {
                field,
                pattern,
                mode,
            } => {
                let source_field = field.as_deref().unwrap_or("message");

                match mode {
                    RexMode::Extract => {
                        // Extract named capture groups from the pattern
                        let named_groups = extract_named_groups(pattern);

                        if named_groups.is_empty() {
                            // No named groups, just return the matches array
                            Ok(format!(
                                "  SELECT *, extractAll({}::String, '{}') AS rex_matches FROM {}",
                                escape_identifier(source_field), escape_string(pattern), source
                            ))
                        } else {
                            // Convert named groups to numbered groups for ClickHouse
                            let ch_pattern = convert_named_groups_to_numbered(pattern);

                            // Generate column extractions for each named group
                            let extractions: Vec<String> = named_groups
                                .iter()
                                .enumerate()
                                .map(|(idx, name)| {
                                    format!(
                                        "extractGroups({}::String, '{}')[{}] AS {}",
                                        escape_identifier(source_field),
                                        escape_string(&ch_pattern),
                                        idx + 1,  // ClickHouse groups are 1-indexed
                                        escape_identifier(name)
                                    )
                                })
                                .collect();

                            Ok(format!(
                                "  SELECT *, {} FROM {}",
                                extractions.join(", "),
                                source
                            ))
                        }
                    }
                    RexMode::Sed { pattern: sed_pattern, replacement } => {
                        Ok(format!(
                            "  SELECT *, replaceRegexpAll({}::String, '{}', '{}') AS rex_result FROM {}",
                            escape_identifier(source_field), escape_string(sed_pattern), escape_string(replacement), source
                        ))
                    }
                }
            }
            Command::Fields { fields, keep } => {
                // Expand wildcard patterns to matching columns
                let expanded_fields: Vec<String> = fields
                    .iter()
                    .flat_map(|f| self.expand_wildcard(f))
                    .collect();

                if *keep {
                    // Same empty-wildcard guard as `table` (NAN-1339).
                    if expanded_fields.is_empty() {
                        return Err(SqlGenError::InvalidQuery(format!(
                            "fields: no fields match the requested pattern(s) {}. Wildcards \
                             expand against schema columns and fields computed earlier in \
                             the pipeline (rex/spath/eval outputs)",
                            fields
                                .iter()
                                .map(|f| format!("`{}`", f))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )));
                    }
                    // Include mode: SELECT only these fields
                    let field_list = expanded_fields
                        .iter()
                        .map(|f| {
                            let (expr, needs_alias) = field_to_sql_expr(f, self);
                            if needs_alias {
                                format!("{} AS {}", expr, escape_identifier(f))
                            } else {
                                expr
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ");

                    // Track available columns for downstream commands
                    *available_columns =
                        Some(expanded_fields.iter().map(|f| f.to_lowercase()).collect());

                    Ok(format!("  SELECT {} FROM {}", field_list, source))
                } else {
                    // Exclude mode: SELECT * EXCEPT (fields)
                    if expanded_fields.is_empty() {
                        Ok(format!("  SELECT * FROM {}", source))
                    } else {
                        let exclude_list = expanded_fields
                            .iter()
                            .map(|f| escape_identifier(f))
                            .collect::<Vec<_>>()
                            .join(", ");
                        Ok(format!(
                            "  SELECT * EXCEPT ({}) FROM {}",
                            exclude_list, source
                        ))
                    }
                }
            }
            Command::Top {
                field,
                limit,
                by_fields,
                show_count,
                show_percent,
                inject_bounds,
            } => {
                // Normalized output alias (raw name for an upstream
                // value-computed field — it shadows the schema alias, NAN-1341)
                let normalized_field = by_field_output_name(field, self);
                let (field_expr, needs_alias) = field_to_sql_expr(field, self);
                // Wrap dynamic/JSON fields with toString() for both SELECT and GROUP BY
                // Always add explicit alias to ensure column name appears in output
                let field_select = if needs_alias {
                    format!(
                        "toString({}) AS {}",
                        field_expr,
                        escape_identifier(normalized_field)
                    )
                } else {
                    format!("{} AS {}", field_expr, escape_identifier(normalized_field))
                };
                let field_group_by = if needs_alias {
                    format!("toString({})", field_expr)
                } else {
                    field_expr.clone()
                };

                let mut select_parts = vec![field_select];
                if *show_count {
                    select_parts.push("count() AS count".to_string());
                }
                if *show_percent {
                    select_parts.push(
                        "round(count() * 100.0 / sum(count()) OVER (), 2) AS percent".to_string(),
                    );
                }
                if *inject_bounds && !top_rare_bounds_alias_collision(field, by_fields, self) {
                    // NAN-1711 / audit D15: canonical per-group activity window,
                    // set only by detection query enrichment (gated on the raw
                    // `timestamp` still being in the stream — D3). Resolved via
                    // field_to_sql_expr so it matches the stats-path emission.
                    let (ts_expr, _) = field_to_sql_expr("timestamp", self);
                    select_parts.push(format!("min({}) AS _first_seen", ts_expr));
                    select_parts.push(format!("max({}) AS _last_seen", ts_expr));
                }

                let mut group_by_parts = vec![field_group_by.clone()];
                for by in by_fields {
                    // Skip "count" and "percent" as by_fields - they're reserved output columns
                    let by_lower = by.to_lowercase();
                    if by_lower == "count" || by_lower == "percent" {
                        continue;
                    }
                    let normalized_by = by_field_output_name(by, self);
                    let (by_expr, by_needs_alias) = field_to_sql_expr(by, self);
                    let by_select = if by_needs_alias {
                        format!(
                            "toString({}) AS {}",
                            by_expr,
                            escape_identifier(normalized_by)
                        )
                    } else {
                        format!("{} AS {}", by_expr, escape_identifier(normalized_by))
                    };
                    let by_group_by = if by_needs_alias {
                        format!("toString({})", by_expr)
                    } else {
                        by_expr.clone()
                    };
                    select_parts.insert(0, by_select);
                    group_by_parts.insert(0, by_group_by);
                }
                let group_by = group_by_parts.join(", ");

                Ok(format!(
                    "  SELECT {}\n  FROM {}\n  GROUP BY {}\n  ORDER BY count DESC\n  LIMIT {}",
                    select_parts.join(", "),
                    source,
                    group_by,
                    limit
                ))
            }
            Command::Rare {
                field,
                limit,
                by_fields,
                show_count,
                show_percent,
                inject_bounds,
            } => {
                // Normalized output alias (raw name for an upstream
                // value-computed field — it shadows the schema alias, NAN-1341)
                let normalized_field = by_field_output_name(field, self);
                let (field_expr, needs_alias) = field_to_sql_expr(field, self);
                // Wrap dynamic/JSON fields with toString() for both SELECT and GROUP BY
                // Always add explicit alias to ensure column name appears in output
                let field_select = if needs_alias {
                    format!(
                        "toString({}) AS {}",
                        field_expr,
                        escape_identifier(normalized_field)
                    )
                } else {
                    format!("{} AS {}", field_expr, escape_identifier(normalized_field))
                };
                let field_group_by = if needs_alias {
                    format!("toString({})", field_expr)
                } else {
                    field_expr.clone()
                };

                let mut select_parts = vec![field_select];
                if *show_count {
                    select_parts.push("count() AS count".to_string());
                }
                if *show_percent {
                    select_parts.push(
                        "round(count() * 100.0 / sum(count()) OVER (), 2) AS percent".to_string(),
                    );
                }
                if *inject_bounds && !top_rare_bounds_alias_collision(field, by_fields, self) {
                    // NAN-1711 / audit D15 — see the `top` arm.
                    let (ts_expr, _) = field_to_sql_expr("timestamp", self);
                    select_parts.push(format!("min({}) AS _first_seen", ts_expr));
                    select_parts.push(format!("max({}) AS _last_seen", ts_expr));
                }

                let mut group_by_parts = vec![field_group_by.clone()];
                for by in by_fields {
                    // Skip "count" and "percent" as by_fields - they're reserved output columns
                    let by_lower = by.to_lowercase();
                    if by_lower == "count" || by_lower == "percent" {
                        continue;
                    }
                    let normalized_by = by_field_output_name(by, self);
                    let (by_expr, by_needs_alias) = field_to_sql_expr(by, self);
                    let by_select = if by_needs_alias {
                        format!(
                            "toString({}) AS {}",
                            by_expr,
                            escape_identifier(normalized_by)
                        )
                    } else {
                        format!("{} AS {}", by_expr, escape_identifier(normalized_by))
                    };
                    let by_group_by = if by_needs_alias {
                        format!("toString({})", by_expr)
                    } else {
                        by_expr.clone()
                    };
                    select_parts.insert(0, by_select);
                    group_by_parts.insert(0, by_group_by);
                }
                let group_by = group_by_parts.join(", ");

                Ok(format!(
                    "  SELECT {}\n  FROM {}\n  GROUP BY {}\n  ORDER BY count ASC\n  LIMIT {}",
                    select_parts.join(", "),
                    source,
                    group_by,
                    limit
                ))
            }
            Command::Transaction {
                fields,
                startswith,
                endswith,
                maxspan,
                maxevents,
            } => {
                // Generate SQL for transaction command - event grouping
                let group_by_fields: Vec<String> = fields
                    .iter()
                    .map(|f| {
                        let normalized = by_field_output_name(f, self);
                        let (expr, needs_cast) = field_to_sql_expr(f, self);
                        if needs_cast {
                            format!("toString({}) AS {}", expr, escape_identifier(normalized))
                        } else {
                            expr
                        }
                    })
                    .collect();

                let group_by_refs: Vec<String> = fields
                    .iter()
                    .map(|f| {
                        let (expr, needs_cast) = field_to_sql_expr(f, self);
                        if needs_cast {
                            format!("toString({})", expr)
                        } else {
                            expr
                        }
                    })
                    .collect();

                // O27 (NAN-1721): transaction aggregates on the dataset time column
                // (`start_time` for spans) and captures the dataset's free-text
                // column (`span_name` for spans) — not the logs-only
                // `timestamp`/`message` columns, absent on `otel_spans`. The window
                // ORDER BY tie-break uses the profile row-identity column (`span_id`
                // on spans). Logs keep `timestamp`/`message`/`id` byte-identical.
                let tc = self.time_column();
                let kw = self.profile.keyword_search_column();
                let order_tiebreak = match self.row_identity_column() {
                    Some(id) => format!("{tc}, {id}"),
                    None => tc.to_string(),
                };

                let having_clause = match (maxspan, maxevents) {
                    (Some(d), Some(n)) => {
                        let secs = d.as_secs();
                        format!("\n  HAVING count() <= {} AND dateDiff('second', min({tc}), max({tc})) <= {}", n, secs)
                    }
                    (Some(d), None) => {
                        let secs = d.as_secs();
                        format!(
                            "\n  HAVING dateDiff('second', min({tc}), max({tc})) <= {}",
                            secs
                        )
                    }
                    (None, Some(n)) => {
                        format!("\n  HAVING count() <= {}", n)
                    }
                    (None, None) => String::new(),
                };

                // Cap groupArray to maxevents (or default 1000) to prevent OOM from unbounded array accumulation
                let array_limit = maxevents.unwrap_or(1000);

                // No start/end markers: one transaction per group key (legacy form).
                if startswith.is_none() && endswith.is_none() {
                    return Ok(format!(
                        "  SELECT \n    {fields},\n    count() AS eventcount,\n    dateDiff('second', min({tc}), max({tc})) AS duration,\n    min({tc}) AS transaction_start,\n    max({tc}) AS transaction_end,\n    groupArray({limit})({kw}) AS _raw_events\n  FROM {source}\n  GROUP BY {group_by}{having}\n  ORDER BY transaction_start DESC",
                        fields = group_by_fields.join(", "),
                        limit = array_limit,
                        source = source,
                        group_by = group_by_refs.join(", "),
                        having = having_clause
                    ));
                }

                // startswith=/endswith= sessionization (NAN-1346 #6). The markers
                // were previously parsed-then-discarded, silently collapsing each
                // group key into ONE transaction over ALL its events. Marker
                // semantics: a transaction opens at an event matching `startswith`
                // and closes at the first subsequent event matching `endswith`;
                // events outside any open transaction are evicted, as are
                // transactions that never see their `endswith` marker.
                //
                // Layered windows (each depends on the previous, so they nest):
                //   1. flag rows matching the markers,
                //   2. assign a per-group session number — a cumulative count of
                //      start markers (rows before the first start get session 0);
                //      with only `endswith`, sessions split AFTER each end marker,
                //   3. within a session, drop rows after the first end marker and
                //      (when `endswith` is given) sessions with no end at all.
                let start_flag = match startswith {
                    Some(expr) => format!("if({}, 1, 0)", self.generate_search_expr(expr)?),
                    None => "0".to_string(),
                };
                let end_flag = match endswith {
                    Some(expr) => format!("if({}, 1, 0)", self.generate_search_expr(expr)?),
                    None => "0".to_string(),
                };
                let partition = group_by_refs.join(", ");
                let session_expr = if startswith.is_some() {
                    format!(
                        "sum(_txn_is_start) OVER (PARTITION BY {partition} ORDER BY {order_tiebreak} ROWS UNBOUNDED PRECEDING)"
                    )
                } else {
                    // endswith only: a new transaction begins on the row AFTER an
                    // end marker, so count only strictly-preceding end markers.
                    format!(
                        "1 + sum(_txn_is_end) OVER (PARTITION BY {partition} ORDER BY {order_tiebreak} ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING)"
                    )
                };
                // Rows after a session's first end marker are evicted; when an
                // end marker is required, sessions without one are too.
                let end_filters = if endswith.is_some() {
                    format!(
                        ",\n      sum(_txn_is_end) OVER (PARTITION BY {partition}, _txn_session ORDER BY {order_tiebreak} ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) AS _txn_ends_before,\n      max(_txn_is_end) OVER (PARTITION BY {partition}, _txn_session) AS _txn_has_end"
                    )
                } else {
                    String::new()
                };
                let row_filter = if endswith.is_some() {
                    "_txn_session > 0 AND _txn_ends_before = 0 AND _txn_has_end = 1"
                } else {
                    "_txn_session > 0"
                };

                Ok(format!(
                    "  SELECT \n    {fields},\n    count() AS eventcount,\n    dateDiff('second', min({tc}), max({tc})) AS duration,\n    min({tc}) AS transaction_start,\n    max({tc}) AS transaction_end,\n    groupArray({limit})({kw}) AS _raw_events\n  FROM (\n    SELECT *{end_filters}\n    FROM (\n      SELECT *, {session_expr} AS _txn_session\n      FROM (\n        SELECT *, {start_flag} AS _txn_is_start, {end_flag} AS _txn_is_end\n        FROM {source}\n      )\n    )\n  )\n  WHERE {row_filter}\n  GROUP BY {group_by}, _txn_session{having}\n  ORDER BY transaction_start DESC",
                    fields = group_by_fields.join(", "),
                    limit = array_limit,
                    end_filters = end_filters,
                    session_expr = session_expr,
                    start_flag = start_flag,
                    end_flag = end_flag,
                    source = source,
                    row_filter = row_filter,
                    group_by = group_by_refs.join(", "),
                    having = having_clause
                ))
            }
            Command::Fillnull { value, fields } => match fields {
                Some(field_list) => {
                    let coalesce_exprs: Vec<String> = field_list
                        .iter()
                        .map(|f| {
                            let (expr, _) = field_to_sql_expr(f, self);
                            format!(
                                "ifNull(toString({}), '{}') AS {}",
                                expr,
                                escape_string(value),
                                escape_identifier(f)
                            )
                        })
                        .collect();
                    Ok(format!(
                        "  SELECT *, {} FROM {}",
                        coalesce_exprs.join(", "),
                        source
                    ))
                }
                None => Ok(format!("  SELECT * FROM {}", source)),
            },
            Command::Mvexpand { field, limit } => {
                let (field_expr, _) = field_to_sql_expr(field, self);
                // Apply user limit if specified, otherwise use configurable default to prevent
                // arrayJoin from expanding billions of rows (expansion happens before LIMIT)
                let effective_limit = limit.unwrap_or(self.max_mvexpand_rows);
                let limit_clause = format!(" LIMIT {}", effective_limit);

                Ok(format!(
                    "  SELECT *, arrayJoin({}) AS {} FROM {}{}",
                    field_expr,
                    escape_identifier(&format!("{}_expanded", field)),
                    source,
                    limit_clause
                ))
            }
            Command::Spath {
                input,
                output,
                path,
            } => {
                // Resolve the source column through the active profile (NAN-1343):
                // a tail name like `ext`/`event` (or no input) targets the profile's
                // JSON tail — `ext` for UDM, `event` for OCSF — so `input=ext` does not
                // 500 with "Unknown identifier `ext`" under OCSF. A name that resolves
                // to a promoted/explicit column extracts from that column directly.
                let input_field = match input {
                    Some(f) => match self.profile.resolve(f) {
                        crate::schema::FieldResolution::ExplicitColumn(c) => c,
                        _ => self.profile.json_tail_column().to_string(),
                    },
                    None => self.profile.json_tail_column().to_string(),
                };
                let output_field = output.as_deref().unwrap_or("spath_result");

                match path {
                    Some(json_path) => Ok(format!(
                        "  SELECT *, JSONExtractString({}, '{}') AS {} FROM {}",
                        escape_identifier(&input_field),
                        escape_string(json_path),
                        escape_identifier(output_field),
                        source
                    )),
                    None => Ok(format!("  SELECT * FROM {}", source)),
                }
            }
            Command::Append { .. } => {
                // Append is handled in generate_command_cte with proper UNION ALL
                Err(SqlGenError::UnsupportedOperation(
                    "Append should be handled via CTE generation".to_string(),
                ))
            }
            Command::Join { .. } => {
                // Join is handled in generate_command_cte with proper JOIN SQL
                Err(SqlGenError::UnsupportedOperation(
                    "Join should be handled via CTE generation".to_string(),
                ))
            }
            Command::Format {
                maxresults,
                row_sep: _,
                col_sep: _,
            } => match maxresults {
                Some(n) => Ok(format!("  SELECT * FROM {} LIMIT {}", source, n)),
                None => Ok(format!("  SELECT * FROM {}", source)),
            },
            Command::Return { count, fields } => {
                let field_list = fields
                    .iter()
                    .map(|f| {
                        let (expr, needs_alias) = field_to_sql_expr(f, self);
                        if needs_alias {
                            format!("{} AS {}", expr, escape_identifier(f))
                        } else {
                            expr
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");

                Ok(format!(
                    "  SELECT DISTINCT {} FROM {} LIMIT {}",
                    field_list, source, count
                ))
            }
            Command::Risk {
                score,
                entity_field,
                factor,
                weight,
            } => {
                // Generate ClickHouse SQL for risk command
                let entity_expr = match entity_field {
                    Some(field) => {
                        let (expr, _) = field_to_sql_expr(field, self);
                        format!("coalesce(toString({}), 'unknown')", expr)
                    }
                    None => "'unknown'".to_string(),
                };

                // Build the factor expression
                let factor_expr = match factor {
                    Some(EvalExpression::Literal(Value::String(s))) => {
                        format!("'{}'", escape_string(s))
                    }
                    Some(expr) => {
                        format!("toString({})", eval_expression_to_sql(self, expr)?)
                    }
                    None => "'risk_assigned'".to_string(),
                };

                // Build the score expression (raw score for this pipe)
                let raw_score_expr = match score {
                    RiskScoreExpr::Literal(s) => {
                        let clamped = (*s).clamp(0, 100);
                        clamped.to_string()
                    }
                    RiskScoreExpr::Dynamic(expr) => {
                        let expr_sql = eval_expression_to_sql(self, expr)?;
                        format!("least(100, greatest(0, toInt32({})))", expr_sql)
                    }
                };

                // Build weight expression if provided
                let weight_clause = match weight {
                    Some(w) => format!(",\n    {} AS risk_weight", w),
                    None => String::new(),
                };

                if has_prior_risk {
                    // Accumulate: sum scores (clamped 0-100), concat factor arrays
                    let accumulated_score =
                        format!("least(100, greatest(0, risk_score + {}))", raw_score_expr);
                    let accumulated_factors =
                        format!("arrayConcat(risk_factors, [{}])", factor_expr);
                    Ok(format!(
                        "  SELECT * EXCEPT(raw_risk_score, risk_score, risk_entity, risk_factors{}),\n    {} AS raw_risk_score,\n    {} AS risk_score,\n    {} AS risk_entity,\n    {} AS risk_factors{}\n  FROM {}",
                        if weight.is_some() { ", risk_weight" } else { "" },
                        raw_score_expr, accumulated_score, entity_expr, accumulated_factors, weight_clause, source
                    ))
                } else {
                    // First risk pipe: initialize score and factors
                    Ok(format!(
                        "  SELECT *,\n    {} AS raw_risk_score,\n    {} AS risk_score,\n    {} AS risk_entity,\n    [{}] AS risk_factors{}\n  FROM {}",
                        raw_score_expr, raw_score_expr, entity_expr, factor_expr, weight_clause, source
                    ))
                }
            }
            // Complex commands delegate to commands_advanced.rs
            Command::StreamStats {
                aggregations,
                group_by,
                current,
                window,
            } => self.generate_streamstats_sql(source, aggregations, group_by, *current, window),
            Command::Prevalence { .. } => {
                // Prevalence command is handled as post-processing by the search service
                Ok(format!("  SELECT * FROM {}", source))
            }
            Command::Sample { limit } => Ok(format!(
                "  SELECT * FROM {}\n  ORDER BY cityHash64(id, now())\n  LIMIT {}",
                source, limit
            )),
            Command::Reverse => {
                if timestamp_available {
                    // Raw events: reverse the default newest-first order → oldest-first.
                    // O27 (NAN-1721): order on the dataset time column (`start_time`
                    // for spans); logs keep `timestamp` byte-identical.
                    Ok(format!(
                        "  SELECT * FROM {}\n  ORDER BY {} ASC",
                        source,
                        self.time_column()
                    ))
                } else {
                    // Post-aggregation / timestamp pruned: reverse the CURRENT result order via
                    // rowNumberInAllBlocks() rather than ORDER BY timestamp (was Code 47, NAN-1146).
                    Ok(format!(
                        "  SELECT * EXCEPT (__nano_rn) FROM (\n    SELECT *, rowNumberInAllBlocks() AS __nano_rn FROM {}\n  )\n  ORDER BY __nano_rn DESC",
                        source
                    ))
                }
            }
            Command::EventStats {
                aggregations,
                group_by,
            } => self.generate_eventstats_sql(source, aggregations, group_by, &stability),
            Command::Sequence {
                group_by,
                maxspan,
                conditions,
                capture_fields,
            } => self.generate_sequence_sql(source, group_by, maxspan, conditions, capture_fields),
            Command::Funnel {
                group_by,
                window,
                steps,
            } => self.generate_funnel_sql(source, group_by, window, steps),
            Command::Anomaly {
                field,
                by_fields,
                threshold,
                method,
            } => self.generate_anomaly_sql(
                source,
                field,
                by_fields,
                *threshold,
                method,
                &stability,
            ),
            // InputLookup is handled in post-processing (Rust code), not SQL
            Command::InputLookup { .. } => Ok(format!("SELECT * FROM {}", source)),
            Command::Tree {
                parent_field,
                child_field,
                label_field,
                detail_field,
                prevalence_field,
                root_filter: _,
            } => {
                // The positional form `tree <field>` parses with an EMPTY
                // parent_field when no `parent=` is given — emitting it would
                // produce `SELECT *, , <field>` (CH Code 62 syntax error,
                // NAN-1346). A tree needs a parent/child pair; refuse with
                // usage guidance instead of generating malformed SQL.
                if parent_field.is_empty() {
                    return Err(SqlGenError::InvalidQuery(
                        "tree requires a parent field: use `tree <field> parent=<parent field>`, \
                         the full form `tree parent=<field> child=<field> label=<field>`, or a \
                         preset (`tree process`, `tree web`)"
                            .to_string(),
                    ));
                }
                // Tree command: pass through all data, tree building happens in post-processing.
                //
                // The tree builder (search/service/tree_view.rs) reads result rows
                // by the AST's literal field names, so each field is resolved
                // through the active profile and ALIASED BACK to its nPL name
                // (NAN-1346 #5): under OCSF the preset's `parent_process_guid`
                // resolves to the promoted `"actor.process.uid"` (the OCSF
                // parent/initiator uid) and class-split concepts (`process_guid`,
                // `process_name`, …) to their unified columns. Under UDM every
                // resolved expr equals the escaped name, so the projection is
                // byte-identical to the old raw-identifier form. Fields the
                // profile can't resolve (custom ext fields like `ppid`) keep the
                // raw identifier — stage_0's ext materialization aliases them.
                let project_as = |f: &str| -> String {
                    let ident = escape_identifier(f).to_string();
                    if let Some(unified) = self.class_split_column(f) {
                        let unified = escape_identifier(&unified).to_string();
                        if unified == ident {
                            ident
                        } else {
                            format!("{} AS {}", unified, ident)
                        }
                    } else if self.resolves_to_column(f) {
                        let (expr, _) = field_to_sql_expr(f, self);
                        if expr == ident {
                            ident
                        } else {
                            format!("{} AS {}", expr, ident)
                        }
                    } else {
                        ident
                    }
                };
                let mut required_fields = vec![
                    project_as(parent_field),
                    project_as(child_field),
                    project_as(label_field),
                ];
                if let Some(detail) = detail_field {
                    required_fields.push(project_as(detail));
                }
                if let Some(prevalence) = prevalence_field {
                    required_fields.push(project_as(prevalence));
                }
                // Prevalence columns used by the tree builder
                // (prevalence_file_hash / process_hash / dest_domain / dest_ip /
                // _min) are selected in the base CTE alongside other MATERIALIZED
                // columns (enriched_*, ioc_*) — see `build_select_clause`. They
                // flow through here via SELECT *, so we don't need to name them
                // explicitly. Naming MATERIALIZED cols that aren't in the
                // upstream CTE's SELECT triggers UNKNOWN_IDENTIFIER.
                // Deduplicate
                required_fields.sort();
                required_fields.dedup();
                let fields_list = required_fields.join(", ");
                Ok(format!("  SELECT *, {} FROM {}", fields_list, source))
            }
            Command::ResolveIdentity { field, max_age } => {
                // Generate ASOF JOIN with identity_observations table
                self.generate_resolve_identity_sql(
                    source,
                    field,
                    max_age,
                    available_columns,
                    single_resolve_identity,
                )
            }
            Command::Asset {
                identifier_field, ..
            } => {
                // Asset command: pass through all data, asset view building happens in post-processing
                if let Some(field) = identifier_field {
                    let field_escaped = escape_identifier(field);
                    Ok(format!("  SELECT *, {} FROM {}", field_escaped, source))
                } else {
                    Ok(format!("  SELECT * FROM {}", source))
                }
            }
            Command::Cloud { .. } => {
                // Cloud command: pass through all data, cloud view building happens in post-processing
                Ok(format!("  SELECT * FROM {}", source))
            }
            Command::Baseline { .. } => {
                // Baseline command (NAN-1868): pass through; the initial fetch is
                // only for entity detection (the literal-entity fast-path skips it
                // entirely). `build_baseline_view` re-queries in post-processing.
                Ok(format!("  SELECT * FROM {}", source))
            }
            Command::Lateral { .. } => {
                // Lateral command: pass through, lateral movement tracing happens in post-processing
                Ok(format!("  SELECT * FROM {}", source))
            }
            Command::Ai { .. } => {
                // AI command: pass through all data, LLM enrichment happens in post-processing
                Ok(format!("  SELECT * FROM {}", source))
            }
            Command::Output { .. } => {
                // Output command: pass through (write-back is a no-op in query execution)
                Ok(format!("  SELECT * FROM {}", source))
            }
            Command::Services
            | Command::Service { .. }
            | Command::Trace { .. }
            | Command::Metric { .. }
            // NAN-1580 STAGE2: `retro` is a terminal page directive like the
            // command-page set — it short-circuits in the search service (the
            // /api/search marker carries the parsed retro request) and never
            // reaches real codegen. Reaching this arm means it appeared
            // mid-pipeline, which is rejected the same way.
            | Command::Retro { .. } => {
                // Command-page directives are PAGE directives, not data
                // transforms. As the terminal command they short-circuit in the
                // search service (NAN-1560) and never reach codegen. Reaching
                // this arm means the directive appeared MID-pipeline (e.g.
                // `… | service x | stats count`); a silent `SELECT *` pass-through
                // there would scan logs and ignore the directive, so reject it
                // and surface a 400 instead of a misleading full-table scan.
                // Name the actual command so the message is actionable.
                let name = match cmd {
                    Command::Services => "services",
                    Command::Service { .. } => "service",
                    Command::Trace { .. } => "trace",
                    Command::Metric { .. } => "metric",
                    Command::Retro { .. } => "retro",
                    _ => "command-page",
                };
                Err(SqlGenError::InvalidQuery(format!(
                    "`{name}` opens a page and must be the last command — it can't be \
                     followed by other commands. Remove everything after `| {name}`."
                )))
            }
        }
    }
}

/// NAN-1711 / audit D15 (defensive): true when the injected canonical bounds
/// aliases (`_first_seen`/`_last_seen`) would collide with the top/rare ranked
/// field's (or a by-field's) OUTPUT name — e.g. `… | top _first_seen`. Emitting
/// both would be ClickHouse MULTIPLE_EXPRESSIONS_FOR_ALIAS, erroring the rule
/// every cycle (the D3 failure class); skipping injection just degrades that
/// (pathological) rule's finding dedup to the content-hash fallback.
fn top_rare_bounds_alias_collision(
    field: &str,
    by_fields: &[String],
    generator: &ClickHouseSqlGenerator,
) -> bool {
    const CANONICAL: [&str; 2] = ["_first_seen", "_last_seen"];
    CANONICAL.contains(&by_field_output_name(field, generator))
        || by_fields
            .iter()
            .any(|b| CANONICAL.contains(&by_field_output_name(b, generator)))
}
