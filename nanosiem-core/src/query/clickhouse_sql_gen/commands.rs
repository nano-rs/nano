// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command SQL generation
//!
//! Contains `generate_command_sql_inner` with its match statement dispatching
//! to simple inline arms and complex helper methods in `commands_advanced`.

use super::eval_functions::eval_expression_to_sql;
use super::helpers::*;
use super::ClickHouseSqlGenerator;
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
    ) -> Result<String, SqlGenError> {
        // Whether the raw `timestamp` column still exists at this pipeline stage:
        // false after an aggregating command (stats/timechart/top/...) or after a
        // table/fields projection that dropped it. tail/reverse branch on this.
        let timestamp_available = !aggregated
            && match available_columns {
                None => true,
                Some(cols) => cols.contains("timestamp"),
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
                        } else {
                            // Regular field - normalize (e.g., _time -> timestamp)
                            let normalized_field = normalize_field_name(&sf.field);
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
                    // presented oldest-first. Unchanged behavior.
                    Ok(format!(
                        "  SELECT * FROM (\n    SELECT * FROM {}\n    ORDER BY timestamp DESC\n    LIMIT {}\n  )\n  ORDER BY timestamp ASC",
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
                            // Expand wildcard to matching explicit columns (no aliases for expanded fields)
                            super::expand_wildcard_pattern(&f.name)
                                .into_iter()
                                .map(|col| (col, None))
                                .collect::<Vec<_>>()
                        } else {
                            vec![(f.name.clone(), f.alias.clone())]
                        }
                    })
                    .collect();

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
            Command::Lookup {
                table_name,
                key_field,
                output_fields,
                case_insensitive,
            } => {
                // Generate a LEFT JOIN with the lookup table
                // Lookup tables are stored as lookup_<table_name> in ClickHouse
                let lookup_table = format!("lookup_{}", table_name);

                // Build the join condition
                let join_condition = if *case_insensitive {
                    format!(
                        "lower(main.{}) = lower(lkp.{})",
                        escape_identifier(key_field),
                        escape_identifier(key_field)
                    )
                } else {
                    format!(
                        "main.{} = lkp.{}",
                        escape_identifier(key_field),
                        escape_identifier(key_field)
                    )
                };

                // Select fields from lookup
                let lookup_fields = match output_fields {
                    Some(fields) => fields
                        .iter()
                        .map(|f| format!("lkp.{}", escape_identifier(f)))
                        .collect::<Vec<_>>()
                        .join(", "),
                    None => "lkp.*".to_string(),
                };

                Ok(format!(
                    "  SELECT main.*, {} FROM {} AS main\n  LEFT JOIN {} AS lkp ON {}",
                    lookup_fields, source, lookup_table, join_condition
                ))
            }
            Command::Eval { assignments } => {
                let mut select_parts = vec!["*".to_string()];

                for assignment in assignments {
                    let expr_sql = eval_expression_to_sql(self, &assignment.expression)?;
                    select_parts.push(format!("{} AS {}", expr_sql, assignment.field));
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
                // Normalize and escape field names
                let partition_fields: Vec<String> = fields
                    .iter()
                    .map(|f| escape_identifier(normalize_field_name(f)))
                    .collect();
                let partition_by = partition_fields.join(", ");

                // ClickHouse uses LIMIT 1 BY for deduplication
                Ok(format!(
                    "  SELECT * FROM {}\n  ORDER BY {}, timestamp\n  LIMIT 1 BY {}",
                    source, partition_by, partition_by
                ))
            }
            Command::Bin {
                span,
                field,
                alias,
                window_type,
            } => {
                match span {
                    BinSpan::Time(duration) => {
                        // Generate ClickHouse SQL for time-based bin command
                        // Map _time (PPL convention) to timestamp (ClickHouse column)
                        let field_name = match field.as_deref() {
                            Some("_time") | None => "timestamp",
                            Some(f) => f,
                        };
                        // Determine alias:
                        // - If alias provided, use it
                        // - If field was explicitly specified, use field name (in-place modification)
                        // - If no field specified (default timestamp), use "time_bucket"
                        let alias_name = alias.as_deref().unwrap_or_else(|| {
                            if field.is_some() {
                                field_name
                            } else {
                                "time_bucket"
                            }
                        });
                        let span_seconds = duration.as_secs();

                        match window_type {
                            WindowType::Tumbling => {
                                // Standard tumbling window - non-overlapping fixed windows
                                let time_bucket_expr = self.generate_time_bucket(duration);

                                // Replace "timestamp" with the actual field name if different
                                let bucket_expr = if field_name != "timestamp" {
                                    time_bucket_expr.replace("timestamp", field_name)
                                } else {
                                    time_bucket_expr
                                };

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
                            WindowType::Hop { advance } => {
                                // Hop window - overlapping windows that advance by a fixed interval
                                // Each event belongs to multiple windows: span/advance windows
                                let advance_seconds = advance.as_secs();
                                let num_windows = (span_seconds / advance_seconds) as i64;

                                // Generate array of window offsets: [0, -advance, -2*advance, ...]
                                // Then ARRAY JOIN to create one row per window the event belongs to
                                Ok(format!(
                                    "  SELECT * EXCEPT ({field}), \
                                    toDateTime(toInt64(toDateTime({field})) - toInt64(toDateTime({field})) % {advance} + window_offset) AS {alias}, \
                                    toDateTime(toInt64(toDateTime({field})) - toInt64(toDateTime({field})) % {advance} + window_offset + {span}) AS {alias}_end \
                                    FROM {source} \
                                    ARRAY JOIN arrayMap(x -> -x * {advance}, range(0, {num_windows})) AS window_offset",
                                    field = escape_identifier(field_name),
                                    advance = advance_seconds,
                                    span = span_seconds,
                                    alias = escape_identifier(alias_name),
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
                                    field = escape_identifier(field_name),
                                    span = span_seconds,
                                    alias = escape_identifier(alias_name),
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
                    .flat_map(|f| super::expand_wildcard_pattern(f))
                    .collect();

                if *keep {
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
            } => {
                // Normalize field name for consistent output
                let normalized_field = normalize_field_name(field);
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

                let mut group_by_parts = vec![field_group_by.clone()];
                for by in by_fields {
                    // Skip "count" and "percent" as by_fields - they're reserved output columns
                    let by_lower = by.to_lowercase();
                    if by_lower == "count" || by_lower == "percent" {
                        continue;
                    }
                    let normalized_by = normalize_field_name(by);
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
            } => {
                // Normalize field name for consistent output
                let normalized_field = normalize_field_name(field);
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

                let mut group_by_parts = vec![field_group_by.clone()];
                for by in by_fields {
                    // Skip "count" and "percent" as by_fields - they're reserved output columns
                    let by_lower = by.to_lowercase();
                    if by_lower == "count" || by_lower == "percent" {
                        continue;
                    }
                    let normalized_by = normalize_field_name(by);
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
                startswith: _,
                endswith: _,
                maxspan,
                maxevents,
            } => {
                // Generate SQL for transaction command - event grouping
                let group_by_fields: Vec<String> = fields
                    .iter()
                    .map(|f| {
                        let normalized = normalize_field_name(f);
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

                let having_clause = match (maxspan, maxevents) {
                    (Some(d), Some(n)) => {
                        let secs = d.as_secs();
                        format!("\n  HAVING count() <= {} AND dateDiff('second', min(timestamp), max(timestamp)) <= {}", n, secs)
                    }
                    (Some(d), None) => {
                        let secs = d.as_secs();
                        format!(
                            "\n  HAVING dateDiff('second', min(timestamp), max(timestamp)) <= {}",
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
                Ok(format!(
                    "  SELECT \n    {fields},\n    count() AS eventcount,\n    dateDiff('second', min(timestamp), max(timestamp)) AS duration,\n    min(timestamp) AS transaction_start,\n    max(timestamp) AS transaction_end,\n    groupArray({limit})(message) AS _raw_events\n  FROM {source}\n  GROUP BY {group_by}{having}\n  ORDER BY transaction_start DESC",
                    fields = group_by_fields.join(", "),
                    limit = array_limit,
                    source = source,
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
                let input_field = input.as_deref().unwrap_or("metadata");
                let output_field = output.as_deref().unwrap_or("spath_result");

                match path {
                    Some(json_path) => Ok(format!(
                        "  SELECT *, JSONExtractString({}, '{}') AS {} FROM {}",
                        escape_identifier(input_field),
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
                    // Raw events: reverse the default newest-first order → oldest-first. Unchanged.
                    Ok(format!(
                        "  SELECT * FROM {}\n  ORDER BY timestamp ASC",
                        source
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
            } => self.generate_eventstats_sql(source, aggregations, group_by),
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
            } => self.generate_anomaly_sql(source, field, by_fields, *threshold, method),
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
                // Tree command: pass through all data, tree building happens in post-processing
                let mut required_fields = vec![
                    escape_identifier(parent_field),
                    escape_identifier(child_field),
                    escape_identifier(label_field),
                ];
                if let Some(detail) = detail_field {
                    required_fields.push(escape_identifier(detail));
                }
                if let Some(prevalence) = prevalence_field {
                    required_fields.push(escape_identifier(prevalence));
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
                self.generate_resolve_identity_sql(source, field, max_age, available_columns)
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
        }
    }
}
