// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command SQL generation for piped query commands
//!
//! Converts Command AST nodes into PostgreSQL SQL for each piped command
//! (stats, where, sort, head, eval, table, etc.).

use super::eval_functions::eval_expression_to_sql;
use super::field_utils::*;
use super::SqlGenError;
use crate::query::ast::*;

impl super::SqlGenerator {
    /// Generate SQL for a command
    pub(super) fn generate_command_sql(
        &self,
        source: &str,
        cmd: &Command,
    ) -> Result<String, SqlGenError> {
        match cmd {
            Command::Stats {
                aggregations,
                group_by,
            } => self.generate_stats_sql(source, aggregations, group_by.as_deref()),
            Command::Chart {
                aggregations,
                group_by,
            } => {
                // Chart is just an alias for stats
                self.generate_stats_sql(source, aggregations, group_by.as_deref())
            }
            Command::StreamStats {
                aggregations,
                group_by,
                current,
                window,
            } => {
                // Generate PostgreSQL SQL for streamstats command using window functions
                let frame_end = if *current {
                    "CURRENT ROW"
                } else {
                    "1 PRECEDING"
                };
                let frame_start = match window {
                    Some(n) => format!("{} PRECEDING", n),
                    None => "UNBOUNDED PRECEDING".to_string(),
                };
                let frame_spec = format!("ROWS BETWEEN {} AND {}", frame_start, frame_end);

                let partition_clause = match group_by {
                    Some(fields) => {
                        let partition_fields: Vec<String> =
                            fields.iter().map(|f| escape_identifier(f)).collect();
                        format!("PARTITION BY {} ", partition_fields.join(", "))
                    }
                    None => String::new(),
                };

                let window_exprs: Vec<String> = aggregations
                    .iter()
                    .map(|agg| {
                        let field_expr = agg
                            .field
                            .as_ref()
                            .map(|f| escape_identifier(f))
                            .unwrap_or_else(|| "*".to_string());

                        let window_func = match agg.func {
                            AggFunc::Count => format!(
                                "count({}) OVER ({}ORDER BY timestamp {})",
                                if field_expr == "*" { "*" } else { &field_expr },
                                partition_clause,
                                frame_spec
                            ),
                            AggFunc::Sum => format!(
                                "sum({}) OVER ({}ORDER BY timestamp {})",
                                field_expr, partition_clause, frame_spec
                            ),
                            AggFunc::Avg => format!(
                                "avg({}) OVER ({}ORDER BY timestamp {})",
                                field_expr, partition_clause, frame_spec
                            ),
                            AggFunc::Min => format!(
                                "min({}) OVER ({}ORDER BY timestamp {})",
                                field_expr, partition_clause, frame_spec
                            ),
                            AggFunc::Max => format!(
                                "max({}) OVER ({}ORDER BY timestamp {})",
                                field_expr, partition_clause, frame_spec
                            ),
                            AggFunc::Last => {
                                if !*current {
                                    format!(
                                        "lag({}, 1) OVER ({}ORDER BY timestamp)",
                                        field_expr, partition_clause
                                    )
                                } else {
                                    format!(
                                        "last_value({}) OVER ({}ORDER BY timestamp {})",
                                        field_expr, partition_clause, frame_spec
                                    )
                                }
                            }
                            AggFunc::First => format!(
                                "first_value({}) OVER ({}ORDER BY timestamp {})",
                                field_expr, partition_clause, frame_spec
                            ),
                            _ => format!(
                                "count({}) OVER ({}ORDER BY timestamp {})",
                                field_expr, partition_clause, frame_spec
                            ),
                        };

                        let alias = agg.alias.as_ref().cloned().unwrap_or_else(|| {
                            let func_name = match agg.func {
                                AggFunc::Count => "count",
                                AggFunc::Sum => "sum",
                                AggFunc::Avg => "avg",
                                AggFunc::Min => "min",
                                AggFunc::Max => "max",
                                AggFunc::First => "first",
                                AggFunc::Last => "last",
                                _ => "agg",
                            };
                            match &agg.field {
                                Some(f) => format!("{}_{}", func_name, f),
                                None => func_name.to_string(),
                            }
                        });

                        format!("{} AS {}", window_func, escape_identifier(&alias))
                    })
                    .collect();

                Ok(format!(
                    "  SELECT *, {} FROM {}",
                    window_exprs.join(", "),
                    source
                ))
            }
            Command::Where { condition } => {
                // For where clauses after other commands (like stats),
                // treat all fields as direct column references
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
                        // After aggregation, fields are direct column references, not JSONB paths
                        let field_expr = escape_identifier(&sf.field);
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
                // For tail, we need to reverse sort, limit, then reverse again
                // This is a simplified version - assumes there's a timestamp or id to sort by
                Ok(format!(
                    "  SELECT * FROM (\n    SELECT * FROM {}\n    ORDER BY timestamp DESC\n    LIMIT {}\n  ) sub\n  ORDER BY timestamp ASC",
                    source, count
                ))
            }
            Command::Timechart {
                span,
                aggregations,
                split_by,
                ..
            } => self.generate_timechart_sql(source, span, aggregations, split_by),
            Command::Table { fields } => {
                // Check for wildcard: table *
                if fields.len() == 1 && fields[0].name == "*" {
                    // Instead of SELECT *, we'll select all fields but use CASE expressions
                    // to dynamically filter out empty/null/zero values
                    let always_include =
                        vec!["id", "timestamp", "message", "source_type", "ingest_time"];

                    // Fields that should be included only if not empty/null/zero
                    let conditional_fields = vec![
                        // Entity fields
                        ("src_ip", "src_ip != ''"),
                        ("dest_ip", "dest_ip != ''"),
                        ("src_host", "src_host != ''"),
                        ("dest_host", "dest_host != ''"),
                        // Network fields
                        ("src_port", "src_port != 0"),
                        ("dest_port", "dest_port != 0"),
                        ("protocol", "protocol != ''"),
                        ("bytes_in", "bytes_in != 0"),
                        ("bytes_out", "bytes_out != 0"),
                        // User/Action fields
                        ("user", "\"user\" != ''"), // user is a reserved word in PostgreSQL
                        ("action", "action != ''"),
                        ("status", "status != ''"),
                        // Auth fields
                        ("auth_type", "auth_type != ''"),
                        ("auth_result", "auth_result != ''"),
                        ("session_id", "session_id != ''"),
                        // Process fields
                        ("process_name", "process_name != ''"),
                        ("process_id", "process_id != 0"),
                        ("command_line", "command_line != ''"),
                        ("parent_process_name", "parent_process_name != ''"),
                        ("parent_command_line", "parent_command_line != ''"),
                        // File fields
                        ("file_path", "file_path != ''"),
                        ("file_name", "file_name != ''"),
                        ("file_hash", "file_hash != ''"),
                        ("file_action", "file_action != ''"),
                        // HTTP fields
                        ("user_agent", "user_agent != ''"),
                    ];

                    let mut select_fields = always_include
                        .iter()
                        .map(|f| {
                            if *f == "user" {
                                "\"user\"".to_string()
                            } else {
                                f.to_string()
                            }
                        })
                        .collect::<Vec<_>>();

                    // Add conditional fields using CASE expressions
                    for (field, condition) in conditional_fields {
                        let field_ref = if field == "user" { "\"user\"" } else { field };
                        select_fields.push(format!(
                            "CASE WHEN {} THEN {} ELSE NULL END AS {}",
                            condition, field_ref, field
                        ));
                    }

                    return Ok(format!(
                        "  SELECT {} FROM {}",
                        select_fields.join(", "),
                        source
                    ));
                }

                let field_list = fields
                    .iter()
                    .map(|f| {
                        let (field_expr, needs_alias) = field_to_sql_expr(&f.name);

                        match &f.alias {
                            Some(alias) => {
                                format!("{} AS {}", field_expr, escape_identifier(alias))
                            }
                            None => {
                                if needs_alias {
                                    // Use the field name as alias for metadata fields
                                    format!("{} AS {}", field_expr, escape_identifier(&f.name))
                                } else {
                                    field_expr
                                }
                            }
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                Ok(format!("  SELECT {} FROM {}", field_list, source))
            }
            Command::Rename { mappings } => {
                // Generate SELECT with renamed fields
                // We select renamed fields with aliases, plus all other columns
                let rename_exprs: Vec<String> = mappings
                    .iter()
                    .map(|m| {
                        let (from_expr, _) = field_to_sql_expr(&m.from);
                        format!("{} AS {}", from_expr, escape_identifier(&m.to))
                    })
                    .collect();

                let renamed_fields = rename_exprs.join(", ");

                // Note: This approach adds renamed columns alongside originals.
                // A more sophisticated approach would exclude the original columns,
                // but that requires knowing the schema at query time.
                Ok(format!("  SELECT *, {} FROM {}", renamed_fields, source))
            }
            Command::Lookup {
                table_name,
                key_field,
                output_fields,
                case_insensitive,
            } => {
                // Generate a LEFT JOIN with the lookup table
                // Lookup tables are stored as lookup_<table_name>
                let lookup_table = format!("lookup_{}", table_name);

                // Build the join condition
                let join_condition = if *case_insensitive {
                    format!(
                        "lower(main.\"{}\") = lower(lkp.\"{}\")",
                        key_field, key_field
                    )
                } else {
                    format!("main.\"{}\" = lkp.\"{}\"", key_field, key_field)
                };

                // Select fields from lookup
                let lookup_fields = match output_fields {
                    Some(fields) => fields
                        .iter()
                        .map(|f| format!("lkp.\"{}\"", f))
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
                // Generate SQL for eval command - add calculated fields
                let mut select_parts = vec!["*".to_string()]; // Include all existing fields

                for assignment in assignments {
                    let expr_sql = eval_expression_to_sql(&assignment.expression)?;
                    select_parts.push(format!("{} AS {}", expr_sql, assignment.field));
                }

                Ok(format!(
                    "  SELECT {} FROM {}",
                    select_parts.join(", "),
                    source
                ))
            }
            Command::Dedup { fields, keep_first } => {
                // Generate SQL for dedup command using ROW_NUMBER() window function
                let partition_by = fields.join(", ");
                let order_clause = if *keep_first {
                    "ORDER BY timestamp ASC" // Keep first occurrence
                } else {
                    "ORDER BY timestamp DESC" // Keep last occurrence
                };

                // Select all columns except the rn (row number) field
                Ok(format!(
                    "  SELECT id, timestamp, source_type, src_ip, dest_ip, src_host, dest_host, src_user, dest_user, \"user\", action, status, src_port, dest_port, protocol, bytes_in, bytes_out, auth_type, auth_result, session_id, process_name, process_id, process, parent_process_name, parent_process, file_path, file_name, file_hash, file_action, message, metadata FROM (\n    SELECT *, ROW_NUMBER() OVER (PARTITION BY {} {}) as rn\n    FROM {}\n  ) ranked WHERE rn = 1",
                    partition_by, order_clause, source
                ))
            }
            Command::Bin {
                span,
                field,
                alias,
                window_type,
            } => {
                // PostgreSQL only supports tumbling windows
                if !matches!(window_type, WindowType::Tumbling) {
                    return Err(SqlGenError::UnsupportedOperation(
                        "Hop and sliding windows are only supported on ClickHouse backend".into(),
                    ));
                }

                match span {
                    BinSpan::Time(duration) => {
                        // Generate SQL for time-based bin command
                        let field_name = field.as_deref().unwrap_or("timestamp");
                        let alias_name = alias.as_deref().unwrap_or("time_bucket");
                        let interval = duration_to_interval(duration);

                        Ok(format!(
                            "  SELECT *, date_trunc('{}', {}) AS {} FROM {}",
                            interval,
                            field_name,
                            escape_identifier(alias_name),
                            source
                        ))
                    }
                    BinSpan::Numeric(bin_size) => {
                        // Generate SQL for numeric bin command
                        let field_name = field.as_ref().ok_or_else(|| {
                            SqlGenError::InvalidQuery(
                                "Field is required for numeric binning".to_string(),
                            )
                        })?;
                        let alias_name = alias.as_deref().unwrap_or(field_name);

                        Ok(format!(
                            "  SELECT *, floor({} / {}) * {} AS {} FROM {}",
                            escape_identifier(field_name),
                            bin_size,
                            bin_size,
                            escape_identifier(alias_name),
                            source
                        ))
                    }
                }
            }
            Command::Rex {
                field,
                pattern,
                mode,
            } => {
                // Generate SQL for rex command - extract fields using regex
                let source_field = field.as_deref().unwrap_or("message");

                match mode {
                    RexMode::Extract => {
                        // Extract named capture groups as new columns
                        // PostgreSQL uses REGEXP_MATCHES with named groups
                        // For simplicity, we pass through and handle at runtime
                        Ok(format!(
                            "  SELECT *, REGEXP_MATCHES({}::text, '{}', 'g') AS rex_matches FROM {}",
                            escape_identifier(source_field), escape_string(pattern), source
                        ))
                    }
                    RexMode::Sed {
                        pattern: sed_pattern,
                        replacement,
                    } => {
                        // Sed mode - replace pattern with replacement
                        Ok(format!(
                            "  SELECT *, REGEXP_REPLACE({}::text, '{}', '{}', 'g') AS rex_result FROM {}",
                            escape_identifier(source_field), escape_string(sed_pattern), escape_string(replacement), source
                        ))
                    }
                }
            }
            Command::Fields { fields, keep } => {
                // Generate SQL for fields command - include or exclude fields
                if *keep {
                    // Include only these fields
                    let field_list = fields
                        .iter()
                        .map(|f| {
                            let (expr, needs_alias) = field_to_sql_expr(f);
                            if needs_alias {
                                format!("{} AS {}", expr, escape_identifier(f))
                            } else {
                                expr
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    Ok(format!("  SELECT {} FROM {}", field_list, source))
                } else {
                    // Exclude these fields - select all except listed
                    // This is tricky in SQL, we'll select * and note the exclusions
                    // For now, we pass through and handle at runtime
                    Ok(format!("  SELECT * FROM {}", source))
                }
            }
            Command::Top {
                field,
                limit,
                by_fields,
                show_count,
                show_percent,
            } => {
                // Generate SQL for top command - find most common values
                let (field_expr, needs_alias) = field_to_sql_expr(field);
                let field_select = if needs_alias {
                    format!("{} AS {}", field_expr, escape_identifier(field))
                } else {
                    field_expr.clone()
                };

                let mut select_parts = vec![field_select];
                if *show_count {
                    select_parts.push("COUNT(*) AS count".to_string());
                }
                if *show_percent {
                    select_parts.push(
                        "ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS percent".to_string(),
                    );
                }

                let mut group_by_parts = vec![field_expr.clone()];
                for by in by_fields {
                    let (by_expr, by_needs_alias) = field_to_sql_expr(by);
                    let by_select = if by_needs_alias {
                        format!("{} AS {}", by_expr, escape_identifier(by))
                    } else {
                        by_expr.clone()
                    };
                    select_parts.insert(0, by_select);
                    group_by_parts.insert(0, by_expr);
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
                // Generate SQL for rare command - find least common values
                let (field_expr, needs_alias) = field_to_sql_expr(field);
                let field_select = if needs_alias {
                    format!("{} AS {}", field_expr, escape_identifier(field))
                } else {
                    field_expr.clone()
                };

                let mut select_parts = vec![field_select];
                if *show_count {
                    select_parts.push("COUNT(*) AS count".to_string());
                }
                if *show_percent {
                    select_parts.push(
                        "ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS percent".to_string(),
                    );
                }

                let mut group_by_parts = vec![field_expr.clone()];
                for by in by_fields {
                    let (by_expr, by_needs_alias) = field_to_sql_expr(by);
                    let by_select = if by_needs_alias {
                        format!("{} AS {}", by_expr, escape_identifier(by))
                    } else {
                        by_expr.clone()
                    };
                    select_parts.insert(0, by_select);
                    group_by_parts.insert(0, by_expr);
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
                // Groups events by field(s) and returns one row per transaction with:
                // - All grouping fields
                // - eventcount: number of events in the transaction
                // - duration: time span of the transaction in seconds
                // - transaction_start: earliest timestamp
                // - transaction_end: latest timestamp
                // - _raw: concatenated raw content from all events

                let group_by_fields: Vec<String> = fields
                    .iter()
                    .map(|f| {
                        let (expr, needs_alias) = field_to_sql_expr(f);
                        if needs_alias {
                            format!("{} AS {}", expr, escape_identifier(f))
                        } else {
                            expr
                        }
                    })
                    .collect();

                let group_by_refs: Vec<String> = fields
                    .iter()
                    .map(|f| {
                        let (expr, _) = field_to_sql_expr(f);
                        expr
                    })
                    .collect();

                let having_clause = match (maxspan, maxevents) {
                    (Some(d), Some(n)) => {
                        let secs = d.as_secs();
                        format!("\n  HAVING COUNT(*) <= {} AND EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) <= {}", n, secs)
                    }
                    (Some(d), None) => {
                        let secs = d.as_secs();
                        format!("\n  HAVING EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) <= {}", secs)
                    }
                    (None, Some(n)) => {
                        format!("\n  HAVING COUNT(*) <= {}", n)
                    }
                    (None, None) => String::new(),
                };

                Ok(format!(
                    "  SELECT \n    {},\n    COUNT(*) AS eventcount,\n    EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) AS duration,\n    MIN(timestamp) AS transaction_start,\n    MAX(timestamp) AS transaction_end,\n    STRING_AGG(message, E'\\n' ORDER BY timestamp) AS _raw\n  FROM {}\n  GROUP BY {}{}\n  ORDER BY transaction_start DESC",
                    group_by_fields.join(", "),
                    source,
                    group_by_refs.join(", "),
                    having_clause
                ))
            }
            Command::Fillnull { value, fields } => {
                // Generate SQL for fillnull command - replace null values
                match fields {
                    Some(field_list) => {
                        let coalesce_exprs: Vec<String> = field_list
                            .iter()
                            .map(|f| {
                                let (expr, _) = field_to_sql_expr(f);
                                format!(
                                    "COALESCE({}::text, '{}') AS {}",
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
                    None => {
                        // Fill all fields - pass through for runtime handling
                        Ok(format!("  SELECT * FROM {}", source))
                    }
                }
            }
            Command::Mvexpand { field, limit } => {
                // Generate SQL for mvexpand command - expand multi-value fields
                let (field_expr, _) = field_to_sql_expr(field);
                let limit_clause = limit.map(|n| format!(" LIMIT {}", n)).unwrap_or_default();

                Ok(format!(
                    "  SELECT *, UNNEST({}) AS {} FROM {}{}",
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
                // Generate SQL for spath command - extract JSON fields
                let input_field = input.as_deref().unwrap_or("metadata");
                let output_field = output.as_deref().unwrap_or("spath_result");

                match path {
                    Some(json_path) => {
                        // Extract specific path
                        Ok(format!(
                            "  SELECT *, {}->>'{}' AS {} FROM {}",
                            escape_identifier(input_field),
                            escape_string(json_path),
                            escape_identifier(output_field),
                            source
                        ))
                    }
                    None => {
                        // Auto-extract all JSON fields - pass through for runtime
                        Ok(format!("  SELECT * FROM {}", source))
                    }
                }
            }
            Command::Append { .. } => {
                // Append is handled in generate_command_cte with proper UNION ALL
                // This branch should not be reached in normal CTE generation
                Err(SqlGenError::UnsupportedOperation(
                    "Append should be handled via CTE generation".to_string(),
                ))
            }
            Command::Join { .. } => {
                // Join is handled in generate_command_cte with proper JOIN SQL
                // This branch should not be reached in normal CTE generation
                Err(SqlGenError::UnsupportedOperation(
                    "Join should be handled via CTE generation".to_string(),
                ))
            }
            Command::Format {
                maxresults,
                row_sep: _,
                col_sep: _,
            } => {
                // Format is typically handled at runtime to format results as a string
                // For SQL, we just limit results if specified
                match maxresults {
                    Some(n) => Ok(format!("  SELECT * FROM {} LIMIT {}", source, n)),
                    None => Ok(format!("  SELECT * FROM {}", source)),
                }
            }
            Command::Return { count, fields } => {
                // Return specific field values - used in subsearches
                let field_list = fields
                    .iter()
                    .map(|f| {
                        let (expr, needs_alias) = field_to_sql_expr(f);
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
                // Generate SQL for risk command - adds risk_score, risk_entity, risk_factors columns
                // Supports both literal scores and dynamic expressions (field references, arithmetic, conditionals)
                // For additive scoring with multiple risk commands, we check if risk_score already exists
                // and add to it, otherwise we start fresh

                // Build the entity expression - use specified field or default to 'unknown'
                let entity_expr = match entity_field {
                    Some(field) => {
                        let (expr, _) = field_to_sql_expr(field);
                        format!("COALESCE({}::text, 'unknown')", expr)
                    }
                    None => "'unknown'".to_string(),
                };

                // Build the factor expression
                let factor_expr = match factor {
                    Some(expr) => {
                        format!("({})", eval_expression_to_sql(expr)?)
                    }
                    None => "'risk_assigned'".to_string(),
                };

                // Build the score expression
                // For literal scores, use the value directly
                // For dynamic expressions, convert to SQL and clamp to 0-100
                let (raw_score_expr, score_expr) = match score {
                    RiskScoreExpr::Literal(s) => {
                        // Literal score - use directly, clamped to 0-100
                        let clamped = (*s).clamp(0, 100);
                        (clamped.to_string(), clamped.to_string())
                    }
                    RiskScoreExpr::Dynamic(expr) => {
                        // Dynamic expression - convert to SQL and clamp the result to 0-100
                        let expr_sql = eval_expression_to_sql(expr)?;
                        let clamped = format!("LEAST(100, GREATEST(0, ({})::int))", expr_sql);
                        (clamped.clone(), clamped)
                    }
                };

                // Build weight expression if provided
                let weight_clause = match weight {
                    Some(w) => format!(",\n    {} AS risk_weight", w),
                    None => String::new(),
                };

                // Output both raw_risk_score (the value from this command, for detection service)
                // and risk_score (cumulative clamped score)
                Ok(format!(
                    "  SELECT *,\n    {} AS raw_risk_score,\n    {} AS risk_score,\n    {} AS risk_entity,\n    ARRAY[{}] AS risk_factors{}\n  FROM {}",
                    raw_score_expr, score_expr, entity_expr, factor_expr, weight_clause, source
                ))
            }
            Command::Prevalence { .. } => {
                // Prevalence command is handled as post-processing by the search service
                // It doesn't modify the SQL query - results are filtered/enriched after execution
                // Just pass through the source query unchanged
                Ok(format!("  SELECT * FROM {}", source))
            }
            Command::Sample { limit } => {
                // Random sampling using ORDER BY random() LIMIT N
                Ok(format!(
                    "  SELECT * FROM {}\n  ORDER BY random()\n  LIMIT {}",
                    source, limit
                ))
            }
            Command::Reverse => {
                // Reverse event order (ascending by timestamp)
                Ok(format!(
                    "  SELECT * FROM {}\n  ORDER BY timestamp ASC",
                    source
                ))
            }
            Command::EventStats {
                aggregations,
                group_by,
            } => {
                // EventStats: calculate aggregates using window functions while preserving all rows
                // This is similar to streamstats but calculates over the entire partition
                let partition_clause = match group_by {
                    Some(fields) => {
                        let partition_fields: Vec<String> =
                            fields.iter().map(|f| escape_identifier(f)).collect();
                        format!("PARTITION BY {}", partition_fields.join(", "))
                    }
                    None => String::new(),
                };

                let window_exprs: Vec<String> = aggregations
                    .iter()
                    .map(|agg| {
                        let field_expr = agg
                            .field
                            .as_ref()
                            .map(|f| escape_identifier(f))
                            .unwrap_or_else(|| "*".to_string());

                        let window_func = match agg.func {
                            AggFunc::Count => format!(
                                "count({}) OVER ({})",
                                if field_expr == "*" { "*" } else { &field_expr },
                                partition_clause
                            ),
                            AggFunc::Dc => format!(
                                "count(DISTINCT {}) OVER ({})",
                                field_expr, partition_clause
                            ),
                            AggFunc::Sum => {
                                format!("sum({}) OVER ({})", field_expr, partition_clause)
                            }
                            AggFunc::Avg => {
                                format!("avg({}) OVER ({})", field_expr, partition_clause)
                            }
                            AggFunc::Min => {
                                format!("min({}) OVER ({})", field_expr, partition_clause)
                            }
                            AggFunc::Max => {
                                format!("max({}) OVER ({})", field_expr, partition_clause)
                            }
                            _ => format!("count({}) OVER ({})", field_expr, partition_clause),
                        };

                        let alias = agg.alias.as_ref().cloned().unwrap_or_else(|| {
                            let func_name = match agg.func {
                                AggFunc::Count => "count",
                                AggFunc::Dc => "dc",
                                AggFunc::Sum => "sum",
                                AggFunc::Avg => "avg",
                                AggFunc::Min => "min",
                                AggFunc::Max => "max",
                                _ => "agg",
                            };
                            match &agg.field {
                                Some(f) => format!("{}_{}", func_name, f),
                                None => func_name.to_string(),
                            }
                        });

                        format!("{} AS {}", window_func, escape_identifier(&alias))
                    })
                    .collect();

                Ok(format!(
                    "  SELECT *, {} FROM {}",
                    window_exprs.join(", "),
                    source
                ))
            }
            Command::Sequence { .. } => {
                // PostgreSQL doesn't have native sequence matching like ClickHouse
                // This would require complex window functions or procedural logic
                Err(SqlGenError::UnsupportedOperation(
                    "Sequence command is only supported on ClickHouse backend".into(),
                ))
            }
            Command::Funnel { .. } => {
                // PostgreSQL doesn't have windowFunnel
                Err(SqlGenError::UnsupportedOperation(
                    "Funnel command is only supported on ClickHouse backend".into(),
                ))
            }
            Command::Anomaly {
                field: _,
                by_fields: _,
                threshold: _,
                method: _,
            } => {
                // PostgreSQL can do this with window functions but implementation would be different
                Err(SqlGenError::UnsupportedOperation(
                    "Anomaly command is only supported on ClickHouse backend".into(),
                ))
            }
            // InputLookup is handled in post-processing (Rust code), not SQL
            // Just pass through the source unchanged
            Command::InputLookup { .. } => Ok(format!("SELECT * FROM {}", source)),
            // Tree is handled in post-processing (Rust code), not SQL
            // Just pass through the source unchanged
            Command::Tree { .. } => Ok(format!("SELECT * FROM {}", source)),
            // ResolveIdentity uses ClickHouse ASOF JOIN - not supported in generic SQL
            // Just pass through the source unchanged (ClickHouse generator handles it)
            Command::ResolveIdentity { .. } => Ok(format!("SELECT * FROM {}", source)),
            // Asset is handled in post-processing (Rust code), not SQL
            // Just pass through the source unchanged
            Command::Asset { .. } => Ok(format!("SELECT * FROM {}", source)),
            // Cloud is handled in post-processing (Rust code), not SQL
            Command::Cloud { .. } => Ok(format!("SELECT * FROM {}", source)),
            // Lateral is handled in post-processing (ClickHouse re-queries), not SQL
            Command::Lateral { .. } => Ok(format!("SELECT * FROM {}", source)),
            // AI is handled in post-processing (LLM call), not SQL
            Command::Ai { .. } => Ok(format!("SELECT * FROM {}", source)),
            // Output is a sink directive, no SQL transformation needed
            Command::Output { .. } => Ok(format!("SELECT * FROM {}", source)),
        }
    }
}
