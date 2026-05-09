// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query generation and CTE assembly
//!
//! Handles top-level query generation, CTE (Common Table Expression) assembly
//! for multi-stage piped queries, and subsearch SQL generation for join/append.

use super::field_utils::escape_string;
use super::{GeneratorContext, QueryStage, SqlGenError};
use crate::query::ast::*;
use std::fmt::Write;

impl super::SqlGenerator {
    /// Generate SQL from a Query AST with time range constraints
    pub fn generate(
        &self,
        query: &Query,
        time_range: &super::TimeRange,
    ) -> Result<String, SqlGenError> {
        let mut ctx = GeneratorContext::new(&self.table_name, time_range);
        self.generate_query(query, &mut ctx)
    }

    /// Generate SQL for a query, handling piped commands via CTEs
    fn generate_query(
        &self,
        query: &Query,
        ctx: &mut GeneratorContext,
    ) -> Result<String, SqlGenError> {
        // Collect all stages (search + commands)
        let stages = self.collect_stages(query);

        if stages.is_empty() {
            return Err(SqlGenError::EmptyQuery);
        }

        // Single stage - no CTEs needed
        if stages.len() == 1 {
            return self.generate_single_stage(&stages[0], ctx);
        }

        // Multiple stages - use CTEs
        self.generate_cte_query(&stages, ctx)
    }

    /// Collect all stages from a query (flattens nested Piped queries)
    pub(super) fn collect_stages<'a>(&self, query: &'a Query) -> Vec<QueryStage<'a>> {
        let mut stages = Vec::new();
        self.collect_stages_recursive(query, &mut stages);
        stages
    }

    fn collect_stages_recursive<'a>(&self, query: &'a Query, stages: &mut Vec<QueryStage<'a>>) {
        match query {
            Query::Search(expr) => {
                stages.push(QueryStage::Search(expr));
            }
            Query::Piped { source, command } => {
                self.collect_stages_recursive(source, stages);
                stages.push(QueryStage::Command(command));
            }
        }
    }

    /// Check if a search expression is a simple keyword search (can use BM25)
    pub(super) fn is_keyword_only(&self, expr: &SearchExpr) -> Option<String> {
        match expr {
            SearchExpr::Keyword(kw) if kw != "*" => Some(kw.clone()),
            _ => None,
        }
    }

    /// Generate SQL for a single-stage query (no CTEs)
    fn generate_single_stage(
        &self,
        stage: &QueryStage,
        ctx: &mut GeneratorContext,
    ) -> Result<String, SqlGenError> {
        match stage {
            QueryStage::Search(expr) => {
                // Check if this is a simple keyword search - use BM25
                if let Some(keyword) = self.is_keyword_only(expr) {
                    let escaped = escape_string(&keyword);
                    return Ok(format!(
                        "SELECT * FROM bm25_search_full('{}', '{}', '{}', 10000) ORDER BY timestamp DESC",
                        escaped,
                        ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                        ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f")
                    ));
                }

                // For complex expressions, use standard WHERE clause
                let where_clause = self.generate_search_expr(expr)?;
                Ok(format!(
                    "SELECT * FROM {} WHERE timestamp BETWEEN '{}' AND '{}' AND ({}) ORDER BY timestamp DESC",
                    ctx.table_name,
                    ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                    ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                    where_clause
                ))
            }
            QueryStage::Command(_) => Err(SqlGenError::UnsupportedOperation(
                "Command without search source".to_string(),
            )),
        }
    }

    /// Generate SQL with CTEs for multi-stage queries
    fn generate_cte_query(
        &self,
        stages: &[QueryStage],
        ctx: &mut GeneratorContext,
    ) -> Result<String, SqlGenError> {
        let mut sql = String::from("WITH ");
        let mut cte_parts = Vec::new();
        let mut last_stage_has_ordering = false;
        let mut has_aggregate_or_projection = false;

        for (i, stage) in stages.iter().enumerate() {
            let cte_name = format!("stage_{}", i);
            let cte_sql = match stage {
                QueryStage::Search(expr) => {
                    // Check if this is a simple keyword search - use BM25
                    if let Some(keyword) = self.is_keyword_only(expr) {
                        let escaped = escape_string(&keyword);
                        format!(
                            "{} AS (\n  SELECT * FROM bm25_search_full('{}', '{}', '{}', 10000)\n)",
                            cte_name,
                            escaped,
                            ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                            ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f")
                        )
                    } else {
                        let where_clause = self.generate_search_expr(expr)?;
                        format!(
                            "{} AS (\n  SELECT * FROM {}\n  WHERE timestamp BETWEEN '{}' AND '{}'\n    AND ({})\n)",
                            cte_name,
                            ctx.table_name,
                            ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                            ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                            where_clause
                        )
                    }
                }
                QueryStage::Command(cmd) => {
                    let prev_cte = format!("stage_{}", i - 1);
                    // Track commands that affect column availability or have their own ordering
                    match cmd {
                        Command::Sort { .. } | Command::Timechart { .. } | Command::Tail { .. } => {
                            if i == stages.len() - 1 {
                                last_stage_has_ordering = true;
                            }
                        }
                        Command::Stats { .. }
                        | Command::Table { .. }
                        | Command::Fields { keep: true, .. } => {
                            // Stats, Table, and Fields (include mode) commands may not include timestamp column,
                            // so we shouldn't add ORDER BY timestamp to any subsequent stage
                            has_aggregate_or_projection = true;
                        }
                        Command::Top { .. }
                        | Command::Rare { .. }
                        | Command::Return { .. }
                        | Command::Transaction { .. } => {
                            // These commands also produce aggregated/projected results
                            has_aggregate_or_projection = true;
                        }
                        _ => {}
                    }
                    self.generate_command_cte(&cte_name, &prev_cte, cmd, ctx)?
                }
            };
            cte_parts.push(cte_sql);
            ctx.current_stage = i;
        }

        sql.push_str(&cte_parts.join(",\n"));

        // Final SELECT from the last CTE
        // Add ORDER BY timestamp DESC unless:
        // - The last stage already has ordering
        // - Any stage was an aggregate/projection that may have removed timestamp
        let last_cte = format!("stage_{}", stages.len() - 1);
        if last_stage_has_ordering || has_aggregate_or_projection {
            write!(sql, "\nSELECT * FROM {}", last_cte).unwrap();
        } else {
            write!(sql, "\nSELECT * FROM {} ORDER BY timestamp DESC", last_cte).unwrap();
        }

        Ok(sql)
    }

    /// Generate a CTE for a command stage
    fn generate_command_cte(
        &self,
        cte_name: &str,
        source_cte: &str,
        cmd: &Command,
        ctx: &GeneratorContext,
    ) -> Result<String, SqlGenError> {
        // Handle join specially since it needs to generate subsearch SQL
        if let Command::Join {
            join_type,
            fields,
            subsearch,
            max,
            overwrite: _,
            maxout,
        } = cmd
        {
            let limit = crate::query::clickhouse_sql_gen::resolve_subsearch_limit(*maxout);
            let inner_sql =
                self.generate_join_sql(source_cte, join_type, fields, subsearch, *max, limit, ctx)?;
            return Ok(format!("{} AS (\n{}\n)", cte_name, inner_sql));
        }

        // Handle append specially - UNION ALL with subsearch
        if let Command::Append { subsearch, maxout } = cmd {
            let limit = crate::query::clickhouse_sql_gen::resolve_subsearch_limit(*maxout);
            let inner_sql = self.generate_append_sql(source_cte, subsearch, limit, ctx)?;
            return Ok(format!("{} AS (\n{}\n)", cte_name, inner_sql));
        }

        let inner_sql = self.generate_command_sql(source_cte, cmd)?;
        Ok(format!("{} AS (\n{}\n)", cte_name, inner_sql))
    }

    /// Generate SQL for an APPEND command (UNION ALL)
    fn generate_append_sql(
        &self,
        source_cte: &str,
        subsearch: &Query,
        limit: usize,
        ctx: &GeneratorContext,
    ) -> Result<String, SqlGenError> {
        // Generate the subsearch SQL
        let subsearch_sql = self.generate_subsearch_sql(subsearch, ctx, limit)?;

        // UNION ALL combines results from main query and subsearch
        Ok(format!(
            "  SELECT * FROM {}\n  UNION ALL\n{}",
            source_cte, subsearch_sql
        ))
    }

    /// Generate SQL for a JOIN command
    fn generate_join_sql(
        &self,
        source_cte: &str,
        join_type: &JoinType,
        fields: &[String],
        subsearch: &Query,
        max: usize,
        limit: usize,
        ctx: &GeneratorContext,
    ) -> Result<String, SqlGenError> {
        // Generate the subsearch SQL
        let subsearch_sql = self.generate_subsearch_sql(subsearch, ctx, limit)?;

        // Build the JOIN condition
        let join_conditions: Vec<String> = fields
            .iter()
            .map(|f| format!("main.\"{}\" = sub.\"{}\"", f, f))
            .collect();
        let join_condition = join_conditions.join(" AND ");

        // Map join type to SQL keyword
        let join_keyword = match join_type {
            JoinType::Inner => "INNER JOIN",
            JoinType::Left => "LEFT JOIN",
            JoinType::Outer => "FULL OUTER JOIN",
        };

        // For max > 1, use ROW_NUMBER to limit matches per key
        if max > 1 {
            Ok(format!(
                "  SELECT main.*, sub.* FROM {} AS main\n  {} (\n    SELECT *, ROW_NUMBER() OVER (PARTITION BY {} ORDER BY timestamp) AS _join_rn\n    FROM ({})\n  ) AS sub ON {} AND sub._join_rn <= {}",
                source_cte,
                join_keyword,
                fields.iter().map(|f| format!("\"{}\"", f)).collect::<Vec<_>>().join(", "),
                subsearch_sql,
                join_condition,
                max
            ))
        } else {
            Ok(format!(
                "  SELECT main.*, sub.* FROM {} AS main\n  {} (\n{}\n  ) AS sub ON {}",
                source_cte, join_keyword, subsearch_sql, join_condition
            ))
        }
    }

    /// Generate SQL for a subsearch (used by join/append)
    fn generate_subsearch_sql(
        &self,
        subsearch: &Query,
        ctx: &GeneratorContext,
        limit: usize,
    ) -> Result<String, SqlGenError> {
        // Collect stages from subsearch
        let stages = self.collect_stages(subsearch);

        if stages.is_empty() {
            return Err(SqlGenError::EmptyQuery);
        }

        // For single-stage subsearch (just a search), generate inline
        if stages.len() == 1 {
            if let QueryStage::Search(expr) = &stages[0] {
                let where_clause = self.generate_search_expr(expr)?;
                return Ok(format!(
                    "    SELECT * FROM {}\n    WHERE timestamp BETWEEN '{}' AND '{}'\n      AND ({})",
                    ctx.table_name,
                    ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                    ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                    where_clause
                ));
            }
        }

        // For multi-stage subsearch, generate nested subqueries
        let mut result = String::new();

        for (i, stage) in stages.iter().enumerate() {
            match stage {
                QueryStage::Search(expr) => {
                    let where_clause = self.generate_search_expr(expr)?;
                    if i == 0 {
                        result = format!(
                            "SELECT * FROM {}\n    WHERE timestamp BETWEEN '{}' AND '{}'\n      AND ({})",
                            ctx.table_name,
                            ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                            ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                            where_clause
                        );
                    }
                }
                QueryStage::Command(cmd) => {
                    let source = format!("({}) AS base", result);
                    let cmd_sql = self.generate_command_sql(&source, cmd)?;
                    result = format!("SELECT * FROM ({})", cmd_sql.trim());
                }
            }
        }

        Ok(format!("    ({} LIMIT {})", result.replace('\n', "\n    "), limit))
    }
}
