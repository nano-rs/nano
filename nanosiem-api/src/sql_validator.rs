// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL Validator
//!
//! Validates raw SQL queries to ensure they are safe SELECT statements.
//! Rejects:
//! - Non-SELECT statements (INSERT, UPDATE, DELETE, DROP, etc.)
//! - Dangerous functions (pg_sleep, pg_terminate_backend, etc.)
//! - Multiple statements
//! - Access to sensitive tables (users, api_keys, sessions, etc.)

use sqlparser::ast::{
    Expr, Function, Query, SelectItem, SetExpr, Statement, TableFactor, TableWithJoins,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::error::ApiError;

/// Tables containing sensitive data that should not be queryable via raw SQL
const BLOCKED_TABLES: &[&str] = &[
    // Auth & credentials
    "users",
    "api_keys",
    "sessions",
    "refresh_tokens",
    // Access control
    "roles",
    "permissions",
    "user_roles",
    "role_permissions",
    "group_roles",
    // SSO/OIDC config
    "oidc_providers",
    "oidc_group_mappings",
];

/// List of dangerous SQL functions that should be blocked
const DANGEROUS_FUNCTIONS: &[&str] = &[
    "pg_sleep",
    "pg_terminate_backend",
    "pg_cancel_backend",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_switch_wal",
    "pg_create_restore_point",
    "pg_start_backup",
    "pg_stop_backup",
    "lo_import",
    "lo_export",
    "dblink",
    "dblink_exec",
];

/// List of dangerous SQL keywords that indicate mutating operations
const DANGEROUS_KEYWORDS: &[&str] = &[
    "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "GRANT", "REVOKE", "COPY",
    "EXECUTE", "PREPARE",
];

/// SQL Validator for ensuring queries are safe
pub struct SqlValidator;

impl SqlValidator {
    /// Validate that SQL is a safe SELECT query
    pub fn validate(sql: &str) -> Result<(), ApiError> {
        // Parse the SQL
        let dialect = PostgreSqlDialect {};
        let statements = Parser::parse_sql(&dialect, sql)
            .map_err(|e| ApiError::SqlValidationError(format!("SQL parse error: {}", e)))?;

        // Must be exactly one statement
        if statements.len() != 1 {
            return Err(ApiError::SqlValidationError(
                "Only single SELECT statements are allowed".to_string(),
            ));
        }

        // Must be a SELECT statement
        let statement = &statements[0];
        match statement {
            Statement::Query(query) => {
                // Recursively check for dangerous functions in the query
                Self::check_query_for_dangerous_functions(query)?;
                // Check for blocked tables
                Self::check_query_tables(query)?;
                Ok(())
            }
            _ => Err(ApiError::SqlValidationError(
                "Only SELECT statements are allowed".to_string(),
            )),
        }?;

        // Additional keyword check for edge cases
        Self::check_dangerous_keywords(sql)?;

        Ok(())
    }

    /// Check a query for references to blocked tables
    fn check_query_tables(query: &Query) -> Result<(), ApiError> {
        // Check CTEs
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                Self::check_query_tables(&cte.query)?;
            }
        }

        // Check the query body
        Self::check_set_expr_tables(&query.body)?;

        Ok(())
    }

    /// Check a set expression for blocked tables
    fn check_set_expr_tables(set_expr: &SetExpr) -> Result<(), ApiError> {
        match set_expr {
            SetExpr::Select(select) => {
                // Check FROM clause
                for table_with_joins in &select.from {
                    Self::check_table_with_joins(table_with_joins)?;
                }
                // Check WHERE clause for subqueries
                if let Some(selection) = &select.selection {
                    Self::check_expr_for_blocked_tables(selection)?;
                }
            }
            SetExpr::Query(query) => {
                Self::check_query_tables(query)?;
            }
            SetExpr::SetOperation { left, right, .. } => {
                Self::check_set_expr_tables(left)?;
                Self::check_set_expr_tables(right)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Check an expression for subqueries that reference blocked tables
    fn check_expr_for_blocked_tables(expr: &Expr) -> Result<(), ApiError> {
        match expr {
            Expr::Subquery(query) => {
                Self::check_query_tables(query)?;
            }
            Expr::InSubquery { subquery, expr, .. } => {
                Self::check_query_tables(subquery)?;
                Self::check_expr_for_blocked_tables(expr)?;
            }
            Expr::BinaryOp { left, right, .. } => {
                Self::check_expr_for_blocked_tables(left)?;
                Self::check_expr_for_blocked_tables(right)?;
            }
            Expr::UnaryOp { expr, .. } => {
                Self::check_expr_for_blocked_tables(expr)?;
            }
            Expr::Nested(e) => {
                Self::check_expr_for_blocked_tables(e)?;
            }
            Expr::InList { expr, list, .. } => {
                Self::check_expr_for_blocked_tables(expr)?;
                for item in list {
                    Self::check_expr_for_blocked_tables(item)?;
                }
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                Self::check_expr_for_blocked_tables(expr)?;
                Self::check_expr_for_blocked_tables(low)?;
                Self::check_expr_for_blocked_tables(high)?;
            }
            Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                if let Some(op) = operand {
                    Self::check_expr_for_blocked_tables(op)?;
                }
                for cond in conditions {
                    Self::check_expr_for_blocked_tables(&cond.condition)?;
                    Self::check_expr_for_blocked_tables(&cond.result)?;
                }
                if let Some(else_r) = else_result {
                    Self::check_expr_for_blocked_tables(else_r)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Check a table with joins for blocked tables
    fn check_table_with_joins(table_with_joins: &TableWithJoins) -> Result<(), ApiError> {
        Self::check_table_factor(&table_with_joins.relation)?;
        for join in &table_with_joins.joins {
            Self::check_table_factor(&join.relation)?;
        }
        Ok(())
    }

    /// Check a table factor for blocked tables
    fn check_table_factor(table_factor: &TableFactor) -> Result<(), ApiError> {
        match table_factor {
            TableFactor::Table { name, .. } => {
                // Get the table name (last part of qualified name)
                let table_name = name
                    .0
                    .last()
                    .map(|ident| ident.to_string().to_lowercase())
                    .unwrap_or_default();
                Self::check_table_name(&table_name)?;
            }
            TableFactor::Derived { subquery, .. } => {
                Self::check_query_tables(subquery)?;
            }
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => {
                Self::check_table_with_joins(table_with_joins)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Check if a table name is blocked
    fn check_table_name(table_name: &str) -> Result<(), ApiError> {
        // Normalize: remove schema prefix if present
        let name = table_name.split('.').last().unwrap_or(table_name);

        if BLOCKED_TABLES.contains(&name) {
            return Err(ApiError::SqlValidationError(format!(
                "Access to table '{}' is not allowed for security reasons",
                name
            )));
        }
        Ok(())
    }

    /// Check a query for dangerous functions
    fn check_query_for_dangerous_functions(query: &sqlparser::ast::Query) -> Result<(), ApiError> {
        // Check the body of the query
        match query.body.as_ref() {
            SetExpr::Select(select) => {
                // Check projection (SELECT items)
                for item in &select.projection {
                    if let SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } =
                        item
                    {
                        Self::check_expr_for_dangerous_functions(expr)?;
                    }
                }

                // Check WHERE clause
                if let Some(selection) = &select.selection {
                    Self::check_expr_for_dangerous_functions(selection)?;
                }

                // Check HAVING clause
                if let Some(having) = &select.having {
                    Self::check_expr_for_dangerous_functions(having)?;
                }
            }
            SetExpr::Query(subquery) => {
                Self::check_query_for_dangerous_functions(subquery)?;
            }
            SetExpr::SetOperation { left, right, .. } => {
                if let SetExpr::Query(q) = left.as_ref() {
                    Self::check_query_for_dangerous_functions(q)?;
                }
                if let SetExpr::Query(q) = right.as_ref() {
                    Self::check_query_for_dangerous_functions(q)?;
                }
            }
            _ => {}
        }

        // Check CTEs
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                Self::check_query_for_dangerous_functions(&cte.query)?;
            }
        }

        Ok(())
    }

    /// Check an expression for dangerous functions
    fn check_expr_for_dangerous_functions(expr: &Expr) -> Result<(), ApiError> {
        match expr {
            Expr::Function(func) => {
                Self::check_function(func)?;
                // Check function arguments - iterate through args
                Self::check_function_args(func)?;
            }
            Expr::BinaryOp { left, right, .. } => {
                Self::check_expr_for_dangerous_functions(left)?;
                Self::check_expr_for_dangerous_functions(right)?;
            }
            Expr::UnaryOp { expr, .. } => {
                Self::check_expr_for_dangerous_functions(expr)?;
            }
            Expr::Nested(e) => {
                Self::check_expr_for_dangerous_functions(e)?;
            }
            Expr::Subquery(q) => {
                Self::check_query_for_dangerous_functions(q)?;
            }
            Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                if let Some(op) = operand {
                    Self::check_expr_for_dangerous_functions(op)?;
                }
                for cond in conditions {
                    Self::check_expr_for_dangerous_functions(&cond.condition)?;
                    Self::check_expr_for_dangerous_functions(&cond.result)?;
                }
                if let Some(else_r) = else_result {
                    Self::check_expr_for_dangerous_functions(else_r)?;
                }
            }
            Expr::InList { expr, list, .. } => {
                Self::check_expr_for_dangerous_functions(expr)?;
                for item in list {
                    Self::check_expr_for_dangerous_functions(item)?;
                }
            }
            Expr::InSubquery { expr, subquery, .. } => {
                Self::check_expr_for_dangerous_functions(expr)?;
                Self::check_query_for_dangerous_functions(subquery)?;
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                Self::check_expr_for_dangerous_functions(expr)?;
                Self::check_expr_for_dangerous_functions(low)?;
                Self::check_expr_for_dangerous_functions(high)?;
            }
            Expr::Cast { expr, .. } => {
                Self::check_expr_for_dangerous_functions(expr)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Check function arguments for dangerous functions
    fn check_function_args(func: &Function) -> Result<(), ApiError> {
        use sqlparser::ast::FunctionArguments;

        match &func.args {
            FunctionArguments::List(arg_list) => {
                for arg in &arg_list.args {
                    use sqlparser::ast::{FunctionArg, FunctionArgExpr};
                    match arg {
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) => {
                            Self::check_expr_for_dangerous_functions(e)?;
                        }
                        FunctionArg::Named {
                            arg: FunctionArgExpr::Expr(e),
                            ..
                        } => {
                            Self::check_expr_for_dangerous_functions(e)?;
                        }
                        _ => {}
                    }
                }
            }
            FunctionArguments::Subquery(q) => {
                Self::check_query_for_dangerous_functions(q)?;
            }
            FunctionArguments::None => {}
        }
        Ok(())
    }

    /// Check if a function is dangerous
    fn check_function(func: &Function) -> Result<(), ApiError> {
        let func_name = func.name.to_string().to_lowercase();

        for dangerous in DANGEROUS_FUNCTIONS {
            if func_name == *dangerous || func_name.ends_with(&format!(".{}", dangerous)) {
                return Err(ApiError::SqlValidationError(format!(
                    "Disallowed function: {}",
                    dangerous
                )));
            }
        }
        Ok(())
    }

    /// Check for dangerous keywords in the raw SQL
    fn check_dangerous_keywords(sql: &str) -> Result<(), ApiError> {
        let sql_upper = sql.to_uppercase();

        for keyword in DANGEROUS_KEYWORDS {
            // Check if keyword appears as a standalone word
            let pattern = format!(r"\b{}\b", keyword);
            if let Ok(re) = regex::Regex::new(&pattern) {
                if re.is_match(&sql_upper) {
                    return Err(ApiError::SqlValidationError(format!(
                        "Disallowed keyword: {}",
                        keyword
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_select() {
        assert!(SqlValidator::validate("SELECT * FROM logs").is_ok());
        assert!(SqlValidator::validate("SELECT id, message FROM alerts WHERE id = 1").is_ok());
        assert!(SqlValidator::validate("SELECT COUNT(*) FROM logs GROUP BY src_ip").is_ok());
        assert!(
            SqlValidator::validate("SELECT * FROM logs WHERE timestamp > '2024-01-01'").is_ok()
        );
    }

    #[test]
    fn test_valid_select_with_cte() {
        assert!(
            SqlValidator::validate("WITH cte AS (SELECT * FROM logs) SELECT * FROM cte").is_ok()
        );
    }

    #[test]
    fn test_valid_select_with_subquery() {
        assert!(
            SqlValidator::validate("SELECT * FROM logs WHERE id IN (SELECT id FROM alerts)")
                .is_ok()
        );
    }

    #[test]
    fn test_reject_insert() {
        let result = SqlValidator::validate("INSERT INTO logs VALUES (1)");
        assert!(result.is_err());
        // The error message should indicate it's not a SELECT statement
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("SELECT") || err_msg.contains("INSERT"));
    }

    #[test]
    fn test_reject_update() {
        let result = SqlValidator::validate("UPDATE logs SET status = 1");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_delete() {
        let result = SqlValidator::validate("DELETE FROM logs");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_drop() {
        let result = SqlValidator::validate("DROP TABLE logs");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_pg_sleep() {
        let result = SqlValidator::validate("SELECT pg_sleep(10)");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("pg_sleep"));
    }

    #[test]
    fn test_reject_pg_terminate_backend() {
        let result = SqlValidator::validate("SELECT pg_terminate_backend(123)");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_multiple_statements() {
        let result = SqlValidator::validate("SELECT * FROM logs; DROP TABLE logs");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_dangerous_in_subquery() {
        let result = SqlValidator::validate("SELECT * FROM logs WHERE id IN (SELECT pg_sleep(10))");
        assert!(result.is_err());
    }

    // Blocked table tests
    #[test]
    fn test_reject_users_table() {
        let result = SqlValidator::validate("SELECT * FROM users");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not allowed"));
    }

    #[test]
    fn test_reject_api_keys_table() {
        let result = SqlValidator::validate("SELECT * FROM api_keys");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_sessions_table() {
        let result = SqlValidator::validate("SELECT * FROM sessions");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_blocked_table_in_join() {
        let result =
            SqlValidator::validate("SELECT * FROM logs JOIN users ON logs.user_id = users.id");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_blocked_table_in_subquery() {
        let result =
            SqlValidator::validate("SELECT * FROM logs WHERE user_id IN (SELECT id FROM users)");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_blocked_table_in_cte() {
        let result = SqlValidator::validate(
            "WITH user_data AS (SELECT * FROM users) SELECT * FROM user_data",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_blocked_table_in_union() {
        let result = SqlValidator::validate("SELECT id FROM logs UNION SELECT id FROM users");
        assert!(result.is_err());
    }

    #[test]
    fn test_allow_audit_logs() {
        // audit_logs should be allowed for compliance queries
        assert!(SqlValidator::validate("SELECT * FROM audit_logs").is_ok());
    }
}
