// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL validation for the raw-SQL surface (`POST /api/search/sql`, dashboards SQL
//! panels, reports, meloD advanced mode).
//!
//! **NAN-2001: this is no longer the security boundary.** The table ALLOWLIST,
//! table-function denial (`url()/s3()/remote()/…` = SSRF), `system.*` denial,
//! writes, and audit-row hiding are all enforced by ClickHouse via two dedicated
//! read-only feature identities — `nanosiem_rawsql` / `nanosiem_rawsql_noaudit`
//! (SELECT-only grants = the allowlist, plus a RESTRICTIVE `source_type!='audit'`
//! row policy on the noaudit identity). The app selects the identity by the
//! caller's `audit:view`; ClickHouse enforces the rest against its own semantics.
//!
//! The old approach hand-walked the sqlparser AST (`validate_sql_query` +
//! `inject_audit_filter`). It was **fail-open** (`match { known…; _ => {} }`) and
//! validated against sqlparser's grammar (which diverges from ClickHouse's); an
//! adversarial review bypassed it in **6 consecutive rounds**. That walk and the
//! audit-filter injection are **deleted**.
//!
//! What remains is intentionally small:
//!   1. a friendly single-SELECT parse check (UX; ClickHouse `readonly` grants
//!      deny DML/DDL regardless), and
//!   2. a MANDATORY reject of `system` / `information_schema` / `pg_catalog`
//!      references and a small set of info-disclosure / sleep FUNCTIONS —
//!      ClickHouse grants do NOT close these (some `system` metadata tables, e.g.
//!      `system.settings`, and functions like `currentDatabase()`/`hostName()`
//!      stay readable to a grant-only readonly user; verified live on CH 26.4).
//!
//! Both mandatory scans run on a **string-literal-stripped** copy of the SQL, so
//! they match SQL *syntax*, never log *content* (`WHERE message LIKE '%system%'`
//! and `'%delete%'` hunts are allowed again — the old substring scan blocked them).

use crate::search::SearchError;

/// Info-disclosure / sleep FUNCTIONS that ClickHouse does not deny for a
/// grant-only readonly user (they are not gated by grants nor by
/// `allow_introspection_functions`). Matched only in FUNCTION-CALL form
/// (`NAME(`) on string-literal-stripped SQL, so identifiers/log content such as
/// `message ILIKE '%hostname%'` are NOT rejected.
///
/// DML/DDL keywords are deliberately NOT here: a real DML/DDL *statement* is
/// already rejected by the single-SELECT parse below, and ClickHouse `readonly`
/// + SELECT-only grants deny them at execution — listing them only caused
/// false-positives on log content (`message LIKE '%delete%'`).
const DISALLOWED_FUNCTIONS: &[&str] = &[
    // Sleep / DoS
    "SLEEP",
    "SLEEPEACHROW",
    "PG_SLEEP",
    // Info disclosure (server / session / filesystem)
    "CURRENTDATABASE",
    "HOSTNAME",
    "CURRENTUSER",
    "GETSETTING",
    "FQDN",
    "DISPLAYNAME",
    "SERVERUUID",
    "BUILDID",
    "TCPPORT",
    "CURRENTPROFILES",
    "ENABLEDROLES",
    "FILESYSTEMCAPACITY",
    "FILESYSTEMFREE",
    "FILESYSTEMAVAILABLE",
    "GETOSKERNELVERSION",
    "GETMACRO",
    // Postgres-oriented file / process functions (harmless on CH, kept for parity)
    "PG_READ_FILE",
    "PG_READ_BINARY_FILE",
    "PG_TERMINATE_BACKEND",
    "PG_CANCEL_BACKEND",
];

/// Validate that raw SQL is a single SELECT and does not reference forbidden
/// schemas or call info-disclosure functions. See the module docs — this is
/// defense-in-depth + UX, NOT the security boundary (ClickHouse is).
pub fn validate_sql_query(sql: &str) -> Result<(), SearchError> {
    use sqlparser::dialect::ClickHouseDialect;
    use sqlparser::parser::Parser;

    // Rejecting comments keeps the literal-stripping scans below sound (a comment
    // can't hide a `system.*` reference from them). Also a cheap friendly check.
    reject_sql_comments(sql)?;

    // Friendly UX: parse as exactly one SELECT. NOT the security boundary —
    // ClickHouse readonly + SELECT-only grants deny DML/DDL regardless.
    let statements = Parser::parse_sql(&ClickHouseDialect {}, sql)
        .map_err(|e| SearchError::SqlValidationError(format!("SQL parse error: {}", e)))?;
    if statements.len() != 1 {
        return Err(SearchError::SqlValidationError(
            "Only a single SELECT statement is allowed".to_string(),
        ));
    }
    if !matches!(statements[0], sqlparser::ast::Statement::Query(_)) {
        return Err(SearchError::SqlValidationError(
            "Only SELECT statements are allowed".to_string(),
        ));
    }

    // A copy with single-quoted string literals removed, so the mandatory scans
    // match SQL SYNTAX, never log CONTENT.
    let code = strip_string_literals(sql);
    reject_system_schema(&code)?;
    reject_disallowed_functions(&code)?;

    Ok(())
}

/// Reject SQL comments to keep the literal-stripping scans sound (a `--`/`/* */`
/// comment could otherwise hide a `system.*` reference from them).
fn reject_sql_comments(sql: &str) -> Result<(), SearchError> {
    let mut in_single_quote = false;
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            if in_single_quote && i + 1 < chars.len() && chars[i + 1] == '\'' {
                i += 2;
                continue;
            }
            in_single_quote = !in_single_quote;
            i += 1;
            continue;
        }

        if !in_single_quote && i + 1 < chars.len() {
            let n = chars[i + 1];
            if (c == '-' && n == '-') || (c == '/' && n == '*') {
                return Err(SearchError::SqlValidationError(
                    "SQL comments are not allowed".to_string(),
                ));
            }
        }

        i += 1;
    }

    Ok(())
}

/// Remove single-quoted string literals (handling doubled-quote `''` escapes) so
/// downstream scans match SQL syntax rather than string content.
fn strip_string_literals(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0usize;
    let mut in_str = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            if in_str && i + 1 < chars.len() && chars[i + 1] == '\'' {
                // Escaped '' inside a string — skip both, stay in the string.
                i += 2;
                continue;
            }
            in_str = !in_str;
            i += 1;
            continue;
        }
        if !in_str {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// MANDATORY (NAN-2001): reject references to `system` / `information_schema` /
/// `pg_catalog`. ClickHouse grants do NOT fully close these — some
/// metadata/constant tables (`system.settings`, `system.tables`, `system.one`)
/// stay readable to a grant-only readonly user (verified live), so this reject is
/// load-bearing, not optional UX. `code` has string literals removed; here we
/// also drop identifier quotes/backticks and collapse whitespace around dots so
/// `"system"."tables"` and `system . tables` are caught.
fn reject_system_schema(code: &str) -> Result<(), SearchError> {
    let normalized: String = code
        .chars()
        .filter(|c| *c != '"' && *c != '`')
        .collect::<String>()
        .to_lowercase();
    // Collapse any whitespace around dots: `system . tables` -> `system.tables`.
    let normalized = regex::Regex::new(r"\s*\.\s*")
        .unwrap()
        .replace_all(&normalized, ".")
        .into_owned();

    for (needle, label) in [
        ("system.", "system"),
        ("information_schema", "information_schema"),
        ("pg_catalog", "pg_catalog"),
    ] {
        if normalized.contains(needle) {
            return Err(SearchError::SqlValidationError(format!(
                "Access to '{}' schema objects is not allowed",
                label
            )));
        }
    }
    Ok(())
}

/// MANDATORY (NAN-2001): reject info-disclosure / sleep function CALLS. Matched
/// as `NAME(` on the (literal-stripped) SQL so log content and identifiers that
/// merely contain a function name are not rejected.
fn reject_disallowed_functions(code: &str) -> Result<(), SearchError> {
    let upper = code.to_uppercase();
    for f in DISALLOWED_FUNCTIONS {
        // Function-call form: word-boundary NAME, optional whitespace, then `(`.
        let pattern = format!(r"\b{}\s*\(", f);
        if regex::Regex::new(&pattern)
            .map(|re| re.is_match(&upper))
            .unwrap_or(false)
        {
            return Err(SearchError::SqlValidationError(format!(
                "Disallowed function: {}()",
                f
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Allowed: any single SELECT that doesn't touch a forbidden schema/function.
    // NAN-2001: the table allowlist is enforced by ClickHouse grants now, so the
    // validator no longer rejects non-allowlisted table names.
    // =========================================================================

    #[test]
    fn allows_plain_selects_including_previously_unknown_tables() {
        assert!(validate_sql_query("SELECT * FROM logs").is_ok());
        assert!(validate_sql_query("SELECT * FROM signals").is_ok());
        assert!(validate_sql_query("SELECT * FROM ocsf_logs").is_ok());
        // Formerly rejected by the in-app allowlist; ClickHouse grants deny these.
        assert!(validate_sql_query("SELECT * FROM some_random_table").is_ok());
        assert!(validate_sql_query("SELECT * FROM users").is_ok());
    }

    #[test]
    fn allows_complex_shapes() {
        assert!(validate_sql_query(
            "SELECT src_ip, count() AS c FROM logs GROUP BY src_ip HAVING count() > 10 ORDER BY c DESC LIMIT 100"
        )
        .is_ok());
        assert!(validate_sql_query(
            "SELECT * FROM logs WHERE src_ip IN (SELECT src_ip FROM signals)"
        )
        .is_ok());
        assert!(validate_sql_query(
            "SELECT message FROM logs UNION ALL SELECT message FROM signals"
        )
        .is_ok());
        assert!(
            validate_sql_query("WITH base AS (SELECT * FROM logs) SELECT * FROM base").is_ok()
        );
        assert!(validate_sql_query(
            "SELECT * FROM logs PREWHERE timestamp > '2026-01-01' LIMIT 1"
        )
        .is_ok());
    }

    #[test]
    fn allows_log_content_that_looks_like_keywords() {
        // Regression guard: the old substring keyword scan false-rejected these.
        // Analysts must be able to hunt for these words in message/command content.
        assert!(validate_sql_query("SELECT * FROM logs WHERE message ILIKE '%delete%'").is_ok());
        assert!(validate_sql_query("SELECT * FROM logs WHERE message ILIKE '%hostname%'").is_ok());
        assert!(
            validate_sql_query("SELECT * FROM logs WHERE lower(message) LIKE '%grant access%'")
                .is_ok()
        );
        assert!(
            validate_sql_query("SELECT * FROM logs WHERE command_line = 'sleep 5; drop table'")
                .is_ok()
        );
    }

    // =========================================================================
    // MANDATORY: system / information_schema / pg_catalog rejected EVERYWHERE.
    // The literal-stripped text scan catches them regardless of AST position —
    // exactly the fail-open weakness that sank the old walk.
    // =========================================================================

    #[test]
    fn rejects_system_schema_in_every_position() {
        assert!(validate_sql_query("SELECT * FROM system.tables").is_err());
        assert!(validate_sql_query("SELECT * FROM system.settings").is_err());
        assert!(validate_sql_query("SELECT * FROM system.numbers LIMIT 1").is_err());
        assert!(validate_sql_query(
            "SELECT * FROM logs JOIN system.query_log ON logs.id = system.query_log.id"
        )
        .is_err());
        assert!(validate_sql_query(
            "SELECT * FROM logs WHERE id IN (SELECT query_id FROM system.processes)"
        )
        .is_err());
        assert!(validate_sql_query(
            "SELECT (SELECT count() FROM system.tables) AS x FROM logs"
        )
        .is_err());
        assert!(
            validate_sql_query("SELECT id FROM logs UNION SELECT id FROM system.tables").is_err()
        );
        assert!(validate_sql_query(
            "WITH evil AS (SELECT * FROM system.settings) SELECT * FROM evil"
        )
        .is_err());
        assert!(validate_sql_query(r#"SELECT name FROM "system"."tables""#).is_err());
        assert!(validate_sql_query("SELECT * FROM information_schema.tables").is_err());
        assert!(validate_sql_query("SELECT * FROM pg_catalog.pg_tables").is_err());
    }

    #[test]
    fn does_not_flag_system_in_string_literal_or_identifier_substring() {
        // 'system.tables' inside a string literal is content, not a schema ref.
        assert!(validate_sql_query("SELECT * FROM logs WHERE message = 'system.tables'").is_ok());
        // An identifier that merely contains 'system' (no `.`) is fine.
        assert!(validate_sql_query("SELECT systemd_unit FROM logs").is_ok());
    }

    // =========================================================================
    // MANDATORY: info-disclosure / sleep functions rejected (CH doesn't gate them).
    // =========================================================================

    #[test]
    fn rejects_info_disclosure_and_sleep_functions() {
        assert!(validate_sql_query("SELECT currentDatabase()").is_err());
        assert!(validate_sql_query("SELECT hostName()").is_err());
        assert!(validate_sql_query("SELECT currentUser()").is_err());
        assert!(validate_sql_query("SELECT getSetting('max_threads')").is_err());
        assert!(validate_sql_query("SELECT FQDN()").is_err());
        assert!(validate_sql_query("SELECT serverUUID()").is_err());
        assert!(validate_sql_query("SELECT sleep(2)").is_err());
        assert!(validate_sql_query("SELECT sleepEachRow(1)").is_err());
        // whitespace before the paren is still a call
        assert!(validate_sql_query("SELECT hostName ()").is_err());
    }

    // =========================================================================
    // Friendly UX + soundness: non-SELECT / multi-statement / comments.
    // =========================================================================

    #[test]
    fn rejects_non_select_multi_statement_and_comments() {
        assert!(validate_sql_query("INSERT INTO logs VALUES (1)").is_err());
        assert!(validate_sql_query("UPDATE logs SET status = 1").is_err());
        assert!(validate_sql_query("DELETE FROM logs").is_err());
        assert!(validate_sql_query("DROP TABLE logs").is_err());
        assert!(validate_sql_query("SELECT * FROM logs; DROP TABLE logs").is_err());
        assert!(validate_sql_query("SELECT * FROM logs -- bypass").is_err());
        assert!(validate_sql_query("SELECT * FROM logs /* bypass */").is_err());
    }
}
