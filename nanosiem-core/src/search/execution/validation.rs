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
use sqlparser::tokenizer::{Token, Whitespace};

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
    use sqlparser::tokenizer::Tokenizer;

    let dialect = ClickHouseDialect {};

    // NAN-2007 (F3,F11,F18,F19,F23): tokenize with the SAME lexer the parser (and
    // ClickHouse) uses, so the MANDATORY scans below cannot desync from what
    // actually executes. The previous hand-rolled `strip_string_literals` /
    // `reject_sql_comments` modeled only `''` doubling and were blind to
    // ClickHouse backslash escapes (`\'`) and backtick / double-quote quoted
    // identifiers — a `'\''` or a `'` inside `` `ident` `` flipped their quote
    // state and hid a `system.*` reference or an info-disclosure function call
    // from the scans while sqlparser/ClickHouse ran it as code.
    let tokens = Tokenizer::new(&dialect, sql)
        .tokenize()
        .map_err(|e| SearchError::SqlValidationError(format!("SQL parse error: {}", e)))?;

    // Reject comments — a `--` / `/* */` can split or hide a `system.*` reference
    // from the reconstructed-text scans. Detected from TOKENS, so a `--` inside a
    // string literal or a quoted identifier is not misread as a comment.
    if tokens.iter().any(is_comment_token) {
        return Err(SearchError::SqlValidationError(
            "SQL comments are not allowed".to_string(),
        ));
    }

    // Friendly UX: parse as exactly one SELECT. NOT the security boundary —
    // ClickHouse readonly + SELECT-only grants deny DML/DDL regardless.
    let statements = Parser::parse_sql(&dialect, sql)
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

    // Reconstruct the SQL from tokens with string LITERALS dropped and quoted
    // identifiers reduced to their bare value, so the mandatory scans match SQL
    // SYNTAX (schema/function references), never log CONTENT.
    let code = strip_string_literals(&tokens);
    reject_system_schema(&code)?;
    reject_disallowed_functions(&code)?;

    Ok(())
}

/// True for the tokenizer's comment whitespace kinds (`--` line, `/* */` block).
fn is_comment_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(
            Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_)
        )
    )
}

/// Reconstruct scannable SQL text from `tokens`, dropping string-literal CONTENT
/// (so `WHERE message LIKE '%system%'` / `'%delete%'` hunts are not flagged) but
/// KEEPING identifiers — including backtick / double-quote quoted ones, which the
/// tokenizer surfaces as [`Token::Word`] with the quotes already stripped, so
/// `` `system` `` and `"hostName"` are still caught. Using the tokenizer's own
/// output means the scanned text can never desync from what the parser sees.
///
/// Tokens are space-separated so word boundaries survive for the regex scans
/// (`hostName (`, `system . tables`). Comments are rejected upstream, so their
/// content never reaches here.
fn strip_string_literals(tokens: &[Token]) -> String {
    let mut out = String::new();
    for token in tokens {
        out.push(' ');
        match token {
            // Quoted identifiers surface as Word with the enclosing quotes
            // removed — emit the bare value.
            Token::Word(w) => out.push_str(&w.value),
            // Single-quote-family VALUE literals: never a schema/function
            // reference in ClickHouse. Drop the content entirely.
            Token::SingleQuotedString(_)
            | Token::TripleSingleQuotedString(_)
            | Token::DollarQuotedString(_)
            | Token::SingleQuotedByteStringLiteral(_)
            | Token::NationalStringLiteral(_)
            | Token::EscapedStringLiteral(_)
            | Token::UnicodeStringLiteral(_)
            | Token::HexStringLiteral(_) => {}
            // Everything else (punctuation, numbers, operators, non-comment
            // whitespace, and — fail-safe — any future token kind) keeps its
            // textual form, so an identifier can never be silently dropped.
            other => out.push_str(&other.to_string()),
        }
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

    // =========================================================================
    // NAN-2007: parser-differential bypasses of the mandatory scans.
    // The old hand-rolled literal stripper desynced from ClickHouse/sqlparser on
    // backslash escapes (`\'`) and backtick/double-quote identifiers, hiding a
    // `system.*` reference or a disallowed function from the scans.
    // =========================================================================

    #[test]
    fn rejects_backslash_escape_desync_hiding_system_schema() {
        // F3/F19: a `\'` closes the string for ClickHouse/sqlparser but the old
        // stripper stayed "in string" and swallowed `... FROM system.tables`.
        assert!(validate_sql_query(
            r#"SELECT message FROM logs WHERE message='\'' UNION ALL SELECT name FROM system.tables"#
        )
        .is_err());
        assert!(
            validate_sql_query(r#"SELECT '\'' AS x, name, engine FROM system.tables"#).is_err()
        );
    }

    #[test]
    fn rejects_backslash_escape_desync_hiding_disallowed_function() {
        // F18: same desync used to hide an info-disclosure function call.
        assert!(validate_sql_query(r#"SELECT 'a\'', hostName() FROM logs"#).is_err());
        assert!(validate_sql_query(r#"SELECT 'x\'' AS a, sleep(3) FROM logs"#).is_err());
    }

    #[test]
    fn rejects_backtick_identifier_desync() {
        // F11: a `'` inside a backtick identifier used to flip the stripper into
        // "in string" and swallow the trailing `hostName()` / `system.*` ref.
        assert!(validate_sql_query("SELECT 1 AS `a'`, hostName() FROM logs").is_err());
        assert!(validate_sql_query("SELECT * FROM `system`.`tables`").is_err());
        assert!(validate_sql_query(
            r#"SELECT "col'x", getSetting('max_threads') FROM logs"#
        )
        .is_err());
    }

    #[test]
    fn allows_benign_backslash_and_backtick_content() {
        // No over-rejection: escaped backslashes in string content, a schema name
        // that only appears inside a string literal, and legit backtick idents.
        assert!(validate_sql_query(r#"SELECT * FROM logs WHERE message = 'a\\b'"#).is_ok());
        assert!(
            validate_sql_query(r#"SELECT * FROM logs WHERE message ILIKE '%system.tables%'"#)
                .is_ok()
        );
        assert!(
            validate_sql_query("SELECT `src_ip`, count() AS c FROM logs GROUP BY `src_ip`").is_ok()
        );
    }
}
