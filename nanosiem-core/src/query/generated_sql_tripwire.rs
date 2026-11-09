// SPDX-License-Identifier: AGPL-3.0-or-later
//! Token-level tripwire over GENERATED nPL SQL (security review 2026-11-08,
//! layer 2).
//!
//! The nPL generator's escaping (`sql_hygiene::quote_identifier`,
//! `escape_sql_string`) is the security boundary for nPL. This module is a
//! defence-in-depth check on its OUTPUT: shapes the generator never emits for a
//! legitimate query, and that an escaping bug would let through.
//!
//! **Log-only in v2.0.1.** [`observe`] never fails, never changes the SQL and
//! never panics out: it logs a warning and increments
//! `nano_npl_sql_tripwire_total{rule=…}` on a hit. Enforcement is planned for
//! v2.1 once production shows zero hits on legitimate traffic.
//!
//! Why not reuse the raw-SQL `validate_sql_query`: its `system.` check is a
//! substring match (it would flag every OCSF query that projects
//! `src_endpoint.autonomous_system.number`), and its full sqlparser parse does
//! not accept all ClickHouse syntax the generator emits (lambdas, ARRAY JOIN,
//! LIMIT BY, inline SETTINGS, JSON subcolumns). This check works on TOKENS from
//! the same tokenizer, so string literals and quoted identifiers are inert.

use sqlparser::dialect::ClickHouseDialect;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

/// Why a generated query tripped the check. The metric label is
/// [`TripwireRule::label`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripwireRule {
    /// `--` or `/* */` comment. The generator never emits one.
    Comment,
    /// A `;` statement separator.
    Semicolon,
    /// An unquoted `system.` / `information_schema.` reference.
    SystemSchema,
    /// An info-disclosure / sleep function call (same list the raw-SQL
    /// validator rejects).
    DisallowedFunction,
    /// A ClickHouse table function that reaches outside the database
    /// (`url(`, `remote(`, `s3(`, `file(`, `executable(`, …).
    TableFunction,
    /// The SQL could not be tokenized at all.
    Untokenizable,
}

impl TripwireRule {
    /// Stable metric/log label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Comment => "comment",
            Self::Semicolon => "semicolon",
            Self::SystemSchema => "system_schema",
            Self::DisallowedFunction => "disallowed_function",
            Self::TableFunction => "table_function",
            Self::Untokenizable => "untokenizable",
        }
    }
}

/// Table functions that read outside the database or run code. The generator
/// never emits any of them. Lowercase; compared case-insensitively.
const TABLE_FUNCTIONS: &[&str] = &[
    "url",
    "urlcluster",
    "s3",
    "s3cluster",
    "gcs",
    "remote",
    "remotesecure",
    "cluster",
    "clusterallreplicas",
    "file",
    "filecluster",
    "hdfs",
    "hdfscluster",
    "mysql",
    "postgresql",
    "jdbc",
    "odbc",
    "executable",
    "input",
    "azureblobstorage",
    "azureblobstoragecluster",
    "iceberg",
    "icebergs3",
    "icebergazure",
    "iceberghdfs",
    "deltalake",
    "hudi",
    "paimon",
    "mongodb",
    "redis",
    "sqlite",
    "arrowflight",
    "ytsaurus",
    "merge",
];

/// Return every rule the SQL trips (empty = clean). Pure; used by [`observe`]
/// and by tests.
pub fn check(sql: &str) -> Vec<TripwireRule> {
    let tokens = match Tokenizer::new(&ClickHouseDialect {}, sql).tokenize() {
        Ok(t) => t,
        Err(_) => return vec![TripwireRule::Untokenizable],
    };
    let mut hits = Vec::new();
    let push = |rule: TripwireRule, hits: &mut Vec<TripwireRule>| {
        if !hits.contains(&rule) {
            hits.push(rule);
        }
    };

    // Significant (non-whitespace) tokens, with comments recorded separately.
    let mut sig: Vec<&Token> = Vec::with_capacity(tokens.len());
    for t in &tokens {
        match t {
            Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_)) => {
                push(TripwireRule::Comment, &mut hits)
            }
            Token::Whitespace(_) => {}
            other => sig.push(other),
        }
    }

    for (i, t) in sig.iter().enumerate() {
        match t {
            Token::SemiColon => push(TripwireRule::Semicolon, &mut hits),
            Token::Word(w) if w.quote_style.is_none() => {
                let lower = w.value.to_ascii_lowercase();
                let prev_is_dot = i > 0 && matches!(sig[i - 1], Token::Period);
                let next = sig.get(i + 1);
                if (lower == "system" || lower == "information_schema")
                    && !prev_is_dot
                    && matches!(next, Some(Token::Period))
                {
                    push(TripwireRule::SystemSchema, &mut hits);
                }
                if matches!(next, Some(Token::LParen)) && !prev_is_dot {
                    let upper = w.value.to_ascii_uppercase();
                    if crate::search::DISALLOWED_FUNCTIONS
                        .contains(&upper.as_str())
                    {
                        push(TripwireRule::DisallowedFunction, &mut hits);
                    }
                    if TABLE_FUNCTIONS.contains(&lower.as_str()) {
                        push(TripwireRule::TableFunction, &mut hits);
                    }
                }
            }
            _ => {}
        }
    }
    hits
}

/// SQL longer than this is not tokenized. Pre-resolved lookups can inline
/// very large literal IN-lists; scanning megabytes per query is not worth the
/// latency for a log-only check. Skips are counted, so a rise is visible.
pub const MAX_CHECKED_SQL_BYTES: usize = 1024 * 1024;

/// Log-only observation of one generated query. Never fails and never panics
/// out of this function, whatever the input.
pub fn observe(sql: &str, origin: &'static str) {
    if sql.len() > MAX_CHECKED_SQL_BYTES {
        metrics::counter!(
            "nano_npl_sql_tripwire_skipped_total",
            "reason" => "oversize",
            "origin" => origin
        )
        .increment(1);
        return;
    }
    let hits = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(sql)));
    let hits = match hits {
        Ok(h) => h,
        Err(_) => vec![TripwireRule::Untokenizable],
    };
    for rule in &hits {
        metrics::counter!(
            "nano_npl_sql_tripwire_total",
            "rule" => rule.label(),
            "origin" => origin
        )
        .increment(1);
    }
    if !hits.is_empty() {
        let labels: Vec<&str> = hits.iter().map(|r| r.label()).collect();
        // The SQL itself is not logged: it can carry search terms. Its length
        // and a short hash are enough to correlate with the query log.
        let digest = {
            use sha2::{Digest, Sha256};
            hex::encode(&Sha256::digest(sql.as_bytes())[..8])
        };
        tracing::warn!(
            rules = ?labels,
            origin,
            sql_len = sql.len(),
            sql_sha256_prefix = %digest,
            "generated nPL SQL tripped the tripwire (log-only; not blocked)"
        );
    }
}

#[cfg(test)]
#[path = "generated_sql_tripwire_tests.rs"]
mod tests;
