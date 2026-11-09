// SPDX-License-Identifier: AGPL-3.0-or-later
//! Injection canary over nPL → SQL (security review 2026-11-08, Group A).
//!
//! Every user-controlled NAME slot (aliases, output fields, captures, filter
//! fields) and STRING slot (literals, formats, patterns, command values) is
//! filled with hostile payloads carrying the marker `QZXC`. Each query goes
//! through the real `explain` path (parse → validate → prevalence pushdown →
//! codegen) under UDM and OCSF. The generated SQL is tokenized with the
//! ClickHouse dialect and must satisfy, for every query that is not rejected:
//!
//! 1. every token containing the marker is a QUOTED identifier or a STRING
//!    literal, never a bare word, number, operator or comment;
//! 2. for NAME slots, the token stream with marker tokens masked is identical
//!    to the same query with a benign marker (`QZXCbenign`), so the payload
//!    cannot change the shape of the SQL. (String values legitimately change
//!    the shape: `%` picks a LIKE form, spaces split keyword tokens.);
//! 3. the layer-2 tripwire stays silent.
//!
//! A rejected query (`ERR:`) passes: refusing hostile input is fine.
//!
//! The string slots include `fillnull` and the other commands whose values the
//! pretty-printer re-quotes (`tree root=`, `cloud principal=`/`account=`,
//! `baseline <type>=`), so a source-scoped pass that round-trips the query
//! text can reuse [`CASES`] and [`assert_canary_safe`].

use super::npl_golden_corpus_tests::{render, sql_only_service, PROFILES};
use crate::auth::ScopeSet;
use sqlparser::dialect::ClickHouseDialect;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

const MARK: &str = "QZXC";

/// Hostile payloads. nPL `"…"` strings cannot contain `"`, so none do.
pub(crate) const PAYLOADS: &[&str] = &[
    "QZXC,(SELECT count() FROM nanosiem.logs) AS leak",
    "QZXC,(SELECT count() FROM logs) AS leak",
    "QZXC) OR (1",
    "QZXC') OR 1=1 --",
    "QZXC\\",
    "QZXC\\') OR 1=1 --",
    "QZXC/**/x",
    "QZXC'x",
    "QZXC%Y') OR 1=1 --",
    "QZXC-- x",
    "QZXC;SELECT 1",
    "QZXCü x",
];

/// Benign payload used for the structure comparison.
const BENIGN: &str = "QZXCbenign";

/// Query templates. `{N}` is a NAME slot, `{S}` a STRING slot.
pub(crate) const CASES: &[&str] = &[
    // Name slots.
    r#"* | eval "{N}"=1"#,
    r#"* | eval "{N}"=1 | where "{N}"=1"#,
    r#"* | prevalence enrich=true | eval "{N}"=host_count"#,
    r#"* | prevalence enrich=true | eval "{N}"=host_count | where "{N}" > 1"#,
    r#"* | prevalence enrich=true | eval "{N}"=host_count | where "{N}" IN (1, 2)"#,
    r#"* | prevalence enrich=true | eval "{N}"=host_count | where "{N}" > abs(1)"#,
    r#"* | eval "{N}"=1 | prevalence enrich=true | where "{N}"="x""#,
    r#"* | eval "{N}"=1 | prevalence enrich=true | where "{N}" IN ("a", "b")"#,
    r#"* | rename src_ip as "{N}""#,
    r#"* | rename src_ip as "{N}" | prevalence enrich=true | where "{N}"="x""#,
    r#"* | table src_ip as "{N}""#,
    r#"* | stats count as "{N}" by src_ip"#,
    r#"* | eval "{N}"=1 | stats count by "{N}""#,
    r#"* | eval "{N}"=user | sequence by user ["{N}"="a"] [action="b"]"#,
    r#"* | eval "{N}"=user | sequence by user ["{N}"=lower("a")] [action="b"]"#,
    r#"* | eval "{N}"=user | sequence by user [action="a"] ["{N}"=lower("b")]"#,
    r#"* | eval "{N}"=timestamp | bin "{N}" span=1h"#,
    r#"* | eval "{N}"=bytes_out | anomaly sum("{N}") by src_ip"#,
    r#"* | spath input=message path=a output="{N}""#,
    r#"* | eval "{N}"=1 | fillnull value=0 "{N}""#,
    r#"* | eval "{N}"=1 | mvexpand "{N}""#,
    r#"* | eval "{N}"=1 | top "{N}""#,
    r#"* | eval "{N}"=1 | dedup "{N}""#,
    r#"* | eval "{N}"=1 | sort -"{N}""#,
    // String slots.
    r#"* | eval s="{S}""#,
    r#"* | where message="{S}""#,
    r#"* | where message!="{S}""#,
    r#"* | where like(message, "{S}")"#,
    r#"* | eval x=if(match(message, "{S}"), 1, 0)"#,
    r#"* | eval t=strftime(timestamp, "{S}")"#,
    r#"* | eval t=strftime(timestamp, lower("{S}"))"#,
    r#"* | eval t=tostring(timestamp, "%Y{S}")"#,
    r#"* | eval t=tostring(timestamp, lower("%Y{S}"))"#,
    r#"* | eval d=to_date(message, "{S}")"#,
    r#"* | eval c=concat(user, "{S}")"#,
    r#"* | prevalence enrich=true | where src_ip="{S}""#,
    r#"* | prevalence enrich=true | eval z="{S}" | where z!="x""#,
    r#"* | fillnull value="{S}" bytes_out"#,
    r#"* | fillnull value="{S}""#,
    r#"* | tree process_name root="{S}""#,
    r#"* | cloud principal="{S}""#,
    r#"* | cloud account="{S}""#,
    r#"* | baseline user="{S}""#,
];

fn fill(template: &str, payload: &str) -> String {
    template.replace("{N}", payload).replace("{S}", payload)
}

/// Significant tokens of the SQL that would execute (explain's trailing
/// `-- Note` lines are dropped). Comments are kept as tokens so a marker in a
/// comment is caught.
fn significant_tokens(sql: &str) -> Result<Vec<Token>, String> {
    let executed = sql.split("\n\n-- Note").next().unwrap_or_default();
    Tokenizer::new(&ClickHouseDialect {}, executed)
        .tokenize()
        .map(|t| {
            t.into_iter()
                .filter(|t| {
                    !matches!(
                        t,
                        Token::Whitespace(Whitespace::Space | Whitespace::Newline | Whitespace::Tab)
                    )
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

fn is_inert(token: &Token) -> bool {
    match token {
        Token::Word(w) => w.quote_style.is_some(),
        Token::SingleQuotedString(_)
        | Token::DoubleQuotedString(_)
        | Token::TripleSingleQuotedString(_)
        | Token::EscapedStringLiteral(_)
        | Token::NationalStringLiteral(_)
        | Token::UnicodeStringLiteral(_) => true,
        _ => false,
    }
}

fn mask(tokens: &[Token]) -> Vec<String> {
    tokens
        .iter()
        .map(|t| {
            if t.to_string().contains(MARK) {
                "<MARK>".to_string()
            } else {
                t.to_string()
            }
        })
        .collect()
}

/// Assert the three canary properties for one rendered query pair.
pub(crate) fn assert_canary_safe(
    label: &str,
    hostile_sql: &str,
    benign_sql: &str,
    check_shape: bool,
) {
    if hostile_sql.starts_with("ERR:") {
        return;
    }
    let tokens = significant_tokens(hostile_sql)
        .unwrap_or_else(|e| panic!("{label}: generated SQL does not tokenize ({e}):\n{hostile_sql}"));
    for t in &tokens {
        if t.to_string().contains(MARK) {
            assert!(
                is_inert(t),
                "{label}: payload escaped its slot as {t:?}\n{hostile_sql}"
            );
        }
    }
    let executed = hostile_sql.split("\n\n-- Note").next().unwrap_or_default();
    let trips = crate::query::generated_sql_tripwire::check(executed);
    assert!(trips.is_empty(), "{label}: tripwire {trips:?}\n{hostile_sql}");

    if check_shape && !benign_sql.starts_with("ERR:") {
        let benign = significant_tokens(benign_sql).expect("benign SQL tokenizes");
        assert_eq!(
            mask(&tokens),
            mask(&benign),
            "{label}: payload changed the SQL shape\n--- hostile\n{hostile_sql}\n--- benign\n{benign_sql}"
        );
    }
}

#[tokio::test]
async fn hostile_names_and_strings_never_escape_their_slot() {
    let scope = ScopeSet::unrestricted();
    for profile in PROFILES {
        let svc = sql_only_service(profile);
        for template in CASES {
            let benign_sql = render(&svc, &fill(template, BENIGN), &scope).await;
            for payload in PAYLOADS {
                let query = fill(template, payload);
                let hostile_sql = render(&svc, &query, &scope).await;
                assert_canary_safe(
                    &format!("[{profile}] {query}"),
                    &hostile_sql,
                    &benign_sql,
                    // A `.` in a NAME is structural (OCSF / JSON path), so the
                    // shape legitimately differs from the dot-free benign name.
                    template.contains("{N}") && !payload.contains('.'),
                );
            }
        }
    }
}

/// The four Group A findings, rendered and checked explicitly so a regression
/// names the finding.
#[tokio::test]
async fn group_a_exploits_are_closed() {
    let scope = ScopeSet::unrestricted();
    let svc = sql_only_service("udm");

    // NAN-5009: eval alias in the prevalence pushdown SELECT list.
    let sql = render(
        &svc,
        r#"* | prevalence enrich=true | eval "x, (SELECT count() FROM nanosiem.logs) AS leak"=1"#,
        &scope,
    )
    .await;
    assert!(!sql.starts_with("ERR:"), "{sql}");
    assert!(sql.contains(r#"AS "x, (SELECT count() FROM nanosiem.logs) AS leak""#), "{sql}");

    // NAN-5010: non-literal strftime format is refused; tostring falls back.
    let sql = render(&svc, r#"* | eval t=strftime(timestamp, lower("') OR 1=1 --"))"#, &scope).await;
    assert!(sql.starts_with("ERR:") && sql.contains("string literal"), "{sql}");
    let sql = render(&svc, r#"* | eval t=tostring(timestamp, lower("%Y') OR 1=1 --"))"#, &scope).await;
    assert!(!sql.contains("formatDateTime"), "{sql}");

    // NAN-5034: non-allowlisted anomaly functions are a parse error.
    for q in [
        "* | anomaly filesystemAvailable() by src_ip",
        "* | anomaly uptime() by user",
        "* | anomaly hostName() by user",
        "* | anomaly tcpPort() by user",
    ] {
        let sql = render(&svc, q, &scope).await;
        assert!(sql.starts_with("ERR:") && sql.contains("anomaly"), "{q}: {sql}");
    }
}
