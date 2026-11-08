// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4943: nPL case-insensitive patterns always emit `lower(<expr>) LIKE`
//! through the single `ci_like` helper — no `iLike` for a literal, no s/k
//! guard, the literal lowered with ClickHouse `lower()` (ASCII-only) semantics.
use super::{ch_lower, ci_like, ClickHouseSqlGenerator};
use crate::query::{parse_query, TimeRange};
use crate::schema::OcsfProfile;
use std::sync::Arc;

fn range() -> TimeRange {
    TimeRange {
        start: "2026-10-01T00:00:00Z".parse().unwrap(),
        end: "2026-10-01T01:00:00Z".parse().unwrap(),
    }
}

fn sql(gen: &ClickHouseSqlGenerator, q: &str) -> String {
    gen.generate(&parse_query(q).unwrap(), &range())
        .unwrap_or_else(|e| panic!("{q}: {e}"))
}

#[test]
fn ch_lower_folds_ascii_only() {
    assert_eq!(ch_lower("MimiKatz"), "mimikatz");
    // Same as ClickHouse lower(): non-ASCII letters keep their case.
    assert_eq!(ch_lower("ÄÉ Жук"), "ÄÉ Жук");
    assert_eq!(ch_lower("Äbc"), "Äbc");
    assert_eq!(ch_lower("\u{212A}elvin \u{17F}vc"), "\u{212A}elvin \u{17F}vc");
}

#[test]
fn ci_like_is_one_form() {
    let l = "lower(message)";
    for (body, neg, want) in [
        ("%adminexec%", false, "lower(message) LIKE '%adminexec%'"),
        ("%adminexec%", true, "lower(message) NOT LIKE '%adminexec%'"),
        // k/s patterns: plain LIKE, no guard, no iLike.
        ("%needlekw7%", false, "lower(message) LIKE '%needlekw7%'"),
        ("%mimikatz%", true, "lower(message) NOT LIKE '%mimikatz%'"),
        ("s%", false, "lower(message) LIKE 's%'"),
        ("%k", true, "lower(message) NOT LIKE '%k'"),
        // Non-ASCII stays as-is (lower() does not fold it either).
        ("%Äbc%", false, "lower(message) LIKE '%Äbc%'"),
        // The helper re-lowers ASCII defensively.
        ("%MimiKatz%", false, "lower(message) LIKE '%mimikatz%'"),
        // Escapes survive lowering (backslashes are always doubled).
        ("%c:\\\\\\\\windows\\\\\\\\system32%", false, "lower(message) LIKE '%c:\\\\\\\\windows\\\\\\\\system32%'"),
        ("%50\\\\%\\\\_off%", false, "lower(message) LIKE '%50\\\\%\\\\_off%'"),
    ] {
        assert_eq!(ci_like(l, body, neg), want);
    }
    // A non-lower expression is wrapped; a compound one is wrapped whole.
    assert_eq!(ci_like("toString(x)", "%abc%", false), "lower(toString(x)) LIKE '%abc%'");
    assert_eq!(ci_like("lower(toString(ext.a))", "%abc%", false), "lower(toString(ext.a)) LIKE '%abc%'");
    assert_eq!(ci_like("lower(a) || lower(b)", "%abc%", false), "lower(lower(a) || lower(b)) LIKE '%abc%'");
    assert_eq!(ci_like("lower(x)", "a%", false), "lower(x) LIKE 'a%'");
}

/// Every literal pattern arm, positive and negated, emits `lower(..) LIKE`.
#[test]
fn every_literal_pattern_arm_emits_lower_like() {
    let gen = ClickHouseSqlGenerator::new();
    for (q, want) in [
        (r#"command_line="*MimiKatz*""#, "lower(command_line) LIKE '%mimikatz%'"),
        (r#"command_line!="*MimiKatz*""#, "lower(command_line) NOT LIKE '%mimikatz%'"),
        (r#"command_line="kerb*""#, "lower(command_line) LIKE 'kerb%'"),
        (r#"command_line="*roast""#, "lower(command_line) LIKE '%roast'"),
        (r#"command_line CONTAINS "Kerberos""#, "lower(command_line) LIKE '%kerberos%'"),
        (r#"command_line NOT CONTAINS "Kerberos""#, "lower(command_line) NOT LIKE '%kerberos%'"),
        (r#"command_line STARTSWITH "svc""#, "lower(command_line) LIKE 'svc%'"),
        (r#"command_line NOT STARTSWITH "svc""#, "lower(command_line) NOT LIKE 'svc%'"),
        (r#"command_line ENDSWITH ".SKS""#, "lower(command_line) LIKE '%.sks'"),
        (r#"command_line NOT ENDSWITH ".SKS""#, "lower(command_line) NOT LIKE '%.sks'"),
        (r#"command_line LIKE "%NeedleKw7%""#, "lower(command_line) LIKE '%needlekw7%'"),
        (r#"command_line NOT LIKE "%NeedleKw7%""#, "lower(command_line) NOT LIKE '%needlekw7%'"),
        (r#"command_line=/MimiKatz/"#, "lower(command_line) LIKE '%mimikatz%'"),
        (r#"command_line!=/MimiKatz/"#, "lower(command_line) NOT LIKE '%mimikatz%'"),
        (r#"*vchost*"#, "lower(message) LIKE '%vchost%'"),
        (r#"*Cmd.EXE*"#, "lower(message) LIKE '%cmd.exe%'"),
        (r#"message=/cmd\.exe/"#, "lower(message) LIKE '%cmd.exe%'"),
        // `%`/`_`/`\` in a CONTAINS value are literal.
        (r#"message CONTAINS "50%_off""#, r"lower(message) LIKE '%50\\%\\_off%'"),
        // Explicit LIKE keeps the user's wildcards.
        (r#"message LIKE "a_c%""#, "lower(message) LIKE 'a_c%'"),
        // Regex literal rewrites that drop match(): k/s no longer block them.
        (r#"message=/^Kerberos.*/"#, "startsWith(lower(message), 'kerberos')"),
        (r#"message=/(kerberos|skeleton)/"#, "lower(message) LIKE '%kerberos%' OR lower(message) LIKE '%skeleton%'"),
        // ext field: lower(toString(..)) wrap.
        (r#"some_ext_field CONTAINS "Kerberos""#, "LIKE '%kerberos%'"),
        // Non-ASCII literal: lowered ASCII-only, so Ä stays Ä.
        (r#"message CONTAINS "ÄBC""#, "lower(message) LIKE '%Äbc%'"),
        // where-pipe path
        (r#"* | where command_line CONTAINS "Kerberos""#, "LIKE '%kerberos%'"),
        (r#"* | where command_line LIKE "%Kerb%""#, "LIKE '%kerb%'"),
        (r#"* | where command_line STARTSWITH "Kerb""#, "LIKE 'kerb%'"),
    ] {
        let s = sql(&gen, q);
        assert!(s.contains(want), "`{q}` must emit {want}, got:\n{s}");
        assert!(!s.contains("iLike") && !s.contains("ILIKE"), "`{q}` still emits iLike:\n{s}");
    }
}

/// Array-element arms (OCSF multi-valued fields) also go through `ci_like`.
#[test]
fn array_element_patterns_emit_lower_like() {
    let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
    for (q, want) in [
        (r#"metadata.labels CONTAINS "Kerb""#, "lower(x) LIKE '%kerb%'"),
        (r#"metadata.labels="Kerb*""#, "lower(x) LIKE 'kerb%'"),
        (r#"metadata.labels STARTSWITH "Kerb""#, "lower(x) LIKE 'kerb%'"),
        (r#"metadata.labels ENDSWITH "Kerb""#, "lower(x) LIKE '%kerb'"),
        (r#"metadata.labels LIKE "K_rb%""#, "lower(x) LIKE 'k_rb%'"),
    ] {
        let s = sql(&gen, q);
        assert!(s.contains(want), "`{q}` must emit {want}, got:\n{s}");
        assert!(!s.contains("iLike"), "`{q}` still emits iLike:\n{s}");
    }
}

/// Ingest-lowercased columns still compare RAW on equality (LOWERCASE_NORMALIZED).
#[test]
fn ingest_lowercased_equality_stays_raw() {
    let gen = ClickHouseSqlGenerator::new();
    let s = sql(&gen, r#"src_ip="10.0.0.1""#);
    assert!(s.contains("src_ip = '10.0.0.1'") && !s.contains("lower(src_ip) ="), "{s}");
    assert!(!s.contains("PREWHERE"), "{s}");
}
