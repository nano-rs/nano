// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4664: cache / in-flight identity normalization.
use super::*;

#[test]
fn normalization_trims_and_collapses_only_outside_strings() {
    assert_eq!(normalize_query("  class_uid=1007   |  stats count by  process.name \t"), "class_uid=1007 | stats count by process.name");
    // Inside quotes whitespace is data.
    assert_eq!(normalize_query(r#"message="a   b"  |  head 5"#), r#"message="a   b" | head 5"#);
    assert_eq!(normalize_query("user='x  y'   | head"), "user='x  y' | head");
    // Newlines are kept: a `//` comment ends at one.
    assert_eq!(normalize_query("a\n  | head 5"), "a\n | head 5");
}

#[test]
fn normalization_is_conservative_where_meaning_could_change() {
    // Regex literals, comments, division: only trimmed.
    for query in ["user=/admin  .*/i", "a // note  x\n| head", "eval r=a/b  | head", r#"message="a\"  b""#, "x=`y  z`"] {
        assert_eq!(normalize_query(&format!("  {query}  ")), query);
    }
    // An unbalanced quote: only trimmed.
    assert_eq!(normalize_query(r#" message="a   b "#), r#"message="a   b"#);
    // Different meanings never collapse together.
    assert_ne!(normalize_query(r#"message="a b""#), normalize_query(r#"message="a  b""#));
}

/// Review (NAN-4664): whatever the lexer guesses, a normalized query is
/// either the trimmed text or parses to exactly the original's AST, so
/// two queries of different meaning can never share an identity.
#[test]
fn normalization_never_changes_the_parsed_query() {
    let corpus = [
        "class_uid=1007   |  stats count by  process.name",
        r#"x=a"b m="p   q" y=c"d"#,
        r#"user=O'Brien   m="x  ' y   z"   n='w'"#,
        r#"* | eval label="a   b"  |  table label"#,
        r#"* | rex field=message "(?<user>\w+)  logged"  | head 5"#,
        "* | where  count  >  10\n  | head  5",
        "process.name=cmd.exe\t\t| stats  count",
        r#"message="unterminated   | head"#,
    ];
    for query in corpus {
        let normalized = normalize_query(query);
        if normalized.as_ref() != query.trim() {
            assert!(
                parses_identically(query.trim(), &normalized),
                "{query:?} normalized to {normalized:?} with a different meaning"
            );
        }
    }
}

#[test]
fn use_cache_tri_state_read_decision() {
    // Absent: today's behavior (read) for every caller.
    assert!(reads_result_cache(false, None));
    assert!(reads_result_cache(false, Some(true)));
    // Explicit false: a fresh run (it still writes and still shares).
    assert!(!reads_result_cache(false, Some(false)));
    // The bypass header always wins.
    assert!(!reads_result_cache(true, None));
    assert!(!reads_result_cache(true, Some(true)));
}

#[test]
fn cache_key_uses_the_normalized_query() {
    let request = |query: &str| -> SearchRequest {
        serde_json::from_value(serde_json::json!({"query": query,
            "time_range": {"start": "2026-10-26T00:00:00Z", "end": "2026-10-27T00:00:00Z"}})).unwrap()
    };
    let scope = ScopeSet::default();
    assert_eq!(
        SearchResultCache::cache_key(&request(" class_uid=1007  | head 5 "), &scope),
        SearchResultCache::cache_key(&request("class_uid=1007 | head 5"), &scope),
    );
    assert_ne!(
        SearchResultCache::cache_key(&request(r#"m="a  b""#), &scope),
        SearchResultCache::cache_key(&request(r#"m="a b""#), &scope),
    );
}
