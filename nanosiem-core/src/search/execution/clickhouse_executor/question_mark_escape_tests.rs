// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5793 review: `escape_question_marks_in_strings` must leave no bare `?`
//! in a literal, a quoted identifier or a comment, and none of those may flip
//! the quote state for what follows (a denied source literal after them).

use super::sql_helpers::escape_question_marks_in_strings as esc;

/// Every `?` the driver would read as a placeholder: a lone `?` not part of
/// a `??` pair.
fn bare_placeholders(sql: &str) -> usize {
    let b = sql.as_bytes();
    let mut i = 0;
    let mut n = 0;
    while i < b.len() {
        if b[i] == b'?' {
            if i + 1 < b.len() && b[i + 1] == b'?' {
                i += 2;
                continue;
            }
            n += 1;
        }
        i += 1;
    }
    n
}

#[test]
fn string_literals_are_escaped_as_before() {
    assert_eq!(esc("x = 'a?b'"), "x = 'a??b'");
    assert_eq!(esc("x = 'it''s?'"), "x = 'it''s??'");
    assert_eq!(esc("match(x, '(?i)a')"), "match(x, '(??i)a')");
}

#[test]
fn a_backslash_escaped_quote_does_not_end_the_literal() {
    assert_eq!(esc(r"x = 'a\'?' AND y = 'we?ird'"), r"x = 'a\'??' AND y = 'we??ird'");
}

#[test]
fn question_marks_in_quoted_identifiers_are_escaped() {
    assert_eq!(esc(r#"SELECT action AS "is_admin?""#), r#"SELECT action AS "is_admin??""#);
    assert_eq!(esc(r#"SELECT a AS "a?fields""#), r#"SELECT a AS "a??fields""#);
    assert_eq!(esc("SELECT `we?ird` FROM t"), "SELECT `we??ird` FROM t");
}

#[test]
fn an_apostrophe_in_a_quoted_identifier_does_not_flip_the_literal_state() {
    let sql = r#"SELECT action AS "don't" FROM t WHERE source_type NOT IN ('we?ird')"#;
    let out = esc(sql);
    assert!(out.contains("('we??ird')"), "{out}");
    assert_eq!(bare_placeholders(&out), 0, "{out}");
}

#[test]
fn an_apostrophe_in_a_comment_does_not_flip_the_literal_state() {
    let sql = "SELECT x -- weighted by the entity's score\nFROM t WHERE s NOT IN ('we?ird')";
    let out = esc(sql);
    assert!(out.contains("('we??ird')"), "{out}");
    assert_eq!(bare_placeholders(&out), 0, "{out}");
    let block = esc("SELECT /* it's? */ 1 WHERE s = 'we?ird'");
    assert_eq!(block, "SELECT /* it's?? */ 1 WHERE s = 'we??ird'");
}

#[test]
fn real_placeholders_outside_literals_are_left_alone() {
    assert_eq!(esc("WHERE a = ? AND b = 'c?'"), "WHERE a = ? AND b = 'c??'");
    assert_eq!(esc("SELECT 1 - -1, 2/3"), "SELECT 1 - -1, 2/3");
}

/// NAN-5793 review round 2: ClickHouse block comments nest.
#[test]
fn nested_block_comments_stay_comments() {
    let out = esc("SELECT /* outer /* inner */ don't? */ 1 WHERE s = 'we?ird'");
    assert_eq!(out, "SELECT /* outer /* inner */ don't?? */ 1 WHERE s = 'we??ird'");
    assert_eq!(bare_placeholders(&out), 0, "{out}");
}

/// NAN-5793 review round 2: `$$…$$` and `$tag$…$tag$` raw strings.
#[test]
fn dollar_quoted_strings_are_escaped_and_do_not_flip_the_state() {
    assert_eq!(esc("SELECT $$a?b$$"), "SELECT $$a??b$$");
    let out = esc("SELECT $$don't$$ FROM logs WHERE s = 'a?b'");
    assert_eq!(out, "SELECT $$don't$$ FROM logs WHERE s = 'a??b'");
    let tagged = esc("SELECT $q$it's ? $q$ , 'x?'");
    assert_eq!(tagged, "SELECT $q$it's ?? $q$ , 'x??'");
    assert_eq!(bare_placeholders(&tagged), 0, "{tagged}");
    // A `$` inside an identifier is not a quote.
    assert_eq!(esc("SELECT a$b$ FROM t WHERE x = ?"), "SELECT a$b$ FROM t WHERE x = ?");
}
