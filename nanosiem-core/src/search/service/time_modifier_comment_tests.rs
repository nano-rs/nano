// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3377: `//` comments must end at their newline. The time-modifier
//! extraction flattens whitespace before the parser strips comments, so a
//! comment on its own line used to swallow every later line.
use super::extract_time_modifiers;
use crate::query::parse_query;

#[test]
fn own_line_comments_keep_the_rest_of_the_query_nan3377() {
    let (cleaned, earliest, latest) = extract_time_modifiers("base\n// note\n| where x=1").unwrap();
    assert_eq!(cleaned, "base | where x=1");
    assert_eq!((earliest, latest), (None, None));
    assert_eq!(
        parse_query(&cleaned).unwrap(),
        parse_query("base | where x=1").unwrap()
    );

    // A leading comment line used to leave an empty query (400).
    let (cleaned, _, _) = extract_time_modifiers("// c\nbase").unwrap();
    assert_eq!(cleaned, "base");
    assert_eq!(parse_query(&cleaned).unwrap(), parse_query("base").unwrap());

    // Time modifiers are still extracted around a comment line.
    let (cleaned, earliest, latest) =
        extract_time_modifiers("earliest=-2h base\n// c\n| head 5").unwrap();
    assert_eq!(cleaned, "base | head 5");
    assert!(earliest.is_some_and(|s| (s + 2 * 3600).abs() <= 1), "{earliest:?}");
    assert_eq!(latest, None);

    // Block comments spanning lines, CRLF line endings and trailing comments
    // all reduce to the same query.
    for query in [
        "base\r\n// note\r\n| where x=1",
        "base /* one\ntwo */\n| where x=1",
        "base // trailing\n| where x=1",
    ] {
        let (cleaned, _, _) = extract_time_modifiers(query).unwrap();
        assert_eq!(cleaned, "base | where x=1", "{query:?}");
    }

    // An `earliest=` written inside a comment is commentary, not the range
    // (the parser never sees it either).
    let (cleaned, earliest, _) =
        extract_time_modifiers("base // earliest=-30d was too slow\n| head 5").unwrap();
    assert_eq!(cleaned, "base | head 5");
    assert_eq!(earliest, None);

    // `//` inside a quoted value is not a comment.
    let (cleaned, _, _) = extract_time_modifiers("url=\"http://x/y\"\n// note\n| head 5").unwrap();
    assert_eq!(cleaned, "url=\"http://x/y\" | head 5");
}

/// Lane A review P2-6: a `//` that is not at a token boundary is query text.
/// The parser accepts bare URL keywords and regex literals; stripping must
/// not truncate them on the server path.
#[test]
fn comment_openers_need_a_token_boundary() {
    // Bare URL keyword: kept whole, a real trailing comment still stripped.
    let (cleaned, _, _) =
        extract_time_modifiers("http://evil.example/payload | stats count // note").unwrap();
    assert_eq!(cleaned, "http://evil.example/payload | stats count");
    assert_eq!(
        parse_query(&cleaned).unwrap(),
        parse_query("http://evil.example/payload | stats count").unwrap()
    );
    // Quoted URL.
    let (cleaned, _, _) = extract_time_modifiers("url=\"https://x/y\" // c\n| head 1").unwrap();
    assert_eq!(cleaned, "url=\"https://x/y\" | head 1");
    // Escaped-slash regex literal (`/a\//`) and a URL path glob.
    let (cleaned, _, _) = extract_time_modifiers("user=/a\\// | head 1").unwrap();
    assert_eq!(cleaned, "user=/a\\// | head 1");
    let (cleaned, _, _) = extract_time_modifiers("uri_path=/api/* | head 1").unwrap();
    assert_eq!(cleaned, "uri_path=/api/* | head 1");
    // Real comments: own line, after whitespace, block, leading.
    for (query, want) in [
        ("base\n// note\n| head 1", "base | head 1"),
        ("base // trailing\n| head 1", "base | head 1"),
        ("base /* block */ | head 1", "base | head 1"),
        ("// leading\nbase", "base"),
        ("/* leading */ base", "base"),
    ] {
        let (cleaned, _, _) = extract_time_modifiers(query).unwrap();
        assert_eq!(cleaned, want, "{query:?}");
    }
}
