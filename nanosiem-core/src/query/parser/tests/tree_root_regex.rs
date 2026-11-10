// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5159: `tree … root=/…/` — the regex literal ends at the first UNESCAPED
//! `/`, and `\` escapes the next character. The web tree pivot escapes `\` and
//! `/` in the clicked value (`nplRegexBody`); these tests pin the server half of
//! that contract.

use crate::query::{parse_query, Command, Query};

fn tree_root(npl: &str) -> (Option<String>, usize) {
    let parsed = parse_query(npl).unwrap_or_else(|e| panic!("{npl} must parse: {e:?}"));
    let mut stages = 0;
    let mut root = None;
    let mut q = &parsed;
    while let Query::Piped { source, command } = q {
        stages += 1;
        if let Command::Tree { root_filter, .. } = command {
            root = Some(root_filter.clone());
        }
        q = source;
    }
    (root.expect("no tree command"), stages)
}

#[test]
fn escaped_slash_and_pipe_stay_inside_the_root_regex() {
    // Value `a/b | x` as the web pivot emits it.
    let (root, stages) = tree_root(r"* | tree web root=/a\/b | x/");
    assert_eq!(root.as_deref(), Some(r"/a\/b | x/"));
    assert_eq!(stages, 1, "the value must not add a pipeline stage");
}

#[test]
fn escaped_regex_body_matches_the_original_value() {
    let (root, _) = tree_root(r"* | tree process root=/C:\\Users\\x\/y/");
    let root = root.unwrap();
    let re = regex::RegexBuilder::new(&root[1..root.len() - 1])
        .case_insensitive(true)
        .build()
        .expect("escaped body must be a valid regex");
    assert!(re.is_match(r"C:\Users\x/y"));
}

#[test]
fn unescaped_slash_ends_the_literal() {
    // What the pre-fix pivot produced: the remainder became more pipeline.
    let (root, stages) = tree_root("* | tree web root=/a/ | head 1");
    assert_eq!(root.as_deref(), Some("/a/"));
    assert_eq!(stages, 2);
}
