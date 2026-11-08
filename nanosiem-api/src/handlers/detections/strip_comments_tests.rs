// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4283: the detection-query comment stripper keeps unquoted URL values
//! and URL globs; only a `//` / `/*` at a token boundary is a comment.
use super::strip_comments;

#[test]
fn url_values_are_never_comments() {
    assert_eq!(
        strip_comments("url=https://host/x | stats count by src_ip"),
        "url=https://host/x | stats count by src_ip"
    );
    assert_eq!(
        strip_comments("url=https://x.example/a/* | stats count"),
        "url=https://x.example/a/* | stats count"
    );
}

#[test]
fn comments_at_a_token_boundary_are_stripped() {
    assert_eq!(strip_comments("a=1 // note\n| stats count"), "a=1\n| stats count");
    assert_eq!(strip_comments("a=\"x//y\" /* c */ | head 1"), "a=\"x//y\"   | head 1");
    assert_eq!(strip_comments("// header\nprocess=cmd.exe"), "process=cmd.exe");
}
