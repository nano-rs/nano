// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{validate_git_ref, validate_path_template, validate_ref_prefix};

#[test]
fn accepts_legit_branch_names() {
    for ok in ["main", "develop", "release/1.2", "feature/foo-bar", "v1.0"] {
        assert!(validate_git_ref(ok).is_ok(), "{ok} should be a valid ref");
    }
}

#[test]
fn rejects_unsafe_branch_names() {
    // NAN-1758: the Caido 191104-style payload plus other malformed refs.
    for bad in [
        "main;touch /tmp/pwn",  // ';' and space
        "main$(id)",            // command-substitution-looking
        "a..b",                 // '..'
        "-main",                // leading '-'
        "/main",                // leading '/'
        "main/",                // trailing '/'
        "main.lock",            // git-reserved suffix
        "feat//x",              // '//'
        "",                     // empty
        "main`id`",             // backtick
        "main\nx",              // control char
    ] {
        assert!(
            validate_git_ref(bad).is_err(),
            "{bad:?} must be rejected as a branch name"
        );
    }
}

#[test]
fn ref_prefix_allows_trailing_slash_but_rejects_injection() {
    for ok in ["nano-tuning/", "tuning/", "auto-", "prefix/sub/", ""] {
        assert!(validate_ref_prefix(ok).is_ok(), "{ok:?} should be a valid prefix");
    }
    for bad in [
        "nano-tuning/$(id)", // Caido 191105
        "nano-tuning/;rm",
        "../evil",
        "/leading",
        "-leading",
        "a b",
    ] {
        assert!(
            validate_ref_prefix(bad).is_err(),
            "{bad:?} must be rejected as a branch prefix"
        );
    }
}

#[test]
fn accepts_legit_path_templates() {
    for ok in [
        "detections/{rule_name}.npl",
        "rules/{rule_id}.yml",
        "sigma/windows/{rule_name}.yaml",
        "single.npl",
    ] {
        assert!(
            validate_path_template(ok).is_ok(),
            "{ok} should be a valid path template"
        );
    }
}

#[test]
fn rejects_unsafe_path_templates() {
    // NAN-1758: the Caido 191106 traversal payload plus siblings.
    for bad in [
        "../../.github/workflows/pwn.yml", // traversal + .github
        ".github/workflows/pwn.yml",       // .github workflow sink
        "/etc/passwd",                     // absolute
        "detections/../../../etc/passwd",  // mid-path traversal
        "detections/{rule_name}/",         // trailing slash (not a file)
        "a//b.npl",                        // empty segment
        "det ections/x.npl",               // space
        "rules/%2e%2e/x.npl",              // percent-encoding
        "",                                // empty
    ] {
        assert!(
            validate_path_template(bad).is_err(),
            "{bad:?} must be rejected as a path template"
        );
    }
}
