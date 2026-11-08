// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn interpolation_syntax_is_detected() {
    for bad in [
        "${VECTOR_AUTH_TOKEN}",
        "x${A:-b}y",
        "$VECTOR_AUTH_TOKEN.attacker:9092",
        "$_X",
        ".leak = \"${CLICKHOUSE_PASSWORD}\"",
        "$$${X}",
    ] {
        assert!(contains_env_interpolation(bad), "{bad}");
    }
    for ok in ["plain", "^end$", "cost $5", "a$", "$$", "50%$", "$$HOME", "r'^a$'", "\"$1\""] {
        assert!(!contains_env_interpolation(ok), "{ok}");
    }
    assert_eq!(first_env_interpolation("ab $$X ${Y}"), Some(7));
}

#[test]
fn escape_file_doubles_every_dollar_and_is_idempotent() {
    let rendered = "source = \"x = \\\"${CLICKHOUSE_PASSWORD}\\\" + \\\"$1\\\"\"\n";
    let escaped = escape_file(rendered);
    assert!(escaped.starts_with(&format!("{ENV_ESCAPED_HEADER}\n")), "{escaped}");
    assert!(escaped.contains("$${CLICKHOUSE_PASSWORD}"), "{escaped}");
    assert!(escaped.contains("$$1"), "{escaped}");
    assert_eq!(escape_file(&escaped), escaped, "escaping twice must be a no-op");
    assert!(is_escaped_file(&escaped));
    assert_eq!(unescape_file(&escaped), rendered);
    // Still valid TOML for the in-process checks.
    toml::from_str::<toml::Value>(&escaped).unwrap();
}

/// What the live Vector will run: substituting the escaped file the way Vector
/// does yields the tenant's text byte for byte, never an environment value.
#[test]
fn vector_substitution_of_an_escaped_file_is_the_original_text() {
    let tenant = "x = \"${CLICKHOUSE_PASSWORD} $VECTOR_AUTH_TOKEN r'^a$' $1 $$\"\n";
    let escaped = escape_file(tenant);
    let after = substitute_like_vector(&escaped);
    assert_eq!(after, format!("{ENV_ESCAPED_HEADER}\n{tenant}"));
}

#[test]
fn substitution_matches_vector_for_nano_owned_references() {
    assert_eq!(substitute_like_vector("a = ${X:-1}"), "a = 1");
    assert_eq!(substitute_like_vector("a = \"${X}\""), "a = \"\"");
    assert_eq!(substitute_like_vector("a = \"$X.b c\""), "a = \" c\"");
    assert_eq!(substitute_like_vector("a = \"$1\""), "a = \"\"");
    assert_eq!(substitute_like_vector("a = \"$$X\""), "a = \"$X\"");
    assert_eq!(substitute_like_vector("re = '^a$'"), "re = '^a$'");
    assert_eq!(substitute_like_vector("u = ${X:-http://h:1}/p"), "u = http://h:1/p");
    assert_eq!(substitute_like_vector("cut ${X"), "cut ${X");
    assert_eq!(substitute_like_vector("é $$ ü"), "é $ ü");
}

#[test]
fn fragment_escape_leaves_surrounding_references_alone() {
    let vrl = ".a = \"${CLICKHOUSE_PASSWORD}\"";
    let file = format!(
        "{ENV_ESCAPED_TENANT_HEADER}\nsource = '''\n{}\n'''\npassword = \"${{CLICKHOUSE_PASSWORD:-nanosiem}}\"\n",
        escape_fragment(vrl)
    );
    let after = substitute_like_vector(&file);
    assert!(after.contains(vrl), "{after}");
    assert!(after.contains("password = \"nanosiem\""), "{after}");
}

#[test]
fn vrl_rejection_names_the_position_and_the_literal_escape() {
    let err = reject_vrl_interpolation("parser_vrl", ".a = 1\n.b = \"${CLICKHOUSE_PASSWORD}\"").unwrap_err();
    assert!(err.contains("parser_vrl"), "{err}");
    assert!(err.contains("line 2, column 7"), "{err}");
    assert!(err.contains("${CLICKHOUSE_PASSWORD}"), "{err}");
    assert!(err.contains("\"$\" + \"{NAME}\""), "{err}");
    assert!(reject_vrl_interpolation("x", ".b = \"$VECTOR_AUTH_TOKEN\"").is_err());
    // The documented literal forms, regex anchors and capture refs pass.
    for ok in [
        ".b = \"$\" + \"{NAME}\"",
        ".b = \"$\" + \"NAME\"",
        "match(.m, r'^a$')",
        "replace(.m, r'(a)', \"$1\")",
        ".price = \"$5\"",
    ] {
        reject_vrl_interpolation("parser_vrl", ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
}

#[test]
fn vrl_rejection_covers_secret_backend_syntax() {
    let err = reject_vrl_interpolation("parser_vrl", ".a = \"SECRET[nano.pw]\"").unwrap_err();
    assert!(err.contains("SECRET["), "{err}");
    reject_vrl_interpolation("parser_vrl", ".a = \"SECRET\" + \"[nano.pw]\"").unwrap();
}
