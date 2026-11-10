// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5142: rule-file import bounds what a YAML document may expand to,
//! and caps the file size, before anything is materialised.

use std::time::{Duration, Instant};

use super::rule_transfer::{
    parse_rule_file, resolve_import_rules, RuleImportParseError, RuleTransferFormat, MAX_RULE_FILE_BYTES,
};

/// Nine levels of nine-way alias fan-out: ~400 bytes of text that expands
/// to 9^9 (~387M) copies of the anchored rule.
fn alias_fanout_doc() -> String {
    let mut doc = String::from("a0: &a0 {name: x, query: error, severity: low}\n");
    for level in 1..=9 {
        let prev = format!("*a{}", level - 1);
        let refs = vec![prev.as_str(); 9].join(", ");
        doc.push_str(&format!("a{level}: &a{level} [{refs}]\n"));
    }
    doc.push_str("rules: *a9\n");
    doc
}

#[test]
fn alias_fanout_is_rejected_quickly() {
    let doc = alias_fanout_doc();
    assert!(doc.len() < 1024, "{}", doc.len());
    let started = Instant::now();
    let result = resolve_import_rules(None, Some(&doc), Some(RuleTransferFormat::Yaml));
    let elapsed = started.elapsed();
    assert!(matches!(result, Err(RuleImportParseError::Expansion)), "{result:?}");
    // Rejected after a few thousand nodes, not hundreds of millions.
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
    let message = result.unwrap_err().to_string();
    assert!(message.contains("aliases are not supported"), "{message}");
}

#[test]
fn large_scalar_fanout_is_rejected() {
    // Few nodes, but each alias replays a 64 KiB string.
    let mut doc = format!("big: &big \"{}\"\nrules:\n", "x".repeat(64 * 1024));
    for _ in 0..200 {
        doc.push_str("  - {name: *big, query: error, severity: low}\n");
    }
    assert!(matches!(
        parse_rule_file(&doc, RuleTransferFormat::Yaml),
        Err(RuleImportParseError::Expansion)
    ));
}

#[test]
fn oversized_file_is_rejected_in_both_formats() {
    let doc = format!("# {}\n[]\n", "x".repeat(MAX_RULE_FILE_BYTES));
    for format in [RuleTransferFormat::Yaml, RuleTransferFormat::Json] {
        assert!(
            matches!(parse_rule_file(&doc, format), Err(RuleImportParseError::TooLarge { .. })),
            "{format:?}"
        );
    }
}

#[test]
fn ordinary_rule_files_still_import() {
    let yaml = r#"rules:
  - name: SSH brute force
    description: "many failures: then success"
    query: 'event_type=auth auth_result=failure user=*admin* | stats count by src_ip | where count > 10'
    severity: high
    mitre_tactics: [credential-access]
    mitre_techniques: [T1110]
    tags:
      - ssh
      - brute-force
  - name: Encoded powershell
    query: |
      process_name="powershell.exe" command_line=*-enc*
      | table src_host, user, command_line
    severity: medium
    narrative: >
      Folded text with a * and & in it,
      and an !exclamation.
"#;
    let rules = parse_rule_file(yaml, RuleTransferFormat::Yaml).unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].name, "SSH brute force");
    assert!(rules[0].query.contains("user=*admin*"));
    assert!(rules[1].query.contains("command_line=*-enc*"));
    assert_eq!(rules[1].narrative.as_deref().map(str::trim), Some("Folded text with a * and & in it, and an !exclamation."));

    // A big but alias-free file (many rules) stays well inside the budget.
    let mut many = String::from("rules:\n");
    for i in 0..2000 {
        many.push_str(&format!("  - {{name: r{i}, query: \"x=1\", severity: low, tags: [a, b, c]}}\n"));
    }
    assert_eq!(parse_rule_file(&many, RuleTransferFormat::Yaml).unwrap().len(), 2000);

    // A tiny file with an incidental, non-amplifying alias still imports.
    let small_alias = "base: &tags [a, b]\nrules:\n  - {name: t, query: error, severity: low, tags: *tags}\n";
    let rules = parse_rule_file(small_alias, RuleTransferFormat::Yaml).unwrap();
    assert_eq!(rules[0].tags.as_deref(), Some(&["a".to_string(), "b".to_string()][..]));
}
