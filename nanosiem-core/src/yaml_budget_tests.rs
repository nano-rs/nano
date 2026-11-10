// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5142: the shared YAML expansion budget, and the user/repo YAML
//! parsers that sit behind it.

use std::time::{Duration, Instant};

/// Nine levels of nine-way alias fan-out (~9^9 expanded nodes) hung off
/// `key` inside an otherwise ordinary document.
fn alias_fanout(prefix: &str, key: &str) -> String {
    let mut doc = String::from(prefix);
    doc.push_str("x0: &a0 [lol, lol, lol, lol, lol, lol, lol, lol, lol]\n");
    for level in 1..=9 {
        let prev = format!("*a{}", level - 1);
        doc.push_str(&format!("x{level}: &a{level} [{}]\n", vec![prev.as_str(); 9].join(", ")));
    }
    doc.push_str(&format!("{key}: *a9\n"));
    doc
}

const SIGMA: &str = r#"title: Suspicious PowerShell
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: experimental
description: Encoded PowerShell command line
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
"#;

#[test]
fn fanout_is_rejected_quickly_and_plain_yaml_passes() {
    let doc = alias_fanout("", "boom");
    assert!(doc.len() < 1024);
    let started = Instant::now();
    assert_eq!(super::check(&doc), Err(super::ExpansionExceeded));
    let err = super::from_str::<serde_yaml::Value>(&doc).unwrap_err();
    assert!(err.to_string().contains("aliases are not supported"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());

    assert_eq!(super::check(SIGMA), Ok(()));
    // Malformed YAML is left to the real parse, which reports it.
    assert_eq!(super::check("not: [valid"), Ok(()));
    assert!(super::from_str::<serde_yaml::Value>("not: [valid").is_err());
}

#[test]
fn sigma_parse_rejects_fanout_and_still_parses_normal_rules() {
    let rule = crate::rule_repository::parse_sigma(SIGMA).expect("normal Sigma parses");
    assert_eq!(rule.title, "Suspicious PowerShell");

    // The fan-out sits in the free-form `detection` block, which is kept
    // as a generic value tree.
    let bomb = alias_fanout("title: t\nlogsource: {product: windows}\n", "anchors_done")
        + "detection:\n  condition: selection\n  selection:\n    CommandLine: *a9\n";
    let started = Instant::now();
    let err = crate::rule_repository::parse_sigma(&bomb).unwrap_err();
    assert!(err.to_string().contains("aliases are not supported"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
}
