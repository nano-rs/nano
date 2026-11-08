// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn lookup_command_is_a_reference() {
    assert!(query_text_references_lookup(
        "process.name=cmd.exe | lookup asset_inventory src_ip",
        "asset_inventory"
    ));
    assert!(query_text_references_lookup(
        "* | lookup Asset_Inventory src_ip OUTPUT owner",
        "asset_inventory"
    ));
}

#[test]
fn table_backed_inputlookup_and_ioc_lookup_are_references() {
    assert!(query_text_references_lookup("| inputlookup threat_intel", "threat_intel"));
    assert!(query_text_references_lookup(
        r#"ioc in lookup("threat_iocs") | stats count by src_ip"#,
        "threat_iocs"
    ));
    assert!(query_text_references_lookup("ioc in [inputlookup threat_iocs]", "threat_iocs"));
}

#[test]
fn references_inside_subsearches_count() {
    assert!(query_text_references_lookup(
        "* | join user [search * | lookup hr_roster user]",
        "hr_roster"
    ));
    assert!(query_text_references_lookup(
        r#"* | append [search ioc in lookup("blocklist")]"#,
        "blocklist"
    ));
}

#[test]
fn other_tables_and_url_inputlookups_are_not_references() {
    assert!(!query_text_references_lookup(
        "* | lookup asset_inventory_v2 src_ip",
        "asset_inventory"
    ));
    assert!(!query_text_references_lookup(
        r#"* | inputlookup url="https://feeds.example.com/asset_inventory.csv""#,
        "asset_inventory"
    ));
    // A field value that merely contains the name is not a dependency.
    assert!(!query_text_references_lookup(r#"message="asset_inventory sync done""#, "asset_inventory"));
}

#[test]
fn legacy_at_token_and_search_prefix_still_count() {
    assert!(query_text_references_lookup("search * | lookup @nan2875.id", "nan2875"));
    assert!(query_text_references_lookup("search * | lookup asset_inventory src_ip", "asset_inventory"));
}

#[test]
fn unparseable_rule_text_is_conservative() {
    assert!(query_text_references_lookup(
        "this is not ) valid npl | lookup asset_inventory",
        "asset_inventory"
    ));
    assert!(!query_text_references_lookup("this is not ) valid npl", "asset_inventory"));
}

#[test]
fn word_bounded_token_match() {
    assert!(has_word_bounded("foo @bar", "@bar"));
    assert!(has_word_bounded("x IN @bar.col", "@bar"));
    assert!(has_word_bounded("where x = @bar)", "@bar"));
    assert!(has_word_bounded("WHERE x = @BAR", "@bar"));
    assert!(!has_word_bounded("use @bar_baz", "@bar"));
    assert!(!has_word_bounded("use @other", "@bar"));
    // Bare names are bounded on both sides.
    assert!(has_word_bounded("lookup bar src_ip", "bar"));
    assert!(!has_word_bounded("lookup foobar src_ip", "bar"));
}
