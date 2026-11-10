// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5227: a rule that writes `source_type` must not choose its own origin.

use super::*;
use crate::db::repository::alerts::distinct_source_types;
use serde_json::json;

fn plan(q: &str) -> RowProvenance {
    RowProvenance::for_rule_query(q)
}

#[test]
fn base_column_is_trusted_through_pass_through_stages() {
    for q in [
        "source_type=windows",
        "source_type=windows | where user=\"a\" | sort -timestamp | head 10",
        "source_type=windows | dedup user | fields user, source_type",
        "source_type=windows | table user, source_type",
        "source_type=windows | stats count by source_type, user",
        "source_type=windows | eval user_lc=lower(user)",
        "source_type=windows | rename user AS account",
        "source_type=windows | top user by source_type",
        "source_type=windows | rex field=message \"user=(?<account>\\w+)\"",
        "source_type=windows | fillnull value=\"-\" user",
        "source_type=windows | spath input=message output=detail path=a.b",
        "source_type=windows | spath input=message path=a.b",
        "source_type=windows | mvexpand user",
    ] {
        let p = plan(q);
        assert!(!p.untrusted_source_type, "{q} should keep the base column");
        assert!(!p.has_subsearch, "{q} has no subsearch");
    }
}

#[test]
fn stages_that_can_write_source_type_are_untrusted() {
    for q in [
        "source_type=audit | eval source_type=\"windows\"",
        "source_type=audit | eval Source_Type=\"windows\"",
        "source_type=audit | rename user AS source_type",
        "source_type=audit | table user AS source_type",
        "source_type=audit | stats count by user | eval source_type=\"windows\"",
        "source_type=audit | stats values(user) AS source_type by host",
        "source_type=audit | rex field=message \"(?<source_type>\\w+)\"",
        "source_type=audit | fillnull value=\"x\" source_type",
        "source_type=audit | fillnull value=\"x\"",
        "source_type=audit | spath input=message output=source_type path=a",
        "source_type=audit | spath input=message path=meta.source_type",
        "source_type=audit | spath input=message",
    ] {
        assert!(plan(q).untrusted_source_type, "{q} can relabel rows");
    }
}

#[test]
fn subsearches_are_flagged() {
    for q in [
        "source_type=windows | append [ search source_type=audit ]",
        "source_type=windows user IN [ search source_type=audit | fields user ]",
    ] {
        assert!(plan(q).has_subsearch, "{q} has a subsearch");
    }
}

#[test]
fn unparseable_rule_fails_closed() {
    let p = plan("source_type=audit | eval (((");
    assert!(p.untrusted_source_type && p.has_subsearch);
}

#[test]
fn demoted_row_takes_its_origin_from_the_stamp() {
    // Before NAN-5227 the forged per-event value was the alert's only origin.
    let mut row = json!({"user": "a", "source_type": "windows"});
    assert_eq!(distinct_source_types(&json!([row.clone()])), vec!["windows"]);

    demote_rule_source_type(&mut row);
    assert!(row.get("source_type").is_none());
    assert_eq!(row[RULE_SOURCE_TYPE_FIELD], "windows");

    // The engine then stamps the base-search provenance.
    row.as_object_mut()
        .unwrap()
        .insert("_nano_source_types".into(), json!(["audit"]));
    assert_eq!(distinct_source_types(&json!([row])), vec!["audit"]);
}

#[test]
fn demote_is_a_no_op_without_the_field() {
    let mut row = json!({"count": 3});
    demote_rule_source_type(&mut row);
    assert_eq!(row, json!({"count": 3}));
}
