// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5694: every `lookup … OUTPUT` form parses with the OCSF dotted event
//! field intact, the output list in order, and the rest of the pipeline
//! (`| stats count by owner`) left as its own stage.

use crate::query::{parse_query, Command, FieldRename, PrettyPrint, Query};

fn lookup(q: &str) -> (Command, Query) {
    let query = parse_query(q).unwrap_or_else(|e| panic!("{q}: {e}"));
    let mut node = &query;
    loop {
        match node {
            Query::Piped { command: c @ Command::Lookup { .. }, .. } => return (c.clone(), query.clone()),
            Query::Piped { source, .. } => node = source,
            Query::Search(_) => panic!("{q}: no lookup"),
        }
    }
}

#[test]
fn output_forms_keep_the_ocsf_event_field_and_their_outputs() {
    let rename = |from: &str, to: &str| FieldRename { from: from.into(), to: to.into() };
    for (q, outputs, renames, new) in [
        ("class_uid=3002 | lookup owners device.hostname OUTPUT owner", vec!["owner"], vec![], false),
        ("class_uid=3002 | lookup owners device.hostname OUTPUT owner AS team", vec!["owner"], vec![rename("owner", "team")], false),
        ("class_uid=3002 | lookup owners device.hostname OUTPUTNEW owner", vec!["owner"], vec![], true),
        ("class_uid=3002 | lookup owners device.hostname OUTPUT owner, site", vec!["owner", "site"], vec![], false),
        ("class_uid=3002 | lookup owners device.hostname OUTPUT owner site", vec!["owner", "site"], vec![], false),
        ("class_uid=3002 | lookup owners actor.user.name AS user OUTPUT owner", vec!["owner"], vec![], false),
    ] {
        let (cmd, query) = lookup(q);
        let Command::Lookup { table_name, event_field, output_fields, output_renames, output_new, .. } = cmd else {
            unreachable!()
        };
        assert_eq!(table_name, "owners", "{q}");
        assert!(event_field == "device.hostname" || event_field == "actor.user.name", "{q}");
        assert_eq!(output_fields, Some(outputs.iter().map(|s| s.to_string()).collect()), "{q}");
        assert_eq!(output_renames, renames, "{q}");
        assert_eq!(output_new, new, "{q}");
        assert_eq!(parse_query(&query.pretty_print()).unwrap(), query, "{q}");
    }
}

#[test]
fn a_stage_after_output_is_its_own_command() {
    let q = "class_uid=3002 | lookup owners device.hostname OUTPUT owner | stats count by owner";
    let Query::Piped { command: Command::Stats { group_by, .. }, source } = parse_query(q).unwrap() else {
        panic!("stats after lookup")
    };
    assert_eq!(group_by, Some(vec!["owner".to_string()]));
    let Query::Piped { command: Command::Lookup { output_fields, .. }, .. } = *source else {
        panic!("lookup")
    };
    assert_eq!(output_fields, Some(vec!["owner".to_string()]));
}
