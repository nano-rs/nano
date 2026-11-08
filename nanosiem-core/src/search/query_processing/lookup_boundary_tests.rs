// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::query::{parse_query, PrettyPrint};

fn plan(q: &str) -> Result<bool, String> {
    lookup_boundary_plan(&parse_query(q).unwrap())
}

#[test]
fn a_lookup_cuts_the_query_and_replays_the_suffix() {
    let q = parse_query(
        r#"class_uid=4001 | lookup assets src_endpoint.ip AS ip OUTPUT owner AS asset_owner | where asset_owner="bob" | stats count by asset_owner"#,
    )
    .unwrap();
    assert_eq!(lookup_boundary_plan(&q), Ok(true));
    assert_eq!(strip_enrichment_and_after(&q).pretty_print(), "class_uid=4001");
    let suffix = extract_post_enrichment_commands(&q);
    assert_eq!(suffix.len(), 2);
    assert!(matches!(suffix[0], Command::Where { .. }) && matches!(suffix[1], Command::Stats { .. }));
}

#[test]
fn lookups_inside_another_stage_suffix_and_refusals() {
    assert_eq!(plan("* | prevalence enrich=true | lookup t src_endpoint.ip AS ip | where owner=\"b\""), Ok(false));
    assert_eq!(plan("* | lookup t src_endpoint.ip AS ip | prevalence enrich=true | where x=1"), Ok(false));
    assert!(plan("* | lookup t src_endpoint.ip AS ip | where owner=\"b\" | prevalence enrich=true").is_err());
    assert!(plan("* | lookup a src_endpoint.ip AS ip | where owner=\"b\" | lookup c actor.user.name AS u").is_err());
    assert_eq!(plan("* | lookup a src_endpoint.ip AS ip | lookup c actor.user.name AS u | where owner=\"b\""), Ok(true));
    assert_eq!(plan("* | where x=1"), Ok(false));
}
