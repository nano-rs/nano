// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn a_hec_source_claims_by_match_values_or_by_name() {
    let claims = vec!["okta".to_string()];
    assert!(hec_source_claims("splunk_hec", "Okta parser", Some(&claims), "okta"));
    assert!(hec_source_claims("HEC", "Okta parser", Some(&claims), "okta"), "aliases are canonicalized");
    assert!(!hec_source_claims("routed", "okta", Some(&claims), "okta"), "another lane cannot collide");
    assert!(!hec_source_claims("splunk_hec", "Okta parser", Some(&claims), "slack_access_log"));
    assert!(hec_source_claims("splunk", "okta", Some(&[]), "okta"), "no match values: claimed by name");
    assert!(!hec_source_claims("splunk_hec", "Other", None, "okta"));
    // Exactly as Vector routes a source with no match values: the safe form
    // of its name (vector_naming::claim_keys), not the raw name.
    assert!(hec_source_claims("splunk_hec", "GWS Login", None, "gws_login"));
    assert!(!hec_source_claims("splunk_hec", "GWS Login", None, "GWS Login"));
    assert!(hec_source_claims("splunk_hec", "Okta", Some(&[]), "okta"));
}

#[test]
fn the_pull_source_is_named_for_the_connector() {
    assert_eq!(owned_source_name("google_workspace", 1), "google_workspace_pull");
    assert_eq!(owned_source_name("google_workspace", 2), "google_workspace_pull_2");
}

#[test]
fn refusals_are_plain_english_and_name_what_to_do() {
    let one = LaneSetupError::NotPermitted { missing: vec!["parser_repositories:import"] };
    assert_eq!(
        one.to_string(),
        "Setting up the log sources this feed needs also takes the parser_repositories:import permission. \
         Ask an admin to give you it, or to set up these log sources under Log sources first."
    );
    assert!(one.is_forbidden());
    let two = LaneSetupError::NotPermitted { missing: vec!["parser_repositories:import", "log_sources:edit"] };
    assert!(two.to_string().contains("permissions. Ask an admin to give you them"), "{two}");

    let none = LaneSetupError::ParserNotInCatalog {
        connector: "Google Workspace".into(),
        parser: "google_workspace_ocsf".into(),
        lanes: "`gws_login`".into(),
    };
    let text = none.to_string();
    assert!(text.contains("could not find the Google Workspace parser (google_workspace_ocsf)"), "{text}");
    assert!(text.contains("Sync the nano-rs/parsers catalog"), "{text}");
    assert!(!none.is_forbidden() && !none.is_conflict());

    assert!(LaneSetupError::Busy.is_conflict());
    assert!(LaneSetupError::NameTaken { name: "okta_pull".into(), holder: "Okta Pull".into() }.is_conflict());
    let held = LaneSetupError::LaneHeldByAnotherSource { lane: "okta".into(), source_name: "My Okta".into(), why: "not deployed" };
    assert!(held.is_conflict());
    assert!(held.to_string().starts_with("The log source \"My Okta\" already takes okta events, but it is not deployed."));

    for e in [one, two, none, held] {
        assert!(!e.to_string().contains('\u{2014}'), "no em dashes: {e}");
    }
}

#[test]
fn a_missing_target_permission_maps_to_its_name() {
    let e: LaneSetupError = ParserRepositoryError::Forbidden("source_configs:edit".into()).into();
    assert!(matches!(e, LaneSetupError::NotPermitted { ref missing } if missing == &vec!["source_configs:edit"]));
    let tier: LaneSetupError = ParserRepositoryError::TierLimitExceeded("Your plan allows 5 data sources.".into()).into();
    assert!(tier.is_forbidden());
}

#[test]
fn the_import_is_linked_hec_with_the_parser_primary() {
    let r = import_request();
    assert!(matches!(r.import_type, ParserImportType::Linked));
    assert_eq!(r.ingestion_method.as_deref(), Some(PULL_FEED_TRANSPORT));
    assert!(r.source_type.is_none(), "the parser's own first match value stays the primary");
    assert!(r.dispatch_source_config_id.is_none());
}

#[test]
fn a_name_clash_at_the_write_is_a_conflict_not_a_500() {
    let e = name_taken_or("duplicate key value violates unique constraint \"log_sources_generated_vector_identity\"".into(), "okta_pull");
    assert!(e.is_conflict(), "{e:?}");
    let e = name_taken_or("Log source with name 'Okta (OCSF)' already exists".into(), "Okta (OCSF)");
    assert!(e.is_conflict(), "{e:?}");
    assert!(name_taken_or("connection reset".into(), "x").is_internal());
}
