// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the risk-notable → default-rule translation (NAN-1805).

use super::*;
use crate::query::{contains_risk_command, parse_query};

#[test]
fn default_rule_query_matches_seed_shape() {
    // The Rust builder and the 9000033 seed migration must agree on the
    // global-thresholds query shape (the migration builds the same text in
    // SQL from the persisted settings; defaults are 500/1000).
    let query = RiskNotableConfig::default().default_rule_query();
    assert_eq!(
        query,
        "* | where score_24h > 500 or score_7d > 1000 | table entity, entity_type, score_24h, score_7d, distinct_rules_7d, last_rule_name"
    );
    let parsed = parse_query(&query).expect("default notable rule query must parse");
    // Feedback-loop guard invariant: the generated body never carries `| risk`.
    assert!(!contains_risk_command(&parsed));
}

#[test]
fn default_rule_query_translates_type_overrides() {
    let mut config = RiskNotableConfig::default();
    config.entity_type_overrides.insert(
        "ip".to_string(),
        RiskNotableTypeThresholds {
            threshold_24h: Some(800),
            threshold_7d: None, // falls back to the global 7d threshold
        },
    );
    config.entity_type_overrides.insert(
        "user".to_string(),
        RiskNotableTypeThresholds {
            threshold_24h: None,
            threshold_7d: Some(2000),
        },
    );

    let query = config.default_rule_query();
    assert_eq!(
        query,
        "* | where (entity_type = \"ip\" and (score_24h > 800 or score_7d > 1000)) \
         or (entity_type = \"user\" and (score_24h > 500 or score_7d > 2000)) \
         or (entity_type != \"ip\" and entity_type != \"user\" and (score_24h > 500 or score_7d > 1000)) \
         | table entity, entity_type, score_24h, score_7d, distinct_rules_7d, last_rule_name"
    );
    parse_query(&query).expect("override notable rule query must parse");
}

#[test]
fn default_rule_query_skips_unsafe_override_keys() {
    // Keys outside the safe charset can never match the dataset's inferred
    // entity types and must not be interpolated into query text.
    let mut config = RiskNotableConfig::default();
    config.entity_type_overrides.insert(
        "ip\" or 1=1 | head 1 //".to_string(),
        RiskNotableTypeThresholds {
            threshold_24h: Some(1),
            threshold_7d: Some(1),
        },
    );
    let query = config.default_rule_query();
    assert_eq!(
        query,
        RiskNotableConfig::default().default_rule_query(),
        "unsafe key must fall back to the global-thresholds query"
    );
}

#[test]
fn default_rule_id_is_stable() {
    // The 9000033 seed migration embeds this literal; a drift here would
    // orphan the settings-card repoint. (The enterprise test suite pins the
    // migration side.)
    assert_eq!(
        DEFAULT_RISK_NOTABLE_RULE_ID.to_string(),
        "b8f3d2a1-6c4e-4f7a-9d2b-3e5a7c901f44"
    );
}
