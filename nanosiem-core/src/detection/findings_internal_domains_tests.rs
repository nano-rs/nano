// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3226 read-time contract: the internal-domain suffix list is never
//! written into a finding. A domain risk object is stored as `domain` whatever
//! the list says, so adding or removing a suffix can never leave a stored
//! finding mis-typed. The risk read projection
//! (`risk::clickhouse_sql::ENTITY_SELECT_COLS`) types entities from the value
//! at read time (any dotted name reads as `hostname`; see
//! `risk_read_projection_never_reads_a_stored_domain_type` there).

use super::tests::sample_rule;
use super::*;
use crate::detection::risk::RiskResult;

#[test]
fn a_domain_risk_object_is_stored_as_a_domain() {
    let rule = DetectionRule {
        risk_score: Some(40),
        risk_entity_field: Some("domain".to_string()),
        ..sample_rule()
    };
    for entity in ["db1.prod", "fileserver.corp.local", "login.example.com"] {
        let risk_result = RiskResult::new(40, 40, entity.to_string(), Some("domain".to_string()), vec![]);
        let finding = FindingEvent::detection_match(&rule, &[], false, risk_result);
        assert_eq!(finding.risk_entity_type, "domain", "{entity}");
        assert_eq!(finding.to_log_json()["risk_entity_type"], "domain", "{entity}");
    }
}
