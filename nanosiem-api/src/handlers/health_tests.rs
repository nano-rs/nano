// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5390: only `/health?strict=1` maps "error" to 503; plain `/health`
//! keeps its 200 contract for healthchecks, routing checks and probes.

use super::HealthQuery;

fn q(strict: Option<&str>) -> HealthQuery {
    HealthQuery { strict: strict.map(str::to_string) }
}

#[test]
fn strict_is_opt_in() {
    assert!(!q(None).is_strict());
    assert!(!q(Some("0")).is_strict());
    assert!(!q(Some("false")).is_strict());
    assert!(!q(Some("")).is_strict());
    assert!(q(Some("1")).is_strict());
    assert!(q(Some("true")).is_strict());
}

#[test]
fn raw_query_parsing_never_rejects() {
    assert!(HealthQuery::from_raw(Some("strict=1")).is_strict());
    assert!(HealthQuery::from_raw(Some("a=b&strict=true")).is_strict());
    assert!(!HealthQuery::from_raw(Some("strict")).is_strict());
    assert!(!HealthQuery::from_raw(Some("%zz&&=")).is_strict());
    assert!(!HealthQuery::from_raw(None).is_strict());
}
