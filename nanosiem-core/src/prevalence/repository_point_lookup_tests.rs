// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5722: the Prevalence API lookups (`POST /api/prevalence/bulk`, the
//! single-artifact GETs, the rarity scatter) count hosts over the same 30-day
//! baseline the dictionaries and `| prevalence enrich=true` read; the window
//! only gates recency.

use super::*;
use crate::auth::{ArtifactScope, ScopeSet};
use std::collections::BTreeSet;

fn repo() -> PrevalenceRepository {
    PrevalenceRepository::new(ClickHouseClient::default(), TableNames::new(false))
}

const KINDS: [DictArtifactKind; 3] =
    [DictArtifactKind::Hash, DictArtifactKind::Domain, DictArtifactKind::Ip];

#[test]
fn lookups_read_the_baseline_summary_not_the_windowed_hourly_buckets() {
    let repo = repo();
    for (kind, table) in KINDS.into_iter().zip([
        "nanosiem.hash_prevalence_summary",
        "nanosiem.domain_prevalence_summary",
        "nanosiem.ip_prevalence_summary",
    ]) {
        let sql = repo.point_lookup_sql(kind, &ArtifactScope::system());
        assert!(sql.contains(&format!("FROM {table} WHERE ")), "{sql}");
        assert!(!sql.contains("_prevalence_agg"), "{sql}");
        assert!(!sql.contains("time_bucket"), "the count is not windowed: {sql}");
        assert!(!sql.contains("PREWHERE"), "single WHERE (NAN-1412): {sql}");
        // Keys and the recency cutoff are bound, never inlined.
        assert_eq!(sql.matches('?').count(), 2, "{sql}");
        assert!(sql.contains(" IN ? GROUP BY "), "{sql}");
        assert!(sql.ends_with("WHERE _ls >= fromUnixTimestamp64Micro(toInt64(?))"), "{sql}");
        // Common artifacts keep their real count (no dict 1000/9998 cap).
        assert!(!sql.contains("1000") && !sql.contains("9998"), "{sql}");
    }
}

#[test]
fn restricted_viewers_read_the_source_attributed_summaries() {
    let repo = repo();
    let scope = ArtifactScope::from_scope(&ScopeSet::from_denied(BTreeSet::from([
        "secret?".to_string(),
        "o'brien?fields".to_string(),
    ])));
    for (kind, table) in KINDS.into_iter().zip([
        "nanosiem.hash_prevalence_source_summary",
        "nanosiem.domain_prevalence_source_summary",
        "nanosiem.ip_prevalence_source_summary",
    ]) {
        let sql = repo.point_lookup_sql(kind, &scope);
        assert!(sql.contains(&format!("FROM {table} WHERE schema_profile = ")), "{sql}");
        // The deny list is a server-side parameter: no denied name, `?` or
        // quote from it reaches the SQL text (review P2).
        assert!(
            sql.contains("lower(trimBoth(source_type)) NOT IN {nano_source_deny:Array(String)}"),
            "{sql}"
        );
        assert!(!sql.contains("secret") && !sql.contains("brien"), "{sql}");
        assert_eq!(sql.matches('?').count(), 2, "only the key and cutoff binds: {sql}");
    }
}

#[test]
fn the_window_gates_recency_like_the_dict_mask() {
    assert_eq!(PrevalenceRepository::lookup_recency_cutoff_micros(TimeWindow::ThirtyDays), 0);
    let now = Utc::now().timestamp_micros();
    for (window, hours) in [
        (TimeWindow::OneHour, 1),
        (TimeWindow::TwentyFourHours, 24),
        (TimeWindow::SevenDays, 168),
    ] {
        let cutoff = PrevalenceRepository::lookup_recency_cutoff_micros(window);
        let expected = now - hours * 3_600_000_000;
        assert!((cutoff - expected).abs() < 60_000_000, "{window}: {cutoff} vs {expected}");
    }
}
