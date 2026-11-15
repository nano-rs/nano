// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5450: data volumes at 80 % / 90 % become SIEM Health findings.

use super::*;
use crate::health::disk_monitor::{DiskComponent, DiskVolumeHealth};
use crate::siem_health::analyzer::fallback_report;
use crate::siem_health::analyzer::tests::base_zero_metrics_fixture;

fn volume(component: DiskComponent, usage: f64) -> DiskVolumeHealth {
    DiskVolumeHealth {
        component,
        host: None,
        name: "default".into(),
        path: None,
        total_bytes: Some(100),
        used_bytes: Some((usage * 100.0) as u64),
        free_bytes: None,
        usage_fraction: Some(usage),
        level: crate::health::disk_monitor::classify_usage(usage),
        detail: format!("{:.1}% used", usage * 100.0),
        forecast: None,
        shared_with: None,
    }
}

fn run(volumes: Vec<DiskVolumeHealth>) -> AnalysisResult {
    let mut metrics = base_zero_metrics_fixture();
    metrics.disk = Some(DiskHealthReport::new(volumes, vec![]));
    let mut analysis = fallback_report(&metrics);
    analysis.overall_score = 100;
    ensure_disk_findings(&mut analysis, &metrics);
    analysis
}

#[test]
fn healthy_disks_add_nothing() {
    let a = run(vec![volume(DiskComponent::Clickhouse, 0.5)]);
    assert_eq!(a.overall_score, 100);
    assert!(!a.recommendations.iter().any(|r| r.title.contains("data disk")));
}

#[test]
fn eighty_percent_is_a_high_finding_capped_at_79() {
    let a = run(vec![volume(DiskComponent::Postgres, 0.82)]);
    assert_eq!(a.overall_score, 79);
    let rec = a.recommendations.iter().find(|r| r.title == DISK_WARNING_TITLE).unwrap();
    assert_eq!(rec.priority, "high");
    assert!(rec.description.contains("PostgreSQL volume default"), "{}", rec.description);
    assert!(rec.description.contains("disk-full-recovery.md"));
}

#[test]
fn ninety_percent_is_critical_capped_at_49_and_both_levels_listed() {
    let a = run(vec![
        volume(DiskComponent::Clickhouse, 0.93),
        volume(DiskComponent::VectorBuffer, 0.85),
    ]);
    assert_eq!(a.overall_score, 49);
    assert_eq!(a.recommendations[0].title, DISK_CRITICAL_TITLE);
    assert_eq!(a.recommendations[0].priority, "critical");
    assert!(a.recommendations.iter().any(|r| r.title == DISK_WARNING_TITLE));
}

#[test]
fn no_disk_report_adds_nothing() {
    let metrics = base_zero_metrics_fixture();
    let mut analysis = fallback_report(&metrics);
    let before = analysis.recommendations.len();
    ensure_disk_findings(&mut analysis, &metrics);
    assert_eq!(analysis.recommendations.len(), before);
}

/// NAN-5450 review: a capped install cycling its ClickHouse disk between the
/// evictor's watermarks (70-80 %) raises no finding, so the SIEM Health score
/// does not drop every cycle. Above the band it does.
#[test]
fn a_clickhouse_disk_inside_the_evictor_band_is_not_a_finding() {
    use crate::health::disk_monitor::{clickhouse_volumes_from_rows, ClickHouseDiskRow, EvictorBand};
    let rows = |free| vec![ClickHouseDiskRow { host: "h".into(), name: "default".into(), path: "/".into(), total_space: 100, free_space: free }];
    let report = |free| DiskHealthReport::new(clickhouse_volumes_from_rows(&rows(free), false, &EvictorBand::DEFAULT), vec![]);
    assert!(disk_recommendations(&report(20)).is_empty(), "80 % on a capped install");
    assert!(disk_recommendations(&report(30)).is_empty());
    let above = disk_recommendations(&report(15));
    assert_eq!(above.len(), 1);
    assert_eq!(above[0].0.title, DISK_WARNING_TITLE);
}
