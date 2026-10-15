// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use chrono::TimeZone;
use std::collections::HashMap;

const H_US: i64 = 3_600_000_000;

fn anchor() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 7, 12, 0, 0).unwrap()
}

fn bucket(hours_ago: u32, rule: &str, fires: u64, score_sum: i64) -> RiskTimelineBucket {
    RiskTimelineBucket {
        hours_ago,
        rule_id: rule.to_string(),
        rule_name: format!("name-{rule}"),
        severity: "high".to_string(),
        fires,
        score_sum,
        // Latest fire 1µs before the bucket end.
        last_fire_us: anchor().timestamp_micros() - hours_ago as i64 * H_US - 1,
        last_fire_score: (score_sum / fires.max(1) as i64) as i32,
        mitre_tactics: vec!["TA0006".to_string()],
    }
}

/// Reference: the readers' per-finding SQL semantics evaluated at `t`
/// (`ts >= t-24h → d0 … ts >= t-7d → d5`, `ts < t`), rounded half-to-even.
fn reference_score(findings: &[(i64, i64)], t_us: i64, decay: &RiskDecayConfig) -> i64 {
    let sum: f64 = findings
        .iter()
        .filter(|(ts, _)| *ts < t_us && *ts >= t_us - 168 * H_US)
        .map(|(ts, score)| {
            let factor = if *ts >= t_us - 24 * H_US {
                decay.decay_0_24h
            } else if *ts >= t_us - 72 * H_US {
                decay.decay_1_3d
            } else if *ts >= t_us - 120 * H_US {
                decay.decay_3_5d
            } else {
                decay.decay_5_7d
            };
            *score as f64 * factor
        })
        .sum();
    sum.round_ties_even() as i64
}

#[test]
fn decay_bands_follow_the_reader_multiif() {
    let d = RiskDecayConfig::default();
    assert_eq!(decay_factor(0, &d), 1.0);
    assert_eq!(decay_factor(23, &d), 1.0);
    assert_eq!(decay_factor(24, &d), 0.7);
    assert_eq!(decay_factor(71, &d), 0.7);
    assert_eq!(decay_factor(72, &d), 0.4);
    assert_eq!(decay_factor(119, &d), 0.4);
    assert_eq!(decay_factor(120, &d), 0.2);
    assert_eq!(decay_factor(167, &d), 0.2);
    assert_eq!(decay_factor(168, &d), 0.0);
}

#[test]
fn hourly_series_is_exact_against_per_finding_reference() {
    let decay = RiskDecayConfig {
        decay_0_24h: 1.0,
        decay_1_3d: 0.65,
        decay_3_5d: 0.35,
        decay_5_7d: 0.15,
    };
    // Findings across the whole 14d lookback, including band edges.
    let a = anchor().timestamp_micros();
    let findings: Vec<(i64, i64)> = vec![
        (a - 1, 40),
        (a - 24 * H_US, 25),     // exactly 24h old at the anchor → d0
        (a - 24 * H_US - 1, 25), // just past → d1
        (a - 72 * H_US, 30),
        (a - 119 * H_US - 7, 11),
        (a - 168 * H_US, 50), // on the 7d edge → d5 at the anchor
        (a - 200 * H_US + 5, 9),
        (a - 335 * H_US - 1, 77),
    ];
    // Bucket them the way the readers do: intDiv(anchor - 1 - ts, 1h).
    let mut buckets: HashMap<u32, RiskTimelineBucket> = HashMap::new();
    for (ts, score) in &findings {
        let h = ((a - 1 - ts) / H_US) as u32;
        let b = buckets.entry(h).or_insert_with(|| RiskTimelineBucket {
            fires: 0,
            score_sum: 0,
            ..bucket(h, "r", 1, 0)
        });
        b.fires += 1;
        b.score_sum += score;
    }
    let buckets: Vec<_> = buckets.into_values().collect();
    let timeline = build_timeline(anchor(), &decay, &buckets, false);

    assert_eq!(timeline.points.len(), 169);
    assert_eq!(timeline.points.last().unwrap().t, anchor());
    assert_eq!(timeline.points[0].t, anchor() - Duration::hours(168));
    for point in &timeline.points {
        assert_eq!(
            point.score,
            reference_score(&findings, point.t.timestamp_micros(), &decay),
            "point at {}",
            point.t
        );
    }
    // The anchor point is the headline: the sum of contributions at the anchor.
    let total: i64 = timeline
        .contributions
        .iter()
        .map(|c| c.decayed_contribution_7d)
        .sum();
    assert_eq!(timeline.points.last().unwrap().score, total);
}

#[test]
fn contributions_at_anchor_match_the_contributions_reader() {
    let d = RiskDecayConfig::default();
    let buckets = vec![
        bucket(0, "r-1", 2, 200),  // 24h, d0
        bucket(30, "r-1", 1, 100), // 7d only, d1
        bucket(10, "r-2", 1, 50),
        bucket(170, "r-3", 1, 999), // outside the 7d window at the anchor
    ];
    let timeline = build_timeline(anchor(), &d, &buckets, false);
    let ids: Vec<_> = timeline
        .contributions
        .iter()
        .map(|c| c.rule_id.as_str())
        .collect();
    assert_eq!(ids, ["r-1", "r-2"], "heaviest first; r-3 has no fire in 7d");
    let r1 = &timeline.contributions[0];
    assert_eq!((r1.fires_24h, r1.fires_7d), (2, 3));
    assert_eq!(r1.decayed_contribution_24h, 200);
    assert_eq!(r1.decayed_contribution_7d, 270);
    assert_eq!(
        r1.last_fire_at.timestamp_micros(),
        anchor().timestamp_micros() - 1
    );
    assert_eq!(r1.last_fire_score, 100);
    // Markers cover only the displayed window, oldest first.
    let marker_hours: Vec<_> = timeline
        .markers
        .iter()
        .map(|m| (anchor() - m.t).num_hours())
        .collect();
    assert_eq!(marker_hours, [31, 11, 1]);
    assert_eq!(timeline.markers[0].mitre_tactics, ["TA0006"]);
}

#[test]
fn empty_and_truncated_reads() {
    let empty = build_timeline(anchor(), &RiskDecayConfig::default(), &[], true);
    assert!(empty.points.iter().all(|p| p.score == 0));
    assert!(empty.markers.is_empty() && empty.contributions.is_empty());
    assert!(empty.truncated);
    let shell = EntityRiskTimeline::empty(anchor());
    assert!(shell.points.is_empty());
    assert_eq!(shell.window_hours, TIMELINE_WINDOW_HOURS);
}

#[test]
fn anchors_are_clamped_to_now_and_the_max_age() {
    let now = anchor();
    assert_eq!(clamp_anchor(None, now), now);
    assert_eq!(clamp_anchor(Some(now + Duration::hours(3)), now), now);
    assert_eq!(
        clamp_anchor(Some(now - Duration::days(90)), now),
        now - Duration::days(TIMELINE_MAX_ANCHOR_AGE_DAYS)
    );
    let past = now - Duration::days(2);
    assert_eq!(clamp_anchor(Some(past), now), past);
}

#[test]
fn mitre_attaches_by_rule_id_only() {
    let mut contributions = build_timeline(
        anchor(),
        &RiskDecayConfig::default(),
        &[
            bucket(0, "6f1c0a52-3c1b-4b8e-9f43-1c2d3e4f5a6b", 1, 10),
            bucket(0, "", 1, 5),
        ],
        false,
    )
    .contributions;
    let ids = contribution_rule_ids(&contributions);
    assert_eq!(ids.len(), 1, "ad-hoc (empty) rule ids are never looked up");
    let mut mitre = HashMap::new();
    mitre.insert(
        ids[0].to_string(),
        (vec!["TA0006".to_string()], vec!["T1110".to_string()]),
    );
    attach_rule_mitre(&mut contributions, &mitre);
    let tagged = contributions
        .iter()
        .find(|c| !c.rule_id.is_empty())
        .unwrap();
    assert_eq!(tagged.mitre_techniques, ["T1110"]);
    let adhoc = contributions.iter().find(|c| c.rule_id.is_empty()).unwrap();
    assert!(adhoc.mitre_tactics.is_empty());
}

#[test]
fn contribution_mitre_fields_are_additive_on_the_wire() {
    // An older server's contribution (no MITRE keys) still deserializes.
    let json = serde_json::json!({
        "rule_id": "r", "rule_name": "n", "severity": "high", "fires_24h": 1, "fires_7d": 1,
        "decayed_contribution_24h": 1, "decayed_contribution_7d": 1,
        "last_fire_at": "2026-10-07T12:00:00Z", "last_fire_score": 1
    });
    let parsed: EntityRuleContribution = serde_json::from_value(json).unwrap();
    assert!(parsed.mitre_tactics.is_empty() && parsed.mitre_techniques.is_empty());
}
