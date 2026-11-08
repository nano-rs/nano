// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-1888 — `| baseline` first-seen day-agg fast path: pure routing tests
//! plus a local-ClickHouse raw/agg parity test.
//!
//! The parity test is the load-bearing one: `entity_dimension_firsts` now has
//! TWO implementations of the same question (raw lookback scan vs
//! `entity_dimension_day_agg`), and the split into known/new happens
//! downstream on whatever rows come back — a silent divergence would change
//! what an analyst is told is "new" for an entity with no error anywhere.

use super::*;

// ---------------------------------------------------------------------------
// Routing — pure
// ---------------------------------------------------------------------------

/// The agg dimension map must stay in lockstep with `baseline::dimensions_for`
/// — every (anchoring, dims) group production sends must be servable, or the
/// fast path silently dies. If this fails you added/renamed a baseline
/// dimension: update the MVs in clickhouse/166 (+ init.sql twins + backfill
/// script) AND `agg_dimension_set`.
#[test]
fn agg_dimension_set_covers_every_production_scope_group() {
    for entity in ["host", "user", "ip"] {
        for (source_side_only, dims) in
            crate::baseline::dimension_scope_groups(entity, true, true, true)
        {
            let supported = agg_dimension_set(entity, source_side_only).unwrap_or_else(|| {
                panic!("agg_dimension_set must cover ({entity}, source_side_only={source_side_only})")
            });
            for d in dims {
                assert!(
                    supported.contains(&d.field),
                    "dim {} of ({entity}, source_side_only={source_side_only}) is not baked into \
                     the day agg",
                    d.field
                );
            }
        }
    }
}

/// Combos the MVs do NOT bake in must be rejected — never served mis-anchored.
#[test]
fn agg_dimension_set_rejects_unknown_combos() {
    assert!(agg_dimension_set("host", true).is_some());
    assert!(agg_dimension_set("ip", true).is_none()); // ip dims are association-anchored
    assert!(agg_dimension_set("user", false).is_none()); // user dims are actor-anchored
    assert!(agg_dimension_set("domain", true).is_none());
    assert!(agg_dimension_set("hash", false).is_none());
}

/// Must mirror the MV regexes (`^10\.` / `^192\.168\.` /
/// `^172\.(1[6-9]|2[0-9]|3[01])\.`) EXACTLY — admitting a value the MVs skip
/// would read as no-history and every peer would look new.
#[test]
fn private_ip_gate_mirrors_mv_regexes() {
    for yes in ["10.0.0.1", "10.255.9.9", "192.168.1.5", "172.16.0.1", "172.31.255.1"] {
        assert!(agg_covers_private_ip(yes), "{yes} should be agg-covered");
    }
    for no in [
        "8.8.8.8",        // public
        "172.15.0.1",     // below the /12
        "172.32.0.1",     // above the /12
        "172.016.0.1",    // leading zero — the regex needs exactly two digits
        "172.1.1.1",      // one digit
        "172.160.1.1",    // three digits
        "169.254.1.1",    // link-local: NOT aggregated, raw path
        "127.0.0.1",      // loopback
        "192.169.1.1",    // adjacent block
        "fe80::1",        // IPv6: raw path
        "",               // empty
        "1092.168.1.1",   // must be a PREFIX match, not a substring match
    ] {
        assert!(!agg_covers_private_ip(no), "{no} should route to the raw scan");
    }
}

#[test]
fn can_serve_requires_subset_and_private_ip() {
    // Production groups are servable.
    assert!(baseline_agg_can_serve("host", "ws-1", true, &["process_name", "dest_ip"]));
    assert!(baseline_agg_can_serve("host", "ws-1", false, &["user"]));
    assert!(baseline_agg_can_serve("user", "bob", true, &["src_host", "src_ip", "process_name"]));
    // A SUBSET (profile skipped a field / analyst passed dims=) still serves.
    assert!(baseline_agg_can_serve("host", "ws-1", true, &["process_name"]));
    // A dim outside the baked-in set for the anchoring must go raw.
    assert!(!baseline_agg_can_serve("host", "ws-1", true, &["process_name", "user"]));
    assert!(!baseline_agg_can_serve("host", "ws-1", false, &["process_name"]));
    // Nothing mapped → nothing to serve.
    assert!(!baseline_agg_can_serve("host", "ws-1", true, &[]));
    // ip entities are only aggregated for RFC1918 values.
    assert!(baseline_agg_can_serve("ip", "10.0.0.5", false, &["src_host", "dest_port", "user"]));
    assert!(!baseline_agg_can_serve("ip", "8.8.8.8", false, &["src_host", "dest_port", "user"]));
}

/// NAN-1895: the agg source-scope gate must admit a deny-set of ONLY sources the
/// agg already excludes (`{audit}`), not just an empty deny-set. Per-source RBAC
/// (NAN-1801) unions `audit` into every non-`audit:view` caller's deny-set, so an
/// `!is_restricted()` gate would send ~every real query to the raw scan and the
/// fast path would never fire. A deny-set naming any OTHER source must fall back.
#[test]
fn scope_gate_admits_audit_only_denyset() {
    use crate::auth::ScopeSet;
    use std::collections::BTreeSet;
    let denied =
        |xs: &[&str]| ScopeSet::from_denied(xs.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>());

    assert!(scope_within_agg_exclusions(&ScopeSet::unrestricted())); // empty deny-set
    assert!(scope_within_agg_exclusions(&denied(&["audit"]))); // exactly the agg's exclusion
    assert!(scope_within_agg_exclusions(&denied(&["AUDIT"]))); // case-insensitive
    assert!(!scope_within_agg_exclusions(&denied(&["sysmon"]))); // a source the agg includes
    assert!(!scope_within_agg_exclusions(&denied(&["audit", "sysmon"]))); // audit ok, sysmon not → raw
}

// ---------------------------------------------------------------------------
// Raw vs agg parity — local ClickHouse
// ---------------------------------------------------------------------------

mod live {
    use super::*;
    use crate::auth::ScopeSet;
    use crate::schema::UdmProfile;
    use crate::{DualPool, DualPoolConfig};
    use chrono::{DateTime, Duration, NaiveDate, Utc};
    use std::sync::Arc;

    /// A fixed far-past activation watermark for the parity / sub-day / scope
    /// tests: any real lookback (days, not years) is at/after this, so the time
    /// gate serves the agg without needing backfill markers.
    fn far_past() -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(2020, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
    }

    async fn local() -> Option<(SearchService, clickhouse::Client)> {
        let config = DualPoolConfig::with_auth(
            "postgres://nanosiem:nanosiem@localhost:5432/nanosiem",
            "http://localhost:8123",
            "nanosiem",
            "default",
            "",
        );
        match DualPool::new(&config).await {
            Ok(pool) => {
                let ch = clickhouse::Client::default()
                    .with_url("http://localhost:8123")
                    .with_database("nanosiem");
                Some((
                    SearchService::with_dual_pool_and_profile(&pool, Arc::new(UdmProfile::new())),
                    ch,
                ))
            }
            Err(e) => {
                eprintln!("Could not connect to local DBs ({e}); is the stack up?");
                None
            }
        }
    }

    fn key(rows: &[DimensionFirst]) -> Vec<(String, String, u64, chrono::DateTime<chrono::Utc>)> {
        let mut v: Vec<_> = rows
            .iter()
            .map(|r| (r.dimension.clone(), r.value.clone(), r.count, r.first_seen))
            .collect();
        v.sort();
        v
    }

    /// A per-run unique suffix. Each live test uses a fresh synthetic host so
    /// its seeded rows are UNIQUE — otherwise ClickHouse insert-block dedup
    /// collapses identical re-seeded `logs` rows to one while the MV still
    /// counts each insert, drifting the agg `event_count` above the raw
    /// `count()` across runs (a test artifact; production events are unique).
    /// A unique host sidesteps dedup entirely and needs no state-clearing
    /// mutation. Old runs' rows linger under TTL but never match this run's
    /// entity-keyed query.
    fn nonce() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    /// Deterministically set the single `baseline_agg_meta.active_since` row the
    /// time gate reads: delete-then-insert (both WAITED) so a freshly-built
    /// SearchService (its OnceCell empty) reads exactly this value. The gate
    /// serves the agg only when a query's lookback is at/after `active_since`
    /// (or the pre-activation days are backfill-markered), so tests drive
    /// coverage purely by choosing this timestamp — no more per-day filler.
    async fn set_active_since(ch: &clickhouse::Client, ts: DateTime<Utc>) {
        ch.query("ALTER TABLE nanosiem.baseline_agg_meta DELETE WHERE 1")
            .with_option("mutations_sync", "2")
            .execute()
            .await
            .expect("clear meta");
        ch.query(&format!(
            "INSERT INTO nanosiem.baseline_agg_meta (k, active_since) \
             VALUES ('active_since', toDateTime64('{}', 6))",
            ts.format("%Y-%m-%d %H:%M:%S%.6f")
        ))
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1")
        .execute()
        .await
        .expect("set active_since");
    }

    /// Remove any backfill-completion markers for `lane` across `[from, to)` so
    /// the "no markers" scenario is isolated from prior runs.
    async fn clear_markers(ch: &clickhouse::Client, lane: &str, from: NaiveDate, to: NaiveDate) {
        ch.query(&format!(
            "ALTER TABLE nanosiem.entity_dimension_day_agg_backfill_progress \
             DELETE WHERE lane = '{lane}' AND day >= toDate('{}') AND day < toDate('{}')",
            from.format("%Y-%m-%d"),
            to.format("%Y-%m-%d"),
        ))
        .with_option("mutations_sync", "2")
        .execute()
        .await
        .expect("clear markers");
    }

    /// Write a completion marker for `lane` for EVERY day in `[from, to)` — the
    /// backfill-extension scenario (pre-activation days proven backfilled).
    async fn set_markers(ch: &clickhouse::Client, lane: &str, from: NaiveDate, to: NaiveDate) {
        let mut values = Vec::new();
        let mut d = from;
        while d < to {
            values.push(format!("('{lane}', toDate('{}'))", d.format("%Y-%m-%d")));
            d = d.succ_opt().unwrap();
        }
        if values.is_empty() {
            return;
        }
        ch.query(&format!(
            "INSERT INTO nanosiem.entity_dimension_day_agg_backfill_progress (lane, day) VALUES {}",
            values.join(", ")
        ))
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1")
        .execute()
        .await
        .expect("set markers");
    }

    /// Seeds a synthetic host with one lookback-window peer and two
    /// incident-window firsts (all past-dated — the MVs aggregate them into the
    /// right days at insert time), PLUS contiguous per-day filler so the
    /// self-enabling coverage gate is satisfied, then proves the raw scan and
    /// the agg read return the SAME rows and the derived known/new split
    /// matches. Re-runnable: a fresh nonce host each run sidesteps insert dedup.
    ///
    /// `#[ignore]` — requires local ClickHouse + Postgres. Run:
    ///   cargo test -p nanosiem-core --lib baseline_agg_parity_live -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "requires local ClickHouse + Postgres with migration 166 applied"]
    async fn baseline_agg_parity_live() {
        let Some((ss, ch)) = local().await else {
            return;
        };

        // Day-aligned spans: incident = [today-2d, today-1d), lookback 7d.
        // Day alignment keeps the day-grain agg edges exactly congruent with
        // the raw scan's timestamp bounds; nothing here touches the (partial)
        // day the MVs went live on.
        let today = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
        let incident_start = today - Duration::days(2);
        let incident_end = today - Duration::days(1);
        let new_start = incident_start - Duration::days(7);

        let host = format!("nan1888-parity-{}", nonce());
        let host = host.as_str();
        let ts = |t: chrono::DateTime<Utc>| t.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        // Coverage seed: strictly before the lookback so it appears in NEITHER
        // path's rows but satisfies the agg's min(day) <= new_start gate even
        // on an otherwise-empty box.
        let seed = ts(new_start - Duration::days(1));
        // A known peer inside the lookback, before the incident.
        let known = ts(new_start + Duration::hours(1));
        // Two first-sightings inside the incident window.
        let fresh = ts(incident_start + Duration::hours(1));
        let insert = format!(
            "INSERT INTO nanosiem.logs (timestamp, source_type, src_host, process_name, dest_ip, user, message) VALUES \
             ('{seed}', 'nan1888_parity', '{host}', 'seed.exe', '', '', 'parity seed'), \
             ('{known}', 'nan1888_parity', '{host}', 'known.exe', '', 'parity-user-a', 'parity known'), \
             ('{fresh}', 'nan1888_parity', '{host}', 'fresh.exe', '10.99.1.2', 'parity-user-b', 'parity fresh')"
        );
        ch.query(&insert).execute().await.expect("seed insert");
        // Activation far in the past ⇒ the whole lookback is MV-active ⇒ agg.
        set_active_since(&ch, far_past()).await;

        let scope = ScopeSet::unrestricted();
        for (source_side_only, dims) in [
            (true, vec!["process_name", "dest_ip"]),
            (false, vec!["user"]),
        ] {
            let agg = ss
                .entity_dimension_firsts_from_agg(
                    "host",
                    host,
                    &dims,
                    new_start,
                    incident_end,
                    crate::baseline::NEW_TO_ENTITY_ROW_CAP,
                )
                .await
                .expect("agg path must be covered — migration 166 applied + contiguous filler seeded?");
            let raw = ss
                .entity_dimension_firsts_raw(
                    &scope,
                    "host",
                    host,
                    source_side_only,
                    &dims,
                    new_start,
                    incident_end,
                    crate::baseline::NEW_TO_ENTITY_ROW_CAP,
                )
                .await
                .expect("raw scan runs");

            assert!(!raw.is_empty(), "seed rows must be visible to the raw scan");
            assert_eq!(
                key(&agg),
                key(&raw),
                "agg vs raw rows diverged for dims {dims:?}"
            );

            // The product-level semantics: the derived new-to-entity split.
            let new_of = |rows: &[DimensionFirst]| {
                let mut v: Vec<_> = rows
                    .iter()
                    .filter(|r| r.first_seen >= incident_start)
                    .map(|r| (r.dimension.clone(), r.value.clone()))
                    .collect();
                v.sort();
                v
            };
            assert_eq!(new_of(&agg), new_of(&raw), "NEW set diverged for dims {dims:?}");
            if source_side_only {
                assert_eq!(
                    new_of(&agg),
                    vec![
                        ("dest_ip".to_string(), "10.99.1.2".to_string()),
                        ("process_name".to_string(), "fresh.exe".to_string()),
                    ],
                    "the incident-window firsts must read as new"
                );
            }
        }

        // Time gate: a lookback that reaches before `active_since` (2020-01-01
        // here) with no backfill markers must decline → raw fallback.
        let ancient = Utc::now() - Duration::days(4000);
        assert!(
            ss.entity_dimension_firsts_from_agg(
                "host",
                host,
                &["process_name"],
                ancient,
                ancient + Duration::days(1),
                crate::baseline::NEW_TO_ENTITY_ROW_CAP,
            )
            .await
            .is_none(),
            "uncovered lookback must fall back to the raw scan"
        );
    }

    /// P1-1 regression: a SUB-DAY window with a value first-seen AFTER
    /// `incident_end` on the SAME day. Day grain reads whole days, so without
    /// the `HAVING min(first_seen) < end` the agg would surface that
    /// after-window value as "new" — a value genuinely outside the search
    /// window. Asserts the agg's rows and derived NEW set match the raw scan
    /// (which bounds `timestamp < end` and excludes it). `new_start` is
    /// day-aligned so the start edge is congruent; only the end edge is
    /// mid-day, which is exactly what P1-1 fixes.
    ///
    /// `#[ignore]` — requires local ClickHouse + Postgres. Run:
    ///   cargo test -p nanosiem-core --lib baseline_agg_subday_parity_live -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "requires local ClickHouse + Postgres with migration 166 applied"]
    async fn baseline_agg_subday_parity_live() {
        let Some((ss, ch)) = local().await else {
            return;
        };

        // Window: lookback from the start of day D-3 to a MID-DAY incident_end
        // on day D-2 (a closed day). incident_start is mid-day D-2 too.
        let day = |d: i64| (Utc::now() - Duration::days(d)).date_naive();
        let d2 = day(2); // the incident day (closed)
        let at = |nd: chrono::NaiveDate, h: u32, m: u32| {
            nd.and_hms_opt(h, m, 0).unwrap().and_utc()
        };
        let new_start = day(3).and_hms_opt(0, 0, 0).unwrap().and_utc(); // day-aligned
        let incident_start = at(d2, 12, 0);
        let incident_end = at(d2, 14, 0);

        let host = format!("nan1888-subday-{}", nonce());
        let host = host.as_str();
        let ts = |t: chrono::DateTime<Utc>| t.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        // coverage seed before the lookback; a known peer inside the lookback;
        // a fresh value inside [incident_start, incident_end); and an
        // AFTER-window value at 15:00 on the SAME incident day D-2.
        let seed = ts(new_start - Duration::days(1));
        let known = ts(at(day(3), 6, 0)); // in the lookback, before incident
        let inside = ts(at(d2, 12, 30)); // inside the window → new
        let after = ts(at(d2, 15, 0)); // same day, AFTER incident_end → must be dropped
        let insert = format!(
            "INSERT INTO nanosiem.logs (timestamp, source_type, src_host, process_name, message) VALUES \
             ('{seed}', 'nan1888_subday', '{host}', 'seed.exe', 's'), \
             ('{known}', 'nan1888_subday', '{host}', 'known.exe', 'k'), \
             ('{inside}', 'nan1888_subday', '{host}', 'inside.exe', 'i'), \
             ('{after}', 'nan1888_subday', '{host}', 'after.exe', 'a')"
        );
        ch.query(&insert).execute().await.expect("seed insert");
        // Activation far in the past ⇒ the whole lookback is MV-active ⇒ agg.
        set_active_since(&ch, far_past()).await;

        let dims = ["process_name"];
        let agg = ss
            .entity_dimension_firsts_from_agg(
                "host", host, &dims, new_start, incident_end,
                crate::baseline::NEW_TO_ENTITY_ROW_CAP,
            )
            .await
            .expect("agg covered");
        let raw = ss
            .entity_dimension_firsts_raw(
                &ScopeSet::unrestricted(), "host", host, true, &dims, new_start, incident_end,
                crate::baseline::NEW_TO_ENTITY_ROW_CAP,
            )
            .await
            .expect("raw runs");

        let vals = |rows: &[DimensionFirst]| {
            let mut v: Vec<String> = rows.iter().map(|r| r.value.clone()).collect();
            v.sort();
            v
        };
        // after.exe (first-seen 15:00 > 14:00 end) must be absent from BOTH.
        assert!(
            !vals(&raw).contains(&"after.exe".to_string()),
            "raw must exclude the after-window value"
        );
        assert!(
            !vals(&agg).contains(&"after.exe".to_string()),
            "P1-1: HAVING must drop the after-window value from the agg (got {:?})",
            vals(&agg)
        );
        assert_eq!(vals(&agg), vals(&raw), "sub-day agg/raw value sets diverged");

        // The NEW set is exactly {inside.exe}; known.exe is history, after.exe gone.
        let new_of = |rows: &[DimensionFirst]| {
            let mut v: Vec<String> = rows
                .iter()
                .filter(|r| r.first_seen >= incident_start)
                .map(|r| r.value.clone())
                .collect();
            v.sort();
            v
        };
        assert_eq!(new_of(&agg), vec!["inside.exe".to_string()], "agg NEW set");
        assert_eq!(new_of(&agg), new_of(&raw), "sub-day NEW set diverged");
    }

    /// ACTIVATION-TIME GATE regression (NAN-1895) — the data-independent gate,
    /// tested at TIMESTAMP granularity (P1-1). A PHANTOM agg row with no backing
    /// log makes the agg and raw genuinely differ, so which path served is
    /// observable. `active_since` is set to NOON of a day D; each scenario uses
    /// a FRESH SearchService (its `active_since` memo reads the value just set):
    ///   A. start = D MIDNIGHT (< active_since, same day), NO markers ⇒ RAW.
    ///      This is the partial-activation-day case: `start_day == active_day`
    ///      yet the D-morning (00:00→noon) is uncaptured, so a DAY-level gate
    ///      would wrongly serve. The timestamp gate must NOT.
    ///   B. start = D NOON (== active_since) ⇒ AGG (fully MV-active lookback).
    ///   C. start = D MIDNIGHT WITH a marker for day D (the INCLUSIVE
    ///      `[start_day, active_day]` range — active_day included because its
    ///      morning needs a full-day backfill) ⇒ AGG.
    ///
    /// `#[ignore]` — requires local ClickHouse + Postgres. Run:
    ///   cargo test -p nanosiem-core --lib baseline_agg_activation_gate_live -- --ignored --nocapture --test-threads=1
    #[tokio::test]
    #[ignore = "requires local ClickHouse + Postgres with migration 166+167 applied"]
    async fn baseline_agg_activation_gate_live() {
        let Some((ss0, ch)) = local().await else {
            return;
        };
        let host = format!("nan1895-act-{}", nonce());
        let host = host.as_str();

        // A recent past day D. active_since = NOON; the lookback candidates are
        // D midnight (partial-day) and D noon; the window ends next midnight.
        let d = (Utc::now() - Duration::days(4)).date_naive();
        let at = |h: u32| d.and_hms_opt(h, 0, 0).unwrap().and_utc();
        let active_noon = at(12);
        let midnight = at(0);
        let incident_end = d
            .succ_opt()
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc(); // D+1 00:00
        let peer_ts = at(13); // 13:00 — inside every candidate window
        let ts = |t: DateTime<Utc>| t.format("%Y-%m-%d %H:%M:%S%.6f").to_string();

        // Real peer log (raw fallback returns it) + PHANTOM agg-only row on day D.
        ch.query(&format!(
            "INSERT INTO nanosiem.logs (timestamp, source_type, src_host, process_name, message) \
             VALUES ('{p}', 'nan1895_act', '{host}', 'realknown.exe', 'k')",
            p = ts(peer_ts)
        ))
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1")
        .execute()
        .await
        .expect("real peer insert");
        ch.query(&format!(
            "INSERT INTO nanosiem.entity_dimension_day_agg \
             (entity_type, entity_value, dim, val, day, first_seen, event_count) VALUES \
             ('host', '{host}', 'process_name', 'phantom.exe', toDate('{d}'), \
              toDateTime64('{p}', 6), 1)",
            d = d.format("%Y-%m-%d"),
            p = ts(peer_ts),
        ))
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1")
        .execute()
        .await
        .expect("phantom insert");
        drop(ss0); // built only to prove the DB is up; each scenario gets a fresh one.

        let dims = ["process_name"];
        let scope = ScopeSet::unrestricted();
        let cap = crate::baseline::NEW_TO_ENTITY_ROW_CAP;
        let has_phantom = |rows: &[DimensionFirst]| rows.iter().any(|r| r.value == "phantom.exe");
        let lane = "udm"; // UdmProfile in local()
        // Inclusive marker range for a D-midnight start: start_day = active_day = D.
        let marker_from = d;
        let marker_to = d.succ_opt().unwrap(); // set/clear_markers seed [from, to)

        // A. start = D midnight, active_since = noon, NO markers ⇒ RAW.
        //    (P1-1: same day as activation, but its uncaptured morning ⇒ raw.)
        clear_markers(&ch, lane, marker_from, marker_to).await;
        set_active_since(&ch, active_noon).await;
        let (ssa, _ca) = local().await.expect("db up");
        let a = ssa
            .entity_dimension_firsts(&scope, "host", host, true, &dims, midnight, incident_end, cap)
            .await
            .expect("routed runs (A)");
        assert!(
            !has_phantom(&a),
            "partial-activation-day (start=midnight < active_since=noon) with no markers must \
             fall back to RAW (phantom absent): {:?}",
            a.iter().map(|r| &r.value).collect::<Vec<_>>()
        );
        assert!(
            a.iter().any(|r| r.value == "realknown.exe"),
            "raw fallback must still return the real peer"
        );

        // B. start = D noon (== active_since) ⇒ AGG.
        set_active_since(&ch, active_noon).await;
        let (ssb, _cb) = local().await.expect("db up");
        let b = ssb
            .entity_dimension_firsts(&scope, "host", host, true, &dims, active_noon, incident_end, cap)
            .await
            .expect("routed runs (B)");
        assert!(
            has_phantom(&b),
            "start >= active_since must serve from the AGG (phantom present): {:?}",
            b.iter().map(|r| &r.value).collect::<Vec<_>>()
        );

        // C. start = D midnight WITH a marker for day D (inclusive range) ⇒ AGG.
        set_markers(&ch, lane, marker_from, marker_to).await;
        set_active_since(&ch, active_noon).await;
        let (ssc, _cc) = local().await.expect("db up");
        let c = ssc
            .entity_dimension_firsts(&scope, "host", host, true, &dims, midnight, incident_end, cap)
            .await
            .expect("routed runs (C)");
        assert!(
            has_phantom(&c),
            "start<active_since WITH an inclusive [start_day, active_day] marker must serve from \
             the AGG (phantom present): {:?}",
            c.iter().map(|r| &r.value).collect::<Vec<_>>()
        );

        // D. Sub-second boundary (P1, micro precision): active_since carries
        //    microseconds; start is in the SAME second but earlier. The reader
        //    must keep the µs — a second-truncated watermark would round DOWN and
        //    wrongly serve. No markers ⇒ RAW.
        clear_markers(&ch, lane, marker_from, marker_to).await;
        let active_sub = active_noon + Duration::microseconds(500_000);
        let start_sub = active_noon + Duration::microseconds(200_000); // same second, < active_sub
        set_active_since(&ch, active_sub).await;
        let (ssd, _cd) = local().await.expect("db up");
        let dd = ssd
            .entity_dimension_firsts(&scope, "host", host, true, &dims, start_sub, incident_end, cap)
            .await
            .expect("routed runs (D)");
        assert!(
            !has_phantom(&dd),
            "sub-second: start 12:00:00.2 < active_since 12:00:00.5 must fall back to RAW — a \
             second-truncated watermark would wrongly serve: {:?}",
            dd.iter().map(|r| &r.value).collect::<Vec<_>>()
        );
    }

    /// P2 regression: the insert-once guard is not atomic, so a race can leave
    /// TWO `baseline_agg_meta` rows with different timestamps. The reader takes
    /// MAX(active_since) — deterministic AND conservative (the LATER activation
    /// trusts less). Proven end-to-end: with two rows (09:00, 12:00 on day D)
    /// and a lookback starting at 10:00 (BETWEEN them), a MAX reader (12:00)
    /// makes `start < active_since` ⇒ RAW; a min/arbitrary reader (09:00) would
    /// wrongly serve. Also asserts the private reader returns exactly the max.
    ///
    /// `#[ignore]` — requires local ClickHouse + Postgres. Run:
    ///   cargo test -p nanosiem-core --lib baseline_agg_meta_race_uses_max_live -- --ignored --nocapture --test-threads=1
    #[tokio::test]
    #[ignore = "requires local ClickHouse + Postgres with migration 166+167 applied"]
    async fn baseline_agg_meta_race_uses_max_live() {
        let Some((_ss0, ch)) = local().await else {
            return;
        };
        let host = format!("nan1895-race-{}", nonce());
        let host = host.as_str();
        let d = (Utc::now() - Duration::days(4)).date_naive();
        let at = |h: u32| d.and_hms_opt(h, 0, 0).unwrap().and_utc();
        let early = at(9);
        let late = at(12);
        let start = at(10); // between the two watermarks
        let incident_end = d.succ_opt().unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc();
        let peer_ts = at(10) + Duration::minutes(30);
        let ts = |t: DateTime<Utc>| t.format("%Y-%m-%d %H:%M:%S%.6f").to_string();

        ch.query(&format!(
            "INSERT INTO nanosiem.logs (timestamp, source_type, src_host, process_name, message) \
             VALUES ('{p}', 'nan1895_race', '{host}', 'realknown.exe', 'k')",
            p = ts(peer_ts)
        ))
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1")
        .execute()
        .await
        .expect("real peer insert");
        ch.query(&format!(
            "INSERT INTO nanosiem.entity_dimension_day_agg \
             (entity_type, entity_value, dim, val, day, first_seen, event_count) VALUES \
             ('host', '{host}', 'process_name', 'phantom.exe', toDate('{d}'), \
              toDateTime64('{p}', 6), 1)",
            d = d.format("%Y-%m-%d"),
            p = ts(peer_ts),
        ))
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1")
        .execute()
        .await
        .expect("phantom insert");

        // Simulate the race: TWO rows, different active_since (no delete between).
        ch.query("ALTER TABLE nanosiem.baseline_agg_meta DELETE WHERE 1")
            .with_option("mutations_sync", "2")
            .execute()
            .await
            .expect("clear meta");
        ch.query(&format!(
            "INSERT INTO nanosiem.baseline_agg_meta (k, active_since) VALUES \
             ('active_since', toDateTime64('{e}', 6)), ('active_since', toDateTime64('{l}', 6))",
            e = ts(early),
            l = ts(late),
        ))
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1")
        .execute()
        .await
        .expect("race insert");
        clear_markers(&ch, "udm", d, d.succ_opt().unwrap()).await;

        // Reader returns MAX (the later, 12:00).
        let (ss, _c) = local().await.expect("db up");
        let read = ss.baseline_agg_active_since(&_c).await;
        assert_eq!(
            read.map(|t| t.timestamp()),
            Some(late.timestamp()),
            "reader must return MAX(active_since) = the later watermark, got {read:?}"
        );

        // End-to-end: start=10:00 is between 09:00 and 12:00. MAX(12:00) ⇒ start <
        // active_since ⇒ no markers ⇒ RAW (phantom absent). A non-MAX reader would
        // have served the agg.
        let dims = ["process_name"];
        let scope = ScopeSet::unrestricted();
        let (ss2, _c2) = local().await.expect("db up");
        let rows = ss2
            .entity_dimension_firsts(
                &scope, "host", host, true, &dims, start, incident_end,
                crate::baseline::NEW_TO_ENTITY_ROW_CAP,
            )
            .await
            .expect("routed runs");
        assert!(
            !rows.iter().any(|r| r.value == "phantom.exe"),
            "with MAX(active_since)=12:00 a 10:00 lookback must fall back to RAW (phantom absent): {:?}",
            rows.iter().map(|r| &r.value).collect::<Vec<_>>()
        );
        assert!(
            rows.iter().any(|r| r.value == "realknown.exe"),
            "raw fallback must still return the real peer"
        );
    }

    /// NAN-1895 regression: the fast path must engage for a caller whose deny-set
    /// is exactly `{audit}` — the source the agg already excludes — because the
    /// audit gate (NAN-1801) unions `audit` into every non-`audit:view` caller,
    /// so an `!is_restricted()` gate would send ~every real query to the raw scan.
    /// Phantom-row proof (activation set far in the past so the time gate
    /// serves): an `{audit}`-only scope sees the phantom (agg); a scope denying
    /// ANOTHER source must not (raw fallback).
    ///
    /// `#[ignore]` — requires local ClickHouse + Postgres. Run:
    ///   cargo test -p nanosiem-core --lib baseline_agg_scope_gate_live -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "requires local ClickHouse + Postgres with migration 166 applied"]
    async fn baseline_agg_scope_gate_live() {
        let Some((ss, ch)) = local().await else {
            return;
        };
        let host = format!("nan1895-scope-{}", nonce());
        let host = host.as_str();
        let today = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
        let incident_start = today - Duration::days(2);
        let incident_end = today - Duration::days(1);
        let new_start = incident_start - Duration::days(7);
        let ts = |t: DateTime<Utc>| t.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        let known = ts(new_start + Duration::hours(1));
        ch.query(&format!(
            "INSERT INTO nanosiem.logs (timestamp, source_type, src_host, process_name, message) VALUES \
             ('{known}', 'nan1895_scope', '{host}', 'realknown.exe', 'k')"
        ))
        .execute()
        .await
        .expect("seed insert");
        // Activation far in the past ⇒ the whole lookback is MV-active ⇒ agg.
        set_active_since(&ch, far_past()).await;
        let phantom_day = (new_start + Duration::hours(1)).date_naive();
        ch.query(&format!(
            "INSERT INTO nanosiem.entity_dimension_day_agg \
             (entity_type, entity_value, dim, val, day, first_seen, event_count) VALUES \
             ('host', '{host}', 'process_name', 'phantom.exe', toDate('{phantom_day}'), \
              toDateTime64('{known}', 6), 1)"
        ))
        .execute()
        .await
        .expect("phantom insert");

        let dims = ["process_name"];
        let has_phantom = |rows: &[DimensionFirst]| rows.iter().any(|r| r.value == "phantom.exe");
        let denied = |xs: &[&str]| {
            ScopeSet::from_denied(xs.iter().map(|s| s.to_string()).collect::<std::collections::BTreeSet<_>>())
        };

        // {audit}-only deny-set (the audit-gate case): MUST use the agg — phantom present.
        let audit_only = ss
            .entity_dimension_firsts(
                &denied(&["audit"]), "host", host, true, &dims, new_start, incident_end,
                crate::baseline::NEW_TO_ENTITY_ROW_CAP,
            )
            .await
            .expect("runs");
        assert!(
            has_phantom(&audit_only),
            "an audit-only deny-set must serve from the AGG (NAN-1895): {:?}",
            audit_only.iter().map(|r| &r.value).collect::<Vec<_>>()
        );

        // Denying ANOTHER source (which the agg includes): MUST fall back to raw.
        let multi = ss
            .entity_dimension_firsts(
                &denied(&["audit", "nan1895_other"]), "host", host, true, &dims, new_start,
                incident_end, crate::baseline::NEW_TO_ENTITY_ROW_CAP,
            )
            .await
            .expect("runs");
        assert!(
            !has_phantom(&multi),
            "a deny-set naming a source the agg includes must fall back to RAW: {:?}",
            multi.iter().map(|r| &r.value).collect::<Vec<_>>()
        );
        assert!(
            multi.iter().any(|r| r.value == "realknown.exe"),
            "raw fallback must still return the real peer"
        );
    }
}
