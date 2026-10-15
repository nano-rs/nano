// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3058: real chDB over identity observation rows shaped exactly like a
//! part's entity-range partial (or a query[T] backfill file). Pins ClickHouse
//! `identity_observations` parity of the lookup: priority then newest at or
//! before the reference time, the 30-day window, the deny set applied before
//! selection, NAT candidates, and host/user reverse lookups.

use nanosiem_lake_worker::executor::NativeExecutor;
use nanosiem_lake_worker::identity_observations::{encode_value, Observation, IDENTITY_PATH};
use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::part_ingest::partials::{write_sorted, EntityRangeRow};
use nanosiem_lake_worker::part_query::identity::{
    output_rows, plan_coverage, plan_lookup, plan_lookup_over, plan_nat, plan_nat_over, Item, LookupKind, Relation,
};
use nanosiem_lake_worker::part_query::identity_merged::{plan_build, BuildTail};
use serde_json::Value;

const HOUR: i64 = 3_600_000_000;
const T: i64 = 1_790_000_000 * 1_000_000 - (1_790_000_000 * 1_000_000) % HOUR; // an hour boundary

fn obs(ip: &str, host: &str, user: &str, source: &str) -> Observation {
    Observation {
        ip: ip.into(), hostname: host.into(), fqdn: format!("{host}.corp.local"),
        mac: String::new(), user: user.into(), source: source.into(),
    }
}

fn row(o: Observation, first: i64, last: i64) -> EntityRangeRow {
    let hour = first.div_euclid(HOUR) * HOUR;
    EntityRangeRow { key: (IDENTITY_PATH.into(), encode_value(&o, hour)), first_time: first, last_time: last, events: 1 }
}

async fn run(executor: &NativeExecutor, sql: String, params: Vec<(String, String)>) -> Vec<Value> {
    let output = executor.execute_sql(sql, params).await.unwrap();
    output.data.split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|l| serde_json::from_slice(l).unwrap()).collect()
}

#[tokio::test]
#[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
async fn index_lookup_matches_clickhouse_identity_semantics() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.parquet");
    let b = dir.path().join("b.parquet");
    // Part a.
    write_sorted(vec![
        EntityRangeRow { key: (IDENTITY_PATH.into(), String::new()), first_time: T - 40 * 24 * HOUR, last_time: T, events: 99 },
        row(obs("10.0.0.1", "ws-a", "alice", "windows_sysmon"), T - 2 * HOUR, T - 2 * HOUR + 300_000_000),
        row(obs("10.0.0.1", "ws-b", "bob", "windows_sysmon"), T - 10 * 24 * HOUR, T - 10 * 24 * HOUR),
        row(obs("10.0.0.1", "ws-future", "carol", "windows_sysmon"), T + 60_000_000, T + 120_000_000),
        row(obs("10.0.0.2", "ws-straddle", "dave", "windows_sysmon"), T - 600_000_000, T + 600_000_000),
        row(obs("10.0.0.2", "ws-older", "erin", "windows_sysmon"), T - HOUR, T - HOUR),
        row(obs("10.0.0.3", "ws-ancient", "frank", "windows_sysmon"), T - 31 * 24 * HOUR, T - 31 * 24 * HOUR),
        // A bloom-path entity row must never read as an observation.
        EntityRangeRow { key: ("src_endpoint.ip".into(), "10.0.0.9".into()), first_time: T - HOUR, last_time: T - HOUR, events: 5 },
    ], &a).unwrap();
    // Part b.
    write_sorted(vec![
        row(obs("10.0.0.4", "ws-secret", "grace", "secret_source"), T - 60_000_000, T - 60_000_000),
        row(obs("10.0.0.4", "ws-allowed", "heidi", "windows_event"), T - 3 * HOUR, T - 3 * HOUR),
        row(obs("10.0.0.5", "nat-1", "", "firewall"), T - 48 * HOUR, T - 48 * HOUR + 1),
        row(obs("10.0.0.5", "nat-2", "", "firewall"), T - 48 * HOUR + 2, T - 48 * HOUR + 3),
        row(obs("10.0.0.5", "nat-3", "", "firewall"), T - 48 * HOUR + 4, T - 48 * HOUR + 5),
        // NAN-3394: an IP whose text extends another item's (the pushed-down
        // value range must not admit it for 10.0.0.1, nor drop it for itself),
        // and a host stored in upper case (the case-insensitive prefilter).
        row(obs("10.0.0.10", "WS-UPPER", "Ivan", "windows_event"), T - 60_000_000, T - 60_000_000),
    ], &b).unwrap();
    let spec = format!("{}/{{a.parquet,b.parquet}}", dir.path().display());
    let settings = " SETTINGS max_threads=1";
    // Coverage: per file, the coverage row's count (b has none: not indexed).
    let (sql, params) = plan_coverage(&spec, settings);
    let coverage = run(&executor, sql, params).await;
    assert_eq!(coverage.len(), 1, "{coverage:?}");
    assert!(coverage[0]["file"].as_str().unwrap().ends_with("/a.parquet"), "{coverage:?}");
    assert_eq!(coverage[0]["covered"].to_string().trim_matches('"'), "99");
    let items = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.9.9.9", "10.0.0.10"]
        .iter()
        .enumerate()
        .map(|(ordinal, ip)| Item { ordinal, key: ip.to_string(), reference_us: T })
        .collect::<Vec<_>>();

    let lookup = |denied: Vec<String>| {
        let (sql, params) = plan_lookup(&spec, LookupKind::Ip, &items, &denied, settings);
        run(&executor, sql, params)
    };
    let (nat_sql, nat_params) = plan_nat(&spec, &items, &[], settings);
    let nat = run(&executor, nat_sql, nat_params).await;
    let rows = output_rows(LookupKind::Ip, &items, &lookup(vec![]).await, &nat).unwrap();
    let by_ip = |ip: &str| rows.iter().find(|r| r["ip"] == ip).cloned();
    // Newest at or before the reference time wins; later observations never do.
    let one = by_ip("10.0.0.1").unwrap();
    assert_eq!((one["hostname"].as_str(), one["user"].as_str()), (Some("ws-a"), Some("alice")));
    assert_eq!(one["fqdn"], "ws-a.corp.local");
    assert_eq!(one["source_priority"], 50);
    // A straddling hourly row counts at its first observation (<= ref).
    let two = by_ip("10.0.0.2").unwrap();
    assert_eq!(two["hostname"], "ws-straddle");
    assert_eq!(two["observed_at"], nanosiem_lake_worker::part_query::identity::format_us(T - 600_000_000));
    // Older than 30 days: a miss. Unknown IP: a miss.
    assert!(by_ip("10.0.0.3").is_none());
    assert!(by_ip("10.9.9.9").is_none());
    assert_eq!(by_ip("10.0.0.4").unwrap()["hostname"], "ws-secret");
    assert_eq!(by_ip("10.0.0.10").unwrap()["hostname"], "WS-UPPER", "a newer row of 10.0.0.10 never answers 10.0.0.1");
    // NAT: 3 hostnames in one hour within 7 days.
    let five = by_ip("10.0.0.5").unwrap();
    assert_eq!(five["nat_candidate"], true);
    assert_eq!(five["nat_host_count"], 3);
    assert_eq!(one["nat_candidate"], false);

    // The deny set drops a denied source BEFORE selection: the older allowed
    // observation answers instead of a masked miss.
    let denied = output_rows(LookupKind::Ip, &items, &lookup(vec!["secret_source".into()]).await, &[]).unwrap();
    let four = denied.iter().find(|r| r["ip"] == "10.0.0.4").unwrap();
    assert_eq!((four["hostname"].as_str(), four["source"].as_str()), (Some("ws-allowed"), Some("windows_event")));

    // NAN-3394: a batch past the per-key range bound (one spanning range
    // and a key set) answers every item exactly as the small batch did.
    let many = items
        .iter()
        .map(|item| item.key.clone())
        .chain((0..20).map(|i| format!("10.200.0.{i}")))
        .enumerate()
        .map(|(ordinal, key)| Item { ordinal, key, reference_us: T })
        .collect::<Vec<_>>();
    let (sql, params) = plan_lookup(&spec, LookupKind::Ip, &many, &[], settings);
    let wide = output_rows(LookupKind::Ip, &many, &run(&executor, sql, params).await, &nat).unwrap();
    let narrow = output_rows(LookupKind::Ip, &items, &lookup(vec![]).await, &nat).unwrap();
    assert_eq!(wide, narrow, "the first items keep their ordinals; the fillers are misses");

    // Reverse lookups: host (short name or FQDN, any case) and user.
    for (kind, key, ip) in [
        (LookupKind::Host, "ws-a", "10.0.0.1"),
        (LookupKind::Host, "ws-a.corp.local", "10.0.0.1"),
        (LookupKind::User, "alice", "10.0.0.1"),
        (LookupKind::Host, "ws-upper", "10.0.0.10"),
        (LookupKind::Host, "ws-upper.corp.local", "10.0.0.10"),
        (LookupKind::User, "ivan", "10.0.0.10"),
    ] {
        let items = vec![Item { ordinal: 0, key: key.into(), reference_us: T }];
        let (sql, params) = plan_lookup(&spec, kind, &items, &[], settings);
        let rows = output_rows(kind, &items, &run(&executor, sql, params).await, &[]).unwrap();
        assert_eq!(rows.len(), 1, "{key}");
        assert_eq!(rows[0]["ip"], ip, "{key}");
        assert_eq!(rows[0]["value"], key);
    }
    // A key that only occurs inside another value (prefix, not a whole name)
    // is a miss, as before the prefilter.
    let items = vec![Item { ordinal: 0, key: "ws".into(), reference_us: T }];
    let (sql, params) = plan_lookup(&spec, LookupKind::Host, &items, &[], settings);
    assert!(run(&executor, sql, params).await.is_empty());
}

/// NAN-3399: lookups over the merged index (live sources it covers) plus the
/// tail read directly answer exactly what the same lookups over the raw
/// sources answer, including after a source leaves the live set and after an
/// incremental rebuild; the merged file is value-sorted in small row groups.
#[tokio::test]
#[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
async fn merged_index_lookups_equal_raw_source_lookups() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut files = Vec::new();
    for n in 0..12_usize {
        // Sources share a file name (a part's own directory) or not
        // (content-addressed objects, backfill files).
        let path = match n % 3 {
            0 => dir.path().join(format!("parts/p{n}/partials/entity_ranges.parquet")),
            1 => dir.path().join(format!("objects/{n:064x}.bin")),
            _ => dir.path().join(format!("backfill/p{n}.parquet")),
        };
        let mut rows = vec![EntityRangeRow { key: (IDENTITY_PATH.into(), String::new()), first_time: T - 40 * 24 * HOUR, last_time: T, events: 9 }];
        for i in 0..900_i64 {
            let ip = format!("10.0.{}.{}", i % 7, (i * 13 + n as i64) % 40);
            let host = format!("ws-{}", (i + n as i64 * 3) % 23);
            let source = ["windows_sysmon", "windows_event", "secret_source", "firewall"][(i % 4) as usize];
            // Unique per row: no argMax ties between sources.
            let first = T - ((i * 7_919 + n as i64 * 104_729) % (35 * 24)) * HOUR - (i % 50) * 60_000_000 - (n as i64 * 1_000 + i);
            rows.push(row(obs(&ip, &host, &format!("user{}", i % 11), source), first, first + (i % 3) * 1_800_000_000));
        }
        rows.push(EntityRangeRow { key: ("src_endpoint.ip".into(), format!("10.0.0.{n}")), first_time: T - HOUR, last_time: T - HOUR, events: 5 });
        let mut seen = std::collections::BTreeSet::new();
        rows.retain(|row| seen.insert(row.key.clone()));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        write_sorted(rows, &path).unwrap();
        files.push(path);
    }
    let text = |path: &std::path::PathBuf| path.to_str().unwrap().to_string();
    let spec = |paths: &[std::path::PathBuf]| {
        let relative = paths.iter().map(|path| path.strip_prefix(dir.path()).unwrap().to_str().unwrap().to_string()).collect::<Vec<_>>();
        format!("{}/{{{}}}", dir.path().display(), relative.join(","))
    };
    let tail = |paths: &[std::path::PathBuf], first_id: u32| BuildTail {
        spec: spec(paths),
        paths: paths.iter().map(text).collect(),
        canonical: paths.iter().map(|path| text(&std::fs::canonicalize(path).unwrap())).collect(),
        first_id,
    };
    let settings = " SETTINGS max_threads=1";
    let items = (0..12_i64)
        .map(|i| Item { ordinal: i as usize, key: format!("10.0.{}.{}", i % 7, (i * 5) % 41), reference_us: T - (i % 5) * 24 * HOUR - i * 60_000_000 })
        .collect::<Vec<_>>();
    let answer = |relation: Relation, kind: LookupKind, items: Vec<Item>, denied: Vec<String>| {
        let executor = &executor;
        async move {
            let (sql, params) = plan_lookup_over(&relation, kind, &items, &denied, settings);
            let found = run(executor, sql, params).await;
            let nat = if kind == LookupKind::Ip {
                let (sql, params) = plan_nat_over(&relation, &items, &denied, settings);
                run(executor, sql, params).await
            } else {
                Vec::new()
            };
            output_rows(kind, &items, &found, &nat).unwrap()
        }
    };
    let build = |output: std::path::PathBuf, tail: Option<BuildTail>, previous: Option<(String, Vec<u32>, Vec<u32>)>| {
        let executor = &executor;
        async move {
            let previous = previous.as_ref().map(|(path, old, new)| (path.as_str(), old.as_slice(), new.as_slice()));
            let (sql, mut params) = plan_build(tail.as_ref(), previous, settings).unwrap();
            params.push(("merge_output".into(), output.to_str().unwrap().to_string()));
            run(executor, sql, params).await;
            output.to_str().unwrap().to_string()
        }
    };
    let count = |rows: Vec<Value>, field: &str| rows[0][field].to_string().trim_matches('"').parse::<u64>().unwrap();
    let cases = |items: &Vec<Item>| {
        vec![
            (LookupKind::Ip, items.clone(), vec![]),
            (LookupKind::Ip, items.clone(), vec!["secret_source".to_string()]),
            (LookupKind::Host, vec![Item { ordinal: 0, key: "ws-7".into(), reference_us: T }, Item { ordinal: 1, key: "ws-7.corp.local".into(), reference_us: T - 3 * 24 * HOUR }], vec![]),
            (LookupKind::User, vec![Item { ordinal: 0, key: "user3".into(), reference_us: T - HOUR }], vec!["windows_event".to_string()]),
        ]
    };

    // First build: sources 0..9 as ids 1..=9.
    let merged = build(dir.path().join("merged-1.parquet"), Some(tail(&files[..9], 1)), None).await;
    let meta = run(&executor, format!("SELECT num_rows, num_row_groups FROM file('{merged}', ParquetMetadata)"), vec![]).await;
    assert!(count(meta.clone(), "num_row_groups") > 1, "{meta:?}");
    let sorted = run(&executor, format!("SELECT toUInt8(groupArray(value) = arraySort(groupArray(value))) AS ok FROM file('{merged}', Parquet) SETTINGS max_threads=1, input_format_parquet_preserve_order=1"), vec![]).await;
    assert_eq!(count(sorted, "ok"), 1, "value-sorted (read in file order: a parallel read reorders groupArray)");
    let coverage = run(&executor, format!("SELECT count() AS n FROM file('{merged}', Parquet) WHERE value = ''"), vec![]).await;
    assert_eq!(count(coverage, "n"), 0, "coverage rows are not observations");
    let per_source = run(&executor, format!("SELECT uniqExact(src) AS n, min(src) AS lo, max(src) AS hi FROM file('{merged}', Parquet)"), vec![]).await;
    assert_eq!((count(per_source.clone(), "n"), count(per_source.clone(), "lo"), count(per_source, "hi")), (9, 1, 9));

    // Live: every source but merged source 3 (id 4, superseded); tail: 9..12.
    let live_files = files.iter().enumerate().filter(|(n, _)| *n != 3).map(|(_, path)| path.clone()).collect::<Vec<_>>();
    let live = vec![1, 2, 3, 5, 6, 7, 8, 9];
    let mut hits = 0;
    for (kind, items, denied) in cases(&items) {
        let raw = answer(Relation::files(&spec(&live_files)), kind, items.clone(), denied.clone()).await;
        hits += raw.len();
        let over_merged = Relation { files: Some(spec(&files[9..])), merged: Some((merged.clone(), live.clone())) };
        assert_eq!(answer(over_merged, kind, items.clone(), denied.clone()).await, raw, "{kind:?} {denied:?}");
        // Every source live: the merged file and the raw sources agree too.
        let all = Relation { files: Some(spec(&files[9..])), merged: Some((merged.clone(), (1..=9).collect())) };
        assert_eq!(answer(all, kind, items.clone(), denied.clone()).await, answer(Relation::files(&spec(&files)), kind, items, denied).await);
    }
    assert!(hits > 10, "the fixture must exercise hits ({hits})");

    // Incremental rebuild: live merged rows renumbered 1..=8, tail 9..=11;
    // the superseded source's rows are gone.
    let rebuilt = build(dir.path().join("merged-2.parquet"), Some(tail(&files[9..], 9)), Some((merged.clone(), live.clone(), (1..=8).collect()))).await;
    let per_source = run(&executor, format!("SELECT uniqExact(src) AS n, min(src) AS lo, max(src) AS hi FROM file('{rebuilt}', Parquet)"), vec![]).await;
    assert_eq!((count(per_source.clone(), "n"), count(per_source.clone(), "lo"), count(per_source, "hi")), (11, 1, 11));
    for (kind, items, denied) in cases(&items) {
        let raw = answer(Relation::files(&spec(&live_files)), kind, items.clone(), denied.clone()).await;
        let only_merged = Relation { files: None, merged: Some((rebuilt.clone(), (1..=11).collect())) };
        assert_eq!(answer(only_merged, kind, items, denied).await, raw);
    }

    // A tail row whose path the build does not know fails the build.
    let mut wrong = tail(&files[9..], 1);
    wrong.paths[0] = "/nowhere".into();
    wrong.canonical[0] = "/nowhere".into();
    let (sql, mut params) = plan_build(Some(&wrong), None, settings).unwrap();
    params.push(("merge_output".into(), dir.path().join("merged-3.parquet").to_str().unwrap().to_string()));
    assert!(executor.execute_sql(sql, params).await.is_err(), "an unknown source is never written under a wrong id");
}
