// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn thresholds_are_80_and_90_percent() {
    assert_eq!(classify_usage(0.0), DiskLevel::Ok);
    assert_eq!(classify_usage(0.7999), DiskLevel::Ok);
    assert_eq!(classify_usage(0.80), DiskLevel::Warning);
    assert_eq!(classify_usage(0.8999), DiskLevel::Warning);
    assert_eq!(classify_usage(0.90), DiskLevel::Critical);
    assert_eq!(classify_usage(0.9499), DiskLevel::Critical);
    // NAN-5450: 95 % (under 5 % free) is imminent.
    assert_eq!(classify_usage(0.95), DiskLevel::Imminent);
    assert_eq!(classify_usage(1.0), DiskLevel::Imminent);
    assert_eq!(classify_usage(f64::NAN), DiskLevel::Unknown);
}

fn vol(component: DiskComponent, level: DiskLevel) -> DiskVolumeHealth {
    DiskVolumeHealth {
        component,
        host: None,
        name: "x".into(),
        path: None,
        total_bytes: None,
        used_bytes: None,
        free_bytes: None,
        usage_fraction: None,
        level,
        detail: String::new(),
        forecast: None,
        shared_with: None,
    }
}

#[test]
fn overall_is_worst_measured_level_and_unknown_does_not_raise_it() {
    assert_eq!(overall_level(&[]), DiskLevel::Unknown);
    assert_eq!(
        overall_level(&[vol(DiskComponent::Postgres, DiskLevel::Unknown)]),
        DiskLevel::Unknown
    );
    assert_eq!(
        overall_level(&[
            vol(DiskComponent::Clickhouse, DiskLevel::Ok),
            vol(DiskComponent::Postgres, DiskLevel::Unknown),
        ]),
        DiskLevel::Ok
    );
    assert_eq!(
        overall_level(&[
            vol(DiskComponent::Clickhouse, DiskLevel::Warning),
            vol(DiskComponent::VectorBuffer, DiskLevel::Critical),
            vol(DiskComponent::Postgres, DiskLevel::Ok),
        ]),
        DiskLevel::Critical
    );
}

#[test]
fn clickhouse_rows_become_volumes_with_host_only_on_a_cluster() {
    let rows = vec![ClickHouseDiskRow {
        host: "ch-0".into(),
        name: "default".into(),
        path: "/var/lib/clickhouse/".into(),
        total_space: 100,
        free_space: 15,
    }];
    let single = clickhouse_volumes_from_rows(&rows, false, &EvictorBand::DEFAULT);
    assert_eq!(single[0].host, None);
    assert_eq!(single[0].used_bytes, Some(85));
    assert_eq!(single[0].level, DiskLevel::Warning);
    let clustered = clickhouse_volumes_from_rows(&rows, true, &EvictorBand::DEFAULT);
    assert_eq!(clustered[0].host.as_deref(), Some("ch-0"));
    assert_eq!(clustered[0].key(), "clickhouse:ch-0:default");
}

#[test]
fn clickhouse_sql_fans_out_only_on_a_cluster_and_escapes_the_name() {
    let local = clickhouse_disks_sql(None);
    assert!(local.contains("FROM system.disks"));
    assert!(local.contains("type = 'Local'"));
    let fanout = clickhouse_disks_sql(Some("de'fault"));
    assert!(fanout.contains("clusterAllReplicas('de''fault', system.disks)"), "{fanout}");
}

#[test]
fn quantities_parse_like_kubernetes() {
    assert_eq!(parse_quantity("20Gi"), Some(20 * 1024 * 1024 * 1024));
    assert_eq!(parse_quantity("500G"), Some(500_000_000_000));
    assert_eq!(parse_quantity("1048576"), Some(1_048_576));
    assert_eq!(parse_quantity("1.5Ki"), Some(1536));
    assert_eq!(parse_quantity("20 GB"), None);
    assert_eq!(parse_quantity(""), None);
}

#[test]
fn postgres_capacity_from_env() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    };
    assert_eq!(
        PostgresCapacity::from_env(env(&[("NANO_POSTGRES_SHARES_CLICKHOUSE_DISK", "true")])),
        PostgresCapacity::SharesClickHouseDisk
    );
    assert_eq!(
        PostgresCapacity::from_env(env(&[("NANO_POSTGRES_VOLUME_SIZE", "1Ki")])),
        PostgresCapacity::VolumeBytes(1024)
    );
    assert_eq!(
        PostgresCapacity::from_env(env(&[("NANO_POSTGRES_SHARES_CLICKHOUSE_DISK", "false")])),
        PostgresCapacity::Unknown
    );
    assert_eq!(PostgresCapacity::from_env(env(&[])), PostgresCapacity::Unknown);
}

#[test]
fn postgres_on_its_own_volume_is_database_plus_wal_over_size() {
    let v = postgres_volume(850, Some(50), &PostgresCapacity::VolumeBytes(1000), None);
    assert_eq!(v.used_bytes, Some(900));
    assert_eq!(v.free_bytes, Some(100));
    assert_eq!(v.level, DiskLevel::Critical);
}

#[test]
fn postgres_sharing_the_clickhouse_disk_takes_its_usage() {
    let ch = clickhouse_volumes_from_rows(
        &[ClickHouseDiskRow {
            host: "h".into(),
            name: "default".into(),
            path: "/".into(),
            total_space: 1000,
            free_space: 150,
        }],
        false,
        &EvictorBand::DEFAULT,
    );
    let v = postgres_volume(10, None, &PostgresCapacity::SharesClickHouseDisk, ch.first());
    assert_eq!(v.level, DiskLevel::Warning);
    assert_eq!(v.usage_fraction, Some(0.85));
    assert_eq!(v.used_bytes, Some(10));
    assert!(v.detail.contains("WAL size not readable"));
}

#[test]
fn postgres_without_capacity_is_unknown_and_says_why() {
    let v = postgres_volume(10, Some(1), &PostgresCapacity::Unknown, None);
    assert_eq!(v.level, DiskLevel::Unknown);
    assert!(v.detail.contains("not visible over SQL"));
}

/// Shape captured from ghcr.io/nano-rs/vector:0.61.0-nano.12-debian.
const VECTOR_PAGE: &str = r#"# HELP nanosiem_vector_buffer_size_bytes buffer_size_bytes
nanosiem_vector_buffer_max_size_bytes{buffer_id="clickhouse_logs",buffer_type="disk",component_id="clickhouse_logs",component_kind="sink",component_type="clickhouse",host="828f11a0f256",stage="0"} 1000 1794693399999
nanosiem_vector_buffer_max_byte_size{buffer_id="clickhouse_logs",buffer_type="disk",component_id="clickhouse_logs",component_kind="sink",component_type="clickhouse",host="828f11a0f256",stage="0"} 1000 1794693399999
nanosiem_vector_buffer_max_size_bytes{buffer_id="clickhouse_ocsf",buffer_type="disk",component_id="clickhouse_ocsf",component_kind="sink",component_type="clickhouse",host="828f11a0f256",stage="0"} 1000 1794693399999
nanosiem_vector_buffer_max_size_events{buffer_id="prometheus_metrics",buffer_type="memory",component_id="prometheus_metrics",component_kind="sink",component_type="prometheus_exporter",host="828f11a0f256",stage="0"} 500 1794693399999
nanosiem_vector_buffer_size_bytes{buffer_id="clickhouse_logs",buffer_type="disk",component_id="clickhouse_logs",component_kind="sink",component_type="clickhouse",host="828f11a0f256",stage="0"} 910 1794693403000
nanosiem_vector_buffer_size_bytes{buffer_id="clickhouse_ocsf",buffer_type="disk",component_id="clickhouse_ocsf",component_kind="sink",component_type="clickhouse",host="828f11a0f256",stage="0"} 10 1794693403000
nanosiem_vector_buffer_size_bytes{buffer_id="prometheus_metrics",buffer_type="memory",component_id="prometheus_metrics",component_kind="sink",component_type="prometheus_exporter",host="828f11a0f256",stage="0"} 0 1794693403000
"#;

#[test]
fn vector_page_yields_disk_buffers_only() {
    let samples = parse_vector_buffers(VECTOR_PAGE);
    assert_eq!(samples.len(), 2, "{samples:?}");
    let logs = samples.iter().find(|s| s.buffer_id == "clickhouse_logs").unwrap();
    assert_eq!(logs.size_bytes, 910);
    assert_eq!(logs.max_bytes, Some(1000));
    assert_eq!(logs.host.as_deref(), Some("828f11a0f256"));
}

#[test]
fn vector_level_follows_the_fullest_buffer() {
    let volumes = vector_volumes(&parse_vector_buffers(VECTOR_PAGE), "vector:9598");
    assert_eq!(volumes.len(), 1);
    let v = &volumes[0];
    assert_eq!(v.level, DiskLevel::Critical);
    assert_eq!(v.used_bytes, Some(920));
    assert_eq!(v.total_bytes, Some(2000));
    assert_eq!(v.usage_fraction, Some(0.91));
    assert!(v.detail.contains("clickhouse_logs"), "{}", v.detail);
}

#[test]
fn vector_without_max_size_is_unknown() {
    let page = r#"nanosiem_vector_buffer_size_bytes{buffer_id="b",buffer_type="disk"} 5"#;
    let volumes = vector_volumes(&parse_vector_buffers(page), "vector:9598");
    assert_eq!(volumes[0].level, DiskLevel::Unknown);
    assert_eq!(volumes[0].host.as_deref(), Some("vector:9598"));
}

#[test]
fn label_parser_handles_escaped_quotes_and_commas() {
    let labels = r#"a="x\",y",buffer_type="disk",b="z""#;
    assert_eq!(label(labels, "buffer_type"), Some("disk"));
    assert_eq!(label(labels, "b"), Some("z"));
    assert_eq!(label(labels, "missing"), None);
}

#[test]
fn vector_scrape_plan_by_topology() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    };
    assert_eq!(
        vector_scrape_plan(env(&[
            ("NANO_VECTOR_ACK_METRICS_PEERS", "nano-vector-metrics-peers.ns.svc.cluster.local:9598"),
            ("VECTOR_METRICS_URL", "http://lb:9598/metrics"),
        ])),
        Some(VectorScrape::Peers("nano-vector-metrics-peers.ns.svc.cluster.local:9598".into()))
    );
    assert_eq!(
        vector_scrape_plan(env(&[("VECTOR_METRICS_URL", "http://lb:9598/metrics")])),
        Some(VectorScrape::Url("http://lb:9598/metrics".into()))
    );
    // Role-split app host: Vector is on the ingest hosts.
    assert_eq!(
        vector_scrape_plan(env(&[("INGEST_SERVICE_URL", "http://ingest-proxy:8080/healthz")])),
        None
    );
    assert_eq!(vector_scrape_plan(env(&[("NANO_VECTOR_ON_INGEST_HOSTS", "true")])), None);
    assert_eq!(
        vector_scrape_plan(env(&[])),
        Some(VectorScrape::Url("http://vector:9598/metrics".into()))
    );
}

#[test]
fn report_lists_alarming_volumes() {
    let r = DiskHealthReport::new(
        vec![
            vol(DiskComponent::Clickhouse, DiskLevel::Ok),
            vol(DiskComponent::Postgres, DiskLevel::Warning),
            vol(DiskComponent::VectorBuffer, DiskLevel::Critical),
        ],
        vec![],
    );
    assert_eq!(r.status, DiskLevel::Critical);
    assert_eq!(r.alarming().count(), 2);
}

#[test]
fn human_bytes_formats() {
    assert_eq!(human_bytes(512), "512 B");
    assert_eq!(human_bytes(1536), "1.5 KiB");
    assert_eq!(human_bytes(20 * 1024 * 1024 * 1024), "20.0 GiB");
}

// -- NAN-5450: forecast --------------------------------------------------------

const GIB: u64 = 1 << 30;

fn series(start_used: u64, per_hour: i64, hours: &[f64]) -> Vec<(DateTime<Utc>, u64)> {
    let t0 = DateTime::parse_from_rfc3339("2026-11-14T00:00:00Z").unwrap().with_timezone(&Utc);
    hours
        .iter()
        .map(|h| {
            let t = t0 + chrono::Duration::milliseconds((h * 3_600_000.0) as i64);
            (t, (start_used as i64 + (per_hour as f64 * h) as i64) as u64)
        })
        .collect()
}

fn measured(usage: f64, total: u64) -> DiskVolumeHealth {
    let used = (usage * total as f64) as u64;
    DiskVolumeHealth {
        component: DiskComponent::Clickhouse,
        host: None,
        name: "default".into(),
        path: None,
        total_bytes: Some(total),
        used_bytes: Some(used),
        free_bytes: Some(total - used),
        usage_fraction: Some(usage),
        level: classify_usage(usage),
        detail: format!("{:.1}% used", usage * 100.0),
        forecast: None,
        shared_with: None,
    }
}

#[test]
fn growth_is_the_least_squares_slope_in_bytes_per_hour() {
    let s = series(10 * GIB, GIB as i64, &[0.0, 1.0, 2.0, 3.0]);
    let (g, span) = growth_bytes_per_hour(&s).unwrap();
    assert!((g - GIB as f64).abs() < 1.0, "{g}");
    assert_eq!(span, 3.0);
    // Noise around a 2 GiB/h trend still fits about 2 GiB/h.
    let mut noisy = series(0, 2 * GIB as i64, &[0.0, 0.5, 1.0, 1.5, 2.0]);
    noisy[1].1 += GIB / 4;
    noisy[3].1 -= GIB / 4;
    let (g, _) = growth_bytes_per_hour(&noisy).unwrap();
    assert!((g / (2 * GIB) as f64 - 1.0).abs() < 0.10, "{g}");
}

#[test]
fn too_few_or_too_close_samples_give_no_forecast() {
    assert!(growth_bytes_per_hour(&series(0, GIB as i64, &[0.0, 1.0])).is_none());
    assert!(growth_bytes_per_hour(&series(0, GIB as i64, &[0.0, 0.1, 0.2])).is_none());
    assert!(growth_bytes_per_hour(&[]).is_none());
}

#[test]
fn hours_to_full_needs_real_growth() {
    assert_eq!(hours_to_full(10 * GIB, GIB as f64), Some(10.0));
    assert_eq!(hours_to_full(10 * GIB, 0.0), None);
    assert_eq!(hours_to_full(10 * GIB, -(GIB as f64)), None);
    assert_eq!(hours_to_full(10 * GIB, 1000.0), None, "under 1 MiB/h is flat");
}

/// NAN-5450 review: on the ClickHouse disk the forecast counts to the
/// evictor's pause threshold (92 %), and escalates only above the high
/// watermark.
#[test]
fn a_clickhouse_disk_reaching_the_pause_within_24_hours_escalates_above_the_high_watermark() {
    // 100 GiB disk, 82 % used, growing 0.5 GiB/h: 10 GiB to the 92 % pause, 20 h.
    let mut v = measured(0.82, 100 * GIB);
    apply_forecast(&mut v, &series(80 * GIB, (GIB / 2) as i64, &[0.0, 1.0, 2.0, 4.0]), &EvictorBand::DEFAULT);
    let f = v.forecast.as_ref().unwrap();
    assert_eq!(v.level, DiskLevel::Critical);
    assert!(f.escalated);
    assert_eq!(f.full_fraction, 0.92);
    assert!((f.hours_to_full.unwrap() - 20.0).abs() < 0.5, "{f:?}");
    assert!(v.detail.contains("ingestion pauses at 92% in about 20 hours"), "{}", v.detail);
}

/// A replay burst on a disk at 60 % is what eviction handles: a forecast,
/// but nobody is paged.
#[test]
fn a_replay_at_60_percent_never_escalates() {
    let mut v = measured(0.60, 100 * GIB);
    apply_forecast(&mut v, &series(54 * GIB, 2 * GIB as i64, &[0.0, 1.0, 2.0, 3.0]), &EvictorBand::DEFAULT);
    let f = v.forecast.as_ref().unwrap();
    assert_eq!(v.level, DiskLevel::Ok);
    assert!(!f.escalated);
    assert!((f.hours_to_full.unwrap() - 16.0).abs() < 0.5, "32 GiB to the pause at 2 GiB/h: {f:?}");
}

/// Other volumes still count to 100 % and escalate from 80 %.
#[test]
fn a_postgres_volume_counts_to_full_and_escalates_from_80_percent() {
    let mut v = measured(0.85, 100 * GIB);
    v.component = DiskComponent::Postgres;
    apply_forecast(&mut v, &series(79 * GIB, 2 * GIB as i64, &[0.0, 1.0, 2.0, 3.0]), &EvictorBand::DEFAULT);
    let f = v.forecast.as_ref().unwrap();
    assert_eq!(f.full_fraction, 1.0);
    assert_eq!(v.level, DiskLevel::Critical);
    assert!(v.detail.contains("full in about"), "{}", v.detail);
}

/// The evictor keeps a capped install between its low and high watermarks:
/// the ClickHouse disk warns only clearly above the high watermark.
#[test]
fn the_clickhouse_disk_warns_only_above_the_evictor_band() {
    let band = EvictorBand::DEFAULT;
    assert!((band.clickhouse_warn_fraction() - 0.83).abs() < 1e-9);
    let row = |free| ClickHouseDiskRow { host: "h".into(), name: "default".into(), path: "/".into(), total_space: 100, free_space: free };
    for (free, level) in [(30, DiskLevel::Ok), (20, DiskLevel::Ok), (19, DiskLevel::Ok), (16, DiskLevel::Warning), (10, DiskLevel::Critical)] {
        assert_eq!(clickhouse_volumes_from_rows(&[row(free)], false, &band)[0].level, level, "{}% used", 100 - free);
    }
    // A raised high watermark moves the warning; never past critical.
    assert!((EvictorBand { high: 0.85, pause: 0.92 }.clickhouse_warn_fraction() - 0.88).abs() < 1e-9);
    assert_eq!(EvictorBand { high: 0.89, pause: 0.95 }.clickhouse_warn_fraction(), DISK_CRITICAL_FRACTION);
    assert_eq!(warn_fraction_for(DiskComponent::Postgres, &band), DISK_WARN_FRACTION);
}

#[test]
fn slow_growth_does_not_escalate_and_imminent_is_kept() {
    // 60 % used, 0.5 GiB/h: 80 h to full, stays Ok.
    let mut v = measured(0.60, 100 * GIB);
    apply_forecast(&mut v, &series(58 * GIB, (GIB / 2) as i64, &[0.0, 1.0, 2.0, 4.0]), &EvictorBand::DEFAULT);
    assert_eq!(v.level, DiskLevel::Ok);
    assert!(!v.forecast.as_ref().unwrap().escalated);
    // Imminent is never lowered by a forecast.
    let mut v = measured(0.96, 100 * GIB);
    apply_forecast(&mut v, &series(96 * GIB, 0, &[0.0, 1.0, 2.0]), &EvictorBand::DEFAULT);
    assert_eq!(v.level, DiskLevel::Imminent);
    assert_eq!(v.forecast.as_ref().unwrap().hours_to_full, None);
}

#[test]
fn a_shared_volume_takes_its_disks_level_and_alerts_list_the_disk_once() {
    let ch = measured(0.97, 100 * GIB);
    let mut pg = vol(DiskComponent::Postgres, DiskLevel::Ok);
    pg.used_bytes = Some(GIB);
    pg.shared_with = Some(ch.key());
    let mut report = DiskHealthReport::new(vec![ch.clone(), pg], vec![]);
    apply_forecasts(&mut report, &std::collections::HashMap::new(), &EvictorBand::DEFAULT);
    assert_eq!(report.volumes[1].level, DiskLevel::Imminent);
    assert_eq!(report.status, DiskLevel::Imminent);
    let disks = report.alarming_disks();
    assert_eq!(disks.len(), 1);
    assert_eq!(disks[0].component, DiskComponent::Clickhouse);
}

#[test]
fn alarming_disks_are_worst_first_then_soonest_full() {
    let mut a = measured(0.85, 100 * GIB);
    a.name = "a".into();
    let mut b = measured(0.96, 100 * GIB);
    b.name = "b".into();
    let report = DiskHealthReport::new(vec![a, b, measured(0.10, 100 * GIB)], vec![]);
    let names: Vec<_> = report.alarming_disks().iter().map(|v| v.name.clone()).collect();
    assert_eq!(names, ["b", "a"]);
}

#[test]
fn human_hours_reads_naturally() {
    assert_eq!(human_hours(0.25), "15 minutes");
    assert_eq!(human_hours(1.0), "1 hour");
    assert_eq!(human_hours(7.4), "7 hours");
    assert_eq!(human_hours(72.0), "3 days");
}
