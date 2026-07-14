use super::*;

#[test]
fn bare_host_defaults_to_https() {
    // Never silently downgrade a SIEM connection to cleartext.
    assert_eq!(normalize_url("siem.acme.io").unwrap(), "https://siem.acme.io");
    assert_eq!(
        normalize_url("siem.acme.io:3000").unwrap(),
        "https://siem.acme.io:3000"
    );
}

#[test]
fn loopback_http_is_preserved() {
    // Cleartext is fine when the bytes never leave the machine (local dev).
    assert_eq!(
        normalize_url("http://localhost:3000").unwrap(),
        "http://localhost:3000"
    );
    assert_eq!(
        normalize_url("http://127.0.0.1:3000").unwrap(),
        "http://127.0.0.1:3000"
    );
    assert_eq!(normalize_url("http://[::1]:3000").unwrap(), "http://[::1]:3000");
}

#[test]
fn remote_http_is_refused() {
    // Would send the password + tokens in cleartext to another machine.
    assert!(matches!(
        normalize_url("http://siem.acme.io"),
        Err(Error::InvalidUrl(_))
    ));
    assert!(matches!(
        normalize_url("http://10.0.0.5:3000"),
        Err(Error::InvalidUrl(_))
    ));
    // But https to the same hosts is fine.
    assert_eq!(
        normalize_url("https://siem.acme.io").unwrap(),
        "https://siem.acme.io"
    );
}

#[test]
fn trailing_slashes_and_whitespace_are_trimmed() {
    assert_eq!(
        normalize_url("  https://siem.acme.io/  ").unwrap(),
        "https://siem.acme.io"
    );
}

#[test]
fn path_prefix_survives_normalization() {
    // Some deployments sit behind a reverse-proxy path prefix; requests are
    // built as `{base}/api/...`, so the prefix has to stay.
    assert_eq!(
        normalize_url("https://acme.io/nano/").unwrap(),
        "https://acme.io/nano"
    );
}

#[test]
fn rejects_empty_and_non_http_schemes() {
    assert!(matches!(normalize_url("   "), Err(Error::InvalidUrl(_))));
    assert!(matches!(
        normalize_url("ftp://siem.acme.io"),
        Err(Error::InvalidUrl(_))
    ));
    assert!(matches!(
        normalize_url("file:///etc/passwd"),
        Err(Error::InvalidUrl(_))
    ));
}

#[tokio::test]
async fn commands_fail_cleanly_before_connect() {
    // Every authed path must report NotConnected rather than panic or hang when
    // no server has been chosen yet.
    let siem = Siem::default();


    let channel = Channel::new(|_| Ok(()));
    assert!(matches!(
        siem.search_stream("tab-1", &serde_json::json!({}), false, channel)
            .await,
        Err(Error::NotConnected)
    ));
}

#[tokio::test]
async fn a_failed_search_does_not_leak_its_cancel_flag() {
    // Not connected ⇒ run_stream errors immediately. The flag must still be
    // retired, or every failed query grows the map for the life of the process.
    let siem = Siem::default();
    let channel = Channel::new(|_| Ok(()));
    let _ = siem
        .search_stream("tab-1", &serde_json::json!({}), false, channel)
        .await;
    assert!(siem.active_searches.lock().await.is_empty());
}

#[tokio::test]
async fn cancelling_one_tab_leaves_the_others_running() {
    let siem = Siem::default();
    let a = siem.begin_search("tab-a").await;
    let b = siem.begin_search("tab-b").await;

    siem.cancel_search("tab-a").await;

    assert!(a.load(Ordering::Relaxed), "tab-a should be cancelled");
    assert!(!b.load(Ordering::Relaxed), "tab-b must keep streaming");
}

#[tokio::test]
async fn rerunning_a_tab_supersedes_only_its_own_stream() {
    let siem = Siem::default();
    let first = siem.begin_search("tab-a").await;
    let other = siem.begin_search("tab-b").await;

    // Same id again: the previous run for THIS tab is cancelled...
    let second = siem.begin_search("tab-a").await;

    assert!(first.load(Ordering::Relaxed));
    assert!(!second.load(Ordering::Relaxed));
    // ...and the unrelated tab is untouched.
    assert!(!other.load(Ordering::Relaxed));
}

#[test]
fn search_base_falls_back_to_the_main_url() {
    // Deployed instances fan /api/search* to the search service from the same
    // origin; only a split deployment (or local dev) sets the override.
    let same_origin = ServerConfig {
        base_url: "https://siem.acme.io".into(),
        search_url: None,
        allow_insecure: false,
        last_email: None,
    };
    assert_eq!(same_origin.search_base(), "https://siem.acme.io");

    let split = ServerConfig {
        base_url: "http://localhost:3000".into(),
        search_url: Some("http://localhost:3002".into()),
        allow_insecure: false,
        last_email: None,
    };
    assert_eq!(split.search_base(), "http://localhost:3002");
}

/// Both fixtures below are the VERBATIM responses the local search service gave
/// for these queries — captured, not imagined.
#[test]
fn an_unseen_indicator_has_no_first_seen() {
    // `min(timestamp)` over an empty match set returns ClickHouse's zero value,
    // not null. Passed through, an indicator nobody has ever seen would report
    // "first seen 1 Jan 1970" — a fabricated fact about an artifact with no data
    // behind it, which is the whole failure mode this feature exists to avoid.
    let unseen = serde_json::json!({
        "results": [{
            "assets": 0,
            "events": 0,
            "first_seen": "1970-01-01T00:00:00.000Z",
            "last_seen": "1970-01-01T00:00:00.000Z"
        }]
    });

    let summary = read_summary(&unseen).expect("a result set, even an empty-match one");
    assert_eq!(summary.events, 0);
    assert_eq!(summary.assets, 0);
    assert_eq!(summary.first_seen, None);
    assert_eq!(summary.last_seen, None);
}

#[test]
fn a_seen_indicator_keeps_its_span() {
    let seen = serde_json::json!({
        "results": [{
            "assets": 1075,
            "events": 1895,
            "first_seen": "2026-06-13T22:51:05.214Z",
            "last_seen": "2026-07-11T15:13:40.279Z"
        }]
    });

    let summary = read_summary(&seen).expect("a result set");
    assert_eq!(summary.events, 1895);
    assert_eq!(summary.assets, 1075);
    assert_eq!(summary.first_seen.as_deref(), Some("2026-06-13T22:51:05.214Z"));
    assert_eq!(summary.last_seen.as_deref(), Some("2026-07-11T15:13:40.279Z"));
}

#[test]
fn an_indicator_with_quotes_cannot_break_out_of_the_query() {
    // The classifier forbids quotes in an indicator, but bulk lookup takes
    // whatever the analyst pasted — this is where text becomes a query.
    let query = summary_query(r#"evil".com"#);
    assert!(query.contains(r#"ioc = "evil\".com""#), "got: {query}");

    let backslash = summary_query(r"evil\.com");
    assert!(backslash.contains(r#"ioc = "evil\\.com""#), "got: {backslash}");
}

#[test]
fn the_ingest_chart_draws_the_quiet_hours_too() {
    use chrono::TimeZone;

    // `timechart` only returns hours that HAD events — verified live: a 24h
    // window over the local instance came back with TWO buckets, not 24. Plotted
    // as-is, two bars from distant hours sit side by side and the chart reads as a
    // continuous ingest rate that never dipped.
    let mut counts = std::collections::HashMap::new();
    counts.insert("2026-07-13T00:00:00Z".to_string(), 1);
    counts.insert("2026-07-13T01:00:00Z".to_string(), 4);

    // A window that does NOT start on the hour — the buckets are hour-aligned, so
    // the series has to align before it can match them.
    let start = Utc.with_ymd_and_hms(2026, 7, 12, 23, 23, 45).unwrap();
    let end = Utc.with_ymd_and_hms(2026, 7, 13, 3, 10, 0).unwrap();

    let series = hourly_series(start, end, &counts);

    // 23:00, 00:00, 01:00, 02:00, 03:00 — every hour, not just the loud ones.
    assert_eq!(series.len(), 5);
    assert_eq!(series[0].at, "2026-07-12T23:00:00Z");
    assert_eq!(series[0].count, 0);
    assert_eq!(series[1].count, 1);
    assert_eq!(series[2].count, 4);
    assert_eq!(series[3].count, 0);
    assert_eq!(series[4].count, 0);

    // And the total the KPI shows is still the real one.
    let total: u64 = series.iter().map(|bucket| bucket.count).sum();
    assert_eq!(total, 5);
}

#[test]
fn the_ingest_request_asks_for_more_buckets_than_the_window_has_hours() {
    // The search `limit` caps the number of GROUPS an aggregate returns, not the
    // events behind them. The peek's default of 20 silently truncated a 24h
    // `| timechart span=1h` (25 buckets) to its first 20 — and because timechart
    // orders by bucket, the five hours it dropped were the most RECENT ones. The
    // dashboard drew ingest cliffing to zero for the last five hours of a
    // perfectly healthy cluster, and marked nothing degraded, because the search
    // had succeeded. The limit is explicit at every call site now.
    assert!(
        INGEST_BUCKETS > 25,
        "a 24h window at span=1h yields up to 25 buckets; asking for {INGEST_BUCKETS} \
         would truncate the newest hours and draw them as zero"
    );

    let request = peek_request("* | timechart span=1h count", &peek_window(1), INGEST_BUCKETS);
    assert_eq!(request["limit"], serde_json::json!(INGEST_BUCKETS));
}

#[test]
fn a_200_that_is_not_a_result_set_is_a_failure_not_a_clean_bill() {
    // A proxy error page, a `{"error": …}` body returned with HTTP 200, a schema
    // change — none of these mean "we looked and found nothing". Read as zero,
    // they would report every indicator in a threat report as unseen, and the
    // bulk table would present them as successfully checked. That is the exact
    // false-clean this feature exists to avoid.
    assert!(read_summary(&serde_json::json!({ "error": "ClickHouse unavailable" })).is_none());
    assert!(read_summary(&serde_json::json!({ "results": "not an array" })).is_none());
    assert!(read_summary(&serde_json::json!({})).is_none());

    // But an empty match set IS a real answer: we looked, and saw nothing.
    let empty = read_summary(&serde_json::json!({ "results": [] })).expect("an empty result set");
    assert_eq!(empty.events, 0);
    assert_eq!(empty.first_seen, None);
}
