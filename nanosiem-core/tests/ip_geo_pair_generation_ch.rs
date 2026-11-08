// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4957 review (codex P2): the two IP geo dictionaries are one generation.
//! A pair reload that fails after the attrs half (the trie keeps the previous
//! generation) must never leave lookups empty, and the next `reload_pair`
//! completes the switch.
//!
//! Needs a DISPOSABLE ClickHouse migrated through 185 (single node), e.g. the
//! infra-only stack of `scripts/e2e/lanes/upgrade-185.sh`, which runs it:
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:<port> \
//! NANOSIEM_TEST_CLICKHOUSE_USER=nanosiem_admin NANOSIEM_TEST_CLICKHOUSE_PASSWORD=... \
//!   cargo test -p nanosiem-core --test ip_geo_pair_generation_ch -- --ignored --nocapture
//! ```

use nanosiem_core::enrichment::ip_geo::{
    geo_attr_expr, refresh_view_and_wait, reload_pair, IP_GEO_ATTRS_DICT, IP_GEO_HISTORY_REFRESH,
    IP_STAGING_REFRESH,
};

fn client() -> clickhouse::Client {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    let mut c = clickhouse::Client::default().with_url(url).with_database("nanosiem");
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        c = c.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        c = c.with_password(password);
    }
    c.with_option("network_compression_method", "LZ4")
}

const SOURCE: &str = "nan4957-pair-test";

async fn put_generation(ch: &clickhouse::Client, as_name: &str, as_domain: &str) {
    ch.query(&format!(
        "INSERT INTO nanosiem.ip_enrichments (network, country, country_code, continent, continent_code, \
         asn, as_name, as_domain, source_id, updated_at, deleted) SETTINGS async_insert = 0 VALUES \
         ('198.51.100.0/24', 'United States', 'US', 'North America', 'NA', 'AS64500', '{as_name}', '{as_domain}', \
          '{SOURCE}', now64(3), 0)"
    ))
    .execute()
    .await
    .expect("seed ip_enrichments");
    // Distinct updated_at between generations (argMax by updated_at).
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    refresh_view_and_wait(ch, IP_STAGING_REFRESH, "").await.expect("staging refresh");
}

async fn as_name(ch: &clickhouse::Client) -> String {
    ch.query(&format!("SELECT {} FROM (SELECT '198.51.100.7' AS ip)", geo_attr_expr("as_name", "ip")))
        .fetch_one::<String>()
        .await
        .expect("lookup")
}

#[tokio::test]
#[ignore = "needs NANOSIEM_TEST_CLICKHOUSE_URL (disposable, migrated through 185)"]
async fn half_reloaded_pair_keeps_serving_the_previous_generation() {
    let ch = client();

    // Generation A, fully active.
    put_generation(&ch, "Example Net A", "a.example").await;
    reload_pair(&ch, &ch, "").await.expect("pair reload A");
    assert_eq!(as_name(&ch).await, "Example Net A");

    // Generation B lands in staging; the pair reload fails after the attrs
    // half: history refresh + attrs reload happen, the trie reload does not.
    put_generation(&ch, "Example Net B", "b.example").await;
    refresh_view_and_wait(&ch, IP_GEO_HISTORY_REFRESH, "").await.expect("history refresh");
    ch.query(&format!("SYSTEM RELOAD DICTIONARY {IP_GEO_ATTRS_DICT}"))
        .execute()
        .await
        .expect("attrs reload");
    // The trie still maps the network to generation A's geo_id, and the attrs
    // half (staging UNION history) still knows it: never empty geo.
    assert_eq!(
        as_name(&ch).await,
        "Example Net A",
        "a half-finished pair reload must keep the previous generation resolvable"
    );

    // The retry completes the switch.
    reload_pair(&ch, &ch, "").await.expect("pair reload B");
    assert_eq!(as_name(&ch).await, "Example Net B");

    ch.query(&format!(
        "ALTER TABLE nanosiem.ip_enrichments DELETE WHERE source_id = '{SOURCE}' SETTINGS mutations_sync = 1"
    ))
    .execute()
    .await
    .expect("cleanup");
}
