// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5132: every deploy and publish waits for Vector's metrics to show the
//! reload's activation marker (`ReloadAckProbe::await_marker`), and those
//! metrics are only exported when `[sources.internal_metrics]` scrapes. At a
//! 10s scrape that wait added 1-11s to every deploy after Vector had already
//! reloaded. These pin the scrape fast enough for the ack path, keep the ack
//! timeout far above it, and keep the scrape feeding nothing but the in-memory
//! Prometheus exporter, so a faster scrape writes and ships nothing.

const METRICS: &str = include_str!("../../../../../config/vector/92-metrics.toml");
// NAN-5899: 92-metrics.toml's ClickHouse sink is YAML (both Vector 0.61 and 0.62 load it).
const METRICS_SINKS: &str = include_str!("../../../../../config/vector/92-metrics-sinks.yaml");

/// The file as Vector reads it: `${NAME:-default}` interpolated to its default
/// (NAN-5810: placeholders are quoted, so a substituted number is a string).
fn metrics_config() -> toml::Table {
    regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
        .unwrap()
        .replace_all(METRICS, "$1")
        .parse()
        .expect("92-metrics.toml parses")
}

fn scrape_interval_secs() -> f64 {
    let config = metrics_config();
    let value = &config["sources"]["internal_metrics"]["scrape_interval_secs"];
    value
        .as_float()
        .or_else(|| value.as_integer().map(|v| v as f64))
        .expect("scrape_interval_secs is a number")
}

#[test]
fn internal_metrics_scrape_is_fast_enough_for_the_deploy_ack() {
    let secs = scrape_interval_secs();
    assert!(
        secs > 0.0 && secs <= 2.0,
        "the deploy ack reads the activation marker from these metrics; a {secs}s scrape adds up \
         to {secs}s to every deploy"
    );
}

#[test]
fn reload_ack_timeout_stays_far_above_the_scrape_interval() {
    let secs = scrape_interval_secs();
    assert!(
        super::DEFAULT_RELOAD_ACK_TIMEOUT_SECS as f64 >= 10.0 * secs,
        "a timeout near the scrape interval reports good reloads as unacknowledged and rolls \
         them back"
    );
}

#[test]
fn internal_metrics_feeds_only_the_in_memory_prometheus_exporter() {
    let config = metrics_config();
    let yaml: toml::Value = serde_yaml::from_str(&crate::vector_env::substitute_like_vector(METRICS_SINKS))
        .expect("92-metrics-sinks.yaml parses");
    let mut consumers = Vec::new();
    for table in [config.get("transforms"), config.get("sinks"), yaml.get("sinks")] {
        let Some(table) = table.and_then(|v| v.as_table()) else {
            continue;
        };
        for (name, component) in table {
            let reads_metrics = component
                .get("inputs")
                .and_then(|v| v.as_array())
                .is_some_and(|inputs| inputs.iter().any(|i| i.as_str() == Some("internal_metrics")));
            if reads_metrics {
                consumers.push((
                    name.clone(),
                    component.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                ));
            }
        }
    }
    assert_eq!(
        consumers,
        vec![("prometheus_metrics".to_string(), "prometheus_exporter".to_string())],
        "a 1s scrape is only cheap while nothing writes or ships each scrape; a sink added here \
         multiplies its rows/traffic by the scrape rate"
    );
}
