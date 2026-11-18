// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5565: the identities that run a rescued (generated, lifted) query must
//! be allowed to SET `max_query_size` per query.
//!
//! Rescue-capable executors (`for_generated_sql`) run as:
//! - `nanosiem` (profile `default`): the API's internal SearchService, which
//!   the scheduled detection engine uses (`DetectionService::
//!   with_dual_pool_prevalence_and_profile` -> `dual_pool.clickhouse()`), and
//!   the jobs/async paths built on the same pool;
//! - `nanosiem_search` (profile `search`): the search service and the API's
//!   user-facing / AI searches (`with_clickhouse_identity`).
//!
//! ClickHouse rejects a per-query `max_query_size` when the profile is
//! `readonly=1` or a `<constraints>` entry pins / caps it. This guard fails if
//! any shipped rendering (XML users.d / workload-users, Helm's users.json and
//! values overrides, the legacy k8s manifests) introduces either for those
//! profiles, or re-points those users at another profile. The raw-SQL
//! identities (`rawsql`, readonly=2) never get the lift and are not covered.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// `<tag>…</tag>` (first occurrence) inside `xml`.
fn element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

fn readonly_value(profile_xml: &str) -> Option<u8> {
    let re = regex::Regex::new(r"<readonly>\s*(\d)\s*</readonly>").unwrap();
    re.captures(profile_xml).map(|c| c[1].parse().unwrap())
}

/// The profiles the rescue-capable users run under, from users.d.
const RESCUE_PROFILES: [&str; 2] = ["default", "search"];

#[test]
fn rescue_identities_keep_their_profiles() {
    let users = read("clickhouse/users.d/nanosiem-users.xml");
    let nanosiem = element(&users, "nanosiem").expect("<nanosiem> user");
    assert!(nanosiem.contains("<profile>default</profile>"), "nanosiem must stay on profile default");
    let workload = read("clickhouse/workload-users/nanosiem-workload-users.xml");
    let search = element(&workload, "nanosiem_search").expect("<nanosiem_search> user");
    assert!(search.contains("<profile>search</profile>"), "nanosiem_search must stay on profile search");

    let json: serde_json::Value =
        serde_json::from_str(&read("deploy/helm/nano/files/clickhouse/users.json")).unwrap();
    assert_eq!(json["users"]["nanosiem"]["profile"], "default");
    if let Some(user) = json["users"].get("nanosiem_search") {
        assert_eq!(user["profile"], "search");
    }
}

#[test]
fn rescue_profiles_allow_setting_max_query_size_in_users_d() {
    for rel in ["clickhouse/users.d/query_limits.xml", "deploy/k8s/clickhouse/users.d/query_limits.xml"] {
        let xml = read(rel);
        assert!(!xml.contains("max_query_size"), "{rel} pins or caps max_query_size");
        let profiles = element(&xml, "profiles").unwrap_or_else(|| panic!("{rel}: no <profiles>"));
        for name in RESCUE_PROFILES {
            let Some(profile) = element(profiles, name) else {
                continue;
            };
            assert_ne!(readonly_value(profile), Some(1), "{rel}: profile {name} is readonly=1");
        }
    }
    // The `search` profile inherits `default`; both must exist in the main one.
    let xml = read("clickhouse/users.d/query_limits.xml");
    let profiles = element(&xml, "profiles").unwrap();
    for name in RESCUE_PROFILES {
        assert!(element(profiles, name).is_some(), "profile {name} missing");
    }
}

#[test]
fn rescue_profiles_allow_setting_max_query_size_in_helm() {
    let json: serde_json::Value =
        serde_json::from_str(&read("deploy/helm/nano/files/clickhouse/users.json")).unwrap();
    let text = serde_json::to_string(&json["profiles"]).unwrap();
    assert!(!text.contains("max_query_size"), "users.json profiles pin or cap max_query_size");
    for name in RESCUE_PROFILES {
        let profile = &json["profiles"][name];
        assert_ne!(profile["readonly"], "1", "users.json: profile {name} is readonly=1");
    }

    let helm = repo().join("deploy/helm/nano");
    let mut values: Vec<PathBuf> = std::fs::read_dir(&helm)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    values.extend(
        std::fs::read_dir(helm.join("ci"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "yaml")),
    );
    assert!(!values.is_empty());
    for path in values {
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let Some(profiles) = doc.get("clickhouse").and_then(|c| c.get("profiles")) else {
            continue;
        };
        let text = serde_yaml::to_string(profiles).unwrap();
        assert!(!text.contains("max_query_size"), "{}: profile override pins max_query_size", path.display());
        for name in RESCUE_PROFILES {
            if let Some(readonly) = profiles.get(name).and_then(|p| p.get("readonly")) {
                let value = match readonly {
                    serde_yaml::Value::String(s) => s.clone(),
                    other => serde_yaml::to_string(other).unwrap().trim().to_string(),
                };
                assert_ne!(value, "1", "{}: profile {name} readonly=1", path.display());
            }
        }
    }
}

#[test]
fn legacy_k8s_manifests_do_not_cap_max_query_size() {
    for rel in [
        "deploy/k8s/clickhouse/clickhouse.yaml",
        "deploy/k8s/aws-db/clickhouse.yaml.tpl",
        "deploy/k8s/rackspace-db/clickhouse.yaml.tpl",
    ] {
        assert!(!read(rel).contains("max_query_size"), "{rel} pins or caps max_query_size");
    }
}

/// install.sh renders per-install profile overrides (`users.d/zzzz-nano-
/// sizing.xml`) from `scripts/lib/resource-sizing.sh`; they must never pin
/// `max_query_size` or make a profile readonly=1.
#[test]
fn install_sizing_overrides_do_not_cap_max_query_size() {
    let script = read("scripts/lib/resource-sizing.sh");
    assert!(!script.contains("max_query_size"), "resource-sizing.sh renders max_query_size");
    assert!(
        !regex::Regex::new(r"<readonly>\s*1\s*</readonly>").unwrap().is_match(&script),
        "resource-sizing.sh renders readonly=1"
    );
}
