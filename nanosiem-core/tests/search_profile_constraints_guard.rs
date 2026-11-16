// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5470: every setting the app sends as the interactive search identity
//! is inside the `search` profile's constraints (clickhouse/users.d/
//! query_limits.xml). A value outside them fails the query with Code 452
//! (SETTING_CONSTRAINT_VIOLATION): the analytics tier's 50 GiB once exceeded
//! a 50 GB cap, so every background job and analytics search failed on a
//! server with 128 GiB of RAM or more. The values are read from the code
//! (admission tiers, background job config, inline SETTINGS literals), so
//! the two cannot drift apart.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nanosiem_core::search::admission::{ClickHouseQuerySettings, QueryPriority};
use nanosiem_core::search::background::{
    BackgroundJobConfig, SEARCH_PROFILE_MAX_EXECUTION_SECS, SEARCH_PROFILE_MAX_RESULT_ROWS,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// `setting -> (min, max)` of a profile's `<constraints>`.
fn constraints(profile: &str) -> BTreeMap<String, (Option<u64>, Option<u64>)> {
    let xml = std::fs::read_to_string(repo_root().join("clickhouse/users.d/query_limits.xml")).unwrap();
    let xml = regex::Regex::new(r"(?s)<!--.*?-->").unwrap().replace_all(&xml, "").into_owned();
    let body = xml
        .split(&format!("<{profile}>"))
        .nth(1)
        .and_then(|b| b.split(&format!("</{profile}>")).next())
        .unwrap_or_else(|| panic!("profile {profile}"));
    let block = body.split("<constraints>").nth(1).unwrap().split("</constraints>").next().unwrap();
    let setting = regex::Regex::new(r"<([a-z_]+)>\s*<(?:min|max|readonly)").unwrap();
    let num = |inner: &str, tag: &str| {
        regex::Regex::new(&format!(r"<{tag}>(\d+)</{tag}>"))
            .unwrap()
            .captures(inner)
            .map(|c| c[1].parse::<u64>().unwrap())
    };
    let mut out = BTreeMap::new();
    for c in setting.captures_iter(block) {
        let name = &c[1];
        let inner = block.split(&format!("<{name}>")).nth(1).unwrap().split(&format!("</{name}>")).next().unwrap();
        out.insert(name.to_string(), (num(inner, "min"), num(inner, "max")));
    }
    out
}

fn within(limits: &BTreeMap<String, (Option<u64>, Option<u64>)>, setting: &str, value: u64, source: &str) {
    if let Some((min, max)) = limits.get(setting) {
        assert!(min.is_none_or(|m| value >= m), "{source}: {setting} = {value} is below the search profile minimum {min:?}");
        assert!(max.is_none_or(|m| value <= m), "{source}: {setting} = {value} exceeds the search profile maximum {max:?}");
    }
}

fn check_settings(limits: &BTreeMap<String, (Option<u64>, Option<u64>)>, s: &ClickHouseQuerySettings, source: &str) {
    within(limits, "max_execution_time", u64::from(s.max_execution_time), source);
    within(limits, "max_threads", u64::from(s.max_threads), source);
    if let Some(bytes) = s.max_memory_usage_bytes {
        within(limits, "max_memory_usage", bytes, source);
    }
}

#[test]
fn every_admission_tier_is_inside_the_search_profile() {
    let limits = constraints("search");
    for tier in [QueryPriority::Detection, QueryPriority::NearRealtime, QueryPriority::Interactive, QueryPriority::Analytics] {
        let source = format!("{tier:?} tier");
        check_settings(&limits, &tier.to_ch_settings(), &source);
        // The deployment ceiling only ever lowers a tier.
        check_settings(&limits, &tier.to_ch_settings_with_memory_ceiling(Some(u64::MAX)), &source);
    }
}

#[test]
fn background_jobs_are_inside_the_search_profile() {
    let limits = constraints("search");
    let jobs = BackgroundJobConfig::default();
    check_settings(&limits, &jobs.ch_settings(), "background jobs");
    within(&limits, "max_result_rows", jobs.result_cap as u64 + 16, "background job result cap");
    // The app clamps env overrides to these; they must BE the profile caps.
    assert_eq!(limits["max_execution_time"].1, Some(u64::from(SEARCH_PROFILE_MAX_EXECUTION_SECS)));
    assert_eq!(limits["max_result_rows"].1, Some(SEARCH_PROFILE_MAX_RESULT_ROWS as u64));
}

/// Inline `SETTINGS name = <literal>` in the code the search identity runs.
#[test]
fn inline_settings_literals_are_inside_the_search_profile() {
    let limits = constraints("search");
    let literal = regex::Regex::new(
        r"\b(max_memory_usage|max_threads|max_execution_time|max_rows_to_read|max_bytes_to_read|max_result_rows)\s*=\s*(\d[\d_]*)\b",
    )
    .unwrap();
    let mut seen = 0;
    let mut stack: Vec<PathBuf> = ["search", "prevalence", "lookup", "query", "inputlookup"]
        .iter()
        .map(|d| repo_root().join("nanosiem-core/src").join(d))
        .filter(|p| p.is_dir())
        .collect();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().filter_map(Result::ok) {
            let path = entry.path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name == "tests.rs" {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            let src = src.split("#[cfg(test)]").next().unwrap_or("");
            for c in literal.captures_iter(src) {
                let value: u64 = c[2].replace('_', "").parse().unwrap();
                within(&limits, &c[1], value, &path.display().to_string());
                seen += 1;
            }
        }
    }
    assert!(seen >= 5, "found only {seen} inline settings; did the code move?");
}

/// ClickHouse resets `max_result_rows` / `max_result_bytes` to 0 for every
/// subquery and remote stage; on a cluster `<secret>` hop the shard runs as
/// the initial user and clamps that 0 to its profile's constraints. A `<min>`
/// on either makes every multi-row subquery, IN / GLOBAL IN and distributed
/// join fail with 396 on secret clusters (measured on 26.10). Every profile a
/// nano workload user carries must leave them without a minimum.
#[test]
fn result_limits_have_no_minimum_in_any_workload_profile() {
    for profile in ["search", "ingest_direct", "dict_source"] {
        let limits = constraints(profile);
        for setting in ["max_result_rows", "max_result_bytes"] {
            if let Some((min, _)) = limits.get(setting) {
                assert!(min.is_none(), "profile {profile}: {setting} has <min>{min:?}</min>; the 0 reset of subquery/remote stages then fails with 396");
            }
        }
    }
}
