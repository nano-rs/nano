// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5457: nano's ClickHouse service users carry no hourly quota cap.
//!
//! A service user's query count grows with ingest volume, not with people:
//! every Vector batch, every Distributed block forwarded to another shard and
//! every cache-dictionary miss is one query. With the old flat `default` quota
//! (100,000 queries per hour, per user, per node) a 2-shard cluster at ~24k
//! events/s ran out before the hour did and inserts failed with
//! QUOTA_EXCEEDED. The users people drive (raw SQL) keep their cap.
//!
//! ClickHouse merges every users.d file in name order, so the quota a user
//! actually gets is the LAST `<quota>` any file gives it, and a
//! `replace="replace"` element drops what earlier files said. This guard
//! resolves that effective quota the same way, for Compose (clickhouse/users.d,
//! mounted as is by single-node Compose and copied as is by
//! render-inventory.py for role-split) and for Helm
//! (files/clickhouse/users.json, generated from the same XML by
//! scripts/sync-files.sh). The `mutation_*` tests feed it broken configs to
//! prove it notices.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Users whose traffic scales with ingest or with nano's own schedulers.
/// NAN-5470: nanosiem_dict runs every dictionary SOURCE query, including the
/// prevalence CACHE dictionaries' insert-time misses.
const SERVICE_USERS: &[&str] = &["nanosiem_admin", "nanosiem", "nanosiem_vector", "nanosiem_ingest", "nanosiem_dict"];
/// Users people drive. Their hourly cap must stay.
const PEOPLE_USERS: &[&str] = &["nanosiem_rawsql", "nanosiem_rawsql_noaudit"];
/// NAN-5470: the interactive search identity: its own capped quota, never a
/// service quota and never the raw-SQL users' one.
const SEARCH_USER: &str = "nanosiem_search";
const SEARCH_QUOTA: &str = "nano_search";
/// NAN-5470: users.d placeholder that docker-compose.opensource.yml and
/// render-inventory.py replace with the workload identities.
const WORKLOAD_FILE: &str = "nanosiem-workload-users.xml";
/// Interval keys that are not limits.
const NOT_LIMITS: &[&str] = &["duration", "randomize"];

type UserQuota = BTreeMap<String, Option<String>>;
type Quotas = BTreeMap<String, Vec<BTreeMap<String, u64>>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn strip_comments(xml: &str) -> String {
    regex::Regex::new(r"(?s)<!--.*?-->").unwrap().replace_all(xml, "").into_owned()
}

/// One child element: name, raw attribute text, inner body (empty when
/// self-closing).
struct Element {
    name: String,
    attrs: String,
    body: String,
}

impl Element {
    fn replaces(&self) -> bool {
        regex::Regex::new(r#"\breplace\s*=\s*["'](replace|1|true)["']"#).unwrap().is_match(&self.attrs)
    }
}

/// Top-level child elements of `inner`, with or without attributes.
fn children(inner: &str) -> Vec<Element> {
    let open = regex::Regex::new(r"<([a-zA-Z_][a-zA-Z0-9_]*)\b([^>]*?)(/?)>").unwrap();
    let mut out = Vec::new();
    let mut rest = inner;
    while let Some(m) = open.captures(rest) {
        let name = m[1].to_string();
        let attrs = m[2].to_string();
        let start = m.get(0).unwrap().end();
        if &m[3] == "/" {
            out.push(Element { name, attrs, body: String::new() });
            rest = &rest[start..];
            continue;
        }
        let close = format!("</{name}>");
        let Some(end) = rest[start..].find(&close) else { break };
        out.push(Element { name, attrs, body: rest[start..start + end].to_string() });
        rest = &rest[start + end + close.len()..];
    }
    out
}

/// Inner text of every top-level `<tag …>` child of `xml`, recursing one
/// level into the root.
fn sections(xml: &str, tag: &str) -> Vec<String> {
    let mut out = Vec::new();
    for root in children(xml) {
        for child in children(&root.body) {
            if child.name == tag {
                out.push(child.body);
            }
        }
    }
    out
}

/// users.d file names ClickHouse would merge that this guard cannot read.
fn unreadable_users_d_files(names: &[String]) -> Vec<String> {
    names.iter().filter(|n| !n.ends_with(".xml")).cloned().collect()
}

/// Effective `user -> quota` and `quota -> [interval limits]` after merging
/// `files` (name, content) in name order, like ClickHouse.
fn merge_users_d(mut files: Vec<(String, String)>) -> (UserQuota, Quotas) {
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut user_quota: UserQuota = BTreeMap::new();
    let mut quotas: Quotas = BTreeMap::new();
    for (_, raw) in files {
        let xml = strip_comments(&raw);
        for users in sections(&xml, "users") {
            for user in children(&users) {
                let quota = children(&user.body)
                    .into_iter()
                    .filter(|c| c.name == "quota")
                    .last()
                    .map(|c| c.body.trim().to_string());
                if user.replaces() {
                    user_quota.insert(user.name, quota);
                } else if let Some(q) = quota {
                    user_quota.insert(user.name, Some(q));
                } else {
                    user_quota.entry(user.name).or_insert(None);
                }
            }
        }
        for defs in sections(&xml, "quotas") {
            for def in children(&defs) {
                let intervals: Vec<BTreeMap<String, u64>> = children(&def.body)
                    .into_iter()
                    .filter(|c| c.name == "interval")
                    .map(|iv| {
                        children(&iv.body)
                            .into_iter()
                            .map(|l| {
                                let v = l.body.trim().parse::<u64>().unwrap_or_else(|_| {
                                    panic!("quota {}: non-numeric {} = {:?}", def.name, l.name, l.body)
                                });
                                (l.name, v)
                            })
                            .collect()
                    })
                    .collect();
                // Without replace, a later file's interval merges into the
                // earlier one; with it, the definition starts over.
                let entry = quotas.entry(def.name.clone()).or_default();
                if def.replaces() || entry.is_empty() {
                    *entry = intervals;
                } else {
                    for (i, iv) in intervals.into_iter().enumerate() {
                        match entry.get_mut(i) {
                            Some(prev) => prev.extend(iv),
                            None => entry.push(iv),
                        }
                    }
                }
            }
        }
    }
    (user_quota, quotas)
}

fn repo_users_d() -> Vec<(String, String)> {
    let dir = repo_root().join("clickhouse/users.d");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("clickhouse/users.d")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let unreadable = unreadable_users_d_files(&names);
    assert!(
        unreadable.is_empty(),
        "clickhouse/users.d has files this guard does not parse ({unreadable:?}); ClickHouse merges \
         .yaml/.yml there too. Keep users.d XML-only or teach this guard the format."
    );
    // NAN-5470: what ClickHouse loads on a shipped Compose topology: the
    // rendered users.d is the shipped files plus the workload identities.
    let workload = std::fs::read_to_string(repo_root().join("clickhouse/workload-users").join(WORKLOAD_FILE))
        .expect("clickhouse/workload-users");
    let mut files: Vec<(String, String)> = names
        .into_iter()
        .map(|n| {
            let c = std::fs::read_to_string(dir.join(&n)).unwrap();
            (n, c)
        })
        .collect();
    files.push((WORKLOAD_FILE.to_string(), workload));
    files
}

fn json_u64(v: &serde_json::Value) -> u64 {
    match v {
        serde_json::Value::String(s) => s.parse().expect("numeric quota limit"),
        serde_json::Value::Number(n) => n.as_u64().expect("numeric quota limit"),
        other => panic!("unexpected quota limit {other}"),
    }
}

fn helm_effective() -> (UserQuota, Quotas) {
    let raw = std::fs::read_to_string(repo_root().join("deploy/helm/nano/files/clickhouse/users.json"))
        .expect("helm users.json");
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let mut user_quota = BTreeMap::new();
    for (user, body) in json["users"].as_object().unwrap() {
        user_quota.insert(user.clone(), body.get("quota").and_then(|q| q.as_str()).map(str::to_string));
    }
    let mut quotas = BTreeMap::new();
    for (name, body) in json["quotas"].as_object().unwrap() {
        let intervals = match &body["interval"] {
            serde_json::Value::Array(a) => a.clone(),
            v => vec![v.clone()],
        };
        let parsed = intervals
            .iter()
            .map(|iv| iv.as_object().unwrap().iter().map(|(k, v)| (k.clone(), json_u64(v))).collect())
            .collect();
        quotas.insert(name.clone(), parsed);
    }
    (user_quota, quotas)
}

/// Every way the effective config breaks the NAN-5457 split.
fn violations((user_quota, quotas): &(UserQuota, Quotas)) -> Vec<String> {
    let mut out = Vec::new();
    for user in SERVICE_USERS {
        let Some(Some(q)) = user_quota.get(*user) else {
            out.push(format!("service user {user} has no explicit quota"));
            continue;
        };
        let Some(intervals) = quotas.get(q) else {
            out.push(format!("service user {user}'s quota {q} is not defined"));
            continue;
        };
        for iv in intervals {
            for (limit, v) in iv {
                if !NOT_LIMITS.contains(&limit.as_str()) && *v != 0 {
                    out.push(format!(
                        "service user {user} gets quota {q} with {limit} = {v} per {}s",
                        iv.get("duration").copied().unwrap_or(0)
                    ));
                }
            }
        }
    }
    for user in PEOPLE_USERS {
        let Some(Some(q)) = user_quota.get(*user) else {
            out.push(format!("raw-SQL user {user} has no quota"));
            continue;
        };
        let capped = quotas
            .get(q)
            .is_some_and(|ivs| ivs.iter().any(|iv| iv.get("queries").copied().unwrap_or(0) > 0));
        if !capped {
            out.push(format!("raw-SQL user {user} lost its hourly query cap (quota {q})"));
        }
        for s in SERVICE_USERS {
            if user_quota.get(*s) == Some(&Some(q.clone())) {
                out.push(format!("raw-SQL user {user} shares quota {q} with service user {s}"));
            }
        }
    }
    // NAN-5470: the search identity has its own capped quota.
    match user_quota.get(SEARCH_USER) {
        Some(Some(q)) if q == SEARCH_QUOTA => {
            let capped = quotas.get(q).is_some_and(|ivs| {
                ivs.iter().any(|iv| {
                    iv.get("queries").copied().unwrap_or(0) > 0 && iv.get("execution_time").copied().unwrap_or(0) > 0
                })
            });
            if !capped {
                out.push(format!("{SEARCH_USER}'s quota {q} lost its hourly query / execution-time cap"));
            }
        }
        other => out.push(format!("{SEARCH_USER} must use quota {SEARCH_QUOTA}, has {other:?}")),
    }
    for other in SERVICE_USERS.iter().chain(PEOPLE_USERS) {
        if user_quota.get(*other) == Some(&Some(SEARCH_QUOTA.to_string())) {
            out.push(format!("{other} shares the search quota {SEARCH_QUOTA}"));
        }
    }
    out
}

fn assert_clean(label: &str, v: Vec<String>) {
    assert!(
        v.is_empty(),
        "{label}: {v:#?}\nService users must not be rationed by the hour (NAN-5457): ingest inserts, \
         Distributed hops and dictionary loads all count, and running out rejects inserts. The raw-SQL \
         users keep their cap."
    );
}

#[test]
fn compose_service_users_have_no_hourly_quota_cap() {
    assert_clean("clickhouse/users.d", violations(&merge_users_d(repo_users_d())));
}

#[test]
fn helm_service_users_have_no_hourly_quota_cap() {
    assert_clean("helm users.json", violations(&helm_effective()));
}

/// The repo's users.d plus one extra file that sorts last.
fn repo_plus(extra: &str) -> Vec<String> {
    let mut files = repo_users_d();
    files.push(("zzzzzz-mutation.xml".into(), extra.into()));
    violations(&merge_users_d(files))
}

#[test]
fn mutation_later_user_element_with_attributes_is_seen() {
    for open in [r#"<nanosiem replace="replace">"#, "<nanosiem >", r#"<nanosiem_vector replace="1">"#] {
        let name = open.trim_start_matches('<').split([' ', '>']).next().unwrap();
        let extra = format!("<clickhouse><users>{open}<quota>default</quota></{name}></users></clickhouse>");
        let v = repo_plus(&extra);
        assert!(
            v.iter().any(|m| m.contains(&format!("service user {name} gets quota default"))),
            "{open}: a later file putting the cap back went unnoticed: {v:?}"
        );
    }
}

#[test]
fn mutation_replace_without_quota_drops_the_service_quota() {
    let v = repo_plus(r#"<clickhouse><users><nanosiem replace="replace"><profile>default</profile></nanosiem></users></clickhouse>"#);
    assert!(v.iter().any(|m| m.contains("service user nanosiem has no explicit quota")), "{v:?}");
}

#[test]
fn mutation_non_xml_users_d_file_is_refused() {
    for name in ["zz-extra.yaml", "zz-extra.yml"] {
        let names = vec!["nanosiem-users.xml".to_string(), name.to_string()];
        assert_eq!(unreadable_users_d_files(&names), vec![name.to_string()]);
    }
    assert!(unreadable_users_d_files(&["a.xml".into(), "b.xml".into()]).is_empty());
}

#[test]
fn mutation_any_nonzero_service_limit_is_seen() {
    for limit in [
        "read_rows",
        "result_rows",
        "read_bytes",
        "result_bytes",
        "written_bytes",
        "failed_sequential_authentications",
        "queries",
    ] {
        let extra = format!(
            "<clickhouse><quotas><nano_service><interval><{limit}>5</{limit}></interval></nano_service></quotas></clickhouse>"
        );
        let v = repo_plus(&extra);
        assert!(
            v.iter().any(|m| m.contains(&format!("{limit} = 5"))),
            "nano_service {limit} = 5 went unnoticed: {v:?}"
        );
    }
}

/// The lines of one top-level Compose service block (`  <name>:` up to the
/// next two-space-indented key).
fn compose_service_block(rel: &str, service: &str) -> String {
    let yaml = std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    let header = format!("  {service}:");
    let mut out = String::new();
    let mut inside = false;
    for line in yaml.lines() {
        if line == header {
            inside = true;
            continue;
        }
        if inside {
            let top_level_key = line.starts_with("  ") && !line.starts_with("   ") && !line.trim().is_empty();
            if top_level_key || (!line.starts_with(' ') && !line.trim().is_empty()) {
                break;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(!out.is_empty(), "{rel}: no `{service}` service");
    out
}

/// Vector writes as its own user on every topology, so its inserts never share
/// a quota bucket with the app (NAN-5457). Generated sinks all take
/// `auth.user = "${CLICKHOUSE_USER:-nanosiem}"`; an unset CLICKHOUSE_USER would
/// silently fall back to the app user.
#[test]
fn vector_inserts_as_its_own_user_on_every_topology() {
    for rel in ["docker-compose.yml", "docker-compose.opensource.yml"] {
        let block = compose_service_block(rel, "vector");
        assert!(
            block.contains("CLICKHOUSE_USER: nanosiem_vector"),
            "{rel}: the vector service must set CLICKHOUSE_USER: nanosiem_vector"
        );
    }
    // Role-split extends the open-source vector service and must not override it.
    let enterprise = compose_service_block("deploy/compose/docker-compose.enterprise.yml", "vector");
    assert!(enterprise.contains("file: ../../docker-compose.opensource.yml"), "role-split vector no longer extends the open-source service");
    assert!(
        !enterprise.contains("CLICKHOUSE_USER:"),
        "role-split vector overrides CLICKHOUSE_USER; it must inherit nanosiem_vector"
    );
    let helm = std::fs::read_to_string(repo_root().join("deploy/helm/nano/templates/vector/statefulset.yaml"))
        .expect("read the helm vector StatefulSet (NAN-5979 replaced the Deployment)");
    assert!(
        helm.contains("- name: CLICKHOUSE_USER\n              value: nanosiem_vector"),
        "helm vector StatefulSet must set CLICKHOUSE_USER=nanosiem_vector"
    );
}

/// NAN-5470: the search quota never trips under normal use: running out
/// locks every search out for the hour (the NAN-5457 failure mode). Sized
/// from the app's own config, all at once and flat out for the hour, with 2x
/// headroom:
/// * every admitted ad-hoc search plus its parallel `count(*)` companion;
/// * background search jobs (per-process concurrency x [`SEARCH_PROCESSES`]);
/// * user and AI searches nano-api runs in process (another admission
///   ceiling's worth).
/// Each running query costs up to 1 s of execution time per second and ~2
/// progress-poll queries per second.
#[test]
fn search_quota_clears_everything_the_app_can_run_at_once() {
    /// Search-serving processes assumed on one ClickHouse server (Helm runs
    /// several search replicas against the same nodes).
    const SEARCH_PROCESSES: u64 = 4;
    let admission = u64::from(nanosiem_core::search::admission::AdmissionConfig::default().global_adhoc_limit);
    let jobs = nanosiem_core::search::background::BackgroundJobConfig::default().concurrency as u64;
    let concurrent = admission * 2 + jobs * SEARCH_PROCESSES + admission;
    for (label, (_, quotas)) in [("compose", merge_users_d(repo_users_d())), ("helm", helm_effective())] {
        let iv = &quotas[SEARCH_QUOTA][0];
        assert_eq!(iv["duration"], 3600, "{label}: {SEARCH_QUOTA} is an hourly quota");
        let need_time = concurrent * 3600 * 2;
        let need_queries = concurrent * 2 * 3600 * 2;
        assert!(iv["execution_time"] >= need_time, "{label}: execution_time {} < {need_time}", iv["execution_time"]);
        assert!(iv["queries"] >= need_queries, "{label}: queries {} < {need_queries}", iv["queries"]);
        assert!(iv["errors"] >= need_queries / 5, "{label}: errors {} too low", iv["errors"]);
    }
}

/// NAN-5470 (P1-3): no shipped users.d file is the workload identities'
/// mount target; they live only in the rendered users.d.
#[test]
fn workload_users_are_not_shipped_in_users_d() {
    assert!(
        !repo_root().join("clickhouse/users.d").join(WORKLOAD_FILE).exists(),
        "clickhouse/users.d/{WORKLOAD_FILE} must not ship (tar re-extract detaches a mount over it)"
    );
}

#[test]
fn mutation_search_user_on_a_service_quota_is_seen() {
    let v = repo_plus(r#"<clickhouse><users><nanosiem_search><quota>nano_service</quota></nanosiem_search></users></clickhouse>"#);
    assert!(v.iter().any(|m| m.contains("nanosiem_search must use quota nano_search")), "{v:?}");
    let v = repo_plus(r#"<clickhouse><users><nanosiem><quota>nano_search</quota></nanosiem></users></clickhouse>"#);
    assert!(v.iter().any(|m| m.contains("nanosiem shares the search quota")), "{v:?}");
}
