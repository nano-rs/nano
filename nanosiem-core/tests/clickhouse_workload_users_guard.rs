// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5470: which ClickHouse user each nano workload connects as, on every
//! topology, so sharing cannot creep back.
//!
//! | Workload                                              | User                 |
//! |-------------------------------------------------------|----------------------|
//! | API, jobs, scheduled detections, connector-runner     | `nanosiem`           |
//! | nano-search (UI, dashboards, pivt, MCP, Desktop)       | `nanosiem_search`    |
//! | API searches on a user's behalf (dashboard panels,     | `nanosiem_search`    |
//! | field values, prevalence, observability, reports, hunt |                      |
//! | recon) and AI (notebook chat, meloD, shadow)           |                      |
//! | dictionary SOURCE queries                              | `nanosiem_dict`      |
//! | Vector inserts                                         | `nanosiem_vector`    |
//! | direct OCSF writers (Tenzir)                           | `nanosiem_ingest`    |
//! | migrations                                             | `nanosiem_admin`     |
//! | clickhouse-proxy healthcheck (role-split)              | none (`/ping`)       |
//!
//! Quotas per user are pinned by `clickhouse_service_quota_guard.rs`, system
//! grants by `clickhouse_system_grants_guard.rs`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The lines of one top-level Compose service block.
fn service(rel: &str, name: &str) -> String {
    let yaml = read(rel);
    let header = format!("  {name}:");
    let mut out = String::new();
    let mut inside = false;
    for line in yaml.lines() {
        if line == header {
            inside = true;
            continue;
        }
        if inside {
            let top = (line.starts_with("  ") && !line.starts_with("   ") && !line.trim().is_empty())
                || (!line.starts_with(' ') && !line.trim().is_empty());
            if top {
                break;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(!out.is_empty(), "{rel}: no `{name}` service");
    out
}

/// `KEY: value` of one env entry in a service block (first match).
fn env(block: &str, key: &str) -> Option<String> {
    block
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix(&format!("{key}: ")).map(|v| v.trim().to_string()))
}

const OPEN: &str = "docker-compose.opensource.yml";
const ROLE_SPLIT: &str = "deploy/compose/docker-compose.enterprise.yml";

#[test]
fn single_node_compose_workload_users() {
    let search = service(OPEN, "nano-search");
    assert_eq!(env(&search, "CLICKHOUSE_USER").as_deref(), Some("nanosiem_search"), "nano-search user");
    let password = env(&search, "CLICKHOUSE_PASSWORD").unwrap();
    // `:-` (NAN-5470 P0-2): no compose call may fail on a v2.0.27 .env.
    assert_eq!(password, "${CLICKHOUSE_SEARCH_PASSWORD:-}", "nano-search password: {password}");
    assert!(
        !search.lines().any(|l| l.trim().ends_with(": ${CLICKHOUSE_PASSWORD}")),
        "nano-search must not hold the nanosiem password"
    );

    for svc in ["nano-api", "nano-jobs", "clickhouse-migrate", "connector-runner"] {
        let block = service(OPEN, svc);
        assert_eq!(env(&block, "CLICKHOUSE_USER").as_deref(), Some("nanosiem"), "{svc} runs as the app user");
    }
    for svc in ["nano-api", "nano-jobs"] {
        assert!(
            env(&service(OPEN, svc), "CLICKHOUSE_SEARCH_PASSWORD").is_some(),
            "{svc} needs the search identity for its AI searches"
        );
    }
    assert!(
        env(&service(OPEN, "clickhouse-migrate"), "CLICKHOUSE_DICT_PASSWORD").is_some(),
        "the migrator points dictionaries at nanosiem_dict"
    );
    assert_eq!(env(&service(OPEN, "vector"), "CLICKHOUSE_USER").as_deref(), Some("nanosiem_vector"));

    let ch = service(OPEN, "clickhouse");
    // The rendered users file (password_sha256_hex) needs nothing from the
    // container environment, so the service passes none of it.
    for key in ["CLICKHOUSE_SEARCH_PASSWORD", "CLICKHOUSE_DICT_PASSWORD", "CLICKHOUSE_SEARCH_PROFILE", "CLICKHOUSE_DICT_PROFILE"] {
        assert!(env(&ch, key).is_none(), "clickhouse must not depend on {key}");
    }
    // P1-3: the users.d ClickHouse runs is the RENDERED directory (never in
    // a package), not a file bind-mounted over a shipped placeholder, which
    // tar's unlink + recreate detaches on every extract (users gone, 516).
    assert!(
        ch.contains("source: ${NANO_CLICKHOUSE_USERS_DIR:-./.nano-generated/clickhouse/users.d}\n        target: /etc/clickhouse-server/users.d"),
        "the clickhouse service mounts the rendered users.d"
    );
    assert!(!ch.contains("nanosiem-workload-users.xml"), "no file mount for the workload identities");
    assert!(!ch.contains("clickhouse/workload-users/"), "the template is never mounted as is");
    assert!(
        !Path::new(&format!("{}/../clickhouse/users.d/nanosiem-workload-users.xml", env!("CARGO_MANIFEST_DIR"))).exists(),
        "no shipped placeholder at a mount target"
    );
    // NAN-5494: nothing is bind-mounted INSIDE users.d or config.d. The
    // networks / sizing / tiering files are copied into the assembled
    // directories (scripts/lib/clickhouse_config_dirs.py); a file mounted
    // over a placeholder detaches when an extract replaces the placeholder.
    for line in ch.lines().filter(|l| !l.trim_start().starts_with('#')) {
        assert!(
            !line.contains(":/etc/clickhouse-server/users.d/") && !line.contains(":/etc/clickhouse-server/config.d/"),
            "file mounted inside a ClickHouse config directory: {line}"
        );
    }
    assert!(
        ch.contains("source: ${NANO_CLICKHOUSE_CONFIG_DIR:-./.nano-generated/clickhouse/config.d}\n        target: /etc/clickhouse-server/config.d"),
        "the clickhouse service mounts the assembled config.d"
    );
    let install = read("install.sh");
    assert!(install.contains("--workload-template clickhouse/workload-users/nanosiem-workload-users.xml"));
    assert!(install.contains("--users-dir-output .nano-generated/clickhouse/users.d"));
    assert!(install.contains("NANO_CLICKHOUSE_USERS_DIR=./.nano-generated/clickhouse/users.d"));
    let upgrade = read("scripts/nano-upgrade.py");
    assert!(upgrade.contains("CLICKHOUSE_USERS_DIR = \".nano-generated/clickhouse/users.d\""));
    assert!(upgrade.contains("\"--users-dir-output\""));
}

#[test]
fn role_split_compose_workload_users() {
    // nano-search and clickhouse inherit the single-node definitions.
    let search = service(ROLE_SPLIT, "nano-search");
    assert!(search.contains("file: ../../docker-compose.opensource.yml"));
    assert!(env(&search, "CLICKHOUSE_USER").is_none() && env(&search, "CLICKHOUSE_PASSWORD").is_none());
    let ch = service(ROLE_SPLIT, "clickhouse");
    assert!(ch.contains("service: clickhouse"));
    assert!(ch.contains("unset CLICKHOUSE_SEARCH_PASSWORD CLICKHOUSE_DICT_PASSWORD"), "healthcheck client env");
    // The proxy healthcheck needs no login, so the proxy holds no password.
    let proxy = service(ROLE_SPLIT, "clickhouse-proxy");
    assert!(!proxy.contains("CLICKHOUSE_PASSWORD"), "clickhouse-proxy must not hold the nanosiem password");
    assert!(proxy.contains("/ping"), "clickhouse-proxy healthcheck uses /ping");
    // The renderer ships the real workload file and renders their networks.
    let render = read("deploy/compose/render-inventory.py");
    assert!(render.contains("_write_xml(networks[\"workload\"], users_output / WORKLOAD_USERS_XML.name)"));
    assert!(render.contains("WORKLOAD_USERS_XML, workload_env, common, per_user={\"nanosiem_dict\": dict_networks},"));
    assert!(!render.contains("shutil.copy2(WORKLOAD_USERS_XML"), "the template is never shipped as is");
}

#[test]
fn helm_workload_users() {
    let helpers = read("deploy/helm/nano/templates/_helpers.tpl");
    let ch_env = helpers
        .split("{{- define \"nano.chEnv\" -}}")
        .nth(1)
        .unwrap()
        .split("{{/* Direct per-shard HTTP endpoints")
        .next()
        .unwrap();
    let (search_branch, app_branch) = ch_env.split_once("{{- else }}").expect("chEnv identity branches");
    assert!(search_branch.contains("value: nanosiem_search") && search_branch.contains("\"key\" \"clickhouse_search_password\""));
    assert!(!search_branch.contains("\"key\" \"clickhouse_password\""), "search must not get the nanosiem password");
    assert!(app_branch.contains("value: nanosiem\n") && app_branch.contains("\"key\" \"clickhouse_password\""));
    assert!(ch_env.contains("\"name\" \"CLICKHOUSE_DICT_PASSWORD\" \"key\" \"clickhouse_dict_password\""));
    let search = read("deploy/helm/nano/templates/app/search.yaml");
    assert!(search.contains("include \"nano.chEnv\" (dict \"root\" . \"chIdentity\" \"search\")"));
    assert!(search.contains("include \"nano.waitForSearchUser\""), "search pods wait for the identity on every replica");
    for app in ["api", "jobs"] {
        let t = read(&format!("deploy/helm/nano/templates/app/{app}.yaml"));
        assert!(t.contains("include \"nano.waitForSearchUser\""), "{app} pods wait for the search identity");
    }
    for app in ["api", "jobs", "connector-runner"] {
        let t = read(&format!("deploy/helm/nano/templates/app/{app}.yaml"));
        assert!(!t.contains("chIdentity"), "{app} runs as the app user");
    }
    let settings = read("deploy/helm/nano/templates/clickhouse/_settings.tpl");
    assert!(settings.contains("$_ := unset $user \"password\""));
    assert!(settings.contains("\"password_sha256_hex\" (include \"nano.workloadPasswordHash\""));
    // existingSecret: hashes from values, never a random one (behavioral:
    // deploy/helm/nano/scripts/test_workload_password_hashes.py).
    assert!(helpers.contains("secrets.workloadPasswordHashes.%s must be the SHA-256"));
    let secrets = read("deploy/helm/nano/templates/secrets.yaml");
    assert!(secrets.contains("\"clickhouse_search_password\" (include \"nano.secretValue\""));
    assert!(secrets.contains("\"clickhouse_dict_password\" (include \"nano.secretValue\""));
    let json: serde_json::Value = serde_json::from_str(&read("deploy/helm/nano/files/clickhouse/users.json")).unwrap();
    assert_eq!(json["users"]["nanosiem_search"]["profile"], "search");
    assert_eq!(json["users"]["nanosiem_dict"]["profile"], "dict_source");
    assert_eq!(json["users"]["nanosiem_search"]["password"]["@from_env"], "CLICKHOUSE_SEARCH_PASSWORD");
    assert_eq!(json["users"]["nanosiem_dict"]["password"]["@from_env"], "CLICKHOUSE_DICT_PASSWORD");
}

/// The workload template: each identity names its password's .env key (the
/// renderers turn it into password_sha256_hex) and a profile that exists.
#[test]
fn workload_template_names_its_passwords_and_profiles() {
    let xml = read("clickhouse/workload-users/nanosiem-workload-users.xml");
    let limits = read("clickhouse/users.d/query_limits.xml");
    for (user, password_env, profile) in [
        ("nanosiem_search", "CLICKHOUSE_SEARCH_PASSWORD", "search"),
        ("nanosiem_dict", "CLICKHOUSE_DICT_PASSWORD", "dict_source"),
    ] {
        let block = xml.split(&format!("<{user}>")).nth(1).unwrap().split(&format!("</{user}>")).next().unwrap();
        assert!(block.contains(&format!("<profile>{profile}</profile>")), "{user} profile");
        assert!(block.contains(&format!("<password from_env=\"{password_env}\"/>")), "{user} password key");
        assert!(limits.contains(&format!("<{profile}>")), "profile {profile} missing from query_limits.xml");
    }
}

/// Every ClickHouse-sourced dictionary reads as the dictionary identity, and
/// that identity can read exactly the tables the sources read.
#[test]
fn dictionary_sources_use_the_dictionary_identity() {
    let source = regex::Regex::new(r"(?s)SOURCE\(CLICKHOUSE\((.*?)\n\)\)").unwrap();
    for rel in ["clickhouse/init.sql", "clickhouse/ocsf/init.sql", "clickhouse/202_dictionary_source_user.sql"] {
        let sql = read(rel);
        let mut n = 0;
        for c in source.captures_iter(&sql) {
            n += 1;
            assert!(
                c[1].contains("USER '{clickhouse_dict_user}'") && c[1].contains("PASSWORD '{clickhouse_dict_password}'"),
                "{rel}: a dictionary source does not log in as the dictionary identity:\n{}",
                &c[1]
            );
        }
        assert!(n >= 3, "{rel}: found only {n} ClickHouse dictionary sources");
    }
    // No numbered migration after 202 may go back to the app user.
    for entry in std::fs::read_dir(repo_root().join("clickhouse")).unwrap().filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(num) = name.split('_').next().and_then(|n| n.parse::<u32>().ok()) else { continue };
        if num <= 202 || !name.ends_with(".sql") {
            continue;
        }
        let sql = std::fs::read_to_string(entry.path()).unwrap();
        for c in source.captures_iter(&sql) {
            assert!(c[1].contains("USER '{clickhouse_dict_user}'"), "{name}: dictionary source not on nanosiem_dict");
        }
    }
    let from = regex::Regex::new(r"FROM nanosiem\.([a-z_]+)").unwrap();
    let read_tables: BTreeSet<String> = source
        .captures_iter(&read("clickhouse/202_dictionary_source_user.sql"))
        .flat_map(|c| from.captures_iter(&c[1]).map(|t| t[1].to_string()).collect::<Vec<_>>())
        .collect();
    let xml = read("clickhouse/workload-users/nanosiem-workload-users.xml");
    let block = xml.split("<nanosiem_dict>").nth(1).unwrap().split("</nanosiem_dict>").next().unwrap();
    let grant = regex::Regex::new(r"<query>GRANT SELECT ON nanosiem\.([a-z_]+)</query>").unwrap();
    let granted: BTreeSet<String> = grant.captures_iter(block).map(|c| c[1].to_string()).collect();
    assert_eq!(granted, read_tables, "nanosiem_dict must read exactly the dictionary source tables");
    assert_eq!(block.matches("<query>").count(), granted.len(), "nanosiem_dict holds only those SELECT grants");
}

/// The API's searches on a user's behalf (and AI-written ones) run as the
/// search identity; its own internal work (scheduled detections, scheduled
/// reports, caches) as the app user. Every handler that runs ClickHouse
/// queries through the app identity is classified here, so a new one fails
/// until someone decides which identity it uses.
#[test]
fn api_user_searches_use_the_search_identity() {
    let melod = read("nanosiem-api/src/state/melod.rs");
    let dal = melod.split("pub fn create_data_access_layer").nth(1).unwrap().split("\n    }\n").next().unwrap();
    assert!(dal.contains("self.dual_pool.clickhouse_search().clone()"), "meloD data access");
    let constructors = read("nanosiem-api/src/state/constructors.rs");
    assert!(constructors.contains("search_service.with_clickhouse_identity(dual_pool.clickhouse_search().clone())"));
    let shadow = constructors.split("ShadowInvestigationService::new(").nth(1).unwrap();
    assert!(shadow.trim_start().starts_with("pg_pool.clone(),\n                    user_search_service.clone(),"));
    let state = read("nanosiem-api/src/state/mod.rs");
    let notebooks = state.split("impl nanosiem_enterprise::handlers::notebooks::NotebooksAppState for AppState").nth(1).unwrap();
    let search_fn = notebooks.split("fn search_service(&self)").nth(1).unwrap().split('}').next().unwrap();
    assert!(search_fn.contains("&self.user_search_service"), "notebook chat searches");

    // User-facing search paths: the search identity.
    let user_paths = [
        "nanosiem-api/src/handlers/dashboards/query.rs",
        "nanosiem-api/src/handlers/fields.rs",
        "nanosiem-api/src/handlers/observability_service_signals.rs",
        "nanosiem-api/src/handlers/observability_slos.rs",
        "nanosiem-api/src/handlers/observability_synthetics.rs",
        "nanosiem-api/src/handlers/reports.rs",
        "nanosiem-api/src/handlers/hunts/recon.rs",
        "nanosiem-api/src/handlers/prevalence/discovery.rs",
        "nanosiem-api/src/handlers/prevalence/export.rs",
        "nanosiem-api/src/handlers/prevalence/lookups.rs",
        // Rule tester (POST /api/rules/test, /api/rules/{id}/test): the
        // caller's query, through DetectionService::with_search_client.
        "nanosiem-api/src/handlers/detections/testing.rs",
        // IP -> host/user resolution (identity_observations) for the UI.
        "nanosiem-api/src/handlers/identity.rs",
    ];
    // The app identity on purpose: admin, settings and enrichment management
    // (reads and writes of nano's own tables, not searches of event data).
    let app_paths = [
        "nanosiem-api/src/handlers/enrichment/platform_feeds.rs",
        "nanosiem-api/src/handlers/enrichment/sources.rs",
        "nanosiem-api/src/handlers/marketplace.rs",
        "nanosiem-api/src/handlers/settings/retention.rs",
        "nanosiem-api/src/handlers/settings/tiering.rs",
        "nanosiem-api/src/handlers/siem_health.rs",
        "nanosiem-api/src/handlers/system.rs",
        "nanosiem-enterprise/src/handlers/custom_enrichment/history.rs",
        "nanosiem-enterprise/src/handlers/threat_intel.rs",
        // Fixed ingest-health aggregates for log source management (source
        // activity, health series): nano's own bounded reads, not a query
        // a user writes.
        "nanosiem-api/src/handlers/log_source_connect.rs",
        "nanosiem-api/src/handlers/log_source_health_series.rs",
    ];
    // The field, not `NotebooksAppState::search_service()` (which returns the
    // user search service, asserted above).
    let search_service = regex::Regex::new(r"\.search_service[^_A-Za-z0-9(]").unwrap();
    // Across line breaks (`dual_pool\n    .clickhouse()`), and service-routed
    // event searches: the app's DetectionService running a stepped analysis.
    let app_client = regex::Regex::new(r"dual_pool(\(\))?\s*\.\s*clickhouse\(\)").unwrap();
    let app_detection_search =
        regex::Regex::new(r"\.detection_service\s*\.\s*(analyze_|run_|evaluate_|backtest)").unwrap();
    // The aliased form: `let pool = state.dual_pool(); pool.clickhouse()`.
    let pool_alias = regex::Regex::new(r"let\s+(\w+)\s*=\s*[^;]*dual_pool\(\)\s*;").unwrap();
    let aliased_app_client = |src: &str| {
        pool_alias.captures_iter(src).any(|c| {
            regex::Regex::new(&format!(r"\b{}\s*\.\s*clickhouse\(\)", regex::escape(&c[1]))).unwrap().is_match(src)
        })
    };
    // Only a trailing test module is skipped, not everything after the first
    // `#[cfg(test)]` (an inline cfg(test) helper hid the rest of fields.rs).
    let test_module = regex::Regex::new(r"(?m)^#\[cfg\(test\)\]\s*\n\s*(#\[path[^\n]*\n\s*)?mod ").unwrap();
    let mut unclassified = Vec::new();
    for dir in ["nanosiem-api/src/handlers", "nanosiem-enterprise/src/handlers"] {
        if !repo_root().join(dir).is_dir() {
            continue;
        }
        let mut stack = vec![repo_root().join(dir)];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).unwrap().filter_map(Result::ok) {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name == "tests.rs" {
                    continue;
                }
                let rel = path.strip_prefix(repo_root()).unwrap().display().to_string();
                let src = std::fs::read_to_string(&path).unwrap();
                let src = match test_module.find(&src) {
                    Some(m) => &src[..m.start()],
                    None => src.as_str(),
                };
                let app_use = search_service.is_match(src)
                    || app_client.is_match(src)
                    || aliased_app_client(src)
                    || app_detection_search.is_match(src);
                if user_paths.contains(&rel.as_str()) {
                    assert!(!app_use, "{rel}: a user-facing search path runs as the app user");
                } else if app_use && !app_paths.contains(&rel.as_str()) {
                    unclassified.push(rel);
                }
            }
        }
    }
    assert!(
        unclassified.is_empty(),
        "handlers run ClickHouse queries as the app user without being classified: {unclassified:?}. \
         Searches on a user's behalf use `user_search_service` / `dual_pool.clickhouse_search()`; \
         add genuine app work to app_paths."
    );
}

/// NAN-5484: nano-search runs as the search identity whatever its
/// CLICKHOUSE_USER says. A launcher that keeps CLICKHOUSE_USER=nanosiem and
/// passes CLICKHOUSE_SEARCH_PASSWORD (the native local stack) used to leave
/// every search on `nanosiem`: the service built everything from the runtime
/// client and never asked the pool for its search client. The behavioral
/// check (query_log user per search path) is e2e/tests/test_search_identity.py.
#[test]
fn nano_search_serves_from_the_search_identity_pool() {
    let main = read("nanosiem-search/src/main.rs");
    let swap = main
        .find("let dual_pool = nanosiem_search::search_identity_pool(dual_pool);")
        .expect("nano-search main must switch its pool to the search identity");
    let state = main.find("SearchState::new(").expect("SearchState::new");
    assert!(swap < state, "the switch must happen before any service is built from the pool");
    let lib = read("nanosiem-search/src/lib.rs");
    let body = lib.split("pub fn search_identity_pool(").nth(1).unwrap().split("\n}\n").next().unwrap();
    assert!(body.contains("dual_pool.with_search_identity()"));
}
