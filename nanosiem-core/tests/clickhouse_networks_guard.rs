// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5367: no ClickHouse user nano defines accepts connections from any
//! address.
//!
//! Every users.d user carries an explicit, non-wildcard `<networks>` list;
//! no other users.d file re-opens one (users.d files MERGE, so an any-address
//! entry anywhere wins); every SQL `CREATE USER` nano issues has a `HOST`
//! clause; and the deployment renderers (install.sh / render-inventory.py via
//! scripts/lib/clickhouse_networks.py, the Helm chart) refuse any-address
//! entries.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(rel: &str) -> Option<String> {
    std::fs::read_to_string(repo_root().join(rel)).ok()
}

/// Entries that admit every address.
fn is_any_address(entry: &str) -> bool {
    let e = entry.trim();
    matches!(e, "::/0" | "0.0.0.0/0" | "::" | "0.0.0.0" | "*" | "%")
        || e.ends_with("/0")
        || e == ".*"
        || e == "^.*$"
}

/// `(user, networks inner XML)` for every user defined in a users.d file.
fn users_networks(xml: &str) -> Vec<(String, Option<String>)> {
    let Some(users) = xml
        .split("<users>")
        .nth(1)
        .and_then(|s| s.split("</users>").next())
    else {
        return Vec::new();
    };
    let without_comments = regex::Regex::new(r"(?s)<!--.*?-->")
        .unwrap()
        .replace_all(users, "");
    let open = regex::Regex::new(r"(?m)^\s*<([a-zA-Z_][a-zA-Z0-9_]*)>\s*$").unwrap();
    let mut out = Vec::new();
    let mut rest: &str = &without_comments;
    while let Some(m) = open.captures(rest) {
        let name = m.get(1).unwrap().as_str().to_string();
        let start = m.get(0).unwrap().end();
        let close = format!("</{name}>");
        let Some(end) = rest[start..].find(&close) else {
            break;
        };
        let body = &rest[start..start + end];
        let networks = body
            .split("<networks")
            .nth(1)
            .and_then(|s| s.split("</networks>").next())
            .map(|s| s.splitn(2, '>').nth(1).unwrap_or("").to_string());
        out.push((name, networks));
        rest = &rest[start + end + close.len()..];
    }
    out
}

fn network_entries(inner: &str) -> Vec<String> {
    regex::Regex::new(r"<(ip|host|host_regexp|host_like)>\s*([^<]*?)\s*</(ip|host|host_regexp|host_like)>")
        .unwrap()
        .captures_iter(inner)
        .map(|c| c[2].to_string())
        .collect()
}

#[test]
fn every_users_d_user_has_an_explicit_non_wildcard_network_list() {
    let xml = read("clickhouse/users.d/nanosiem-users.xml").expect("nanosiem-users.xml");
    let users = users_networks(&xml);
    let names: Vec<&str> = users.iter().map(|(n, _)| n.as_str()).collect();
    for expected in [
        "nanosiem_admin",
        "nanosiem",
        "nanosiem_vector",
        "nanosiem_ingest",
        "nanosiem_rawsql",
        "nanosiem_rawsql_noaudit",
    ] {
        assert!(names.contains(&expected), "{expected} missing from users.d: {names:?}");
    }
    for (user, networks) in &users {
        let inner = networks
            .as_deref()
            .unwrap_or_else(|| panic!("users.d user {user} has no <networks> (CH would admit any address)"));
        let entries = network_entries(inner);
        assert!(!entries.is_empty(), "{user}: empty <networks>");
        for entry in &entries {
            assert!(!is_any_address(entry), "{user}: <networks> admits every address ({entry})");
        }
        assert!(
            entries.iter().any(|e| e == "127.0.0.1") && entries.iter().any(|e| e == "::1"),
            "{user}: loopback must stay allowed (self-sourced dictionaries / refreshable views, docker exec tools)"
        );
    }
}

#[test]
fn no_users_d_file_reopens_a_user() {
    // users.d files merge into the same user: an any-address entry in ANY
    // shipped users.d file re-opens that user.
    let dirs = [
        "clickhouse/users.d",
        "deploy/k8s/clickhouse/users.d",
        "ludus/roles/nanosiem_stack/files/clickhouse/users.d",
        "config/sizing-defaults",
    ];
    let mut checked = 0;
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(repo_root().join(dir)) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().is_none_or(|x| x != "xml") {
                continue;
            }
            let xml = std::fs::read_to_string(&path).unwrap();
            for (user, networks) in users_networks(&xml) {
                if let Some(inner) = networks {
                    for e in network_entries(&inner) {
                        assert!(
                            !is_any_address(&e),
                            "{}: user {user} admits every address ({e})",
                            path.display()
                        );
                    }
                }
            }
            checked += 1;
        }
    }
    assert!(checked >= 4, "guard scanned too few users.d files ({checked})");
}

#[test]
fn helm_users_json_has_no_any_address_network() {
    let Some(json) = read("deploy/helm/nano/files/clickhouse/users.json") else {
        return; // chart not in this tree (open-core mirror)
    };
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let users = v["users"].as_object().expect("users");
    assert!(users.len() >= 6);
    for (user, def) in users {
        let ips = &def["networks"]["ip"];
        let list: Vec<String> = match ips {
            serde_json::Value::Array(a) => a.iter().map(|x| x.as_str().unwrap().to_string()).collect(),
            serde_json::Value::String(s) => vec![s.clone()],
            other => panic!("{user}: unexpected networks.ip {other}"),
        };
        assert!(!list.is_empty(), "{user}: no networks");
        for e in list {
            assert!(!is_any_address(&e), "helm users.json {user} admits every address ({e})");
        }
    }
    let tpl = read("deploy/helm/nano/templates/clickhouse/_settings.tpl").unwrap();
    assert!(
        tpl.contains("allowedNetworks") && tpl.contains("admits every address"),
        "the chart must render clickhouse.allowedNetworks and refuse any-address entries"
    );
}

#[test]
fn every_sql_create_user_has_a_host_clause() {
    // Migrator-created raw-SQL users, the backup scheduler's user and the
    // legacy k8s init job.
    let create = regex::Regex::new(r"(?is)CREATE USER IF NOT EXISTS[^;]*").unwrap();
    let sources = [
        "nanosiem-core/src/db/clickhouse_migrate/distributed.rs",
        "scripts/nano-backup-scheduler.py",
        "deploy/k8s/clickhouse/clickhouse.yaml",
    ];
    let mut seen = 0;
    for rel in sources {
        let Some(src) = read(rel) else { continue };
        for m in create.find_iter(&src) {
            let stmt = m.as_str();
            // Only real statements (skip doc comments that merely mention it).
            if stmt.contains("IDENTIFIED") {
                assert!(stmt.contains("HOST"), "{rel}: CREATE USER without HOST: {stmt}");
                assert!(!stmt.contains("::/0") && !stmt.contains("HOST ANY"), "{rel}: {stmt}");
                seen += 1;
            }
        }
    }
    assert!(seen >= 3, "too few CREATE USER statements found ({seen})");
    let distributed = read("nanosiem-core/src/db/clickhouse_migrate/distributed.rs").unwrap();
    let clause = distributed
        .split("SQL_USER_HOST_CLAUSE: &str = ")
        .nth(1)
        .and_then(|s| s.split(';').next())
        .expect("SQL_USER_HOST_CLAUSE");
    for entry in regex::Regex::new(r"IP '([^']+)'").unwrap().captures_iter(clause) {
        assert!(!is_any_address(&entry[1]), "SQL_USER_HOST_CLAUSE admits every address");
    }
}

#[test]
fn renderer_refuses_any_address_and_replaces_every_user() {
    let module = repo_root().join("scripts/lib/clickhouse_networks.py");
    let Ok(src) = std::fs::read_to_string(&module) else {
        return;
    };
    assert!(src.contains("prefixlen == 0"), "renderer must refuse /0 entries");
    assert!(src.contains("replace=\"replace\""), "renderer must replace each user's <networks>");
}
