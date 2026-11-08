// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4982: static guards for OCSF ingest-time IOC stamping parity with UDM
//! (ClickHouse migration 188 + the overlay scripts/gen-ocsf-ddl.py renders).
//!
//! The behaviour (every source x indicator type stamped on a real OCSF stack,
//! and a detection on the stamps firing) is proven by
//! `scripts/e2e/lanes/upgrade-188.sh` and `e2e/tests/enterprise/test_ocsf_ioc_stamping.py`.

use nanosiem_core::query::EXPLICIT_COLUMNS;
use nanosiem_core::schema::{FieldResolution, OcsfProfile, SchemaProfile};

const OCSF_INIT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../clickhouse/ocsf/init.sql"));
const MIGRATION_188: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/188_ocsf_ioc_stamping_parity.sql"
));
const USERS_XML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/users.d/nanosiem-users.xml"
));
const URL_CANON_VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ocsf_url_canonicalization.tsv"
));

/// A deploy-side grant file, read at RUN time: the open-core mirror strips
/// deploy/helm and deploy/k8s, and an `include_str!` of a stripped path would
/// break the mirror's build (NAN-2169). `None` in the stripped tree.
fn deploy_file(rel: &str) -> Option<String> {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)).ok()
}

const SLOTS: [&str; 5] = ["src_ip", "dest_ip", "domain", "hash", "url"];
const ATTRS: [&str; 3] = ["threat_type", "malware", "confidence"];
/// The four columns the store had before 188.
const PRE_188: [&str; 4] = [
    "enrichments.ioc_src_ip_threat_type",
    "enrichments.ioc_dest_ip_threat_type",
    "enrichments.ioc_domain_threat_type",
    "enrichments.ioc_hash_threat_type",
];

fn overlay_view_body() -> &'static str {
    OCSF_INIT
        .split(
            "CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_raw_mv\n\
             TO nanosiem.ocsf_logs\n\
             DEFINER = CURRENT_USER\n\
             SQL SECURITY DEFINER\n\
             AS ",
        )
        .nth(1)
        .and_then(|rest| rest.split("\n;").next())
        .expect("overlay ocsf_logs_raw_mv body")
}

fn overlay_table() -> &'static str {
    OCSF_INIT
        .split("CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs\n(")
        .nth(1)
        .and_then(|rest| rest.split("\nENGINE").next())
        .expect("overlay ocsf_logs table")
}

/// `(name, definition)` of every IOC column of the overlay's ocsf_logs.
fn overlay_ioc_columns() -> Vec<(String, String)> {
    overlay_table()
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("`enrichments.ioc_") || l.starts_with("`enrichments.custom_ioc_"))
        .map(|l| {
            let name = l.split('`').nth(1).unwrap().to_string();
            let def = l.split_once("` ").unwrap().1.trim_end_matches(',').to_string();
            (name, def)
        })
        .collect()
}

fn expected_columns() -> Vec<String> {
    let mut out = Vec::new();
    for prefix in ["ioc", "custom_ioc"] {
        for slot in SLOTS {
            for attr in ATTRS {
                out.push(format!("enrichments.{prefix}_{slot}_{attr}"));
            }
        }
        if prefix == "ioc" {
            for n in ["ioc_confidence", "ioc_tags", "ioc_source"] {
                out.push(format!("enrichments.{n}"));
            }
        }
    }
    out
}

#[test]
fn migration_188_view_body_is_the_generated_overlay_body() {
    let migration = MIGRATION_188
        .split("ALTER TABLE nanosiem.ocsf_logs_raw_mv /* nano:skip-if-unknown-table */\nMODIFY QUERY ")
        .nth(1)
        .and_then(|rest| rest.split(";\n").next())
        .expect("188 MODIFY QUERY body");
    assert_eq!(
        migration,
        overlay_view_body(),
        "rerun scripts/gen-ocsf-ddl.py and regenerate 188's MODIFY QUERY"
    );
}

#[test]
fn the_store_carries_every_slot_of_both_dictionaries() {
    let names: Vec<String> = overlay_ioc_columns().into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, expected_columns());
}

#[test]
fn migration_188_adds_exactly_the_new_columns_with_the_overlay_definitions() {
    let adds: Vec<(String, String)> = MIGRATION_188
        .lines()
        .filter_map(|l| {
            l.strip_prefix("ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ ADD COLUMN IF NOT EXISTS `")
        })
        .map(|rest| {
            let (name, rest) = rest.split_once("` ").unwrap();
            let def = rest.split(" AFTER ").next().unwrap();
            (name.to_string(), def.to_string())
        })
        .collect();
    let want: Vec<(String, String)> = overlay_ioc_columns()
        .into_iter()
        .filter(|(n, _)| !PRE_188.contains(&n.as_str()))
        .collect();
    assert_eq!(adds, want);
    assert!(!MIGRATION_188.contains("MODIFY COLUMN"), "plain-column ADDs only (metadata-only)");
    assert!(!MIGRATION_188.contains("MATERIALIZE COLUMN"), "no backfill in a boot migration");
    assert!(!MIGRATION_188.contains("DROP VIEW"), "MODIFY QUERY, never DROP + CREATE (Null source)");
}

#[test]
fn the_view_stamps_every_slot_from_its_dictionary() {
    let body = overlay_view_body();
    for prefix in ["ioc", "custom_ioc"] {
        for slot in SLOTS {
            for attr in ATTRS {
                let col = format!("AS `enrichments.{prefix}_{slot}_{attr}`");
                let line = body.lines().find(|l| l.ends_with(&format!("{col},"))).unwrap_or_else(|| panic!("{col}"));
                let dict = if prefix == "ioc" { "'nanosiem.ioc_enrichment_dict'" } else { "'nanosiem.custom_ioc_enrichment_dict'" };
                assert!(line.contains(dict), "{col} must read {dict}: {line}");
                // A producer-supplied enrichments[] entry still wins.
                assert!(line.starts_with(&format!(
                    "    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, '{prefix}_{slot}_{attr}')) != ''"
                )), "{line}");
            }
        }
    }
    for col in ["ioc_hash_threat_type", "custom_ioc_hash_threat_type"] {
        let hash = body.lines().find(|l| l.ends_with(&format!("AS `enrichments.{col}`,"))).unwrap();
        for arr in ["file.hashes", "process.file.hashes", "actor.process.file.hashes"] {
            // Bounded: the first 16 elements of every hashes[] array ...
            assert!(hash.contains(&format!("arraySlice(`{arr}.value`, 1, 16)")), "{col}/{arr}: {hash}");
            let algo = arr.split('.').map(|s| format!("`{s}`")).collect::<Vec<_>>().join(".");
            assert!(hash.contains(&format!("arraySlice(event.{algo}[].`algorithm_id`, 1, 16)")), "{col}/{arr}: {hash}");
        }
        // ... recognized algorithms with their hex shape only, at most 16 probes.
        assert!(hash.contains("multiIf(a = 1, length(v) = 32, a = 2, length(v) = 40, a = 3, length(v) = 64, 0) AND match(v, '^[0-9a-f]+$')"), "{hash}");
        assert!(hash.contains("arrayFirst(h -> dictHas("), "{hash}");
        assert!(hash.contains(", 1, 16))) AS `_"), "the candidate set is capped at 16: {hash}");
        assert!(!hash.contains("hashes.sha256"), "the SHA-256 pick misses MD5/SHA-1: {hash}");
    }
    let url = body.lines().find(|l| l.ends_with("AS `enrichments.custom_ioc_url_threat_type`,")).unwrap();
    for col in ["`url.url_string`", "`http_request.url.url_string`"] {
        assert!(url.contains(&format!("tuple('url', {})", url_canon(col))), "{url}");
    }
    assert!(!url.contains("lower(trimBoth("), "never lowercase the whole URL: {url}");
    assert!(
        url.contains("substring(url_authority, 1, url_userinfo_end)"),
        "userinfo must be copied before only the host is lowercased: {url}"
    );
    let domain = body.lines().find(|l| l.ends_with("AS `enrichments.custom_ioc_domain_threat_type`,")).unwrap();
    assert!(domain.contains("tuple('domain', lower(`query.hostname`))"), "{domain}");
    assert!(!body.contains("PREWHERE"));
}

/// Twin of scripts/gen-ocsf-ddl.py `url_canon_sql`.
fn url_canon(x: &str) -> String {
    let bind = |name: &str, value: String, body: String| {
        format!("arrayElement(arrayMap({name} -> {body}, [{value}]), 1)")
    };
    let host_end = "if(startsWith(url_host_port, '[') AND position(url_host_port, ']') > 0, position(url_host_port, ']'), if(position(url_host_port, ':') > 0, position(url_host_port, ':') - 1, length(url_host_port)))";
    let canonical_authority = bind(
        "url_at_from_end",
        "position(reverse(url_authority), '@')".to_string(),
        bind(
            "url_userinfo_end",
            "if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)".to_string(),
            bind(
                "url_host_port",
                "substring(url_authority, url_userinfo_end + 1)".to_string(),
                bind(
                    "url_host_end",
                    host_end.to_string(),
                    "concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1))".to_string(),
                ),
            ),
        ),
    );
    let with_authority = bind(
        "url_authority",
        "if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))".to_string(),
        format!(
            "concat(lower(substring(url_t, 1, position(url_t, '://') + 2)), {canonical_authority}, if(url_tail_pos = 0, '', substring(url_rest, url_tail_pos)))"
        ),
    );
    let with_tail = bind(
        "url_tail_pos",
        "multiSearchFirstPosition(url_rest, ['/', char(63), '#'])".to_string(),
        with_authority,
    );
    let with_rest = bind(
        "url_rest",
        "substring(url_t, position(url_t, '://') + 3)".to_string(),
        with_tail,
    );
    bind(
        "url_t",
        format!("trimBoth({x})"),
        format!("if(position(url_t, '://') > 0, {with_rest}, url_t)"),
    )
}

#[test]
fn shared_url_vectors_cover_positive_and_negative_userinfo_cases() {
    let mut positive = None;
    let mut negative = None;
    for (line_no, line) in URL_CANON_VECTORS.lines().enumerate() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 3, "vector line {}: {line:?}", line_no + 1);
        assert_eq!(
            nanosiem_core::enrichment::ioc::canonical_url(fields[1]),
            fields[2],
            "vector {}",
            fields[0]
        );
        match fields[0] {
            "userinfo_positive" => positive = Some(fields[2]),
            "userinfo_negative" => negative = Some(fields[2]),
            _ => {}
        }
    }
    assert_ne!(positive, negative, "userinfo case is part of the IOC key");
}

/// Both dictionaries key a `url` row by the same canonical form the view
/// stamps with; every other key type stays lower() (migration 148).
#[test]
fn migration_188_dictionaries_canonicalize_url_keys_like_the_view() {
    let esc = |s: String| s.replace('\'', "\\'");
    let ioc = format!(
        "QUERY 'SELECT {} AS ioc_value, ioc_type, source_id, threat_type, malware, confidence_level, tags FROM nanosiem.ioc_enrichment_dict_staging'",
        esc(format!("if(ioc_type = 'url', {}, lower(ioc_value))", url_canon("ioc_value")))
    );
    let custom = format!(
        "QUERY 'SELECT key_type, {} AS key_value, threat_type, malware, confidence, tags, enrichment_names FROM nanosiem.custom_ioc_enrichment_dict_staging'",
        esc(format!("if(key_type = 'url', {}, lower(key_value))", url_canon("key_value")))
    );
    assert!(MIGRATION_188.contains(&ioc), "ioc_enrichment_dict source");
    assert!(MIGRATION_188.contains(&custom), "custom_ioc_enrichment_dict source");
    assert!(MIGRATION_188.contains("CREATE OR REPLACE DICTIONARY nanosiem.ioc_enrichment_dict\n"));
    assert!(MIGRATION_188.contains("CREATE OR REPLACE DICTIONARY nanosiem.custom_ioc_enrichment_dict\n"));
}

#[test]
fn every_udm_ioc_column_resolves_on_ocsf() {
    let p = OcsfProfile::new();
    let udm: Vec<&str> = EXPLICIT_COLUMNS
        .iter()
        .copied()
        .filter(|c| (c.starts_with("ioc_") || c.starts_with("custom_ioc_")) && *c != "ioc_matched")
        .collect();
    assert!(udm.len() >= 25, "{udm:?}");
    for c in udm {
        assert_eq!(
            p.resolve(c),
            FieldResolution::ExplicitColumn(format!("enrichments.{c}")),
            "UDM `{c}` must resolve to its OCSF stamp"
        );
    }
    for c in expected_columns() {
        assert!(p.is_known_field(&c), "{c}");
    }
}

#[test]
fn direct_ocsf_writers_can_read_the_custom_ioc_dictionary() {
    let ingest = USERS_XML
        .split("<nanosiem_ingest>")
        .nth(1)
        .and_then(|r| r.split("</nanosiem_ingest>").next())
        .expect("nanosiem_ingest user");
    assert!(ingest.contains("<query>GRANT dictGet ON nanosiem.custom_ioc_enrichment_dict</query>"));
    let helm = deploy_file("deploy/helm/nano/files/clickhouse/users.json");
    let k8s = deploy_file("deploy/k8s/clickhouse/clickhouse.yaml");
    let templates: Vec<String> = ["deploy/k8s/aws-db/clickhouse.yaml.tpl", "deploy/k8s/rackspace-db/clickhouse.yaml.tpl"]
        .into_iter()
        .filter_map(deploy_file)
        .collect();
    if let Some(h) = &helm {
        assert!(h.contains("\"GRANT dictGet ON nanosiem.custom_ioc_enrichment_dict\""));
    }
    if let Some(k) = &k8s {
        assert!(k.contains("GRANT dictGet ON nanosiem.custom_ioc_enrichment_dict TO nanosiem_ingest;"));
    }
    for tpl in &templates {
        assert!(tpl.contains("- \"GRANT dictGet ON nanosiem.custom_ioc_enrichment_dict\""));
    }
    assert!(MIGRATION_188.contains("GRANT dictGet ON nanosiem.custom_ioc_enrichment_dict TO nanosiem_ingest;"));
    // The chained prevalence-source MVs (migration 170) run under the inserting
    // user: without SELECT on their agg tables every direct write with an IP /
    // hash / domain fails 497 before any stamp lands.
    for t in ["ip", "hash", "domain"] {
        let table = format!("nanosiem.{t}_prevalence_source_agg");
        assert!(ingest.contains(&format!("<query>GRANT SELECT ON {table}</query>")), "{table}");
        if let Some(h) = &helm {
            assert!(h.contains(&format!("\"GRANT SELECT ON {table}\"")), "{table}");
        }
        if let Some(k) = &k8s {
            assert!(k.contains(&format!("GRANT SELECT ON {table} TO nanosiem_ingest;")), "{table}");
        }
        for tpl in &templates {
            assert!(tpl.contains(&format!("- \"GRANT SELECT ON {table}\"")), "{table}");
        }
        assert!(MIGRATION_188.contains(&format!("GRANT SELECT ON {table} TO nanosiem_ingest;")), "{table}");
    }
}
