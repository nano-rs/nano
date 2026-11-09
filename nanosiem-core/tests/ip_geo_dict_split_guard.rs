// SPDX-License-Identifier: AGPL-3.0-or-later

//! Static guards for ClickHouse migration 185 (NAN-4957): the IPinfo geo/ASN
//! dictionary split into `ip_geo_trie_dict` (network -> geo_id) and
//! `ip_geo_attrs_dict` (geo_id -> seven attributes).
//!
//! The upgrade/fresh behaviour on a real ClickHouse is covered by
//! `scripts/e2e/lanes/upgrade-185.sh`; these pin the text the migration must
//! carry so a later edit cannot silently drift the two paths apart.

use std::collections::BTreeSet;

const UDM_INIT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../clickhouse/init.sql"));
const OCSF_INIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/ocsf/init.sql"
));
const MIGRATION_136: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/136_lengthen_ip_enrichment_dict_lifetime.sql"
));
const MIGRATION_185: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/185_ip_geo_dict_split.sql"
));
const USERS_XML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/users.d/nanosiem-users.xml"
));

const GEO_ID: &str =
    "cityHash64(country, country_code, continent, continent_code, asn, as_name, as_domain) AS geo_id";

/// Statements of a SQL file with `--` comment lines removed.
fn statements(sql: &str) -> Vec<String> {
    let stripped: String = sql
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    stripped
        .split(";\n")
        .map(|s| s.trim().trim_end_matches(';').trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The `nano:fatal` marker (NAN-4957 review) makes the runner abort instead
/// of skipping a failed statement; it is not part of the definition.
const FATAL: &str = " /* nano:fatal */";

fn dictionary(sql: &str, name: &str) -> Option<String> {
    let head = format!("CREATE OR REPLACE DICTIONARY {name}\n");
    statements(sql)
        .into_iter()
        .map(|s| s.replacen(FATAL, "", 1))
        .find(|s| s.starts_with(&head))
}

/// `name type` of every enriched_* column whose MATERIALIZED expression in
/// init.sql still reads the old single dictionary.
fn init_columns_on_old_dict() -> BTreeSet<(String, String)> {
    UDM_INIT
        .lines()
        .filter(|l| l.contains("'nanosiem.ip_enrichment_dict'") && l.contains(" MATERIALIZED "))
        .map(|l| {
            let l = l.trim();
            let name = l.split('`').nth(1).expect("backquoted column").to_string();
            let ty = l.split("` ").nth(1).unwrap().split(" MATERIALIZED").next().unwrap().to_string();
            (name, ty)
        })
        .collect()
}

fn migration_modified_columns() -> BTreeSet<(String, String)> {
    MIGRATION_185
        .lines()
        .filter_map(|l| l.trim().strip_prefix("MODIFY COLUMN `"))
        .map(|rest| {
            let (name, rest) = rest.split_once("` ").unwrap();
            let ty = rest.split(" MATERIALIZED").next().unwrap();
            (name.to_string(), ty.to_string())
        })
        .collect()
}

#[test]
fn migration_185_defines_exactly_the_two_geo_dicts_and_reissues_the_old_one() {
    let created: Vec<String> = statements(MIGRATION_185)
        .into_iter()
        .filter_map(|s| {
            s.strip_prefix("CREATE OR REPLACE DICTIONARY ")
                .map(|r| r.lines().next().unwrap().trim_end_matches(FATAL).trim().to_string())
        })
        .collect();
    assert_eq!(
        created,
        ["nanosiem.ip_geo_attrs_dict", "nanosiem.ip_geo_trie_dict", "nanosiem.ip_enrichment_dict"]
    );
    // The re-issue only unloads the 1.32 GiB trie (lazy load); it must not
    // change the compatibility dictionary in any way.
    assert_eq!(
        dictionary(MIGRATION_185, "nanosiem.ip_enrichment_dict"),
        dictionary(MIGRATION_136, "nanosiem.ip_enrichment_dict"),
        "185 must re-issue ip_enrichment_dict identical to migration 136"
    );
    // All three dictionary statements are fatal: a skipped re-issue would
    // record 185 with the 1.32 GiB trie still resident.
    for name in ["nanosiem.ip_geo_attrs_dict", "nanosiem.ip_geo_trie_dict", "nanosiem.ip_enrichment_dict"] {
        assert!(
            MIGRATION_185.contains(&format!("CREATE OR REPLACE DICTIONARY {name}{FATAL}\n")),
            "{name} must carry the nano:fatal marker"
        );
    }
}

#[test]
fn both_geo_dicts_derive_geo_id_identically_from_staging() {
    let trie = dictionary(MIGRATION_185, "nanosiem.ip_geo_trie_dict").expect("trie");
    let attrs = dictionary(MIGRATION_185, "nanosiem.ip_geo_attrs_dict").expect("attrs");
    for (label, dict) in [("trie", &trie), ("attrs", &attrs)] {
        assert!(dict.contains(GEO_ID), "{label} must compute {GEO_ID}");
        assert!(
            dict.contains("FROM nanosiem.ip_enrichment_dict_staging"),
            "{label} must load the committed staging table"
        );
        // NAN-1310: the default profile caps results at 1M rows.
        assert!(dict.contains("SETTINGS(max_result_rows = 0, max_result_bytes = 0)"), "{label}");
        // One generation: never reloaded on its own (enrichment::ip_geo::reload_pair).
        assert!(dict.contains("LIFETIME(0)"), "{label}");
    }
    assert!(trie.contains("LAYOUT(IP_TRIE())") && trie.contains("geo_id UInt64 DEFAULT 0"));
    assert!(attrs.contains("LAYOUT(HASHED())") && attrs.contains("PRIMARY KEY geo_id"));
    // The attrs half also covers the combinations of earlier generations, so a
    // trie that failed to reload stays resolvable.
    assert!(attrs.contains("UNION ALL SELECT geo_id, country, country_code, continent, continent_code, asn, as_name, as_domain FROM nanosiem.ip_geo_attrs_history"));
    assert!(MIGRATION_185.contains("REFRESH EVERY 6 HOUR APPEND TO nanosiem.ip_geo_attrs_history AS"));
    assert!(MIGRATION_185.contains("TTL seen_at + INTERVAL 30 DAY"));
    for attr in ["country", "country_code", "continent", "continent_code", "asn", "as_name", "as_domain"] {
        assert!(attrs.contains(&format!("    {attr} String DEFAULT ''")), "attrs lacks {attr}");
    }
}

#[test]
fn every_udm_column_on_the_old_dict_is_cut_over_with_its_type() {
    let init = init_columns_on_old_dict();
    assert_eq!(init.len(), 14, "init.sql enriched_* columns on ip_enrichment_dict: {init:?}");
    assert_eq!(migration_modified_columns(), init);
    for line in MIGRATION_185.lines().filter(|l| l.trim().starts_with("MODIFY COLUMN")) {
        assert!(!line.contains("ip_enrichment_dict"), "{line}");
        assert!(line.contains("ip_geo_trie_dict") && line.contains("ip_geo_attrs_dict"), "{line}");
        // Same codec as init.sql, so the ALTER stays metadata-only.
        assert!(line.trim_end().ends_with("CODEC(ZSTD(1)),") || line.trim_end().ends_with("CODEC(ZSTD(1));"), "{line}");
    }
}

/// The overlay creates ocsf_logs_raw_mv on fresh OCSF installs; 185 converts
/// existing ones. Both must end on the same body, apart from the IOC stamping
/// columns migration 188 (NAN-4982) redefined afterwards (188's own body is
/// pinned byte-for-byte to the overlay in tests/ocsf_ioc_stamping_guard.rs).
#[test]
fn ocsf_view_body_in_185_matches_the_generated_overlay() {
    fn without_ioc(body: &str) -> String {
        body.lines()
            .filter(|l| !l.contains("AS `enrichments.ioc_") && !l.contains("AS `enrichments.custom_ioc_"))
            // ocsf/193 (NAN-5032) redefined the source_type line afterwards.
            .filter(|l| !l.trim_end().ends_with("AS source_type,"))
            .collect::<Vec<_>>()
            .join("\n")
    }
    let overlay = OCSF_INIT
        .split(
            "CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_raw_mv\n\
             TO nanosiem.ocsf_logs\n\
             DEFINER = CURRENT_USER\n\
             SQL SECURITY DEFINER\n\
             AS ",
        )
        .nth(1)
        .and_then(|rest| rest.split("\n;").next())
        .expect("overlay ocsf_logs_raw_mv body");
    let migration = MIGRATION_185
        .split("ALTER TABLE nanosiem.ocsf_logs_raw_mv /* nano:skip-if-unknown-table */\nMODIFY QUERY ")
        .nth(1)
        .and_then(|rest| rest.split(";\n").next())
        .expect("185 MODIFY QUERY body");
    assert_eq!(
        without_ioc(migration),
        without_ioc(overlay),
        "rerun scripts/gen-ocsf-ddl.py and regenerate 185's MODIFY QUERY"
    );
    assert!(!OCSF_INIT.contains("ip_enrichment_dict'"), "the OCSF overlay must not read the old dict");
    assert_eq!(overlay.matches("'nanosiem.ip_geo_trie_dict'").count(), 16);
}

#[test]
fn direct_ocsf_writers_can_read_the_new_dicts() {
    let ingest = USERS_XML
        .split("<nanosiem_ingest>")
        .nth(1)
        .and_then(|r| r.split("</nanosiem_ingest>").next())
        .expect("nanosiem_ingest user");
    for dict in ["nanosiem.ip_geo_trie_dict", "nanosiem.ip_geo_attrs_dict"] {
        assert!(
            ingest.contains(&format!("<query>GRANT dictGet ON {dict}</query>")),
            "nanosiem_ingest needs dictGet on {dict}: the OCSF view runs under the inserting user"
        );
    }
}

const MIGRATION_184: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/184_platform_feed_commits.sql"
));

fn refresh_body(sql: &str) -> String {
    sql.split("ALTER TABLE nanosiem.ip_enrichment_dict_refresh\nMODIFY QUERY ")
        .nth(1)
        .and_then(|r| r.split(';').next())
        .expect("ip_enrichment_dict_refresh MODIFY QUERY")
        .to_string()
}

/// 185 only lowers the refresh view's spill threshold; the platform-feed
/// visibility predicate and every other clause stay exactly as 184 set them.
#[test]
fn refresh_view_keeps_184_body_with_a_lower_spill_threshold() {
    let old = refresh_body(MIGRATION_184);
    let new = refresh_body(MIGRATION_185);
    let old_settings =
        "SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2";
    let new_settings =
        "SETTINGS max_bytes_before_external_group_by = 268435456, max_memory_usage = 1500000000, max_threads = 2, \
         min_insert_block_size_rows = 262144, min_insert_block_size_bytes = 67108864, max_insert_block_size = 262144";
    assert!(old.ends_with(old_settings), "{old}");
    assert!(new.ends_with(new_settings), "{new}");
    assert_eq!(
        old.trim_end_matches(old_settings),
        new.trim_end_matches(new_settings),
        "185 must not change the refresh query itself"
    );
    assert!(new.contains("platform_feed = 0 OR source_id GLOBAL IN"));
}

/// NAN-4957 review: the narrow direct-ingest credential must not be able to
/// lazy-load the retired 1.32 GiB trie.
#[test]
fn direct_ingest_user_loses_the_old_dictionary() {
    let ingest = USERS_XML
        .split("<nanosiem_ingest>")
        .nth(1)
        .and_then(|r| r.split("</nanosiem_ingest>").next())
        .expect("nanosiem_ingest user");
    assert!(!ingest.contains("GRANT dictGet ON nanosiem.ip_enrichment_dict<"), "users.d still grants it");
    assert!(MIGRATION_185.contains("REVOKE dictGet ON nanosiem.ip_enrichment_dict FROM nanosiem_ingest;"));
}

