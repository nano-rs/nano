// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5359: generated SQL for the Agent Lane profile, workload, role, grants
//! and audit row policies.

use super::agentlane::*;

fn env<'a>(
    rows: Option<&'a str>,
    bytes: Option<&'a str>,
    threads: Option<&'a str>,
) -> AgentlaneEnv<'a> {
    AgentlaneEnv {
        max_rows_to_read: rows,
        max_bytes_to_read: bytes,
        max_concurrent_threads: threads,
        ..AgentlaneEnv::default()
    }
}

/// The workload DDL with the default limits apart from the thread cap.
fn workload(on_cluster: &str, threads: u64) -> String {
    workload_statement(on_cluster, threads, 1 << 30)
}

fn table(name: &str, engine: &str) -> ExistingTable {
    ExistingTable {
        name: name.to_string(),
        engine: engine.to_string(),
    }
}

fn select_grant(db: &str, table: &str) -> ObservedGrant {
    ObservedGrant {
        access_type: "SELECT".into(),
        database: Some(db.into()),
        table: Some(table.into()),
        column: None,
        is_partial_revoke: 0,
        grant_option: 0,
        is_wildcard: 0,
    }
}

/// OCSF single node: bare MergeTree tables, no `logs`.
fn single_node_ocsf() -> Vec<ExistingTable> {
    [
        "ocsf_logs",
        "signals",
        "identity_observations",
        "hash_prevalence_source_summary",
        "domain_prevalence_source_summary",
        "ip_prevalence_source_summary",
    ]
    .iter()
    .map(|n| table(n, "MergeTree"))
    .collect()
}

/// Clustered: `_local` physical, bare + `_distributed` wrappers.
fn clustered_ocsf() -> Vec<ExistingTable> {
    let mut out = Vec::new();
    for base in ["ocsf_logs", "signals", "identity_observations"] {
        out.push(table(&format!("{base}_local"), "ReplicatedMergeTree"));
        out.push(table(base, "Distributed"));
        out.push(table(&format!("{base}_distributed"), "Distributed"));
    }
    out
}

#[test]
fn profile_pins_every_lockdown_setting_and_cap() {
    let sql = profile_settings_sql(&AgentlaneSettings::default());
    for expected in [
        "readonly = 1 CONST",
        "allow_ddl = 0 CONST",
        "allow_introspection_functions = 0 CONST",
        "force_index_by_date = 1 CONST",
        "skip_unavailable_shards = 0 CONST",
        "serialize_query_plan = 0 CONST",
        "distributed_product_mode = 'global' CONST",
        "workload = 'agentlane' CONST",
        "max_execution_time = 60 MIN 1 MAX 60 CHANGEABLE_IN_READONLY",
        "max_result_rows = 100000 MAX 100000 CHANGEABLE_IN_READONLY",
        "max_result_bytes = 67108864 CONST",
        "timeout_overflow_mode = 'throw' CONST",
        "max_query_size = 1048576 CONST",
        "result_overflow_mode = 'throw' CONST",
        "read_overflow_mode = 'throw' CONST",
        "max_rows_to_read = 500000000 CONST",
        "max_bytes_to_read = 53687091200 CONST",
        "max_memory_usage = 4294967296 CONST",
        "max_memory_usage_for_user = 4294967296 CONST",
        "max_threads = 4 CONST",
        "max_concurrent_queries_for_user = 2 CONST",
        "http_wait_end_of_query = 1 CONST",
        "http_response_buffer_size = 67108864 CONST",
        "log_comment CHANGEABLE_IN_READONLY",
        "session_timezone CHANGEABLE_IN_READONLY",
        "default_format CHANGEABLE_IN_READONLY",
    ] {
        assert!(sql.contains(expected), "profile is missing `{expected}`: {sql}");
    }
}

#[test]
fn only_output_settings_and_lowering_caps_are_changeable_in_readonly() {
    let sql = profile_settings_sql(&AgentlaneSettings::default());
    let changeable: Vec<&str> = sql
        .split(", ")
        .filter(|part| part.contains("CHANGEABLE_IN_READONLY"))
        .map(|part| part.split_whitespace().next().unwrap())
        .collect();
    let mut allowed: Vec<&str> = CHANGEABLE_OUTPUT_SETTINGS.to_vec();
    allowed.extend(["max_execution_time", "max_result_rows"]);
    for name in &changeable {
        assert!(allowed.contains(name), "`{name}` must not be changeable in readonly");
    }
    for forbidden in [
        "format_schema",
        "output_format_schema",
        "max_threads",
        "workload",
        "readonly",
        "distributed_product_mode",
    ] {
        assert!(!changeable.contains(&forbidden), "`{forbidden}` must stay locked");
    }
    // Every CHANGEABLE cap carries a MAX equal to its default (lower only).
    // max_execution_time also has MIN 1 (0 = unlimited); max_result_rows has
    // no MIN because ClickHouse sends it as 0 to shard hops (see
    // `max_result_rows_can_reach_zero_but_bytes_still_bound_the_result`).
    for part in sql.split(", ").filter(|p| p.contains("CHANGEABLE_IN_READONLY") && p.contains('=')) {
        let words: Vec<&str> = part.split_whitespace().collect();
        let max_at = words.iter().position(|w| *w == "MAX").unwrap_or_else(|| panic!("no MAX: {part}"));
        assert_eq!(words[2], words[max_at + 1], "changeable cap MAX must equal its value: {part}");
        match words[0] {
            "max_execution_time" => assert_eq!(&words[3..5], ["MIN", "1"], "{part}"),
            "max_result_rows" => assert!(!part.contains(" MIN "), "{part}"),
            other => panic!("unexpected changeable cap {other}"),
        }
    }
}

/// Codex FIX FIRST (P1): every setting where 0 (or a negative value)
/// disables a limit is CONST or carries `MIN 1`. A caller can never reach
/// 0 through the SETTINGS clause or an HTTP parameter.
#[test]
fn no_limit_can_be_set_to_zero() {
    let sql = profile_settings_sql(&AgentlaneSettings::default());
    let parts: Vec<&str> = sql.split(", ").collect();
    for limit in [
        "max_execution_time",
        "max_result_rows",
        "max_result_bytes",
        "max_rows_to_read",
        "max_bytes_to_read",
        "max_memory_usage",
        "max_memory_usage_for_user",
        "max_threads",
        "max_concurrent_queries_for_user",
        "memory_overcommit_ratio_denominator",
        "memory_overcommit_ratio_denominator_for_user",
        "max_query_size",
        "http_response_buffer_size",
        "http_wait_end_of_query",
        "readonly",
        "force_index_by_date",
        "timeout_overflow_mode",
        "result_overflow_mode",
        "read_overflow_mode",
    ] {
        let part = parts
            .iter()
            .find(|p| p.starts_with(&format!("{limit} = ")))
            .unwrap_or_else(|| panic!("profile does not pin {limit}"));
        if limit == "max_result_rows" {
            continue; // reset to 0 on shard hops; covered by the test below
        }
        assert!(
            part.ends_with(" CONST") || part.contains(" MIN 1 "),
            "{limit} could be set to 0: {part}"
        );
        if limit.starts_with("max_") {
            assert!(!part.starts_with(&format!("{limit} = 0 ")), "{limit} defaults to unlimited: {part}");
        }
    }
    // The settings a caller may change at all: none of them is a limit.
    for name in CHANGEABLE_OUTPUT_SETTINGS {
        assert!(!name.starts_with("max_") && !name.contains("timeout") && !name.contains("overflow"),
            "{name} looks like a limit; it must not be changeable");
    }
}

#[test]
fn read_caps_come_from_env_and_never_go_unlimited() {
    assert_eq!(
        agentlane_settings_from_env(env(None, Some("  "), Some(""))).unwrap(),
        AgentlaneSettings::default()
    );
    let caps = agentlane_settings_from_env(env(Some("2000000000"), Some("214748364800"), None)).unwrap();
    assert_eq!(caps.max_rows_to_read, 2_000_000_000);
    assert_eq!(caps.max_bytes_to_read, 214_748_364_800);
    let sql = profile_settings_sql(&caps);
    assert!(sql.contains("max_rows_to_read = 2000000000 CONST"));
    assert!(sql.contains("max_bytes_to_read = 214748364800 CONST"));
    // Zero is "unlimited" to ClickHouse; junk and out-of-range are refused.
    for bad in ["0", "-1", "1e9", "abc", "999"] {
        assert!(agentlane_settings_from_env(env(Some(bad), None, None)).is_err(), "rows {bad}");
        assert!(agentlane_settings_from_env(env(None, Some(bad), None)).is_err(), "bytes {bad}");
    }
}

#[test]
fn profile_is_created_then_altered_never_replaced() {
    let [create, alter] = profile_statements(" ON CLUSTER 'c1'", &AgentlaneSettings::default());
    assert!(create.starts_with("CREATE SETTINGS PROFILE IF NOT EXISTS agentlane ON CLUSTER 'c1' SETTINGS readonly = 1 CONST"));
    assert!(alter.starts_with("ALTER SETTINGS PROFILE agentlane ON CLUSTER 'c1' SETTINGS readonly = 1 CONST"));
    for sql in [&create, &alter] {
        assert!(!sql.contains("OR REPLACE"), "OR REPLACE detaches users from the profile: {sql}");
    }
    let [create, alter] = profile_statements("", &AgentlaneSettings::default());
    assert!(create.starts_with("CREATE SETTINGS PROFILE IF NOT EXISTS agentlane SETTINGS "));
    assert!(alter.starts_with("ALTER SETTINGS PROFILE agentlane SETTINGS "));
}

#[test]
fn workload_sits_below_its_siblings_with_a_thread_cap() {
    assert_eq!(
        workload_statement(" ON CLUSTER 'c1'", DEFAULT_MAX_CONCURRENT_THREADS, 8589934592),
        "CREATE OR REPLACE WORKLOAD agentlane ON CLUSTER 'c1' IN nano \
         SETTINGS weight = 1, priority = 10, max_concurrent_threads = 2, \
         max_memory = 8589934592"
    );
    assert!(workload("", 2).starts_with("CREATE OR REPLACE WORKLOAD agentlane IN nano "));
}

#[test]
fn role_carries_the_profile_and_is_never_replaced() {
    let [create, alter] = role_statements("");
    assert_eq!(
        create,
        "CREATE ROLE IF NOT EXISTS agentlane_reader SETTINGS PROFILE 'agentlane'"
    );
    assert_eq!(alter, "ALTER ROLE agentlane_reader SETTINGS PROFILE 'agentlane'");
    let [create, _] = role_statements(" ON CLUSTER 'c1'");
    assert!(create.contains("agentlane_reader ON CLUSTER 'c1' SETTINGS"));
}

#[test]
fn every_granted_table_has_an_audit_policy_column() {
    let names: Vec<&str> = AGENTLANE_TABLES.iter().map(|(t, _)| *t).collect();
    for required in [
        "ocsf_logs",
        "logs",
        "signals",
        "identity_observations",
        "hash_prevalence_source_summary",
        "domain_prevalence_source_summary",
        "ip_prevalence_source_summary",
    ] {
        assert!(names.contains(&required), "missing {required}");
    }
    for excluded in [
        "ingestion_errors",
        "hash_prevalence_summary",
        "ip_prevalence_agg",
        "custom_enrichment_results",
        "otel_spans",
    ] {
        assert!(!names.contains(&excluded), "{excluded} must not be granted");
    }
    let identity = AGENTLANE_TABLES.iter().find(|(t, _)| *t == "identity_observations");
    assert_eq!(identity.unwrap().1, "source");
    assert!(AGENTLANE_TABLES
        .iter()
        .filter(|(t, _)| *t != "identity_observations")
        .all(|(_, c)| *c == "source_type"));
}

#[test]
fn single_node_grants_and_policies_cover_the_bare_tables() {
    let objects = plan_objects(&single_node_ocsf());
    assert_eq!(objects.grant_tables.len(), 6);
    assert!(!objects.grant_tables.contains("logs"), "absent UDM table is not granted");
    assert_eq!(objects.policy_tables.len(), 6);

    let policies = policy_statements("nanosiem", "", &objects);
    assert_eq!(policies.len(), 3);
    assert_eq!(
        policies[0],
        "CREATE ROW POLICY OR REPLACE agentlane_hide_audit ON nanosiem.identity_observations \
         USING lower(source) != 'audit' AS RESTRICTIVE TO agentlane_reader"
    );
    assert!(policies[1].starts_with(
        "CREATE ROW POLICY OR REPLACE agentlane_hide_audit ON nanosiem.ocsf_logs, nanosiem.signals, "
    ));
    assert!(policies[1].ends_with("USING lower(source_type) != 'audit' AS RESTRICTIVE TO agentlane_reader"));
    assert!(policies[2].starts_with("CREATE ROW POLICY OR REPLACE agentlane_baseline ON "));
    assert!(policies[2].ends_with("USING 1 AS PERMISSIVE TO agentlane_reader"));
    for t in &objects.grant_tables {
        assert!(policies[2].contains(&format!("nanosiem.{t}")), "baseline misses {t}");
    }

    let grant = grant_statement("nanosiem", "", &objects).unwrap();
    assert!(grant.starts_with("GRANT SELECT ON nanosiem."));
    assert!(grant.ends_with(" TO agentlane_reader"));
    assert_eq!(grant.matches("SELECT ON ").count(), 6);
}

#[test]
fn clustered_policies_attach_to_local_tables_never_wrappers() {
    let objects = plan_objects(&clustered_ocsf());
    assert_eq!(objects.grant_tables.len(), 9, "bare, _local and _distributed are granted");
    let policy_names: Vec<&str> = objects.policy_tables.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(
        policy_names,
        ["ocsf_logs_local", "signals_local", "identity_observations_local"]
    );

    let policies = policy_statements("nanosiem", " ON CLUSTER 'c1'", &objects);
    for sql in &policies {
        assert!(sql.contains("ON CLUSTER 'c1' ON nanosiem."), "{sql}");
        assert!(!sql.contains("nanosiem.ocsf_logs,") && !sql.contains("_distributed"), "{sql}");
    }
    let grant = grant_statement("nanosiem", " ON CLUSTER 'c1'", &objects).unwrap();
    assert!(grant.starts_with("GRANT ON CLUSTER 'c1' SELECT ON "));
    for name in ["ocsf_logs", "ocsf_logs_local", "ocsf_logs_distributed"] {
        assert!(grant.contains(&format!("SELECT ON nanosiem.{name},")) || grant.contains(&format!("SELECT ON nanosiem.{name} TO")));
    }
}

#[test]
fn restrictive_audit_policies_come_before_the_permissive_baseline() {
    let policies = policy_statements("nanosiem", "", &plan_objects(&single_node_ocsf()));
    let last = policies.len() - 1;
    assert!(policies[..last].iter().all(|p| p.contains("AS RESTRICTIVE")));
    assert!(policies[last].contains("AS PERMISSIVE"));
}

#[test]
fn nothing_is_granted_or_policied_when_no_table_exists() {
    let objects = plan_objects(&[table("other", "MergeTree")]);
    assert!(policy_statements("nanosiem", "", &objects).is_empty());
    assert!(grant_statement("nanosiem", "", &objects).is_none());
}

#[test]
fn no_statement_creates_a_user_or_touches_other_identities() {
    let caps = AgentlaneSettings::default();
    let objects = plan_objects(&clustered_ocsf());
    let mut all: Vec<String> = Vec::new();
    all.extend(profile_statements(" ON CLUSTER 'c1'", &caps));
    all.extend(role_statements(" ON CLUSTER 'c1'"));
    all.push(workload(" ON CLUSTER 'c1'", caps.max_concurrent_threads));
    all.extend(resource_statements(" ON CLUSTER 'c1'"));
    all.extend(policy_statements("nanosiem", " ON CLUSTER 'c1'", &objects));
    all.extend(grant_statement("nanosiem", " ON CLUSTER 'c1'", &objects));
    for sql in &all {
        let upper = sql.to_uppercase();
        assert!(!upper.contains("CREATE USER") && !upper.contains("ALTER USER"), "{sql}");
        assert!(!upper.contains("DICTGET") && !upper.contains("READ ON"), "{sql}");
        assert!(!upper.contains("PREWHERE"), "{sql}");
    }
}

#[test]
fn converged_grants_need_no_revoke() {
    let objects = plan_objects(&single_node_ocsf());
    let observed: Vec<ObservedGrant> = objects
        .grant_tables
        .iter()
        .map(|t| select_grant("nanosiem", t))
        .collect();
    assert!(revoke_statements("nanosiem", "", &objects, &observed).unwrap().is_empty());
}

#[test]
fn drifted_grants_are_revoked() {
    let objects = plan_objects(&single_node_ocsf());
    let mut insert = select_grant("nanosiem", "ocsf_logs");
    insert.access_type = "INSERT".into();
    let mut column = select_grant("nanosiem", "signals");
    column.column = Some("rule_id".into());
    let mut with_option = select_grant("nanosiem", "ocsf_logs");
    with_option.grant_option = 1;
    let mut dict = select_grant("nanosiem", "ip_geo");
    dict.access_type = "dictGet".into();
    let mut global = select_grant("nanosiem", "x");
    global.database = None;
    global.table = None;
    let mut partial = select_grant("nanosiem", "ingestion_errors");
    partial.is_partial_revoke = 1;
    let observed = vec![
        select_grant("nanosiem", "ingestion_errors"),
        select_grant("system", "query_log"),
        insert,
        column,
        with_option,
        dict,
        global,
        partial,
    ];
    let revokes = revoke_statements("nanosiem", " ON CLUSTER 'c1'", &objects, &observed).unwrap();
    assert_eq!(
        revokes,
        vec![
            "REVOKE ON CLUSTER 'c1' SELECT ON nanosiem.ingestion_errors FROM agentlane_reader",
            "REVOKE ON CLUSTER 'c1' SELECT ON system.query_log FROM agentlane_reader",
            "REVOKE ON CLUSTER 'c1' INSERT ON nanosiem.ocsf_logs FROM agentlane_reader",
            "REVOKE ON CLUSTER 'c1' SELECT(rule_id) ON nanosiem.signals FROM agentlane_reader",
            "REVOKE ON CLUSTER 'c1' GRANT OPTION FOR SELECT ON nanosiem.ocsf_logs FROM agentlane_reader",
            "REVOKE ON CLUSTER 'c1' dictGet ON nanosiem.ip_geo FROM agentlane_reader",
            "REVOKE ON CLUSTER 'c1' SELECT ON *.* FROM agentlane_reader",
        ]
    );
}

#[test]
fn an_unnameable_grant_fails_closed() {
    let objects = plan_objects(&single_node_ocsf());
    let weird = select_grant("nanosiem", "bad`name; DROP");
    assert!(revoke_statements("nanosiem", "", &objects, &[weird]).is_err());
    let mut weird_type = select_grant("nanosiem", "t");
    weird_type.access_type = "SELECT; DROP".into();
    assert!(revoke_statements("nanosiem", "", &objects, &[weird_type]).is_err());
}

#[test]
fn on_cluster_clause_escapes_the_cluster_name() {
    assert_eq!(on_cluster_clause(None), "");
    assert_eq!(on_cluster_clause(Some("nanosiem_cluster")), " ON CLUSTER 'nanosiem_cluster'");
    assert_eq!(on_cluster_clause(Some("a'b")), " ON CLUSTER 'a''b'");
}

#[test]
fn candidate_names_cover_every_suffix() {
    let names = candidate_table_names();
    assert_eq!(names.len(), AGENTLANE_TABLES.len() * 3);
    assert!(names.contains(&"logs_local".to_string()));
    assert!(names.contains(&"ip_prevalence_source_summary_distributed".to_string()));
}

#[test]
fn existing_installs_converge_on_distributed_product_mode_through_alter() {
    // The ALTER carries the full settings list, so an install whose profile
    // predates the pin picks it up on the next migrator run.
    let [_, alter] = profile_statements("", &AgentlaneSettings::default());
    assert!(alter.starts_with("ALTER SETTINGS PROFILE agentlane SETTINGS "));
    assert!(alter.contains("distributed_product_mode = 'global' CONST"));
    assert_eq!(alter.matches("distributed_product_mode").count(), 1);
}

#[test]
fn workload_thread_cap_defaults_to_two_and_is_configurable() {
    let defaults = agentlane_settings_from_env(AgentlaneEnv::default()).unwrap();
    assert_eq!(defaults.max_concurrent_threads, 2);
    assert!(workload("", defaults.max_concurrent_threads)
        .contains("SETTINGS weight = 1, priority = 10, max_concurrent_threads = 2,"));

    let raised = agentlane_settings_from_env(env(None, None, Some(" 8 "))).unwrap();
    assert_eq!(raised.max_concurrent_threads, 8);
    assert_eq!(raised.max_rows_to_read, DEFAULT_MAX_ROWS_TO_READ);
    assert_eq!(
        workload(" ON CLUSTER 'c1'", raised.max_concurrent_threads),
        "CREATE OR REPLACE WORKLOAD agentlane ON CLUSTER 'c1' IN nano \
         SETTINGS weight = 1, priority = 10, max_concurrent_threads = 8, \
         max_memory = 1073741824"
    );
    for ok in ["1", "256"] {
        assert!(agentlane_settings_from_env(env(None, None, Some(ok))).is_ok(), "{ok}");
    }
    // 0 would mean "no cap" to ClickHouse; junk and a runaway value are refused.
    for bad in ["0", "-1", "2.5", "four", "257", "4000"] {
        let err = agentlane_settings_from_env(env(None, None, Some(bad))).unwrap_err();
        assert!(err.to_string().contains("NANO_AGENTLANE_MAX_CONCURRENT_THREADS"), "{bad}: {err}");
    }
}

#[test]
fn the_workload_is_replaced_in_place_never_dropped() {
    let sql = workload("", 4);
    assert!(sql.starts_with("CREATE OR REPLACE WORKLOAD agentlane "));
    assert!(!sql.to_uppercase().contains("DROP"));
}

#[test]
fn workload_memory_cap_comes_from_env() {
    let defaults = agentlane_settings_from_env(AgentlaneEnv::default()).unwrap();
    assert_eq!(defaults.workload_max_memory, None, "unset derives from the server");

    let set = agentlane_settings_from_env(AgentlaneEnv {
        workload_max_memory: Some("17179869184"),
        ..AgentlaneEnv::default()
    })
    .unwrap();
    assert_eq!(set.workload_max_memory, Some(17_179_869_184));
    assert_eq!(
        agentlane_settings_from_env(AgentlaneEnv {
            workload_max_memory: Some("  "),
            ..AgentlaneEnv::default()
        })
        .unwrap()
        .workload_max_memory,
        None
    );

    // 0 means "no limit" to ClickHouse; junk and out-of-range are refused.
    for bad in ["0", "-1", "1e9", "lots", "1000", "2199023255552"] {
        let err = agentlane_settings_from_env(AgentlaneEnv {
            workload_max_memory: Some(bad),
            ..AgentlaneEnv::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("NANO_AGENTLANE_WORKLOAD_MAX_MEMORY"), "{bad}: {err}");
    }
}

#[test]
fn derived_workload_memory_is_a_quarter_of_the_server_with_floors() {
    const GIB: u64 = 1 << 30;
    assert_eq!(derived_workload_max_memory(64 * GIB), 16 * GIB);
    assert_eq!(derived_workload_max_memory(3 * GIB + GIB / 4), 832 * 1024 * 1024);
    assert_eq!(derived_workload_max_memory(GIB), 512 * 1024 * 1024, "floor");
    assert_eq!(derived_workload_max_memory(0), 4 * GIB, "unknown server limit");
}

#[test]
fn workload_memory_needs_its_resource_and_never_limits_queries() {
    assert_eq!(
        resource_statements(" ON CLUSTER 'c1'"),
        [
            "CREATE RESOURCE IF NOT EXISTS memory ON CLUSTER 'c1' (MEMORY RESERVATION)".to_string(),
            "DROP RESOURCE IF EXISTS query ON CLUSTER 'c1'".to_string(),
        ]
    );
    for sql in resource_statements("") {
        assert!(!sql.contains("OR REPLACE") && !sql.contains("ON CLUSTER"), "{sql}");
    }
    // A workload query-slot cap deadlocks cross-node queries (shard hops take
    // a slot on the remote node): it must never come back.
    let sql = workload_statement("", 2, 6 << 30);
    assert!(sql.ends_with("max_concurrent_threads = 2, max_memory = 6442450944"), "{sql}");
    assert!(!sql.contains("max_concurrent_queries"), "{sql}");
    assert!(!sql.contains("max_waiting_queries"), "{sql}");
}

#[test]
fn agent_queries_are_the_first_overcommit_victims() {
    let sql = profile_settings_sql(&AgentlaneSettings::default());
    assert!(sql.contains("memory_overcommit_ratio_denominator = 1048576 CONST"), "{sql}");
    assert!(sql.contains("memory_overcommit_ratio_denominator_for_user = 1048576 CONST"), "{sql}");
    // Far below the 1 GiB server default every other profile uses.
    assert!(OVERCOMMIT_RATIO_DENOMINATOR * 1024 <= 1 << 30);
    // Per-token concurrency refuses (202) instead of queueing.
    assert!(sql.contains("max_concurrent_queries_for_user = 2 CONST"));
}

#[test]
fn only_token_users_keep_the_role() {
    for ok in ["agentlane_abc123", "agentlane_0"] {
        assert!(is_token_user(ok), "{ok}");
    }
    for bad in ["agentlane_", "agentlane_ABC", "agentlane_a-b", "nanosiem", "nanosiem_agentlane_audit", "xagentlane_a"] {
        assert!(!is_token_user(bad), "{bad}");
    }
    let member = |user: Option<&str>, role: Option<&str>, admin: u8| ObservedMembership {
        user_name: user.map(str::to_string),
        role_name: role.map(str::to_string),
        with_admin_option: admin,
    };
    let observed = vec![
        member(Some("agentlane_tok1"), None, 0),
        member(Some("agentlane_tok2"), None, 1),
        member(Some("nanosiem"), None, 0),
        member(Some("nanosiem_agentlane_audit"), None, 0),
        member(None, Some("analyst_role"), 0),
        member(Some("nanosiem"), None, 0),
    ];
    assert_eq!(
        membership_revoke_statements(" ON CLUSTER 'c1'", &observed).unwrap(),
        vec![
            "REVOKE ON CLUSTER 'c1' ADMIN OPTION FOR agentlane_reader FROM agentlane_tok2",
            "REVOKE ON CLUSTER 'c1' agentlane_reader FROM analyst_role",
            "REVOKE ON CLUSTER 'c1' agentlane_reader FROM nanosiem",
            "REVOKE ON CLUSTER 'c1' agentlane_reader FROM nanosiem_agentlane_audit",
        ]
    );
    assert!(membership_revoke_statements("", &[member(Some("bad`user"), None, 0)]).is_err());
}

#[test]
fn per_node_reads_use_remote_with_the_password_escaped_and_redacted() {
    assert_eq!(node_source("grants", None, "admin", "pw"), "system.grants");
    assert_eq!(
        node_source("role_grants", Some(("ch-2", 9000)), "nanosiem_admin", "fa'ke"),
        "remote('ch-2:9000', system.role_grants, 'nanosiem_admin', 'fa''ke')"
    );
    assert!(node_source("grants", Some(("ch-2", 9440)), "a", "b").starts_with("remoteSecure("));
    assert_eq!(redact("auth failed for s3cr3t", "s3cr3t"), "auth failed for [HIDDEN]");
    assert_eq!(redact("nothing", ""), "nothing");
    let creds = NodeCredentials { user: "u", password: "s3cr3t" };
    assert!(!format!("{creds:?}").contains("s3cr3t"));
}

#[test]
fn per_token_memory_budget_is_shared_and_never_unlimited() {
    const GIB: u64 = 1 << 30;
    let defaults = agentlane_settings_from_env(AgentlaneEnv::default()).unwrap();
    assert_eq!(defaults.max_memory_per_token, None, "unset derives from the server");
    assert!(profile_settings_sql(&defaults).contains("max_memory_usage_for_user = 4294967296 CONST"));
    assert_eq!(derived_max_memory_per_token(64 * GIB), 4 * GIB, "the per-query cap on big nodes");
    assert_eq!(derived_max_memory_per_token(3 * GIB + GIB / 5), (3 * GIB + GIB / 5) / 4, "a quarter on small nodes");
    assert_eq!(derived_max_memory_per_token(512 << 20), 256 << 20, "floor");
    assert_eq!(derived_max_memory_per_token(0), 4 * GIB, "unknown server limit");
    let set = agentlane_settings_from_env(AgentlaneEnv {
        max_memory_per_token: Some("2147483648"),
        ..AgentlaneEnv::default()
    })
    .unwrap();
    assert!(profile_settings_sql(&set).contains("max_memory_usage_for_user = 2147483648 CONST"));
    for bad in ["0", "-1", "1e9", "x", "1000", "2199023255552"] {
        let err = agentlane_settings_from_env(AgentlaneEnv {
            max_memory_per_token: Some(bad),
            ..AgentlaneEnv::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("NANO_AGENTLANE_MAX_MEMORY_PER_TOKEN"), "{bad}: {err}");
    }
}

/// P5 regression: ClickHouse resets `max_result_rows` to 0 for subqueries on
/// shard hops and the shard clamps it to the profile's constraints, so a
/// `MIN 1` broke every multi-row subquery across `_distributed`. With no MIN a
/// caller may lower it to 0, but the bytes cap and `throw` stay CONST.
#[test]
fn max_result_rows_can_reach_zero_but_bytes_still_bound_the_result() {
    let sql = profile_settings_sql(&AgentlaneSettings::default());
    let rows = sql.split(", ").find(|p| p.starts_with("max_result_rows = ")).unwrap();
    assert_eq!(rows, "max_result_rows = 100000 MAX 100000 CHANGEABLE_IN_READONLY");
    let bytes = sql.split(", ").find(|p| p.starts_with("max_result_bytes = ")).unwrap();
    assert_eq!(bytes, "max_result_bytes = 67108864 CONST");
    assert!(sql.contains("readonly = 1 CONST"));
    assert!(sql.contains("result_overflow_mode = 'throw' CONST"));
    let time = sql.split(", ").find(|p| p.starts_with("max_execution_time = ")).unwrap();
    assert_eq!(time, "max_execution_time = 60 MIN 1 MAX 60 CHANGEABLE_IN_READONLY");
}
