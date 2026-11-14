// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::collections::HashSet;

fn observed(ordinal: u32, policy: &DesiredRowPolicy, filter: &str) -> ObservedRowPolicy {
    ObservedRowPolicy {
        ordinal,
        short_name: policy.short_name.clone(),
        select_filter: filter.to_string(),
        is_restrictive: u8::from(policy.restrictive),
        apply_to_all: 0,
        apply_to_list: vec![RAWSQL_NOAUDIT_ROLE.to_string()],
        apply_to_except: Vec::new(),
    }
}

fn current_on(ordinal: u32, desired: &[DesiredRowPolicy; 2]) -> Vec<ObservedRowPolicy> {
    desired
        .iter()
        .map(|policy| observed(ordinal, policy, &policy.filter))
        .collect()
}

#[test]
fn specs_match_the_historical_policy_pair() {
    let [baseline, hide] = rawsql_policy_specs("logs", "source_type");
    assert_eq!(baseline.short_name, "rawsql_baseline_logs");
    assert_eq!(baseline.filter, "1");
    assert!(!baseline.restrictive);
    assert_eq!(hide.short_name, "rawsql_hide_audit_logs");
    assert_eq!(hide.filter, "lower(source_type) != 'audit'");
    assert!(hide.restrictive);
}

#[test]
fn reformatted_filters_still_count_as_current() {
    assert_eq!(
        normalize_policy_filter("lower(`source_type`) <> 'audit'"),
        normalize_policy_filter("lower(source_type) != 'audit'")
    );
    let desired = rawsql_policy_specs("logs", "source_type");
    let rows = vec![
        observed(1, &desired[0], "1"),
        observed(1, &desired[1], "lower(source_type)  !=  'audit'"),
    ];
    assert!(row_policies_match(&desired, &rows));
}

#[test]
fn missing_or_drifted_policies_are_reissued() {
    let desired = rawsql_policy_specs("logs", "source_type");

    // Missing hide-audit policy.
    assert!(!row_policies_match(&desired, &current_on(1, &desired)[..1]));

    // Wrong filter column (the silent-leak class the per-table column guards).
    let mut wrong_column = current_on(1, &desired);
    wrong_column[1].select_filter = "lower(source) != 'audit'".to_string();
    assert!(!row_policies_match(&desired, &wrong_column));

    // PERMISSIVE instead of RESTRICTIVE.
    let mut permissive = current_on(1, &desired);
    permissive[1].is_restrictive = 0;
    assert!(!row_policies_match(&desired, &permissive));

    // Applied to the wrong role set.
    let mut everyone = current_on(1, &desired);
    everyone[1].apply_to_all = 1;
    assert!(!row_policies_match(&desired, &everyone));
    let mut other_role = current_on(1, &desired);
    other_role[1].apply_to_list = vec!["nanosiem".to_string()];
    assert!(!row_policies_match(&desired, &other_role));
}

#[test]
fn every_reachable_replica_must_hold_the_policies() {
    let desired = rawsql_policy_specs("signals", "source_type");
    let reachable: HashSet<u32> = [1, 2, 3].into_iter().collect();

    let mut rows = current_on(1, &desired);
    rows.extend(current_on(2, &desired));
    // Replica 3 answered but has only the baseline.
    rows.push(observed(3, &desired[0], "1"));
    assert!(!row_policies_match_on_replicas(&desired, &rows, &reachable));

    rows.extend(current_on(3, &desired));
    assert!(row_policies_match_on_replicas(&desired, &rows, &reachable));

    // Rows from an unreachable replica are irrelevant; no reachable set means
    // no evidence.
    assert!(!row_policies_match_on_replicas(&desired, &rows, &HashSet::new()));
}

#[test]
fn policy_lookup_is_scoped_to_the_physical_table() {
    let desired = rawsql_policy_specs("logs", "source_type");
    assert_eq!(
        rawsql_policy_filter_sql("nanosiem", "logs_local", &desired),
        "database = 'nanosiem' AND \"table\" = 'logs_local' AND short_name IN ('rawsql_baseline_logs', 'rawsql_hide_audit_logs')"
    );
}

#[test]
fn policies_reissue_without_blocking_only_when_a_replica_is_down() {
    assert!(rawsql_policy_ddl_options(false, false).is_empty());
    assert!(rawsql_policy_ddl_options(true, true).is_empty());
    assert_eq!(
        rawsql_policy_ddl_options(true, false),
        &[
            ("distributed_ddl_output_mode", "null_status_on_timeout"),
            ("distributed_ddl_task_timeout", "15"),
        ]
    );
}

// ---- NAN-5404: SQL users follow the app user's networks ----

fn hosts(name: &str, storage: &str, ips: &[&str], names: &[&str]) -> UserHosts {
    UserHosts {
        name: name.into(),
        storage: storage.into(),
        host_ip: ips.iter().map(|s| s.to_string()).collect(),
        host_names: names.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

#[test]
fn nan5404_sql_users_copy_the_app_users_networks() {
    let app = hosts(APP_CH_USER, "users_xml", &["172.16.0.0/12", "192.168.0.0/16"], &["localhost"]);
    assert_eq!(
        host_clause_from_app(&app).as_deref(),
        Some("IP '172.16.0.0/12', IP '192.168.0.0/16', LOCAL")
    );
    // An older private-range user is narrowed to the app's list ...
    let wide = hosts("nanosiem_rawsql", "local_directory", &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], &["localhost"]);
    assert_eq!(sql_user_host_fix(&wide, Some(&app)).as_deref(), Some("IP '172.16.0.0/12', IP '192.168.0.0/16', LOCAL"));
    // ... one already in line is left alone, and so is a users.xml user.
    let same = hosts("nanosiem_rawsql", "local_directory", &["192.168.0.0/16", "172.16.0.0/12"], &["localhost"]);
    assert_eq!(sql_user_host_fix(&same, Some(&app)), None);
    // Narrow only: already inside the app's list (another node's) is kept.
    let narrower = hosts("nanosiem_rawsql", "local_directory", &["172.16.0.0/12"], &["localhost"]);
    assert_eq!(sql_user_host_fix(&narrower, Some(&app)), None);
    assert_eq!(sql_user_host_fix(&hosts("x", "users_xml", &["::/0"], &[]), Some(&app)), None);
}

#[test]
fn nan5404_legacy_app_user_falls_back_to_private_ranges_for_open_users_only() {
    let legacy = hosts(APP_CH_USER, "users_xml", &["::/0"], &[]);
    assert_eq!(host_clause_from_app(&legacy), None);
    let open = hosts("nanosiem_rawsql", "local_directory", &["::/0"], &[]);
    assert_eq!(sql_user_host_fix(&open, Some(&legacy)).as_deref(), Some(SQL_USER_HOST_CLAUSE));
    assert_eq!(sql_user_host_fix(&open, None).as_deref(), Some(SQL_USER_HOST_CLAUSE));
    let private = hosts("nanosiem_rawsql", "local_directory", &["10.0.0.0/8"], &["localhost"]);
    assert_eq!(sql_user_host_fix(&private, Some(&legacy)), None);
    // A value that is not a plain address is never spliced into SQL.
    let odd = hosts(APP_CH_USER, "users_xml", &["10.0.0.0/8' OR 1"], &[]);
    assert_eq!(host_clause_from_app(&odd), None);
    let mut rx = hosts(APP_CH_USER, "users_xml", &["10.0.0.0/8"], &[]);
    rx.host_names_regexp = vec![".*".into()];
    assert_eq!(host_clause_from_app(&rx), None);
}
