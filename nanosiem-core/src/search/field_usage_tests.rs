// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `search::field_usage`.

use super::*;

fn row(user: Uuid, query: &str, hours_ago: i64, now: DateTime<Utc>) -> FieldUsageRow {
    FieldUsageRow { user_id: user, query: query.into(), created_at: now - chrono::Duration::hours(hours_ago) }
}

#[test]
fn extracts_filter_and_command_fields_in_order() {
    let fields = extract_query_fields(
        r#"metadata.log_source="aws_cloudtrail" src_endpoint.ip=10.0.0.1 | where actor.user.name="root" | stats count by dst_endpoint.ip | sort -count"#,
    );
    assert_eq!(fields, vec!["metadata.log_source", "src_endpoint.ip", "actor.user.name", "dst_endpoint.ip"]);
}

#[test]
fn never_reports_values_keywords_or_derived_names() {
    let q = r#"powershell "secret-token" user="alice@corp.example" src_ip IN ("10.1.1.1", "10.2.2.2") | eval risky=1 | rename user AS who | stats count AS hits by who, risky | table hits, who"#;
    let fields = extract_query_fields(q);
    assert_eq!(fields, vec!["user", "src_ip"]);
    for leaked in ["powershell", "secret-token", "alice@corp.example", "10.1.1.1", "risky", "who", "hits"] {
        assert!(!fields.iter().any(|f| f == leaked), "{leaked} leaked: {fields:?}");
    }
}

#[test]
fn unparseable_or_empty_queries_yield_nothing() {
    assert!(extract_query_fields("").is_empty());
    assert!(extract_query_fields("| | |").is_empty());
    assert!(extract_query_fields(&"a".repeat(MAX_QUERY_LEN + 1)).is_empty());
}

#[test]
fn recent_is_the_callers_own_recency_weighted_fields() {
    let now = Utc::now();
    let me = Uuid::new_v4();
    let other = Uuid::new_v4();
    let user_rows = vec![
        row(me, "src_endpoint.ip=1.2.3.4", 1, now),
        row(me, "user=bob", 24 * 60, now),
        row(me, "user=carol", 24 * 61, now),
        // A row for someone else must never count toward my Recent.
        row(other, "process.name=cmd.exe", 0, now),
    ];
    let usage = rank_field_usage(me, &user_rows, &[], now);
    assert_eq!(usage.recent.first().map(String::as_str), Some("src_endpoint.ip"));
    assert!(usage.recent.contains(&"user".to_string()));
    assert!(!usage.recent.contains(&"process.name".to_string()));
}

#[test]
fn recent_ignores_history_outside_the_window() {
    let now = Utc::now();
    let me = Uuid::new_v4();
    let rows = vec![row(me, "file.path=x", 24 * (HISTORY_WINDOW_DAYS + 1), now)];
    assert!(rank_field_usage(me, &rows, &rows, now).recent.is_empty());
}

#[test]
fn popular_needs_three_distinct_users_and_caps_one_heavy_user() {
    let now = Utc::now();
    let me = Uuid::new_v4();
    let users: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();
    let mut workspace = Vec::new();
    // src_ip: 4 users. dest_ip: 3 users. hostname: 2 users (below the bar).
    for (i, u) in users.iter().enumerate() {
        workspace.push(row(*u, "src_ip=1.2.3.4", i as i64, now));
        if i < 3 {
            workspace.push(row(*u, "dest_ip=8.8.8.8", i as i64, now));
        }
        if i < 2 {
            workspace.push(row(*u, "hostname=web01", i as i64, now));
        }
    }
    // One heavy user hammering a public field still counts as one user.
    for i in 0..50 {
        workspace.push(row(users[0], "process_name=cmd.exe", i, now));
    }
    let usage = rank_field_usage(me, &[], &workspace, now);
    assert_eq!(usage.popular, vec!["src_ip".to_string(), "dest_ip".to_string()], "{:?}", usage.popular);
    assert!(usage.recent.is_empty());
}

/// Review P2-5: custom / dynamic names never cross users, whatever the count;
/// they stay in their author's own Recent.
#[test]
fn custom_and_ext_fields_never_appear_in_popular() {
    let now = Utc::now();
    let me = Uuid::new_v4();
    let users: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();
    let workspace: Vec<_> = users
        .iter()
        .flat_map(|u| {
            [
                row(*u, "ext.project_merger_codename=x", 1, now),
                row(*u, "acme_custom_field=1", 1, now),
                row(*u, "src_ip=10.0.0.1", 1, now),
            ]
        })
        .collect();
    let usage = rank_field_usage(me, &[], &workspace, now);
    assert_eq!(usage.popular, vec!["src_ip".to_string()]);

    let mine = vec![row(me, "ext.project_merger_codename=x", 1, now)];
    assert_eq!(rank_field_usage(me, &mine, &[], now).recent, vec!["ext.project_merger_codename".to_string()]);
    assert!(is_public_schema_field("src_ip") && is_public_schema_field("dst_endpoint.ip"));
    assert!(!is_public_schema_field("ext.src_ip") && !is_public_schema_field("acme_custom_field"));
}

#[test]
fn cache_is_keyed_by_user_and_expires() {
    let cache = FieldUsageCache::new(Duration::from_secs(60));
    let (user, other) = (Uuid::new_v4(), Uuid::new_v4());
    let computed = SearchFieldUsage { recent: vec!["mine".into()], popular: vec!["shared_field".into()] };
    let served = cache.fill(user, CachedFieldUsage::default(), computed.clone());
    assert_eq!(served, computed);
    assert_eq!(cache.lookup(user).complete(), Some(computed));

    // Another user shares Popular but never sees my Recent.
    let peer = cache.lookup(other);
    assert_eq!(peer.popular, Some(vec!["shared_field".to_string()]));
    assert!(peer.needs_user_rows() && !peer.needs_workspace_rows());

    // A cached part beats the empty placeholder of an unread group.
    let merged = cache.fill(other, peer, SearchFieldUsage { recent: vec!["x".into()], popular: vec![] });
    assert_eq!(merged.popular, vec!["shared_field".to_string()]);
    assert_eq!(cache.lookup(other).recent, Some(vec!["x".to_string()]));
    assert_eq!(cache.lookup(user).recent, Some(vec!["mine".to_string()]));

    cache.invalidate(user);
    let after = cache.lookup(user);
    assert!(after.needs_user_rows() && !after.needs_workspace_rows());

    let expired = FieldUsageCache::new(Duration::ZERO);
    expired.fill(user, CachedFieldUsage::default(), SearchFieldUsage::default());
    assert_eq!(expired.lookup(user), CachedFieldUsage::default());
}
