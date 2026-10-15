// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

// Keep resource arrays intact while grouping: expanding them would multiply
// totals and every scalar facet, and drop events with no resources.
const CLOUD_SUMMARY_FIELDS: &[&str] = &[
    "cloud.provider",
    "api.service.name",
    "cloud.region",
    "cloud.account.uid",
    "activity_name",
    "resources.type",
];
pub(super) const CLOUD_SUMMARY_GROUP_CAP: usize = 50_000;

impl SearchService {
    pub fn lake_cloud_correlated_summary_query(filtered: &str) -> String {
        format!(
            "{filtered} | stats count() as event_count by {}",
            CLOUD_SUMMARY_FIELDS.join(",")
        )
    }

    /// Fold complete correlated groups; never use a truncated group page.
    pub fn assemble_lake_cloud_correlated_summary(rows: &[Value]) -> (u64, CloudFacets) {
        let mut total = 0_u64;
        let mut counts: [BTreeMap<String, u64>; 6] = Default::default();
        for row in rows {
            let count = cloud_u64(row, "event_count").unwrap_or_default();
            total += count;
            for (index, field) in CLOUD_SUMMARY_FIELDS.iter().enumerate() {
                if index == 5 {
                    // mvexpand counts each occurrence, including duplicate types.
                    if let Some(values) = cloud_value(row, field).and_then(Value::as_array) {
                        for value in values
                            .iter()
                            .filter_map(Value::as_str)
                            .filter(|v| !v.is_empty())
                        {
                            *counts[index].entry(value.to_owned()).or_default() += count;
                        }
                    }
                } else if let Some(value) = cloud_string(row, field).filter(|v| !v.is_empty()) {
                    *counts[index].entry(value).or_default() += count;
                }
            }
        }
        let [provider, service, region, account, change, resource] =
            counts.map(|counts| ranked_counts(&counts, 20));
        (
            total,
            CloudFacets {
                cloud_provider: provider,
                cloud_service: service,
                cloud_region: region,
                cloud_account_id: account,
                resource_type: resource,
                change_type: change,
            },
        )
    }
}

impl SearchService {
    // Exact product counts must never inherit mvexpand's preview-row cap.
    // Native time/scan/memory budgets still refuse work that cannot complete.
    pub fn lake_cloud_events_summary_queries(
        filtered: &str,
    ) -> crate::search::DurableCloudEventsSummaryQueries {
        let grouped = |field: &str| {
            format!(
                "{filtered} | where {field}!=\"\" | stats count() as event_count by {field} | sort -event_count | head 20"
            )
        };
        crate::search::DurableCloudEventsSummaryQueries {
            total: format!("{filtered} | stats count() as event_count"),
            providers: grouped("cloud.provider"),
            services: grouped("api.service.name"),
            regions: grouped("cloud.region"),
            accounts: grouped("cloud.account.uid"),
            resource_types: format!(
                "{filtered} | eval cloud_resource_type=resources.type | mvexpand cloud_resource_type limit={} | where cloud_resource_type!=\"\" | stats count() as event_count by cloud_resource_type | rename cloud_resource_type as resources.type | sort -event_count | head 20",
                usize::MAX
            ),
            change_types: grouped("activity_name"),
            resources: format!(
                "{filtered} | eval resource_pair=mvzip(resources.uid,resources.name,\"||\"), resource_tuple=mvzip(resource_pair,resources.type,\"||\") | mvexpand resource_tuple limit={} | eval resource_parts=split(resource_tuple,\"||\"), resource_id=mvindex(resource_parts,0), resource_name=mvindex(resource_parts,1), resource_type=mvindex(resource_parts,2) | where resource_id!=\"\" | stats count() as event_count, min(time) as first_seen, max(time) as last_seen, values(activity_name) as change_types by resource_id, resource_name, resource_type | sort -event_count | head 100",
                usize::MAX
            ),
            users: format!(
                "{filtered} | eval cloud_user=coalesce(actor.user.name,user.name) | where cloud_user!=\"\" | stats count() as event_count, dc(api.service.name) as distinct_services, dc(cloud.region) as distinct_regions, dc(src_endpoint.ip) as distinct_ips, count(eval(status_id=2 OR lower(status)=\"failure\" OR http_response.code>=400)) as fail_count, count(eval(activity_name contains \"permission\" OR activity_name contains \"privilege\")) as permission_change_count, count(eval(lower(activity_name)=\"delete\")) as delete_count, count(eval(is_mfa=true OR unmapped.mfa_authenticated=true)) as mfa_count by cloud_user | sort -event_count | head 100"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrays_do_not_multiply_scalar_facets_or_drop_empty_events() {
        let rows = vec![
            json!({"cloud.provider": "AWS", "api.service.name": "iam", "resources.type": ["Role", "Role", ""], "event_count": 3}),
            json!({"cloud.provider": "AWS", "api.service.name": "s3", "resources.type": [], "event_count": 5}),
            json!({"cloud.provider": null, "resources.type": null, "event_count": 2}),
        ];
        let (total, facets) = SearchService::assemble_lake_cloud_correlated_summary(&rows);
        assert_eq!(total, 10);
        assert_eq!(facets.cloud_provider, vec![("AWS".into(), 8)]);
        assert_eq!(
            facets.cloud_service,
            vec![("s3".into(), 5), ("iam".into(), 3)]
        );
        assert_eq!(facets.resource_type, vec![("Role".into(), 6)]);
    }

    #[test]
    fn complete_groups_are_folded_before_top_twenty() {
        let rows: Vec<_> = (0..30)
            .flat_map(|i| {
                [
                    json!({"cloud.provider": format!("p{i:02}"), "event_count": 1}),
                    json!({"cloud.provider": format!("p{i:02}"), "event_count": 2}),
                ]
            })
            .collect();
        let (total, facets) = SearchService::assemble_lake_cloud_correlated_summary(&rows);
        assert_eq!(total, 90);
        assert_eq!(facets.cloud_provider.len(), 20);
        assert_eq!(facets.cloud_provider[0], ("p00".into(), 3));
        assert_eq!(facets.cloud_provider[19], ("p19".into(), 3));
        assert_eq!(
            SearchService::assemble_lake_cloud_correlated_summary(&[]).0,
            0
        );
    }

    #[test]
    fn correlated_plan_keeps_resources_as_one_array_per_event() {
        let query = SearchService::lake_cloud_correlated_summary_query(
            "class_uid=6003 AND cloud.account.uid=\"100\"",
        );
        let parsed = crate::query::parse_query(&query).unwrap();
        crate::search::service::validate_query_field_names(
            &parsed,
            &crate::schema::OcsfProfile::lake_1_9(),
        )
        .unwrap();
        assert!(!query.contains("mvexpand"));
        assert!(!query.contains("head"));
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn summary_uses_one_scoped_read_and_refuses_truncated_groups() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path},
        };
        let server = MockServer::start().await;
        let tenant = uuid::Uuid::new_v4();
        let token_dir = tempfile::tempdir().unwrap();
        let token_file = token_dir.path().join("router.token");
        let token = "cloud-summary-fixture-token-1234567890";
        std::fs::write(&token_file, token).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let pool =
            crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
                "postgres://unused:unused@127.0.0.1:1/nanosiem",
                "http://127.0.0.1:1",
                "nanosiem",
                "unused",
                "nanosiem",
            ))
            .await
            .unwrap();
        let route = crate::search::LakeCellRoute {
            tenant_id: tenant,
            assignment_generation: 1,
            part_log_writer_epoch: 1,
            worker_revision: 1,
            assignment_fenced: true,
            cell_origin: server.uri(),
            query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()),
            router_token_file: token_file,
        };
        let service = SearchService::with_dual_pool(&pool)
            .enterprise_shared_cell_tenant_view(
                &route,
                crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0)
                    .unwrap(),
                std::sync::Arc::new(crate::search::InMemoryJobStore::new()),
            )
            .unwrap();
        let end = chrono::DateTime::parse_from_rfc3339("2026-09-30T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let range = TimeRange::new(end - chrono::Duration::days(7), end);
        let scope = ScopeSet::from_denied(["hidden-source".to_string()].into());
        for (has_more, returned) in [(false, 1), (true, 1), (false, CLOUD_SUMMARY_GROUP_CAP)] {
            Mock::given(method("POST"))
                .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
                .and(header("authorization", format!("Bearer {token}").as_str()))
                .respond_with(move |request: &wiremock::Request| {
                    let body: Value = serde_json::from_slice(&request.body).unwrap();
                    assert_eq!(body["tenant_id"], tenant.to_string());
                    assert_eq!(body["deny_source_types"], json!(["hidden-source"]));
                    assert_eq!(body["limit"], CLOUD_SUMMARY_GROUP_CAP);
                    assert!(body["query"].as_str().unwrap().contains("by cloud.provider,"));
                    ResponseTemplate::new(200).set_body_json(json!({
                        "ok": true, "request_id": body["request_id"], "tenant_id": tenant, "route": "broad_npl", "source_mode": "parts",
                        "result": {"result_rows": returned, "rows": [{"cloud.provider": "AWS", "event_count": 9}], "page_has_more": has_more},
                    }))
                }).expect(1).mount(&server).await;
            let result = service
                .query_lake_cloud_events_summary("class_uid=6003", &range, None, &scope, has_more)
                .await;
            if has_more || returned == CLOUD_SUMMARY_GROUP_CAP {
                assert!(matches!(result, Err(SearchError::ResourceExhausted(_))));
            } else {
                let (total, facets, resources, users) = result.unwrap();
                assert_eq!(total, 9);
                assert_eq!(facets.cloud_provider, vec![("AWS".into(), 9)]);
                assert!(resources.is_none() && users.is_none());
            }
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
            server.reset().await;
        }
    }
}
