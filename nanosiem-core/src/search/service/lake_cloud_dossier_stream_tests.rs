// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3078: the streaming [`CloudDossierAccumulator`] must produce exactly
//! what the pre-streaming multi-pass assembler produced. The reference below
//! is that assembler verbatim (origin/main before NAN-3078).

use super::*;

#[allow(clippy::too_many_lines)]
pub(super) fn reference_assemble_lake_cloud_dossier(
    principal: &str,
    rows: Vec<Value>,
    facet_filters: &CloudDossierFacetFilters,
    time_range: &TimeRange,
    risk_summary: Option<(i32, Option<String>)>,
) -> CloudDossier {
    let rows = rows
        .into_iter()
        .filter(|row| cloud_rows_match_dossier_filters(row, facet_filters))
        .collect::<Vec<_>>();

    let first_seen = rows
        .iter()
        .map(cloud_time)
        .filter(|value| !value.is_empty())
        .min();
    let last_seen = rows
        .iter()
        .map(cloud_time)
        .filter(|value| !value.is_empty())
        .max();
    let first_row = rows.first();
    let account = first_row
        .map(|row| cloud_account(row))
        .filter(|value| !value.is_empty());
    let arn = first_row
        .and_then(|row| cloud_string(row, "actor.user.uid"))
        .filter(|value| !value.is_empty());

    let user_agents = ranked(
        rows.iter()
            .filter_map(|row| cloud_string(row, "http_request.user_agent")),
        10,
    )
    .into_iter()
    .map(|(ua, count)| {
        let lower = ua.to_ascii_lowercase();
        let kind = if lower.contains("terraform") {
            "terraform"
        } else if lower.contains("aws-cli")
            || lower.contains("gcloud")
            || lower.contains("azure-cli")
        {
            "cli"
        } else if lower.contains("sdk") || lower.contains("boto") {
            "sdk"
        } else if lower.contains("mozilla")
            || lower.contains("chrome")
            || lower.contains("safari")
        {
            "browser"
        } else {
            "other"
        };
        CloudDossierUserAgent {
            ua,
            kind: kind.to_string(),
            count,
        }
    })
    .collect::<Vec<_>>();

    #[derive(Default)]
    struct IpRollup {
        count: u64,
        first: String,
        last: String,
    }
    let mut ip_rollups = BTreeMap::<String, IpRollup>::new();
    for row in &rows {
        let Some(ip) = cloud_string(row, "src_endpoint.ip").filter(|value| !value.is_empty())
        else {
            continue;
        };
        let timestamp = cloud_time(row);
        let rollup = ip_rollups.entry(ip).or_default();
        rollup.count += 1;
        if rollup.first.is_empty() || timestamp < rollup.first {
            rollup.first = timestamp.clone();
        }
        if timestamp > rollup.last {
            rollup.last = timestamp;
        }
    }
    let mut ips = ip_rollups.into_iter().collect::<Vec<_>>();
    ips.sort_by(|left, right| right.1.count.cmp(&left.1.count));
    let ips = ips
        .into_iter()
        .take(20)
        .map(|(ip, rollup)| CloudDossierIp {
            ip,
            first_seen: Some(rollup.first).filter(|value| !value.is_empty()),
            last_seen: Some(rollup.last).filter(|value| !value.is_empty()),
            event_count: rollup.count,
            ..Default::default()
        })
        .collect::<Vec<_>>();

    let mfa_values = rows.iter().map(cloud_mfa).collect::<Vec<_>>();
    let mfa = (!mfa_values.is_empty()).then(|| mfa_values.iter().all(|value| *value));
    let console = rows.iter().any(|row| {
        let operation = cloud_operation(row).to_ascii_lowercase();
        operation.contains("consolelogin")
            || cloud_string(row, "http_request.user_agent")
                .is_some_and(|value| value.to_ascii_lowercase().contains("mozilla"))
    });
    let assumed_roles = rows
        .iter()
        .filter(|row| cloud_operation(row).eq_ignore_ascii_case("AssumeRole"))
        .flat_map(|row| cloud_resources(row))
        .filter_map(|resource| {
            resource
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let identity = CloudDossierIdentity {
        id: principal.to_string(),
        principal_type: cloud_principal_type(principal, first_row),
        arn,
        account: account.clone(),
        first_seen: first_seen.clone(),
        last_seen: last_seen.clone(),
        mfa,
        console,
        api_only: !console,
        assumed_roles,
        user_agents,
        ips: ips.clone(),
        ..Default::default()
    };

    let risk_score = risk_summary
        .as_ref()
        .map(|(score, _)| score.max(&0).to_owned() as u32)
        .unwrap_or(0)
        .min(100);
    let risk = CloudDossierRisk {
        score: risk_score,
        band: lake_cloud_band(risk_score),
        factors: risk_summary
            .and_then(|(_, rule)| rule)
            .map(|rule| {
                vec![CloudDossierRiskFactor {
                    w: risk_score,
                    label: rule,
                    detail: "latest matching detection".to_string(),
                }]
            })
            .unwrap_or_default(),
        ..Default::default()
    };

    let facets = CloudDossierFacets {
        provider: lake_cloud_facet(rows.iter().map(cloud_provider)),
        service: lake_cloud_facet(rows.iter().map(cloud_service)),
        region: lake_cloud_facet(rows.iter().map(cloud_region)),
        account: lake_cloud_facet(rows.iter().map(cloud_account)),
        resource_type: lake_cloud_facet(rows.iter().flat_map(|row| {
            cloud_resources(row).filter_map(|resource| {
                resource
                    .get("type")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
        })),
        change_type: lake_cloud_facet(rows.iter().map(cloud_change_type)),
    };

    let assume_rows = rows
        .iter()
        .filter(|row| cloud_operation(row).eq_ignore_ascii_case("AssumeRole"))
        .collect::<Vec<_>>();
    let hops = assume_rows
        .iter()
        .take(12)
        .map(|row| CloudDossierAssumeHop {
            at: cloud_time(row),
            session_name: cloud_string(row, "session.uid").unwrap_or_default(),
            via: "sts:AssumeRole".to_string(),
            to_label: cloud_primary_resource(row, "name"),
            to_account: Some(cloud_account(row)).filter(|value| !value.is_empty()),
            calls: 1,
            sensitive: true,
            ..Default::default()
        })
        .collect::<Vec<_>>();
    let key_actions = rows
        .iter()
        .filter(|row| cloud_sensitive(row))
        .take(20)
        .map(|row| CloudDossierKeyAction {
            at: cloud_time(row),
            role: cloud_principal(row),
            action: cloud_operation(row),
            target: cloud_primary_resource(row, "name"),
            severity: if cloud_denied(row) { "high" } else { "medium" }.to_string(),
            detail: cloud_string(row, "message"),
        })
        .collect::<Vec<_>>();
    let assume_chain = CloudDossierAssumeChain {
        origin_label: principal.to_string(),
        origin_account: account.clone(),
        origin_ip: ips.first().map(|row| row.ip.clone()),
        origin_first_at: first_seen.clone(),
        hops,
        key_actions: key_actions.clone(),
        ..Default::default()
    };

    let service_rank = ranked(rows.iter().map(cloud_service), 5);
    let lanes = service_rank
        .iter()
        .map(|(service, _)| CloudDossierTimelineLane {
            id: service.clone(),
            label: service.clone(),
            accent: lake_cloud_service_accent(service),
        })
        .collect::<Vec<_>>();
    let lane_ids = lanes
        .iter()
        .map(|lane| lane.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut point_counts = BTreeMap::<(u32, String), u64>::new();
    for row in &rows {
        let service = cloud_service(row);
        if lane_ids.contains(service.as_str()) {
            *point_counts
                .entry((cloud_bucket(row, time_range, 45), service))
                .or_default() += 1;
        }
    }
    let timeline = CloudDossierTimeline {
        label: lake_cloud_window_label(time_range),
        buckets: 45,
        lanes,
        points: point_counts
            .into_iter()
            .map(|((bucket, service), count)| json!([bucket, service, count.min(3)]))
            .collect(),
        markers: key_actions
            .iter()
            .take(6)
            .map(|action| CloudDossierTimelineMarker {
                at: 44,
                label: action.action.clone(),
                severity: action.severity.clone(),
            })
            .collect(),
    };

    let regions = ranked(rows.iter().map(cloud_region), 20)
        .into_iter()
        .map(|(id, count)| CloudDossierRegion {
            id,
            count,
            ..Default::default()
        })
        .collect::<Vec<_>>();

    #[derive(Default)]
    struct ActionRollup {
        count: u64,
        errors: u64,
        principal: String,
    }
    let mut action_rollups = BTreeMap::<(String, String), ActionRollup>::new();
    for row in &rows {
        let operation = cloud_operation(row);
        if operation.is_empty() {
            continue;
        }
        let rollup = action_rollups
            .entry((operation, cloud_service(row)))
            .or_default();
        rollup.count += 1;
        rollup.errors += cloud_error(row) as u64;
        rollup.principal = cloud_principal(row);
    }
    let mut top_actions = action_rollups.into_iter().collect::<Vec<_>>();
    top_actions.sort_by(|left, right| right.1.count.cmp(&left.1.count));
    let top_actions = top_actions
        .into_iter()
        .take(16)
        .map(|((name, service), rollup)| CloudDossierActionRow {
            sensitive: cloud_sensitive(&json!({"api": {"operation": name}})),
            anomaly: rollup.errors > 0,
            name,
            service,
            count: rollup.count,
            errors: rollup.errors,
            principal: Some(rollup.principal).filter(|value| !value.is_empty()),
        })
        .collect::<Vec<_>>();

    #[derive(Default)]
    struct ResourceRollup {
        kind: String,
        account: String,
        changes: u64,
        last_at: String,
        actions: BTreeSet<String>,
        spark: Vec<u64>,
        sensitive: bool,
    }
    let mut resource_rollups = BTreeMap::<String, ResourceRollup>::new();
    for row in &rows {
        let operation = cloud_operation(row);
        for resource in cloud_resources(row) {
            let Some(uid) = resource
                .get("uid")
                .or_else(|| resource.get("name"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let rollup =
                resource_rollups
                    .entry(uid.to_string())
                    .or_insert_with(|| ResourceRollup {
                        spark: vec![0; 8],
                        ..Default::default()
                    });
            rollup.kind = resource
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            rollup.account = cloud_account(row);
            rollup.changes += 1;
            let timestamp = cloud_time(row);
            if timestamp > rollup.last_at {
                rollup.last_at = timestamp;
            }
            rollup.actions.insert(operation.clone());
            rollup.sensitive |= cloud_sensitive(row);
            let bucket = cloud_bucket(row, time_range, 8) as usize;
            if let Some(slot) = rollup.spark.get_mut(bucket.min(7)) {
                *slot += 1;
            }
        }
    }
    let mut top_resources = resource_rollups.into_iter().collect::<Vec<_>>();
    top_resources.sort_by(|left, right| right.1.changes.cmp(&left.1.changes));
    let top_resources = top_resources
        .into_iter()
        .take(8)
        .map(|(arn, rollup)| CloudDossierResource {
            arn,
            r#type: rollup.kind,
            account: rollup.account,
            changes: rollup.changes,
            last_at: rollup.last_at,
            severity: if rollup.sensitive { "medium" } else { "low" }.to_string(),
            spark: rollup.spark,
            touched: rollup.actions.into_iter().collect(),
        })
        .collect::<Vec<_>>();

    let privileged_calls = rows.iter().filter(|row| cloud_sensitive(row)).count() as u64;
    let auth_posture = CloudDossierAuthPosture {
        total_principals: (!rows.is_empty()) as u64,
        with_mfa: (mfa == Some(true)) as u64,
        without_mfa: (mfa == Some(false)) as u64,
        privileged_without_mfa: (mfa == Some(false) && privileged_calls > 0) as u64,
        privileged_calls_without_mfa: if mfa == Some(false) {
            privileged_calls
        } else {
            0
        },
        console_logins: console as u64,
        console_logins_without_mfa: (console && mfa == Some(false)) as u64,
        api_key_only_principals: (!rows.is_empty() && !console) as u64,
        principals: (!rows.is_empty())
            .then(|| CloudDossierPosturePrincipal {
                name: principal.to_string(),
                mfa,
                privileged: privileged_calls > 0,
                last_call: last_seen.clone(),
                privileged_calls,
                anomaly: mfa == Some(false) && privileged_calls > 0,
                is_role: identity.principal_type.contains("role"),
                ..Default::default()
            })
            .into_iter()
            .collect(),
        ..Default::default()
    };

    let failed = rows.iter().filter(|row| cloud_error(row)).count() as u64;
    let denied = rows.iter().filter(|row| cloud_denied(row)).count() as u64;
    let mut error_counts = BTreeMap::<String, u64>::new();
    for row in rows.iter().filter(|row| cloud_error(row)) {
        *error_counts
            .entry(cloud_error_label(row).unwrap_or_else(|| "request_failed".to_string()))
            .or_default() += 1;
    }
    let mut error_counts = error_counts.into_iter().collect::<Vec<_>>();
    error_counts.sort_by(|left, right| right.1.cmp(&left.1));
    let error_rate = CloudDossierErrorRate {
        events_total: rows.len() as u64,
        events_allowed: rows.len() as u64 - failed,
        events_failed: failed,
        events_denied: denied,
        top_errors: error_counts
            .into_iter()
            .take(5)
            .map(|(code, count)| CloudDossierErrorCode {
                code,
                count,
                pct: count as f64 / failed.max(1) as f64,
                severity: if count * 2 >= failed {
                    "high"
                } else {
                    "medium"
                }
                .to_string(),
            })
            .collect(),
    };

    let stream = rows
        .iter()
        .take(200)
        .enumerate()
        .map(|(index, row)| {
            let service = cloud_service(row);
            let operation = cloud_operation(row);
            let change = cloud_change_type(row);
            let event_type = if service.eq_ignore_ascii_case("sts")
                || operation.to_ascii_lowercase().contains("login")
            {
                "AUTH"
            } else if cloud_sensitive(row) {
                "PERM"
            } else if operation.to_ascii_lowercase().starts_with("get")
                || operation.to_ascii_lowercase().starts_with("list")
                || operation.to_ascii_lowercase().starts_with("describe")
            {
                "READ"
            } else {
                "WRITE"
            };
            CloudDossierStreamEvent {
                id: cloud_string(row, "metadata.uid")
                    .unwrap_or_else(|| format!("cloud-event-{index}")),
                ts: cloud_time(row),
                r#type: event_type.to_string(),
                event_name: operation,
                service,
                user: cloud_principal(row),
                account: cloud_account(row),
                region: cloud_region(row),
                source_ip: cloud_string(row, "src_endpoint.ip").unwrap_or_default(),
                resource: cloud_primary_resource(row, "name"),
                error_code: cloud_error_label(row),
                summary: json!({
                    "change_type": change,
                    "provider": cloud_provider(row),
                    "status": cloud_string(row, "status"),
                }),
                detail: (*row).clone(),
                interesting: cloud_error(row) || cloud_sensitive(row),
            }
        })
        .collect::<Vec<_>>();

    CloudDossier {
        bounded_preview: false,
        identity,
        risk,
        facets,
        assume_chain,
        timeline,
        regions,
        top_actions,
        top_resources,
        auth_posture,
        error_rate,
        stream,
        window_label: lake_cloud_window_label(time_range),
        durable_job: None,
    }
}


fn fixture_rows(count: usize) -> Vec<Value> {
    let operations = ["ListRoles", "AssumeRole", "ConsoleLogin", "PutBucketAcl", "GetObject", "DeleteBucket", "CreateUser"];
    let services = ["iam", "sts", "signin", "s3", "s3", "s3", "iam", "ec2", "kms", "lambda"];
    let regions = ["us-east-1", "us-west-2", "eu-west-1"];
    let agents = ["aws-cli/2.0", "Mozilla/5.0", "Boto3/1.2", "terraform/1.5", ""];
    (0..count)
        .map(|i| {
            let minute = (count - i) % 120;
            let mut row = json!({
                "time": format!("2026-08-11T{:02}:{:02}:{:02}Z", minute / 60, minute % 60, i % 60),
                "metadata.uid": format!("event-{i}"),
                "metadata.log_source": "cloudtrail",
                "cloud.provider": if i % 11 == 0 { "GCP" } else { "AWS" },
                "cloud.account.uid": format!("{}", 100 + i % 3),
                "cloud.region": regions[i % regions.len()],
                "actor.user.name": "alice",
                "actor.user.uid": "arn:aws:iam::100:user/alice",
                "api.operation": operations[i % operations.len()],
                "api.service.name": services[i % services.len()],
                "http_request.user_agent": agents[i % agents.len()],
                "src_endpoint.ip": format!("10.0.{}.{}", i % 4, i % 7),
                "session.uid": format!("session-{}", i % 5),
                "status": if i % 9 == 0 { "Failure" } else { "Success" },
                "is_mfa": i % 13 != 0,
                "message": format!("event {i}"),
                "resources.uid": [format!("arn:res-{}", i % 6)],
                "resources.name": [format!("res-{}", i % 6)],
                "resources.type": [if i % 2 == 0 { "AWS::S3::Bucket" } else { "AWS::IAM::Role" }],
            });
            if i % 9 == 0 {
                row["unmapped.error_code"] = json!(if i % 18 == 0 { "AccessDenied" } else { "Throttling" });
                row["http_response.code"] = json!(if i % 18 == 0 { 403 } else { 429 });
            }
            row
        })
        .collect()
}

#[test]
fn the_streaming_dossier_equals_the_multi_pass_assembler() {
    let range = TimeRange::new(
        chrono::DateTime::parse_from_rfc3339("2026-08-11T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
        chrono::DateTime::parse_from_rfc3339("2026-08-11T02:00:00Z").unwrap().with_timezone(&chrono::Utc),
    );
    let filters = [
        CloudDossierFacetFilters::default(),
        CloudDossierFacetFilters { services: vec!["s3".to_string()], ..Default::default() },
        CloudDossierFacetFilters { regions: vec!["us-west-2".to_string()], accounts: vec!["101".to_string()], ..Default::default() },
    ];
    // Past every bounded head (12 hops, 20 key actions, 200 stream rows).
    for count in [0, 1, 7, 350] {
        let rows = fixture_rows(count);
        for filter in &filters {
            for risk in [None, Some((72, Some("rule".to_string())))] {
                let expected = reference_assemble_lake_cloud_dossier("alice", rows.clone(), filter, &range, risk.clone());
                let actual = SearchService::assemble_lake_cloud_dossier("alice", rows.clone(), filter, &range, risk.clone());
                assert_eq!(
                    serde_json::to_value(&actual).unwrap(),
                    serde_json::to_value(&expected).unwrap(),
                    "rows={count} filter={filter:?}"
                );
                // Folding in arbitrary batches is the same fold.
                let mut accumulator = CloudDossierAccumulator::new("alice", filter, &range);
                for batch in rows.chunks(17) {
                    for row in batch {
                        accumulator.push(row.clone());
                    }
                }
                assert_eq!(serde_json::to_value(accumulator.finish(risk)).unwrap(), serde_json::to_value(&expected).unwrap());
            }
        }
    }
}
