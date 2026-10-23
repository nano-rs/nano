// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tenant-pinned IOC reads for query[T]. Each request pins the durable current
//! pointer and verifies its immutable revision before returning a result.
use anyhow::{ensure, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use uuid::Uuid;

use crate::lean_enrichment_snapshot::LeanEnrichmentSnapshots;
use crate::lean_platform_bundle::{platform_feed_display_name, PlatformBundle, TenantPlatformPolicy};
use crate::parts::part_log::ObjectStore;
use nanosiem_core::enrichment::ioc::IocLookupResult;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub snapshot_id: String,
    pub value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub snapshot_id: String,
    #[serde(default)]
    pub feeds: Vec<String>,
    #[serde(default)]
    pub feed_name_contains: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub artifact_types: Vec<String>,
    #[serde(default)]
    pub cursor_published_at_ms: Option<i64>,
    #[serde(default)]
    pub cursor_value: Option<String>,
    pub limit: usize,
    #[serde(default)]
    pub count_only: bool,
}

fn binding(tenant: Uuid, request_id: &str, body_tenant: &str, snapshot_id: &str) -> Result<()> {
    ensure!(
        !tenant.is_nil() && body_tenant == tenant.to_string(),
        "IOC request tenant differs from process tenant"
    );
    ensure!(
        !request_id.is_empty()
            && request_id.len() <= 128
            && request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "invalid IOC request id"
    );
    ensure!(
        snapshot_id == format!("ioc-{tenant}-current"),
        "IOC pointer is not assigned to this tenant"
    );
    Ok(())
}

pub async fn lookup(
    objects: &dyn ObjectStore,
    scratch: &Path,
    tenant: Uuid,
    request: LookupRequest,
) -> Result<Value> {
    binding(
        tenant,
        &request.request_id,
        &request.tenant_id,
        &request.snapshot_id,
    )?;
    ensure!(
        !request.value.trim().is_empty()
            && request.value.len() <= 4096
            && !request.value.chars().any(char::is_control),
        "invalid IOC value"
    );
    let store = LeanEnrichmentSnapshots::new(tenant, objects, scratch)?;
    let pointer = store
        .current()
        .await?
        .ok_or_else(|| anyhow::anyhow!("tenant IOC pointer is absent"))?;
    let snapshot = store.load(&pointer).await?;
    let results = snapshot.lookup_all(&request.value);
    // NAN-3881: the tenant's own indicator sources searched, so a miss can
    // say "no matches in N sources". Additive; older readers ignore it.
    let sources = snapshot.ioc_sources();
    Ok(json!({
        "ok": true, "schema_version": 1, "request_id": request.request_id,
        "tenant_id": request.tenant_id, "snapshot_id": request.snapshot_id,
        "snapshot_version": pointer.sha256, "value": request.value,
        "budget": {"decision":"allow", "estimated_scan_bytes":0,
                   "resident_snapshot_bytes":pointer.bytes,
                   "estimate_kind":"resident-immutable-ioc-snapshot"},
        "results": results, "sources": sources, "wall_seconds": 0.0
    }))
}

/// The platform baseline IOC feeds as this process sees them (NAN-3881).
pub enum PlatformIocs<'a> {
    /// No platform mounts on this process (open core, a cell without a
    /// bundle): there are no baseline feeds to search.
    NotConfigured,
    /// Mounts exist but the tenant's policy or bundle could not be read now.
    /// Ingest records `unknown` for the same state; the lookup says so.
    Unavailable,
    /// The node bundle and this tenant's own fresh policy, the exact pair
    /// ingest stamping matches with.
    Granted {
        bundle: &'a PlatformBundle,
        policy: &'a TenantPlatformPolicy,
    },
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// NAN-3881: one value across every IOC source the tenant has enabled — its
/// own published IOC lists/feeds (the tenant snapshot) plus the platform
/// baseline feeds its policy grants (ThreatFox, Tor exit nodes...) — read
/// through the same gates ingest matching uses, so the flyout and ingest
/// cannot disagree. `sources` names every source searched, matched or not.
/// A tenant without a published snapshot still searches its baseline feeds.
/// Strictly per tenant: the request must be this process's tenant, the
/// snapshot is the tenant's own prefix, and the policy is the tenant's own
/// projection (`read_for_query` refuses any other tenant's).
pub async fn indicator_sets(
    objects: Option<&dyn ObjectStore>,
    scratch: &Path,
    tenant: Uuid,
    platform: PlatformIocs<'_>,
    request: LookupRequest,
) -> Result<Value> {
    binding(
        tenant,
        &request.request_id,
        &request.tenant_id,
        &request.snapshot_id,
    )?;
    ensure!(
        !request.value.trim().is_empty()
            && request.value.len() <= 4096
            && !request.value.chars().any(char::is_control),
        "invalid IOC value"
    );
    let mut results: Vec<IocLookupResult> = Vec::new();
    let mut sources: BTreeSet<String> = BTreeSet::new();
    let mut snapshot_version: Option<String> = None;
    if let Some(objects) = objects {
        let store = LeanEnrichmentSnapshots::new(tenant, objects, scratch)?;
        if let Some(pointer) = store.current().await? {
            let snapshot = store.load(&pointer).await?;
            results.extend(snapshot.lookup_all(&request.value));
            sources.extend(snapshot.ioc_sources());
            snapshot_version = Some(pointer.sha256.clone());
        }
    }
    let (platform_status, platform_feeds, bundle_digest) = match platform {
        PlatformIocs::NotConfigured => ("not_configured", Vec::new(), None),
        PlatformIocs::Unavailable => ("unavailable", Vec::new(), None),
        PlatformIocs::Granted { bundle, policy } => {
            ensure!(
                policy.tenant_id == tenant,
                "platform policy tenant differs from process tenant"
            );
            let now = chrono::Utc::now();
            let feeds = bundle.granted_ioc_feeds(policy, now)?;
            for row in bundle.lookup_indicator(policy, &request.value, now)? {
                // `lookup_indicator` only returns granted feeds; keep the
                // listing and the matches provably consistent anyway.
                if !feeds.contains(&row.source_id) {
                    continue;
                }
                results.push(IocLookupResult {
                    found: true,
                    source_id: Some(platform_feed_display_name(&row.source_id)),
                    ioc_type: non_empty(&row.ioc_type),
                    threat_type: non_empty(&row.threat_type),
                    malware: non_empty(&row.malware),
                    confidence_level: Some(row.confidence_level),
                    first_seen_at: row
                        .data
                        .get("first_seen")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    last_seen_at: None,
                    tags: row.tags,
                });
            }
            sources.extend(feeds.iter().map(|feed| platform_feed_display_name(feed)));
            ("ok", feeds, Some(bundle.digest().to_string()))
        }
    };
    Ok(json!({
        "ok": true, "schema_version": 1, "request_id": request.request_id,
        "tenant_id": request.tenant_id, "snapshot_id": request.snapshot_id,
        "snapshot_version": snapshot_version, "value": request.value,
        "results": results, "sources": sources.into_iter().collect::<Vec<_>>(),
        "platform_status": platform_status, "platform_feeds": platform_feeds,
        "platform_bundle_sha256": bundle_digest, "wall_seconds": 0.0
    }))
}

pub async fn source_records(
    objects: &dyn ObjectStore,
    scratch: &Path,
    tenant: Uuid,
    request: SourceRequest,
) -> Result<Value> {
    binding(
        tenant,
        &request.request_id,
        &request.tenant_id,
        &request.snapshot_id,
    )?;
    let valid_text = |value: &String| {
        !value.trim().is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
    };
    ensure!(
        request.feeds.len() <= 1024
            && request.feed_name_contains.len() <= 1024
            && request.tags.len() <= 1024
            && request.artifact_types.len() <= 64,
        "IOC filters exceed limits"
    );
    ensure!(
        request
            .feeds
            .iter()
            .chain(&request.feed_name_contains)
            .chain(&request.tags)
            .chain(&request.artifact_types)
            .all(valid_text),
        "invalid IOC filter"
    );
    ensure!(
        (1..=100_000).contains(&request.limit)
            && request.cursor_published_at_ms.is_some() == request.cursor_value.is_some(),
        "invalid IOC page or cursor"
    );
    ensure!(
        request.cursor_published_at_ms.is_none_or(|ms| ms >= 0)
            && request.cursor_value.as_ref().is_none_or(valid_text),
        "invalid IOC cursor"
    );
    let store = LeanEnrichmentSnapshots::new(tenant, objects, scratch)?;
    let pointer = store
        .current()
        .await?
        .ok_or_else(|| anyhow::anyhow!("tenant IOC pointer is absent"))?;
    let snapshot = store.load(&pointer).await?;
    let cursor = request
        .cursor_published_at_ms
        .zip(request.cursor_value.as_deref());
    let count = snapshot.source_record_count(
        &request.feeds,
        &request.feed_name_contains,
        &request.tags,
        &request.artifact_types,
        cursor,
    );
    let records = if request.count_only {
        Vec::new()
    } else {
        snapshot.source_records(
            &request.feeds,
            &request.feed_name_contains,
            &request.tags,
            &request.artifact_types,
            cursor,
            request.limit,
        )
    };
    Ok(json!({
        "ok": true, "schema_version": 1, "request_id": request.request_id,
        "tenant_id": request.tenant_id, "snapshot_id": request.snapshot_id,
        "snapshot_version": pointer.sha256, "count": count, "records": records,
        "budget": {"decision":"allow", "estimated_scan_bytes":0,
                   "resident_snapshot_bytes":pointer.bytes,
                   "estimate_kind":"resident-immutable-ioc-snapshot"},
        "wall_seconds": 0.0
    }))
}

/// NAN-4169: a retro hunt's request for the platform IOC feeds it has not
/// processed yet. `known` maps feed id to the revision the hunt last finished.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformRecordsRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub snapshot_id: String,
    #[serde(default)]
    pub known: std::collections::BTreeMap<String, i64>,
    #[serde(default)]
    pub artifact_types: Vec<String>,
    pub max_records: usize,
}

/// Upper bound on platform rows one retro delta request may enumerate.
pub const MAX_PLATFORM_RECORDS: usize = 500_000;

/// The coarse retro artifact type of a platform IOC row (`ip`, `ip:port`,
/// `domain`, `url`, `hash`), or `None` for a type retro does not hunt.
pub fn platform_retro_type(ioc_type: &str) -> Option<&'static str> {
    let t = ioc_type.trim().to_ascii_lowercase();
    match t.as_str() {
        "ip" | "ipv4" | "ipv6" | "ip_address" | "ip-dst" | "ip-src" => Some("ip"),
        "ip:port" | "ip_port" => Some("ip:port"),
        "domain" | "hostname" | "fqdn" => Some("domain"),
        "url" | "uri" => Some("url"),
        _ if t.contains("hash") || matches!(t.as_str(), "md5" | "sha1" | "sha256") => Some("hash"),
        _ => None,
    }
}

/// NAN-4169: the granted platform IOC feeds (ThreatFox, Tor exit nodes...)
/// whose bundle revision differs from the caller's `known` revision, with
/// every live row of each changed feed. Unchanged feeds come back with their
/// revision and no rows, so an idle feed costs one policy read. Only feeds
/// this process tenant's own policy grants, through the ingest gate
/// ([`PlatformBundle::granted_feed_rows`]); never another tenant's.
pub fn platform_records(
    tenant: Uuid,
    platform: PlatformIocs<'_>,
    request: PlatformRecordsRequest,
) -> Result<Value> {
    binding(
        tenant,
        &request.request_id,
        &request.tenant_id,
        &request.snapshot_id,
    )?;
    ensure!(
        (1..=MAX_PLATFORM_RECORDS).contains(&request.max_records)
            && request.known.len() <= 64
            && request.artifact_types.len() <= 16,
        "invalid platform record request bounds"
    );
    let wanted_types: BTreeSet<&'static str> = request
        .artifact_types
        .iter()
        .filter_map(|t| platform_retro_type(t))
        .collect();
    let (bundle, policy) = match platform {
        PlatformIocs::NotConfigured => {
            return Ok(json!({
                "ok": true, "schema_version": 1, "request_id": request.request_id,
                "tenant_id": request.tenant_id, "snapshot_id": request.snapshot_id,
                "platform_status": "not_configured", "feeds": []
            }))
        }
        PlatformIocs::Unavailable => {
            anyhow::bail!("platform IOC feeds are unavailable for this tenant now")
        }
        PlatformIocs::Granted { bundle, policy } => (bundle, policy),
    };
    ensure!(
        policy.tenant_id == tenant,
        "platform policy tenant differs from process tenant"
    );
    let now = chrono::Utc::now();
    let revisions = bundle.granted_ioc_feed_revisions(policy, now)?;
    let changed: BTreeSet<String> = revisions
        .iter()
        .filter(|(feed, revision)| request.known.get(*feed) != Some(*revision))
        .map(|(feed, _)| feed.clone())
        .collect();
    let rows = bundle.granted_feed_rows(policy, &changed, now, request.max_records)?;
    let mut by_feed: std::collections::BTreeMap<String, Vec<Value>> = std::collections::BTreeMap::new();
    for row in rows {
        let Some(kind) = platform_retro_type(&row.ioc_type) else { continue };
        // `ip:port` rows are hunted under the `ip` filter too.
        let type_matches = wanted_types.is_empty()
            || wanted_types.contains(&kind)
            || (kind == "ip:port" && wanted_types.contains(&"ip"));
        let value = row.ioc_value.trim().to_ascii_lowercase();
        if !type_matches || value.is_empty() || value.len() > 4096 {
            continue;
        }
        by_feed.entry(row.source_id.clone()).or_default().push(json!({
            "value": value, "key_type": kind,
            "confidence": row.confidence_level.clamp(0, 100),
            "tags": row.tags,
        }));
    }
    let feeds: Vec<Value> = revisions
        .iter()
        .map(|(feed, revision)| {
            let is_changed = changed.contains(feed);
            json!({
                "feed": feed,
                "display_name": platform_feed_display_name(feed),
                "revision": revision,
                "changed": is_changed,
                "records": if is_changed { by_feed.remove(feed).unwrap_or_default() } else { Vec::new() },
            })
        })
        .collect();
    Ok(json!({
        "ok": true, "schema_version": 1, "request_id": request.request_id,
        "tenant_id": request.tenant_id, "snapshot_id": request.snapshot_id,
        "platform_status": "ok", "platform_bundle_sha256": bundle.digest(),
        "feeds": feeds
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{enrichment::IocSnapshotInput, parts::part_log::LocalObjectStore};

    fn platform_row(feed: &str, value: &str) -> IocSnapshotInput {
        IocSnapshotInput {
            ioc_value: value.into(),
            ioc_type: "ip".into(),
            source_id: feed.into(),
            enrichment_name: feed.into(),
            is_ioc: true,
            threat_type: if feed == "tor_exit_nodes" { "tor_exit".into() } else { "botnet_cc".into() },
            confidence_level: if feed == "tor_exit_nodes" { 100 } else { 75 },
            ..Default::default()
        }
    }

    fn policy(
        tenant: Uuid,
        digest: &str,
        grants: &[(&str, i64, i64)],
    ) -> TenantPlatformPolicy {
        let now = chrono::Utc::now();
        TenantPlatformPolicy {
            tenant_id: tenant,
            revision: 1,
            bundle_sha256: digest.to_string(),
            grants: grants
                .iter()
                .map(|(feed, revision, minutes)| {
                    (
                        feed.to_string(),
                        crate::lean_platform_bundle::PlatformGrant {
                            feed_revision: *revision,
                            valid_until: now + chrono::Duration::minutes(*minutes),
                            premium: None,
                        },
                    )
                })
                .collect(),
        }
    }

    fn granted<'a>(bundle: &'a PlatformBundle, policy: &'a TenantPlatformPolicy) -> PlatformIocs<'a> {
        PlatformIocs::Granted { bundle, policy }
    }

    fn names(answer: &Value, key: &str) -> Vec<String> {
        answer[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    fn matched_sources(answer: &Value) -> BTreeSet<String> {
        answer["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["source_id"].as_str().unwrap().to_string())
            .collect()
    }

    /// Regression: the flyout lookup searched only the
    /// tenant's own IOC list (easy_intel), never its enabled ThreatFox / Tor
    /// baseline feeds. `indicator_sets` searches both, through the same
    /// bundle + policy gate as ingest stamping, and only what this tenant's
    /// own policy grants.
    #[tokio::test]
    async fn indicator_sets_search_own_lists_and_granted_baseline_feeds() {
        let dir = tempfile::tempdir().unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let bundle_path = dir.path().join("bundle.nanpfb");
        let digest = PlatformBundle::publish(
            &bundle_path,
            None,
            &[
                platform_row("threatfox", "198.51.100.7"),
                platform_row("tor_exit_nodes", "198.51.100.7"),
                platform_row("tor_exit_nodes", "203.0.113.5"),
            ],
            std::collections::BTreeMap::from([
                ("threatfox".to_string(), 3),
                ("tor_exit_nodes".to_string(), 4),
            ]),
        )
        .unwrap();
        let bundle = PlatformBundle::open(&bundle_path, &digest).unwrap();
        // Tenant A: its own IOC list plus ThreatFox and Tor enabled.
        let a_objects = LocalObjectStore::new(dir.path().join("objects-a")).unwrap();
        LeanEnrichmentSnapshots::new(a, &a_objects, &dir.path().join("publish-a"))
            .unwrap()
            .publish(&[IocSnapshotInput {
                ioc_value: "198.51.100.7".into(),
                ioc_type: "ip".into(),
                source_id: "list-a".into(),
                enrichment_name: "easy_intel".into(),
                is_ioc: true,
                ..Default::default()
            }])
            .await
            .unwrap();
        let a_policy = policy(a, &digest, &[("threatfox", 3, 60), ("tor_exit_nodes", 4, 60)]);
        let request = |tenant: Uuid, value: &str| LookupRequest {
            request_id: "sets1".into(),
            tenant_id: tenant.to_string(),
            snapshot_id: format!("ioc-{tenant}-current"),
            value: value.into(),
        };
        let hit = indicator_sets(Some(&a_objects), &dir.path().join("q-a"), a,
            granted(&bundle, &a_policy), request(a, " 198.51.100.7 ")).await.unwrap();
        assert_eq!(names(&hit, "sources"), ["ThreatFox", "Tor exit nodes", "easy_intel"]);
        assert_eq!(matched_sources(&hit), BTreeSet::from(["ThreatFox".into(), "Tor exit nodes".into(), "easy_intel".into()]));
        assert_eq!(hit["platform_status"], "ok");
        assert_eq!(hit["platform_feeds"], json!(["threatfox", "tor_exit_nodes"]));
        // A miss still lists every source searched.
        let miss = indicator_sets(Some(&a_objects), &dir.path().join("q-a2"), a,
            granted(&bundle, &a_policy), request(a, "192.0.2.1")).await.unwrap();
        assert_eq!(names(&miss, "sources").len(), 3);
        assert!(miss["results"].as_array().unwrap().is_empty());

        // Tenant B: no own snapshot, only ThreatFox enabled. Tor is neither
        // searched nor matched, and A's easy_intel list never appears.
        let b_objects = LocalObjectStore::new(dir.path().join("objects-b")).unwrap();
        let b_policy = policy(b, &digest, &[("threatfox", 3, 60)]);
        let b_hit = indicator_sets(Some(&b_objects), &dir.path().join("q-b"), b,
            granted(&bundle, &b_policy), request(b, "198.51.100.7")).await.unwrap();
        assert_eq!(names(&b_hit, "sources"), ["ThreatFox"]);
        assert_eq!(matched_sources(&b_hit), BTreeSet::from(["ThreatFox".into()]));
        assert!(b_hit["snapshot_version"].is_null());
        let b_tor = indicator_sets(Some(&b_objects), &dir.path().join("q-b2"), b,
            granted(&bundle, &b_policy), request(b, "203.0.113.5")).await.unwrap();
        assert!(b_tor["results"].as_array().unwrap().is_empty());

        // Cross-tenant negatives: B's policy is refused on A's process, A's
        // request is refused on B's process, and A's request on A's process
        // with B's policy never borrows B's grants.
        assert!(indicator_sets(Some(&a_objects), &dir.path().join("x1"), a,
            granted(&bundle, &b_policy), request(a, "198.51.100.7")).await.is_err());
        assert!(indicator_sets(Some(&b_objects), &dir.path().join("x2"), b,
            granted(&bundle, &b_policy), request(a, "198.51.100.7")).await.is_err());

        // Same gate as ingest: an expired grant or a grant at a revision the
        // bundle does not carry is not an enabled feed.
        let stale = policy(a, &digest, &[("threatfox", 2, 60), ("tor_exit_nodes", 4, -1)]);
        let gated = indicator_sets(Some(&a_objects), &dir.path().join("q-a3"), a,
            granted(&bundle, &stale), request(a, "198.51.100.7")).await.unwrap();
        assert_eq!(names(&gated, "sources"), ["easy_intel"]);
        assert_eq!(matched_sources(&gated), BTreeSet::from(["easy_intel".into()]));

        // Zero enabled sources: no snapshot, no platform mounts.
        let none = indicator_sets(None, &dir.path().join("q-n"), b,
            PlatformIocs::NotConfigured, request(b, "198.51.100.7")).await.unwrap();
        assert!(names(&none, "sources").is_empty());
        assert_eq!(none["platform_status"], "not_configured");
        let unavailable = indicator_sets(Some(&a_objects), &dir.path().join("q-u"), a,
            PlatformIocs::Unavailable, request(a, "198.51.100.7")).await.unwrap();
        assert_eq!(unavailable["platform_status"], "unavailable");
        assert_eq!(names(&unavailable, "sources"), ["easy_intel"]);
    }

    /// The flyout's platform gate is the ingest gate: a value stamps a
    /// platform feed at ingest exactly when the lookup returns that feed.
    #[test]
    fn platform_lookup_agrees_with_ingest_stamping() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let bundle_path = dir.path().join("bundle.nanpfb");
        let digest = PlatformBundle::publish(
            &bundle_path,
            None,
            &[platform_row("threatfox", "198.51.100.7"), platform_row("tor_exit_nodes", "198.51.100.7")],
            std::collections::BTreeMap::from([("threatfox".to_string(), 3), ("tor_exit_nodes".to_string(), 4)]),
        )
        .unwrap();
        let bundle = PlatformBundle::open(&bundle_path, &digest).unwrap();
        for grants in [
            vec![("threatfox", 3, 60), ("tor_exit_nodes", 4, 60)],
            vec![("threatfox", 3, 60)],
            vec![("tor_exit_nodes", 4, -1)],
            vec![],
        ] {
            let policy = policy(tenant, &digest, &grants);
            let now = chrono::Utc::now();
            let looked_up: BTreeSet<String> = bundle
                .lookup_indicator(&policy, "198.51.100.7", now)
                .unwrap()
                .into_iter()
                .map(|row| row.source_id)
                .collect();
            let mut event = json!({"src_endpoint": {"ip": "198.51.100.7"}});
            bundle.stamp(event.as_object_mut().unwrap(), &policy, now).unwrap();
            let stamped: BTreeSet<String> = event["enrichments"]
                .as_array()
                .map(|stamps| {
                    stamps
                        .iter()
                        .map(|s| s["provider"].as_str().unwrap().trim_start_matches("platform/").to_string())
                        .collect()
                })
                .unwrap_or_default();
            assert_eq!(looked_up, stamped, "grants {grants:?}");
            let listed: BTreeSet<String> = bundle.granted_ioc_feeds(&policy, now).unwrap().into_iter().collect();
            assert!(looked_up.is_subset(&listed));
        }
    }

    #[tokio::test]
    async fn current_revision_replays_and_other_tenant_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        let objects = LocalObjectStore::new(dir.path().join("objects")).unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let store = LeanEnrichmentSnapshots::new(a, &objects, &dir.path().join("publish")).unwrap();
        store
            .publish(&[IocSnapshotInput {
                ioc_value: "8.8.8.8".into(),
                ioc_type: "ip".into(),
                source_id: "feed".into(),
                ..Default::default()
            }])
            .await
            .unwrap();
        let request = || LookupRequest {
            request_id: "request1".into(),
            tenant_id: a.to_string(),
            snapshot_id: format!("ioc-{a}-current"),
            value: "8.8.8.8".into(),
        };
        let first = lookup(&objects, &dir.path().join("query"), a, request())
            .await
            .unwrap();
        assert_eq!(first["results"].as_array().unwrap().len(), 1);
        let replay = lookup(&objects, &dir.path().join("restart"), a, request())
            .await
            .unwrap();
        assert_eq!(first["snapshot_version"], replay["snapshot_version"]);
        assert_eq!(first["sources"], json!(["feed"]));
        assert!(lookup(&objects, &dir.path().join("other"), b, request())
            .await
            .is_err());
        // NAN-3881: tenant B publishes its own indicator for the same value
        // under its own feed, in its own tenant-scoped object store (the
        // snapshot pointer key is per kind, so each tenant has its own
        // store, as in production). Tenant A's lookup never returns B's
        // verdict or lists B's source, and B's process never answers for A.
        let b_objects = LocalObjectStore::new(dir.path().join("objects-b")).unwrap();
        let b_store =
            LeanEnrichmentSnapshots::new(b, &b_objects, &dir.path().join("publish-b")).unwrap();
        b_store
            .publish(&[
                IocSnapshotInput {
                    ioc_value: "8.8.8.8".into(),
                    ioc_type: "ip".into(),
                    source_id: "b-private-feed".into(),
                    enrichment_name: "B private feed".into(),
                    is_ioc: true,
                    ..Default::default()
                },
                IocSnapshotInput {
                    ioc_value: "203.0.113.9".into(),
                    ioc_type: "ip".into(),
                    source_id: "b-private-feed".into(),
                    enrichment_name: "B private feed".into(),
                    is_ioc: true,
                    ..Default::default()
                },
            ])
            .await
            .unwrap();
        let a_after = lookup(&objects, &dir.path().join("query-a2"), a, request())
            .await
            .unwrap();
        assert_eq!(a_after["sources"], json!(["feed"]));
        let a_results = a_after["results"].as_array().unwrap();
        assert_eq!(a_results.len(), 1);
        assert!(a_results.iter().all(|r| r["source_id"] != "B private feed"));
        let b_only = LookupRequest { value: "203.0.113.9".into(), ..request() };
        let a_miss = lookup(&objects, &dir.path().join("query-a3"), a, b_only)
            .await
            .unwrap();
        assert!(a_miss["results"].as_array().unwrap().is_empty());
        // Tenant A's request (A's tenant id and pointer) on tenant B's process
        // is refused by the binding, not answered from B's snapshot.
        assert!(lookup(&b_objects, &dir.path().join("other-b"), b, request())
            .await
            .is_err());
        let page = SourceRequest {
            request_id: "page1".into(),
            tenant_id: a.to_string(),
            snapshot_id: format!("ioc-{a}-current"),
            feeds: vec!["feed".into()],
            feed_name_contains: vec![],
            tags: vec![],
            artifact_types: vec!["ip".into()],
            cursor_published_at_ms: None,
            cursor_value: None,
            limit: 10,
            count_only: false,
        };
        let records = source_records(&objects, &dir.path().join("restart"), a, page)
            .await
            .unwrap();
        assert_eq!(records["count"], 1);
        assert_eq!(records["records"][0]["value"], "8.8.8.8");
    }

    /// NAN-4169: the retro delta enumerates only the platform feeds this
    /// tenant's own policy grants, only when their bundle revision moved past
    /// the caller's `known` revision, and types `ip:port` rows apart.
    #[test]
    fn platform_records_return_changed_granted_feeds_only() {
        let dir = tempfile::tempdir().unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let bundle_path = dir.path().join("bundle.nanpfb");
        let mut port = platform_row("threatfox", "198.51.100.9:443");
        port.ioc_type = "ip:port".into();
        let digest = PlatformBundle::publish(
            &bundle_path,
            None,
            &[
                platform_row("threatfox", "198.51.100.7"),
                port,
                platform_row("tor_exit_nodes", "203.0.113.5"),
            ],
            std::collections::BTreeMap::from([
                ("threatfox".to_string(), 3),
                ("tor_exit_nodes".to_string(), 4),
            ]),
        )
        .unwrap();
        let bundle = PlatformBundle::open(&bundle_path, &digest).unwrap();
        let a_policy = policy(a, &digest, &[("threatfox", 3, 60), ("tor_exit_nodes", 4, 60)]);
        let request = |tenant: Uuid, known: &[(&str, i64)]| PlatformRecordsRequest {
            request_id: "retro1".into(),
            tenant_id: tenant.to_string(),
            snapshot_id: format!("ioc-{tenant}-current"),
            known: known.iter().map(|(f, r)| (f.to_string(), *r)).collect(),
            artifact_types: vec![],
            max_records: 1_000,
        };
        let feeds = |answer: &Value| -> Vec<(String, bool, Vec<(String, String)>)> {
            answer["feeds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| {
                    let rows = f["records"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|r| (r["value"].as_str().unwrap().to_string(), r["key_type"].as_str().unwrap().to_string()))
                        .collect();
                    (f["feed"].as_str().unwrap().to_string(), f["changed"].as_bool().unwrap(), rows)
                })
                .collect()
        };
        // First sight: both granted feeds are changed and fully enumerated.
        let first = platform_records(a, granted(&bundle, &a_policy), request(a, &[])).unwrap();
        assert_eq!(
            feeds(&first),
            vec![
                ("threatfox".into(), true, vec![
                    ("198.51.100.7".into(), "ip".into()),
                    ("198.51.100.9:443".into(), "ip:port".into()),
                ]),
                ("tor_exit_nodes".into(), true, vec![("203.0.113.5".into(), "ip".into())]),
            ]
        );
        // Already processed revisions are reported without rows.
        let idle = platform_records(a, granted(&bundle, &a_policy), request(a, &[("threatfox", 3), ("tor_exit_nodes", 4)])).unwrap();
        assert!(feeds(&idle).iter().all(|(_, changed, rows)| !changed && rows.is_empty()));
        let moved = platform_records(a, granted(&bundle, &a_policy), request(a, &[("threatfox", 2), ("tor_exit_nodes", 4)])).unwrap();
        assert_eq!(feeds(&moved)[0].1, true);
        assert_eq!(feeds(&moved)[0].2.len(), 2);
        // Tenant B is granted Tor only: ThreatFox is never enumerated for it.
        let b_policy = policy(b, &digest, &[("tor_exit_nodes", 4, 60)]);
        let b_answer = platform_records(b, granted(&bundle, &b_policy), request(b, &[])).unwrap();
        assert_eq!(feeds(&b_answer).iter().map(|f| f.0.clone()).collect::<Vec<_>>(), ["tor_exit_nodes"]);
        // Another tenant's request on B's process is refused by the binding.
        assert!(platform_records(b, granted(&bundle, &b_policy), request(a, &[])).is_err());
        // No platform mounts (open core): nothing to hunt, not an error.
        let open = platform_records(a, PlatformIocs::NotConfigured, request(a, &[])).unwrap();
        assert_eq!(open["platform_status"], "not_configured");
        // The enumeration bound refuses instead of truncating a feed.
        let mut small = request(a, &[]);
        small.max_records = 1;
        assert!(platform_records(a, granted(&bundle, &a_policy), small).is_err());
    }
}
