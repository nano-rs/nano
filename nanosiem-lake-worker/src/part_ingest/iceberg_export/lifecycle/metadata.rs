// SPDX-License-Identifier: AGPL-3.0-or-later

//! Metadata deletion is a separate, scoped authority. Never use FileIO's raw
//! delete grant or the lake-part delete API for catalog metadata.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataDeleteRequest {
    pub tenant_id: String,
    pub bucket: String,
    pub metadata_prefix: String,
    pub key: String,
    pub current_metadata: String,
    pub table_uuid: uuid::Uuid,
}

/// Implementations attest writer ownership, retire one immutable metadata
/// object and acknowledge its absence. There is no unguarded live adapter.
#[async_trait::async_trait]
pub trait MetadataDeleteAuthority: Send + Sync {
    fn tenant_id(&self) -> &str;
    fn metadata_prefix(&self) -> &str;
    /// Complete, strongly consistent inventory under the same writer lease.
    /// Truncation, missing pages and unavailable ownership must return errors.
    async fn inventory(&self) -> Result<Vec<String>>;
    async fn retire(&self, request: &MetadataDeleteRequest) -> Result<MetadataDeleteRequest>;
}

pub struct MetadataGc {
    tenant: String,
    bucket: String,
    prefix: String,
    authority: Arc<dyn MetadataDeleteAuthority>,
}

impl MetadataGc {
    /// A serving table was dropped and its public name fenced before this is
    /// called. Its whole immutable metadata prefix can now be retired.
    pub(super) async fn purge_dropped(&self) -> Result<()> {
        let inventory=self.authority.inventory().await?;
        ensure!(inventory.len()<=1_000_000,"catalog metadata inventory exceeds bound");
        for key in &inventory {self.validate_path(key)?;}
        for key in inventory {
            let request=MetadataDeleteRequest {tenant_id:self.tenant.clone(),bucket:self.bucket.clone(),metadata_prefix:self.prefix.clone(),key,
                current_metadata:String::new(),table_uuid:uuid::Uuid::nil()};
            ensure!(self.authority.retire(&request).await?==request,"metadata retirement acknowledgment differs");
        }
        ensure!(self.authority.inventory().await?.is_empty(),"dropped serving metadata remains reachable");
        Ok(())
    }
    pub fn new(
        tenant: &str,
        table_location: &str,
        authority: Arc<dyn MetadataDeleteAuthority>,
    ) -> Result<Self> {
        crate::parts::format::validate_tenant_uuid(tenant)?;
        super::super::validate_object_uri(table_location)?;
        let bucket = crate::lake_part_gc::request::tenant_bucket(tenant);
        let root = format!(
            "s3://{bucket}/{}/",
            crate::parts::format::iceberg_export_prefix(tenant)?
        );
        // NAN-4614: the R2-managed platform root, or the legacy one a recorded
        // installation keeps until its writer rotation. Exactly this tenant's.
        let platform_roots = [
            format!("s3://{bucket}/__r2_data_catalog/agent/v2/tenant={tenant}/"),
            format!("s3://{bucket}/lake/agent-catalog/v2/tenant={tenant}/"),
        ];
        let suffix = if let Some(suffix) = table_location.strip_prefix(&root) {
            suffix
        } else {
            let suffix = platform_roots
                .iter()
                .find_map(|platform_root| table_location.strip_prefix(platform_root.as_str()))
                .context("foreign catalog metadata location")?;
            ensure!(
                suffix.starts_with("agent/"),
                "foreign platform metadata location"
            );
            suffix
        };
        ensure!(
            suffix.split('/').count() == 2 && suffix.split('/').all(|s| !s.is_empty()),
            "invalid catalog table location"
        );
        let prefix = format!("{table_location}/metadata/");
        ensure!(
            authority.tenant_id() == tenant && authority.metadata_prefix() == prefix,
            "foreign metadata delete authority"
        );
        Ok(Self {
            tenant: tenant.into(),
            bucket,
            prefix,
            authority,
        })
    }

    pub fn validate_binding(&self, tenant: &str, table_location: &str) -> Result<()> {
        ensure!(
            self.tenant == tenant && self.prefix == format!("{table_location}/metadata/"),
            "metadata GC binding differs"
        );
        Ok(())
    }

    fn validate_path(&self, path: &str) -> Result<()> {
        super::super::validate_object_uri(path)?;
        let leaf = path
            .strip_prefix(&self.prefix)
            .context("metadata delete escaped tenant table")?;
        ensure!(
            !leaf.is_empty()
                && !leaf.contains('/')
                && (leaf.ends_with(".avro") || leaf.ends_with(".json")),
            "invalid catalog metadata object"
        );
        Ok(())
    }

    /// Call only after the catalog reload/identity check, under writer custody.
    /// metadata-log entries are historical navigation, not retained snapshots:
    /// their old JSON versions must be erased along with obsolete manifests.
    pub async fn purge(
        &self,
        table_uuid: uuid::Uuid,
        current_metadata: &str,
        retained: &BTreeSet<String>,
    ) -> Result<()> {
        self.validate_path(current_metadata)?;
        ensure!(
            retained.contains(current_metadata),
            "current catalog metadata is not retained"
        );
        for path in retained {
            self.validate_path(path)?;
        }
        let inventory = self.authority.inventory().await?;
        ensure!(
            inventory.len() <= 1_000_000,
            "catalog metadata inventory exceeds bound"
        );
        // Validate the entire inventory before the first destructive request.
        let mut unique = BTreeSet::new();
        for path in inventory {
            self.validate_path(&path)?;
            ensure!(unique.insert(path), "duplicate metadata inventory object");
        }
        ensure!(
            retained.is_subset(&unique),
            "reachable catalog metadata absent from inventory"
        );
        for path in unique.difference(retained) {
            let request = MetadataDeleteRequest {
                tenant_id: self.tenant.clone(),
                bucket: self.bucket.clone(),
                metadata_prefix: self.prefix.clone(),
                key: path.clone(),
                current_metadata: current_metadata.into(),
                table_uuid,
            };
            ensure!(
                self.authority.retire(&request).await? == request,
                "catalog metadata absence receipt differs"
            );
        }
        // No receipt/cache acknowledgment until a fresh inventory confirms all
        // old versions and abandoned commit manifests are actually gone.
        let verified = self.authority.inventory().await?;
        ensure!(
            verified.len() <= 1_000_000,
            "catalog metadata inventory exceeds bound"
        );
        let mut remaining = BTreeSet::new();
        for path in verified {
            self.validate_path(&path)?;
            ensure!(
                retained.contains(&path),
                "unreachable catalog metadata remains"
            );
            ensure!(
                remaining.insert(path),
                "duplicate metadata inventory object"
            );
        }
        ensure!(
            &remaining == retained,
            "reachable catalog metadata disappeared during purge"
        );
        Ok(())
    }
}

pub(super) async fn retained_metadata(
    table: &iceberg::table::Table,
    bound: usize,
) -> Result<BTreeSet<String>> {
    ensure!(
        bound > 0 && bound <= 1_000_000 && table.metadata().snapshots().len() <= 1024,
        "catalog metadata reachability exceeds bound"
    );
    let mut retained = BTreeSet::new();
    let current = table
        .metadata_location()
        .context("catalog metadata location missing")?;
    super::super::hosted::check_metadata_path(table, current)?;
    retained.insert(current.to_string());
    for snapshot in table.metadata().snapshots() {
        super::super::hosted::check_metadata_path(table, snapshot.manifest_list())?;
        retained.insert(snapshot.manifest_list().to_string());
        let list = table.manifest_list_reader(snapshot).load().await?;
        ensure!(
            list.entries().len() <= bound,
            "catalog manifest list exceeds bound"
        );
        for descriptor in list.entries() {
            super::super::hosted::check_metadata_path(table, &descriptor.manifest_path)?;
            retained.insert(descriptor.manifest_path.clone());
            ensure!(
                retained.len() <= bound,
                "catalog metadata reachability exceeds bound"
            );
        }
    }
    Ok(retained)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };
    const TENANT: &str = "3867aaaa-0000-4000-8000-000000000001";
    struct Authority {
        tenant: String,
        prefix: String,
        objects: Mutex<Vec<String>>,
        requests: Mutex<Vec<MetadataDeleteRequest>>,
        acknowledge_only: AtomicBool,
    }
    #[async_trait::async_trait]
    impl MetadataDeleteAuthority for Authority {
        fn tenant_id(&self) -> &str {
            &self.tenant
        }
        fn metadata_prefix(&self) -> &str {
            &self.prefix
        }
        async fn inventory(&self) -> Result<Vec<String>> {
            Ok(self.objects.lock().unwrap().clone())
        }
        async fn retire(&self, request: &MetadataDeleteRequest) -> Result<MetadataDeleteRequest> {
            self.requests.lock().unwrap().push(request.clone());
            if !self.acknowledge_only.load(Ordering::SeqCst) {
                self.objects.lock().unwrap().retain(|p| p != &request.key);
            }
            Ok(request.clone())
        }
    }
    fn fixture() -> (MetadataGc, Arc<Authority>, BTreeSet<String>, String) {
        let location = format!(
            "s3://nano-shared-r2-{TENANT}/{}/nano/events_v1",
            crate::parts::format::iceberg_export_prefix(TENANT).unwrap()
        );
        let prefix = format!("{location}/metadata/");
        let current = format!("{prefix}current.metadata.json");
        let retained = BTreeSet::from([current.clone(), format!("{prefix}live.avro")]);
        let authority = Arc::new(Authority {
            tenant: TENANT.into(),
            prefix: prefix.clone(),
            objects: Mutex::new(
                retained
                    .iter()
                    .cloned()
                    .chain([
                        format!("{prefix}old.avro"),
                        format!("{prefix}old.metadata.json"),
                    ])
                    .collect(),
            ),
            requests: Mutex::new(vec![]),
            acknowledge_only: AtomicBool::new(false),
        });
        (
            MetadataGc::new(TENANT, &location, authority.clone()).unwrap(),
            authority,
            retained,
            current,
        )
    }
    #[tokio::test]
    async fn metadata_gc_keeps_current_reachable_files_and_requires_verified_absence() {
        let (gc, authority, retained, current) = fixture();
        authority.acknowledge_only.store(true, Ordering::SeqCst);
        assert!(gc
            .purge(uuid::Uuid::nil(), &current, &retained)
            .await
            .is_err());
        authority.acknowledge_only.store(false, Ordering::SeqCst);
        gc.purge(uuid::Uuid::nil(), &current, &retained)
            .await
            .unwrap();
        assert_eq!(
            authority
                .objects
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            retained
        );
        assert!(authority
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.tenant_id == TENANT && r.key != current));
    }
    #[tokio::test]
    async fn metadata_gc_rejects_foreign_or_escaped_inventory_before_any_delete() {
        for suffix in [
            "s3://nano-shared-r2-3867bbbb-0000-4000-8000-000000000002/foreign.avro".to_string(),
            "../data-00000.parquet".to_string(),
            "nested/old.avro".to_string(),
        ] {
            let (gc, authority, retained, current) = fixture();
            let path = if suffix.starts_with("s3://") {
                suffix
            } else {
                format!("{}{suffix}", authority.prefix)
            };
            authority.objects.lock().unwrap().push(path);
            assert!(gc
                .purge(uuid::Uuid::nil(), &current, &retained)
                .await
                .is_err());
            assert!(authority.requests.lock().unwrap().is_empty());
        }
    }
    #[test]
    fn metadata_gc_constructor_rejects_foreign_authority_or_table() {
        let (_, authority, _, _) = fixture();
        let location = authority.prefix.trim_end_matches("/metadata/");
        assert!(MetadataGc::new(
            "3867bbbb-0000-4000-8000-000000000002",
            location,
            authority.clone()
        )
        .is_err());
        assert!(MetadataGc::new(TENANT, &format!("{location}/other"), authority).is_err());
    }
    /// NAN-4614: platform tables live under this tenant's R2-managed root (or
    /// its legacy root until rotation), never another tenant's or a wider one.
    #[test]
    fn metadata_gc_accepts_only_this_tenants_platform_roots() {
        const OTHER: &str = "3867bbbb-0000-4000-8000-000000000002";
        let bucket = format!("nano-shared-r2-{TENANT}");
        let gc = |location: String| {
            let authority = Arc::new(Authority {
                tenant: TENANT.into(),
                prefix: format!("{location}/metadata/"),
                objects: Mutex::new(Vec::new()),
                requests: Mutex::new(vec![]),
                acknowledge_only: AtomicBool::new(false),
            });
            MetadataGc::new(TENANT, &location, authority)
        };
        gc(format!(
            "s3://{bucket}/__r2_data_catalog/agent/v2/tenant={TENANT}/agent/events_v1"
        ))
        .unwrap();
        gc(format!(
            "s3://{bucket}/lake/agent-catalog/v2/tenant={TENANT}/agent/events_v1"
        ))
        .unwrap();
        for refused in [
            format!("s3://{bucket}/__r2_data_catalog/agent/v2/tenant={OTHER}/agent/events_v1"),
            format!("s3://{bucket}/__r2_data_catalog/agent/v2/agent/events_v1"),
            format!("s3://{bucket}/__r2_data_catalog/{TENANT}/agent/events_v1"),
            format!("s3://{bucket}/__r2_data_catalog/agent/v2/tenant={TENANT}/other/events_v1"),
            format!("s3://nano-shared-r2-{OTHER}/__r2_data_catalog/agent/v2/tenant={TENANT}/agent/events_v1"),
        ] {
            assert!(gc(refused.clone()).is_err(), "{refused}");
        }
    }
}
