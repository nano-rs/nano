// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire shape of a schema profile's queryable field universe.
//!
//! `GET /api/schema/fields` answers with this in every deployment mode. The
//! builder is pure (no I/O) so both the dedicated handler and the hosted-shared
//! adapter (NAN-2361) render the exact same contract from any `SchemaProfile`
//! without a live pool — the shared adapter serves the canonical OCSF 1.9 lake
//! universe with an empty snapshot inventory because the process-global
//! manifest belongs to no tenant.

use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

use super::{OcsfProfile, SchemaId, SchemaProfile};

/// A single field in the active schema profile's queryable universe.
///
/// Profile-agnostic (OCSF Phase 3b): the shape is the same whether the
/// deployment runs UDM or OCSF — only the discriminator + the field set differ.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SchemaFieldInfo {
    /// Canonical field name as typed in nPL (e.g. `src_ip`, `src_endpoint.ip`).
    pub name: String,
    /// Value type (`string`, `ip_address`, `integer`, `uuid`, ...).
    pub r#type: String,
    /// Coarse category for grouping/UX (`network`, `authentication`, ...).
    pub category: String,
    /// Security entity the field denotes, if any (`ip`, `host`, `user`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
    /// Whether the field is PREWHERE/index-eligible for the active profile.
    pub prewhere: bool,
    /// Whether the profile exposes a `_search`/`.search` full-text companion for
    /// this field (UDM today exposes none in the field universe; reserved for
    /// OCSF's declared search companions).
    pub search: bool,
}

/// Response for the profile-aware `GET /api/schema/fields` endpoint.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SchemaFieldsResponse {
    /// The active schema discriminator (`udm` | `ocsf`) — lets the frontend
    /// hydrate its field universe and report the deployment's schema.
    pub schema: String,
    /// Exact external schema release for a strict canonical contract. Legacy
    /// table compatibility profiles intentionally return `None`: advertising
    /// merely `ocsf` is not enough for a client to prove OCSF 1.9 semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    /// True only when query fields are exact canonical schema paths. Desktop
    /// and other thick clients use this with `schema_version` to reject a
    /// legacy compatibility profile before they issue or persist queries.
    pub strict_canonical_fields: bool,
    /// The active profile's full field universe.
    pub fields: Vec<SchemaFieldInfo>,
}

/// Render a `#[serde(rename_all = "snake_case")]` enum to its wire string
/// (e.g. `FieldType::IpAddress` → `"ip_address"`) by reusing its `Serialize`
/// impl, so the API surface matches the schema-core vocabulary exactly and never
/// drifts from a hand-maintained `match`.
fn serde_field_value<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Build the `/api/schema/fields` response from a schema profile.
///
/// Pure (no I/O) so it is unit-testable against any profile without a live
/// AppState/DualPool.
pub fn schema_fields_response(profile: &dyn SchemaProfile) -> SchemaFieldsResponse {
    // PREWHERE-eligible set, looked up O(1) per field.
    let prewhere: HashSet<&str> = profile.prewhere_fields().iter().copied().collect();
    // Field-universe set, so a `{name}_search` companion can be detected without
    // a dedicated trait method (the profile declares its own search companions as
    // fields; UDM declares none, OCSF may declare `.search` siblings).
    let universe: HashSet<&str> = profile.fields().iter().map(|f| f.name).collect();

    let mut fields = profile
        .fields()
        .iter()
        .map(|f| {
            let search_companion = format!("{}_search", f.name);
            SchemaFieldInfo {
                name: f.name.to_string(),
                r#type: serde_field_value(&f.field_type),
                category: serde_field_value(&f.category),
                entity_type: f.entity_type.as_ref().map(serde_field_value),
                prewhere: prewhere.contains(f.name),
                search: universe.contains(search_companion.as_str()),
            }
        })
        .collect::<Vec<_>>();
    let static_names = fields
        .iter()
        .map(|field| field.name.clone())
        .collect::<HashSet<_>>();
    fields.extend(
        profile
            .snapshot_fields()
            .into_iter()
            .filter(|(name, _)| !static_names.contains(name))
            .map(|(name, field_type)| SchemaFieldInfo {
                category: serde_field_value(&profile.category(&name)),
                entity_type: profile.entity_type(&name).as_ref().map(serde_field_value),
                prewhere: prewhere.contains(name.as_str()),
                search: false,
                name,
                r#type: serde_field_value(&field_type),
            }),
    );
    fields.sort_by(|left, right| left.name.cmp(&right.name));

    let strict_canonical_fields = profile.uses_strict_canonical_fields();
    SchemaFieldsResponse {
        schema: serde_field_value(&profile.id()),
        schema_version: (profile.id() == SchemaId::Ocsf && strict_canonical_fields)
            .then(|| crate::parsers::OCSF_VALIDATION_VERSION.to_string()),
        strict_canonical_fields,
        fields,
    }
}

/// The tenant-neutral hosted-shared field universe (NAN-2361).
///
/// Every shared tenant queries the canonical OCSF 1.9 lake contract. The
/// process-global snapshot inventory (`unmapped.*` spill paths parsed from the
/// worker manifest) describes whichever generation this API instance is
/// pinned to and therefore must never be shown to a tenant, so the shared
/// adapter renders the static universe with an EMPTY snapshot inventory. A
/// tenant's own spill paths are discovered through the tenant-pinned search
/// worker, not through this deployment-level endpoint.
pub fn shared_tenant_lake_schema_fields() -> Result<SchemaFieldsResponse, String> {
    let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::new())?;
    Ok(schema_fields_response(&profile))
}

/// NAN-2718: one tenant's field list in a shared process: that tenant's own
/// verified lake inventory from the tenant-keyed cache, or the canonical
/// OCSF 1.9 universe when none is verified yet. Never another tenant's fields.
pub fn tenant_lake_schema_fields(tenant_id: uuid::Uuid) -> SchemaFieldsResponse {
    schema_fields_response(super::tenant_lake_schema::profile_for_tenant(tenant_id).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_tenant_universe_is_strict_ocsf_1_9_with_no_snapshot_inventory() {
        let response = shared_tenant_lake_schema_fields().expect("static lake profile");
        assert_eq!(response.schema, "ocsf");
        assert!(response.strict_canonical_fields);
        assert_eq!(
            response.schema_version.as_deref(),
            Some(crate::parsers::OCSF_VALIDATION_VERSION)
        );
        assert!(!response.fields.is_empty());
        assert!(
            response.fields.iter().all(|f| !f.name.starts_with("unmapped.")),
            "no deployment-pinned spill inventory may leak into the shared universe"
        );
        let mut names: Vec<&str> = response.fields.iter().map(|f| f.name.as_str()).collect();
        let sorted = {
            let mut copy = names.clone();
            copy.sort_unstable();
            copy
        };
        assert_eq!(names, sorted, "fields are sorted for a stable contract");
        names.dedup();
        assert_eq!(names.len(), response.fields.len(), "no duplicate field names");
    }

    #[test]
    fn shared_tenant_universe_matches_the_static_lake_profile_exactly() {
        let shared = shared_tenant_lake_schema_fields().expect("static lake profile");
        let dedicated = schema_fields_response(&OcsfProfile::lake_1_9());
        assert_eq!(
            serde_json::to_value(&shared).unwrap(),
            serde_json::to_value(&dedicated).unwrap()
        );
    }
}
