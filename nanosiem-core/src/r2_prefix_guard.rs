// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hard deny guard for object deletes in a tenant R2 bucket (NAN-2596).
//!
//! `nano-shared-r2-<tenant_uuid>` is shared by two owners. nanosiem writes
//! and reaps its own namespaces (`bronze-v2/`, `raw-handoff-v1/`, `raw-handoff-v2/`,
//! `otel-handoff-v1/`, `query-results-v1/`, `__r2_data_catalog/`, the UID
//! ledger, ...). The platform owns `tenants/<tenant_uuid>/...`, which holds the
//! verified tenant parser bundles (`tenants/<uuid>/parser-bundles/<sha>.tar.gz`)
//! the Worker fetches at runtime. The platform owns their whole lifecycle, so no
//! nanosiem reaper, compactor, GC, retention or teardown path may ever delete
//! (or list-then-delete) anything there.
//!
//! Every nanosiem delete path calls [`assert_deletable`] on each key and,
//! when it lists before deleting, [`assert_deletable_prefix`] on the list
//! prefix. The Worker mirrors this in `workers/hosted-ingest/src/r2-prefix-guard.js`;
//! keep the two in lockstep.

/// Namespaces in a tenant bucket that nanosiem's Rust delete paths must never
/// delete from:
/// - `tenants/`: the platform's (verified tenant parser bundles);
/// - `edge-log-v1/` (NAN-2874): the tenant Worker's edge-log Durable Object
///   owns its overflow objects and deletes them itself after commit plus
///   retention (or at purge). No reaper, GC, retention or teardown path here
///   may touch them, or it could drop uncommitted edge batches. The Worker's
///   JS guard does not list it: the Worker is the owner.
pub const RESERVED_PREFIXES: [&str; 2] = ["tenants/", "edge-log-v1/"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum R2PrefixGuardError {
    #[error("refusing R2 delete: key is empty or ambiguous")]
    InvalidKey,
    #[error("refusing R2 delete: key is under the platform-owned or Worker-owned `{0}` namespace")]
    ReservedKey(&'static str),
    #[error("refusing R2 list-then-delete: prefix can match the platform-owned or Worker-owned `{0}` namespace")]
    ReservedPrefix(&'static str),
}

/// The key as the provider will store it. OpenDAL and object_store both drop
/// leading `/` and `./` segments and collapse `//`, so `/tenants/x` and
/// `./tenants//x` land on `tenants/x`; check that form. `..` segments are
/// ambiguous and refused outright.
fn canonical(key: &str) -> Option<String> {
    let mut parts = Vec::new();
    for part in key.split('/') {
        match part {
            "" | "." => continue,
            ".." => return None,
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

/// Refuse one object delete whose key is (or canonicalises to) a key under a
/// reserved namespace.
pub fn assert_deletable(key: &str) -> Result<(), R2PrefixGuardError> {
    if key.chars().any(char::is_control) {
        return Err(R2PrefixGuardError::InvalidKey);
    }
    let canonical = canonical(key).ok_or(R2PrefixGuardError::InvalidKey)?;
    if canonical.is_empty() {
        return Err(R2PrefixGuardError::InvalidKey);
    }
    // A trailing-slash-less "tenants" also names the reserved directory.
    let probe = format!("{canonical}/");
    for reserved in RESERVED_PREFIXES {
        if probe.starts_with(reserved) {
            return Err(R2PrefixGuardError::ReservedKey(reserved));
        }
    }
    Ok(())
}

/// Refuse a list prefix that a list-then-delete loop would use when any key it
/// can return lies under a reserved namespace. That is: the prefix is empty
/// (the whole bucket), a prefix of `tenants/` (`t`, `ten`, `tenants`), or
/// inside `tenants/`.
pub fn assert_deletable_prefix(prefix: &str) -> Result<(), R2PrefixGuardError> {
    if prefix.chars().any(char::is_control) || prefix.split('/').any(|part| part == "..") {
        return Err(R2PrefixGuardError::InvalidKey);
    }
    let trimmed = prefix.trim_start_matches('/');
    for reserved in RESERVED_PREFIXES {
        if reserved.starts_with(trimmed) || trimmed.starts_with(reserved) {
            return Err(R2PrefixGuardError::ReservedPrefix(reserved));
        }
    }
    Ok(())
}

/// [`assert_deletable`] for an `s3://bucket/key` URI.
pub fn assert_deletable_uri(uri: &str) -> Result<(), R2PrefixGuardError> {
    let rest = uri.strip_prefix("s3://").ok_or(R2PrefixGuardError::InvalidKey)?;
    let (_, key) = rest.split_once('/').ok_or(R2PrefixGuardError::InvalidKey)?;
    assert_deletable(key)
}

/// Whether `key` is (or canonicalises to) a key under a reserved namespace.
pub fn is_reserved_key(key: &str) -> bool {
    matches!(assert_deletable(key), Err(R2PrefixGuardError::ReservedKey(_)))
}

/// Wire-level backstop for S3-compatible HTTP clients (OpenDAL, object_store).
///
/// Returns a refusal when one provider request would delete a reserved key:
/// a `DELETE` object (or multipart abort) whose path names one, or a
/// `POST ?delete` DeleteObjects batch whose XML body lists one. The bucket may
/// be in the host (virtual-host style) or the first path segment (path
/// style), so both readings of the path are checked. A DeleteObjects batch
/// whose body cannot be inspected fails closed.
pub fn wire_delete_refusal(
    method: &str,
    path: &str,
    query: &str,
    body: Option<&[u8]>,
) -> Option<R2PrefixGuardError> {
    let reserved = |key: &str| match assert_deletable(key) {
        Err(refusal @ R2PrefixGuardError::ReservedKey(_)) => Some(refusal),
        _ => None,
    };
    if method.eq_ignore_ascii_case("DELETE") {
        let decoded = urlencoding::decode(path).map(|p| p.into_owned()).unwrap_or_else(|_| path.to_string());
        let virtual_host = decoded.trim_start_matches('/');
        let path_style = virtual_host.split_once('/').map(|(_, key)| key).unwrap_or("");
        return reserved(virtual_host).or_else(|| reserved(path_style));
    }
    let batch_delete = method.eq_ignore_ascii_case("POST")
        && query
            .split('&')
            .any(|pair| pair.split('=').next() == Some("delete"));
    if !batch_delete {
        return None;
    }
    let Some(body) = body else {
        return Some(R2PrefixGuardError::InvalidKey);
    };
    let Ok(text) = std::str::from_utf8(body) else {
        return Some(R2PrefixGuardError::InvalidKey);
    };
    let mut rest = text;
    while let Some(start) = rest.find("<Key>") {
        let after = &rest[start + 5..];
        let Some(end) = after.find("</Key>") else {
            return Some(R2PrefixGuardError::InvalidKey);
        };
        let key = after[..end]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&");
        if let Some(refusal) = reserved(&key) {
            return Some(refusal);
        }
        rest = &after[end + 6..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE: &str = "tenants/23610000-0000-4000-8000-00000000000a/parser-bundles/\
        0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.tar.gz";

    #[test]
    fn parser_bundle_keys_are_never_deletable() {
        for key in [
            BUNDLE,
            "tenants/x",
            "tenants",
            "tenants/",
            "/tenants/x",
            "./tenants/x",
            "//tenants//x",
        ] {
            assert!(assert_deletable(key).is_err(), "{key} must be refused");
        }
        assert!(assert_deletable_uri(&format!(
            "s3://nano-shared-r2-23610000-0000-4000-8000-00000000000a/{BUNDLE}"
        ))
        .is_err());
    }

    #[test]
    fn nanosiem_namespaces_stay_deletable() {
        for key in [
            "bronze-v2/shard=0/tenant_id=t1/1758585600-x.parquet",
            "raw-handoff-v1/tenant_uuid=u/a.bin",
            "raw-handoff-v2/tenant_uuid=u/group=0000000000000000000000000000000000000000000000000000000000000000.rawg",
            "otel-handoff-v1/tenant_uuid=u/dataset=spans/hour=1/b",
            "query-results-v1/tenant-abc/job-1/manifest.json",
            "__r2_data_catalog/u/events/data/x.parquet",
            "tenants-archive/x",
            "a/tenants/x",
        ] {
            assert_eq!(assert_deletable(key), Ok(()), "{key}");
        }
    }

    /// NAN-2874: the Worker's edge-log DO owns its overflow objects; no Rust
    /// delete path may drop them (they can hold uncommitted edge batches).
    #[test]
    fn worker_owned_edge_log_objects_are_never_deletable() {
        let key = "edge-log-v1/tenant_uuid=23610000-0000-4000-8000-00000000000a/overflow/0000000000000001-0000000000000002.bin";
        assert_eq!(assert_deletable(key), Err(R2PrefixGuardError::ReservedKey("edge-log-v1/")));
        assert!(is_reserved_key(&format!("./{key}")));
        assert!(assert_deletable_prefix("edge-log-v1/").is_err());
        assert!(assert_deletable_prefix("edge").is_err());
        assert!(assert_deletable_uri(&format!("s3://nano-shared-r2-x/{key}")).is_err());
        assert!(wire_delete_refusal("DELETE", &format!("/bucket/{key}"), "", None).is_some());
    }

    #[test]
    fn empty_ambiguous_and_control_keys_are_refused() {
        for key in ["", "/", "./", "a/../tenants/x", "bronze-v2/\n"] {
            assert!(assert_deletable(key).is_err(), "{key:?}");
        }
    }

    #[test]
    fn wire_deletes_naming_tenants_are_refused_in_both_url_styles() {
        let bucket = "nano-shared-r2-23610000-0000-4000-8000-00000000000a";
        assert!(wire_delete_refusal("DELETE", &format!("/{bucket}/tenants/u/parser-bundles/a.tar.gz"), "", None).is_some());
        assert!(wire_delete_refusal("DELETE", "/tenants/u/parser-bundles/a.tar.gz", "", None).is_some());
        assert!(wire_delete_refusal("DELETE", &format!("/{bucket}/tenants%2Fu%2Fa.tar.gz"), "", None).is_some());
        assert!(wire_delete_refusal("DELETE", &format!("/{bucket}/tenants/u/a"), "uploadId=x", None).is_some());
        assert!(wire_delete_refusal("DELETE", &format!("/{bucket}/bronze-v2/shard=0/x"), "", None).is_none());
        assert!(wire_delete_refusal("DELETE", "/bronze-v2/shard=0/x", "", None).is_none());
        assert!(wire_delete_refusal("GET", &format!("/{bucket}/tenants/u/a"), "", None).is_none());

        let batch = |keys: &[&str]| {
            let objects: String = keys.iter().map(|k| format!("<Object><Key>{k}</Key></Object>")).collect();
            format!("<?xml version=\"1.0\"?><Delete><Quiet>true</Quiet>{objects}</Delete>")
        };
        let mixed = batch(&["bronze-v2/a", "tenants/u/parser-bundles/b.tar.gz"]);
        assert!(wire_delete_refusal("POST", &format!("/{bucket}"), "delete", Some(mixed.as_bytes())).is_some());
        assert!(wire_delete_refusal("POST", "/", "delete=", Some(batch(&["./tenants/u/x"]).as_bytes())).is_some());
        let clean = batch(&["bronze-v2/a", "raw-handoff-v1/b&amp;c"]);
        assert!(wire_delete_refusal("POST", &format!("/{bucket}"), "delete", Some(clean.as_bytes())).is_none());
        assert!(wire_delete_refusal("POST", &format!("/{bucket}"), "delete", None).is_some(), "uninspectable batch fails closed");
        assert!(wire_delete_refusal("POST", &format!("/{bucket}/k"), "uploads", None).is_none());
    }

    #[test]
    fn list_prefixes_that_can_reach_tenants_are_refused() {
        for prefix in ["", "/", "t", "ten", "tenants", "tenants/", "tenants/u/", "/tenants/u"] {
            assert!(assert_deletable_prefix(prefix).is_err(), "{prefix:?}");
        }
        for prefix in [
            "bronze-v2/",
            "raw-handoff-v1/tenant_uuid=u/",
            "raw-handoff-v2/tenant_uuid=u/",
            "query-results-v1/",
            "__r2_data_catalog/u/",
            "tenants-archive/",
        ] {
            assert_eq!(assert_deletable_prefix(prefix), Ok(()), "{prefix}");
        }
    }
}
