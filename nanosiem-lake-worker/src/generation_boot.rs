// SPDX-License-Identifier: AGPL-3.0-or-later
//! Retained config recovery precedes next-generation preparation. This is not
//! readiness: normal assignment, signed-tail and completeness gates still run.
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};
use crate::config::WorkerConfigFile;
const DOMAIN: &[u8] = b"nano-retained-worker-config-v1\0";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retained { config: serde_json::Value, mac: String }
fn authenticate(key: &[u8], value: &serde_json::Value) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(DOMAIN); mac.update(&serde_json::to_vec(value)?); Ok(mac)
}
pub fn remember(config: &Path) -> Result<()> {
    let configured = WorkerConfigFile::read(config)?;
    configured.admission_proof()?;
    let key = crate::generation_proof::key(&configured.entity_sidecar.hmac_key.path)?;
    let value = serde_json::from_slice(&fs::read(config)?)?;
    let mac = hex::encode(authenticate(&key, &value)?.finalize().into_bytes());
    atomic(&config.with_extension("retained.json"), &serde_json::to_vec(&Retained { config: value, mac })?)
}
pub fn restore(config: &Path) -> Result<bool> {
    let lock = fs::OpenOptions::new().create(true).truncate(false).read(true).write(true)
        .open(config.with_extension("generation.lock"))?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let seed = WorkerConfigFile::read(config)?;
    if seed.generation_id != "bootstrap-pending" { return Ok(false); }
    let path = config.with_extension("retained.json");
    if !path.exists() { return Ok(false); }
    if fs::metadata(&path)?.len() > 16 * 1024 * 1024 { bail!("retained config exceeds its bound"); }
    let key = crate::generation_proof::key(&seed.entity_sidecar.hmac_key.path)?;
    let mut retained: Retained = serde_json::from_slice(&fs::read(path)?)?;
    authenticate(&key, &retained.config)?.verify_slice(&hex::decode(&retained.mac)?)
        .context("retained configuration authentication failed")?;
    let parsed: WorkerConfigFile = serde_json::from_value(retained.config.clone())?;
    if parsed.assigned_tenant_id != seed.assigned_tenant_id { bail!("retained assignment differs from seed"); }
    parsed.admission_proof()?;
    // Keep receiver runtime, credentials, capacity and independently published
    // enrichment state. Only the retained event generation crosses this seam.
    let seed_value: serde_json::Value = serde_json::from_slice(&fs::read(config)?)?;
    retained.config = event_config_from_seed(&seed_value, &retained.config)?;
    atomic(config, &serde_json::to_vec_pretty(&retained.config)?)?;
    tracing::info!("restored proven retained generation before next-generation preparation");
    Ok(true)
}
/// Merge proven event artifacts into this pod's existing assignment/config.
/// Risk/IOC state and runtime executables have separate admission lifetimes.
pub fn event_config_from_seed(seed: &serde_json::Value, retained: &serde_json::Value) -> Result<serde_json::Value> {
    if seed["assigned_tenant_id"] != retained["assigned_tenant_id"] { bail!("retained event assignment mismatch"); }
    let mut value = seed.clone();
    for field in ["generation_id", "generation_proof", "snapshot_cache", "entity_sidecar", "keyword_sidecar", "count_rollup", "identity_snapshot", "prevalence_snapshots"] {
        if let Some(retained) = retained.get(field) { value[field] = retained.clone(); }
        else { value.as_object_mut().context("seed must be an object")?.remove(field); }
    }
    for field in ["source_manifest", "iceberg_metadata_file_path"] { value["tenant"][field] = retained["tenant"][field].clone(); }
    value["entity_sidecar"]["hmac_key"] = seed["entity_sidecar"]["hmac_key"].clone();
    crate::config::refresh_derivative_generation_id(&mut value)?;
    Ok(value)
}

pub(crate) fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("config has no parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?; file.as_file().sync_all()?; file.persist(path)?;
    fs::File::open(parent)?.sync_all()?; Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_restores_before_consumer_work_and_rejects_failed_proof() {
        let root = tempfile::tempdir().unwrap();
        let (proof, config) = crate::generation_proof::tests::fixture(&root.path().join("generation"));
        let path = root.path().join("worker.json");
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        remember(&path).unwrap();
        let mut seed = config.clone(); seed["generation_id"] = serde_json::json!("bootstrap-pending"); seed.as_object_mut().unwrap().remove("generation_proof");
        fs::write(&path, serde_json::to_vec(&seed).unwrap()).unwrap();
        assert!(restore(&path).unwrap());
        let restored = WorkerConfigFile::read(&path).unwrap();
        assert_ne!(restored.generation_id, "bootstrap-pending");
        assert_eq!(restored.admission_proof().unwrap().identity, proof.identity);
        assert!(!restore(&path).unwrap(), "active config is never overwritten");
        fs::write(&path, serde_json::to_vec(&seed).unwrap()).unwrap();
        fs::remove_file(proof.root.join("derivatives/index/0.idx")).unwrap();
        assert!(restore(&path).is_err());
        assert_eq!(WorkerConfigFile::read(&path).unwrap().generation_id, "bootstrap-pending");
    }
    #[test]
    fn retirement_tombstone_blocks_retained_boot_even_while_files_are_pinned() {
        let root = tempfile::tempdir().unwrap();
        let (_, config) = crate::generation_proof::tests::fixture(&root.path().join("snapshot-42-fixture"));
        let path = root.path().join("worker.json"); fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        remember(&path).unwrap();
        let mut seed = config; seed["generation_id"] = serde_json::json!("bootstrap-pending");
        fs::write(&path, serde_json::to_vec(&seed).unwrap()).unwrap();
        let marker = crate::generation_proof::tombstone(root.path(), "snapshot-42-fixture");
        fs::create_dir_all(marker.parent().unwrap()).unwrap(); fs::write(marker, b"retired").unwrap();
        assert!(restore(&path).is_err());
        assert_eq!(WorkerConfigFile::read(&path).unwrap().generation_id, "bootstrap-pending");
    }

    #[test]
    fn retained_events_keep_receivers_runtime_capacity_and_enrichment_state() {
        let root = tempfile::tempdir().unwrap();
        let (_, retained) = crate::generation_proof::tests::fixture(&root.path().join("generation"));
        let mut seed = retained.clone();
        seed["generation_id"] = serde_json::json!("bootstrap-pending");
        seed["compiler"]["sha256"] = serde_json::json!("a".repeat(64));
        seed["tenant"]["max_memory_bytes"] = serde_json::json!(123456789);
        seed["risk_snapshot"] = serde_json::json!({"receiver":"risk"});
        seed["ioc_snapshot"] = serde_json::json!({"receiver":"ioc"});
        let adopted = event_config_from_seed(&seed, &retained).unwrap();
        for field in ["compiler", "native_library", "risk_snapshot", "ioc_snapshot"] { assert_eq!(adopted[field], seed[field]); }
        assert_eq!(adopted["tenant"]["max_memory_bytes"], seed["tenant"]["max_memory_bytes"]);
        assert_eq!(adopted["snapshot_cache"], retained["snapshot_cache"]);
        assert_ne!(adopted["generation_id"], "bootstrap-pending");
    }

    #[test]
    fn absent_or_tampered_retained_config_cannot_boot() {
        let root = tempfile::tempdir().unwrap();
        let (_, mut config) = crate::generation_proof::tests::fixture(&root.path().join("generation"));
        config["generation_id"] = serde_json::json!("bootstrap-pending");
        let path = root.path().join("worker.json"); fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(!restore(&path).unwrap());
        fs::write(path.with_extension("retained.json"), b"{}").unwrap();
        assert!(restore(&path).is_err());
    }
}
