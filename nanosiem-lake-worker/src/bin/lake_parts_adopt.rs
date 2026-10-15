// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lean-lake phase 4 (NAN-2870): adopt a tenant's existing history as parts.
//!
//! Subcommands (runbook: docs-internal/NAN-2870-adopt-history-runbook.md):
//! - `extract-stamps` verify the signed generation and extract its stamp
//!   ledger from the downloaded `source-object-stamps` archive.
//! - `plan`   verify the signed generation + stamp ledger; print the plan.
//! - `run`    adopt (resumable, idempotent) into a part store.
//! - `counts` read the generation snapshot's per-object Iceberg counts.
//! - `parity` check adopted history against those counts (the exit gate).
//!
//! Source objects are only read (a read-only bucket mirror). Writes go only
//! to the part store: sidecars, records and log entries under
//! `lake/parts/v1/tenant=<uuid>/`. This binary has no live mode: the store is
//! a local directory (`--store-root`) and records are signed by a LAB owner
//! key (`--lab-signer-key-id` / `--lab-signing-key-file`), a rehearsal of
//! the platform's `lake-parts:sign`. The live run needs the owner writer-class
//! store adapter and the owner sign client (runbook precondition 1).

use anyhow::{bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use iceberg::Catalog;
use nanosiem_lake_worker::generation::ObjectStampManifest;
use nanosiem_lake_worker::iceberg::{table_ident, CatalogConfig};
use nanosiem_lake_worker::parts::part_log::LocalObjectStore;
use nanosiem_lake_worker::parts::provenance::TenantKeySet;
use nanosiem_lake_worker::parts::format::MAX_OBJECT_BYTES;
use nanosiem_lake_worker::parts::{event_hour_of, HOUR_US};
use nanosiem_lake_worker::parts_adopt::build::{object_profile, BuildBudgets, ObjectProfile};
use nanosiem_lake_worker::parts_adopt::{
    check_parity, extract_stamp_ledger, run_adoption, verify_generation, AdoptOptions, AdoptSigner, AdoptionPlan, BucketMirrorSource,
    GenerationCounts,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    let mut argv = std::env::args().skip(1);
    let command = argv.next().context("usage: lake_parts_adopt <extract-stamps|plan|run|counts|parity> --flag value ...")?;
    let mut args = Args::parse(argv)?;
    let output = match command.as_str() {
        "extract-stamps" => {
            let tenant = args.take("--tenant-id")?;
            let bytes = std::fs::read(args.path("--bundle-manifest")?)?;
            let public_key = hex32(&args.take("--bundle-public-key-hex")?)?;
            let identity = args.take("--expected-bundle-identity")?;
            let archive = std::fs::read(args.path("--stamp-archive")?)?;
            let out = args.path("--out")?;
            args.done()?;
            let verified = verify_generation(&bytes, &tenant, &public_key, &identity)?;
            let ledger = extract_stamp_ledger(&verified, &archive)?;
            std::fs::write(&out, serde_json::to_vec(&ledger)?)?;
            serde_json::json!({ "objects": ledger.objects.len(), "snapshot_id": ledger.snapshot_id, "out": out })
        }
        "plan" => {
            let plan = load_plan(&mut args)?;
            let mirror = args.maybe("--source-mirror").map(PathBuf::from);
            let max_object_bytes: u64 = args.maybe("--max-object-bytes").map(|v| v.parse()).transpose()?.unwrap_or(MAX_OBJECT_BYTES);
            let max_row_group_rows: u64 = args
                .maybe("--max-row-group-rows")
                .map(|v| v.parse())
                .transpose()?
                .unwrap_or(BuildBudgets::default().max_row_group_rows);
            args.done()?;
            let largest = plan.largest_object().context("plan has no objects")?;
            // Footers only (no row decoding): the largest row group bounds a
            // build's token set; the largest object bounds a mirror read.
            let mut widest = None::<(String, ObjectProfile)>;
            if let Some(mirror) = &mirror {
                for object in &plan.objects {
                    let path = mirror.join(&object.key);
                    if !path.exists() {
                        continue;
                    }
                    let profile = object_profile(&path)?;
                    if widest.as_ref().is_none_or(|(_, p)| profile.max_row_group_rows > p.max_row_group_rows) {
                        widest = Some((object.key.clone(), profile));
                    }
                }
            }
            let largest_profile = mirror.as_ref().map(|m| m.join(&largest.key)).filter(|p| p.exists()).map(|p| object_profile(&p)).transpose()?;
            let mut refusals = Vec::new();
            if largest.stamp.size_bytes > max_object_bytes {
                refusals.push(format!("largest object {} is {} bytes > {max_object_bytes}", largest.key, largest.stamp.size_bytes));
            }
            if let Some((key, profile)) = &widest {
                if profile.max_row_group_rows > max_row_group_rows {
                    refusals.push(format!("object {key} has a {}-row row group > {max_row_group_rows}", profile.max_row_group_rows));
                }
            }
            let report = serde_json::json!({
                "tenant_id": plan.tenant_id,
                "generation_id": plan.anchor.generation_id,
                "snapshot_id": plan.anchor.snapshot_id,
                "bucket": plan.bucket,
                "objects": plan.objects.len(),
                "bytes": plan.total_bytes(),
                "t0_hour": plan.t0_hour(),
                "generation_min_event_hour": plan.generation_min_event_hour,
                "generation_max_event_hour": plan.generation_max_event_hour,
                "objects_skipped_by_key_partition": plan.objects_at_or_after_t0(),
                "largest_object": { "key": largest.key, "bytes": largest.stamp.size_bytes, "profile": largest_profile },
                "widest_row_group": widest.as_ref().map(|(key, profile)| serde_json::json!({ "key": key, "profile": profile })),
                "bounds": { "max_object_bytes": max_object_bytes, "max_row_group_rows": max_row_group_rows },
                "refusals": refusals,
                "anchor": plan.anchor,
            });
            if !refusals.is_empty() {
                println!("{}", serde_json::to_string_pretty(&report)?);
                bail!("plan exceeds its configured bounds");
            }
            report
        }
        "run" => {
            let plan = load_plan(&mut args)?;
            let store = LocalObjectStore::new(args.path("--store-root")?)?;
            let source = BucketMirrorSource::new(args.path("--source-mirror")?);
            let (signer, trusted) = load_signer(&mut args)?;
            let epoch = args.take("--writer-epoch")?.parse().context("--writer-epoch")?;
            let signer = AdoptSigner { signer: &signer, trusted: &trusted, writer_epoch: epoch };
            let mut options = AdoptOptions::new(args.path("--work-dir")?, args.take("--writer-build")?);
            if let Some(batch) = args.maybe("--batch-parts") {
                options.batch_parts = batch.parse().context("--batch-parts")?;
            }
            if let Some(rows) = args.maybe("--max-row-group-rows") {
                options.budgets.max_row_group_rows = rows.parse().context("--max-row-group-rows")?;
            }
            if let Some(sign) = args.maybe("--sign-batch") {
                options.sign_batch = sign.parse().context("--sign-batch")?;
            }
            if let Some(max) = args.maybe("--max-objects") {
                options.max_objects = Some(max.parse().context("--max-objects")?);
            }
            args.done()?;
            let now = || chrono::Utc::now().timestamp_millis();
            serde_json::to_value(run_adoption(&store, &source, &plan, &signer, &options, &now).await?)?
        }
        "counts" => {
            let catalog = catalog_config(&mut args)?;
            let table = table_ident(&args.take("--table")?)?;
            let snapshot_id: i64 = args.take("--snapshot-id")?.parse().context("--snapshot-id")?;
            args.done()?;
            let table = catalog.load().await?.load_table(&table).await?;
            serde_json::to_value(GenerationCounts::from_iceberg_snapshot(&table, snapshot_id).await?)?
        }
        "parity" => {
            let plan = load_plan(&mut args)?;
            let store = LocalObjectStore::new(args.path("--store-root")?)?;
            let counts: GenerationCounts = serde_json::from_slice(&std::fs::read(args.path("--expected-counts")?)?)?;
            if u64::try_from(counts.snapshot_id).ok() != Some(plan.anchor.snapshot_id) {
                bail!("expected counts are for snapshot {}, the generation is {}", counts.snapshot_id, plan.anchor.snapshot_id);
            }
            let trusted = trusted_keys(&args.take("--trusted-keys")?)?;
            args.done()?;
            let report =
                check_parity(&store, &plan.tenant_id, &trusted, &counts, plan.t0_us, plan.generation_max_event_hour).await?;
            let ok = report.ok;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !ok {
                std::process::exit(2);
            }
            return Ok(());
        }
        other => bail!("unknown subcommand {other}"),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn load_plan(args: &mut Args) -> Result<AdoptionPlan> {
    let tenant = args.take("--tenant-id")?;
    let manifest_path = args.path("--bundle-manifest")?;
    let manifest_key = args.maybe("--bundle-manifest-key");
    let public_key = hex32(&args.take("--bundle-public-key-hex")?)?;
    // Required: adoption anchors on the CURRENT published generation.
    let expected_identity = args.take("--expected-bundle-identity")?;
    let stamps: ObjectStampManifest =
        serde_json::from_slice(&std::fs::read(args.path("--object-stamps")?)?).context("parse --object-stamps")?;
    let t0 = chrono::DateTime::parse_from_rfc3339(&args.take("--t0")?).context("--t0 must be RFC 3339")?;
    let t0_us = t0.timestamp_micros();
    if t0_us % HOUR_US != 0 {
        bail!("--t0 must be an hour boundary (UTC); event hour {}", event_hour_of(t0_us));
    }
    let bytes = std::fs::read(&manifest_path)?;
    let verified = verify_generation(&bytes, &tenant, &public_key, &expected_identity)?;
    // The key is derived from the signed identity and the bytes; a given key
    // must agree with it.
    if let Some(key) = manifest_key {
        if key != verified.manifest_key() {
            bail!("--bundle-manifest-key differs from the key derived from the signed manifest ({})", verified.manifest_key());
        }
    }
    AdoptionPlan::from_verified_generation(&verified, &stamps, t0_us)
}

/// The rehearsal signer: a lab key standing in for the owner release key.
fn load_signer(args: &mut Args) -> Result<(LocalPartSigner, nanosiem_lake_worker::parts::provenance::TenantKeySet)> {
    let key_id = args.take("--lab-signer-key-id")?;
    let seed = std::fs::read_to_string(args.path("--lab-signing-key-file")?)?;
    let signer = LocalPartSigner::new(&key_id, SigningKey::from_bytes(&hex32(seed.trim())?))?;
    // No default trust: the operator names the tenant's trusted key set. The
    // (lab) signer must be in it: every signature is verified against it
    // before a record is stored, so an untrusted signer fails the first batch.
    let list = args.take("--trusted-keys")?;
    if !list.split(',').any(|item| item.trim().split_once('=').is_some_and(|(id, _)| id == key_id)) {
        bail!("--trusted-keys does not name the signer key id {key_id}");
    }
    Ok((signer, trusted_keys(&list)?))
}

/// `key_id=hex,key_id=hex`: the tenant's trusted owner release keys.
fn trusted_keys(list: &str) -> Result<TenantKeySet> {
    let keys = list
        .split(',')
        .map(|item| {
            let (id, hex) = item.trim().split_once('=').context("--trusted-keys items are key_id=hex")?;
            Ok((id.to_string(), VerifyingKey::from_bytes(&hex32(hex)?).context("invalid public key")?))
        })
        .collect::<Result<Vec<_>>>()?;
    if keys.is_empty() {
        bail!("--trusted-keys is empty");
    }
    Ok(TenantKeySet::new(keys))
}

fn hex32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).context("expected 64 hex characters")?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

fn catalog_config(args: &mut Args) -> Result<CatalogConfig> {
    let env = |name: Option<String>| -> Result<Option<String>> {
        name.map(|n| std::env::var(&n).with_context(|| format!("environment variable {n} is required"))).transpose()
    };
    let default_credentials = args.flag("--s3-default-credentials");
    let (access, secret) = if default_credentials {
        (String::new(), String::new())
    } else {
        (
            env(Some(args.take("--s3-access-key-env")?))?.unwrap_or_default(),
            env(Some(args.take("--s3-secret-key-env")?))?.unwrap_or_default(),
        )
    };
    Ok(CatalogConfig {
        uri: args.take("--catalog-uri")?,
        warehouse: args.take("--warehouse")?,
        credential: env(args.maybe("--catalog-credential-env"))?,
        token_file: args.maybe("--catalog-token-file").map(PathBuf::from),
        oauth_scope: args.maybe("--catalog-oauth-scope"),
        oauth_audience: args.maybe("--catalog-oauth-audience"),
        oauth_server_uri: args.maybe("--catalog-oauth-server-uri"),
        realm: args.maybe("--catalog-realm"),
        allow_anonymous: false,
        s3_endpoint: args.maybe("--s3-endpoint").unwrap_or_default(),
        s3_region: args.maybe("--s3-region").unwrap_or_else(|| "us-east-1".into()),
        s3_access_key: access,
        s3_secret_key: secret,
        s3_session_token: env(args.maybe("--s3-session-token-env"))?,
        s3_path_style_access: !args.flag("--s3-virtual-host-style"),
        s3_default_credentials: default_credentials,
        vended_credentials: args.flag("--vended-credentials"),
    })
}

struct Args {
    values: BTreeMap<String, String>,
    flags: Vec<String>,
}

const FLAGS: &[&str] = &["--s3-default-credentials", "--s3-virtual-host-style", "--vended-credentials"];

impl Args {
    fn parse(mut argv: impl Iterator<Item = String>) -> Result<Self> {
        let mut values = BTreeMap::new();
        let mut flags = Vec::new();
        while let Some(name) = argv.next() {
            if FLAGS.contains(&name.as_str()) {
                flags.push(name);
                continue;
            }
            let value = argv.next().with_context(|| format!("{name} requires a value"))?;
            if values.insert(name.clone(), value).is_some() {
                bail!("duplicate argument {name}");
            }
        }
        Ok(Self { values, flags })
    }

    fn take(&mut self, name: &str) -> Result<String> {
        self.values.remove(name).with_context(|| format!("{name} is required"))
    }

    fn maybe(&mut self, name: &str) -> Option<String> {
        self.values.remove(name)
    }

    fn path(&mut self, name: &str) -> Result<PathBuf> {
        Ok(PathBuf::from(self.take(name)?))
    }

    fn flag(&mut self, name: &str) -> bool {
        let found = self.flags.iter().position(|f| f == name);
        if let Some(index) = found {
            self.flags.remove(index);
        }
        found.is_some()
    }

    fn done(&self) -> Result<()> {
        if !self.values.is_empty() || !self.flags.is_empty() {
            bail!("unknown arguments: {:?} {:?}", self.values.keys().collect::<Vec<_>>(), self.flags);
        }
        Ok(())
    }
}
