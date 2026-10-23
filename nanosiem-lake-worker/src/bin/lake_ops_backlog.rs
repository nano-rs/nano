// SPDX-License-Identifier: AGPL-3.0-or-later
//! Dry run: lake_ops_backlog --tenant UUID --token-file PATH --plan-file PATH
//! Apply: same command plus --apply HASH. Credentials never appear in argv.
use anyhow::{ensure, Context, Result};
use nanosiem_lake_worker::edge_log::{backlog::{old_segment_rows, BacklogSkipPlan, BacklogSummary, OPS_TENANT}, protocol::{decode_pull, MAX_PULL_RESPONSE_BYTES}};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};
use zeroize::Zeroizing;

struct Admin { http: reqwest::Client, token: Zeroizing<String> }
impl Admin {
    async fn call(&self, path: &str, body: Option<serde_json::Value>) -> Result<Vec<u8>> {
        use futures::StreamExt;
        let url = format!("https://ops.ingest.nano.rs/admin/edge-log/{path}");
        let request = match body { Some(body) => self.http.post(url).json(&body), None => self.http.get(url) };
        let response = request.bearer_auth(self.token.as_str()).header("x-nano-confirm-backlog-tenant", OPS_TENANT)
            .send().await.context("admin request failed")?;
        ensure!(response.status().is_success(), "admin recovery HTTP {}", response.status().as_u16());
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            ensure!(bytes.len() + chunk.len() <= MAX_PULL_RESPONSE_BYTES, "admin response too large");
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

async fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(args.len() == 6 || args.len() == 8, "usage");
    let (mut tenant, mut token_file, mut plan_file, mut apply) = (None, None, None, None);
    for pair in args.chunks_exact(2) {
        let slot = match pair[0].as_str() { "--tenant" => &mut tenant, "--token-file" => &mut token_file,
            "--plan-file" => &mut plan_file, "--apply" => &mut apply, _ => anyhow::bail!("unknown argument") };
        ensure!(slot.replace(pair[1].clone()).is_none(), "duplicate argument");
    }
    ensure!(tenant.as_deref() == Some(OPS_TENANT), "explicit allowlisted tenant required");
    let token_file = PathBuf::from(token_file.context("token-file required")?);
    let plan_file = PathBuf::from(plan_file.context("plan-file required")?);
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        ensure!(std::fs::metadata(&token_file)?.permissions().mode() & 0o077 == 0, "token file permissions");
    }
    let token = Zeroizing::new(std::fs::read_to_string(token_file)?);
    let token = Zeroizing::new(token.trim().to_string());
    ensure!(!token.is_empty() && !token.contains(char::is_whitespace), "invalid token");
    let admin = Admin { token, http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60)).build()? };
    if let Some(hash) = apply {
        let plan: BacklogSkipPlan = serde_json::from_slice(&std::fs::read(&plan_file)?)?;
        plan.validate(OPS_TENANT, chrono::Utc::now().timestamp_millis())?;
        ensure!(hash == plan.plan_hash, "apply hash differs from dry run");
        let result: serde_json::Value = serde_json::from_slice(&admin.call("backlog/apply",
            Some(json!({"tenantUuid": OPS_TENANT, "planHash": hash}))).await?)?;
        ensure!(result["applied"] == true && result["planHash"].as_str() == Some(hash.as_str()), "apply receipt differs");
        println!("APPLIED hash={} replay={}", hash, result["replay"].as_bool().unwrap_or(false));
        return Ok(());
    }
    // Reserve the output path before making requests; never overwrite a plan.
    let mut options = std::fs::OpenOptions::new(); options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut output = options.open(&plan_file)?;
    let state: serde_json::Value = serde_json::from_slice(&admin.call("state", None).await?)?;
    ensure!(state["tenantUuid"].as_str() == Some(OPS_TENANT), "state tenant differs");
    let through = state["head"].as_u64().context("missing head")?;
    let mut after = state["committedThrough"].as_u64().context("missing committed point")?;
    let first = after + 1;
    ensure!(first <= through, "no pending backlog");
    let cutoff = chrono::Utc::now().timestamp_millis() - 3_600_000;
    let mut summary = BacklogSummary { segments: 0, bytes: 0, rows: 0, kept: 0, ranges: Vec::new(), manifest_sha256: String::new() };
    let mut manifest = Sha256::new();
    while after < through {
        let bytes = admin.call("backlog/scan", Some(json!({"tenantUuid": OPS_TENANT, "after": after}))).await?;
        let batch = decode_pull(&bytes, after)?;
        ensure!(!batch.segments.is_empty(), "snapshot no longer available; repeat dry run");
        for segment in batch.segments.into_iter().take_while(|s| s.seq <= through) {
            after = segment.seq;
            let rows = old_segment_rows(&segment.bytes, cutoff);
            manifest.update(format!("{}:{}:{}:{}\n", segment.seq, segment.sha256, segment.length,
                rows.map(|n| n.to_string()).unwrap_or_else(|| "keep".into())).as_bytes());
            if let Some(rows) = rows {
                summary.segments += 1; summary.bytes += segment.length; summary.rows += rows;
                match summary.ranges.last_mut() {
                    Some([_, last]) if *last + 1 == segment.seq => *last = segment.seq,
                    _ => summary.ranges.push([segment.seq, segment.seq]),
                }
            } else { summary.kept += 1; }
        }
        ensure!(summary.ranges.len() <= 8192, "too many recovery ranges");
        eprintln!("scan segments={} eligible={} kept={}", after - first + 1, summary.segments, summary.kept);
    }
    summary.manifest_sha256 = hex::encode(manifest.finalize());
    let response = admin.call("backlog/plan", Some(json!({"tenantUuid": OPS_TENANT, "cutoffMs": cutoff,
        "firstSeq": first, "throughSeq": through, "summary": summary}))).await?;
    let plan: BacklogSkipPlan = serde_json::from_slice(&response)?;
    plan.validate(OPS_TENANT, chrono::Utc::now().timestamp_millis())?;
    use std::io::Write;
    output.write_all(&serde_json::to_vec_pretty(&plan)?)?; output.sync_all()?;
    println!("DRY-RUN hash={} segments={} bytes={} rows={} kept={} ranges={} cutoffMs={} through={}",
        plan.plan_hash, plan.summary.segments, plan.summary.bytes, plan.summary.rows, plan.summary.kept,
        plan.summary.ranges.len(), plan.cutoff_ms, plan.through_seq);
    Ok(())
}
#[tokio::main]
async fn main() {
    if run().await.is_err() {
        // Decoder, filesystem, HTTP and provider errors can embed credentials
        // or payload values. The stage counters above are safe diagnostics.
        eprintln!("backlog recovery failed; no apply is automatic; inspect deployment, plan and input arguments");
        std::process::exit(1);
    }
}
