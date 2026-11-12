// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5132: profile the phases of a single log-source deploy over N shipped
//! parsers, the way `LogSourceService::deploy` runs them.
//!
//! ```text
//! cargo run --release -p nanosiem-core --example parser_deploy_profile -- \
//!     <parsers-ocsf dir> <repo config/vector dir> <N> [--vector-validate <image>]
//! ```
//!
//! The parser set is the first N `*/parser.yaml` under the directory, sorted by
//! directory name, so runs are comparable. The target of the "deploy" is the
//! last parser in the set. Every phase is timed with a monotonic clock; the
//! `vector validate` phase runs in a throwaway `docker run --rm` container with
//! the staged tree mounted read-only (it never touches a running stack).

use std::path::{Path, PathBuf};
use std::time::Instant;

use nanosiem_core::parser_repository::parse_parser_yaml;
use nanosiem_core::parsers::Parser;
use nanosiem_core::parsers::{VectorConfigManager, VrlValidator};

fn load_parsers(dir: &Path, n: usize) -> Vec<Parser> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read parsers dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("parser.yaml").is_file())
        .collect();
    dirs.sort();
    dirs.into_iter()
        .take(n)
        .map(|d| {
            let raw = std::fs::read_to_string(d.join("parser.yaml")).expect("read parser.yaml");
            let y = parse_parser_yaml(&raw).expect("parse parser.yaml");
            let now = chrono::Utc::now();
            Parser {
                // Deterministic ids so two runs over the same set render the
                // same `_nano_parser_id` stamps.
                id: stable_id(&y.name),
                name: y.name.clone(),
                description: y.description.clone(),
                source_type: "http".into(),
                parser_vrl: y.parser_vrl.clone().unwrap_or_default(),
                output_fields: None,
                feed_id: None,
                dispatch_source_config_id: None,
                dispatch_route_name: None,
                enabled: true,
                validated: true,
                validation_error: None,
                category: y.category.clone(),
                vendor: y.vendor.clone(),
                product: y.product.clone(),
                kind: "log".into(),
                enrich_kind: None,
                enrich_source: None,
                target_table: None,
                normalize_vrl: None,
                namespace: "default".into(),
                timezone: "UTC".into(),
                match_values: y.match_values.clone(),
                sampling_ratio: None,
                sampling_exclude_condition: None,
                extension_vrl: None,
                extension_enabled: false,
                created_at: now,
                updated_at: now,
            }
        })
        .collect()
}

fn stable_id(name: &str) -> uuid::Uuid {
    use std::hash::{Hash, Hasher};
    let mut a = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut a);
    let mut b = std::collections::hash_map::DefaultHasher::new();
    (name, 1u8).hash(&mut b);
    uuid::Uuid::from_u128(((a.finish() as u128) << 64) | b.finish() as u128)
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap().flatten() {
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &target);
        } else {
            std::fs::copy(&path, &target).unwrap();
        }
    }
}

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let parsers_dir = PathBuf::from(args.get(1).expect("parsers dir"));
    let base_config = PathBuf::from(args.get(2).expect("config/vector dir"));
    let n: usize = args.get(3).expect("N").parse().expect("N is a number");
    let image = args
        .iter()
        .position(|a| a == "--vector-validate")
        .map(|i| args[i + 1].clone());
    // Copy the promoted `sources/parsers` tree here (for reload experiments).
    let emit = args
        .iter()
        .position(|a| a == "--emit")
        .map(|i| PathBuf::from(&args[i + 1]));

    let parsers = load_parsers(&parsers_dir, n);
    assert_eq!(parsers.len(), n, "fewer than N parsers under {parsers_dir:?}");
    let target = parsers.last().unwrap().clone();

    let work = std::env::temp_dir().join(format!("nan5132-profile-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    copy_tree(&base_config, &work);
    // A clean tree: no promoted parser files from the repo seed.
    let manager = VectorConfigManager::new(&work);

    // Step 1 of LogSourceService::deploy: the target's VRL validation.
    let validator = VrlValidator::new();
    let t = Instant::now();
    let verdict = validator.validate_vrl(&target.parser_vrl).await.expect("validate");
    let vrl_ms = ms(t);
    assert!(verdict.valid, "target VRL invalid: {:?}", verdict.error);

    // Step 2: stage every enabled parser (render + guard), twice to show the
    // second deploy does not get cheaper.
    let t = Instant::now();
    manager.stage_parsers(&parsers).await.expect("stage");
    let stage_ms = ms(t);
    let t = Instant::now();
    manager.stage_parsers(&parsers).await.expect("stage again");
    let stage2_ms = ms(t);

    // Step 2b: vector validate on the staged tree.
    let validate_ms = image.as_ref().map(|image| {
        let staging = work.join("staging");
        let mut cmd = std::process::Command::new("docker");
        cmd.args(["run", "--rm", "--network", "none", "--cpus", "2"]);
        // The env the live nano-vector container carries (compose), so the
        // validator interpolates the same values `docker exec` would see.
        for kv in [
            "VECTOR_AUTH_TOKEN=profile-token",
            "CLICKHOUSE_URL=http://clickhouse:8123",
            "CLICKHOUSE_PASSWORD=profile",
            "CLICKHOUSE_USER=nanosiem_vector",
            "VECTOR_DATA_DIR=/var/lib/vector",
            "NANO_OTLP_EDGE_KEY=",
        ] {
            cmd.args(["-e", kv]);
        }
        cmd.arg("-v")
            .arg(format!("{}:/etc/vector/staging:ro", staging.display()))
            .args([
                "--entrypoint",
                "vector",
                image.as_str(),
                "validate",
                "--no-environment",
                "--dangerously-allow-env-var-interpolation",
                "--config-dir",
                "/etc/vector/staging",
                "--config-dir",
                "/etc/vector/staging/sources/parsers",
                "--config-dir",
                "/etc/vector/staging/sources/configs",
                "--config-dir",
                "/etc/vector/staging/sinks",
            ]);
        let t = Instant::now();
        let out = cmd.output().expect("docker run vector validate");
        let elapsed = ms(t);
        if !out.status.success() {
            eprintln!(
                "vector validate FAILED:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            std::process::exit(2);
        }
        elapsed
    });

    // Step 3: backup + promote.
    let t = Instant::now();
    let _backup = manager.backup_current().await.expect("backup");
    let backup_ms = ms(t);
    let t = Instant::now();
    manager.promote_staged().await.expect("promote");
    let promote_ms = ms(t);

    let rendered_bytes: u64 = std::fs::read_dir(work.join("sources/parsers"))
        .unwrap()
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum();

    println!(
        "{{\"n\":{n},\"target\":\"{}\",\"vrl_validate_ms\":{vrl_ms:.1},\"stage_ms\":{stage_ms:.1},\"stage_again_ms\":{stage2_ms:.1},\"vector_validate_ms\":{},\"backup_ms\":{backup_ms:.1},\"promote_ms\":{promote_ms:.1},\"rendered_parser_dir_bytes\":{rendered_bytes}}}",
        target.name,
        validate_ms.map(|v| format!("{v:.1}")).unwrap_or_else(|| "null".into()),
    );
    if let Some(emit) = emit {
        let _ = std::fs::remove_dir_all(&emit);
        copy_tree(&work.join("sources"), &emit);
    }
    let _ = std::fs::remove_dir_all(&work);
}
