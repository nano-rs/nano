//! nano-connector CLI.
//!
//!   nano-connector schema                       JSON schema for specs
//!   nano-connector validate <spec.yaml>...      compile-check spec + VRL
//!   nano-connector preview <spec.yaml> <recording.json>
//!       [--config K=V]... [--cred K=V]... [--artifact V --type T]
//!       [--now RFC3339] [--show N]    run once, offline
//!       [--checkpoints FILE] [--all-batches]
//!   nano-connector shadow <spec.yaml> --mock-url http://127.0.0.1:PORT [opts]
//!       same options as preview; requests go to a loopback vendor mock
//!       (shadow runs against the Deno original)
//!   nano-connector check-uids <parser.yaml> <batches.json>
//!       parse shipped events twice; fail on a missing, random or shared
//!       metadata.uid (batches = [[source_type, [events]]])
//!   nano-connector vrl-worker                   internal: VRL sandbox child
//!   nano-connector sandbox-probe <op>           internal: sandbox self-test

use std::process::ExitCode;

use nano_connector::auth::Credentials;
use nano_connector::preview::{self, PreviewInput, Recorded};
use nano_connector::spec::ConnectorSpec;
use serde_json::{Value, json};

fn load(path: &str) -> Result<ConnectorSpec, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    ConnectorSpec::from_yaml(&text).map_err(|e| format!("{path}: {e}"))
}

fn kv(s: &str) -> Result<(String, String), String> {
    s.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())).ok_or_else(|| format!("expected K=V, got `{s}`"))
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: nano-connector schema | validate <spec>... | preview <spec> <recording.json> [opts] \
         | shadow <spec> --mock-url URL [opts] | check-uids <parser.yaml> <batches.json> | vrl-worker"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("vrl-worker") => match nano_connector::vrl_exec::worker_main(&args[2..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        Some("sandbox-probe") => match nano_connector::vrl_exec::sandbox_probe(&args[2..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        Some("schema") => {
            println!("{}", serde_json::to_string_pretty(&ConnectorSpec::json_schema()).unwrap_or_default());
            ExitCode::SUCCESS
        }
        Some("validate") if args.len() > 2 => {
            let mut failed = false;
            for p in &args[2..] {
                let checked = load(p).and_then(|s| {
                    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
                    rt.block_on(preview::validate(exe, &s)).map_err(|e| e.to_string())
                });
                match checked {
                    Ok(summary) => println!("{}", json!({ "file": p, "ok": true, "summary": summary })),
                    Err(e) => {
                        failed = true;
                        println!("{}", json!({ "file": p, "ok": false, "error": e }));
                    }
                }
            }
            if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
        }
        Some("preview") if args.len() > 3 => report(run_preview(&args[2], Some(&args[3]), &args[4..])),
        Some("shadow") if args.len() > 2 => report(run_preview(&args[2], None, &args[3..])),
        Some("check-uids") if args.len() == 4 => report(check_uids(&args[2], &args[3])),
        _ => usage(),
    }
}

fn report(r: Result<Value, String>) -> ExitCode {
    match r {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            if v["ok"] == true { ExitCode::SUCCESS } else { ExitCode::FAILURE }
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn check_uids(parser: &str, batches: &str) -> Result<Value, String> {
    let program = nano_connector::parse_check::compile_parser(&read(parser)?)?;
    let b: Vec<(String, Vec<Value>)> = serde_json::from_str(&read(batches)?).map_err(|e| format!("{batches}: {e}"))?;
    Ok(nano_connector::parse_check::check_uids(&program, &b))
}

/// `preview` (recording given) or `shadow` (no recording; `--mock-url`).
fn run_preview(spec_path: &str, rec_path: Option<&str>, rest: &[String]) -> Result<Value, String> {
    let spec = load(spec_path)?;
    let rec: Option<Vec<Recorded>> = match rec_path {
        Some(p) => Some(serde_json::from_str(&read(p)?).map_err(|e| format!("{p}: {e}"))?),
        None => None,
    };
    let mut config = serde_json::Map::new();
    let mut creds = std::collections::HashMap::new();
    let (mut artifact, mut typ, mut now, mut show) = (None, None, None, 5usize);
    let (mut mock_url, mut checkpoints, mut all_batches) = (None::<String>, std::collections::HashMap::new(), false);
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--config" => {
                let (k, v) = kv(&val()?)?;
                config.insert(k, Value::String(v));
            }
            "--cred" => {
                let (k, v) = kv(&val()?)?;
                creds.insert(k, v);
            }
            "--artifact" => artifact = Some(val()?),
            "--type" => typ = Some(val()?),
            "--now" => {
                let v = val()?;
                now = Some(chrono::DateTime::parse_from_rfc3339(&v).map_err(|e| format!("--now: {e}"))?.with_timezone(&chrono::Utc));
            }
            "--show" => show = val()?.parse().map_err(|e| format!("--show: {e}"))?,
            // K=PATH: the credential is the file's content (PEM keys).
            "--cred-file" => {
                let (k, p) = kv(&val()?)?;
                creds.insert(k, read(&p)?);
            }
            "--mock-url" => mock_url = Some(val()?),
            "--checkpoints" => {
                let p = val()?;
                checkpoints = serde_json::from_str(&read(&p)?).map_err(|e| format!("{p}: {e}"))?;
            }
            "--all-batches" => all_batches = true,
            other => return Err(format!("unknown option {other}")),
        }
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    let input = PreviewInput {
        config,
        credentials: Credentials::new(creds),
        artifact: artifact.map(|a| (a, typ.unwrap_or_else(|| "ip".into()))),
        now,
        max_events_shown: show,
        checkpoints,
        all_batches,
    };
    match (rec, mock_url) {
        (Some(rec), None) => Ok(rt.block_on(preview::preview(exe, &spec, rec, input))),
        (None, Some(url)) => rt.block_on(preview::shadow(exe, &spec, &url, input)),
        (Some(_), Some(_)) => Err("--mock-url is for `shadow`; `preview` replays its recording".into()),
        (None, None) => Err("shadow needs --mock-url http://127.0.0.1:PORT".into()),
    }
}
