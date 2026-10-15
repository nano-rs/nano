//! NAN-3056: cost of the contract 4.2 row digest (every merged row is
//! digested for the part's Merkle root). `row_digests` must stay
//! byte-identical to the reference encoding while getting cheaper.
//! Run: cargo test --release -p nanosiem-lake-worker --test nan3056_row_digest_cost -- --ignored --nocapture

use nanosiem_lake_worker::part_ingest::schema::{decode, infer_schema};
use nanosiem_lake_worker::parts::provenance::{row_digests, row_digests_for_merge, write_canonical_json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn event(i: usize) -> serde_json::Value {
    let mut value = base_event(i);
    let unmapped = value["unmapped"].as_object_mut().unwrap();
    unmapped.insert(format!("vendor_s{}", i % 1500), serde_json::json!(format!("value {i}")));
    unmapped.insert(format!("vendor_n{}", (i * 7) % 1500), serde_json::json!(i as i64));
    value
}

fn base_event(i: usize) -> serde_json::Value {
    serde_json::json!({
        "time": format!("2026-09-29T19:{:02}:{:02}.{:06}Z", (i / 60) % 60, i % 60, i % 1_000_000),
        "class_uid": 1007, "category_uid": 1, "activity_id": (i % 5) as i64, "severity_id": 1,
        "metadata": {"uid": format!("uid-{i:012}"), "log_source": format!("src-{}", i % 9), "product": {"name": "Sysmon", "vendor_name": "Microsoft"},
            "version": "1.1.0", "original_time": "Sep 29 19:00:00"},
        "src_endpoint": {"ip": format!("10.0.{}.{}", i % 250, i % 200), "hostname": format!("host-{}.corp.local", i % 700), "port": (i % 65000) as i64},
        "dst_endpoint": {"ip": format!("52.1.{}.{}", i % 250, i % 13), "hostname": "login.microsoftonline.com", "port": 443},
        "process": {"name": "powershell.exe", "pid": (i % 30000) as i64, "cmd_line": format!("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-Item C:\\\\Users\\\\u{i}\\\\AppData\\\\Local\\\\Temp\\\\x.ps1\" -n {i}"),
            "file": {"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "hashes": [{"algorithm_id": 3, "value": format!("{:064x}", i as u128 * 7919)}]},
            "parent_process": {"name": "explorer.exe", "pid": 4412, "cmd_line": "C:\\Windows\\explorer.exe"}},
        "actor": {"user": {"name": format!("user{}", i % 400), "domain": "CORP", "uid": format!("S-1-5-21-{}", i % 400)}},
        "score": (i as f64) * 0.25, "ratio": 1.5e-7, "flag": i % 2 == 0,
        "message": format!("Process Create: RuleName: - UtcTime: 2026-09-29 19:00:00.{i} ProcessGuid: {{{i:08x}-0000-0000-0000-000000000000}} Image: powershell.exe"),
        "raw_data": "x".repeat(900) + &format!(" \"quoted\" \\ tab\t unicode é ü 漢 {i}"),
        "unmapped": {"EventID": 1, "Keywords": "0x8000000000000000", "Channel": "Microsoft-Windows-Sysmon/Operational", "Opcode": null},
    })
}

/// The contract reference: arrow_json line, re-parsed, keys sorted.
fn reference(batch: &arrow_array::RecordBatch) -> Vec<[u8; 32]> {
    let mut writer = arrow_json::LineDelimitedWriter::new(Vec::new());
    writer.write(batch).unwrap();
    writer.finish().unwrap();
    let bytes = writer.into_inner();
    bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|line| {
        let value: serde_json::Value = serde_json::from_slice(line).unwrap();
        let mut out = Vec::new();
        write_canonical_json(&value, &mut out).unwrap();
        Sha256::digest(&out).into()
    }).collect()
}

fn batch(rows: usize) -> arrow_array::RecordBatch {
    let events = (0..rows).map(event).collect::<Vec<_>>();
    let refs = events.iter().collect::<Vec<_>>();
    // Wide like a real tenant schema: every sparse vendor leaf is a column.
    let schema = Arc::new(infer_schema(&refs[..3_000.min(rows)]).unwrap());
    decode(schema, &refs).unwrap()
}

#[test]
fn row_digests_match_the_reference_encoding() {
    let b = batch(3_000);
    assert_eq!(row_digests(&b).unwrap(), reference(&b));
    assert_eq!(row_digests_for_merge(&b).unwrap(), reference(&b));
    let sliced = b.slice(17, 1_000);
    assert_eq!(row_digests_for_merge(&sliced).unwrap(), reference(&sliced));
}

#[test]
#[ignore]
fn row_digest_cost() {
    let b = batch(100_000);
    let started = std::time::Instant::now();
    let slow = reference(&b);
    let reference_s = started.elapsed().as_secs_f64();
    let started = std::time::Instant::now();
    let fast = row_digests_for_merge(&b).unwrap();
    let fast_s = started.elapsed().as_secs_f64();
    assert_eq!(fast, slow);
    println!("{} columns; 100k rows: reference {reference_s:.2} s ({:.1} us/row), row_digests_for_merge (2 niced threads) {fast_s:.2} s ({:.1} us/row); 1M-row hour: {:.0} s -> {:.0} s",
        b.schema().flattened_fields().len(), reference_s * 10.0, fast_s * 10.0, reference_s * 10.0, fast_s * 10.0);
}
