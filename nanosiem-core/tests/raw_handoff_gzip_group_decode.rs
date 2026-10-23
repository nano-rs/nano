//! NAN-4111: a grouped gzip NDJSON raw-handoff delivery is a multi-member gzip
//! stream (each request's own gzip bytes, plus a one-newline gzip member after
//! any member whose content does not end in a newline). The only consumer of
//! that body is the tenant Vector `http_server` source, which decodes
//! `Content-Encoding: gzip` with `CappedDecoder::gzip_with_limit`
//! (nano-rs/vector nano/v0.59, `src/sources/util/http/encoding.rs:63` →
//! `lib/vector-common/src/decompression.rs:276-285`): a `flate2::read::MultiGzDecoder`
//! behind a `take(limit + 1)` and `read_to_end`. This test reproduces that
//! decoder exactly over the fixture the hosted-ingest receipt object is
//! asserted to send byte for byte
//! (`workers/hosted-ingest/test/nan4111-ingest-cost.test.js`).

use std::io::Read;

use base64::Engine as _;
use flate2::read::{GzDecoder, MultiGzDecoder};
use serde_json::Value;

/// The fork's global default decompressed-size cap (100 MiB).
const VECTOR_MAX_DECOMPRESSED: u64 = 100 * 1024 * 1024;

fn fixture() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/raw_handoff_gzip_group/three_member_ndjson.json");
    serde_json::from_slice(&std::fs::read(path).expect("fixture")).expect("fixture is JSON")
}

fn b64(value: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value.as_str().expect("base64 string"))
        .expect("valid base64")
}

/// `CappedDecoder::gzip_with_limit(body.reader(), limit).decompress()`.
fn vector_http_gzip_decode(body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    MultiGzDecoder::new(body)
        .take(VECTOR_MAX_DECOMPRESSED + 1)
        .read_to_end(&mut out)?;
    assert!(out.len() as u64 <= VECTOR_MAX_DECOMPRESSED);
    Ok(out)
}

#[test]
fn vector_http_source_decodes_every_member_of_a_grouped_gzip_delivery() {
    let fixture = fixture();
    let delivery = b64(&fixture["delivery_base64"]);
    let decoded = vector_http_gzip_decode(&delivery).expect("multi-member gzip decodes");
    assert_eq!(
        String::from_utf8(decoded).expect("utf-8"),
        fixture["decoded"].as_str().unwrap(),
        "every line of all three members arrives, each on its own line"
    );
}

#[test]
fn the_fixture_really_is_multi_member_so_a_single_member_decoder_would_lose_data() {
    // Guards the test above: a single-member decoder stops after the first
    // member, so a regression to it would be caught, not silently pass.
    let fixture = fixture();
    let delivery = b64(&fixture["delivery_base64"]);
    let mut first = Vec::new();
    GzDecoder::new(delivery.as_slice()).read_to_end(&mut first).expect("first member");
    assert_eq!(String::from_utf8(first).unwrap(), "{\"m\":1}\n{\"m\":2}");
    let members = fixture["members"].as_array().unwrap();
    let newline = b64(&fixture["gzip_newline_member_base64"]);
    let mut expected_len = 0;
    for member in members {
        expected_len += b64(&member["gzip_base64"]).len();
        if member["open_line"].as_bool().unwrap() {
            expected_len += newline.len();
        }
    }
    assert_eq!(delivery.len(), expected_len, "members and newline members are concatenated as is");
}

#[test]
fn the_newline_member_decodes_to_one_newline() {
    let newline = b64(&fixture()["gzip_newline_member_base64"]);
    assert_eq!(vector_http_gzip_decode(&newline).unwrap(), b"\n");
}
