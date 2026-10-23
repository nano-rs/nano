// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4319 test fixture: Parquet shaped exactly like Tenzir 6.19.1's
//! `read_ndjson | ocsf_derive | ocsf_cast | write_parquet` output for OCSF
//! Authentication (3002) events (the file that OOM-looped ingest on FP):
//! 21 columns, nested structs, `tenzir.ip` FixedSizeBinary(16) extension
//! columns, a zone-less nanosecond `time`, the `TENZIR:name:0` schema tag,
//! and every row in ONE row group (Tenzir's writer does that for a flush).
//! The values follow `tzlive2/gen_ndjson.py`: highly repetitive, so the
//! file compresses like the real one (50k rows ≈ 3.3 MB).

use arrow_array::builder::{BooleanBuilder, FixedSizeBinaryBuilder, Int64Builder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch, StructArray, TimestampNanosecondArray};
use arrow_schema::{DataType, Field, Fields, Schema, TimeUnit};
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use std::collections::HashMap;
use std::sync::Arc;

fn ip_field(name: &str) -> Field {
    Field::new(name, DataType::FixedSizeBinary(16), true).with_metadata(HashMap::from([
        ("ARROW:extension:name".to_string(), "tenzir.ip".to_string()),
        ("ARROW:extension:metadata".to_string(), "tenzir.ip".to_string()),
    ]))
}

fn text(name: &str) -> Field {
    Field::new(name, DataType::Utf8, true)
}

fn int(name: &str) -> Field {
    Field::new(name, DataType::Int64, true)
}

fn endpoint_fields() -> Fields {
    Fields::from(vec![text("hostname"), ip_field("ip")])
}

fn product_fields() -> Fields {
    Fields::from(vec![text("name"), text("vendor_name")])
}

fn metadata_fields() -> Fields {
    Fields::from(vec![Field::new("product", DataType::Struct(product_fields()), true), text("uid"), text("version")])
}

fn user_fields() -> Fields {
    Fields::from(vec![text("name"), text("uid")])
}

/// The schema Tenzir 6.19.1 wrote for the FP file.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new_with_metadata(
        vec![
            int("activity_id"),
            text("activity_name"),
            text("auth_protocol"),
            int("auth_protocol_id"),
            text("category_name"),
            int("category_uid"),
            text("class_name"),
            int("class_uid"),
            Field::new("dst_endpoint", DataType::Struct(endpoint_fields()), true),
            Field::new("is_mfa", DataType::Boolean, true),
            text("message"),
            Field::new("metadata", DataType::Struct(metadata_fields()), true),
            text("severity"),
            int("severity_id"),
            Field::new("src_endpoint", DataType::Struct(endpoint_fields()), true),
            text("status"),
            int("status_id"),
            Field::new("time", DataType::Timestamp(TimeUnit::Nanosecond, None), true),
            text("type_name"),
            int("type_uid"),
            Field::new("user", DataType::Struct(user_fields()), true),
        ],
        HashMap::from([("TENZIR:name:0".to_string(), "ocsf.authentication".to_string())]),
    ))
}

fn strings(values: impl Iterator<Item = String>) -> ArrayRef {
    let mut builder = StringBuilder::new();
    values.for_each(|v| builder.append_value(v));
    Arc::new(builder.finish())
}

fn ints(values: impl Iterator<Item = i64>) -> ArrayRef {
    let mut builder = Int64Builder::new();
    values.for_each(|v| builder.append_value(v));
    Arc::new(builder.finish())
}

fn ips(values: impl Iterator<Item = [u8; 4]>) -> ArrayRef {
    let mut builder = FixedSizeBinaryBuilder::new(16);
    values.for_each(|v| builder.append_value(std::net::Ipv4Addr::from(v).to_ipv6_mapped().octets()).unwrap());
    Arc::new(builder.finish())
}

fn batch(run: &str, from: usize, to: usize, t0_ms: i64) -> RecordBatch {
    let schema = schema();
    let range = || from..to;
    let n = to - from;
    let constant = |v: &str| strings(std::iter::repeat_n(v.to_string(), n));
    let constant_int = |v: i64| ints(std::iter::repeat_n(v, n));
    let endpoint = |hosts: ArrayRef, addresses: ArrayRef| -> ArrayRef {
        Arc::new(StructArray::new(endpoint_fields(), vec![hosts, addresses], None))
    };
    let product: ArrayRef = Arc::new(StructArray::new(product_fields(), vec![constant("tzlive2-gen"), constant("Tenzir")], None));
    let metadata: ArrayRef = Arc::new(StructArray::new(
        metadata_fields(),
        vec![product, strings(range().map(|i| format!("tzlive2-{run}-{i}"))), constant("1.9.0")],
        None,
    ));
    let user: ArrayRef = Arc::new(StructArray::new(
        user_fields(),
        vec![strings(range().map(|i| format!("tz-user-{}", i % 7))), strings(range().map(|i| format!("u{}", i % 7)))],
        None,
    ));
    let mut mfa = BooleanBuilder::new();
    range().for_each(|_| mfa.append_value(false));
    let columns: Vec<ArrayRef> = vec![
        constant_int(1),
        constant("Logon"),
        constant("Kerberos"),
        constant_int(2),
        constant("Identity & Access Management"),
        constant_int(3),
        constant("Authentication"),
        constant_int(3002),
        endpoint(constant("dc01"), ips(range().map(|_| [10, 0, 0, 5]))),
        Arc::new(mfa.finish()),
        strings(range().map(|i| format!("tzlive2 {run} login attempt {i}"))),
        metadata,
        constant("Informational"),
        constant_int(1),
        endpoint(
            strings(range().map(|i| format!("tz-host-{}", i % 3))),
            ips(range().map(|i| [10, 77, (i % 4) as u8, (i % 250) as u8])),
        ),
        strings(range().map(|i| if i % 5 == 0 { "Failure" } else { "Success" }.to_string())),
        ints(range().map(|i| if i % 5 == 0 { 2 } else { 1 })),
        Arc::new(TimestampNanosecondArray::from_iter_values(range().map(|i| (t0_ms + i as i64 * 1_000) * 1_000_000))),
        constant("Authentication: Logon"),
        constant_int(300201),
        user,
    ];
    RecordBatch::try_new(schema, columns).unwrap()
}

/// `rows` Tenzir-shaped 3002 rows, one row group, times from `t0_ms` (1 s apart).
pub fn tenzir_auth_parquet(run: &str, rows: usize, t0_ms: i64) -> Vec<u8> {
    let properties = WriterProperties::builder().set_max_row_group_row_count(Some(rows.max(1))).build();
    let mut out = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut out, schema(), Some(properties)).unwrap();
    let mut from = 0;
    while from < rows {
        let to = (from + 8_192).min(rows);
        writer.write(&batch(run, from, to, t0_ms)).unwrap();
        from = to;
    }
    writer.close().unwrap();
    out
}
