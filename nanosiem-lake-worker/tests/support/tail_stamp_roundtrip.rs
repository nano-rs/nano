//! NAN-2520: exercise the publisher's actual admission and Parquet writer,
//! followed by heterogeneous staged-tail packing. No JSONEachRow encoding.
use super::*;
use iceberg::{Catalog, CatalogBuilder};
use nanosiem_lake_worker::{bronze::admit_bronze_files_with_enrichment,
    enrichment::BronzeIngestEnricher, iceberg::*};

fn source_parquet(path: &std::path::Path, event: &Value) {
    let mut input = std::io::Cursor::new(event.to_string().into_bytes());
    let (schema, _) = arrow_json::reader::infer_json_schema_from_seekable(&mut input, None).unwrap();
    let schema = Arc::new(schema);
    let reader = arrow_json::ReaderBuilder::new(schema.clone()).build(input).unwrap();
    let mut writer = parquet::arrow::ArrowWriter::try_new(
        std::fs::File::create(path).unwrap(), schema, None).unwrap();
    for batch in reader { writer.write(&batch.unwrap()).unwrap(); }
    writer.close().unwrap();
}

fn read_parquet(bytes: &[u8]) -> Vec<Value> {
    let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
        bytes::Bytes::copy_from_slice(bytes)).unwrap().build().unwrap();
    let mut writer = arrow_json::LineDelimitedWriter::new(Vec::new());
    for batch in reader { writer.write(&batch.unwrap()).unwrap(); }
    writer.finish().unwrap();
    writer.into_inner().split(|b| *b == b'\n').filter(|s| !s.is_empty())
        .map(|s| serde_json::from_slice(s).unwrap()).collect()
}

// Nullable union fields may be added, but every original key/value must survive.
fn assert_contains(actual: &Value, expected: &Value, path: &str) {
    match expected {
        Value::Object(fields) => for (key, value) in fields {
            assert_contains(&actual[key], value, &format!("{path}.{key}"));
        },
        Value::Array(values) => {
            assert_eq!(actual.as_array().map(Vec::len), Some(values.len()), "{path}");
            for (i, value) in values.iter().enumerate() {
                assert_contains(&actual[i], value, &format!("{path}[{i}]"));
            }
        },
        _ => assert_eq!(actual, expected, "{path}"),
    }
}

async fn roundtrip(native: bool) {
    let dir = tempfile::tempdir().unwrap();
    let catalog = iceberg::memory::MemoryCatalogBuilder::default().load("test",
        std::collections::HashMap::from([("warehouse".into(), "memory:///warehouse".into())]))
        .await.unwrap();
    let id = table_ident("tenant.events").unwrap();
    catalog.create_namespace(&id.namespace, Default::default()).await.unwrap();
    let location = "s3://test/warehouse/events";
    // MemoryCatalog rejects the REST create-table reserved format-version
    // property. Provision the time-only table locally, then use production
    // additive admission for every producer and platform field below.
    let seed = arrow_schema::Schema::new(vec![arrow_schema::Field::new("time",
        arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, Some("+00:00".into())), true)]);
    let seed = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(&seed).unwrap();
    let partition = iceberg::spec::UnboundPartitionField::builder()
        .source_id(seed.field_by_name("time").unwrap().id).field_id(1000)
        .name("event_hour".into()).transform(iceberg::spec::Transform::Hour).build();
    let spec = iceberg::spec::UnboundPartitionSpec::builder().with_spec_id(0)
        .add_partition_fields([partition]).unwrap().build();
    catalog.create_table(&id.namespace, iceberg::TableCreation::builder()
        .name("events".into()).location(location.into()).schema(seed).partition_spec(spec)
        .properties(std::collections::HashMap::from([("nano.tenant-id".into(), fixture::TENANT.into())]))
        .build()).await.unwrap();
    let mut producer = fixture::event();
    producer["time"] = json!("2026-09-21T12:00:00Z");
    producer["metadata"]["uid"] = json!("producer");
    producer["src_endpoint"]["ip"] = json!("8.8.8.8");
    producer["dst_endpoint"]["ip"] = json!("1.1.1.1");
    producer["enrichments"] = json!([{"provider":"Conduit Proxy", "name":"src_endpoint.ip",
        "type":"reputation", "value":"8.8.8.8", "data":{"score":12,"confidence":95}}]);
    let mut expected = Vec::new();
    let mut paths = Vec::new();
    let mut table = None;
    let mut stale_table = None;
    let mut hour = 0;
    // First object has only producer-shaped data; the second evolves the schema
    // with platform stamp leaves. Then read both under one admitted schema.
    for live in [false, true] {
        let mut event = producer.clone();
        if live { event["metadata"]["uid"] = json!("stamped"); }
        let source = dir.path().join(format!("bronze-{live}.parquet"));
        source_parquet(&source, &event);
        let enricher = if live {
            BronzeIngestEnricher::disabled().with_platform_shadow(Arc::new(stamper(runtime::Mode::Live)))
        } else { BronzeIngestEnricher::disabled() };
        let mut admitted = admit_bronze_files_with_enrichment(&[source], fixture::TENANT, &enricher).unwrap();
        let normalized = admitted.batch.rows()[0].ocsf_event.clone();
        if live {
            assert!(admitted.enrichment.platform_admission_sha256.is_some());
            assert_eq!(normalized["src_endpoint"]["location"]["country"], "US");
            assert!(normalized["enrichments"].as_array().unwrap().iter()
                .any(|s| s["provider"] == "platform/ipinfo_lite"));
        }
        admitted.batch.seal_source_identity().unwrap();
        let current = ensure_additive_event_schema_with_cache(&catalog, &id, location,
            &admitted.batch, true).await.unwrap();
        let files = encode_staged_event_files_normalized(&current, &admitted.batch).unwrap();
        assert_eq!(files.len(), 1);
        let file = &files[0];
        assert!(file.relative_path.contains("/batch-"));
        let rows = read_parquet(&file.bytes);
        assert_eq!(rows.len(), 1);
        assert_contains(&rows[0]["enrichments"], &normalized["enrichments"], "batch.enrichments");
        assert_contains(&rows[0]["src_endpoint"], &normalized["src_endpoint"], "batch.src_endpoint");
        let path = dir.path().join(format!("batch-{live}.parquet"));
        std::fs::write(&path, &file.bytes).unwrap();
        paths.push(path);
        expected.push(normalized);
        if !live { stale_table = Some(current.clone()); }
        table = Some(current);
        hour = file.event_hour;
    }
    let table = table.unwrap();
    let stale_table = stale_table.unwrap();
    let schema: arrow_schema::Schema = table.metadata().current_schema().as_ref().try_into().unwrap();
    let (read_schema, available_paths) = table_read_contract(&table).unwrap();
    assert!(available_paths.iter().any(|p| p == "enrichments.data.feed_id"));
    assert!(available_paths.iter().any(|p| p == "src_endpoint.location.country"));
    // A persistently stale rewrite fails after exactly two attempts; unrelated
    // failures never trigger a catalog refresh/retry.
    let stale_schema: arrow_schema::Schema = stale_table.metadata().current_schema().as_ref().try_into().unwrap();
    let mut attempts = 0;
    let result = with_refreshed_staged_schema(&catalog, &id, &stale_table, |_| {
        attempts += 1;
        repack_staged_files_with_profile(Arc::new(stale_schema.clone()), TailIdentityProfile::Ocsf,
            fixture::TENANT, hour, &"a".repeat(64), &paths, 9)
    }).await;
    assert!(result.is_err());
    assert_eq!(attempts, 2);
    let mut attempts = 0;
    let result = with_refreshed_staged_schema(&catalog, &id, &table, |_| -> anyhow::Result<()> {
        attempts += 1;
        anyhow::bail!("unrelated rewrite failure")
    }).await;
    assert!(result.is_err());
    assert_eq!(attempts, 1);
    for reverse in [false, true] {
        if reverse { paths.reverse(); }
        let baseline = repack_staged_files_with_profile(Arc::new(schema.clone()), TailIdentityProfile::Ocsf,
            fixture::TENANT, hour, &"a".repeat(64), &paths, 9).unwrap();
        let mut attempts = 0;
        let packed = with_refreshed_staged_schema(&catalog, &id, &stale_table, |schema| {
            attempts += 1;
            repack_staged_files_with_profile(schema, TailIdentityProfile::Ocsf,
                fixture::TENANT, hour, &"a".repeat(64), &paths, 9)
        }).await.unwrap();
        assert_eq!(attempts, 2, "stale schema must refresh and retry once");
        assert_eq!(packed.bytes, baseline.bytes, "refresh must preserve the exact output");
        let mut attempts = 0;
        let steady = with_refreshed_staged_schema(&catalog, &id, &table, |schema| {
            attempts += 1;
            repack_staged_files_with_profile(schema, TailIdentityProfile::Ocsf,
                fixture::TENANT, hour, &"a".repeat(64), &paths, 9)
        }).await.unwrap();
        assert_eq!(attempts, 1);
        assert_eq!(steady.bytes, baseline.bytes);
        assert_eq!(packed.rows, 2);
        let output = dir.path().join(format!("pack-{reverse}.parquet"));
        std::fs::write(&output, &packed.bytes).unwrap();
        let rows = if native {
            let runtime = super::super::runtime();
            let c = runtime.connect(&[]).unwrap();
            let result = c.query_with_params(
                "SELECT * FROM file({input:String}, Parquet, {schema:String}) SETTINGS output_format_json_quote_64bit_integers=0",
                "JSONEachRow", &[("input", output.to_str().unwrap()), ("schema", read_schema.as_str())]).unwrap();
            result.data.split(|b| *b == b'\n').filter(|s| !s.is_empty())
                .map(|s| serde_json::from_slice(s).unwrap()).collect::<Vec<Value>>()
        } else { read_parquet(&packed.bytes) };
        assert_eq!(rows.len(), 2);
        for expected in &expected {
            let actual = rows.iter().find(|r| r["metadata"]["uid"] == expected["metadata"]["uid"]).unwrap();
            for key in ["enrichments", "src_endpoint", "dst_endpoint"] {
                assert_contains(&actual[key], &expected[key], &format!("pack.{key}"));
            }
        }
    }
}

#[tokio::test]
async fn nan2520_bronze_batch_and_heterogeneous_pack_preserve_stamps() { roundtrip(false).await; }

#[tokio::test]
#[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
async fn nan2520_native_bronze_batch_and_heterogeneous_pack_preserve_stamps() { roundtrip(true).await; }

#[test]
fn nan2520_shadow_admission_digest_does_not_imply_visible_stamps() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.parquet");
    let mut event = fixture::event();
    event["src_endpoint"]["ip"] = json!("8.8.8.8");
    source_parquet(&path, &event);
    let enricher = BronzeIngestEnricher::disabled().with_platform_shadow(Arc::new(stamper(runtime::Mode::Shadow)));
    let admitted = admit_bronze_files_with_enrichment(&[path], fixture::TENANT, &enricher).unwrap();
    assert!(admitted.enrichment.platform_admission_sha256.is_some());
    let row = &admitted.batch.rows()[0].ocsf_event;
    assert!(row.get("enrichments").is_none());
    assert!(row.pointer("/src_endpoint/location/country").is_none());
}
