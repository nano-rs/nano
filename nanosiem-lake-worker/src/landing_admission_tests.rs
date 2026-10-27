// SPDX-License-Identifier: AGPL-3.0-or-later
//! T2 tests: real converter chunks admit with Root's facts; staged bytes
//! that differ from Root's facts, hostile page headers and rows admission
//! refuses all refuse the whole response.
use super::*;
use crate::landing::{convert_file, encode_bronze, FileFormat, LandingSource};
use nanosiem_core::parquet_page_bounds::PageBoundsRefusal;
use nanosiem_core::parsers::landing_ocsf::{BronzeRow, LandingOcsfStage};
use serde_json::{json, Value};
use uuid::Uuid;

const TENANT: &str = "tenant-a";

fn source() -> LandingSource {
    LandingSource {
        source_id: Uuid::parse_str("0b8f6c1e-3c55-4a8e-9d3e-2f7c1a4b5d60").unwrap(),
        route_key: "tenzir_sysmon".into(),
        credential_id: Uuid::parse_str("1b84f015-b560-433b-8bb6-ed4e39f48334").unwrap(),
        active: true,
    }
}

fn sysmon(i: usize) -> Value {
    json!({
        "class_uid": 1007, "class_name": "Process Activity",
        "category_uid": 1, "category_name": "System Activity",
        "activity_id": 1, "activity_name": "Launch", "type_uid": 100701,
        "severity_id": 1, "severity": "Informational",
        "time": 1_791_975_595_105_i64 + i as i64,
        "message": "Process launched",
        "metadata": {"version": "1.9.0", "uid": format!("sysmon:wks-01:{i}"),
                     "product": {"name": "Sysmon", "vendor_name": "Microsoft"}},
        "device": {"hostname": "wks-01", "type_id": 0},
        "actor": {"process": {"pid": 900, "name": "explorer.exe"}},
        "process": {"pid": 1000 + i, "cmd_line": format!("cmd.exe /c echo {i}")}
    })
}

/// Bronze chunks exactly as the worker's converter emits them.
fn converted(rows: usize) -> Vec<(Vec<u8>, u64)> {
    let mut ndjson = Vec::new();
    for i in 0..rows {
        serde_json::to_writer(&mut ndjson, &sysmon(i)).unwrap();
        ndjson.push(b'\n');
    }
    let stage = LandingOcsfStage::new(1).unwrap();
    let converted = convert_file(&ndjson, FileFormat::Ndjson { gzip: false }, &stage, TENANT, &source(), chrono::Utc::now())
        .expect("converter");
    assert_eq!(converted.rows_refused, 0);
    converted.objects.into_iter().map(|(_, bytes, rows)| (bytes, rows)).collect()
}

/// What Root T1 computes for a chunk it accepted.
fn root_facts(ordinal: u32, bytes: &[u8], rows: u64) -> RootChunkFacts {
    let metadata = ParquetMetaDataReader::new().parse_and_finish(&Bytes::copy_from_slice(bytes)).unwrap();
    let declared_decoded = metadata
        .row_groups()
        .iter()
        .flat_map(|g| g.columns())
        .map(|c| c.uncompressed_size() as u64)
        .sum();
    RootChunkFacts {
        ordinal,
        encoded_len: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
        rows,
        declared_decoded,
    }
}

fn stage(dir: &tempfile::TempDir, chunks: &[(Vec<u8>, u64)]) -> Vec<StagedChunk> {
    chunks
        .iter()
        .enumerate()
        .map(|(i, (bytes, rows))| {
            let path = dir.path().join(format!("chunk-{i:03}.parquet"));
            std::fs::write(&path, bytes).unwrap();
            StagedChunk { path, facts: root_facts(i as u32, bytes, *rows) }
        })
        .collect()
}

fn admit(staged: &[StagedChunk]) -> Result<LandingAdmitted, LandingAdmissionRefusal> {
    admit_root_validated_chunks(staged, TENANT, &BronzeIngestEnricher::disabled(), &IngestTimes::now())
}

#[test]
fn root_validated_converter_chunks_admit_and_reconcile() {
    let mut chunks = converted(40);
    chunks.extend(converted(3).into_iter().map(|(b, r)| (b, r)));
    let dir = tempfile::tempdir().unwrap();
    let staged = stage(&dir, &chunks);
    let total_rows: u64 = chunks.iter().map(|(_, r)| r).sum();
    let admitted = admit(&staged).expect("validated chunks admit");
    assert_eq!(admitted.admission.source_rows, total_rows);
    assert_eq!(admitted.admission.source_files, staged.len());
    assert_eq!(admitted.decoded, staged.iter().map(|s| s.facts.declared_decoded).sum::<u64>());
    assert!(admitted.decoded > 0);
}

#[test]
fn staged_bytes_or_facts_that_differ_from_root_refuse() {
    let chunks = converted(10);
    let dir = tempfile::tempdir().unwrap();

    let mut staged = stage(&dir, &chunks);
    staged[0].facts.sha256[0] ^= 1;
    assert_eq!(admit(&staged).unwrap_err(), LandingAdmissionRefusal::Bytes, "sha");

    let staged = stage(&dir, &chunks);
    let mut tampered = chunks[0].0.clone();
    tampered[4] ^= 0x55; // first data byte; footer untouched
    std::fs::write(&staged[0].path, &tampered).unwrap();
    assert_eq!(admit(&staged).unwrap_err(), LandingAdmissionRefusal::Bytes, "file swapped after Root");

    let mut staged = stage(&dir, &chunks);
    staged[0].facts.encoded_len += 1;
    assert_eq!(admit(&staged).unwrap_err(), LandingAdmissionRefusal::Bytes, "length");

    let mut staged = stage(&dir, &chunks);
    staged[0].facts.rows += 1;
    assert_eq!(admit(&staged).unwrap_err(), LandingAdmissionRefusal::Rows, "rows");

    let mut staged = stage(&dir, &chunks);
    staged[0].facts.declared_decoded -= 1;
    assert_eq!(admit(&staged).unwrap_err(), LandingAdmissionRefusal::DecodedCeiling, "declared decoded");

    let mut staged = stage(&dir, &chunks);
    staged[0].facts.declared_decoded = MAX_CHUNK_DECODED + 1;
    assert_eq!(admit(&staged).unwrap_err(), LandingAdmissionRefusal::Shape, "ceiling");
}

#[test]
fn response_shape_refuses() {
    let chunks = converted(5);
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(admit(&[]).unwrap_err(), LandingAdmissionRefusal::Shape, "empty");
    let mut staged = stage(&dir, &chunks);
    staged[0].facts.ordinal = 1;
    assert_eq!(admit(&staged).unwrap_err(), LandingAdmissionRefusal::Shape, "ordinal");
    let staged = stage(&dir, &chunks);
    let mut twice = vec![staged[0].clone(), staged[0].clone()];
    twice[1].facts.ordinal = 1;
    assert_eq!(admit(&twice).unwrap_err(), LandingAdmissionRefusal::Shape, "duplicate path");
    let mut relative = stage(&dir, &chunks);
    relative[0].path = PathBuf::from("chunk-000.parquet");
    assert_eq!(admit(&relative).unwrap_err(), LandingAdmissionRefusal::Shape, "relative path");
}

#[test]
fn rows_admission_refuses_fail_the_whole_response() {
    // Footer-perfect bronze whose event is not admissible OCSF (no uid, no
    // class): Root T1 cannot see this; T2 must refuse the response.
    let rows = [BronzeRow {
        partition: String::new(),
        time_micros: 1_761_400_000_000_000,
        event_json: r#"{"hello":"world"}"#.into(),
        uid: "u-1".into(),
    }];
    let refs: Vec<&BronzeRow> = rows.iter().collect();
    let bytes = encode_bronze(&refs).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let staged = stage(&dir, &[(bytes, 1)]);
    assert!(matches!(admit(&staged).unwrap_err(), LandingAdmissionRefusal::Rows | LandingAdmissionRefusal::Admission));
}

// ---- page-header walk ------------------------------------------------------

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}
fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}
/// Compact PageHeader {1: type, 2: uncompressed, 3: compressed} + extra
/// (no type-specific header: refused as a header).
fn raw_header(page_type: i64, uncompressed: i64, compressed: i64, extra: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in [page_type, uncompressed, compressed] {
        out.push(0x15); // delta 1, i32
        varint(&mut out, zigzag(value));
    }
    out.extend_from_slice(extra);
    out.push(0);
    out
}
/// Values each synthetic page claims (data pages sum to the span's values).
const PAGE_VALUES: i64 = 2;
/// A well-formed header with its typed header: 5 data {1: num_values,
/// 2: encoding}, 7 dictionary {1: num_values, 2: encoding, 3: is_sorted},
/// 8 data v2 {1: num_values, 2: num_nulls, 3: num_rows, 4: encoding, ...}.
fn typed_header(page_type: i64, uncompressed: i64, compressed: i64, counts: &[i64]) -> Vec<u8> {
    let mut out = raw_header(page_type, uncompressed, compressed, &[]);
    out.pop();
    let field = match page_type {
        0 => 0x2c, // +2 -> 5, struct
        2 => 0x4c, // +4 -> 7
        _ => 0x5c, // +5 -> 8
    };
    out.push(field);
    for value in counts {
        out.push(0x15);
        varint(&mut out, zigzag(*value));
    }
    out.push(0x15); // encoding PLAIN
    varint(&mut out, zigzag(0));
    if page_type == 2 {
        out.push(0x12); // is_sorted = false (compact bool)
    }
    out.push(0); // end typed header
    out.push(0); // end PageHeader
    out
}
fn header(page_type: i64, uncompressed: i64, compressed: i64, _extra: &[u8]) -> Vec<u8> {
    match page_type {
        3 => typed_header(3, uncompressed, compressed, &[PAGE_VALUES, 0, PAGE_VALUES]),
        _ => typed_header(page_type, uncompressed, compressed, &[PAGE_VALUES]),
    }
}
/// A one-column file of the given pages; returns bytes and its span.
fn pages(parts: &[(Vec<u8>, usize, u64)]) -> (Vec<u8>, ColumnSpan) {
    let mut file = b"PAR1".to_vec();
    let (mut compressed, mut uncompressed, mut values) = (0u64, 0u64, 0u64);
    for (h, data, unc) in parts {
        file.extend_from_slice(h);
        file.extend(std::iter::repeat_n(0u8, *data));
        compressed += (h.len() + data) as u64;
        uncompressed += h.len() as u64 + unc;
        // Page type 0/3 (data) count toward the column's values.
        if h.len() > 1 && h[1] != 4 {
            values += PAGE_VALUES as u64;
        }
    }
    (file, ColumnSpan { start: 4, compressed, uncompressed, num_values: values, rows: 1024, value_width: 1 })
}
fn walk(file: &[u8], span: ColumnSpan) -> Result<nanosiem_core::parquet_page_bounds::PageTotals, PageBoundsRefusal> {
    walk_pages(file, &[span], MAX_CHUNK_DECODED, MAX_CHUNK_DECODED)
}

#[test]
fn page_walk_proves_real_converter_chunks_against_their_footer() {
    for (bytes, _) in converted(200) {
        let facts = root_facts(0, &bytes, 0);
        let metadata = ParquetMetaDataReader::new().parse_and_finish(&Bytes::from(bytes.clone())).unwrap();
        let spans: Vec<ColumnSpan> = metadata
            .row_groups()
            .iter()
            .flat_map(|g| g.columns())
            .map(|c| ColumnSpan {
                start: c.byte_range().0,
                compressed: c.compressed_size() as u64,
                uncompressed: c.uncompressed_size() as u64,
                num_values: c.num_values() as u64,
                rows: metadata.row_group(0).num_rows() as u64,
                value_width: 1,
            })
            .collect();
        let totals = walk_pages(&bytes, &spans, MAX_CHUNK_DECODED, MAX_CHUNK_DECODED).expect("real pages tile");
        assert_eq!(totals.decoded, facts.declared_decoded, "writer formula: header + uncompressed");
        assert!(totals.pages >= 2);
    }
}

#[test]
fn hostile_page_headers_refuse_before_any_decoder_allocates() {
    let ok = pages(&[(header(2, 10, 6, &[]), 6, 10), (header(0, 20, 8, &[]), 8, 20)]);
    assert!(walk(&ok.0, ok.1).is_ok());

    // A page claiming 1 GiB decoded in 4 bytes: refused from the header.
    let (file, span) = pages(&[(header(0, 1 << 30, 4, &[]), 4, 1 << 30)]);
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Ceiling, "page ceiling");

    // Footer totals that the pages do not sum to.
    let (file, mut span) = pages(&[(header(0, 20, 8, &[]), 8, 20)]);
    span.uncompressed -= 1;
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Totals, "uncompressed total");
    let (mut file, mut span) = pages(&[(header(0, 20, 8, &[]), 8, 20)]);
    file.extend_from_slice(&[0, 0]);
    span.compressed += 2;
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Header, "trailing garbage is not a header");

    // Page data running past the column chunk.
    let (file, mut span) = pages(&[(header(0, 20, 8, &[]), 8, 20)]);
    span.compressed -= 1;
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Header, "page past chunk");

    // Column range outside the file.
    let (file, mut span) = pages(&[(header(0, 20, 8, &[]), 8, 20)]);
    span.start = file.len() as u64;
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Layout, "range");

    // Index pages, a late dictionary page, negative sizes.
    for (h, data, unc, why) in [
        (raw_header(1, 10, 4, &[]), 4, 10, "index page"),
        (raw_header(0, -1, 4, &[]), 4, 0, "negative uncompressed"),
        (raw_header(0, 10, -4, &[]), 0, 10, "negative compressed"),
        (raw_header(0, 20, 8, &[]), 8, 20, "data page without its typed header"),
        (typed_header(0, 20, 8, &[-1]), 8, 20, "negative num_values"),
    ] {
        let (file, span) = pages(&[(h, data, unc)]);
        assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Header, "{why}");
    }
    let (file, span) = pages(&[(header(0, 20, 8, &[]), 8, 20), (header(2, 10, 6, &[]), 6, 10)]);
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Header, "dictionary after data");

    // Duplicate size field: a later field id must exceed the last.
    let mut duplicate = raw_header(0, 20, 8, &[]);
    duplicate.pop();
    duplicate.push(0x05); // delta 0 -> explicit id follows
    varint(&mut duplicate, zigzag(2));
    varint(&mut duplicate, zigzag(1 << 30));
    duplicate.push(0);
    let (file, span) = pages(&[(duplicate, 8, 20)]);
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Header, "duplicate field");

    // Missing required size field, truncated header, absurd nested lists.
    let mut missing = Vec::new();
    missing.push(0x15);
    varint(&mut missing, zigzag(0));
    missing.push(0x25); // field 3 (skips 2)
    varint(&mut missing, zigzag(8));
    missing.push(0);
    let (file, span) = pages(&[(missing, 8, 0)]);
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Header, "missing uncompressed");
    let truncated = header(0, 20, 8, &[])[..3].to_vec();
    let (file, span) = pages(&[(truncated, 0, 0)]);
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Header, "truncated");
    // field 5 (data_page_header) as a list claiming 2^31 elements.
    let mut huge_list = vec![0x29, 0xf5];
    varint(&mut huge_list, 1 << 31);
    let (file, span) = pages(&[(raw_header(0, 20, 8, &huge_list), 8, 20)]);
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Header, "huge list");
    // 9 nested structs: deeper than the nesting cap.
    let mut deep = Vec::new();
    for _ in 0..9 {
        deep.push(0x2c); // field +2, struct
    }
    deep.extend(std::iter::repeat_n(0u8, 9));
    let (file, span) = pages(&[(raw_header(0, 20, 8, &deep), 8, 20)]);
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Header, "nesting");
}

#[test]
fn page_walk_never_panics_on_arbitrary_header_bytes() {
    let (base, span) = pages(&[(header(2, 10, 6, &[]), 6, 10), (header(0, 20, 8, &[]), 8, 20)]);
    for at in 4..base.len() {
        for flip in [0x01u8, 0x80, 0xff] {
            let mut file = base.clone();
            file[at] ^= flip;
            let _ = walk(&file, span);
        }
    }
    for cut in 4..base.len() {
        let _ = walk(&base[..cut], span);
    }
}

// ---- value counts (pR CP33 P1-1) -------------------------------------------

#[test]
fn page_value_counts_are_bound_by_bytes_rows_and_the_footer() {
    let walk_with = |parts: &[(Vec<u8>, usize, u64)], edit: &dyn Fn(&mut ColumnSpan)| {
        let (file, mut span) = pages(parts);
        edit(&mut span);
        walk(&file, span)
    };
    let none = |_: &mut ColumnSpan| {};
    // Dictionary of 10 bytes: at most 10 one-byte values, 1 eight-byte value.
    assert!(walk_with(&[(typed_header(2, 10, 6, &[10]), 6, 10), (header(0, 20, 8, &[]), 8, 20)], &none).is_ok());
    assert_eq!(
        walk_with(&[(typed_header(2, 10, 6, &[11]), 6, 10), (header(0, 20, 8, &[]), 8, 20)], &none).unwrap_err(),
        PageBoundsRefusal::Ceiling,
        "dictionary claims more values than its bytes"
    );
    assert_eq!(
        walk_with(&[(typed_header(2, 10, 6, &[2]), 6, 10), (header(0, 20, 8, &[]), 8, 20)], &|s| s.value_width = 8)
            .unwrap_err(),
        PageBoundsRefusal::Ceiling,
        "two INT64 values need 16 bytes"
    );
    assert_eq!(
        walk_with(&[(typed_header(2, 10, 6, &[i32::MAX as i64]), 6, 10)], &none).unwrap_err(),
        PageBoundsRefusal::Ceiling,
        "the pR probe shape: a tiny dictionary claiming 2^31 values"
    );
    // Data pages: at most the row group's rows; nulls within values.
    assert_eq!(
        walk_with(&[(header(0, 20, 8, &[]), 8, 20)], &|s| s.rows = 1).unwrap_err(),
        PageBoundsRefusal::Ceiling,
        "v1 values above rows"
    );
    let (file, mut span) = pages(&[(typed_header(3, 20, 8, &[2, 3, 2]), 8, 20)]);
    span.num_values = 2;
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Ceiling, "v2 nulls above values");
    let (file, mut span) = pages(&[(typed_header(3, 20, 8, &[2, 0, 2000]), 8, 20)]);
    span.num_values = 2;
    assert_eq!(walk(&file, span).unwrap_err(), PageBoundsRefusal::Ceiling, "v2 rows above the group");
    let (file, mut span) = pages(&[(header(3, 20, 8, &[]), 8, 20)]);
    span.num_values = 2;
    assert!(walk(&file, span).is_ok(), "well-formed v2");
    // Footer num_values must equal the data pages' sum.
    assert_eq!(
        walk_with(&[(header(0, 20, 8, &[]), 8, 20)], &|s| s.num_values += 1).unwrap_err(),
        PageBoundsRefusal::Totals,
        "footer num_values"
    );
    // A typed header that does not match the page type.
    assert_eq!(
        walk_with(&[(typed_header(0, 20, 8, &[2]).iter().map(|b| if *b == 0x2c { 0x4c } else { *b }).collect(), 8, 20)], &none)
            .unwrap_err(),
        PageBoundsRefusal::Header,
        "data page carrying a dictionary header"
    );
}

fn read_varint(bytes: &[u8], at: &mut usize) -> u64 {
    let (mut value, mut shift) = (0u64, 0);
    loop {
        let byte = bytes[*at];
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}
fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// pR's CP33 probe, generalized to any dictionary-encoded column: a real
/// converter chunk whose dictionary page header for `column` claims `claimed`
/// values, with every footer total and later offset shifted so the file
/// stays self-consistent.
fn forge_dictionary_num_values(bytes: &[u8], column: usize, claimed: i32) -> Vec<u8> {
    use parquet::file::metadata::{ParquetMetaDataWriter, RowGroupMetaData};
    let metadata = ParquetMetaDataReader::new().parse_and_finish(&Bytes::copy_from_slice(bytes)).unwrap();
    assert_eq!(metadata.row_groups().len(), 1, "forge expects one row group");
    let group = &metadata.row_groups()[0];
    let target = group.column(column);
    let dict = target.dictionary_page_offset().expect("dictionary encoded") as usize;
    let data = target.data_page_offset() as usize;
    let mut at = dict;
    let mut fields = [0i64; 3];
    for field in &mut fields {
        assert_eq!(bytes[at], 0x15, "delta-1 i32 field");
        at += 1;
        *field = unzigzag(read_varint(bytes, &mut at));
    }
    assert_eq!(fields[0], 2, "dictionary page first");
    let old_header_len = data - dict - fields[2] as usize;
    let mut header = Vec::new();
    for value in fields {
        header.push(0x15);
        varint(&mut header, zigzag(value));
    }
    header.push(0x4c); // field 7, struct DictionaryPageHeader
    header.push(0x15); // 1: num_values
    varint(&mut header, zigzag(i64::from(claimed)));
    header.push(0x15); // 2: encoding PLAIN
    varint(&mut header, zigzag(0));
    header.push(0);
    header.push(0);
    let shift = header.len() as i64 - old_header_len as i64;
    let footer_len = u32::from_le_bytes(bytes[bytes.len() - 8..bytes.len() - 4].try_into().unwrap()) as usize;
    let footer_start = bytes.len() - 8 - footer_len;
    let mut out = bytes[..dict].to_vec();
    out.extend_from_slice(&header);
    out.extend_from_slice(&bytes[dict + old_header_len..footer_start]);
    let columns = group
        .columns()
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut b = c
                .clone()
                .into_builder()
                .set_offset_index_offset(c.offset_index_offset().map(|o| o + shift))
                .set_column_index_offset(c.column_index_offset().map(|o| o + shift));
            if i == column {
                b = b
                    .set_data_page_offset(c.data_page_offset() + shift)
                    .set_total_compressed_size(c.compressed_size() + shift)
                    .set_total_uncompressed_size(c.uncompressed_size() + shift);
            } else if i > column {
                b = b
                    .set_data_page_offset(c.data_page_offset() + shift)
                    .set_dictionary_page_offset(c.dictionary_page_offset().map(|o| o + shift));
            }
            b.build().unwrap()
        })
        .collect::<Vec<_>>();
    let rg = RowGroupMetaData::builder(group.schema_descr_ptr())
        .set_num_rows(group.num_rows())
        .set_total_byte_size(group.total_byte_size() + shift)
        .set_column_metadata(columns)
        .build()
        .unwrap();
    let forged = metadata.into_builder().set_row_groups(vec![rg]).build();
    ParquetMetaDataWriter::new(&mut out, &forged).finish().unwrap();
    out
}

#[test]
fn forged_dictionary_counts_refuse_with_pages_before_any_decoder_runs() {
    use parquet::basic::Type;
    let (bytes, rows) = converted(3).into_iter().next().unwrap();
    let metadata = ParquetMetaDataReader::new().parse_and_finish(&Bytes::copy_from_slice(&bytes)).unwrap();
    let group = metadata.row_group(0);
    let dictionary_column = |physical: Type| {
        (0..group.num_columns())
            .find(|i| group.column(*i).column_type() == physical && group.column(*i).dictionary_page_offset().is_some())
            .unwrap_or_else(|| panic!("a dictionary-encoded {physical:?} column"))
    };
    // The writer's own dictionary count, read back from the original header
    // (fields 1..3, optional 4 crc, then the typed struct's field 1).
    let original_values = |column: usize| -> i32 {
        let mut at = group.column(column).dictionary_page_offset().unwrap() as usize;
        for _ in 0..3 {
            at += 1;
            read_varint(&bytes, &mut at);
        }
        if bytes[at] == 0x15 {
            at += 1;
            read_varint(&bytes, &mut at); // crc
        }
        assert_eq!(bytes[at] & 0x0f, 12, "typed dictionary header");
        at += 1;
        assert_eq!(bytes[at], 0x15, "num_values");
        at += 1;
        unzigzag(read_varint(&bytes, &mut at)) as i32
    };
    for physical in [Type::INT64, Type::BYTE_ARRAY] {
        let column = dictionary_column(physical);
        let honest = original_values(column);
        // Control: the same forge with an honest count still admits.
        let dir = tempfile::tempdir().unwrap();
        let staged = stage(&dir, &[(forge_dictionary_num_values(&bytes, column, honest), rows)]);
        admit(&staged).unwrap_or_else(|e| panic!("{physical:?} honest forge admits: {e:?}"));
        // pR's exact probe count (2^28) and the i32 maximum.
        for claimed in [1 << 28, i32::MAX] {
            let dir = tempfile::tempdir().unwrap();
            let staged = stage(&dir, &[(forge_dictionary_num_values(&bytes, column, claimed), rows)]);
            assert_eq!(check_chunk(&staged[0]).unwrap_err(), LandingAdmissionRefusal::Pages, "{physical:?} {claimed}");
            assert_eq!(admit(&staged).unwrap_err(), LandingAdmissionRefusal::Pages, "{physical:?} {claimed}");
        }
    }
}

// ---- one verified buffer (pR CP33 P2-1) -------------------------------------

#[test]
fn staged_symlinks_refuse_and_admission_decodes_only_the_verified_buffer() {
    let chunks = converted(4);
    let dir = tempfile::tempdir().unwrap();
    let staged = stage(&dir, &chunks);
    // A symlink at the staged path is never followed.
    let link = dir.path().join("link.parquet");
    std::os::unix::fs::symlink(&staged[0].path, &link).unwrap();
    let mut linked = staged.clone();
    linked[0].path = link;
    assert_eq!(admit(&linked).unwrap_err(), LandingAdmissionRefusal::Bytes, "symlink");
    // Bronze admission over verified bytes never reads the path.
    let gone = dir.path().join("never-written.parquet");
    let sources = vec![(gone.clone(), Bytes::from(chunks[0].0.clone()))];
    let (admission, refused, _) = crate::bronze::admit_bronze_bytes_received(
        &sources,
        TENANT,
        &BronzeIngestEnricher::disabled(),
        &IngestTimes::now(),
    )
    .expect("verified bytes admit without the file");
    assert!(refused.is_empty());
    assert_eq!(admission.files[0].path, gone);
    assert_eq!(admission.files[0].sha256, hex::encode(Sha256::digest(&chunks[0].0)));
}
