// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

fn compiled(predicate: &str) -> CompiledQuery {
    serde_json::from_value(json!({"schema_version":1,"profile":"ocsf","dataset":"logs",
        "source_placeholder":"__nano_lake_source__","query_sha256":"fixture",
        "start":"1970-01-01T00:00:00Z","end":"1970-01-01T03:00:00Z","limit":101,
        "table_view":false,"required_columns":[],
        "sql":format!("WITH stage_0 AS (\n SELECT time, \"user.name\" FROM __nano_lake_source__\n WHERE time BETWEEN '1970-01-01 00:00:00.000000' AND '1970-01-01 03:00:00.000000'\n AND {predicate}\n),\nstage_1 AS (\n SELECT count() AS count\n FROM stage_0\n)\nSELECT * FROM stage_1 LIMIT 101 SETTINGS max_threads=2")
    })).unwrap()
}

#[test]
fn entity_count_plan_accepts_only_exact_compiled_same_kind_equalities() {
    for predicate in [
        r#"((lower("user.name") = 'alice' OR lower("actor.user.name") = 'alice'))"#,
        r#"("src_endpoint.ip" = '10.0.0.1' OR "dst_endpoint.ip" = '10.0.0.1')"#,
        r#"lower("user.email_addr") = 'alice@example.com'"#,
        r#"("device.hostname" = 'host.example' OR "src_endpoint.hostname" = 'host.example')"#,
        r#"lower("user.name") = 'a\'b\\c'"#,
        r#"lower("user.name") = ''"#,
    ] {
        assert!(shape(&compiled(predicate)).is_some(), "{predicate}");
    }
    for predicate in [
        r#"lower("user.name") = 'alice' AND lower("actor.user.name") = 'alice'"#,
        r#"lower("user.name") = 'alice' OR lower("actor.user.name") = 'bob'"#,
        r#"lower("user.name") = 'alice' OR "device.hostname" = 'alice'"#,
        r#"lower("user.name") != 'alice'"#,
        r#""user.name" = 'alice'"#,
        r#"startsWith("device.hostname", 'host.')"#,
        r#"lower("user.name") = 'älIce'"#,
        r#"lower("user.name") = 'Alice'"#,
        r#"lower("enrichments.name") = 'alice'"#,
    ] {
        assert!(shape(&compiled(predicate)).is_none(), "{predicate}");
    }
    let base = compiled(r#"lower("user.name") = 'alice'"#);
    for (old, new) in [
        ("count()", "count(\"user.name\")"),
        ("FROM stage_0", "FROM stage_0 GROUP BY x"),
        (
            "SELECT * FROM stage_1",
            "SELECT * FROM stage_1 WHERE count > 1",
        ),
        ("1970-01-01 03:00:00.000000", "1970-01-01 04:00:00.000000"),
    ] {
        let mut changed = base.clone();
        changed.sql = changed.sql.replace(old, new);
        assert!(shape(&changed).is_none(), "{new}");
    }
}

#[test]
fn entity_count_split_partitions_inclusive_windows_without_overlap() {
    for from in [-HOUR_US, -HOUR_US + 1, 0, 1, HOUR_US - 1] {
        for to in [
            HOUR_US - 1,
            HOUR_US,
            3 * HOUR_US - 1,
            3 * HOUR_US,
            3 * HOUR_US + 1,
        ] {
            let Some((index, native)) = split(from, to) else {
                continue;
            };
            for t in [
                from,
                from + 1,
                index.0 - 1,
                index.0,
                index.1 - 1,
                index.1,
                to,
                to + 1,
            ] {
                let legs = usize::from(t >= index.0 && t < index.1)
                    + native.iter().filter(|(a, b)| t >= *a && t <= *b).count();
                assert_eq!(legs, usize::from(t >= from && t <= to), "{from} {to} {t}");
            }
        }
    }
    assert_eq!(split(0, HOUR_US - 1), Some(((0, HOUR_US), vec![])));
    assert!(split(1, HOUR_US - 1).is_none());
    assert!(split(10, 9).is_none());
    assert!(split(i64::MAX - 1, i64::MAX).is_none());
}

#[test]
fn entity_count_memo_is_byte_bounded_lru_and_keeps_unknown_coverage() {
    let memo = Memo::default();
    memo.answers.lock().unwrap().cap = 500;
    assert!(memo.answer("missing".into(), None).is_none());
    assert!(memo.cached("missing").unwrap().is_none());
    memo.answer("a".into(), None);
    memo.answer("b".into(), None);
    memo.cached("missing");
    memo.answer("c".into(), None);
    assert!(memo.cached("missing").is_some());
    assert!(memo.cached("a").is_none());
    assert!(memo.cached("b").is_some());
    assert!(memo.cached("c").is_some());
    assert!(memo.answers.lock().unwrap().bytes <= 500);
}

#[test]
fn entity_count_memo_reuses_hour_vector_for_sliding_windows_and_or_masks() {
    use crate::part_ingest::partials::EntityRangeRow;
    use crate::parts::entity_counts::{COVERAGE_PATH, PATH};
    let index = Index::from_rows([
        EntityRangeRow { key: (COVERAGE_PATH.into(), "1".into()), first_time: 0, last_time: HOUR_US, events: 10 },
        EntityRangeRow { key: (PATH.into(), "[0,0,3,\"10.0.0.1\"]".into()), first_time: 0, last_time: 0, events: 3 },
        EntityRangeRow { key: (PATH.into(), "[0,1,2,\"10.0.0.1\"]".into()), first_time: HOUR_US, last_time: HOUR_US, events: 4 },
    ], 10, 0, HOUR_US).unwrap().unwrap().select_value(0, "10.0.0.1");
    let memo = Memo::default();
    memo.answer("digest:0:10.0.0.1".into(), Some(index));
    let first = memo.cached("digest:0:10.0.0.1").unwrap().unwrap();
    let next = memo.cached("digest:0:10.0.0.1").unwrap().unwrap();
    assert!(Arc::ptr_eq(&first, &next));
    assert_eq!(first.count_from_index((0, HOUR_US), &[("src_endpoint.ip", "10.0.0.1")]), Some(3));
    assert_eq!(next.count_from_index((HOUR_US, 2*HOUR_US), &[("dst_endpoint.ip", "10.0.0.1")]), Some(4));
    assert_eq!(next.count_from_index((0, 2*HOUR_US), &[("src_endpoint.ip", "10.0.0.1"), ("dst_endpoint.ip", "10.0.0.1")]), Some(7));
    assert!(memo.cached("other-digest:0:10.0.0.1").is_none());
}

#[test]
fn entity_count_kind_decoder_requires_signed_coverage_and_rejects_corrupt_cells() {
    use crate::part_ingest::partials::{EntityRangeRow, PartialRow};
    use crate::parts::entity_counts::{COVERAGE_PATH, PATH};
    let file = tempfile::NamedTempFile::new().unwrap();
    let coverage = EntityRangeRow {
        key: (COVERAGE_PATH.into(), "3".into()),
        first_time: 0,
        last_time: HOUR_US,
        events: 10,
    };
    let cell = EntityRangeRow {
        key: (PATH.into(), "[1,0,1,\"alice\"]".into()),
        first_time: 0,
        last_time: 0,
        events: 3,
    };
    let other = EntityRangeRow {
        key: (PATH.into(), "[0,0,1,\"10.0.0.1\"]".into()),
        first_time: 0,
        last_time: 0,
        events: 5,
    };
    let write = |rows: &[EntityRangeRow]| {
        let mut writer = parquet::arrow::ArrowWriter::try_new(
            std::fs::File::create(file.path()).unwrap(),
            EntityRangeRow::schema(),
            None,
        )
        .unwrap();
        writer
            .write(&EntityRangeRow::to_batch(rows).unwrap())
            .unwrap();
        writer.close().unwrap();
    };
    write(&[coverage.clone(), cell.clone(), other]);
    let index = Index::from_kind_file(file.path(), 1, 10, 0, HOUR_US)
        .unwrap()
        .unwrap();
    assert_eq!(
        index.count_from_index((0, HOUR_US), &[("user.name", "ALICE")]),
        Some(3)
    );
    assert_eq!(
        index.count_from_index((0, HOUR_US), &[("src_endpoint.ip", "10.0.0.1")]),
        None
    );
    assert!(Index::from_kind_file(file.path(), 1, 11, 0, HOUR_US).is_err());
    write(&[cell.clone()]);
    assert!(Index::from_kind_file(file.path(), 1, 10, 0, HOUR_US)
        .unwrap()
        .is_none());
    write(&[coverage.clone(), cell.clone(), cell.clone()]);
    assert!(Index::from_kind_file(file.path(), 1, 10, 0, HOUR_US).is_err());
    let mut later = cell.clone();
    later.key.1 = "[1,1,1,\"alice\"]".into();
    later.first_time = HOUR_US;
    later.last_time = HOUR_US;
    later.events = 8;
    write(&[coverage.clone(), cell.clone(), later]);
    assert!(Index::from_kind_file(file.path(), 1, 10, 0, HOUR_US).is_err());
    let mut corrupt = cell;
    corrupt.key.1 = "[1,0,16,\"alice\"]".into();
    write(&[coverage, corrupt]);
    assert!(Index::from_kind_file(file.path(), 1, 10, 0, HOUR_US).is_err());
}

#[test]
fn entity_count_aggregate_ignores_table_view_and_keeps_source_gate_literals() {
    let mut query =
        compiled(r#"((lower("user.name") = 'alice') AND lower("metadata.log_source") != 'audit')"#);
    query.table_view = true;
    assert_eq!(
        shape(&query).unwrap().denied,
        BTreeSet::from(["audit".into()])
    );
    let disjunction = compiled(
        r#"((lower("user.name") = 'alice' OR lower("actor.user.name") = 'alice') AND lower("metadata.log_source") != 'audit')"#,
    );
    assert_eq!(shape(&disjunction).unwrap().pivot.len(), 2);
    assert_eq!(shape(&disjunction).unwrap().denied, BTreeSet::from(["audit".into()]));
    let multi = compiled(
        r#"((lower("user.name") = 'alice') AND lower("metadata.log_source") NOT IN ('audit', 'windows_sysmon'))"#,
    );
    assert_eq!(
        shape(&multi).unwrap().denied,
        BTreeSet::from(["audit".into(), "windows_sysmon".into()])
    );
    for predicate in [
        r#"(lower("user.name") = 'alice' OR lower("metadata.log_source") != 'audit')"#,
        r#"((lower("user.name") = 'alice' AND lower("metadata.log_source") != 'audit') OR lower("actor.user.name") = 'alice')"#,
        r#"(lower("user.name") = 'alice' OR lower("actor.user.name") = 'alice' AND lower("metadata.log_source") != 'audit')"#,
        r#"(lower("user.name") = 'alice' AND lower("metadata.log_source") IN ('audit'))"#,
        r#"(lower("user.name") = 'alice' AND lower("metadata.log_source") NOT IN ('audit') AND class_uid = 1)"#,
    ] {
        assert!(shape(&compiled(predicate)).is_none(), "{predicate}");
    }
}

#[test]
fn entity_count_decoder_expired_budget_is_not_a_negative_memo_answer() {
    use crate::part_ingest::partials::{EntityRangeRow, PartialRow};
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut writer = parquet::arrow::ArrowWriter::try_new(
        std::fs::File::create(file.path()).unwrap(),
        EntityRangeRow::schema(),
        None,
    )
    .unwrap();
    writer
        .write(
            &EntityRangeRow::to_batch(&[EntityRangeRow {
                key: (
                    crate::parts::entity_counts::COVERAGE_PATH.into(),
                    "1".into(),
                ),
                first_time: 0,
                last_time: 0,
                events: 1,
            }])
            .unwrap(),
        )
        .unwrap();
    writer.close().unwrap();
    assert!(Index::from_kind_file_before(file.path(), 0, 1, 0, 0, Some(Instant::now())).is_err());
    assert!(Index::from_kind_file(file.path(), 0, 1, 0, 0)
        .unwrap()
        .is_some());
}

#[test]
fn entity_count_signed_source_inventory_is_conservative_for_mixed_and_legacy_files() {
    let mut record = crate::parts::provenance::tests::sample_record();
    let denied = BTreeSet::from(["audit".into()]);
    assert!(sources_allowed(&record, &BTreeSet::new()));
    record.files.data[0].log_sources = None;
    assert!(!sources_allowed(&record, &denied));
    record.files.data[0].log_sources = Some(vec!["windows_sysmon".into()]);
    assert!(sources_allowed(&record, &denied));
    record.files.data.push(record.files.data[0].clone());
    record.files.data[1].log_sources = Some(vec!["Audit".into(), "windows_sysmon".into()]);
    assert!(!sources_allowed(&record, &denied));
    record.files.data[1].log_sources = None;
    assert!(!sources_allowed(&record, &denied));
}
