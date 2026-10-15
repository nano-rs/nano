// SPDX-License-Identifier: AGPL-3.0-or-later

//! Conservative equality pruning of immutable local tail Parquet objects.
//! Statistics/blooms describe raw strings, whereas nPL uses ASCII lower().
//! Never probe a raw bloom with only the lowercased spelling: enumerate all
//! ASCII spellings within a bounded budget, or keep the object.
use crate::{generation::HotTailManifest, planner::CandidateHint};
use parquet::{bloom_filter::Sbbf, file::{reader::FileReader, serialized_reader::SerializedFileReader, statistics::Statistics}};
use std::{collections::BTreeMap, fs::File, path::Path, sync::{Mutex, OnceLock}};

pub const IDENTITY_PATHS: &[&str] = &[
    "user.name", "user.uid", "actor.user.name", "actor.user.uid",
    "src_endpoint.ip", "dst_endpoint.ip", "src_endpoint.hostname", "dst_endpoint.hostname",
    "device.hostname", "src_endpoint.mac", "dst_endpoint.mac", "process.name", "process.uid",
    // Hash leaves are eligible only when physically scalar (never repeated arrays).
    "file_hash", "process_hash", "file.hashes.value",
    "process.file.hashes.value", "actor.process.file.hashes.value",
    "actor.process.name", "actor.process.uid", "metadata.uid",
    // NAN-3694: asset-pivot identities. Blooms, entity sidecars and locators
    // only; their entity-range rows are not written (see
    // `parts::format::ENTITY_RANGE_PATHS`). A part written before these were
    // added has no bloom for them, which every reader keeps.
    "device.ip", "device.uid", "user.email_addr", "actor.user.email_addr",
    "actor.process.user.name",
];

fn spellings(value: &str) -> Option<Vec<Vec<u8>>> {
    if !value.is_ascii() || value.bytes().filter(u8::is_ascii_alphabetic).count() > 8 { return None; }
    let mut values = vec![value.as_bytes().to_ascii_lowercase()];
    for (i, byte) in value.bytes().enumerate() {
        if byte.is_ascii_alphabetic() {
            let upper = values.iter().map(|v| { let mut v = v.clone(); v[i] = byte.to_ascii_uppercase(); v }).collect::<Vec<_>>();
            values.extend(upper);
        }
    }
    Some(values)
}

fn entity_may_match(reader: &SerializedFileReader<File>, file: &File, path: &str, value: &str) -> Option<bool> {
    if !IDENTITY_PATHS.contains(&path) || !value.is_ascii() { return None; }
    let index = reader.metadata().file_metadata().schema_descr().columns().iter()
        .position(|column| column.path().string() == path && column.max_rep_level() == 0)?;
    let variants = spellings(value);
    for group in reader.metadata().row_groups() {
        let column = group.column(index);
        let stats = match column.statistics() {
            Some(Statistics::ByteArray(stats)) if stats.min_is_exact() && stats.max_is_exact() => Some(stats),
            _ => None,
        };
        // Constant groups can be excluded without enumerating long names.
        if let Some((min, max)) = stats.and_then(|s| s.min_opt().zip(s.max_opt())) {
            if min.data() == max.data() && min.data().is_ascii()
                && !min.data().eq_ignore_ascii_case(value.as_bytes()) { continue; }
        }
        let Some(variants) = variants.as_ref() else { return Some(true); };
        let remaining = variants.iter().filter(|v| stats.is_none_or(|s| {
            s.min_opt().is_none_or(|min| v.as_slice() >= min.data())
                && s.max_opt().is_none_or(|max| v.as_slice() <= max.data())
        })).collect::<Vec<_>>();
        if remaining.is_empty() { continue; }
        // Missing/corrupt bloom is unknown, never proof of absence.
        let bloom = Sbbf::read_from_column_chunk(column, file).ok().flatten();
        if remaining.iter().any(|v| bloom.as_ref().is_none_or(|b| b.check(v.as_slice()))) { return Some(true); }
    }
    Some(false)
}

fn may_match(reader: &SerializedFileReader<File>, file: &File, hint: &CandidateHint) -> bool {
    match hint {
        CandidateHint::Entity { source_path, value } => entity_may_match(reader, file, source_path, value).unwrap_or(true),
        CandidateHint::Any { alternatives } => alternatives.is_empty() || alternatives.iter().any(|h| may_match(reader, file, h)),
        _ => true,
    }
}

pub fn object_may_match(path: &Path, hints: &[CandidateHint]) -> bool {
    let Ok(file) = File::open(path) else { return true; };
    let Ok(copy) = file.try_clone() else { return true; };
    let Ok(reader) = SerializedFileReader::new(copy) else { return true; };
    hints.iter().all(|hint| may_match(&reader, &file, hint))
}

#[derive(Default)]
struct ProofCache {
    entries: BTreeMap<(String, Vec<CandidateHint>), bool>,
    bytes: usize,
}

// Only verified schema-v4 content hashes key this cache. The proof concerns
// raw immutable Parquet values, not tenant permissions or mutable paths.
// Missing hashes (legacy/test manifests) bypass caching. Bound keys as well as
// entry count, and release the lock before local I/O.
fn cached_may_match(path: &Path, sha256: Option<&str>, hints: &[CandidateHint]) -> bool {
    static CACHE: OnceLock<Mutex<ProofCache>> = OnceLock::new();
    let Some(hash) = sha256.filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())) else {
        return object_may_match(path, hints);
    };
    let key = (hash.to_owned(), hints.to_vec());
    let bytes = 64 + format!("{hints:?}").len();
    let cache = CACHE.get_or_init(|| Mutex::new(ProofCache::default()));
    if let Ok(cache) = cache.lock() {
        if let Some(result) = cache.entries.get(&key) { return *result; }
    }
    let result = object_may_match(path, hints);
    if bytes <= 8 * 1024 * 1024 {
        if let Ok(mut cache) = cache.lock() {
            if cache.entries.len() >= 4096 || cache.bytes + bytes > 8 * 1024 * 1024 {
                cache.entries.clear(); cache.bytes = 0;
            }
            if cache.entries.insert(key, result).is_none() { cache.bytes += bytes; }
        }
    }
    result
}

pub fn prune(tail: &mut HotTailManifest, hints: &[CandidateHint]) {
    if hints.is_empty() || tail.schema_version != 4 || tail.local_paths.len() != tail.objects.len() { return; }
    let keep = tail.local_paths.iter().zip(&tail.objects).map(|(path, object)| cached_may_match(path, object.sha256.as_deref(), hints)).collect::<Vec<_>>();
    let mut i = 0;
    tail.objects.retain(|_| { let retain = keep[i]; i += 1; retain });
    let mut i = 0;
    tail.local_paths.retain(|_| { let retain = keep[i]; i += 1; retain });
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{Array, ArrayRef, RecordBatch, StringArray, StructArray};
    use arrow_schema::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    #[test]
    fn non_equality_queries_without_hints_keep_tail_objects() {
        // The compiler regression test covers hint omission for these queries,
        // including OR alternatives. Exercise its empty-hint contract on real
        // Parquet with matching values (NULL matches the empty-string query).
        for (query, root, leaf, values, literal) in [
            ("user.name=jsm*", "user", "name", vec![Some("JSmith"), None], "jsm*"),
            ("user.name=*", "user", "name", vec![Some("JSmith"), None], "*"),
            (r#"user.name="""#, "user", "name", vec![Some("JSmith"), None], ""),
            ("src_endpoint.ip=10.0.0.0/8", "src_endpoint", "ip", vec![Some("10.1.2.3"), None], "10.0.0.0/8"),
        ] {
            let fields = vec![Field::new(leaf, DataType::Utf8, true)].into();
            let values = StructArray::new(fields, vec![Arc::new(StringArray::from(values)) as ArrayRef], None);
            let schema = Arc::new(Schema::new(vec![Field::new(root, values.data_type().clone(), false)]));
            let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(values)]).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("object.parquet");
            let mut writer = ArrowWriter::try_new(File::create(&path).unwrap(), schema, None).unwrap();
            writer.write(&batch).unwrap(); writer.close().unwrap();
            // Prove the old exact-value hint would incorrectly drop this file.
            assert!(!object_may_match(&path, &[CandidateHint::Entity {
                source_path: format!("{root}.{leaf}"), value: literal.into(),
            }]), "{query}");
            assert!(object_may_match(&path, &[]), "{query}");
        }
    }

    #[test]
    fn immutable_proof_cache_distinguishes_predicates_and_unknown_branches() {
        let fields = vec![Field::new("name", DataType::Utf8, false)].into();
        let users = StructArray::new(fields, vec![Arc::new(StringArray::from(vec!["JSmith"])) as ArrayRef], None);
        let schema = Arc::new(Schema::new(vec![Field::new("user", users.data_type().clone(), false)]));
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(users)]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("object.parquet");
        let mut writer = ArrowWriter::try_new(File::create(&path).unwrap(), schema, None).unwrap();
        writer.write(&batch).unwrap(); writer.close().unwrap();
        let hash = hex::encode(Sha256::digest(std::fs::read(&path).unwrap()));
        let hint = |value: &str| CandidateHint::Entity { source_path:"user.name".into(), value:value.into() };
        assert!(!cached_may_match(&path, Some(&hash), &[hint("bob")]));
        assert!(cached_may_match(&path, Some(&hash), &[hint("jsmith")]));
        assert!(cached_may_match(&path, Some(&hash), &[CandidateHint::Any { alternatives:vec![hint("bob"), CandidateHint::Keyword { mode:"token".into(), value:"other".into() }] }]));
        assert!(object_may_match(&path, &[hint("İ")]));
        std::fs::remove_file(&path).unwrap();
        assert!(!cached_may_match(&path, Some(&hash), &[hint("bob")]));
        assert!(cached_may_match(&path, None, &[hint("bob")]));
        assert!(cached_may_match(&path, Some(&"b".repeat(64)), &[hint("bob")]));
    }
}
