// SPDX-License-Identifier: AGPL-3.0-or-later
//! Decoded entity locators from currently leased, signature-verified files.
//! This engine-local cache never supplies coverage, totals or authorization.
//! The signed digest and expected shape bind each immutable summary; the
//! caller still selects live parts, leases the file and runs final SQL/masks.
use crate::parts::entity_locators::EntityLocators;
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    path::Path,
    sync::{Arc, Mutex},
};

/// NAN-3165: 256 MiB (was 32 MiB, smaller than one 24 h hot window's
/// locators, so every query re-decoded every file). Entries are projected to
/// a query's hinted fields, so one field's locators cost a fraction of the
/// file's full decode.
const MAX_BYTES: usize = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 16_384;
/// `(digest, groups, rows, projected fields)`; `None` = every field.
type Key = (String, usize, u64, Option<Vec<String>>);

#[derive(Default)]
struct Inner {
    entries: HashMap<Key, (usize, Arc<EntityLocators>)>,
    order: VecDeque<Key>,
    bytes: usize,
}

#[derive(Default)]
pub(crate) struct EntityCache {
    inner: Mutex<Inner>,
}

impl EntityCache {
    /// Every field (tests and ingest proofs). Only call while holding the
    /// fetcher's verified lease for `digest`.
    #[cfg(test)]
    pub fn get(
        &self,
        path: &Path,
        digest: &str,
        groups: usize,
        rows: u64,
    ) -> Option<Arc<EntityLocators>> {
        self.get_with((digest.to_owned(), groups, rows, None), path, |bytes| EntityLocators::decode(bytes, groups, rows))
    }

    /// NAN-3165: the locator of `digest` holding only `fields` (a query's
    /// hinted paths); other fields are skipped at decode and read as unknown.
    /// Only call while holding the fetcher's verified lease for `digest`.
    pub fn get_fields(
        &self,
        path: &Path,
        digest: &str,
        groups: usize,
        rows: u64,
        fields: &BTreeSet<String>,
    ) -> Option<Arc<EntityLocators>> {
        let key = (digest.to_owned(), groups, rows, Some(fields.iter().cloned().collect()));
        self.get_with(key, path, |bytes| EntityLocators::decode_fields(bytes, groups, rows, fields))
    }

    fn get_with(
        &self,
        key: Key,
        path: &Path,
        decode: impl FnOnce(&[u8]) -> anyhow::Result<EntityLocators>,
    ) -> Option<Arc<EntityLocators>> {
        if let Some((_, value)) = self.inner.lock().ok()?.entries.get(&key) {
            return Some(value.clone());
        }
        // Bound the read as well as the decoder; an oversized file remains
        // unknown evidence and therefore falls back to the normal SQL path.
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .ok()?
            .take((crate::parts::entity_locators::MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .ok()?;
        let value = Arc::new(decode(&bytes).ok()?);
        let fields_bytes = key.3.as_ref().map_or(0, |fields| fields.iter().map(|f| f.len() + 24).sum());
        let size = resident_bytes(&value).saturating_add(256 + key.0.len() * 2 + fields_bytes);
        if size > MAX_BYTES {
            return Some(value);
        }
        let mut inner = self.inner.lock().ok()?;
        if let Some((_, existing)) = inner.entries.get(&key) {
            return Some(existing.clone());
        }
        while inner.bytes + size > MAX_BYTES || inner.entries.len() >= MAX_ENTRIES {
            let oldest = inner.order.pop_front()?;
            inner.bytes -= inner.entries.remove(&oldest)?.0;
        }
        inner.bytes += size;
        inner.order.push_back(key.clone());
        inner.entries.insert(key, (size, value.clone()));
        Some(value)
    }
}

fn resident_bytes(value: &EntityLocators) -> usize {
    // Account vector capacity and conservative BTree node overhead, rather
    // than serialized bytes (tiny offsets can expand considerably in RAM).
    std::mem::size_of::<EntityLocators>()
        + value.groups.capacity() * std::mem::size_of::<crate::parts::entity_locators::Group>()
        + value
            .groups
            .iter()
            .map(|group| {
                group
                    .fields
                    .iter()
                    .map(|(path, values)| {
                        256 + path.capacity()
                            + values
                                .iter()
                                .map(|(value, offsets)| {
                                    256 + value.capacity()
                                        + offsets.capacity() * std::mem::size_of::<u32>()
                                })
                                .sum::<usize>()
                    })
                    .sum::<usize>()
            })
            .sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parts::entity_locators::Group, planner::CandidateHint};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn signed_shape_changes_and_invalid_evidence_never_reuse_negatives() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let locator = EntityLocators {
            version: 1,
            groups: vec![Group {
                rows: 3,
                fields: BTreeMap::from([(
                    "device.hostname".into(),
                    BTreeMap::from([("host".into(), vec![0, 2])]),
                )]),
            }],
        };
        std::fs::write(file.path(), serde_json::to_vec(&locator).unwrap()).unwrap();
        let cache = EntityCache::default();
        let cold = cache.get(file.path(), "signed-a", 1, 3).unwrap();
        let warm = cache.get(file.path(), "signed-a", 1, 3).unwrap();
        assert!(Arc::ptr_eq(&cold, &warm));
        assert!(cache.get(file.path(), "signed-a", 2, 3).is_none());
        assert!(cache.get(file.path(), "signed-a", 1, 4).is_none());
        std::fs::write(file.path(), b"invalid").unwrap();
        assert!(cache.get(file.path(), "signed-b", 1, 3).is_none());
        assert_eq!(cache.inner.lock().unwrap().entries.len(), 1);
    }

    #[test]
    fn random_and_chains_preserve_rows_masks_and_counts_cold_and_warm() {
        let paths = ["device.hostname", "src_endpoint.ip", "user.name"];
        let rows: Vec<[String; 3]> = (0..256)
            .map(|i| {
                [
                    format!("host{}", i % 7),
                    format!("10.0.0.{}", i % 11),
                    format!("user{}", i % 5),
                ]
            })
            .collect();
        let fields = paths
            .iter()
            .enumerate()
            .map(|(column, path)| {
                let mut values = BTreeMap::<String, Vec<u32>>::new();
                for (offset, row) in rows.iter().enumerate() {
                    values
                        .entry(row[column].clone())
                        .or_default()
                        .push(offset as u32);
                }
                (path.to_string(), values)
            })
            .collect();
        let locator = EntityLocators {
            version: 1,
            groups: vec![Group {
                rows: rows.len() as u32,
                fields,
            }],
        };
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), serde_json::to_vec(&locator).unwrap()).unwrap();
        let cache = EntityCache::default();
        let mut seed = 3077_u64;
        for _ in 0..120 {
            let mut hints = Vec::new();
            let mut predicates = Vec::new();
            for _ in 0..3 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let column = (seed % 3) as usize;
                let value = rows[(seed >> 8) as usize % rows.len()][column].clone();
                hints.push(CandidateHint::Entity {
                    source_path: paths[column].into(),
                    value: value.clone(),
                });
                predicates.push((column, value));
                let expected: Vec<bool> = rows
                    .iter()
                    .map(|row| {
                        predicates
                            .iter()
                            .all(|(column, value)| &row[*column] == value)
                    })
                    .collect();
                for _ in 0..2 {
                    let decoded = cache
                        .get(file.path(), "signed-fixture", 1, rows.len() as u64)
                        .unwrap();
                    let actual = EntityLocators::row_mask(&decoded.groups[0], &hints);
                    assert_eq!(actual, expected);
                    assert_eq!(
                        decoded.group_mask(&hints),
                        vec![expected.iter().any(|keep| *keep)]
                    );
                    let selected: Vec<_> = rows
                        .iter()
                        .zip(&actual)
                        .filter_map(|(row, keep)| keep.then_some(row))
                        .collect();
                    let reference: Vec<_> = rows
                        .iter()
                        .zip(&expected)
                        .filter_map(|(row, keep)| keep.then_some(row))
                        .collect();
                    assert_eq!(selected, reference);
                    assert_eq!(
                        selected.len(),
                        expected.iter().filter(|keep| **keep).count()
                    );
                }
            }
        }
    }

    #[test]
    #[ignore = "local reader microbenchmark"]
    fn repeated_signed_summary_decode_cost() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut values = BTreeMap::<String, Vec<u32>>::new();
        for row in 0..65_536_u32 {
            values
                .entry(format!("host{}", row % 700))
                .or_default()
                .push(row);
        }
        let locator = EntityLocators {
            version: 1,
            groups: vec![Group {
                rows: 65_536,
                fields: BTreeMap::from([("device.hostname".into(), values)]),
            }],
        };
        let bytes = serde_json::to_vec(&locator).unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..100 {
            std::hint::black_box(
                EntityLocators::decode(&std::fs::read(file.path()).unwrap(), 1, 65_536).unwrap(),
            );
        }
        let before = start.elapsed();
        let cache = EntityCache::default();
        let start = std::time::Instant::now();
        cache
            .get(file.path(), "signed-benchmark", 1, 65_536)
            .unwrap();
        let cold = start.elapsed();
        let start = std::time::Instant::now();
        for _ in 0..100 {
            std::hint::black_box(
                cache
                    .get(file.path(), "signed-benchmark", 1, 65_536)
                    .unwrap(),
            );
        }
        eprintln!(
            "entity locator bytes={} repeated=100 before={before:?} cold={cold:?} warm={:?}",
            bytes.len(),
            start.elapsed()
        );
    }

    /// NAN-3165: one hinted field's projected decode against the full decode
    /// of a four-field locator (the live sidecar shape).
    #[test]
    #[ignore = "local reader microbenchmark"]
    fn projected_versus_full_locator_decode_cost() {
        let paths = ["device.hostname", "src_endpoint.ip", "dst_endpoint.ip", "user.name"];
        let fields = paths
            .iter()
            .enumerate()
            .map(|(column, path)| {
                let mut values = BTreeMap::<String, Vec<u32>>::new();
                for row in 0..65_536_u32 {
                    values.entry(format!("value{}-{}", column, row % 4_000)).or_default().push(row);
                }
                (path.to_string(), values)
            })
            .collect();
        let bytes = serde_json::to_vec(&EntityLocators { version: 1, groups: vec![Group { rows: 65_536, fields }] }).unwrap();
        let wanted = BTreeSet::from(["src_endpoint.ip".to_string()]);
        let start = std::time::Instant::now();
        for _ in 0..20 {
            std::hint::black_box(EntityLocators::decode(&bytes, 1, 65_536).unwrap());
        }
        let full = start.elapsed() / 20;
        let start = std::time::Instant::now();
        for _ in 0..20 {
            std::hint::black_box(EntityLocators::decode_fields(&bytes, 1, 65_536, &wanted).unwrap());
        }
        let projected = start.elapsed() / 20;
        eprintln!("NAN3165 locator bytes={} full_decode={full:?} projected_one_field={projected:?}", bytes.len());
    }

    #[test]
    fn resident_byte_bound_evicts_before_entry_bound() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let locator = EntityLocators {
            version: 1,
            groups: vec![Group {
                rows: 1,
                fields: BTreeMap::from([(
                    "device.hostname".into(),
                    BTreeMap::from([("h".repeat(1024 * 1024), vec![0])]),
                )]),
            }],
        };
        std::fs::write(file.path(), serde_json::to_vec(&locator).unwrap()).unwrap();
        let cache = EntityCache::default();
        let inserts = MAX_BYTES / (1024 * 1024) + 6;
        for i in 0..inserts {
            cache
                .get(file.path(), &format!("signed-{i}"), 1, 1)
                .unwrap();
        }
        let inner = cache.inner.lock().unwrap();
        assert!(inner.entries.len() < inserts);
        assert!(inner.bytes <= MAX_BYTES);
        assert!(!inner.entries.contains_key(&("signed-0".into(), 1, 1, None)));
    }

    /// NAN-3165: a projected decode answers its hinted fields exactly as
    /// the full decode, holds no other field (unknown, never empty), is
    /// cached apart from the full entry, and still refuses a bad shape.
    #[test]
    fn projected_fields_match_the_full_decode_for_their_hints() {
        let fields = ["device.hostname", "src_endpoint.ip", "user.name"]
            .iter()
            .enumerate()
            .map(|(column, path)| {
                let mut values = BTreeMap::<String, Vec<u32>>::new();
                for row in 0..64_u32 {
                    values.entry(format!("v{}", (row as usize + column) % 5)).or_default().push(row);
                }
                (path.to_string(), values)
            })
            .collect();
        let locator = EntityLocators { version: 1, groups: vec![Group { rows: 64, fields }] };
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), serde_json::to_vec(&locator).unwrap()).unwrap();
        let cache = EntityCache::default();
        let full = cache.get(file.path(), "signed-p", 1, 64).unwrap();
        let wanted = BTreeSet::from(["src_endpoint.ip".to_string()]);
        let projected = cache.get_fields(file.path(), "signed-p", 1, 64, &wanted).unwrap();
        assert_eq!(projected.groups[0].fields.keys().collect::<Vec<_>>(), vec!["src_endpoint.ip"]);
        for value in ["v0", "v3", "absent"] {
            let hints = [CandidateHint::Entity { source_path: "src_endpoint.ip".into(), value: value.into() }];
            assert_eq!(projected.group_mask(&hints), full.group_mask(&hints), "{value}");
            assert_eq!(
                EntityLocators::row_mask(&projected.groups[0], &hints),
                EntityLocators::row_mask(&full.groups[0], &hints)
            );
            assert!(projected.covers(&hints));
        }
        // A field outside the projection is unknown: it keeps every row.
        let other = [CandidateHint::Entity { source_path: "user.name".into(), value: "absent".into() }];
        assert_eq!(projected.group_mask(&other), vec![true]);
        assert!(!projected.covers(&other));
        assert!(!Arc::ptr_eq(&full, &projected));
        assert!(Arc::ptr_eq(&projected, &cache.get_fields(file.path(), "signed-p", 1, 64, &wanted).unwrap()));
        // Shape checks still apply to a projected decode.
        assert!(cache.get_fields(file.path(), "signed-p", 2, 64, &wanted).is_none());
        std::fs::write(file.path(), br#"{"version":1,"groups":[{"rows":1,"fields":{}}],"extra":1}"#).unwrap();
        assert!(cache.get_fields(file.path(), "signed-q", 1, 1, &wanted).is_none());
    }

    #[test]
    fn entry_count_and_resident_bytes_are_bounded() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            br#"{"version":1,"groups":[{"rows":1,"fields":{}}]}"#,
        )
        .unwrap();
        let cache = EntityCache::default();
        for i in 0..MAX_ENTRIES + 10 {
            cache
                .get(file.path(), &format!("signed-{i}"), 1, 1)
                .unwrap();
        }
        let inner = cache.inner.lock().unwrap();
        assert_eq!(inner.entries.len(), MAX_ENTRIES);
        assert!(inner.bytes <= MAX_BYTES);
        assert!(!inner.entries.contains_key(&("signed-0".into(), 1, 1, None)));
    }
}
