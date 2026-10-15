// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact scalar entity offsets. Only signed, leased inventories may supply
//! these bytes. Unknown fields, non-ASCII values and incomplete groups retain
//! every row; final SQL and authorization masking still run normally.
use crate::planner::CandidateHint;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_GROUP_BYTES: usize = 2 * 1024 * 1024;
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityLocators {
    pub version: u32,
    pub groups: Vec<Group>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub rows: u32,
    /// Omitted field means unknown, never an empty set.
    pub fields: BTreeMap<String, BTreeMap<String, Vec<u32>>>,
}

pub fn normalized(path: &str, value: &str) -> String {
    if crate::part_query::prune::INGEST_LOWERCASED_BLOOM_PATHS.contains(&path) {
        value.to_owned()
    } else {
        value.to_ascii_lowercase()
    }
}
pub fn uses_locators(hints: &[CandidateHint]) -> bool {
    hints.iter().any(|hint| match hint {
        CandidateHint::Entity { source_path, value } => {
            value.is_ascii()
                && source_path != crate::parts::format::UID_PATH
                && crate::parts::format::BLOOM_PATHS.contains(&source_path.as_str())
        }
        CandidateHint::Any { alternatives } => uses_locators(alternatives),
        _ => false,
    })
}
/// The locator-eligible fields `hints` consult (NAN-3165 projection key).
pub fn hinted_fields(hints: &[CandidateHint]) -> std::collections::BTreeSet<String> {
    fn walk(hint: &CandidateHint, out: &mut std::collections::BTreeSet<String>) {
        match hint {
            CandidateHint::Entity { source_path, .. } => {
                out.insert(source_path.clone());
            }
            CandidateHint::Any { alternatives } => alternatives.iter().for_each(|hint| walk(hint, out)),
            _ => {}
        }
    }
    let mut out = std::collections::BTreeSet::new();
    hints.iter().for_each(|hint| walk(hint, &mut out));
    out
}

/// NAN-3165: serde seeds that decode only the `wanted` fields of a locator;
/// every other field's values are skipped with `IgnoredAny` (scanned, never
/// allocated). The document shape stays strict: unknown keys are refused.
mod projected {
    use super::{EntityLocators, Group};
    use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt;

    pub struct Locators<'a>(pub &'a BTreeSet<String>);
    struct Groups<'a>(&'a BTreeSet<String>);
    struct OneGroup<'a>(&'a BTreeSet<String>);
    struct Fields<'a>(&'a BTreeSet<String>);

    impl<'de> DeserializeSeed<'de> for Locators<'_> {
        type Value = EntityLocators;
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for Locators<'_> {
        type Value = EntityLocators;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("an entity locator") }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let (mut version, mut groups) = (None, None);
            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "version" if version.is_none() => version = Some(map.next_value::<u32>()?),
                    "groups" if groups.is_none() => groups = Some(map.next_value_seed(Groups(self.0))?),
                    other => return Err(de::Error::custom(format!("unexpected locator key {other}"))),
                }
            }
            Ok(EntityLocators {
                version: version.ok_or_else(|| de::Error::missing_field("version"))?,
                groups: groups.ok_or_else(|| de::Error::missing_field("groups"))?,
            })
        }
    }
    impl<'de> DeserializeSeed<'de> for Groups<'_> {
        type Value = Vec<Group>;
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_seq(self)
        }
    }
    impl<'de> Visitor<'de> for Groups<'_> {
        type Value = Vec<Group>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("locator groups") }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(group) = seq.next_element_seed(OneGroup(self.0))? {
                out.push(group);
            }
            Ok(out)
        }
    }
    impl<'de> DeserializeSeed<'de> for OneGroup<'_> {
        type Value = Group;
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for OneGroup<'_> {
        type Value = Group;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("a locator group") }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let (mut rows, mut fields) = (None, None);
            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "rows" if rows.is_none() => rows = Some(map.next_value::<u32>()?),
                    "fields" if fields.is_none() => fields = Some(map.next_value_seed(Fields(self.0))?),
                    other => return Err(de::Error::custom(format!("unexpected locator group key {other}"))),
                }
            }
            Ok(Group {
                rows: rows.ok_or_else(|| de::Error::missing_field("rows"))?,
                fields: fields.ok_or_else(|| de::Error::missing_field("fields"))?,
            })
        }
    }
    impl<'de> DeserializeSeed<'de> for Fields<'_> {
        type Value = BTreeMap<String, BTreeMap<String, Vec<u32>>>;
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for Fields<'_> {
        type Value = BTreeMap<String, BTreeMap<String, Vec<u32>>>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("locator fields") }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some(path) = map.next_key::<String>()? {
                if self.0.contains(&path) {
                    let values = map.next_value::<BTreeMap<String, Vec<u32>>>()?;
                    if out.insert(path, values).is_some() {
                        return Err(de::Error::custom("duplicate locator field"));
                    }
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(out)
        }
    }
}

impl EntityLocators {
    pub fn decode(bytes: &[u8], groups: usize, rows: u64) -> Result<Self> {
        ensure!(bytes.len() <= MAX_BYTES, "entity locator exceeds byte cap");
        let value: Self = serde_json::from_slice(bytes)?;
        Self::validated(value, groups, rows)
    }

    /// NAN-3165: [`Self::decode`] keeping only the `wanted` fields (the ones
    /// a query's hints consult). A field outside `wanted` is absent, which
    /// every reader treats as unknown evidence (keep), never as empty; kept
    /// fields are validated exactly as in a full decode.
    pub fn decode_fields(bytes: &[u8], groups: usize, rows: u64, wanted: &std::collections::BTreeSet<String>) -> Result<Self> {
        use serde::de::DeserializeSeed;
        ensure!(bytes.len() <= MAX_BYTES, "entity locator exceeds byte cap");
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let value = projected::Locators(wanted).deserialize(&mut deserializer)?;
        deserializer.end()?;
        Self::validated(value, groups, rows)
    }

    fn validated(value: Self, groups: usize, rows: u64) -> Result<Self> {
        ensure!(
            value.version == 1 && value.groups.len() == groups,
            "entity locator shape differs"
        );
        ensure!(
            value
                .groups
                .iter()
                .map(|group| u64::from(group.rows))
                .sum::<u64>()
                == rows,
            "entity locator row count differs"
        );
        for group in &value.groups {
            ensure!(
                group.rows > 0
                    && group.rows as usize <= crate::parts::format::MAX_ROW_GROUP_ROWS,
                "entity locator group rows out of bounds"
            );
            for (path, values) in &group.fields {
                ensure!(
                    crate::parts::format::BLOOM_PATHS.contains(&path.as_str()),
                    "unsupported entity locator field"
                );
                for (value, offsets) in values {
                    ensure!(
                        value.is_ascii() && normalized(path, value) == *value,
                        "entity locator normalization differs"
                    );
                    ensure!(
                        offsets.iter().all(|row| *row < group.rows)
                            && offsets.windows(2).all(|pair| pair[0] < pair[1]),
                        "invalid entity locator offsets"
                    );
                }
            }
        }
        Ok(value)
    }
    /// Exact offsets for supported predicates, a conservative superset otherwise.
    pub fn row_mask(group: &Group, hints: &[CandidateHint]) -> Vec<bool> {
        fn hint_mask(group: &Group, hint: &CandidateHint) -> Vec<bool> {
            match hint {
                CandidateHint::Entity { source_path, value } if value.is_ascii() => {
                    let Some(values) = group.fields.get(source_path) else {
                        return vec![true; group.rows as usize];
                    };
                    // Query raw-lowercase fields compare to a lowered literal.
                    let key = value.to_ascii_lowercase();
                    let mut mask = vec![false; group.rows as usize];
                    for row in values.get(&key).into_iter().flatten() {
                        mask[*row as usize] = true;
                    }
                    mask
                }
                CandidateHint::Any { alternatives } if !alternatives.is_empty() => {
                    let mut mask = vec![false; group.rows as usize];
                    for alternative in alternatives {
                        for (keep, other) in mask.iter_mut().zip(hint_mask(group, alternative)) {
                            *keep |= other;
                        }
                    }
                    mask
                }
                _ => vec![true; group.rows as usize],
            }
        }
        let mut mask = vec![true; group.rows as usize];
        for hint in hints {
            for (keep, other) in mask.iter_mut().zip(hint_mask(group, hint)) {
                *keep &= other;
            }
        }
        mask
    }
    /// Whether every group answers every locator-eligible hint exactly
    /// (no field of a hint is unknown in any group). When false, the bloom
    /// sidecar can still prune what the locator leaves unknown (NAN-3156:
    /// a group over the writer's byte budget keeps no field at all).
    pub fn covers(&self, hints: &[CandidateHint]) -> bool {
        fn known(group: &Group, hint: &CandidateHint) -> bool {
            match hint {
                CandidateHint::Entity { source_path, value } => {
                    !value.is_ascii() || !uses_locators(std::slice::from_ref(hint))
                        || group.fields.contains_key(source_path)
                }
                CandidateHint::Any { alternatives } => alternatives.iter().all(|hint| known(group, hint)),
                _ => true,
            }
        }
        self.groups.iter().all(|group| hints.iter().all(|hint| known(group, hint)))
    }

    pub fn group_mask(&self, hints: &[CandidateHint]) -> Vec<bool> {
        self.groups
            .iter()
            .map(|group| Self::group_matches(group, hints))
            .collect()
    }

    /// Prove row-level co-occurrence directly from signed sorted offsets.
    /// Missing fields and unsupported predicates remain unknown evidence.
    /// This is only a pruning proof; final SQL and authorization still run.
    fn group_matches(group: &Group, hints: &[CandidateHint]) -> bool {
        enum Evidence<'a> {
            Unknown,
            Rows(&'a [u32]),
            Any(Vec<Evidence<'a>>),
        }
        impl Evidence<'_> {
            fn matches(&self, row: u32) -> bool {
                match self {
                    Self::Unknown => true,
                    Self::Rows(rows) => rows.binary_search(&row).is_ok(),
                    Self::Any(alternatives) => alternatives.iter().any(|hint| hint.matches(row)),
                }
            }
            fn candidate_count(&self) -> Option<usize> {
                match self {
                    Self::Unknown => None,
                    Self::Rows(rows) => Some(rows.len()),
                    Self::Any(alternatives) => {
                        alternatives.iter().try_fold(0_usize, |count, hint| {
                            Some(count.saturating_add(hint.candidate_count()?))
                        })
                    }
                }
            }
            fn any_candidate(&self, matches: &impl Fn(u32) -> bool) -> bool {
                match self {
                    Self::Rows(rows) => rows.iter().any(|row| matches(*row)),
                    Self::Any(alternatives) => {
                        alternatives.iter().any(|hint| hint.any_candidate(matches))
                    }
                    Self::Unknown => unreachable!("unknown evidence never supplies candidates"),
                }
            }
        }
        fn evidence<'a>(group: &'a Group, hint: &CandidateHint) -> Evidence<'a> {
            match hint {
                CandidateHint::Entity { source_path, value } if value.is_ascii() => {
                    match group.fields.get(source_path) {
                        Some(values) => Evidence::Rows(
                            values
                                .get(&value.to_ascii_lowercase())
                                .map_or(&[], Vec::as_slice),
                        ),
                        None => Evidence::Unknown,
                    }
                }
                CandidateHint::Any { alternatives } if !alternatives.is_empty() => Evidence::Any(
                    alternatives
                        .iter()
                        .map(|hint| evidence(group, hint))
                        .collect(),
                ),
                _ => Evidence::Unknown,
            }
        }
        // Normalize and look up each value once, not once per candidate row.
        let proofs: Vec<_> = hints.iter().map(|hint| evidence(group, hint)).collect();
        // A rare entity bounds the adjacency check, independent of group size
        // and the number of OR alternatives in a lateral frontier.
        let candidates = proofs
            .iter()
            .filter_map(|proof| proof.candidate_count().map(|count| (count, proof)))
            .min_by_key(|(count, _)| *count);
        match candidates {
            Some((count, proof)) if count <= (group.rows as usize / 8).max(1) => {
                proof.any_candidate(&|row| proofs.iter().all(|proof| proof.matches(row)))
            }
            // Dense frontiers retain the linear bitmap algorithm rather than
            // paying a binary search for every row and every alternative.
            _ => Self::row_mask(group, hints).into_iter().any(|keep| keep),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hint(path: &str, value: &str) -> CandidateHint {
        CandidateHint::Entity {
            source_path: path.into(),
            value: value.into(),
        }
    }
    #[test]
    fn signed_adjacency_preserves_unknown_nested_or_and_disjoint_offsets() {
        let group = Group {
            rows: 64,
            fields: BTreeMap::from([
                (
                    "device.hostname".into(),
                    BTreeMap::from([("host".into(), vec![0, 2])]),
                ),
                (
                    "user.name".into(),
                    BTreeMap::from([("alice".into(), vec![1, 3])]),
                ),
            ]),
        };
        let predicates = vec![
            hint("device.hostname", "HOST"),
            hint("user.name", "alice"),
            hint("user.name", "absent"),
            hint("unknown", "x"),
            hint("user.name", "Älice"),
            CandidateHint::Any {
                alternatives: vec![],
            },
            CandidateHint::Any {
                alternatives: vec![hint("user.name", "absent"), hint("unknown", "x")],
            },
            CandidateHint::Any {
                alternatives: vec![
                    hint("user.name", "alice"),
                    CandidateHint::Any {
                        alternatives: vec![
                            hint("device.hostname", "host"),
                            hint("user.name", "absent"),
                        ],
                    },
                ],
            },
        ];
        for left in &predicates {
            for right in &predicates {
                for third in &predicates {
                    let hints = [left.clone(), right.clone(), third.clone()];
                    assert_eq!(
                        EntityLocators::group_matches(&group, &hints),
                        EntityLocators::row_mask(&group, &hints)
                            .into_iter()
                            .any(|keep| keep)
                    );
                }
            }
        }
        assert!(EntityLocators::group_matches(&group, &[]));
        assert!(!EntityLocators::group_matches(
            &group,
            &[hint("device.hostname", "host"), hint("user.name", "alice")]
        ));
    }

    #[test]
    #[ignore = "local signed adjacency microbenchmark"]
    fn signed_adjacency_probe_cost() {
        let group = Group {
            rows: 65_536,
            fields: BTreeMap::from([
                (
                    "device.hostname".into(),
                    BTreeMap::from([("host".into(), vec![7, 33_000, 65_535])]),
                ),
                (
                    "user.name".into(),
                    BTreeMap::from([("alice".into(), vec![8, 33_001, 65_534])]),
                ),
            ]),
        };
        let hints = [hint("device.hostname", "HOST"), hint("user.name", "alice")];
        let start = std::time::Instant::now();
        for _ in 0..1_000 {
            assert!(
                !std::hint::black_box(EntityLocators::row_mask(&group, &hints))
                    .into_iter()
                    .any(|keep| keep)
            );
        }
        let before = start.elapsed();
        let start = std::time::Instant::now();
        for _ in 0..1_000 {
            assert!(!std::hint::black_box(EntityLocators::group_matches(
                &group, &hints
            )));
        }
        eprintln!(
            "signed adjacency 65536 rows, 1000 disjoint probes: before={before:?} after={:?}",
            start.elapsed()
        );
    }
    #[test]
    fn exact_and_or_unknown_and_invalid_offsets() {
        assert!(!uses_locators(&[hint("metadata.uid", "u0")]));
        let group = Group {
            rows: 3,
            fields: BTreeMap::from([
                (
                    "device.hostname".into(),
                    BTreeMap::from([("host".into(), vec![0, 2])]),
                ),
                (
                    "user.name".into(),
                    BTreeMap::from([("alice".into(), vec![1, 2])]),
                ),
            ]),
        };
        assert_eq!(
            EntityLocators::row_mask(
                &group,
                &[hint("device.hostname", "HOST"), hint("user.name", "Alice")]
            ),
            vec![false, false, true]
        );
        assert_eq!(
            EntityLocators::row_mask(&group, &[hint("unknown", "x")]),
            vec![true; 3]
        );
        assert_eq!(
            EntityLocators::row_mask(&group, &[hint("user.name", "Älice")]),
            vec![true; 3]
        );
        let any = CandidateHint::Any {
            alternatives: vec![hint("user.name", "alice"), hint("unknown", "x")],
        };
        assert_eq!(EntityLocators::row_mask(&group, &[any]), vec![true; 3]);
        let mut locator = EntityLocators {
            version: 1,
            groups: vec![group],
        };
        assert!(EntityLocators::decode(&serde_json::to_vec(&locator).unwrap(), 1, 3).is_ok());
        locator.groups[0]
            .fields
            .get_mut("user.name")
            .unwrap()
            .get_mut("alice")
            .unwrap()
            .push(3);
        assert!(EntityLocators::decode(&serde_json::to_vec(&locator).unwrap(), 1, 3).is_err());
    }

    #[test]
    fn wide_groups_decode_and_partial_fields_report_coverage() {
        // NAN-3156: 262,144-row groups decode; one row more does not.
        let wide = |rows: u32| EntityLocators {
            version: 1,
            groups: vec![Group {
                rows,
                fields: BTreeMap::from([(
                    "user.name".into(),
                    BTreeMap::from([("alice".into(), vec![0, rows - 1])]),
                )]),
            }],
        };
        let max = crate::parts::format::MAX_ROW_GROUP_ROWS as u32;
        assert!(EntityLocators::decode(&serde_json::to_vec(&wide(max)).unwrap(), 1, u64::from(max)).is_ok());
        assert!(EntityLocators::decode(&serde_json::to_vec(&wide(max + 1)).unwrap(), 1, u64::from(max) + 1).is_err());
        // `user.name` known, `device.hostname` unknown.
        let locator = wide(max);
        assert!(locator.covers(&[hint("user.name", "alice")]));
        assert!(!locator.covers(&[hint("device.hostname", "h")]));
        assert!(!locator.covers(&[CandidateHint::Any {
            alternatives: vec![hint("user.name", "alice"), hint("device.hostname", "h")],
        }]));
        // Not locator-eligible: no sidecar can do better, so "covered".
        assert!(locator.covers(&[hint("metadata.uid", "u"), hint("unknown", "x"), hint("user.name", "Älice")]));
        // Exact answers for kept fields; unknown (keep) for dropped ones.
        assert_eq!(locator.group_mask(&[hint("user.name", "bob")]), vec![false]);
        assert_eq!(locator.group_mask(&[hint("device.hostname", "h")]), vec![true]);
    }
}
