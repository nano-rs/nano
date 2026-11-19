// SPDX-License-Identifier: AGPL-3.0-or-later

//! Streaming, filtering decode of a STIX bundle (NAN-5668).
//!
//! The pinned ATT&CK v19.1 bundle is 53 MB, and most of it is prose the
//! catalog never stores: relationship descriptions (`uses`, `mitigates`,
//! `subtechnique-of`), groups, software, campaigns, citation lists. Decoding
//! it into a `Vec<StixObject>` kept every one of those strings alive at once
//! (about 32 MiB on top of the body), which with the PostgreSQL read put
//! nano-jobs over its 214 MiB limit on an 8 GB host.
//!
//! This visitor walks `objects` one element at a time and keeps only what
//! `parse_catalog` reads: tactics and attack-patterns (description cut to the
//! stored first paragraph, external references cut to the canonical
//! `mitre-attack` entry), the data-component / analytic / detection-strategy
//! graph without prose, and `detects` / `revoked-by` relationships. Every
//! other object is dropped as soon as it is decoded, so the peak heap above
//! the body is a few MiB regardless of how much prose the bundle carries.

use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

use super::types::{StixBundle, StixObject};

/// A bundle reduced to the objects the catalog parse reads.
#[derive(Debug)]
pub struct FilteredBundle {
    /// Identity plus the retained objects only.
    pub bundle: StixBundle,
    /// Every object in the source bundle, retained or not (the shape floor
    /// `min_objects` is checked against the upstream count).
    pub object_count: usize,
}

/// Decode `body` as a STIX bundle, keeping only catalog-relevant objects.
/// Trailing bytes after the bundle are an error, as with `from_slice`.
pub fn decode_filtered_bundle(body: &[u8]) -> Result<FilteredBundle, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let bundle = (&mut deserializer).deserialize_map(BundleVisitor)?;
    deserializer.end()?;
    Ok(bundle)
}

/// Same cut as the stored description (first paragraph, 500 chars).
pub(crate) fn truncate_description(description: &str) -> String {
    let first_paragraph = description.split("\n\n").next().unwrap_or(description);
    if first_paragraph.chars().count() <= 500 {
        return first_paragraph.to_string();
    }
    format!(
        "{}...",
        first_paragraph.chars().take(497).collect::<String>()
    )
}

/// Reduce one decoded object to what the catalog parse reads, or drop it.
fn retain(mut object: StixObject) -> Option<StixObject> {
    match object.object_type.as_str() {
        "x-mitre-tactic" | "attack-pattern" => {
            // `truncate_description` is idempotent, so cutting here and again
            // in parse_tactic / parse_technique stores the same text.
            object.description = object.description.as_deref().map(truncate_description);
            // Only the first `mitre-attack` reference is ever read (external
            // id and URL); the rest are citations.
            object.external_references = object.external_references.map(|references| {
                references
                    .into_iter()
                    .find(|reference| reference.source_name.as_deref() == Some("mitre-attack"))
                    .into_iter()
                    .collect()
            });
        }
        "x-mitre-data-component" | "x-mitre-analytic" | "x-mitre-detection-strategy" => {
            object.description = None;
            object.external_references = None;
        }
        "relationship"
            if matches!(
                object.relationship_type.as_deref(),
                Some("detects") | Some("revoked-by")
            ) =>
        {
            object.description = None;
            object.external_references = None;
        }
        _ => return None,
    }
    Some(object)
}

struct BundleVisitor;

impl<'de> Visitor<'de> for BundleVisitor {
    type Value = FilteredBundle;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a STIX bundle object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut bundle_type: Option<String> = None;
        let mut id: Option<String> = None;
        let mut objects: Option<(Vec<StixObject>, usize)> = None;
        while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            match key.as_ref() {
                "type" => {
                    if bundle_type.is_some() {
                        return Err(de::Error::duplicate_field("type"));
                    }
                    bundle_type = Some(map.next_value()?);
                }
                "id" => {
                    if id.is_some() {
                        return Err(de::Error::duplicate_field("id"));
                    }
                    id = Some(map.next_value()?);
                }
                "objects" => {
                    if objects.is_some() {
                        return Err(de::Error::duplicate_field("objects"));
                    }
                    objects = Some(map.next_value_seed(ObjectsSeed)?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        let (objects, object_count) = objects.ok_or_else(|| de::Error::missing_field("objects"))?;
        Ok(FilteredBundle {
            bundle: StixBundle {
                bundle_type: bundle_type.ok_or_else(|| de::Error::missing_field("type"))?,
                id: id.ok_or_else(|| de::Error::missing_field("id"))?,
                objects,
            },
            object_count,
        })
    }
}

struct ObjectsSeed;

impl<'de> DeserializeSeed<'de> for ObjectsSeed {
    type Value = (Vec<StixObject>, usize);

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(ObjectsVisitor)
    }
}

struct ObjectsVisitor;

impl<'de> Visitor<'de> for ObjectsVisitor {
    type Value = (Vec<StixObject>, usize);

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of STIX objects")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut retained = Vec::new();
        let mut count = 0usize;
        while let Some(object) = seq.next_element::<StixObject>()? {
            count += 1;
            if let Some(object) = retain(object) {
                retained.push(object);
            }
        }
        Ok((retained, count))
    }
}

#[cfg(test)]
#[path = "stix_stream_tests.rs"]
mod tests;
