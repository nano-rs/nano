// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounds what a YAML document may expand to before it is materialised
//! (NAN-5142, security review 2026-11-09).
//!
//! serde_yaml replays an anchored node for every alias that references it,
//! so a small file of aliases to aliases can expand into a tree many orders
//! of magnitude larger than itself (its own repetition guard counts alias
//! jumps, not expanded nodes). An alias-free document can never yield more
//! nodes or scalar bytes than it has bytes of text, so a budget derived from
//! the input length never trips on ordinary YAML, while any meaningful
//! fan-out stops early, before anything large is allocated.
//!
//! Every parse of user- or repository-supplied YAML goes through
//! [`from_str`] (or [`check`] first). Trusted, compiled-in config need not.

use serde::de::{self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use std::cell::Cell;
use std::fmt;

/// Slack on top of the input length (tiny documents, implicit nulls).
const SLACK: usize = 1024;
const OVER_BUDGET: &str = "nano: yaml expansion budget exceeded";

struct Budget {
    nodes: Cell<usize>,
    bytes: Cell<usize>,
    limit: usize,
}

impl Budget {
    fn node<E: de::Error>(&self, scalar_bytes: usize) -> Result<(), E> {
        let nodes = self.nodes.get() + 1;
        let bytes = self.bytes.get().saturating_add(scalar_bytes);
        self.nodes.set(nodes);
        self.bytes.set(bytes);
        if nodes > self.limit || bytes > self.limit {
            return Err(E::custom(OVER_BUDGET));
        }
        Ok(())
    }
}

/// `Err` only when the budget is exceeded. Any other parse error is left
/// to the real parse, which reports it with context.
pub fn check(data: &str) -> Result<(), ExpansionExceeded> {
    let budget = Budget { nodes: Cell::new(0), bytes: Cell::new(0), limit: data.len().saturating_add(SLACK) };
    match Count(&budget).deserialize(serde_yaml::Deserializer::from_str(data)) {
        Err(e) if e.to_string().contains(OVER_BUDGET) => Err(ExpansionExceeded),
        _ => Ok(()),
    }
}

#[derive(Clone, Copy)]
struct Count<'b>(&'b Budget);

impl<'de> DeserializeSeed<'de> for Count<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Count<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any YAML value")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        self.0.node(0)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        self.0.node(0)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        self.0.node(0)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        self.0.node(0)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<(), E> {
        self.0.node(v.len())
    }
    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<(), E> {
        self.0.node(v.len())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.0.node(0)
    }
    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        self.0.node(0)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        self.0.node(0)?;
        self.deserialize(d)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        self.0.node(0)?;
        while seq.next_element_seed(self)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        self.0.node(0)?;
        while map.next_key_seed(self)?.is_some() {
            map.next_value_seed(self)?;
        }
        Ok(())
    }
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<(), A::Error> {
        // A tagged node (`!tag value`): count the tag, then its value.
        let ((), variant) = data.variant_seed(self)?;
        variant.newtype_variant_seed(self)
    }
}

/// The document expands past its budget (YAML aliases fanning out).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("YAML expands to far more content than it contains; YAML aliases are not supported here")]
pub struct ExpansionExceeded;

/// [`serde_yaml::from_str`] behind the expansion budget. Over budget is a
/// `serde_yaml::Error`, so callers keep their existing error mapping.
pub fn from_str<T: serde::de::DeserializeOwned>(data: &str) -> Result<T, serde_yaml::Error> {
    check(data).map_err(|e| <serde_yaml::Error as de::Error>::custom(e))?;
    serde_yaml::from_str(data)
}

#[cfg(test)]
#[path = "yaml_budget_tests.rs"]
mod tests;
