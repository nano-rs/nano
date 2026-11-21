// SPDX-License-Identifier: AGPL-3.0-or-later
//! The wire form of a lookup row id (`_row_id`), NAN-5715.
//!
//! ClickHouse lookup rows carry 64-bit snowflake ids (19 digits, above 2^53).
//! As JSON numbers the browser rounded them, so a cell edit `PUT` the rounded
//! id and the ClickHouse store wrote a NEW row under it (insert-on-top), and a
//! delete could miss the row or tombstone a neighbour. Row ids therefore cross
//! the API as decimal STRINGS, and requests accept a string or a number.
//!
//! Canonical form: the id's unsigned 64-bit value. Idempotent-append ids set
//! bit 63 (`repository::idempotent_row_id`), so they are above `i64::MAX` as
//! decimals; the stores take the same bits as `i64` (`row_id as u64` on the
//! way in), and parsing accepts both spellings.

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;

/// The wire string for a row id held as `i64` (its unsigned 64-bit value).
pub fn row_id_to_wire(id: i64) -> String {
    (id as u64).to_string()
}

/// Parse a wire row id: an unsigned 64-bit decimal (canonical) or a signed
/// one. `None` for anything else, including a rounded float like `7.5e18`.
pub fn parse_row_id(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    raw.parse::<u64>()
        .map(|u| u as i64)
        .ok()
        .or_else(|| raw.parse::<i64>().ok())
}

/// Rewrite every row's numeric `_row_id` as its wire string (in place).
pub fn stringify_row_ids(rows: &mut [HashMap<String, serde_json::Value>]) {
    for row in rows {
        let Some(v) = row.get_mut("_row_id") else { continue };
        let wire = match &*v {
            serde_json::Value::Number(n) => match (n.as_u64(), n.as_i64()) {
                (Some(u), _) => u.to_string(),
                (None, Some(i)) => row_id_to_wire(i),
                _ => n.to_string(),
            },
            _ => continue,
        };
        *v = serde_json::Value::String(wire);
    }
}

/// `serde(deserialize_with)` for a list of row ids sent as strings or numbers.
pub fn deserialize_row_ids<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<i64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire {
        U(u64),
        I(i64),
        S(String),
    }
    Vec::<Wire>::deserialize(d)?
        .into_iter()
        .map(|w| match w {
            Wire::U(u) => Ok(u as i64),
            Wire::I(i) => Ok(i),
            Wire::S(s) => parse_row_id(&s)
                .ok_or_else(|| serde::de::Error::custom(format!("invalid row id {s:?}"))),
        })
        .collect()
}

/// `serde(serialize_with)` for a list of row ids: wire strings.
pub fn serialize_row_ids<S: serde::Serializer>(ids: &[i64], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(ids.iter().map(|id| row_id_to_wire(*id)))
}

#[cfg(test)]
#[path = "row_id_tests.rs"]
mod tests;
