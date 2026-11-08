// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-entity read-time score weights.
//!
//! Neutral plumbing for the shared risk builders ([`super::clickhouse_sql`]):
//! an optional multiplier `w` per normalized (trimmed, lowercased) entity
//! value, applied at read time as `effective = round(base x (1 + w))`. The
//! open edition never supplies weights (every map is empty, so every score is
//! its base score); a deployment that does provides them through
//! [`crate::extensions::RiskScoreWeightsSource`].

use std::collections::BTreeMap;

/// Entity value -> weight in hundredths (`1..=100`). Empty means no
/// amplification anywhere.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntityScoreWeights {
    by_entity: BTreeMap<String, u8>,
}

impl EntityScoreWeights {
    /// Build from `(value, weight hundredths)` rows, keeping the maximum per
    /// normalized value and dropping zero weights.
    pub fn from_rows(rows: impl IntoIterator<Item = (String, u8)>) -> Self {
        let mut by_entity: BTreeMap<String, u8> = BTreeMap::new();
        for (entity, centi) in rows {
            let centi = centi.min(100);
            let key = entity.trim().to_lowercase();
            if centi == 0 || key.is_empty() {
                continue;
            }
            let slot = by_entity.entry(key).or_insert(0);
            *slot = (*slot).max(centi);
        }
        Self { by_entity }
    }

    pub fn is_empty(&self) -> bool {
        self.by_entity.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_entity.len()
    }

    /// The weight for an entity value (`0.0` when none applies).
    pub fn weight(&self, entity: &str) -> f64 {
        self.by_entity
            .get(&entity.trim().to_lowercase())
            .map_or(0.0, |centi| f64::from(*centi) / 100.0)
    }

    /// Parallel `(entities, weights)` arrays for the ClickHouse
    /// `arrayElement(weights, indexOf(entities, lower(entity)))` lookup, with
    /// a trailing `('', 0.0)` sentinel so neither array is ever empty.
    pub fn parallel_arrays(&self) -> (Vec<String>, Vec<f64>) {
        let mut entities = Vec::with_capacity(self.by_entity.len() + 1);
        let mut weights = Vec::with_capacity(self.by_entity.len() + 1);
        for (entity, centi) in &self.by_entity {
            entities.push(entity.clone());
            weights.push(f64::from(*centi) / 100.0);
        }
        entities.push(String::new());
        weights.push(0.0);
        (entities, weights)
    }
}

/// `round_half_even(base x (1 + weight))`, ClickHouse `round()` on Float64.
pub fn weighted_score(base: i64, weight: f64) -> i64 {
    if !weight.is_finite() || weight <= 0.0 {
        return base;
    }
    (base as f64 * (1.0 + weight)).round_ties_even() as i64
}

#[cfg(test)]
#[path = "score_weights_tests.rs"]
mod score_weights_tests;
