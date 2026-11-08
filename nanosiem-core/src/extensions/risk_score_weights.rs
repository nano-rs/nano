// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-time risk score weights hook.
//!
//! The risk builders can amplify an entity's score at read time
//! (`effective = base x (1 + w)`, see [`crate::risk::score_weights`]). The open
//! edition has no weights; an enterprise build supplies them here so the nPL
//! `dataset=risk` source scores entities exactly like the enterprise readers.

use async_trait::async_trait;

use crate::extensions::ExtensionError;
use crate::risk::score_weights::EntityScoreWeights;

#[async_trait]
pub trait RiskScoreWeightsSource: Send + Sync {
    /// The current per-entity weights. An error makes the caller keep its
    /// last good snapshot (stale-ok), never invent weights.
    async fn score_weights(&self) -> Result<EntityScoreWeights, ExtensionError>;
}

/// Open-core default: no weights, every score is its base score.
pub struct NoopRiskScoreWeightsSource;

#[async_trait]
impl RiskScoreWeightsSource for NoopRiskScoreWeightsSource {
    async fn score_weights(&self) -> Result<EntityScoreWeights, ExtensionError> {
        Ok(EntityScoreWeights::default())
    }
}
