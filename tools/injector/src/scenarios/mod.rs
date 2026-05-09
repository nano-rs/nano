//! Attack scenarios for the injector tool

pub mod exfil;
pub mod lateral;
pub mod persistence;
pub mod quick;
pub mod staggered;

use event_core::entity::Entity;
use event_core::event::Event;
use std::time::Duration;

/// A single step in an attack scenario
pub struct AttackStep {
    /// Delay from scenario start
    pub delay: Duration,
    /// Events to send at this step
    pub events: Vec<Event>,
    /// MITRE ATT&CK stage label
    pub stage: String,
    /// Human-readable description
    pub description: String,
}

/// Trait for attack scenarios
pub trait AttackScenario {
    fn name(&self) -> &str;
    fn generate(&self, target: &Entity, all_entities: &[Entity]) -> Vec<AttackStep>;
}
