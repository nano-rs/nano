//! Attack scenarios for the injector tool

pub mod exfil;
pub mod lateral;
pub mod persistence;
pub mod quick;
pub mod staggered;

use chrono::{DateTime, Utc};
use event_core::entity::Entity;
use event_core::event::Event;
use event_core::generators::SysmonGenerator;
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

/// Build an `AttackStep` that emits a Sysmon Event ID 1 for a scripted process.
///
/// NAN-1058: replaces the broken pattern every scenario used to follow, which
/// called `gen.generate(ts, entity, rng)` AFTER `spawn_process` — silently
/// discarding the scripted (child, parent) pair and emitting a random
/// profile-sampled event instead. That made the injector's stdout a fiction:
/// detection rules looking for `comsvcs` / `MiniDump` / `certutil ... urlcache`
/// never had anything to match.
///
/// The helper threads the spawned `(child, parent)` into
/// `SysmonGenerator::process_create_from`, so the wire event carries the
/// scripted command line, process name, hash, and parent-tree fields. The
/// function signature makes the bug structurally hard to reintroduce —
/// there's no place to plug `gen.generate(...)` back in.
#[allow(clippy::too_many_arguments)]
pub(super) fn process_create_step(
    gen: &SysmonGenerator,
    entity: &Entity,
    base_time: DateTime<Utc>,
    delay_secs: u64,
    name: &str,
    path: &str,
    cmdline: &str,
    process_hash: Option<&str>,
    stage: &str,
    description: impl Into<String>,
) -> AttackStep {
    process_create_step_as(
        gen,
        entity,
        base_time,
        delay_secs,
        name,
        path,
        cmdline,
        None,
        process_hash,
        stage,
        description,
    )
}

/// Variant of `process_create_step` that lets a scenario spawn the scripted
/// process as a specific user (e.g. `NT AUTHORITY\SYSTEM` for service-creation
/// steps). Without this, all scripted processes inherit the entity's default
/// user, which masks SYSTEM-vs-user provenance signals that some persistence
/// detection rules look for.
#[allow(clippy::too_many_arguments)]
pub(super) fn process_create_step_as(
    gen: &SysmonGenerator,
    entity: &Entity,
    base_time: DateTime<Utc>,
    delay_secs: u64,
    name: &str,
    path: &str,
    cmdline: &str,
    user: Option<&str>,
    process_hash: Option<&str>,
    stage: &str,
    description: impl Into<String>,
) -> AttackStep {
    let ts = base_time + chrono::Duration::seconds(delay_secs as i64);
    let (child, parent) = entity.spawn_process(name, path, cmdline, user);
    AttackStep {
        delay: Duration::from_secs(delay_secs),
        events: vec![gen.process_create_from(ts, entity, &child, &parent, process_hash)],
        stage: stage.into(),
        description: description.into(),
    }
}
