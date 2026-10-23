//! NAN-3490: a declarative connector engine with a VRL request loop, and
//! the feed runner service around it (`service`).
//!
//! See `docs/AUTHORING.md` for the spec format and `docs/connector.schema.json`
//! for the schema. Shipped specs live in the nano-integrations and
//! nano-enrichments content repos, next to each manifest.

pub mod auth;
pub mod broker;
pub mod egress_proxy;
pub mod egress_policy;
pub mod paging;
pub mod policy;
pub mod spec;
pub mod template;
pub mod vrl_exec;
pub mod engine;
pub mod preview;
pub mod sink;
pub mod service;
pub mod loopback;
pub mod parse_check;
pub mod sandbox;
pub mod secrets;
#[cfg(feature = "enterprise")]
pub mod pull_broker;
#[cfg(not(feature = "enterprise"))]
#[path = "pull_broker_open.rs"]
pub mod pull_broker;
pub mod identity;
pub mod point_forward;

pub mod first_party;
pub mod lookup;
pub mod sequence;
