// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3490: a declarative connector engine with a VRL request loop.
//!
//! The engine library (NAN-4914 phase 3): spec, templating, host policy, the
//! egress broker, auth plugins, pagination, checkpoints, the sandboxed VRL
//! worker, preview/validate and lookups; and the pull-feed runner service
//! (`service`, `first_party`: scheduler, PostgreSQL checkpoints, HEC emit
//! into the local Vector, bundled collector specs; phase 4). SOAR
//! (enterprise) builds its request sequences, private-network authority and
//! proxy settings in `nanosiem-enterprise::soar_engine` on top of these
//! generic primitives; none of that lives here.
//!
//! See `docs/AUTHORING.md` for the spec format and `docs/connector.schema.json`
//! for the schema.

pub mod auth;
pub mod broker;
pub mod egress;
pub mod paging;
pub mod policy;
pub mod spec;
pub mod template;
pub mod vrl_exec;
pub mod engine;
pub mod identity;
pub mod preview;
pub mod loopback;
pub mod parse_check;
pub mod sandbox;
pub mod secrets;
pub mod point_forward;

pub mod lookup;
pub mod first_party;
pub mod service;
