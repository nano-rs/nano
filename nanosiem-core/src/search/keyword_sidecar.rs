// SPDX-License-Identifier: AGPL-3.0-or-later

//! The keyword-sidecar field contract, shared by the query compiler and the
//! lake worker that builds the index.
//!
//! These are the fields a `contains`/keyword hint may be answered from by the
//! Tantivy sidecar rather than by scanning source Parquet. The compiler (which
//! decides when to emit a hint) and the worker (which decides what to index)
//! MUST agree.
//!
//! A previous comment claimed a mismatch was safe "because the exact Parquet
//! predicate is always rechecked". That is wrong in one direction and worth
//! stating precisely, because the failure is silent:
//!
//! - A path indexed but never hinted only forgoes an optimization. Harmless.
//! - A path **hinted but not indexed** is not harmless. When the fragment
//!   dictionary is complete and no indexed term contains the token, the planner
//!   returns an EMPTY candidate set, and that set fences the query *before* the
//!   recheck ever runs. Every hunt on that field then returns zero rows, with no
//!   error — the same silent-wrong-answer shape as the regex guard that
//!   harvested a literal from a conditional branch.
//!
//! Living in one place, with `keyword_body_fields_match_the_compiler_contract`
//! in the worker asserting against it, is what keeps that from being one
//! careless edit away.

/// Fields a keyword/`contains` hint may be answered from by the sidecar index.
pub const KEYWORD_SIDECAR_PATHS: &[&str] = &[
    "message",
    "raw_data",
    "process.cmd_line",
    "actor.process.cmd_line",
    "process.name",
    "actor.process.name",
    "process.file.path",
    "actor.process.file.path",
    "process.file.hashes.value",
    "actor.process.file.hashes.value",
    "file.path",
    "file.name",
    "file.hashes.value",
    "module.file.path",
    "module.file.name",
    "http_request.url.url_string",
    "http_request.url.hostname",
    "http_request.user_agent",
    "query.hostname",
    "src_endpoint.hostname",
    "dst_endpoint.hostname",
    "device.hostname",
    "user.name",
    "actor.user.name",
    "finding_info.title",
    "finding_info.analytic.name",
    "enrichments.name",
    "enrichments.value",
    "enrichments.provider",
    "enrichments.short_desc",
];
