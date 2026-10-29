// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared by the runtime registry and the build-time prompt catalog.
pub const BLOCKED_VRL_FUNCTIONS: &[&str] = &[
    "get_env_var",
    "get_hostname",
    "http_request",
    "dns_lookup",
    "reverse_dns",
];

pub fn safe_vrl_functions() -> Vec<Box<dyn vrl::compiler::Function>> {
    vrl::stdlib::all()
        .into_iter()
        .filter(|f| !BLOCKED_VRL_FUNCTIONS.contains(&f.identifier()))
        .collect()
}
