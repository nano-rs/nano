// SPDX-License-Identifier: AGPL-3.0-or-later

//! Concurrency admission for expensive per-request work, keyed on the
//! authenticated PRINCIPAL (security review 2026-11-08).
//!
//! Two limits, both non-blocking (a refusal is immediate; nothing queues):
//! - **per principal**: how many requests one user / API key may have running
//!   at once, so one caller cannot hold every slot;
//! - **global**: a generous per-replica ceiling, so the total never exceeds
//!   what the replica can run without starving other handlers.
//!
//! The key is never a source IP. Many legitimate callers share one egress
//! address (corporate NAT, a SOC behind one proxy, nano Desktop users in one
//! office), and behind the bundled reverse proxy every request arrives from the
//! proxy's address, so an IP key would turn a per-caller limit into a global
//! one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Which limit refused the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateScope {
    Principal,
    Global,
}

/// A refused admission. Maps to HTTP 429 with `Retry-After`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateRefused {
    pub what: &'static str,
    pub scope: GateScope,
    pub limit: usize,
    pub retry_after_secs: u64,
}

impl std::fmt::Display for GateRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scope = match self.scope {
            GateScope::Principal => "per-user",
            GateScope::Global => "server-wide",
        };
        write!(
            f,
            "{}: {scope} limit of {} concurrent requests reached; retry in {}s",
            self.what, self.limit, self.retry_after_secs
        )
    }
}

impl std::error::Error for GateRefused {}

/// A principal-keyed concurrency gate. Cheap to clone (shared state).
#[derive(Clone)]
pub struct PrincipalGate {
    what: &'static str,
    per_principal: usize,
    global_limit: usize,
    retry_after_secs: u64,
    global: Arc<Semaphore>,
    running: Arc<Mutex<HashMap<String, usize>>>,
}

/// Held while the admitted work runs; releases both slots on drop (including
/// when the request future is cancelled).
pub struct GatePermit {
    running: Arc<Mutex<HashMap<String, usize>>>,
    principal: String,
    _global: OwnedSemaphorePermit,
}

impl PrincipalGate {
    /// `what` names the work in the refusal message ("VRL test").
    pub fn new(
        what: &'static str,
        per_principal: usize,
        global_limit: usize,
        retry_after_secs: u64,
    ) -> Self {
        let per_principal = per_principal.max(1);
        let global_limit = global_limit.max(per_principal);
        Self {
            what,
            per_principal,
            global_limit,
            retry_after_secs,
            global: Arc::new(Semaphore::new(global_limit)),
            running: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Admit one request for `principal` (a stable id such as `user:<uuid>` or
    /// `api_key:<uuid>`), or refuse immediately.
    pub fn try_acquire(&self, principal: &str) -> Result<GatePermit, GateRefused> {
        let refused = |scope, limit| GateRefused {
            what: self.what,
            scope,
            limit,
            retry_after_secs: self.retry_after_secs,
        };
        {
            let mut running = self.running.lock().unwrap_or_else(|p| p.into_inner());
            let count = running.entry(principal.to_string()).or_insert(0);
            if *count >= self.per_principal {
                return Err(refused(GateScope::Principal, self.per_principal));
            }
            *count += 1;
        }
        // Per-principal first, so one caller never holds a global slot while
        // their own limit refuses them.
        match self.global.clone().try_acquire_owned() {
            Ok(global) => Ok(GatePermit {
                running: self.running.clone(),
                principal: principal.to_string(),
                _global: global,
            }),
            Err(_) => {
                release(&self.running, principal);
                Err(refused(GateScope::Global, self.global_limit))
            }
        }
    }
}

fn release(running: &Mutex<HashMap<String, usize>>, principal: &str) {
    let mut running = running.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(count) = running.get_mut(principal) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            running.remove(principal);
        }
    }
}

impl Drop for GatePermit {
    fn drop(&mut self) {
        release(&self.running, &self.principal);
    }
}

#[cfg(test)]
#[path = "principal_gate_tests.rs"]
mod tests;
