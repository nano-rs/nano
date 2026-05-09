// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lateral movement AST types
//!
//! This module defines types for the `| lateral` command which traces
//! lateral movement paths across authentication events, network connections,
//! and process execution for a given seed entity (user or host).

use serde::{Deserialize, Serialize};

/// How to identify the seed entity for lateral movement tracing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LateralSeedType {
    /// Auto-detect from the query context (check user first, then host)
    #[default]
    Auto,
    /// Seed by user identity
    User,
    /// Seed by hostname/IP
    Host,
}

impl LateralSeedType {
    /// Parse seed type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Some(LateralSeedType::Auto),
            "user" => Some(LateralSeedType::User),
            "host" => Some(LateralSeedType::Host),
            _ => None,
        }
    }

    /// Returns the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            LateralSeedType::Auto => "auto",
            LateralSeedType::User => "user",
            LateralSeedType::Host => "host",
        }
    }
}

/// Categories of lateral movement evidence to search for
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LateralMethod {
    /// Authentication events (RDP, SSH, SMB logins)
    Auth,
    /// Network connections (internal-to-internal on lateral ports)
    Network,
    /// Process execution (PsExec, WMIC, PowerShell remoting, WinRS)
    Process,
}

impl LateralMethod {
    /// Parse method from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "auth" => Some(LateralMethod::Auth),
            "network" => Some(LateralMethod::Network),
            "process" => Some(LateralMethod::Process),
            _ => None,
        }
    }

    /// Returns the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            LateralMethod::Auth => "auth",
            LateralMethod::Network => "network",
            LateralMethod::Process => "process",
        }
    }

    /// Get all available methods
    pub fn all() -> Vec<LateralMethod> {
        vec![
            LateralMethod::Auth,
            LateralMethod::Network,
            LateralMethod::Process,
        ]
    }
}
