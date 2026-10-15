// SPDX-License-Identifier: AGPL-3.0-or-later

//! Open-core builds cannot configure or call the hosted credential broker.
use crate::policy::{EgressDeny, HostPolicy, PolicyError};

pub const UNCONFIGURED: &str = "google_dwd_broker_unconfigured";

/// Uninhabited: even library callers cannot supply a hosted broker to an open engine.
#[derive(Clone, Debug)]
pub enum PlatformBroker {}

impl PlatformBroker {
    pub fn new(_: &str, _: &str, _: &str) -> Result<Self, String> {
        Err(UNCONFIGURED.into())
    }
    pub fn from_env() -> Result<Option<Self>, String> {
        Ok(None)
    }

    pub fn host(&self) -> &str {
        match *self {}
    }
    pub fn endpoint(&self) -> &url::Url {
        match *self {}
    }
    pub fn graph_token_endpoint(&self) -> url::Url {
        match *self {}
    }
    pub fn okta_assertion_endpoint(&self) -> url::Url {
        match *self {}
    }
    pub fn caller_token(&self, _: &str) -> Result<String, String> {
        match *self {}
    }
    pub fn object_header(_: &str) -> Result<String, String> {
        Err(UNCONFIGURED.into())
    }
    pub fn host_policy(&self, _: EgressDeny) -> Result<HostPolicy, PolicyError> {
        match *self {}
    }
    pub fn check_platform_deny(&self, _: &EgressDeny) -> Result<(), String> {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn hosted_broker_is_unavailable_in_open_builds() {
        assert!(super::PlatformBroker::new("https://example.com", "1", "fixture").is_err());
        assert!(super::PlatformBroker::from_env().unwrap().is_none());
        assert!(super::PlatformBroker::object_header("tenant").is_err());
    }
}
