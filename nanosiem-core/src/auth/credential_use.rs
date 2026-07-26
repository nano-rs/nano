// SPDX-License-Identifier: AGPL-3.0-or-later

//! Capability token for operations that may use stored credential material.
//!
//! The HTTP layer constructs this grant after evaluating `credentials:use`.
//! Core services accept it explicitly and re-check it at the branch that
//! precedes credential lookup or decryption. Keeping the grant fail-closed
//! prevents internal callers from accidentally bypassing that boundary.

use super::permissions;

/// Proof that a caller may use stored credential material.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CredentialUseGrant {
    allowed: bool,
}

impl CredentialUseGrant {
    /// Construct a fail-closed grant.
    pub const fn none() -> Self {
        Self { allowed: false }
    }

    /// Construct a grant for an authenticated principal whose permission was
    /// checked by the API authorization adapter.
    pub const fn granted() -> Self {
        Self { allowed: true }
    }

    /// Construct a grant for an explicit trusted system workflow, such as
    /// startup reconciliation.
    pub const fn system() -> Self {
        Self { allowed: true }
    }

    /// Whether stored credential material may be used.
    pub const fn allows(self) -> bool {
        self.allowed
    }

    /// Require the grant, returning the canonical permission ID on denial.
    pub fn ensure(self) -> Result<(), &'static str> {
        if self.allowed {
            Ok(())
        } else {
            Err(permissions::CREDENTIALS_USE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_fail_closed() {
        assert_eq!(CredentialUseGrant::default(), CredentialUseGrant::none());
        assert!(!CredentialUseGrant::none().allows());
        assert_eq!(
            CredentialUseGrant::none().ensure(),
            Err(permissions::CREDENTIALS_USE)
        );
    }

    #[test]
    fn authenticated_and_system_grants_allow_use() {
        assert!(CredentialUseGrant::granted().allows());
        assert!(CredentialUseGrant::granted().ensure().is_ok());
        assert!(CredentialUseGrant::system().allows());
        assert!(CredentialUseGrant::system().ensure().is_ok());
    }
}
