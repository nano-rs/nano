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
    /// NAN-5147: may also point a bound credential at a new destination
    /// (credential-owner level, `credentials:edit`).
    retarget: bool,
}

impl CredentialUseGrant {
    /// Construct a fail-closed grant.
    pub const fn none() -> Self {
        Self { allowed: false, retarget: false }
    }

    /// Construct a grant for an authenticated principal whose permission was
    /// checked by the API authorization adapter. Does not allow retargeting a
    /// bound credential; see [`Self::with_credential_edit`].
    pub const fn granted() -> Self {
        Self { allowed: true, retarget: false }
    }

    /// Construct a grant for an explicit trusted system workflow, such as
    /// startup reconciliation.
    pub const fn system() -> Self {
        Self { allowed: true, retarget: true }
    }

    /// NAN-5147: record whether the principal also holds `credentials:edit`,
    /// which is required to move a bound credential to a different connection
    /// host. Never widens a grant that does not allow use.
    pub const fn with_credential_edit(self, can_edit: bool) -> Self {
        Self { allowed: self.allowed, retarget: self.allowed && can_edit }
    }

    /// Whether stored credential material may be used.
    pub const fn allows(self) -> bool {
        self.allowed
    }

    /// Require permission to send a bound credential to a new destination,
    /// returning the canonical permission ID on denial.
    pub fn ensure_retarget(self) -> Result<(), &'static str> {
        self.ensure()?;
        if self.retarget {
            Ok(())
        } else {
            Err(permissions::CREDENTIALS_EDIT)
        }
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

    #[test]
    fn retarget_requires_credential_edit() {
        assert_eq!(
            CredentialUseGrant::granted().ensure_retarget(),
            Err(permissions::CREDENTIALS_EDIT)
        );
        assert!(CredentialUseGrant::granted()
            .with_credential_edit(true)
            .ensure_retarget()
            .is_ok());
        assert!(CredentialUseGrant::system().ensure_retarget().is_ok());
        // Edit alone never upgrades a denied use grant.
        assert_eq!(
            CredentialUseGrant::none().with_credential_edit(true).ensure_retarget(),
            Err(permissions::CREDENTIALS_USE)
        );
        assert!(!CredentialUseGrant::none().with_credential_edit(true).allows());
    }
}
