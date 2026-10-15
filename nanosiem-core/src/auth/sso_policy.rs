// SPDX-License-Identifier: AGPL-3.0-or-later
//! Persisted provider policy; evaluated only against validated IdP membership.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SsoGroupMapping {
    pub idp_group: String,
    #[serde(default)]
    pub group_ids: Vec<Uuid>,
    #[serde(default)]
    pub role_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SsoAccessPolicy {
    pub mapped_groups_only: bool,
    pub mappings: Vec<SsoGroupMapping>,
    pub entra_tenant_id: Option<Uuid>,
    pub verified_domains: Vec<String>,
    pub google_delegated_admin: Option<String>,
}
impl Default for SsoAccessPolicy {
    fn default() -> Self {
        Self {
            mapped_groups_only: true,
            mappings: vec![],
            entra_tenant_id: None,
            verified_domains: vec![],
            google_delegated_admin: None,
        }
    }
}
impl SsoAccessPolicy {
    pub fn validate(&self, hosted: bool) -> Result<(), &'static str> {
        if self.mappings.len() > 64
            || self.verified_domains.len() > 64
            || self.entra_tenant_id.is_some_and(|id| id.is_nil())
        {
            return Err("Invalid SSO policy");
        }
        let mut seen = std::collections::HashSet::new();
        for m in &self.mappings {
            if m.idp_group.is_empty()
                || m.idp_group.len() > 512
                || m.idp_group.trim() != m.idp_group
                || m.idp_group.chars().any(char::is_control)
                || !seen.insert(&m.idp_group)
                || m.group_ids.len() + m.role_ids.len() == 0
                || m.group_ids.len() + m.role_ids.len() > 64
                || m.group_ids.iter().chain(&m.role_ids).any(Uuid::is_nil)
                || (hosted && !m.group_ids.is_empty())
                || (!hosted && !m.role_ids.is_empty())
            {
                return Err("Invalid SSO group mapping");
            }
        }
        for domain in &self.verified_domains {
            if domain.is_empty()
                || domain.len() > 253
                || domain != &domain.to_ascii_lowercase()
                || domain.split('.').any(|p| {
                    p.is_empty()
                        || p.len() > 63
                        || p.starts_with('-')
                        || p.ends_with('-')
                        || !p
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                })
            {
                return Err("Use exact lowercase verified domains");
            }
        }
        if self.google_delegated_admin.as_ref().is_some_and(|v| {
            v.len() > 254
                || v.trim() != v
                || v.split('@').count() != 2
                || v.starts_with('@')
                || v.ends_with('@')
                || v.chars().any(char::is_control)
        }) {
            return Err("Invalid delegated administrator");
        }
        Ok(())
    }
    pub fn matching<'a>(&'a self, groups: &[String]) -> Vec<&'a SsoGroupMapping> {
        self.mappings
            .iter()
            .filter(|m| groups.contains(&m.idp_group))
            .collect()
    }
    /// Turning the gate off keeps invitation-only access; it never opens JIT to everyone.
    pub fn allows(&self, groups: &[String], invited: bool, membership_known: bool) -> bool {
        invited
            || (self.mapped_groups_only && membership_known && !self.matching(groups).is_empty())
    }
    pub fn verifies_email(&self, claims: &super::IdTokenClaims) -> bool {
        if claims.verified_email() {
            return true;
        }
        let Some(tid) = claims.entra_tenant().and_then(|s| Uuid::parse_str(s).ok()) else {
            return false;
        };
        self.entra_tenant_id == Some(tid)
            && claims.email.as_ref().is_some_and(|email| {
                let parts: Vec<_> = email.split('@').collect();
                parts.len() == 2
                    && !parts[0].is_empty()
                    && !email.chars().any(char::is_whitespace)
                    && self
                        .verified_domains
                        .iter()
                        .any(|domain| domain.eq_ignore_ascii_case(parts[1]))
            })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> SsoAccessPolicy {
        SsoAccessPolicy {
            mappings: vec![SsoGroupMapping {
                idp_group: "allowed".into(),
                group_ids: vec![Uuid::new_v4()],
                role_ids: vec![],
            }],
            ..Default::default()
        }
    }
    #[test]
    fn admission_is_exact_and_invites_survive() {
        let mut p = policy();
        assert!(p.allows(&["allowed".into()], false, true));
        assert!(!p.allows(&["Allowed".into()], false, true));
        assert!(!p.allows(&["allowed".into()], false, false));
        assert!(p.allows(&[], true, false));
        assert!(!SsoAccessPolicy::default().allows(&[], false, true));
        p.mapped_groups_only = false;
        assert!(!p.allows(&["allowed".into()], false, true));
    }
    #[test]
    fn tenant_roles_and_dedicated_groups_are_distinct() {
        assert!(policy().validate(true).is_err());
        assert!(policy().validate(false).is_ok());
    }
    #[test]
    fn domain_fallback_requires_exact_tenant_and_domain() {
        let mut p = SsoAccessPolicy::default();
        let tid = Uuid::new_v4();
        p.entra_tenant_id = Some(tid);
        p.verified_domains = vec!["example.com".into()];
        let mut c: super::super::IdTokenClaims = serde_json::from_value(serde_json::json!({
            "iss":format!("https://login.microsoftonline.com/{tid}/v2.0"),"tid":tid,
            "sub":"subject","aud":"client","iat":1,"exp":2,"email":"user@example.com"
        }))
        .unwrap();
        assert!(p.verifies_email(&c));
        c.email = Some("user@evil.example.com".into());
        assert!(!p.verifies_email(&c));
        c.email = Some("user@example.com".into());
        c.tid = Some(Uuid::new_v4().to_string());
        assert!(!p.verifies_email(&c));
    }
}
