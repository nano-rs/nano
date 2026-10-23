//! Resolve the SAME pinned connector specs and HostPolicy the run path uses.
//! Never infer fetch destinations from result links or arbitrary input URLs.
use nanosiem_core::egress::{Grant, Purpose, host_grants};
use serde_json::Value;
use uuid::Uuid;

pub fn connector_grants(
    tenant: Uuid,
    yaml: &str,
    expected_sha256: &str,
    config: Value,
) -> Result<Vec<Grant>, &'static str> {
    if crate::service::feed::spec_sha256(yaml) != expected_sha256 {
        return Err("connector revision differs");
    }
    let spec = crate::spec::ConnectorSpec::from_yaml(yaml).map_err(|_| "invalid connector spec")?;
    let policy = crate::policy::HostPolicy::compile(
        &spec.allow,
        &crate::template::Scope {
            config,
            ..Default::default()
        },
    )
    .map_err(|_| "connector hosts could not be resolved")?;
    host_grants(
        tenant,
        Purpose::Connector,
        policy.hosts().map(str::to_owned),
        expected_sha256,
        "nano-connector-runner",
    )
}

pub fn ti_grants(tenant: Uuid, enabled: &[String]) -> Result<Vec<Grant>, &'static str> {
    let mut grants = Vec::new();
    for spec in crate::lookup::official_specs()
        .iter()
        .filter(|s| enabled.contains(&s.name))
    {
        spec.validate()
            .map_err(|_| "invalid official lookup spec")?;
        let policy =
            crate::policy::HostPolicy::compile(&spec.allow, &crate::template::Scope::default())
                .map_err(|_| "invalid lookup host policy")?;
        grants.extend(host_grants(
            tenant,
            Purpose::ThreatIntel,
            policy.hosts().map(str::to_owned),
            "official-lookup-v1",
            "api",
        )?);
    }
    Ok(grants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::egress::{Grants, Origin};
    #[test]
    fn production_spec_resolution_generates_exact_tenant_hosts_and_checks_revision() {
        let tenant = Uuid::from_u128(10);
        let yaml = include_str!("../specs/okta_system_log.yaml");
        let sha = crate::service::feed::spec_sha256(yaml);
        let grants = connector_grants(
            tenant,
            yaml,
            &sha,
            serde_json::json!({"OKTA_DOMAIN":"acme.okta.com"}),
        )
        .unwrap();
        let policy = Grants::compile(&grants).unwrap();
        let origin = Origin::from_url("https://acme.okta.com", Purpose::Connector).unwrap();
        assert!(policy.permits(tenant, Purpose::Connector, &origin));
        assert!(!policy.permits(Uuid::from_u128(11), Purpose::Connector, &origin));
        assert!(!policy.permits(
            tenant,
            Purpose::Connector,
            &Origin::from_url("https://unlisted.okta.com", Purpose::Connector).unwrap()
        ));
        assert!(
            connector_grants(
                tenant,
                yaml,
                "wrong-revision",
                serde_json::json!({"OKTA_DOMAIN":"acme.okta.com"})
            )
            .is_err()
        );
        assert!(
            connector_grants(
                tenant,
                yaml,
                &sha,
                serde_json::json!({"OKTA_DOMAIN":"okta.com.evil.example"})
            )
            .is_err()
        );
    }
    #[test]
    fn lookup_acl_comes_from_enabled_official_specs() {
        let tenant = Uuid::from_u128(10);
        assert!(ti_grants(tenant, &[]).unwrap().is_empty());
        let grants = ti_grants(tenant, &["virustotal".into()]).unwrap();
        assert!(!grants.is_empty());
        assert!(
            grants
                .iter()
                .all(|g| g.origin.host() == "www.virustotal.com")
        );
    }
}
