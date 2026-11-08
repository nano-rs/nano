//! NAN-4914: the broker's address check includes the platform's shared SSRF
//! validator (`nanosiem_core::inputlookup::SsrfValidator`). Whatever that
//! validator refuses, the connector refuses too; the connector's own
//! reserved-range list stays in force on top of it. There is no
//! private-network scope in the open crate.

use std::net::IpAddr;

use nano_connector::policy::{self, HostPolicy, PolicyError};
use nano_connector::spec::AllowRule;
use nano_connector::template::Scope;
use nanosiem_core::inputlookup::SsrfValidator;

const SAMPLE: &[&str] = &[
    // public
    "8.8.8.8", "93.184.215.14", "1.1.1.1", "100.128.0.1", "172.32.0.1", "2606:4700:4700::1111",
    // private / reserved / special
    "10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1", "0.0.0.0", "255.255.255.255", "100.64.0.1",
    "169.254.169.254", "169.254.1.1", "192.0.2.1", "198.51.100.7", "203.0.113.9", "224.0.0.1", "198.18.0.1",
    "::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1", "2001:db8::1", "::ffff:10.0.0.1",
    "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1",
];

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn every_address_the_shared_validator_refuses_is_refused_by_the_connector() {
    let shared = SsrfValidator::default_secure();
    let public = HostPolicy::default();
    for a in SAMPLE.iter().map(|s| ip(s)) {
        if shared.validate_ip_address(a).is_err() {
            assert!(matches!(policy::check_ip(a), Err(PolicyError::IpBlocked(_))), "{a}: shared validator refuses it, connector allowed it");
            assert!(public.check_ip(a).is_err(), "{a}");
        }
    }
    // The public scope admits ordinary public addresses.
    for a in ["8.8.8.8", "93.184.215.14", "2606:4700:4700::1111"] {
        assert!(policy::check_ip(ip(a)).is_ok(), "{a}");
    }
}

#[test]
fn the_open_engine_has_no_private_network_scope() {
    // NAN-4914: no API in this crate admits a private, loopback, link-local
    // or metadata destination; a self-managed (on-prem) vendor needs the
    // enterprise transport. Every policy refuses them, by name and by address.
    let p = HostPolicy::compile(
        &[AllowRule { host: Some("api.example.com".into()), host_suffixes: vec![], path_prefixes: vec![] }],
        &Scope::default(),
    )
    .unwrap();
    for a in ["10.0.0.5", "172.16.0.9", "192.168.10.10", "fd12:3456::1", "127.0.0.1", "169.254.169.254", "::ffff:10.0.0.5"] {
        assert!(matches!(p.check_ip(ip(a)), Err(PolicyError::IpBlocked(_))), "{a}");
    }
    for host in ["thehive.customer.internal", "jira.corp.local", "10.0.0.5", "metadata.google.internal"] {
        let rules = vec![AllowRule { host: Some(host.into()), host_suffixes: vec![], path_prefixes: vec![] }];
        assert!(HostPolicy::compile(&rules, &Scope::default()).is_err(), "{host}");
    }
}
