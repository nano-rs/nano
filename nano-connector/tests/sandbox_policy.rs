//! NAN-4914 (codex P1): `NANO_CONNECTOR_SANDBOX=strict` is authoritative.
//! A per-layer override next to it can never downgrade a layer; anything but
//! `require` is a startup error.

use nano_connector::sandbox::{Enforce, SandboxPolicy};

fn policy(pairs: &[(&str, &str)]) -> Result<SandboxPolicy, String> {
    let pairs: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    SandboxPolicy::from_lookup(move |k| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))
}

#[test]
fn strict_cannot_be_downgraded_by_layer_overrides() {
    for layer in ["NANO_CONNECTOR_SECCOMP", "NANO_CONNECTOR_CGROUP"] {
        for weaker in ["prefer", "off", "auto", "0"] {
            // Either order in the environment: the result is the same error.
            let e = policy(&[("NANO_CONNECTOR_SANDBOX", "strict"), (layer, weaker)]).expect_err(weaker);
            assert!(e.contains(layer) && e.contains("strict"), "{e}");
            let e = policy(&[(layer, weaker), ("NANO_CONNECTOR_SANDBOX", "strict")]).expect_err(weaker);
            assert!(e.contains("conflicts"), "{e}");
        }
    }
    // Agreeing overrides are fine; strict still requires both layers.
    let p = policy(&[("NANO_CONNECTOR_SANDBOX", "strict"), ("NANO_CONNECTOR_SECCOMP", "require")]).unwrap();
    assert_eq!((p.seccomp, p.cgroup), (Enforce::Require, Enforce::Require));
    let p = policy(&[("NANO_CONNECTOR_SANDBOX", "strict")]).unwrap();
    assert_eq!((p.seccomp, p.cgroup), (Enforce::Require, Enforce::Require));
    // Without strict, per-layer settings apply as before.
    let p = policy(&[("NANO_CONNECTOR_SECCOMP", "off")]).unwrap();
    assert_eq!(p.seccomp, Enforce::Off);
    assert!(policy(&[("NANO_CONNECTOR_SANDBOX", "prefer"), ("NANO_CONNECTOR_CGROUP", "require")]).unwrap().cgroup == Enforce::Require);
}
