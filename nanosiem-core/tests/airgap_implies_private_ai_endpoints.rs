// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2231: `AIRGAP_MODE` implies the private-AI-endpoint allowance.
//!
//! An air-gapped deployment's inference server is, by definition, on a private
//! address, and there is no egress for an SSRF to pivot to. Requiring a second
//! opt-in (`NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS`) on top of `AIRGAP_MODE` was
//! friction that bought nothing — the operator had already declared the
//! deployment air-gapped.
//!
//! This lives in its own integration binary, and holds the only test in it, on
//! purpose: it mutates process-global environment variables, and the SSRF unit
//! tests in `nanosiem-core` assert the secure-by-default behaviour that these
//! variables switch off. Same-process parallelism would make both flaky.

use nanosiem_core::inputlookup::{
    ai_base_url_validator, private_ai_endpoints_allowed, ALLOW_PRIVATE_AI_ENDPOINTS_ENV,
};

const AIRGAP_MODE_ENV: &str = "AIRGAP_MODE";
const LOOPBACK_ENDPOINT: &str = "http://127.0.0.1:8000/v1";
const PRIVATE_ENDPOINT: &str = "http://10.1.2.3:8000/v1";
const METADATA_ENDPOINT: &str = "http://169.254.169.254/latest/meta-data";

#[test]
fn airgap_mode_permits_private_ai_endpoints_without_a_second_flag() {
    // Baseline: neither flag set — secure by default (NAN-1368).
    unsafe {
        std::env::remove_var(AIRGAP_MODE_ENV);
        std::env::remove_var(ALLOW_PRIVATE_AI_ENDPOINTS_ENV);
    }
    assert!(!private_ai_endpoints_allowed());
    assert!(
        ai_base_url_validator().validate_url(LOOPBACK_ENDPOINT).is_err(),
        "a connected deployment must still reject a loopback base_url"
    );

    // Air-gap alone is now sufficient: the operator should not have to discover
    // a second environment variable to point nano at their own model server.
    unsafe {
        std::env::set_var(AIRGAP_MODE_ENV, "true");
    }
    assert!(private_ai_endpoints_allowed());
    let v = ai_base_url_validator();
    assert!(v.validate_url(LOOPBACK_ENDPOINT).is_ok());
    assert!(v.validate_url(PRIVATE_ENDPOINT).is_ok());

    // Cloud metadata stays blocked regardless — air-gap loosens the private
    // network rule, never the metadata rule.
    assert!(
        v.validate_url(METADATA_ENDPOINT).is_err(),
        "metadata endpoints must never be reachable, even air-gapped"
    );

    // The explicit opt-in still works on its own, for a connected deployment
    // running its own inference box.
    unsafe {
        std::env::remove_var(AIRGAP_MODE_ENV);
        std::env::set_var(ALLOW_PRIVATE_AI_ENDPOINTS_ENV, "1");
    }
    assert!(private_ai_endpoints_allowed());
    assert!(ai_base_url_validator().validate_url(PRIVATE_ENDPOINT).is_ok());

    // A falsy value must not enable it — `AIRGAP_MODE=false` is a real thing
    // operators write in compose files.
    unsafe {
        std::env::remove_var(ALLOW_PRIVATE_AI_ENDPOINTS_ENV);
        std::env::set_var(AIRGAP_MODE_ENV, "false");
    }
    assert!(!private_ai_endpoints_allowed());

    unsafe {
        std::env::remove_var(AIRGAP_MODE_ENV);
    }
}
