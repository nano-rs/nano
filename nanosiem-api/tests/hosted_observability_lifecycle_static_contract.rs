//! Hosted jobs must never probe tenant-supplied synthetic URLs.
#[test]
fn hosted_synthetics_remain_refused_while_tenant_evaluator_starts() {
    let lifecycle = include_str!("../src/state/lifecycle.rs");
    let shared = lifecycle
        .split("if self.config.deployment_mode.is_enterprise_shared() {")
        .nth(1)
        .unwrap()
        .split("return handles;")
        .next()
        .unwrap();
    assert!(shared.contains("refused = \"synthetics_runner\""));
    assert!(shared.contains("tenant_observability_eval_runtime"));
    assert!(!shared.contains("start_synthetic"));
    assert!(!shared.contains("start_metric_monitor_evaluator"));
}
