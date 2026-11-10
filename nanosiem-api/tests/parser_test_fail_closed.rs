// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5234: a process that never registered a parser-test worker (this test
//! harness, like any binary whose `main` does not dispatch the worker) must
//! not execute tenant VRL in-process. Before NAN-5234 this test's program ran
//! inside the calling process and succeeded.

use nanosiem_core::parsers::VrlValidator;

#[tokio::test]
async fn parser_tests_never_execute_in_an_unregistered_process() {
    let validator = VrlValidator::new();
    // The draft is valid: only execution is refused.
    assert!(validator.validate_vrl(".x = 1").await.unwrap().valid);
    match validator.test_vrl(".x = 1", "{}").await {
        Err(error) => assert!(error.to_string().contains("isolation is unavailable"), "{error}"),
        Ok(result) => panic!("executed in-process: {result:?}"),
    }

    let batch = validator.test_vrl_batch(".x = 1", &["{}".to_string()]).await;
    assert!(batch.is_err(), "executed in-process: {batch:?}");
    let chain = validator.test_vrl_chain(&[".x = 1", ".y = 2"], "{}").await;
    assert!(chain.is_err(), "executed in-process: {chain:?}");
}
