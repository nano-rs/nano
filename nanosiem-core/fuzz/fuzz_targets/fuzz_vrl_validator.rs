#![no_main]

use libfuzzer_sys::fuzz_target;
use nanosiem_core::parsers::VrlValidator;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, skip invalid UTF-8
    let Ok(vrl_code) = std::str::from_utf8(data) else {
        return;
    };

    // Limit input size to prevent OOM (validator has 64KB limit anyway)
    if vrl_code.len() > 70_000 {
        return;
    }

    // Create validator without Docker (tests pure validation logic)
    let validator = VrlValidator::without_docker();

    // Run validation - should never panic
    // Uses tokio runtime since validate_vrl is async
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let _ = rt.block_on(validator.validate_vrl(vrl_code));
});
