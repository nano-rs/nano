#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use nanosiem_core::auth::{
    validate_password_complexity, PasswordRequirements,
    TokenService, TokenConfig,
};

#[derive(Arbitrary, Debug)]
struct AuthFuzzInput {
    password: String,
    token: String,
    // Password requirements (will be bounded)
    min_length: u8,
    require_uppercase: bool,
    require_lowercase: bool,
    require_digit: bool,
    require_special: bool,
}

fuzz_target!(|input: AuthFuzzInput| {
    // 1. Fuzz password complexity validation with arbitrary requirements
    let requirements = PasswordRequirements {
        min_length: (input.min_length % 64) as usize, // Cap at 64 to avoid OOM
        require_uppercase: input.require_uppercase,
        require_lowercase: input.require_lowercase,
        require_digit: input.require_digit,
        require_special: input.require_special,
    };

    // Should never panic regardless of input
    let _ = validate_password_complexity(&input.password, &requirements);

    // 2. Fuzz JWT token validation
    // Construct config directly to avoid Default::default() which reads env vars
    let config = TokenConfig {
        jwt_secret: "fuzz-test-secret-key-32chars!!".to_string(),
        access_token_ttl: 900,
        refresh_token_ttl: 604800,
    };
    let service = TokenService::new(config);

    // Should never panic on malformed tokens
    let _ = service.validate_access_token(&input.token);
    let _ = service.validate_refresh_token(&input.token);
    let _ = service.decode_token_claims(&input.token);
});
