// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5412 (totp-rs 5 -> 6): enrolled authenticators must keep working.
//!
//! nano stores each user's TOTP secret as encrypted, unpadded RFC 4648 base32
//! text (what totp-rs 5's `Secret::to_encoded` produced). These pin that text
//! format and the codes it yields against RFC 6238 Appendix B (SHA-1 seed
//! "12345678901234567890"), truncated to nano's 6 digits. The expected values
//! were computed independently of totp-rs (Python `hmac`), so a library
//! change cannot move both sides.
use super::*;

/// base32 of the RFC 6238 SHA-1 seed: 32 chars, unpadded, as 5.x stored it.
const RFC6238_SHA1_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

const RFC6238_SHA1_6_DIGIT: &[(u64, &str)] = &[
    (59, "287082"),
    (1_111_111_109, "081804"),
    (1_111_111_111, "050471"),
    (1_234_567_890, "005924"),
    (2_000_000_000, "279037"),
    (20_000_000_000, "353130"),
];

#[test]
fn stored_base32_secrets_yield_the_rfc6238_codes() {
    let totp = totp_from_secret(RFC6238_SHA1_SEED_B32, "user@example.com").unwrap();
    assert_eq!(totp.secret().as_bytes(), b"12345678901234567890");
    for (time, code) in RFC6238_SHA1_6_DIGIT {
        assert_eq!(totp.generate(*time).to_string(), *code, "t={time}");
        assert!(totp.check(code, *time).is_some(), "t={time}");
    }
}

#[test]
fn skew_still_accepts_one_step_either_side_and_nothing_further() {
    let totp = totp_from_secret(RFC6238_SHA1_SEED_B32, "user@example.com").unwrap();
    let (time, code) = (1_111_111_111u64, "050471");
    assert!(totp.check(code, time + 30).is_some(), "one step late");
    assert!(totp.check(code, time - 30).is_some(), "one step early");
    assert!(totp.check(code, time + 60).is_none(), "two steps late");
    assert!(totp.check(code, time - 60).is_none(), "two steps early");
    assert!(totp.check("000000", time).is_none());
}

#[test]
fn generated_secrets_round_trip_through_the_stored_text_form() {
    let (issued, secret_b32) = generate_totp_secret("user@example.com").unwrap();
    // 160-bit secret, unpadded base32 (no '='), uppercase RFC 4648 alphabet.
    assert_eq!(secret_b32.len(), 32);
    assert!(secret_b32.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
    let restored = totp_from_secret(&secret_b32, "user@example.com").unwrap();
    assert_eq!(restored.secret().as_bytes(), issued.secret().as_bytes());
    assert_eq!(issued.generate(1_700_000_000).to_string(), restored.generate(1_700_000_000).to_string());
    assert!(generate_qr_code(&issued).is_ok_and(|png| !png.is_empty()));
}

#[test]
fn short_or_malformed_secrets_are_refused_as_before() {
    // 80-bit secret: below RFC 6238's 128-bit floor, which 5.x refused too.
    assert!(totp_from_secret("JBSWY3DPEHPK3PXP", "user@example.com").is_err());
    assert!(totp_from_secret("not base32!", "user@example.com").is_err());
}

/// The enrollment URI the authenticator app scans must keep 5.x's exact form.
#[test]
fn otpauth_uri_keeps_the_5x_shape() {
    let totp = totp_from_secret(RFC6238_SHA1_SEED_B32, "analyst+soc@example.com").unwrap();
    assert_eq!(
        totp.to_url().unwrap(),
        "otpauth://totp/nano:analyst%2Bsoc%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=nano"
    );
}
