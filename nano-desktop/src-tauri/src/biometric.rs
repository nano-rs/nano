//! Touch ID for the trusted-device fast path.
//!
//! The refresh token in the keychain is what makes a device "trusted" — but on
//! its own it means anyone who sits down at an unlocked Mac is inside the SIEM.
//! Gating it behind a biometric check turns "the app remembered me" into "the
//! app remembered me, and confirmed it's still me."

use robius_authentication::{
    AndroidText, BiometricStrength, Context, PolicyBuilder, Text, WindowsText,
};

use crate::error::{Error, Result};

/// Prompt for Touch ID (falling back to the device password, which is what
/// macOS itself does when a finger doesn't read).
///
/// Blocking: the OS presents a modal, so it runs off the async runtime.
pub async fn authenticate(reason: String) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let policy = PolicyBuilder::new()
            .biometrics(Some(BiometricStrength::Strong))
            // Without this, a Mac with no Touch ID hardware could never unlock.
            .password(true)
            .watch(true)
            .build()
            .ok_or_else(|| Error::Internal("could not build an auth policy".into()))?;

        let text = Text {
            apple: &reason,
            android: AndroidText {
                title: "nano",
                subtitle: None,
                description: Some(&reason),
            },
            windows: WindowsText::new("nano", &reason)
                .ok_or_else(|| Error::Internal("invalid auth prompt".into()))?,
        };

        Context::new(())
            .blocking_authenticate(text, &policy)
            .map_err(|e| Error::Unauthorized(format!("Device unlock failed: {e:?}")))
    })
    .await
    .map_err(|e| Error::Internal(format!("auth task: {e}")))?
}
