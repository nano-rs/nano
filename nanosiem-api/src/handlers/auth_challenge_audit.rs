// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::state::AppState;
use nanosiem_core::audit::ClientContext;

/// A route selector alone never authorizes tenant audit. Verify the dedicated
/// challenge envelope, then resolve its current exact tenant/member/IP binding.
pub(super) async fn record(
    state: &AppState, challenge: &str, tenant_slug: Option<&str>,
    client: &ClientContext, action: &'static str, success: bool,
    details: Option<serde_json::Value>,
) -> Result<(), ()> {
    #[cfg(feature = "enterprise")]
    if !state.config.deployment_mode.is_enterprise_shared() { return Err(()); }
    #[cfg(feature = "enterprise")]
    {
        use nanosiem_core::audit::{AuditEvent, AuditSource};
        let claims = state.token_service
            .validate_enterprise_shared_mfa_challenge_token_async(challenge).await.map_err(|_| ())?;
        let tenant = state.auth_service.resolve_enterprise_shared_continuation(
            claims.claims.sub, claims.tenant_id, claims.credential_time_micros.ok_or(())?,
            tenant_slug, client.ip_address.as_deref(),
        ).await.map_err(|_| ())?;
        let runtime = state.tenant_ai_rls_runtime.as_ref().ok_or(())?;
        let mut builder = AuditEvent::builder(AuditSource::Auth, action)
            .actor(Some(claims.claims.sub), None)
            .resource("user", Some(claims.claims.sub), None)
            .client_context(client).success(success);
        if let Some(details) = details { builder = builder.details(details); }
        runtime.tenant_mfa_challenge_audit().record(
            &tenant.context, claims.claims.sub, &builder.build(),
        ).await.map_err(|_| ())
    }
    #[cfg(not(feature = "enterprise"))]
    { let _ = (challenge, tenant_slug, client, action, success, details); Err(()) }
}
