-- NAN-657: server-side OIDC authorization transaction store
--
-- The OIDC authorization flow previously generated `state`, `nonce`, and
-- `code_verifier` server-side, then handed all three back to the browser to
-- echo at the callback. The server kept no record of what it issued, so
-- `state` was never actually validated server-side and `nonce`/`code_verifier`
-- arrived from a client-controlled source. This left login CSRF, fixation,
-- and replay paths open.
--
-- This table persists the transaction server-side. At /authorize we INSERT a
-- row keyed on `state`. At /callback we look it up, verify it isn't consumed
-- or expired, mark it consumed, and use the *stored* code_verifier/nonce for
-- PKCE/nonce validation. Only `state` and the redirect URL flow back to the
-- browser.

CREATE TABLE public.oidc_auth_transactions (
    state            TEXT        PRIMARY KEY,
    provider_id      UUID        NOT NULL REFERENCES public.oidc_providers(id) ON DELETE CASCADE,
    nonce            TEXT        NOT NULL,
    code_verifier    TEXT        NOT NULL,
    redirect_uri     TEXT        NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    consumed_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Cleanup index: the housekeeping job (or a future periodic delete) scans
-- WHERE expires_at < NOW().
CREATE INDEX idx_oidc_auth_transactions_expires_at
    ON public.oidc_auth_transactions (expires_at);

-- Provider lookups (for "all open transactions for provider X" queries that
-- audit / admin tooling may want).
CREATE INDEX idx_oidc_auth_transactions_provider_id
    ON public.oidc_auth_transactions (provider_id);
