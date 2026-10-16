-- NAN-3910: operator-owned per-tenant IOC capacity overrides. Empty config
-- inherits code defaults; tenant APIs have no write path to this relation.
CREATE TABLE IF NOT EXISTS public.ioc_list_limits (
    tenant_id UUID PRIMARY KEY REFERENCES public.tenants(id) ON DELETE RESTRICT,
    limits JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(limits) = 'object'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
REVOKE ALL ON public.ioc_list_limits FROM PUBLIC;
