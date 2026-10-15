-- NAN-3580 PR4a: durable synchronous metering, still no hosted activation.
-- Keep hosted_reads_require_cost_guard CHECK (NOT active) until gateway release.
CREATE TABLE public.iceberg_hosted_read_budget (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    budget_day DATE NOT NULL,
    allowance_bytes BIGINT NOT NULL CHECK (allowance_bytes BETWEEN 1 AND 1125899906842624),
    allowance_requests BIGINT NOT NULL CHECK (allowance_requests BETWEEN 1 AND 100000000),
    charged_bytes BIGINT NOT NULL DEFAULT 0 CHECK (charged_bytes BETWEEN 0 AND allowance_bytes),
    charged_requests BIGINT NOT NULL DEFAULT 0 CHECK (charged_requests BETWEEN 0 AND allowance_requests),
    alerted BOOLEAN NOT NULL DEFAULT FALSE,
    suspended BOOLEAN NOT NULL DEFAULT FALSE,
    committed_bytes BIGINT NOT NULL CHECK (committed_bytes >= 0)
);
CREATE TABLE public.iceberg_hosted_read_reservations (
    tenant_id UUID NOT NULL,
    id UUID NOT NULL,
    credential_id UUID NOT NULL,
    budget_day DATE NOT NULL,
    reserved_bytes BIGINT NOT NULL CHECK (reserved_bytes >= 0),
    delivered_bytes BIGINT CHECK (delivered_bytes BETWEEN 0 AND reserved_bytes),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,id),
    FOREIGN KEY (tenant_id) REFERENCES public.iceberg_hosted_read_budget(tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,credential_id) REFERENCES public.iceberg_hosted_read_credentials(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX iceberg_hosted_reservations_day ON public.iceberg_hosted_read_reservations(tenant_id,budget_day);
CREATE INDEX iceberg_hosted_reservations_outstanding ON public.iceberg_hosted_read_reservations(tenant_id,budget_day) WHERE delivered_bytes IS NULL;
-- Privacy/retention barriers persist through a crashed or ambiguous REST commit.
-- Reads fail closed until all registered versions no longer reference the part.
CREATE TABLE public.iceberg_hosted_erasure_barriers (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    part_id TEXT NOT NULL CHECK (part_id ~ '^[0-9]{13}-[0-9a-f]{16}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,part_id)
);
